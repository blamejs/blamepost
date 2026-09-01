// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost doctor` says about the certificate an operator has on
 * disk.
 *
 * `doctor` is where an operator goes before mail stops, so a certificate
 * line that reports only whether two files exist is a line that reads
 * "ok" on the morning of the outage. Every way a present, readable
 * certificate can be the wrong one is silent: it expired overnight, the
 * key beside it is from the previous issuance, it is the leaf without
 * the issuer that vouches for it, or it is issued to a name this server
 * does not answer to. In each case both paths point at real files.
 *
 * The leaf-only case deserves its own sentence, because it is the one
 * that survives an operator's own testing. A certificate client writes
 * `cert.pem` and `fullchain.pem` into the same directory and only the
 * second is complete. A browser handed the first fetches the missing
 * issuer itself and shows a padlock; a sending mail server does not
 * fetch anything and fails the handshake. So the operator checks the web
 * port, sees it working, and cannot account for the mail that stopped.
 *
 * Each case is driven through the shipped command rather than through
 * the reader underneath it, because the reader answering correctly into
 * a report that never printed the answer is exactly the failure this
 * covers. What is asserted is the mark and the sentence an operator
 * reads.
 *
 * The certificates are minted per run and written to a temporary
 * directory. Nothing here resolves DNS: the records are expected to be
 * unreadable in this environment and the rows this file reads are the
 * local ones, above the zone report.
 *
 * Run standalone: node test/layer-1-state/cli-doctor-certificate.test.js
 */

var nodeFs     = require("node:fs");
var nodePath   = require("node:path");
var nodeCrypto = require("node:crypto");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var certs     = require("../helpers/certs");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var PASS_MARK = "  ok    ";
var FAIL_MARK = "  FAIL  ";
var NOTE_MARK = "  note  ";

// The line `doctor` printed for one check, whatever mark it carries.
function rowFor(output, checkName) {
  var lines = String(output).split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var trimmed = lines[i];
    if (trimmed.indexOf(checkName + ":") !== -1 &&
        (trimmed.indexOf(PASS_MARK) === 0 || trimmed.indexOf(FAIL_MARK) === 0 ||
         trimmed.indexOf(NOTE_MARK) === 0)) {
      return trimmed;
    }
  }
  return null;
}

function markOf(row) {
  if (row === null) return null;
  if (row.indexOf(PASS_MARK) === 0) return "ok";
  if (row.indexOf(FAIL_MARK) === 0) return "FAIL";
  if (row.indexOf(NOTE_MARK) === 0) return "note";
  return null;
}

// One doctor run against one certificate pair.
function doctorOver(root, name, certBytes, keyBytes) {
  var dataDir = nodePath.join(root, name, "data");
  var workDir = nodePath.join(root, name, "work");
  var tlsDir  = nodePath.join(root, name, "tls");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.mkdirSync(tlsDir,  { recursive: true });
  var certFile = nodePath.join(tlsDir, "chain.pem");
  var keyFile  = nodePath.join(tlsDir, "privkey.pem");
  nodeFs.writeFileSync(certFile, certBytes, "utf8");
  nodeFs.writeFileSync(keyFile, keyBytes, "utf8");

  var run = cliHelper.create({
    dataDir:         dataDir,
    workDir:         workDir,
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
    env: {
      BLAMEPOST_TLS_CERT: certFile,
      BLAMEPOST_TLS_KEY:  keyFile,
    },
  });
  return { output: run(["doctor"]).both, certFile: certFile, keyFile: keyFile };
}

// Every file in the data directory's keys folder. Read off the folder
// rather than off a row, because the whole question these cases ask is
// whether the two agree, and a reading taken from the rows cannot
// answer it.
function sealedKeysIn(dataDir) {
  try { return nodeFs.readdirSync(nodePath.join(dataDir, "keys")).sort(); }
  catch (_e) { return []; }
}

// ---- the cases --------------------------------------------------------------

function aCompletePairPasses(root, material) {
  var report = doctorOver(root, "good", material.chain, material.key);

  count("doctor reports the certificate it read rather than only the path",
    rowFor(report.output, "certificate") !== null, report.output);
  count("a current, complete, matching pair passes the validity check",
    markOf(rowFor(report.output, "certificate validity")) === "ok", report.output);
  count("and the private key check",
    markOf(rowFor(report.output, "private key")) === "ok", report.output);
  count("and the chain check",
    markOf(rowFor(report.output, "certificate chain")) === "ok", report.output);
  count("and the name check",
    markOf(rowFor(report.output, "certificate name")) === "ok", report.output);
  count("the validity row prints the date rather than leaving the operator to look it up",
    /valid until /.test(rowFor(report.output, "certificate validity") || ""), report.output);
}

function aLeafWithNoIssuerFails(root, material) {
  // The mistake: cert.pem instead of fullchain.pem.
  var report = doctorOver(root, "leafonly", material.cert, material.key);
  var row = rowFor(report.output, "certificate chain");

  count("a leaf with no issuer beside it is a FAIL rather than a passing certificate line",
    markOf(row) === "FAIL", report.output);
  count("the row explains why a browser accepts this certificate and a mail server does not",
    /browser fetches that issuer/.test(report.output), report.output);
  count("and names the file an operator should point at instead",
    /fullchain\.pem/.test(report.output), report.output);
  count("the run does not claim everything is in place",
    !/Everything this server expects is in place/.test(report.output), report.output);
}

async function aKeyFromAnotherIssuanceFails(root, material) {
  var other = await certs.pair({ hostname: HOSTNAME, authorityName: "a different authority" });
  var report = doctorOver(root, "mismatch", material.chain, other.key);
  var row = rowFor(report.output, "private key");

  count("a key that does not belong to the certificate is a FAIL",
    markOf(row) === "FAIL", report.output);
  count("the row names both files, so the operator knows which two disagree",
    report.output.indexOf(report.certFile) !== -1 &&
    report.output.indexOf(report.keyFile) !== -1, report.output);
}

async function aCertificateForAnotherNameFails(root) {
  var elsewhere = await certs.pair({ hostname: "mail.example.net" });
  var report = doctorOver(root, "wrongname", elsewhere.chain, elsewhere.key);
  var row = rowFor(report.output, "certificate name");

  count("a certificate issued to a name this server does not answer to is a FAIL",
    markOf(row) === "FAIL", report.output);
  count("the row names the name this server announces",
    (row || "").indexOf(HOSTNAME) !== -1, report.output);
}

function theKeyIsNeverPrinted(root, material) {
  var report = doctorOver(root, "secrecy", material.chain, material.key);

  // The report opens the private key in order to compare it against the
  // certificate. An operator pastes this output into an issue.
  count("no part of the private key reaches the report",
    report.output.indexOf("PRIVATE KEY") === -1, "(output withheld)");
  var body = material.key.split(/\r?\n/).filter(function (l) {
    return l.length > 40 && l.indexOf("-----") === -1;
  });
  var leaked = body.some(function (line) { return report.output.indexOf(line) !== -1; });
  count("and no line of the key material appears in it either", leaked === false,
    "(output withheld)");
}

function anAbsentCertificateStillReportsTheOriginalRefusal(root) {
  var dataDir = nodePath.join(root, "absent", "data");
  var workDir = nodePath.join(root, "absent", "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  var run = cliHelper.create({
    dataDir: dataDir, workDir: workDir, hostname: HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  });
  var output = run(["doctor"]).both;

  // The reading below is the point of running `doctor` on a host that
  // has no certificate yet, which is exactly when an operator needs it.
  count("a host with no certificate is told so rather than shown a parse failure",
    markOf(rowFor(output, "certificate")) === "FAIL", output);
  count("and told which two variables to set",
    /BLAMEPOST_TLS_CERT and BLAMEPOST_TLS_KEY/.test(output), output);
}

// ---- the sealed private keys, held against the rows that name them ----------

// A selector row's keyRef is the only handle this server has on the file
// it points at. Nothing walks the keys folder during ordinary operation,
// and the code that erases a key finds its subject through a row, so a
// key file that no record claims is signing material for a domain that
// nothing here will ever use or remove, and every backup taken from then
// on carries it. Whoever holds one signs mail as that domain, and that
// stays true after somebody else takes the name on.
//
// The opposite reading is an outage that is already running: an active
// selector whose key is not on the volume cannot sign, so mail from that
// domain leaves unsigned and fails DMARC wherever the domain's policy
// sends failures. A retiring selector with no key is neither of those
// and must not be counted as either, because retirement destroys the
// private half and keeps the record published through the overlap.
//
// Driven through the shipped command rather than the reader underneath
// it, because a reader answering correctly into a report that never
// printed the answer is exactly the failure this covers.
function theSigningKeysAreHeldAgainstTheRowsThatNameThem(root, material) {
  var dataDir = nodePath.join(root, "signingkeys", "data");
  var workDir = nodePath.join(root, "signingkeys", "work");
  var tlsDir  = nodePath.join(root, "signingkeys", "tls");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.mkdirSync(tlsDir,  { recursive: true });
  var certFile = nodePath.join(tlsDir, "chain.pem");
  var keyFile  = nodePath.join(tlsDir, "privkey.pem");
  nodeFs.writeFileSync(certFile, material.chain, "utf8");
  nodeFs.writeFileSync(keyFile, material.key, "utf8");

  var run = cliHelper.create({
    dataDir:         dataDir,
    workDir:         workDir,
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
    env: { BLAMEPOST_TLS_CERT: certFile, BLAMEPOST_TLS_KEY: keyFile },
  });

  var hosted = run(["domain", "add", DOMAIN]);
  count("hosting a domain mints its signing pair, so the volume has keys to hold the rows " +
    "against", hosted.status === 0 && sealedKeysIn(dataDir).length === 2,
    "exit " + hosted.status + " " + sealedKeysIn(dataDir).join(","));

  var clean = run(["doctor"]);
  count("a volume whose every sealed key is named by a selector record passes",
    markOf(rowFor(clean.both, "signing keys")) === "ok",
    rowFor(clean.both, "signing keys") || clean.both.slice(0, 400));
  count("and the passing line says how many it held against the rows, so a run that read " +
    "nothing does not print the same answer as one that read everything",
    /2 sealed private keys on disk/.test(rowFor(clean.both, "signing keys") || ""),
    rowFor(clean.both, "signing keys") || "");

  // A key file left by a removal that took the rows and not the files,
  // which is what earlier versions of this server did. Its bytes are not
  // key material and do not need to be: what is being measured is
  // whether a file in this folder that no record claims is reported.
  var orphan = "withdrawn.example.com.bpgone.ed25519.sealed";
  nodeFs.writeFileSync(nodePath.join(dataDir, "keys", orphan),
    "stands in for a sealed key that no selector record names", "utf8");

  var stranded = run(["doctor"]);
  count("a sealed private key no selector record names fails the check",
    markOf(rowFor(stranded.both, "signing keys")) === "FAIL",
    rowFor(stranded.both, "signing keys") || stranded.both.slice(0, 400));
  count("and it is named, because nothing else on this server can name it",
    (rowFor(stranded.both, "signing keys") || "").indexOf(orphan) !== -1,
    rowFor(stranded.both, "signing keys") || "");
  count("and the operator is told to delete it rather than left with a line that only " +
    "reports",
    /by hand/.test(rowFor(stranded.both, "signing keys") || ""),
    rowFor(stranded.both, "signing keys") || "");

  nodeFs.rmSync(nodePath.join(dataDir, "keys", orphan));

  // The other direction. An active selector whose key is gone is a
  // domain that cannot sign, which no count of files can report on its
  // own: the folder is smaller and everything in it still belongs.
  var live = sealedKeysIn(dataDir).filter(function (name) {
    return name.indexOf(DOMAIN + ".") === 0 && /\.ed25519\.sealed$/.test(name);
  })[0];
  count("the hosted domain has an Ed25519 key on the volume to take away",
    typeof live === "string", sealedKeysIn(dataDir).join(","));
  nodeFs.rmSync(nodePath.join(dataDir, "keys", live));

  var unsigned = run(["doctor"]);
  count("an active selector whose sealed key is not on the volume fails the check",
    markOf(rowFor(unsigned.both, "signing keys")) === "FAIL",
    rowFor(unsigned.both, "signing keys") || unsigned.both.slice(0, 400));
  count("and the line says the domain's mail is leaving unsigned rather than only that a " +
    "file is missing",
    /leaves? unsigned/.test(rowFor(unsigned.both, "signing keys") || ""),
    rowFor(unsigned.both, "signing keys") || "");
}

async function run() {
  var root = helpers.tempDir("doctorcert");
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  try {
    var material = await certs.pair({ hostname: HOSTNAME });
    // Every case below reads a certificate that is current, so a run
    // that started passing because the fixture aged would be reporting
    // something other than what it says. Checked once, here.
    var validTo = Date.parse(new nodeCrypto.X509Certificate(material.cert).validTo);
    count("the fixture certificate is current, so every case below reads what it says",
      validTo > Date.now(), new Date(validTo).toISOString());

    aCompletePairPasses(root, material);
    aLeafWithNoIssuerFails(root, material);
    await aKeyFromAnotherIssuanceFails(root, material);
    await aCertificateForAnotherNameFails(root);
    theKeyIsNeverPrinted(root, material);
    anAbsentCertificateStillReportsTheOriginalRefusal(root);
    theSigningKeysAreHeldAgainstTheRowsThatNameThem(root, material);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-doctor-certificate", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
