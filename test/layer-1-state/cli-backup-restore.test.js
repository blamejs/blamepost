// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Taking a backup, and then restoring it.
 *
 * A backup nobody has restored is a hypothesis, so nothing here asserts
 * that a bundle was written and stops. The run populates a data volume
 * with a hosted domain, an account, a message in that account's inbox
 * and a pair of DKIM keys, takes a bundle, restores it, and then asks
 * the restored deployment four questions: does the account still
 * resolve, is the message still readable, do the sealed DKIM keys still
 * produce a signature that verifies against the records this server
 * publishes, and does the audit chain still verify.
 *
 * Three of those are there because a bundle can come back looking
 * perfect and still be useless.
 *
 * The account lookup is the sharpest of the four. An address column is
 * sealed and the equality match runs against a derived hash keyed by a
 * per-deployment secret that lives in its own sealed file. A bundle
 * carrying the database and not that file restores a database that
 * opens, an audit chain that verifies, an account listing that shows
 * every account, and an address lookup that answers "no such mailbox"
 * for every one of them. The server would accept no mail for anybody
 * and every green light would stay green. So the include list is the
 * whole volume rather than a list of files somebody remembered.
 *
 * The message body is the second. The parsed message lives in the
 * database and the octets a client actually receives live sealed under
 * `blobs/`, which is a directory rather than a file, so a bundler that
 * takes a flat list of files silently leaves every message body behind.
 *
 * And the restore target is the third. The database encryption key is
 * sealed to the absolute path of the data directory it belongs to, so a
 * restore into a different directory produces a volume that will not
 * open. That is checked before anything is swapped, because finding out
 * afterwards means the live directory has already been moved aside.
 *
 * Run standalone: node test/layer-1-state/cli-backup-restore.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var blamepost = require("../../lib");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;
var SUBJECT  = "the message that has to survive a restore";

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var BUNDLE_PASSPHRASE = "a different passphrase that only the bundle uses";
var ALICE_PASSWORD    = "quiet lantern bicycle 4291";

// A fingerprint no key on this run produces. Pinning is what turns a
// signature into provenance, so a pin that let this through would be
// worse than no pin at all.
var OTHER_FINGERPRINT =
  "1111111111111111111111111111111111111111111111111111111111111111";

// ---- fixtures ---------------------------------------------------------------

function message(subject, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + ADDRESS + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <restore-drill@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// The zone this server asks for, answered from the records it publishes,
// so a signature is checked against the key the operator was told to
// publish rather than against the one that made it.
function zoneFrom(records) {
  var byName = {};
  records.forEach(function (r) {
    byName[String(r.dnsName).toLowerCase().replace(/\.$/, "")] = r.dnsTxtValue;
  });
  return async function dnsLookup(qname) {
    var value = byName[String(qname).toLowerCase().replace(/\.$/, "")];
    if (!value) return [];
    return [[value]];
  };
}

// ---- what the volume held before the backup ---------------------------------

async function populate(cfg) {
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var account = await handle.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    handle.mailbox.appendMessage("INBOX", message(SUBJECT, "keep me across the restore"),
      { actor: actorFor(account) });
    var dkim = blamepost.mail.dkim.create({ dataDir: cfg.paths.dataDir, store: handle });
    if (dkim.list(DOMAIN).length === 0) await dkim.generate({ domain: DOMAIN });
    return { selectors: dkim.list(DOMAIN).length };
  } finally {
    handle.close();
  }
}

// ---- the four questions asked of a restored volume --------------------------

async function everythingCameBack(cfg, label) {
  var handle = await store.open(cfg);
  try {
    var verdict = await handle.resolve(ADDRESS);
    count(label + ": the account resolves as a deliverable target, which is the " +
      "sealed-column lookup rather than a row listing",
      verdict.deliverable === true, JSON.stringify(verdict.reason || verdict));

    var accounts = handle.accounts.list();
    count(label + ": the account row is there too",
      accounts.length === 1 && accounts[0].address === ADDRESS,
      accounts.map(function (a) { return a.address; }).join(", "));

    var domains = handle.domains.list();
    count(label + ": the hosted domain is there",
      domains.length === 1 && domains[0].domain === DOMAIN,
      domains.map(function (d) { return d.domain; }).join(", "));

    var actor = actorFor(accounts[0]);
    var fetched = handle.mailbox.fetchRange(actor, "INBOX", "1:*", "BODY[]", {});
    var octets = fetched.length === 1 ? String(fetched[0].payload || "") : "";
    count(label + ": the message is still in the inbox and its sealed octets still open",
      octets.indexOf(SUBJECT) !== -1,
      fetched.length + " message(s), " + octets.slice(0, 80));

    var dkim = blamepost.mail.dkim.create({ dataDir: cfg.paths.dataDir, store: handle });
    var records = dkim.dnsRecords(DOMAIN);
    count(label + ": the domain still publishes its selectors",
      records.length === 2, records.map(function (r) { return r.selector; }).join(", "));
    var signed = await dkim.sign(DOMAIN,
      message("a message signed after the restore", "x").toString("utf8"));
    var checked = await b.mail.dkim.verify(signed, { dnsLookup: zoneFrom(records) });
    count(label + ": a message signed with the restored keys verifies against the " +
      "records this server publishes",
      checked.length === 2 && checked.every(function (r) { return r.result === "pass"; }),
      checked.map(function (r) { return r.s + "=" + r.result; }).join(", "));

    var chain = await b.audit.verify();
    count(label + ": the audit chain verifies",
      chain.ok === true, JSON.stringify(chain).slice(0, 160));
  } finally {
    handle.close();
  }
}

// ---- cases ------------------------------------------------------------------

function theGroupsAnnounceTheirVerbs(cli) {
  var backup = cli(["backup"]);
  count("`backup` with no verb prints its usage rather than doing something",
    backup.status === 2 && /Usage: blamepost backup/.test(backup.both),
    "exit " + backup.status + " " + backup.both.slice(0, 90));
  ["run", "list", "inspect", "verify", "purge"].forEach(function (verb) {
    count("`backup` offers " + verb, new RegExp("^ {2}" + verb + "\\s", "m").test(backup.both),
      backup.both.slice(0, 200));
  });

  var restore = cli(["restore"]);
  count("`restore` with no verb prints its usage",
    restore.status === 2 && /Usage: blamepost restore/.test(restore.both),
    "exit " + restore.status + " " + restore.both.slice(0, 90));
  ["apply", "rollback", "list-rollbacks"].forEach(function (verb) {
    count("`restore` offers " + verb, new RegExp("^ {2}" + verb + "\\s", "m").test(restore.both),
      restore.both.slice(0, 200));
  });
}

function aBundleNeedsItsOwnPassphrase(cli, storageDir, vaultPassFile) {
  var none = cli(["backup", "run", "--storage", storageDir]);
  count("taking a backup without a passphrase file is refused",
    none.status === 2 && /give --passphrase-file/.test(none.both),
    "exit " + none.status + " " + none.both.slice(0, 160));

  var missing = cli(["backup", "run", "--storage", storageDir,
    "--passphrase-file", nodePath.join(storageDir, "no-such-file")]);
  count("and a passphrase file that is not there is refused rather than read as empty",
    missing.status === 2 && /passphrase file/.test(missing.both),
    "exit " + missing.status + " " + missing.both.slice(0, 160));

  // One secret opening both the volume and the bundle means a bundle
  // that leaks takes the live volume with it. The bundle travels and
  // the volume does not, so they cannot be the same secret.
  var reused = cli(["backup", "run", "--storage", storageDir, "--passphrase-file", vaultPassFile]);
  count("and a passphrase file holding the vault passphrase is refused",
    reused.status === 2 && /vault passphrase/.test(reused.both),
    "exit " + reused.status + " " + reused.both.slice(0, 200));
}

function takingABundle(cli, storageDir, passFile) {
  var run = cli(["backup", "run", "--storage", storageDir, "--passphrase-file", passFile, "--json"]);
  count("taking a backup succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 300));
  var summary = parseJson(run.stdout);
  count("and reports the bundle it wrote",
    summary !== null && typeof summary.bundleId === "string" && summary.bundleId.length > 0,
    run.stdout.slice(0, 200));
  count("and how many files went into it",
    summary !== null && summary.fileCount >= 7, JSON.stringify(summary && summary.fileCount));
  count("and that the manifest it wrote is signed",
    summary !== null && summary.signature && summary.signature.ok === true,
    JSON.stringify(summary && summary.signature));

  var listed = cli(["backup", "list", "--storage", storageDir]);
  count("the bundle is listed afterwards",
    listed.status === 0 && listed.stdout.indexOf(summary.bundleId) !== -1,
    "exit " + listed.status + " " + listed.stdout.slice(0, 200));

  // Inspect answers without the passphrase, because an operator picking
  // a bundle to restore should not have to unlock every candidate.
  var inspected = cli(["backup", "inspect", "--storage", storageDir, "--bundle", summary.bundleId]);
  count("a bundle can be inspected without the passphrase",
    inspected.status === 0 && inspected.stdout.indexOf(summary.bundleId) !== -1,
    "exit " + inspected.status + " " + inspected.stdout.slice(0, 200));
  count("and the inspection names the data directory the bundle came from",
    /data directory/.test(inspected.stdout), inspected.stdout.slice(0, 300));
  count("and the key that signed it, which is the value --fingerprint pins",
    inspected.stdout.indexOf(summary.signature.fingerprint) !== -1,
    inspected.stdout.slice(0, 400));

  // A signature travels with the key that made it, so on its own it says
  // the bundle is unmodified and nothing about who made it. Pinning is
  // what turns it into provenance, and a pin that accepted any key would
  // be worse than none.
  var pinned = cli(["backup", "inspect", "--storage", storageDir, "--bundle", summary.bundleId,
    "--fingerprint", OTHER_FINGERPRINT]);
  count("inspecting with a fingerprint from another key is refused",
    pinned.status === 1, "exit " + pinned.status + " " + pinned.both.slice(0, 300));
  count("and the refusal shows both fingerprints so the operator can see which is which",
    pinned.stdout.indexOf(OTHER_FINGERPRINT) !== -1 &&
    pinned.stdout.indexOf(summary.signature.fingerprint) !== -1,
    pinned.stdout.slice(0, 400));

  return summary.bundleId;
}

function verifyingWithoutRestoring(cli, storageDir, passFile, bundleId, dataDir, wrongPassFile) {
  var before = nodeFs.readdirSync(dataDir).sort().join(",");

  var ok = cli(["backup", "verify", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile]);
  count("verifying a bundle succeeds", ok.status === 0,
    "exit " + ok.status + " " + ok.both.slice(0, 300));
  count("and says how many files it decrypted and checked",
    /file\(s\)/.test(ok.stdout), ok.stdout.slice(0, 240));

  count("and nothing on the data volume changed",
    nodeFs.readdirSync(dataDir).sort().join(",") === before,
    nodeFs.readdirSync(dataDir).sort().join(","));

  var wrong = cli(["backup", "verify", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", wrongPassFile]);
  count("verifying with the wrong passphrase fails rather than reporting a clean bundle",
    wrong.status === 1, "exit " + wrong.status + " " + wrong.both.slice(0, 240));
  count("and the refusal is not the word that reads as success",
    !/verifies\./.test(wrong.stdout), wrong.stdout.slice(0, 200));

  var otherKey = cli(["backup", "verify", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile, "--fingerprint", OTHER_FINGERPRINT]);
  count("and a bundle signed by another key is refused when a fingerprint is pinned",
    otherKey.status === 1, "exit " + otherKey.status + " " + otherKey.both.slice(0, 300));
}

function restoringIntoADifferentDirectoryIsRefused(cli, storageDir, passFile, bundleId, elsewhere) {
  var refused = cli(["--data-dir", elsewhere, "restore", "apply",
    "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile, "--confirm",
    "--reason", "checking the restore target guard"]);
  count("restoring into a different data directory is refused before anything moves",
    refused.status === 2, "exit " + refused.status + " " + refused.both.slice(0, 300));
  count("and the refusal names both directories so the operator can see the mismatch",
    refused.both.indexOf(elsewhere) !== -1, refused.both.slice(0, 400));
  count("and nothing was written where the restore was aimed",
    !nodeFs.existsSync(elsewhere) || nodeFs.readdirSync(elsewhere).length === 0,
    nodeFs.existsSync(elsewhere) ? nodeFs.readdirSync(elsewhere).join(",") : "absent");
}

function applyingWithoutConfirmationIsRefused(cli, storageDir, passFile, bundleId, dataDir) {
  var before = nodeFs.readdirSync(dataDir).sort().join(",");

  var noConfirm = cli(["restore", "apply", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile, "--reason", "no confirmation given"]);
  count("a restore without --confirm is refused",
    noConfirm.status === 2 && /--confirm/.test(noConfirm.both),
    "exit " + noConfirm.status + " " + noConfirm.both.slice(0, 200));

  var noReason = cli(["restore", "apply", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile, "--confirm"]);
  count("and a restore without --reason is refused",
    noReason.status === 2 && /give --reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 200));

  count("and the data volume is untouched by either refusal",
    nodeFs.readdirSync(dataDir).sort().join(",") === before,
    nodeFs.readdirSync(dataDir).sort().join(","));
}

function theRestoreDrill(cli, storageDir, passFile, bundleId) {
  var applied = cli(["restore", "apply", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile, "--confirm",
    "--reason", "the restore drill this suite exists to run", "--json"]);
  count("the restore succeeds", applied.status === 0,
    "exit " + applied.status + " " + applied.both.slice(0, 400));

  var report = parseJson(applied.stdout);
  count("and reports what it put back",
    report !== null && report.bundleId === bundleId && report.fileCount >= 7,
    applied.stdout.slice(0, 300));
  count("and keeps the directory it replaced as a rollback point",
    report !== null && typeof report.rollbackPath === "string" && report.rollbackPath.length > 0,
    JSON.stringify(report && report.rollbackPath));
  count("and reports that the restored volume opened and its chain verified",
    report !== null && report.verified === true && report.chain && report.chain.ok === true,
    JSON.stringify(report && { verified: report.verified, chain: report.chain }));

  // The vault keypair comes back out of the manifest during a restore.
  // It is the key to every sealed column on the volume and it must never
  // reach a terminal, a log or a pipeline that captures one.
  count("and the vault keypair the restore recovered is never printed",
    applied.both.indexOf("privateKey") === -1 && applied.both.indexOf("ecPrivateKey") === -1,
    applied.both.slice(0, 200));

  return report;
}

function theRollbackPointIsUsable(cli, report) {
  var listed = cli(["restore", "list-rollbacks"]);
  count("the rollback point is listed", listed.status === 0 &&
    listed.stdout.indexOf(nodePath.basename(report.rollbackPath)) !== -1,
    "exit " + listed.status + " " + listed.stdout.slice(0, 260));
  count("and the listing carries the reason the restore was run for",
    /restore drill/.test(listed.stdout), listed.stdout.slice(0, 300));

  var noConfirm = cli(["restore", "rollback", "--reason", "no confirmation given"]);
  count("rolling back without --confirm is refused",
    noConfirm.status === 2 && /--confirm/.test(noConfirm.both),
    "exit " + noConfirm.status + " " + noConfirm.both.slice(0, 200));

  var rolled = cli(["restore", "rollback", "--confirm",
    "--reason", "putting the pre-restore volume back"]);
  count("rolling back succeeds", rolled.status === 0,
    "exit " + rolled.status + " " + rolled.both, { limit: 1200 });
  count("and names the directory it put back",
    rolled.stdout.indexOf(nodePath.basename(report.rollbackPath)) !== -1,
    rolled.stdout.slice(0, 260));
}

// ---- the day the verbs matter ----------------------------------------------

// Break the chain the way somebody holding the database file does: drop
// the two triggers that make `audit_log` append-only and edit a row
// underneath them. The framework then refuses to open the volume at all,
// which is exactly the state an operator is in when they reach for a
// backup. Everything else in this file has to have run already.
async function breakTheVolume(cfg) {
  var handle = await store.open(cfg);
  try {
    var triggers = b.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'").all();
    triggers.forEach(function (t) { b.db.runSql("DROP TRIGGER " + t.name); });
    var target = b.db.prepare(
      "SELECT monotonicCounter FROM audit_log ORDER BY monotonicCounter LIMIT 1").get();
    b.db.runSql("UPDATE audit_log SET outcome='denied' WHERE monotonicCounter=" +
      Number(target.monotonicCounter));
  } finally {
    handle.close();
  }
}

// The claim these verbs make is that they never open the database, so a
// volume that will not open does not take them with it. A claim like
// that is worth nothing unless somebody has been in that state and run
// them.
function theReadVerbsStillAnswerOnABrokenVolume(cli, storageDir, passFile, bundleId) {
  var chain = cli(["audit", "verify-chain"]);
  count("the volume is genuinely broken, so this is testing what it claims to",
    chain.status === 1, "exit " + chain.status + " " + chain.both.slice(0, 200));

  var listed = cli(["backup", "list", "--storage", storageDir]);
  count("listing bundles still answers on a volume that will not open",
    listed.status === 0 && listed.stdout.indexOf(bundleId) !== -1,
    "exit " + listed.status + " " + listed.both.slice(0, 200));

  var inspected = cli(["backup", "inspect", "--storage", storageDir, "--bundle", bundleId]);
  count("and so does inspecting one",
    inspected.status === 0 && inspected.stdout.indexOf(bundleId) !== -1,
    "exit " + inspected.status + " " + inspected.both.slice(0, 200));

  var verified = cli(["backup", "verify", "--storage", storageDir, "--bundle", bundleId,
    "--passphrase-file", passFile]);
  count("and so does verifying one, which is the verb this state exists to need",
    verified.status === 0, "exit " + verified.status + " " + verified.both.slice(0, 300));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root       = helpers.tempDir("cli-backup");
  var dataDir    = nodePath.join(root, "data");
  var workDir    = nodePath.join(root, "work");
  var storageDir = nodePath.join(root, "backups");
  var elsewhere  = nodePath.join(root, "elsewhere");
  var passFile      = nodePath.join(root, "bundle.pass");
  var wrongPassFile = nodePath.join(root, "wrong.pass");
  var vaultPassFile = nodePath.join(root, "vault.pass");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.writeFileSync(passFile, BUNDLE_PASSPHRASE + "\n", { mode: 0o600 });
  nodeFs.writeFileSync(wrongPassFile, "not the passphrase this bundle was written with\n",
    { mode: 0o600 });
  nodeFs.writeFileSync(vaultPassFile, VAULT_PASSPHRASE + "\n", { mode: 0o600 });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    await populate(cfg);
    await everythingCameBack(cfg, "before the backup");

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    theGroupsAnnounceTheirVerbs(cli);
    aBundleNeedsItsOwnPassphrase(cli, storageDir, vaultPassFile);
    var bundleId = takingABundle(cli, storageDir, passFile);
    verifyingWithoutRestoring(cli, storageDir, passFile, bundleId, dataDir, wrongPassFile);
    restoringIntoADifferentDirectoryIsRefused(cli, storageDir, passFile, bundleId, elsewhere);
    applyingWithoutConfirmationIsRefused(cli, storageDir, passFile, bundleId, dataDir);

    var report = theRestoreDrill(cli, storageDir, passFile, bundleId);
    await everythingCameBack(cfg, "after the restore");

    theRollbackPointIsUsable(cli, report);
    await everythingCameBack(cfg, "after the rollback");

    await breakTheVolume(cfg);
    theReadVerbsStillAnswerOnABrokenVolume(cli, storageDir, passFile, bundleId);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-backup-restore", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
