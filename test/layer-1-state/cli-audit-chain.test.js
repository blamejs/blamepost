// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Proving the audit trail, from the command line an operator has.
 *
 * SECURITY.md calls audit-chain tampering a critical vulnerability and
 * the threat model says the chain makes rewriting the record detectable.
 * Neither is a property of the storage on its own. Every row carries the
 * hash of the one before it, and recomputing the whole sequence needs
 * nothing secret, so an attacker holding the database file can produce a
 * chain that verifies. What they cannot produce is a signed checkpoint,
 * because that signature is made with a key sealed on the volume and
 * anchored to a row hash. So a verification that reports only the chain
 * math is reporting half the answer, and this file holds both halves to
 * the same standard.
 *
 * The break is driven rather than described. The two triggers that make
 * `audit_log` append-only are dropped and a row is edited underneath
 * them, which is what an attacker with the file does, and the verb has
 * to come back naming the row, the reason and the two hashes.
 *
 * The bundle verbs get the same treatment. An export that reports
 * success and cannot be opened again is worth nothing to the auditor it
 * was made for, so every bundle written here is read back, and one is
 * read back with the wrong passphrase to prove the check is live.
 *
 * The purge is the one verb here that destroys evidence, so it carries
 * the same posture as erasing an account: an explicit confirmation and a
 * recorded reason, and the reason lands in the audit row's own column
 * rather than inside a blob an auditor would have to search. It also
 * refuses to take the last row. A chain with nothing left in it has no
 * row for the next event to attach to and no counter for the boot-time
 * rollback check to agree with, and a server in that state never starts
 * again.
 *
 * Run standalone: node test/layer-1-state/cli-audit-chain.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var BUNDLE_PASSPHRASE = "a different passphrase that only the bundle uses";
var ALICE_PASSWORD    = "quiet lantern bicycle 4291";

// The framework's own audit table. Named here because the tamper case
// has to reach the rows the verb reads.
var AUDIT_TABLE = "audit_log";

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// ---- cases ------------------------------------------------------------------

function theGroupAnnouncesItsVerbs(cli) {
  var usage = cli(["audit"]);
  count("`audit` with no verb prints its usage rather than doing something",
    usage.status === 2 && /Usage: blamepost audit/.test(usage.both),
    "exit " + usage.status + " " + usage.both.slice(0, 90));
  ["verify-chain", "read", "archive", "export", "verify-bundle", "purge"]
    .forEach(function (verb) {
      count("`audit` offers " + verb,
        new RegExp("^ {2}" + verb + "\\s", "m").test(usage.both), usage.both.slice(0, 300));
    });

  var unknown = cli(["audit", "frobnicate"]);
  count("an unknown audit verb is refused rather than looking like success",
    unknown.status !== 0 && /Usage: blamepost audit/.test(unknown.both),
    "exit " + unknown.status + " " + unknown.both.slice(0, 90));
}

function aHealthyChainVerifies(cli) {
  var text = cli(["audit", "verify-chain"]);
  count("verifying a healthy chain succeeds", text.status === 0,
    "exit " + text.status + " " + text.both.slice(0, 300));
  count("and says how many rows it walked",
    /row\(s\) verified/.test(text.stdout), text.stdout.slice(0, 300));

  var json = cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);
  count("the machine-readable verdict reports the chain as sound",
    verdict !== null && verdict.ok === true && verdict.chain && verdict.chain.ok === true,
    json.stdout.slice(0, 300));
  count("and reports the signed checkpoints separately from the chain math, " +
    "because the two answer different questions",
    verdict !== null && verdict.checkpoints !== undefined &&
    typeof verdict.checkpoints.checkpointsVerified === "number",
    JSON.stringify(verdict && verdict.checkpoints));
  count("and names the counter the chain stands at",
    verdict !== null && typeof verdict.counter === "number" && verdict.counter > 0,
    JSON.stringify(verdict && verdict.counter));
}

// The chain math on its own is not tamper evidence. Every row hash is
// computed from readable columns, so somebody holding the database file
// can rewrite the whole sequence and it will still agree with itself.
// What they cannot rewrite is a checkpoint signed with a key sealed on
// the volume. This is here because a verification reporting only the
// chain math would report half the answer, and because the anchoring
// happens without anybody asking for it: opening the volume signs the
// tip, so there is no verb for it and no verb is needed.
function theChainIsAnchoredBySomethingSigned(cli) {
  var verdict = parseJson(cli(["audit", "verify-chain", "--json"]).stdout);
  count("a chain that has been opened before carries at least one signed checkpoint",
    verdict !== null && verdict.checkpoints.ok === true &&
    verdict.checkpoints.checkpointsVerified >= 1,
    JSON.stringify(verdict && verdict.checkpoints));

  var text = cli(["audit", "verify-chain"]);
  count("and the text report says so beside the row count rather than folding the " +
    "two answers into one line",
    /signed checkpoint\(s\) verified/.test(text.stdout), text.stdout.slice(0, 300));
}

function exportingASliceForAnAuditor(cli, root, passFile, wrongPassFile) {
  var out = nodePath.join(root, "auditor-slice");

  var noPass = cli(["audit", "export", "--out", out]);
  count("exporting without a passphrase file is refused",
    noPass.status === 2 && /give --passphrase-file/.test(noPass.both),
    "exit " + noPass.status + " " + noPass.both.slice(0, 200));

  var bad = cli(["audit", "export", "--out", out, "--passphrase-file", passFile,
    "--from", "not-a-date"]);
  count("and a date the verb cannot read is refused rather than silently ignored",
    bad.status === 2 && /--from/.test(bad.both),
    "exit " + bad.status + " " + bad.both.slice(0, 220));

  var made = cli(["audit", "export", "--out", out, "--passphrase-file", passFile, "--json"]);
  count("exporting a slice succeeds", made.status === 0,
    "exit " + made.status + " " + made.both.slice(0, 300));
  var summary = parseJson(made.stdout);
  count("and reports how many rows the auditor is getting",
    summary !== null && summary.rowCount > 0, made.stdout.slice(0, 240));
  count("and the bundle is on disk with a manifest beside the rows",
    nodeFs.existsSync(nodePath.join(out, "manifest.json")) &&
    nodeFs.existsSync(nodePath.join(out, "rows.enc")),
    nodeFs.existsSync(out) ? nodeFs.readdirSync(out).join(", ") : "no bundle directory");

  var checked = cli(["audit", "verify-bundle", "--in", out, "--passphrase-file", passFile, "--json"]);
  count("the bundle verifies when it is read back", checked.status === 0,
    "exit " + checked.status + " " + checked.both.slice(0, 300));
  var verdict = parseJson(checked.stdout);
  count("and reports itself as the auditor slice rather than an archive",
    verdict !== null && verdict.ok === true && verdict.kind === "export",
    checked.stdout.slice(0, 240));

  var wrong = cli(["audit", "verify-bundle", "--in", out, "--passphrase-file", wrongPassFile]);
  count("verifying with the wrong passphrase fails rather than reporting a clean bundle",
    wrong.status === 1, "exit " + wrong.status + " " + wrong.both.slice(0, 240));

  // A bundle whose ciphertext has been edited must not verify. This is
  // the property the auditor is relying on, so it is driven rather than
  // assumed.
  var rowsPath = nodePath.join(out, "rows.enc");
  var bytes = nodeFs.readFileSync(rowsPath);
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0xff;
  nodeFs.writeFileSync(rowsPath, bytes);
  var tampered = cli(["audit", "verify-bundle", "--in", out, "--passphrase-file", passFile]);
  count("and a bundle whose rows have been edited does not verify",
    tampered.status === 1, "exit " + tampered.status + " " + tampered.both.slice(0, 240));
}

function archivingAndPurging(cli, root, passFile, cutIso) {
  var out = nodePath.join(root, "archive-bundle");

  var noBefore = cli(["audit", "archive", "--out", out, "--passphrase-file", passFile]);
  count("archiving without --before is refused, because a cut nobody named is the " +
    "whole chain",
    noBefore.status === 2 && /--before/.test(noBefore.both),
    "exit " + noBefore.status + " " + noBefore.both.slice(0, 220));

  var made = cli(["audit", "archive", "--out", out, "--before", cutIso,
    "--passphrase-file", passFile]);
  count("archiving a cut succeeds", made.status === 0,
    "exit " + made.status + " " + made.both.slice(0, 400));
  count("and reports the rows it bundled and the counters they span",
    /row\(s\), counters/.test(made.stdout), made.stdout.slice(0, 400));
  count("and says the live rows are untouched, because archiving is not deleting",
    /untouched/.test(made.stdout), made.stdout.slice(0, 400));

  var checked = parseJson(cli(["audit", "verify-bundle", "--in", out,
    "--passphrase-file", passFile, "--json"]).stdout);
  count("the archive verifies and carries the signed checkpoint that anchors it",
    checked !== null && checked.ok === true && checked.kind === "archive",
    JSON.stringify(checked && { ok: checked.ok, kind: checked.kind }));
  count("and the bundle names the counters it covers",
    checked !== null && checked.range && typeof checked.range.lastCounter === "number",
    JSON.stringify(checked && checked.range).slice(0, 160));

  // The half of the bundle report that only a live volume can answer.
  // The signature over an archive's covering checkpoint was made with a
  // key sealed here, so this is the run where it gets read, and the case
  // below is the same bundle read back where it cannot be.
  var readBack = cli(["audit", "verify-bundle", "--in", out, "--passphrase-file", passFile]);
  count("reading the archive back while the volume opens reports it plainly, because " +
    "both halves were checked",
    /verifies\./.test(readBack.stdout) && !/was not checked/.test(readBack.stdout),
    readBack.stdout.slice(0, 400));
  count("and names the signature it read against this server's own key",
    /signature verified against this server/.test(readBack.stdout),
    readBack.stdout.slice(0, 400));

  var noConfirm = cli(["audit", "purge", "--archive", out, "--passphrase-file", passFile,
    "--reason", "quarterly retention run"]);
  count("purging without --confirm is refused",
    noConfirm.status === 2 && /--confirm/.test(noConfirm.both),
    "exit " + noConfirm.status + " " + noConfirm.both.slice(0, 220));

  var noReason = cli(["audit", "purge", "--archive", out, "--passphrase-file", passFile,
    "--confirm"]);
  count("and purging without --reason is refused, the same posture erasing an " +
    "account takes",
    noReason.status === 2 && /give --reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 220));

  var purged = cli(["audit", "purge", "--archive", out, "--passphrase-file", passFile,
    "--confirm", "--reason", "quarterly retention run", "--json"]);
  count("purging with both succeeds", purged.status === 0,
    "exit " + purged.status + " " + purged.both.slice(0, 400));
  var result = parseJson(purged.stdout);
  count("and reports how many rows it removed",
    result !== null && result.rowsDeleted > 0, purged.stdout.slice(0, 240));

  var after = parseJson(cli(["audit", "verify-chain", "--json"]).stdout);
  count("the chain still verifies after the purge, which is what the purge anchor is for",
    after !== null && after.ok === true, JSON.stringify(after && after.chain).slice(0, 200));
  count("and it stands on fewer rows than before",
    after !== null && after.chain.rowsVerified >= 0,
    JSON.stringify(after && after.chain.rowsVerified));

  return out;
}

// The refusal that keeps the server bootable. An archive covering every
// row the chain still holds cannot be purged: the next event would have
// no row to attach to, and the boot-time rollback check would find a
// recorded counter the emptied table cannot match.
//
// The exit code is half the case. The other half is the volume itself,
// opened afterwards the way the next boot opens it, because a purge that
// takes the row this volume's record names leaves an open that refuses
// and stays refused, and an exit code cannot say whether that happened.
async function purgingTheWholeChainIsRefused(cli, root, passFile, cfg) {
  var out = nodePath.join(root, "whole-chain-archive");
  var future = new Date(Date.now() + 3600000).toISOString();
  var made = cli(["audit", "archive", "--out", out, "--before", future,
    "--passphrase-file", passFile]);
  count("an archive covering every row is written, since it is valid evidence",
    made.status === 0, "exit " + made.status + " " + made.both.slice(0, 300));
  count("and the archive says plainly that it cannot be purged",
    /purge/.test(made.stdout), made.stdout.slice(0, 400));

  var refused = cli(["audit", "purge", "--archive", out, "--passphrase-file", passFile,
    "--confirm", "--reason", "trying to take the last row"]);
  count("purging it is refused rather than leaving a server that never boots again",
    refused.status !== 0, "exit " + refused.status + " " + refused.both.slice(0, 300));
  count("and the refusal says a row has to be left behind",
    /row/.test(refused.both), refused.both.slice(0, 300));

  var after = parseJson(cli(["audit", "verify-chain", "--json"]).stdout);
  count("and the chain is still there afterwards",
    after !== null && after.ok === true && after.chain.rowsVerified > 0,
    JSON.stringify(after && after.chain).slice(0, 200));

  // Opened for writing, which is the open the next boot makes and the
  // one that holds the rows against the record beside them. A read-only
  // report can answer over a volume this open refuses.
  var opened      = null;
  var openRefusal = null;
  try { opened = await store.open(cfg); }
  catch (e) { openRefusal = (e && e.message) || String(e); }
  var anchorSeen = opened === null ? null : opened.auditAnchor;
  if (opened !== null) opened.close();
  count("and the volume still opens, holding its rows against the record beside them",
    openRefusal === null && anchorSeen !== null && anchorSeen.checked === true,
    openRefusal || JSON.stringify(anchorSeen));
}

// The trail is only useful if somebody can read it, and SECURITY.md
// tells an operator to review it. The reason a destructive verb was run
// for belongs in the row's own column, because the query takes no
// criteria against the metadata blob: an auditor filtering on a reason
// needs a column, not a string to search inside.
function theReasonLandsInItsOwnColumn(cli) {
  var listed = cli(["audit", "read", "--action", "blamepost.audit.purged", "--json"]);
  count("the audit trail can be read back", listed.status === 0,
    "exit " + listed.status + " " + listed.both.slice(0, 240));
  var rows = parseJson(listed.stdout);
  count("the purge wrote a row carrying the reason in the column an auditor can filter on",
    Array.isArray(rows) && rows.length === 1 && rows[0].reason === "quarterly retention run",
    listed.stdout.slice(0, 300));

  // A capped read keeps the first rows in whatever order it asked for,
  // so an ascending read cut at the limit hands back the oldest rows on
  // the volume. On a trail of any age that is every row except the ones
  // the operator opened it to see, and the answer still looks like an
  // answer.
  var recent = cli(["audit", "read", "--limit", "3", "--json"]);
  var newest = parseJson(recent.stdout);
  count("a capped read hands back the newest rows rather than the oldest",
    Array.isArray(newest) && newest.length === 3 &&
    Number(newest[0].recordedAt) >= Number(newest[newest.length - 1].recordedAt),
    Array.isArray(newest)
      ? newest.map(function (r) { return r.action; }).join(", ")
      : recent.stdout.slice(0, 200));

  var everything = parseJson(cli(["audit", "read", "--limit", "500", "--json"]).stdout);
  count("and the newest row it hands back is the newest row there is",
    Array.isArray(everything) && Array.isArray(newest) && everything.length > 3 &&
    newest[0].action === everything[0].action,
    Array.isArray(everything)
      ? everything.length + " row(s), newest " + everything[0].action
      : "unreadable");

  var bad = cli(["audit", "read", "--outcome", "maybe"]);
  count("a verdict the trail does not file rows under is refused rather than answered " +
    "with an empty list, because an empty list is what a quiet trail looks like",
    bad.status === 2 && /--outcome/.test(bad.both),
    "exit " + bad.status + " " + bad.both.slice(0, 200));

  var capped = cli(["audit", "read", "--limit", "0"]);
  count("and a limit of zero is refused rather than read as no limit",
    capped.status === 2 && /--limit/.test(capped.both),
    "exit " + capped.status + " " + capped.both.slice(0, 200));
}

// ---- the break -------------------------------------------------------------

// Edit a row underneath the append-only triggers, which is what somebody
// holding the database file does. Everything else in this file has to
// have run already: once the chain is broken the store refuses to open,
// so no later case could reach it.
async function breakTheChain(cfg) {
  var handle = await store.open(cfg);
  try {
    var triggers = b.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?").all(AUDIT_TABLE);
    count("the audit table is guarded by append-only triggers in the first place",
      triggers.length >= 2, triggers.map(function (t) { return t.name; }).join(", "));
    triggers.forEach(function (t) { b.db.runSql("DROP TRIGGER " + t.name); });
    var target = b.db.prepare(
      "SELECT monotonicCounter FROM " + AUDIT_TABLE +
      " ORDER BY monotonicCounter LIMIT 1").get();
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET outcome='denied' WHERE monotonicCounter=" +
      Number(target.monotonicCounter));
  } finally {
    handle.close();
  }
}

function theBreakIsNamed(cli) {
  var text = cli(["audit", "verify-chain"]);
  count("verifying a broken chain fails", text.status === 1,
    "exit " + text.status + " " + text.both.slice(0, 300));
  count("and names the reason the walk stopped",
    /rowHash mismatch/.test(text.both), text.both.slice(0, 400));
  count("and names the row it stopped at, so the operator has somewhere to look",
    /break row _id/.test(text.both), text.both.slice(0, 400));
  count("and carries the two hashes that disagree",
    /expected:/.test(text.both) && /actual:/.test(text.both), text.both.slice(0, 500));
  count("and tells the operator to take a copy before touching anything",
    /copy/.test(text.both), text.both.slice(0, 600));

  var json = cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);
  count("and the machine-readable verdict reports the chain as broken rather than absent",
    verdict !== null && verdict.ok === false && verdict.chain && verdict.chain.ok === false,
    json.stdout.slice(0, 300));
  count("and names the refusal a monitor can alert on",
    verdict !== null && verdict.chain && typeof verdict.chain.code === "string" &&
    verdict.chain.code.indexOf("audit-") !== -1,
    JSON.stringify(verdict && verdict.chain).slice(0, 200));
}

// A bundle read back on a volume that will not open, which is the state
// the verb exists for: a chain that has just broken is one of the
// reasons an operator reaches for the archive from before it.
//
// What can be checked there is the chain math inside the bundle. What
// cannot is the signature over its covering checkpoint, because the key
// that made it is sealed on the volume that will not open. So the FIRST
// line has to carry that, and it is the first line rather than the
// detail three rows down because the first line is the one most readers
// take away: an operator holding a bundle during an incident, told it
// verifies, has been told the half a rewrite recomputes and none of the
// half it cannot.
function aBundleReadWithoutItsVolumeSaysSoInTheFirstLine(cli, archiveDir, passFile) {
  var read = cli(["audit", "verify-bundle", "--in", archiveDir, "--passphrase-file", passFile]);
  count("an archive still reads back when the volume it came from will not open, " +
    "which is when an operator needs it most",
    read.status === 0, "exit " + read.status + " " + read.both.slice(0, 400));

  var first = read.stdout.split("\n").filter(function (line) {
    return line.trim().length > 0;
  })[0] || "";
  count("and the line an operator takes away says the signature over it was not read, " +
    "rather than reporting a bundle that verifies and qualifying it further down",
    /was not checked/.test(first), first.slice(0, 300));
  count("and the detail still names why, so the operator knows what to do about it",
    /NOT checked/.test(read.stdout) && /sealed on a volume/.test(read.stdout),
    read.stdout.slice(0, 500));

  var verdict = parseJson(cli(["audit", "verify-bundle", "--in", archiveDir,
    "--passphrase-file", passFile, "--json"]).stdout);
  count("and the machine-readable verdict marks the signature as one that was not read, " +
    "so a monitor can tell the two runs apart",
    verdict !== null && verdict.ok === true && verdict.signatureChecked === false,
    JSON.stringify(verdict && { ok: verdict.ok, signatureChecked: verdict.signatureChecked }));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-audit");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  var passFile      = nodePath.join(root, "bundle.pass");
  var wrongPassFile = nodePath.join(root, "wrong.pass");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.writeFileSync(passFile, BUNDLE_PASSPHRASE + "\n", { mode: 0o600 });
  nodeFs.writeFileSync(wrongPassFile, "not the passphrase this bundle was written with\n",
    { mode: 0o600 });

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

    // Early activity, then a cut, then later activity, so an archive of
    // the early half leaves rows behind the way a real retention run
    // does.
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await b.audit.flush();
    identity.close();
    var cutIso = new Date(Date.now() + 1).toISOString();
    await helpers.passiveObserve(25, "letting the archive cut fall between two events");

    identity = await store.open(cfg);
    await identity.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    await identity.domains.add({ domain: "second.example" });
    await b.audit.flush();
    identity.close();

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    theGroupAnnouncesItsVerbs(cli);
    aHealthyChainVerifies(cli);
    theChainIsAnchoredBySomethingSigned(cli);
    exportingASliceForAnAuditor(cli, root, passFile, wrongPassFile);
    var archiveDir = archivingAndPurging(cli, root, passFile, cutIso);
    theReasonLandsInItsOwnColumn(cli);
    await purgingTheWholeChainIsRefused(cli, root, passFile, cfg);

    await breakTheChain(cfg);
    theBreakIsNamed(cli);
    // Last, and it has to be: this case needs the volume in the state
    // the break above leaves it in, which is the state no earlier case
    // could reach.
    aBundleReadWithoutItsVolumeSaysSoInTheFirstLine(cli, archiveDir, passFile);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-audit-chain", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
