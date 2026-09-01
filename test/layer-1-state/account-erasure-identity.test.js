// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The last two writes an account erasure makes, each driven while it is
 * refused.
 *
 * An erasure destroys the mail first and settles the identity last: the
 * account row is erased when nothing still names it, and marked as
 * erasing when something does. Both of those writes can be refused, and
 * both run on the far side of the destruction. That is what makes them
 * different from every other refusal on this path. There is nothing left
 * to undo and nothing to read back, so a refusal allowed to leave hands
 * the caller an exception in place of the report, never reaches the audit
 * row written after it, and leaves nothing anywhere saying the mail was
 * ever on the volume. An operator answering an Article 17 request is told
 * the call failed while the mailbox they were asked to erase is still
 * authenticating and still taking delivery.
 *
 * Both refusals here come from framework gates declared on the account
 * table and recorded in the database, rather than from a stand-in that
 * patches the erase, so the erasure meets exactly what an operator's
 * volume would raise. A dual-control gate refuses the erase the way a
 * second approver does, which is something keeping the row on purpose.
 * Write-once triggers refuse the status write as well, which is a fault
 * and the harshest case: then not even the record that the erasure ran
 * can be put on the row.
 *
 * It is a file of its own rather than another vector beside the erasures
 * next door, for two reasons. A gate declared on a table stands for the
 * life of the database and nothing lifts one, so every account this
 * fixture erases has to be created before the gates and no other vector
 * may share the volume. And the command-line half needs the volume this
 * process opened to be the only one it opened: the per-deployment sealing
 * material is written into the data directory the first time it is
 * needed, so a process that opens two volumes seals the second one's rows
 * with the first one's material and a child process reading it alone
 * cannot open them.
 *
 * Run standalone: node test/layer-1-state/account-erasure-identity.test.js
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

// One account per vector, all created before the gates below, because a
// gate on the account table refuses the erase for every account after it
// and nothing lifts one.
var GATED_ADDRESS   = "approver@" + DOMAIN;
var FROZEN_ADDRESS  = "frozen@" + DOMAIN;
var CLI_ADDRESS     = "unmarked@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The identity table's name, read here rather than imported so a rename
// shows up as a failing vector against the shipped schema instead of
// following the source silently.
var ACCOUNTS = "blamepost_accounts";

function mailFor(address, subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + address + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\nthe body of " + subject + "\r\n", "utf8");
}

function actorFor(row) {
  return { id: row.id, address: row.address, domain: row.domain, roles: ["account"] };
}

function auditRows(action) {
  return b.db.from("audit_log").all().filter(function (row) {
    return row.action === action;
  });
}

// ---- the library path ------------------------------------------------------

async function theIdentityStepReportsWhatItCouldNotWrite(cfg) {
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    // Mail and nothing else on each account. This is about the identity
    // step itself, so nothing else may still name the row and stop the
    // erase being attempted at all.
    var gated  = await handle.accounts.create({
      address: GATED_ADDRESS, password: ACCOUNT_PASSWORD,
    });
    var frozen = await handle.accounts.create({
      address: FROZEN_ADDRESS, password: ACCOUNT_PASSWORD,
    });
    var forCli = await handle.accounts.create({
      address: CLI_ADDRESS, password: ACCOUNT_PASSWORD,
    });
    handle.mailbox.appendMessage("INBOX", mailFor(GATED_ADDRESS, "gated-mail"),
      { actor: actorFor(gated) });
    handle.mailbox.appendMessage("INBOX", mailFor(FROZEN_ADDRESS, "frozen-mail"),
      { actor: actorFor(frozen) });
    handle.mailbox.appendMessage("INBOX", mailFor(CLI_ADDRESS, "cli-mail"),
      { actor: actorFor(forCli) });

    // A second approver wanted for anything erased out of the account
    // table. The erase is refused; the status write is untouched by it.
    b.db.declareRequireDualControl({ tables: [ACCOUNTS], m: 2, n: 2 });

    var thrown = null;
    var removed = null;
    try {
      removed = await handle.accounts["delete"]({
        id: gated.id, reason: "erasure requested by the account holder", destroy: true,
      });
    } catch (e) { thrown = e; }

    count("an erasure whose last step is refused answers with a report rather than " +
      "raising, because the mail it was asked to destroy is already gone",
      thrown === null && removed !== null,
      thrown === null ? "nothing was thrown" : helpers.formatErr(thrown));
    count("and the mail really did go, which is what the report has to be able to say",
      removed !== null && removed.mailErased === 1,
      JSON.stringify(removed === null ? null : { mailErased: removed.mailErased }));

    var refusals = (removed && removed.identityRefused) || [];
    count("the account row that could not be erased is named in the report",
      refusals.length === 1 && /account row/.test(String(refusals[0].record)),
      JSON.stringify(refusals));
    count("and a gate wanting a second approver is reported as something keeping the row " +
      "on purpose rather than as a fault",
      refusals.length === 1 &&
      refusals[0].reason === "db/erase-hard-dual-control-required" &&
      refusals[0].preserved === true, JSON.stringify(refusals));
    count("the outcome says the identity stayed",
      removed !== null && removed.outcome === "partially-erased",
      JSON.stringify(removed === null ? null : removed.outcome));

    var keptGated = handle.accounts.get(gated.id);
    count("the account is still on the table and marked erasing, so the outstanding job " +
      "is visible and the row can be reached to finish it",
      keptGated !== null && keptGated.status === "erasing",
      JSON.stringify(keptGated === null ? null : keptGated.status));

    count("and the trail carries the row saying the mail was destroyed, which is the only " +
      "record left that it was ever here",
      auditRows("blamepost.mail.mailbox.account_mail_erased").length === 1,
      JSON.stringify(auditRows("blamepost.mail.mailbox.account_mail_erased").length));
    count("recorded as an erasure held back rather than as an account destroyed",
      auditRows("account.erasure_held").length === 1 &&
      auditRows("account.destroyed").length === 0,
      JSON.stringify({
        held:      auditRows("account.erasure_held").length,
        destroyed: auditRows("account.destroyed").length,
      }));
    count("and recorded as a success, because a gate wanting a second approver is the " +
      "system working rather than a volume that failed",
      auditRows("account.erasure_held").length === 1 &&
      auditRows("account.erasure_held")[0].outcome === "success",
      JSON.stringify(auditRows("account.erasure_held").map(function (r) {
        return r.outcome;
      })));

    // The harshest case: nothing about the identity can be written at
    // all. The erase is refused by the gate above and the status write by
    // the write-once triggers, so both arms of the step are driven on one
    // account.
    b.db.declareWorm({ tables: [ACCOUNTS] });

    var frozenThrown = null;
    var frozenRemoved = null;
    try {
      frozenRemoved = await handle.accounts["delete"]({
        id: frozen.id, reason: "erasure requested by the account holder", destroy: true,
      });
    } catch (e) { frozenThrown = e; }

    count("an erasure that can neither erase the account row nor mark it still answers " +
      "with a report",
      frozenThrown === null && frozenRemoved !== null,
      frozenThrown === null ? "nothing was thrown" : helpers.formatErr(frozenThrown));

    var frozenRefusals = (frozenRemoved && frozenRemoved.identityRefused) || [];
    count("both refusals are reported, because they are two different things an operator " +
      "has to act on",
      frozenRefusals.length === 2, JSON.stringify(frozenRefusals));
    count("the write the volume refused is a fault rather than something kept on purpose, " +
      "and it names which of the two writes it was",
      frozenRefusals.filter(function (entry) {
        return entry.preserved !== true && /marked as erasing/.test(String(entry.record));
      }).length === 1, JSON.stringify(frozenRefusals));
    count("the outcome still says the identity stayed, rather than claiming a status that " +
      "was never written",
      frozenRemoved !== null && frozenRemoved.outcome === "partially-erased" &&
      handle.accounts.get(frozen.id) !== null,
      JSON.stringify(frozenRemoved === null ? null : frozenRemoved.outcome));
    count("and the row is left in service, which is the state the report has to be " +
      "believed about",
      (handle.accounts.get(frozen.id) || {}).status === "active",
      JSON.stringify((handle.accounts.get(frozen.id) || {}).status));

    count("both erasures filed the row recording the mail they destroyed",
      auditRows("blamepost.mail.mailbox.account_mail_erased").length === 2,
      JSON.stringify(auditRows("blamepost.mail.mailbox.account_mail_erased").length));
    count("and the run where the volume refused a write is recorded as a failure",
      auditRows("account.erasure_held").length === 2 &&
      auditRows("account.erasure_held")[1].outcome === "failure",
      JSON.stringify(auditRows("account.erasure_held").map(function (r) {
        return r.outcome;
      })));
  } finally {
    handle.close();
  }
}

// ---- the command line ------------------------------------------------------

// The same two refusals as an operator meets them. A report the library
// returns and the command line renders as a success is a report nobody
// acts on, and the state it describes is the one that needs a person:
// mail destroyed, and the mailbox still authenticating.
function theCommandLineNamesTheIdentityItCouldNotWrite(run) {
  var erased = run(["account", "remove", CLI_ADDRESS, "--destroy",
    "--reason", "erasure requested by the account holder"]);

  count("the command line does not report an erasure the volume refused as a finished one",
    /^Partly erased /m.test(erased.stdout),
    "exit " + erased.status + " " + erased.both.slice(0, 400));
  count("and it says how much mail actually went",
    /1 message destroyed across \d+ mailboxe?s?/.test(erased.stdout),
    erased.stdout.slice(0, 600));
  count("the account row the volume would not mark is named as a failure rather than as " +
    "something kept on purpose",
    /FAIL {2}the account row for .*could not be marked as erasing/.test(erased.stdout),
    erased.stdout.slice(0, 900));
  count("and the operator is told the mailbox is still in service with its mail gone, " +
    "which is the state that needs a person rather than a rerun",
    /still in service with its mail destroyed/.test(erased.stdout),
    erased.stdout.slice(0, 900));
  count("the exit status is 1, so a script driving a bulk erasure stops here",
    erased.status === 1, "exit " + erased.status + " " + erased.both.slice(0, 300));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("account-erasure-identity");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    // The store refuses to open without this: it decrypts a working copy
    // of the database and will not put one somewhere it was not told to.
    process.env.BLAMEJS_TMPDIR = workDir;

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    await theIdentityStepReportsWhatItCouldNotWrite(cfg);

    // One handle per process at a time: the database is encrypted at rest
    // and each process decrypts its own working copy, so a handle held
    // open while the child writes would flush a stale snapshot back over
    // the child's work.
    theCommandLineNamesTheIdentityItCouldNotWrite(cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    }));

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "account-erasure-identity",
  run:       run,
  getChecks: helpers.getChecks,
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
