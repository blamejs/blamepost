// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The command line, run the way an operator runs it.
 *
 * Nothing in this suite had ever spawned `bin/blamepost.js`, and the
 * command line is the whole of the operator's interface. That gap is
 * where a specific kind of defect lives: five times over, a document
 * described a verb or a flag that was never built, and a sixth was
 * caught only because somebody checked by hand before shipping the
 * sentence. A test that runs the binary cannot be fooled that way.
 *
 * The verb under test is `account sieve`, which exists because the
 * incident-response guidance tells an operator to read a possibly
 * compromised account's filter script, and until now the only way to do
 * that was to authenticate as the account. Resetting somebody's password
 * to read their rules tips off whoever is watching the mailbox.
 *
 * Reading another person's filter rules is administrative access to
 * their private configuration, so it takes a reason and writes an audit
 * row, the same position `account remove` already takes. The refusal
 * without a reason is asserted first, because a gate that can be skipped
 * by omitting an argument is not a gate.
 *
 * Run standalone: node test/layer-1-state/cli-account-sieve.test.js
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// Two scripts, so the listing has something to mark and something to
// leave unmarked. The bodies are distinguishable on sight, because the
// point of reading one is seeing what it does.
var ACTIVE_SCRIPT = "require [\"fileinto\"];\n" +
  "if header :contains \"Subject\" \"invoice\" { fileinto \"Archive\"; }\n";
var IDLE_SCRIPT = "require [\"fileinto\"];\n" +
  "if header :contains \"Subject\" \"newsletter\" { fileinto \"Junk\"; }\n";

async function run() {
  var root    = helpers.tempDir("cli-sieve");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var identity = null;
  try {
    // Set the account up through the library rather than the CLI, so a
    // failure here reads as a broken fixture rather than as a failing
    // assertion about the verb under test.
    process.env.BLAMEJS_TMPDIR = workDir;
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
    var alice = await identity.accounts.create({
      address: ADDRESS, password: ALICE_PASSWORD });

    // The account holder uploading their own filters, in the shape a
    // signed in session carries. The role is what the filter surface
    // checks on a write; the operator read this file is about carries
    // none, which is the point of the next few lines.
    var actor = { id: alice.id, address: alice.address, roles: ["account"] };
    identity.mailbox.sieveScripts.put(actor, "file-invoices", ACTIVE_SCRIPT, { force: true });
    identity.mailbox.sieveScripts.put(actor, "file-newsletters", IDLE_SCRIPT, { force: true });
    identity.mailbox.sieveScripts.setActive(actor, "file-invoices");
    identity.close();
    identity = null;

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    // ---- the gate --------------------------------------------------------

    var noReason = cli(["account", "sieve", ADDRESS]);
    count("reading a filter script without a reason is refused",
      noReason.status !== 0, "exit " + noReason.status);
    count("and the refusal names the argument that is missing",
      /--reason/.test(noReason.both), noReason.both.slice(0, 140));
    count("and it says why, rather than only that the flag is required",
      /audit trail/.test(noReason.both), noReason.both.slice(0, 140));

    // ---- the listing -----------------------------------------------------

    var listed = cli(
      ["account", "sieve", ADDRESS, "--reason", "incident 4471, credential suspected stolen"]);
    count("with a reason, the listing succeeds", listed.status === 0,
      "exit " + listed.status + " " + listed.both.slice(0, 120));
    count("both scripts are listed",
      /file-invoices/.test(listed.stdout) && /file-newsletters/.test(listed.stdout),
      listed.stdout.slice(0, 200));
    count("the active one is marked",
      /^\*\s+file-invoices$/m.test(listed.stdout), listed.stdout.slice(0, 200));
    count("and the idle one is not",
      /^\s+file-newsletters$/m.test(listed.stdout), listed.stdout.slice(0, 200));
    count("the listing says which script actually runs",
      /Only the marked script runs/.test(listed.stdout), listed.stdout.slice(0, 240));

    // ---- reading one -----------------------------------------------------

    var body = cli(["account", "sieve", ADDRESS,
      "--reason", "incident 4471", "--script", "file-invoices"]);
    count("a named script can be read", body.status === 0,
      "exit " + body.status + " " + body.both.slice(0, 120));
    count("and its body is what was stored",
      body.stdout.indexOf("fileinto \"Archive\"") !== -1, body.stdout.slice(0, 200));

    var missing = cli(["account", "sieve", ADDRESS,
      "--reason", "incident 4471", "--script", "no-such-script"]);
    count("a script that does not exist is refused rather than printed empty",
      missing.status !== 0, "exit " + missing.status);
    count("and the refusal names the script that was asked for",
      /no-such-script/.test(missing.both), missing.both.slice(0, 140));

    var absent = cli(
      ["account", "sieve", "nobody@" + DOMAIN, "--reason", "incident 4471"]);
    count("an account that does not exist is refused",
      absent.status !== 0 && /no account/.test(absent.both),
      "exit " + absent.status + " " + absent.both.slice(0, 120));

    // ---- the audit row ---------------------------------------------------

    // The reason exists to be readable later. A verb that demands one and
    // then drops it on the floor is worse than one that never asked,
    // because the operator believes the record was made.
    identity = await store.open(cfg);
    var rows = await b.audit.query({ action: "account.sieve_read", limit: 50 });
    count("every successful read left an audit row",
      Array.isArray(rows) && rows.length >= 3,
      Array.isArray(rows) ? rows.length + " row(s)" : String(rows));

    // The reason belongs in the row's own `reason` column rather than
    // inside the metadata blob, because an auditor filters on a column.
    var withReason = (rows || []).filter(function (r) {
      return String((r && r.reason) || "").indexOf("incident 4471") !== -1;
    });
    count("and the row carries the reason in its own column",
      withReason.length >= 3, withReason.length + " of " + (rows || []).length);

    // Metadata comes back as the JSON text it was stored as.
    var named = withReason.filter(function (r) {
      var meta = r.metadata;
      if (typeof meta === "string") {
        try { meta = JSON.parse(meta); } catch (_e) { return false; }
      }
      return meta && meta.address === ADDRESS;
    });
    count("and names the account whose script was read",
      named.length >= 3, named.length + " of " + withReason.length);

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

module.exports = { name: "cli-account-sieve", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
