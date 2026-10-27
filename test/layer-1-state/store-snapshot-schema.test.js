// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A reporting verb against a volume whose schema does not match this
 * build.
 *
 * Tokens exercised here:
 *
 *   blamepost.store.openSnapshot
 *   blamepost.store.open
 *
 * The reporting verbs fall back to a read-only open while the server
 * holds the volume. That open skips the schema reconcile and runs no
 * migrations, so a volume last opened for writing by an older build keeps
 * the older schema, and a statement this build prepares can name a column
 * or table the volume does not have. An operator who upgrades the binary
 * and runs `blamepost reports list` before the server has been restarted
 * is the ordinary way to get there.
 *
 * The rules below are written as the failures they stop:
 *
 *   - every verb that may answer from a read-only open refuses a volume
 *     whose schema is behind this build, under
 *     `store/snapshot-schema-behind`, rather than printing a SQLite error
 *     or answering from rows this build does not read correctly;
 *   - the refusal names what is missing: a column of a table this build
 *     declares, a table it declares, a column of the framework's mail
 *     store or its own tables, and a migration the volume has not
 *     recorded, whether the record table is absent or only the row is;
 *   - the refusal says nothing on the volume changed, and nothing on the
 *     volume did change, and no decrypted copy is left behind, including
 *     when the open fails after every check while its handle is built;
 *   - opening the volume for writing with this build, which is the remedy
 *     the refusal names, brings the schema up to date, after which the
 *     same verbs answer from a read-only open again;
 *   - a volume that records a migration this build does not ship was
 *     written by a newer build, and the verbs refuse it under
 *     `store/snapshot-schema-ahead`, naming the migration when its name
 *     has the shape of one and never echoing a name that does not.
 *
 * The server is this process, holding the volume through
 * `blamepost.store.open`, and every verb is the real binary in a child
 * process, so each one meets the lock and takes the read-only path an
 * operator's command takes.
 *
 * Run standalone: node test/layer-1-state/store-snapshot-schema.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers       = require("../helpers");
var cliHelper     = require("../helpers/cli");
var snapshotVerbs = require("../helpers/snapshot-verbs");
var b             = require("../../lib/vendor/blamejs");
var config        = require("../../lib/config");
var store         = require("../../lib/store");
var tables        = require("../../lib/store/tables");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The two refusals, pinned as codes. A reworded refusal is a documentation
// change; a recoded one breaks every script branching on it.
var BEHIND = "store/snapshot-schema-behind";
var AHEAD  = "store/snapshot-schema-ahead";

// What SQLite says when a statement names something the schema lacks. Any
// of these reaching the operator is the failure under test.
var RAW_SCHEMA_ERROR = /no such column|has no column named|no such table|SQLITE_ERROR/i;

// The one migration this build ships, and the uniqueness rule it removes.
var MIGRATION_DIR     = nodePath.join(helpers.REPO_ROOT, "lib", "store", "migrations");
var SHIPPED_MIGRATION = "0001-dmarc-reports-unique-by-organization.js";
var OLD_UNIQUE_INDEX  = "idx_blamepost_dmarc_reports_id";
var MIGRATIONS_TABLE  = b.migrations.MIGRATIONS_TABLE;

// The column and table the earlier build did not have.
var MISSING_COLUMN = tables.DMARC_REPORTS + ".verifiedOrgDomain";
var MISSING_TABLE  = tables.DMARC_FORENSIC;

// A column of the framework's mail store, and a column of one of the
// framework's own tables, both dropped by the last case.
var MAIL_STORE_TABLE  = "blamejs_mail_messages";
var MAIL_STORE_COLUMN = "body_html";
var FRAMEWORK_TABLE   = "_blamejs_api_keys";
var FRAMEWORK_COLUMN  = "lastUsedAt";

// A migration a newer build shipped, and a recorded name that is not
// shaped like a migration at all, which the refusal must not print.
var NEWER_MIGRATION = "0999-written-by-a-newer-build.js";
var FORGED_NAME     = "0998-\r\nforged line on the operator's terminal.js";
var FORGED_TEXT     = "forged line";

// The four verbs driven against a volume ahead of this build. The open
// they share is what refuses, and the full table is driven for the volume
// behind it.
var AHEAD_VERBS = [
  ["reports", "list"],
  ["account", "list"],
  ["doctor", "--domain", DOMAIN],
  ["audit", "verify-chain"],
];

// ---- fixtures --------------------------------------------------------------

function volumeAt(root, name) {
  var dataDir = helpers.dataDir(root, name);
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });
  var runner = {
    dataDir: dataDir, workDir: workDir, hostname: HOSTNAME, vaultPassphrase: VAULT_PASSPHRASE,
  };
  return {
    dataDir: dataDir,
    workDir: workDir,
    cli:     cliHelper.create(runner),
    zoneCli: cliHelper.create(Object.assign({}, runner, {
      env: { BLAMEPOST_ZONE_PROVIDER: snapshotVerbs.ZONE_PROVIDER },
    })),
    cfg: config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    }),
  };
}

async function seed(vol) {
  var seeded = await store.open(vol.cfg);
  try {
    await seeded.domains.add({ domain: DOMAIN });
    await seeded.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
  } finally {
    seeded.close();
  }
}

function digestOf(filePath) {
  return nodeCrypto.createHash("sha512").update(nodeFs.readFileSync(filePath)).digest("hex");
}

function columnsOf(table) {
  return b.db.prepare("PRAGMA table_info(\"" + table + "\")").all()
    .map(function (row) { return row.name; });
}

function tableExists(table) {
  return b.db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").all(table).length > 0;
}

function recordedMigrations() {
  if (!tableExists(MIGRATIONS_TABLE)) return [];
  return b.db.prepare("SELECT name FROM \"" + MIGRATIONS_TABLE + "\"").all()
    .map(function (row) { return row.name; });
}

// The decrypted working copies under the shared directory. The holder
// owns one; any other is a copy a refused command left behind.
function plaintextCopies(workDir) {
  var found = [];
  (function walk(dir, prefix) {
    var entries;
    try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
    catch (_e) { return; }
    entries.forEach(function (entry) {
      var name = prefix ? prefix + "/" + entry.name : entry.name;
      if (entry.isDirectory()) walk(nodePath.join(dir, entry.name), name);
      else if (/(^|\/)blamejs-[^/]*\.db$/.test(name)) found.push(name);
    });
  })(workDir, "");
  return found.sort();
}

// Put the volume the holder has open back into the shape a build from
// before the reporter's organization was recorded left it in: no column
// for that organization, the uniqueness rule on the reporter's own name,
// no forensic report table, and no migration record at all, which is what
// a volume from before this build shipped migrations carries.
function rewindToAnEarlierBuild() {
  var table = tables.DMARC_REPORTS;
  b.db.prepare("PRAGMA index_list(\"" + table + "\")").all().forEach(function (index) {
    if (index.origin !== "c") return;
    var cols = b.db.prepare("PRAGMA index_info(\"" + index.name + "\")").all()
      .map(function (row) { return row.name; });
    if (cols.indexOf("verifiedOrgDomain") !== -1) {
      b.db.prepare("DROP INDEX \"" + index.name + "\"").run();
    }
  });
  b.db.prepare("ALTER TABLE \"" + table + "\" DROP COLUMN verifiedOrgDomain").run();
  b.db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS \"" + OLD_UNIQUE_INDEX + "\" ON \"" + table +
    "\" (orgKey, reportId)").run();
  b.db.prepare("DROP TABLE \"" + MISSING_TABLE + "\"").run();
  b.db.prepare("DROP TABLE IF EXISTS \"" + MIGRATIONS_TABLE + "\"").run();
}

// ---- cases -----------------------------------------------------------------

// Every command that may answer from a read-only open, against a volume an
// earlier build wrote.
function everyReportingVerbRefusesAVolumeBehindThisBuild(vol, encBefore, copiesBefore) {
  var vectors = snapshotVerbs.vectors({ address: ADDRESS, domain: DOMAIN, hostname: HOSTNAME });
  var results = vectors.map(function (entry) {
    return { entry: entry, result: (entry.provider ? vol.zoneCli : vol.cli)(entry.argv) };
  });

  // One check over the whole table first, whose detail is what every
  // command printed, so a run that fails here carries every verdict. A
  // failure line is bounded at 2000 characters, so an answer printed off
  // a copy is shortened to that fact and anything else to its first
  // sentence or so.
  var transcript = results.map(function (one) {
    var text = one.result.both.replace(/\s+/g, " ").trim();
    var shown = /^Snapshot of /.test(text)
      ? "answered off a copy"
      : text.replace(/ Re-run with BLAMEPOST_LOG_LEVEL=debug for the full trace\./, "").slice(0, 70);
    return one.entry.argv.slice(0, 2).join(" ") + " exit " + one.result.status + ": " + shown;
  }).join(" | ");
  count("every reporting verb refuses a volume behind this build under " + BEHIND,
    results.every(function (one) {
      return one.result.status !== 0 && one.result.both.indexOf(BEHIND) !== -1;
    }), transcript, { limit: 20000 });

  results.forEach(function (one) {
    var label = "`" + one.entry.argv.join(" ") + "`";
    count(label + " exits non-zero against a volume behind this build",
      one.result.status !== 0, "exit " + one.result.status + " " + one.result.both.slice(0, 300));
    count(label + " names the refusal code",
      one.result.both.indexOf(BEHIND) !== -1, one.result.both.slice(0, 400));
    count(label + " prints no SQLite error",
      !RAW_SCHEMA_ERROR.test(one.result.both), one.result.both.slice(0, 400));
    count(label + " does not report the volume as unreadable or damaged",
      !/could not be read|damaged/i.test(one.result.both), one.result.both.slice(0, 400));
  });

  var said = results[0].result.both.replace(/\s+/g, " ");
  count("the refusal names the column the volume lacks",
    said.indexOf(MISSING_COLUMN) !== -1, said.slice(0, 800));
  count("the refusal names the table the volume lacks",
    said.indexOf(MISSING_TABLE) !== -1, said.slice(0, 800));
  count("the refusal names the migration the volume has not recorded",
    said.indexOf(SHIPPED_MIGRATION) !== -1, said.slice(0, 800));
  count("the refusal says an older release last opened the volume for writing",
    /older release/i.test(said), said.slice(0, 800));
  count("the refusal names both ways to bring the schema up to date",
    /start the server/i.test(said) && /stop the server/i.test(said), said.slice(0, 800));
  count("the refusal says nothing on the volume was changed",
    /nothing on the volume was changed/i.test(said), said.slice(0, 800));

  count("the encrypted database is byte identical after every refused verb",
    digestOf(nodePath.join(vol.dataDir, "db.enc")) === encBefore, "db.enc changed");
  var strays = plaintextCopies(vol.workDir).filter(function (name) {
    return copiesBefore.indexOf(name) === -1;
  });
  count("no refused verb leaves a decrypted copy behind",
    strays.length === 0, JSON.stringify(strays));
}

// The remedy the refusal names: open the volume for writing with this
// build. A reporting verb run against the stopped server is one such open.
async function openingItForWritingBringsItUpToDate(vol) {
  var listed = vol.cli(["account", "list"]);
  count("with the server stopped, `account list` opens the volume for writing and answers",
    listed.status === 0 && listed.both.indexOf(ADDRESS) !== -1 && !/snapshot/i.test(listed.both),
    "exit " + listed.status + " " + listed.both.slice(0, 400));

  var server = await store.open(vol.cfg);
  try {
    count("the writable open added the column the earlier build did not have",
      columnsOf(tables.DMARC_REPORTS).indexOf("verifiedOrgDomain") !== -1,
      JSON.stringify(columnsOf(tables.DMARC_REPORTS)));
    count("and created the table it did not have",
      tableExists(MISSING_TABLE), MISSING_TABLE);
    count("and recorded the migration it ran",
      recordedMigrations().indexOf(SHIPPED_MIGRATION) !== -1, JSON.stringify(recordedMigrations()));
    b.db.flushToDisk();

    var vectors = snapshotVerbs.vectors({ address: ADDRESS, domain: DOMAIN, hostname: HOSTNAME });
    vectors.forEach(function (entry) {
      var label = "`" + entry.argv.join(" ") + "`";
      var result = (entry.provider ? vol.zoneCli : vol.cli)(entry.argv);
      count(label + " no longer refuses the volume as behind this build",
        result.both.indexOf(BEHIND) === -1 && !RAW_SCHEMA_ERROR.test(result.both),
        result.both.slice(0, 400));
      if (entry.answers) {
        count(label + " answers from a read-only open while the server holds the volume",
          result.status === 0 && /snapshot/i.test(result.both),
          "exit " + result.status + " " + result.both.slice(0, 400));
      } else {
        count(label + " reaches the copy and stops on its own subject",
          result.both.indexOf(entry.stopsOn) !== -1,
          "exit " + result.status + " " + result.both.slice(0, 400));
      }
    });
  } finally {
    server.close();
  }
}

// The code itself, read off the store's own refusal, for a volume that
// carries the migration record table with the row missing. It is the
// other shape a pending migration takes, and the one the rewind above
// does not produce.
async function aMissingMigrationRowRefusesUnderItsCode(vol) {
  var server = await store.open(vol.cfg);
  try {
    b.db.prepare("DELETE FROM \"" + MIGRATIONS_TABLE + "\"").run();
  } finally {
    server.close();
  }

  var copiesBefore = plaintextCopies(vol.workDir);
  var refused = null;
  try { await store.openSnapshot(vol.cfg); }
  catch (e) { refused = e; }
  count("a volume with the migration record table and no row for the shipped migration " +
    "refuses under " + BEHIND,
    refused !== null && refused.code === BEHIND,
    refused === null ? "the open was accepted" : refused.code + ": " + refused.message);
  count("and the refusal names that migration and no column or table",
    refused !== null && String(refused.message).indexOf(SHIPPED_MIGRATION) !== -1 &&
      String(refused.message).indexOf(MISSING_COLUMN) === -1,
    refused === null ? "" : String(refused.message).slice(0, 600));
  count("a refused read-only open leaves no store open",
    store.isOpen() === false, String(store.isOpen()));
  count("and no decrypted copy behind",
    JSON.stringify(plaintextCopies(vol.workDir)) === JSON.stringify(copiesBefore),
    JSON.stringify(plaintextCopies(vol.workDir)));

  // Put the record back through the remedy, so the next case starts from
  // a volume this build has brought up to date.
  var again = await store.open(vol.cfg);
  try {
    count("the writable open records the migration again",
      recordedMigrations().indexOf(SHIPPED_MIGRATION) !== -1, JSON.stringify(recordedMigrations()));
  } finally {
    again.close();
  }
}

// A read-only open that gets past every check and then fails while its
// handle is built. The fault is the mail store refusing to be created over
// the open database, which is where a column this code prepares a
// statement for surfaces when nothing caught it first. The copy has to go
// and the database has to be closed, or the next open in the same process
// finds a read-only database already open and fails on its first write.
async function aHandleThatFailsToBuildLeavesNothingOpen(vol) {
  var copiesBefore = plaintextCopies(vol.workDir);
  var realCreate = b.mailStore.create;
  var faulted = 0;
  b.mailStore.create = function (opts) {
    if (opts && opts.backend === b.db) {
      faulted += 1;
      throw new Error("the mail store could not be created over this database");
    }
    return realCreate.apply(b.mailStore, arguments);
  };
  var refused = null;
  try {
    try { await store.openSnapshot(vol.cfg); }
    catch (e) { refused = e; }
  } finally {
    b.mailStore.create = realCreate;
  }

  count("the fault reached the handle build of a read-only open",
    faulted === 1 && refused !== null, "faulted " + faulted + ", refused " + String(refused));
  count("the failed build is refused under a store code",
    refused !== null && /^store\//.test(String(refused.code)),
    refused === null ? "" : refused.code + ": " + String(refused.message).slice(0, 300));
  count("a read-only open whose handle fails to build removes its decrypted copy",
    JSON.stringify(plaintextCopies(vol.workDir)) === JSON.stringify(copiesBefore),
    "before " + JSON.stringify(copiesBefore) + " after " + JSON.stringify(plaintextCopies(vol.workDir)));

  var opened = null;
  var failed = null;
  try { opened = await store.open(vol.cfg); }
  catch (e2) { failed = e2; }
  try {
    count("and a writable open in the same process afterwards succeeds",
      opened !== null && failed === null, failed === null ? "" : String(failed.message).slice(0, 300));
  } finally {
    if (opened !== null) opened.close();
  }
}

// A volume a newer build wrote: it records a migration this build does not
// ship. One recorded name has the shape of a migration and one does not.
async function aVolumeAheadOfThisBuildRefuses(vol) {
  var server = await store.open(vol.cfg);
  try {
    var insert = b.db.prepare("INSERT INTO \"" + MIGRATIONS_TABLE +
      "\" (name, description, appliedAt) VALUES (?, ?, ?)");
    insert.run(NEWER_MIGRATION, "a migration from a newer build", new Date().toISOString());
    insert.run(FORGED_NAME, "a name that is not a migration file", new Date().toISOString());
    b.db.flushToDisk();

    AHEAD_VERBS.forEach(function (argv) {
      var label = "`" + argv.join(" ") + "`";
      var result = vol.cli(argv);
      count(label + " refuses a volume ahead of this build under " + AHEAD,
        result.status !== 0 && result.both.indexOf(AHEAD) !== -1,
        "exit " + result.status + " " + result.both.slice(0, 500));
      count(label + " prints no SQLite error against a volume ahead of this build",
        !RAW_SCHEMA_ERROR.test(result.both), result.both.slice(0, 400));
    });
  } finally {
    server.close();
  }

  var refused = null;
  try { await store.openSnapshot(vol.cfg); }
  catch (e) { refused = e; }
  var said = refused === null ? "" : String(refused.message);
  count("the store refuses a volume ahead of this build under " + AHEAD,
    refused !== null && refused.code === AHEAD,
    refused === null ? "the open was accepted" : refused.code + ": " + said);
  count("the refusal names the migration a newer build recorded",
    said.indexOf(NEWER_MIGRATION) !== -1, said.slice(0, 600));
  count("the refusal says a newer release last opened the volume for writing",
    /newer release/i.test(said), said.slice(0, 600));
  count("a recorded name that is not a migration file is counted and not printed",
    said.indexOf(FORGED_TEXT) === -1 && !/[\r\n]/.test(said), said.slice(0, 600));
  count("the refusal says nothing on the volume was changed",
    /nothing on the volume was changed/i.test(said), said.slice(0, 600));
}

// A column of the framework's mail store and a column of one of the
// framework's own tables. The mail store prepares its statements when the
// handle is built, so a column missing there is refused before any of them
// is prepared rather than surfacing from the prepare.
//
// It runs last on the same volume. Every store opened in one process
// shares one vault, so a second volume created here could not be read by
// a spawned command, and a volume missing a mail store column no longer
// opens for writing at all.
async function aFrameworkColumnThisBuildReadsIsMissing(vol) {
  var server = await store.open(vol.cfg);
  var result;
  try {
    // The rows the case above recorded, so what is refused here is the
    // missing columns rather than the volume being ahead.
    b.db.prepare("DELETE FROM \"" + MIGRATIONS_TABLE + "\" WHERE name <> ?").run(SHIPPED_MIGRATION);
    b.db.prepare("ALTER TABLE \"" + MAIL_STORE_TABLE + "\" DROP COLUMN " + MAIL_STORE_COLUMN).run();
    b.db.prepare("ALTER TABLE \"" + FRAMEWORK_TABLE + "\" DROP COLUMN " + FRAMEWORK_COLUMN).run();
    b.db.flushToDisk();
    result = vol.cli(["account", "list"]);
  } finally {
    server.close();
  }

  var said = result.both.replace(/\s+/g, " ");
  count("`account list` refuses a volume missing a column of the framework's mail store",
    result.status !== 0 && said.indexOf(BEHIND) !== -1,
    "exit " + result.status + " " + said.slice(0, 600));
  count("and prints no SQLite error", !RAW_SCHEMA_ERROR.test(said), said.slice(0, 600));
  count("the refusal names the mail store column",
    said.indexOf(MAIL_STORE_TABLE + "." + MAIL_STORE_COLUMN) !== -1, said.slice(0, 800));
  count("and the framework table column",
    said.indexOf(FRAMEWORK_TABLE + "." + FRAMEWORK_COLUMN) !== -1, said.slice(0, 800));

  var copiesBefore = plaintextCopies(vol.workDir);
  var refused = null;
  try { await store.openSnapshot(vol.cfg); }
  catch (e) { refused = e; }
  // The copy first, because it holds whatever the refusal turned out to
  // be: an open that fails anywhere after the database is decrypted has
  // to remove the copy, including a failure while the handle is built.
  count("the refused open removes its decrypted copy rather than leaving the database open",
    refused !== null &&
      JSON.stringify(plaintextCopies(vol.workDir)) === JSON.stringify(copiesBefore),
    "before " + JSON.stringify(copiesBefore) + " after " + JSON.stringify(plaintextCopies(vol.workDir)));
  count("the store refuses the same volume under " + BEHIND,
    refused !== null && refused.code === BEHIND,
    refused === null ? "the open was accepted" : refused.code + ": " + refused.message);
}

// The reader of recorded migrations and the runner that applies them at
// boot have to agree about which files are migrations, or a file one
// applies is a file the other never reports as pending.
function everyShippedMigrationHasTheFrameworksFileShape() {
  var names = nodeFs.readdirSync(MIGRATION_DIR).filter(function (name) {
    return /\.js$/.test(name);
  });
  count("the store ships at least one migration", names.length >= 1, JSON.stringify(names));
  var misshapen = names.filter(function (name) { return !b.migrations.FILE_RE.test(name); });
  count("every file in the migration directory has the shape b.migrations reads",
    misshapen.length === 0, JSON.stringify(misshapen));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("snapshot-schema");
  var vol  = volumeAt(root, "data");

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  // The same memory backed directory for this process and every command
  // it spawns, which is what the server and `docker exec` share.
  process.env.BLAMEJS_TMPDIR = vol.workDir;

  var server = null;
  try {
    everyShippedMigrationHasTheFrameworksFileShape();

    await seed(vol);

    // The server, still running the earlier build's schema.
    server = await store.open(vol.cfg);
    rewindToAnEarlierBuild();
    count("the volume carries the earlier build's schema before any verb runs",
      columnsOf(tables.DMARC_REPORTS).indexOf("verifiedOrgDomain") === -1 &&
        !tableExists(MISSING_TABLE) && !tableExists(MIGRATIONS_TABLE),
      JSON.stringify(columnsOf(tables.DMARC_REPORTS)));
    b.db.flushToDisk();

    everyReportingVerbRefusesAVolumeBehindThisBuild(vol,
      digestOf(nodePath.join(vol.dataDir, "db.enc")), plaintextCopies(vol.workDir));

    server.close();
    server = null;

    await openingItForWritingBringsItUpToDate(vol);
    await aMissingMigrationRowRefusesUnderItsCode(vol);
    await aHandleThatFailsToBuildLeavesNothingOpen(vol);
    await aVolumeAheadOfThisBuildRefuses(vol);
    await aFrameworkColumnThisBuildReadsIsMissing(vol);

    return helpers.getChecks();
  } finally {
    if (server) {
      try { server.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e2) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "store-snapshot-schema", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
