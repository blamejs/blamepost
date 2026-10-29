// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A data directory that is not an absolute path.
 *
 * Every subsystem that keeps files builds its own directory by joining a
 * name onto the one it was handed, and `node:path` resolves a relative
 * base against the working directory of whatever process is running. So a
 * relative value never fails: the spool, the message blobs and the sealed
 * DKIM keys are written into whichever tree the server was started from,
 * and into a different tree the next time it is started from elsewhere.
 * The stray `queue/` and `tlsrpt/` directories that used to appear inside
 * this repository were exactly that.
 *
 * `config.load` resolves the setting, so a configuration that was read
 * cannot carry a relative one. What was open is every caller that builds
 * a configuration by hand, which is every embedder and every test, and
 * the primitives they call checked that the value was a non-empty string
 * and nothing else.
 *
 * The measurement is the stray directory rather than the message. A child
 * process is started in a temporary directory of its own and asked to
 * build the outbound handle against a relative name; the assertion is
 * that the refusal happened AND that the directory is not there
 * afterwards. Asserting only the throw would pass on a guard that threw
 * after `ensureDir` had already run.
 *
 * Run standalone: node test/layer-1-state/data-dir-absolute.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeProc = require("node:child_process");

var helpers   = require("../helpers");
var blamepost = require("../../lib");
// The mailbox adapter is composed by the facade rather than re-exported
// from it, so it is reached through the module that owns it.
var mailbox   = require("../../lib/mail/mailbox");

var count = helpers.count;

var HOSTNAME = "mx.example.com";

// The relative name the child is handed. It is not a name any part of
// this server would choose, so a directory carrying it can only have come
// from the run under measurement.
var RELATIVE_NAME = "relative-data-dir-probe";

// The library entry point, resolved here so the child can require it from
// a working directory that is not this repository.
var LIB_ENTRY = nodePath.join(helpers.REPO_ROOT, "lib");

// The store is reached directly rather than through the facade, because
// `open` takes the resolved paths table and the facade does not hand one
// out.
var LIB_STORE = nodePath.join(helpers.REPO_ROOT, "lib", "store");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The refusal's own words, matched on the part that states the rule
// rather than on the primitive that raised it, so the same assertion
// serves every call site below.
var REFUSAL = "must be an absolute path";

// Build the outbound handle in a child process whose working directory is
// `cwd`, and report what the child did and what it left behind.
function buildDeliveryIn(cwd) {
  var source =
    "var blamepost = require(" + JSON.stringify(LIB_ENTRY) + ");" +
    "blamepost.mail.delivery.create({" +
    "  hostname: " + JSON.stringify(HOSTNAME) + "," +
    "  dataDir: " + JSON.stringify(RELATIVE_NAME) +
    "});";
  var result = nodeProc.spawnSync(process.execPath, ["-e", source], {
    cwd:      cwd,
    encoding: "utf8",
  });
  return {
    status: result.status,
    said:   String(result.stdout || "") + String(result.stderr || ""),
    left:   nodeFs.existsSync(nodePath.join(cwd, RELATIVE_NAME)),
  };
}

// Open the store in a child process whose working directory is `cwd`,
// against a configuration built by hand rather than read, and report what
// the child did and what it left behind. The store is given its paths
// table directly because that is the shape it takes: `open` reads
// `cfg.paths`, not `cfg.dataDir`, so a guard on the second one never sees
// this call at all.
function openStoreIn(cwd, tmp) {
  var paths = {
    dataDir:  RELATIVE_NAME,
    database: RELATIVE_NAME + "/db.enc",
    queue:    RELATIVE_NAME + "/queue",
    blobs:    RELATIVE_NAME + "/blobs",
    keys:     RELATIVE_NAME + "/keys",
    tls:      RELATIVE_NAME + "/tls",
  };
  var source =
    "var store = require(" + JSON.stringify(LIB_STORE) + ");" +
    "store.open({" +
    "  paths: " + JSON.stringify(paths) + "," +
    "  hostname: " + JSON.stringify(HOSTNAME) + "," +
    "  vaultPassphrase: " + JSON.stringify(VAULT_PASSPHRASE) +
    "}).then(function () { process.exit(0); }," +
    "  function (e) { console.error(e && e.message ? e.message : String(e)); process.exit(3); });";
  var result = nodeProc.spawnSync(process.execPath, ["-e", source], {
    cwd:      cwd,
    encoding: "utf8",
    // The framework refuses to open a volume without somewhere to put the
    // decrypted working copy, and a refusal for that reason would be a
    // different measurement from this one. It is given a directory of its
    // own rather than the working directory, so what is found in the
    // working directory afterwards came from the value under measurement.
    env:      Object.assign({}, process.env, { BLAMEJS_TMPDIR: tmp }),
  });
  return {
    status: result.status,
    said:   String(result.stdout || "") + String(result.stderr || ""),
    left:   nodeFs.readdirSync(cwd),
  };
}

// ---- cases --------------------------------------------------------------------

function theOutboundHandleRefusesAndWritesNothing(cwd) {
  var run = buildDeliveryIn(cwd);
  count("building the outbound handle against a relative directory fails",
    run.status !== 0, "exit " + run.status + " " + run.said.slice(0, 300));
  count("and the refusal says what is wrong with the value rather than reporting a " +
    "failure from whichever call tried to use it first",
    run.said.indexOf(REFUSAL) !== -1, run.said.slice(0, 400));
  count("and nothing was created in the directory the process was started from, which is " +
    "the fault this refuses rather than the message it prints",
    run.left === false,
    nodeFs.readdirSync(cwd).join(" "));
}

// The store is the door the value reaches in a different shape. Every
// primitive above is handed `opts.dataDir`; `store.open` is handed the
// resolved paths table and reads `cfg.paths.dataDir`, so a guard written
// against the first name never sees this call.
//
// It is also the door that writes the most. The refusal an unguarded tree
// produces arrives from the mailbox adapter at the very end of the open,
// by which time the sealed vault key, the sealed audit-signing key, the
// encrypted database and its sealed key are all on disk in whichever tree
// the process was started from. So the assertion is the empty working
// directory rather than the throw: a run that refuses after writing those
// four files has not refused anything worth having.
function theStoreRefusesBeforeItWritesAnything(cwd, tmp) {
  var run = openStoreIn(cwd, tmp);
  count("opening the store against a relative data directory fails",
    run.status !== 0, "exit " + run.status + " " + run.said.slice(0, 300));
  count("and the refusal says what is wrong with the value rather than reporting it from " +
    "whichever subsystem happened to be built last",
    run.said.indexOf(REFUSAL) !== -1, run.said.slice(0, 400));
  count("and the working directory is untouched, which is the fault this refuses: the " +
    "sealed keys and the encrypted database are written before the end of the open",
    run.left.length === 0, run.left.join(" "));
}

// The reporting open reads rather than writes, and it takes the same
// table. A relative value there reads a volume out of whichever tree the
// command was run from and decrypts a working copy of it.
async function theReportingOpenRefusesTheSameValue() {
  var store = require("../../lib/store");
  var message = null;
  try {
    await store.openSnapshot({
      paths: { dataDir: RELATIVE_NAME, database: RELATIVE_NAME + "/db.enc" },
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
  } catch (e) {
    message = (e && e.message) || String(e);
  }
  count("the reporting open refuses a relative data directory rather than reporting that " +
    "there is no database at a path it resolved against the working directory",
    message !== null && message.indexOf(REFUSAL) !== -1, String(message).slice(0, 300));
}

// Whose name the refusal carries. An operator reading it goes to the verb
// it names, so a reporting verb refusing under the writing verb's name
// sends them to a call they did not make. Both entry points reach one
// helper, and the helper is what has to say which of them it is speaking
// for.
async function eachStoreDoorNamesItselfWhenItRefuses() {
  var store = require("../../lib/store");
  var relative = {
    paths: { dataDir: RELATIVE_NAME, database: RELATIVE_NAME + "/db.enc" },
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  };

  var snapshotSaid = null;
  try { await store.openSnapshot(relative); }
  catch (e) { snapshotSaid = (e && e.message) || String(e); }
  count("the reporting open names openSnapshot in the refusal, which is the verb the " +
    "operator called",
    String(snapshotSaid).indexOf("store.openSnapshot: cfg.paths.dataDir") !== -1,
    String(snapshotSaid).slice(0, 300));
  count("and it does not name the writing open, which is a verb the operator did not call",
    String(snapshotSaid).indexOf("store.open:") === -1, String(snapshotSaid).slice(0, 300));

  var openSaid = null;
  try { await store.open(relative); }
  catch (e) { openSaid = (e && e.message) || String(e); }
  count("the writing open still names itself",
    String(openSaid).indexOf("store.open: cfg.paths.dataDir") !== -1,
    String(openSaid).slice(0, 300));

  // The same helper raises the shape refusal one line above the path
  // refusal, so it answers for the caller's name twice and both answers
  // have to be the caller's.
  var snapshotShape = null;
  try { await store.openSnapshot({}); }
  catch (e) { snapshotShape = (e && e.message) || String(e); }
  count("and the refusal for a configuration that is not one names the reporting open too",
    String(snapshotShape).indexOf("store.openSnapshot takes the object") !== -1,
    String(snapshotShape).slice(0, 300));

  var openShape = null;
  try { await store.open({}); }
  catch (e) { openShape = (e && e.message) || String(e); }
  count("while the writing open keeps its own",
    String(openShape).indexOf("store.open takes the object") !== -1,
    String(openShape).slice(0, 300));
}

// The two doors onto one volume, given one table. The writing open runs
// the whole table through the directory maker and the reporting open
// never calls it, so an entry neither door dereferences by name is the
// one a check written per door answers for at only one of them. The
// measurement is that one table gets one answer whichever door it is
// handed to.
async function bothStoreDoorsAnswerForEveryEntryInTheTable(root) {
  var store  = require("../../lib/store");
  var volume = nodePath.join(root, "table-volume");
  var table  = {
    paths: {
      dataDir:  volume,
      database: nodePath.join(volume, "db.enc"),
      queue:    nodePath.join(volume, "queue"),
      // Absolute everywhere the two doors read by name, relative in an
      // entry only the directory maker ever touches.
      blobs:    RELATIVE_NAME,
      keys:     nodePath.join(volume, "keys"),
      tls:      nodePath.join(volume, "tls"),
    },
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  };

  var openSaid = null;
  try { await store.open(table); }
  catch (e) { openSaid = (e && e.message) || String(e); }
  count("the writing open refuses a relative blobs entry",
    String(openSaid).indexOf(REFUSAL) !== -1, String(openSaid).slice(0, 300));

  var snapshotSaid = null;
  try { await store.openSnapshot(table); }
  catch (e) { snapshotSaid = (e && e.message) || String(e); }
  count("and the reporting open refuses the same entry in the same table, rather than " +
    "accepting it and going on to report on the database",
    String(snapshotSaid).indexOf(REFUSAL) !== -1, String(snapshotSaid).slice(0, 300));
  count("and it names the entry that is wrong",
    String(snapshotSaid).indexOf("cfg.paths.blobs") !== -1, String(snapshotSaid).slice(0, 300));
}

// `blamepost.config.assertAbsoluteDataPaths` is the check both store
// doors and the directory maker run over a resolved table, so one table
// gets one answer wherever it is handed in. This drives the one refusal
// none of those three can produce: each establishes that `cfg.paths` is
// an object before reaching it, so a caller handing it something that is
// not a table at all is the branch only a direct call reaches.
function theTableCheckRefusesSomethingThatIsNotATable() {
  var config = require("../../lib/config");
  var notTables = [
    { what: "a string",  value: "/var/lib/blamepost" },
    { what: "an array",  value: [] },
    { what: "null",      value: null },
    { what: "a number",  value: 7 },
  ];
  for (var i = 0; i < notTables.length; i += 1) {
    var message = null;
    try { config.assertAbsoluteDataPaths("probe: cfg.paths", notTables[i].value); }
    catch (e) { message = (e && e.message) || String(e); }
    count("the table check refuses " + notTables[i].what + " in place of a paths table",
      message !== null && message.indexOf("must be the resolved paths table") !== -1,
      String(message).slice(0, 200));
  }

  // And it hands a good table back, so a caller can assign through it the
  // way the guard beside it lets a caller assign through a single entry.
  var good = { dataDir: "/var/lib/blamepost", blobs: "/var/lib/blamepost/blobs" };
  count("and it returns the table it was given when every entry is absolute",
    config.assertAbsoluteDataPaths("probe: cfg.paths", good) === good, "returned a copy");
}

// Node's own message for a path that is not a string. A refusal carrying
// it is one that arrived from whichever call first tried to use the
// value, which names neither the value's entry nor the caller handed it.
var NODE_PATH_TYPE_ERROR = "The \"path\" argument must be of type string";

// A value that is not a path at all. Every caller that names its own data
// directory rejects a non-string first and answers with its own sentence,
// so the doors to measure are the two that take the resolved table and
// pass whatever it holds straight through. At those the guard is the only
// thing between a wrong type and a refusal raised by whichever call first
// joined or created under the value, which names neither the entry nor
// the caller.
async function everyDoorRefusesAValueThatIsNotAPathAtAll(root) {
  var config = require("../../lib/config");
  var store  = require("../../lib/store");
  var volume = nodePath.join(root, "type-volume");

  var wrong = [
    { what: "a number",     value: 42 },
    { what: "null",         value: null },
    { what: "an object",    value: { path: "/var/lib/blamepost" } },
    { what: "an array",     value: ["/var/lib/blamepost"] },
    { what: "a boolean",    value: true },
    { what: "an entry named with nothing in it", value: undefined },
  ];

  for (var i = 0; i < wrong.length; i += 1) {
    var each = wrong[i];

    var madeSaid = null;
    try {
      config.ensureDataDirectories({
        paths: { dataDir: each.value, database: nodePath.join(volume, "db.enc") },
      });
    } catch (e) { madeSaid = (e && e.message) || String(e); }
    count("the directory maker refuses " + each.what + " as the data directory",
      madeSaid !== null && madeSaid.indexOf(NODE_PATH_TYPE_ERROR) === -1,
      String(madeSaid).slice(0, 250));
    count("and it names the entry rather than leaving the failure to whichever call first " +
      "used the value as a path, for " + each.what,
      String(madeSaid).indexOf("cfg.paths.dataDir") !== -1, String(madeSaid).slice(0, 250));

    var openSaid = null;
    try {
      await store.open({
        paths: { dataDir: each.value, database: nodePath.join(volume, "db.enc") },
        hostname:        HOSTNAME,
        vaultPassphrase: VAULT_PASSPHRASE,
      });
    } catch (e) { openSaid = (e && e.message) || String(e); }
    count("the writing open refuses " + each.what + " before it holds the volume",
      openSaid !== null && openSaid.indexOf(NODE_PATH_TYPE_ERROR) === -1,
      String(openSaid).slice(0, 250));

    var snapshotSaid = null;
    try {
      await store.openSnapshot({
        paths: { dataDir: each.value, database: nodePath.join(volume, "db.enc") },
        hostname:        HOSTNAME,
        vaultPassphrase: VAULT_PASSPHRASE,
      });
    } catch (e) { snapshotSaid = (e && e.message) || String(e); }
    // Named rather than merely refused. This door reaches the database
    // before it reaches the directory, so an unguarded value here is
    // reported as a volume that has never been through `blamepost init`,
    // which is a refusal that carries neither the entry nor the type and
    // reads as a true answer about a different fault.
    count("and the reporting open refuses " + each.what + " naming the entry, rather than " +
      "reporting that there is no database at a path it never had",
      String(snapshotSaid).indexOf("cfg.paths.dataDir") !== -1,
      String(snapshotSaid).slice(0, 250));
  }

  // The entry missing altogether, which is a different fault from an
  // entry holding the wrong thing: there is no value to describe, and the
  // door that dereferences the name is the one that has to say so.
  var absentOpen = null;
  try {
    await store.open({
      paths: { database: nodePath.join(volume, "db.enc") },
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
  } catch (e) { absentOpen = (e && e.message) || String(e); }
  count("the writing open refuses a table with no data directory in it at all",
    absentOpen !== null && absentOpen.indexOf(NODE_PATH_TYPE_ERROR) === -1,
    String(absentOpen).slice(0, 250));
  count("and it says which entry is missing",
    String(absentOpen).indexOf("cfg.paths.dataDir") !== -1, String(absentOpen).slice(0, 250));
}

// The reservation the guard's prose makes, held to. Every caller that
// names its own data directory has a sentence saying what it keeps under
// it, and that sentence is what an operator who left the setting out
// should read. Refusing a wrong TYPE at the guard must not take those
// sentences away from the callers that own the absent case.
async function theAbsentCaseStillBelongsToTheCaller() {
  var doors = [
    {
      what: "the DKIM signer",
      says: "opts.dataDir is required",
      call: function () { blamepost.mail.dkim.create({ store: {} }); },
    },
    {
      what: "the key erasure",
      says: "dataDir is required",
      call: function () { return blamepost.mail.dkim.eraseKeyFiles(undefined, []); },
    },
    {
      what: "the mailbox adapter",
      says: "opts.dataDir is required",
      call: function () {
        mailbox.create({
          store: {
            appendMessage:   function () {},
            fetchByObjectId: function () {},
            hardExpunge:     function () {},
          },
        });
      },
    },
    {
      what: "the outbound handle",
      says: "opts.dataDir is required",
      call: function () { blamepost.mail.delivery.create({ hostname: HOSTNAME }); },
    },
    {
      what: "the server itself",
      says: "config.dataDir is required",
      call: function () { blamepost.create({ config: { hostname: HOSTNAME } }); },
    },
  ];

  for (var i = 0; i < doors.length; i += 1) {
    var door = doors[i];
    var message = null;
    try { await door.call(); }
    catch (e) { message = (e && e.message) || String(e); }
    count(door.what + " keeps its own sentence for a data directory that was left out",
      message !== null && message.indexOf(door.says) !== -1, String(message).slice(0, 250));
  }
}

// The primitive that turns the table into directories on disk. It is the
// one place `cfg.paths` becomes files, so it answers for every entry
// rather than for the one the other callers name.
//
// The working directory is moved into the temporary tree for the length
// of this check and put back afterwards. An unguarded tree creates the
// relative name where the process is standing, and where this process is
// standing is the repository.
function theDirectoryMakerRefusesEveryRelativeEntry(cwd) {
  var config  = require("../../lib/config");
  var entries = ["dataDir", "queue", "blobs", "keys", "tls"];
  var was     = process.cwd();
  process.chdir(cwd);
  try {
    for (var i = 0; i < entries.length; i += 1) {
      var paths = {
        dataDir:  nodePath.join(cwd, "volume"),
        database: nodePath.join(cwd, "volume", "db.enc"),
        queue:    nodePath.join(cwd, "volume", "queue"),
        blobs:    nodePath.join(cwd, "volume", "blobs"),
        keys:     nodePath.join(cwd, "volume", "keys"),
        tls:      nodePath.join(cwd, "volume", "tls"),
      };
      paths[entries[i]] = RELATIVE_NAME;
      var message = null;
      try { config.ensureDataDirectories({ paths: paths }); }
      catch (e) { message = (e && e.message) || String(e); }
      count("ensureDataDirectories refuses a relative " + entries[i] +
        ", because it is the call that creates the directory",
        message !== null && message.indexOf(REFUSAL) !== -1, String(message).slice(0, 200));
      count("and it created nothing under the directory it was standing in for a relative " +
        entries[i],
        nodeFs.existsSync(nodePath.join(cwd, RELATIVE_NAME)) === false,
        nodeFs.readdirSync(cwd).join(" "));
    }
  } finally {
    process.chdir(was);
  }
}

// The same value reaching the same guard through every other primitive
// that keeps files under the data directory. A guard on one of them
// closes one door in a corridor: the spool, the sealed keys, the message
// blobs and the identity layer's key erasure all join onto this value.
async function everyDoorToTheDataDirectoryRefusesIt() {
  var doors = [
    {
      what: "the DKIM signer, which keeps the sealed private keys",
      call: function () {
        blamepost.mail.dkim.create({
          dataDir: RELATIVE_NAME,
          store:   { domains: { addSelector: function () {}, listSelectors: function () {},
            get: function () {} } },
        });
      },
    },
    {
      what: "the key erasure, which unlinks the files it names",
      call: function () { return blamepost.mail.dkim.eraseKeyFiles(RELATIVE_NAME, []); },
    },
    {
      what: "the mailbox adapter, which writes the message octets",
      call: function () {
        mailbox.create({
          store: {
            appendMessage:   function () {},
            fetchByObjectId: function () {},
            hardExpunge:     function () {},
          },
          dataDir: RELATIVE_NAME,
        });
      },
    },
    {
      what: "the server itself, which hands the value to all of them",
      call: function () {
        blamepost.create({ config: { hostname: HOSTNAME, dataDir: RELATIVE_NAME } });
      },
    },
  ];

  for (var i = 0; i < doors.length; i += 1) {
    var door = doors[i];
    var message = null;
    try {
      // Awaited rather than called, because one of these is async and a
      // guard inside an async function rejects where the others throw.
      // A caller that only caught the synchronous form would record the
      // async one as having passed.
      await door.call();
    } catch (e) {
      message = (e && e.message) || String(e);
    }
    count(door.what + " refuses a relative data directory",
      message !== null && message.indexOf(REFUSAL) !== -1,
      String(message).slice(0, 300));
  }
}

// The value the loader produces is absolute whatever the operator wrote,
// so the guard cannot refuse a configuration that was read. Asserted
// because a guard that broke the ordinary path would be the worse defect.
function aLoadedConfigurationIsNeverRefused(cwd) {
  var config = require("../../lib/config");
  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         RELATIVE_NAME,
      BLAMEPOST_VAULT_PASSPHRASE: "a long enough vault passphrase for one test run",
    },
    cwd: cwd,
  });
  count("a relative directory written in the configuration is resolved by the loader, so " +
    "an operator who wrote one still boots",
    nodePath.isAbsolute(cfg.dataDir), cfg.dataDir);
  count("and it resolves under the directory the loader was given rather than anywhere else",
    cfg.dataDir === nodePath.resolve(cwd, RELATIVE_NAME), cfg.dataDir);
  count("so the guard has nothing to refuse about it",
    config.assertAbsoluteDataDir("probe", cfg.dataDir) === cfg.dataDir, cfg.dataDir);
}

// ---- runner -------------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("data-dir-absolute");
  // One directory per child, so what is found in each after a run came
  // from that run rather than from the one before it.
  var storeCwd = nodePath.join(root, "store-cwd");
  var storeTmp = nodePath.join(root, "store-tmp");
  var makerCwd = nodePath.join(root, "maker-cwd");
  nodeFs.mkdirSync(storeCwd, { recursive: true });
  nodeFs.mkdirSync(storeTmp, { recursive: true });
  nodeFs.mkdirSync(makerCwd, { recursive: true });

  try {
    theOutboundHandleRefusesAndWritesNothing(root);
    theStoreRefusesBeforeItWritesAnything(storeCwd, storeTmp);
    await theReportingOpenRefusesTheSameValue();
    await eachStoreDoorNamesItselfWhenItRefuses();
    await bothStoreDoorsAnswerForEveryEntryInTheTable(root);
    theTableCheckRefusesSomethingThatIsNotATable();
    await everyDoorRefusesAValueThatIsNotAPathAtAll(root);
    await theAbsentCaseStillBelongsToTheCaller();
    theDirectoryMakerRefusesEveryRelativeEntry(makerCwd);
    await everyDoorToTheDataDirectoryRefusesIt();
    aLoadedConfigurationIsNeverRefused(root);
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "data-dir-absolute", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
