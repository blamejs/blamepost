// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The Sieve script store, and the budget the interpreter runs under.
 *
 * RFC 5804 puts a small number of hard rules on a server that keeps
 * filter scripts for other people, and every one of them exists because
 * of a way an account holder loses mail. A script is checked before it
 * is stored (section 2.6), so a filter that cannot run is refused while
 * its author is still looking at the error rather than months later.
 * At most one script is active (section 2.8), so there is one answer to
 * what filters a message. The active script cannot be deleted (section
 * 2.10), so a mailbox is never left filtering by a script that is gone.
 * And a server holding scripts for many accounts answers each about its
 * own, which is the rule nothing in the protocol states because it is
 * assumed.
 *
 * The interpreter's budget belongs here too. A script is written by an
 * account holder and then runs against every message that arrives for
 * them, so its cost is attacker-controlled in the one case that
 * matters: an account somebody else has taken over. The framework's
 * interpreter counts operations and refuses past a cap, and the size
 * cap on a stored script does not on its own keep a script under it.
 * The vector below is a script that passes every storage check and
 * still exhausts the budget, which is the shape the cap has to catch.
 *
 * No sockets here: the store and the interpreter, on real files in a
 * temporary directory. The wire is the other file's job.
 *
 * Run standalone: node test/layer-1-state/sieve-script-lifecycle.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The interpreter's operation budget, from the framework's own default.
// Named here so the vector below is written against the number that is
// actually in force rather than against a copy of it.
var GAS_CAP = 10000;

var FILE_JUNK = "require [\"fileinto\"];\n" +
  "if header :contains \"X-Category\" \"noise\" { fileinto \"Junk\"; }\n";

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    // The shape a signed in session carries, roles and no scopes array.
    // `b.permissions` reads a scopes array in preference to the roles,
    // so an empty one here would be an actor granted nothing rather than
    // an actor with a role, and every filter write below would refuse.
    roles:     ["account"],
  };
}

// The refusal, by code. A store verb refuses with a `mailbox/` code, and
// asserting the code rather than the message distinguishes the rule
// that was meant to fire from any other failure on the way to it.
function refusesWith(label, code, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "accepted" : thrown.code + " " + thrown.message);
  return thrown;
}

// ---- storage is gated on the script being runnable -------------------------

function aScriptIsCheckedBeforeItIsStored(handle, actor) {
  refusesWith("a script that does not parse is refused", "mailbox/script-refused", function () {
    handle.mailbox.sieveScripts.put(actor, "unparseable", "if header :is \"Subject\"");
  });
  count("and nothing is left behind by the refusal",
    handle.mailbox.sieveScripts.get(actor, "unparseable") === null,
    JSON.stringify(handle.mailbox.sieveScripts.get(actor, "unparseable")));

  // RFC 5228 section 3.2: a script naming a capability the server does
  // not implement is refused at `require`, before any of it runs. The
  // account holder finds out at upload, which is the only moment they
  // are present to be told.
  refusesWith("a script requiring a capability this build cannot run is refused",
    "mailbox/script-refused", function () {
      handle.mailbox.sieveScripts.put(actor, "away",
        "require [\"vacation\"];\nvacation :days 7 \"back next week\";");
    });
  count("and that script is not stored either",
    handle.mailbox.sieveScripts.get(actor, "away") === null);

  var stored = handle.mailbox.sieveScripts.put(actor, "file-junk", FILE_JUNK);
  count("a script that parses is stored", stored.ok === true);
  count("and the reply names the capabilities it asked for",
    Array.isArray(stored.requiredCaps) && stored.requiredCaps.indexOf("fileinto") !== -1,
    JSON.stringify(stored.requiredCaps));
}

function theStoreHasCeilings(handle, actor) {
  var oversize = "# " + new Array(70000).join("x") + "\nkeep;\n";
  refusesWith("a script past the size ceiling is refused", "mailbox/script-too-large",
    function () { handle.mailbox.sieveScripts.put(actor, "oversize", oversize); });
  count("and the refusal names a ceiling rather than a parse failure",
    handle.mailbox.sieveScripts.get(actor, "oversize") === null);

  var answer = handle.mailbox.sieveScripts.haveSpace(actor, "oversize", oversize.length);
  count("and asking beforehand gets the same answer without the upload",
    answer.ok === false, JSON.stringify(answer));

  // The count ceiling. `file-junk` is already stored, so the run fills
  // to the cap from there and the next one is the one that is refused.
  var held = handle.mailbox.sieveScripts.list(actor).length;
  for (var i = held; i < 32; i += 1) {
    handle.mailbox.sieveScripts.put(actor, "filler-" + i, "keep;\n");
  }
  count("an account fills to the script ceiling",
    handle.mailbox.sieveScripts.list(actor).length === 32,
    String(handle.mailbox.sieveScripts.list(actor).length));
  refusesWith("and the one past it is refused", "mailbox/script-limit", function () {
    handle.mailbox.sieveScripts.put(actor, "one-too-many", "keep;\n");
  });

  // Replacing a script that is already there is not a new script, so it
  // is not refused by a ceiling that is about how many there are.
  var replaced = handle.mailbox.sieveScripts.put(actor, "filler-31", "discard;\n");
  count("replacing a script already stored is not refused at the ceiling",
    replaced.ok === true);
  count("and the replacement is what reads back",
    handle.mailbox.sieveScripts.get(actor, "filler-31").body.indexOf("discard") !== -1);

  for (var j = held; j < 32; j += 1) {
    handle.mailbox.sieveScripts.delete(actor, "filler-" + j);
  }
}

// ---- exactly one script filters a mailbox ----------------------------------

function oneScriptIsActiveAtATime(handle, actor) {
  handle.mailbox.sieveScripts.put(actor, "file-newsletters",
    "require [\"fileinto\"];\nif header :contains \"List-Id\" \"news\" { fileinto \"Junk\"; }\n");

  count("an account with nothing activated has no active script",
    handle.mailbox.sieveScripts.active(actor) === null);

  handle.mailbox.sieveScripts.setActive(actor, "file-junk");
  count("activating one makes it the active script",
    handle.mailbox.sieveScripts.active(actor).name === "file-junk",
    JSON.stringify(handle.mailbox.sieveScripts.active(actor)));

  handle.mailbox.sieveScripts.setActive(actor, "file-newsletters");
  var listed = handle.mailbox.sieveScripts.list(actor);
  var active = listed.filter(function (row) { return row.active === true; });
  count("activating a second one leaves exactly one active",
    active.length === 1, JSON.stringify(listed));
  count("and it is the one just activated", active[0].name === "file-newsletters");

  refusesWith("the active script cannot be deleted", "mailbox/script-active", function () {
    handle.mailbox.sieveScripts.delete(actor, "file-newsletters");
  });

  handle.mailbox.sieveScripts.setActive(actor, "");
  count("an empty name deactivates whatever was active",
    handle.mailbox.sieveScripts.active(actor) === null);
  handle.mailbox.sieveScripts.delete(actor, "file-newsletters");
  count("and the script can be deleted once nothing is filtering by it",
    handle.mailbox.sieveScripts.get(actor, "file-newsletters") === null);

  refusesWith("activating a script that is not there is refused", "mailbox/no-script",
    function () { handle.mailbox.sieveScripts.setActive(actor, "never-uploaded"); });
}

function renameKeepsTheNamespaceUnambiguous(handle, actor) {
  handle.mailbox.sieveScripts.put(actor, "keeper", "keep;\n");
  refusesWith("renaming onto a name already taken is refused", "mailbox/script-exists",
    function () { handle.mailbox.sieveScripts.rename(actor, "keeper", "file-junk"); });
  handle.mailbox.sieveScripts.rename(actor, "keeper", "kept");
  count("a rename onto a free name moves the script",
    handle.mailbox.sieveScripts.get(actor, "kept") !== null &&
    handle.mailbox.sieveScripts.get(actor, "keeper") === null);
  handle.mailbox.sieveScripts.delete(actor, "kept");
}

// ---- one account's scripts are not another's -------------------------------

function scriptsAreScopedToTheAccountThatWroteThem(handle, alice, bob) {
  handle.mailbox.sieveScripts.setActive(alice, "file-junk");

  count("the other account lists none of them",
    handle.mailbox.sieveScripts.list(bob).length === 0,
    JSON.stringify(handle.mailbox.sieveScripts.list(bob)));
  count("and reads none of them by name",
    handle.mailbox.sieveScripts.get(bob, "file-junk") === null);
  count("and has no active script of its own because another account activated one",
    handle.mailbox.sieveScripts.active(bob) === null);

  refusesWith("and cannot activate one it does not own", "mailbox/no-script", function () {
    handle.mailbox.sieveScripts.setActive(bob, "file-junk");
  });
  refusesWith("and cannot delete one it does not own", "mailbox/no-script", function () {
    handle.mailbox.sieveScripts.delete(bob, "file-junk");
  });
  refusesWith("and cannot rename one it does not own", "mailbox/no-script", function () {
    handle.mailbox.sieveScripts.rename(bob, "file-junk", "mine-now");
  });

  count("and the owner's script is untouched by any of that",
    handle.mailbox.sieveScripts.active(alice).name === "file-junk");

  // The two accounts may hold a script of the same name, and each reads
  // its own. A name is only unique inside one account.
  handle.mailbox.sieveScripts.put(bob, "file-junk", "discard;\n");
  count("the same script name in two accounts is two scripts",
    handle.mailbox.sieveScripts.get(bob, "file-junk").body.indexOf("discard") !== -1 &&
    handle.mailbox.sieveScripts.get(alice, "file-junk").body.indexOf("fileinto") !== -1);
  handle.mailbox.sieveScripts.delete(bob, "file-junk");
}

// ---- the interpreter runs under a budget -----------------------------------

// A stored script is inside the size ceiling by construction, and the
// size ceiling is not the operation budget: cheap statements are short,
// so a script well inside the byte cap can ask for more work than the
// interpreter will do. The budget is what stops delivery for one
// account from being held up by that account's own script.
function theInterpreterRunsUnderAnOperationBudget(handle, actor) {
  var env = {
    headers:   [{ name: "Subject", value: "hello" }],
    envelope:  { from: "peer@example.net", to: actor.address },
    sizeBytes: 512,
  };

  var underBudget = new Array(GAS_CAP - 999).join("keep;\n");
  var ran = b.mail.sieve.runScript(underBudget, env, { profile: "strict" });
  count("a script inside the budget runs to the end",
    ran.gas < GAS_CAP && ran.actions.length > 0, "gas " + ran.gas);

  var overBudget = new Array(GAS_CAP + 501).join("keep;\n");
  var storedOk = handle.mailbox.sieveScripts.put(actor, "expensive", overBudget);
  count("a script that outruns the budget is still inside the storage ceiling",
    storedOk.ok === true, String(Buffer.byteLength(overBudget, "utf8")) + " bytes");

  var thrown = null;
  try { b.mail.sieve.runScript(overBudget, env, { profile: "strict" }); }
  catch (e) { thrown = e; }
  count("and the interpreter refuses it rather than running it out",
    thrown !== null && thrown.code === "mail-sieve/gas-exhausted",
    thrown === null ? "ran to completion" : thrown.code + " " + thrown.message);

  handle.mailbox.sieveScripts.delete(actor, "expensive");
}

// ---- runner ----------------------------------------------------------------

// ---------------------------------------------------------------------------
// A deleted script leaves nothing of itself on the volume
// ---------------------------------------------------------------------------

// The table a filter script lives in, and the two columns of it that
// are sealed. Named here rather than reached for through a helper,
// because what is being read is the row as it is written rather than as
// the store hands it back.
var SIEVE_TABLE = "blamepost_mailbox_sieve";

// Every file the store keeps, under both of the places it keeps them:
// the working copy the database is open against, and the encrypted
// volume it is flushed to.
function storeFiles(dirs) {
  var out = [];
  dirs.forEach(function walkOne(dir) {
    var entries;
    try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
    catch (_e) { return; }
    for (var i = 0; i < entries.length; i += 1) {
      var full = nodePath.join(dir, entries[i].name);
      if (entries[i].isDirectory()) walkOne(full);
      else out.push(full);
    }
  });
  return out;
}

function filesHolding(paths, needle) {
  var found = [];
  var bytes = Buffer.from(needle, "utf8");
  for (var i = 0; i < paths.length; i += 1) {
    var buf;
    try { buf = nodeFs.readFileSync(paths[i]); }
    catch (_e) { continue; }
    if (buf.indexOf(bytes) !== -1) found.push(nodePath.basename(paths[i]));
  }
  return found;
}

// A filter script names the correspondents its owner sorts on and the
// addresses they forward to, so both its name and its body are sealed
// columns. What deleting one owes is that the script is removed rather
// than unlinked: a row unlinked from a B-tree leaves its bytes in the
// page until some later write happens to reuse the slot, and those
// bytes are what a forensic read of the volume recovers.
//
// The disposal is settled by the database this server composes, which
// is opened with SQLite's secure delete, so freed content is overwritten
// rather than abandoned. That is a property of the vendored framework
// rather than one this repository implements, which is exactly why it is
// asserted here against the volume: nothing else in this tree would
// notice a refresh that stopped setting it, and the first sign would be
// a script somebody deleted turning up in a disk image.
//
// The ciphertext is read out of the row before the delete and looked for
// afterwards, byte for byte, in every file the store keeps. Looking for
// the plaintext would prove nothing, because it was never written to the
// volume at all, which the first two checks establish. A third check
// finds the ciphertext while the script is still stored, so a search
// that comes back empty afterwards cannot be a search that was reaching
// the wrong files.
function aDeletedScriptLeavesNothingOfItselfBehind(handle, actor, dirs) {
  var NAME = "residue-check";
  var BODY = "# a filter naming somebody\n" +
    "if header :contains \"From\" \"oncology@clinic.example\" { fileinto \"Private\"; }\n";

  var before = {};
  b.db.prepare("SELECT _id FROM " + SIEVE_TABLE).all().forEach(function (row) {
    before[row._id] = true;
  });

  handle.mailbox.sieveScripts.put(actor, NAME, BODY);

  var written = b.db.prepare("SELECT _id, name, body FROM " + SIEVE_TABLE).all()
    .filter(function (row) { return !before[row._id]; });
  count("the script is one new row", written.length === 1, String(written.length));

  var sealedBody = String(written[0].body);
  var sealedName = String(written[0].name);
  count("its body is sealed in the row rather than stored as it was written",
    sealedBody.indexOf("oncology@clinic.example") === -1 && sealedBody !== BODY,
    sealedBody.slice(0, 60));
  count("and so is its name",
    sealedName.indexOf(NAME) === -1, sealedName.slice(0, 60));

  b.db.flushToDisk();
  var present = storeFiles(dirs);
  count("the sealed body is findable on the volume while the script is stored, " +
    "so a search that finds nothing later is a search that was working",
    filesHolding(present, sealedBody).length > 0,
    JSON.stringify(filesHolding(present, sealedBody)));

  handle.mailbox.sieveScripts.delete(actor, NAME);
  count("the script is gone from the store",
    handle.mailbox.sieveScripts.get(actor, NAME) === null);

  b.db.flushToDisk();
  var after = storeFiles(dirs);
  count("and its sealed body is on the volume nowhere",
    filesHolding(after, sealedBody).length === 0,
    JSON.stringify(filesHolding(after, sealedBody)));
  count("nor is the sealed name it was filed under",
    filesHolding(after, sealedName).length === 0,
    JSON.stringify(filesHolding(after, sealedName)));
}

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-sieve-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var handle = await store.open(cfg);
    await handle.domains.add({ domain: "example.com" });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@example.com", password: ACCOUNT_PASSWORD }));
    var bob = actorFor(await handle.accounts.create({
      address: "bob@example.com", password: ACCOUNT_PASSWORD }));

    aScriptIsCheckedBeforeItIsStored(handle, alice);
    theStoreHasCeilings(handle, alice);
    oneScriptIsActiveAtATime(handle, alice);
    renameKeepsTheNamespaceUnambiguous(handle, alice);
    scriptsAreScopedToTheAccountThatWroteThem(handle, alice, bob);
    theInterpreterRunsUnderAnOperationBudget(handle, alice);
    aDeletedScriptLeavesNothingOfItselfBehind(handle, alice, [workDir, dataDir]);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not
      // a test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = { name: "sieve-script-lifecycle", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
