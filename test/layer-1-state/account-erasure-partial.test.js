// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An account erasure that cannot erase everything the account holds, and
 * what the operator is left with when it cannot.
 *
 * Erasing an account destroys mail first and the identity last, and the
 * destruction is irreversible the moment it starts. Nothing can be read
 * back afterwards to find out what happened, so the report the call
 * returns is the whole of the record. That makes one failure mode worse
 * than every other here: a refusal raised as an exception on the far side
 * of the destruction takes the report with it. The mail is gone, the
 * account is still on the table, and the audit chain holds no row saying
 * the mail was ever destroyed. An operator answering an Article 17
 * request has no way to find out that the erasure half ran.
 *
 * The messages already answer in that shape: a message a preservation
 * order or the retention floor keeps comes back under `refused` and the
 * call still returns. So do the mailbox rows. The account's other
 * material, its filter scripts and its annotations, went through a bare
 * erase whose refusal escaped, which is what these vectors pin.
 *
 * Both refusals are produced by framework gates rather than by a stand-in
 * that patches the erase, so the vector exercises the same code path an
 * operator's volume would. A dual-control gate on the Sieve table makes
 * the erase refuse the way a gate wanting a second approver does, which
 * is something being kept on purpose. Write-once triggers on the
 * annotation table make it refuse the way storage does, which is a fault.
 * The two need opposite responses from whoever reads the result, and both
 * have to reach them.
 *
 * A row that stayed has to stay REACHABLE, which is the second thing
 * these vectors measure. The identity is what every surface resolves a
 * record through, so it goes only once nothing the account holds still
 * names it, and a filter script or an annotation a gate kept names it
 * exactly as a mailbox row does. An identity erased over one of those
 * leaves a row carrying an account id that resolves to nothing: no verb
 * reaches it, and it is on the volume and in every backup taken
 * afterwards.
 *
 * The identity step is two writes that can be refused in the same way,
 * and both run after the mail has gone.
 * `test/layer-1-state/account-erasure-identity.test.js` drives those,
 * from a volume of its own: the gates it needs stand on the account
 * table, and every account this file erases goes through that table.
 *
 * The third vector measures how far a preservation order actually
 * reaches, rather than assuming it covers everything the account owns.
 *
 * Run standalone: node test/layer-1-state/account-erasure-partial.test.js
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

// One account per vector, because the first vector destroys the mail of
// the account it runs on and the second has to drive the same erasure
// from the command line.
var LIBRARY_ADDRESS = "gated@" + DOMAIN;
var CLI_ADDRESS     = "spooled@" + DOMAIN;
var ORDER_ADDRESS   = "ordered@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The adapter's own table names. They are read here rather than imported
// so a rename shows up as a failing vector against the shipped schema
// instead of following the source silently.
var SCRIPTS  = "blamepost_mailbox_sieve";
var METADATA = "blamepost_mailbox_metadata";
var FOLDERS  = "blamepost_mailbox_folders";

var SCRIPT_NAME = "filing";
var SCRIPT_BODY = 'require ["fileinto"];\r\nfileinto "Archive";\r\n';
var ANNOTATION  = "/private/comment";

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

// Everything one account holds on the mailbox layer: a message, a filter
// script and an annotation, so an erasure of it has all three to reach.
async function seedAccount(handle, address) {
  var row   = await handle.accounts.create({ address: address, password: ACCOUNT_PASSWORD });
  var actor = actorFor(row);
  var stored = handle.mailbox.appendMessage("INBOX", mailFor(address, "ordinary-mail"),
    { actor: actor });
  await handle.mailbox.sieveScripts.put(actor, SCRIPT_NAME, SCRIPT_BODY);
  handle.mailbox.setMetadata(actor, "INBOX", [{ entry: ANNOTATION, value: "a note" }]);
  return { row: row, actor: actor, objectid: stored.objectid };
}

function rowsFor(table, accountId) {
  return b.db.from(table).where({ account: accountId }).count();
}

// The metadata blob off one audit row, whichever way the column comes
// back. The framework serializes it to JSON on the way in, and a reader
// that assumed one of the two shapes would report a missing count as a
// failing assertion about the erasure rather than about itself.
function metadataOf(row) {
  if (!row) return null;
  var raw = row.metadata;
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "object") return raw;
  try { return JSON.parse(String(raw)); }
  catch (_e) { return null; }
}

// ---- the library path ------------------------------------------------------

// The verb an operator's erasure actually runs, driven through the store
// handle. What is asserted is the RETURNED report and the audit row,
// never a thrown error, because the defect is precisely that a throw
// replaces the report.
async function theLibraryReportsWhatItCouldNotErase(cfg, seeded) {
  var handle = await store.open(cfg);
  var thrown = null;
  var removed = null;
  try {
    try {
      removed = await handle.accounts["delete"]({
        id:      seeded.row.id,
        reason:  "erasure requested by the account holder",
        destroy: true,
      });
    } catch (e) { thrown = e; }

    count("erasing an account whose filter scripts and annotations both refuse to be " +
      "erased answers with a report rather than raising, because the mail is already " +
      "destroyed by the time either of them is reached",
      thrown === null && removed !== null,
      thrown === null ? "nothing was thrown" : helpers.formatErr(thrown));

    count("and the mail it was asked to destroy really did go",
      removed.mailErased === 1, JSON.stringify({ mailErased: removed.mailErased }));

    // What the report calls mail has to be mail. The adapter answers with
    // one refusal list carrying four kinds of record, and only one of them
    // is a message: the mailbox rows something is still bound to, the
    // account's filter scripts and its annotations arrive in the same
    // list. A number under a name that says mail is what an operator
    // answers a preservation order or an Article 17 request with, so an
    // annotation folded into it overstates how much of somebody's mail
    // survived the erasure.
    var recordsPreserved = Array.isArray(removed.recordsPreserved)
      ? removed.recordsPreserved : [];
    var recordsFailed = Array.isArray(removed.recordsFailed)
      ? removed.recordsFailed : [];
    count("the report carries the account's other records in lists of their own, so a " +
      "filter script or an annotation is never counted as a message",
      Array.isArray(removed.recordsPreserved) && Array.isArray(removed.recordsFailed),
      JSON.stringify({
        recordsPreserved: removed.recordsPreserved,
        recordsFailed:    removed.recordsFailed,
      }));

    var notMail = removed.mailPreserved.concat(removed.mailFailed)
      .filter(function (entry) {
        return entry.objectid === null || entry.objectid === undefined;
      });
    count("and nothing without a message identifier is listed under either name that says " +
      "mail, because those two lists are what a count of the subject's surviving mail is " +
      "read off",
      notMail.length === 0, JSON.stringify(notMail));

    var kinds = recordsPreserved.concat(recordsFailed).map(function (entry) {
      return entry.record || entry.objectid || entry.mailbox;
    });

    var script = recordsPreserved.filter(function (entry) {
      return /filter script/.test(String(entry.record));
    });
    count("the filter script a gate is holding back comes back as preserved, so an " +
      "erasure held up by a second approver is not reported as a fault",
      script.length === 1 && script[0].reason === "db/erase-hard-dual-control-required",
      JSON.stringify(recordsPreserved));
    count("and the entry names the script rather than only the table it was in, because " +
      "the operator has to be able to find the row the gate is holding",
      script.length === 1 && String(script[0].record).indexOf(SCRIPT_NAME) !== -1,
      JSON.stringify(script));

    var annotation = recordsFailed.filter(function (entry) {
      return /annotation/.test(String(entry.record));
    });
    count("the annotation storage refused comes back as a fault rather than as something " +
      "kept on purpose, because nothing chose to keep it",
      annotation.length === 1 && annotation[0].preserved !== true,
      JSON.stringify(recordsFailed));
    count("and it names the annotation and the mailbox it was set on",
      annotation.length === 1 &&
      String(annotation[0].record).indexOf(ANNOTATION) !== -1 &&
      String(annotation[0].record).indexOf("INBOX") !== -1,
      JSON.stringify(annotation));

    count("neither row is counted as erased, so the counts describe what went rather " +
      "than what was attempted",
      removed.mailErased === 1 && kinds.length === 2, JSON.stringify(kinds));

    count("and both rows are still on the volume, which is what the report says",
      rowsFor(SCRIPTS, seeded.row.id) === 1 && rowsFor(METADATA, seeded.row.id) === 1,
      JSON.stringify({
        scripts:     rowsFor(SCRIPTS, seeded.row.id),
        annotations: rowsFor(METADATA, seeded.row.id),
      }));

    // A row that stayed and a row that can be reached are two different
    // claims, and only the second one is worth anything to the person
    // answering for the record. Every verb that could produce one resolves
    // the account first, so an identity erased over a row it still owns
    // leaves that row addressable by nothing at all.
    count("an erasure a filter script and an annotation were held back from is reported " +
      "as partial rather than as finished",
      removed.outcome === "partially-erased", JSON.stringify({ outcome: removed.outcome }));

    var keptIdentity = handle.accounts.get(seeded.row.id);
    count("the identity is kept, because rows this erasure could not destroy still name it",
      keptIdentity !== null, JSON.stringify({ account: keptIdentity }));
    count("and it is out of service and marked as erasing, so the unfinished job is visible",
      keptIdentity !== null && keptIdentity.status === "erasing",
      JSON.stringify(keptIdentity === null ? null : keptIdentity.status));

    var strandedScript = b.db.from(SCRIPTS).where({ account: seeded.row.id }).all()[0];
    count("the filter script the gate is holding still names an account that resolves, " +
      "rather than an id nothing on the volume answers to",
      strandedScript !== undefined &&
      handle.accounts.get(String(strandedScript.account)) !== null,
      JSON.stringify({ names: strandedScript && strandedScript.account }));
    var strandedAnnotation = b.db.from(METADATA).where({ account: seeded.row.id }).all()[0];
    count("and so does the annotation storage refused",
      strandedAnnotation !== undefined &&
      handle.accounts.get(String(strandedAnnotation.account)) !== null,
      JSON.stringify({ names: strandedAnnotation && strandedAnnotation.account }));

    // An annotation names a mailbox as well as an account, and the same
    // rule has to hold one level in. It is filed against the opaque token
    // the adapter generated for the mailbox rather than against the name
    // its owner chose, so a mailbox row erased while an annotation still
    // names it leaves that annotation pointing at nothing: no verb reaches
    // it, and the report an operator runs the erasure again on can no
    // longer say which of their mailboxes it was set on.
    var namedFolder = strandedAnnotation === undefined
      ? null
      : b.db.from(FOLDERS).where({ folder: String(strandedAnnotation.folder) }).first();
    count("the mailbox the annotation was set on still has a row, so the record that " +
      "stayed is reachable through the same chain every surface resolves one through",
      !!namedFolder,
      JSON.stringify({ folder: strandedAnnotation && strandedAnnotation.folder }));
    count("and that mailbox is counted as kept rather than erased, because something it " +
      "holds could not be destroyed",
      removed.mailboxesKept >= 1,
      JSON.stringify({ kept: removed.mailboxesKept, erased: removed.mailboxesErased }));

    // The audit trail is the only record that survives the data. A run
    // that destroyed mail and wrote nothing is the outcome this whole
    // vector exists to stop.
    var rows = b.db.from("audit_log").all().filter(function (r) {
      return r.action === "blamepost.mail.mailbox.account_mail_erased";
    });
    count("the erasure filed its own audit row, so the destruction is recorded even " +
      "though part of it was refused",
      rows.length === 1, JSON.stringify(rows.map(function (r) { return r.action; })));
    count("and the row records the destruction as a failure, because something that was " +
      "not kept on purpose could not be erased",
      rows.length === 1 && rows[0].outcome === "failure",
      JSON.stringify(rows.length === 1 ? rows[0].outcome : null));

    var identityRows = b.db.from("audit_log").all().filter(function (r) {
      return r.action === "account.destroyed" || r.action === "account.erasure_held";
    });
    count("and it is recorded as an erasure held back rather than as an account destroyed, " +
      "because the identity is still on the table answering for the rows that stayed",
      identityRows.length === 1 && identityRows[0].action === "account.erasure_held",
      JSON.stringify(identityRows.map(function (r) { return r.action; })));

    // The trail is read long after the report has gone, and the question
    // it is read with is how much of one subject's mail is still on the
    // volume. A filter script counted under a name that says mail answers
    // that question with a number nobody can act on, and it answers it in
    // the direction that overstates what survived.
    var heldMeta = metadataOf(identityRows.length === 1 ? identityRows[0] : null);
    count("the row counts the annotation and the filter script apart from the mail, so a " +
      "count of the subject's surviving messages is a count of messages",
      heldMeta !== null && heldMeta.mailPreserved === 0 && heldMeta.mailFailed === 0 &&
      heldMeta.recordsPreserved === 1 && heldMeta.recordsFailed === 1,
      JSON.stringify(heldMeta));

    // The remediation the report offers, taken. An operator releases what
    // they can and runs the same command again, and the second report is
    // worth exactly as much as the first is readable: a line naming an
    // annotation on a mailbox that has already gone tells them which
    // record is still on the volume and nothing about where to look for
    // it. Run last, because it files a second erasure row and the counts
    // above are about the first.
    var again = await handle.accounts["delete"]({
      id:      seeded.row.id,
      reason:  "erasure requested by the account holder",
      destroy: true,
    });
    var annotationAgain = (Array.isArray(again.recordsFailed) ? again.recordsFailed : [])
      .filter(function (entry) {
        return /annotation/.test(String(entry.record));
      });
    count("running the erasure again still names the mailbox the annotation was set on, " +
      "rather than one the first run erased out from under it",
      annotationAgain.length === 1 &&
      String(annotationAgain[0].record).indexOf("INBOX") !== -1,
      JSON.stringify(again.recordsFailed));
  } finally {
    handle.close();
  }
}

// ---- the command line ------------------------------------------------------

// The same erasure as an operator runs it. A report the library returns
// and the command line cannot render is a report nobody reads.
function theCommandLineNamesTheRowsThatStayed(run) {
  var erased = run(["account", "remove", CLI_ADDRESS, "--destroy",
    "--reason", "erasure requested by the account holder"]);

  // What an operator reads. A run that ends on the framework's own error
  // rather than on the erasure report prints neither of the two headline
  // forms, which is the shape the exception produced.
  count("the command line renders the erasure report rather than ending on the refusal " +
    "that stopped one of the rows",
    /^(?:Erased|Partly erased) /m.test(erased.stdout),
    "exit " + erased.status + " " + erased.both.slice(0, 400));

  count("and it says how much mail actually went",
    /1 message destroyed across \d+ mailboxe?s?/.test(erased.stdout),
    erased.stdout.slice(0, 600));

  count("the filter script a gate is holding back is named, with the reason it stayed",
    /kept {2}the filter script "filing": db\/erase-hard-dual-control-required/
      .test(erased.stdout), erased.stdout.slice(0, 900));

  count("the annotation that could not be erased is named as a failure rather than as " +
    "something kept on purpose",
    /FAIL {2}the annotation \/private\/comment on INBOX could not be erased/
      .test(erased.stdout), erased.stdout.slice(0, 900));

  // The line that sends an operator to the volume reader, in the state
  // where it is false. Every message this account held was destroyed; a
  // filter script was held back and an annotation faulted, and neither is
  // mail. An operator told their account holder's mail is still readable,
  // and sent to `blobs report --verify` to find out how much, is being
  // told to go and look for something that is not there, in answer to the
  // one request where a wrong answer cannot be corrected afterwards.
  count("an erasure whose only fault was an annotation does not report mail still on the " +
    "volume, because every message it was asked to destroy went",
    !/Mail this server was asked to lose is still on the volume/.test(erased.stdout),
    erased.stdout.slice(0, 1200));
  count("nor the other half of that sentence, which describes rows kept over a message " +
    "that was destroyed and is about mail just as much",
    !/The rest is destroyed and its rows were kept/.test(erased.stdout),
    erased.stdout.slice(0, 1200));

  count("and the exit status is 1, so a script driving a bulk erasure stops on the " +
    "account that needs a person",
    erased.status === 1, "exit " + erased.status + " " + erased.both.slice(0, 300));

  // The remediation is only remediation while there is something to run
  // it against. The verb resolves the account first, so an operator told
  // to run it again over an identity that has gone is told to do
  // something that answers that there is no such address, and the record
  // the line is about is left with nothing naming it. Asserted as the
  // pair rather than as either half, because which half is true depends
  // on whether the identity survived this run.
  count("the operator is never told to run the erasure again over an identity the same " +
    "run destroyed",
    !(/^Erased /m.test(erased.stdout) && /run the same command again/.test(erased.stdout)),
    erased.stdout.slice(0, 900));
  count("nor told that a record held back still resolves to an account that has gone",
    !(/^Erased /m.test(erased.stdout) && /still resolves to this account/.test(erased.stdout)),
    erased.stdout.slice(0, 900));
}

// ---- how far a preservation order reaches ----------------------------------

// Measured rather than assumed. The registry is keyed on an exact subject
// identifier and the only subject this server ever places one under is a
// single message, so an order covers the message it names and nothing
// else the account owns. The operator guide says so because this says so.
async function aPreservationOrderCoversTheMessageItNames(cfg, ordered) {
  var handle = await store.open(cfg);
  try {
    await handle.mailbox.legalHold.place(ordered.actor, "INBOX", [ordered.objectid], {
      reason:   "preservation order 24-cv-01933",
      citation: "FRCP-26",
    });

    var holds = b.legalHold.create({ db: b.db, audit: b.audit });
    count("an order placed on a message registers that message as the held subject",
      holds.isHeld("message:" + ordered.objectid) === true, ordered.objectid);
    count("and it does not make the account's address a held subject, so nothing that " +
      "asks about the address is answered by an order over one of its messages",
      holds.isHeld(ordered.row.address) === false, ordered.row.address);
    count("nor the account identifier",
      holds.isHeld(ordered.row.id) === false, ordered.row.id);

    // The consequence, driven through the erase the account's own
    // material goes through. The order is in force and the row goes.
    var scriptRow = b.db.from(SCRIPTS).where({ account: ordered.row.id }).all()[0];
    var refusal = null;
    try {
      b.db.eraseHard(SCRIPTS, scriptRow._id, {
        reason:    "measuring what the order reaches",
        subjectId: ordered.row.id,
      });
    } catch (e) { refusal = e; }
    count("so an order over the account's mail does not stop its filter scripts being " +
      "erased, whichever subject the erase names",
      refusal === null && rowsFor(SCRIPTS, ordered.row.id) === 0,
      refusal === null ? "the row was erased" : refusal.code);
  } finally {
    handle.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("account-erasure-partial");
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

    var seeded  = null;
    var ordered = null;
    var handle  = await store.open(cfg);
    try {
      await handle.domains.add({ domain: DOMAIN });
      seeded  = await seedAccount(handle, LIBRARY_ADDRESS);
      await seedAccount(handle, CLI_ADDRESS);
      ordered = await seedAccount(handle, ORDER_ADDRESS);

      count("the fixture holds a message, a filter script and an annotation per account " +
        "before anything is erased",
        rowsFor(SCRIPTS, seeded.row.id) === 1 && rowsFor(METADATA, seeded.row.id) === 1,
        JSON.stringify({
          scripts:     rowsFor(SCRIPTS, seeded.row.id),
          annotations: rowsFor(METADATA, seeded.row.id),
        }));
    } finally {
      handle.close();
    }

    // How far an order reaches is measured on an ungated volume and
    // therefore before the gates below exist. A table already refusing
    // every erase would answer this vector with its own refusal and prove
    // nothing about the order.
    await aPreservationOrderCoversTheMessageItNames(cfg, ordered);

    var gated = await store.open(cfg);
    try {
      // The two gates, declared through the framework's own verbs and
      // recorded in the database, so the child process the command line
      // runs in meets exactly the same refusals this one does. Nothing
      // here patches the erase: a stand-in would prove the report shape
      // and nothing about the path an operator's volume takes.
      b.db.declareRequireDualControl({ tables: [SCRIPTS], m: 2, n: 2 });
      b.db.declareWorm({ tables: [METADATA] });
    } finally {
      gated.close();
    }

    // One handle per process at a time: the database is encrypted at rest
    // and each process decrypts its own working copy, so a handle held
    // open while the child writes would flush a stale snapshot back over
    // the child's work.
    await theLibraryReportsWhatItCouldNotErase(cfg, seeded);

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
    theCommandLineNamesTheRowsThatStayed(cli);

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
  name:      "account-erasure-partial",
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
