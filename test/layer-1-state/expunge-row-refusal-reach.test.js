// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A hard delete that destroyed the message and could not take the row
 * binding it to a mailbox, and whether what it leaves behind can ever be
 * reached again.
 *
 * The delete path answers per message and reports rather than raises, so
 * a message the volume half gave up comes back under `refused` with the
 * reason `row-not-removed` and the octets are still on the volume. That
 * much is the system working, and the first vector here holds it to
 * that: the caller is told, the trail carries the digest, and nothing
 * claims a destruction that did not happen.
 *
 * The rest of the file is about the sentence that refusal is worth. Every
 * refusal on this path is written as something to come back to: release
 * the order, obtain the grant, clear whatever is holding the file, and
 * run the same verb again. That is only a remediation while the record
 * is still ADDRESSABLE by the verb that named it. Membership on this
 * layer is its own rows intersected with the message store's, and the
 * agent destroys the store row BEFORE this layer removes its own, so a
 * refusal here leaves a row on the outside of the intersection: the
 * message store row it was paired with is gone for good, and no repair
 * to the volume brings it back.
 *
 * What that costs is measured rather than argued. The rerun the operator
 * was told to run answers about the record with the reason it gives an
 * identifier that names nothing, so the second answer and the first
 * disagree about the same row. An account erasure over it reports mail it
 * could not destroy under the same reason, keeps the mailbox row because
 * something is still bound to it, keeps the identity because the mailbox
 * still names it, and settles at `partially-erased` on every run it will
 * ever have. And the message rows are exactly what holds a body against
 * the reference-counted release, so the octets of a message this server
 * was asked to lose stay sealed under the volume's live key, open, on
 * every backup taken afterwards, with no verb anywhere that removes them.
 *
 * The refusal is produced by the framework's own write-once triggers on
 * the message table rather than by a stand-in that patches the delete, so
 * the vector meets the same refusal an operator's records-retention
 * posture produces. Those triggers are recorded in the database, which is
 * why this file holds a volume of its own: a table that refuses every
 * delete is not a state to leave behind for another vector.
 *
 * Run standalone: node test/layer-1-state/expunge-row-refusal-reach.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var mailboxMod = require("../../lib/mail/mailbox");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "held@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The adapter's own table name, read from the module that owns it. The
// triggers below stand on the real table, so a rename has to move them
// with it rather than leaving them on a table nothing writes to.
var MESSAGES = mailboxMod.MESSAGES;

var SUBJECT = "the-message-under-the-request";

function mailFor(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + ADDRESS + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject + "@example.net>\r\n" +
    "\r\nthe body of " + subject + "\r\n", "utf8");
}

function refusalFor(outcome, objectid) {
  var rows = (outcome && outcome.refused) || [];
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].id === objectid || rows[i].objectid === objectid) return rows[i];
  }
  return null;
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("expunge-row-refusal");
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

    var handle = await store.open(cfg);
    try {
      await handle.domains.add({ domain: DOMAIN });
      var account = await handle.accounts.create({
        address: ADDRESS, password: ACCOUNT_PASSWORD });
      var actor = {
        id: account.id, address: account.address, domain: account.domain, roles: ["account"] };

      var stored = handle.mailbox.appendMessage("INBOX", mailFor(SUBJECT), { actor: actor });
      var digest = b.db.from(MESSAGES).where({ objectid: stored.objectid }).first().blobDigest;
      var blobDir  = handle.mailbox.describe().blobDir;
      var bodyPath = mailboxMod.blobPathFor(blobDir, digest);

      count("the message is on the volume with its sealed body beside its row",
        nodeFs.existsSync(bodyPath) &&
        b.db.from(MESSAGES).where({ objectid: stored.objectid }).count() === 1,
        bodyPath);

      var clean = handle.blobs.reconcile({ verify: true });
      count("and the volume reads clean before anything is destroyed",
        clean.ok === true, JSON.stringify({ ok: clean.ok, drift: clean.quotaDrift }));

      // A records-retention posture, declared through the framework's own
      // verb and recorded in the database. Nothing here patches the
      // delete: this is the refusal an operator's own table produces.
      b.db.declareWorm({ tables: [MESSAGES] });

      // ---- the refusal itself, which is the part that works ----------------

      // The verb JMAP `Email/set` `destroyed` and the browser interface's
      // purge both drive, rather than an internal helper.
      var first = await handle.mailbox.expungeObjects(actor, "INBOX", [stored.objectid]);
      var firstRefusal = refusalFor(first, stored.objectid);

      count("a delete the volume half gave up reports the message as refused rather than " +
        "counting it destroyed",
        first.deleted.length === 0 && firstRefusal !== null,
        JSON.stringify(first));
      count("and names the act that did not happen, so the operator knows the octets are " +
        "still stored here",
        firstRefusal !== null && firstRefusal.reason === "row-not-removed",
        JSON.stringify(firstRefusal));
      count("the row the volume kept is still on the volume, which is what the refusal said",
        b.db.from(MESSAGES).where({ objectid: stored.objectid }).count() === 1,
        stored.objectid);

      // The trail is the only place the half no protocol carries can
      // land, and it is what turns "something did not go" into a file
      // somebody can go and look at. It is written through the
      // drop-silent emitter, so it is buffered until the trail is flushed.
      await b.audit.flush();
      var incomplete = b.db.from("audit_log").all().filter(function (r) {
        return String(r.action) === "blamepost.mail.mailbox.destruction_incomplete";
      });
      count("the trail carries the one row that names the body left behind, because no " +
        "protocol reply does",
        incomplete.length === 1 && incomplete[0].outcome === "failure",
        JSON.stringify(incomplete.map(function (r) { return r.action + "/" + r.outcome; })));
      count("and it names the body by the digest `blobs report` files it under",
        incomplete.length === 1 && String(incomplete[0].resourceId) === digest,
        JSON.stringify(incomplete.length === 1
          ? { kind: incomplete[0].resourceKind, id: incomplete[0].resourceId }
          : null));

      // ---- and the part the refusal is worth ------------------------------

      // Every refusal on this path tells the operator to clear what is
      // holding the record and run the verb again. A rerun is only a
      // remediation while the verb can still see the record it named.
      var second = await handle.mailbox.expungeObjects(actor, "INBOX", [stored.objectid]);
      var secondRefusal = refusalFor(second, stored.objectid);

      count("running the same delete again reaches the record the first run named, rather " +
        "than answering about it with the reason reserved for an identifier that names " +
        "nothing here",
        secondRefusal !== null && secondRefusal.reason !== "not-in-folder",
        JSON.stringify(second));

      // The account erasure is the other verb that has to reach it, and
      // the one an Article 17 answer is built out of.
      var erased = await handle.accounts["delete"]({
        id: account.id, reason: "erasure requested by the account holder", destroy: true,
      });
      var mailStuck = erased.mailFailed[0] || null;

      count("an erasure over the same record reports mail it could not destroy",
        erased.mailFailed.length === 1, JSON.stringify(erased.mailFailed));
      count("and names what is actually keeping it, so the operator can act on the same " +
        "condition the delete path reported",
        mailStuck !== null && mailStuck.reason !== "not-in-folder",
        JSON.stringify(mailStuck));

      // The remediation, taken twice. A record that cannot be reached is
      // one the erasure settles at the same partial answer on every run
      // it will ever have, and an account that can never finish erasing
      // is the state the ordering of this verb exists to stop producing.
      var againErased = await handle.accounts["delete"]({
        id: account.id, reason: "erasure requested by the account holder", destroy: true,
      });
      count("and a rerun makes progress on it rather than settling at the same answer for " +
        "the life of the volume",
        againErased.mailErased > 0 || againErased.outcome === "destroyed",
        JSON.stringify({
          outcome: againErased.outcome, mailErased: againErased.mailErased,
          mailFailed: againErased.mailFailed,
        }));

      // The rows are what hold a body against the reference-counted
      // release, so a row nothing can remove is a body nothing can free.
      var afterReclaim = await handle.blobs.reclaim({
        reason: "freeing the octets of a message that was asked to be destroyed",
      });
      count("the octets of a message this server was asked to lose are not still readable " +
        "on the volume after every verb that removes one has run",
        !nodeFs.existsSync(bodyPath),
        JSON.stringify({
          bodyPath:  bodyPath,
          reclaimed: afterReclaim.reclaimed.length,
          heldBack:  afterReclaim.heldBack.length,
          skipped:   afterReclaim.skipped.length,
          failed:    afterReclaim.failed.length,
        }));

      // The reconciliation is the reading an operator runs on a schedule,
      // and it does see this state. Held here as the answer that works,
      // so a change that stopped it reporting is caught with the rest.
      var drifted = handle.blobs.reconcile({ verify: true });
      count("the volume report refuses to call this clean, and names the mailbox charged " +
        "for mail no protocol lists",
        drifted.ok === false && drifted.quotaDrift.length === 1 &&
        drifted.quotaDrift[0].rowCount > drifted.quotaDrift[0].storeCount,
        JSON.stringify(drifted.quotaDrift));
    } finally {
      handle.close();
    }

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
  name:      "expunge-row-refusal-reach",
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
