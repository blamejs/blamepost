// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What holds an account out of service when the write that marks it
 * cannot be made.
 *
 * A destroy that cannot finish leaves the row behind and marks it
 * `erasing`, and that word is what every sibling verb reads: suspend,
 * reinstate and the archive branch of delete all refuse it, which is
 * what keeps an outstanding erasure from being archived and then
 * reinstated back into a working mailbox whose mail is gone.
 *
 * The mark is one write, and the code around it already expects that
 * write to fail. It is made inside a guard whose comment names the
 * result as the worst state the verb can end in. What that guard does
 * about it is report it. The row keeps whatever status it had, which is
 * a state that IS in service, and nothing durable anywhere says an
 * erasure ran against it: there is no second column for it, no
 * re-attempt, and neither the archive branch nor reinstate reads the
 * trail.
 *
 * So the refusals that close the path are all reading one column, and
 * the write to that column is the one the verb is allowed to lose. This
 * asks whether the path is still closed when it is lost, by running the
 * two ordinary operator verbs afterwards and looking at what comes back.
 *
 * The fault is placed on the mark itself rather than on every write, so
 * the erasure ahead of it runs exactly as it does in service and only
 * the one write under examination is refused.
 *
 * Run standalone: node test/layer-1-state/account-erasure-mark-refusal.test.js
 */

var helpers    = require("../helpers");
var writeFault = require("../helpers/account-status-write-fault");
var config     = require("../../lib/config");
var store      = require("../../lib/store");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var OWNER_PASSWORD   = "quiet lantern bicycle 4291";
var DOMAIN           = "example.com";
var SUBJECT          = "subject@example.com";
var UNWRITABLE       = "unwritable@example.com";
var ERASURE_REASON   = "erasure requested by the account holder";

function heldMail(address) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + address + ">\r\n" +
    "Subject: held\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <held@example.net>\r\n" +
    "\r\nBody.\r\n", "utf8");
}

function statusOf(identity, address) {
  var row = identity.accounts.get(address);
  return (row === null || row === undefined) ? null : row.status;
}

async function raisedBy(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}

// The two faults are `test/helpers/account-status-write-fault.js`, which
// the delivery-refusal case beside this one drives as well. The first
// refuses the status transition and lets the marker through. The second
// refuses every write to one account row, which is the state no marker
// on the row can survive, and it is the one that says whether anything
// OTHER than the row is holding the account: a fixture that lets any
// write through cannot ask that question, because whatever it let
// through is what answers.

async function testAnErasureThatCouldNotBeMarkedStaysOutOfService(identity) {
  var doomed = await identity.accounts.create({
    address: SUBJECT, password: OWNER_PASSWORD });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"],
  };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(SUBJECT), { actor: owner });
  identity.messageStore.setLegalHold([kept.objectid], { hold: true });

  var restore = writeFault.refuseErasingStatusWrite();
  var partial;
  try {
    partial = await identity.accounts["delete"]({
      id: doomed.id, destroy: true, reason: ERASURE_REASON });
  } finally {
    restore();
  }

  count("the destroy reports that it could not finish",
    partial.outcome === "partially-erased", JSON.stringify(partial.outcome));
  count("and the account row is still there to answer for what was held back",
    identity.accounts.get(SUBJECT) !== null,
    String(statusOf(identity, SUBJECT)));

  // The two ordinary operator verbs, in the order that laundered an
  // outstanding erasure back into a working mailbox before the archive
  // branch learned to refuse one.
  var archived  = await raisedBy(function () {
    return identity.accounts["delete"]({ id: doomed.id, reason: "the owner has left" });
  });
  var reinstated = await raisedBy(function () {
    return identity.accounts.reinstate({ id: doomed.id });
  });

  count("an account whose erasure could not be marked is not returned to service by " +
    "archiving it and reinstating it",
    statusOf(identity, SUBJECT) !== "active",
    JSON.stringify({
      status:     statusOf(identity, SUBJECT),
      archive:    archived === null ? "accepted" : archived.code,
      reinstate:  reinstated === null ? "accepted" : reinstated.code,
    }));
}

// A row the volume will take no write to at all, which is the state no
// marker on the row can survive. It is the column the matrix beside this
// file has no case for: every `erasing` row it stands up is stood up
// through a helper that lets the mark succeed, so it proves the gates
// READ that column and cannot prove anything about a row where the
// column was never written.
//
// The erasure runs, because the mail is the part of the request that
// matters most and a row nothing can write is not a reason to leave
// somebody's mail on the volume. What has to hold afterwards is that
// nothing walks the account back into service, and with the row saying
// nothing the only record left is the one the erasure filed on the
// chain.
async function testAnErasureNoWriteCouldMarkStaysOutOfService(identity) {
  var doomed = await identity.accounts.create({
    address: UNWRITABLE, password: OWNER_PASSWORD });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"],
  };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(UNWRITABLE), { actor: owner });
  identity.messageStore.setLegalHold([kept.objectid], { hold: true });

  var restore = writeFault.refuseEveryWriteTo(doomed.id);
  var partial;
  try {
    partial = await identity.accounts["delete"]({
      id: doomed.id, destroy: true, reason: ERASURE_REASON });
  } finally {
    restore();
  }

  count("the destroy still reports that it could not finish",
    partial.outcome === "partially-erased", JSON.stringify(partial.outcome));
  count("and it names the mark as a write that did not happen, rather than reporting a " +
    "clean erasure",
  partial.identityRefused.some(function (entry) {
    return /marked as erasing/.test(String(entry.record));
  }),
  JSON.stringify(partial.identityRefused));
  count("the row carries no mark of its own, which is the state this case exists to reach",
    statusOf(identity, UNWRITABLE) === "active", String(statusOf(identity, UNWRITABLE)));

  var archived = await raisedBy(function () {
    return identity.accounts["delete"]({ id: doomed.id, reason: "the owner has left" });
  });
  count("archiving is refused over a row carrying no mark at all, because the record the " +
    "erasure filed on the chain is what answers when the row cannot",
  archived !== null && archived.code === "store/account-erasing",
  archived === null ? "accepted" : archived.code);

  var reinstated = await raisedBy(function () {
    return identity.accounts.reinstate({ id: doomed.id });
  });
  count("and so is reinstating it, so the two verbs that laundered an outstanding erasure " +
    "back into service are both closed on the row the column cannot describe",
  reinstated !== null && reinstated.code === "store/account-erasing",
  reinstated === null ? "accepted" : reinstated.code);
}

async function run() {
  var root = helpers.tempDir("erasure-mark");
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(workDir, { recursive: true });

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
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });

    await testAnErasureThatCouldNotBeMarkedStaysOutOfService(identity);
    await testAnErasureNoWriteCouldMarkStaysOutOfService(identity);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name: "account-erasure-mark-refusal",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
