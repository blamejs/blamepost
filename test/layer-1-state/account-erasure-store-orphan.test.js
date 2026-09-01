// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An account erasure and the one message it cannot see.
 *
 * Erasing an account destroys the mail first, and the set it destroys is
 * built by reading THIS layer's message rows per mailbox. That set is not
 * the mail. A message lives on two layers, and the two are written one
 * after the other: `blamepost.mail.mailbox.appendMessage` writes the
 * sealed octets, then the message store's row, then this layer's row. A
 * process that stops between the second and the third leaves the store
 * holding a message this layer never recorded, and so does a rollback the
 * store refuses, which is the case
 * `blamepost.mail.mailbox.filing_not_rolled_back` is recorded for. The two
 * routes end in the identical state.
 *
 * That message is outside every read the erasure takes, so an Article 17
 * erasure walks past it. What survives is the message itself: the message
 * store seals the subject, the correspondents and the body in its own
 * row, and that row opens exactly as it did before, on this volume and in
 * every backup taken afterwards. The account it belonged to is gone, so
 * nothing is left to run the erasure against a second time.
 *
 * The reach is narrow and the consequence is not, which is why it is
 * pinned here rather than left to the audit row that reports the
 * interruption.
 *
 * WHAT THE SWEEP MAY NOT DO is the other half of these vectors. A message
 * store row carries the per-message preservation flag `b.mail.agent.expunge`
 * reads and the arrival stamp the retention floor is measured against, so
 * an erasure that reached past the agent to the store's own destructive
 * call would destroy the record a court ordered kept and write no audit row
 * saying so. The sweep therefore goes through the same agent every other
 * hard delete on this server goes through, and a message the agent keeps
 * keeps its mailbox row with it: a preserved message addressed through a
 * mailbox nothing answers to is a record the operator cannot name for the
 * court that asked for it.
 *
 * Run standalone: node test/layer-1-state/account-erasure-store-orphan.test.js
 */

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The mailbox adapter's own table name, read here rather than imported so
// a rename shows up as a failing vector against the shipped schema rather
// than following the source silently.
var FOLDERS = "blamepost_mailbox_folders";

var SECRET_SUBJECT = "the-unfiled-subject";
var SECRET_BODY    = "the body nobody was supposed to keep";

function mailFor(address, subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + address + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + SECRET_BODY + " (" + subject + ")\r\n", "utf8");
}

function actorFor(row) {
  return { id: row.id, address: row.address, domain: row.domain, roles: ["account"] };
}

function storeFolderOf(handle, actor, wireName) {
  return handle.mailbox.accountFolders(actor)
    .filter(function (f) { return f.name === wireName; })[0].storeName;
}

/**
 * An account holding two ordinary messages and one the store has and this
 * layer does not.
 *
 * The unfiled message is made by calling the message store's own append on
 * its own, which is the second of the three writes `appendMessage` makes
 * and exactly the state an interruption after it leaves. It is also the
 * state a refused rollback leaves, since the rollback's only act is to take
 * that row back.
 */
async function seedAccount(handle, address) {
  var row   = await handle.accounts.create({ address: address, password: ACCOUNT_PASSWORD });
  var actor = actorFor(row);
  var folder = storeFolderOf(handle, actor, "INBOX");

  var filed = [];
  filed.push(handle.mailbox.appendMessage("INBOX", mailFor(address, "ordinary-one"),
    { actor: actor }).objectid);
  filed.push(handle.mailbox.appendMessage("INBOX", mailFor(address, "ordinary-two"),
    { actor: actor }).objectid);

  var unfiled = handle.messageStore.appendMessage(folder, mailFor(address, SECRET_SUBJECT), {});

  return {
    row:      row,
    actor:    actor,
    folder:   folder,
    filed:    filed,
    unfiled:  unfiled.objectid,
  };
}

// Whether the message store still answers for a message, and whether what
// it answers with is readable. A row that comes back with the subject and
// the body in the clear is mail, whatever table it is in.
function readableInStore(handle, folder, objectid) {
  var row = handle.messageStore.fetchByObjectId(folder, objectid);
  if (row === null || row === undefined) return null;
  return JSON.stringify(row);
}

function storeRowCount(handle, folder) {
  return handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 10000 }).length;
}

// ---- the erasure reaches the message no mailbox row names ------------------

async function anErasureDestroysTheUnfiledMessageToo(handle, seeded) {
  count("the fixture holds a message the store has and this layer has no row for",
    storeRowCount(handle, seeded.folder) === 3 &&
    b.db.from("blamepost_mailbox_messages").where({ folder: seeded.folder }).count() === 2,
    JSON.stringify({
      store: storeRowCount(handle, seeded.folder),
      here:  b.db.from("blamepost_mailbox_messages").where({ folder: seeded.folder }).count(),
    }));

  var before = readableInStore(handle, seeded.folder, seeded.unfiled);
  count("and before the erasure that message is readable, subject and body in the clear",
    before !== null &&
    before.indexOf(SECRET_SUBJECT) !== -1 && before.indexOf(SECRET_BODY) !== -1,
    String(before).slice(0, 200));

  var swept = await handle.mailbox.eraseAccountMail(seeded.actor, seeded.row.id, {
    reason: "erasure requested by the account holder",
  });

  count("the erasure destroys the message no mailbox row names, rather than walking " +
    "past it because this layer never recorded it",
    readableInStore(handle, seeded.folder, seeded.unfiled) === null,
    String(readableInStore(handle, seeded.folder, seeded.unfiled)).slice(0, 200));

  count("and the mailbox holds no stored message at all afterwards",
    storeRowCount(handle, seeded.folder) === 0,
    JSON.stringify({ left: storeRowCount(handle, seeded.folder) }));

  count("the report counts it among what was destroyed",
    swept.destroyed.length === 3,
    JSON.stringify({ destroyed: swept.destroyed.length, refused: swept.refused.length }));

  count("and says how much of that was mail no mailbox row named, because an operator " +
    "answering the request cannot see it any other way",
    swept.unfiledErased === 1 && swept.unfiledKept === 0,
    JSON.stringify({ erased: swept.unfiledErased, kept: swept.unfiledKept }));

  var entry = swept.destroyed.filter(function (e) { return e.objectid === seeded.unfiled; })[0];
  count("the entry for it names the mailbox and marks it as mail no row here named",
    entry !== undefined && entry.mailbox === "INBOX" && entry.unfiled === true,
    JSON.stringify(entry === undefined ? null : entry));

  var ordinary = swept.destroyed.filter(function (e) {
    return seeded.filed.indexOf(e.objectid) !== -1;
  });
  count("and the ordinary messages carry the same field saying they were filed here",
    ordinary.length === 2 && ordinary.every(function (e) { return e.unfiled === false; }),
    JSON.stringify(ordinary));

  count("the mailbox row goes, because nothing on either layer is still bound to it",
    b.db.from(FOLDERS).where({ account: seeded.row.id }).count() === 0 &&
    swept.mailboxesKept === 0,
    JSON.stringify({
      rows: b.db.from(FOLDERS).where({ account: seeded.row.id }).count(),
      kept: swept.mailboxesKept,
    }));

  var rows = b.db.from("audit_log").all().filter(function (r) {
    return r.action === "blamepost.mail.mailbox.account_mail_erased";
  });
  count("the audit row records how much of the destruction reached mail no mailbox " +
    "row named",
    rows.length === 1 && rows[0].metadata &&
    JSON.parse(typeof rows[0].metadata === "string" ? rows[0].metadata : "{}")
      .messagesUnfiledErased === 1,
    JSON.stringify(rows.length === 1 ? rows[0].metadata : null));
}

// ---- a preservation order outranks the sweep -------------------------------

// The order is placed through the verb an operator drives, not by setting
// the store's flag underneath it. A hold that the placing verb cannot reach
// is one an operator cannot place, and a sweep that destroys mail no order
// can be placed on is a sweep with no preservation order in front of it at
// all.
async function anOrderOnAnUnfiledMessageStopsTheSweep(handle, seeded) {
  var placed = await handle.mailbox.legalHold.place(seeded.actor, "INBOX", [seeded.unfiled], {
    reason: "preservation order, matter 2026-11",
  });

  count("a preservation order can be placed on a message no mailbox row names, so the " +
    "mail the sweep can now destroy is mail an order can now protect",
    placed && Array.isArray(placed.held) && placed.held.indexOf(seeded.unfiled) !== -1,
    JSON.stringify(placed));

  var swept = await handle.mailbox.eraseAccountMail(seeded.actor, seeded.row.id, {
    reason: "erasure requested by the account holder",
  });

  count("the erasure keeps it, because the agent reads the order and the sweep goes " +
    "through the agent rather than around it",
    readableInStore(handle, seeded.folder, seeded.unfiled) !== null,
    JSON.stringify({ left: storeRowCount(handle, seeded.folder) }));

  var kept = swept.refused.filter(function (e) { return e.objectid === seeded.unfiled; })[0];
  count("and reports it as a record something is deliberately keeping rather than as a " +
    "fault, because those two need opposite responses",
    kept !== undefined && kept.reason === "legal-hold" && kept.preserved === true &&
    kept.unfiled === true,
    JSON.stringify(kept === undefined ? null : kept));

  count("the count of mail no mailbox row named separates what went from what stayed",
    swept.unfiledErased === 0 && swept.unfiledKept === 1,
    JSON.stringify({ erased: swept.unfiledErased, kept: swept.unfiledKept }));

  count("the ordinary messages still went, so one held record does not stop the rest " +
    "of the request",
    swept.destroyed.length === 2, JSON.stringify(swept.destroyed));

  count("and the mailbox row is KEPT, because a preserved message addressed through a " +
    "mailbox nothing answers to is one the operator cannot name for the court",
    b.db.from(FOLDERS).where({ account: seeded.row.id }).count() === 1 &&
    swept.mailboxesKept === 1,
    JSON.stringify({
      rows: b.db.from(FOLDERS).where({ account: seeded.row.id }).count(),
      kept: swept.mailboxesKept,
    }));

  // The remedy the report offers, taken. An order that cannot be lifted is
  // not an order, and a sweep that can never finish is the state this whole
  // path exists to avoid producing.
  await handle.mailbox.legalHold.release(seeded.actor, "INBOX", [seeded.unfiled], {
    reason:   "the order was lifted",
    approver: "records@" + DOMAIN,
  });
  var again = await handle.mailbox.eraseAccountMail(seeded.actor, seeded.row.id, {
    reason: "erasure rerun once the order lifted",
  });
  count("once the order is lifted the rerun the operator was told to run reaches it",
    readableInStore(handle, seeded.folder, seeded.unfiled) === null &&
    again.unfiledErased === 1,
    JSON.stringify({ erased: again.unfiledErased, left: storeRowCount(handle, seeded.folder) }));
  count("and the mailbox row goes on that run, because nothing is bound to it any more",
    b.db.from(FOLDERS).where({ account: seeded.row.id }).count() === 0,
    JSON.stringify({ rows: b.db.from(FOLDERS).where({ account: seeded.row.id }).count() }));
}

// ---- the retention floor outranks it too -----------------------------------

// A different volume, because the floor is set by the operator's posture
// and the posture is read when the server is composed.
async function theRetentionFloorStopsTheSweep(root) {
  var dataDir = path.join(root, "floor-data");
  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:            HOSTNAME,
      BLAMEPOST_DATA_DIR:            dataDir,
      BLAMEPOST_VAULT_PASSPHRASE:    VAULT_PASSPHRASE,
      BLAMEPOST_COMPLIANCE_POSTURE:  "soc2",
    },
    cwd: root,
  });
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var seeded = await seedAccount(handle, "floored@" + DOMAIN);

    var swept = await handle.mailbox.eraseAccountMail(seeded.actor, seeded.row.id, {
      reason: "erasure requested by the account holder",
    });

    count("under a posture the floor keeps a message no mailbox row names, measured on " +
      "the arrival the server stamped rather than on a date a client sent",
      readableInStore(handle, seeded.folder, seeded.unfiled) !== null,
      JSON.stringify({ left: storeRowCount(handle, seeded.folder) }));

    var kept = swept.refused.filter(function (e) { return e.objectid === seeded.unfiled; })[0];
    count("and it is reported under the floor's own reason, with the same word every " +
      "other wire on this server answers with",
      kept !== undefined && kept.reason === "retention-floor" && kept.preserved === true &&
      kept.unfiled === true,
      JSON.stringify(kept === undefined ? null : kept));

    count("the counts say one was kept and none went",
      swept.unfiledErased === 0 && swept.unfiledKept === 1,
      JSON.stringify({ erased: swept.unfiledErased, kept: swept.unfiledKept }));
  } finally {
    if (store.isOpen()) store.close();
  }
}

// ---- the empty case --------------------------------------------------------

// A mailbox whose two layers agree pays nothing and reports nothing, which
// is the answer for every account on a healthy volume.
async function anAccountWithNoUnfiledMailReportsNone(handle) {
  var row   = await handle.accounts.create({
    address: "tidy@" + DOMAIN, password: ACCOUNT_PASSWORD });
  var actor = actorFor(row);
  handle.mailbox.appendMessage("INBOX", mailFor(row.address, "ordinary"), { actor: actor });

  var swept = await handle.mailbox.eraseAccountMail(actor, row.id, {
    reason: "erasure requested by the account holder",
  });
  count("an account whose two layers agree reports no mail outside the mailbox rows",
    swept.unfiledErased === 0 && swept.unfiledKept === 0 && swept.destroyed.length === 1,
    JSON.stringify({
      erased:    swept.unfiledErased,
      kept:      swept.unfiledKept,
      destroyed: swept.destroyed.length,
    }));
}

async function run() {
  var root    = helpers.tempDir("erasure-store-orphan");
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
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

      await anErasureDestroysTheUnfiledMessageToo(handle,
        await seedAccount(handle, "erased@" + DOMAIN));
      await anOrderOnAnUnfiledMessageStopsTheSweep(handle,
        await seedAccount(handle, "ordered@" + DOMAIN));
      await anAccountWithNoUnfiledMailReportsNone(handle);
    } finally {
      if (store.isOpen()) store.close();
    }

    await theRetentionFloorStopsTheSweep(root);

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
  name:      "account-erasure-store-orphan",
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
