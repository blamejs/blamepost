// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What one message store row with no partner on this layer does to
 * every OTHER message in the same mailbox.
 *
 * Membership is this layer's rows intersected with the message store's,
 * and the intersection is built by reading the store's rows for the
 * folder and matching them against this layer's. The delete path has an
 * answer for one side of a disagreement: a row here whose store partner
 * is gone is found by a second question and finished rather than
 * reported as an identifier naming nothing.
 *
 * The other side of the same disagreement is a store row with no row
 * here, and `blamepost.mail.mailbox.appendMessage` can leave one. It
 * writes the store's row and then this layer's, in that order, in two
 * separate writes with no rollback between them: a process that stops
 * in the gap leaves the store holding a message this layer never
 * recorded. Nothing on this server LISTS that message, and erasing the
 * account it was addressed to is what destroys it, which
 * test/layer-1-state/account-erasure-store-orphan.test.js pins.
 *
 * The cost is not the orphan. The cost is every message filed after it.
 * The store read that builds the intersection is bounded by the number
 * of rows THIS layer holds, so one unmatched row in the store shortens
 * that read by one, and the row it drops is the one the store orders
 * last. What falls out is not the orphan. It is a live message, on
 * both layers, that a client filed afterwards.
 *
 * So the mailbox reports a smaller EXISTS than it holds, FETCH 1:*
 * returns fewer messages than are stored, and the hard delete answers
 * for one of them with the reason reserved for an identifier that names
 * nothing on either layer. And because the store orders that read by
 * modification sequence, WHICH message is hidden moves every time a
 * client marks one read: a message reappears and a different one goes.
 *
 * The orphan is made here by calling the store's own append on its own,
 * which is the first of the two writes `appendMessage` makes and
 * exactly what an interruption after it leaves behind.
 *
 * Run standalone: node test/layer-1-state/mailbox-store-orphan-snapshot.test.js
 */

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var store   = require("../../lib/store");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

function message(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <alice@example.com>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject + "@example.net>\r\n" +
    "\r\n" + subject + " body\r\n", "utf8");
}

function storeFolderOf(handle, actor, wireName) {
  return handle.mailbox.accountFolders(actor)
    .filter(function (f) { return f.name === wireName; })[0].storeName;
}

// The subjects a client can actually read out of the mailbox, in the
// order the mailbox serves them. Read through the wire-facing fetch
// rather than off the tables, because the question is what a client
// sees.
function subjectsVisibleTo(handle, actor) {
  return handle.mailbox.fetchRange(actor, "INBOX", "1:*", "BODY.PEEK[]", {})
    .map(function (entry) {
      var found = /Subject: (\S+)/.exec(entry.payload);
      return found ? found[1] : "(no subject)";
    })
    .sort();
}

async function testAnOrphanedStoreRowHidesLiveMail(handle, alice) {
  var folder = storeFolderOf(handle, alice, "INBOX");

  // The first of the two writes `appendMessage` makes, on its own. This
  // is the state an interruption between them leaves: the store holds
  // the message, this layer never recorded it.
  handle.messageStore.appendMessage(folder, message("interrupted"), {});
  count("the store holds a message this layer has no row for",
    handle.messageStore.queryByModseq(folder, { limit: 1000 }).length === 1 &&
    b.db.from(mailbox.MESSAGES).where({ folder: folder }).count() === 0);

  var filed = [];
  for (var i = 1; i <= 3; i += 1) {
    filed.push(handle.mailbox.appendMessage("INBOX", message("filed" + i),
      { actor: alice }).objectid);
  }

  count("all three messages filed afterwards are on both layers",
    b.db.from(mailbox.MESSAGES).where({ folder: folder }).count() === 3 &&
    filed.every(function (id) {
      return handle.messageStore.fetchByObjectId(folder, id) !== null;
    }));

  var selected = handle.mailbox.selectFolder(alice, "INBOX", {});
  count("SELECT reports every message the mailbox holds, not one fewer for " +
    "each row the store has no partner for",
    selected.exists === 3, "EXISTS " + selected.exists);

  count("FETCH 1:* returns all three",
    subjectsVisibleTo(handle, alice).join(",") === "filed1,filed2,filed3",
    subjectsVisibleTo(handle, alice).join(","));

  return { folder: folder, filed: filed };
}

// The store orders the read that builds membership by modification
// sequence, so anything that changes one message's sequence changes
// which message the shortened read drops. Setting a flag is the most
// ordinary thing a client does.
async function testWhichMessageIsHiddenDoesNotMoveWhenAFlagChanges(handle, alice) {
  var before = subjectsVisibleTo(handle, alice);

  handle.mailbox.storeFlags(alice, "INBOX", "1", "+FLAGS", ["\\Seen"], {});
  var afterSeen = subjectsVisibleTo(handle, alice);
  count("marking a message read does not change which messages the mailbox holds",
    afterSeen.join(",") === before.join(","),
    before.join(",") + " became " + afterSeen.join(","));

  handle.mailbox.storeFlags(alice, "INBOX", "1", "+FLAGS", ["\\Flagged"], {});
  var afterFlagged = subjectsVisibleTo(handle, alice);
  count("nor does flagging one",
    afterFlagged.join(",") === before.join(","),
    before.join(",") + " became " + afterFlagged.join(","));
}

// The store assigns ONE modification sequence to a whole batch, so a
// membership read that RESUMED after the last row it saw would step over
// every other row sharing that sequence. The read raises its bound and
// starts from zero again instead, which has no such seam in it, and this
// is the vector that says so on the batch a client actually produces:
// RFC 9051 section 6.4.5 makes a non-peeking BODY[] a read the server
// records, so `FETCH 1:*` marks every unseen message in one call.
async function testABatchSharingOneSequenceDoesNotMoveMembership(handle, alice) {
  var folder = storeFolderOf(handle, alice, "INBOX");
  var before = subjectsVisibleTo(handle, alice);

  handle.mailbox.fetchRange(alice, "INBOX", "1:*", "BODY[]", {});

  var held = handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 1000 });
  var perSequence = Object.create(null);
  held.forEach(function (entry) {
    perSequence[entry.modseq] = (perSequence[entry.modseq] || 0) + 1;
  });
  var sharedBy = Object.keys(perSequence).map(function (k) { return perSequence[k]; })
    .sort(function (x, y) { return y - x; })[0];

  // Without this the vector is vacuous: a batch that happened to take one
  // sequence per message would satisfy every claim below on a read that
  // had reintroduced the seam.
  count("a single FETCH really does give several messages one shared sequence, which is " +
    "the state a resuming read would lose rows to",
    sharedBy >= 2, JSON.stringify(perSequence));

  var after = subjectsVisibleTo(handle, alice);
  count("and the mailbox holds exactly what it held before the batch",
    after.join(",") === before.join(","), before.join(",") + " became " + after.join(","));

  count("SELECT still reports every message, so the shared sequence cost the mailbox none " +
    "of them",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === before.length,
    "EXISTS " + handle.mailbox.selectFolder(alice, "INBOX", {}).exists +
      " of " + before.length);
}

// Termination is by construction rather than by expectation, and this is
// the construction, measured on the volume rather than read off the
// comment. An answer SHORT of its own bound cannot have been truncated,
// because a limit only ever removes rows; an answer equal to its bound
// may have been. The bound only ever doubles, the folder holds finitely
// many rows, so the bound passes that number and the read taken there is
// short of it.
async function testTheBoundRaisingReadStopsOnItsOwnAnswer(handle, alice) {
  var folder = storeFolderOf(handle, alice, "INBOX");
  var total = handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 100000 }).length;

  var shortAt = null;
  var doublings = 0;
  for (var bound = 1; ; bound *= 2) {
    var held = handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: bound });
    if (held.length < bound) { shortAt = bound; break; }
    doublings += 1;
    // A guard on the vector rather than on the loop: if the rule did not
    // hold, this is what stops the test rather than the runner's clock.
    if (bound > total * 4 + 8) break;
  }

  count("raising the bound reaches an answer short of it, which is the answer a limit " +
    "cannot have truncated",
    shortAt !== null && shortAt > total,
    JSON.stringify({ storeRows: total, shortAt: shortAt, doublings: doublings }));

  count("and it takes no more doublings than the store has rows to hide, so the loop is " +
    "bounded by the folder rather than by luck",
    shortAt !== null && doublings <= Math.ceil(Math.log2(total + 2)) + 1,
    JSON.stringify({ storeRows: total, doublings: doublings }));

  var truncated = [];
  for (var b2 = 1; b2 <= total; b2 *= 2) {
    if (handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: b2 }).length < b2) {
      truncated.push(b2);
    }
  }
  count("no bound at or below the row count ever answers short, so being short of the " +
    "bound is the whole signal and not a coincidence of this folder",
    truncated.length === 0, JSON.stringify(truncated));
}

// `not-in-folder` is the reason reserved for an identifier no row on
// either layer answers to. A message the store and this layer both hold
// is not that, whatever the membership read managed to see.
async function testTheHardDeleteDoesNotCallALiveMessageAbsent(handle, alice, filed) {
  // Asked through the read that answers by identifier. A body fetch
  // answers with the message and never names it, so a message the
  // mailbox is hiding cannot be looked for in what a fetch returns.
  var served = handle.mailbox.searchScan(alice, "INBOX")
    .map(function (entry) { return entry.objectid; });
  var stillHidden = filed.filter(function (id) { return served.indexOf(id) === -1; });

  for (var i = 0; i < filed.length; i += 1) {
    var id = filed[i];
    var onThisLayer = b.db.from(mailbox.MESSAGES)
      .where({ folder: storeFolderOf(handle, alice, "INBOX"), objectid: id }).count() === 1;
    var inTheStore = handle.messageStore
      .fetchByObjectId(storeFolderOf(handle, alice, "INBOX"), id) !== null;
    if (!onThisLayer || !inTheStore) continue;

    var outcome = await handle.mailbox.expungeObjects(alice, "INBOX", [id]);
    var absent = (outcome.refused || []).filter(function (entry) {
      return entry.reason === "not-in-folder";
    });
    count("a message both layers hold is not refused as one nothing answers to",
      absent.length === 0, JSON.stringify(outcome));
    break;
  }

  count("no message the mailbox holds is unreadable to its own account",
    stillHidden.length === 0, stillHidden.length + " unreadable");
}

async function run() {
  var root = helpers.tempDir("store-orphan");
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
    var handle = await store.open(cfg);
    await handle.domains.add({ domain: "example.com" });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD }));

    var made = await testAnOrphanedStoreRowHidesLiveMail(handle, alice);
    await testWhichMessageIsHiddenDoesNotMoveWhenAFlagChanges(handle, alice);
    await testABatchSharingOneSequenceDoesNotMoveMembership(handle, alice);
    await testTheBoundRaisingReadStopsOnItsOwnAnswer(handle, alice);
    await testTheHardDeleteDoesNotCallALiveMessageAbsent(handle, alice, made.filed);

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
  name: "mailbox-store-orphan-snapshot",
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
