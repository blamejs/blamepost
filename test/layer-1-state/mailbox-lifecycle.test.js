// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Removing and renaming a mailbox, and the set of names an account has
 * subscribed to, on the adapter the listeners drive.
 *
 * `imap-mailbox-lifecycle` drives the same four verbs over real IMAP
 * sessions, which is where a client's answer is settled. This is the
 * state underneath it: which rows the account is left holding, what the
 * hierarchy looks like after a level has been removed from the middle of
 * it, and what an account's subscribed set carries once the mailboxes it
 * named have gone. A wire session cannot see any of those directly, and
 * an assertion that inferred them from a listing would be reading the
 * answer rather than the state that produced it.
 *
 * The verbs driven here are `blamepost.mail.mailbox.deleteFolder`,
 * `blamepost.mail.mailbox.renameFolder`,
 * `blamepost.mail.mailbox.subscribeFolder` and
 * `blamepost.mail.mailbox.unsubscribeFolder`, against the namespace that
 * `blamepost.mail.mailbox.HIERARCHY_DELIMITER` separates the levels of.
 *
 * DELETE destroys the mail with the mailbox, so `deleteFolder` is also
 * driven against a mailbox a preservation order keeps, which is where its
 * refusal and its destroyed count carry a number rather than a zero.
 * `mailbox-legal-hold` covers placing and releasing an order; this covers
 * what DELETE does while one is in force.
 *
 * Run standalone: node test/layer-1-state/mailbox-lifecycle.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var mailbox = require("../../lib/mail/mailbox");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "second quiet lantern bicycle 4292";

var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";
var HOLD_APPROVER = "records@example.com";

function message(subject, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <alice@example.com>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

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

function namesOf(handle, actor) {
  return handle.mailbox.accountFolders(actor).map(function (f) { return f.name; });
}

function listedNamed(handle, actor, name) {
  var found = handle.mailbox.listFolders(actor).filter(function (entry) {
    return entry.name === name;
  });
  return found.length > 0 ? found[0] : null;
}

// The refusal one call raised, or null when it did not refuse. Returned
// rather than asserted, so a case reads what it expected against what it
// got. Some refusals here carry counts beside the code, so the whole
// value is handed back and `refusalCode` reads the code off it.
async function refusalOf(run) {
  try {
    await run();
    return null;
  } catch (e) {
    return e;
  }
}

// The code one call refused with, or the empty string when it did not
// refuse.
async function refusalCode(run) {
  var refusal = await refusalOf(run);
  if (refusal === null) return "";
  return refusal.code || "unknown";
}

// ---- cases -----------------------------------------------------------------

// The separator the namespace is built from. Every level boundary on
// this server is this one value, so it is read from the module by
// everything that needs it rather than written again.
function testTheHierarchyDelimiterIsOneValue(handle, actor) {
  count("the module names the separator between the levels of a mailbox name",
    mailbox.HIERARCHY_DELIMITER === "/", String(mailbox.HIERARCHY_DELIMITER));

  var made = handle.mailbox.createFolder(actor,
    "Sep" + mailbox.HIERARCHY_DELIMITER + "Under");
  count("a name built from it creates the two levels it names",
    made.created.length === 2, made.created.join(","));
  var parent = listedNamed(handle, actor, "Sep");
  count("and the level above is listed as one holding children",
    parent !== null && parent.attributes.indexOf("HasChildren") !== -1,
    parent === null ? "" : parent.attributes.join(" "));
}

// The ordinary removal. The mailbox row goes, the name is free again,
// and the next incarnation of the name cannot be mistaken for the one
// that went (RFC 9051 sections 6.3.5 and 2.3.1.1).
async function testRemovingAMailbox(handle, actor) {
  handle.mailbox.createFolder(actor, "Receipts");
  var before = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Receipts";
  })[0];

  var removed = await handle.mailbox.deleteFolder(actor, "Receipts");
  count("deleteFolder answers with the name it removed, and destroyed nothing because the " +
    "mailbox was empty",
    removed.name === "Receipts" && removed.destroyed === 0, JSON.stringify(removed));
  count("and the account no longer holds the mailbox",
    namesOf(handle, actor).indexOf("Receipts") === -1, namesOf(handle, actor).join(","));

  count("removing a name that is not there is refused as a name that is not there",
    await refusalCode(function () { return handle.mailbox.deleteFolder(actor, "Receipts"); }) ===
      "mailbox/no-folder");

  handle.mailbox.createFolder(actor, "Receipts");
  var after = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Receipts";
  })[0];
  count("and the name taken again carries a higher UIDVALIDITY, so a cached client refetches",
    after.uidvalidity > before.uidvalidity,
    before.uidvalidity + " then " + after.uidvalidity);
}

// RFC 9051 section 6.3.5 removes the mailbox permanently, so DELETE
// destroys the mail rather than moving it, and it is one of the paths a
// preservation order decides. A mailbox holding a message the order keeps
// is refused, and the refusal carries the counts: the messages ahead of
// the kept one are already gone by the time the gate is reached, so a
// caller told only "refused" would report a mailbox that is still there
// as removed and would not know any mail had left it.
//
// The removal above answers zero for `destroyed` because the mailbox it
// removed was empty, which is the one value that answer can take without
// the count having been read at all. This is where it carries a number.
async function testRemovingAMailboxAPreservationOrderKeeps(handle, actor) {
  handle.mailbox.createFolder(actor, "Preserved");
  var held = handle.mailbox.appendMessage("Preserved",
    message("under-order", "evidence"), { actor: actor });
  var ordinary = handle.mailbox.appendMessage("Preserved",
    message("ordinary-mail", "no order"), { actor: actor });
  await handle.mailbox.legalHold.place(actor, "Preserved", [held.objectid], {
    reason:    HOLD_REASON,
    citation:  HOLD_CITATION,
    custodian: "legal@example.com",
    placedBy:  "operator",
  });

  var refusal = await refusalOf(function () {
    return handle.mailbox.deleteFolder(actor, "Preserved");
  });
  count("removing a mailbox holding a message under a preservation order is refused",
    refusal !== null && refusal.code === "mailbox/mailbox-preserved",
    refusal === null ? "the mailbox was removed" : String(refusal.code));
  count("and the refusal counts what went and what stayed",
    refusal !== null && refusal.destroyed === 1 && refusal.kept === 1,
    JSON.stringify({ destroyed: refusal && refusal.destroyed, kept: refusal && refusal.kept,
      held: held.objectid, other: ordinary.objectid }));
  count("and names the gate that kept it, so the answer says which order to ask about",
    refusal !== null && Array.isArray(refusal.reasons) &&
      refusal.reasons.indexOf("legal-hold") !== -1,
    JSON.stringify(refusal && refusal.reasons));
  count("and the account still holds the mailbox",
    namesOf(handle, actor).indexOf("Preserved") !== -1, namesOf(handle, actor).join(","));

  // The same verb over the same mailbox with one thing changed. Without
  // this half the refusal above reads the same whether the order held the
  // message or the mailbox could not be removed for some other reason.
  await handle.mailbox.legalHold.release(actor, "Preserved", [held.objectid], {
    reason: "the order was lifted", approver: HOLD_APPROVER });
  var removed = await handle.mailbox.deleteFolder(actor, "Preserved");
  count("once the order is lifted the mailbox goes, and the message it still held goes with it",
    removed.name === "Preserved" && removed.destroyed === 1, JSON.stringify(removed));
  count("and the account no longer holds it",
    namesOf(handle, actor).indexOf("Preserved") === -1, namesOf(handle, actor).join(","));
}

// RFC 9051 section 6.3.5 removes INBOX for nobody, and this server holds
// the five mailboxes beside it under the names it files into.
async function testTheMailboxesThatStay(handle, actor) {
  var refusals = [];
  var names = ["INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive"];
  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    refusals.push(await refusalCode(function () {
      return handle.mailbox.deleteFolder(actor, name);
    }));
  }
  count("every mailbox the account is provisioned with refuses to be removed",
    refusals.filter(function (code) { return code === "mailbox/mailbox-protected"; })
      .length === names.length, refusals.join(","));
  count("and all six are still there",
    names.filter(function (name) {
      return namesOf(handle, actor).indexOf(name) !== -1;
    }).length === 6, namesOf(handle, actor).join(","));

  count("a rename of one carrying a role is refused the same way",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Sent", "Posted");
    }) === "mailbox/mailbox-protected");
}

// RFC 9051 section 6.3.5 leaves the inferior names where they are. The
// level that held them stays in a listing as a name that does not exist,
// so what is underneath it is still reachable, and it is not a mailbox
// any verb opens.
async function testRemovingALevelFromTheMiddle(handle, actor) {
  handle.mailbox.createFolder(actor, "Deep/Middle/Leaf");
  await handle.mailbox.deleteFolder(actor, "Deep/Middle");

  count("the level below is untouched",
    namesOf(handle, actor).indexOf("Deep/Middle/Leaf") !== -1, namesOf(handle, actor).join(","));
  count("and the removed level is no longer a mailbox the account holds",
    namesOf(handle, actor).indexOf("Deep/Middle") === -1, namesOf(handle, actor).join(","));

  var derived = listedNamed(handle, actor, "Deep/Middle");
  count("the listing still names it",
    derived !== null, derived === null ? "" : derived.attributes.join(" "));
  count("as a name that does not exist and holds children",
    derived !== null && derived.exists === false &&
      derived.attributes.indexOf("NonExistent") !== -1 &&
      derived.attributes.indexOf("HasChildren") !== -1,
    derived === null ? "" : derived.attributes.join(" "));
  count("and nothing opens it",
    await refusalCode(function () {
      return handle.mailbox.selectFolder(actor, "Deep/Middle", {});
    }) === "mailbox/no-folder");
}

// RFC 9051 section 6.3.6: the inferior names move with the name above
// them, the superior levels the new name needs are created, and the
// mailbox keeps the identifiers a client addresses its messages by.
async function testRenamingAMailbox(handle, actor) {
  handle.mailbox.createFolder(actor, "Old/Deep/Deeper");
  var before = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Old";
  })[0];

  var moved = await handle.mailbox.renameFolder(actor, "Old", "Filed/2026");
  count("renameFolder answers with both names, what it moved and what it created",
    moved.from === "Old" && moved.to === "Filed/2026" && moved.moved === 3 &&
      moved.created.join(",") === "Filed", JSON.stringify(moved));

  var names = namesOf(handle, actor);
  count("every level under the old name moved with it",
    names.indexOf("Filed/2026") !== -1 && names.indexOf("Filed/2026/Deep") !== -1 &&
      names.indexOf("Filed/2026/Deep/Deeper") !== -1, names.join(","));
  count("and nothing is left under the old one",
    names.filter(function (name) {
      return name === "Old" || name.indexOf("Old/") === 0;
    }).length === 0, names.join(","));

  var after = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Filed/2026";
  })[0];
  count("the renamed mailbox keeps the UIDVALIDITY it had",
    after.uidvalidity === before.uidvalidity,
    before.uidvalidity + " then " + after.uidvalidity);
  count("and the store folder underneath it, which is why the identifiers still mean what " +
    "they meant", after.storeName === before.storeName,
    before.storeName + " then " + after.storeName);
}

// The renames that are refused, each because the result would be a
// hierarchy a client could not follow.
async function testTheRenamesThatAreRefused(handle, actor) {
  handle.mailbox.createFolder(actor, "Source");
  handle.mailbox.createFolder(actor, "Taken");
  handle.mailbox.createFolder(actor, "Source/Kept");

  count("a rename from a name that is not there is refused",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Absent", "Anywhere");
    }) === "mailbox/no-folder");
  count("a rename onto a name that is already there is refused",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Source", "Taken");
    }) === "mailbox/mailbox-exists");
  count("a rename of a name into its own hierarchy is refused, because the mailbox would be " +
    "its own ancestor",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Source", "Source/Nested");
    }) === "mailbox/bad-rename");
  count("a rename onto a name the namespace rule refuses is refused at the point of parse",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Source", "Half*Done");
    }) === "mailbox/bad-mailbox-name");

  // A collision one level down: the target is free and a name the
  // rename would produce underneath it is not.
  handle.mailbox.createFolder(actor, "Destination/Kept");
  count("a rename whose inferior name would land on one that exists is refused",
    await refusalCode(function () {
      return handle.mailbox.renameFolder(actor, "Source", "Destination");
    }) === "mailbox/mailbox-exists");
  count("and the mailbox is where it was",
    namesOf(handle, actor).indexOf("Source/Kept") !== -1, namesOf(handle, actor).join(","));
}

// The trap RFC 9051 section 6.3.6 writes out: renaming INBOX moves the
// messages into a new mailbox and leaves INBOX where it is, and the
// inferior names of INBOX are unaffected.
async function testRenamingInbox(handle, account) {
  var actor = actorFor(account);
  handle.mailbox.createFolder(actor, "INBOX/Kept");
  handle.mailbox.appendMessage("INBOX", [
    "From: sender@example.net",
    "To: " + account.address,
    "Subject: inbox-one",
    "Message-ID: <inbox-one@example.net>",
    "",
    "Body.",
    "",
  ].join("\r\n"), { actor: actor });

  var before = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "INBOX";
  })[0];
  count("INBOX holds one message before the rename",
    handle.mailbox.selectFolder(actor, "INBOX", {}).exists === 1);

  var moved = await handle.mailbox.renameFolder(actor, "INBOX", "Archived2026");
  count("renaming INBOX reports the one mailbox it moved messages into",
    moved.from === "INBOX" && moved.to === "Archived2026" && moved.moved === 1,
    JSON.stringify(moved));

  var names = namesOf(handle, actor);
  count("INBOX is still there", names.indexOf("INBOX") !== -1, names.join(","));
  count("and its inferior name is unaffected",
    names.indexOf("INBOX/Kept") !== -1 && names.indexOf("Archived2026/Kept") === -1,
    names.join(","));

  var after = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "INBOX";
  })[0];
  count("INBOX keeps the UIDVALIDITY it had, because its identifiers were not reused",
    after.uidvalidity === before.uidvalidity,
    before.uidvalidity + " then " + after.uidvalidity);
  count("INBOX is empty", handle.mailbox.selectFolder(actor, "INBOX", {}).exists === 0);

  var landed = handle.mailbox.selectFolder(actor, "Archived2026", {});
  count("and the new mailbox holds the message, under a UIDVALIDITY of its own",
    landed.exists === 1 && landed.uidvalidity !== before.uidvalidity,
    before.uidvalidity + " then " + landed.uidvalidity);
}

// The subscribed set. RFC 9051 section 6.3.7 adds a name to it, section
// 6.3.8 takes one out, and section 6.3.8 is explicit that nothing else
// does: the entry outlives the mailbox.
async function testTheSubscribedSet(handle, actor) {
  handle.mailbox.createFolder(actor, "Watched");

  var added = handle.mailbox.subscribeFolder(actor, "Watched");
  count("subscribeFolder reports the name it added", added.name === "Watched" &&
    added.added === true, JSON.stringify(added));
  var again = handle.mailbox.subscribeFolder(actor, "Watched");
  count("and reports a name already there as one it did not add",
    again.added === false, JSON.stringify(again));

  var entry = listedNamed(handle, actor, "Watched");
  count("the listing marks the mailbox Subscribed",
    entry !== null && entry.attributes.indexOf("Subscribed") !== -1,
    entry === null ? "" : entry.attributes.join(" "));

  count("a name the account does not hold is refused rather than recorded",
    await refusalCode(function () {
      return handle.mailbox.subscribeFolder(actor, "NeverMade");
    }) === "mailbox/no-folder");
  count("and a name the namespace rule refuses is refused at the point of parse",
    await refusalCode(function () {
      return handle.mailbox.subscribeFolder(actor, "Half*Done");
    }) === "mailbox/bad-mailbox-name");

  // The rule the whole table exists for.
  await handle.mailbox.deleteFolder(actor, "Watched");
  var orphan = listedNamed(handle, actor, "Watched");
  count("removing the mailbox leaves the name subscribed, which section 6.3.8 requires",
    orphan !== null && orphan.exists === false &&
      orphan.attributes.indexOf("Subscribed") !== -1,
    orphan === null ? "" : orphan.attributes.join(" "));

  var dropped = handle.mailbox.unsubscribeFolder(actor, "Watched");
  count("unsubscribeFolder removes a name whose mailbox has gone",
    dropped.removed === true, JSON.stringify(dropped));
  count("and the listing stops naming it", listedNamed(handle, actor, "Watched") === null);
  count("unsubscribing from a name the set does not carry reports nothing removed",
    handle.mailbox.unsubscribeFolder(actor, "Watched").removed === false);
}

// One account's namespace says nothing about another's. The same name in
// two accounts is two mailboxes, and every verb here is scoped to the
// account that sent it.
async function testTheAccountBoundary(handle, alice, bob) {
  handle.mailbox.createFolder(alice, "Shared");
  handle.mailbox.createFolder(bob, "Shared");
  handle.mailbox.subscribeFolder(bob, "Shared");

  await handle.mailbox.deleteFolder(alice, "Shared");
  count("removing one account's mailbox leaves the other account's alone",
    namesOf(handle, bob).indexOf("Shared") !== -1, namesOf(handle, bob).join(","));
  var kept = listedNamed(handle, bob, "Shared");
  count("and leaves the other account's entry in its own subscribed set",
    kept !== null && kept.exists === true &&
      kept.attributes.indexOf("Subscribed") !== -1,
    kept === null ? "" : kept.attributes.join(" "));
  count("while the first account has no entry for it at all",
    listedNamed(handle, alice, "Shared") === null);

  handle.mailbox.createFolder(alice, "Shared");
  await handle.mailbox.renameFolder(alice, "Shared", "Renamed");
  count("renaming one account's mailbox leaves the other account's name where it was",
    namesOf(handle, bob).indexOf("Shared") !== -1 &&
      namesOf(handle, bob).indexOf("Renamed") === -1, namesOf(handle, bob).join(","));
}

// ---- runner ----------------------------------------------------------------

// RFC 9051 section 2.3.1.1: a name taken again after DELETE takes a
// UIDVALIDITY higher than any the volume issued before. Creating many
// mailboxes inside one second moves the counter ahead of the clock, so
// once the highest of them is deleted no surviving row and no clock
// reading carries its value. The floor has to survive a restart anyway.
async function testTheUidvalidityFloorOutlivesARestart(handle, actor, cfg) {
  for (var n = 0; n < 40; n += 1) handle.mailbox.createFolder(actor, "Burst" + n);
  var highest = handle.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Burst39";
  })[0];
  await handle.mailbox.deleteFolder(actor, "Burst39");

  store.close();
  var reopened = await store.open(cfg);
  reopened.mailbox.createFolder(actor, "Burst39");
  var again = reopened.mailbox.accountFolders(actor).filter(function (f) {
    return f.name === "Burst39";
  })[0];
  count("a name taken again after a restart carries a UIDVALIDITY above the one it had before " +
    "DELETE, even when no surviving row carries that value",
    again.uidvalidity > highest.uidvalidity,
    highest.uidvalidity + " then " + again.uidvalidity);
}

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-lifecycle-"));
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
      address: "alice@example.com", password: ALICE_PASSWORD }));
    var bob = actorFor(await handle.accounts.create({
      address: "bob@example.com", password: BOB_PASSWORD }));
    // Renaming INBOX is driven on an account of its own, because it
    // empties the one mailbox every other case would otherwise be
    // reading afterwards.
    var carol = await handle.accounts.create({
      address: "carol@example.com", password: BOB_PASSWORD });

    testTheHierarchyDelimiterIsOneValue(handle, alice);
    await testRemovingAMailbox(handle, alice);
    await testRemovingAMailboxAPreservationOrderKeeps(handle, alice);
    await testTheMailboxesThatStay(handle, alice);
    await testRemovingALevelFromTheMiddle(handle, alice);
    await testRenamingAMailbox(handle, alice);
    await testTheRenamesThatAreRefused(handle, alice);
    await testRenamingInbox(handle, carol);
    await testTheSubscribedSet(handle, alice);
    await testTheAccountBoundary(handle, alice, bob);
    await testTheUidvalidityFloorOutlivesARestart(handle, alice, cfg);

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

module.exports = {
  name: "mailbox-lifecycle",
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
