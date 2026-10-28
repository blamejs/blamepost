// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Removing, renaming and subscribing to a mailbox over IMAP.
 *
 * RFC 9051 sections 6.3.5 to 6.3.8 make DELETE, RENAME, SUBSCRIBE and
 * UNSUBSCRIBE part of IMAP4rev2, which this server advertises. An
 * account holder whose client offers a folder control reaches these
 * verbs and nothing else, and a client that can make a folder and never
 * remove or rename it is one every mailbox mistake is permanent in.
 *
 * The cases drive real sessions against the bound listener. What each
 * one asserts is what the client was told and what the next command
 * finds, because a removal recorded where no other verb reads it is not
 * a removal.
 *
 * Two of them carry the decisions this file exists to pin. DELETE
 * destroys the mail the mailbox holds, and every message goes through
 * the one delete path this server has, so a message under a
 * preservation order or inside the retention window stays and the
 * mailbox holding it is not removed. RENAME of INBOX moves the messages
 * and leaves INBOX itself in place, which section 6.3.6 writes out.
 *
 * Run standalone: node test/layer-2-integration/imap-mailbox-lifecycle.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var b = helpers.b;

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var listedNamed = wire.imapListedNamed;
var listed      = wire.imapListed;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE_PASSWORD   = "a long enough account password for one test run";
var BOB_PASSWORD     = "a second long enough account password for one run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

function message(marker) {
  return [
    "From: sender@example.net",
    "To: alice@" + DOMAIN,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "",
    "Body of " + marker + ".",
    "",
  ].join("\r\n");
}

// The store token one of an account's mailboxes is known by, which is
// what the message store indexes and what a legal hold is placed
// through.
function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; });
  return found.length > 0 ? found[0].storeName : "";
}

// DELETE removes the store folder with the mailbox, so a folder that is
// gone holds no messages.
function objectIdsIn(identity, storeFolder) {
  var present = identity.messageStore.listFolders().some(function (f) {
    return f.name === storeFolder;
  });
  if (!present) return [];
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 })
    .map(function (r) { return r.objectid; });
}

// The UIDVALIDITY one SELECT reported, or zero when the reply carried
// none. A number rather than the line, because every case comparing two
// of them is asking whether a client's cache survived.
function uidValidityOf(text) {
  var found = /^\* OK \[UIDVALIDITY (\d+)\]/m.exec(text);
  return found === null ? 0 : parseInt(found[1], 10);
}

function existsIn(text) {
  var found = /^\* (\d+) EXISTS/m.exec(text);
  return found === null ? -1 : parseInt(found[1], 10);
}

// ---- DELETE (RFC 9051 section 6.3.5) ---------------------------------------

// The ordinary removal, and the whole of what makes it one: LIST stops
// naming the mailbox, SELECT refuses it with the response code section
// 7.1 gives a name that is not there, and the name is free to take
// again.
async function deleteRemovesAMailboxEveryOtherVerbThenRefuses(ctx) {
  var session = await ctx.session("delete-basic");

  await session.imapAsk("CREATE Receipts");
  var removed = await session.imapAsk("DELETE Receipts");
  count("DELETE answers a mailbox it removed with a tagged OK",
    removed.verdict === "OK", visible(removed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("and LIST stops naming it", listedNamed(after.text, "Receipts") === null,
    visible(after.text));

  var opened = await session.imapAsk("SELECT Receipts");
  count("SELECT refuses the removed name", opened.verdict === "NO", visible(opened.text));
  count("with the NONEXISTENT response code of RFC 9051 section 7.1",
    /\[NONEXISTENT\]/.test(opened.text), visible(opened.text));

  var again = await session.imapAsk("DELETE Receipts");
  count("a second DELETE of the same name is refused as a name that is not there",
    again.verdict === "NO" && /\[NONEXISTENT\]/.test(again.text), visible(again.text));

  var remade = await session.imapAsk("CREATE Receipts");
  count("and the name is free to take again", remade.verdict === "OK", visible(remade.text));

  session.close();
}

// RFC 9051 section 6.3.5 removes the mailbox permanently, so the mail it
// holds goes with it. Every message leaves through the one delete path
// this server has rather than through a second one written for this
// verb.
async function deleteDestroysTheMailTheMailboxHeld(ctx) {
  var session = await ctx.session("delete-with-mail");

  await session.imapAsk("CREATE Ledger");
  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Ledger", message("ledger-one"), "<ledger-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Ledger");

  var folder = storeFolderOf(ctx.identity, ctx.alice.id, "Ledger");
  count("the message reached the message store", objectIdsIn(ctx.identity, folder).length === 1,
    folder);

  var removed = await session.imapAsk("DELETE Ledger");
  count("DELETE removes a mailbox holding ordinary mail", removed.verdict === "OK",
    visible(removed.text));
  count("and the message store holds none of its messages afterwards",
    objectIdsIn(ctx.identity, folder).length === 0, folder);

  session.close();
}

// The decision this file exists to pin. Every message goes through the
// delete path that enforces the preservation gates, so a mailbox holding
// one the gates keep cannot be removed. The client is told the count
// rather than answered OK over a mailbox that is still there.
async function deleteIsRefusedForAMailboxHoldingPreservedMail(ctx) {
  var session = await ctx.session("delete-held");

  await session.imapAsk("CREATE Discovery");
  var markers = ["discovery-ordinary", "discovery-held"];
  for (var i = 0; i < markers.length; i += 1) {
    var filed = session.tag();
    await session.sendLiteral(filed + " APPEND Discovery", message(markers[i]),
      "<" + markers[i] + ">");
    await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND " + markers[i]);
  }

  var folder = storeFolderOf(ctx.identity, ctx.alice.id, "Discovery");
  var ids = objectIdsIn(ctx.identity, folder);
  count("both messages reached the mailbox", ids.length === 2, String(ids.length));
  await ctx.identity.mailbox.legalHold.place({ id: ctx.alice.id }, "Discovery", [ids[1]], {
    reason:    "preservation order",
    citation:  "FRCP-26",
    custodian: "legal@" + DOMAIN,
    placedBy:  "operator",
  });

  var removed = await session.imapAsk("DELETE Discovery");
  count("DELETE is refused for a mailbox holding a message under a preservation order",
    removed.verdict === "NO", visible(removed.text));
  count("and the refusal says how many messages were kept",
    /\b1\b/.test(removed.text), visible(removed.text));
  count("and carries a response code the client can act on",
    /\[CONTACTADMIN\]/.test(removed.text), visible(removed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("the mailbox is still listed", listedNamed(after.text, "Discovery") !== null,
    visible(after.text));

  var opened = await session.imapAsk("SELECT Discovery");
  count("and it opens holding exactly the message that could not be destroyed",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));

  session.close();
}

// RFC 9051 section 6.3.5: it is an error to attempt to delete INBOX.
// The five mailboxes this server provisions beside it carry the RFC 6154
// roles it files into by name, so removing one leaves a delivery path
// with nowhere to land.
async function deleteRefusesInboxAndTheProvisionedRoles(ctx) {
  var session = await ctx.session("delete-roles");

  var inbox = await session.imapAsk("DELETE INBOX");
  count("DELETE INBOX is refused, which RFC 9051 section 6.3.5 calls an error",
    inbox.verdict === "NO", visible(inbox.text));
  var cased = await session.imapAsk("DELETE inbox");
  count("and so is any other case of it, because section 5.1 matches INBOX case insensitively",
    cased.verdict === "NO", visible(cased.text));

  var roles = ["Sent", "Drafts", "Trash", "Junk", "Archive"];
  var kept = [];
  for (var i = 0; i < roles.length; i += 1) {
    var answer = await session.imapAsk("DELETE " + roles[i]);
    if (answer.verdict === "OK") kept.push(roles[i]);
  }
  count("a mailbox carrying a special use role is refused as well", kept.length === 0,
    kept.join(", "));

  var after = await session.imapAsk("LIST \"\" *");
  count("and every provisioned mailbox is still listed",
    listed(after.text).filter(function (entry) {
      return ["INBOX"].concat(roles).indexOf(entry.name) !== -1;
    }).length === 6, visible(after.text));

  session.close();
}

// RFC 9051 section 6.3.5: DELETE MUST NOT remove inferior hierarchical
// names. The name that held them stays in the listing under the
// \NonExistent attribute of section 7.3.1, which implies \NoSelect, so a
// client can still reach what is underneath it.
async function deleteLeavesInferiorNamesAndMarksTheParentNonExistent(ctx) {
  var session = await ctx.session("delete-parent");

  await session.imapAsk("CREATE Clients/Acme/2026");
  var removed = await session.imapAsk("DELETE Clients/Acme");
  count("a name holding inferior names is removed", removed.verdict === "OK",
    visible(removed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("its inferior name is untouched", listedNamed(after.text, "Clients/Acme/2026") !== null,
    visible(after.text));
  var parent = listedNamed(after.text, "Clients/Acme");
  count("the removed name is still listed, because something is underneath it",
    parent !== null, visible(after.text));
  count("with the NonExistent attribute of RFC 9051 section 7.3.1",
    parent !== null && /NonExistent/.test(parent.attributes),
    parent === null ? "" : parent.attributes);
  count("and with HasChildren, which is what makes it worth listing at all",
    parent !== null && /HasChildren/.test(parent.attributes),
    parent === null ? "" : parent.attributes);

  var opened = await session.imapAsk("SELECT Clients/Acme");
  count("SELECT refuses a name that is listed and does not exist",
    opened.verdict === "NO" && /\[NONEXISTENT\]/.test(opened.text), visible(opened.text));

  var child = await session.imapAsk("SELECT Clients/Acme/2026");
  count("while the name underneath it still opens", child.verdict === "OK",
    visible(child.text));

  session.close();
}

// RFC 9051 section 2.3.1.1: a mailbox whose unique identifiers do not
// persist takes a UIDVALIDITY larger than the one it had. A name removed
// and taken again is that case, and a client handed the old value would
// keep a cache naming messages that are gone.
async function aRecreatedNameCannotBeMistakenForTheOneThatWent(ctx) {
  var session = await ctx.session("delete-uidvalidity");

  await session.imapAsk("CREATE Cycle");
  var first = await session.imapAsk("SELECT Cycle");
  var before = uidValidityOf(first.text);
  count("the first incarnation reports a UIDVALIDITY", before > 0, String(before));

  await session.imapAsk("DELETE Cycle");
  await session.imapAsk("CREATE Cycle");
  var second = await session.imapAsk("SELECT Cycle");
  var after = uidValidityOf(second.text);
  count("the second incarnation reports a higher one, so a cached client refetches",
    after > before, before + " then " + after);

  session.close();
}

// ---- RENAME (RFC 9051 section 6.3.6) ---------------------------------------

// The ordinary rename. The messages and the identifiers a client
// addresses them by travel with the mailbox, so the UIDVALIDITY is
// unchanged: the cache a client holds is still true of the mailbox it
// now names.
async function renameMovesTheMailboxItsMailAndItsIdentifiers(ctx) {
  var session = await ctx.session("rename-basic");

  await session.imapAsk("CREATE Temporary");
  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Temporary", message("rename-one"), "<rename-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Temporary");

  var before = await session.imapAsk("SELECT Temporary");
  var wasValid = uidValidityOf(before.text);
  var fetched = await session.imapAsk("FETCH 1 (UID)");
  var wasUid = /UID (\d+)/.exec(fetched.text);

  var renamed = await session.imapAsk("RENAME Temporary Permanent");
  count("RENAME answers a mailbox it renamed with a tagged OK", renamed.verdict === "OK",
    visible(renamed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("LIST names the mailbox under the new name only",
    listedNamed(after.text, "Permanent") !== null &&
      listedNamed(after.text, "Temporary") === null, visible(after.text));

  var opened = await session.imapAsk("SELECT Permanent");
  count("the mailbox opens under the new name holding the message it held",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));
  count("with the UIDVALIDITY it had, because the identifiers moved with it",
    uidValidityOf(opened.text) === wasValid,
    wasValid + " then " + uidValidityOf(opened.text));
  var nowFetched = await session.imapAsk("FETCH 1 (UID)");
  count("and the message keeps the UID a cached client is holding",
    wasUid !== null && new RegExp("UID " + wasUid[1] + "\\b").test(nowFetched.text),
    visible(nowFetched.text));

  var old = await session.imapAsk("SELECT Temporary");
  count("the old name is gone", old.verdict === "NO" && /\[NONEXISTENT\]/.test(old.text),
    visible(old.text));

  session.close();
}

// The rename above re-selects afterwards, so it never asks what happens
// to a session that is still IN the mailbox while it moves. That session
// is the ordinary case: a client keeps a mailbox open, and a rename can
// arrive from the browser, from another client or from the operator
// interface at any point.
//
// The selection has to follow the mailbox. The identifiers moved with it
// and the UIDVALIDITY did not change, so it is the same mailbox under a
// new name, and a session holding it open is holding the thing that
// moved. A selection left pointing at the old name resolves nothing, and
// worse, it still names a mailbox anyone may CREATE again, so the grant
// the session holds would land on a mailbox it never opened.
async function aSelectionFollowsTheMailboxItIsHoldingOpen(ctx) {
  var session = await ctx.session("rename-selected");

  await session.imapAsk("CREATE Moving");
  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Moving", message("moving-one"), "<moving-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Moving");

  var opened = await session.imapAsk("SELECT Moving");
  count("the session opens the mailbox it is about to rename",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));
  var heldUid = /UID (\d+)/.exec((await session.imapAsk("FETCH 1 (UID)")).text);
  count("and can read the message before the rename", heldUid !== null);

  var renamed = await session.imapAsk("RENAME Moving Moved");
  count("the rename of a mailbox this session holds open completes",
    renamed.verdict === "OK", visible(renamed.text));

  // The selected state is still selected, and it is the mailbox that
  // moved. Every verb of RFC 9051 section 6.4 answers from it.
  var stillFetched = await session.imapAsk("FETCH 1 (UID)");
  count("the session can still read the message it had selected",
    stillFetched.verdict === "OK" && heldUid !== null &&
      new RegExp("UID " + heldUid[1] + "\\b").test(stillFetched.text),
    visible(stillFetched.text));

  var stored = await session.imapAsk("STORE 1 +FLAGS (\\Seen)");
  count("and can still write a flag on it, so the grant moved with the selection",
    stored.verdict === "OK", visible(stored.text));

  // The old name is free again. Anything may take it, and when it does
  // it is a different mailbox: a session still holding the renamed one
  // must not reach into it.
  await session.imapAsk("CREATE Moving");
  var reopened = await session.imapAsk("SELECT Moving");
  count("the old name can be created again and opens empty",
    reopened.verdict === "OK" && existsIn(reopened.text) === 0, visible(reopened.text));

  var moved = await session.imapAsk("SELECT Moved");
  count("while the renamed mailbox still holds the message, under the new name",
    moved.verdict === "OK" && existsIn(moved.text) === 1, visible(moved.text));

  session.close();
}

// The other half of the same question. DELETE removes the name a session
// may be holding open, and unlike a rename there is nothing for the
// selection to follow: the mailbox is gone. The session has to leave the
// selected state rather than keep addressing a name that resolves to
// nothing and that anything may create again.
async function aSelectionDoesNotOutliveTheMailboxItHeld(ctx) {
  var session = await ctx.session("delete-selected");

  await session.imapAsk("CREATE Doomed");
  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Doomed", message("doomed-one"), "<doomed-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Doomed");

  var opened = await session.imapAsk("SELECT Doomed");
  count("the session opens the mailbox it is about to delete",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));

  var removed = await session.imapAsk("DELETE Doomed");
  count("the delete of a mailbox this session holds open completes",
    removed.verdict === "OK", visible(removed.text));
  count("and the session is told its selection closed, ahead of the tagged answer",
    /^\* OK \[CLOSED\]/m.test(removed.text), visible(removed.text));

  // Whatever the session does next, it must not be answered from a
  // mailbox that no longer exists.
  var after = await session.imapAsk("FETCH 1 (UID)");
  count("a read after the mailbox went is refused rather than answered",
    after.verdict !== "OK", visible(after.text));

  // And the name is free. Recreating it makes a different mailbox, which
  // the session is not holding.
  await session.imapAsk("CREATE Doomed");
  var fresh = await session.imapAsk("FETCH 1 (UID)");
  count("recreating the name does not hand the session the new mailbox",
    fresh.verdict !== "OK", visible(fresh.text));

  session.close();
}

// The same two verbs sent by a different session of the same account. A
// mailbox open in one session is renamed or deleted by another, and the
// session holding it must follow the rename and leave a deleted mailbox,
// rather than go on resolving the old name, which anything may create
// again. RFC 9051 has no response that closes another session's
// selection, so the holding session is sent an untagged BYE and
// disconnected, and its client reconnects.
async function anotherSessionsSelectionFollowsTooRename(ctx) {
  var holder = await ctx.session("rename-held-elsewhere");
  var actor  = await ctx.session("rename-sent-elsewhere");

  await actor.imapAsk("CREATE Shared");
  var filed = actor.tag();
  await actor.sendLiteral(filed + " APPEND Shared", message("shared-one"), "<shared-one>");
  await actor.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Shared");

  var opened = await holder.imapAsk("SELECT Shared");
  count("one session opens the mailbox another session is about to rename",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));

  var renamed = await actor.imapAsk("RENAME Shared Shared2");
  count("the other session's rename completes", renamed.verdict === "OK", visible(renamed.text));
  await actor.imapAsk("CREATE Shared");

  var fetched = await holder.imapAsk("FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])");
  count("the holding session still reads the message it had open, under the new name, " +
    "and not the empty mailbox now under the old one",
    fetched.verdict === "OK" && fetched.text.indexOf("shared-one") !== -1,
    visible(fetched.text));

  var removed = await actor.imapAsk("DELETE Shared2");
  count("the other session's delete completes", removed.verdict === "OK", visible(removed.text));
  count("and the session that sent it, holding no selection, is told nothing about one",
    !/^\* OK \[CLOSED\]/m.test(removed.text), visible(removed.text));
  var told = await holder.read(/^\* BYE [^\r\n]*\r\n/m, "BYE to the holding session");
  count("once it is deleted the holding session is told so with BYE, rather than left " +
    "believing it still has the mailbox open",
    /deleted/.test(String(told)), visible(String(told)));

  holder.close();
  actor.close();
}

// RFC 9051 section 6.3.6: if the name has inferior hierarchical names,
// they MUST be renamed too. A server that moved the parent alone would
// leave every child listed under a name its parent no longer has.
async function renameCarriesTheWholeHierarchyUnderTheName(ctx) {
  var session = await ctx.session("rename-hierarchy");

  await session.imapAsk("CREATE Old/Deep/Deeper");
  var renamed = await session.imapAsk("RENAME Old New");
  count("a name holding inferior names is renamed", renamed.verdict === "OK",
    visible(renamed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("every inferior name moved with it",
    listedNamed(after.text, "New") !== null &&
      listedNamed(after.text, "New/Deep") !== null &&
      listedNamed(after.text, "New/Deep/Deeper") !== null, visible(after.text));
  count("and none of them is still listed under the old parent",
    listed(after.text).filter(function (entry) {
      return entry.name === "Old" || entry.name.indexOf("Old/") === 0;
    }).length === 0, visible(after.text));

  session.close();
}

// RFC 9051 section 6.3.6: where the separator appears in the new name,
// the server SHOULD create the superior names the rename needs.
async function renameCreatesTheSuperiorLevelsTheNewNameNeeds(ctx) {
  var session = await ctx.session("rename-superior");

  await session.imapAsk("CREATE Loose");
  var renamed = await session.imapAsk("RENAME Loose Filed/2026/January");
  count("a rename into a name with superior levels completes", renamed.verdict === "OK",
    visible(renamed.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("and the superior levels are created with it",
    listedNamed(after.text, "Filed") !== null &&
      listedNamed(after.text, "Filed/2026") !== null &&
      listedNamed(after.text, "Filed/2026/January") !== null, visible(after.text));

  var opened = await session.imapAsk("SELECT Filed/2026");
  count("a level created this way is a mailbox SELECT opens", opened.verdict === "OK",
    visible(opened.text));

  session.close();
}

// The trap RFC 9051 section 6.3.6 names: renaming INBOX moves the
// messages to a new mailbox and leaves INBOX itself in place, empty.
// Inferior names of INBOX are unaffected.
async function renamingInboxMovesTheMailAndLeavesInboxWhereItWas(ctx) {
  var session = await ctx.bobSession("rename-inbox");

  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND INBOX", message("inbox-one"), "<inbox-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into INBOX");
  await session.imapAsk("CREATE INBOX/Keep");

  var before = await session.imapAsk("SELECT INBOX");
  var inboxValidity = uidValidityOf(before.text);
  count("INBOX holds the message that was filed into it", existsIn(before.text) === 1,
    visible(before.text));

  var renamed = await session.imapAsk("RENAME INBOX Archived2026");
  count("RENAME INBOX completes", renamed.verdict === "OK", visible(renamed.text));
  count("and the session holding INBOX is told its selection closed",
    /^\* OK \[CLOSED\]/m.test(renamed.text), visible(renamed.text));

  // The session had INBOX selected and its messages left. The sequence
  // numbers it holds name nothing now, so the session is out of the
  // selected state rather than answered against a mailbox it last saw
  // full.
  var stale = await session.imapAsk("FETCH 1 (UID)");
  count("a session that had INBOX selected is no longer answered from it after RENAME INBOX",
    stale.verdict !== "OK", visible(stale.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("INBOX is still listed", listedNamed(after.text, "INBOX") !== null, visible(after.text));
  count("and so is the new mailbox", listedNamed(after.text, "Archived2026") !== null,
    visible(after.text));
  count("while the inferior name of INBOX is unaffected",
    listedNamed(after.text, "INBOX/Keep") !== null &&
      listedNamed(after.text, "Archived2026/Keep") === null, visible(after.text));

  var emptied = await session.imapAsk("SELECT INBOX");
  count("INBOX opens empty", emptied.verdict === "OK" && existsIn(emptied.text) === 0,
    visible(emptied.text));
  count("keeping the UIDVALIDITY it had, because its identifiers were not reused",
    uidValidityOf(emptied.text) === inboxValidity,
    inboxValidity + " then " + uidValidityOf(emptied.text));

  var moved = await session.imapAsk("SELECT Archived2026");
  count("the new mailbox holds the message INBOX held",
    moved.verdict === "OK" && existsIn(moved.text) === 1, visible(moved.text));
  count("under a UIDVALIDITY of its own, because it is a mailbox no client has cached",
    uidValidityOf(moved.text) !== inboxValidity,
    inboxValidity + " then " + uidValidityOf(moved.text));

  session.close();
}

// RFC 9051 section 6.3.6: it is an error to rename from a name that does
// not exist or to a name that already does. The rest are this server's
// own, and each one is a rename whose result a client could not follow.
async function renameRefusesTheNamesItCannotMove(ctx) {
  var session = await ctx.session("rename-refusals");

  await session.imapAsk("CREATE Source");
  await session.imapAsk("CREATE Taken");

  var missing = await session.imapAsk("RENAME Absent Anywhere");
  count("a rename from a name that does not exist is refused",
    missing.verdict === "NO" && /\[NONEXISTENT\]/.test(missing.text), visible(missing.text));

  var taken = await session.imapAsk("RENAME Source Taken");
  count("a rename onto a name that already exists is refused",
    taken.verdict === "NO" && /\[ALREADYEXISTS\]/.test(taken.text), visible(taken.text));

  var role = await session.imapAsk("RENAME Sent Posted");
  count("a rename of a mailbox carrying a special use role is refused",
    role.verdict === "NO", visible(role.text));

  var under = await session.imapAsk("RENAME Source Source/Nested");
  count("a rename of a name into its own hierarchy is refused", under.verdict === "NO",
    visible(under.text));

  var bad = await session.imapAsk("RENAME Source \"Half*Done\"");
  count("a rename onto a name this server will not keep is refused", bad.verdict === "NO",
    visible(bad.text));

  var short = await session.imapAsk("RENAME Source");
  count("a rename carrying one name is refused", short.verdict !== "OK", visible(short.text));
  var long = await session.imapAsk("RENAME Source Target Extra");
  count("a rename carrying three names is refused", long.verdict !== "OK", visible(long.text));

  var after = await session.imapAsk("LIST \"\" *");
  count("and none of them moved the mailbox",
    listedNamed(after.text, "Source") !== null &&
      listedNamed(after.text, "Taken") !== null &&
      listedNamed(after.text, "Sent") !== null &&
      listedNamed(after.text, "Posted") === null, visible(after.text));

  session.close();
}

// ---- SUBSCRIBE and UNSUBSCRIBE (sections 6.3.7 and 6.3.8) ------------------

// The subscribed set, which is the account's rather than the mailbox's.
// RFC 9051 section 6.3.9 is where a client reads it back: the SUBSCRIBED
// selection option narrows the listing to it, and the return option of
// the same name marks the entries.
async function subscribingMarksAMailboxAndNarrowsTheListing(ctx) {
  var session = await ctx.session("subscribe-basic");

  await session.imapAsk("CREATE Watched");
  var subscribed = await session.imapAsk("SUBSCRIBE Watched");
  count("SUBSCRIBE answers with a tagged OK", subscribed.verdict === "OK",
    visible(subscribed.text));

  var marked = await session.imapAsk("LIST \"\" * RETURN (SUBSCRIBED)");
  var entry = listedNamed(marked.text, "Watched");
  count("the SUBSCRIBED return option marks the mailbox \\Subscribed",
    entry !== null && /Subscribed/.test(entry.attributes),
    entry === null ? "" : entry.attributes);
  var unmarkedEntry = listedNamed(marked.text, "Junk");
  count("and leaves a mailbox nobody subscribed to unmarked",
    unmarkedEntry !== null && !/Subscribed/.test(unmarkedEntry.attributes),
    unmarkedEntry === null ? "" : unmarkedEntry.attributes);

  var only = await session.imapAsk("LIST (SUBSCRIBED) \"\" *");
  count("the SUBSCRIBED selection option narrows the listing to the subscribed set",
    listedNamed(only.text, "Watched") !== null && listedNamed(only.text, "Junk") === null,
    visible(only.text));

  var again = await session.imapAsk("SUBSCRIBE Watched");
  count("subscribing to a name already subscribed to completes", again.verdict === "OK",
    visible(again.text));

  var dropped = await session.imapAsk("UNSUBSCRIBE Watched");
  count("UNSUBSCRIBE answers with a tagged OK", dropped.verdict === "OK", visible(dropped.text));
  var emptied = await session.imapAsk("LIST (SUBSCRIBED) \"\" *");
  count("and the name leaves the subscribed set",
    listedNamed(emptied.text, "Watched") === null, visible(emptied.text));
  var spare = await session.imapAsk("UNSUBSCRIBE Watched");
  count("unsubscribing from a name that is not subscribed completes", spare.verdict === "OK",
    visible(spare.text));

  session.close();
}

// RFC 9051 section 6.3.8 is explicit: a server MUST NOT remove a name
// from the subscribed set because the mailbox stopped existing. So the
// entry outlives the mailbox, and UNSUBSCRIBE is what removes it.
async function aSubscribedNameOutlivesTheMailboxItNames(ctx) {
  var session = await ctx.session("subscribe-outlives");

  await session.imapAsk("CREATE Ephemeral");
  await session.imapAsk("SUBSCRIBE Ephemeral");
  var removed = await session.imapAsk("DELETE Ephemeral");
  count("the subscribed mailbox is removed", removed.verdict === "OK", visible(removed.text));

  var kept = await session.imapAsk("LIST (SUBSCRIBED) \"\" *");
  count("the name is still in the subscribed set, which section 6.3.8 requires",
    listedNamed(kept.text, "Ephemeral") !== null, visible(kept.text));
  var entry = listedNamed(kept.text, "Ephemeral");
  count("and the entry says the mailbox does not exist",
    entry !== null && /NonExistent/.test(entry.attributes),
    entry === null ? "" : entry.attributes);

  var dropped = await session.imapAsk("UNSUBSCRIBE Ephemeral");
  count("UNSUBSCRIBE removes it", dropped.verdict === "OK", visible(dropped.text));
  var after = await session.imapAsk("LIST (SUBSCRIBED) \"\" *");
  count("and the subscribed set no longer names it",
    listedNamed(after.text, "Ephemeral") === null, visible(after.text));

  session.close();
}

// The subscribed set is names this server keeps for an account, so each
// passes the screen every other mailbox name passes, and a name the
// account does not hold is refused rather than recorded. RFC 9051
// section 6.3.7 permits the server to check that the mailbox exists.
async function subscribeScreensTheNameAndRefusesOneTheAccountDoesNotHold(ctx) {
  var session = await ctx.session("subscribe-refusals");

  var absent = await session.imapAsk("SUBSCRIBE NeverMade");
  count("subscribing to a name the account does not hold is refused",
    absent.verdict === "NO" && /\[NONEXISTENT\]/.test(absent.text), visible(absent.text));

  var wildcard = await session.imapAsk("SUBSCRIBE \"Half*Done\"");
  count("subscribing to a name this server will not keep is refused",
    wildcard.verdict !== "OK", visible(wildcard.text));

  var extra = await session.imapAsk("SUBSCRIBE One Two");
  count("a SUBSCRIBE carrying a second argument is refused", extra.verdict !== "OK",
    visible(extra.text));
  var none = await session.imapAsk("UNSUBSCRIBE");
  count("an UNSUBSCRIBE carrying no name is refused", none.verdict !== "OK", visible(none.text));

  var after = await session.imapAsk("LIST (SUBSCRIBED) \"\" *");
  count("and none of them reached the subscribed set",
    listed(after.text).filter(function (entry) {
      return /NeverMade|Half|^One$|^Two$/.test(entry.name);
    }).length === 0, visible(after.text));

  session.close();
}

// ---- boundaries ------------------------------------------------------------

// Each of the four is an Authenticated state command (RFC 9051 section
// 6.3). A session that sent no credential names no account, and this
// server has no mailbox that is not an account's.
async function theFourVerbsNeedAnAuthenticatedSession(ctx) {
  var session = await Wire.imap(ctx.imapPort, {
    caPem: ctx.caPem, servername: HOSTNAME,
    label: "imap-mailbox-lifecycle unauthenticated",
  });
  ctx.track(session);

  var commands = ["DELETE Anything", "RENAME Anything Else", "SUBSCRIBE Anything",
    "UNSUBSCRIBE Anything"];
  var allowed = [];
  for (var i = 0; i < commands.length; i += 1) {
    var answer = await session.imapAsk(commands[i]);
    if (answer.verdict === "OK") allowed.push(commands[i]);
  }
  count("no unauthenticated session is answered OK by any of the four", allowed.length === 0,
    allowed.join(", "));

  session.close();
}

// The mailbox belongs to the account that holds it. One account's name
// says nothing about another's, and neither removal nor rename may reach
// across.
async function neitherVerbReachesAnotherAccountsMailbox(ctx) {
  var alice = await ctx.session("boundary-owner");
  var bob   = await ctx.bobSession("boundary-other");

  await alice.imapAsk("CREATE Shared");
  var filed = alice.tag();
  await alice.sendLiteral(filed + " APPEND Shared", message("boundary-one"), "<boundary-one>");
  await alice.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Shared");

  var missing = await bob.imapAsk("DELETE Shared");
  count("the other account cannot remove it",
    missing.verdict === "NO" && /\[NONEXISTENT\]/.test(missing.text), visible(missing.text));
  var moved = await bob.imapAsk("RENAME Shared Taken");
  count("and cannot rename it",
    moved.verdict === "NO" && /\[NONEXISTENT\]/.test(moved.text), visible(moved.text));

  var mine = await bob.imapAsk("CREATE Shared");
  count("the same name is free for the other account to take", mine.verdict === "OK",
    visible(mine.text));
  var own = await bob.imapAsk("DELETE Shared");
  count("and removing its own leaves the first account's alone", own.verdict === "OK",
    visible(own.text));

  var opened = await alice.imapAsk("SELECT Shared");
  count("the first account's mailbox still opens holding its message",
    opened.verdict === "OK" && existsIn(opened.text) === 1, visible(opened.text));

  alice.close();
  bob.close();
}

// RFC 9051 section 6.3.9 gives LIST a reference and a pattern, and this
// server now reads both. A listing that ignored them would answer every
// narrowed question with the whole namespace, which is the same answer a
// client gets when it asks for one mailbox and when it asks for all of
// them.
async function listReadsItsReferenceAndPattern(ctx) {
  var session = await ctx.session("list-patterns");

  await session.imapAsk("CREATE Books/Fiction/Recent");
  await session.imapAsk("CREATE Books/History");

  var exact = await session.imapAsk("LIST \"\" \"Books/History\"");
  count("a pattern naming one mailbox answers with that mailbox",
    listedNamed(exact.text, "Books/History") !== null &&
      listedNamed(exact.text, "Books/Fiction") === null, visible(exact.text));

  // RFC 9051 section 5.1: INBOX matches in any case, and nothing else does.
  var spellings = ["inbox", "Inbox", "iNbOx"];
  for (var sp = 0; sp < spellings.length; sp += 1) {
    var asked = await session.imapAsk("LIST \"\" \"" + spellings[sp] + "\"");
    count("LIST of " + spellings[sp] + " answers with INBOX",
      listedNamed(asked.text, "INBOX") !== null, visible(asked.text));
  }
  var wrongCase = await session.imapAsk("LIST \"\" \"books/history\"");
  count("while another mailbox name still matches only in its own case",
    listedNamed(wrongCase.text, "Books/History") === null, visible(wrongCase.text));

  var oneLevel = await session.imapAsk("LIST \"\" \"Books/%\"");
  count("the % wildcard stops at the hierarchy separator",
    listedNamed(oneLevel.text, "Books/Fiction") !== null &&
      listedNamed(oneLevel.text, "Books/Fiction/Recent") === null, visible(oneLevel.text));

  var everything = await session.imapAsk("LIST \"\" \"Books/*\"");
  count("the * wildcard crosses it",
    listedNamed(everything.text, "Books/Fiction/Recent") !== null, visible(everything.text));

  var referenced = await session.imapAsk("LIST \"Books/\" \"%\"");
  count("the reference is prefixed to the pattern",
    listedNamed(referenced.text, "Books/History") !== null &&
      listedNamed(referenced.text, "INBOX") === null, visible(referenced.text));

  var root = await session.imapAsk("LIST \"\" \"\"");
  count("an empty pattern answers with the hierarchy separator alone (section 6.3.9)",
    /^\* LIST \(\\Noselect\) "\/" ""\r?$/m.test(root.text), visible(root.text));

  var several = await session.imapAsk("LIST \"\" (\"INBOX\" \"Books/History\")");
  count("a parenthesized list of patterns answers for each of them",
    listedNamed(several.text, "INBOX") !== null &&
      listedNamed(several.text, "Books/History") !== null &&
      listedNamed(several.text, "Drafts") === null, visible(several.text));

  var sent = await session.imapAskLiteral("LIST \"\"", "Books/History", "<a pattern as a literal>");
  count("a pattern sent as a literal is matched the same way",
    listedNamed(sent.text, "Books/History") !== null &&
      listedNamed(sent.text, "INBOX") === null, visible(sent.text));

  // RFC 9051 section 6.3.9 puts the counts in an untagged STATUS
  // response of their own, which is what a client asking for a folder
  // pane with unread counts sends on connect.
  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Books/History", message("listed-one"), "<listed-one>");
  await session.read(new RegExp("^" + filed + " OK", "m"), "APPEND into Books/History");
  var counted = await session.imapAsk(
    "LIST \"\" \"Books/History\" RETURN (STATUS (MESSAGES UNSEEN))");
  count("the STATUS return option carries the counts beside the name",
    /^\* STATUS "Books\/History" \(MESSAGES 1 UNSEEN 1\)\r?$/m.test(counted.text),
    visible(counted.text));

  var recursive = await session.imapAsk("LIST (SUBSCRIBED RECURSIVEMATCH) \"\" *");
  count("an option this server does not serve is refused by name rather than ignored",
    recursive.verdict === "BAD" && /RECURSIVEMATCH/.test(recursive.text),
    visible(recursive.text));
  var unknown = await session.imapAsk("LIST \"\" * RETURN (NOTHINGLIKEIT)");
  count("and so is a return option it does not serve",
    unknown.verdict === "BAD" && /NOTHINGLIKEIT/.test(unknown.text), visible(unknown.text));

  // The two ceilings on a pattern. The walk pays a pass over the name for
  // each wildcard against each mailbox the account holds, so a pattern
  // matching nothing is what costs, and both ceilings are measured on the
  // reference joined to the pattern rather than on the pattern alone: a
  // ceiling read off the pattern is one a long reference walks past.
  var wildcards = await session.imapAsk("LIST \"\" \"" + "a%".repeat(20) + "z\"");
  count("a pattern carrying more wildcards than this server matches is refused",
    wildcards.verdict === "BAD", visible(wildcards.text));
  var long = await session.imapAsk("LIST \"" + "b".repeat(250) + "/\" \"" + "c".repeat(20) + "*\"");
  count("and so is a reference and pattern that come to more bytes than a name can be",
    long.verdict === "BAD", visible(long.text));

  var ordinary = await session.imapAsk("LIST \"\" \"Books/*\"");
  count("while an ordinary pattern from the same session still answers",
    ordinary.verdict === "OK" && listedNamed(ordinary.text, "Books/History") !== null,
    visible(ordinary.text));

  session.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-mailbox-lifecycle");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;
  var sessions = [];
  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    function opener(address, password) {
      return async function (label) {
        var opened = await Wire.imap(sections.imap.port, {
          caPem: leaf.ca, servername: HOSTNAME,
          address: address, password: password,
          label: "imap-mailbox-lifecycle " + label,
        });
        sessions.push(opened);
        return opened;
      };
    }

    var ctx = {
      identity:   identity,
      alice:      alice,
      bob:        bob,
      imapPort:   sections.imap.port,
      caPem:      leaf.ca,
      track:      function (session) { sessions.push(session); },
      session:    opener(alice.address, ALICE_PASSWORD),
      bobSession: opener(bob.address, BOB_PASSWORD),
    };

    await deleteRemovesAMailboxEveryOtherVerbThenRefuses(ctx);
    await deleteDestroysTheMailTheMailboxHeld(ctx);
    await deleteIsRefusedForAMailboxHoldingPreservedMail(ctx);
    await deleteRefusesInboxAndTheProvisionedRoles(ctx);
    await deleteLeavesInferiorNamesAndMarksTheParentNonExistent(ctx);
    await aRecreatedNameCannotBeMistakenForTheOneThatWent(ctx);
    await renameMovesTheMailboxItsMailAndItsIdentifiers(ctx);
    await aSelectionFollowsTheMailboxItIsHoldingOpen(ctx);
    await aSelectionDoesNotOutliveTheMailboxItHeld(ctx);
    await anotherSessionsSelectionFollowsTooRename(ctx);
    await renameCarriesTheWholeHierarchyUnderTheName(ctx);
    await renameCreatesTheSuperiorLevelsTheNewNameNeeds(ctx);
    await renamingInboxMovesTheMailAndLeavesInboxWhereItWas(ctx);
    await renameRefusesTheNamesItCannotMove(ctx);
    await subscribingMarksAMailboxAndNarrowsTheListing(ctx);
    await aSubscribedNameOutlivesTheMailboxItNames(ctx);
    await subscribeScreensTheNameAndRefusesOneTheAccountDoesNotHold(ctx);
    await theFourVerbsNeedAnAuthenticatedSession(ctx);
    await neitherVerbReachesAnotherAccountsMailbox(ctx);
    await listReadsItsReferenceAndPattern(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) { s.close(); });
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "imap-mailbox-lifecycle", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
