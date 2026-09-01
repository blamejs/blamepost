// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the browser surface accepts back off a request, and what it does
 * with it.
 *
 * `test/layer-1-state/web.test.js` pins the folder half: a folder name
 * that names another account's folder resolves to nothing and the route
 * answers 404. This file pins the other half of the same question. A
 * folder name is not the only identifier a request carries. A message
 * identifier is one too, and a route that has checked the folder and
 * then hands the identifier straight to the mailbox access agent has
 * checked the part the reader could not have guessed and skipped the
 * part they could.
 *
 * That distinction is not academic against this substrate. The message
 * store scopes a move and an expunge by folder and does not scope a flag
 * change at all: `setFlags` writes one row per identifier and never
 * looks at the folder it was handed. So a route that passes an
 * unresolved identifier through reaches every message on the server, and
 * the audit row it leaves says the change happened in the caller's own
 * folder.
 *
 * The vectors here are the ones a signed in account can send by hand:
 *
 *   - a bulk action posted to a folder this account owns, naming a
 *     message identifier belonging to another account;
 *   - a JMAP `Thread/get` naming another account's message, which
 *     reaches the store's thread index without passing through any
 *     folder at all;
 *   - a JMAP `Email/set` that names a keyword IMAP does not expose to a
 *     JMAP client, or asks to create an Email this surface cannot
 *     create;
 *   - a redirect target this route reads as a path and the redirect
 *     helper underneath it reads as an authority.
 *
 * Every one of them is driven over a real loopback port with a real
 * session, because a helper called directly proves what the helper does
 * and not what the route does.
 *
 * Run standalone: node test/layer-1-state/web-isolation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var LOOPBACK = "127.0.0.1";
var DOMAIN   = "example.com";

var ALICE_PASSWORD = "quiet lantern bicycle 4291";
var BOB_PASSWORD   = "another quiet lantern 7715";

// One shared address pointed at each mailbox. Each account may write
// its own and neither may write the other's, which is the claim the
// sending identity vectors are about.
var ALICE_ALIAS = "alices-desk@" + DOMAIN;
var BOB_ALIAS   = "bobs-desk@" + DOMAIN;

var ALICE_SUBJECT = "Alices own quarterly note";
var BOB_SUBJECT   = "Bobs private quarterly numbers";
var BOB_BODY      = "zebra7741 belongs to bob and to nobody else";

// A recipient list a comma alone cannot be read as. RFC 5322 section 3.4
// lets a display name be a quoted string and a quoted string may hold a
// comma, so this list has three recipients and four commas.
var QUOTED_SUBJECT = "Room booking for the offsite";
var QUOTED_TO      = "<alice@" + DOMAIN + ">, \"Doe, Jane\" <jane@example.net>, " +
  "<colleague@example.net>";

// A message whose images are all carried inside it. Nothing here points
// off site, which is the case a count of remote images reads as no
// images at all.
var INLINE_SUBJECT = "Floor plan for the offsite";
var INLINE_PIXEL   = "data:image/gif;base64," +
  "R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";

// The two images are told apart by their alt text, which the tag
// allowlist keeps and which goes with the tag when the tag is dropped.
// So finding one and not the other is the whole assertion about which
// message a reader's request for images reached.
var INLINE_ALT       = "floor plan";
var INLINE_REPLY_ALT = "site map";

function inlineHtml(alt) {
  return "<p>The room is upstairs.</p>" +
    "<img src=\"" + INLINE_PIXEL + "\" alt=\"" + alt + "\" width=\"1\" height=\"1\">";
}

// The adapter names each account's physical folders with this prefix, so
// finding one anywhere in a rendered page is the leak itself.
var STORE_FOLDER_PREFIX = "mbx_";

// Ceiling on the listener drain. The per request ceiling belongs to the
// reader in test/helpers/browser.js.
var HTTP_TIMEOUT_MS = 5000;

// A path to this server's URL parser and an authority to a browser's.
// The WHATWG URL parser folds a backslash into a slash for an HTTP URL,
// so a Location header carrying this one navigates off site.
var BACKSLASH_AUTHORITY = "/\\attacker.example.net/pwned";

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

function wiringFor(cfg, identity, mailStore) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent:     b.mail.agent.create({ store: mailStore, dispatch: { mode: "local" } }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: mailStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: mailStore,
    }),
    dkim:     dkimHandle,
    delivery: deliveryHandle,
    config:   cfg,
  };
}

function messageIdFor(subject) {
  return subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net";
}

// One builder for every fixture here. The messages differ only in which
// headers they carry, so writing them as one function with the parts
// named keeps a change to the shape of a fixture from having to be made
// four times and applied to three of them.
function messageWith(fields) {
  var lines = ["Message-ID: <" + fields.messageId + ">"];
  if (fields.inReplyTo) {
    lines.push("In-Reply-To: <" + fields.inReplyTo + ">");
    lines.push("References: <" + fields.inReplyTo + ">");
  }
  lines.push("From: Sender <sender@example.net>");
  lines.push("To: " + fields.to);
  lines.push("Subject: " + fields.subject);
  lines.push("Date: " + (fields.date || "Sat, 22 Aug 2026 09:00:00 +0000"));
  if (fields.contentType) lines.push("Content-Type: " + fields.contentType);
  return Buffer.from(lines.join("\r\n") + "\r\n\r\n" + fields.body + "\r\n", "utf8");
}

function messageFor(recipient, subject, body) {
  return messageWith({
    messageId: messageIdFor(subject),
    to:        "<" + recipient + ">",
    subject:   subject,
    body:      body,
  });
}

// A reply to a message, so the two land in one thread. The thread index
// is keyed on the root's identifier, which is what a JMAP client is
// handed as a thread id and what it sends back.
function replyTo(recipient, subject, body, parentMessageId) {
  return messageWith({
    messageId:  subject.replace(/[^A-Za-z0-9]/g, "") + "reply@example.net",
    inReplyTo:  parentMessageId,
    to:         "<" + recipient + ">",
    subject:    "Re: " + subject,
    date:       "Sat, 22 Aug 2026 10:00:00 +0000",
    body:       body,
  });
}

// The reader holding one session, and the method response reader beside
// it, both live in test/helpers/browser.js. They are shared rather than
// copied because three files need them now, and two readers that
// disagree about what a sign in looks like is how one of them stops
// catching things.
var jmapAnswer = browser.answer;

// The flags a message carries right now, read through the folder that
// actually holds it rather than through the folder the request named.
async function flagsOf(agent, accountId, folder, objectId) {
  var message = await agent.fetch({
    actor:    { id: accountId, roles: ["account"] },
    folder:   folder.storeName,
    objectId: objectId,
  });
  return message && Array.isArray(message.flags) ? message.flags : null;
}

// ---- the vectors ----

// A bulk action names its folder and its messages separately. The folder
// is resolved against the account; the identifiers were not, and the
// substrate's flag write ignores the folder it is handed, so an
// identifier belonging to another account lands on that account's
// message.
async function testABulkActionCannotReachAnotherAccountsMessage(reader, agent, victim) {
  var before = await flagsOf(agent, victim.accountId, victim.inbox, victim.objectId);
  count("the other account's message starts unflagged and unread",
    before !== null && before.indexOf("\\Flagged") === -1 && before.indexOf("\\Seen") === -1,
    JSON.stringify(before));

  // The mutation is asserted before the status code, because a route
  // that writes the flag and then answers 404 has done the damage and
  // hidden it, and a status-first assertion stops at the cover story.
  var flagged = await reader.form("/mail/INBOX/actions", {
    action: "flag", objectId: victim.objectId,
  });
  var afterFlag = await flagsOf(agent, victim.accountId, victim.inbox, victim.objectId);
  count("the other account's message did not become flagged",
    afterFlag !== null && afterFlag.indexOf("\\Flagged") === -1, JSON.stringify(afterFlag));
  count("a bulk flag naming another account's message is refused",
    flagged.status === 404 || flagged.status === 403, flagged.status);

  var read = await reader.form("/mail/INBOX/actions", {
    action: "read", objectId: victim.objectId,
  });
  var afterRead = await flagsOf(agent, victim.accountId, victim.inbox, victim.objectId);
  count("the other account's message was not marked read",
    afterRead !== null && afterRead.indexOf("\\Seen") === -1, JSON.stringify(afterRead));
  count("a bulk mark-read naming another account's message is refused",
    read.status === 404 || read.status === 403, read.status);

  // A batch that mixes one of the reader's own messages with one of the
  // other account's must not act on either. A route that filters the
  // list and proceeds has still told the caller which identifiers exist.
  var mixed = await reader.form("/mail/INBOX/actions", {
    action: "flag", objectId: [victim.readerObjectId, victim.objectId],
  });
  count("a batch mixing an owned message with another account's is refused whole",
    mixed.status === 404 || mixed.status === 403, mixed.status);

  var mixedVictim = await flagsOf(agent, victim.accountId, victim.inbox, victim.objectId);
  count("the mixed batch left the other account's message untouched",
    mixedVictim !== null && mixedVictim.indexOf("\\Flagged") === -1,
    JSON.stringify(mixedVictim));

  // Move and purge reach different verbs than a flag change does. The
  // substrate scopes those two by folder underneath, so they were never
  // the leak, and that is exactly why they are driven: the refusal has
  // to come from this surface rather than from a layer below it that
  // could stop scoping them tomorrow.
  var moved = await reader.form("/mail/INBOX/actions", {
    action: "move", objectId: victim.objectId, destination: "Archive",
  });
  count("a move naming another account's message is refused",
    moved.status === 404 || moved.status === 403, moved.status);

  var purged = await reader.form("/mail/INBOX/actions", {
    action: "purge", objectId: victim.objectId,
  });
  count("a purge naming another account's message is refused",
    purged.status === 404 || purged.status === 403, purged.status);

  var trashed = await reader.form("/mail/INBOX/actions", {
    action: "trash", objectId: victim.objectId,
  });
  count("a trash naming another account's message is refused",
    trashed.status === 404 || trashed.status === 403, trashed.status);
}

// A form on a folder page can select at most the rows the page shows, so
// a request naming far more than that is not one. Resolving each
// identifier costs a sealed column read, which is why the ceiling
// refuses rather than slicing: answering the first hundred would report
// a partial result as a whole one.
//
// Two shapes, because the request layer bounds one of them and not the
// other. A repeated form field is capped where the body is parsed; a
// JSON array is not, and that is the shape the route has to bound for
// itself.
async function testABulkActionIsBounded(reader) {
  var many = [];
  for (var i = 0; i < 400; i += 1) many.push("obj_" + String(i));

  var asForm = await reader.form("/mail/INBOX/actions", {
    action: "read", objectId: many,
  });
  count("a form naming more messages than the body parser accepts is refused there",
    asForm.status === 413, asForm.status);

  var asJson = await reader.post("/mail/INBOX/actions", "application/json",
    JSON.stringify({ action: "read", objectId: many }));
  count("a JSON body naming far more messages than a page holds is refused by the route",
    asJson.status === 400, asJson.status + " " + asJson.body.slice(0, 160));
}

// The same route, driven the way the page drives it, because a check
// that refuses everything has certified a broken mailbox rather than an
// isolated one.
async function testTheReadersOwnBulkActionStillWorks(reader, agent, own) {
  var flagged = await reader.form("/mail/INBOX/actions", {
    action: "flag", objectId: own.objectId,
  });
  count("the reader's own message takes a bulk flag",
    flagged.status === 302, flagged.status + " " + flagged.body.slice(0, 160));

  var after = await flagsOf(agent, own.accountId, own.inbox, own.objectId);
  count("the reader's own message is flagged afterwards",
    after !== null && after.indexOf("\\Flagged") !== -1, JSON.stringify(after));

  var unflagged = await reader.form("/mail/INBOX/actions", {
    action: "unflag", objectId: own.objectId,
  });
  count("the reader's own message takes the flag back off",
    unflagged.status === 302, unflagged.status);

  var cleared = await flagsOf(agent, own.accountId, own.inbox, own.objectId);
  count("the flag is gone again",
    cleared !== null && cleared.indexOf("\\Flagged") === -1, JSON.stringify(cleared));

  // Filing the message away and bringing it back, because a check that
  // only ever drives the flag verbs would let a move break unnoticed.
  var filed = await reader.form("/mail/INBOX/actions", {
    action: "move", objectId: own.objectId, destination: "Archive",
  });
  count("the reader's own message moves to a folder the reader owns",
    filed.status === 302, filed.status + " " + filed.body.slice(0, 160));

  var archive = await reader.get("/mail/Archive");
  count("the moved message is in the folder it was moved to",
    archive.body.indexOf(ALICE_SUBJECT) !== -1, archive.status);

  var back = await reader.form("/mail/Archive/actions", {
    action: "move", objectId: own.objectId, destination: "INBOX",
  });
  count("and it moves back", back.status === 302, back.status);

  // A destination this account does not own used to send the reader back
  // to the folder with no notice, which reads on screen as a move that
  // happened.
  var nowhere = await reader.form("/mail/INBOX/actions", {
    action: "move", objectId: own.objectId, destination: "no-such-folder",
  });
  count("a move to a folder this account does not own is refused rather than ignored",
    nowhere.status === 404, nowhere.status);
}

// Filing a message away has to file it somewhere the reader can reach.
// Every account here has its own Trash, and a soft delete that names a
// Trash belonging to nobody takes the message out of the mailbox
// entirely: gone from the folder it was in, absent from the folder the
// reader would look in, and not deleted either.
async function testTrashLandsInTheReadersOwnTrash(reader, agent, own) {
  var trashed = await reader.form("/mail/INBOX/actions", {
    action: "trash", objectId: own.objectId,
  });
  count("the reader's own message takes a trash action",
    trashed.status === 302, trashed.status + " " + trashed.body.slice(0, 200));

  // Anchored on the identifier rather than the subject: the reply in
  // this account's inbox carries the parent's subject inside its own, so
  // a subject match would report the message as still there when what is
  // still there is its reply.
  var inbox = await reader.get("/mail/INBOX");
  count("the trashed message has left the inbox",
    inbox.body.indexOf(own.objectId) === -1, inbox.status);

  var trash = await reader.get("/mail/Trash");
  count("the trashed message is in the reader's own Trash",
    trash.status === 200 && trash.body.indexOf(own.objectId) !== -1, trash.status);

  var trashFolder = own.folders.filter(function (f) { return f.name === "Trash"; })[0];
  var flags = await flagsOf(agent, own.accountId, trashFolder, own.objectId);
  count("and it carries the deleted mark a soft delete sets",
    flags !== null && flags.indexOf("\\Deleted") !== -1, JSON.stringify(flags));

  var restored = await reader.form("/mail/Trash/actions", {
    action: "move", objectId: own.objectId, destination: "INBOX",
  });
  count("the reader can take it back out of Trash", restored.status === 302, restored.status);

  // Nothing on this surface clears the deleted mark on its own, so a
  // message brought back out of Trash would otherwise sit in the inbox
  // struck through with no way to undo it, and the next purge of that
  // folder would take it.
  var afterRestore = await flagsOf(agent, own.accountId, own.inbox, own.objectId);
  count("taking it out of Trash takes the deleted mark off it",
    afterRestore !== null && afterRestore.indexOf("\\Deleted") === -1,
    JSON.stringify(afterRestore));
}

// A folder name in a search is resolved like every other folder name a
// request carries. Falling back to the inbox on a miss answers a
// question the reader did not ask and labels the results as though it
// had.
async function testSearchResolvesItsFolderName(reader, victim) {
  var borrowed = await reader.get("/search?q=quarterly&folder=" +
    encodeURIComponent(victim.inbox.storeName));
  count("a search scoped to another account's folder is refused",
    borrowed.status === 404, borrowed.status);
  count("that refusal carries none of the other account's mail",
    borrowed.body.indexOf(BOB_SUBJECT) === -1 && borrowed.body.indexOf(BOB_BODY) === -1,
    borrowed.body.slice(0, 200));

  var own = await reader.get("/search?q=quarterly&folder=INBOX");
  count("a search scoped to a folder this account owns still runs",
    own.status === 200, own.status);
  count("and it finds this account's own message",
    own.body.indexOf(ALICE_SUBJECT) !== -1, own.status);

  var unscoped = await reader.get("/search?q=quarterly");
  count("a search naming no folder starts in the inbox rather than refusing",
    unscoped.status === 200, unscoped.status);
}

// RFC 8620 section 5.1 wants a state string that changes when the
// objects change and holds still when they do not. A wall clock reading
// does neither: it moves when nothing has happened, so every answer
// invalidates a client's cached copy, and it can step backwards.
async function testJmapStateTracksTheMailAndNotTheClock(reader, readerId, own) {
  var first = jmapAnswer(await reader.jmap([
    ["Mailbox/get", { accountId: readerId }, "c0"],
  ]))[1].state;
  var second = jmapAnswer(await reader.jmap([
    ["Mailbox/get", { accountId: readerId }, "c0"],
  ]))[1].state;
  count("two reads with nothing changed in between answer the same state",
    typeof first === "string" && first.length > 0 && first === second,
    first + " then " + second);

  var changed = await reader.jmap([
    ["Email/set", {
      accountId: readerId,
      update: (function () {
        var update = {};
        update[own.objectId] = { "keywords/$flagged": true };
        return update;
      }()),
    }, "c0"],
  ]);
  var setAnswer = jmapAnswer(changed)[1];
  count("a change reports the state it started from",
    setAnswer.oldState === first, setAnswer.oldState + " against " + first);
  count("and a state that has moved on",
    typeof setAnswer.newState === "string" && setAnswer.newState !== first,
    setAnswer.newState);
  count("the new state is ahead of the old one rather than beside it",
    parseInt(setAnswer.newState, 10) > parseInt(first, 10),
    setAnswer.oldState + " to " + setAnswer.newState);

  var afterwards = jmapAnswer(await reader.jmap([
    ["Mailbox/get", { accountId: readerId }, "c0"],
  ]))[1].state;
  count("a later read agrees with the state the change reported",
    afterwards === setAnswer.newState, afterwards + " against " + setAnswer.newState);
}

// `Thread/get` reaches the store's thread index directly. Nothing in the
// call names a folder, so an identifier that is not resolved against the
// account's own folders first answers with every copy of that thread on
// the server.
async function testThreadGetAnswersOnlyForTheReadersOwnMail(reader, readerId, victim, inboxCount) {
  var borrowed = await reader.jmap([
    ["Thread/get", { accountId: readerId, ids: [victim.objectId] }, "c0"],
  ]);
  var answer = jmapAnswer(borrowed)[1];
  var listed = Array.isArray(answer.list) ? answer.list : [];
  var leaked = [];
  for (var i = 0; i < listed.length; i += 1) {
    var ids = Array.isArray(listed[i].emailIds) ? listed[i].emailIds : [];
    for (var j = 0; j < ids.length; j += 1) leaked.push(ids[j]);
  }
  count("a Thread/get naming another account's message lists none of its messages",
    leaked.length === 0, JSON.stringify(leaked));
  // The identifier the reader never held is the one that proves the
  // difference between an answer echoing the request back and an answer
  // handing over something new.
  count("and the answer carries no identifier the reader could not already name",
    borrowed.body.indexOf(victim.unseenObjectId) === -1,
    borrowed.body.slice(0, 300));
  count("that thread is reported not found rather than answered empty",
    Array.isArray(answer.notFound) && answer.notFound.indexOf(victim.objectId) !== -1,
    JSON.stringify(answer.notFound));

  // The reader's own thread, through the same method, and it has two
  // messages in it so an answer of one would be a filter that is too
  // wide as well as one that is too narrow.
  var own = await reader.jmap([
    ["Email/query", { accountId: readerId, filter: { inMailbox: "INBOX" } }, "c0"],
    ["Email/get", { accountId: readerId, "#ids": {
      resultOf: "c0", name: "Email/query", path: "/ids",
    } }, "c1"],
  ]);
  var fetched = jmapAnswer(own, 1)[1];
  count("the reader's own inbox answers Email/get for every message in it",
    Array.isArray(fetched.list) && fetched.list.length === inboxCount &&
    Array.isArray(fetched.notFound) && fetched.notFound.length === 0,
    fetched.list.length + " of " + inboxCount + ", missing " +
    JSON.stringify(fetched.notFound));
  // Newest first, and the newest message in this inbox is the reply, so
  // this is the thread with two messages in it rather than one of the
  // single-message fixtures appended before it.
  var threadId = fetched.list[0].threadId;

  var ownThread = await reader.jmap([
    ["Thread/get", { accountId: readerId, ids: [threadId] }, "c0"],
  ]);
  var ownAnswer = jmapAnswer(ownThread)[1];
  count("the reader's own thread carries both of the reader's messages",
    Array.isArray(ownAnswer.list) && ownAnswer.list.length === 1 &&
    ownAnswer.list[0].emailIds.length === 2,
    JSON.stringify(ownAnswer.list));
}

// RFC 8621 section 4.1.1 maps four JMAP keywords onto IMAP system flags
// and exposes no others. A patch key is not a free-form flag name: a
// client that can name `$deleted` can mark mail for an IMAP EXPUNGE that
// no JMAP method would have let it ask for.
async function testEmailSetRefusesKeywordsJmapDoesNotExpose(reader, readerId, agent, own) {
  var deleted = await reader.jmap([
    ["Email/set", {
      accountId: readerId,
      update: (function () {
        var update = {};
        update[own.objectId] = { "keywords/$deleted": true };
        return update;
      }()),
    }, "c0"],
  ]);
  var answer = jmapAnswer(deleted)[1];
  count("Email/set refuses a keyword JMAP does not expose",
    answer.notUpdated !== undefined &&
    Object.prototype.hasOwnProperty.call(answer.notUpdated, own.objectId),
    JSON.stringify(answer));

  var flags = await flagsOf(agent, own.accountId, own.inbox, own.objectId);
  count("no \\Deleted flag was written by that patch",
    flags !== null && flags.indexOf("\\Deleted") === -1, JSON.stringify(flags));
}

// A keyword set that replaces the whole map has to replace the whole
// map. Reporting the update as applied while dropping `$draft` on the
// floor tells a client something that is not true about its own mail.
async function testEmailSetHonoursAWholeKeywordSet(reader, readerId, agent, own) {
  var applied = await reader.jmap([
    ["Email/set", {
      accountId: readerId,
      update: (function () {
        var update = {};
        update[own.objectId] = { keywords: { $seen: true, $draft: true } };
        return update;
      }()),
    }, "c0"],
  ]);
  var answer = jmapAnswer(applied)[1];
  count("Email/set accepts a whole keyword set for the reader's own message",
    answer.updated !== undefined &&
    Object.prototype.hasOwnProperty.call(answer.updated, own.objectId),
    JSON.stringify(answer));

  var flags = await flagsOf(agent, own.accountId, own.inbox, own.objectId);
  count("the keywords the set named are the flags the message carries",
    flags !== null && flags.indexOf("\\Seen") !== -1 && flags.indexOf("\\Draft") !== -1,
    JSON.stringify(flags));

  var read = await reader.jmap([
    ["Email/get", { accountId: readerId, ids: [own.objectId] }, "c0"],
  ]);
  var keywords = jmapAnswer(read)[1].list[0].keywords;
  count("Email/get reports back the keywords Email/set accepted",
    keywords !== undefined && keywords.$seen === true && keywords.$draft === true,
    JSON.stringify(keywords));
}

// This surface has no way to create an Email: a draft is composed
// through the outbound composer, not appended by a client. Answering a
// create request with a response that names neither `created` nor
// `notCreated` loses the client's message and reports nothing.
async function testEmailSetRefusesACreateItCannotPerform(reader, readerId) {
  var created = await reader.jmap([
    ["Email/set", {
      accountId: readerId,
      create: { draft1: { mailboxIds: { INBOX: true }, subject: "a draft" } },
    }, "c0"],
  ]);
  var answer = jmapAnswer(created)[1];
  count("Email/set answers a create request rather than dropping it",
    answer.notCreated !== undefined &&
    Object.prototype.hasOwnProperty.call(answer.notCreated, "draft1"),
    JSON.stringify(answer));
  count("the create refusal carries no created entry for the same key",
    answer.created === undefined || answer.created === null ||
    !Object.prototype.hasOwnProperty.call(answer.created, "draft1"),
    JSON.stringify(answer.created));
}

// A redirect target that begins with a slash is not automatically a
// path: a browser resolving `/\host` treats the backslash as a second
// slash and navigates to `host`. The redirect helper knows that and
// refuses the shape, which is why this vector is an error page rather
// than a trip off site. A route reading a target more loosely than the
// helper does hands it one the helper throws on, and the reader loses a
// preference change to a 500 instead of changing a theme.
//
// Both halves are asserted, because a route that started answering 302
// by waving the target through would satisfy the first alone.
async function testThePreferenceRedirectStaysOnThisServer(reader) {
  var away = await reader.form("/prefs/theme", {
    theme: "dark", back: BACKSLASH_AUTHORITY,
  });
  count("a preference post is answered rather than thrown on", away.status === 302, away.status);
  count("the redirect does not carry an authority a browser would follow off site",
    typeof away.location === "string" &&
    !(away.location.charAt(0) === "/" &&
      (away.location.charAt(1) === "/" || away.location.charAt(1) === "\\")),
    away.location);

  var scheme = await reader.form("/prefs/theme", {
    theme: "light", back: "https://attacker.example.net/pwned",
  });
  count("an absolute target for another origin is not followed either",
    typeof scheme.location === "string" &&
    scheme.location.indexOf("attacker.example.net") === -1,
    scheme.location);

  var ordinary = await reader.form("/prefs/theme", {
    theme: "dark", back: "/mail/INBOX",
  });
  count("an ordinary path is still where the reader lands",
    ordinary.location === "/mail/INBOX", ordinary.location);
}

// The physical folder name is the token the one namespacing layer keeps
// to itself. A page that prints one anywhere has handed a caller the
// name it would need to address another account's mail directly.
async function testNoStoreFolderNameReachesAnyPage(reader) {
  var pages = ["/mail/INBOX", "/compose", "/search?q=quarterly"];
  for (var i = 0; i < pages.length; i += 1) {
    var page = await reader.get(pages[i]);
    count(pages[i] + " renders for the signed in reader", page.status === 200, page.status);
    count(pages[i] + " prints no store folder name",
      page.body.indexOf(STORE_FOLDER_PREFIX) === -1,
      page.body.slice(Math.max(0, page.body.indexOf(STORE_FOLDER_PREFIX) - 80), 200));
  }
}

// Where the page sends a reader who wants to go back to their mail. It
// is a folder this account owns, resolved from the one layer that holds
// the map, rather than a folder name a template spelled for itself.
async function testTheWayBackToMailIsThisAccountsOwnFolder(reader, own) {
  var compose = await reader.get("/compose");
  var links = [];
  var pattern = /class="topnav-link" href="([^"]*)"|class="btn btn-quiet" href="([^"]*)"/g;
  var hit = pattern.exec(compose.body);
  while (hit !== null) {
    var href = hit[1] || hit[2] || "";
    if (href.indexOf("/mail/") === 0 && links.indexOf(href) === -1) links.push(href);
    hit = pattern.exec(compose.body);
  }
  count("the page offers a way back to this reader's mail", links.length > 0, links.join(","));

  for (var i = 0; i < links.length; i += 1) {
    var landed = await reader.get(links[i]);
    count("the way back at " + links[i] + " reaches a folder this account owns",
      landed.status === 200, landed.status);
    count("and that folder is the one holding this reader's own mail",
      landed.body.indexOf(own.objectId) !== -1, links[i]);
  }
}

// A recipient list is not a list of anything a comma separates. RFC 5322
// section 3.4 lets a display name be a quoted string, and a quoted
// string may hold a comma, so splitting on the separator alone cuts one
// recipient into two: the half before the comma becomes a recipient that
// is not an address, and the half after keeps the address.
async function testAReplyAllReadsQuotedDisplayNames(reader, quoted) {
  var draft = await reader.get("/compose?mode=reply-all&folder=INBOX&source=" +
    encodeURIComponent(quoted.objectId));
  count("the reply-all draft renders", draft.status === 200, draft.status);

  var cc = /id="cc"[^>]*value="([^"]*)"/.exec(draft.body);
  var value = cc === null ? "" : cc[1];
  count("the reply-all copy list carries the other recipient's address",
    value.indexOf("colleague@example.net") !== -1, value);
  count("and carries no fragment of a display name as though it were an address",
    value.indexOf("Doe") === -1 && value.indexOf("&quot;") === -1, value);
}

// The compose form validates who a message is going to. Every list it
// goes to is a list of recipients, so a copy list that cannot be parsed
// is the reader's mistake to fix on the form rather than a failure
// reported as though the next server along had refused it.
async function testEveryRecipientListIsValidated(reader) {
  var badCopy = await reader.post("/compose", "application/x-www-form-urlencoded",
    "to=" + encodeURIComponent("bob@" + DOMAIN) +
    "&cc=" + encodeURIComponent("not an address at all") +
    "&subject=probe&text=probe" +
    "&_csrf=" + encodeURIComponent(/name="_csrf" value="([^"]*)"/.exec(
      (await reader.get("/compose")).body)[1]));
  count("a copy list that is not an address is refused on the form",
    badCopy.status === 400, badCopy.status + " " + badCopy.body.slice(0, 200));
  count("and the refusal names the address it could not read",
    badCopy.body.indexOf("not an address at all") !== -1,
    badCopy.body.slice(0, 300));
}

// The set of addresses an account may write is an answer about that
// account, and it is security relevant in both directions: it tells the
// holder of one mailbox which other names it may put on a message, and
// an answer that leaked another account's would both disclose the shape
// of somebody else's delegation and offer an address that account holds.
//
// Both surfaces that compose their own outbound mail read that set, so
// both are asked here. The identity a client is refused is a REAL one
// belonging to the other account, read off that account's own session
// rather than derived a second time in this file: an id invented here
// would be refused for being unknown to anybody and would prove nothing
// about the account boundary.
async function testTheSendingIdentitySetIsThisAccountsOwn(reader, stranger, own, other) {
  var mine = jmapAnswer(await reader.jmap([
    ["Identity/get", { accountId: own.accountId }, "i0"],
  ]), 0)[1];
  var addresses = (mine.list || []).map(function (identity) { return identity.email; });
  count("Identity/get answers with this account's own address and the alias pointed " +
    "at its mailbox",
    addresses.indexOf(own.address) !== -1 && addresses.indexOf(own.alias) !== -1,
    JSON.stringify(addresses));
  count("and with nothing belonging to the other account",
    addresses.indexOf(other.address) === -1 && addresses.indexOf(other.alias) === -1,
    JSON.stringify(addresses));

  var theirs = jmapAnswer(await stranger.jmap([
    ["Identity/get", { accountId: other.accountId }, "i1"],
  ]), 0)[1];
  var theirIdentity = (theirs.list || []).filter(function (identity) {
    return identity.email === other.alias;
  })[0];
  count("the other account really does hold the alias this reader is about to be " +
    "refused, so the refusal is about who holds it rather than whether it exists",
    theirIdentity !== undefined,
    JSON.stringify((theirs.list || []).map(function (i) { return i.email; })));

  var offered = jmapAnswer(await reader.jmap([
    ["Identity/get", { accountId: own.accountId, ids: [theirIdentity.id] }, "i2"],
  ]), 0)[1];
  count("asking for the other account's identity by its real id answers not found " +
    "rather than handing it over",
    (offered.list || []).length === 0 && (offered.notFound || []).indexOf(theirIdentity.id) !== -1,
    JSON.stringify(offered));

  var page = await reader.get("/compose");
  count("the compose form offers this account its own alias",
    page.body.indexOf("value=\"" + own.alias + "\"") !== -1, "HTTP " + page.status);
  count("and never offers the other account's",
    page.body.indexOf("value=\"" + other.alias + "\"") === -1, "HTTP " + page.status);

  var posted = await reader.form("/compose", {
    from: other.alias, to: "buyer@peer.example", subject: "probe", text: "probe",
  });
  count("writing as an address the other account holds is refused on the form",
    posted.status === 400, posted.status + " " + posted.body.slice(0, 200));
  count("and the refusal names the address that was rejected",
    posted.body.indexOf(other.alias) !== -1, posted.body.slice(0, 300));

  var submitted = jmapAnswer(await reader.jmap([["EmailSubmission/set", {
    accountId: own.accountId,
    create:    { s0: { identityId: theirIdentity.id, emailId: own.objectId } },
  }, "e0"]]), 0)[1];
  var refusal = (submitted.notCreated || {}).s0 || null;
  count("and a submission naming that identity is refused as one this account does " +
    "not hold",
    refusal !== null && refusal.type === "identityNotFound",
    JSON.stringify(submitted));
}

// Images are held out of a message until the reader asks for them. Which
// images those are is decided by the tag allowlist, and every `img` the
// message carried is dropped, not only the ones pointing off site. A
// count that reads only the off-site ones leaves a message whose images
// are all inline showing no images and offering no way to ask for them.
async function testHeldImagesAreOfferedBackToTheReader(reader, inline) {
  var page = await reader.get("/mail/INBOX/" + encodeURIComponent(inline.objectId));
  count("the message with inline images renders", page.status === 200, page.status);
  count("the reader is told images are being held back",
    page.body.indexOf("images are held back") !== -1, page.status);
  count("and is offered a way to ask for them",
    page.body.indexOf("?images=on") !== -1, page.status);

  var shown = await reader.get("/mail/INBOX/" + encodeURIComponent(inline.objectId) +
    "?images=on");
  count("asking for them renders the image",
    shown.status === 200 && shown.body.indexOf("<img") !== -1, shown.status);
}

// Asking to see one message's images is not asking to tell every other
// sender in the conversation that their message was open on the screen.
// A conversation page renders the whole chain, so the request has to
// reach the message it names and no other, and every message still
// holding images has to carry its own way to ask.
async function testAskingForImagesReachesOneMessage(reader, opened, alongside) {
  var held = await reader.get("/mail/INBOX/" + encodeURIComponent(opened.objectId));
  count("both messages in the conversation hold their images back",
    held.body.indexOf("alt=\"" + INLINE_ALT + "\"") === -1 &&
    held.body.indexOf("alt=\"" + INLINE_REPLY_ALT + "\"") === -1, held.status);
  count("and the other message offers its own way to ask",
    held.body.indexOf(encodeURIComponent(alongside.objectId) + "?images=on") !== -1,
    held.status);

  var shown = await reader.get("/mail/INBOX/" + encodeURIComponent(opened.objectId) +
    "?images=on");
  count("asking renders the image in the message that was asked about",
    shown.body.indexOf("alt=\"" + INLINE_ALT + "\"") !== -1, shown.status);
  count("and leaves the other message's image held back",
    shown.body.indexOf("alt=\"" + INLINE_REPLY_ALT + "\"") === -1, shown.status);
  count("the other message still offers its own way to ask",
    shown.body.indexOf(encodeURIComponent(alongside.objectId) + "?images=on") !== -1,
    shown.status);
}

// A folder page is a window over the folder's sequence numbers, and the
// window is chosen from the folder's own high-water mark. A permanent
// delete moves that mark by a different rule than every other write does,
// so the two stop agreeing about what scale the numbers are on, and a
// window sized for one lands nowhere near the other.
//
// Which is to say: the messages a purge did not touch have to still be
// there afterwards, on the page and through JMAP alike, and the folder
// this runs against is the one every other vector already used, so the
// numbers it holds are the ordinary ones rather than a fresh folder's.
async function testAPurgeLeavesTheRestOfTheFolderReadable(reader, readerId, doomed, survivors) {
  var purged = await reader.form("/mail/INBOX/actions", {
    action: "purge", objectId: doomed.objectId,
  });
  count("the reader's own message takes a purge",
    purged.status === 302, purged.status + " " + purged.body.slice(0, 200));

  var page = await reader.get("/mail/INBOX");
  count("the folder still renders after the purge", page.status === 200, page.status);
  count("the purged message is gone from it",
    page.body.indexOf(doomed.objectId) === -1, page.status);
  for (var i = 0; i < survivors.length; i += 1) {
    count("the message at " + survivors[i] + " the purge did not touch is still listed",
      page.body.indexOf(survivors[i]) !== -1,
      page.body.indexOf("msglist") === -1 ? "no list rendered" : "list rendered without it");
  }

  var queried = await reader.jmap([
    ["Email/query", { accountId: readerId, filter: { inMailbox: "INBOX" } }, "c0"],
  ]);
  var ids = jmapAnswer(queried)[1].ids;
  count("Email/query answers with the messages the purge left",
    Array.isArray(ids) && ids.length === survivors.length,
    JSON.stringify(ids));
}

// A patch is one request and RFC 8621 section 5.3 answers it per id, so
// a message that appears under `notUpdated` has to be a message nothing
// happened to. `Object.keys` decides the order the properties are read
// in, so a patch that both files a message and names a property this
// server cannot set would otherwise file it and then refuse the request
// that filed it, leaving the client's view and the server's apart with
// nothing to reconcile them: the client is told the update did not
// happen, and the message has moved.
async function testARefusedPatchMovesNothing(reader, readerId, agent, own) {
  var trash = own.folders.filter(function (row) { return row.name === "Trash"; })[0];
  count("the reader's account has a Trash folder to file into",
    trash !== undefined, JSON.stringify(own.folders.map(function (r) { return r.name; })));
  if (trash === undefined) return;

  var patch = {};
  patch["mailboxIds/" + trash.name] = true;
  patch.notAPropertyThisServerSets = 1;

  var refused = await reader.jmap([
    ["Email/set", {
      accountId: readerId,
      update:    (function () { var u = {}; u[own.objectId] = patch; return u; }()),
    }, "c0"],
  ]);
  var answer = jmapAnswer(refused)[1];
  count("Email/set refuses a patch naming a property it cannot set",
    answer.notUpdated !== undefined &&
    Object.prototype.hasOwnProperty.call(answer.notUpdated, own.objectId),
    JSON.stringify(answer));

  var stillHome = await agent.fetch({
    actor:    { id: own.accountId, roles: ["account"] },
    folder:   own.inbox.storeName,
    objectId: own.objectId,
  });
  count("the refused patch left the message in the folder it started in",
    stillHome !== null && stillHome !== undefined, String(stillHome === null));

  var filed = await agent.fetch({
    actor:    { id: own.accountId, roles: ["account"] },
    folder:   trash.storeName,
    objectId: own.objectId,
  });
  count("and the refused patch did not file it into the folder it named",
    filed === null || filed === undefined, JSON.stringify(filed && filed.objectid));
}

// ---- the drive ----

async function driveTheSurface(identity, wiring) {
  await identity.domains.add({ domain: DOMAIN });
  var alice = await identity.accounts.create({
    address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
  var bob = await identity.accounts.create({
    address: "bob@" + DOMAIN, password: BOB_PASSWORD });

  // One alias into each mailbox. Both accounts holding one is what makes
  // the sending identity vectors below a boundary check rather than a
  // check that this server has aliases at all: an answer that leaked the
  // whole table would look right for either account on its own.
  await identity.aliases.add({ address: ALICE_ALIAS, destination: alice.address });
  await identity.aliases.add({ address: BOB_ALIAS,   destination: bob.address });

  // Appended ahead of the thread below so the newest two messages in
  // this inbox stay the ones the thread assertions read, and both of
  // these carry a subject the search vectors do not match.
  var quotedStored = identity.mailbox.appendMessage("INBOX", messageWith({
    messageId: messageIdFor(QUOTED_SUBJECT),
    to:        QUOTED_TO,
    subject:   QUOTED_SUBJECT,
    body:      "the room is booked",
  }), { actor: { id: alice.id } });
  var inlineStored = identity.mailbox.appendMessage("INBOX", messageWith({
    messageId:   messageIdFor(INLINE_SUBJECT),
    to:          "<" + alice.address + ">",
    subject:     INLINE_SUBJECT,
    contentType: "text/html; charset=utf-8",
    body:        inlineHtml(INLINE_ALT),
  }), { actor: { id: alice.id } });
  // A second message carrying images in the same conversation, so a
  // request for one message's images has another message to reach past.
  var inlineReply = identity.mailbox.appendMessage("INBOX", messageWith({
    messageId:   "sitemapreply@example.net",
    inReplyTo:   messageIdFor(INLINE_SUBJECT),
    to:          "<" + alice.address + ">",
    subject:     "Re: " + INLINE_SUBJECT,
    contentType: "text/html; charset=utf-8",
    body:        inlineHtml(INLINE_REPLY_ALT),
  }), { actor: { id: alice.id } });

  var alicesFirst = identity.mailbox.appendMessage("INBOX",
    messageFor(alice.address, ALICE_SUBJECT, "alice body"), { actor: { id: alice.id } });
  var alicesReply = identity.mailbox.appendMessage("INBOX",
    replyTo(alice.address, ALICE_SUBJECT, "alice reply body",
      messageIdFor(ALICE_SUBJECT)),
    { actor: { id: alice.id } });
  var bobsStored = identity.mailbox.appendMessage("INBOX",
    messageFor(bob.address, BOB_SUBJECT, BOB_BODY), { actor: { id: bob.id } });
  // A second message in the other account's thread, and the identifier
  // that matters: the reader never receives it, never guesses it and has
  // no route to it, so finding it in an answer is disclosure rather than
  // an echo of what the request already carried.
  var bobsReply = identity.mailbox.appendMessage("INBOX",
    replyTo(bob.address, BOB_SUBJECT, "bob reply body",
      BOB_SUBJECT.replace(/[^A-Za-z0-9]/g, "") + "@example.net"),
    { actor: { id: bob.id } });

  function inboxOf(accountId) {
    var rows = identity.mailbox.accountFolders({ id: accountId });
    return rows.filter(function (row) { return row.name === "INBOX"; })[0];
  }
  var alicesInbox = inboxOf(alice.id);
  var bobsInbox   = inboxOf(bob.id);
  count("the two accounts hold their inboxes in different store folders",
    alicesInbox !== undefined && bobsInbox !== undefined &&
    alicesInbox.storeName !== bobsInbox.storeName,
    JSON.stringify([alicesInbox && alicesInbox.storeName, bobsInbox && bobsInbox.storeName]));

  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    address:   LOOPBACK,
    httpPort:  0,
    listeners: function () { return []; },
  }));
  try {
    var ports = await listener.start();
    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var landed = await reader.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
    count("the sign in form carried a token for the reader to send back",
      reader.csrf().length > 0, JSON.stringify(reader.csrf()));
    count("the reader is signed in", landed.status === 302,
      landed.status + " " + landed.body.slice(0, 160));

    var own = {
      accountId: alice.id,
      address:   alice.address,
      alias:     ALICE_ALIAS,
      inbox:     alicesInbox,
      folders:   identity.mailbox.accountFolders({ id: alice.id }),
      objectId:  alicesFirst.objectid,
    };
    var victim = {
      accountId:      bob.id,
      address:        bob.address,
      alias:          BOB_ALIAS,
      inbox:          bobsInbox,
      objectId:       bobsStored.objectid,
      unseenObjectId: bobsReply.objectid,
      readerObjectId: alicesFirst.objectid,
    };
    count("the other account's thread has a second message the reader never sees",
      typeof victim.unseenObjectId === "string" &&
      victim.unseenObjectId !== victim.objectId,
      victim.unseenObjectId);

    await testNoStoreFolderNameReachesAnyPage(reader);
    await testTheWayBackToMailIsThisAccountsOwnFolder(reader, own);
    await testABulkActionCannotReachAnotherAccountsMessage(reader, wiring.agent, victim);
    await testABulkActionIsBounded(reader);
    await testTheReadersOwnBulkActionStillWorks(reader, wiring.agent, own);
    await testTrashLandsInTheReadersOwnTrash(reader, wiring.agent, own);
    await testSearchResolvesItsFolderName(reader, victim);
    await testThreadGetAnswersOnlyForTheReadersOwnMail(reader, alice.id, victim, 5);
    await testEmailSetRefusesKeywordsJmapDoesNotExpose(reader, alice.id, wiring.agent, own);
    await testEmailSetHonoursAWholeKeywordSet(reader, alice.id, wiring.agent, own);
    await testEmailSetRefusesACreateItCannotPerform(reader, alice.id);
    await testARefusedPatchMovesNothing(reader, alice.id, wiring.agent, own);
    await testJmapStateTracksTheMailAndNotTheClock(reader, alice.id, own);
    // A second session on the same server, held by the account whose
    // addresses the reader must not be able to write. The identity it
    // is refused is read off this session rather than invented, so the
    // refusal is about the account boundary and not about an id nobody
    // has ever issued.
    var stranger = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var strangerLanded = await stranger.signIn(bob.address, BOB_PASSWORD);
    count("the other account signs in, so its own answers can be read",
      strangerLanded.status === 302, String(strangerLanded.status));
    await testTheSendingIdentitySetIsThisAccountsOwn(reader, stranger, own, victim);
    await testThePreferenceRedirectStaysOnThisServer(reader);
    await testAReplyAllReadsQuotedDisplayNames(reader, { objectId: quotedStored.objectid });
    await testHeldImagesAreOfferedBackToTheReader(reader, { objectId: inlineStored.objectid });
    await testAskingForImagesReachesOneMessage(reader,
      { objectId: inlineStored.objectid }, { objectId: inlineReply.objectid });
    // Next to last, because it is the one vector that reaches the
    // outbound composer, and a refusal on the form is the assertion.
    await testEveryRecipientListIsValidated(reader);
    // Last, because a permanent delete is the one action nothing after
    // it can undo.
    await testAPurgeLeavesTheRestOfTheFolderReadable(reader, alice.id,
      { objectId: inlineStored.objectid },
      [alicesFirst.objectid, alicesReply.objectid, quotedStored.objectid,
        inlineReply.objectid]);

    // Read last: every assertion above claimed nothing of the other
    // account's mail moved, and the honest way to say so is to look.
    var stillThere = await wiring.agent.fetch({
      actor:    { id: bob.id, roles: ["account"] },
      folder:   bobsInbox.storeName,
      objectId: bobsStored.objectid,
    });
    count("the other account's message is where it started, with its own content",
      stillThere !== null && stillThere.subject === BOB_SUBJECT,
      stillThere === null ? "gone" : String(stillThere.subject));
  } finally {
    await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS });
  }
}

// ---- runner ----

async function run() {
  var root = helpers.tempDir("web-isolation");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    var identity = await store.open(cfg);
    var mailStore = b.mailStore.create({ backend: b.db });
    await driveTheSurface(identity, wiringFor(cfg, identity, mailStore));
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "web-isolation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (count2) {
    console.log("CHECKS " + count2);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
