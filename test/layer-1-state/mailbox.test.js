// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The protocol facing mailbox adapter, driven the way the wire
 * listeners drive it: a real temporary data directory, a real vault, a
 * real encrypted database, real sealed message octets on disk, and the
 * real `b.mail.agent` on the delete path. Two accounts exist
 * throughout, because the property most worth holding is that one
 * cannot see the other.
 *
 * The last section binds a real IMAP listener to a loopback port and
 * runs a client session against it, so the SELECT path is proven
 * through the listener's own handler rather than by calling the
 * adapter directly. That session authenticates over plaintext, which
 * the listener allows only under its permissive profile: the transport
 * is the harness here, and the mailbox backend is what is under test.
 * Every other listener in this file is constructed under the strict
 * profile the server ships with.
 *
 * Run standalone: node test/layer-1-state/mailbox.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodeOs   = require("node:os");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var store   = require("../../lib/store");

// The assertion that quotes the value that produced the verdict, and
// the counter behind it, are both the shared ones. A file that kept its
// own counter reported a total that only covered the assertions made
// through its own wrapper, so a `check` written directly ran and was
// invisible in the number the runner aggregated.
var count = helpers.count;

// Assert a call refuses under one stable code. The code is the
// contract a listener maps onto its own protocol reply, so a refusal
// under the wrong one is a change a caller would not survive.
async function refuses(label, code, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code);
}

var VAULT_PASSPHRASE   = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD     = "quiet lantern bicycle 4291";
var BOB_PASSWORD       = "another quiet lantern 7715";
var LOOPBACK_IMAP_PORT = 14393;

// RFC 4616 puts a NUL between the three fields of a SASL PLAIN
// response. Built from its code point rather than typed, so the byte
// is visible to anyone reading this file.
var SASL_NUL = String.fromCharCode(0);

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
    // an actor with a role, and every verb below would refuse.
    roles:     ["account"],
  };
}

function message(subject, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <alice@example.com>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

// ---- the backend the message store is built on ----

// The store takes the framework database with nothing in between: it
// runs its append and its hard delete in a transaction and works out
// which calling convention its backend offers by whether the body ran.
// What it will not do is proceed on a backend it cannot get a
// transaction out of at all, and that refusal is what stands between a
// misassembled store and a half-written delete. The behavior behind
// both statements is driven in mailbox-expunge-path; this is the
// construction the store module performs, and the refusal in front of
// something that is not a database at all.
function testTheStoreTakesTheFrameworkDatabaseDirectly() {
  var built = b.mailStore.create({ backend: b.db, init: false });
  count("b.mailStore is built on the framework database itself",
    typeof built.appendMessage === "function" && typeof built.hardExpunge === "function");

  var thrown = null;
  try {
    b.mailStore.create({ backend: { transaction: function () { return null; } }, init: false });
  } catch (e) { thrown = e; }
  count("and refuses something that cannot answer a statement, so a misassembled store " +
    "is a boot failure rather than a delete that half runs",
    thrown !== null && thrown.code === "mail-store/bad-backend",
    thrown === null ? "nothing was thrown" : thrown.code);
}

function testTables() {
  var names = mailbox.TABLES.map(function (t) { return t.name; });
  // Named rather than counted. A bare number says a table went missing
  // and not which one, and it reads as a pass for a table swapped for
  // another.
  var wanted = [mailbox.FOLDERS, mailbox.MESSAGES, mailbox.SCRIPTS, mailbox.METADATA,
    mailbox.SUBSCRIBED, mailbox.COUNTERS, mailbox.WIRE_SIZES];
  var absent = wanted.filter(function (name) { return names.indexOf(name) === -1; });
  count("blamepost.mail.mailbox.TABLES declares every mailbox table",
    absent.length === 0 && names.length === wanted.length, names.join(","));
  count("blamepost.mail.mailbox.TABLES seals the folder name",
    mailbox.TABLES[0].sealedFields.indexOf("wireName") !== -1);
  count("blamepost.mail.mailbox.TABLES carries a derived hash for the sealed folder name, " +
    "because a sealed column cannot anchor a lookup",
    mailbox.TABLES[0].derivedHashes.wireNameKey.from === "wireName");
  var sieveTable = mailbox.TABLES.filter(function (t) { return t.name === mailbox.SCRIPTS; })[0];
  count("blamepost.mail.mailbox.TABLES seals the Sieve script body",
    sieveTable.sealedFields.indexOf("body") !== -1);

  // A subscribed name is a mailbox its owner reads often, so the set is
  // sealed the same way the folder names are, and it carries no folder
  // column: RFC 9051 section 6.3.8 keeps the entry after the mailbox has
  // gone, so a name is what the row holds.
  var subs = mailbox.TABLES.filter(function (t) {
    return t.name === mailbox.SUBSCRIBED;
  })[0];
  count("blamepost.mail.mailbox.TABLES seals the subscribed name",
    subs.sealedFields.indexOf("wireName") !== -1, subs.sealedFields.join(","));
  count("and anchors its lookup on a derived hash of that name",
    subs.derivedHashes.wireNameKey.from === "wireName");
  count("and binds a subscribed name to an account rather than to a mailbox row",
    Object.prototype.hasOwnProperty.call(subs.columns, "account") &&
      !Object.prototype.hasOwnProperty.call(subs.columns, "folder"),
    Object.keys(subs.columns).join(","));

  // The mailbox row records nothing about the subscribed set. Two
  // records of one fact is the pair that comes apart, and the one on the
  // mailbox row is the one RFC 9051 section 6.3.8 forbids: it would go
  // with the row when DELETE takes it.
  count("the mailbox row carries no subscribed column",
    !Object.prototype.hasOwnProperty.call(mailbox.TABLES[0].columns, "subscribed"),
    Object.keys(mailbox.TABLES[0].columns).join(","));
}

// ---- listener construction ----

function testListenerConstruction(handle) {
  var secure = nodeTls.createSecureContext({});
  var auth = {
    mechanisms: ["PLAIN"],
    verify: async function () { return { ok: false, reason: "not-in-this-test" }; },
  };

  var pop3 = b.mail.server.pop3.create({
    tlsContext: secure, greeting: "mx.example.com POP3 blamepost",
    profile: "strict", auth: auth, mailStore: handle.mailbox,
  });
  count("b.mail.server.pop3.create accepts the adapter as its mailStore",
    pop3 !== null && typeof pop3.listen === "function");

  var managesieve = b.mail.server.managesieve.create({
    tlsContext: secure, greeting: "mx.example.com ManageSieve blamepost",
    profile: "strict", auth: auth, mailStore: handle.mailbox,
  });
  count("b.mail.server.managesieve.create accepts the adapter as its mailStore",
    managesieve !== null && typeof managesieve.listen === "function");

  var imap = b.mail.server.imap.create({
    tlsContext: secure, greeting: "mx.example.com IMAP4rev2 blamepost",
    profile: "strict", auth: auth, mailStore: handle.mailbox,
  });
  count("b.mail.server.imap.create accepts the adapter as its mailStore",
    imap !== null && typeof imap.listen === "function");

  count("the adapter answers SELECT, which is what the listener probes for before " +
    "refusing the command outright",
    typeof handle.mailbox.selectFolder === "function");
  count("the adapter answers the POP3 drop verb the listener requires at construction",
    typeof handle.mailbox.openPop3Drop === "function");
  count("the adapter answers the Sieve upload verb the listener requires at construction",
    typeof handle.mailbox.sieveScripts.put === "function");
}

// ---- folders and isolation ----

async function testFolders(handle, alice, bob) {
  var selected = handle.mailbox.selectFolder(alice, "INBOX", { readOnly: false, qresync: null });
  count("SELECT answers a new mailbox as empty", selected.exists === 0);
  count("SELECT starts UIDNEXT at one", selected.uidnext === 1);
  count("SELECT returns a 32 bit UIDVALIDITY (RFC 9051 section 2.3.1.1)",
    selected.uidvalidity > 0 && selected.uidvalidity < 4294967296, String(selected.uidvalidity));
  count("SELECT reports no recent messages, because IMAP4rev2 dropped the flag",
    selected.recent === 0);
  count("SELECT names the flags this server keeps",
    selected.flags.indexOf("\\Seen") !== -1 && selected.flags.indexOf("\\Recent") === -1);

  count("LIST returns the default folder set", handle.mailbox.listFolders(alice)
    .map(function (f) { return f.name; }).join(",") === "INBOX,Sent,Drafts,Trash,Junk,Archive");
  var sent = handle.mailbox.listFolders(alice).filter(function (f) { return f.name === "Sent"; })[0];
  count("LIST marks the special use folders (RFC 6154)",
    sent.attributes.indexOf("Sent") !== -1, sent.attributes.join(" "));

  count("a mailbox name is matched case insensitively only for INBOX",
    handle.mailbox.selectFolder(alice, "inbox", {}).uidvalidity === selected.uidvalidity);
  await refuses("a mailbox that does not exist is refused", "mailbox/no-folder", function () {
    return handle.mailbox.selectFolder(alice, "Nowhere", {});
  });
  await refuses("SELECT without an authenticated account refuses rather than " +
    "falling back to a shared folder", "mailbox/no-actor", function () {
    return handle.mailbox.selectFolder(null, "INBOX", {});
  });
  await refuses("APPEND without an authenticated account refuses the same way",
    "mailbox/no-actor", function () {
      return handle.mailbox.appendMessage("INBOX", message("orphan", "no owner"), {});
    });

  count("bob has his own folder set", handle.mailbox.listFolders(bob).length === 6);
  count("the two accounts hold twelve folders between them, not six",
    handle.mailbox.describe().folders === 12, String(handle.mailbox.describe().folders));

  // What the browser surface and JMAP read. They hold no session, so an
  // IMAP LIST reply gives them neither the store folder nor the role,
  // and the mailbox access agent over the store answers every call with
  // every folder in it. This accessor is the only account scoped folder
  // list any other layer has.
  var mine = handle.mailbox.accountFolders(alice);
  count("accountFolders answers with this account's folders and no others",
    mine.length === 6, String(mine.length));
  var alicesStoreFolders = mine.map(function (f) { return f.storeName; });
  var bobsStoreFolders = handle.mailbox.accountFolders(bob)
    .map(function (f) { return f.storeName; });
  count("no store folder appears in both accounts' lists",
    alicesStoreFolders.filter(function (name) {
      return bobsStoreFolders.indexOf(name) !== -1;
    }).length === 0, alicesStoreFolders.concat(bobsStoreFolders).join(","));
  count("accountFolders carries the name the owner sees beside the store folder, so a " +
    "caller never derives one from the other",
    mine[0].name === "INBOX" && mine[0].storeName.indexOf("mbx_") === 0,
    mine[0].name + " " + mine[0].storeName);
  count("accountFolders carries the role, so a reader has no reason to match on an " +
    "attribute list to find the inbox",
    mine[0].role === "inbox", mine[0].role);
  count("accountFolders carries the folder's highest modseq, which is where a reader " +
    "paging backwards starts",
    typeof mine[0].modseqMax === "number", String(mine[0].modseqMax));
  await refuses("accountFolders without an authenticated account refuses rather than " +
    "answering with the whole store", "mailbox/no-actor", function () {
    return handle.mailbox.accountFolders(null);
  });
}

async function testAppendAndIsolation(handle, alice, bob) {
  var first = handle.mailbox.appendMessage("INBOX", message("first", "hello"),
    { actor: alice, flags: ["\\Seen"] });
  count("APPEND assigns UID one to the first message", first.uid === 1);
  count("APPEND returns the UIDVALIDITY the APPENDUID response carries",
    first.uidvalidity > 0);
  var second = handle.mailbox.appendMessage("INBOX", message("second", "again"),
    { actor: alice, flags: [] });
  count("APPEND assigns UIDs in ascending order", second.uid === 2);

  count("alice sees both messages", handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 2);
  count("bob sees neither of them, which is the whole point of the adapter",
    handle.mailbox.selectFolder(bob, "INBOX", {}).exists === 0);

  await refuses("a flag no client may set is refused (RFC 9051 section 2.3.2)",
    "mailbox/bad-flag", function () {
      return handle.mailbox.appendMessage("INBOX", message("third", "nope"),
        { actor: alice, flags: ["\\Recent"] });
    });

  // Flags cannot ride along with the store's append, so the adapter
  // sets them afterwards. This is the check that the second step ran.
  //
  // Membership rather than the whole list, because the same step writes
  // the mark saying whether the message carries files and the store
  // answers the two in no particular order. The client's flag being
  // there is what this is about, and it still fails if the step is
  // dropped.
  var flagged = handle.mailbox.fetchRange(alice, "INBOX", "1", "FLAGS", {});
  count("APPEND flags are on the message, set as their own step",
    flagged[0].payload.indexOf("\\Seen") !== -1, flagged[0].payload);
  count("and the same step recorded that this message carries no files",
    flagged[0].payload.indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) !== -1,
    flagged[0].payload);
}

// A literal announces an octet count and is followed by exactly that
// many octets. Both halves are read off the buffer rather than off a
// decoded copy of it: a count taken on a decode is the count of a
// different message, which is the whole failure this pins.
//
// The latin1 view is a one to one mapping from octets to code units, so
// an index into it is an offset into the buffer.
function _literalParts(payload) {
  if (!Buffer.isBuffer(payload)) return null;
  var view  = payload.toString("latin1");
  var match = /^BODY\[[^\]]*\](?:<\d+>)? \{(\d+)\}\r\n/.exec(view);
  if (!match) return null;
  return { announced: parseInt(match[1], 10), present: payload.length - match[0].length };
}

function _literalCountMatchesPayload(payload) {
  var parts = _literalParts(payload);
  return parts !== null && parts.announced === parts.present;
}

function _literalReport(payload) {
  var parts = _literalParts(payload);
  if (parts === null) return "no literal header: " + String(payload).slice(0, 80);
  return "announced " + parts.announced + ", present " + parts.present;
}

function testFetch(handle, alice) {
  var rows = handle.mailbox.fetchRange(alice, "INBOX", "1:*",
    "(UID FLAGS RFC822.SIZE INTERNALDATE)", { useUid: false });
  count("FETCH returns one row per message in the set", rows.length === 2);
  count("FETCH numbers messages from one", rows[0].seq === 1 && rows[1].seq === 2);
  // The flag list is matched loosely and the attributes around it are
  // not. What this is about is that each attribute is rendered, in the
  // order the client named them; which flags the message holds is a
  // question the checks above answer, and the list carries the mark
  // saying whether the message carries files beside the client's own.
  count("FETCH renders the attributes the client asked for",
    /^UID 1 FLAGS \([^)]*\) RFC822\.SIZE \d+ INTERNALDATE "\d\d-[A-Z][a-z][a-z]-\d{4} /
      .test(rows[0].payload) && rows[0].payload.indexOf("\\Seen") !== -1,
    rows[0].payload);

  var uidRows = handle.mailbox.fetchRange(alice, "INBOX", "2", "FLAGS", { useUid: true });
  count("a UID FETCH selects by UID and carries UID back unasked (RFC 9051 section 6.4.9)",
    uidRows.length === 1 && uidRows[0].payload.indexOf("UID 2") === 0, uidRows[0].payload);

  // A row that carries message content leaves as octets. That is the
  // contract the listener reads: a Buffer payload is framed and written
  // as the bytes it holds, and a string payload is encoded on the way to
  // the socket, which is where an octet outside UTF-8 stops surviving
  // and the literal count stops matching what was written. Asserting the
  // type here is what keeps the wire case in
  // `test/layer-2-integration/mail-octet-fidelity` from being the only
  // thing standing between a message and a re-encoding of it.
  var body = handle.mailbox.fetchRange(alice, "INBOX", "1", "BODY.PEEK[]", {});
  count("a row carrying message content leaves this layer as octets",
    Buffer.isBuffer(body[0].payload), typeof body[0].payload);
  count("BODY[] returns the message as it arrived, which the store does not keep",
    body[0].payload.indexOf("Subject: first") !== -1);
  count("BODY[] counts the octets it is about to write",
    _literalCountMatchesPayload(body[0].payload),
    _literalReport(body[0].payload));

  var header = handle.mailbox.fetchRange(alice, "INBOX", "1",
    "BODY.PEEK[HEADER.FIELDS (SUBJECT)]", {});
  count("a header field selection returns that field and no other",
    header[0].payload.indexOf("Subject: first") !== -1 &&
    header[0].payload.indexOf("From:") === -1,
    header[0].payload.toString("latin1").replace(/\r\n/g, "|"));

  var envelope = handle.mailbox.fetchRange(alice, "INBOX", "1", "ALL", {});
  count("the ALL macro renders an ENVELOPE with parsed addresses",
    envelope[0].payload.indexOf("(\"Sender\" NIL \"sender\" \"example.net\")") !== -1,
    envelope[0].payload);

  // The ENVELOPE cuts each address at the LAST pair of angle brackets in
  // the entry, and the pair does not have to end it. RFC 5322 §3.2.2
  // lets a comment follow the address and §3.4 lets a quoted display
  // name carry angle brackets of its own, so both of these are ordinary
  // mail. An end-anchored reading answers the first with the whole entry
  // as the mailbox name, and a first-match reading answers the second
  // with the display name as the address; both spellings are one line
  // away in `b.codepointClass`, and neither answers this question.
  //
  // Filed in Archive rather than INBOX so the message counts INBOX is
  // asserted on further down do not move.
  var commented = handle.mailbox.appendMessage("Archive", Buffer.from(
    "From: Alice <alice@example.net> (out of office)\r\n" +
    "To: \"R <x>\" <recipient@example.org>\r\n" +
    "Subject: address shapes\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <addressshapes@example.net>\r\n" +
    "\r\nbody\r\n", "utf8"), { actor: alice, flags: [] });
  count("the message carrying the two address shapes is filed", commented.uid >= 1);
  var shapes = handle.mailbox.fetchRange(alice, "Archive", "1", "ALL", {});
  count("an address followed by a comment is cut at its angle brackets",
    shapes[0].payload.indexOf("(\"Alice\" NIL \"alice\" \"example.net\")") !== -1,
    shapes[0].payload);
  count("a quoted display name holding angle brackets does not become the address",
    shapes[0].payload.indexOf("\"recipient\" \"example.org\"") !== -1,
    shapes[0].payload);

  var peeked = handle.mailbox.fetchRange(alice, "INBOX", "2", "FLAGS", {});
  // `\Seen` is the flag this is about. The list is not empty, because
  // filing records whether the message carries files, and that mark says
  // nothing about whether anybody has read it.
  count("a peeking fetch left the message unread",
    peeked[0].payload.indexOf("\\Seen") === -1, peeked[0].payload);
  handle.mailbox.fetchRange(alice, "INBOX", "2", "BODY[]", {});
  var afterRead = handle.mailbox.fetchRange(alice, "INBOX", "2", "FLAGS", {})[0].payload;
  count("a fetch that is not peeking records the read (RFC 9051 section 6.4.5)",
    afterRead.indexOf("\\Seen") !== -1, afterRead);
}

async function testWireRefusals(handle, alice) {
  await refuses("a malformed sequence set is refused rather than guessed at",
    "mailbox/bad-sequence-set", function () {
      return handle.mailbox.fetchRange(alice, "INBOX", "1:bogus", "UID", {});
    });
  await refuses("an empty sequence set is refused", "mailbox/bad-sequence-set", function () {
    return handle.mailbox.fetchRange(alice, "INBOX", "", "UID", {});
  });
  await refuses("an attribute this server cannot answer exactly is refused, because a " +
    "wrong body structure renders the wrong bytes", "mailbox/unsupported-fetch", function () {
    return handle.mailbox.fetchRange(alice, "INBOX", "1", "BODYSTRUCTURE", {});
  });
  await refuses("a MIME part fetched by number is refused for the same reason",
    "mailbox/unsupported-fetch", function () {
      return handle.mailbox.fetchRange(alice, "INBOX", "1", "BODY[1.MIME]", {});
    });
  await refuses("an annotation name outside the RFC 5464 namespace is refused",
    "mailbox/bad-annotation", function () {
      return handle.mailbox.setMetadata(alice, "INBOX", [{ entry: "comment", value: "x" }]);
    });
}

function testStatusAndFlags(handle, alice) {
  var status = handle.mailbox.statusFolder(alice, "INBOX",
    ["MESSAGES", "UIDNEXT", "UIDVALIDITY", "UNSEEN"]);
  count("STATUS counts the messages", status.MESSAGES === 2);
  count("STATUS counts the unread ones", status.UNSEEN === 0, String(status.UNSEEN));
  count("STATUS reports the same UIDNEXT SELECT does",
    status.UIDNEXT === handle.mailbox.selectFolder(alice, "INBOX", {}).uidnext);

  var added = handle.mailbox.storeFlags(alice, "INBOX", "1", "add", ["\\Flagged"], {});
  count("STORE adds a flag", added.rows[0].flags.indexOf("\\Flagged") !== -1,
    added.rows[0].flags.join(" "));
  var removed = handle.mailbox.storeFlags(alice, "INBOX", "1", "remove", ["\\Flagged"], {});
  count("STORE removes a flag", removed.rows[0].flags.indexOf("\\Flagged") === -1,
    removed.rows[0].flags.join(" "));
  var replaced = handle.mailbox.storeFlags(alice, "INBOX", "1", "replace", ["\\Answered"], {});
  count("STORE replaces the whole set a client sets and keeps the derived attachment mark",
    replaced.rows[0].flags.join(" ") === "\\Answered $HasNoAttachment",
    replaced.rows[0].flags.join(" "));

  var conditional = handle.mailbox.storeFlags(alice, "INBOX", "1:*", "add", ["\\Draft"],
    { unchangedSince: 0 });
  count("a conditional STORE reports the messages it would not touch (RFC 7162 section 3.1.3)",
    conditional.modified === "1:2", conditional.modified);
}

async function testExpungeRoutesThroughTheAgent(handle, alice) {
  handle.mailbox.storeFlags(alice, "INBOX", "2", "add", ["\\Deleted"], {});
  var expunged = await handle.mailbox.expungeFolder(alice, "INBOX");
  count("EXPUNGE removes the message a client flagged", expunged.expunged.length === 1,
    JSON.stringify(expunged.expunged));
  count("the mailbox is one message shorter",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1);
  count("UIDNEXT did not go backwards, so a UID is never reused",
    handle.mailbox.selectFolder(alice, "INBOX", {}).uidnext === 3);

  // The agent is the layer holding legal hold and the retention floor,
  // so this is the check that the adapter goes through it rather than
  // reaching for the store's destructive primitive.
  var held = handle.mailbox.appendMessage("INBOX", message("held", "keep this"),
    { actor: alice, flags: ["\\Deleted"] });
  var raw = b.mailStore.create({ backend: b.db, init: false });
  raw.setLegalHold([held.objectid], { hold: true });
  var refused = await handle.mailbox.expungeFolder(alice, "INBOX");
  count("a message under legal hold survives EXPUNGE, which only the agent path enforces",
    refused.expunged.length === 0, JSON.stringify(refused.expunged));
  count("and it is still in the mailbox",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 2);
  raw.setLegalHold([held.objectid], { hold: false });
  var released = await handle.mailbox.expungeFolder(alice, "INBOX");
  count("releasing the hold lets the same EXPUNGE through", released.expunged.length === 1);
}

async function testSieve(handle, alice, bob) {
  var put = handle.mailbox.sieveScripts.put(alice, "default",
    "require [\"fileinto\"];\nfileinto \"Junk\";\n", {});
  count("PUTSCRIPT stores a script that parses", put.ok === true);
  count("PUTSCRIPT reports the capabilities the script requires",
    put.requiredCaps.indexOf("fileinto") !== -1, put.requiredCaps.join(","));
  await refuses("a script that does not parse is refused before it is stored " +
    "(RFC 5804 section 2.6)", "mailbox/script-refused", function () {
    return handle.mailbox.sieveScripts.put(alice, "broken", "this is not sieve {{{", {});
  });

  handle.mailbox.sieveScripts.setActive(alice, "default");
  count("LISTSCRIPTS marks the active script",
    handle.mailbox.sieveScripts.list(alice)[0].active === true);
  count("GETSCRIPT returns the body as stored",
    handle.mailbox.sieveScripts.get(alice, "default").body.indexOf("fileinto") !== -1);
  count("bob sees none of alice's scripts", handle.mailbox.sieveScripts.list(bob).length === 0);
  count("and reading one by name returns nothing",
    handle.mailbox.sieveScripts.get(bob, "default") === null);

  await refuses("the active script cannot be deleted (RFC 5804 section 2.10)",
    "mailbox/script-active", function () {
      return handle.mailbox.sieveScripts.delete(alice, "default");
    });
  handle.mailbox.sieveScripts.rename(alice, "default", "sorting");
  count("RENAMESCRIPT moves the script",
    handle.mailbox.sieveScripts.get(alice, "sorting") !== null);
  count("HAVESPACE accepts a script inside the limit",
    handle.mailbox.sieveScripts.haveSpace(alice, "sorting", 1024).ok === true);
  count("HAVESPACE refuses one above it",
    handle.mailbox.sieveScripts.haveSpace(alice, "huge", 1024 * 1024).ok === false);
  handle.mailbox.sieveScripts.setActive(alice, "");
  count("an empty SETACTIVE deactivates everything (RFC 5804 section 2.8)",
    handle.mailbox.sieveScripts.list(alice)[0].active === false);
  handle.mailbox.sieveScripts.delete(alice, "sorting");
  count("a script that is not active can be deleted",
    handle.mailbox.sieveScripts.list(alice).length === 0);
}

async function testPop3(handle, alice) {
  var drop = handle.mailbox.openPop3Drop(alice, {});
  count("the maildrop opens with a message count and a byte total",
    drop.count === 1 && drop.totalBytes > 0, String(drop.count));
  await refuses("a second session is refused exclusive access (RFC 1939 section 3)",
    "mailbox/drop-locked", function () {
      return handle.mailbox.openPop3Drop(alice, {});
    });

  var listed = handle.mailbox.listMessages(alice, drop.dropId);
  count("LIST numbers messages from one", listed[0].msgNum === 1);
  count("UIDL is printable ASCII inside the 70 byte ceiling RFC 1939 sets",
    /^[!-~]{1,70}$/.test(listed[0].uid), listed[0].uid);

  var retrieved = handle.mailbox.getMessage(alice, drop.dropId, 1, {});
  count("RETR returns the original octets as a buffer",
    Buffer.isBuffer(retrieved.rawBytes) &&
    retrieved.rawBytes.toString("utf8").indexOf("Subject: first") !== -1);
  count("RETR reports the size it is about to write",
    retrieved.size === retrieved.rawBytes.length);
  var topped = handle.mailbox.getMessage(alice, drop.dropId, 1,
    { headersOnly: true, headerLines: 0 });
  count("TOP returns the headers without the body",
    topped.rawBytes.toString("utf8").indexOf("Subject: first") !== -1 &&
    topped.rawBytes.toString("utf8").indexOf("hello") === -1);
  count("a message number nobody has returns nothing rather than throwing",
    handle.mailbox.getMessage(alice, drop.dropId, 99, {}) === null);

  handle.mailbox.markDelete(alice, drop.dropId, 1);
  count("a marked message drops out of LIST",
    handle.mailbox.listMessages(alice, drop.dropId).length === 0);
  count("the mailbox itself is untouched until the session commits",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1);
  handle.mailbox.resetPop3Drop(alice, drop.dropId);
  count("RSET clears the marks", handle.mailbox.listMessages(alice, drop.dropId).length === 1);

  handle.mailbox.markDelete(alice, drop.dropId, 1);
  var committed = await handle.mailbox.commitPop3Drop(alice, drop.dropId);
  count("QUIT applies the marks", committed.deleted === 1);
  count("and the mailbox is empty afterwards",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 0);
  var reopened = handle.mailbox.openPop3Drop(alice, {});
  count("the exclusive lock is released when the session commits", reopened.count === 0);
  await handle.mailbox.commitPop3Drop(alice, reopened.dropId);
  await refuses("a drop id from a finished session is refused", "mailbox/no-drop", function () {
    return handle.mailbox.listMessages(alice, reopened.dropId);
  });
}

function testAnnotations(handle, alice, bob) {
  handle.mailbox.setMetadata(alice, "INBOX", [{ entry: "/private/comment", value: "mine" }]);
  count("GETMETADATA reads back what SETMETADATA stored",
    handle.mailbox.getMetadata(alice, "INBOX", ["/private/comment"], {})[0].value === "mine");
  count("bob reads nothing under the same entry on his own INBOX",
    handle.mailbox.getMetadata(bob, "INBOX", ["/private/comment"], {})[0].value === null);
  handle.mailbox.setMetadata(alice, "", [{ entry: "/shared/vendor", value: "blamepost" }]);
  count("a server wide annotation is stored against the empty mailbox name",
    handle.mailbox.getMetadata(alice, "", ["/shared/vendor"], {})[0].value === "blamepost");
  handle.mailbox.setMetadata(alice, "INBOX", [{ entry: "/private/comment", value: null }]);
  count("a null value clears the entry (RFC 5464 section 4.3)",
    handle.mailbox.getMetadata(alice, "INBOX", ["/private/comment"], {})[0].value === null);
}

function testDescribe(handle) {
  var described = handle.mailbox.describe();
  count("describe counts folders without unsealing anything",
    described.folders === 12, String(described.folders));
  count("describe reports no session holding a maildrop", described.openDrops === 0);
  count("describe names the directory the octets are written to",
    typeof described.blobDir === "string" && described.blobDir.length > 0);
}

// ---- a live IMAP session ----

function imapSession(port) {
  return new Promise(function (resolve, reject) {
    var transcript = "";
    var sent = 0;
    var lines = [
      "a1 AUTHENTICATE PLAIN " + Buffer.from(
        SASL_NUL + "alice@example.com" + SASL_NUL + ALICE_PASSWORD,
        "utf8").toString("base64"),
      "a2 SELECT INBOX",
      "a3 LOGOUT",
    ];
    var socket = nodeNet.connect({ port: port, host: "127.0.0.1" });
    socket.setEncoding("utf8");
    socket.on("data", function (chunk) {
      transcript += chunk;
      if (!/^(a\d) (OK|NO|BAD)/m.test(chunk) && !/^\* OK/.test(chunk)) return;
      if (sent >= lines.length) return;
      socket.write(lines[sent] + "\r\n");
      sent += 1;
    });
    socket.on("error", reject);
    socket.on("close", function () { resolve(transcript); });
  });
}

async function testLiveSelect(handle) {
  var live = b.mail.server.imap.create({
    tlsContext: nodeTls.createSecureContext({}),
    greeting:   "mx.example.com IMAP4rev2 blamepost",
    profile:    "permissive",
    mailStore:  handle.mailbox,
    auth: {
      mechanisms: ["PLAIN"],
      verify: async function (mechanism, credentials) {
        var fields = Buffer.from(String(credentials.clientResponse || "").trim(), "base64")
          .toString("utf8").split(SASL_NUL);
        var verdict = await handle.accounts.authenticate({
          address: fields[1], password: fields[2] });
        if (!verdict.ok) return { ok: false, reason: verdict.reason };
        return { ok: true, actor: actorFor({
          id: verdict.accountId, address: verdict.address, domain: verdict.domain }) };
      },
    },
  });
  await live.listen({ port: LOOPBACK_IMAP_PORT, host: "127.0.0.1" });
  try {
    var transcript = await helpers.withTestTimeout("imap select session", function () {
      return imapSession(LOOPBACK_IMAP_PORT);
    }, { timeoutMs: 10000 });
    count("the listener authenticated the session",
      /a1 OK \[CAPABILITY [^\]]+\] AUTHENTICATE completed/.test(transcript), transcript);
    count("the listener completed SELECT through the adapter rather than refusing it",
      /a2 OK \[READ-WRITE\] SELECT completed/.test(transcript), transcript);
    count("it emitted a real UIDVALIDITY", /\* OK \[UIDVALIDITY \d+\]/.test(transcript),
      transcript);
    count("no unconfigured backend refusal appears in the transcript",
      transcript.indexOf("selectFolder is not configured") === -1, transcript);
  } finally {
    await live.close();
  }
}

// ---- orchestration ----

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-mailbox-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted-at-rest
  // path exactly as it ships rather than opting the test out of it.
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

    count("blamepost.store.open exposes the protocol facing adapter as mailbox",
      handle.mailbox !== undefined && typeof handle.mailbox.appendMessage === "function");
    count("blamepost.store.open exposes the store underneath it as messageStore, so the " +
      "process holds one rather than two",
      handle.messageStore !== undefined &&
      typeof handle.messageStore.hardExpunge === "function");

    testTheStoreTakesTheFrameworkDatabaseDirectly();
    testTables();
    testListenerConstruction(handle);

    await handle.domains.add({ domain: "example.com" });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD }));
    var bob = actorFor(await handle.accounts.create({
      address: "bob@example.com", password: BOB_PASSWORD }));

    await testFolders(handle, alice, bob);
    await testAppendAndIsolation(handle, alice, bob);
    testFetch(handle, alice);
    await testWireRefusals(handle, alice);
    testStatusAndFlags(handle, alice);
    await testExpungeRoutesThroughTheAgent(handle, alice);
    await testSieve(handle, alice, bob);
    await testPop3(handle, alice);
    testAnnotations(handle, alice, bob);
    testDescribe(handle);
    await testLiveSelect(handle);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not a
      // test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = { name: "mailbox", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
