// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `blamepost.mail.mailbox.readMessageSource`, the read a reply and a
 * forward are derived from.
 *
 * The message store keeps the subject, the sender, the To addresses and
 * the two body texts it indexes, and it keeps no `Reply-To`, no `Cc` and
 * no octets. Three things follow from that, and this file drives all
 * three through `blamepost.mail.compose` rather than asserting on the
 * fields alone, because the composer is what an account holder's draft
 * actually comes out of:
 *
 *   - a reply addresses the author of a message whose sender named
 *     somewhere else for replies to go (RFC 5322 section 3.6.2),
 *   - a reply-all copies the To list and drops everybody who was only
 *     on the Cc,
 *   - a forward has no octets to carry as a `message/rfc822` part
 *     (RFC 2046 section 5.2.1).
 *
 * The bound is the other half. A stored message reaches fifty mebibytes
 * and a sealed body opens whole or not at all, so the read decides from
 * the octet count on this layer's own row. The boundary is driven from
 * the shipped value rather than from a second copy of it.
 *
 * And the read is a read: no flag moves, no modification sequence moves,
 * and the message an IMAP client saw as unread is still unread
 * afterwards.
 *
 * Run standalone: node test/layer-1-state/mailbox-message-source.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var compose = require("../../lib/mail/compose");
var store   = require("../../lib/store");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var LIST_ADDRESS  = "discuss@lists.example.net";
var AUTHOR        = "sender@example.net";
var CAROL         = "carol@example.org";
var ERIN          = "erin@example.net";
var DAVE          = "dave@example.org";

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

// Assert a call refuses under one stable code. The code is what the
// surface above maps onto its own answer, so a refusal under the wrong
// one is a change a caller would not survive.
function refuses(label, code, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + " " + thrown.message);
}

function message(fields, body) {
  return Buffer.from(fields.concat(["", body, ""]).join("\r\n"), "utf8");
}

// A message of exactly `total` octets, whose body is one run of a single
// character. The content type keeps the padding out of the store's text
// extraction, so a message built to a byte count does not also become a
// megabyte of indexed body text.
function messageOfSize(subject, total) {
  var head = [
    "From: Bulk <" + AUTHOR + ">",
    "To: Alice <alice@example.com>",
    "Cc: Carol <" + CAROL + ">",
    "Subject: " + subject,
    "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "") + "@example.net>",
    "Content-Type: application/octet-stream",
    "",
  ].join("\r\n") + "\r\n";
  var pad = total - Buffer.byteLength(head, "utf8");
  if (pad < 0) throw new Error("messageOfSize: header block already exceeds " + total);
  return Buffer.concat([Buffer.from(head, "utf8"), Buffer.alloc(pad, 0x41)]);
}

// ---- the three fields ------------------------------------------------------

function testTheSourceCarriesWhatTheStoreDropped(handle, alice, filed) {
  var source = handle.mailbox.readMessageSource(alice, "INBOX", filed.listed.objectid);

  count("the source answers with the message it was asked for",
    source !== null && source.objectid === filed.listed.objectid,
    source === null ? "null" : source.objectid);
  count("the source carries the UID an IMAP client addresses the message by",
    typeof source.uid === "number" && source.uid > 0, String(source.uid));

  // RFC 5322 section 3.6.2 gives Reply-To exactly this purpose. The
  // store's row has no column for it.
  count("the source carries the Reply-To header the message store keeps no column for",
    source.message.replyTo.indexOf(LIST_ADDRESS) !== -1, source.message.replyTo);
  // RFC 5322 section 3.6.3. The store keeps the To addresses and not
  // these.
  count("the source carries the Cc addresses the message store keeps no column for",
    source.message.cc.indexOf(CAROL) !== -1 && source.message.cc.indexOf(ERIN) !== -1,
    source.message.cc);
  count("the source still carries every field the message store did keep",
    source.message.subject.length > 0 &&
    source.message.from.indexOf(AUTHOR) !== -1 &&
    source.message.to.indexOf("alice@example.com") !== -1 &&
    source.message.messageId.indexOf("listed@example.net") !== -1,
    [source.message.subject, source.message.from, source.message.to,
      source.message.messageId].join(" | "));

  // The octets come back as they were stored. A retrieval verb next to
  // this one answers in IMAP response octets, which is a wire format,
  // and this one answers in the message.
  count("the source carries the message octets exactly as they were stored",
    Buffer.isBuffer(source.bytes) && source.bytes.equals(filed.listed.raw),
    Buffer.isBuffer(source.bytes) ? source.bytes.length + " of " + filed.listed.raw.length
      : String(source.bytes));
  count("the octet count on the source is the one the message was filed under",
    source.sizeBytes === filed.listed.raw.length,
    source.sizeBytes + " against " + filed.listed.raw.length);
  count("a source that opened the message withholds nothing",
    source.withheld === null, String(source.withheld));

  // A message carrying no Reply-To reads as one, rather than as a
  // question that was not asked: both fields are on every answer so a
  // caller reads one shape.
  var plain = handle.mailbox.readMessageSource(alice, "INBOX", filed.plain.objectid);
  count("a message with no Reply-To carries the field empty rather than absent",
    plain.message.replyTo === "" &&
    Object.prototype.hasOwnProperty.call(plain.message, "replyTo"),
    JSON.stringify(plain.message.replyTo));
  count("a message with no Cc carries the field empty rather than absent",
    plain.message.cc === "" && Object.prototype.hasOwnProperty.call(plain.message, "cc"),
    JSON.stringify(plain.message.cc));
}

// ---- the three derivations -------------------------------------------------

async function testTheDerivationsThatWereWrong(handle, alice, filed) {
  var composer = compose.create({
    hostname: "mx.example.com",
    delivery: helpers.standInDelivery(),
  });

  var listed = handle.mailbox.readMessageSource(alice, "INBOX", filed.listed.objectid);
  var plain  = handle.mailbox.readMessageSource(alice, "INBOX", filed.plain.objectid);

  // 1. RFC 5322 section 3.6.2: the reply goes where Reply-To names, not
  //    to the author.
  var reply = await composer.reply({
    original: listed.bytes,
    message:  listed.message,
    from:     "alice@example.com",
    draft:    true,
  });
  var replyTo = reply.to.join(", ");
  count("a reply addresses the Reply-To the sender named rather than the From",
    replyTo.indexOf(LIST_ADDRESS) !== -1 && replyTo.indexOf(AUTHOR) === -1, replyTo);

  // The same derivation over the row alone, which is what the store's
  // read hands back and what this verb exists to replace.
  var fromRowAlone = await composer.reply({
    message: { subject: listed.message.subject, from: listed.message.from,
      to: listed.message.to, messageId: listed.message.messageId,
      internalDate: listed.message.internalDate },
    from:  "alice@example.com",
    draft: true,
  });
  count("the message store's row on its own addresses the author instead, which is the " +
    "answer this read replaces",
    fromRowAlone.to.join(", ").indexOf(AUTHOR) !== -1,
    fromRowAlone.to.join(", "));

  // A row for an html-only message carries the markup in both body
  // fields, because the store fills the text body with whatever part it
  // found. The quote is taken from the html, rendered, rather than from
  // the copy of it in the text field.
  var markup = "<p>Quarterly <b>numbers</b> &amp; notes</p>";
  var htmlOnly = await composer.reply({
    message: { subject: "html only", from: listed.message.from, to: listed.message.to,
      messageId: "<html-only@example.net>", internalDate: listed.message.internalDate,
      bodyText: markup, bodyHtml: markup },
    from:  "alice@example.com",
    draft: true,
  });
  var quotedText = String(htmlOnly.text || "");
  count("a reply to an html-only message quotes readable text rather than its markup",
    quotedText.indexOf("<p>") === -1 && quotedText.indexOf("&amp;") === -1 &&
      quotedText.indexOf("Quarterly") !== -1,
    quotedText.slice(0, 200));

  // Paragraphs stay apart in the quote.
  var blocks = "<p>First paragraph</p><p>Second paragraph</p><div>Third<br>Fourth</div>";
  var blocked = await composer.reply({
    message: { subject: "blocks", from: listed.message.from, to: listed.message.to,
      messageId: "<blocks@example.net>", internalDate: listed.message.internalDate,
      bodyText: blocks, bodyHtml: blocks },
    from:  "alice@example.com",
    draft: true,
  });
  var blockText = String(blocked.text || "");
  count("each html paragraph and line break starts a quoted line of its own",
    /^> First paragraph$/m.test(blockText) && /^> Second paragraph$/m.test(blockText) &&
      /^> Third$/m.test(blockText) && /^> Fourth$/m.test(blockText),
    blockText.slice(0, 300));

  // An html-only body larger than the html sanitizer reads at once still
  // gives a quote, cut to the quote's own limit.
  var big = "<p>" + new Array(3 * 1024 * 1024 / 16).join("lots of words here ") + "</p>";
  var bigError = null;
  var bigReply = null;
  try {
    bigReply = await composer.reply({
      message: { subject: "big", from: listed.message.from, to: listed.message.to,
        messageId: "<big@example.net>", internalDate: listed.message.internalDate,
        bodyText: big, bodyHtml: big },
      from:  "alice@example.com",
      draft: true,
    });
  } catch (e) { bigError = e; }
  count("a reply to an html-only message over 2 MiB is drafted with a bounded quote",
    bigError === null && bigReply !== null &&
      Buffer.byteLength(String(bigReply.text || ""), "utf8") <= 70 * 1024 &&
      String(bigReply.text || "").indexOf("lots of words here") !== -1,
    bigError === null ? String(Buffer.byteLength(String(bigReply.text || ""), "utf8"))
      : String(bigError.code) + " " + bigError.message);

  // A message carrying no Reply-To still addresses its author.
  var plainReply = await composer.reply({
    original: plain.bytes,
    message:  plain.message,
    from:     "alice@example.com",
    draft:    true,
  });
  count("a reply to a message carrying no Reply-To addresses the From",
    plainReply.to.join(", ").indexOf(AUTHOR) !== -1, plainReply.to.join(", "));

  // 2. Reply-all keeps everybody who was on the Cc.
  var all = await composer.reply({
    original:   listed.bytes,
    message:    listed.message,
    from:       "alice@example.com",
    identities: ["alice@example.com"],
    replyAll:   true,
    draft:      true,
  });
  var copies = all.cc.join(", ");
  count("a reply-all copies the Cc addresses as well as the To addresses",
    copies.indexOf(CAROL) !== -1 && copies.indexOf(ERIN) !== -1 &&
    copies.indexOf(DAVE) !== -1, copies);
  count("a reply-all leaves the replying account off its own copy list",
    copies.indexOf("alice@example.com") === -1, copies);

  // 3. RFC 2046 section 5.2.1: the forward carries the original as a
  //    message/rfc822 part.
  var forwarded = await composer.forward({
    original: listed.bytes,
    message:  listed.message,
    draft:    true,
  });
  var parts = (forwarded.attachments || []).filter(function (att) {
    return att.contentType === "message/rfc822";
  });
  count("a forward carries the original as a message/rfc822 part",
    parts.length === 1, JSON.stringify((forwarded.attachments || []).map(function (a) {
      return a.contentType;
    })));
  count("the message/rfc822 part holds the stored octets and nothing re-encoded",
    parts.length === 1 && Buffer.isBuffer(parts[0].content) &&
    parts[0].content.equals(filed.listed.raw),
    parts.length === 1 ? String(parts[0].content && parts[0].content.length) : "no part");

  // The same forward over the row alone has no part to carry, which is
  // the shape the composer already documents: it quotes the original
  // underneath the header block instead.
  var quotedForward = await composer.forward({
    message: { subject: listed.message.subject, from: listed.message.from,
      bodyText: listed.message.bodyText, internalDate: listed.message.internalDate },
    draft: true,
  });
  count("the message store's row on its own carries no part to forward, which is the " +
    "answer this read replaces",
    (quotedForward.attachments || []).length === 0,
    JSON.stringify((quotedForward.attachments || []).length));
}

// ---- the bound -------------------------------------------------------------

function testTheBound(handle, alice, atBound, overBound) {
  var at = handle.mailbox.readMessageSource(alice, "INBOX", atBound.objectid);
  count("a message at the bound is opened",
    at !== null && Buffer.isBuffer(at.bytes) &&
    at.bytes.length === mailbox.MAX_SOURCE_READ_BYTES,
    at === null ? "null" : String(at.bytes && at.bytes.length));
  count("a message at the bound withholds nothing", at.withheld === null, String(at.withheld));
  count("a message at the bound still carries the headers the store dropped",
    at.message.cc.indexOf(CAROL) !== -1, at.message.cc);

  var over = handle.mailbox.readMessageSource(alice, "INBOX", overBound.objectid);
  count("a message one octet above the bound is not opened",
    over !== null && over.bytes === null,
    over === null ? "null" : String(over.bytes && over.bytes.length));
  count("a message above the bound says the octets were withheld rather than leaving the " +
    "caller to infer it", over.withheld === "message-too-large", String(over.withheld));
  count("a message above the bound still answers with the octet count and the identifiers",
    over.sizeBytes === mailbox.MAX_SOURCE_READ_BYTES + 1 &&
    over.objectid === overBound.objectid && typeof over.uid === "number",
    over.sizeBytes + " " + over.objectid);
  // The store's own row is carried whole, with both header fields
  // present and empty, so a caller reads one shape whether or not the
  // message was opened.
  count("a message above the bound carries the message store's row with both header " +
    "fields empty",
    over.message.replyTo === "" && over.message.cc === "" &&
    over.message.subject.length > 0 && over.message.from.indexOf(AUTHOR) !== -1,
    [over.message.replyTo, over.message.cc, over.message.subject].join(" | "));
}

// ---- the read disturbs nothing ---------------------------------------------

function testTheReadDisturbsNothing(handle, alice, filed) {
  function stateOf() {
    var rows = handle.mailbox.searchScan(alice, "INBOX");
    return rows.map(function (r) {
      return r.objectid + ":" + r.flags.slice().sort().join("|");
    }).join(" ");
  }
  function modseqOf() {
    var folders = handle.mailbox.accountFolders(alice);
    var inbox = folders.filter(function (f) { return f.name === "INBOX"; })[0];
    return inbox.modseqMax;
  }
  function seenOf(objectid) {
    var rows = handle.mailbox.searchScan(alice, "INBOX");
    var hit = rows.filter(function (r) { return r.objectid === objectid; })[0];
    return hit ? hit.flags.indexOf("\\Seen") !== -1 : null;
  }

  var flagsBefore  = stateOf();
  var modseqBefore = modseqOf();
  count("the message this read is taken over is unread before it", seenOf(filed.listed.objectid) === false,
    String(seenOf(filed.listed.objectid)));

  handle.mailbox.readMessageSource(alice, "INBOX", filed.listed.objectid);
  handle.mailbox.readMessageSource(alice, "INBOX", filed.plain.objectid);

  count("reading a message to quote it sets no flag on it",
    stateOf() === flagsBefore, flagsBefore + " became " + stateOf());
  count("reading a message to quote it leaves it unread, which the retrieval verb beside " +
    "it does not", seenOf(filed.listed.objectid) === false,
    String(seenOf(filed.listed.objectid)));
  count("reading a message to quote it moves no modification sequence",
    modseqOf() === modseqBefore, modseqBefore + " became " + modseqOf());

  // The retrieval verb beside it does record the read, which is what
  // makes the assertion above worth taking: the two are told apart by
  // behavior rather than by intent.
  handle.mailbox.fetchRange(alice, "INBOX", String(filed.listed.uid), "(BODY[])", { useUid: true });
  count("a non peeking FETCH over the same message does set \\Seen, so the assertion " +
    "above is measuring something", seenOf(filed.listed.objectid) === true,
    String(seenOf(filed.listed.objectid)));

  // Nothing this read does touches the hold substrate or the floor: the
  // message is still destroyable and still under no hold afterwards.
  var held = handle.mailbox.legalHold.status(alice, "INBOX", [filed.listed.objectid]);
  count("reading a message places no legal hold on it",
    held.length === 1 && held[0].held === false, JSON.stringify(held[0] && held[0].held));
}

// ---- refusals and isolation ------------------------------------------------

function testTheReadRefuses(handle, alice, bob, filed) {
  refuses("a source read with no acting account refuses", "mailbox/no-actor",
    function () { return handle.mailbox.readMessageSource(null, "INBOX", filed.listed.objectid); });
  refuses("a source read whose actor carries no id refuses", "mailbox/no-actor",
    function () {
      return handle.mailbox.readMessageSource({ address: "alice@example.com" }, "INBOX",
        filed.listed.objectid);
    });
  refuses("a source read of a folder this account does not have refuses", "mailbox/no-folder",
    function () { return handle.mailbox.readMessageSource(alice, "Nowhere", filed.listed.objectid); });
  refuses("a source read of a name the folder namespace refuses is refused there",
    "mailbox/bad-mailbox-name",
    function () { return handle.mailbox.readMessageSource(alice, "Arch*ive", filed.listed.objectid); });

  count("a source read of an identifier this mailbox does not hold answers with nothing",
    handle.mailbox.readMessageSource(alice, "INBOX", "obj_0000000000000000") === null);
  count("a source read carrying no identifier answers with nothing",
    handle.mailbox.readMessageSource(alice, "INBOX", null) === null);

  // One account cannot read another's message by naming its identifier,
  // and the answer is the same one it gets for an identifier that names
  // nothing: the folder is resolved against the acting account first.
  count("one account cannot read another account's message by its identifier",
    handle.mailbox.readMessageSource(bob, "INBOX", filed.listed.objectid) === null);
  count("the other account's own message is still readable to them",
    handle.mailbox.readMessageSource(bob, "INBOX", filed.bob.objectid) !== null);
}

// ---- the run ---------------------------------------------------------------

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-message-source-"));
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

    // A list message: it names somewhere else for replies to go, and it
    // copies two people who are on neither the To line nor the From.
    var listedRaw = message([
      "From: Author <" + AUTHOR + ">",
      "Reply-To: Discuss <" + LIST_ADDRESS + ">",
      "To: Alice <alice@example.com>, Dave <" + DAVE + ">",
      "Cc: Carol <" + CAROL + ">, Erin <" + ERIN + ">",
      "Subject: The thread everybody is on",
      "Message-ID: <listed@example.net>",
    ], "The body as it was appended.");
    var listed = handle.mailbox.appendMessage("INBOX", listedRaw, { actor: alice, flags: [] });
    listed.raw = listedRaw;

    // An ordinary message, carrying neither header.
    var plainRaw = message([
      "From: Author <" + AUTHOR + ">",
      "To: Alice <alice@example.com>",
      "Subject: A note with no Reply-To and no Cc",
      "Message-ID: <plain@example.net>",
    ], "A shorter body.");
    var plain = handle.mailbox.appendMessage("INBOX", plainRaw, { actor: alice, flags: [] });
    plain.raw = plainRaw;

    var bobs = handle.mailbox.appendMessage("INBOX", message([
      "From: Someone <someone@example.net>",
      "To: Bob <bob@example.com>",
      "Subject: bob's own message",
      "Message-ID: <bobs-only@example.net>",
    ], "bob's own body"), { actor: bob, flags: [] });

    var filed = { listed: listed, plain: plain, bob: bobs };

    testTheSourceCarriesWhatTheStoreDropped(handle, alice, filed);
    await testTheDerivationsThatWereWrong(handle, alice, filed);

    // The boundary, driven from the shipped value. Two messages, one of
    // exactly the bound and one an octet above it, so the comparison is
    // measured rather than assumed to be on the right side.
    var atBound = handle.mailbox.appendMessage("INBOX",
      messageOfSize("At the bound", mailbox.MAX_SOURCE_READ_BYTES),
      { actor: alice, flags: [] });
    var overBound = handle.mailbox.appendMessage("INBOX",
      messageOfSize("Over the bound", mailbox.MAX_SOURCE_READ_BYTES + 1),
      { actor: alice, flags: [] });
    testTheBound(handle, alice, atBound, overBound);

    testTheReadDisturbsNothing(handle, alice, filed);
    testTheReadRefuses(handle, alice, bob, filed);

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
  name: "mailbox-message-source",
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
