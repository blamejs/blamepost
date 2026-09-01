// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `blamepost.mail.mailbox.searchScan`, the read IMAP SEARCH is built
 * on, and `blamepost.mail.mailbox.sequenceSet`, the grammar its
 * sequence set keys share with FETCH and STORE.
 *
 * The wire behavior is pinned in
 * `test/layer-2-integration/imap-search.test.js`, over a real session.
 * What that file cannot reach cheaply is what this one is for: the
 * verb's own refusals, and the fields the row carries.
 *
 * Two properties decide whether the search above it can be right at
 * all. The scan is scoped to the acting account, because the message
 * store keeps one flat namespace of folders and records no owner, so a
 * verb that did not scope would hand one account's search every
 * account's mail. And a message in the folder that cannot be read is a
 * refusal rather than a row left out, because a result set short by a
 * row is indistinguishable from a mailbox that does not hold it.
 *
 * Run standalone: node test/layer-1-state/mailbox-search-scan.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var store   = require("../../lib/store");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var ALICE_SUBJECT = "Roundtrip probe 8fa21c";
var ALICE_BODY    = "The body that was appended, marker 4d91e07b.";
var BOB_SUBJECT   = "zebra7741 belongs to bob and to nobody else";

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
    // so an empty one is an actor granted nothing rather than an actor
    // with a role.
    roles:     ["account"],
  };
}

// Assert a call refuses under one stable code. The code is what the
// listener maps onto its own protocol reply, so a refusal under the
// wrong one is a change a caller would not survive.
function refuses(label, code, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + " " + thrown.message);
}

function message(fields, body) {
  return Buffer.from(fields.concat(["", body, ""]).join("\r\n"), "utf8");
}

// ---- the sequence set grammar ----------------------------------------------

function testSequenceSet() {
  var inSet = mailbox.sequenceSet("2:4,9", 12);
  count("blamepost.mail.mailbox.sequenceSet holds the numbers inside a range",
    inSet(2) && inSet(3) && inSet(4));
  count("blamepost.mail.mailbox.sequenceSet holds a number named on its own", inSet(9));
  count("blamepost.mail.mailbox.sequenceSet holds nothing outside what was named",
    !inSet(1) && !inSet(5) && !inSet(8) && !inSet(10));

  // RFC 9051 section 9 gives `*` the largest number in use, and lets a
  // range be written in either order.
  var toTop = mailbox.sequenceSet("3:*", 5);
  count("blamepost.mail.mailbox.sequenceSet reads * as the highest number in use",
    toTop(3) && toTop(5) && !toTop(2));
  var reversed = mailbox.sequenceSet("7:4", 10);
  count("blamepost.mail.mailbox.sequenceSet reads a range written backwards as the " +
    "same range", reversed(4) && reversed(7) && !reversed(3));

  refuses("blamepost.mail.mailbox.sequenceSet refuses a set that is not a set",
    "mailbox/bad-sequence-set", function () { return mailbox.sequenceSet("2:banana", 9); });
  refuses("blamepost.mail.mailbox.sequenceSet refuses a sequence number below one",
    "mailbox/bad-sequence-set", function () { return mailbox.sequenceSet("0", 9); });
  refuses("blamepost.mail.mailbox.sequenceSet refuses an empty set",
    "mailbox/bad-sequence-set", function () { return mailbox.sequenceSet("", 9); });
}

// ---- the scan --------------------------------------------------------------

function testTheRowCarriesWhatASearchKeyReads(handle, alice) {
  var rows = handle.mailbox.searchScan(alice, "INBOX");
  count("the scan answers with every message in the folder", rows.length === 2,
    String(rows.length));

  var first = rows[0];
  count("the scan numbers messages from one, in the order IMAP counts them",
    first.seq === 1 && rows[1].seq === 2, JSON.stringify([first.seq, rows[1].seq]));
  count("the scan carries the UID an IMAP client addresses the message by",
    typeof first.uid === "number" && first.uid > 0, String(first.uid));
  count("the scan carries the subject a SUBJECT key is matched against",
    first.subject === ALICE_SUBJECT, first.subject);
  count("the scan carries the sender and the recipient as separate fields, which is " +
    "what tells a FROM key from a TO key",
    first.from.indexOf("sender@example.net") !== -1 &&
    first.to.indexOf("alice@example.com") !== -1 &&
    first.from.indexOf("alice@example.com") === -1,
    first.from + " | " + first.to);
  // The store keeps a body text and a body HTML, and the scan carries
  // neither. `b.safeMime.extractText` returns ONE part, so the pair is
  // the first text part and the first HTML part rather than the body,
  // and a message with a second text part or a forwarded message part
  // matches in a place they do not reach. A field named body sitting
  // next to a key called BODY is the whole of what it takes for that
  // wrong answer to get written, so the field is absent and the key
  // refuses.
  count("the scan carries no body, because the store keeps one text part and not a body",
    first.bodyText === undefined && first.bodyHtml === undefined,
    Object.keys(first).join(","));
  count("the scan carries the message id a HEADER Message-ID key is matched against",
    first.messageId.indexOf("first@example.net") !== -1, first.messageId);
  count("the scan carries the flags a flag key reads",
    Array.isArray(first.flags), JSON.stringify(first.flags));
  count("the scan carries the octet count LARGER and SMALLER are measured against",
    typeof first.sizeBytes === "number" && first.sizeBytes > 0, String(first.sizeBytes));
  count("the scan carries the internal date BEFORE, ON and SINCE are measured against",
    typeof first.internalDate === "number" && first.internalDate > 0,
    String(first.internalDate));

  // The two numbers a size key and a date key are decided on have to be
  // the ones FETCH reports for the same message, or a client that
  // searched and then fetched reads two different messages.
  var fetched = handle.mailbox.fetchRange(alice, "INBOX", "1",
    "(RFC822.SIZE INTERNALDATE)", {});
  var reported = /RFC822\.SIZE (\d+)/.exec(fetched[0].payload);
  count("the octet count the scan carries is the one FETCH reports for the same message",
    reported !== null && parseInt(reported[1], 10) === first.sizeBytes,
    fetched[0].payload);

  // Nothing in the row is a decoded copy of the stored octets. The
  // fields are text the store already holds as text, which is why the
  // scan never round trips a message through a decode.
  count("the scan carries no message octets, only the text the store keeps as text",
    first.rawBytes === undefined && first.digest === undefined,
    Object.keys(first).join(","));
}

function testTheScanIsScopedToOneAccount(handle, alice, bob) {
  var hers = handle.mailbox.searchScan(alice, "INBOX");
  var his  = handle.mailbox.searchScan(bob, "INBOX");

  var herSubjects = hers.map(function (r) { return r.subject; });
  var hisSubjects = his.map(function (r) { return r.subject; });

  count("bob's scan answers with bob's own message",
    hisSubjects.length === 1 && hisSubjects[0] === BOB_SUBJECT, hisSubjects.join(" | "));
  count("alice's scan never carries a message from bob's mailbox",
    herSubjects.indexOf(BOB_SUBJECT) === -1, herSubjects.join(" | "));
  count("the two accounts' scans share no message identity at all",
    hers.every(function (r) {
      return his.every(function (o) { return o.objectid !== r.objectid; });
    }), hers.length + " and " + his.length + " messages");
}

function testTheScanRefuses(handle, alice) {
  // A call that cannot say whose mailbox it is has no mailbox to answer
  // with. There is no fallback to a shared folder, because a fallback
  // here is a search that serves somebody else's mail.
  refuses("a scan with no acting account refuses", "mailbox/no-actor",
    function () { return handle.mailbox.searchScan(null, "INBOX"); });
  refuses("a scan whose actor carries no id refuses", "mailbox/no-actor",
    function () { return handle.mailbox.searchScan({ address: "alice@example.com" }, "INBOX"); });

  // A folder the account does not have is refused by name rather than
  // answered with nothing, which is a different fact about the mailbox.
  refuses("a scan of a folder this account does not have refuses", "mailbox/no-folder",
    function () { return handle.mailbox.searchScan(alice, "Nowhere"); });

  // The folder name goes through the same namespace rule every other
  // verb reads it through, so a name that could render as another name
  // is refused at the point of parse.
  refuses("a scan of a name the folder namespace refuses is refused there",
    "mailbox/bad-mailbox-name",
    function () { return handle.mailbox.searchScan(alice, "Arch*ive"); });
}

// ---- the run ---------------------------------------------------------------

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-search-scan-"));
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

    testSequenceSet();

    handle.mailbox.appendMessage("INBOX", message([
      "From: Sender <sender@example.net>",
      "To: Recipient <alice@example.com>",
      "Subject: " + ALICE_SUBJECT,
      "Message-ID: <first@example.net>",
    ], ALICE_BODY), { actor: alice, flags: [] });
    handle.mailbox.appendMessage("INBOX", message([
      "From: Other <other@example.org>",
      "To: Recipient <alice@example.com>",
      "Subject: Second note",
      "Message-ID: <second@example.org>",
    ], "A shorter body."), { actor: alice, flags: [] });
    handle.mailbox.appendMessage("INBOX", message([
      "From: Someone <someone@example.net>",
      "To: Bob <bob@example.com>",
      "Subject: " + BOB_SUBJECT,
      "Message-ID: <bobs-only@example.net>",
    ], "bob's own body"), { actor: bob, flags: [] });

    testTheRowCarriesWhatASearchKeyReads(handle, alice);
    testTheScanIsScopedToOneAccount(handle, alice, bob);
    testTheScanRefuses(handle, alice);

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
  name: "mailbox-search-scan",
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
