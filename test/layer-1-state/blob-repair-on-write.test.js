// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a delivery does when the body it was about to write is already on
 * the volume and has gone bad.
 *
 * Content addressing means the second account handed a message this
 * server already holds writes nothing: the file at the digest's own path
 * is that message, so the delivery files a row and reuses the file. That
 * is right, and it is the whole reason two accounts handed one mailing
 * list message cost one copy rather than two.
 *
 * It is also the one case where "the file is there" is not the same
 * question as "the file is the message". A body that was cut short by a
 * restore that copied a prefix, by a write that stopped part way, or by
 * a volume that gave back less than it was given is still a file at that
 * path. Every later account handed the same message inherits it, and
 * their mail is unreadable from the moment it arrives: they never had a
 * good copy of their own to lose.
 *
 * The delivery is holding the good octets while that happens, which
 * makes it the one moment where putting it right costs a write that was
 * going to happen anyway. So it writes them.
 *
 * Four properties are driven here, and the fourth is the boundary rather
 * than the promise:
 *
 *   - **The ordinary case stays free.** A delivery landing on an intact
 *     body rewrites nothing, measured on the file rather than inferred
 *     from a timing.
 *   - **A short body is repaired by the next identical delivery**, and
 *     both accounts read their mail afterwards, over IMAP and over POP3,
 *     because both read a body through the same check.
 *   - **The repair is recorded.** One repair is a bad sector; a run of
 *     them is a volume on its way out, and an operator can only read
 *     that off a trail that has them in it.
 *   - **A body that changed without changing length is not repaired.**
 *     The check that decides is a length, because unsealing and
 *     re-hashing every file a duplicate delivery lands on would put a
 *     full read and a full digest of the message on the delivery path
 *     for every message this server already holds. A flipped bit leaves
 *     the length alone, so it is still refused at the read and still
 *     named by `blobs report --verify`, and this pins that rather than
 *     letting the repair be read as covering it.
 *
 * Reference counting is not touched by any of it. A repair rewrites
 * octets; it files no row, releases no body, and leaves the count of
 * rows naming a digest exactly where it found it.
 *
 * Run standalone: node test/layer-1-state/blob-repair-on-write.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var blobs   = require("../../lib/store/blobs");
var mailbox = require("../../lib/mail/mailbox");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var MESSAGES = mailbox.MESSAGES;

var BODY_REPAIRED = "blamepost.mail.mailbox.body_repaired";

// Every message built here is the same length, and one case depends on
// that. Holding a body against its digest costs a read and a hash, so
// the write path decides on a length instead, and the case that pins
// what a length cannot see needs two bodies that differ in content and
// not in size. A marker of a fixed width is what makes that true without
// measuring anything afterwards.
var MARKER_CHARS = 12;

// Far enough below any correct sealed body that a filesystem cannot
// round it back up. The sealed form of a message carries a ciphertext of
// the base64 text of the octets, so it runs well past the message
// itself, and this is a prefix of the front of it.
var TRUNCATED_BYTES = 96;

// Older than the settle window by a clear margin, so the moment a
// delivery lands on the file is unmistakable in its timestamp. Nothing
// here reclaims anything; the age is a marker, not a policy.
var WELL_AGED_MS = blobs.SETTLE_MS + b.constants.TIME.hours(6);

// The shape a signed in session carries. The mail agent reads the roles
// in front of every delete, so an actor without them is refused before
// this layer is reached.
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

function messageFor(marker) {
  if (marker.length !== MARKER_CHARS) {
    throw new Error("blob-repair-on-write: every marker is " + MARKER_CHARS +
      " characters wide, and " + JSON.stringify(marker) + " is not");
  }
  return Buffer.from(
    "From: Announcements <list@example.net>\r\n" +
    "To: everyone@example.net\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker + "@example.net>\r\n" +
    "\r\n" +
    "The body nobody but the account holder reads: " + marker + ".\r\n", "utf8");
}

function digestOf(objectid) {
  var row = b.db.from(MESSAGES).where({ objectid: objectid }).first();
  return row ? row.blobDigest : null;
}

function rowsNaming(digest) {
  return b.db.from(MESSAGES).where({ blobDigest: digest }).count();
}

function ageFile(path) {
  var when = new Date(Date.now() - WELL_AGED_MS);
  nodeFs.utimesSync(path, when, when);
}

// What the account holder's own client gets back, read through the verb
// that client speaks rather than through a query into the store. A body
// a row can find and a FETCH cannot is exactly the failure these cases
// exist to catch, so nothing here asserts on a row.
function imapBody(handle, actor) {
  var rendered = handle.mailbox.fetchRange(actor, "INBOX", "1", "BODY.PEEK[]", {});
  return rendered[0].payload.toString("utf8");
}

async function pop3Body(handle, actor) {
  var drop = handle.mailbox.openPop3Drop(actor, {});
  try {
    var retrieved = handle.mailbox.getMessage(actor, drop.dropId, 1, {});
    return retrieved === null ? "" : retrieved.rawBytes.toString("utf8");
  } finally {
    // The drop is held exclusively for the session that opened it, so it
    // is given back on the way out of a read that refused as well as one
    // that answered. Nothing was marked for deletion, so the commit
    // destroys nothing.
    await handle.mailbox.commitPop3Drop(actor, drop.dropId);
  }
}

// The refusal code a read answered with, or null when it answered with a
// message. Both protocols are asked, because a refusal one of them makes
// and the other does not is a message one client can open and the other
// cannot.
async function refusalFrom(read) {
  try {
    await read();
    return null;
  } catch (e) {
    return (e && e.code) || "thrown-without-a-code";
  }
}

// The same refusal read for its sentence rather than its code. A code
// says which branch answered and the sentence says what an operator is
// being told, and one refusal that carries several causes is only worth
// having if it names them.
async function refusalTextFrom(read) {
  try {
    await read();
    return null;
  } catch (e) {
    return (e && e.message) || String(e);
  }
}

async function repairRowsFor(digest) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: BODY_REPAIRED, order: "desc", limit: 50 });
  if (!Array.isArray(rows)) return [];
  return rows.filter(function (row) { return row.resourceId === digest; });
}

// ---- the ordinary case -------------------------------------------------------

// The delivery that finds an intact body writes nothing. Asserted on the
// file's own timestamp rather than on how long the call took: the file is
// aged first, so a rewrite would move it to now and a reuse leaves it
// where it was put.
function anIntactBodyIsLeftAlone(handle, alice, bob, blobDir) {
  var bytes = messageFor("intact-body1");
  var hers = handle.mailbox.appendMessage("INBOX", bytes, { actor: alice });
  var digest = digestOf(hers.objectid);
  var bodyPath = blobs.pathFor(blobDir, digest);

  ageFile(bodyPath);
  var before = nodeFs.statSync(bodyPath);

  var his = handle.mailbox.appendMessage("INBOX", bytes, { actor: bob });
  var after = nodeFs.statSync(bodyPath);

  count("two accounts handed the same octets still name one body",
    digestOf(his.objectid) === digest, String(digest).slice(0, 24));
  count("and the delivery that found it there rewrote nothing, so the ordinary " +
    "duplicate costs a look at the file and no seal",
    after.mtimeMs === before.mtimeMs && after.size === before.size,
    JSON.stringify({ before: before.mtimeMs, after: after.mtimeMs }));

  var forAlice = imapBody(handle, alice);
  var forBob   = imapBody(handle, bob);
  count("both accounts read the shared body over IMAP",
    forAlice.indexOf("intact-body1") !== -1 && forBob.indexOf("intact-body1") !== -1,
    forAlice.length + " / " + forBob.length + " octets");
}

// ---- a body cut short --------------------------------------------------------

async function aShortBodyIsRewrittenByTheNextIdenticalDelivery(handle, carol, dave, blobDir) {
  var bytes = messageFor("cut-short-01");
  var hers = handle.mailbox.appendMessage("INBOX", bytes, { actor: carol });
  var digest = digestOf(hers.objectid);
  var bodyPath = blobs.pathFor(blobDir, digest);
  var whole = nodeFs.statSync(bodyPath).size;

  // What a restore that copied a prefix leaves, and what a write cut off
  // part way through leaves: a file at the right path holding the front
  // of the right bytes.
  nodeFs.truncateSync(bodyPath, TRUNCATED_BYTES);
  ageFile(bodyPath);
  count("the body on disk is cut short, so the volume is in the state the repair " +
    "is for rather than in a state that only looks like it",
    nodeFs.statSync(bodyPath).size === TRUNCATED_BYTES && whole > TRUNCATED_BYTES,
    TRUNCATED_BYTES + " of " + whole + " bytes");

  var beforeImap = await refusalFrom(function () { return imapBody(handle, carol); });
  var beforePop3 = await refusalFrom(function () { return pop3Body(handle, carol); });
  // A cut-short body does not decrypt at all, because the seal
  // authenticates what it carries end to end, so this is a different
  // refusal from a body that opened and hashed to the wrong name. It is
  // still this layer's own: what the vault raises carries no code, and a
  // listener with no reading for it would tell the client to try again
  // at something that can never succeed.
  //
  // The code says which form the file was in rather than what went wrong
  // inside it. A body is sealed under the message it belongs to, and an
  // AEAD tag fails identically for bytes cut short, for a value sealed
  // as something else, and for one written under another volume's vault
  // key, so the refusal names all three and the operator reads which
  // applies off the rest of the volume.
  count("the account that already had the message cannot read it, and is refused in " +
    "this layer's own words rather than in the vault's",
    beforeImap === "mailbox/blob-seal-foreign", String(beforeImap));
  count("and the same on POP3, which reads the same body through the same check",
    beforePop3 === "mailbox/blob-seal-foreign", String(beforePop3));
  var beforeText = await refusalTextFrom(function () { return imapBody(handle, carol); });
  count("and the refusal names damage among the causes, because the seal cannot tell a " +
    "body cut short from a value sealed as something else",
    /cut short or altered/.test(String(beforeText)), String(beforeText));

  // The second account, handed octets that are byte for byte the ones
  // the file was supposed to hold.
  var his = handle.mailbox.appendMessage("INBOX", bytes, { actor: dave });
  count("the second account's message names the same body, because the octets are " +
    "the same octets",
    digestOf(his.objectid) === digest, String(digestOf(his.objectid)).slice(0, 24));

  var repaired = nodeFs.statSync(bodyPath);
  count("and the delivery holding those octets wrote them, so the file is whole again",
    repaired.size === whole, repaired.size + " vs " + whole);

  var hisImap  = imapBody(handle, dave);
  var hisPop3  = await pop3Body(handle, dave);
  var herImap  = imapBody(handle, carol);
  var herPop3  = await pop3Body(handle, carol);
  count("the account that arrived after the corruption reads its mail over IMAP",
    hisImap.indexOf("cut-short-01") !== -1, hisImap.length + " octets");
  count("and over POP3, which reads the same body through the same check",
    hisPop3.indexOf("cut-short-01") !== -1, hisPop3.length + " octets");
  count("and the account that was already holding it reads it again, because one file " +
    "is what the two of them share",
    herImap.indexOf("cut-short-01") !== -1 && herPop3.indexOf("cut-short-01") !== -1,
    herImap.length + " / " + herPop3.length + " octets");

  var report = handle.blobs.reconcile({ verify: true });
  count("unsealing every referenced body and hashing it back finds nothing wrong " +
    "with the volume",
    report.corrupt.length === 0 && report.missing.length === 0,
    JSON.stringify({ corrupt: report.corrupt.length, missing: report.missing.length }));

  count("the repair filed no row and released no body, so the two rows naming these " +
    "octets are still the two that were there",
    rowsNaming(digest) === 2, String(rowsNaming(digest)));

  var rows = await repairRowsFor(digest);
  count("the repair is on the audit chain, so a volume repairing bodies repeatedly " +
    "is something an operator can read rather than infer",
    rows.length === 1, String(rows.length));
  var row = rows[0] || null;
  count("and the row names the body by the digest `blobs report --verify` names it by",
    row !== null && row.resourceId === digest && row.outcome === "success",
    JSON.stringify(row && { resourceId: row.resourceId, outcome: row.outcome }));
  count("and says how short the file was against how long the message is, which is " +
    "what separates a truncation from a file that was never written",
    row !== null && JSON.parse(row.metadata || "{}").foundBytes === TRUNCATED_BYTES &&
    JSON.parse(row.metadata || "{}").messageBytes === bytes.length,
    String(row && row.metadata));
}

// ---- what a length cannot see ------------------------------------------------

// The boundary, driven rather than described. A body that changed without
// changing length is what a flipped bit leaves, and the write path is not
// told about it: deciding otherwise would mean unsealing and re-hashing
// every file every duplicate delivery lands on.
//
// So this asserts the two things that are true instead. The read still
// refuses, on both protocols, and the reconciliation still names it. A
// repair that was read as covering this shape would leave an operator
// believing a volume repairs itself while it quietly serves refusals.
async function aBodyChangedInPlaceIsRefusedRatherThanRepaired(handle, erin, frank, blobDir) {
  var bytes = messageFor("bit-rot-0001");
  var other = messageFor("other-body-1");
  count("the two messages are the same length, so a body sealed from one is exactly " +
    "as long on disk as a body sealed from the other",
    bytes.length === other.length, bytes.length + " vs " + other.length);

  var hers = handle.mailbox.appendMessage("INBOX", bytes, { actor: erin });
  var digest = digestOf(hers.objectid);
  var bodyPath = blobs.pathFor(blobDir, digest);
  var whole = nodeFs.statSync(bodyPath).size;

  // Sealed by this server's own vault, under the name this file is
  // filed as, so the seal opens and only the content is wrong. Nothing
  // is forged and no key is needed. The context is the one the writer
  // uses: a body planted under any other would be refused by the seal,
  // which is a different shape from the one being driven here.
  nodeFs.writeFileSync(bodyPath,
    b.vault.aad.seal(other.toString("base64"), mailbox.bodySealContext(digest)),
    { mode: 0o600 });
  ageFile(bodyPath);
  var swapped = nodeFs.statSync(bodyPath);
  count("the body on disk holds different octets and occupies the same bytes, which " +
    "is the shape a length can never separate from an intact file",
    swapped.size === whole, swapped.size + " vs " + whole);

  var his = handle.mailbox.appendMessage("INBOX", bytes, { actor: frank });
  count("an identical delivery still files its row and still shares the body",
    digestOf(his.objectid) === digest, String(digestOf(his.objectid)).slice(0, 24));
  count("and leaves the file exactly as it found it, because nothing about its length " +
    "said anything was wrong",
    nodeFs.statSync(bodyPath).mtimeMs === swapped.mtimeMs,
    JSON.stringify({ before: swapped.mtimeMs, after: nodeFs.statSync(bodyPath).mtimeMs }));

  var herImap  = await refusalFrom(function () { return imapBody(handle, erin); });
  var hisImap  = await refusalFrom(function () { return imapBody(handle, frank); });
  var hisPop3  = await refusalFrom(function () { return pop3Body(handle, frank); });
  count("so neither account is served the other message over IMAP: the read hashes " +
    "the octets back and refuses",
    herImap === "mailbox/blob-digest-mismatch" && hisImap === "mailbox/blob-digest-mismatch",
    String(herImap) + " / " + String(hisImap));
  count("nor over POP3, which reads the same body through the same check",
    hisPop3 === "mailbox/blob-digest-mismatch", String(hisPop3));

  var report = handle.blobs.reconcile({ verify: true });
  count("and the reconciliation names the file, which is where this shape is found " +
    "rather than on the delivery path",
    report.ok === false &&
    report.corrupt.some(function (entry) { return entry.digest === digest; }),
    JSON.stringify(report.corrupt.map(function (entry) {
      return String(entry.digest).slice(0, 16);
    })));

  var rows = await repairRowsFor(digest);
  count("with nothing recorded as repaired, because nothing was",
    rows.length === 0, String(rows.length));
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("blob-repair");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

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
    await handle.domains.add({ domain: DOMAIN });

    var made = {};
    var names = ["alice", "bob", "carol", "dave", "erin", "frank"];
    for (var i = 0; i < names.length; i += 1) {
      made[names[i]] = actorFor(await handle.accounts.create({
        address: names[i] + "@" + DOMAIN, password: PASSWORD,
      }));
    }

    var blobDir = handle.mailbox.describe().blobDir;

    anIntactBodyIsLeftAlone(handle, made.alice, made.bob, blobDir);
    await aShortBodyIsRewrittenByTheNextIdenticalDelivery(handle, made.carol, made.dave,
      blobDir);
    // Last, because it deliberately leaves one body on the volume that
    // does not hash to its own name, and every reconciliation afterwards
    // would report it.
    await aBodyChangedInPlaceIsRefusedRatherThanRepaired(handle, made.erin, made.frank,
      blobDir);

    handle.close();
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

module.exports = { name: "blob-repair-on-write", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
