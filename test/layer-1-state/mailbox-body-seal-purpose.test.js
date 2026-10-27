// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a stored message body is sealed under, and what a volume whose
 * bodies were sealed before that binding existed does next.
 *
 * The vault's plain seal produces a value that opens wherever it is
 * found, so every sealed value one volume holds is interchangeable with
 * every other as far as the vault is concerned. A message body has a
 * second thing placing it that a signing key never had: the file name is
 * the SHA3-512 of the octets, and the read hashes what it opened and
 * refuses anything that does not come back to the name. That check is
 * what has been closing this, and it still runs.
 *
 * What the binding adds is the order. A value sealed as something other
 * than this message's body is refused before its plaintext is ever
 * produced, so the octets of another secret are not base64 decoded and
 * hashed inside the read path serving a mailbox. The vector below that
 * proves the order is the one where the content address would have said
 * yes: a message's own octets, sealed under another message's name. The
 * hash comes back correct and the read still refuses, so the refusal can
 * only have come from the binding.
 *
 * Nothing here is faked. A real vault seals, a real encrypted database
 * holds the rows, and every body is written by the adapter's own append.
 *
 * Run standalone: node test/layer-1-state/mailbox-body-seal-purpose.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blobs     = require("../../lib/store/blobs");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var DOMAIN = "example.com";
var PASSWORD = "a sufficiently long account password";

// The context a message body is sealed under, written out here rather
// than imported from the module that seals with it.
//
// It decides whether a body sealed by the server running today opens in
// the server running tomorrow, and a mailbox holds the only copy.
// Importing the constant would let a changed tuple pass this file while
// every body already on every volume stopped opening.
var BODY_SEAL_PURPOSE = "blamepost.mail.mailbox.message-body";

function bodyContext(digest) {
  return { purpose: BODY_SEAL_PURPOSE, digest: digest };
}

// The other purpose this server seals a secret under. A value carrying
// it is sealed, is this volume's, and is not a message body, which is
// exactly the value the binding exists to keep out of the read path.
var TOKEN_SEAL_CONTEXT = { purpose: "blamepost.dns.provider-token" };

function mailFor(address, subject, filler) {
  return Buffer.from(
    "From: sender@example.net\r\n" +
    "To: " + address + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 1 Jun 2026 10:00:00 +0000\r\n" +
    "Message-ID: <" + subject.replace(/\s+/g, "-") + "@example.net>\r\n" +
    "\r\n" +
    "the body of " + subject + "\r\n" + (filler || "") + "\r\n", "utf8");
}

function refusalOf(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

// One body's file, read and written where the adapter put it.
function bodyPathOf(blobDir, digest) { return blobs.pathFor(blobDir, digest); }

function readBody(blobDir, digest) {
  return nodeFs.readFileSync(bodyPathOf(blobDir, digest), "utf8");
}

function writeBody(blobDir, digest, text) {
  nodeFs.writeFileSync(bodyPathOf(blobDir, digest), text, { mode: 0o600 });
}

// ---- a stored body carries its purpose --------------------------------------

function aStoredBodyIsBoundToItsName(seeded) {
  var onDisk = readBody(seeded.blobDir, seeded.first.digest);

  count("a message body the adapter has just stored is sealed under a purpose rather than " +
    "to the volume at large",
    b.vault.aad.isAadSealed(onDisk), onDisk.slice(0, 32));
  count("and it does not carry the plain volume seal, which every other sealed value on " +
    "this volume also carries",
    onDisk.indexOf(b.constants.VAULT_PREFIX) !== 0, onDisk.slice(0, 32));
  count("no plaintext of the message reaches the volume",
    onDisk.indexOf("the body of") === -1 && onDisk.indexOf("Subject:") === -1,
    onDisk.slice(0, 64));

  var source = seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
  count("and the message reads back through the path a reply is derived from",
    source !== null && Buffer.isBuffer(source.bytes) &&
    source.bytes.toString("utf8").indexOf(seeded.first.subject) !== -1,
    source === null ? "(no source)" : String(source.withheld));
}

// ---- a value sealed for something else is not a body ------------------------

function aValueSealedElsewhereDoesNotOpenAsABody(seeded) {
  var digest = seeded.first.digest;
  var whole = readBody(seeded.blobDir, digest);
  try {
    // A value this volume sealed, this volume's own vault key, and not a
    // message body. Its octets do not hash to the name either, so the
    // content address would refuse it as well: what this pins is WHICH
    // refusal answers.
    writeBody(seeded.blobDir, digest,
      b.vault.aad.seal("a provider token that is not anybody's mail", TOKEN_SEAL_CONTEXT));
    var planted = refusalOf(function () {
      return seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
    });

    count("a value this volume sealed for something other than this message's body is " +
      "refused rather than opened",
      planted !== null && planted.code === "mailbox/blob-seal-foreign",
      planted ? String(planted.code) : "the mailbox served it");
    count("and it is refused by the seal rather than by the digest, so the octets of " +
      "another secret are never produced inside the read serving a mailbox",
      planted !== null && planted.code !== "mailbox/blob-digest-mismatch",
      planted ? String(planted.code) : "(no refusal)");
    count("and the refusal carries no part of the volume's layout, because it is answered " +
      "to whoever asked for the message",
      planted !== null && planted.message.indexOf(seeded.blobDir) === -1 &&
      planted.message.indexOf(seeded.dataDir) === -1,
      planted ? planted.message : "(no refusal)");
    count("and it names the message rather than only saying something is wrong",
      planted !== null && planted.message.indexOf(digest.slice(0, 12)) !== -1,
      planted ? planted.message : "(no refusal)");
  } finally {
    writeBody(seeded.blobDir, digest, whole);
  }

  var again = seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
  count("and the message reads again once its own body is back, so the refusal was about " +
    "the value rather than about the mailbox",
    again !== null && again.bytes !== null, "the mailbox stopped serving the message");
}

// ---- the order: a body the content address would have accepted --------------
//
// This is the vector that says the binding is load-bearing rather than
// decoration. The octets written here ARE the octets the file name says,
// so the digest comparison at the end of the read would pass. They are
// sealed under a second message's name, and the read refuses. Nothing
// but the binding can be answering.

function theBindingRefusesBeforeTheContentAddress(seeded) {
  var digest = seeded.first.digest;
  var whole = readBody(seeded.blobDir, digest);
  try {
    var octets = seeded.first.raw.toString("base64");
    writeBody(seeded.blobDir, digest,
      b.vault.aad.seal(octets, bodyContext(seeded.second.digest)));

    // What the content address would have said about the same octets,
    // measured rather than asserted: they hash to the name they are
    // filed under, so the check at the end of the read is one this value
    // passes.
    count("the planted octets are the ones this file name says, so the content address " +
      "would have accepted them",
      b.crypto.sha3Hash(Buffer.from(octets, "base64")) === digest,
      b.crypto.sha3Hash(Buffer.from(octets, "base64")).slice(0, 16));

    var planted = refusalOf(function () {
      return seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
    });
    count("a body whose octets the content address accepts is still refused when it is " +
      "sealed under another message's name, so the refusal comes from the binding",
      planted !== null && planted.code === "mailbox/blob-seal-foreign",
      planted ? String(planted.code) : "the mailbox served a body sealed as another message");

    // The same value under the purpose and nothing else. This is what
    // the seal would carry if the digest were dropped from the context,
    // and it is the reading that says the digest is load-bearing: every
    // body on this volume carries the same purpose, so a purpose on its
    // own puts every message's body back in reach of every other.
    writeBody(seeded.blobDir, digest,
      b.vault.aad.seal(octets, { purpose: BODY_SEAL_PURPOSE }));
    var purposeOnly = refusalOf(function () {
      return seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
    });
    count("the right octets sealed under the purpose alone do not open either, so the seal " +
      "names the message rather than only the kind of secret",
      purposeOnly !== null && purposeOnly.code === "mailbox/blob-seal-foreign",
      purposeOnly ? String(purposeOnly.code) : "a purpose-only seal was served");
  } finally {
    writeBody(seeded.blobDir, digest, whole);
  }
}

// ---- every wire the body is served on -------------------------------------
//
// One read opens every stored body, so a refusal that reached only the
// path a reply is derived from would be a refusal three protocols route
// around. IMAP FETCH BODY[] and POP3 RETR are driven here because they
// are the two that answer with the stored octets themselves.

async function everyReadOfTheBodyRefusesTheSameWay(seeded) {
  var digest = seeded.first.digest;
  var whole = readBody(seeded.blobDir, digest);
  try {
    writeBody(seeded.blobDir, digest,
      b.vault.aad.seal("a provider token that is not anybody's mail", TOKEN_SEAL_CONTEXT));

    var fetched = refusalOf(function () {
      return seeded.mailbox.fetchRange(seeded.actor, "INBOX", "1", "BODY[]", {});
    });
    count("an IMAP fetch of the stored octets is refused by the binding",
      fetched !== null && fetched.code === "mailbox/blob-seal-foreign",
      fetched ? String(fetched.code) : "the fetch served it");

    var drop = seeded.mailbox.openPop3Drop(seeded.actor, { exclusive: true });
    var retrieved;
    try {
      retrieved = refusalOf(function () {
        return seeded.mailbox.getMessage(seeded.actor, drop.dropId, 1, {});
      });
    } finally {
      seeded.mailbox.releasePop3Drop(drop.dropId);
    }
    count("and so is a POP3 retrieval, which is a separate read of the same file",
      retrieved !== null && retrieved.code === "mailbox/blob-seal-foreign",
      retrieved ? String(retrieved.code) : "the retrieval served it");
  } finally {
    writeBody(seeded.blobDir, digest, whole);
  }
}

// ---- a volume sealed before the binding existed -----------------------------

function aVolumeSealedTheOldWayKeepsServing(seeded) {
  var digest = seeded.first.digest;
  var whole = readBody(seeded.blobDir, digest);
  var octets = seeded.first.raw.toString("base64");
  try {
    writeBody(seeded.blobDir, digest, b.vault.seal(octets));
    var served = seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
    count("a body sealed the way this volume sealed them before still opens, so an upgrade " +
      "does not make a mailbox of existing mail unreadable",
      served !== null && Buffer.isBuffer(served.bytes) &&
      served.bytes.toString("utf8").indexOf(seeded.first.subject) !== -1,
      served === null ? "(nothing served)" : String(served.withheld));

    // The guard the old form still has, and the reason no migration is
    // needed for it: the name is the hash of the octets, so a value
    // sealed the old way that is not this message's body is refused by
    // the content address exactly as it always was.
    writeBody(seeded.blobDir, digest,
      b.vault.seal(Buffer.from("different octets entirely", "utf8").toString("base64")));
    var stranger = refusalOf(function () {
      return seeded.mailbox.readMessageSource(seeded.actor, "INBOX", seeded.first.objectid);
    });
    count("and a value sealed the old way that is not the octets its name says is still " +
      "refused, so a volume carrying both forms serves nothing it cannot place",
      stranger !== null && stranger.code === "mailbox/blob-digest-mismatch",
      stranger ? String(stranger.code) : "the mailbox served a stranger's octets");
  } finally {
    writeBody(seeded.blobDir, digest, whole);
  }
}

// ---- the reconciliation reads the same two forms ----------------------------

function theReconciliationAgreesWithTheReader(seeded) {
  var digest = seeded.first.digest;
  var whole = readBody(seeded.blobDir, digest);
  try {
    var clean = seeded.handle.blobs.reconcile({ verify: true });
    count("a volume whose bodies are bound reconciles, so the walk that unseals every " +
      "referenced body reads the form the adapter writes",
      clean.corrupt.length === 0, JSON.stringify(clean.corrupt));

    writeBody(seeded.blobDir, digest, b.vault.seal(seeded.first.raw.toString("base64")));
    var mixed = seeded.handle.blobs.reconcile({ verify: true });
    count("and a body still sealed the old way is not reported as damaged, so the " +
      "reconciliation does not send an operator to restore a volume that is intact",
      mixed.corrupt.length === 0, JSON.stringify(mixed.corrupt));

    writeBody(seeded.blobDir, digest,
      b.vault.aad.seal("a provider token that is not anybody's mail", TOKEN_SEAL_CONTEXT));
    var planted = seeded.handle.blobs.reconcile({ verify: true });
    var entry = planted.corrupt.filter(function (c) { return c.digest === digest; })[0];
    count("a value sealed as something other than this message's body is reported by the " +
      "reconciliation rather than passed over",
      entry !== undefined, JSON.stringify(planted.corrupt));
    count("and the reason names the seal rather than the hash, because the two send an " +
      "operator to different places",
      entry !== undefined && /sealed/.test(entry.reason) && !/hash to/.test(entry.reason),
      entry ? entry.reason : "(nothing reported)");
  } finally {
    writeBody(seeded.blobDir, digest, whole);
  }
}

// ---- runner -----------------------------------------------------------------

async function seed(handle, dataDir) {
  await handle.domains.add({ domain: DOMAIN });
  var alice = await handle.accounts.create({
    address: "alice@" + DOMAIN, password: PASSWORD });
  var actor = { id: alice.id, address: alice.address, roles: ["account"] };
  var mailbox = handle.mailbox;

  var firstRaw = mailFor(alice.address, "the first message");
  var secondRaw = mailFor(alice.address, "the second message");
  var first = mailbox.appendMessage("INBOX", firstRaw, { actor: actor });
  var second = mailbox.appendMessage("INBOX", secondRaw, { actor: actor });

  return {
    handle:   handle,
    mailbox:  mailbox,
    actor:    actor,
    dataDir:  dataDir,
    blobDir:  mailbox.describe().blobDir,
    first: {
      objectid: first.objectid,
      raw:      firstRaw,
      digest:   b.crypto.sha3Hash(firstRaw),
      subject:  "the first message",
    },
    second: {
      objectid: second.objectid,
      raw:      secondRaw,
      digest:   b.crypto.sha3Hash(secondRaw),
      subject:  "the second message",
    },
  };
}

async function run() {
  var root    = helpers.tempDir("mailbox-body-seal-purpose");
  var dataDir = helpers.dataDir(root);
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var handle = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    handle = await store.open(cfg);
    var seeded = await seed(handle, dataDir);

    aStoredBodyIsBoundToItsName(seeded);
    aValueSealedElsewhereDoesNotOpenAsABody(seeded);
    theBindingRefusesBeforeTheContentAddress(seeded);
    await everyReadOfTheBodyRefusesTheSameWay(seeded);
    aVolumeSealedTheOldWayKeepsServing(seeded);
    theReconciliationAgreesWithTheReader(seeded);

    return helpers.getChecks();
  } finally {
    if (handle) {
      try { handle.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "mailbox-body-seal-purpose",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (checks) {
    console.log("CHECKS " + checks);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
