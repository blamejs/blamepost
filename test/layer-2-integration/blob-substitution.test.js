// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The message a client is handed is the message the row names.
 *
 * A body is stored once under the hash of its own content and a row
 * points at it by that hash. Two accounts holding identical octets share
 * one file, which is the point of storing them that way. It also means
 * the file name is the ONLY thing binding a body to the account whose row
 * names it: swap two files and each account's row now points at the
 * other's message, and every seal still opens, because every body on a
 * volume is sealed under the same vault key.
 *
 * That matters more than it first looks. Forging a sealed body needs the
 * key. MOVING one that this server sealed itself needs nothing but the
 * ability to rename a file, and the names are in plaintext on the volume
 * while the rows that would disagree are inside a database that is
 * encrypted and authenticated. The two halves of the binding are not
 * equally protected, so the half that is cheap to attack is the half the
 * read has to check.
 *
 * So the read re-hashes. Both cases here drive the wire an account holder
 * actually uses, IMAP and POP3, because the property is about what
 * reaches a client and an assertion on an internal helper would not have
 * seen the octets leave.
 *
 * The second case is the digest itself. A hash out of a row decides which
 * file on the volume is opened, and one that is not a hash at all decides
 * which file anywhere is opened. The path is built in one place and the
 * shape is checked in front of it, so a row that has been rewritten
 * addresses nothing.
 *
 * Run standalone: node test/layer-2-integration/blob-substitution.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var mailbox   = require("../../lib/mail/mailbox");
var blobs     = require("../../lib/store/blobs");
var blamepost = require("../../lib");

var count = helpers.count;

var Wire     = wire.Wire;
var LOOPBACK = wire.LOOPBACK;
var visible  = wire.visible;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// One marker per account, distinct enough that a body arriving under the
// wrong name is unmistakable in a transcript.
var ALICE_MARKER = "alice-private-4f1c";
var BOB_MARKER   = "bob-private-9d20";

function messageFor(address, marker) {
  return Buffer.from([
    "From: sender@example.net",
    "To: " + address,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "The body nobody but " + address + " is supposed to read: " + marker + ".",
    "",
  ].join("\r\n"), "utf8");
}

// ---- reading the way an account holder reads --------------------------------

async function imapBody(port, caPem, address, label) {
  var session = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD, label: label,
  });
  try {
    var selectTag = session.tag();
    session.send(selectTag + " SELECT INBOX");
    await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");
    var fetchTag = session.tag();
    session.send(fetchTag + " FETCH 1 BODY[]");
    return await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "FETCH answered");
  } finally {
    session.close();
  }
}

async function pop3Body(port, caPem, address, label) {
  var session = await Wire.pop3(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD, label: label,
  });
  try {
    session.send("RETR 1");
    return await session.read(/^(\+OK[\s\S]*?\r\n\.\r\n|-ERR[^\r\n]*\r\n)/m, "RETR answered");
  } finally {
    session.send("QUIT");
    session.close();
  }
}

// ---- reaching the volume the way somebody who holds it would -----------------

// The hash each account's one message is filed under, read off the rows
// the listeners serve from rather than recomputed here, so the case acts
// on the binding the server is actually using.
function digestsByFolder(identity) {
  var rows = b.db.from(mailbox.MESSAGES).all();
  var out = {};
  for (var i = 0; i < rows.length; i += 1) out[String(rows[i].folder)] = rows[i];
  return out;
}

function folderOf(identity, accountId) {
  var rows = b.db.from(mailbox.FOLDERS).where({ account: accountId }).all();
  for (var i = 0; i < rows.length; i += 1) {
    if (String(rows[i].wireName).toUpperCase() === "INBOX") return rows[i];
  }
  throw new Error("blob-substitution: no INBOX for account " + accountId);
}

// ---- cases -------------------------------------------------------------------

// Before anything is moved. If this half does not hold, the case below
// would pass against a server that cannot serve a message at all.
async function eachAccountReadsItsOwnMessageFirst(ports, caPem, alice, bob) {
  var forAlice = await imapBody(ports.imap, caPem, alice, "imap-alice-before");
  count("alice reads her own message over IMAP before anything is moved",
    forAlice.indexOf(ALICE_MARKER) !== -1, visible(forAlice).slice(0, 300));
  var forBob = await imapBody(ports.imap, caPem, bob, "imap-bob-before");
  count("and bob reads his", forBob.indexOf(BOB_MARKER) !== -1,
    visible(forBob).slice(0, 300));
  count("and neither sees the other's", forBob.indexOf(ALICE_MARKER) === -1 &&
    forAlice.indexOf(BOB_MARKER) === -1,
    visible(forBob).slice(0, 200) + " | " + visible(forAlice).slice(0, 200));
}

// Exchange the two sealed files. Nothing is forged and no key is needed:
// each file is exactly what this server wrote, filed under the name of
// the other account's message.
function exchangeTheTwoBodies(blobDir, aliceRow, bobRow) {
  var alicePath = blobs.pathFor(blobDir, aliceRow.blobDigest);
  var bobPath   = blobs.pathFor(blobDir, bobRow.blobDigest);
  var aliceSealed = nodeFs.readFileSync(alicePath);
  var bobSealed   = nodeFs.readFileSync(bobPath);
  nodeFs.writeFileSync(alicePath, bobSealed);
  nodeFs.writeFileSync(bobPath, aliceSealed);
  count("the two accounts' messages are filed under different names, so exchanging " +
    "the files is a change and not a no-op",
    aliceRow.blobDigest !== bobRow.blobDigest,
    String(aliceRow.blobDigest).slice(0, 16) + " and " + String(bobRow.blobDigest).slice(0, 16));
}

async function anExchangedBodyIsNotServedOverImap(ports, caPem, bob) {
  var fetched = await imapBody(ports.imap, caPem, bob, "imap-bob-after");
  count("a body filed under another account's name does not reach the account over IMAP",
    fetched.indexOf(ALICE_MARKER) === -1, visible(fetched).slice(0, 400));
  count("and the fetch is refused rather than answered with something else",
    /^\S+ (NO|BAD)/m.test(fetched), visible(fetched).slice(0, 400));
}

async function anExchangedBodyIsNotServedOverPop3(ports, caPem, bob) {
  var retrieved = await pop3Body(ports.pop3, caPem, bob, "pop3-bob-after");
  count("nor over POP3, which reads the same bodies through a different verb",
    retrieved.indexOf(ALICE_MARKER) === -1, visible(retrieved).slice(0, 400));
  count("and POP3 refuses rather than returning the wrong message",
    /^-ERR/m.test(retrieved), visible(retrieved).slice(0, 400));
}

// A hash out of a row decides which file is opened. One that is not a
// hash decides which file ANYWHERE is opened, so the shape is checked
// before a path is built rather than after one has been read.
async function aDigestThatIsNotOneAddressesNothing(ports, caPem, bob, bobFolder, outsideFile) {
  b.db.from(mailbox.MESSAGES).where({ folder: bobFolder.folder }).updateOne({
    blobDigest: "../".repeat(8) + nodePath.basename(outsideFile),
  });

  var fetched = await imapBody(ports.imap, caPem, bob, "imap-bob-traversal");
  count("a row naming something that is not a hash is refused rather than opening a path " +
    "built out of it",
    /^\S+ (NO|BAD)/m.test(fetched), visible(fetched).slice(0, 400));
  count("and nothing from outside the message store reaches the client",
    fetched.indexOf("the operator's own note") === -1, visible(fetched).slice(0, 400));
  count("and the file outside the message store is still there afterwards",
    nodeFs.existsSync(outsideFile), outsideFile);
}

// ---- runner -------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("blob-sub");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_POP3_ENABLED:     "true",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "blob substitution run" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: PASSWORD });

    identity.mailbox.appendMessage("INBOX", messageFor(alice.address, ALICE_MARKER), {
      actor: { id: alice.id, address: alice.address, roles: ["account"] },
    });
    identity.mailbox.appendMessage("INBOX", messageFor(bob.address, BOB_MARKER), {
      actor: { id: bob.id, address: bob.address, roles: ["account"] },
    });

    var aliceFolder = folderOf(identity, alice.id);
    var bobFolder   = folderOf(identity, bob.id);
    var rows        = digestsByFolder(identity);
    var aliceRow    = rows[String(aliceFolder.folder)];
    var bobRow      = rows[String(bobFolder.folder)];
    count("both messages were stored and each folder holds one",
      aliceRow !== undefined && bobRow !== undefined,
      Object.keys(rows).join(", "));

    // A file on the volume that is not a message body, so the traversal
    // case can assert that nothing outside the message store is opened
    // and that nothing outside it is removed.
    var outsideFile = nodePath.join(dataDir, "operator-note.txt");
    nodeFs.writeFileSync(outsideFile, "the operator's own note\n", "utf8");

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: names[i] === "imap" || names[i] === "pop3",
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.mail.listeners.bound();
    var ports = { imap: bound.imap, pop3: bound.pop3 };
    count("the IMAP and POP3 listeners took their ports",
      typeof ports.imap === "number" && ports.imap > 0 &&
      typeof ports.pop3 === "number" && ports.pop3 > 0,
      ports.imap + " and " + ports.pop3);

    await eachAccountReadsItsOwnMessageFirst(ports, material.caPem, alice.address, bob.address);

    exchangeTheTwoBodies(identity.mailbox.describe().blobDir, aliceRow, bobRow);
    await anExchangedBodyIsNotServedOverImap(ports, material.caPem, bob.address);
    await anExchangedBodyIsNotServedOverPop3(ports, material.caPem, bob.address);

    await aDigestThatIsNotOneAddressesNothing(ports, material.caPem, bob.address,
      bobFolder, outsideFile);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
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

module.exports = { name: "blob-substitution", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
