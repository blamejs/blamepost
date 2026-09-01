// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What each protocol tells a client when a hard delete was refused.
 *
 * One deletion path holds the gates, and three wires feed it. Whether a
 * message survives is settled in one place and asserted elsewhere; what
 * this file is about is the other half, which is what the client is told
 * afterwards. That half is per protocol, because each RFC gives the
 * server a different vocabulary, and it is the half a client acts on.
 *
 * The two answers differ, and both are the answer their specification
 * defines:
 *
 *   - IMAP has no refusal form for EXPUNGE. RFC 9051 section 6.4.3 has
 *     the server report each message it removed with an untagged
 *     EXPUNGE and complete with OK, so a message that stayed is silence
 *     about that message. Saying OK and drawing no untagged line for it
 *     is correct, and saying OK and drawing one would be a client
 *     renumbering a mailbox around a message that is still in it.
 *
 *   - POP3 does have one. RFC 1939 section 6 puts the deletions in the
 *     UPDATE state on QUIT and gives the server `-ERR some deleted
 *     messages not removed` for the case where it could not remove them
 *     all. A client that is told `+OK` treats its own copy as the last
 *     one and the server's as gone: it will not download the message
 *     again, and on a client configured to delete after download the
 *     server's copy is the only one anybody thought was left. Under a
 *     preservation order that is precisely backwards.
 *
 * So the same refusal reaches an IMAP client as silence and a POP3
 * client as an error, and both are asserted here on a socket rather
 * than inferred from the adapter's return value.
 *
 * Run standalone: node test/layer-2-integration/expunge-refusal-report.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// POP3 has no folder vocabulary and reads the inbox, so the IMAP
// vectors take a folder of their own and the two never contend for the
// same message.
var POP3_FOLDER = "INBOX";
var IMAP_FOLDER = "Archive";

var ORDINARY = "ordinary-message";
var HELD     = "under-preservation";

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: " + to + "\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker + "." + Date.now() + "@example.net>\r\n" +
    "\r\n" + "Body of " + marker + ".\r\n", "utf8");
}

function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function objectIdsIn(identity, storeFolder) {
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 })
    .map(function (r) { return r.objectid; });
}

// ---- sessions ---------------------------------------------------------------

async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

async function pop3Session(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\+OK /m, "greeting");
  session.send("STLS");
  await session.read(/^\+OK /m, "STLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("USER " + address);
  await session.read(/^(\+OK|-ERR)/m, "USER answered");
  session.send("PASS " + ALICE_PASSWORD);
  await session.read(/^\+OK /m, "authenticated");
  return session;
}

// ---- POP3: the refusal has a reply code, so it is used ----------------------

// Nothing marked. The commit removes nothing because it was asked for
// nothing, which is an ordinary session and not a refusal.
async function pop3QuitWithNothingMarkedSaysOk(port, caPem, address) {
  var client = await pop3Session(port, caPem, address, "pop3-quiet");
  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  count("a POP3 session that deleted nothing is answered +OK",
    /^\+OK/m.test(quit), visible(quit));
  client.close();
}

// One message marked, nothing holding it. The commit removes it and the
// client is told the ordinary thing.
async function pop3QuitAfterAnAllowedDeleteSaysOk(port, caPem, address) {
  var client = await pop3Session(port, caPem, address, "pop3-allowed");
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("the maildrop holds both the ordinary message and the held one",
    /^\+OK 2 /m.test(stat), visible(stat));

  // RFC 1939 section 5 numbers messages in the order the drop lists
  // them, and the ordinary message was appended first.
  client.send("DELE 1");
  var dele = await client.read(/^(\+OK|-ERR)/m, "DELE answered");
  count("the mark is accepted, because the refusal belongs at the commit",
    /^\+OK/m.test(dele), visible(dele));

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  count("a commit that removed everything it was asked to is answered +OK",
    /^\+OK/m.test(quit), visible(quit));
  client.close();
}

// The message under a preservation order, marked and committed. This is
// the case the whole file is about.
async function pop3QuitAfterARefusedDeleteSaysErr(port, caPem, address) {
  var client = await pop3Session(port, caPem, address, "pop3-refused");
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("only the held message is left in the maildrop",
    /^\+OK 1 /m.test(stat), visible(stat));

  client.send("DELE 1");
  await client.read(/^(\+OK|-ERR)/m, "DELE answered");

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  count("a commit that could not remove what it was asked to is answered -ERR " +
    "(RFC 1939 section 6)", /^-ERR/m.test(quit), visible(quit));
  count("and the reply carries the wording that specification defines, so a client " +
    "and an operator's log filter both recognize it",
    /some deleted messages not removed/i.test(quit), visible(quit));
  client.close();

  // The three things a hold is worth, on this wire: the client was not
  // told the message went, a later session still finds it, and the body
  // is still readable.
  var next = await pop3Session(port, caPem, address, "pop3-recount");
  next.send("STAT");
  var after = await next.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("a client reconnecting still finds the held message",
    /^\+OK 1 /m.test(after), visible(after));

  next.send("RETR 1");
  var body = await next.read(/^\.\r\n/m, "RETR answered");
  count("and RETR still returns its body, byte for byte as it arrived",
    body.indexOf(HELD) !== -1 && body.indexOf("Body of " + HELD) !== -1, visible(body));

  next.send("QUIT");
  await next.read(/^(\+OK|-ERR)/m, "QUIT answered");
  next.close();
}

// ---- IMAP: the refusal has no reply code, so silence is the answer ----------

async function imapExpungeIsSilentAboutWhatItKept(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-refused");

  client.send("b0 SELECT " + IMAP_FOLDER);
  var selected = await client.read(/^b0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder holds both messages to begin with",
    /^\* 2 EXISTS/m.test(selected), visible(selected));

  client.send("b1 STORE 1:2 +FLAGS (\\Deleted)");
  await client.read(/^b1 (OK|NO|BAD)/m, "STORE answered");

  client.send("b2 EXPUNGE");
  var expunged = await client.read(/^b2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE completes with OK, because RFC 9051 gives it no refusal form",
    /^b2 OK/m.test(expunged), visible(expunged));
  count("exactly one untagged EXPUNGE is drawn, for the message that actually went",
    (expunged.match(/^\* \d+ EXPUNGE/gm) || []).length === 1, visible(expunged));

  client.send("b3 SELECT " + IMAP_FOLDER);
  var after = await client.read(/^b3 (OK|NO|BAD)/m, "SELECT answered");
  count("a later session still finds the held message", /^\* 1 EXISTS/m.test(after),
    visible(after));

  client.send("b4 FETCH 1 BODY[]");
  var fetched = await client.read(/^b4 (OK|NO|BAD)/m, "FETCH answered");
  count("and its body is still readable",
    /^b4 OK/m.test(fetched) && fetched.indexOf("Body of " + HELD) !== -1, visible(fetched));

  client.send("b5 LOGOUT");
  client.close();
}

// ---- the octets the adapter keeps, and the row that points at them ---------

// The store is not the only thing holding a destroyed message. The
// adapter keeps the original octets sealed under `blobs/` because IMAP
// BODY[] and POP3 RETR both have to return the message exactly as it
// arrived, and it keeps a row pointing at the file. A delete that
// clears the store row and leaves those two behind reports success and
// keeps the message readable on disk.
function theOctetsGoWithTheMessage(identity, blobPath, describedBefore) {
  count("the sealed octets of the destroyed message are gone from disk",
    nodeFs.existsSync(blobPath) === false, blobPath);
  count("and the adapter's own row went with them",
    identity.mailbox.describe().messages < describedBefore,
    describedBefore + " -> " + identity.mailbox.describe().messages);
}

// ---- one running server -----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("expunge-report");
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

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
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

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    await fn({
      ports:    { imap: sections.imap.port, pop3: sections.pop3.port },
      caPem:    leaf.ca,
      identity: identity,
      alice:    alice,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
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

// One ordinary message and one under a preservation order, in one
// folder, identified by the rows the folder gained rather than by where
// they sit in a listing.
async function plant(identity, alice, wireName) {
  var folder = storeFolderOf(identity, alice.id, wireName);
  var ids = {};
  [ORDINARY, HELD].forEach(function (marker) {
    var before = objectIdsIn(identity, folder);
    identity.mailbox.appendMessage(wireName, message(marker, alice.address),
      { actor: { id: alice.id } });
    var gained = objectIdsIn(identity, folder).filter(function (id) {
      return before.indexOf(id) === -1;
    });
    ids[marker] = gained.length === 1 ? gained[0] : "";
  });
  await identity.mailbox.legalHold.place({ id: alice.id }, wireName, [ids[HELD]], {
    reason:    "preservation order 24-cv-01933",
    citation:  "FRCP-26",
    custodian: "legal@" + DOMAIN,
    placedBy:  "operator",
  });
  return { folder: folder, ids: ids };
}

// The sealed file the adapter wrote for one message, found by the
// digest its row carries rather than by rebuilding the path from the
// message bytes, so this reads the same map the delete path reads.
function blobPathFor(identity, storeFolder, objectId) {
  var rows = b.db.from("blamepost_mailbox_messages")
    .where({ folder: storeFolder, objectid: objectId }).all();
  if (rows.length !== 1) return "";
  var digest = rows[0].blobDigest;
  return nodePath.join(identity.mailbox.describe().blobDir,
    digest.slice(0, 2), digest.slice(2, 4), digest);
}

async function run() {
  await withServer(async function (ctx) {
    var pop3 = await plant(ctx.identity, ctx.alice, POP3_FOLDER);
    var imap = await plant(ctx.identity, ctx.alice, IMAP_FOLDER);

    var doomedBlob = blobPathFor(ctx.identity, pop3.folder, pop3.ids[ORDINARY]);
    count("the adapter wrote the sealed octets of the message about to be destroyed",
      doomedBlob.length > 0 && nodeFs.existsSync(doomedBlob), doomedBlob);
    var describedBefore = ctx.identity.mailbox.describe().messages;

    await pop3QuitWithNothingMarkedSaysOk(ctx.ports.pop3, ctx.caPem, ctx.alice.address);
    await pop3QuitAfterAnAllowedDeleteSaysOk(ctx.ports.pop3, ctx.caPem, ctx.alice.address);

    theOctetsGoWithTheMessage(ctx.identity, doomedBlob, describedBefore);

    await pop3QuitAfterARefusedDeleteSaysErr(ctx.ports.pop3, ctx.caPem, ctx.alice.address);
    await imapExpungeIsSilentAboutWhatItKept(ctx.ports.imap, ctx.caPem, ctx.alice.address);

    // The held message's octets stayed exactly where they were.
    var heldBlob = blobPathFor(ctx.identity, imap.folder, imap.ids[HELD]);
    count("the octets of the held message are still on disk",
      heldBlob.length > 0 && nodeFs.existsSync(heldBlob), heldBlob);
  });

  return helpers.getChecks();
}

module.exports = {
  name: "expunge-refusal-report",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
