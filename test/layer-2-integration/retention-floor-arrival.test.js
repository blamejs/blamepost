// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The retention floor measures an arrival time. This asks whose clock
 * that time came from.
 *
 * A floor decides whether a message is old enough to destroy by
 * subtracting its arrival from now. If the value it subtracts is one the
 * client chose, the floor is decoration: a client dates a message a
 * decade into the past, asks for it to be destroyed, and the window an
 * operator configured is walked straight through with an ordinary
 * protocol command.
 *
 * RFC 9051 section 6.3.12 gives the client that opportunity in as many
 * words. An IMAP APPEND takes an optional date-time argument, this
 * server's listener parses it, and the appended message answers
 * INTERNALDATE with it afterwards. RFC 5322 section 3.3 gives a second:
 * the message's own Date header, which is a header like any other and is
 * written by whoever composed the message.
 *
 * So every message here arrives over a real IMAP APPEND carrying a
 * date-time of 01-Jan-2015 and a Date header naming the same instant,
 * and every one of them is then asked for on a protocol that destroys.
 * IMAP EXPUNGE, POP3 DELE and JMAP `Email/set` `destroyed` all end at
 * the same hard delete, and a rule shared by three wire protocols is
 * only as strong as the one it is weakest on, so each drives its own
 * message in its own folder.
 *
 * Two refusals are told apart rather than counted together. A message
 * inside the window is refused as `retention-floor`. A message whose
 * arrival the server cannot establish at all is refused as
 * `retention-floor-unknown-arrival`, which is a different fact: an age
 * computed from an absent value reads as the epoch, makes every message
 * look five decades old, and clears every window an operator can set. A
 * case asserting only that the delete did not happen passes for either
 * reason and for a third the day something upstream breaks differently.
 *
 * What is asserted about the arrival stamps themselves is the sentinel.
 * The framework's mail store stamps `receivedAt` and `internalDate` from
 * its own clock today and carries a note that RFC 5322 date-time parsing
 * into those two fields is still to be wired. On the day it is, the
 * value the floor subtracts becomes a value the sender wrote, and no
 * static gate here would see the change: the wiring in this repository
 * would not move a line. The counts below read both fields off the row
 * the floor reads and require each to sit beside this server's own clock
 * rather than beside the client's claim.
 *
 * Run standalone: node test/layer-2-integration/retention-floor-arrival.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// A year, which is what the posture below puts between a message and the
// earliest moment it may be destroyed. Every message here is minutes old
// by this server's clock and eleven years old by its own account, so the
// two readings fall on opposite sides of the window and a count cannot
// pass by accident.
var POSTURE = "soc2";

// The date a client picks, in the two spellings a client can pick it in:
// the IMAP APPEND date-time of RFC 9051 section 6.3.12, and the RFC 5322
// section 3.3 Date header the message carries.
var CLAIMED_DATE_TIME = "01-Jan-2015 00:00:00 +0000";
var CLAIMED_HEADER    = "Thu, 01 Jan 2015 00:00:00 +0000";
var CLAIMED_MS        = Date.UTC(2015, 0, 1, 0, 0, 0);

// How far this server's own stamp may sit from the moment the APPEND was
// made and still be this server's own stamp. Wide enough that a loaded
// runner does not fail the run, and eleven years narrower than the
// distance to the value under suspicion.
var STAMP_WINDOW_MS = 300000;

// One folder per protocol, so a delete driven on one wire cannot carry a
// message another wire is about to ask for. POP3 has no folder
// vocabulary and reads the inbox, so it takes INBOX.
var POP3_FOLDER    = "INBOX";
var IMAP_FOLDER    = "Archive";
var JMAP_FOLDER    = "Junk";
var ARRIVAL_FOLDER = "Drafts";

// Distinctive enough that finding one in a fetch, a listing or a JMAP
// answer is proof that message is still there rather than a coincidence
// of ordinary words.
var MARKER = "dated-by-its-client";

// The message a client composes when it wants the server to believe the
// mail is old. Both channels say the same thing, because a server that
// read only one of them would still be reading the client.
function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: " + CLAIMED_HEADER + "\r\n" +
    "Message-Id: <" + marker.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + marker + ".\r\n", "utf8");
}

function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function objectIdsIn(identity, storeFolder) {
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 })
    .map(function (row) { return row.objectid; });
}

// ---- the arrival, driven on the wire ---------------------------------------

// One APPEND carrying the client's date-time, and the identity the store
// gave the message it filed.
//
// The message is named by the row the folder gained rather than by
// position in a listing. Position is a property of the store's own
// counters and a hard delete rewrites one of them, so a case that names
// a message by where it sits can end up holding a different message than
// the one it placed.
async function appendOverTheWire(session, identity, accountId, wireName) {
  var folder = storeFolderOf(identity, accountId, wireName);
  var before = objectIdsIn(identity, folder);
  var placedAt = Date.now();

  var tag = session.tag();
  await session.sendLiteral(
    tag + ' APPEND "' + wireName + '" "' + CLAIMED_DATE_TIME + '"',
    message(MARKER, "alice@" + DOMAIN), "<the message>");
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "APPEND answered");
  count("the listener accepts an APPEND carrying the date-time RFC 9051 section 6.3.12 " +
    "defines, into " + wireName,
  new RegExp("^" + tag + " OK", "m").test(reply), visible(reply));

  var gained = objectIdsIn(identity, folder).filter(function (id) {
    return before.indexOf(id) === -1;
  });
  count("and exactly one message landed in " + wireName, gained.length === 1,
    JSON.stringify(gained));
  return { folder: folder, wireName: wireName, objectId: gained[0], placedAt: placedAt };
}

// ---- what the claim reached, and what it did not ---------------------------

// The claim has to have LANDED somewhere for the counts below it to mean
// anything. A server that parsed the date-time and threw it away would
// refuse every delete here for a reason that has nothing to do with the
// floor, and the file would still say the words it was written to say.
async function theClientsClaimIsAnsweredBackOnTheWire(session, wireName) {
  var selectTag = session.tag();
  session.send(selectTag + " SELECT " + wireName);
  var selected = await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  count("the folder the message was appended to holds it",
    /^\* 1 EXISTS/m.test(selected), visible(selected).slice(0, 200));

  var fetchTag = session.tag();
  session.send(fetchTag + " FETCH 1 (INTERNALDATE)");
  var fetched = await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH answered");
  count("and INTERNALDATE answers the date the client asked for, so the date-time " +
    "argument is carried rather than discarded",
  fetched.indexOf(CLAIMED_DATE_TIME) !== -1, visible(fetched));
}

// The two values this server keeps beside each other, and the distance
// between them. One is what the client said; the other is when the
// message actually arrived here.
function theTwoDatesAreKeptApart(placed) {
  var row = b.db.from(mailbox.MESSAGES).where({ objectid: placed.objectId }).first();
  count("the row this server keeps holds the client's date, which is what INTERNALDATE " +
    "is answered from",
  row !== null && row.internalDate === CLAIMED_MS,
  JSON.stringify(row === null ? null : { internalDate: row.internalDate, claimed: CLAIMED_MS }));
  count("and beside it this server's own clock at the moment the message was filed, so " +
    "the two are separate values rather than one field doing both jobs",
  row !== null && typeof row.createdAt === "number" &&
    Math.abs(row.createdAt - placed.placedAt) < STAMP_WINDOW_MS,
  JSON.stringify(row === null ? null : { createdAt: row.createdAt, placedAt: placed.placedAt }));
  count("the two are more than a decade apart, so a count that reads one of them cannot " +
    "pass by reading the other",
  row !== null && row.createdAt - row.internalDate > STAMP_WINDOW_MS,
  JSON.stringify(row === null ? null : { createdAt: row.createdAt, internalDate: row.internalDate }));
}

// The row the retention floor actually reads. `receivedAt` is what it
// subtracts, and `internalDate` on the same row is what it falls back to
// when the first is not a usable number, so both are asked about: a
// change that put the sender's date in either one would put it in front
// of the floor.
function theFloorReadsThisServersClock(identity, placed) {
  var meta = identity.messageStore.fetchByObjectId(placed.folder, placed.objectId);
  count("the message store still holds the row the floor decides from",
    meta !== null, placed.objectId);
  if (meta === null) return;

  count("the arrival the floor subtracts is this server's own clock at the moment the " +
    "message was filed",
  typeof meta.receivedAt === "number" &&
    Math.abs(meta.receivedAt - placed.placedAt) < STAMP_WINDOW_MS,
  JSON.stringify({ receivedAt: meta.receivedAt, placedAt: placed.placedAt }));
  count("and it is not the date the client put on the APPEND",
    meta.receivedAt !== CLAIMED_MS,
    JSON.stringify({ receivedAt: meta.receivedAt, claimed: CLAIMED_MS }));

  count("the value the floor falls back to when the first is unusable is this server's " +
    "clock as well, so the fallback is not a second way in",
  typeof meta.internalDate === "number" &&
    Math.abs(meta.internalDate - placed.placedAt) < STAMP_WINDOW_MS,
  JSON.stringify({ internalDate: meta.internalDate, placedAt: placed.placedAt }));
  count("and that one is not the client's date either, which is the count that moves if " +
    "the message's own Date header is ever parsed into these fields",
  meta.internalDate !== CLAIMED_MS,
  JSON.stringify({ internalDate: meta.internalDate, claimed: CLAIMED_MS }));
}

// ---- the three wires that destroy ------------------------------------------

// IMAP carries no per-message reason on an EXPUNGE, so the wire is asked
// what the wire can answer and the reason is read off the trail the
// delete writes. RFC 9051 section 6.4.3: a message that was not removed
// draws no untagged EXPUNGE, so telling the client it went and keeping
// it is a failure in one direction and keeping it silently is a failure
// in the other.
async function imapExpungeIsRefused(session, audit, identity, placed) {
  var selectTag = session.tag();
  session.send(selectTag + " SELECT " + placed.wireName);
  var selected = await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  count("the folder holds the client-dated message before the delete",
    /^\* 1 EXISTS/m.test(selected), visible(selected).slice(0, 200));

  var storeTag = session.tag();
  session.send(storeTag + " STORE 1 +FLAGS (\\Deleted)");
  await session.read(new RegExp("^" + storeTag + " (OK|NO|BAD)", "m"), "STORE answered");

  var expungeTag = session.tag();
  session.send(expungeTag + " EXPUNGE");
  var expunged = await session.read(new RegExp("^" + expungeTag + " (OK|NO|BAD)", "m"),
    "EXPUNGE answered");
  count("EXPUNGE completes rather than erroring",
    new RegExp("^" + expungeTag + " OK", "m").test(expunged), visible(expunged));
  count("the client is NOT told a message it dated into the past was removed",
    !/^\* \d+ EXPUNGE/m.test(expunged), visible(expunged));

  var afterTag = session.tag();
  session.send(afterTag + " SELECT " + placed.wireName);
  var after = await session.read(new RegExp("^" + afterTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  count("and the message is still in the folder afterwards",
    /^\* 1 EXISTS/m.test(after), visible(after).slice(0, 200));

  var fetchTag = session.tag();
  session.send(fetchTag + " FETCH 1 BODY[]");
  var fetched = await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH answered");
  count("the message the floor kept is still readable, so it was kept rather than left " +
    "as a row whose octets went",
  fetched.indexOf(MARKER) !== -1, visible(fetched).slice(0, 200));

  count("the store agrees the message is still there",
    objectIdsIn(identity, placed.folder).indexOf(placed.objectId) !== -1, placed.objectId);

  // The reason, from the record the delete writes. IMAP has no field for
  // it, and an operator asking why a client's delete did nothing reads
  // this.
  await helpers.waitUntil(function () {
    return audit.forAction("mail.agent.expunge.success").length > 0;
  }, {
    timeoutMs: 5000,
    label:     "retention-floor-arrival: the trail the refused IMAP delete writes",
  });
  var rows = audit.forAction("mail.agent.expunge.success");
  var reasons = rows.map(function (row) {
    return helpers.metadataOf(row).refusedReasons || {};
  });
  count("the trail names the retention floor as what refused the IMAP delete",
    reasons.some(function (r) { return r["retention-floor"] >= 1; }),
    JSON.stringify(reasons));
  count("and it names nothing else, so the refusal is the floor rather than a message " +
    "the delete could not find",
  reasons.every(function (r) {
    return Object.keys(r).every(function (name) { return name === "retention-floor"; });
  }),
  JSON.stringify(reasons));
}

// JMAP answers per message with a SetError, so the reason is on the wire.
async function jmapDestroyIsRefused(reader, accountId, placed) {
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, destroy: [placed.objectId] }, "c0"],
  ]);
  count("JMAP answers Email/set for the signed in account", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 160));
  var result = browser.answer(answer)[1];

  count("no client-dated message is reported destroyed",
    Array.isArray(result.destroyed) && result.destroyed.length === 0,
    JSON.stringify(result.destroyed));
  var refusal = result.notDestroyed && result.notDestroyed[placed.objectId];
  count("the client is told the destroy was refused rather than answered as a success",
    refusal !== undefined && refusal !== null, JSON.stringify(result.notDestroyed));
  count("the refusal carries the SetError type JMAP defines for it",
    refusal && refusal.type === "forbidden", JSON.stringify(refusal));
  count("and it names the retention floor rather than the client's own date",
    refusal && refusal.description === "retention-floor", JSON.stringify(refusal));

  var still = await reader.jmap([
    ["Email/get", { accountId: accountId, ids: [placed.objectId], properties: ["subject"] }, "c0"],
  ]);
  var got = browser.answer(still)[1];
  count("the message the floor kept is still readable over JMAP",
    got.list.length === 1, JSON.stringify(got.notFound));
}

// POP3 commits at QUIT, and RFC 1939 section 6 gives the UPDATE state a
// reply for a commit that could not remove everything it was asked for.
// A client set to delete after download treats +OK as "the server's copy
// is gone", so answering +OK over a message that is still here is the
// wrong way round.
async function pop3DeleteIsRefused(port, caPem, address, identity, placed) {
  var client = await Wire.pop3(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: ALICE_PASSWORD,
    label: "pop3-arrival",
  });

  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("the maildrop holds the client-dated message before the delete",
    wire.pop3Stat(stat).messages === 1, visible(stat));

  client.send("DELE 1");
  var marked = await client.read(/^(\+OK|-ERR)/m, "DELE answered");
  count("the mark is accepted, because the refusal belongs at the commit",
    /^\+OK/m.test(marked), visible(marked));

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  count("QUIT reports that the message was kept rather than answering the client with a " +
    "success it would act on by deleting its own copy",
  /^-ERR/m.test(quit), visible(quit));
  count("and it names the retention floor as the reason",
    /retention-floor/.test(quit), visible(quit));
  client.close();

  var again = await Wire.pop3(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: ALICE_PASSWORD,
    label: "pop3-arrival-recount",
  });
  again.send("STAT");
  var recount = await again.read(/^\+OK \d+ \d+/m, "STAT answered");
  again.send("QUIT");
  await again.read(/^(\+OK|-ERR)/m, "QUIT answered");
  again.close();
  count("a client reconnecting still finds the message",
    wire.pop3Stat(recount).messages === 1, visible(recount));
  count("and the store agrees it is still there",
    objectIdsIn(identity, placed.folder).indexOf(placed.objectId) !== -1, placed.objectId);
}

// ---- an arrival this server never observed ---------------------------------

// The message store this server runs stamps every row it writes, so a
// row carrying no arrival at all is not a state a client can produce
// here. It is a state the framework's own refusal is written for, and
// the only way to ask whether that refusal still holds is to put the
// shipped delete path over a substrate whose rows answer the way an
// unstamped row would.
//
// One field is replaced and nothing else: the same folders, the same
// rows, the same destructive call underneath. What changes is the one
// question the floor asks, which is when the message got here.
function arrivalBlindSubstrate(real) {
  var proxy = Object.create(null);
  Object.keys(real).forEach(function (name) {
    proxy[name] = typeof real[name] === "function" ? real[name].bind(real) : real[name];
  });
  proxy.fetchByObjectId = function (folderName, objectid) {
    var row = real.fetchByObjectId(folderName, objectid);
    if (row === null) return null;
    var copy = Object.assign({}, row);
    delete copy.receivedAt;
    delete copy.internalDate;
    return copy;
  };
  return proxy;
}

// The two refusals, told apart on one message.
//
// Both are the floor keeping mail, and an operator reading a report needs
// to know which one happened: a message inside the window comes out the
// other side of it, and a message whose arrival nothing can establish
// never does. Asserting only that neither was destroyed would pass for
// either, and would pass for the day the unknown case starts reading as
// the epoch and clearing every window there is.
async function anArrivalNobodyObservedIsRefusedByName(identity, cfg, actor, placed) {
  var ordinary = await identity.mailbox.expungeObjects(
    actor, placed.wireName, [placed.objectId]);
  count("a message inside the window is refused, and the reason names the window",
    ordinary.deleted.length === 0 && ordinary.refused.length === 1 &&
    ordinary.refused[0].reason === "retention-floor",
    JSON.stringify(ordinary));

  var blind = mailbox.create({
    store:   arrivalBlindSubstrate(identity.messageStore),
    dataDir: cfg.paths.dataDir,
    posture: POSTURE,
  });
  var unknown = await blind.expungeObjects(actor, placed.wireName, [placed.objectId]);
  count("a message whose arrival this server cannot establish is refused as well",
    unknown.deleted.length === 0 && unknown.refused.length === 1,
    JSON.stringify(unknown));
  count("and it is refused under its own name rather than under the window's, because an " +
    "age computed from nothing reads as the epoch and clears every window an operator " +
    "can set",
  unknown.refused.length === 1 &&
    unknown.refused[0].reason === "retention-floor-unknown-arrival",
  JSON.stringify(unknown.refused));
  count("the two refusals are different words, so a report can tell a message inside the " +
    "window from one nothing can date",
  ordinary.refused[0].reason !== unknown.refused[0].reason,
  ordinary.refused[0].reason + " / " + unknown.refused[0].reason);

  count("the message survived both, row and octets",
    objectIdsIn(identity, placed.folder).indexOf(placed.objectId) !== -1 &&
    b.db.from(mailbox.MESSAGES).where({ objectid: placed.objectId }).count() === 1,
    placed.objectId);
}

// ---- one running server ----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("floor-arrival");
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
  var audit    = null;

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
        BLAMEPOST_HOSTNAME:           HOSTNAME,
        BLAMEPOST_DATA_DIR:           dataDir,
        BLAMEPOST_VAULT_PASSPHRASE:   VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED:   "1",
        BLAMEPOST_COMPLIANCE_POSTURE: POSTURE,
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

    audit = helpers.auditCapture();

    await fn({
      cfg:      cfg,
      ports:    { imap: sections.imap.port, pop3: sections.pop3.port },
      httpPort: server.web.describe().bound.http,
      caPem:    leaf.ca,
      identity: identity,
      alice:    alice,
      audit:    audit,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // The audit store is process-wide, so it is handed back whatever the
    // verdict was.
    if (audit) {
      try { audit.release(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // `server.stop` leaves the store alone: it belongs to whoever opened
    // it. The database handle behind it is one per process, so a second
    // server opened before this one closes would find the first
    // server's rows under its own temporary directory.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    var address = "alice@" + DOMAIN;
    var actor   = { id: ctx.alice.id, roles: ["account"] };

    count("the posture under test names a floor, so the message really is inside a window",
      b.retention.complianceFloor(POSTURE) > 0,
      String(b.retention.complianceFloor(POSTURE)));
    count("and the window is longer than the distance between this server's clock and the " +
      "date the client claimed, so the claim would clear it if the floor read it",
    Date.now() - CLAIMED_MS > b.retention.complianceFloor(POSTURE),
    String(Date.now() - CLAIMED_MS) + " vs " + String(b.retention.complianceFloor(POSTURE)));

    // Every message arrives the same way: a real APPEND over a real
    // listener, carrying the client's date-time.
    var session = await Wire.imap(ctx.ports.imap, {
      caPem: ctx.caPem, servername: HOSTNAME,
      address: address, password: ALICE_PASSWORD, label: "imap-arrival",
    });

    var forImap = await appendOverTheWire(session, ctx.identity, ctx.alice.id, IMAP_FOLDER);
    var forJmap = await appendOverTheWire(session, ctx.identity, ctx.alice.id, JMAP_FOLDER);
    var forPop3 = await appendOverTheWire(session, ctx.identity, ctx.alice.id, POP3_FOLDER);
    var forBlind = await appendOverTheWire(
      session, ctx.identity, ctx.alice.id, ARRIVAL_FOLDER);

    await theClientsClaimIsAnsweredBackOnTheWire(session, IMAP_FOLDER);
    theTwoDatesAreKeptApart(forImap);
    theFloorReadsThisServersClock(ctx.identity, forImap);
    await imapExpungeIsRefused(session, ctx.audit, ctx.identity, forImap);
    session.send(session.tag() + " LOGOUT");
    session.close();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await reader.signIn(address, ALICE_PASSWORD);
    count("the account can sign in to the browser surface", landed.status === 302,
      landed.status + " " + String(landed.body).slice(0, 120));
    await jmapDestroyIsRefused(reader, ctx.alice.id, forJmap);

    await pop3DeleteIsRefused(ctx.ports.pop3, ctx.caPem, address, ctx.identity, forPop3);

    await anArrivalNobodyObservedIsRefusedByName(ctx.identity, ctx.cfg, actor, forBlind);
  });

  return helpers.getChecks();
}

module.exports = { name: "retention-floor-arrival", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
