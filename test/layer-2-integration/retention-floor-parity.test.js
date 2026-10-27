// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One retention floor, six ways to ask for a hard delete.
 *
 * An operator who sets a compliance posture is promised one thing: a
 * message younger than the floor does not go, for the account owner as
 * much as for an administrator. That promise is only worth the wire it
 * is weakest on. IMAP EXPUNGE, IMAP CLOSE, POP3 QUIT, JMAP `Email/set`
 * `destroyed` and the webmail purge button all end at the same hard
 * delete, so all five are driven here, on real listeners, by clients
 * speaking the protocol rather than by a call into the adapter.
 *
 * The sixth is UID EXPUNGE, and it is here because a command that
 * removes nothing today is one release away from removing something.
 * RFC 9051 section 6.4.9 gives it its own arguments and its own subset
 * rule, so serving it means a second route into the store rather than a
 * spelling of the first, and the vector that would notice is one that
 * already runs. What it pins now is that the command is refused and the
 * messages stay, in both configurations.
 *
 * Both directions are asserted, because either one alone is a test that
 * passes for the wrong reason. Under a posture the message stays and
 * the client is told why in the shape its protocol defines. With no
 * posture, which is what most operators run, the same delete goes
 * through: a floor that refuses everything is not a floor, it is a
 * server that cannot delete mail.
 *
 * The legal hold vectors run on the server with no posture set, which
 * is the configuration where the hold is the only thing between the
 * message and the disk. On the server that has a posture the floor
 * would refuse first and a hold vector could not tell the two gates
 * apart, so what is asserted there instead is that the reason a held
 * message comes back with is the hold rather than the floor.
 *
 * Messages are put in place through the adapter's `appendMessage`,
 * which is the same call inbound delivery makes once a message has been
 * accepted. What is under test is the delete, so the arrival is set up
 * rather than driven.
 *
 * Run standalone: node test/layer-2-integration/retention-floor-parity.test.js
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

// One folder per way of deleting. POP3 has no folder vocabulary and
// reads the inbox, so it takes INBOX and the other four take one each,
// which keeps a delete driven on one wire from carrying a message
// another wire is about to ask for.
var POP3_FOLDER       = "INBOX";
var IMAP_FOLDER       = "Archive";
var IMAP_CLOSE_FOLDER = "Drafts";
var IMAP_UID_FOLDER   = "Sent";
var JMAP_FOLDER       = "Junk";
var WEB_FOLDER        = "Trash";

// Distinctive enough that finding one in a page, a fetch or a listing
// is proof that message is still there rather than a coincidence of
// ordinary words.
var ORDINARY = "ordinary";
var HELD     = "under-preservation";

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
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

// ---- a browser's view of the HTTP surface ----------------------------------

// The session cookie and the CSRF cookie are both set by the server and
// both have to come back on the next request, so this holds a jar the
// way a browser does. The CSRF token is re-read from every page that
// carries one, because a page rendered after the session changed is the
// page whose token is current.
function cookieJar() {
  var held = Object.create(null);
  return {
    absorb: function (res) {
      var list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
      for (var i = 0; i < list.length; i += 1) {
        var pair = list[i].split(";")[0];
        var eq = pair.indexOf("=");
        if (eq === -1) continue;
        held[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    },
    header: function () {
      return Object.keys(held).map(function (name) { return name + "=" + held[name]; }).join("; ");
    },
  };
}

function browser(origin) {
  var jar = cookieJar();
  var csrf = "";

  function absorbToken(body) {
    var found = /name="_csrf" value="([^"]*)"/.exec(body);
    if (found !== null) csrf = found[1];
  }

  async function get(path) {
    var res = await fetch(origin + path, {
      redirect: "manual",
      headers:  { "Cookie": jar.header() },
    });
    jar.absorb(res);
    var body = await res.text();
    absorbToken(body);
    return { status: res.status, body: body, location: res.headers.get("location") };
  }

  async function post(path, contentType, payload) {
    var res = await fetch(origin + path, {
      method:   "POST",
      redirect: "manual",
      headers: {
        "Content-Type": contentType,
        "Origin":       origin,
        "Cookie":       jar.header(),
        "X-CSRF-Token": csrf,
      },
      body: payload,
    });
    jar.absorb(res);
    var body = await res.text();
    return { status: res.status, body: body, location: res.headers.get("location") };
  }

  return {
    get:  get,
    post: post,
    signIn: async function (address, password) {
      await get("/sign-in");
      return post("/sign-in", "application/x-www-form-urlencoded",
        "address=" + encodeURIComponent(address) +
        "&password=" + encodeURIComponent(password) +
        "&_csrf=" + encodeURIComponent(csrf));
    },
    jmap: function (methodCalls) {
      return post("/jmap/api", "application/json", JSON.stringify({
        using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        methodCalls: methodCalls,
      }));
    },
  };
}

function emailSetResponse(raw) {
  return JSON.parse(raw).methodResponses[0][1];
}

// ---- protocol sessions -----------------------------------------------------

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

// How many messages the maildrop holds, read from a session of its own
// so the count is what a client reconnecting would see rather than what
// the session that did the deleting still remembers.
async function pop3Count(port, caPem, address, label) {
  var session = await pop3Session(port, caPem, address, label);
  session.send("STAT");
  var stat = await session.read(/^\+OK \d+ \d+/m, "STAT answered");
  session.send("QUIT");
  await session.read(/^\+OK /m, "QUIT answered");
  session.close();
  var found = /^\+OK (\d+) /m.exec(stat);
  return found === null ? -1 : parseInt(found[1], 10);
}

// ---- vectors under a compliance posture ------------------------------------

async function jmapRefusesADestroyInsideTheFloor(session, accountId, ids) {
  var answer = await session.jmap([
    ["Email/set", { accountId: accountId, destroy: ids }, "c0"],
  ]);
  count("JMAP answers Email/set for a signed in account", answer.status === 200, answer.status);
  var result = emailSetResponse(answer.body);
  count("no message inside the floor is reported destroyed",
    Array.isArray(result.destroyed) && result.destroyed.length === 0,
    JSON.stringify(result.destroyed));
  count("the client is told the destroy was refused rather than answered as a success",
    Object.keys(result.notDestroyed).length === ids.length,
    JSON.stringify(Object.keys(result.notDestroyed)));
  var refusal = result.notDestroyed[ids[0]];
  count("the refusal carries the SetError type JMAP defines for it",
    refusal && refusal.type === "forbidden", JSON.stringify(refusal));
  count("and it names the retention floor as the reason",
    refusal && refusal.description === "retention-floor", JSON.stringify(refusal));

  var still = await session.jmap([
    ["Email/get", { accountId: accountId, ids: [ids[0]], properties: ["subject"] }, "c0"],
  ]);
  var got = JSON.parse(still.body).methodResponses[0][1];
  count("the message the floor kept is still readable over JMAP",
    got.list.length === 1, JSON.stringify(got.notFound));
}

async function theWebPurgeButtonIsRefusedInsideTheFloor(session, identity, entry) {
  var base = "/mail?folder=" + encodeURIComponent(WEB_FOLDER);
  var purge = await session.post("/mail/actions?folder=" + encodeURIComponent(WEB_FOLDER),
    "application/x-www-form-urlencoded",
    "action=purge&objectId=" + encodeURIComponent(entry.ordinaryId));
  count("the purge button redirects rather than erroring", purge.status === 302,
    purge.status + " " + purge.body.slice(0, 120));
  count("and the reader is told messages were kept",
    String(purge.location).indexOf("notice=purge-refused") !== -1, purge.location);

  // The store's own view, because a page and a store can agree about a
  // message both of them have lost track of, and the store is the one
  // that decides whether the mail still exists.
  var left = objectIdsIn(identity, entry.folder);
  count("the store still holds the message the floor kept",
    left.length === 1 && left[0] === entry.ordinaryId, JSON.stringify(left));

  var page = await session.get(base);
  count("the folder still lists it to the reader who tried to purge it",
    page.body.indexOf(ORDINARY) !== -1, page.status);
}

async function imapExpungeIsRefusedInsideTheFloor(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-floor");

  client.send("b0 SELECT " + IMAP_FOLDER);
  var selected = await client.read(/^b0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder holds the message to begin with",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("b1 STORE 1 +FLAGS (\\Deleted)");
  await client.read(/^b1 (OK|NO|BAD)/m, "STORE answered");

  client.send("b2 EXPUNGE");
  var expunged = await client.read(/^b2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE completes rather than erroring", /^b2 OK/m.test(expunged), visible(expunged));
  // RFC 9051: a message that was not removed draws no untagged EXPUNGE.
  // Telling the client it went and keeping it is the failure this is
  // asserting against, and so is the reverse.
  count("the client is NOT told a message inside the floor was removed",
    !/^\* \d+ EXPUNGE/m.test(expunged), visible(expunged));

  client.send("b3 SELECT " + IMAP_FOLDER);
  var after = await client.read(/^b3 (OK|NO|BAD)/m, "SELECT answered");
  count("and the message is still in the folder", /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("b4 LOGOUT");
  client.close();
}

// RFC 9051 section 6.4.1 has CLOSE remove every message flagged
// `\Deleted` and send no untagged EXPUNGE, so the only thing a client
// can read is the tagged completion. The message is counted again from
// a fresh SELECT, which is the answer that shows whether it went.
async function imapCloseIsRefusedInsideTheFloor(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-close-floor");

  client.send("e0 SELECT " + IMAP_CLOSE_FOLDER);
  var selected = await client.read(/^e0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder CLOSE is driven on holds the message to begin with",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("e1 STORE 1 +FLAGS (\\Deleted)");
  await client.read(/^e1 (OK|NO|BAD)/m, "STORE answered");

  client.send("e2 CLOSE");
  var closed = await client.read(/^e2 (OK|NO|BAD)/m, "CLOSE answered");
  count("CLOSE completes rather than erroring", /^e2 OK/m.test(closed), visible(closed));

  client.send("e3 SELECT " + IMAP_CLOSE_FOLDER);
  var after = await client.read(/^e3 (OK|NO|BAD)/m, "SELECT answered");
  count("and the message inside the floor is still in the folder after CLOSE",
    /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("e4 LOGOUT");
  client.close();
}

// The UIDs a selected mailbox holds, in the order it reports them. UID
// EXPUNGE names messages by unique identifier rather than by sequence
// number (RFC 9051 section 6.4.9), so a vector that guessed `1` would
// be naming whatever UID the store happened to issue first.
async function uidsIn(client, tag) {
  client.send(tag + " UID FETCH 1:* (UID)");
  var listing = await client.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "UID FETCH answered");
  return (listing.match(/UID (\d+)/g) || []).map(function (piece) {
    return parseInt(piece.slice(4), 10);
  });
}

// The sixth way to ask, and the one a client reaches for when it has
// two connections open. RFC 9051 section 6.4.9 removes only the
// messages the UID set names AND the `\Deleted` flag marks, so it is a
// second removal path rather than a spelling of the first: a session
// that flagged three messages and names one of them here expects the
// other two to stay. The floor is asked of it separately because it
// arrives at the store through its own arguments.
async function imapUidExpungeIsRefusedInsideTheFloor(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-uid-floor");

  client.send("g0 SELECT " + IMAP_UID_FOLDER);
  var selected = await client.read(/^g0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder UID EXPUNGE is driven on holds the message to begin with",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  var uids = await uidsIn(client, "g1");
  count("the message's UID can be read, so the set below names it rather than a guess",
    uids.length === 1 && uids[0] > 0, JSON.stringify(uids));

  client.send("g2 STORE 1 +FLAGS (\\Deleted)");
  await client.read(/^g2 (OK|NO|BAD)/m, "STORE answered");

  client.send("g3 UID EXPUNGE " + uids[0]);
  var expunged = await client.read(/^g3 (OK|NO|BAD)/m, "UID EXPUNGE answered");
  count("UID EXPUNGE is refused rather than answered, because this server does not serve " +
    "the command RFC 9051 section 6.4.9 defines",
    /^g3 NO/m.test(expunged), visible(expunged));
  count("the client is NOT told a message inside the floor was removed by UID EXPUNGE",
    !/^\* \d+ EXPUNGE/m.test(expunged), visible(expunged));

  client.send("g4 SELECT " + IMAP_UID_FOLDER);
  var after = await client.read(/^g4 (OK|NO|BAD)/m, "SELECT answered");
  count("and the message inside the floor is still in the folder after UID EXPUNGE",
    /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("g5 LOGOUT");
  client.close();
}

async function pop3DeleteIsRefusedInsideTheFloor(port, caPem, address) {
  var client = await pop3Session(port, caPem, address, "pop3-floor");
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("the maildrop holds the message to begin with", /^\+OK 1 /m.test(stat), visible(stat));

  client.send("DELE 1");
  var marked = await client.read(/^(\+OK|-ERR)/m, "DELE answered");
  count("the mark is accepted, because the refusal belongs at the commit",
    /^\+OK/m.test(marked), visible(marked));

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  // RFC 1939 section 6 gives the UPDATE state a reply for a commit that
  // could not remove everything it was asked to, and a POP3 client told
  // +OK treats the server's copy as gone. On a client set to delete
  // after download that is the wrong way round: the message it thinks it
  // has the only copy of is the one still on the server.
  count("QUIT reports the floor kept the message rather than answering the client " +
    "with a success", /^-ERR/m.test(quit), visible(quit));
  count("and it names the reason, so an operator's log filter can tell the floor from " +
    "an ordinary failure", /retention-floor/.test(quit), visible(quit));
  client.close();

  var remaining = await pop3Count(port, caPem, address, "pop3-floor-recount");
  count("a client reconnecting still finds the message", remaining === 1, String(remaining));
}

// Under a posture both gates are armed, and the hold is the one checked
// first. A client told the floor kept a message it may never delete
// would come back for it in a year and find it still there with no
// explanation, so the reason has to be the one that is actually true.
async function aHeldMessageNamesTheHoldAndNotTheFloor(session, accountId, heldId) {
  var answer = await session.jmap([
    ["Email/set", { accountId: accountId, destroy: [heldId] }, "c0"],
  ]);
  var result = emailSetResponse(answer.body);
  var refusal = result.notDestroyed[heldId];
  count("a held message is refused under a posture as well",
    Array.isArray(result.destroyed) && result.destroyed.length === 0,
    JSON.stringify(result.destroyed));
  count("and the reason given is the hold rather than the floor",
    refusal && refusal.description === "legal-hold", JSON.stringify(refusal));
}

// ---- vectors with no posture set -------------------------------------------

async function jmapDestroysWhatIsNotHeld(session, accountId, ordinaryId, heldId) {
  var answer = await session.jmap([
    ["Email/set", { accountId: accountId, destroy: [ordinaryId, heldId] }, "c0"],
  ]);
  var result = emailSetResponse(answer.body);
  count("with no posture JMAP destroys the message that is not held",
    result.destroyed.length === 1 && result.destroyed[0] === ordinaryId,
    JSON.stringify(result.destroyed));
  count("and refuses the held one in the same call",
    result.notDestroyed[heldId] && result.notDestroyed[heldId].description === "legal-hold",
    JSON.stringify(result.notDestroyed));

  var still = await session.jmap([
    ["Email/get", { accountId: accountId, ids: [ordinaryId, heldId], properties: ["subject"] }, "c0"],
  ]);
  var got = JSON.parse(still.body).methodResponses[0][1];
  count("afterwards JMAP finds the held message and not the destroyed one",
    got.list.length === 1 && got.notFound.length === 1 && got.notFound[0] === ordinaryId,
    JSON.stringify(got.notFound));
}

async function theWebPurgeButtonDestroysWhatIsNotHeld(session, identity, entry) {
  var base = "/mail?folder=" + encodeURIComponent(WEB_FOLDER);
  var purge = await session.post("/mail/actions?folder=" + encodeURIComponent(WEB_FOLDER),
    "application/x-www-form-urlencoded",
    "action=purge" +
    "&objectId=" + encodeURIComponent(entry.ordinaryId) +
    "&objectId=" + encodeURIComponent(entry.heldId));
  count("the purge button redirects rather than erroring", purge.status === 302,
    purge.status + " " + purge.body.slice(0, 120));
  count("and the reader is told some messages were kept, because one was held",
    String(purge.location).indexOf("notice=purge-refused") !== -1, purge.location);

  var left = objectIdsIn(identity, entry.folder);
  count("the store keeps the held message and nothing else",
    left.length === 1 && left[0] === entry.heldId, JSON.stringify(left));

  var page = await session.get(base);
  count("the held message is still listed", page.body.indexOf(HELD) !== -1, page.status);
  count("and the one that was not held is gone", page.body.indexOf(ORDINARY) === -1, page.status);
}

async function imapExpungeDestroysWhatIsNotHeld(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-open");

  client.send("c0 SELECT " + IMAP_FOLDER);
  var selected = await client.read(/^c0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder holds both messages to begin with",
    /^\* 2 EXISTS/m.test(selected), visible(selected));

  client.send("c1 STORE 1:2 +FLAGS (\\Deleted)");
  await client.read(/^c1 (OK|NO|BAD)/m, "STORE answered");

  client.send("c2 EXPUNGE");
  var expunged = await client.read(/^c2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE succeeds", /^c2 OK/m.test(expunged), visible(expunged));
  count("exactly one message is reported removed",
    (expunged.match(/^\* \d+ EXPUNGE/gm) || []).length === 1, visible(expunged));

  client.send("c3 SELECT " + IMAP_FOLDER);
  var after = await client.read(/^c3 (OK|NO|BAD)/m, "SELECT answered");
  count("one message is left in the folder", /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("c4 FETCH 1 BODY[]");
  var fetched = await client.read(/^c4 (OK|NO|BAD)/m, "FETCH answered");
  count("and the one left is the held one, still readable",
    /^c4 OK/m.test(fetched) && fetched.indexOf(HELD) !== -1, visible(fetched));

  client.send("c5 LOGOUT");
  client.close();
}

// The same path with no posture set, where the hold is the only gate
// left. Both messages are flagged and both UIDs are named, so a UID
// EXPUNGE that reached the store past the hold would take both.
async function imapUidExpungeDestroysWhatIsNotHeld(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-uid-open");

  client.send("h0 SELECT " + IMAP_UID_FOLDER);
  var selected = await client.read(/^h0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder UID EXPUNGE is driven on holds both messages to begin with",
    /^\* 2 EXISTS/m.test(selected), visible(selected));

  var uids = await uidsIn(client, "h1");
  count("both UIDs can be read", uids.length === 2, JSON.stringify(uids));

  client.send("h2 STORE 1:2 +FLAGS (\\Deleted)");
  await client.read(/^h2 (OK|NO|BAD)/m, "STORE answered");

  client.send("h3 UID EXPUNGE " + uids.join(","));
  var expunged = await client.read(/^h3 (OK|NO|BAD)/m, "UID EXPUNGE answered");
  count("UID EXPUNGE is refused with no posture set either, so the command is closed " +
    "rather than gated",
    /^h3 NO/m.test(expunged), visible(expunged));
  count("and it removes nothing on its way to being refused",
    (expunged.match(/^\* \d+ EXPUNGE/gm) || []).length === 0, visible(expunged));

  client.send("h4 SELECT " + IMAP_UID_FOLDER);
  var after = await client.read(/^h4 (OK|NO|BAD)/m, "SELECT answered");
  count("both messages are still in the folder, the held one and the one beside it",
    /^\* 2 EXISTS/m.test(after), visible(after));

  // The ordinary message is the one an EXPUNGE in this folder WOULD
  // take, so reading it back is what says the refusal above stopped the
  // removal rather than the hold stopping half of it.
  client.send("h5 FETCH 1:2 BODY[]");
  var fetched = await client.read(/^h5 (OK|NO|BAD)/m, "FETCH answered");
  count("and both are still readable",
    fetched.indexOf(HELD) !== -1 && fetched.indexOf(ORDINARY) !== -1, visible(fetched));

  client.send("h6 LOGOUT");
  client.close();
}

async function imapCloseDestroysWhatIsNotHeld(port, caPem, address) {
  var client = await imapSession(port, caPem, address, "imap-close-open");

  client.send("f0 SELECT " + IMAP_CLOSE_FOLDER);
  var selected = await client.read(/^f0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder CLOSE is driven on holds both messages to begin with",
    /^\* 2 EXISTS/m.test(selected), visible(selected));

  client.send("f1 STORE 1:2 +FLAGS (\\Deleted)");
  await client.read(/^f1 (OK|NO|BAD)/m, "STORE answered");

  client.send("f2 CLOSE");
  var closed = await client.read(/^f2 (OK|NO|BAD)/m, "CLOSE answered");
  count("CLOSE succeeds", /^f2 OK/m.test(closed), visible(closed));
  count("without the untagged EXPUNGE RFC 9051 section 6.4.1 says CLOSE does not send",
    !/^\* \d+ EXPUNGE/m.test(closed), visible(closed));

  client.send("f3 SELECT " + IMAP_CLOSE_FOLDER);
  var after = await client.read(/^f3 (OK|NO|BAD)/m, "SELECT answered");
  count("CLOSE removed the message that was not held", /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("f4 FETCH 1 BODY[]");
  var fetched = await client.read(/^f4 (OK|NO|BAD)/m, "FETCH answered");
  count("and the one left is the held one, still readable",
    /^f4 OK/m.test(fetched) && fetched.indexOf(HELD) !== -1, visible(fetched));

  client.send("f5 LOGOUT");
  client.close();
}

async function pop3DeleteDestroysWhatIsNotHeld(port, caPem, address) {
  var client = await pop3Session(port, caPem, address, "pop3-open");
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("the maildrop holds both messages to begin with", /^\+OK 2 /m.test(stat), visible(stat));

  client.send("DELE 1");
  await client.read(/^(\+OK|-ERR)/m, "first DELE answered");
  client.send("DELE 2");
  await client.read(/^(\+OK|-ERR)/m, "second DELE answered");

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  // Partly removed is the case RFC 1939 section 6 describes: the message
  // that could go has gone, the held one has not, and the client is told
  // so rather than being left to assume both went.
  count("QUIT reports that one of the two could not be removed",
    /^-ERR/m.test(quit), visible(quit));
  count("and names the hold rather than the floor, because no posture is set here",
    /legal-hold/.test(quit) && !/retention-floor/.test(quit), visible(quit));
  client.close();

  var remaining = await pop3Count(port, caPem, address, "pop3-open-recount");
  count("a client reconnecting finds the held message and nothing else",
    remaining === 1, String(remaining));
}

// ---- one running server ----------------------------------------------------

async function withServer(label, posture, fn) {
  var root    = helpers.tempDir("floor-wire-" + label);
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

    var env = {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    };
    if (posture) env.BLAMEPOST_COMPLIANCE_POSTURE = posture;
    var cfg = config.load({ env: env, cwd: root });

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
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
      }),
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
      httpPort: server.web.describe().bound.http,
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
    // `server.stop` leaves the store alone, deliberately: it belongs to
    // whoever opened it. The database handle behind it is one per
    // process, so a second server opened before this one closes would
    // find the first server's rows under its own temporary directory.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// Put one message in a folder and hand back the identity the store gave
// it, read as the row the folder gained rather than by position in a
// listing. Position is a property of the store's own counters, and a
// hard delete rewrites one of them, so a test that names a message by
// where it sits in a list can end up holding a different message than
// the one it planted.
function appendAndIdentify(identity, alice, wireName, marker) {
  var folder = storeFolderOf(identity, alice.id, wireName);
  var before = objectIdsIn(identity, folder);
  identity.mailbox.appendMessage(wireName, message(marker, alice.address),
    { actor: { id: alice.id } });
  var gained = objectIdsIn(identity, folder).filter(function (id) {
    return before.indexOf(id) === -1;
  });
  return { folder: folder, objectId: gained.length === 1 ? gained[0] : "" };
}

// One message per folder, or two where the case needs an ordinary
// message beside one under a preservation order.
function plant(identity, alice, withHeld) {
  var placed = {};
  [POP3_FOLDER, IMAP_FOLDER, IMAP_CLOSE_FOLDER, IMAP_UID_FOLDER, JMAP_FOLDER,
    WEB_FOLDER].forEach(function (name) {
    var ordinary = appendAndIdentify(identity, alice, name, ORDINARY);
    var entry = { folder: ordinary.folder, ordinaryId: ordinary.objectId, heldId: "" };
    if (withHeld) {
      var held = appendAndIdentify(identity, alice, name, HELD);
      entry.heldId = held.objectId;
      identity.messageStore.setLegalHold([held.objectId], { hold: true });
    }
    placed[name] = entry;
  });
  return placed;
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer("soc2", "soc2", async function (ctx) {
    var placed = plant(ctx.identity, ctx.alice, false);
    // The one held message on this server exists so the reason a client
    // is given can be checked against the gate that actually refused.
    var held = appendAndIdentify(ctx.identity, ctx.alice, JMAP_FOLDER, HELD);
    ctx.identity.messageStore.setLegalHold([held.objectId], { hold: true });

    var session = browser("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await session.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
    count("the account can sign in to the browser surface", landed.status === 302,
      landed.status + " " + landed.body.slice(0, 120));

    await jmapRefusesADestroyInsideTheFloor(session, ctx.alice.id,
      [placed[JMAP_FOLDER].ordinaryId]);
    await aHeldMessageNamesTheHoldAndNotTheFloor(session, ctx.alice.id, held.objectId);
    await theWebPurgeButtonIsRefusedInsideTheFloor(session, ctx.identity, placed[WEB_FOLDER]);
    await imapExpungeIsRefusedInsideTheFloor(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await imapCloseIsRefusedInsideTheFloor(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await imapUidExpungeIsRefusedInsideTheFloor(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await pop3DeleteIsRefusedInsideTheFloor(ctx.ports.pop3, ctx.caPem, ctx.alice.address);
  });

  await withServer("none", null, async function (ctx) {
    var placed = plant(ctx.identity, ctx.alice, true);

    var session = browser("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await session.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
    count("the account can sign in to the browser surface with no posture set",
      landed.status === 302, landed.status + " " + landed.body.slice(0, 120));

    await jmapDestroysWhatIsNotHeld(session, ctx.alice.id,
      placed[JMAP_FOLDER].ordinaryId, placed[JMAP_FOLDER].heldId);
    await theWebPurgeButtonDestroysWhatIsNotHeld(session, ctx.identity, placed[WEB_FOLDER]);
    await imapExpungeDestroysWhatIsNotHeld(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await imapCloseDestroysWhatIsNotHeld(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await imapUidExpungeDestroysWhatIsNotHeld(ctx.ports.imap, ctx.caPem, ctx.alice.address);
    await pop3DeleteDestroysWhatIsNotHeld(ctx.ports.pop3, ctx.caPem, ctx.alice.address);
  });

  return helpers.getChecks();
}

module.exports = { name: "retention-floor-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
