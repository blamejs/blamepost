// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * POP3 as a client speaks it: a real session on a bound port, against
 * the maildrop model RFC 1939 defines.
 *
 * POP3 is off unless an operator turns it on, which is exactly why it
 * is worth driving. The listener nobody enables is the listener nobody
 * has watched, and this protocol's model carries hazards the other
 * three do not have:
 *
 *   - The maildrop is a SNAPSHOT taken at authentication, and message
 *     numbers are positions in it rather than identifiers. Anything
 *     arriving or being removed through IMAP, JMAP or the browser while
 *     a session is open must not shift them, because the client is
 *     addressing messages by position and nothing on the wire tells it
 *     the positions moved.
 *
 *   - Deletions apply in the UPDATE state on QUIT and nowhere else
 *     (section 6). A session that resets, or that ends any other way,
 *     leaves every message it marked exactly where it was.
 *
 *   - One session at a time holds the maildrop (section 3).
 *
 *   - The unique id is stable for the life of the maildrop and is never
 *     reused (section 7). It is the whole of what a client running
 *     "leave mail on server" compares against, so an id that moves
 *     redownloads the message and an id that repeats skips one.
 *
 * The last section is about who a `USER` line names. A domain arrives in
 * more than one spelling and all of them are legitimate: `EXAMPLE.COM`
 * differs from `example.com` only in case, which RFC 4343 says is not a
 * difference, and `example.com.` carries the DNS root's dot, which RFC
 * 1035 section 2.3.1 makes the absolute form of the same name. A client
 * writes whichever one its account was configured with. Both directions
 * of getting that wrong are failures, and this protocol can show both:
 * a spelling refused locks an account holder out of their own mailbox,
 * and a spelling admitted as a SECOND identity would hold a second
 * maildrop over one mailbox, which RFC 1939 section 3 forbids and which
 * no other protocol here can demonstrate as plainly.
 *
 * The store level cases for the same model are in
 * `test/layer-1-state/pop3-maildrop-lease.test.js`. These are the ones
 * that need a socket: a refusal a client reads, a snapshot two
 * protocols are touching at once, a session that dies without saying
 * goodbye, and a lock that has to not outlive the process holding it.
 *
 * Run standalone: node test/layer-2-integration/pop3-maildrop-wire.test.js
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
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// A ceiling on what the lock-file search opens. A sealed body can be
// large and none of them is a lock, so the scan reads the small files
// where a lock would be written rather than every message on the volume.
var MAX_SCANNED_FILE_BYTES = helpers.b.constants.BYTES.mib(4);

var count = helpers.count;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function messageFor(address, subject) {
  return Buffer.from([
    "From: sender@example.net",
    "To: " + address,
    "Subject: " + subject,
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "-") + "@example.net>",
    "",
    "the body of " + subject,
    "",
  ].join("\r\n"), "utf8");
}

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

async function accountWith(identity, address, subjects) {
  var account = await identity.accounts.create({ address: address, password: PASSWORD });
  var actor = actorFor(account);
  for (var i = 0; i < subjects.length; i += 1) {
    identity.mailbox.appendMessage("INBOX", messageFor(address, subjects[i]), { actor: actor });
  }
  return account;
}

// The UIDL listing and the STAT line, read from `test/helpers/wire.js`.
// More than one file now asks a maildrop what it is holding, and two
// copies of these are two ideas about what a listing line looks like.
var uidlPairs = wire.pop3Uidl;
var statCount = wire.pop3Stat;

// A session raised to the point where a credential can be offered, with
// the credential left to the caller. The shared ladder throws on a
// refusal, which is right everywhere except the cases whose subject IS
// the refusal.
function unauthenticatedPop3(port, ladder, label) {
  return Wire.pop3(port, {
    caPem: ladder.caPem, servername: ladder.servername, label: label });
}

// One USER and PASS pair, and the verdict, with the session handed back
// open. Every case below whose subject is the verdict goes through this
// rather than the shared ladder, which throws on a refusal.
async function popSignIn(port, ladder, label, written) {
  var session = await unauthenticatedPop3(port, ladder, label);
  session.send("USER " + written);
  await session.read(/^(\+OK|-ERR)/m, "USER answered");
  session.send("PASS " + PASSWORD);
  var verdict = await session.read(/^(\+OK|-ERR)/m, "PASS answered");
  return { session: session, verdict: verdict };
}

async function endPop3(session) {
  session.send("QUIT");
  try { await session.read(/^(\+OK|-ERR)/m, "QUIT answered"); }
  catch (_e) { /* drop-silent by design: the session's verdict is already read */ }
  session.close();
}

// The four spellings of one name, written the way
// `test/layer-2-integration/domain-spelling-wire-parity.test.js` writes
// them, so a claim made there and a claim made here are the same claim
// about the same four strings.
function spellingsOf(name) {
  return [
    ["the recorded spelling",     name],
    ["the absolute form",         name + "."],
    ["a difference only in case", name.toUpperCase()],
    ["both at once",              name.toUpperCase() + "."],
  ];
}

// Names that render like a hosted domain and are different strings: the
// IDN homograph class, a separator that is not one, and the A-label the
// first would arrive as if something upstream had converted it. Plus a
// domain this server has never hosted, which is the control that keeps a
// listener accepting everything from reading as a listener deciding.
var NOT_THIS_DOMAIN = [
  ["a Cyrillic letter standing in for a Latin one", "exаmple.com"],
  ["an ideographic full stop reading as a dot",     "example。com"],
  ["an A-label whose decoded form is not this one", "xn--exmple-4nf.com"],
  ["a domain this server has never hosted",         "notours.example.net"],
];

// ---------------------------------------------------------------------------
// One session at a time (RFC 1939 section 3)
// ---------------------------------------------------------------------------

// A second client reaching for a maildrop somebody is holding has to be
// told so, and has to be left unable to read or delete anything. Being
// refused the drop but admitted to the transaction state would be the
// worse half of both outcomes: two sessions numbering one mailbox.
//
// The refused session's ENDING is the other half of the rule, and this
// is the arrangement on the wire that can show it. The listener reports
// every session's ending, one refused the maildrop included, and the
// report carries an actor for the account that session named. A release
// that looked its maildrop up by ACCOUNT rather than by session would
// find the HOLDER's, hand it back, and throw away the marks the holder
// is carrying: RFC 1939 section 6 gives a DELE one place to become a
// deletion, so the account holder is offered the mail they deleted all
// over again. The holder marks a message before the contender arrives,
// so a release that reached past it has something to lose, and the
// assertions after the contender ends are what report the loss.
//
// The ordering is fixed rather than raced. The listener reports the
// ending inside the refused session's own dispatch, before the reply to
// its QUIT is written, and nothing is sent to the holder until that
// reply has been read.
async function aSecondSessionIsRefusedTheMaildrop(port, ladder, address) {
  var first = await Wire.pop3(port, Object.assign({ label: "pop3-holder" }, ladder));
  try {
    first.send("STAT");
    var held = await first.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("the first session holds a maildrop it can read",
      statCount(held).messages === 3, visible(held));

    first.send("DELE 1");
    var holderMark = await first.read(/^(\+OK|-ERR)/m, "DELE answered");
    count("and it marks a message, so the maildrop it is holding carries something a " +
      "release reaching past it would destroy",
      /^\+OK/m.test(holderMark), visible(holderMark));

    var second = await unauthenticatedPop3(port, ladder, "pop3-contender");
    try {
      second.send("USER " + address);
      await second.read(/^(\+OK|-ERR)/m, "USER answered");
      second.send("PASS " + PASSWORD);
      var verdict = await second.read(/^(\+OK|-ERR)/m, "PASS answered");
      count("a second session for the same account is refused the maildrop rather than " +
        "handed a second view of it (RFC 1939 section 3)",
        /^-ERR/m.test(verdict), visible(verdict));
      count("and the refusal says the maildrop is held rather than that the password was wrong",
        /maildrop/i.test(verdict), visible(verdict));

      second.send("STAT");
      var refused = await second.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("the refused session cannot read the mailbox either",
        /^-ERR/m.test(refused), visible(refused));

      second.send("DELE 1");
      var cannotDelete = await second.read(/^(\+OK|-ERR)/m, "DELE answered");
      count("nor delete from it", /^-ERR/m.test(cannotDelete), visible(cannotDelete));

      second.send("QUIT");
      await second.read(/^(\+OK|-ERR)/m, "QUIT answered");
    } finally {
      second.close();
    }

    // The contender has ended, and its ending has already been reported.
    // Read as a verdict rather than waited on as a `+OK`: a holder whose
    // maildrop was released underneath it answers `-ERR` here, and a
    // read that only accepts the success runs out its budget and reports
    // a timeout instead of the property that broke.
    first.send("STAT");
    var survived = await first.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("a refused session ending released nothing, so the session that opened the " +
      "maildrop is still the one holding it, with the mark it made still on it",
      statCount(survived).messages === 2, visible(survived));

    first.send("QUIT");
    var goodbye = await first.read(/^(\+OK|-ERR)/m, "QUIT answered");
    count("and the holder's own QUIT applies what it marked rather than failing on a " +
      "maildrop handed back on somebody else's ending",
      /^\+OK/m.test(goodbye), visible(goodbye));
  } finally {
    first.close();
  }

  // The lock has to come off at the QUIT rather than at some later
  // sweep, or every client that closes one session and opens another is
  // locked out of its own mailbox.
  var next = await Wire.pop3(port, Object.assign({ label: "pop3-after-quit" }, ladder));
  try {
    next.send("STAT");
    var again = await next.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("a clean QUIT releases the maildrop, so the next session opens straight away, " +
      "onto the mailbox the holder's UPDATE state left behind",
      statCount(again).messages === 2, visible(again));
    next.send("QUIT");
    await next.read(/^\+OK/m, "QUIT answered");
  } finally {
    next.close();
  }
}

// ---------------------------------------------------------------------------
// Marks are applied at QUIT and at no other point (RFC 1939 section 6)
// ---------------------------------------------------------------------------

async function resetUnmarksEverythingAndQuitDeletesNothing(port, ladder) {
  var session = await Wire.pop3(port, Object.assign({ label: "pop3-rset" }, ladder));
  try {
    session.send("DELE 1");
    var marked = await session.read(/^(\+OK|-ERR)/m, "DELE answered");
    count("a message can be marked for deletion", /^\+OK/m.test(marked), visible(marked));

    session.send("DELE 2");
    await session.read(/^(\+OK|-ERR)/m, "second DELE answered");

    session.send("STAT");
    var shrunk = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("a marked message is not counted while the session holds it (RFC 1939 section 5)",
      statCount(shrunk).messages === 1, visible(shrunk));

    session.send("RETR 1");
    var gone = await session.read(/^(\+OK|-ERR)/m, "RETR answered");
    count("and a marked message cannot be retrieved by its number",
      /^-ERR/m.test(gone), visible(gone));

    session.send("RSET");
    var reset = await session.read(/^(\+OK|-ERR)/m, "RSET answered");
    count("RSET is accepted", /^\+OK/m.test(reset), visible(reset));

    session.send("STAT");
    var restored = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("and it unmarks every message the session had marked",
      statCount(restored).messages === 3, visible(restored));

    session.send("QUIT");
    var quit = await session.read(/^(\+OK|-ERR)/m, "QUIT answered");
    count("QUIT after a RSET reports success rather than a partial removal",
      /^\+OK/m.test(quit), visible(quit));
  } finally {
    session.close();
  }

  var after = await Wire.pop3(port, Object.assign({ label: "pop3-rset-recount" }, ladder));
  try {
    after.send("STAT");
    var held = await after.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("so the mailbox is exactly as the session found it",
      statCount(held).messages === 3, visible(held));
    after.send("QUIT");
    await after.read(/^\+OK/m, "QUIT answered");
  } finally {
    after.close();
  }
}

// ---------------------------------------------------------------------------
// The snapshot does not move while a session is holding it
// ---------------------------------------------------------------------------

// A POP3 client addresses messages by position. Another protocol
// writing to the same mailbox mid-session is ordinary: a message
// arrives, or the account holder clears something from the browser on
// their phone. What must not happen is the positions changing
// underneath the session, because there is no vocabulary in RFC 1939
// for telling a client that message 2 is now message 1.
async function anotherProtocolDoesNotRenumberTheMaildrop(ports, ladder, address, dataDir) {
  var pop3 = await Wire.pop3(ports.pop3, Object.assign({ label: "pop3-snapshot" }, ladder));
  var imap = null;
  try {
    pop3.send("UIDL");
    var opened = await pop3.read(/^\.\r\n/m, "UIDL answered");
    var before = uidlPairs(opened);
    count("the maildrop opens with two messages numbered from one",
      before.length === 2 && before[0].msgNum === 1 && before[1].msgNum === 2,
      visible(opened));

    // Messages arrive, and an existing one is destroyed, both through a
    // protocol that knows nothing about this session.
    //
    // Two arrive against one destroyed on purpose. With one of each, a
    // maildrop that re-read the folder on every command would report
    // the same count as a frozen one, and the assertion below would
    // hold against exactly the implementation it exists to refuse.
    imap = await Wire.imap(ports.imap, Object.assign({ label: "imap-writer" }, ladder, {
      address: address, password: PASSWORD }));
    // Read by the tag each command was sent under. RFC 9051 section 7
    // gives a result the command's tag and gives a remark the asterisk,
    // and a `\S+` pattern matches both, so a read written that way
    // returns whichever line lands first. This listener writes a remark
    // after every APPEND (blamejs issue 699: the CRLF ending a
    // synchronizing literal's command line is taken as a line of its
    // own on the next turn of the read loop, and there is no branch for
    // an empty one), so the two orders are both reachable and only one
    // of them reads as a pass.
    //
    // The NOOP after each APPEND is a barrier rather than a wait. The
    // remark is written on the turn after the APPEND, so a command sent
    // now is answered after it and reading that answer clears it,
    // leaving the next literal's continuation nothing stale to read as
    // a refusal.
    for (var arrival = 1; arrival <= 2; arrival += 1) {
      var appendTag = imap.tag();
      await imap.sendLiteral(appendTag + " APPEND INBOX",
        messageFor(address, "arrived mid session " + arrival),
        "<a message that arrives mid session>");
      var appended = await imap.read(new RegExp("^" + appendTag + " (OK|NO|BAD)", "m"),
        "APPEND answered");
      count("a message can arrive over IMAP while a POP3 session is open",
        new RegExp("^" + appendTag + " OK", "m").test(appended), visible(appended));
      var barrier = imap.tag();
      imap.send(barrier + " NOOP");
      await imap.read(new RegExp("^" + barrier + " (OK|NO|BAD)", "m"), "NOOP answered");
    }

    var selectTag = imap.tag();
    imap.send(selectTag + " SELECT INBOX");
    await imap.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");
    var storeTag = imap.tag();
    imap.send(storeTag + " STORE 1 +FLAGS (\\Deleted)");
    await imap.read(new RegExp("^" + storeTag + " (OK|NO|BAD)", "m"), "STORE answered");
    var expungeTag = imap.tag();
    imap.send(expungeTag + " EXPUNGE");
    var expunged = await imap.read(new RegExp("^" + expungeTag + " (OK|NO|BAD)", "m"),
      "EXPUNGE answered");
    count("and the first message can be destroyed over IMAP while the same session is open",
      /^\* 1 EXPUNGE/m.test(expunged), visible(expunged));

    // None of those writes is allowed to reach the open maildrop. The
    // folder now holds three; a maildrop reading it live would say so.
    pop3.send("STAT");
    var stat = await pop3.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("the open maildrop still holds the two messages it opened with, rather than the " +
      "three the folder now holds, so mail arriving mid session is not numbered into a " +
      "listing the client has already read",
      statCount(stat).messages === 2, visible(stat));

    pop3.send("UIDL");
    var reread = await pop3.read(/^\.\r\n/m, "UIDL answered");
    var after = uidlPairs(reread);
    count("and every message is still at the number it had, with the id it had",
      after.length === before.length &&
      after[0].msgNum === before[0].msgNum && after[0].uid === before[0].uid &&
      after[1].msgNum === before[1].msgNum && after[1].uid === before[1].uid,
      visible(reread));

    // The message the other protocol destroyed is the interesting half.
    // Whatever the server says about it, it must not say it by moving
    // the message that is still there.
    pop3.send("RETR 2");
    var second = await pop3.read(/(\r\n\.\r\n|^-ERR)/m, "RETR 2 answered");
    count("the message at number two is still the message that was at number two",
      /Subject: second/.test(second), visible(second.slice(0, 300)));

    pop3.send("RETR 1");
    var first = await pop3.read(/(\r\n\.\r\n|^-ERR)/m, "RETR 1 answered");
    count("a message another protocol destroyed mid session is refused rather than served " +
      "from a stale body or answered with somebody else's message",
      /^-ERR/m.test(first), visible(first.slice(0, 300)));

    // What the refusal is allowed to say. A snapshot outliving one of
    // its messages is an ordinary race between two protocols, so the
    // read that finds the body gone is a condition this server has a
    // sentence for. Handing the client the exception instead puts the
    // operator's volume layout and the message's content digest on the
    // wire, in front of anybody who can authenticate.
    count("the refusal does not carry the server's data directory, nor a path into the " +
      "volume the bodies are stored on",
      first.indexOf(dataDir) === -1 && !/blobs[\\/][0-9a-f]{2}[\\/]/.test(first),
      visible(first.slice(0, 300)));
    count("nor the stored content digest of the message",
      !/[0-9a-f]{64,}/.test(first), visible(first.slice(0, 300)));
    count("and it reads as a refusal an operator can act on rather than a file layer errno",
      /volume/i.test(first) && !/file not found/i.test(first),
      visible(first.slice(0, 300)));
    count("and the sentence reaches the client whole rather than cut by the reply-line cap",
      /affected\.\r\n/.test(first), visible(first.slice(0, 300)));

    pop3.send("QUIT");
    await pop3.read(/^(\+OK|-ERR)/m, "QUIT answered");
  } finally {
    if (imap) { try { imap.send(imap.tag() + " LOGOUT"); } catch (_e) { /* the session is over */ } imap.close(); }
    pop3.close();
  }
}

// ---------------------------------------------------------------------------
// Malformed input refuses loud, at the point of parse
// ---------------------------------------------------------------------------

// Every wire-protocol reader here refuses at the parse rather than
// tolerating a shape "for compatibility", and POP3 is where being
// lenient has a CVE catalogue attached. What each of these also has
// to do is leave the session usable: a refusal that desynchronises the
// connection turns one bad command into a dead mailbox.
async function malformedCommandsAreRefusedAndTheSessionSurvives(port, ladder) {
  var session = await Wire.pop3(port, Object.assign({ label: "pop3-malformed" }, ladder));
  try {
    var vectors = [
      { line: "RETR 0",     why: "a message number counts from one, so zero names nothing" },
      { line: "RETR 007",   why: "a leading zero is a different token on the wire" },
      { line: "RETR abc",   why: "a message number is decimal" },
      { line: "RETR",       why: "RETR takes a message number" },
      { line: "RETR 1 2",   why: "RETR takes one message number" },
      { line: "DELE -1",    why: "a message number is not signed" },
      { line: "TOP 1",      why: "TOP takes a message number and a line count" },
      { line: "TOP 1 -1",   why: "a line count is not signed" },
      { line: "STAT extra", why: "STAT takes no arguments" },
      { line: "FROB 1",     why: "a verb RFC 1939 does not define is not a verb" },
      { line: "UIDL 0",     why: "an optional message number is still a message number" },
    ];

    for (var i = 0; i < vectors.length; i += 1) {
      session.send(vectors[i].line);
      var answer = await session.read(/^(\+OK|-ERR)/m, vectors[i].line + " answered");
      count("`" + vectors[i].line + "` is refused: " + vectors[i].why,
        /^-ERR/m.test(answer), visible(answer));
    }

    session.send("STAT");
    var alive = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("and the session is still usable after every one of them, so a refusal ends the " +
      "command rather than the mailbox",
      statCount(alive).messages === 3, visible(alive));

    session.send("QUIT");
    await session.read(/^(\+OK|-ERR)/m, "QUIT answered");
  } finally {
    session.close();
  }
}

// ---------------------------------------------------------------------------
// A session that ends without saying goodbye
// ---------------------------------------------------------------------------

// RFC 1939 section 6 gives the marks one place to become deletions, and
// a connection that dies is not it. A client killed mid-download, a
// laptop lid closed, a mobile link dropped: each of those has to leave
// the mailbox untouched, because the alternative is mail destroyed by a
// session that never confirmed it wanted to destroy anything.
//
// The lock the dead session was holding is the other half. The listener
// reports a session that ended by any route, a link that dropped without
// a QUIT included, and that report is what releases the maildrop, so the
// account holder collects their mail on the next connection rather than
// waiting out a timer that cannot tell a finished session from a slow
// one.
async function aDeadSessionDeletesNothing(ports, ladder, address) {
  var session = await Wire.pop3(ports.pop3, Object.assign({ label: "pop3-dies" }, ladder));
  session.send("DELE 1");
  var marked = await session.read(/^(\+OK|-ERR)/m, "DELE answered");
  count("the session marks a message for deletion", /^\+OK/m.test(marked), visible(marked));
  session.send("DELE 2");
  await session.read(/^(\+OK|-ERR)/m, "second DELE answered");

  // No QUIT. The socket simply stops, which is what a dropped
  // connection looks like from this end.
  session.close();

  // Read the mailbox back over a protocol whose view does not depend on
  // the maildrop the dead session was holding.
  var imap = await Wire.imap(ports.imap, Object.assign({ label: "imap-reader" }, ladder, {
    address: address, password: PASSWORD }));
  try {
    var tag = imap.tag();
    imap.send(tag + " SELECT INBOX");
    var selected = await imap.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT answered");
    count("a session that ended without QUIT deleted nothing, however much it had marked " +
      "(RFC 1939 section 6)", /^\* 2 EXISTS/m.test(selected), visible(selected));
    imap.send(imap.tag() + " LOGOUT");
  } finally {
    imap.close();
  }

  // The listener reports the end after any store work the session left
  // in flight has settled, so the release lands a moment after the
  // socket does. Polled rather than slept: a fixed budget here is the
  // shape that passes alone and fails under load.
  var reopened = null;
  await helpers.waitUntil(async function () {
    var attempt = await popSignIn(ports.pop3, ladder, "pop3-reconnects", address);
    if (/^\+OK/m.test(attempt.verdict)) { reopened = attempt; return true; }
    await endPop3(attempt.session);
    return false;
  }, {
    timeoutMs: 5000,
    label:     "pop3 wire: the maildrop a dropped connection was holding is released",
  });

  try {
    count("a client reconnecting after its own connection dropped opens its maildrop " +
      "again, because the session ending is what releases the hold rather than a timer",
      /^\+OK/m.test(reopened.verdict), visible(reopened.verdict));
    reopened.session.send("STAT");
    var back = await reopened.session.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("and the mail the dropped session had marked is still there for them",
      statCount(back).messages === 2, visible(back));
  } finally {
    await endPop3(reopened.session);
  }
}

// ---------------------------------------------------------------------------
// The other direction: QUIT still applies what it marked
// ---------------------------------------------------------------------------

// The release above runs on a report that fires however a session ended,
// and QUIT is the one route where the marks are not discarded. RFC 1939
// section 6 applies them in the UPDATE state, so the release has to land
// after that commit rather than instead of it. A release that ran first
// would answer the client `+OK` for a removal the server never
// performed, and the message it was told was gone would be offered again
// on the next collection.
//
// Which session a release NAMES is asserted by
// `aSecondSessionIsRefusedTheMaildrop` above rather than here, and this
// arrangement cannot reach it. Measured on the shipped composition, the
// listener reports a quitting session's ending inside that session's own
// QUIT dispatch, one millisecond after the UPDATE state commits and
// before the `+OK` for the QUIT is written. A successor cannot begin its
// own connection until it has read that reply, so it always opens after
// the ending has landed, whatever is or is not done between the two. No
// ordering of POP3 clients puts a live successor in front of a previous
// session's ending, which is why the case that earns the claim is the
// one whose ending belongs to a session refused the maildrop its holder
// is still using.
async function quitAppliesTheMarksTheSessionMade(ports, ladder, address) {
  var quitting = await Wire.pop3(ports.pop3, Object.assign({ label: "pop3-quits" }, ladder));
  try {
    quitting.send("DELE 1");
    var marked = await quitting.read(/^(\+OK|-ERR)/m, "DELE answered");
    count("a session marks a message and then ends the way the protocol asks",
      /^\+OK/m.test(marked), visible(marked));
    quitting.send("DELE 2");
    await quitting.read(/^(\+OK|-ERR)/m, "second DELE answered");
    quitting.send("QUIT");
    var goodbye = await quitting.read(/^(\+OK|-ERR)/m, "QUIT answered");
    count("QUIT reports the removal rather than a partial one",
      /^\+OK/m.test(goodbye), visible(goodbye));
  } finally {
    quitting.close();
  }

  var imap = await Wire.imap(ports.imap, Object.assign({ label: "imap-after-quit" }, ladder, {
    address: address, password: PASSWORD }));
  try {
    var tag = imap.tag();
    imap.send(tag + " SELECT INBOX");
    var selected = await imap.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT answered");
    count("QUIT applied the marks the session made, so releasing a maildrop when its session " +
      "ends does not discard what the UPDATE state already committed",
      /^\* 1 EXISTS/m.test(selected), visible(selected));
    imap.send(imap.tag() + " LOGOUT");
  } finally {
    imap.close();
  }

  var next = await Wire.pop3(ports.pop3, Object.assign({ label: "pop3-follows" }, ladder));
  try {
    next.send("STAT");
    var still = await next.read(/^(\+OK|-ERR)/m, "STAT answered");
    count("a maildrop opens straight after the session before it quit, onto the mailbox " +
      "that session's UPDATE state left rather than the one it opened with",
      statCount(still).messages === 1, visible(still));

    next.send("DELE 1");
    var marks = await next.read(/^(\+OK|-ERR)/m, "DELE answered");
    count("so it can still mark what it is holding", /^\+OK/m.test(marks), visible(marks));

    next.send("QUIT");
    var last = await next.read(/^(\+OK|-ERR)/m, "QUIT answered");
    count("and its own QUIT applies rather than failing on a maildrop taken from underneath it",
      /^\+OK/m.test(last), visible(last));
  } finally {
    next.close();
  }

  var reader = await Wire.imap(ports.imap, Object.assign({ label: "imap-after-second" }, ladder, {
    address: address, password: PASSWORD }));
  try {
    var tag2 = reader.tag();
    reader.send(tag2 + " SELECT INBOX");
    var emptied = await reader.read(new RegExp("^" + tag2 + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    count("and the mailbox holds what the two sessions between them left in it",
      /^\* 0 EXISTS/m.test(emptied), visible(emptied));
    reader.send(reader.tag() + " LOGOUT");
  } finally {
    reader.close();
  }
}

// ---------------------------------------------------------------------------
// NOOP is the keepalive the protocol defines, and it has to count
// ---------------------------------------------------------------------------

// A hold that ages out on idleness has to see every command, and NOOP is
// the one the listener answers entirely on its own. A client sitting on
// a maildrop it is not reading issues nothing else, so a hold that never
// saw the keepalive would age out under a live connection and take that
// session's deletion marks with it.
//
// Measured as a window rather than as a flag: the idle reading is taken
// after a deliberate pause, then again immediately after one NOOP. A
// keepalive that reached the hold moves the second reading back behind
// the first.
var IDLE_OBSERVATION_MS = 600;

async function noopIsAKeepaliveTheHoldCanSee(port, ladder, identity) {
  var session = await Wire.pop3(port, Object.assign({ label: "pop3-keepalive" }, ladder));
  try {
    session.send("STAT");
    await session.read(/^(\+OK|-ERR)/m, "STAT answered");

    await helpers.passiveObserve(IDLE_OBSERVATION_MS,
      "pop3 wire: letting an open maildrop go quiet");

    var beforeIdle = identity.mailbox.describe().dropIdleMs;
    count("an open maildrop reports how long it has been since anything touched it",
      Array.isArray(beforeIdle) && beforeIdle.length === 1,
      JSON.stringify(beforeIdle));
    count("and the reading has grown over a window nothing was sent in",
      beforeIdle[0] >= IDLE_OBSERVATION_MS / 2, String(beforeIdle[0]) + "ms");

    session.send("NOOP");
    var noop = await session.read(/^(\+OK|-ERR)/m, "NOOP answered");
    count("the listener answers NOOP itself", /^\+OK/m.test(noop), visible(noop));

    var afterIdle = identity.mailbox.describe().dropIdleMs;
    count("and the keepalive reached the hold, so a session doing nothing but NOOP does " +
      "not age out of the maildrop it is holding",
      afterIdle[0] < beforeIdle[0],
      String(beforeIdle[0]) + "ms before, " + String(afterIdle[0]) + "ms after");
  } finally {
    await endPop3(session);
  }
}

// ---------------------------------------------------------------------------
// The lock does not outlive the process holding it
// ---------------------------------------------------------------------------

// Every classic POP3 server has a story about a lock file that outlived
// the process that wrote it and left a mailbox unopenable until somebody
// went and deleted it by hand. The exclusive access RFC 1939 section 3
// asks for is a property of a live session, so it has to live where the
// sessions do and nowhere else.
// The one lock this server does keep on the volume, which is a
// different claim from a maildrop and has to stay out of the search.
// `lib/store` takes it so a second process cannot open the same data
// directory underneath the first; it names no account and no session,
// and it is the thing whose absence would be the defect.
var VOLUME_OPENER_LOCK = "blamepost.lock";

// The needle is the shape a drop identifier takes rather than one this
// test can name, because the session holding it is gone and it never
// left the process. `examined` comes back with the hits so the caller
// can say the search actually read something: a walk that silently
// found no files would report the clean answer for the wrong reason.
function lockFilesRecordingAMaildrop(roots, needle) {
  var hits = [];
  var examined = 0;
  function walk(dir) {
    var entries;
    try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
    catch (_e) { return; }
    for (var i = 0; i < entries.length; i += 1) {
      var full = nodePath.join(dir, entries[i].name);
      if (entries[i].isDirectory()) { walk(full); continue; }
      examined += 1;
      if (entries[i].name === VOLUME_OPENER_LOCK) continue;
      if (entries[i].name.indexOf(needle) !== -1 || /\.lock$/.test(entries[i].name)) {
        hits.push(full);
        continue;
      }
      var stat;
      try { stat = nodeFs.statSync(full); } catch (_e2) { continue; }
      if (stat.size > MAX_SCANNED_FILE_BYTES) continue;
      var body;
      try { body = nodeFs.readFileSync(full); } catch (_e3) { continue; }
      if (body.indexOf(needle) !== -1) hits.push(full);
    }
  }
  for (var r = 0; r < roots.length; r += 1) walk(roots[r]);
  return { hits: hits, examined: examined };
}

// ---------------------------------------------------------------------------
// One account, however its domain is spelled (RFC 4343, RFC 1035 §2.3.1)
// ---------------------------------------------------------------------------

// Every spelling of the account's own domain opens the account's own
// maildrop. A refusal here is an account holder locked out of their mail
// for how their client was configured, and it is silent at every
// management surface: the console lists the mailbox, the command line
// finds it, and only the socket says no.
//
// The maildrop is read after each sign-in, because a `+OK` on PASS says
// the credential was accepted and says nothing about which mailbox was
// opened. A spelling that authenticated onto an empty drop would pass a
// check that stopped at the greeting.
async function everySpellingOfTheDomainOpensTheSameMaildrop(port, ladder, account, held) {
  var at = account.address.indexOf("@");
  var localPart = account.address.slice(0, at);
  var spellings = spellingsOf(account.address.slice(at + 1));

  for (var i = 0; i < spellings.length; i += 1) {
    var written = localPart + "@" + spellings[i][1];
    var attempt = await popSignIn(port, ladder, "pop3-spelling-" + i, written);
    try {
      count("POP3 signs the account in when its domain is written as " + spellings[i][0] +
        " (" + written + "), because the identity layer derives the mailbox rather than " +
        "comparing the bytes the client wrote",
        /^\+OK/m.test(attempt.verdict), visible(attempt.verdict));
      if (!/^\+OK/m.test(attempt.verdict)) continue;

      attempt.session.send("STAT");
      var stat = await attempt.session.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("and the maildrop it opens is the account's own, holding the mail that account " +
        "holds rather than an empty one at a domain nobody hosts",
        statCount(stat).messages === held, visible(stat));
    } finally {
      await endPop3(attempt.session);
    }
  }
}

// The other direction, which this protocol can prove and the others
// cannot. RFC 1939 section 3 gives one session the maildrop at a time, so
// a spelling that had become a second identity would be handed a second
// view of one mailbox while the first session was still numbering it.
// Being refused BECAUSE the drop is held is the answer that says there is
// one identity; being refused for a bad credential would say the spelling
// reached no account at all, which is the lock-out failure above.
async function noSpellingOpensASecondMaildrop(port, ladder, account) {
  var at = account.address.indexOf("@");
  var localPart = account.address.slice(0, at);
  var spellings = spellingsOf(account.address.slice(at + 1));

  var holder = await Wire.pop3(port, Object.assign({ label: "pop3-spelling-holder" }, ladder,
    { address: account.address, password: PASSWORD }));
  try {
    for (var i = 1; i < spellings.length; i += 1) {
      var written = localPart + "@" + spellings[i][1];
      var attempt = await popSignIn(port, ladder, "pop3-spelling-second-" + i, written);
      try {
        count("a session opening " + spellings[i][0] + " (" + written + ") while the account " +
          "already holds its maildrop is refused, so a spelling is not a second identity " +
          "with a maildrop of its own",
          /^-ERR/m.test(attempt.verdict), visible(attempt.verdict));
        count("and it is refused because the maildrop is held rather than because the " +
          "credential was wrong, which is the answer a second identity would have given",
          /maildrop/i.test(attempt.verdict), visible(attempt.verdict));
      } finally {
        await endPop3(attempt.session);
      }
    }
  } finally {
    await endPop3(holder);
  }
}

// The control. A name that only renders like the hosted one, and one this
// server has never hosted, are both refused, so the spellings admitted
// above are a decision about the name rather than a listener that admits
// whatever it is handed.
async function aDomainThisServerDoesNotHostIsRefused(port, ladder, account) {
  var localPart = account.address.slice(0, account.address.indexOf("@"));
  for (var i = 0; i < NOT_THIS_DOMAIN.length; i += 1) {
    var written = localPart + "@" + NOT_THIS_DOMAIN[i][1];
    var attempt = await popSignIn(port, ladder, "pop3-not-ours-" + i, written);
    try {
      count("POP3 refuses a credential naming " + NOT_THIS_DOMAIN[i][0] + ", rather than " +
        "handing over the maildrop at the domain it is drawn to look like",
        /^-ERR/m.test(attempt.verdict), visible(attempt.verdict));

      attempt.session.send("STAT");
      var stat = await attempt.session.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("and the refused session reaches no mailbox", /^-ERR/m.test(stat), visible(stat));
    } finally {
      await endPop3(attempt.session);
    }
  }
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("pop3wire");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

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
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });

    // One account per case, because the maildrop is exclusive and two
    // cases sharing an address would be waiting on each other's locks
    // rather than asserting about their own.
    var alice = await accountWith(identity, "alice@" + DOMAIN, ["first", "second", "third"]);
    var bob   = await accountWith(identity, "bob@" + DOMAIN,   ["first", "second"]);
    var carol = await accountWith(identity, "carol@" + DOMAIN, ["first", "second"]);
    var dave  = await accountWith(identity, "dave@" + DOMAIN,  ["first", "second", "third"]);
    var erin  = await accountWith(identity, "erin@" + DOMAIN,  ["first", "second", "third"]);
    var frank = await accountWith(identity, "frank@" + DOMAIN, ["first", "second", "third"]);
    var grace = await accountWith(identity, "grace@" + DOMAIN, ["first", "second"]);
    var heidi = await accountWith(identity, "heidi@" + DOMAIN, ["first", "second", "third"]);

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default, and every case in this file is about it.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    function buildServer(handle) {
      return blamepost.create({
        config: Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
        store:        handle,
        mailStore:    handle.mailbox,
        messageStore: handle.messageStore,
        tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
        httpAddress:  LOOPBACK,
      });
    }

    server = buildServer(identity);
    await server.start();
    running = true;

    var base = { caPem: leaf.ca, servername: HOSTNAME };
    function ladderFor(account) {
      return Object.assign({}, base, { address: account.address, password: PASSWORD });
    }

    await helpers.withTestTimeout("pop3 wire: a second session is refused the maildrop",
      function () {
        return aSecondSessionIsRefusedTheMaildrop(sections.pop3.port, ladderFor(alice),
          alice.address);
      });

    await helpers.withTestTimeout("pop3 wire: RSET unmarks and QUIT deletes nothing",
      function () {
        return resetUnmarksEverythingAndQuitDeletesNothing(sections.pop3.port, ladderFor(dave));
      });

    await helpers.withTestTimeout("pop3 wire: another protocol does not renumber the maildrop",
      function () {
        return anotherProtocolDoesNotRenumberTheMaildrop(
          { pop3: sections.pop3.port, imap: sections.imap.port },
          Object.assign({}, base, { address: bob.address, password: PASSWORD }),
          bob.address, dataDir);
      });

    await helpers.withTestTimeout("pop3 wire: malformed commands are refused",
      function () {
        return malformedCommandsAreRefusedAndTheSessionSurvives(sections.pop3.port,
          ladderFor(erin));
      });

    await helpers.withTestTimeout("pop3 wire: a session that dies deletes nothing",
      function () {
        return aDeadSessionDeletesNothing(
          { pop3: sections.pop3.port, imap: sections.imap.port },
          Object.assign({}, base, { address: carol.address, password: PASSWORD }),
          carol.address);
      });

    await helpers.withTestTimeout("pop3 wire: QUIT applies the marks the session made",
      function () {
        return quitAppliesTheMarksTheSessionMade(
          { pop3: sections.pop3.port, imap: sections.imap.port },
          Object.assign({}, base, { address: heidi.address, password: PASSWORD }),
          heidi.address);
      });

    await helpers.withTestTimeout("pop3 wire: one account however its domain is spelled",
      function () {
        return everySpellingOfTheDomainOpensTheSameMaildrop(sections.pop3.port, base, frank, 3);
      });

    await helpers.withTestTimeout("pop3 wire: no spelling opens a second maildrop",
      function () {
        return noSpellingOpensASecondMaildrop(sections.pop3.port, base, frank);
      });

    await helpers.withTestTimeout("pop3 wire: a domain this server does not host is refused",
      function () {
        return aDomainThisServerDoesNotHostIsRefused(sections.pop3.port, base, frank);
      });

    await helpers.withTestTimeout("pop3 wire: NOOP is a keepalive the hold can see",
      function () {
        return noopIsAKeepaliveTheHoldCanSee(sections.pop3.port, ladderFor(grace), identity);
      });

    // ---- nothing is held once the sessions have ended ---------------------
    //
    // Every session above has ended, one of them by dropping its
    // connection rather than by quitting. A hold left standing after
    // that is a mailbox its own owner cannot open.
    await helpers.waitUntil(function () {
      return identity.mailbox.describe().openDrops === 0;
    }, {
      timeoutMs: 5000,
      label:     "pop3 wire: every maildrop is released once its session has ended",
    });
    count("no maildrop is held once every session has ended, whichever way each ended",
      identity.mailbox.describe().openDrops === 0,
      String(identity.mailbox.describe().openDrops));

    // Anything on either volume naming the drop, or any lock file at
    // all, would be a hold that could outlive the process that took it.
    // The database lives on the work volume rather than the data one,
    // so both are walked.
    var recorded = lockFilesRecordingAMaildrop([dataDir, workDir], "drop_");
    count("the search for a persisted lock actually read the volumes",
      recorded.examined > 0, String(recorded.examined) + " files");
    count("and nothing on them records an open maildrop, so a session that never quit " +
      "leaves no lock for an operator to clear by hand after a crash",
      recorded.hits.length === 0, recorded.hits.join(", "));

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    store.close();

    var restarted = await store.open(cfg);
    server = buildServer(restarted);
    await server.start();
    running = true;

    count("the restarted server holds no maildrop locks",
      restarted.mailbox.describe().openDrops === 0,
      String(restarted.mailbox.describe().openDrops));

    var recovered = await Wire.pop3(sections.pop3.port,
      Object.assign({ label: "pop3-after-restart" }, base,
        { address: carol.address, password: PASSWORD }));
    try {
      recovered.send("STAT");
      var back = await recovered.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("and the account holder gets their maildrop back, with the mail the dead " +
        "session had marked still in it",
        statCount(back).messages === 2, visible(back));
      recovered.send("QUIT");
      await recovered.read(/^\+OK/m, "QUIT answered");
    } finally {
      recovered.close();
    }

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "pop3-maildrop-wire", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
