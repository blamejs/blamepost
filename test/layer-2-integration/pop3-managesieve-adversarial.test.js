// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two listeners an account holder reaches their maildrop and their
 * filters through, driven the way somebody trying to get past them
 * would drive them.
 *
 * The files beside this one drive POP3 and ManageSieve the way a
 * conforming client does: a maildrop is opened, listed, marked and
 * committed, and a script is uploaded, activated and read back. What
 * they do not drive is the input a client is not supposed to send. That
 * is where being lenient has a CVE catalogue attached to it, and a
 * refusal that arrives as a success is invisible to every case written
 * around the conforming path.
 *
 * Four claims, and the last two are the ones with teeth:
 *
 *   - One account's filter does not decide where another account's mail
 *     lands. Delivery reads the recipient's active script with an actor
 *     the server builds for the occasion, so nobody is signed in when
 *     that read happens and the account it is scoped to is the only
 *     thing keeping one account's rules off another's mail.
 *   - A POP3 command outside the grammar draws the protocol's own error
 *     at the point of parse, and the session stays usable afterwards.
 *   - The octet counts STAT and LIST advertise are the octets a client
 *     gets back from RETR once it has undone the dot-stuffing RFC 1939
 *     section 3 defines. A message carrying a bare line feed and a line
 *     beginning with a dot is the shape where the two come apart.
 *   - A ManageSieve literal the listener refuses is still a payload the
 *     client has already put on the wire, and what happens to those
 *     octets decides whether the next thing the listener reads is a
 *     command the client sent or a line out of a script.
 *
 * Run standalone: node test/layer-2-integration/pop3-managesieve-adversarial.test.js
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
var pop3Body    = wire.pop3Body;
var pop3Stat    = wire.pop3Stat;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The line cap the POP3 listener runs on. RFC 2449 section 4 puts a
// command line at 255 octets and the framework ships the permissive
// 1024, which is what this listener composes because nothing here
// overrides it.
var POP3_LINE_CAP = 1024;

// The script ceiling, which the wire guard and the store agree on: 64
// KiB under the strict profile this server composes.
var SIEVE_SCRIPT_CAP = 65536;

// How many scripts an account keeps, from `MAX_SIEVE_SCRIPTS` in the
// mailbox adapter.
var SIEVE_SCRIPT_COUNT = 32;

var ONE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

var lastReply = wire.lastManageSieveReply;

function replyTo(session, what) {
  return session.read(ONE_REPLY, what).then(lastReply);
}

function pop3Reply(session, what) {
  return session.read(/^(\+OK|-ERR)/m, what);
}

// ---------------------------------------------------------------------------
// One account's filter, one account's mail
// ---------------------------------------------------------------------------

async function deliver(mxPort, caPem, to, subject) {
  var peer = await Wire.mx(mxPort, { caPem: caPem, servername: HOSTNAME, label: "mx-deliver" });
  try {
    peer.send("MAIL FROM:<" + PEER + ">");
    await peer.read(/^250 /m, "MAIL FROM accepted");
    peer.send("RCPT TO:<" + to + ">");
    await peer.read(/^250 /m, "RCPT TO accepted");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw([
      "From: " + PEER,
      "To: " + to,
      "Subject: " + subject,
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "") + "." + Date.now() + "@example.net>",
      "",
      "Body of " + subject + ".",
      "",
      ".",
      "",
    ].join("\r\n"), "<the message and its terminating dot>");
    return await peer.read(/^\d{3} /m, "message answered");
  } finally { peer.close(); }
}

async function heldBy(port, caPem, address, folder, label) {
  var session = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD, label: label });
  try {
    var tag = session.tag();
    session.send(tag + ' STATUS "' + folder + '" (MESSAGES)');
    var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "STATUS answered");
    var match = reply.match(/MESSAGES (\d+)/);
    return match === null ? -1 : parseInt(match[1], 10);
  } finally { session.close(); }
}

// The account holder who wrote the filter is the only account it
// decides for. Both directions are asserted, because a filter that never
// ran passes the isolation half on its own and says nothing at all.
async function oneAccountsFilterDecidesForThatAccountOnly(ports, caPem, owner, stranger) {
  var session = await Wire.managesieve(ports.managesieve, {
    caPem: caPem, servername: HOSTNAME, address: owner, password: PASSWORD,
    label: "managesieve-scope" });
  try {
    session.sendNonSyncLiteral('PUTSCRIPT "everything-to-junk"',
      'require ["fileinto"];\nfileinto "Junk";\n', "<a filter that moves every message>");
    var stored = await replyTo(session, "PUTSCRIPT answered");
    count("one account uploads a filter that moves every message it receives",
      /^OK/.test(stored), visible(stored));

    session.send('SETACTIVE "everything-to-junk"');
    var activated = await replyTo(session, "SETACTIVE answered");
    count("and activates it", /^OK/.test(activated), visible(activated));
  } finally {
    session.send("LOGOUT");
    try { await session.read(ONE_REPLY, "LOGOUT answered"); }
    catch (_e) { /* drop-silent by design: the verdict is already read */ }
    session.close();
  }

  var ownerJunkBefore    = await heldBy(ports.imap, caPem, owner, "Junk", "owner-junk-before");
  var strangerJunkBefore = await heldBy(ports.imap, caPem, stranger, "Junk", "other-junk-before");
  var strangerInboxBefore = await heldBy(ports.imap, caPem, stranger, "INBOX",
    "other-inbox-before");

  var toOwner = await deliver(ports.mx, caPem, owner, "for the owner");
  count("a message for the account that wrote the filter is accepted",
    /^250 /m.test(toOwner), visible(toOwner));
  await helpers.waitUntil(function () {
    return heldBy(ports.imap, caPem, owner, "Junk", "owner-junk-poll")
      .then(function (n) { return n === ownerJunkBefore + 1; });
  }, {
    timeoutMs: 8000,
    label:     "pop3-managesieve-adversarial: the owner's own message reaching the filed folder",
  });
  count("and the filter files it, so the filter is live rather than merely stored", true);

  var toStranger = await deliver(ports.mx, caPem, stranger, "for the stranger");
  count("a message for a different account on the same domain is accepted",
    /^250 /m.test(toStranger), visible(toStranger));
  await helpers.waitUntil(function () {
    return heldBy(ports.imap, caPem, stranger, "INBOX", "other-inbox-poll")
      .then(function (n) { return n === strangerInboxBefore + 1; });
  }, {
    timeoutMs: 8000,
    label:     "pop3-managesieve-adversarial: the other account's message reaching its INBOX",
  });
  count("and it lands in that account's own INBOX, because delivery reads the recipient's " +
    "filter rather than whichever one is active on the volume", true);

  var strangerJunkAfter = await heldBy(ports.imap, caPem, stranger, "Junk", "other-junk-after");
  count("the other account's filed folder is untouched, so one account's rules moved none " +
    "of another account's mail",
    strangerJunkAfter === strangerJunkBefore,
    "before " + strangerJunkBefore + ", after " + strangerJunkAfter);
}

// ---------------------------------------------------------------------------
// POP3: input outside the grammar
// ---------------------------------------------------------------------------

// RFC 1939 gives the server one error reply, and the grammar in RFC 2449
// section 5 gives TOP two decimal arguments. Every line below is outside
// that grammar, and each is followed by a command that has to be
// answered, because a refusal that leaves the reader out of step is a
// session where the next reply answers the wrong command.
async function aPop3CommandOutsideTheGrammarIsRefused(port, caPem, address) {
  var session = await Wire.pop3(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD,
    label: "pop3-grammar" });
  try {
    var refused = [
      ["TOP with no line count",           "TOP 1"],
      ["TOP with a line count that is not a number", "TOP 1 seventeen"],
      ["TOP with a line count past the digit ceiling", "TOP 1 99999999999"],
      ["a message number written with a leading zero", "RETR 007"],
      ["a message number of zero",         "RETR 0"],
      ["a verb the protocol does not define", "FROBNICATE 1"],
    ];
    for (var i = 0; i < refused.length; i += 1) {
      session.send(refused[i][1]);
      var reply = await pop3Reply(session, refused[i][0] + " answered");
      count("POP3 refuses " + refused[i][0] + " at the point of parse",
        /^-ERR/m.test(reply), visible(reply));

      session.send("STAT");
      var still = await pop3Reply(session, "STAT after the refusal");
      count("and the session is still in step afterwards, so the refusal cost the client " +
        "one command rather than the rest of the session",
        /^\+OK \d+ \d+/m.test(still), visible(still));
    }

    // The largest line count the grammar admits. The reader walks the
    // body looking for that many line feeds and stops when it runs out,
    // so the ceiling is the message rather than the number, and a client
    // asking for more lines than the message has gets the message.
    // Read to the terminator in one go. TOP answers with a status line
    // and then a multi-line body, so a read that stopped at the status
    // line would take an unknown amount of the body off the buffer with
    // it and the terminator might already be gone by the next read.
    session.send("TOP 1 9999999999");
    var wholeMessage = await session.read(/\r\n\.\r\n/, "TOP answered and terminated");
    count("POP3 accepts the largest line count the grammar admits and answers with the " +
      "message rather than walking that many times",
      /^\+OK/m.test(wholeMessage), visible(wholeMessage.slice(0, 120)));

    session.send("STAT");
    var afterTop = await pop3Reply(session, "STAT after TOP");
    count("and the session is still in step after it",
      /^\+OK \d+ \d+/m.test(afterTop), visible(afterTop));
  } finally {
    session.send("QUIT");
    try { await pop3Reply(session, "QUIT answered"); }
    catch (_e) { /* drop-silent by design: the verdict is already read */ }
    session.close();
  }
}

// A line that never ends is the shape a reader has to bound, and the
// credential verbs are where it costs the most: USER and PASS are the
// two lines a client sends before it is anybody, so the buffer behind
// them is reachable without an account.
async function anOversizedPop3LineIsRefused(port, caPem) {
  var session = await Wire.pop3(port, { caPem: caPem, servername: HOSTNAME, label: "pop3-long" });
  try {
    session.send("USER " + new Array(POP3_LINE_CAP * 2).join("a"));
    var reply = await session.read(/^(\+OK|-ERR)/m, "an oversized USER answered");
    count("a POP3 command line past the listener's cap is refused rather than buffered",
      /^-ERR/m.test(reply), visible(reply.slice(0, 160)));
    count("and the refusal names the cap, so an operator reading it knows what moved",
      /cap /.test(reply), visible(reply.slice(0, 160)));
  } finally { session.close(); }
}

// ---------------------------------------------------------------------------
// POP3: the octets the counts promise
// ---------------------------------------------------------------------------

// RFC 1939 section 5 makes the LIST size the size of the message and the
// STAT total the sum of them, and section 3 has the server double a
// leading dot on the wire and the client undo it. So the claim is about
// what is left after the client has undone the framing, and the message
// below is the shape where a framing layer that reads bare line feeds as
// line boundaries would come apart from it: a bare line feed, and a line
// that begins with a dot after a canonical CRLF.
function messageWithAwkwardLineEndings(address) {
  return Buffer.from([
    "From: " + PEER,
    "To: " + address,
    "Subject: awkward line endings",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <awkward@example.net>",
    "",
    ".this line begins with a dot",
    "ordinary line",
  ].join("\r\n") + "\r\n" +
    // A bare line feed, and a line after it beginning with a dot. A
    // framing layer that treated the bare line feed as a boundary would
    // stuff this dot as well, and the octets the client recovered would
    // be one longer than the count it was given.
    "bare-lf-follows\n.dot after a bare line feed\r\n", "utf8");
}

async function theCountsArePromisesAboutTheOctetsRetrReturns(port, caPem, address, stored) {
  var session = await Wire.pop3(port, {
    caPem:  caPem, servername: HOSTNAME, address: address, password: PASSWORD,
    label:  "pop3-octets", binary: true });
  // RFC 1939 section 3 sends a message with CRLF line endings, so the
  // octets a client recovers are the stored message with its bare line
  // feed written as CRLF.
  var onWire = b.safeSmtp.canonicalizeEol(stored);
  try {
    session.send("STAT");
    var statLine = await session.read(/^\+OK \d+ \d+/m, "STAT answered");
    var stat = pop3Stat(statLine);
    count("STAT counts the one message this maildrop holds", stat.messages === 1,
      JSON.stringify(stat));
    count("and its total is the octets the message takes on the wire",
      stat.bytes === onWire.length, "advertised " + stat.bytes + ", on the wire " + onWire.length);

    session.send("LIST 1");
    var listLine = await session.read(/^(\+OK|-ERR)/m, "LIST answered");
    var listed = /^\+OK 1 (\d+)/m.exec(listLine.toString());
    count("LIST advertises a size for it", listed !== null, visible(String(listLine)));
    count("and it is the same number STAT gave",
      listed !== null && parseInt(listed[1], 10) === stat.bytes,
      listed === null ? "no size" : listed[1] + " vs " + stat.bytes);

    session.send("RETR 1");
    var raw = await session.readBytes(/\r\n\.\r\n/, "RETR answered");
    var recovered = pop3Body(raw);
    count("RETR returns exactly the octets the counts promised, once the client has undone " +
      "the dot-stuffing RFC 1939 section 3 defines",
      recovered.length === stat.bytes,
      "recovered " + recovered.length + ", advertised " + stat.bytes);
    count("and they are the stored octets with each line ending written as CRLF, byte for " +
      "byte, so the dot after the bare line feed is stuffed and unstuffed exactly once",
      recovered.equals(onWire),
      "recovered " + recovered.length + " ending " +
        recovered.subarray(-12).toString("hex") + ", on the wire " + onWire.length +
        " ending " + onWire.subarray(-12).toString("hex"));
  } finally {
    session.send("QUIT");
    try { await session.read(/^(\+OK|-ERR)/m, "QUIT answered"); }
    catch (_e) { /* drop-silent by design: the verdict is already read */ }
    session.close();
  }
}

// ---------------------------------------------------------------------------
// ManageSieve: the ceiling, and the verbs around it
// ---------------------------------------------------------------------------

// A Sieve script of an exact octet length. The body does something, and
// the rest is a comment, so the length is a dial rather than a property
// of what the script says.
function scriptOfExactly(bytes) {
  var head = 'require ["fileinto"];\nkeep;\n#';
  var tail = "\n";
  var pad  = bytes - Buffer.byteLength(head, "utf8") - Buffer.byteLength(tail, "utf8");
  if (pad < 0) throw new Error("scriptOfExactly: " + bytes + " is shorter than the head");
  return head + new Array(pad + 1).join("a") + tail;
}

// RFC 5804 section 2.5 gives HAVESPACE so a client can ask before it
// uploads. An answer that does not predict the upload is worse than no
// answer: the client trusts it, sends, and is refused after the transfer
// rather than before it.
async function haveSpaceAnswersWhatTheUploadWillDo(session) {
  var atCap = scriptOfExactly(SIEVE_SCRIPT_CAP);
  session.send('HAVESPACE "at-cap" ' + SIEVE_SCRIPT_CAP);
  var askedAtCap = await replyTo(session, "HAVESPACE at the ceiling answered");
  count("HAVESPACE says there is room for a script of exactly the ceiling",
    /^OK/.test(askedAtCap), visible(askedAtCap));

  session.sendNonSyncLiteral('PUTSCRIPT "at-cap"', atCap, "<a script of exactly the ceiling>");
  var storedAtCap = await replyTo(session, "PUTSCRIPT at the ceiling answered");
  count("and the upload of exactly that size is accepted, so the answer predicted it",
    /^OK/.test(storedAtCap), visible(storedAtCap));

  session.send('HAVESPACE "over-cap" ' + (SIEVE_SCRIPT_CAP + 1));
  var askedOverCap = await replyTo(session, "HAVESPACE past the ceiling answered");
  count("HAVESPACE refuses one octet past the ceiling",
    /^NO/.test(askedOverCap), visible(askedOverCap));

  // The upload of that size is refused at the wire guard, before any of
  // the payload is read, which is the whole point of announcing a count.
  // The literal is a synchronizing one, so the client waits for the answer
  // and sends nothing after a refusal. A non-synchronizing literal refused
  // here also closes the connection, since its payload is already on the
  // way; that case is the one aRefusedLiteralIsNotReadAsCommands covers.
  session.send('PUTSCRIPT "over-cap" {' + (SIEVE_SCRIPT_CAP + 1) + "}");
  var storedOverCap = await replyTo(session, "PUTSCRIPT past the ceiling answered");
  count("and the upload announcing that size is refused on the announcement rather than " +
    "after the transfer, so the two answers agree",
    /^NO/.test(storedOverCap) && /exceeds cap/.test(storedOverCap), visible(storedOverCap));

  session.send('DELETESCRIPT "at-cap"');
  await session.read(ONE_REPLY, "DELETESCRIPT answered");
}

// The count ceiling, asked the same way. An account at the ceiling has
// to be told so BEFORE it transfers a script, and told the same thing
// when it transfers one anyway.
async function haveSpaceAnswersWhatTheCountCeilingWillDo(session) {
  var body = 'require ["fileinto"];\nkeep;\n';
  for (var i = 0; i < SIEVE_SCRIPT_COUNT; i += 1) {
    session.sendNonSyncLiteral('PUTSCRIPT "filler-' + i + '"', body, "<filler " + i + ">");
    var reply = await replyTo(session, "filler " + i + " answered");
    if (!/^OK/.test(reply)) {
      count("an account can fill to the script ceiling", false,
        "filler " + i + ": " + visible(reply));
      return;
    }
  }
  count("an account can fill to the script ceiling of " + SIEVE_SCRIPT_COUNT, true);

  session.send('HAVESPACE "one-too-many" 128');
  var asked = await replyTo(session, "HAVESPACE at the count ceiling answered");
  count("HAVESPACE refuses a new name once the account holds as many scripts as it may",
    /^NO/.test(asked), visible(asked));

  session.sendNonSyncLiteral('PUTSCRIPT "one-too-many"', body, "<one past the ceiling>");
  var stored = await replyTo(session, "PUTSCRIPT at the count ceiling answered");
  count("and the upload is refused the same way, so the answer predicted it",
    /^NO/.test(stored), visible(stored));

  // Replacing one already held is not a new name, so it is not at the
  // ceiling. A HAVESPACE that answered otherwise would stop a client
  // editing a filter it already has.
  session.send('HAVESPACE "filler-0" 128');
  var replacing = await replyTo(session, "HAVESPACE for a name already held answered");
  count("a name the account already holds is still answered with room, because replacing a " +
    "script is not a new one",
    /^OK/.test(replacing), visible(replacing));

  for (var d = 0; d < SIEVE_SCRIPT_COUNT; d += 1) {
    session.send('DELETESCRIPT "filler-' + d + '"');
    await session.read(ONE_REPLY, "DELETESCRIPT answered");
  }
}

// RFC 5804 section 2.8 has SETACTIVE name a script the account holds,
// and section 2.11 refuses a rename onto a name already taken. Both are
// refusals a client has to be able to tell from a success, because both
// leave something in place that the client believes it replaced.
async function theNamingVerbsRefuseRatherThanOverwrite(session) {
  var oneBody = 'require ["fileinto"];\nfileinto "Junk";\n';
  var twoBody = 'require ["fileinto"];\nkeep;\n';

  session.sendNonSyncLiteral('PUTSCRIPT "one"', oneBody, "<the first script>");
  count("the first script is stored", /^OK/.test(await replyTo(session, "PUTSCRIPT answered")));
  session.sendNonSyncLiteral('PUTSCRIPT "two"', twoBody, "<the second script>");
  count("and so is the second", /^OK/.test(await replyTo(session, "PUTSCRIPT answered")));

  session.send('SETACTIVE "neither"');
  var missing = await replyTo(session, "SETACTIVE for a name nobody holds answered");
  count("SETACTIVE naming a script the account does not hold is refused",
    /^NO/.test(missing), visible(missing));

  session.send("LISTSCRIPTS");
  var afterMissing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("and nothing became active on the way to that refusal",
    afterMissing.indexOf("ACTIVE") === -1, visible(afterMissing));

  session.send('RENAMESCRIPT "one" "two"');
  var collided = await replyTo(session, "RENAMESCRIPT onto a name already held answered");
  count("RENAMESCRIPT onto a name the account already holds is refused",
    /^NO/.test(collided), visible(collided));

  session.send('GETSCRIPT "two"');
  var fetched = await session.read(ONE_REPLY, "GETSCRIPT answered");
  count("and the script under that name is still the one that was there, rather than the " +
    "one the rename would have moved onto it",
    fetched.indexOf("keep;") !== -1 && fetched.indexOf('fileinto "Junk"') === -1,
    visible(fetched.slice(0, 200)));

  session.send('GETSCRIPT "one"');
  var original = await session.read(ONE_REPLY, "GETSCRIPT answered");
  count("and the one the rename would have moved is still under its own name",
    original.indexOf('fileinto "Junk"') !== -1, visible(original.slice(0, 200)));

  session.send('DELETESCRIPT "one"');
  await session.read(ONE_REPLY, "DELETESCRIPT answered");
  session.send('DELETESCRIPT "two"');
  await session.read(ONE_REPLY, "DELETESCRIPT answered");
}

// ---------------------------------------------------------------------------
// ManageSieve: what happens to a refused literal
// ---------------------------------------------------------------------------

// RFC 5804 section 4 lets a client announce a literal and send the
// payload without waiting, which is the `{N+}` form every client uses
// for PUTSCRIPT. The announcement and the payload are therefore already
// on the wire together, and a listener that refuses the announcement has
// N octets in its buffer that nobody has claimed.
//
// Reading them as commands means the next thing the listener parses is a
// line out of a Sieve script rather than a line the client wrote as a
// command. The refusal happens in two places, and the listener answers
// each differently:
//
// - `_handlePutScript` refuses on an unauthenticated session. The listener
//   then discards the announced octets, so the upload draws one refusal.
// - `guardManageSieveCommand.validate` refuses an announced count past the
//   script ceiling before any handler runs. The listener answers NO, then
//   BYE, and closes the connection, so no line of the payload is parsed.
//
// The observation is made over a window rather than by waiting for a
// reply, because the claim is about how many replies arrive: a read that
// stopped at the first one would report the same thing either way.
var SMUGGLED_VERB = "FROBNICATE";
var VICTIM_SCRIPT = "keep-this-one";

function payloadCarryingACommand(verb) {
  return 'require ["fileinto"];\r\n' + verb + "\r\nkeep;\r\n";
}

function refusalsIn(text) {
  return String(text).split("\r\n").filter(function (line) {
    return /^NO/.test(line);
  });
}

async function aRefusedLiteralIsNotReadAsCommands(port, caPem, address) {
  // Before authentication, where the handler refuses.
  var unauthenticated = await Wire.connect(port, "managesieve-refused-literal");
  try {
    await unauthenticated.read(/^OK[^\r\n]*\r\n/m, "capability banner");
    unauthenticated.sendNonSyncLiteral('PUTSCRIPT "before-auth"',
      payloadCarryingACommand(SMUGGLED_VERB),
      "<a script carrying a line that reads as a command>");
    var beforeAuth = await unauthenticated.readQuietly("everything said to the refused upload");
    count("a PUTSCRIPT before authentication is refused once",
      refusalsIn(beforeAuth).length === 1,
      refusalsIn(beforeAuth).length + " refusal(s): " + visible(beforeAuth));
    count("and the payload behind it is discarded rather than read line by line as commands",
      beforeAuth.indexOf(SMUGGLED_VERB) === -1, visible(beforeAuth));
  } finally { unauthenticated.close(); }

  // After authentication, where the wire guard refuses on the announced
  // count. A line of the script that is a ManageSieve verb would run with
  // the authority of the session that was uploading the script.
  var session = await Wire.managesieve(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD,
    label: "managesieve-over-cap-literal" });
  try {
    session.sendNonSyncLiteral('PUTSCRIPT "' + VICTIM_SCRIPT + '"',
      'require ["fileinto"];\nkeep;\n', "<the script the payload below names>");
    var seeded = await replyTo(session, "PUTSCRIPT answered");
    count("an account holds a script under a name of its own", /^OK/.test(seeded),
      visible(seeded));

    session.send('PUTSCRIPT "over-cap" {' + (SIEVE_SCRIPT_CAP + 1) + "+}");
    session.sendRaw(payloadCarryingACommand('DELETESCRIPT "' + VICTIM_SCRIPT + '"'),
      "<the payload behind an announcement past the ceiling>");
    var overCap = await session.readQuietly("everything said to the oversized upload");
    count("a PUTSCRIPT announcing more octets than the ceiling admits is refused",
      refusalsIn(overCap).length === 1, visible(overCap));
    count("and the listener closes the connection rather than parsing the payload",
      /(^|\r\n)BYE/.test(overCap), visible(overCap));
  } finally { session.close(); }

  var check = await Wire.managesieve(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: PASSWORD,
    label: "managesieve-over-cap-aftermath" });
  try {
    check.send("LISTSCRIPTS");
    var listing = await check.read(ONE_REPLY, "LISTSCRIPTS answered");
    count("so the script the payload named is still there",
      listing.indexOf('"' + VICTIM_SCRIPT + '"') !== -1, visible(listing));
    check.send('DELETESCRIPT "' + VICTIM_SCRIPT + '"');
    await check.read(ONE_REPLY, "DELETESCRIPT answered");
  } finally {
    check.send("LOGOUT");
    try { await check.read(ONE_REPLY, "LOGOUT answered"); }
    catch (_e) { /* drop-silent by design: the verdict is already read */ }
    check.close();
  }
}

// The same root, on the one literal that carries a credential.
//
// RFC 5804 section 2.1 lets a client send its SASL initial response as a
// literal on the AUTHENTICATE line, which is what every client does
// because a base64 response is exactly the payload the quoted form would
// have to escape. `_handleAuthenticate` in the vendored listener has
// several refusals that return before it registers that transfer, and a
// mechanism the listener does not advertise is one of them, reachable
// over TLS by a client that offered the wrong one.
//
// The listener discards the announced octets after that refusal, as it
// does for any other refused literal. A listener that read them as a
// command line would quote the initial response back in a refusal that
// is written to the socket and recorded, so the value a client sent as
// its credential would be the value an operator reads afterwards.
//
// The token below stands in for the credential. It is not one, so the
// case can assert on where it ends up without putting a credential
// shape in the tree.
var INITIAL_RESPONSE_MARKER = "bWFya2VyLWZvci10aGlzLWNhc2U";

function mechanismNotAdvertised(banner) {
  var line = (String(banner).match(/"SASL" "([^"]*)"/) || [null, ""])[1];
  var advertised = line.toUpperCase().split(" ");
  var candidates = ["SCRAM-SHA-1", "CRAM-MD5", "DIGEST-MD5", "GSSAPI", "ANONYMOUS"];
  for (var i = 0; i < candidates.length; i += 1) {
    if (advertised.indexOf(candidates[i]) === -1) return { mech: candidates[i], line: line };
  }
  return { mech: null, line: line };
}

async function aRefusedCredentialLiteralIsNotQuotedBack(port, caPem) {
  var session = await Wire.connect(port, "managesieve-refused-credential");
  try {
    await session.read(/^OK[^\r\n]*\r\n/m, "capability banner");
    session.send("STARTTLS");
    await session.read(/^OK/m, "STARTTLS accepted");
    await session.upgrade(caPem, HOSTNAME);
    var banner = await session.read(/^OK/m, "capability banner re-emitted over TLS");

    var chosen = mechanismNotAdvertised(banner);
    count("the listener advertises the mechanisms it will accept, and one it does not " +
      "advertise can be named", chosen.mech !== null, chosen.line);
    if (chosen.mech === null) return;

    session.sendNonSyncLiteral('AUTHENTICATE "' + chosen.mech + '"', INITIAL_RESPONSE_MARKER,
      "<an initial response for a mechanism the listener does not advertise>");
    var said = await session.readQuietly("everything said to the refused exchange");

    count("an AUTHENTICATE naming a mechanism the listener does not advertise is refused",
      /Mechanism/.test(said), visible(said));
    count("once, because the initial response behind it is discarded rather than read as a " +
      "command line", refusalsIn(said).length === 1, visible(said));
    // The comparison is case-folded because a reader that took the value
    // as a verb would upper-case it before quoting it.
    count("so the value a client sent as its credential is not quoted back in any refusal",
      said.toUpperCase().indexOf(INITIAL_RESPONSE_MARKER.toUpperCase()) === -1, visible(said));
  } finally { session.close(); }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("pop3-ms-adversarial");
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
  var session  = null;

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
        BLAMEPOST_POP3_ENABLED:     "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "adversarial test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: PASSWORD });
    var carol = await identity.accounts.create({
      address: "carol@" + DOMAIN, password: PASSWORD });
    var dan = await identity.accounts.create({
      address: "dan@" + DOMAIN, password: PASSWORD });

    // The message whose octets the counts are a promise about, written
    // onto the volume rather than delivered, because the shape being
    // measured is one no peer would be allowed to transmit.
    var awkward = messageWithAwkwardLineEndings(carol.address);
    identity.mailbox.appendMessage("INBOX", awkward, {
      actor: {
        id: carol.id, username: carol.address, address: carol.address, domain: carol.domain,
        isAdmin: false, mailboxes: [carol.address], roles: ["account"],
      },
      flags: [],
    });

    // One ordinary message for the grammar session to aim its verbs at.
    identity.mailbox.appendMessage("INBOX",
      Buffer.from([
        "From: " + PEER,
        "To: " + dan.address,
        "Subject: ordinary",
        "Date: Sat, 23 Aug 2026 12:00:00 +0000",
        "Message-ID: <ordinary@example.net>",
        "",
        "Body.",
        "",
      ].join("\r\n"), "utf8"), {
        actor: {
          id: dan.id, username: dan.address, address: dan.address, domain: dan.domain,
          isAdmin: false, mailboxes: [dan.address], roles: ["account"],
        },
        flags: [],
      });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default, and half of this file is about it.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ports = {
      mx:          sections.mx.port,
      imap:        sections.imap.port,
      pop3:        sections.pop3.port,
      managesieve: sections.managesieve.port,
    };

    await helpers.withTestTimeout("adversarial: one account's filter decides for one account",
      function () {
        return oneAccountsFilterDecidesForThatAccountOnly(ports, leaf.ca, alice.address,
          bob.address);
      });

    await helpers.withTestTimeout("adversarial: POP3 refuses input outside its grammar",
      function () {
        return aPop3CommandOutsideTheGrammarIsRefused(ports.pop3, leaf.ca, dan.address);
      });

    await helpers.withTestTimeout("adversarial: an oversized POP3 line is refused",
      function () { return anOversizedPop3LineIsRefused(ports.pop3, leaf.ca); });

    await helpers.withTestTimeout("adversarial: the POP3 counts promise the RETR octets",
      function () {
        return theCountsArePromisesAboutTheOctetsRetrReturns(ports.pop3, leaf.ca,
          carol.address, awkward);
      });

    session = await Wire.managesieve(ports.managesieve, {
      caPem: leaf.ca, servername: HOSTNAME, address: bob.address, password: PASSWORD,
      label: "managesieve-ceilings" });

    await helpers.withTestTimeout("adversarial: HAVESPACE answers what the upload will do",
      function () { return haveSpaceAnswersWhatTheUploadWillDo(session); });
    await helpers.withTestTimeout("adversarial: HAVESPACE answers the count ceiling too",
      function () { return haveSpaceAnswersWhatTheCountCeilingWillDo(session); });
    await helpers.withTestTimeout("adversarial: the naming verbs refuse rather than overwrite",
      function () { return theNamingVerbsRefuseRatherThanOverwrite(session); });

    session.send("LOGOUT");
    await session.read(ONE_REPLY, "LOGOUT answered");
    session.close();
    session = null;

    await helpers.withTestTimeout("adversarial: a refused literal is not read as commands",
      function () {
        return aRefusedLiteralIsNotReadAsCommands(ports.managesieve, leaf.ca, carol.address);
      });

    await helpers.withTestTimeout("adversarial: a refused credential literal is not quoted back",
      function () { return aRefusedCredentialLiteralIsNotQuotedBack(ports.managesieve, leaf.ca); });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (session) session.close();
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

module.exports = {
  name:      "pop3-managesieve-adversarial",
  run:       run,
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
