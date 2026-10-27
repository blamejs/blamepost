// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Filtering as an account holder's client reaches it: over port 4190,
 * in RFC 5804 grammar, against a bound listener.
 *
 * Everything else that exercises Sieve in this suite calls the store
 * adapter directly, which is a view no mail client has. It cannot see a
 * capability banner that omits the extension a script requires, a
 * PUTSCRIPT the listener accepts and never stores, a LISTSCRIPTS that
 * does not mark the active one, or a refusal that arrives as OK. Those
 * are the failures a client actually meets, and a transcript is the
 * only thing that catches them.
 *
 * The end of the file is the claim worth the port: a script uploaded
 * over the wire, activated over the wire, then a message delivered by a
 * peer over SMTP and read back over IMAP from the folder the script
 * named. Nothing short of that says filtering works, because the
 * upload, the activation and the delivery hook are three separate
 * pieces and any two of them can be right while the third does nothing.
 *
 * Run standalone: node test/layer-2-integration/sieve-managesieve-wire.test.js
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
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The interpreter's operation budget, from the framework's own default.
var GAS_CAP = 10000;

// One reply line. RFC 5804 section 4 ends every command line with CRLF,
// the ones carrying a literal payload included, and the PUTSCRIPT
// example in section 2.3 shows that terminator as the empty line after
// the script. It is outside the declared octet count, so a listener owes
// it a consume; one that reads it as a line instead reads a command with
// nothing in it and answers a refusal of its own, written before the
// reply to the command that CRLF was terminating. A client reading one
// reply per command then takes the refusal as the answer and is a reply
// out of step for the rest of the session.
//
// Both literal-bearing commands, AUTHENTICATE and PUTSCRIPT, answer
// once. That is the whole of what this file waits for, and the two cases
// that drive it are `oneAuthenticateDrawsOneReply` and
// `onePutscriptDrawsOneReply`: a listener that starts writing a second
// reply to either fails there rather than being quietly read past.
var ONE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

// RFC 5804 section 2.1 writes the server's SASL challenge as a literal,
// so an empty challenge reaches the client as a zero-length one. This is
// the invitation, and it is not an OK, a NO or a BYE, so a client
// waiting on a verdict pattern never sees it.
var EMPTY_CHALLENGE = /^\{0\}\r\n\r\n/m;

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- ManageSieve, spoken the way RFC 5804 spells it -------------------------

// The last reply line in a transcript, which is the one that answers
// the command just sent.
function lastReply(text) {
  var replies = String(text).split("\r\n").filter(function (line) {
    return /^(?:OK|NO|BYE)/.test(line);
  });
  return replies.length === 0 ? "" : replies[replies.length - 1];
}

// A command whose payload is a literal: the announcement line, the
// bytes, then the CRLF that ends the command. The non-synchronizing
// form is used so the client does not have to wait for a continuation
// it would then have to tell apart from the final reply.
function sendLiteral(session, command, payload, note) {
  var bytes = Buffer.byteLength(payload, "utf8");
  session.send(command + " {" + bytes + "+}");
  session.sendRaw(payload + "\r\n", note);
}

function replyTo(session, what) {
  return session.read(ONE_REPLY, what).then(lastReply);
}

// Everything up to the point where a credential may be offered. The
// SASL cases below each open the exchange their own way, so the ladder
// stops before AUTHENTICATE rather than carrying one spelling of it.
async function manageSieveUpgraded(port, caPem, label) {
  var session = await Wire.connect(port, label);
  var banner = await session.read(/^OK[^\r\n]*\r\n/m, "capability banner");
  session.send("STARTTLS");
  await session.read(/^OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  await session.read(/^OK/m, "capabilities re-sent after the upgrade");
  return { session: session, banner: banner };
}

async function manageSieveSession(port, caPem, address, label) {
  var opened = await manageSieveUpgraded(port, caPem, label);
  sendLiteral(opened.session, "AUTHENTICATE \"PLAIN\"",
    plainResponse(address, ALICE_PASSWORD), "<the SASL response>");
  var authReply = await replyTo(opened.session, "authenticated");
  return { session: opened.session, banner: opened.banner, authReply: authReply };
}

// One command, one reply. The literal form of the initial response is
// what a real client sends, because a base64 credential is exactly the
// payload the quoted form would have to escape, and a listener that
// answers it twice puts every later reply in that session one command
// out of step.
//
// The absence is the claim, so it is observed over a window rather than
// waited for: a read that stopped at the first reply would pass against
// a listener whose second one was merely slow.
async function oneAuthenticateDrawsOneReply(port, caPem, address) {
  var opened = await manageSieveUpgraded(port, caPem, "managesieve-one-reply");
  var session = opened.session;

  sendLiteral(session, "AUTHENTICATE \"PLAIN\"",
    plainResponse(address, ALICE_PASSWORD), "<the SASL response>");
  await session.read(ONE_REPLY, "the reply to AUTHENTICATE");
  var after = await session.readQuietly("everything said after the first reply");

  count("one AUTHENTICATE written the way RFC 5804 spells it draws exactly one reply",
    after.indexOf("\r\n") === -1 || !/^(?:OK|NO|BYE)/m.test(after), visible(after));
  count("and nothing refuses the CRLF that ended the command",
    !/empty command line/.test(after), visible(after));

  // A second command proves the session is in step: an extra reply left
  // in the buffer would answer this one.
  session.send("LISTSCRIPTS");
  var listing = await replyTo(session, "LISTSCRIPTS answered");
  count("so the command after it reads its own reply",
    /^OK/.test(listing), visible(listing));

  session.send("LOGOUT");
  await session.read(/^OK/m, "LOGOUT answered");
  session.close();
}

// The sibling path, driven the same way and pinned to the same count.
//
// The two literal-bearing commands are one rule read twice, and a client
// cannot tell which of them a listener consumes the terminator for
// without asking each: an upload is the only place a script name, a
// payload size and a stored body all move at once, so a spurious reply
// there desynchronises a session in the middle of the account holder's
// filter rules rather than at a greeting.
//
// The absence is the claim, so it is observed over a window rather than
// waited for: a read that stopped at the first reply would pass against
// a listener whose second one was merely slow.
async function onePutscriptDrawsOneReply(session) {
  var body = "require [\"fileinto\"];\nkeep;\n";
  sendLiteral(session, "PUTSCRIPT \"terminator\"", body, "<a script and its terminating CRLF>");
  var reply = await replyTo(session, "the reply to PUTSCRIPT");
  count("one PUTSCRIPT written the way RFC 5804 spells it stores the script",
    /^OK/.test(reply), visible(reply));

  var after = await session.readQuietly("everything said after the first reply");
  count("and draws exactly one reply, so a client reading one reply per command reports the " +
    "outcome it was given",
    after.indexOf("\r\n") === -1 || !/^(?:OK|NO|BYE)/m.test(after), visible(after));
  count("with nothing refusing the CRLF that ended the command",
    !/empty command line/.test(after), visible(after));

  // A second command proves the session is in step: an extra reply left
  // in the buffer would answer this one.
  session.send("DELETESCRIPT \"terminator\"");
  var deleted = await replyTo(session, "DELETESCRIPT answered");
  count("so the command after it reads its own reply", /^OK/.test(deleted), visible(deleted));
}

// RFC 5804 section 2.1 lets a client open AUTHENTICATE with no initial
// response and be asked for one. PLAIN is client first, so the ask
// carries nothing: an empty challenge, written as a zero-length
// literal, and the credential arrives on the line after it.
//
// A listener that answers this with a refusal instead is not merely
// less convenient. It spends one of the account's authentication
// failure slots on what the specification calls a normal round trip,
// so a client that opens the exchange this way locks its own account
// holder out of a mailbox nobody attacked.
async function theChallengePathCompletes(port, caPem, address) {
  var opened = await manageSieveUpgraded(port, caPem, "managesieve-challenge");
  var session = opened.session;

  session.send("AUTHENTICATE \"PLAIN\"");
  var invitation = await session.read(/^(?:\{0\}|OK|NO|BYE)/m, "the answer to a bare AUTHENTICATE");
  count("AUTHENTICATE with no initial response is answered with a challenge rather than " +
    "a refusal (RFC 5804 section 2.1)",
    EMPTY_CHALLENGE.test(invitation), visible(invitation));

  session.send("\"" + plainResponse(address, ALICE_PASSWORD) + "\"");
  var verdict = await replyTo(session, "the verdict on the challenged exchange");
  count("and the credential sent in answer to it authenticates the account",
    /^OK/.test(verdict), visible(verdict));

  session.send("LISTSCRIPTS");
  var listing = await replyTo(session, "LISTSCRIPTS answered");
  count("so the session reached the authenticated state, not just an OK",
    /^OK/.test(listing), visible(listing));

  session.send("LOGOUT");
  await session.read(/^OK/m, "LOGOUT answered");
  session.close();
}

// RFC 5804 section 2.1 gives the client a way out of an exchange it has
// opened: a line holding one asterisk. That is a withdrawal rather than
// a wrong password, so it must not be answered as a syntax error and
// must not be charged to the account's failure budget.
//
// The budget is what makes this worth driving. An exchange a client can
// open and abandon for free is an exchange an attacker can open and
// abandon until the account holder cannot sign in, so the same session
// is made to authenticate afterwards: the slot the cancelled exchange
// took has to have come back.
async function theExchangeIsCancellable(port, caPem, address) {
  var opened = await manageSieveUpgraded(port, caPem, "managesieve-cancel");
  var session = opened.session;

  session.send("AUTHENTICATE \"PLAIN\"");
  await session.read(/^(?:\{0\}|OK|NO|BYE)/m, "the challenge");

  session.send("*");
  var cancelled = await replyTo(session, "the answer to a cancellation");
  count("an asterisk answering a challenge is refused as a cancellation",
    /^NO/.test(cancelled), visible(cancelled));
  count("and is not read as a verb the protocol does not define, which is what a " +
    "listener holding no exchange would call it",
    !/unknown verb/.test(cancelled), visible(cancelled));

  sendLiteral(session, "AUTHENTICATE \"PLAIN\"",
    plainResponse(address, ALICE_PASSWORD), "<the SASL response>");
  var verdict = await replyTo(session, "the verdict after the cancellation");
  count("and the cancelled exchange released what it held, so the same session still " +
    "signs in", /^OK/.test(verdict), visible(verdict));

  session.send("LOGOUT");
  await session.read(/^OK/m, "LOGOUT answered");
  session.close();
}

// ---- cases -----------------------------------------------------------------

// A client reads the banner to decide what it may write. An extension
// the interpreter implements and the banner omits is a feature nobody
// can use, and one the banner claims and the interpreter refuses is a
// script the account holder writes and cannot store.
function theBannerDescribesTheInterpreterBehindIt(banner) {
  count("the listener names itself in the capability banner",
    /"IMPLEMENTATION"/.test(banner), visible(banner.slice(0, 120)));
  count("and names the RFC 5804 version it speaks",
    /"VERSION" "1\.0"/.test(banner), visible(banner.slice(0, 120)));

  var sieveLine = (banner.match(/"SIEVE" "([^"]*)"/) || [null, ""])[1];
  var advertised = sieveLine.split(" ").filter(function (n) { return n.length > 0; });
  count("and advertises the extensions a script may require",
    advertised.indexOf("fileinto") !== -1, sieveLine);

  // Every advertised name has to be one the parser will accept in a
  // `require`, or the banner is an invitation to write a script that
  // cannot be stored.
  var refused = advertised.filter(function (name) {
    var script = "require [\"" + name + "\"];\nkeep;\n";
    return b.safeSieve.validate(script, { profile: "strict" }).ok !== true;
  });
  count("and every extension it advertises is one a script may require",
    refused.length === 0, refused.join(", "));

  // The one action that is advertised nowhere is the one this build
  // cannot perform, so an account holder is told at upload rather than
  // finding out from a reply that never went.
  count("and does not advertise an action this build cannot perform",
    advertised.indexOf("vacation") === -1, sieveLine);
}

async function anUnrunnableScriptIsRefusedOnTheWire(session) {
  sendLiteral(session, "PUTSCRIPT \"unparseable\"", "if header :is \"Subject\"",
    "<a script that does not parse>");
  var reply = await replyTo(session, "PUTSCRIPT answered");
  count("a script that does not parse is refused over the wire",
    /^NO/.test(reply), visible(reply));

  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("and the refusal stored nothing",
    listing.indexOf("unparseable") === -1, visible(listing));

  sendLiteral(session, "PUTSCRIPT \"away\"",
    "require [\"vacation\"];\nvacation :days 7 \"back next week\";",
    "<a script requiring an action this build cannot perform>");
  var awayReply = await replyTo(session, "PUTSCRIPT answered");
  count("a script requiring an action the interpreter does not carry is refused at upload",
    /^NO/.test(awayReply), visible(awayReply));
}

async function theScriptSurfaceAnswersOverTheWire(session) {
  var body = "require [\"fileinto\"];\n" +
    "if header :contains \"X-Category\" \"wired\" { fileinto \"Junk\"; }\n";

  sendLiteral(session, "PUTSCRIPT \"over-the-wire\"", body, "<the filter script>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("a script that parses is accepted over the wire", /^OK/.test(stored), visible(stored));

  session.send("LISTSCRIPTS");
  var beforeActivation = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("LISTSCRIPTS names it", beforeActivation.indexOf("\"over-the-wire\"") !== -1,
    visible(beforeActivation));
  count("and marks nothing active while nothing is",
    beforeActivation.indexOf("ACTIVE") === -1, visible(beforeActivation));

  session.send("SETACTIVE \"over-the-wire\"");
  var activated = await replyTo(session, "SETACTIVE answered");
  count("SETACTIVE is accepted", /^OK/.test(activated), visible(activated));

  session.send("LISTSCRIPTS");
  var afterActivation = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("and the listing marks the active one, which is how a client shows it",
    /"over-the-wire" ACTIVE/.test(afterActivation), visible(afterActivation));

  session.send("GETSCRIPT \"over-the-wire\"");
  var fetched = await session.read(ONE_REPLY, "GETSCRIPT answered");
  count("GETSCRIPT returns the body that was uploaded",
    fetched.indexOf("fileinto \"Junk\"") !== -1, visible(fetched));
  count("and frames it as the literal RFC 5804 section 2.9 asks for",
    /\{\d+\}\r\n/.test(fetched), visible(fetched));

  // RFC 5804 section 2.10. Deleting the script a mailbox is filtering
  // by would leave the mailbox filtering by nothing, without the owner
  // asking for that.
  session.send("DELETESCRIPT \"over-the-wire\"");
  var deleted = await replyTo(session, "DELETESCRIPT answered");
  count("the active script cannot be deleted", /^NO/.test(deleted), visible(deleted));

  session.send("HAVESPACE \"another\" 128");
  var roomFor = await replyTo(session, "HAVESPACE answered");
  count("HAVESPACE answers before an upload is attempted", /^OK/.test(roomFor), visible(roomFor));

  session.send("HAVESPACE \"another\" 999999");
  var noRoomFor = await replyTo(session, "HAVESPACE answered");
  count("and refuses a size past the ceiling rather than accepting the upload first",
    /^NO/.test(noRoomFor), visible(noRoomFor));
}

// ---- the octets a script is stored and served as -----------------------------

// Four scripts that differ only in how their last line ends. RFC 5804
// section 4 carries a script as a length-counted literal, so unlike an
// SMTP body nothing about where one ends is inferred from its content,
// and the octets a client counted are the octets it should get back.
//
// The first is what a conforming client sends: ManageSieve literals
// carry CRLF line endings, so a script ending with CRLF is the ordinary
// case rather than an edge one. Every fixture already in this file ends
// with a bare LF, which is the one shape the writer below handles the
// same way in both branches.
var TAIL_SCRIPTS = {
  "tail-crlf":  "require [\"fileinto\"];\r\nkeep;\r\n",
  "tail-lf":    "require [\"fileinto\"];\nkeep;\n",
  "tail-none":  "require [\"fileinto\"];\r\nkeep;",
  "tail-blank": "require [\"fileinto\"];\r\nkeep;\r\n\r\n",
};

// One upload and one read-back, measured as octets. The literal opener
// and the payload are returned as a pair, because the pair is the
// claim: a literal that announces one count and is followed by a
// different number of octets desynchronizes a client's parser whatever
// the payload says.
// The payload is octets rather than text, because one of the callers
// sends a byte no string would survive being turned back into.
async function roundTripOneScript(session, name, payload) {
  // `sendNonSyncLiteral` writes the CRLF that ends the command line
  // after the counted payload, which is where RFC 5804 section 4 puts
  // it and what the listener's reader consumes unconditionally. Sending
  // a second one here would be an empty command line, and the refusal it
  // draws would arrive between this reply and the next.
  session.sendNonSyncLiteral("PUTSCRIPT \"" + name + "\"", payload, "<" + name + ">");
  var stored = await session.read(ONE_REPLY, "PUTSCRIPT answered");
  if (!/^OK/.test(lastReply(stored))) return { accepted: false, reply: lastReply(stored) };

  session.send("GETSCRIPT \"" + name + "\"");
  var raw = await session.readBytes(ONE_REPLY, "GETSCRIPT answered");
  // A latin1 view is one character per octet, so an index into it is an
  // offset into the buffer and the announced count applies directly.
  var opener = /\{(\d+)\}\r\n/.exec(raw.toString("latin1"));
  if (opener === null) return { accepted: true, framed: false, raw: raw };
  var announced = parseInt(opener[1], 10);
  var at = opener.index + opener[0].length;
  var served = raw.subarray(at, at + announced);
  var after  = raw.subarray(at + announced);
  return {
    accepted:    true,
    framed:      true,
    put:         payload,
    announced:   announced,
    served:      served,
    identical:   served.equals(payload),
    crlfFollows: after.length >= 2 && after.subarray(0, 2).toString("latin1") === "\r\n",
    after:       visible(after.toString("latin1").slice(0, 40)),
  };
}

async function theScriptStoredIsTheScriptServed(port, caPem, address) {
  // Its own session, and a binary one, because the octets are the claim
  // and the sessions above read the transcript as text.
  var session = await Wire.managesieve(port, {
    caPem:    caPem,
    servername: HOSTNAME,
    address:  address,
    password: ALICE_PASSWORD,
    label:    "managesieve-octets",
    binary:   true,
  });
  try {
    var names = Object.keys(TAIL_SCRIPTS);
    var results = {};
    for (var i = 0; i < names.length; i += 1) {
      var name = names[i];
      var r = await roundTripOneScript(session, name,
        Buffer.from(TAIL_SCRIPTS[name], "utf8"));
      results[name] = r;
      count(name + ": the upload is accepted and the read-back is framed as the literal " +
        "RFC 5804 section 2.9 asks for",
        r.accepted === true && r.framed === true,
        JSON.stringify({ accepted: r.accepted, framed: r.framed, reply: r.reply }));
      if (r.framed !== true) continue;

      count(name + ": the announced count is the number of octets the client uploaded",
        r.announced === r.put.length,
        "announced " + r.announced + ", uploaded " + r.put.length);
      count(name + ": and those octets are the ones it uploaded, so a script is stored as " +
        "what was counted rather than as what a normalizer made of it",
        r.identical === true,
        "served " + r.served.length + " octets ending " +
          r.served.subarray(-6).toString("hex") + ", uploaded " + r.put.length +
          " ending " + r.put.subarray(-6).toString("hex"));
    }

    // What follows the literal is the CRLF that ends the response line
    // carrying it. RFC 5804 section 4 puts that terminator outside the
    // declared octet count, and this listener's own reader agrees: a
    // PUTSCRIPT literal is followed by a CRLF the listener consumes
    // unconditionally, which is why `roundTripOneScript` sends one.
    //
    // The writer does not answer it the same way. `_handleGetScript` in
    // the vendored ManageSieve listener announces the count and then
    // decides whether to write the terminator by looking at the
    // script's last two octets, so the framing of a response depends on
    // the content of the script inside it. A script ending with CRLF
    // gets no terminator, and a client that reads the announced count
    // and then expects the end of the line reads the next reply instead.
    //
    // The two checks below hold that partition to its exact shape. It
    // cannot be closed here: the writer is in the vendored tree, which
    // is read-only, and the only lever this repository has is the script
    // body the store hands back, so trading the framing defect for a
    // content one by stripping the script's own last line is not a fix.
    // When the writer terminates the line whatever the script ends with,
    // the second check becomes the first and the two collapse into one.
    var terminated   = ["tail-lf", "tail-none"];
    var unterminated = ["tail-crlf", "tail-blank"];
    count("a script whose last line ends in something other than CRLF is followed by the " +
      "terminator that ends the response line carrying it",
      terminated.every(function (n) {
        return results[n].framed === true && results[n].crlfFollows === true;
      }),
      terminated.map(function (n) { return n + " " + results[n].after; }).join(", "));

    count("and a script that ends with CRLF is not, because the writer reads the script's " +
      "last two octets rather than the count it announced, so the next reply begins where " +
      "the end of the line should be",
      unterminated.every(function (n) {
        return results[n].framed === true && results[n].crlfFollows === false;
      }),
      unterminated.map(function (n) { return n + " " + results[n].after; }).join(", "));

    // A literal carrying an octet that cannot begin a UTF-8 sequence.
    // RFC 5804 section 1.6 makes a script a UTF-8 string, so this is
    // malformed input arriving on a wire protocol, and the answer owed
    // to it is a refusal at the point of parse.
    //
    // A substituting decoder would turn the octet into U+FFFD, store a
    // script the client did not send, and answer OK. The account
    // holder's filtering rules would then not be the rules they wrote,
    // and a client that read its own upload back would see a length it
    // cannot account for: the substitution is three octets where the
    // original was one. A Sieve script decides what is filed, forwarded
    // and discarded, so an octet altered inside a string, a header name
    // or an address changes what the rule does.
    //
    // The refusal is in the vendored listener, where the literal is
    // still a buffer. By the time a body reaches this repository it is a
    // string and the octet is already gone, so no composition here could
    // tell a substituted script from one that genuinely contains the
    // replacement character.
    var malformed = Buffer.concat([
      Buffer.from("require [\"fileinto\"];\r\n# ", "ascii"),
      Buffer.from([0xff]),
      Buffer.from("\r\nkeep;\r\n", "ascii"),
    ]);
    var notUtf8 = await roundTripOneScript(session, "tail-not-utf8", malformed);
    count("a script literal carrying an octet that is not well-formed UTF-8 is refused " +
      "rather than repaired, so nothing the client did not send reaches the store",
      notUtf8.accepted === false,
      JSON.stringify({ accepted: notUtf8.accepted, reply: notUtf8.reply }));
    count("and the refusal names what was wrong with it, so an operator can tell this from " +
      "a script that failed Sieve validation",
      /not valid UTF-8/.test(String(notUtf8.reply)),
      JSON.stringify({ reply: notUtf8.reply }));

    for (var d = 0; d < names.length; d += 1) {
      session.send("DELETESCRIPT \"" + names[d] + "\"");
      await session.read(ONE_REPLY, "DELETESCRIPT answered");
    }
    session.send("LOGOUT");
    await session.read(ONE_REPLY, "LOGOUT answered");
  } finally { session.close(); }
}

// The wire grammar is a refusal surface, not a parsing convenience. A
// PUTSCRIPT with no payload announcement, or a verb before
// authentication, is refused at the point of parse.
async function malformedCommandsAreRefused(port, caPem) {
  var session = await Wire.connect(port, "managesieve-malformed");
  await session.read(/^OK[^\r\n]*\r\n/m, "capability banner");

  session.send("LISTSCRIPTS");
  var beforeAuth = await replyTo(session, "LISTSCRIPTS before AUTH answered");
  count("a script verb before authentication is refused",
    /^NO/.test(beforeAuth), visible(beforeAuth));

  session.send("PUTSCRIPT \"nopayload\"");
  var noPayload = await replyTo(session, "PUTSCRIPT with no literal answered");
  count("a PUTSCRIPT that announces no payload is refused rather than left open",
    /^NO/.test(noPayload), visible(noPayload));

  session.send("FROBNICATE \"x\"");
  var unknown = await replyTo(session, "unknown verb answered");
  count("a verb the protocol does not define is refused",
    /^NO/.test(unknown), visible(unknown));

  session.send("LOGOUT");
  await session.read(/^OK/m, "LOGOUT answered");
  session.close();
}

// ---- one account, however its domain is spelled -----------------------------

// The four spellings of one name, written the way
// `test/layer-2-integration/domain-spelling-wire-parity.test.js` writes
// them, so a claim made there and a claim made here are the same claim
// about the same four strings. `EXAMPLE.COM` differs from `example.com`
// only in case, which RFC 4343 says is not a difference, and
// `example.com.` carries the DNS root's dot, which RFC 1035 section 2.3.1
// makes the absolute form of the same name.
function spellingsOf(name) {
  return [
    ["the recorded spelling",     name],
    ["the absolute form",         name + "."],
    ["a difference only in case", name.toUpperCase()],
    ["both at once",              name.toUpperCase() + "."],
  ];
}

// Names that render like the hosted one and are different strings, plus a
// domain this server has never hosted. Without them a file where every
// spelling signs in reads exactly like a listener that admits anything.
var NOT_THIS_DOMAIN = [
  ["a Cyrillic letter standing in for a Latin one", "exаmple.com"],
  ["an ideographic full stop reading as a dot",     "example。com"],
  ["an A-label whose decoded form is not this one", "xn--exmple-4nf.com"],
  ["a domain this server has never hosted",         "notours.example.net"],
];

// The script this file uses to tell one account's session apart from an
// empty one. A verdict on AUTHENTICATE says a credential was accepted and
// says nothing about whose scripts the session then holds.
//
// It is seeded through the store rather than uploaded over the wire, so
// what a spelling reaches is read against a fixture this case owns. A
// witness written by a PUTSCRIPT would make every assertion below depend
// on the upload path as well, and the claim here is about who a
// credential names.
var WITNESS_SCRIPT = "witness";
var WITNESS_BODY   = "require [\"fileinto\"];\nkeep;\n";

// One AUTHENTICATE and its verdict, with the session handed back open.
// The shared ladder throws on a refusal, which is right everywhere except
// the cases whose subject IS the refusal.
async function authenticateAs(port, caPem, label, written) {
  var opened = await manageSieveUpgraded(port, caPem, label);
  sendLiteral(opened.session, "AUTHENTICATE \"PLAIN\"",
    plainResponse(written, ALICE_PASSWORD), "<the SASL response>");
  var verdict = await replyTo(opened.session, "AUTHENTICATE answered");
  return { session: opened.session, verdict: verdict };
}

async function endManageSieve(session) {
  session.send("LOGOUT");
  try { await session.read(ONE_REPLY, "LOGOUT answered"); }
  catch (_e) { /* drop-silent by design: the session's verdict is already read */ }
  session.close();
}

// Both directions of one claim, on the listener an account holder's
// filter rules arrive over. A spelling refused is an account holder
// locked out of the rules that decide where their mail lands, and it is
// silent everywhere except this socket. A spelling admitted as a SECOND
// identity would hand a client an empty script list and let it write a
// set of rules that never runs, which is worse than a refusal because
// nothing anywhere reports it.
async function everySpellingOfTheDomainReachesTheSameAccount(port, caPem, account) {
  var at = account.indexOf("@");
  var localPart = account.slice(0, at);
  var spellings = spellingsOf(account.slice(at + 1));

  for (var i = 0; i < spellings.length; i += 1) {
    var written = localPart + "@" + spellings[i][1];
    var attempt = await authenticateAs(port, caPem, "managesieve-spelling-" + i, written);
    try {
      count("ManageSieve signs the account in when its domain is written as " +
        spellings[i][0] + " (" + written + "), because the identity layer derives the " +
        "mailbox rather than comparing the bytes the client wrote",
        /^OK/.test(attempt.verdict), visible(attempt.verdict));
      if (!/^OK/.test(attempt.verdict)) continue;

      attempt.session.send("LISTSCRIPTS");
      var listing = await attempt.session.read(ONE_REPLY, "LISTSCRIPTS answered");
      count("and the session holds the account's own scripts, so the spelling reached one " +
        "identity rather than opening a second one with an empty script set",
        listing.indexOf("\"" + WITNESS_SCRIPT + "\"") !== -1, visible(listing));
    } finally {
      await endManageSieve(attempt.session);
    }
  }
}

// The control. A name that only renders like the hosted one, and one this
// server has never hosted, are both refused with the NO RFC 5804 section
// 1.2 defines, so the spellings admitted above are a decision about the
// name rather than a listener that admits whatever it is handed.
async function aDomainThisServerDoesNotHostIsRefusedOverManageSieve(port, caPem, account) {
  var localPart = account.slice(0, account.indexOf("@"));
  for (var i = 0; i < NOT_THIS_DOMAIN.length; i += 1) {
    var written = localPart + "@" + NOT_THIS_DOMAIN[i][1];
    var attempt = await authenticateAs(port, caPem, "managesieve-not-ours-" + i, written);
    try {
      count("ManageSieve refuses a credential naming " + NOT_THIS_DOMAIN[i][0] +
        ", rather than opening the script set of the account it is drawn to look like",
        /^NO/.test(attempt.verdict), visible(attempt.verdict));

      attempt.session.send("LISTSCRIPTS");
      var listing = await attempt.session.read(ONE_REPLY, "LISTSCRIPTS answered");
      count("and the refused session reaches no script set",
        /^NO/.test(lastReply(listing)), visible(listing));
    } finally {
      await endManageSieve(attempt.session);
    }
  }
}

// ---- the end to end claim ---------------------------------------------------

async function deliver(mxPort, caPem, to, category) {
  var peer = await Wire.connect(mxPort, "mx-deliver");
  await peer.read(/^220 /m, "banner");
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted");
  peer.send("STARTTLS");
  await peer.read(/^220 /m, "STARTTLS accepted");
  await peer.upgrade(caPem, HOSTNAME);
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted over TLS");
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: " + PEER,
    "To: " + to,
    "Subject: " + category,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + category.replace(/[^a-z0-9]/gi, "") + "@example.net>",
    "X-Category: " + category,
    "",
    "Body of " + category + ".",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

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

async function heldBy(port, caPem, address, folder, label) {
  var session = await imapSession(port, caPem, address, label);
  session.send("b1 STATUS \"" + folder + "\" (MESSAGES)");
  var reply = await session.read(/^b1 (OK|NO|BAD)/m, "STATUS answered");
  session.send("b2 LOGOUT");
  session.close();
  var match = reply.match(/MESSAGES (\d+)/);
  return match === null ? -1 : parseInt(match[1], 10);
}

// The three pieces joined up. A script the account holder uploaded from
// their own client, activated from their own client, deciding where a
// stranger's message lands.
async function aScriptUploadedOverTheWireFilesRealMail(ports, caPem, address) {
  var junkBefore  = await heldBy(ports.imap, caPem, address, "Junk", "junk-before");
  var inboxBefore = await heldBy(ports.imap, caPem, address, "INBOX", "inbox-before");

  var reply = await deliver(ports.mx, caPem, address, "wired");
  count("the peer's message is accepted", /^250 /m.test(reply), visible(reply));

  await helpers.waitUntil(function () {
    return heldBy(ports.imap, caPem, address, "Junk", "junk-poll")
      .then(function (n) { return n > junkBefore; });
  }, {
    timeoutMs: 8000,
    label:     "sieve-managesieve-wire: the message reaching the folder the script named",
  });

  var inboxAfter = await heldBy(ports.imap, caPem, address, "INBOX", "inbox-after");
  count("and it is not also left in INBOX", inboxAfter === inboxBefore,
    "before " + inboxBefore + ", after " + inboxAfter);
}

// A script inside every storage ceiling can still ask the interpreter
// for more work than it will do. The message is what must not pay for
// that: it lands in INBOX, and the operator gets a line saying why.
async function aScriptThatOutrunsItsBudgetKeepsTheMessage(session, ports, caPem, address) {
  var expensive = new Array(GAS_CAP + 501).join("keep;\n");
  sendLiteral(session, "PUTSCRIPT \"expensive\"", expensive, "<a script that outruns the budget>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("a script that outruns the interpreter budget is inside the storage ceiling",
    /^OK/.test(stored), visible(stored));

  session.send("SETACTIVE \"expensive\"");
  var activated = await replyTo(session, "SETACTIVE answered");
  count("and it can be made the active script", /^OK/.test(activated), visible(activated));

  var inboxBefore = await heldBy(ports.imap, caPem, address, "INBOX", "inbox-before-budget");
  var reply = await deliver(ports.mx, caPem, address, "budget");
  count("the peer's message is still accepted", /^250 /m.test(reply), visible(reply));

  await helpers.waitUntil(function () {
    return heldBy(ports.imap, caPem, address, "INBOX", "inbox-poll-budget")
      .then(function (n) { return n === inboxBefore + 1; });
  }, {
    timeoutMs: 8000,
    label:     "sieve-managesieve-wire: the message reaching INBOX when the script runs out",
  });
  count("and the message is delivered to INBOX rather than lost with the script", true);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sieve-wire");
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
  var opened   = null;

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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "sieve wire test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // The witness a spelling has to reach. Written under the address the
    // account row carries, so a session opened by any other spelling of
    // that address either lists it or is not this account's session.
    // `b.permissions` reads a scopes array in preference to roles, so the
    // actor carries roles and no scopes, which is the shape a signed in
    // session holds.
    identity.mailbox.sieveScripts.put({
      id:        alice.id,
      username:  alice.address,
      address:   alice.address,
      domain:    alice.domain,
      isAdmin:   false,
      mailboxes: [alice.address],
      roles:     ["account"],
    }, WITNESS_SCRIPT, WITNESS_BODY);

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
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
      managesieve: sections.managesieve.port,
    };

    opened = await manageSieveSession(ports.managesieve, leaf.ca, alice.address, "managesieve");
    count("an account signs in over ManageSieve", /^OK/.test(opened.authReply),
      visible(opened.authReply));

    await oneAuthenticateDrawsOneReply(ports.managesieve, leaf.ca, alice.address);
    await theChallengePathCompletes(ports.managesieve, leaf.ca, alice.address);
    await theExchangeIsCancellable(ports.managesieve, leaf.ca, alice.address);
    theBannerDescribesTheInterpreterBehindIt(opened.banner);
    await everySpellingOfTheDomainReachesTheSameAccount(ports.managesieve, leaf.ca,
      alice.address);
    await aDomainThisServerDoesNotHostIsRefusedOverManageSieve(ports.managesieve, leaf.ca,
      alice.address);
    await onePutscriptDrawsOneReply(opened.session);
    await anUnrunnableScriptIsRefusedOnTheWire(opened.session);
    await theScriptSurfaceAnswersOverTheWire(opened.session);
    await theScriptStoredIsTheScriptServed(ports.managesieve, leaf.ca, alice.address);
    await malformedCommandsAreRefused(ports.managesieve, leaf.ca);
    await aScriptUploadedOverTheWireFilesRealMail(ports, leaf.ca, alice.address);
    await aScriptThatOutrunsItsBudgetKeepsTheMessage(opened.session, ports, leaf.ca,
      alice.address);

    opened.session.send("LOGOUT");
    await opened.session.read(/^OK/m, "LOGOUT answered");
    opened.session.close();
    opened = null;

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (opened && opened.session) opened.session.close();
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

module.exports = { name: "sieve-managesieve-wire", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
