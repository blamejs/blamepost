// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Message building against the standards a receiver actually enforces.
 *
 * Composition is the half no framework ships, so every rule in RFC 5322
 * and RFC 2045 is one this repository has to keep on its own. The
 * vectors below are the ones where getting it wrong is invisible from
 * the sending side: the message leaves, the log says delivered, and the
 * damage shows up as a body a receiver decoded differently, a recipient
 * nobody addressed, or a reply that starts a new conversation.
 *
 * Four properties carry most of the weight.
 *
 * Nothing a caller supplies may reach the wire as structure. A header
 * value carrying CR or LF is the classic way to forge a second header,
 * and a caller-supplied header name is the same hole one level up: a
 * `Bcc` written that way defeats the blind copy the module promises.
 *
 * An address header that has been through RFC 2047 decoding is no
 * longer splittable on the separator. The decoder turns an encoded
 * display name back into text, and that text may contain a comma, so a
 * comma alone can no longer tell an address boundary from somebody's
 * surname. Reading it as a boundary either loses the reply or gains a
 * recipient the sender never chose.
 *
 * Quoted-printable has two rules that look cosmetic and are not.
 * Whitespace at the end of an encoded line is stripped in transit, and
 * a line that begins `From ` or `.` is rewritten by stores and
 * transports along the way. Both change the bytes the reader sees.
 *
 * A message carries a ceiling, not each attachment separately. The
 * per-attachment check passes for every one of a hundred large parts.
 *
 * Run standalone: node test/layer-0-primitives/compose-conformance.test.js
 */

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var BYTES = b.constants.BYTES;

// A delivery handle that records envelopes instead of dialling anyone.
function collectingDelivery(sent) {
  return {
    send: function (envelope) {
      sent.push(envelope);
      return Promise.resolve({
        delivered: envelope.to.map(function (r) { return { recipient: r }; }),
        deferred:  [],
        failed:    [],
      });
    },
    bounce: function () { return Promise.resolve({}); },
  };
}

function refuses(label, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  check(label + (thrown ? "" : " (it was accepted)"), thrown !== null);
  return thrown;
}

async function refusesAsync(label, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  check(label + (thrown ? "" : " (it was accepted)"), thrown !== null);
  return thrown;
}

// A header line has to be readable by a receiver that speaks no
// encoding at all, so every byte in one is inside US-ASCII.
function _asciiOnly(line) {
  for (var i = 0; i < line.length; i += 1) {
    if (line.charCodeAt(i) > 127) return false;
  }
  return true;
}

// The longest physical line in a built message, in octets, which is
// the unit RFC 5322 section 2.1.1 counts in.
function longestLine(wire) {
  return wire.split("\r\n").reduce(function (longest, line) {
    var octets = Buffer.byteLength(line, "utf8");
    return octets > longest ? octets : longest;
  }, 0);
}

function bodyOf(built) {
  var text = built.rfc822.toString("utf8");
  var split = text.indexOf("\r\n\r\n");
  return split === -1 ? "" : text.slice(split + 4);
}

// One header value, unfolded the way RFC 5322 section 2.2.3 says a
// reader unfolds it, so an assertion reads what the receiver reads
// rather than the first physical line.
function headerValue(built, name) {
  var lines = built.headers.split("\r\n");
  var wanted = name.toLowerCase() + ":";
  var value = null;
  for (var i = 0; i < lines.length; i += 1) {
    if (value !== null) {
      if (/^[ \t]/.test(lines[i])) { value += lines[i].replace(/^[ \t]+/, " "); continue; }
      break;
    }
    if (lines[i].toLowerCase().indexOf(wanted) === 0) {
      value = lines[i].slice(wanted.length).replace(/^[ \t]+/, "");
    }
  }
  return value;
}

// The first occurrence of one header anywhere in a built message, part
// headers included, unfolded the way a receiver unfolds it.
function unfoldedLine(wire, name) {
  var lines = wire.split("\r\n");
  var wanted = name.toLowerCase() + ":";
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].toLowerCase().indexOf(wanted) !== 0) continue;
    var value = lines[i];
    for (var j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]); j += 1) {
      value += lines[j].replace(/^[ \t]+/, " ");
    }
    return value;
  }
  return "";
}

// An encoded word carrying `text`, as the sender's client would write
// it. The point of every vector below that uses one is that the decoder
// hands the composer back plain text with the quoting gone.
function encodedWord(text) {
  return "=?UTF-8?B?" + Buffer.from(text, "utf8").toString("base64") + "?=";
}

function messageWith(headers, bodyText) {
  return headers.concat(["", bodyText, ""]).join("\r\n");
}

// ---- the envelope sender ---------------------------------------------------

// Every other address in a message is validated, and this is the one
// that becomes `MAIL FROM` on the wire. The outbound composer asks only
// that it be a non-empty string, so nothing between the caller and the
// peer reads its shape.
function theReturnPathIsValidated(compose) {
  refuses("an envelope sender that is not an address is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      envelopeFrom: "not an address at all",
    });
  });

  refuses("an envelope sender carrying a second command is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      envelopeFrom: "alice@example.com>\r\nRCPT TO:<victim@example.org",
    });
  });

  var nullPath = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    envelopeFrom: "",
  });
  check("the empty reverse path RFC 5321 section 4.5.5 defines still passes",
    nullPath.envelopeFrom === "");

  var explicit = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    envelopeFrom: "bounces@example.com",
  });
  check("an ordinary return path is carried through",
    explicit.envelopeFrom === "bounces@example.com");
}

// ---- caller-supplied headers -----------------------------------------------

// The `headers` option is the one place a caller writes a header name
// as well as a value. A name the composer writes itself arrives twice,
// and `Bcc` written this way lands on the wire copy, which is the one
// guarantee the blind copy has.
function suppliedHeadersCannotForgeStructure(compose) {
  refuses("a supplied Bcc header cannot reach the wire copy", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], bcc: ["dave@example.net"],
      text: "hello", headers: { Bcc: "leaked@example.org" },
    });
  });

  refuses("a supplied header cannot duplicate the subject the composer wrote", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], subject: "Lunch",
      text: "hello", headers: { Subject: "something else" },
    });
  });

  refuses("a supplied header cannot restate the MIME structure", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  });

  refuses("a supplied header name that is not a field name is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      headers: { "X Category": "reports" },
    });
  });

  var built = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    headers: { "X-Category": "reports" },
  });
  check("a header the composer does not own still rides",
    headerValue(built, "X-Category") === "reports");
}

// ---- MIME structure --------------------------------------------------------

// RFC 2387 section 3.1: the `type` parameter names the media type of
// the root part, and a receiver uses it to decide which part to render
// first. Naming the wrong one sends a reader to a part that is not
// there.
function theRelatedRootIsNamedCorrectly(compose) {
  var htmlOnly = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    html: "<p><img src=\"cid:logo\"></p>",
    attachments: [{ filename: "logo.png", content: Buffer.from("PNG"),
                    contentType: "image/png", cid: "logo" }],
  });
  count("a related part whose root is html says so in its type parameter",
    /type="text\/html"/.test(headerValue(htmlOnly, "Content-Type")),
    headerValue(htmlOnly, "Content-Type"));

  var both = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    text: "plain", html: "<p><img src=\"cid:logo\"></p>",
    attachments: [{ filename: "logo.png", content: Buffer.from("PNG"),
                    contentType: "image/png", cid: "logo" }],
  });
  count("a related part wrapping both bodies names the alternative",
    /type="multipart\/alternative"/.test(headerValue(both, "Content-Type")),
    headerValue(both, "Content-Type"));
}

// ---- quoted-printable ------------------------------------------------------

// RFC 2045 section 6.7 rule 3: a space or tab may not sit at the end of
// an encoded line. Every transport along the way strips it, so the
// reader gets two words run together.
function quotedPrintableKeepsEveryByte(compose) {
  var built = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    text: "word ".repeat(40),
  });
  var body = bodyOf(built);
  count("no encoded line ends in whitespace before its soft break",
    !/[ \t]=\r\n/.test(body),
    (body.match(/.{0,12}[ \t]=\r\n/) || ["none"])[0]);
  check("no encoded line exceeds the 76 character limit",
    body.split("\r\n").every(function (line) { return line.length <= 76; }));

  // A store that keeps messages in mbox form rewrites a body line
  // beginning `From `, and a transport dot-stuffs one beginning with a
  // period. Encoding the first character leaves neither anything to
  // rewrite.
  var risky = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    text: "From nowhere in particular\r\n.hidden line\r\nordinary line",
  });
  var riskyBody = bodyOf(risky);
  count("a body line beginning From has that F encoded",
    riskyBody.indexOf("=46rom nowhere") !== -1, JSON.stringify(riskyBody.slice(0, 40)));
  count("a body line beginning with a period has it encoded",
    riskyBody.indexOf("=2Ehidden line") !== -1, JSON.stringify(riskyBody.slice(0, 80)));
  check("an ordinary line beside them is untouched",
    riskyBody.indexOf("ordinary line") !== -1);

  // Whitespace at the end of a short ASCII line does not survive
  // either: transports trim it, and RFC 6376 section 3.4.2 relaxed
  // canonicalization trims it before the DKIM signature is computed.
  var trailing = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    text: "signed off \r\nand the next line",
  });
  var trailingWire = trailing.rfc822.toString("utf8");
  count("a body line ending in whitespace is encoded rather than emitted raw",
    /Content-Transfer-Encoding: quoted-printable/.test(trailingWire),
    (trailingWire.match(/Content-Transfer-Encoding: [^\r\n]*/) || [""])[0]);
  count("and the whitespace is carried as its escape",
    bodyOf(trailing).indexOf("signed off=20") !== -1, JSON.stringify(bodyOf(trailing)));
}

// The message has already left by the time the sender's copy is
// written. Reporting a failure there as a send failure is how a caller
// answers by sending it a second time.
async function afiledCopyThatCannotBeWrittenIsNotASendFailure(sent) {
  var refusingStore = {
    appendMessage: function () { throw new Error("quota exceeded on the Sent folder"); },
  };
  var compose = blamepost.mail.compose.create({
    delivery:  collectingDelivery(sent),
    hostname:  "mx.example.com",
    mailStore: refusingStore,
  });

  var before = sent.length;
  var result = await compose.send({
    from: "alice@example.com", to: ["bob@example.net"], subject: "Lunch", text: "One o'clock?",
  });
  check("the message still went", sent.length === before + 1);
  count("the caller is told the copy was not filed rather than that the send failed",
    result.filed === null, JSON.stringify(result.filed));
  count("and the message id is still the one that left",
    typeof result.messageId === "string" && result.messageId.charAt(0) === "<",
    result.messageId);
}

// ---- threading -------------------------------------------------------------

// RFC 5322 section 3.6.4 puts no cap on References, and a receiver's
// header size limit does. The chain is trimmed where it is written, so
// every caller inherits the bound rather than the two that remembered.
function theReferenceChainIsBounded(compose) {
  var many = [];
  for (var i = 0; i < 200; i += 1) many.push("<id" + i + "@example.net>");
  var built = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    references: many,
  });
  var value = headerValue(built, "References");
  var ids = value.match(/<[^>]+>/g) || [];
  count("a chain longer than the cap is trimmed where the header is written",
    ids.length <= 20, "carried " + ids.length);
  count("the root of the conversation is kept so the thread stays anchored",
    ids[0] === "<id0@example.net>", ids[0]);
  count("the most recent ancestor is kept so the position resolves",
    ids[ids.length - 1] === "<id199@example.net>", ids[ids.length - 1]);
}

// ---- attachments -----------------------------------------------------------

// The ceiling is a property of the message. Checking it per attachment
// lets any number of parts each pass and the message as a whole exceed
// what a receiver will take.
function theMessageCarriesOneCeiling(compose) {
  var half = Buffer.alloc(BYTES.mib(20), 0x41);
  var one = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    attachments: [{ filename: "one.dat", content: half }],
  });
  check("one attachment inside the ceiling is built", one.rfc822.length > BYTES.mib(20));

  refuses("two attachments that together pass the ceiling are refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      attachments: [
        { filename: "one.dat", content: half },
        { filename: "two.dat", content: half },
      ],
    });
  });
}

// A filename is a MIME parameter here, never a path this server opens,
// so the screening that matters is what a receiver's parser will do
// with it. Names an operator sends every day have to go, and the shapes
// that mislead a reader or forge a header have to stop.
function attachmentNamesAreScreenedForTheHeaderTheyEnter(compose) {
  var ordinary = ["backup.tar.gz", "firmware.bin", "helper.js", "quarterly report.pdf"];
  ordinary.forEach(function (name) {
    var built = compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      attachments: [{ filename: name, content: Buffer.from("x") }],
    });
    check("an ordinary attachment named " + name + " is carried",
      built.rfc822.toString("utf8").indexOf(name) !== -1);
  });

  refuses("a filename carrying a line break cannot forge a header", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      attachments: [{ filename: "notes.pdf\r\nBcc: leaked@example.org", content: Buffer.from("x") }],
    });
  });
  refuses("a filename with a path in it is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      attachments: [{ filename: "../../etc/passwd", content: Buffer.from("x") }],
    });
  });
  refuses("a filename with a direction override is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "hello",
      attachments: [{ filename: "harmless‮gpj.exe", content: Buffer.from("x") }],
    });
  });

  // RFC 2231 section 4 is how a parameter carries a name outside ASCII.
  // Writing the raw bytes into the header instead is what a receiver
  // rejects, and refusing the attachment outright is what an account
  // holder reports as the server losing their file.
  var accented = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    attachments: [{ filename: "résumé.pdf", content: Buffer.from("x") }],
  });
  var wire = accented.rfc822.toString("utf8");
  var disposition = unfoldedLine(wire, "Content-Disposition");
  count("a name outside ASCII is carried as an RFC 2231 parameter",
    /filename\*=UTF-8''/.test(disposition), disposition);
  count("and the parameter percent-encodes the bytes outside the token set",
    /r%C3%A9sum%C3%A9\.pdf/.test(disposition), disposition);
  count("and no header line anywhere in the message leaves ASCII",
    wire.split("\r\n").filter(function (line) { return /^[A-Za-z-]+:/.test(line); })
      .every(function (line) { return _asciiOnly(line); }),
    disposition);

  // RFC 2231 section 3 splits a parameter too long for a line into
  // numbered segments, with the charset prefix on the first alone. A
  // name whose percent-encoded form is longer than a line has no other
  // conforming representation.
  var longName = new Array(80).join(String.fromCodePoint(0x65e5)) + ".pdf";
  var long = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    attachments: [{ filename: longName, content: Buffer.from("x") }],
  });
  var longWire = long.rfc822.toString("utf8");
  var longDisposition = unfoldedLine(longWire, "Content-Disposition");
  count("a name too long for one parameter is continued across numbered segments",
    /filename\*0\*=UTF-8''/.test(longDisposition) && /filename\*1\*=/.test(longDisposition),
    longDisposition.slice(0, 160));
  count("and only the first segment carries the charset",
    (longDisposition.match(/UTF-8''/g) || []).length === 1, longDisposition.slice(0, 160));
  count("and no line of the message passes the RFC 5322 limit of 998 octets",
    longestLine(longWire) <= 998, String(longestLine(longWire)));
}

// A run of characters with no whitespace in it has no fold point, so a
// long one cannot go out as written. Encoded words are what it becomes,
// because a sequence of them folds where the run could not.
function anUnfoldableRunIsEncodedRatherThanEmittedLong(compose) {
  var token = new Array(1400).join("q");

  var subject = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello", subject: token,
  });
  count("a subject with no fold point in it does not produce an over-length line",
    longestLine(subject.rfc822.toString("utf8")) <= 998,
    String(longestLine(subject.rfc822.toString("utf8"))));
  count("and it travels as encoded words, which fold",
    /=\?UTF-8\?B\?/.test(headerValue(subject, "Subject")),
    headerValue(subject, "Subject").slice(0, 80));

  var supplied = compose.build({
    from: "alice@example.com", to: ["bob@example.net"], text: "hello",
    headers: { "X-Token": token },
  });
  count("a supplied header value gets the same treatment",
    longestLine(supplied.rfc822.toString("utf8")) <= 998,
    String(longestLine(supplied.rfc822.toString("utf8"))));

  // The bytes still have to survive it, or the fold is a rewrite. RFC
  // 2047 section 6.2: adjacent encoded words are decoded one at a time
  // and the whitespace between them is discarded.
  var words = headerValue(supplied, "X-Token").match(/=\?UTF-8\?B\?([^?]*)\?=/g) || [];
  var decoded = words.map(function (word) {
    return Buffer.from(word.slice("=?UTF-8?B?".length, -2), "base64").toString("utf8");
  }).join("");
  count("and the value comes back byte for byte", decoded === token,
    decoded.length + " of " + token.length + " across " + words.length + " word(s)");
}

// ---- reading the message being answered ------------------------------------

// The parser hands back header values with RFC 2047 encoded words
// already decoded, and the decoder does not restore the quoting the
// encoding replaced. So a display name that decoded to `Doe, John` is
// indistinguishable from two addresses, and reading the comma as a
// boundary turns one recipient into a fragment nobody can deliver to.
async function aDecodedDisplayNameIsNotAnAddressBoundary(compose, sent) {
  var original = messageWith([
    "From: " + encodedWord("Doe, John") + " <john@example.net>",
    "To: bob@example.com",
    "Subject: Quarterly",
    "Message-ID: <parent@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  ], "the original body");

  await compose.reply({ original: original, from: "bob@example.com", text: "noted" });
  var envelope = sent[sent.length - 1];
  count("a reply to a sender whose decoded name carries a comma still goes",
    envelope.to.length === 1, JSON.stringify(envelope.to));
  count("and it goes to the sender rather than to a fragment of their name",
    envelope.to[0] === "john@example.net", JSON.stringify(envelope.to));

  // The same ambiguity read the other way. An address planted in the
  // display name becomes a second recipient of a reply that quotes the
  // conversation back.
  var crafted = messageWith([
    "From: " + encodedWord("accounts@example.org, Finance") + " <john@example.net>",
    "To: bob@example.com",
    "Subject: Quarterly close",
    "Message-ID: <crafted@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  ], "confidential body");

  await compose.reply({ original: crafted, from: "bob@example.com", text: "noted" });
  var craftedEnvelope = sent[sent.length - 1];
  count("an address planted in a decoded display name is not a recipient",
    craftedEnvelope.to.indexOf("accounts@example.org") === -1,
    JSON.stringify(craftedEnvelope.to));
  count("and the reply still reaches the real sender",
    craftedEnvelope.to.indexOf("john@example.net") !== -1,
    JSON.stringify(craftedEnvelope.to));
}

// A quoted display name is the case the decoder leaves alone, and it
// has to keep working: this is the reading that was already right and
// must survive the fix for the one that was not.
async function aQuotedDisplayNameStillSplitsCorrectly(compose, sent) {
  var original = messageWith([
    "From: \"Doe, John\" <john@example.net>",
    "To: \"Smith, Ann\" <ann@example.org>, bob@example.com",
    "Subject: Quarterly",
    "Message-ID: <quoted@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  ], "the original body");

  await compose.reply({
    original: original, from: "bob@example.com", text: "noted", replyAll: true,
  });
  var envelope = sent[sent.length - 1];
  count("a quoted name carrying a comma is still one recipient",
    envelope.to.indexOf("john@example.net") !== -1, JSON.stringify(envelope.to));
  count("reply-all keeps the other party",
    envelope.to.indexOf("ann@example.org") !== -1, JSON.stringify(envelope.to));
  count("and drops the replying identity",
    envelope.to.indexOf("bob@example.com") === -1, JSON.stringify(envelope.to));

  // RFC 5322 section 3.2.1 quoted-pair. A display name that ends in a
  // literal backslash still ends at its closing quote, and reading that
  // quote as escaped leaves the rest of the header inside a string that
  // never closes, taking every recipient after it with it.
  var backslash = messageWith([
    "From: sales@example.net",
    "To: \"Prices \\\\\" <john@example.net>, ann@example.org",
    "Subject: Quarterly",
    "Message-ID: <escaped@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  ], "the original body");

  await compose.reply({
    original: backslash, from: "bob@example.com", text: "noted", replyAll: true,
  });
  var escapedEnvelope = sent[sent.length - 1];
  count("a display name ending in a backslash does not swallow the recipients after it",
    escapedEnvelope.to.indexOf("ann@example.org") !== -1,
    JSON.stringify(escapedEnvelope.to));
  count("and the one it belongs to is still read correctly",
    escapedEnvelope.to.indexOf("john@example.net") !== -1,
    JSON.stringify(escapedEnvelope.to));
}

// RFC 5322 section 3.4 group syntax, which bulk mail puts in `To` as
// `undisclosed-recipients:;` on more or less every list message an
// account holder receives. It names nobody, and reading it as an
// address is a reply-all that cannot be sent at all.
async function groupSyntaxNamesNobodyRatherThanOneBrokenAddress(compose, sent) {
  var original = messageWith([
    "From: list@example.net",
    "To: undisclosed-recipients:;",
    "Cc: Managers: ann@example.org, bob@example.com;",
    "Subject: Notice",
    "Message-ID: <group@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  ], "the original body");

  await compose.reply({
    original: original, from: "bob@example.com", text: "noted", replyAll: true,
  });
  var envelope = sent[sent.length - 1];
  count("an empty group contributes no recipient",
    envelope.to.indexOf("undisclosed-recipients:;") === -1, JSON.stringify(envelope.to));
  count("a group with members contributes its members",
    envelope.to.indexOf("ann@example.org") !== -1, JSON.stringify(envelope.to));
  count("and the group label is not carried as one of them",
    envelope.to.every(function (address) { return address.indexOf(":") === -1; }),
    JSON.stringify(envelope.to));
  count("and the reply still reaches the sender",
    envelope.to.indexOf("list@example.net") !== -1, JSON.stringify(envelope.to));
}

// The quoted original is somebody else's markup traveling onward under
// this account's name. It goes to a third party and it is filed in the
// sender's own mailbox, so it is screened before it is quoted rather
// than trusted because it arrived.
async function quotedMarkupIsScreened(compose, sent) {
  var original = messageWith([
    "From: john@example.net",
    "To: bob@example.com",
    "Subject: Look",
    "Message-ID: <markup@example.net>",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
  ], "<p>hello<script>fetch('https://example.org')</scr" +
     "ipt><img src=x onerror=\"fetch('https://example.org')\"></p>");

  await compose.reply({
    original: original, from: "bob@example.com", html: "<p>noted</p>", text: "noted",
  });
  var wire = sent[sent.length - 1].rfc822.toString("utf8");
  check("a script tag in the quoted original does not travel onward",
    wire.indexOf("<script") === -1);
  check("an event handler in the quoted original does not travel onward",
    wire.indexOf("onerror") === -1);
  check("and the quoted markup is still there",
    wire.indexOf("blockquote") !== -1);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var sent = [];
  var compose = blamepost.mail.compose.create({
    delivery: collectingDelivery(sent),
    hostname: "mx.example.com",
  });

  theReturnPathIsValidated(compose);
  suppliedHeadersCannotForgeStructure(compose);
  theRelatedRootIsNamedCorrectly(compose);
  quotedPrintableKeepsEveryByte(compose);
  theReferenceChainIsBounded(compose);
  theMessageCarriesOneCeiling(compose);
  attachmentNamesAreScreenedForTheHeaderTheyEnter(compose);
  anUnfoldableRunIsEncodedRatherThanEmittedLong(compose);
  await aDecodedDisplayNameIsNotAnAddressBoundary(compose, sent);
  await aQuotedDisplayNameStillSplitsCorrectly(compose, sent);
  await groupSyntaxNamesNobodyRatherThanOneBrokenAddress(compose, sent);
  await quotedMarkupIsScreened(compose, sent);
  await afiledCopyThatCannotBeWrittenIsNotASendFailure(sent);

  // The async refusal helper is used by no vector above today. It stays
  // wired so the next reply-side refusal has the same shape as the
  // build-side ones rather than growing a second convention.
  await refusesAsync("a reply with no original message bytes is refused", function () {
    return compose.reply({ from: "bob@example.com", text: "noted" });
  });

  return helpers.getChecks();
}

module.exports = { name: "compose-conformance", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
