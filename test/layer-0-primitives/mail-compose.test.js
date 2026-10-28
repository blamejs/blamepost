// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Message composition, the outbound spool, and the checks that read DNS
 * without needing any of it to be live.
 *
 * Composition is pure: bytes in, bytes out, so the wire format is
 * asserted directly rather than through a listener. The spool needs a
 * temporary directory and nothing else. The posture checker reads a
 * resolver that answers from a fixed table, because the point of these
 * vectors is the verdict a given zone produces, and a real zone cannot
 * be made to publish a wrong record on demand.
 *
 * Run standalone: node test/layer-0-primitives/mail-compose.test.js
 */

var helpers   = require("../helpers");
var blamepost = require("../../lib");

var check = helpers.check;

// A delivery handle that records envelopes instead of dialling anyone.
// Composition's contract is what it hands the outbound path, and that
// is exactly what this captures.
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

function collectingStore(filed) {
  return {
    appendMessage: function (folder, bytes, opts) {
      filed.push({ folder: folder, bytes: bytes, opts: opts });
      return { objectid: "obj_test", modseq: filed.length };
    },
  };
}

function refuses(label, fn) {
  var thrown = false;
  try { fn(); } catch (_e) { thrown = true; }
  check(label, thrown);
}

// What a call threw, or the empty string when it returned. Beside
// `refuses` rather than inside it, because a refusal that arrives for
// the wrong reason is indistinguishable from the right one when all that
// is read is whether something was thrown.
function refusalFrom(fn) {
  try { fn(); }
  catch (e) { return (e && e.message) || String(e); }
  return "";
}

async function run() {
  var sent  = [];
  var filed = [];
  var compose = blamepost.mail.compose.create({
    delivery:  collectingDelivery(sent),
    hostname:  "mx.example.com",
    mailStore: collectingStore(filed),
  });

  // ---- the header set ------------------------------------------------------

  var built = compose.build({
    from:    { name: "Alice Ünicode", address: "alice@example.com" },
    to:      ["bob@example.net"],
    cc:      ["carol@example.org"],
    bcc:     ["dave@example.net"],
    subject: "Lunch on Tuesday, Grüße?",
    text:    "One o'clock?\nSee you then.\n",
    html:    "<p>One o'clock?</p>",
    attachments: [
      { filename: "note.txt", content: Buffer.from("hello"), contentType: "text/plain" },
    ],
  });
  var wire = built.rfc822.toString("utf8");
  var copy = built.filed.toString("utf8");

  // Blind copies belong in the envelope and nowhere else on the wire.
  // The sender's own copy is the one place they are meant to be
  // readable, which is why the two differ.
  check("bcc is absent from the wire copy", wire.indexOf("Bcc:") === -1);
  check("bcc is present in the filed copy", copy.indexOf("Bcc: dave@example.net") !== -1);
  check("the envelope carries to, cc and bcc", built.recipients.length === 3);

  check("a non-ASCII display name becomes an encoded word",
    /^From: =\?UTF-8\?B\?/m.test(wire));
  check("a non-ASCII subject becomes an encoded word",
    /^Subject: =\?UTF-8\?B\?/m.test(wire));
  check("the date carries a numeric zone offset",
    /^Date: [A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000$/m.test(wire));
  check("the message id is bracketed and on the From domain",
    /^Message-ID: <[0-9a-f]+@example\.com>$/m.test(wire));
  check("MIME-Version is declared", /^MIME-Version: 1\.0$/m.test(wire));

  check("attachments produce multipart/mixed",
    wire.indexOf("Content-Type: multipart/mixed;") !== -1);
  check("text and html produce multipart/alternative",
    wire.indexOf("Content-Type: multipart/alternative;") !== -1);
  check("the attachment part carries its disposition and filename",
    wire.indexOf('Content-Disposition: attachment; filename="note.txt"') !== -1);
  check("every line ends CRLF", wire.indexOf("\r\n") !== -1 && wire.indexOf("\n\n") === -1);

  var longest = wire.split("\r\n").reduce(function (m, l) { return Math.max(m, l.length); }, 0);
  check("no line exceeds the RFC 5322 limit of 998 octets", longest <= 998);

  // ---- transfer encoding chosen from the content ---------------------------

  var accented = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    subject: "plain", text: "Grüße aus München\n",
  }).rfc822.toString("utf8");
  check("a body outside ASCII is quoted-printable",
    accented.indexOf("Content-Transfer-Encoding: quoted-printable") !== -1);
  check("quoted-printable encodes the high bytes",
    accented.indexOf("Gr=C3=BC=C3=9Fe") !== -1);

  var plain = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    subject: "plain", text: "short line\n",
  }).rfc822.toString("utf8");
  check("a plain ASCII body inside the line limit stays 7bit",
    plain.indexOf("Content-Transfer-Encoding: 7bit") !== -1);

  var wrapped = compose.build({
    from: "alice@example.com", to: ["bob@example.net"],
    subject: "long", text: new Array(400).join("x") + "\n",
  }).rfc822.toString("utf8");
  check("a body line past the soft limit is wrapped rather than emitted long",
    wrapped.split("\r\n").every(function (l) { return l.length <= 998; }));

  // ---- header injection ----------------------------------------------------

  // A newline inside a header value smuggles a second header, and Bcc
  // is the one an attacker reaches for. Every field that reaches the
  // wire is checked, not only the obvious one.
  refuses("CRLF in a subject is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"],
      subject: "hi\r\nBcc: mallory@example.net", text: "x",
    });
  });
  refuses("CRLF in a display name is refused", function () {
    compose.build({
      from: { name: "Alice\r\nBcc: mallory@example.net", address: "alice@example.com" },
      to: ["bob@example.net"], text: "x",
    });
  });
  refuses("CRLF in an extra header value is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "x",
      headers: { "X-Note": "one\r\nBcc: mallory@example.net" },
    });
  });
  refuses("an address the guard refuses is refused", function () {
    compose.build({ from: "alice@example.com", to: ["not an address"], text: "x" });
  });
  refuses("a message with no recipient is refused", function () {
    compose.build({ from: "alice@example.com", text: "x" });
  });
  refuses("a message with no body is refused", function () {
    compose.build({ from: "alice@example.com", to: ["bob@example.net"] });
  });
  refuses("an attachment filename the guard refuses is refused", function () {
    compose.build({
      from: "alice@example.com", to: ["bob@example.net"], text: "x",
      attachments: [{ filename: "../../etc/passwd", content: Buffer.from("x") }],
    });
  });

  // ---- reading an address header -------------------------------------------
  //
  // Two readers, exposed because two surfaces measure the same header
  // with them: the composer deciding who a reply goes to, and the
  // submission listener deciding whose name is on a message it is about
  // to sign. The vectors that matter are the ones where a display name
  // is trying to be read as an address, because that is the input the
  // two would otherwise disagree about.

  var splitAddressHeader = blamepost.mail.compose.splitAddressHeader;
  var normalizeAddress   = blamepost.mail.compose.normalizeAddress;

  check("a plain list splits on its commas",
    splitAddressHeader("a@example.com, b@example.net").length === 2);

  // RFC 5322 §3.2.2: a comment is text. A double quote, a comma or an
  // angle bracket inside one opens or ends nothing, and a backslash in
  // one escapes the character after it.
  var quoteInComment = "Alice (nickname \"Ace) <alice@example.com>";
  check("a quote inside a comment does not open a quoted string, so the angle address " +
    "after it is the address",
    normalizeAddress(quoteInComment, "test").address === "alice@example.com");
  var commentedList = splitAddressHeader(
    "Alice (says \"hi, there) <alice@example.com>, (a <b> c) bob@example.net");
  check("and a comma or an angle bracket inside a comment separates and opens nothing",
    commentedList.length === 2 &&
    normalizeAddress(commentedList[0], "test").address === "alice@example.com" &&
    normalizeAddress(commentedList[1], "test").address === "bob@example.net");
  check("a nested comment and an escaped parenthesis inside one close where they should",
    normalizeAddress("Alice (outer (inner) \\) still) <alice@example.com>", "test").address ===
      "alice@example.com");

  // The comma is inside a quoted display name, so it separates nothing.
  // Splitting here would invent a recipient out of half of somebody's
  // name, and on the submission side it would invent an author.
  var quoted = splitAddressHeader("\"Doe, John\" <john@example.net>");
  check("a comma inside a quoted display name does not end an address",
    quoted.length === 1);
  check("and the address inside it is the one in the angle brackets",
    normalizeAddress(quoted[0], "test").address === "john@example.net");

  // The MIME reader hands back header values with encoded words already
  // decoded and does not restore the quoting the encoding replaced, so
  // this is what a decoded `=?UTF-8?B?RG9lLCBKb2hu?=` arrives as: a
  // comma with nothing left to say it is part of a name. The angle
  // brackets are what the reader anchors on instead.
  var decoded = splitAddressHeader("Doe, John <john@example.net>, carol@example.org");
  check("a decoded display name is rejoined onto the address it was cut from",
    decoded.length === 2);
  check("the rejoined entry keeps the real address",
    normalizeAddress(decoded[0], "test").address === "john@example.net");
  check("and the address after it is read on its own",
    normalizeAddress(decoded[1], "test").address === "carol@example.org");

  // The two readings of a comma-separated piece that is an address on
  // its own, and the option that picks between them.
  //
  // RFC 5322 §3.6.1 gives From a LIST of mailboxes and §3.4 writes a
  // mailbox as a bare addr-spec or as an angle address, so
  // `bob@example.net, Alice <alice@example.com>` names two authors and a
  // receiver displays both. The same decoded string is what an encoded
  // display name of `bob@example.net, Alice` arrives as, which names
  // one. Nothing left in the value says which was sent, so the caller
  // says which way it needs the ambiguity resolved.
  var AUTHOR_READING = { bareAddressIsAMailbox: true };
  var bareFirstRaw = "bob@example.net, Alice <alice@example.com>";

  // The default, which the IMAP ENVELOPE and the addressees of a reply
  // take: the mailboxes the sender CERTAINLY named. An address added to
  // that list is one somebody replies to without meaning to.
  check("by default a bare address before an angle address is display text",
    splitAddressHeader(bareFirstRaw).length === 1);

  // The author binding's reading: every mailbox a receiver MIGHT
  // display. A mailbox missing from that list is one this server signs
  // for without measuring.
  var bareFirst = splitAddressHeader(bareFirstRaw, AUTHOR_READING);
  check("and under the author reading it is a mailbox of its own",
    bareFirst.length === 2);
  check("and the bare one is read as the address it is",
    normalizeAddress(bareFirst[0], "test").address === "bob@example.net" &&
    normalizeAddress(bareFirst[1], "test").address === "alice@example.com");

  // The same piece with an RFC 5322 §3.2.2 comment on it, which is
  // where the shape hides from a reader that measures the piece whole.
  var commentedBare = splitAddressHeader(
    "bob@example.net (Bob), Alice <alice@example.com>", AUTHOR_READING);
  check("a comment on a bare address does not turn it back into display text",
    commentedBare.length === 2);

  // A group label sits in front of its first member (§3.4), and the
  // member is a mailbox whether or not the group names it.
  var labeled = splitAddressHeader(
    "Authors: bob@example.net, Alice <alice@example.com>;", AUTHOR_READING);
  check("a bare address behind a group label is still a mailbox",
    labeled.length === 2 &&
    normalizeAddress(labeled[0], "test").address === "bob@example.net");

  // The name fragments the author reading must still keep joined. Each
  // one carries an at sign or a dot or both and is somebody's name
  // rather than an address, which is what the dotted domain tells apart.
  // Splitting these would refuse ordinary mail from a client that writes
  // an unquoted display name.
  check("a decoded name holding an at sign is still joined to the address after it",
    splitAddressHeader("Doe, John@Home <j@example.net>", AUTHOR_READING).length === 1);
  check("and a decoded name holding a dot is too",
    splitAddressHeader("Doe, John Jr. <j@example.net>", AUTHOR_READING).length === 1);
  check("and a one-word name beside an address it does not own",
    splitAddressHeader("Smith, Alice <alice@example.com>", AUTHOR_READING).length === 1 &&
    normalizeAddress(splitAddressHeader("Smith, Alice <alice@example.com>",
      AUTHOR_READING)[0], "test").address === "alice@example.com");

  // An address planted in a display name must not become a second
  // address. On the submission side this is the shape that would let a
  // forged author ride along beside a permitted one.
  var planted = splitAddressHeader("\"chair@example.com\" <alice@example.com>");
  check("an address written inside a display name is not a second address",
    planted.length === 1);
  check("and the address is the one outside the quotes",
    normalizeAddress(planted[0], "test").address === "alice@example.com");

  // RFC 5322 §3.4 group syntax. An empty group names nobody, which is
  // what `undisclosed-recipients:;` is for, so it yields no address
  // rather than one nothing can deliver to or attribute anything to.
  check("an empty group names nobody",
    splitAddressHeader("undisclosed-recipients:;").length === 0);
  check("a group with members yields the members",
    splitAddressHeader("Team: a@example.com, b@example.com;").length === 2);

  check("a header naming nobody yields nothing",
    splitAddressHeader("").length === 0 && splitAddressHeader(null).length === 0);

  // RFC 5322 §3.2.1 quoted-pair. A name ending in a backslash still
  // ends where its closing quote says it does; reading that quote as
  // escaped would leave the rest of the header inside a string that
  // never closes and lose every address after it.
  check("a display name ending in a backslash does not swallow the rest",
    splitAddressHeader("\"Back\\\\\" <a@example.com>, b@example.net").length === 2);

  check("an entry with no angle brackets is an address on its own",
    normalizeAddress("alice@example.com", "test").address === "alice@example.com");
  check("and the display name beside one is read off the front",
    normalizeAddress("\"Alice Smith\" <alice@example.com>", "test").name === "Alice Smith");

  // The addr-spec is cut at the LAST pair of angle brackets, and the
  // pair does not have to end the entry. RFC 5322 §3.2.2 lets a comment
  // follow the address, and §3.4 lets a quoted display name hold angle
  // brackets of its own, so an entry that ends in something other than
  // `>` and an entry whose first `<` is inside a quoted string are both
  // ordinary mail rather than malformed input.
  //
  // These four are the shapes that separate this reading from an
  // end-anchored one and from a first-match one. They are pinned
  // because both readings are one line away: `b.codepointClass`
  // offers `lastDelimited` and `firstDelimited`, and each answers a
  // different question from this one.
  var commented = normalizeAddress("Alice <alice@example.com> (work)", "test");
  check("an address followed by a comment is still cut at its angle brackets",
    commented.address === "alice@example.com" && commented.name === "Alice");

  var quotedBrackets = normalizeAddress("\"A <b>\" <alice@example.com>", "test");
  check("a quoted display name holding angle brackets does not become the address",
    quotedBrackets.address === "alice@example.com");

  var twoPairs = normalizeAddress("<a@example.com> <b@example.net>", "test");
  check("the last pair of angle brackets wins when an entry carries two",
    twoPairs.address === "b@example.net");

  var nested = normalizeAddress("Name <<a@example.com>", "test");
  check("a second opening bracket starts the address rather than joining it",
    nested.address === "a@example.com");

  // The cut is made at a PAIR, and the two readers of this entry have to
  // agree about where the pairs are. A `<` inside a quoted display name
  // is text in somebody's name and a `>` that closes nothing is stray
  // punctuation, so `"A <b>" .com>` carries no angle address at all:
  // `angleAddressCount` says 0, and cutting between those two hands back
  // a span running from inside the name to past the end of the entry.
  //
  // An entry carrying none is an addr-spec on its own, so the address is
  // the entry, which the guard on the way in then refuses. What must not
  // happen is a third answer that is neither the entry nor a bracket
  // pair's contents.
  var STRAY = "\"A <b>\" .com>";
  check("an entry whose only brackets are quoted or stray carries no angle address",
    blamepost.mail.compose.angleAddressCount(STRAY) === 0);
  var strayClose = normalizeAddress(STRAY, "test");
  check("and nothing is cut out of it, so the address is the entry itself",
    strayClose.address === STRAY);

  // The same disagreement one bracket earlier: an opening bracket, then a
  // quoted name holding a pair, then a stray close.
  var NESTED_STRAY = "<shop\"A <b>\" .com>";
  check("an opening bracket closed past a quoted pair is one angle address",
    blamepost.mail.compose.angleAddressCount(NESTED_STRAY) === 1);
  var quotedThenStray = normalizeAddress(NESTED_STRAY, "test");
  check("and the address is what that one pair holds, cut at its own opening bracket",
    quotedThenStray.address === "shop\"A <b>\" .com");

  // The count beside that reading. `normalizeAddress` answers with one
  // address whatever the entry holds, so an entry holding two is one it
  // chose between, and the address it did not choose is the one a forged
  // author is built on: a receiver that stops at the first angle address
  // is shown a mailbox nothing here measured.
  var angleAddressCount = blamepost.mail.compose.angleAddressCount;

  check("an ordinary mailbox carries one angle address",
    angleAddressCount("Alice <alice@example.com>") === 1);
  check("a bare addr-spec carries none, and an empty entry carries none",
    angleAddressCount("alice@example.com") === 0 && angleAddressCount("") === 0);

  // The entry the submission listener refuses on. Both halves are
  // syntactically addresses and no grammar says which one is the author.
  check("two angle addresses in one entry are counted as two",
    angleAddressCount("<a@example.com> <b@example.net>") === 2);

  // Quoting is what separates a name from an address, and the counter
  // reads it the same way the splitter does. Counting a bracket inside a
  // display name would refuse `"A <b>" <alice@example.com>`, which is
  // one mailbox and ordinary mail.
  check("angle brackets inside a quoted display name are not counted",
    angleAddressCount("\"A <b>\" <alice@example.com>") === 1);
  check("and a display name ending in a backslash still ends at its closing quote",
    angleAddressCount("\"Back\\\\\" <a@example.com>") === 1);

  // A `>` that closes nothing is stray punctuation rather than a
  // mailbox, so it is not counted as one.
  check("a closing bracket with no address open is not an angle address",
    angleAddressCount("a>b <alice@example.com>") === 1);

  // An entry whose second bracket pair is inside an RFC 5322 §3.2.2
  // comment counts two, so the listener refuses it: a receiver that does
  // not parse comments can take that pair as the address. This server's
  // own reading skips the comment and takes the mailbox in front of it.
  check("a comment carrying an angle address counts two",
    angleAddressCount("Alice <alice@example.net> (see <x>)") === 2);
  check("and this server reads the mailbox outside the comment",
    normalizeAddress("Alice <alice@example.net> (see <x>)", "test").address ===
      "alice@example.net");
  // `inComments: false` counts only the pairs the address is cut from.
  check("with inComments off, the pair inside the comment is not counted",
    angleAddressCount("Alice <alice@example.net> (see <x>)", { inComments: false }) === 1 &&
    angleAddressCount("alice@example.net (see <x>)", { inComments: false }) === 0 &&
    angleAddressCount("alice@example.net (see <x>)") === 1);
  // A comment that never closes holds the rest of the entry, so a pair
  // after its opening is inside it.
  check("and a pair after a comment that never closes is inside that comment",
    angleAddressCount("sop<(@ex>sop<(@ex>m", { inComments: false }) === 0);

  // A comment with no brackets in it is the documented shape and stays
  // one mailbox.
  check("a comment with no angle brackets leaves the count at one",
    angleAddressCount("Alice <alice@example.com> (work)") === 1);

  // The nested opening above opens one address and closes one, so it is
  // not two.
  check("a second opening bracket does not add an address",
    angleAddressCount("Name <<a@example.com>") === 1);

  // A comma is what RFC 5322 §3.4 separates two mailboxes with, and the
  // splitter is what acts on it, so each entry it yields is counted on
  // its own rather than as one entry carrying two.
  var separated = splitAddressHeader("<a@example.com>, <b@example.net>");
  check("a comma-separated pair yields two entries carrying one address each",
    separated.length === 2 && angleAddressCount(separated[0]) === 1 &&
    angleAddressCount(separated[1]) === 1);

  // ---- send, reply, forward ------------------------------------------------

  var result = await compose.send({
    from: "alice@example.com", to: ["bob@example.net"],
    subject: "Lunch", text: "One o'clock?",
  });
  check("send hands the envelope to the outbound path",
    sent.length === 1 && sent[0].from === "alice@example.com");
  check("the sender's copy is filed in Sent", filed.length === 1 && filed[0].folder === "Sent");
  check("send reports the message id", result.messageId.charAt(0) === "<");

  var original = compose.build({
    from:       { name: "Bob", address: "bob@example.net" },
    to:         ["alice@example.com", "carol@example.org"],
    subject:    "Re: Lunch",
    text:       "Tuesday works.\nBob",
    references: ["<root@example.net>"],
  });

  sent.length = 0;
  await compose.reply({
    original: original.rfc822,
    from:     "alice@example.com",
    text:     "Perfect.",
    replyAll: true,
  });
  var reply = sent[0].rfc822.toString("utf8");
  check("a reply names its parent in In-Reply-To",
    /^In-Reply-To: <[0-9a-f]+@example\.net>$/m.test(reply));
  check("a reply carries the parent chain with the parent appended",
    reply.indexOf("References: <root@example.net> <") !== -1);
  check("the subject gains one Re prefix, not two", /^Subject: Re: Lunch$/m.test(reply));
  check("the reply goes to the original sender", /^To: Bob <bob@example\.net>$/m.test(reply));
  check("replyAll keeps the other recipients", reply.indexOf("carol@example.org") !== -1);
  check("the original is quoted", reply.indexOf("> Tuesday works.") !== -1);

  // A recipient override naming one mailbox as an object. `build` takes
  // `{ name, address }` wherever it takes an address, and the reply
  // override is documented to keep the name a caller wrote, so one of
  // them is the same value the array form carries as its only entry.
  // Read through `String()` instead it becomes the six characters of a
  // default object rendering, and the address reader then refuses a
  // reply the caller spelled correctly.
  sent.length = 0;
  await compose.reply({
    original: original.rfc822,
    from:     "alice@example.com",
    text:     "Just you.",
    to:       { name: "Bob", address: "bob@example.net" },
    cc:       { name: "Carol", address: "carol@example.org" },
  });
  check("a reply override naming one recipient as an object is sent rather than refused",
    sent.length === 1);
  var objectReply = sent.length === 1 ? sent[0].rfc822.toString("utf8") : "";
  check("and it is addressed to that mailbox, keeping the name the caller wrote",
    /^To: Bob <bob@example\.net>$/m.test(objectReply));
  check("and the copy list reads the same way",
    /^Cc: Carol <carol@example\.org>$/m.test(objectReply));
  check("and the envelope names both mailboxes, because a copy is delivered like any other",
    sent.length === 1 && sent[0].to.length === 2 &&
    sent[0].to.indexOf("bob@example.net") !== -1 &&
    sent[0].to.indexOf("carol@example.org") !== -1);

  sent.length = 0;
  await compose.forward({
    original: original.rfc822,
    from:     "alice@example.com",
    to:       ["dave@example.net"],
    text:     "Passing this on.",
  });
  var forward = sent[0].rfc822.toString("utf8");
  check("a forward prefixes the subject", /^Subject: Fwd: Re: Lunch$/m.test(forward));
  check("the original travels as message/rfc822",
    forward.indexOf("Content-Type: message/rfc822") !== -1);
  check("a forward answers nobody", forward.indexOf("In-Reply-To:") === -1);
  check("a forward stays attached to the conversation",
    forward.indexOf("References: <root@example.net>") !== -1);

  // ---- the spellings a header may legitimately carry ------------------------

  // A stranger writes their own From header, and nothing at the wire
  // reads a header against the envelope grammar: RFC 5321 §4.1.2 leaves
  // no empty label at the end of a domain, but RFC 1035 §2.3.1 makes the
  // absolute form the same name, and a message carrying it is accepted
  // and filed like any other. So the two verbs that read an address out
  // of somebody else's header meet that spelling, and both have to
  // answer about the mailbox rather than about the bytes.
  //
  // Built by hand rather than through `build`, because `build` derives
  // every address it is given and would fold the spelling away before
  // the reply ever saw it.
  var spelledOriginal = Buffer.from([
    "From: Bob <bob@EXAMPLE.NET.>",
    "To: <alice@EXAMPLE.COM.>",
    "Subject: Lunch",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <spelled@example.net>",
    "",
    "Tuesday works.",
    "",
  ].join("\r\n"), "utf8");

  sent.length = 0;
  await compose.reply({
    original: spelledOriginal,
    from:     "alice@example.com",
    text:     "Perfect.",
    replyAll: true,
  });
  var spelledReply = sent[0].rfc822.toString("utf8");
  check("a reply to a From header carrying the DNS root's dot is sent rather than refused",
    sent.length === 1);
  check("and it is addressed to the mailbox that header names, in the form a receiver reads",
    /^To: Bob <bob@example\.net>$/m.test(spelledReply));
  check("with the envelope naming the same one address",
    sent[0].to.length === 1 && sent[0].to[0] === "bob@example.net");
  check("and replyAll leaves the replying identity off its own copy list, however the " +
    "original spelled it",
    spelledReply.indexOf("Cc:") === -1);

  sent.length = 0;
  await compose.forward({
    original: spelledOriginal,
    from:     "alice@example.com",
    to:       ["dave@EXAMPLE.NET."],
    text:     "Passing this on.",
  });
  var spelledForward = sent[0].rfc822.toString("utf8");
  check("a forward to a recipient written the same way is sent too",
    sent.length === 1);
  check("and the header and the envelope both name the derived address",
    /^To: dave@example\.net$/m.test(spelledForward) &&
      sent[0].to.length === 1 && sent[0].to[0] === "dave@example.net");

  // The RFC 5233 tag belongs to the mailbox the sender chose rather than
  // to this server, so it survives the fold. A reply that dropped it
  // would land outside the filter the recipient wrote for it.
  sent.length = 0;
  await compose.send({
    from: "alice@example.com", to: ["Bob+Lists@EXAMPLE.NET."],
    subject: "Lunch", text: "One o'clock?",
  });
  check("a subaddress tag survives the derivation",
    sent[0].to.length === 1 && sent[0].to[0] === "bob+lists@example.net");

  // The control. A composer that admitted the spelling by admitting
  // everything would pass every case above.
  var refusedConfusable = null;
  try {
    compose.build({
      from: "alice@example.com", to: ["bob@exаmple.net"],
      subject: "Lunch", text: "One o'clock?",
    });
  } catch (e) { refusedConfusable = e; }
  check("a recipient at a name that only renders like one is still refused",
    refusedConfusable !== null);

  var refusedShapeless = null;
  try {
    compose.build({
      from: "alice@example.com", to: ["bob@"],
      subject: "Lunch", text: "One o'clock?",
    });
  } catch (e) { refusedShapeless = e; }
  check("and so is a string naming no domain at all", refusedShapeless !== null);

  // ---- the outbound spool --------------------------------------------------

  var dataDir = helpers.tempDir("outbound");
  // A resolver that answers "no mail exchanger" for everything, so the
  // outbound path reaches its verdict without opening a socket. This
  // layer has none, and a report is a message: once it is composed it
  // goes out over the same path as any other, so the path needs
  // somewhere to stop.
  var NO_MX = {
    queryMx:  function (name) { return Promise.reject(new Error("no mail exchanger for " + name)); },
    queryTxt: function () { return Promise.resolve([]); },
    query:    function () { return Promise.resolve([]); },
  };

  var delivery = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: NO_MX,
    policy:   { mtaSts: "off", dane: "off" },
  });
  check("the spool starts empty", delivery.describe().waiting === 0);
  check("the spool is reachable as blamepost.mail.delivery.queue",
    typeof delivery.queue.list === "function" && typeof delivery.queue.runDue === "function");

  // The sweep timer is armed and disarmed explicitly, so a one shot
  // command that only sends never leaves a timer holding the loop open.
  check("no sweep runs until it is armed", delivery.describe().sweeping === false);
  delivery.start();
  check("start arms the sweep", delivery.describe().sweeping === true);
  delivery.start();
  check("arming twice keeps the first timer", delivery.describe().sweeping === true);
  delivery.stop();
  check("stop disarms it", delivery.describe().sweeping === false);

  // A report is composed and then sent, over the same outbound path as
  // any other message, traveling with the RFC 5321 §4.5.5 empty reverse
  // path that §6.1 requires of it. This layer can see everything up to
  // the socket: the report's shape, the envelope it was handed to the
  // outbound path with, and that nothing was recorded as unsent.
  // Named apart from the `sent` collector above deliberately. That one is
  // an array this function handed to the collecting delivery by reference,
  // so a second `var sent` here would not shadow it, it would overwrite
  // the name while the collector kept filling an array nobody could reach.
  // Nothing below reads it today, which is exactly why the next assertion
  // added here would have been the one to find out.
  var bounced = await delivery.bounce({
    to:        "sender@example.net",
    recipient: "nobody@example.com",
    reason:    "No such mailbox",
  });
  check("a report is handed to the outbound path rather than recorded",
    bounced.reportUnsent === undefined);
  check("the report is an RFC 3464 delivery status notification",
    bounced.report.indexOf("Final-Recipient: rfc822; nobody@example.com") !== -1);
  check("the report carries the enhanced status code",
    bounced.report.indexOf("Status: 5.1.1") !== -1);
  check("nothing is counted as a report the sender did not get",
    delivery.describe().reportsUnsent === 0);

  // The envelope it went out under is the half a receiver reads first,
  // and the one shape that must never be anything else.
  var waiting = await delivery.queue.list();
  check("the report is waiting for its next attempt like any other message",
    waiting.length === 1 && waiting[0].recipient === "sender@example.net");
  check("and it travels with the empty reverse path RFC 5321 6.1 requires",
    waiting[0].from === "");

  // RFC 5321 section 6.1: a report travels with the null return path so
  // a broken sender address cannot start a loop of reports about
  // reports. There is nobody to tell, so no report is composed at all.
  var suppressed = await delivery.bounce({
    to: "", recipient: "nobody@example.com", reason: "x",
  });
  check("a report about the null return path is suppressed",
    suppressed.failed.length === 0 && suppressed.report === undefined);
  check("suppressing that report writes nothing to the spool",
    (await delivery.queue.list()).length === 1);

  // ---- the DNS posture checker ---------------------------------------------

  var zone = {
    "example.com|MX":             { rrs: [{ decoded: { preference: 10, exchange: "mx.example.com." } }] },
    "example.com|TXT":            { rrs: [{ decoded: ["v=spf1 mx ~all"] }] },
    "_dmarc.example.com|TXT":     { rrs: [{ decoded: ["v=DMARC1; p=none; rua=mailto:d@example.com"] }] },
    "_mta-sts.example.com|TXT":   { rrs: [] },
    "_smtp._tls.example.com|TXT": { rrs: [] },
  };
  var fixedZoneResolver = {
    queryMx:   function (n) { return Promise.resolve(zone[n + "|MX"]  || { rrs: [] }); },
    queryTxt:  function (n) { return Promise.resolve(zone[n + "|TXT"] || { rrs: [] }); },
    queryTlsa: function () { return Promise.resolve({ rrs: [] }); },
  };
  var posture = blamepost.mail.posture.create({
    hostname: "mx.example.com",
    resolver: fixedZoneResolver,
  });
  var report = await posture.check({ domains: ["example.com"] });
  var byRecord = {};
  report.domains[0].findings.forEach(function (f) {
    if (!byRecord[f.record]) byRecord[f.record] = f;
  });

  check("an MX naming this server passes", byRecord.MX.ok === true);
  check("a soft SPF ending is named precisely",
    byRecord.SPF.ok === false && byRecord.SPF.detail.indexOf("~all") !== -1);
  check("a DMARC policy of none is named precisely",
    byRecord.DMARC.ok === false && byRecord.DMARC.detail.indexOf("p=none") !== -1);
  check("a missing MTA-STS record is a finding", byRecord["MTA-STS TXT"].ok === false);
  check("a missing TLS-RPT record is advisory rather than fatal",
    byRecord["TLS-RPT"].ok === false && byRecord["TLS-RPT"].severity === "advised");
  check("the run fails when a required record is wrong", report.ok === false);

  // A zone with everything right passes, which is the vector that
  // proves the checker is reading rather than always refusing.
  zone["example.com|TXT"] = { rrs: [{ decoded: ["v=spf1 mx -all"] }] };
  zone["_dmarc.example.com|TXT"] = { rrs: [{ decoded: ["v=DMARC1; p=reject"] }] };
  zone["_mta-sts.example.com|TXT"] = { rrs: [{ decoded: ["v=STSv1; id=20260101000000Z"] }] };
  zone["_smtp._tls.example.com|TXT"] =
    { rrs: [{ decoded: ["v=TLSRPTv1; rua=mailto:tls@example.com"] }] };
  var second = await posture.check({ domains: ["example.com"] });
  var spf = second.domains[0].findings.filter(function (f) { return f.record === "SPF"; })[0];
  var dmarc = second.domains[0].findings.filter(function (f) { return f.record === "DMARC"; })[0];
  check("a strict SPF ending passes", spf.ok === true);
  check("a DMARC policy of reject passes", dmarc.ok === true);

  // RFC 7505: a null MX says the domain accepts no mail at all, which
  // is a different diagnosis from having no MX record.
  zone["example.com|MX"] = { rrs: [{ decoded: { preference: 0, exchange: "" } }] };
  var third = await posture.check({ domains: ["example.com"] });
  var mx = third.domains[0].findings.filter(function (f) { return f.record === "MX"; })[0];
  check("a null MX is named as a null MX",
    mx.ok === false && mx.detail.indexOf("RFC 7505") !== -1);

  // ---- the two framework helpers the facade exposes ------------------------

  var sharedResolver = blamepost.resolver();
  check("blamepost.resolver builds a resolver with the per type shortcuts",
    typeof sharedResolver.queryMx === "function" && typeof sharedResolver.queryTxt === "function");
  check("and it runs the strict profile, because these lookups drive security decisions",
    sharedResolver.profile === "strict");

  // A certificate that is not on disk is a boot failure, not something
  // to discover on the first connection.
  refuses("blamepost.tlsContext refuses a certificate path that is not there", function () {
    blamepost.tlsContext({
      certFile: helpers.path.join(dataDir, "absent", "fullchain.pem"),
      keyFile:  helpers.path.join(dataDir, "absent", "privkey.pem"),
      watch:    false,
    });
  });

  // Whether the certificate files are watched decides whether a renewal
  // written to them is ever served. The loader refuses a value that is
  // not a boolean, and a caller narrowing one to `=== true` on the way in
  // turns that refusal off: every truthy non-boolean then reads as a
  // request for the watch and arrives as false, so the server presents
  // the certificate it started with for as long as it runs while the
  // renewal sits on disk. Nothing throws and nothing is logged.
  //
  // The refusal is read by its message rather than by its presence,
  // because these paths do not exist either: a refusal naming the
  // missing file would satisfy a check that only asked whether something
  // was thrown, and that is the answer the coerced form gives.
  ["true", 1, "yes", {}].forEach(function (value) {
    var said = refusalFrom(function () {
      blamepost.tlsContext({
        certFile: helpers.path.join(dataDir, "absent", "fullchain.pem"),
        keyFile:  helpers.path.join(dataDir, "absent", "privkey.pem"),
        watch:    value,
      });
    });
    check("blamepost.tlsContext refuses watch: " + JSON.stringify(value) +
      " by name rather than turning the watch off",
      said.indexOf("opts.watch") !== -1);
  });

  // The two values that are an answer still are, and neither is refused
  // by the check above.
  check("blamepost.tlsContext reads watch: false past the refusal",
    refusalFrom(function () {
      blamepost.tlsContext({
        certFile: helpers.path.join(dataDir, "absent", "fullchain.pem"),
        keyFile:  helpers.path.join(dataDir, "absent", "privkey.pem"),
        watch:    false,
      });
    }).indexOf("opts.watch") === -1);
  check("blamepost.tlsContext reads watch: true past the refusal",
    refusalFrom(function () {
      blamepost.tlsContext({
        certFile: helpers.path.join(dataDir, "absent", "fullchain.pem"),
        keyFile:  helpers.path.join(dataDir, "absent", "privkey.pem"),
        watch:    true,
      });
    }).indexOf("opts.watch") === -1);

  helpers.removeTempDir(dataDir);
  return helpers.getChecks();
}

module.exports = { name: "mail-compose", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
