// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Sending mail, which is the thing an account holder does most and the
 * thing nothing here exercised.
 *
 * It is reachable today even though outbound delivery is blocked
 * upstream, because a recipient this server hosts is delivered locally
 * rather than sent back out to the internet. Alice writing to Bob on the
 * same server never touches the transport that cannot reach a peer, so
 * the whole submission path can be driven end to end while that stands.
 *
 * Three claims, and the second and third are the ones that matter:
 *
 *   - A message alice submits reaches bob's mailbox, and he reads it
 *     over IMAP with the body she wrote.
 *   - A `MAIL FROM` for an address alice does not own is refused at the
 *     wire, before RCPT, before DATA, before anything is stored. An
 *     authenticated account that can post as a colleague is a spoofing
 *     surface with a valid password in front of it, which is worse than
 *     an open relay, because the mail it sends looks internal.
 *   - A body carrying an end-of-data sequence some receiver will honor
 *     is refused however it arrived. This server offers three ways to
 *     hand a message over and they have to answer that question the
 *     same, because it is a question about the octets and not about the
 *     framing they arrived in.
 *
 * The refusal is asserted on the code the server actually writes rather
 * than the one four documents claimed it wrote. That mismatch is the
 * reason to assert a wire code at all: an operator filtering their logs
 * for a refusal that never appears has a rule that never fires.
 *
 * Run standalone: node test/layer-2-integration/mail-submission.test.js
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

// The second domain this server hosts. Every rule about what an account
// may send as is measured across two of them, because a rule tested on a
// server hosting one domain is a rule nobody has asked whether the
// domain is part of.
var SECOND_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

var BODY = "Bob, the pipe under the sink is dripping again. Marker 5c1f9a0d.";

// The subject of the second message hidden inside the first, so a
// mailbox can be searched for the one thing that must never be in it.
var SMUGGLED_MARKER = "smuggled-8ba41c7e";

// The four end-of-data sequences a receiver might honor besides the one
// RFC 5321 section 4.1.1.4 defines. Each is a line boundary, a dot and
// another line boundary with at least one of the two written as
// something other than CRLF, which is the whole of what CVE-2023-51764
// and its Sendmail and Exim siblings turn on.
var END_OF_DATA_VARIANTS = [
  { name: "bare LF either side",      bytes: "\n.\n" },
  { name: "bare CR either side",      bytes: "\r.\r" },
  { name: "bare LF then CRLF",        bytes: "\n.\r\n" },
  { name: "CRLF then bare LF",        bytes: "\r\n.\n" },
];

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// A submission session raised to TLS and authenticated, which is where
// every mail client sits before it says anything about an envelope.
async function submissionSession(port, caPem, address, password, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + plainResponse(address, password));
  await session.read(/^235 /m, "authenticated");
  return session;
}

// The same session on the implicit-TLS port, RFC 8314 section 3.3: the
// socket carries TLS from its first byte, the banner arrives on the
// encrypted channel, and there is no STARTTLS to send. Written out
// rather than taken from the shared ladders because those all raise a
// cleartext socket, and the difference between the two is the whole
// point of the cases below.
//
// The chain is verified against the run's own authority, as everywhere
// else here. A session that skipped verification would authenticate
// against a listener presenting anything at all.
async function implicitTlsSubmissionSession(port, caPem, address, password, label) {
  var session = await new Promise(function (resolve, reject) {
    var socket = nodeTls.connect({
      host: LOOPBACK, port: port, servername: HOSTNAME, ca: caPem,
    }, function () { resolve(new Wire(socket, label)); });
    socket.once("error", reject);
  });
  await session.read(/^220 /m, "banner on the encrypted channel");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("AUTH PLAIN " + plainResponse(address, password));
  await session.read(/^235 /m, "authenticated");
  return session;
}

async function imapSession(port, caPem, address, password, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, password));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

// ---- cases -----------------------------------------------------------------

async function aliceWritesToBobAndBobReadsIt(ports, caPem, alice, bob) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-send");

  sender.send("MAIL FROM:<" + alice + ">");
  var mailReply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an account may send as itself", /^250 /m.test(mailReply), visible(mailReply));

  sender.send("RCPT TO:<" + bob + ">");
  var rcptReply = await sender.read(/^\d{3} /m, "RCPT TO answered");
  count("a recipient on this server is accepted", /^250 /m.test(rcptReply), visible(rcptReply));

  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: " + alice,
    "To: " + bob,
    "Subject: The sink",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <submission-5c1f9a0d@example.com>",
    "",
    BODY,
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");

  var accepted = await sender.read(/^\d{3} /m, "message answered");
  count("the message is accepted for delivery", /^250 /m.test(accepted), visible(accepted));
  sender.send("QUIT");
  sender.close();

  // Bob's side. A separate session as a separate account, because the
  // claim is that the message crossed between two mailboxes rather than
  // that one session remembers writing it.
  var reader = await imapSession(ports.imap, caPem, bob, BOB_PASSWORD, "imap-bob");
  reader.send("b0 SELECT INBOX");
  var selected = await reader.read(/^b0 (OK|NO|BAD)/m, "SELECT answered");
  count("bob's mailbox holds the message alice sent",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  reader.send("b1 FETCH 1 BODY[]");
  var fetched = await reader.read(/^b1 (OK|NO|BAD)/m, "FETCH answered");
  count("and it is the message she wrote",
    /^b1 OK/m.test(fetched) && fetched.indexOf(BODY) !== -1, visible(fetched));
  count("carrying her address as the sender",
    fetched.indexOf(alice) !== -1, visible(fetched));

  reader.send("b2 LOGOUT");
  reader.close();
}

// The gate that stops an authenticated account posting as somebody else.
// It has to fire at MAIL FROM: refusing later would mean the server had
// already accepted recipients for a message it was never going to send,
// and refusing never would mean a password gets you a colleague's
// letterhead.
async function aliceCannotSendAsBob(ports, caPem, alice, bob) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-spoof");

  sender.send("MAIL FROM:<" + bob + ">");
  var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");

  count("an authenticated account cannot send as another account",
    !/^250 /m.test(reply), visible(reply));
  count("the refusal is permanent rather than a retry invitation",
    /^5\d\d /m.test(reply), visible(reply));
  // Pinned exactly, because the value of a wire code is that somebody
  // can filter on it. RFC 5321 puts a rejected sender address at 553,
  // and the enhanced code says why.
  count("and it is 553 5.7.1, the code an operator would filter for",
    /^553 5\.7\.1 /m.test(reply), visible(reply));

  // The session survives the refusal, so a client that guesses wrong
  // once can correct itself rather than reconnecting.
  sender.send("MAIL FROM:<" + alice + ">");
  var recovered = await sender.read(/^\d{3} /m, "second MAIL FROM answered");
  count("and the session carries on for a sender she does own",
    /^250 /m.test(recovered), visible(recovered));

  sender.send("QUIT");
  sender.close();
}

// Everything above drives 587, where a session starts in the clear and
// is raised with STARTTLS. The shipped configuration binds a SECOND
// submission listener on 465, where the socket is encrypted from its
// first byte, and `enabled: true` is its default rather than something
// an operator turns on. RFC 8314 section 3 tells a mail client to
// prefer that port, so for a large share of real clients it is the only
// submission listener they ever touch.
//
// Both are built from one function, so they carry the same binding
// today. They are still two separately constructed listeners, and a
// change that left 587 strict while 465 went permissive is a change
// every case above reports as passing, because every case above binds
// the other port.
//
// The binding has two halves and they fail independently, which is why
// three envelopes are asked here rather than one:
//
//   - The listener's own set holds the addresses the account was
//     created with, so a spoof of another account is refused by that
//     set alone.
//   - An alias is not in that set. It is owned according to the store,
//     and the only thing that says so is the sender policy this
//     repository composes in. A listener that kept the binding and
//     dropped the policy refuses the spoof and the alias alike, and the
//     alias is the only envelope that tells those two apart.
//   - An address that merely ROUTES to the account is refused, so the
//     policy is answering with the sending set rather than with
//     anything that reaches her.
async function theImplicitTlsPortBindsTheSameIdentity(ports, caPem, alice, bob,
  aliasAddress, routesButIsNotAnIdentity) {
  var sender = await implicitTlsSubmissionSession(ports.submissions, caPem,
    alice, ALICE_PASSWORD, "submissions-implicit");
  count("the implicit-TLS submission listener authenticates an account, so the port RFC " +
    "8314 tells a client to prefer is a door this server actually opens",
    sender.socket.authorized === true, String(sender.socket.authorized));

  sender.send("MAIL FROM:<" + bob + ">");
  var spoof = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an authenticated account cannot send as another account on the implicit-TLS " +
    "port either, and the code is the same 553 5.7.1 an operator filters for",
    /^553 5\.7\.1 /m.test(spoof), visible(spoof));
  count("and the refusal names the binding rather than a parse failure",
    /not owned by authenticated identity/.test(spoof), visible(spoof));

  sender.send("MAIL FROM:<" + aliasAddress + ">");
  var alias = await sender.read(/^\d{3} /m, "alias MAIL FROM answered");
  count("an alias the account owns is accepted on the implicit-TLS port, so the sender " +
    "policy reaches this listener and not only the one that starts in the clear",
    /^250 /m.test(alias), visible(alias));

  sender.send("RSET");
  await sender.read(/^250 /m, "RSET answered");
  sender.send("MAIL FROM:<" + routesButIsNotAnIdentity + ">");
  var routed = await sender.read(/^\d{3} /m, "catch-all MAIL FROM answered");
  count("an address that routes to her mailbox and is not a sending identity is refused " +
    "here too, so the policy answers with the sending set rather than with delivery",
    /^553 5\.7\.1 /m.test(routed), visible(routed));

  sender.send("QUIT");
  sender.close();
}

// An active alias that lands in an account's mailbox is an address that
// account may speak for, on the envelope exactly as in the header. The
// two halves are measured against one set, so a client that puts the
// alias in both fields sends, and the message carries the alias to the
// recipient.
var ALIAS_ENVELOPE_MARKER = "alias-envelope-2d61b4f8";

async function sendingAsAnOwnedAlias(ports, caPem, alice, bob, aliasAddress) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-alias");

  sender.send("MAIL FROM:<" + aliasAddress + ">");
  var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an alias that lands in the account's mailbox is accepted as an envelope sender",
    /^250 /m.test(reply), visible(reply));

  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: " + aliasAddress,
    "To: " + bob,
    "Subject: " + ALIAS_ENVELOPE_MARKER,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + ALIAS_ENVELOPE_MARKER + "@" + DOMAIN + ">",
    "",
    "A message whose envelope and author are both the alias.",
    "",
    ".",
    "",
  ].join("\r\n"), "<a message written entirely under the alias>");
  var accepted = await sender.read(/^\d{3} /m, "message answered");
  count("and the message goes, so the envelope and the author binding agree about " +
    "the same address rather than one permitting what the other refuses",
    /^250 /m.test(accepted), visible(accepted));

  sender.send("QUIT");
  sender.close();
}

// The addresses that route to an account and are still not identities it
// may send under. Each is refused at `MAIL FROM`, which is where the
// envelope binding answers, and each is refused for a reason the author
// binding already applies to the header.
async function theEnvelopeRefusesWhatIsNotASendingIdentity(ports, caPem, alice, vectors) {
  for (var i = 0; i < vectors.length; i += 1) {
    var vector = vectors[i];
    var sender = await submissionSession(ports.submission, caPem,
      alice, ALICE_PASSWORD, "submission-not-an-identity-" + i);
    sender.send("MAIL FROM:<" + vector.address + ">");
    var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
    count(vector.name + " is refused as an envelope sender, because " + vector.why,
      /^553 5\.7\.1 /m.test(reply), visible(reply));
    count("and " + vector.name + " draws the not-owned refusal rather than a parse failure",
      /not owned by authenticated identity/.test(reply), visible(reply));
    sender.send("QUIT");
    sender.close();
  }
}

// An alias on a second hosted domain is an identity exactly as one on
// the first is. Asked on a server hosting two domains, because a
// binding measured on a single-domain server cannot show whether the
// domain is part of what it compares.
async function anAliasOnASecondHostedDomainIsASendingIdentity(ports, caPem, alice, aliasAddress) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-alias-second-domain");
  sender.send("MAIL FROM:<" + aliasAddress + ">");
  var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an alias on a second hosted domain is accepted as an envelope sender, so the " +
    "set follows the alias rows rather than the account's own domain",
    /^250 /m.test(reply), visible(reply));
  sender.send("QUIT");
  sender.close();
}

// The withdrawal an operator performs, read on the next message rather
// than at the next sign-in. The session below authenticated while the
// alias was active, so a set cached on the session would still hold it.
async function awithdrawnAliasStopsBeingASender(ports, caPem, identity, alice, aliasAddress) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-alias-withdrawn");

  sender.send("MAIL FROM:<" + aliasAddress + ">");
  var before = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("the alias is a sending identity while it is active",
    /^250 /m.test(before), visible(before));

  sender.send("RSET");
  await sender.read(/^250 /m, "RSET answered");

  // One source can hold several destinations, so the source alone does
  // not name a single alias and the store refuses it. Name the pair.
  await identity.aliases.setStatus({
    address:     aliasAddress,
    destination: alice,
    status:      "disabled",
    reason:      "withdrawn mid-session by the submission test",
  });

  sender.send("MAIL FROM:<" + aliasAddress + ">");
  var after = await sender.read(/^\d{3} /m, "second MAIL FROM answered");
  count("and it stops being one at the next message rather than at the next sign-in, " +
    "because the set is read from the store on every envelope",
    /^553 5\.7\.1 /m.test(after), visible(after));

  sender.send("QUIT");
  sender.close();

  await identity.aliases.setStatus({
    address:     aliasAddress,
    destination: alice,
    status:      "active",
    reason:      "restored by the submission test",
  });
}

// The account's own subaddress, on both ports. RFC 5233 makes
// `alice+receipts@` a sub-address of `alice@`, and the routing layer
// folds the tag away, so the MX listener accepts it as a recipient and
// delivers it to her. The envelope binding folds the same tag against
// the same canonical form, so the port she sends from and the port that
// receives give one answer about one address.
//
// Both are asserted together, because a client configured with a
// subaddress as its identity puts that address in `MAIL FROM` and in
// `From`, and one port answering differently from the other is the
// failure this pair exists to catch.
async function theTwoPortsAgreeAboutAnOwnedSubaddress(ports, caPem, alice, bob) {
  var at = alice.indexOf("@");
  var tagged = alice.slice(0, at) + "+receipts" + alice.slice(at);

  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-subaddress");
  sender.send("MAIL FROM:<" + tagged + ">");
  var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("submission accepts the account's own subaddress as an envelope sender, which " +
    "is the address a client configured with that identity writes",
    /^250 /m.test(reply), visible(reply));
  sender.send("QUIT");
  sender.close();

  // The other half, on the port that receives. An address this server
  // accepts mail for on her behalf is one it lets her send as.
  var peer = await Wire.mx(ports.mx, { caPem: caPem, servername: HOSTNAME, label: "mx-subaddress" });
  peer.send("MAIL FROM:<outsider@peer.example>");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + tagged + ">");
  var rcpt = await peer.read(/^\d{3} /m, "RCPT TO answered");
  count("and the MX listener accepts the same address as a recipient",
    /^250 /m.test(rcpt), visible(rcpt));
  peer.send("QUIT");
  peer.close();

  // A tag on an address that is not hers is still not hers. The fold
  // takes the tag off and the mailbox underneath is what is compared, so
  // this is the vector that separates folding from stripping and
  // trusting whatever is left.
  var forger = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-subaddress-forged");
  var forged = bob.slice(0, bob.indexOf("@")) + "+receipts" + bob.slice(bob.indexOf("@"));
  forger.send("MAIL FROM:<" + forged + ">");
  var refused = await forger.read(/^\d{3} /m, "MAIL FROM answered");
  count("a tag on somebody else's local part is refused, because the fold reads the " +
    "mailbox the address is delivered to rather than dropping the part it cannot check",
    /^553 5\.7\.1 /m.test(refused), visible(refused));
  forger.send("QUIT");
  forger.close();
}

// The two spellings of an envelope sender that decide whether the
// binding compares addresses or compares strings, neither of which is
// asked anywhere else on this port.
//
// One must be accepted and one must be refused, and a comparison that
// gets either wrong is wrong in a direction somebody can use. A case
// variation of her own address is her address: SMTP domains are
// case-insensitive and RFC 5321 section 2.4 leaves the local part to
// the receiving host, which here is this one, so refusing it locks out
// a client that upper-cases what the user typed. A domain drawn with a
// letter from another script is a different domain that renders the
// same, so accepting it would let an account send under a name the
// operator never registered and this server would sign it.
async function theEnvelopeBindingComparesAddressesRatherThanStrings(ports, caPem, alice) {
  var upper = alice.toUpperCase();
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-envelope-spelling");

  sender.send("MAIL FROM:<" + upper + ">");
  var upperReply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("the account's own address upper-cased is accepted as an envelope sender, " +
    "because it is the same mailbox and refusing it locks out a client that " +
    "upper-cases what its user typed",
    /^250 /m.test(upperReply), visible(upperReply));

  sender.send("RSET");
  await sender.read(/^250 /m, "RSET answered");

  // The middle letter is Cyrillic U+0430. It renders as an "a" beside
  // the Latin ones around it and is a different code point, so this is
  // a domain nothing here hosts wearing the look of one it does.
  sender.send("MAIL FROM:<alice@exаmple.com>");
  var confusableReply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("and a domain spelled with a letter from another script is refused, because " +
    "it is not the domain it is drawn to look like and this account holds no " +
    "address at it",
    /^5\d\d /m.test(confusableReply), visible(confusableReply));

  sender.send("QUIT");
  sender.close();
}

// ---- the From header an account may write ----------------------------------
//
// The envelope sender is bound and the From header is the one a person
// reads. A message whose envelope names the account and whose From
// names somebody else arrives signed with the domain's own key, aligned
// and passing DMARC, which is impersonation carried by this server's
// own authority rather than in spite of it.
//
// What the account may write is computed from the store rather than
// from a fixed list, so it folds an RFC 5233 tag the way routing does
// and it follows an alias to the mailbox it lands in. Each vector below
// carries a marker in its subject, and the settling assertion at the
// end reads bob's mailbox for the markers that must not be in it: a
// wire code is a claim about what the server did next, and the mailbox
// is where that claim is settled.

// The replies a refused submission draws, each pinned exactly. A code
// an operator cannot filter for is a refusal they cannot find, and a
// reply whose enhanced status contradicts its code gives a peer parsing
// one the opposite verdict from a peer parsing the other, so both halves
// are in every pattern.
//
// The two the author binding writes are separated by what an operator
// would go and look at. `5.7.1` says the author was read and this
// account may not write it, which sends them to the alias table.
// `5.6.0` says the header block does not name one readable author,
// which sends them to the client that wrote it. Both are permanent: the
// verdict is a function of the message and the credential, and a retry
// carries the same two.
var AUTHOR_REFUSAL    = /^550 5\.7\.1 /m;
var HEADER_REFUSAL    = /^550 5\.6\.0 /m;
// 554, not 550. RFC 5321 section 4.2.2 gives 554 for a transaction that
// failed after the message was accepted for transfer, which is where a
// body check runs, and it is what the listener's own bare-LF refusal
// writes. Pinning 550 here would have asserted a code no path produces.
var SMUGGLING_REFUSAL = /^554 5\.7\.0 /m;

// Any reply at all whose class is permanent, for the assertions whose
// subject is that the peer was not told to retry.
var PERMANENT_REPLY = /^5\d\d 5\.\d{1,3}\.\d{1,3} /m;

function fromVectors(alice, bob) {
  var at     = alice.indexOf("@");
  var tagged = alice.slice(0, at) + "+receipts" + alice.slice(at);
  return [
    {
      name:     "her own address",
      marker:   "from-own-3b71c4e2",
      headers:  ["From: " + alice],
      accepted: true,
      why:      "an account may write its own address in From",
    },
    {
      name:     "her own address with a display name",
      marker:   "from-display-9d02af51",
      headers:  ["From: \"Alice Smith\" <" + alice + ">"],
      accepted: true,
      why:      "a display name beside an address she owns changes nothing",
    },
    {
      name:     "her own subaddress",
      marker:   "from-subaddress-6ea3f180",
      headers:  ["From: " + tagged],
      accepted: true,
      why:      "an RFC 5233 tag on her own local part is still her address, " +
                "which is what the routing layer already says about it",
    },
    {
      name:     "an alias that lands in her mailbox",
      marker:   "from-alias-c47b0d93",
      headers:  ["From: sales@" + DOMAIN],
      accepted: true,
      why:      "an alias routed to her mailbox is an address she may write as",
    },
    {
      name:     "another account's address",
      marker:   "from-other-account-71fa9b26",
      headers:  ["From: " + bob],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "an account may not write a colleague's address in From, which " +
                "is the impersonation the envelope binding never covered",
    },
    {
      name:     "an address at a hosted domain that belongs to nobody",
      marker:   "from-unassigned-2c8e6f04",
      headers:  ["From: \"The Chair\" <ceo@" + DOMAIN + ">"],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "an address nobody holds is not an address this account holds, " +
                "and the domain key would sign it into alignment",
    },
    {
      name:     "an outside address and nothing else",
      marker:   "from-foreign-domain-84d15a7c",
      headers:  ["From: alice@notmine.example"],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "nothing in the message is an identity this account may write, so " +
                "the message is attributable to nobody who authenticated for it",
    },
    {
      name:     "two authors and no Sender",
      marker:   "from-list-unbound-5f39ea18",
      headers:  ["From: " + alice + ", " + bob],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "bob is at a domain this server hosts and is not an identity this " +
                "account may write, so it is refused. The screen is per author and " +
                "applies to hosted domains only: a list naming her alongside an " +
                "author at a domain hosted elsewhere is accepted, because this " +
                "server's key creates no alignment for a domain it does not host. " +
                "Sender is not what decides this vector",
    },
    {
      name:     "two authors she may both write, named by Sender",
      marker:   "from-list-bound-a90c73df",
      headers:  ["From: " + alice + ", sales@" + DOMAIN, "Sender: " + alice],
      accepted: true,
      why:      "a list whose authors she may all write is one she may send",
    },
    {
      name:     "a colleague's address under her own Sender",
      marker:   "from-delegated-local-e26b45c1",
      headers:  ["From: " + bob, "Sender: " + alice],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "a Sender header the same client writes cannot license an author " +
                "at a domain this server signs for, or the binding is one header " +
                "away from being bypassed by whoever it was meant to stop",
    },
    {
      name:     "an outside author under her own Sender",
      marker:   "from-delegated-foreign-30fc8a72",
      headers:  ["From: \"A Partner\" <partner@othercorp.example>", "Sender: " + alice],
      accepted: true,
      why:      "RFC 5322 section 3.6.2 makes Sender the agent that transmitted " +
                "the message, and an author this server hosts nothing for gets no " +
                "alignment from this server's key, so their own DMARC policy is " +
                "what answers for them and refusing it breaks the delegation shape",
    },
    {
      name:     "her own From under somebody else's Sender",
      marker:   "from-sender-forged-d3810b6f",
      headers:  ["From: " + alice, "Sender: " + bob],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "Sender names who sent it, so a Sender she may not write is a " +
                "claim that somebody else transmitted this",
    },
    {
      name:     "two Sender fields",
      marker:   "from-sender-doubled-b7c209e5",
      headers:  ["From: " + alice, "Sender: " + alice, "Sender: " + bob],
      accepted: false,
      wire:     HEADER_REFUSAL,
      why:      "RFC 5322 section 3.6 allows one Sender, and two leave the " +
                "transmitting agent for the receiver to guess at",
    },
    {
      name:     "two From fields",
      marker:   "from-doubled-1ac4de70",
      headers:  ["From: " + alice, "From: " + bob],
      accepted: false,
      wire:     HEADER_REFUSAL,
      why:      "RFC 5322 section 3.6 allows one From, and two leave the author " +
                "for the receiver to choose, which is the choice being forged",
    },
    {
      name:     "no From at all",
      marker:   "from-absent-48b3e0c9",
      headers:  [],
      accepted: false,
      wire:     HEADER_REFUSAL,
      why:      "RFC 5322 section 3.6 makes From mandatory, and a message with " +
                "none is one this server would sign without knowing whose it is",
    },
    {
      name:     "a From naming an empty group",
      marker:   "from-empty-group-f5027ab4",
      headers:  ["From: undisclosed-authors:;"],
      accepted: false,
      wire:     HEADER_REFUSAL,
      why:      "RFC 6854 group syntax naming nobody identifies no author, so " +
                "there is no identity to bind and none to display",
    },
    {
      name:     "a colleague's address written into the display name",
      marker:   "from-display-carries-another-2f8c19b0",
      headers:  ["From: \"" + alice + "\" <" + bob + ">"],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "the address is the part inside the angle brackets, and it is a " +
                "colleague's. A reader that took the quoted text for the address " +
                "would bind against a name the author chose rather than against " +
                "the mailbox the message is actually from",
    },
    {
      name:     "her own address quoted inside a display name beside a colleague's",
      marker:   "from-display-shadow-a4e17d6c",
      headers:  ["From: \"Alice <" + alice + ">\" <" + bob + ">"],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "an owned address spelled inside the display name, angle brackets " +
                "and all, is still text. Reading it as a second address would let " +
                "any account write any colleague's address by naming its own beside it",
    },
    {
      name:     "a group naming a colleague",
      marker:   "from-group-names-another-7c30b5e9",
      headers:  ["From: recipients:" + bob + ";"],
      accepted: false,
      wire:     AUTHOR_REFUSAL,
      why:      "RFC 6854 group syntax is a wrapper rather than an exemption: the " +
                "address inside is the author, and it is one this account does not hold",
    },
    {
      name:     "a domain whose letters are not the letters they look like",
      marker:   "from-confusable-domain-8b52ea07",
      // The middle letter is Cyrillic U+0430, which renders as an "a"
      // beside the Latin ones around it. The address is at a domain this
      // server does not host, so a reader that let it through would sign
      // mail for a name the operator never registered.
      headers:  ["From: alice@exаmple.com"],
      accepted: false,
      wire:     HEADER_REFUSAL,
      why:      "a mixed-script domain is not the domain it is drawn to look like, " +
                "and the address guard refuses to read it at all rather than " +
                "resolving a name whose letters are not the letters they appear to be",
    },
  ];
}

// One submission carried to the reply the server writes about the
// message. The envelope sender is always her own address, so the
// envelope binding passes on every vector and the only thing under test
// is the header.
async function submitWith(ports, caPem, alice, bob, vector) {
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-from-" + vector.marker);
  sender.send("MAIL FROM:<" + alice + ">");
  await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw(vector.headers.concat([
    "To: " + bob,
    "Subject: " + vector.marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + vector.marker + "@" + DOMAIN + ">",
    "",
    "A message written to test which From header this account may write.",
    "",
    ".",
    "",
  ]).join("\r\n"), "<a message whose From names " + vector.name + ">");
  var reply = await sender.read(/^\d{3} /m, "message answered");
  sender.send("QUIT");
  sender.close();
  return reply;
}

async function theFromHeaderIsBoundToTheAuthenticatedAccount(ports, caPem, alice, bob) {
  var vectors = fromVectors(alice, bob);
  for (var i = 0; i < vectors.length; i += 1) {
    var vector = vectors[i];
    var reply  = await submitWith(ports, caPem, alice, bob, vector);
    if (vector.accepted) {
      count("From naming " + vector.name + " is accepted, because " + vector.why,
        /^250 /m.test(reply), visible(reply));
      continue;
    }
    count("From naming " + vector.name + " is refused, because " + vector.why,
      !/^250 /m.test(reply), visible(reply));
    // The refusal is permanent, so a conforming MTA bounces it to its
    // own sender instead of retrying a message that will be refused
    // identically until its queue lifetime runs out (RFC 5321 §4.2.1).
    count("and the refusal of " + vector.name + " is permanent rather than a retry invitation",
      PERMANENT_REPLY.test(reply), visible(reply));
    // Pinned on the exact pair the listener writes, because an operator
    // filtering their log needs the code that actually appears and a
    // peer reads the enhanced status rather than the code.
    count("and it carries the code this refusal names for itself",
      vector.wire.test(reply), visible(reply));
  }
}

// Where the wire codes are settled. Every accepted vector is a message
// in bob's mailbox and every refused one is a message that was never
// stored, never signed and never relayed.
async function onlyThePermittedFromHeadersReachedTheMailbox(ports, caPem, alice, bob) {
  var vectors = fromVectors(alice, bob);
  var reader  = await imapSession(ports.imap, caPem, bob, BOB_PASSWORD, "imap-bob-from");
  reader.send("f0 SELECT INBOX");
  var selected = await reader.read(/^f0 (OK|NO|BAD)/m, "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  count("bob's mailbox can be read", existing !== null, visible(selected));

  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var seen = "";
  for (var seq = 1; seq <= held; seq += 1) {
    reader.send("f" + seq + " FETCH " + seq + " BODY.PEEK[]");
    seen += await reader.read(new RegExp("^f" + seq + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
  }
  reader.send("fx LOGOUT");
  reader.close();

  for (var i = 0; i < vectors.length; i += 1) {
    var vector = vectors[i];
    var landed = seen.indexOf(vector.marker) !== -1;
    if (vector.accepted) {
      count("the message whose From named " + vector.name + " reached the mailbox",
        landed, vector.marker + (landed ? " is present" : " is missing"));
      continue;
    }
    count("nothing reached the mailbox from the message whose From named " + vector.name,
      !landed, vector.marker + (landed ? " is present" : " is absent"));
  }

  // The alias case settled in the same mailbox. A 250 is a claim about
  // what the server did next, and this is where it is answered.
  var aliasLanded = seen.indexOf(ALIAS_ENVELOPE_MARKER) !== -1;
  count("the message sent entirely under an alias reached the recipient's mailbox",
    aliasLanded, ALIAS_ENVELOPE_MARKER + (aliasLanded ? " is present" : " is missing"));
}

// The same rule on the other way in. RFC 3030 chunked transfer is a
// second way to hand this server a message and it reaches the same
// relay, so a binding that held only on DATA would be a binding any
// client could step around by announcing CHUNKING, which this listener
// advertises. Both answers are asserted, because a check that refused
// every chunked message would satisfy the refusal on its own.
async function theBindingHoldsOnTheChunkedPathToo(ports, caPem, alice, bob) {
  var cases = [
    { marker: "bdat-own-9f21c845",   from: alice, accepted: true },
    { marker: "bdat-forged-04ae7b13", from: "ceo@" + DOMAIN, accepted: false },
  ];

  for (var i = 0; i < cases.length; i += 1) {
    var vector = cases[i];
    var sender = await submissionSession(ports.submission, caPem,
      alice, ALICE_PASSWORD, "submission-bdat-from-" + i);
    await envelopeFor(sender, alice, bob, "a chunked message from " + vector.from);
    var payload = Buffer.from([
      "From: " + vector.from,
      "To: " + bob,
      "Subject: " + vector.marker,
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + vector.marker + "@" + DOMAIN + ">",
      "",
      "A chunked message written to test the author binding.",
      "",
    ].join("\r\n"), "ascii");
    bdat(sender, payload, true, "<a chunked message from " + vector.from + ">");
    var reply = await sender.read(/^\d{3} /m, "chunked message answered");
    if (vector.accepted) {
      count("a chunked message she may write is accepted",
        /^250 /m.test(reply), visible(reply));
    } else {
      count("and a chunked message under an address she may not write is refused, " +
        "so announcing CHUNKING is not a way around the binding",
        AUTHOR_REFUSAL.test(reply), visible(reply));
    }
    sender.send("QUIT");
    sender.close();
  }

  var reader = await imapSession(ports.imap, caPem, bob, BOB_PASSWORD, "imap-bob-bdat-from");
  reader.send("c0 SELECT INBOX");
  var selected = await reader.read(/^c0 (OK|NO|BAD)/m, "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var seen = "";
  for (var seq = 1; seq <= held; seq += 1) {
    reader.send("c" + seq + " FETCH " + seq + " BODY.PEEK[]");
    seen += await reader.read(new RegExp("^c" + seq + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
  }
  reader.send("cx LOGOUT");
  reader.close();

  count("the chunked message she may write reached the mailbox",
    seen.indexOf("bdat-own-9f21c845") !== -1, "bdat-own-9f21c845");
  count("and the chunked message under a forged author reached nothing",
    seen.indexOf("bdat-forged-04ae7b13") === -1, "bdat-forged-04ae7b13");
}

// The binding belongs to authenticated submission and to nothing else.
//
// Two things must stay outside it, and both would break loudly if the
// rule were applied where it does not belong. Inbound mail carries a
// From nobody here authenticated as, because that is what inbound mail
// is: a stranger writing under their own name. And the reports this
// server composes for itself, the delivery report a failed recipient
// produces among them, name the postmaster as their author and are
// handed to the delivery path rather than submitted, so a rule about
// what a client may write would silence exactly the reports that say a
// message failed.
//
// Both are asserted on the wire and on the record rather than on the
// shape of the source, because the claim is about which messages the
// rule is applied to and that is a thing the server does rather than a
// thing the code looks like.
var FROM_REJECTED = "blamepost.mail.listeners.submission_from_not_owned";

async function theBindingIsScopedToAuthenticatedSubmission(ports, caPem, bob) {
  await b.audit.flush();
  var before = await b.audit.query({ action: FROM_REJECTED, limit: 200 });
  var beforeCount = Array.isArray(before) ? before.length : 0;

  // A stranger delivering to bob, writing under their own name on their
  // own domain. Nobody on this server owns that address and the message
  // has to be accepted anyway.
  var peer = await Wire.mx(ports.mx, { caPem: caPem, servername: HOSTNAME,
    label: "mx-foreign-from" });
  peer.send("MAIL FROM:<outsider@peer.example>");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + bob + ">");
  await peer.read(/^\d{3} /m, "RCPT TO answered");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: \"An Outsider\" <outsider@peer.example>",
    "To: " + bob,
    "Subject: inbound-foreign-from-0d5a91cc",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <inbound-foreign-from-0d5a91cc@peer.example>",
    "",
    "Mail from somebody this server never authenticated.",
    "",
    ".",
    "",
  ].join("\r\n"), "<an inbound message under a foreign From>");
  var inboundReply = await peer.read(/^\d{3} /m, "message answered");
  count("inbound mail under a From nobody here owns is still accepted",
    /^250 /m.test(inboundReply), visible(inboundReply));
  peer.send("QUIT");
  peer.close();

  await b.audit.flush();
  var after = await b.audit.query({ action: FROM_REJECTED, limit: 200 });
  var afterCount = Array.isArray(after) ? after.length : 0;
  count("and the header binding wrote no row about it, because it never ran",
    afterCount === beforeCount,
    beforeCount + " row(s) before, " + afterCount + " after");
}

// A recipient this server hosts and does not have. The message is
// accepted, the recipient is refused, and the server composes a
// delivery report addressed back to the sender under its own postmaster
// identity. That report is internally generated mail traveling through
// the delivery path, and the binding must not have been applied to it.
async function theServerStillReportsAFailedRecipient(ports, caPem, alice) {
  await b.audit.flush();
  var before = await b.audit.query({ action: FROM_REJECTED, limit: 200 });
  var beforeCount = Array.isArray(before) ? before.length : 0;

  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-report");
  sender.send("MAIL FROM:<" + alice + ">");
  await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<nobody@" + DOMAIN + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: " + alice,
    "To: nobody@" + DOMAIN,
    "Subject: report-trigger-7c3e04b8",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <report-trigger-7c3e04b8@" + DOMAIN + ">",
    "",
    "A message for a mailbox that is not here.",
    "",
    ".",
    "",
  ].join("\r\n"), "<a message for a local address that does not exist>");
  var reply = await sender.read(/^\d{3} /m, "message answered");
  sender.send("QUIT");
  sender.close();

  // Her own From, so the binding passes and whatever the wire says next
  // is about the recipient rather than about the header.
  count("a message she may write is not refused for its header when the " +
    "recipient is the thing that is wrong",
    !AUTHOR_REFUSAL.test(reply) && !HEADER_REFUSAL.test(reply), visible(reply));

  await b.audit.flush();
  var after = await b.audit.query({ action: FROM_REJECTED, limit: 200 });
  var afterCount = Array.isArray(after) ? after.length : 0;
  count("and composing the report for it wrote no header refusal of its own",
    afterCount === beforeCount,
    beforeCount + " row(s) before, " + afterCount + " after");
}

// The refusal an operator reads. A shared or delegated mailbox is the
// first thing an operator trips over here, and a bare refusal sends
// them looking at their mail client. The row has to name the identity
// that was rejected and the ones that would have been accepted, or the
// operator cannot tell a misconfigured client from a missing alias.
async function theRefusalNamesWhatItRejectedAndWhatItWouldAccept(alice, bob) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: FROM_REJECTED, limit: 200 });
  count("a refused From header is on the audit chain under its own action",
    Array.isArray(rows) && rows.length >= 1,
    Array.isArray(rows) ? rows.length + " row(s)" : String(rows));
  if (!Array.isArray(rows) || rows.length === 0) return;

  count("and it is filed as a denial rather than a failure",
    rows.every(function (row) { return row.outcome === "denied"; }),
    JSON.stringify(rows.map(function (row) { return row.outcome; })));

  var text = JSON.stringify(rows);
  count("the row names the identity that was rejected",
    text.indexOf(bob) !== -1, "looked for " + bob);
  count("and the ones this account would have been allowed to write",
    text.indexOf(alice) !== -1 && text.indexOf("sales@" + DOMAIN) !== -1,
    "looked for " + alice + " and sales@" + DOMAIN);
}

// ---- the chunked ingest path ------------------------------------------------

// A message built to be read as two. The first half is an ordinary note
// from alice; then an end-of-data sequence written the way a lenient
// receiver accepts it, and then a whole second SMTP transaction with a
// sender alice does not own.
function twoMessagesInOne(alice, bob, separator) {
  var first = [
    "From: " + alice,
    "To: " + bob,
    "Subject: chunked note",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <chunked-8ba41c7e@example.com>",
    "",
    "The first message.",
    "",
  ].join("\r\n");
  var second = [
    "MAIL FROM:<chair@" + DOMAIN + ">",
    "RCPT TO:<" + bob + ">",
    "DATA",
    "From: chair@" + DOMAIN,
    "Subject: " + SMUGGLED_MARKER,
    "",
    "The second message, from a sender the account does not own.",
    ".",
    "",
  ].join("\r\n");
  return Buffer.from(first + separator + second, "ascii");
}

async function envelopeFor(session, alice, bob, what) {
  session.send("MAIL FROM:<" + alice + ">");
  await session.read(/^\d{3} /m, what + ": MAIL FROM answered");
  session.send("RCPT TO:<" + bob + ">");
  await session.read(/^\d{3} /m, what + ": RCPT TO answered");
}

function bdat(session, payload, last, note) {
  session.sendRaw(Buffer.concat([
    Buffer.from("BDAT " + payload.length + (last ? " LAST" : "") + "\r\n", "ascii"),
    payload,
  ]), "BDAT " + payload.length + (last ? " LAST" : "") + " + " + note);
}

// The extension is advertised, so it is offered, so it is used. An
// advertised verb nothing exercises is the one whose refusals nobody
// has read.
async function chunkingIsAdvertised(ports, caPem, alice) {
  var session = await Wire.connect(ports.submission, "submission-caps");
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  var caps = await session.read(/^250 /m, "EHLO accepted over TLS");
  count("the submission listener offers RFC 3030 chunked transfer",
    /^250[- ]CHUNKING\r?$/m.test(caps), visible(caps));
  session.send("QUIT");
  session.close();

  // And it works, so nothing below can be satisfied by a listener that
  // refuses every chunked message rather than the hostile ones. A
  // refusal bought that way costs every client that speaks the
  // extension this listener told it to speak.
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-chunked-ok");
  await envelopeFor(sender, alice, alice, "a well formed chunked message");
  var whole = Buffer.from([
    "From: " + alice,
    "To: " + alice,
    "Subject: chunked and well formed",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <chunked-ok-8ba41c7e@example.com>",
    "",
    "A body with nothing hidden in it.",
    "",
  ].join("\r\n"), "ascii");
  bdat(sender, whole, true, "<a well formed message>");
  var accepted = await sender.read(/^\d{3} /m, "chunked message answered");
  count("and a well formed chunked message is accepted",
    /^250 /m.test(accepted), visible(accepted));
  sender.send("QUIT");
  sender.close();
}

// The claim. A body that some receiver will read as two messages is
// refused on every way in this server offers of handing one over: the
// port a stranger delivers to, and both of the two an account holder
// submits through.
//
// It has to be refused rather than repaired. The second message
// inherits the first's authentication: it travels on a connection this
// server opened to the receiver, from an address this server is
// authorized to send from, so a forged sender inside it passes SPF,
// DKIM alignment and DMARC on the strength of the relay rather than on
// anything the forgery can prove for itself.
//
// All three are asserted because the rule is about the octets rather
// than about the framing they arrived in, and a rule shared by several
// ingest paths and tested on one is a rule that holds on one.
async function aBodyReadAsTwoMessagesIsRefusedOnEveryPath(ports, caPem, alice, bob) {
  for (var i = 0; i < END_OF_DATA_VARIANTS.length; i += 1) {
    var variant = END_OF_DATA_VARIANTS[i];
    var payload = twoMessagesInOne(alice, bob, variant.bytes);
    var terminated = Buffer.concat([payload, Buffer.from("\r\n.\r\n", "ascii")]);

    var peer = await Wire.mx(ports.mx, { caPem: caPem, servername: HOSTNAME,
      label: "mx-smuggling-" + i });
    peer.send("MAIL FROM:<outsider@peer.example>");
    await peer.read(/^\d{3} /m, "MAIL FROM answered");
    peer.send("RCPT TO:<" + bob + ">");
    await peer.read(/^\d{3} /m, "RCPT TO answered");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw(terminated, "<a body ending " + variant.name + ", and its terminating dot>");
    var mxReply = await peer.read(/^\d{3} /m, "message answered");
    count("a body carrying " + variant.name + " is refused on the port a stranger delivers to",
      SMUGGLING_REFUSAL.test(mxReply), visible(mxReply));
    peer.send("QUIT");
    peer.close();

    var viaData = await submissionSession(ports.submission, caPem,
      alice, ALICE_PASSWORD, "submission-data-" + i);
    await envelopeFor(viaData, alice, bob, variant.name + " over DATA");
    viaData.send("DATA");
    await viaData.read(/^354 /m, "DATA answered");
    viaData.sendRaw(terminated,
      "<a body ending " + variant.name + ", and its terminating dot>");
    var dataReply = await viaData.read(/^\d{3} /m, "message answered");
    count(variant.name + " is refused when an account holder submits it over DATA",
      SMUGGLING_REFUSAL.test(dataReply), visible(dataReply));
    viaData.send("QUIT");
    viaData.close();

    var viaBdat = await submissionSession(ports.submission, caPem,
      alice, ALICE_PASSWORD, "submission-bdat-" + i);
    await envelopeFor(viaBdat, alice, bob, variant.name + " over BDAT");
    bdat(viaBdat, payload, true, "<a body carrying " + variant.name + ">");
    var bdatReply = await viaBdat.read(/^\d{3} /m, "chunked message answered");
    count(variant.name + " is refused when the same account holder submits it in chunks",
      SMUGGLING_REFUSAL.test(bdatReply), visible(bdatReply));
    viaBdat.send("QUIT");
    viaBdat.close();
  }
}

// The shape DATA cannot produce at all. A chunk boundary placed inside
// the sequence means no single chunk holds it: the first ends on the
// line break, the second opens on the dot. A check that ran per chunk
// would see two innocent halves, so the check has to be on the message
// the chunks add up to.
async function aSequenceSplitAcrossTwoChunksIsRefused(ports, caPem, alice, bob) {
  var payload = twoMessagesInOne(alice, bob, "\n.\n");
  var cut     = payload.indexOf(Buffer.from("\n.\n", "ascii")) + 1;

  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-bdat-split");
  await envelopeFor(sender, alice, bob, "a sequence split across two chunks");

  bdat(sender, payload.subarray(0, cut), false, "<up to and including the line break>");
  var first = await sender.read(/^\d{3} /m, "first chunk answered");
  count("a chunk that ends mid-sequence is acknowledged like any other",
    /^250 /m.test(first), visible(first));

  bdat(sender, payload.subarray(cut), true, "<the dot and everything after it>");
  var second = await sender.read(/^\d{3} /m, "last chunk answered");
  count("and the message the two chunks add up to is refused",
    SMUGGLING_REFUSAL.test(second), visible(second));

  sender.send("QUIT");
  sender.close();
}

// Nothing the refusals above turned away reached a mailbox. A wire code
// is a claim about what the server did next, and the mailbox is where
// that claim is settled.
async function nothingSmuggledReachedTheMailbox(ports, caPem, bob) {
  var reader = await imapSession(ports.imap, caPem, bob, BOB_PASSWORD, "imap-bob-smuggling");
  reader.send("s0 SELECT INBOX");
  var selected = await reader.read(/^s0 (OK|NO|BAD)/m, "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  count("bob's mailbox can be read", existing !== null, visible(selected));

  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var carrying = 0;
  for (var seq = 1; seq <= held; seq += 1) {
    reader.send("s" + seq + " FETCH " + seq + " BODY.PEEK[]");
    var fetched = await reader.read(new RegExp("^s" + seq + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
    if (fetched.indexOf(SMUGGLED_MARKER) !== -1) carrying += 1;
  }
  count("and no message in it carries the second message that was hidden in the first",
    carrying === 0, carrying + " of " + held + " message(s) carry " + SMUGGLED_MARKER);

  reader.send("sx LOGOUT");
  reader.close();
}

// The signing half of the submission path, driven on the wire.
//
// Two claims, and they are about different failures. A domain holding
// no selector relays unsigned, which the client is answered 250 for and
// told nothing about, so the record is the only place an operator can
// find it. And an ordinary 8-bit message, which is what an unencoded
// body in a legacy single-byte charset is, is SIGNED rather than
// relayed unsigned or rewritten on the way.
//
// The second one is the one that needs a wire session to prove. A
// signer that decodes the message hands back a different message from
// the one submitted, and the copy that reaches the mailbox is that
// different message with a valid signature over it, so nothing anywhere
// still holds what the account sent and the alteration reads as
// authentic. The mailbox is where that shows, which is why the reader
// below keeps the socket in binary mode: a session that decodes before
// asserting cannot tell the stored octets from a re-encoding of them.
async function theSubmissionPathSignsWithoutRewriting(ports, caPem, alice, bob, dkimHandle) {
  var NO_KEY = "blamepost.mail.listeners.submission_unsigned_no_key";
  var UNSIGNED = "blamepost.mail.listeners.submission_unsigned";

  // Everything sent so far went out from a domain holding no selector,
  // so the setup-state rows are already on the chain.
  await b.audit.flush();
  var noKeyRows = await b.audit.query({ action: NO_KEY, limit: 50 });
  count("relaying from a domain with no selector is filed under its own action",
    Array.isArray(noKeyRows) && noKeyRows.length >= 1,
    Array.isArray(noKeyRows) ? noKeyRows.length + " row(s)" : String(noKeyRows));
  count("and the row that says a message was relayed unsigned is filed as a failure, " +
    "which is the one thing an operator queries an audit trail on",
    noKeyRows[0] && noKeyRows[0].outcome === "failure",
    JSON.stringify(noKeyRows[0] && noKeyRows[0].outcome));

  // Now the domain has keys, so the next message is one that signs.
  await dkimHandle.generate({ domain: DOMAIN, selector: "bp202608" });

  // Six of these octets are not valid UTF-8 standing alone, and a decode
  // turns each of them into three, so a rewrite is visible as a length
  // change as well as a content change.
  var body = Buffer.from([
    0x43, 0x61, 0x66, 0xe9, 0x0d, 0x0a,           // "Cafe" with an acute e, ISO-8859-1
    0x82, 0xa0, 0x82, 0xa2, 0x0d, 0x0a,           // two Shift_JIS kana
  ]);
  var message = Buffer.concat([
    Buffer.from([
      "From: " + alice,
      "To: " + bob,
      "Subject: legacy charset",
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <submission-8bit@example.com>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=iso-8859-1",
      "Content-Transfer-Encoding: 8bit",
      "", "",
    ].join("\r\n"), "latin1"),
    body,
  ]);

  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-8bit");
  sender.send("MAIL FROM:<" + alice + ">");
  await sender.read(/^250 /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^250 /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  // RFC 5321 section 4.1.1.4 terminates the mail data with CRLF, a
  // period and CRLF, and the CRLF that opens that sequence is not part
  // of the message. So the terminator is written in full here rather
  // than borrowing the message's own last line ending for it, which
  // leaves the stored copy comparable to the fixture octet for octet
  // instead of two bytes short of it for a reason that has nothing to do
  // with signing.
  sender.sendRaw(Buffer.concat([message, Buffer.from("\r\n.\r\n", "latin1")]),
    "<a message carrying octets that are not valid UTF-8>");
  var accepted = await sender.read(/^\d{3} /m, "message answered");
  count("an 8-bit message is accepted for delivery", /^250 /m.test(accepted), visible(accepted));
  sender.send("QUIT");
  sender.close();

  await b.audit.flush();
  var noKeyAfter = await b.audit.query({ action: NO_KEY, limit: 50 });
  var unsignedAfter = await b.audit.query({ action: UNSIGNED, limit: 50 });
  count("relaying it drew no unsigned row at all, because it was signed",
    Array.isArray(noKeyAfter) && noKeyAfter.length === noKeyRows.length &&
    Array.isArray(unsignedAfter) && unsignedAfter.length === 0,
    noKeyRows.length + " no-key before, " + (noKeyAfter || []).length + " after; " +
      (unsignedAfter || []).length + " unclassified");

  // What reached the mailbox. The message is found by its Message-ID
  // rather than by position, because the cases before this one left mail
  // in the same folder.
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "imap-bob-8bit",
    address: bob, password: BOB_PASSWORD, binary: true,
  });
  try {
    reader.send("c0 SELECT INBOX");
    await reader.read(/^c0 (OK|NO|BAD)/m, "SELECT answered");
    reader.send("c1 SEARCH HEADER MESSAGE-ID \"<submission-8bit@example.com>\"");
    var found = await reader.read(/^c1 (OK|NO|BAD)/m, "SEARCH answered");
    var hit = /^\* SEARCH ([0-9 ]+)/m.exec(found);
    count("the 8-bit message reached the recipient's mailbox", hit !== null, visible(found));
    if (hit === null) return;
    var seq = hit[1].trim().split(/\s+/).pop();

    reader.send("c2 FETCH " + seq + " BODY.PEEK[]");
    var raw = await reader.readBytes(/^c2 (OK|NO|BAD)/m, "stored copy fetched");
    var view = raw.toString("latin1");
    var literal = /\{(\d+)\}\r\n/.exec(view);
    count("the stored copy comes back as a counted literal", literal !== null,
      visible(view.slice(0, 200)));
    if (literal === null) return;
    var from    = literal.index + literal[0].length;
    var stored  = raw.subarray(from, from + parseInt(literal[1], 10));

    count("the delivered copy carries a signature from each algorithm",
      (stored.toString("latin1").match(/^DKIM-Signature:/gm) || []).length === 2,
      String((stored.toString("latin1").match(/^DKIM-Signature:/gm) || []).length));
    count("and the message below the signatures is the octets the account submitted",
      stored.subarray(stored.length - message.length).equals(message),
      stored.length + " octets stored for a " + message.length +
        " octet message plus its signatures; stored tail " +
        stored.subarray(stored.length - 24).toString("hex") + ", submitted tail " +
        message.subarray(message.length - 24).toString("hex"));

    reader.send("c3 LOGOUT");
  } finally {
    reader.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("submission");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "submission test" });
    // A second hosted domain, because a binding measured on a server
    // hosting one domain cannot show whether the domain is part of what
    // it compares.
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: SECOND_DOMAIN, by: "submission test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    var aliasAddress = "sales@" + DOMAIN;
    await identity.aliases.add({ address: aliasAddress, destination: alice.address });
    // An alias on the second domain, which is an identity, and a
    // catch-all on the same domain, which is not.
    var secondDomainAlias = "support@" + SECOND_DOMAIN;
    await identity.aliases.add({ address: secondDomainAlias, destination: alice.address });
    await identity.aliases.add({ domain: SECOND_DOMAIN, catchAll: true,
      destination: alice.address });
    // An alias whose destination is another alias rather than a mailbox.
    // Mail addressed to it reaches alice, and the author set follows one
    // row rather than a chain, so it is not an identity either.
    var chainedAlias = "events@" + DOMAIN;
    await identity.aliases.add({ address: chainedAlias, destination: aliasAddress });
    var withdrawableAlias = "orders@" + DOMAIN;
    await identity.aliases.add({ address: withdrawableAlias, destination: alice.address });

    var sections = {
      // The MX port is bound here because one case below asks both
      // listeners about the same address and compares their answers.
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // Bound because the shipped configuration binds it. Leaving it off
      // would run this whole file against the one submission transport
      // where a binding defect on the other cannot appear.
      submissions: { enabled: true,  port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
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
      submission:  sections.submission.port,
      submissions: sections.submissions.port,
      imap:        sections.imap.port,
      mx:          sections.mx.port,
    };

    await aliceWritesToBobAndBobReadsIt(ports, leaf.ca, alice.address, bob.address);
    await aliceCannotSendAsBob(ports, leaf.ca, alice.address, bob.address);
    await sendingAsAnOwnedAlias(ports, leaf.ca, alice.address, bob.address, aliasAddress);
    await anAliasOnASecondHostedDomainIsASendingIdentity(ports, leaf.ca, alice.address,
      secondDomainAlias);
    await theEnvelopeRefusesWhatIsNotASendingIdentity(ports, leaf.ca, alice.address, [
      {
        name:    "a catch-all that routes to her mailbox",
        address: "anything-at-all@" + SECOND_DOMAIN,
        why:     "a catch-all claims every name at a domain, so counting one would hand " +
                 "the account holding it every address the domain could ever carry",
      },
      {
        name:    "an alias that reaches her through a second alias",
        address: chainedAlias,
        why:     "the set follows one alias row rather than a chain, which is the same " +
                 "rule the author binding applies to the header",
      },
    ]);
    await theImplicitTlsPortBindsTheSameIdentity(ports, leaf.ca, alice.address, bob.address,
      aliasAddress, "anything-at-all@" + SECOND_DOMAIN);
    await awithdrawnAliasStopsBeingASender(ports, leaf.ca, identity, alice.address,
      withdrawableAlias);
    await theTwoPortsAgreeAboutAnOwnedSubaddress(ports, leaf.ca, alice.address, bob.address);
    await theEnvelopeBindingComparesAddressesRatherThanStrings(ports, leaf.ca, alice.address);
    await theFromHeaderIsBoundToTheAuthenticatedAccount(ports, leaf.ca, alice.address, bob.address);
    await onlyThePermittedFromHeadersReachedTheMailbox(ports, leaf.ca, alice.address, bob.address);
    await theBindingHoldsOnTheChunkedPathToo(ports, leaf.ca, alice.address, bob.address);
    await theBindingIsScopedToAuthenticatedSubmission(ports, leaf.ca, bob.address);
    await theServerStillReportsAFailedRecipient(ports, leaf.ca, alice.address);
    await theRefusalNamesWhatItRejectedAndWhatItWouldAccept(alice.address, bob.address);
    await chunkingIsAdvertised(ports, leaf.ca, alice.address);
    await aBodyReadAsTwoMessagesIsRefusedOnEveryPath(ports, leaf.ca, alice.address, bob.address);
    await aSequenceSplitAcrossTwoChunksIsRefused(ports, leaf.ca, alice.address, bob.address);
    await nothingSmuggledReachedTheMailbox(ports, leaf.ca, bob.address);
    await theSubmissionPathSignsWithoutRewriting(ports, leaf.ca,
      alice.address, bob.address, server.mail.dkim);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // `server.stop` does not close the store, because the caller owns
    // what it passed in, and the database handle behind it is one per
    // process.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "mail-submission", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
