// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a sending credential may open and what it may write, measured on
 * the wire of every listener this server binds.
 *
 * A sending credential is scoped to one hosted domain and may write any
 * local part in it. An account is scoped to its own addresses. The two
 * are verified by the same code path today, so the claims below are the
 * ones that separate them:
 *
 *   - Submission authenticates a credential and relays a message written
 *     under an ordinary address at its own domain.
 *   - An address at a SECOND hosted domain is refused, on the envelope
 *     and in the header, and the reply says the identity does not own the
 *     address rather than that it has no mailbox assigned to it.
 *   - IMAP, POP3 and ManageSieve refuse the same credential. A credential
 *     that opened a mailbox would read every message in the domain, which
 *     is a scope nobody granted and no refusal list bounds.
 *   - The refusal list still applies to the domain it is scoped to, and
 *     revoking, expiring or withdrawing the domain each stop it at the
 *     next verify rather than at the next restart.
 *
 * Two hosted domains throughout. A scope bug cannot manifest on a server
 * hosting one domain, because there is no second domain to leak into.
 *
 * Run standalone: node test/layer-2-integration/sending-credential-scope.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers     = require("../helpers");
var wire        = require("../helpers/wire");
var b           = require("../../lib/vendor/blamejs");
var config      = require("../../lib/config");
var store       = require("../../lib/store");
var blamepost   = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var saslPlain   = wire.saslPlain;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME      = "mx.example.com";
var DOMAIN        = "example.com";
// The domain the credential is NOT scoped to. Every cross-domain claim
// below is measured against this one, because a rule about which domain
// an identity may write cannot be tested on a server hosting one.
var SECOND_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

// The mailbox each credential's bounces are delivered to. Not `bounces`:
// that local part is the one every return path folds down to, so an
// account standing on it would be a mailbox competing with the alias the
// registry mints.
var BOUNCE_MAILBOX        = "postbox@" + DOMAIN;
var SECOND_BOUNCE_MAILBOX = "postbox@" + SECOND_DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The reply an envelope sender draws when the identity does not hold it.
// RFC 5321 puts a rejected sender at 553 and the enhanced status says
// why. Pinned as a pair because a peer reads one and an operator filters
// on the other.
var SENDER_REFUSAL = /^553 5\.7\.1 /m;

// The reply an author draws when the identity may not write it. This is
// the composition's own refusal rather than the listener's, and it
// carries 550 because the header is read after the message is accepted
// for transfer.
var AUTHOR_REFUSAL = /^550 5\.7\.1 /m;

// The sentence the framework's submission listener writes when the
// authenticated actor carries an EMPTY mailbox set. It is true of an
// account whose provisioning is unfinished and false of a credential,
// which is scoped to a domain and holds no mailbox by design. An
// operator who reads it goes and assigns a mailbox that has nothing to
// do with the refusal, so it must not be what a credential draws.
var NO_MAILBOXES_TEXT = /has no assigned mailboxes/;

var OWNED_TEXT = /not owned by authenticated identity/;

// ---- cases -----------------------------------------------------------------

// The credential signs in on both submission ports and writes an
// ordinary address at the domain it is scoped to. Both ports are asked
// because they are two separately constructed listeners, and RFC 8314
// tells a client to prefer the implicit-TLS one.
async function submissionAcceptsTheCredential(ports, caPem, token, bob) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-submission",
    address: DOMAIN, password: token,
  });

  sender.send("MAIL FROM:<shop@" + DOMAIN + ">");
  var mailReply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("a sending credential may write an ordinary address at the domain it is scoped " +
    "to, which is the whole of what a domain scope means",
    /^250 /m.test(mailReply), visible(mailReply));

  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: shop@" + DOMAIN,
    "To: " + bob,
    "Subject: " + CREDENTIAL_MARKER,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + CREDENTIAL_MARKER + "@" + DOMAIN + ">",
    "",
    "A receipt written by an application rather than by a person.",
    "",
    ".",
    "",
  ].join("\r\n"), "<a message written under the credential's own domain>");
  var accepted = await sender.read(/^\d{3} /m, "message answered");
  count("and the message it wrote is accepted for delivery, so the author binding " +
    "reaches the same verdict about the same address as the envelope binding",
    /^250 /m.test(accepted), visible(accepted));

  sender.send("QUIT");
  sender.close();

  // The implicit-TLS port is built from the same function and is still a
  // separate listener. A split applied to one and not the other is a
  // change every case above reports as passing.
  var implicit = await new Promise(function (resolve, reject) {
    var socket = nodeTls.connect({
      host: LOOPBACK, port: ports.submissions, servername: HOSTNAME, ca: caPem,
    }, function () { resolve(new Wire(socket, "credential-submissions")); });
    socket.once("error", reject);
  });
  await implicit.read(/^220 /m, "banner on the encrypted channel");
  implicit.send("EHLO client.example.net");
  await implicit.read(/^250 /m, "EHLO accepted");
  implicit.send("AUTH PLAIN " + saslPlain(DOMAIN, token));
  var implicitAuth = await implicit.read(/^\d{3} /m, "AUTH answered");
  count("the credential authenticates on the implicit-TLS submission port too, so the " +
    "port RFC 8314 tells a client to prefer is one an application can actually use",
    /^235 /m.test(implicitAuth), visible(implicitAuth));
  implicit.send("QUIT");
  implicit.close();
}

var CREDENTIAL_MARKER = "credential-own-domain-31f0a7c4";

// A marker for each message that must never reach a mailbox, so the wire
// codes below are settled against the folder rather than believed.
var CROSS_DOMAIN_MARKER = "credential-cross-domain-6b48d21e";
var UNHOSTED_MARKER     = "credential-unhosted-9c2f5730";
var DELEGATED_MARKER    = "credential-delegated-4d87ba05";

// The scope, measured across the two hosted domains. The envelope half
// and the header half fail independently and both are asked, because a
// composition that moved one reader onto the credential scope and left
// the other on the account set would permit as an author what it refuses
// as a sender.
async function theCredentialIsScopedToOneHostedDomain(ports, caPem, token, bob) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-cross-domain",
    address: DOMAIN, password: token,
  });

  sender.send("MAIL FROM:<shop@" + SECOND_DOMAIN + ">");
  var envelope = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an envelope sender at a SECOND hosted domain is refused, so a credential for " +
    "one domain cannot send under another this server signs for",
    SENDER_REFUSAL.test(envelope), visible(envelope));
  count("and the refusal says the identity does not own the address rather than that it " +
    "has no mailbox assigned, which is a sentence about provisioning a credential has none of",
    OWNED_TEXT.test(envelope) && !NO_MAILBOXES_TEXT.test(envelope), visible(envelope));

  sender.send("RSET");
  await sender.read(/^250 /m, "RSET answered");

  // The header half, with an envelope the credential does hold, so the
  // only thing under test is the author.
  sender.send("MAIL FROM:<shop@" + DOMAIN + ">");
  await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: shop@" + SECOND_DOMAIN,
    "To: " + bob,
    "Subject: " + CROSS_DOMAIN_MARKER,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + CROSS_DOMAIN_MARKER + "@" + SECOND_DOMAIN + ">",
    "",
    "A message whose author is at a domain this credential is not scoped to.",
    "",
    ".",
    "",
  ].join("\r\n"), "<a message authored at the other hosted domain>");
  var header = await sender.read(/^\d{3} /m, "message answered");
  count("an author at the second hosted domain is refused too, and with 550 5.7.1, " +
    "because that domain is one this server holds a selector for and would sign into " +
    "alignment over a name the credential does not speak for",
    AUTHOR_REFUSAL.test(header), visible(header));

  sender.send("QUIT");
  sender.close();
}

// A domain this server does not host at all. The envelope is refused,
// because a credential names one domain and this is not it. The author
// is refused for a different reason: no address in the message is one
// this credential may write, so the message is attributable to nobody.
async function theCredentialCannotWriteAtAnUnhostedDomain(ports, caPem, token, bob) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-unhosted",
    address: DOMAIN, password: token,
  });

  sender.send("MAIL FROM:<shop@notmine.example>");
  var envelope = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("an envelope sender at a domain this server does not host is refused, so a " +
    "credential is a scope rather than a license to relay",
    SENDER_REFUSAL.test(envelope), visible(envelope));
  count("and that refusal names the binding rather than a missing mailbox",
    OWNED_TEXT.test(envelope) && !NO_MAILBOXES_TEXT.test(envelope), visible(envelope));

  sender.send("RSET");
  await sender.read(/^250 /m, "RSET answered");
  sender.send("MAIL FROM:<shop@" + DOMAIN + ">");
  await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: partner@notmine.example",
    "To: " + bob,
    "Subject: " + UNHOSTED_MARKER,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + UNHOSTED_MARKER + "@notmine.example>",
    "",
    "A message naming an outside author and nobody this credential speaks for.",
    "",
    ".",
    "",
  ].join("\r\n"), "<a message authored outside every hosted domain>");
  var header = await sender.read(/^\d{3} /m, "message answered");
  count("a message naming only an outside author is refused, because nothing in it is " +
    "an address this credential may write and it is attributable to nobody",
    AUTHOR_REFUSAL.test(header), visible(header));

  sender.send("QUIT");
  sender.close();
}

// The allowance that has to survive the change. RFC 5322 section 3.6.2
// makes Sender the agent that transmitted a message, and an author at a
// domain this server hosts nothing for gets no alignment from this
// server's key. A credential naming itself in Sender is the on-behalf-of
// shape a sending application actually emits.
async function theOutsideAuthorAllowanceStillHolds(ports, caPem, token, bob) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-delegated",
    address: DOMAIN, password: token,
  });
  sender.send("MAIL FROM:<shop@" + DOMAIN + ">");
  await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + bob + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: \"A Partner\" <partner@othercorp.example>",
    "Sender: shop@" + DOMAIN,
    "To: " + bob,
    "Subject: " + DELEGATED_MARKER,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + DELEGATED_MARKER + "@othercorp.example>",
    "",
    "An outside author transmitted by an address this credential holds.",
    "",
    ".",
    "",
  ].join("\r\n"), "<an outside author under the credential's own Sender>");
  var reply = await sender.read(/^\d{3} /m, "message answered");
  count("an outside author under a Sender the credential may write is still accepted, " +
    "so moving the author reader onto the credential scope did not narrow the " +
    "delegation shape a sending application depends on",
    /^250 /m.test(reply), visible(reply));
  sender.send("QUIT");
  sender.close();
}

// The refusal list, which is what stops a domain scope from covering the
// addresses a person reads. It is derived per credential and enforced on
// the envelope like every other address the scope does not cover.
async function theRefusalListStillBoundsTheScope(ports, caPem, token) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-refusal-list",
    address: DOMAIN, password: token,
  });
  sender.send("MAIL FROM:<postmaster@" + DOMAIN + ">");
  var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  count("a local part on the credential's refusal list is refused inside its own domain, " +
    "because a whole-domain scope is a decision about ordinary addresses and postmaster " +
    "is the one a recipient writes to when they want a person",
    SENDER_REFUSAL.test(reply), visible(reply));
  count("and that refusal names the binding rather than a missing mailbox",
    OWNED_TEXT.test(reply) && !NO_MAILBOXES_TEXT.test(reply), visible(reply));
  sender.send("QUIT");
  sender.close();
}

// The name a credential's scope goes by inside the listener, spelled
// back at the listener on the wire.
//
// A domain scope has no address set to hand the framework, so the actor
// carries a name for the scope where an address set would go. That name
// must not be something a client can write into `MAIL FROM`: a match
// against it is an envelope the refusal list never sees. RFC 5321
// section 4.1.2 puts the reverse path in angle brackets and the reader
// stops at the first one, so a name carrying `>` cannot come off that
// line. This spells it anyway, both ways round, because the grammar it
// rests on lives in the vendored tree and a refresh can move it.
async function theScopeNameCannotBeSpelledOnTheWire(ports, caPem, token) {
  var attempts = [
    "<any address at " + DOMAIN + ">",
    "any address at " + DOMAIN,
  ];
  for (var i = 0; i < attempts.length; i += 1) {
    var sender = await Wire.submission(ports.submission, {
      caPem: caPem, servername: HOSTNAME, label: "credential-scope-name-" + i,
      address: DOMAIN, password: token,
    });
    sender.send("MAIL FROM:<" + attempts[i] + ">");
    var reply = await sender.read(/^\d{3} /m, "MAIL FROM answered");
    count("a client that writes the scope name itself into MAIL FROM is refused rather " +
      "than matched against it, so the name the listener carries is not an envelope " +
      "sender anybody can claim (" + attempts[i] + ")",
      !/^250 /m.test(reply), visible(reply));
    sender.send("QUIT");
    sender.close();
  }
}

// The claim this whole file exists for. One verifier serves submission
// and the three mailbox protocols, so a credential implemented into that
// one function opens every mailbox in its domain over IMAP, POP3 and
// ManageSieve. Each is asked with a credential that WORKS on submission,
// and each must refuse it the way it refuses a wrong password.
//
// The account is signed in on the same listener straight afterwards, so
// a refusal cannot be bought by a listener that authenticates nobody.
async function noMailboxProtocolOpensForACredential(ports, caPem, token, alice) {
  var imap = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "credential-imap",
  });
  var imapTag = imap.tag();
  imap.send(imapTag + " AUTHENTICATE PLAIN " + saslPlain(DOMAIN, token));
  var imapReply = await imap.read(new RegExp("^" + imapTag + " (OK|NO|BAD)", "m"),
    "IMAP AUTHENTICATE answered");
  count("IMAP refuses a sending credential, so a secret issued to send mail cannot open " +
    "every mailbox in the domain it sends for",
    new RegExp("^" + imapTag + " NO", "m").test(imapReply), visible(imapReply));
  imap.close();

  var imapAccount = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "credential-imap-account",
    address: alice, password: ALICE_PASSWORD,
  });
  count("and the same IMAP listener still signs an account in, so the refusal above is " +
    "about the credential rather than about a listener that authenticates nobody",
    true, "alice authenticated");
  imapAccount.send(imapAccount.tag() + " LOGOUT");
  imapAccount.close();

  var pop3 = await Wire.pop3(ports.pop3, {
    caPem: caPem, servername: HOSTNAME, label: "credential-pop3",
  });
  pop3.send("USER " + DOMAIN);
  await pop3.read(/^(\+OK|-ERR)/m, "POP3 USER answered");
  pop3.send("PASS " + token);
  var pop3Reply = await pop3.read(/^(\+OK|-ERR)/m, "POP3 PASS answered");
  count("POP3 refuses a sending credential, which matters more here than anywhere else " +
    "because a POP3 session that opened would download the maildrop and mark it deleted",
    /^-ERR/m.test(pop3Reply), visible(pop3Reply));
  pop3.send("QUIT");
  pop3.close();

  var pop3Account = await Wire.pop3(ports.pop3, {
    caPem: caPem, servername: HOSTNAME, label: "credential-pop3-account",
    address: alice, password: ALICE_PASSWORD,
  });
  count("and the same POP3 listener still signs an account in",
    true, "alice authenticated");
  pop3Account.send("QUIT");
  pop3Account.close();

  var sieve = await Wire.managesieve(ports.managesieve, {
    caPem: caPem, servername: HOSTNAME, label: "credential-managesieve",
  });
  sieve.sendNonSyncLiteral('AUTHENTICATE "PLAIN"', saslPlain(DOMAIN, token),
    "<the credential as a SASL response>");
  var sieveReply = await sieve.read(/^(?:OK|NO|BYE)[^\r\n]*\r\n/m,
    "ManageSieve AUTHENTICATE answered");
  count("ManageSieve refuses a sending credential, so a secret that sends mail cannot " +
    "rewrite the filters deciding where an account's mail lands",
    /^NO/.test(wire.lastManageSieveReply(sieveReply)), visible(sieveReply));
  sieve.close();

  var sieveAccount = await Wire.managesieve(ports.managesieve, {
    caPem: caPem, servername: HOSTNAME, label: "credential-managesieve-account",
    address: alice, password: ALICE_PASSWORD,
  });
  count("and the same ManageSieve listener still signs an account in",
    true, "alice authenticated");
  sieveAccount.send("LOGOUT");
  sieveAccount.close();
}

// A token presented under a domain other than the one its row names.
// The scope comes off the row, so a credential pasted into the wrong
// application's configuration would otherwise sign in and send as the
// domain it really belongs to, under a name the operator never wrote.
async function aTokenPresentedUnderTheWrongDomainIsRefused(ports, caPem, token) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-wrong-domain",
  });
  session.send("AUTH PLAIN " + saslPlain(SECOND_DOMAIN, token));
  var reply = await session.read(/^\d{3} /m, "AUTH answered");
  count("a token presented under a domain other than the one it was issued for is " +
    "refused, so a credential pasted into the wrong place fails loudly rather than " +
    "sending as the domain it really belongs to",
    /^535 /m.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
}

// A username that is neither an address nor a domain this server can
// read. It falls to the account path and is refused there, which is what
// keeps an operator's mistyped username out of the credential budget.
async function aBareUsernameIsStillAnAccountAttempt(ports, caPem) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-bare-username",
  });
  session.send("AUTH PLAIN " + saslPlain("alice", ALICE_PASSWORD));
  var reply = await session.read(/^\d{3} /m, "AUTH answered");
  count("a bare username is refused, because it reads as neither an address nor a " +
    "domain and an identity this server cannot read names nobody",
    /^535 /m.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
}

// The three ways a credential stops working, each measured at the next
// sign-in rather than at the next restart.
async function aRevokedCredentialStopsAtTheNextVerify(ports, caPem, creds, made) {
  await creds.revoke({ id: made.id, reason: "revoked by the scope test" });
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-revoked",
  });
  session.send("AUTH PLAIN " + saslPlain(DOMAIN, made.token));
  var reply = await session.read(/^\d{3} /m, "AUTH answered");
  count("a revoked credential is refused at the next sign-in rather than at the next " +
    "restart, which is what makes revocation a containment step",
    /^535 /m.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
}

async function anExpiredCredentialIsRefused(ports, caPem, creds) {
  var made = await creds.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a short-lived credential for the scope test",
    expiresAt:     Date.now() + b.constants.TIME.seconds(2),
  });
  // Polled rather than slept: the moment the registry starts refusing it
  // is the moment under test, and a fixed budget is the shape that
  // passes alone and fails under load.
  await helpers.waitUntil(async function () {
    var verdict = await creds.verify(made.token);
    return verdict.ok === false;
  }, { timeoutMs: 10000, label: "sending-credential-scope: the short-lived credential expires" });

  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-expired",
  });
  session.send("AUTH PLAIN " + saslPlain(DOMAIN, made.token));
  var reply = await session.read(/^\d{3} /m, "AUTH answered");
  count("an expired credential is refused on the wire, so an end date is a thing the " +
    "listener enforces rather than a field an operator reads",
    /^535 /m.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
  await creds.remove({ id: made.id, destroy: true,
    reason: "the short-lived credential has served the scope test" });
}

async function aCredentialWhoseDomainIsWithdrawnIsRefused(ports, caPem, identity, creds) {
  var made = await creds.create({
    domain:        SECOND_DOMAIN,
    bounceMailbox: SECOND_BOUNCE_MAILBOX,
    reason:        "a credential on the second domain for the scope test",
  });

  var live = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-second-domain-live",
  });
  live.send("AUTH PLAIN " + saslPlain(SECOND_DOMAIN, made.token));
  var before = await live.read(/^\d{3} /m, "AUTH answered");
  count("a credential on the second hosted domain signs in while that domain is in " +
    "service, so the case below is about the withdrawal rather than about the domain",
    /^235 /m.test(before), visible(before));
  live.send("QUIT");
  live.close();

  await identity.domains.setStatus({
    domain: SECOND_DOMAIN, status: "disabled",
    reason: "withdrawn mid-run by the scope test",
  });

  var after = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "credential-second-domain-withdrawn",
  });
  after.send("AUTH PLAIN " + saslPlain(SECOND_DOMAIN, made.token));
  var reply = await after.read(/^\d{3} /m, "AUTH answered");
  count("and it stops signing in once the domain is withdrawn, because the scope is read " +
    "off the row on every verify rather than fixed when the credential was issued",
    /^535 /m.test(reply), visible(reply));
  after.send("QUIT");
  after.close();

  await identity.domains.setStatus({
    domain: SECOND_DOMAIN, status: "active",
    reason: "restored by the scope test",
  });
  await creds.remove({ id: made.id, destroy: true,
    reason: "the second-domain credential has served the scope test" });
}

// Where the wire codes are settled. A refusal is a claim about what the
// server did next, and the mailbox is the only place that answers it.
async function onlyThePermittedMessagesReachedTheMailbox(ports, caPem, bob) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "credential-imap-settle",
    address: bob, password: BOB_PASSWORD,
  });
  var selectTag = reader.tag();
  reader.send(selectTag + " SELECT INBOX");
  var selected = await reader.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  count("the recipient's mailbox can be read", existing !== null, visible(selected));

  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var seen = "";
  for (var seq = 1; seq <= held; seq += 1) {
    var fetchTag = reader.tag();
    reader.send(fetchTag + " FETCH " + seq + " BODY.PEEK[]");
    seen += await reader.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
  }
  reader.send(reader.tag() + " LOGOUT");
  reader.close();

  count("the message the credential was entitled to write reached the mailbox",
    seen.indexOf(CREDENTIAL_MARKER) !== -1, CREDENTIAL_MARKER);
  count("the outside author under the credential's own Sender reached it too",
    seen.indexOf(DELEGATED_MARKER) !== -1, DELEGATED_MARKER);
  count("nothing reached it from the message authored at the second hosted domain",
    seen.indexOf(CROSS_DOMAIN_MARKER) === -1, CROSS_DOMAIN_MARKER);
  count("and nothing from the message authored outside every hosted domain",
    seen.indexOf(UNHOSTED_MARKER) === -1, UNHOSTED_MARKER);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-scope");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "credential scope test" });
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: SECOND_DOMAIN, by: "credential scope test" });

    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    // A credential must name a mailbox for its bounces, and that mailbox
    // has to be in service before the credential is written. One per
    // hosted domain, so neither credential below points its return path
    // at a mailbox in the other domain.
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });
    await identity.accounts.create({
      address: SECOND_BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    // The registry the store built, rather than a second one composed
    // here. The composition facade reads it off the store handle, so a
    // credential issued through this one is the credential the
    // submission listener below verifies. A registry built beside it
    // would keep its own ceiling counters, and every claim about a
    // ceiling would be measured against a counter the server never
    // reads.
    var creds = identity.credentials;
    count("the store hands out the registry, so every credential this file issues is one " +
      "the assembled server below verifies against rather than one it has never seen",
      creds !== null && creds !== undefined && typeof creds.verify === "function",
      String(creds));

    var made = await creds.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts",
    });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: true,  port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // Both are bound here rather than left at their shipped state,
      // because the claim is about which listeners refuse a credential
      // and a listener that is not bound refuses nothing and proves
      // nothing.
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
      submission:  sections.submission.port,
      submissions: sections.submissions.port,
      imap:        sections.imap.port,
      pop3:        sections.pop3.port,
      managesieve: sections.managesieve.port,
    };

    await submissionAcceptsTheCredential(ports, leaf.ca, made.token, bob.address);
    await theCredentialIsScopedToOneHostedDomain(ports, leaf.ca, made.token, bob.address);
    await theCredentialCannotWriteAtAnUnhostedDomain(ports, leaf.ca, made.token, bob.address);
    await theOutsideAuthorAllowanceStillHolds(ports, leaf.ca, made.token, bob.address);
    await theRefusalListStillBoundsTheScope(ports, leaf.ca, made.token);
    await theScopeNameCannotBeSpelledOnTheWire(ports, leaf.ca, made.token);
    await noMailboxProtocolOpensForACredential(ports, leaf.ca, made.token, alice.address);
    await aTokenPresentedUnderTheWrongDomainIsRefused(ports, leaf.ca, made.token);
    await aBareUsernameIsStillAnAccountAttempt(ports, leaf.ca);
    await onlyThePermittedMessagesReachedTheMailbox(ports, leaf.ca, bob.address);
    await anExpiredCredentialIsRefused(ports, leaf.ca, creds);
    await aCredentialWhoseDomainIsWithdrawnIsRefused(ports, leaf.ca, identity, creds);
    // Last, because it takes the credential every case above drives away.
    await aRevokedCredentialStopsAtTheNextVerify(ports, leaf.ca, creds, made);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // The registry is the store's, so closing the store is what gives
    // its counter cache back. Closing it here as well would be a second
    // owner for one handle.
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
  name:      "sending-credential-scope",
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
