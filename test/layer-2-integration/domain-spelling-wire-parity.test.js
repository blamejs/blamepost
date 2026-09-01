// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One hosted domain, however it is spelled, on the surfaces a client
 * actually drives.
 *
 * `test/layer-1-state/domain-identity-parity.test.js` asks this question
 * of the signer, the mint, the sealed key file and the browser console.
 * All four are reached by a function call. None of them is a socket, and
 * the surfaces that ARE sockets (port 25, the submission port, the JMAP
 * mount) were never asked, so the answer that file gives holds for the
 * management side of the server and says nothing about the wire.
 *
 * That gap is not cosmetic, because the two sides fold differently. The
 * identity layer derives a name: `example.com.` carries the DNS root's
 * trailing dot, which RFC 1035 section 2.3.1 makes the absolute form of
 * the same name, and `EXAMPLE.COM` differs only in case, which RFC 4343
 * says is not a difference, and `lib/store/address.js` folds both away.
 * The framework's listeners compare with `indexOf` against a set this
 * server hands them. So a set built from a spelling and a wire value
 * folded some other way meet as two different strings, and both
 * directions of that are failures:
 *
 *   - A spelling that becomes a SECOND identity is a second hosted
 *     domain, a second selector row, a second sealed key file.
 *   - A spelling of a hosted domain that is REFUSED as if it were
 *     somebody else's is mail this server was supposed to accept and
 *     answered `550` to. That one is silent at every management surface
 *     and total at the wire.
 *
 * What this file pins, over the four surfaces the task names:
 *
 *   - The hosted set the MX listener is built from is DERIVED from the
 *     stored domain rather than folded by hand. The framework matches it
 *     per recipient with an `indexOf`, against the array this server
 *     hands it once, so a row that ever carried a spelling, whether from
 *     a restore, a direct store call or a write path added later, becomes
 *     port 25 refusing mail for a domain every management surface calls
 *     hosted.
 *   - Port 25 answers about one domain for every spelling an SMTP
 *     envelope may legitimately carry, and refuses a name that only
 *     renders like one.
 *   - The submission port answers about one address for every such
 *     spelling of its domain, in the envelope and in the From header.
 *   - JMAP publishes one identity per address and not one per spelling,
 *     and a send resolves the recipient to the folded name.
 *   - The command line hosts one domain and keys one pair however the
 *     name was typed.
 *
 * The envelope and the rest of the server do not admit the same set of
 * spellings, and the difference is a rule rather than a gap. RFC 5321
 * section 4.1.2 writes `Domain = sub-domain *("." sub-domain)`, which
 * has no empty label at the end of it, so the absolute form is not a
 * spelling of a hosted domain on this wire. It is a malformed forward
 * path, and the command guard refuses it where it is read, with the
 * protocol's syntax code. That is the command guard doing its job, and what
 * this file pins about it is the SHAPE of the answer rather than the
 * refusal: a relay denial there would be this server telling a peer it
 * does not host a domain it hosts, and an acceptance would be a wire
 * reader tolerating malformed input. Both are the failures this file is
 * about; a syntax refusal is neither. Everywhere the absolute form IS
 * legitimate, which is a message header, an operator's argument and a
 * stored row, it is folded, and those are checked here too.
 *
 * Where a divergence is deliberate it is asserted rather than erased.
 * `lib/mail/posture.js` folds names for COMPARISON with a fold of its
 * own and must keep doing so: those values arrived from DNS or from a
 * policy document, and the identity derivation refuses a raw Unicode
 * label outright, which would throw away the finding an operator needs.
 * Names this server IS go through the derivation; names a zone SAYS are
 * compared and never key anything. Both halves are checked here.
 *
 * What existing files already cover, and this one therefore does not:
 * an upper-cased envelope sender and a confusable envelope sender at the
 * submission port (`test/layer-2-integration/mail-submission.test.js`),
 * the absolute form through the browser console
 * (`test/layer-1-state/web-admin-verbs.test.js`), and every spelling
 * through the signer and the mint (`domain-identity-parity`).
 *
 * Run standalone: node test/layer-2-integration/domain-spelling-wire-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var browser    = require("../helpers/browser");
var certs      = require("../helpers/certs");
var cliHelper  = require("../helpers/cli");
var dnsZone    = require("../helpers/dns-zone");
var wire       = require("../helpers/wire");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var blamepost  = require("../../lib");
var postureMod = require("../../lib/mail/posture");
var address    = require("../../lib/store/address");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;
var count       = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE    = "alice@" + DOMAIN;
var BOB      = "bob@" + DOMAIN;

// The sender a peer writes. Nobody here owns it, which is what an
// inbound peer looks like.
var PEER_SENDER = "postmaster@peer.example.net";

// A domain this server has never hosted, so the refusal direction has a
// control beside it. Without one, a file where every spelling is refused
// reads exactly like a file where every spelling is accepted.
var STRANGER_DOMAIN = "notours.example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The four spellings of one name, written the way
// `domain-identity-parity` writes them so a claim made there and a claim
// made here are the same claim about the same four strings.
function spellingsOf(name) {
  return [
    ["the recorded spelling",     name],
    ["the absolute form",         name + "."],
    ["a difference only in case", name.toUpperCase()],
    ["both at once",              name.toUpperCase() + "."],
  ];
}

// A name that renders like a hosted domain and is a different string:
// the IDN homograph class, a separator that is not one, and the A-label
// the first would arrive as if something upstream had converted it.
var CONFUSABLES = [
  ["a Cyrillic letter standing in for a Latin one", "exаmple.com"],
  ["an ideographic full stop reading as a dot",     "example。com"],
  ["an A-label whose decoded form is not this one", "xn--exmple-4nf.com"],
];

// ---- the wire ---------------------------------------------------------------

// One RCPT, over a session of its own, and the reply to it. A session
// each rather than one held open, so a reply can never belong to the
// command before it.
async function rcptReplyOn(port, caPem, label, recipient) {
  var peer = await Wire.mx(port, { caPem: caPem, servername: HOSTNAME, label: label });
  peer.send("MAIL FROM:<" + PEER_SENDER + ">");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + recipient + ">");
  var reply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

// One MAIL FROM over an authenticated submission session, and the reply.
async function mailFromReplyOn(port, caPem, label, sender) {
  var session = await Wire.submission(port, {
    caPem: caPem, servername: HOSTNAME, label: label,
    address: ALICE, password: ALICE_PASSWORD,
  });
  session.send("MAIL FROM:<" + sender + ">");
  var reply = await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("QUIT");
  session.close();
  return reply;
}

// ---- the hosted set the MX listener is built from ---------------------------

// The store as it looks when a row carries a spelling rather than a
// name. Every write path folds today, so this is the arrangement a
// restore, a direct store call or a write path added later produces.
// The framework matches the hosted set with an `indexOf` against the
// array it was handed once, so nothing downstream can notice.
//
// Everything except the hosted set answers from the real derivation, so
// what differs between a run of this and a run of the shipped
// composition is the spelling of one row and nothing else.
function _standInStore(spelling) {
  return {
    resolve: function (recipient) {
      var parsed = address.parse(recipient);
      if (parsed.ok && parsed.address === ALICE) {
        return {
          deliverable: true, local: true, domain: DOMAIN,
          targets: [{ local: true, deliverable: true, accountId: "acct", mailbox: ALICE }],
        };
      }
      return {
        deliverable: false,
        local:       parsed.ok && parsed.domain === DOMAIN,
        domain:      parsed.ok ? parsed.domain : "",
        reason:      parsed.ok && parsed.domain === DOMAIN ? "no-such-mailbox" : "unknown-domain",
        targets:     [],
      };
    },
    accounts: {
      authenticate: async function () { return { ok: false, reason: "credentials-rejected" }; },
    },
    domains: {
      list: async function () {
        return [{ domain: spelling, status: "active", dnsAcknowledged: true }];
      },
    },
    aliases: { list: function () { return []; } },
  };
}

async function _mxOverStoredSpelling(material, spelling) {
  var port = await reservePort();
  var handle = blamepost.mail.listeners.create({
    config: {
      hostname:        HOSTNAME,
      dnsAcknowledged: true,
      // The message authentication gate resolves SPF and DMARC against
      // live DNS at the end of DATA and this process has no resolver.
      // Everything asserted here is decided at RCPT, before it runs.
      inbound:         { mode: "monitor" },
      listeners: {
        mx:          { enabled: true,  port: port,                address: LOOPBACK },
        submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
        submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
        imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
        pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
        managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
      },
    },
    store:       _standInStore(spelling),
    mailStore:   {
      appendMessage: async function () { return { objectid: "obj_1" }; },
      sieveScripts:  { active: function () { return null; } },
    },
    certificate: certs.handle(material),
    delivery:    helpers.standInDelivery(),
  });
  await handle.start();
  return { port: port, handle: handle };
}

// The finding this file exists for on the store side. The recipient is
// spelled the one way an operator's own management surfaces spell it,
// and the only thing that varies is how the ROW was spelled. Every one
// of the four names the same domain, so all four have to be accepted:
// a listener built from a spelling refuses mail for a domain the console
// and the command line both call hosted, and says `550` while doing it.
async function theHostedSetIsDerivedRatherThanFolded(material) {
  var spellings = spellingsOf(DOMAIN);
  for (var i = 0; i < spellings.length; i += 1) {
    var label = spellings[i][0];
    var spelling = spellings[i][1];
    var run = await _mxOverStoredSpelling(material, spelling);
    try {
      var reply = await rcptReplyOn(run.port, material.caPem,
        "stored-" + i, ALICE);
      count("a mailbox is accepted at RCPT when its domain is stored as " + label +
        " (" + spelling + "), because the hosted set is derived from the domain rather " +
        "than carried in the spelling the row happened to hold",
        /^250 /m.test(reply), visible(reply));
    } finally {
      await run.handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    }
  }
}

// ---- port 25 ----------------------------------------------------------------

// The refusal that must never be the answer to a spelling of a hosted
// name. `550 5.7.1 Relaying denied` says the recipient belongs to
// somebody else, and saying it about a domain this server hosts is the
// direction of this defect that loses real mail without appearing
// anywhere an operator looks.
var RELAY_DENIED = /^550 5\.7\.1 /m;

// Every spelling an SMTP envelope may carry for a domain this server
// hosts. A peer chooses this string and both of these name the same
// domain, so a refusal on either is mail lost for a reason the operator
// has no way to see.
async function everyEnvelopeSpellingOfAHostedRecipientIsAccepted(ctx) {
  var accepted = [
    ["the recorded spelling",     DOMAIN],
    ["a difference only in case", DOMAIN.toUpperCase()],
  ];
  for (var i = 0; i < accepted.length; i += 1) {
    var recipient = "alice@" + accepted[i][1];
    var reply = await rcptReplyOn(ctx.mxPort, ctx.caPem, "mx-spelling-" + i, recipient);
    count("port 25 accepts a hosted recipient written in " + accepted[i][0] +
      " (" + recipient + ")",
      /^250 /m.test(reply), visible(reply));
  }
}

// The absolute form, which RFC 5321 section 4.1.2 does not admit into an
// envelope: `Domain` is `sub-domain *("." sub-domain)` and there is no
// empty label at the end of one. So this is a malformed forward path
// rather than a spelling of a hosted name, and the command guard refuses
// it where it is read.
//
// Which refusal it is, is the thing worth holding. A syntax code says
// the path could not be read, which is true and says nothing about who
// the domain belongs to. A relay denial would say this server does not
// host a domain it hosts, and that answer is indistinguishable at the
// sender from the domain having been withdrawn. An acceptance would be a
// wire reader tolerating malformed input, which is the other half of the
// same rule and has a CVE catalogue attached to it.
async function theAbsoluteFormIsRefusedAsMalformedRatherThanAsAStrangers(ctx) {
  var dotted = [
    ["the absolute form", DOMAIN + "."],
    ["both at once",      DOMAIN.toUpperCase() + "."],
  ];
  for (var i = 0; i < dotted.length; i += 1) {
    var recipient = "alice@" + dotted[i][1];
    var reply = await rcptReplyOn(ctx.mxPort, ctx.caPem, "mx-dotted-" + i, recipient);
    count("port 25 refuses a forward path carrying the DNS root's dot (" + recipient +
      "), because RFC 5321 section 4.1.2 has no empty label at the end of a domain",
      /^5\d\d /m.test(reply), visible(reply));
    count("and it refuses it as a path it could not read rather than as a domain " +
      "belonging to somebody else, which is what " + dotted[i][0] + " would be answered " +
      "with by a listener whose hosted set and whose wire disagreed about the name",
      /5\.5\.\d/.test(reply) && !RELAY_DENIED.test(reply), visible(reply));
  }
}

// The control for the direction above. A domain this server has never
// hosted is refused, so an accepted spelling is a decision about the
// name rather than a listener that accepts everything.
async function aStrangersDomainIsStillRefused(ctx) {
  var reply = await rcptReplyOn(ctx.mxPort, ctx.caPem, "mx-stranger",
    "anyone@" + STRANGER_DOMAIN);
  count("port 25 still refuses a recipient at a domain this server does not host, so an " +
    "accepted spelling above is a decision about the name and not an open relay",
    RELAY_DENIED.test(reply), visible(reply));
}

// A name that only renders like a hosted one has to be refused at the
// wire as well as at the console. Accepting it would put mail for a
// domain nobody registered into a mailbox here.
async function aConfusableRecipientIsRefused(ctx) {
  for (var i = 0; i < CONFUSABLES.length; i += 1) {
    var label = CONFUSABLES[i][0];
    var recipient = "alice@" + CONFUSABLES[i][1];
    var reply = await rcptReplyOn(ctx.mxPort, ctx.caPem, "mx-confusable-" + i, recipient);
    count("port 25 refuses a recipient at " + label + ", rather than delivering it to the " +
      "mailbox at the domain it is drawn to look like",
      /^5\d\d /m.test(reply), visible(reply));
    count("and it is refused for what the name is rather than for who it belongs to, so " +
      "the answer does not tell the peer anything about the hosted set",
      !RELAY_DENIED.test(reply), visible(reply));
  }
}

// ---- the submission port ----------------------------------------------------

// The refusal that must never answer a spelling of the account's own
// address. It says the envelope sender belongs to somebody else, and
// saying it about an address the account holds locks a client out for
// how it typed a domain.
var NOT_OWNED = /^553 5\.7\.1 /m;

// The envelope sender in the spellings nothing else drives. An
// upper-cased sender and a confusable sender are already pinned by
// `test/layer-2-integration/mail-submission.test.js`; the absolute form
// is the one no file has ever put on this port, and the pair of them
// together is what says the binding compares addresses rather than
// deciding by how the domain was written.
async function theEnvelopeBindingAnswersAboutTheMailboxNotTheSpelling(ctx) {
  var same = await mailFromReplyOn(ctx.submissionPort, ctx.caPem,
    "submission-recorded", ALICE);
  count("the submission port accepts the account's own address as recorded",
    /^250 /m.test(same), visible(same));

  var dotted = [
    ["the absolute form", "alice@" + DOMAIN + "."],
    ["both at once",      "alice@" + DOMAIN.toUpperCase() + "."],
  ];
  for (var i = 0; i < dotted.length; i += 1) {
    var reply = await mailFromReplyOn(ctx.submissionPort, ctx.caPem,
      "submission-dotted-" + i, dotted[i][1]);
    count("an envelope sender carrying the DNS root's dot (" + dotted[i][1] + ") is refused " +
      "at the parse, because RFC 5321 section 4.1.2 admits no empty label at the end of a " +
      "domain and the reverse path is read against the same shape as the forward one",
      /^5\d\d /m.test(reply) && /5\.5\.\d/.test(reply), visible(reply));
    count("and it is not refused as an address the account does not own, which is what " +
      dotted[i][0] + " would draw from a binding that compared the bytes a client wrote " +
      "against the mailbox set",
      !NOT_OWNED.test(reply), visible(reply));
  }
}

// The From header, which is the address a person reads and the one this
// server signs over. A spelling of the account's own domain is the
// account's own address, so the author binding has to read it as one.
async function aFromHeaderSpelledAbsolutelyIsTheSameAuthor(ctx) {
  var session = await Wire.submission(ctx.submissionPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "submission-from-header",
    address: ALICE, password: ALICE_PASSWORD,
  });
  session.send("MAIL FROM:<" + ALICE + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("RCPT TO:<" + BOB + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: Alice <alice@" + DOMAIN.toUpperCase() + ".>",
    "To: <" + BOB + ">",
    "Subject: one domain, one author",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <spelling-from@" + DOMAIN + ">",
    "",
    "Body.",
    ".",
    "",
  ].join("\r\n"), "<the message>");
  var reply = await session.read(/^\d{3} /m, "message answered");
  count("a From header naming the account's own address with its domain in the absolute " +
    "form and in upper case is accepted, because the author binding derives the address " +
    "rather than comparing the bytes the client wrote",
    /^250 /m.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
}

// A refused submission is answered by the framework listener, which
// writes one reply for every reason an agent handoff can fail.
// `test/layer-2-integration/mail-submission.test.js` pins this code for
// the author binding; it is restated here rather than re-derived so a
// refusal that file calls the author binding and one this file calls the
// author binding are the same reply.
var HANDOFF_REFUSAL = /^451 4\.3\.0 /m;

// The refusal direction on the same port. A From header at a domain this
// server hosts and this account does not hold stays refused, so the case
// above is the binding reading a spelling rather than the binding having
// stopped looking.
async function aFromHeaderAtAnotherAccountIsStillRefused(ctx) {
  var session = await Wire.submission(ctx.submissionPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "submission-from-other",
    address: ALICE, password: ALICE_PASSWORD,
  });
  session.send("MAIL FROM:<" + ALICE + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("RCPT TO:<" + BOB + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: Bob <bob@" + DOMAIN.toUpperCase() + ".>",
    "To: <" + BOB + ">",
    "Subject: somebody else's name",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <spelling-from-other@" + DOMAIN + ">",
    "",
    "Body.",
    ".",
    "",
  ].join("\r\n"), "<the message>");
  var reply = await session.read(/^\d{3} /m, "message answered");
  count("a From header naming ANOTHER account at this domain is still refused when its " +
    "domain is spelled absolutely and in upper case, so folding the name did not fold the " +
    "binding away with it",
    HANDOFF_REFUSAL.test(reply), visible(reply));
  session.send("QUIT");
  session.close();
}

// ---- JMAP -------------------------------------------------------------------

// The identity set a JMAP client reads. It is derived from the store on
// every request, so a spelling can only reach it by having become a row;
// this asserts what the client is actually handed rather than assuming
// the derivation upstream.
async function identityGetPublishesOneIdentityPerAddress(reader, accountId, allowed) {
  var answer = await reader.jmap([["Identity/get", { accountId: accountId }, "i0"]]);
  count("Identity/get is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  var list = Array.isArray(result.list) ? result.list : [];
  var emails = list.map(function (identity) { return identity.email; });

  count("one identity is published for each address this account may write, and not one " +
    "per spelling of its domain",
    emails.length === allowed.length, JSON.stringify(emails));
  count("and every published address is the folded one, so a client that stores it names " +
    "the same mailbox the store does",
    emails.every(function (email) {
      var parsed = address.parse(email);
      return parsed.ok && parsed.address === email;
    }), JSON.stringify(emails));
  count("no two identities fold to one address, which is what a second spelling reaching " +
    "this set would look like",
    emails.filter(function (email, at) { return emails.indexOf(email) === at; }).length ===
      emails.length, JSON.stringify(emails));

  var byAddress = {};
  for (var i = 0; i < list.length; i += 1) byAddress[list[i].email] = list[i].id;
  return byAddress;
}

// A send. The recipient is a hosted mailbox whose domain is written in
// upper case, which RFC 4343 says is not a difference, and what reaches
// the outbound path has to name the same mailbox the recorded spelling
// names. A recipient that resolved to anything else would be a second
// mailbox at a domain this server hosts, reached by writing its name
// differently.
async function aSendResolvesARecipientSpellingToTheSameMailbox(reader, accountId,
  emailId, identityId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: identityId, emailId: emailId } },
  }, "e0"]]);
  count("EmailSubmission/set is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  count("a send whose recipient names a hosted domain in another case is created rather " +
    "than refused",
    Object.prototype.hasOwnProperty.call(result.created || {}, "s0"),
    JSON.stringify(result.notCreated));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);

  var out = log.last();
  count("it carries exactly one recipient, so a spelling did not become a second one",
    out !== null && out.to.length === 1,
    out === null ? "nothing sent" : JSON.stringify(out.to));
  count("and that recipient names the same mailbox the recorded spelling names, read " +
    "through the derivation this server decides mailbox identity with",
    out !== null && out.to.length === 1 &&
      address.parse(out.to[0]).ok && address.parse(out.to[0]).address === BOB,
    out === null ? "nothing sent" : JSON.stringify(out.to));
}

// An identity id that belongs to no address this account holds is
// refused. The set is keyed on the folded address, so an id derived from
// a spelling is not in it, which is the same answer as an id belonging
// to nobody, and it has to be, or a second spelling would be a second
// sending identity.
async function anIdentityIdOutsideTheSetIsRefused(reader, accountId, emailId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: "idt_0000000000000000000000000000000f", emailId: emailId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];
  var refusal = (result.notCreated || {}).s0 || null;
  count("a send naming an identity this account does not hold is refused",
    refusal !== null && refusal.type === "identityNotFound",
    refusal === null ? "created" : String(refusal.type));
  count("and nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// ---- the command line -------------------------------------------------------

// `domain add` in every spelling. The first hosts the domain; the other
// three are the same request and have to be refused as already hosted,
// because a second row is a second hosted domain with its own selectors
// and its own sealed keys.
async function theCommandLineHostsOneDomainHoweverItIsTyped(run) {
  var spellings = spellingsOf(DOMAIN);
  var first = run(["domain", "add", spellings[0][1]]);
  count("`domain add` hosts the domain", first.status === 0, first.both.slice(0, 400));

  for (var i = 1; i < spellings.length; i += 1) {
    var again = run(["domain", "add", spellings[i][1]]);
    count("`domain add` refuses " + spellings[i][0] + " (" + spellings[i][1] + ") as the " +
      "domain already hosted, rather than hosting a second one",
      again.status !== 0, again.status + " " + again.both.slice(0, 200));
  }

  var listed = run(["domain", "list", "--json"]);
  count("`domain list` is answered", listed.status === 0, listed.both.slice(0, 200));
  var rows = _json(listed.stdout);
  var names = Array.isArray(rows) ? rows.map(function (row) { return row.domain; }) : [];
  count("and the hosted set holds one domain rather than four spellings of one",
    names.length === 1 && names[0] === DOMAIN, JSON.stringify(names));
}

// `domain show` and `dkim` reached by a spelling. Both are read verbs an
// operator types by hand, and a spelling that misses the row sends them
// to `domain add` for a domain they are already hosting.
function theCommandLineReadsOneDomainHoweverItIsTyped(run) {
  var spellings = spellingsOf(DOMAIN);
  for (var i = 0; i < spellings.length; i += 1) {
    var shown = run(["domain", "show", spellings[i][1], "--json"]);
    count("`domain show` finds the hosted domain by " + spellings[i][0] +
      " (" + spellings[i][1] + ")",
      shown.status === 0, shown.status + " " + shown.both.slice(0, 200));
    var body = shown.status === 0 ? _json(shown.stdout) : null;
    count("and it reports the folded name rather than the spelling it was given",
      body !== null && body.domain && body.domain.domain === DOMAIN,
      JSON.stringify(body && body.domain && body.domain.domain));

    var listed = run(["dkim", "list", "--domain", spellings[i][1], "--json"]);
    count("`dkim list` answers about the same pair for " + spellings[i][0],
      listed.status === 0, listed.status + " " + listed.both.slice(0, 200));
    var pairs = listed.status === 0 ? _json(listed.stdout) : null;
    count("and every selector it names belongs to the folded domain",
      Array.isArray(pairs) && pairs.length > 0 && pairs.every(function (row) {
        return row.domain === DOMAIN;
      }),
      JSON.stringify(pairs));
  }
}

// `dkim generate` reached by a spelling. A domain already holding an
// active pair refuses a second mint, so a spelling that missed the rows
// would mint over the live key and leave the sealed halves stranded.
function theCommandLineKeysOneDomainHoweverItIsTyped(run) {
  var spellings = spellingsOf(DOMAIN);
  for (var i = 1; i < spellings.length; i += 1) {
    var minted = run(["dkim", "generate", "--domain", spellings[i][1]]);
    count("`dkim generate` for " + spellings[i][0] + " (" + spellings[i][1] + ") is " +
      "refused as a domain that already holds a pair, rather than minting a second one " +
      "over the live key",
      minted.status !== 0, minted.status + " " + minted.both.slice(0, 200));
  }
  var listed = run(["dkim", "list", "--json"]);
  var pairs = listed.status === 0 ? _json(listed.stdout) : null;
  count("and the domain still holds exactly the one pair the first mint wrote",
    Array.isArray(pairs) && pairs.length === 2, JSON.stringify(pairs && pairs.length));
}

// `domain remove` reached by a spelling. Removal takes the selectors and
// there is no archived copy, so a verb that missed the row would tell an
// operator a domain was erased while it was still hosted.
function theCommandLineRemovesTheOneDomainHoweverItIsTyped(run) {
  var removed = run(["domain", "remove", DOMAIN.toUpperCase() + ".", "--destroy",
    "--reason", "domain spelling parity: removed by a spelling of its name"]);
  count("`domain remove` erases the hosted domain when it is typed in the absolute form " +
    "and in upper case",
    removed.status === 0, removed.status + " " + removed.both.slice(0, 300));

  var listed = run(["domain", "list", "--json"]);
  var rows = listed.status === 0 ? _json(listed.stdout) : null;
  count("and nothing is left hosted, so the removal reached the row it named",
    Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
}

function _json(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// ---- the boundary the posture checker keeps ---------------------------------

// Names this server IS are folded by the identity derivation. Names a
// zone SAYS are folded by the posture checker's own comparison fold and
// never key anything, because they arrived from DNS and the identity
// derivation refuses a raw Unicode label outright, which would throw
// away exactly the finding an operator needs to see.
//
// Both halves are asserted here, because erasing the boundary is as much
// a defect as never having drawn it.
async function thePostureCheckerFoldsNamesItIsAndComparesNamesAZoneSays() {
  var z = {};
  // The zone answers with the absolute form of the MX host, which is
  // what a resolver hands back and is a name this server did not choose.
  z[DOMAIN] = { mx: [HOSTNAME + "."], txt: ["v=spf1 mx -all"] };
  z["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject; rua=mailto:dmarc@" + DOMAIN] };
  z["_mta-sts." + DOMAIN] = { txt: ["v=STSv1; id=20260823T000000"] };
  z["_smtp._tls." + DOMAIN] = { txt: ["v=TLSRPTv1; rua=mailto:tls@" + DOMAIN] };

  var checker = postureMod.create({ hostname: HOSTNAME, resolver: dnsZone.resolverOver(z) });
  var report = await checker.check({ domains: [DOMAIN.toUpperCase() + "."] });

  var entry = report.domains[0];
  count("the domain a report is about is the derived name, whichever spelling the operator " +
    "asked with",
    entry !== undefined && entry.domain === DOMAIN, JSON.stringify(entry && entry.domain));

  var mx = (entry ? entry.findings : []).filter(function (f) { return f.record === "MX"; })[0];
  count("and an MX answer carrying the DNS root's dot still matches the host this server " +
    "runs as, because the answers a zone gives are compared rather than derived",
    mx !== undefined && mx.ok === true, JSON.stringify(mx && mx.detail));

  // The other half of the boundary. A zone that publishes a name the
  // identity derivation would refuse still produces a finding: the
  // operator has to be told what is published, and a name that vanished
  // on the way into the comparison would report as a record that matched
  // nothing rather than as the record that is there.
  var hostile = {};
  hostile[DOMAIN] = { mx: ["exаmple-mx.example"], txt: ["v=spf1 mx -all"] };
  hostile["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject; rua=mailto:dmarc@" + DOMAIN] };
  hostile["_mta-sts." + DOMAIN] = { txt: ["v=STSv1; id=20260823T000000"] };
  hostile["_smtp._tls." + DOMAIN] = { txt: ["v=TLSRPTv1; rua=mailto:tls@" + DOMAIN] };

  var second = await postureMod.create({
    hostname: HOSTNAME, resolver: dnsZone.resolverOver(hostile),
  }).check({ domains: [DOMAIN] });
  var hostileMx = second.domains[0].findings.filter(function (f) {
    return f.record === "MX";
  })[0];
  count("a zone publishing an MX name from another script is reported as a wrong record " +
    "rather than refused out of the report, which is the answer an operator has to see",
    hostileMx !== undefined && hostileMx.ok === false,
    JSON.stringify(hostileMx && hostileMx.detail));
}

// ---- the outbound path a JMAP send reaches ----------------------------------

function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({
        from:   envelope.from,
        to:     (envelope.to || []).slice(),
        rfc822: envelope.rfc822,
      });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
  };
}

function draftFor(recipient) {
  return Buffer.from([
    "Message-ID: <spelling-draft@" + DOMAIN + ">",
    "From: Alice <" + ALICE + ">",
    "To: <" + recipient + ">",
    "Subject: one domain, one recipient",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "",
    "Body.",
    "",
  ].join("\r\n"), "utf8");
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root       = helpers.tempDir("domain-spelling-wire-parity");
  var dataDir    = nodePath.join(root, "data");
  var workDir    = nodePath.join(root, "work");
  var cliDataDir = nodePath.join(root, "cli-data");
  var cliWorkDir = nodePath.join(root, "cli-work");
  [dataDir, workDir, cliDataDir, cliWorkDir].forEach(function (dir) {
    nodeFs.mkdirSync(dir, { recursive: true });
  });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable, and refuses to open a store
  // without one. Pointing it inside the run's own tree keeps the
  // encrypted at rest path exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  var web      = null;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    // The hosted set, before any real store exists. It needs nothing
    // from the volume, and running it first means a failure here names
    // the derivation rather than the fixture around it.
    await theHostedSetIsDerivedRatherThanFolded(material);

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "domain spelling parity" });
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });
    await identity.accounts.create({ address: BOB, password: BOB_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ctx = {
      caPem:          material.caPem,
      mxPort:         sections.mx.port,
      submissionPort: sections.submission.port,
    };

    await everyEnvelopeSpellingOfAHostedRecipientIsAccepted(ctx);
    await theAbsoluteFormIsRefusedAsMalformedRatherThanAsAStrangers(ctx);
    await aStrangersDomainIsStillRefused(ctx);
    await aConfusableRecipientIsRefused(ctx);

    await theEnvelopeBindingAnswersAboutTheMailboxNotTheSpelling(ctx);
    await aFromHeaderSpelledAbsolutelyIsTheSameAuthor(ctx);
    await aFromHeaderAtAnotherAccountIsStillRefused(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    server = null;

    // JMAP, over the browser surface that mounts it. The outbound path
    // is a recorder rather than the shipped delivery handle, because the
    // claim is about the recipient a send resolves to and a real
    // transport would answer about this host's resolver instead.
    var log = recorder();
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  log.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });
    web = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   composer,
      dkim:      dkimHandle,
      delivery:  blamepost.mail.delivery.create({
        hostname: cfg.hostname, dataDir: cfg.dataDir }),
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports = await web.start();

    var draft = identity.mailbox.appendMessage("Drafts",
      draftFor("bob@" + DOMAIN.toUpperCase()), { actor: { id: alice.id } });

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var landed = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the account signs in to the browser surface that mounts JMAP",
      landed.status === 302, landed.status + " " + String(landed.location));

    var allowed = blamepost.mail.listeners.permittedAuthors(identity,
      { id: alice.id, address: alice.address });
    var byAddress = await identityGetPublishesOneIdentityPerAddress(reader, alice.id, allowed);
    await aSendResolvesARecipientSpellingToTheSameMailbox(reader, alice.id,
      draft.objectid, byAddress[ALICE], log);
    await anIdentityIdOutsideTheSetIsRefused(reader, alice.id, draft.objectid, log);

    await web.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    web = null;

    identity.close();
    identity = null;

    // The command line, against a volume of its own. The store admits
    // one opener, and this is the shipped binary in a child process
    // rather than a call into the module it runs.
    var cliRun = cliHelper.create({
      dataDir: cliDataDir, workDir: cliWorkDir,
      hostname: HOSTNAME, vaultPassphrase: VAULT_PASSPHRASE,
    });
    await theCommandLineHostsOneDomainHoweverItIsTyped(cliRun);
    theCommandLineReadsOneDomainHoweverItIsTyped(cliRun);
    theCommandLineKeysOneDomainHoweverItIsTyped(cliRun);
    theCommandLineRemovesTheOneDomainHoweverItIsTyped(cliRun);

    await thePostureCheckerFoldsNamesItIsAndComparesNamesAZoneSays();

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (web) {
      try { await web.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the temporary volume is going anyway */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "domain-spelling-wire-parity",
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
