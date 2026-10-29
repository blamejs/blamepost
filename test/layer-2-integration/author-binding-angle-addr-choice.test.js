// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which mailbox of a `From` header carrying more than one angle address
 * this server measures the author binding against, and which one the
 * message that leaves actually shows.
 *
 * RFC 5322 section 3.4 writes a mailbox as an optional display name
 * followed by ONE angle address. A header holding two of them separated
 * by a space rather than a comma is malformed under that grammar, and
 * nothing in it says which of the two a reader should take. Readers
 * disagree: some stop at the first angle address and some take the last.
 *
 * This server takes the LAST. The submission listener reads the header
 * through `blamepost.mail.compose.splitAddressHeader`, which keeps a
 * piece carrying no comma whole, and then through
 * `blamepost.mail.compose.normalizeAddress`, which slices between
 * `lastIndexOf("<")` and `lastIndexOf(">")`. The first angle address is
 * never parsed, so it is never measured against the refusal list, never
 * measured against the account's own addresses, and never compared with
 * the domains this server signs for.
 *
 * The message is then signed and relayed with the header as written. A
 * receiver that stops at the first angle address is shown an address
 * this server never checked, carried under this server's own DKIM
 * signature and aligned for DMARC.
 *
 * ## What this file drives
 *
 * Every case is a real SMTP submission session against a real listener,
 * and every one is settled at the recipient's mailbox rather than at the
 * reply code, because a refusal is a claim about what the server did
 * next.
 *
 *   - A sending credential writes a `From` whose FIRST angle address is
 *     `postmaster`, the local part its own refusal list names, and whose
 *     last one is an address it holds. The refusal list exists to keep a
 *     whole-domain scope away from the addresses a recipient writes to
 *     when they want a person, so this has to be refused.
 *   - An ordinary account writes a `From` whose first angle address is a
 *     COLLEAGUE's mailbox at the same hosted domain and whose last one
 *     is its own. The author binding exists to stop exactly that, so
 *     this has to be refused too. It is here because the reader is
 *     shared: a credential and an account reach the same two functions,
 *     and a defect in them is not a credential defect.
 *   - The same entry written into `Sender` instead, beside a `From` the
 *     account does hold. Both headers reach one candidate list, and
 *     `Sender` is the header a receiver shows as "on behalf of", so a
 *     reader that measured only the last angle address of a `From` would
 *     leave the same forgery one line further down.
 *   - The two controls that localize it. The same pair written in the
 *     other order is refused, and the same pair written with a comma
 *     between them is refused, so what is under test is WHICH angle
 *     address is read rather than whether the binding runs at all.
 *   - What the recipient's mailbox holds afterwards, and whether the
 *     header it holds still carries the unmeasured address first.
 *   - A `From` list whose first mailbox is a bare address and whose second
 *     is an angle address, separated by a comma. RFC 5322 section 3.4
 *     reads two mailboxes there and a receiver displays both. The
 *     listener reads the header after the MIME reader has decoded it, and
 *     `splitAddressHeader` joins a piece carrying no angle bracket back
 *     onto the piece after it as decoded display text, so the bare
 *     address reaches the binding as part of a display name and is never
 *     measured. An account writing a colleague's address in that position
 *     has to be refused.
 *
 * Run standalone:
 *   node test/layer-2-integration/author-binding-angle-addr-choice.test.js
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

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The reply an author draws when the identity may not write it. The
// binding runs after the message is accepted for transfer, so it is the
// answer to the final dot rather than to a command.
var AUTHOR_REFUSAL = /^550 5\.[67]\.[01] /m;

// The two classes that reply draws, told apart. RFC 3463 gives each a
// status of its own and the listener answers with one of exactly two:
// `5.6.0` when the header block names no single readable author, and
// `5.7.1` when it names a readable address at a domain this server
// signs for that the identity does not hold.
//
// Both match the pattern above, so a case that is refused says nothing
// on its own about WHY. The distinction is the whole subject of this
// file: an entry carrying two angle addresses is ambiguous and is
// refused unread, and a comma-separated list is READ, each mailbox in
// it measured against the identity. A case that reached the second is
// evidence that the mailbox was measured; the same case answered by the
// first would be a message refused for being unreadable, which is a
// different server and would pass the pattern above just as well.
var UNREADABLE_AUTHOR = /^550 5\.6\.0 /m;
var UNOWNED_AUTHOR    = /^550 5\.7\.1 /m;

// One marker per message, so the mailbox settles each wire code rather
// than each one being believed.
var CREDENTIAL_FORGED_MARKER = "angle-addr-credential-8f21c6da";
var ACCOUNT_FORGED_MARKER    = "angle-addr-account-3ac95e17";
var SENDER_FORGED_MARKER     = "angle-addr-sender-1b76d40c";
var REVERSED_MARKER          = "angle-addr-reversed-70b4e2f9";
var COMMA_MARKER             = "angle-addr-comma-5d18af03";
var BARE_FIRST_MARKER        = "angle-addr-bare-first-c2e7094b";

// One submission of one header block, with the reply it drew.
//
// The envelope sender is always an address the identity holds, so the
// only thing any case below can be refused for is the author. A case
// that failed at MAIL FROM would report the envelope binding rather than
// the author binding, and the envelope reply is returned beside the
// message reply so a run can say which of the two answered.
// `senderHeader` is optional, and a case that passes one is asking about
// the OTHER header the binding measures. The two reach one candidate
// list, so the reader under test here is the same reader whichever
// header the entry was written into.
async function submitWithFrom(ports, caPem, label, signIn, envelopeFrom, fromHeader,
                              marker, recipient, senderHeader) {
  var sender = await Wire.submission(ports.submission, Object.assign({
    caPem: caPem, servername: HOSTNAME, label: label,
  }, signIn));

  sender.send("MAIL FROM:<" + envelopeFrom + ">");
  var envelope = await sender.read(/^\d{3} /m, "MAIL FROM answered");

  sender.send("RCPT TO:<" + recipient + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  var block = ["From: " + fromHeader];
  if (senderHeader) block.push("Sender: " + senderHeader);
  sender.sendRaw(block.concat([
    "To: " + recipient,
    "Subject: " + marker,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@" + DOMAIN + ">",
    "",
    "A message whose author header names two mailboxes with no comma between them.",
    "",
    ".",
    "",
  ]).join("\r\n"), "<an author header carrying two angle addresses>");
  var reply = await sender.read(/^\d{3} /m, "message answered");

  sender.send("QUIT");
  sender.close();
  return { envelope: envelope, reply: reply };
}

// Every case is DRIVEN before any of them is asserted.
//
// `helpers.check` ends the run at the first failure, and a file that
// asserted as it went would report one refusal that did not happen and
// leave the controls beside it unmeasured. The controls are what say the
// binding runs at all, so a reader of the failure needs their verdicts
// in the same run.
async function driveEveryCase(ports, caPem, token, alice, bob) {
  return {
    // The credential case. `postmaster` is on every credential's refusal
    // list by construction, and it is the address a recipient writes to
    // when they want a person rather than the application, which is the
    // whole reason the list holds it.
    credentialFirst: await submitWithFrom(ports, caPem, "credential-first-angle-addr",
      { address: DOMAIN, password: token },
      "shop@" + DOMAIN,
      "<postmaster@" + DOMAIN + "> <shop@" + DOMAIN + ">",
      CREDENTIAL_FORGED_MARKER, bob),

    // The same reader, reached by an ordinary account. The author
    // binding's stated job is to stop a mailbox owner writing a
    // colleague's address at a domain this server signs for, and the two
    // identities reach one implementation of it.
    accountFirst: await submitWithFrom(ports, caPem, "account-first-angle-addr",
      { address: alice, password: ALICE_PASSWORD },
      alice,
      "<" + bob + "> <" + alice + ">",
      ACCOUNT_FORGED_MARKER, bob),

    // The same reader, reached through the OTHER header it measures.
    // The From here is the account's own and would pass on its own, so
    // the only thing left to refuse the message for is the Sender entry
    // beside it. RFC 5322 section 3.6.2 gives Sender one mailbox, and
    // Sender is the header a receiver shows as "on behalf of", so a
    // colleague's address written into its first position is the same
    // forgery moved one line down. A fix that read only From would leave
    // it here.
    senderPiece: await submitWithFrom(ports, caPem, "account-sender-angle-addr",
      { address: alice, password: ALICE_PASSWORD },
      alice,
      "<" + alice + ">",
      SENDER_FORGED_MARKER, bob,
      "<" + bob + "> <" + alice + ">"),

    // The first control. The same two mailboxes, written the other way
    // round.
    reversed: await submitWithFrom(ports, caPem, "credential-last-angle-addr",
      { address: DOMAIN, password: token },
      "shop@" + DOMAIN,
      "<shop@" + DOMAIN + "> <postmaster@" + DOMAIN + ">",
      REVERSED_MARKER, bob),

    // The second control. A comma is what makes the header two mailboxes
    // under RFC 5322 section 3.4.
    comma: await submitWithFrom(ports, caPem, "credential-comma-form",
      { address: DOMAIN, password: token },
      "shop@" + DOMAIN,
      "<postmaster@" + DOMAIN + ">, <shop@" + DOMAIN + ">",
      COMMA_MARKER, bob),

    // Two mailboxes a comma separates, the first written bare. The
    // comma control above wrote both in angle brackets and is refused;
    // this one differs only in leaving the brackets off the first.
    bareFirst: await submitWithFrom(ports, caPem, "account-bare-first-mailbox",
      { address: alice, password: ALICE_PASSWORD },
      alice,
      bob + ", Alice <" + alice + ">",
      BARE_FIRST_MARKER, bob),
  };
}

// The controls first, because they are what make the two cases after
// them mean anything. Each one names a pair this server does refuse, so
// a run where these fail is a run where the author binding is not
// reached at all and nothing below it is evidence of anything.
function theControlsHold(drove) {
  count("every case reached the author binding rather than being stopped at MAIL FROM, " +
    "so each envelope sender above is one its identity holds",
    /^250 /m.test(drove.credentialFirst.envelope) &&
    /^250 /m.test(drove.accountFirst.envelope) &&
    /^250 /m.test(drove.senderPiece.envelope) &&
    /^250 /m.test(drove.reversed.envelope) &&
    /^250 /m.test(drove.comma.envelope) &&
    /^250 /m.test(drove.bareFirst.envelope),
    visible(drove.credentialFirst.envelope + " | " + drove.accountFirst.envelope +
      " | " + drove.senderPiece.envelope + " | " + drove.reversed.envelope +
      " | " + drove.comma.envelope + " | " + drove.bareFirst.envelope));

  count("the same two mailboxes written in the other order ARE refused, so the reader " +
    "measures the last angle address in a piece and not the first",
    AUTHOR_REFUSAL.test(drove.reversed.reply), visible(drove.reversed.reply));

  count("the same pair with a comma between them IS refused, so every mailbox a comma " +
    "separates reaches the binding and the gap is the piece a comma never split",
    AUTHOR_REFUSAL.test(drove.comma.reply), visible(drove.comma.reply));

  // Which of the two refusals each control drew, because the pattern
  // above accepts either and the difference is what this file is about.
  // An entry holding two angle addresses is refused for being
  // unreadable; the comma form is refused for naming an address the
  // identity does not hold, which is a refusal only a mailbox that was
  // actually READ can draw.
  count("the reversed pair is refused as an entry naming no single author, which is the " +
    "answer for an ambiguity rather than for a measurement",
    UNREADABLE_AUTHOR.test(drove.reversed.reply), visible(drove.reversed.reply));
  count("and the comma form is refused for naming an address the identity does not hold, " +
    "so each mailbox a comma separated was measured rather than refused unread",
    UNOWNED_AUTHOR.test(drove.comma.reply), visible(drove.comma.reply));
}

function theFirstAngleAddressIsMeasuredToo(drove) {
  count("a From header whose FIRST angle address is a local part on the credential's " +
    "refusal list is refused, because a reader that stops at the first one is shown " +
    "postmaster under this server's own signature",
    AUTHOR_REFUSAL.test(drove.credentialFirst.reply), visible(drove.credentialFirst.reply));

  count("an account writing a From header whose FIRST angle address is a colleague's " +
    "mailbox at the same hosted domain is refused, which is the binding's own claim",
    AUTHOR_REFUSAL.test(drove.accountFirst.reply), visible(drove.accountFirst.reply));

  count("and the same entry written into Sender instead is refused too, beside a From " +
    "the account does hold, so both headers the binding measures are read the same way",
    AUTHOR_REFUSAL.test(drove.senderPiece.reply), visible(drove.senderPiece.reply));
}

// Where every wire code above is settled, and where the consequence is
// read. A message this server refused reaches no mailbox; a message it
// accepted reaches one carrying the header exactly as the client wrote
// it, first angle address and all.
async function whatReachedTheMailbox(ports, caPem, bob) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "angle-addr-settle",
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

  // The controls first, for the reason the wire assertions take them
  // first: a run where a refused message DID reach the mailbox is a run
  // where nothing below says anything.
  count("nothing reached it from the reversed pair, which is the control",
    seen.indexOf(REVERSED_MARKER) === -1, REVERSED_MARKER);
  count("nothing reached it from the comma form, which is the other control",
    seen.indexOf(COMMA_MARKER) === -1, COMMA_MARKER);

  // Every From header the mailbox actually holds, quoted into the
  // failures below. A refusal that did not happen is read alongside the
  // header a receiver would be shown, because the header is the whole
  // consequence and a marker alone does not carry it.
  var delivered = (seen.match(/^From:[^\r\n]*/gm) || []).join(" | ");
  var signedForDomain = /^DKIM-Signature:[\s\S]*?d=example\.com/m.test(seen);

  count("nothing reached the mailbox from the credential's forged-first-address message",
    seen.indexOf(CREDENTIAL_FORGED_MARKER) === -1,
    CREDENTIAL_FORGED_MARKER + " signedForDomain=" + signedForDomain +
    " delivered From headers: " + delivered);
  count("nothing reached it from the account's forged-first-address message",
    seen.indexOf(ACCOUNT_FORGED_MARKER) === -1,
    ACCOUNT_FORGED_MARKER + " delivered From headers: " + delivered);

  // The Sender case is settled here too, because its From was one the
  // account holds: a refusal that did not happen leaves a message whose
  // Sender names a colleague first, under this server's own signature.
  var deliveredSenders = (seen.match(/^Sender:[^\r\n]*/gm) || []).join(" | ");
  count("nothing reached it from the message whose Sender entry named two mailboxes",
    seen.indexOf(SENDER_FORGED_MARKER) === -1,
    SENDER_FORGED_MARKER + " delivered Sender headers: " + deliveredSenders);

  // The consequence, separate from the refusal. If a forged message did
  // arrive, this says the header a receiver reads still carries the
  // address this server never measured, in the first position a lenient
  // reader takes.
  var forgedHeader = "<postmaster@" + DOMAIN + "> <shop@" + DOMAIN + ">";
  count("and no delivered message carries a From header whose first angle address is " +
    "one this server never measured",
    seen.indexOf(forgedHeader) === -1, "delivered From headers: " + delivered);

  return { seen: seen, delivered: delivered };
}

// Last, so every case above has reported before this one can stop the run.
// The reply is settled at the mailbox as well, because a refusal is a
// claim about what the server did next.
function aBareMailboxBeforeAnAngleAddressIsMeasured(drove, mailbox) {
  count("an account writing a From list whose first mailbox is a colleague's bare address " +
    "and whose second is its own angle address is refused, because a receiver displays " +
    "both mailboxes and this server measured only the second",
  AUTHOR_REFUSAL.test(drove.bareFirst.reply), visible(drove.bareFirst.reply));

  // For the same reason its comma control is refused, and that is the
  // claim rather than the refusal itself. The two headers name the same
  // two mailboxes and differ only in the brackets around the first, so
  // a run where this one answers `5.6.0` is a run where the bare
  // mailbox made the entry unreadable instead of being measured, and
  // the pattern above cannot tell those apart.
  count("for naming an address the account does not hold, the same refusal its bracketed " +
    "control draws, so the bare mailbox was measured rather than made the entry unreadable",
    UNOWNED_AUTHOR.test(drove.bareFirst.reply), visible(drove.bareFirst.reply));

  count("and nothing reached the colleague's mailbox from that message",
    mailbox.seen.indexOf(BARE_FIRST_MARKER) === -1,
    BARE_FIRST_MARKER + " delivered From headers: " + mailbox.delivered);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("angle-addr-choice");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "angle addr choice test" });

    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    var creds = identity.credentials;
    var made = await creds.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts",
    });
    count("the credential's refusal list holds postmaster, which is what the first case " +
      "below asks this server to enforce",
      made.refusedLocalParts.indexOf("postmaster") !== -1,
      JSON.stringify(made.refusedLocalParts));

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
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

    // A live selector for the hosted domain, so a message that gets past
    // the binding leaves signed rather than leaving unsigned for a reason
    // that has nothing to do with this file. The signature is what turns
    // an unmeasured author into one a receiver authenticates.
    await server.mail.dkim.generate({ domain: DOMAIN, selector: "angle" });

    var ports = {
      submission: sections.submission.port,
      imap:       sections.imap.port,
    };

    var drove = await driveEveryCase(ports, leaf.ca, made.token, alice.address, bob.address);
    theControlsHold(drove);
    var mailbox = await whatReachedTheMailbox(ports, leaf.ca, bob.address);
    theFirstAngleAddressIsMeasuredToo(drove);
    aBareMailboxBeforeAnAngleAddressIsMeasured(drove, mailbox);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
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
  name:      "author-binding-angle-addr-choice",
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
