// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * listener-resource-bounds: what a listener does when a peer asks for
 * more of it than the operator agreed to give.
 *
 * A mail server accepts connections from anyone, on port 25 by design,
 * so every bound these listeners hold is the difference between a busy
 * afternoon and an outage. The framework holds all of them and holds
 * them well. What this file is about is the other half: whether the
 * operator running the server can say what the numbers are.
 *
 * Four claims, and the first is the one an operator hits first.
 *
 *   - The concurrent-connection ceiling an operator writes is the one
 *     that applies. The framework's own default is ten per source
 *     address, which is right for a peer delivering mail and wrong for
 *     a household: two mail clients behind one home address open more
 *     than ten IMAP connections between them, and the eleventh is
 *     refused. An operator who cannot raise that number cannot run this
 *     server for their own family.
 *   - The message-size ceiling an operator writes is the one that
 *     applies, and it is the number the listener advertises. A sender
 *     that reads SIZE and believes it should not then be refused, and a
 *     sender refused for a message under the advertised number has been
 *     lied to.
 *   - The recipient-failure ceiling an operator writes is the one that
 *     applies. It bounds how fast a stranger can read the difference
 *     between a mailbox that exists and one that does not, which is a
 *     bound on how fast this server's account map can be copied.
 *   - Exceeding a ceiling is answered with the code the protocol
 *     defines, not with a closed socket. A peer told 552 knows not to
 *     retry; a peer whose connection vanished retries for days.
 *
 * The fifth claim is a floor rather than a ceiling. RFC 5321 section
 * 4.5.3.1.8 sets one hundred recipients as the minimum a server must
 * accept on a single message, which is a number to meet rather than a
 * number to enforce, and nothing here checked that it was met.
 *
 * Run standalone: node test/layer-2-integration/listener-resource-bounds.test.js
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

var SHUTDOWN_TIMEOUT_MS = 5000;

// The ceiling this run configures, chosen well away from the
// framework's own ten so a test that passes cannot be passing on the
// default. Six connections are opened against it, so the split is three
// admitted and three refused whichever way the race lands.
var CONCURRENT_CAP = 3;
var CONNECTIONS_OPENED = 6;

// A message ceiling far below the framework's fifty mebibytes, for the
// same reason.
var MESSAGE_CAP_BYTES = 65536;

// The recipient-failure ceiling this run configures, and the number the
// framework holds when nobody configures one. They are far apart on
// purpose: a run that stopped a scanner at fifty would have proved the
// framework works and said nothing about whether the operator's number
// ever left the configuration file.
var RCPT_FAILURE_CAP       = 6;
var FRAMEWORK_RCPT_DEFAULT = 50;

// A list that expands wider than that ceiling, every address on it
// live. The width is the point: a ceiling smaller than the recipient
// count must not touch a message whose recipients all exist.
var LIST_MEMBERS   = ["team", "sales", "support", "newsroom", "info", "hello", "post"];
var LIST_SENDER    = "announce@lists.example.net";
var CLOSED_MEMBER  = "left-last-year@example.com";

// RFC 5321 section 4.5.3.1.8. A server may accept more; it may not
// accept fewer.
var RFC5321_MINIMUM_RECIPIENTS = 100;

var plainResponse = wire.saslPlain;

// Open several connections at once and report what each one was told.
// Every listener answers a refusal in its own spelling, so the caller
// passes the pattern that covers both outcomes and classifies after.
async function openMany(port, howMany, pattern, label) {
  var sessions = [];
  var replies  = [];
  for (var i = 0; i < howMany; i += 1) {
    sessions.push(await Wire.connect(port, label + "-" + i));
  }
  for (var j = 0; j < sessions.length; j += 1) {
    replies.push(await sessions[j].read(pattern, "first line"));
  }
  for (var k = 0; k < sessions.length; k += 1) sessions[k].close();
  return replies;
}

// ---- cases -----------------------------------------------------------------

// The ceiling an operator writes is the ceiling the listener holds. On a
// build that passes no rate-limit configuration at all this fails by
// admitting every connection, because the framework default of ten is
// above the six opened here.
async function theOperatorsConnectionCeilingIsTheOneThatApplies(ports) {
  var imap = await openMany(ports.imap, CONNECTIONS_OPENED, /^\* (OK|BAD)/m, "imap-cap");
  var imapAdmitted = imap.filter(function (r) { return /^\* OK/m.test(r); }).length;
  var imapRefused  = imap.filter(function (r) { return /^\* BAD/m.test(r); }).length;

  count("IMAP admits exactly the number of concurrent connections the operator allowed",
    imapAdmitted === CONCURRENT_CAP,
    imapAdmitted + " admitted of " + CONNECTIONS_OPENED + ", cap " + CONCURRENT_CAP);
  count("and refuses the rest rather than accepting and starving them",
    imapRefused === CONNECTIONS_OPENED - CONCURRENT_CAP,
    imapRefused + " refused");
  count("naming the reason in the IMAP untagged form a client can read",
    imap.some(function (r) { return /^\* BAD .*[Tt]oo many connections/m.test(r); }),
    visible(imap.join(" | ")));

  var sub = await openMany(ports.submission, CONNECTIONS_OPENED, /^(220|421) /m, "sub-cap");
  var subAdmitted = sub.filter(function (r) { return /^220 /m.test(r); }).length;
  var subRefused  = sub.filter(function (r) { return /^421 /m.test(r); }).length;

  count("submission holds the same ceiling the operator wrote",
    subAdmitted === CONCURRENT_CAP,
    subAdmitted + " admitted of " + CONNECTIONS_OPENED + ", cap " + CONCURRENT_CAP);
  // 421 is RFC 5321 section 4.2.1's "service not available, closing
  // channel". A sender reading it backs off and returns later, which is
  // exactly what a server at capacity wants it to do.
  count("and refuses with 421, the transient code that invites a retry later",
    subRefused === CONNECTIONS_OPENED - CONCURRENT_CAP &&
      sub.some(function (r) { return /^421 4\.7\.0 /m.test(r); }),
    visible(sub.join(" | ")));
}

// A submission session raised to TLS and authenticated.
async function submissionSession(port, caPem, address, password, label) {
  var session = await Wire.connect(port, label);
  // Both outcomes are read, so a session refused at the door fails on
  // an assertion naming the refusal rather than on a ten-second wait
  // for a banner that was never coming.
  var banner = await session.read(/^(220|421) /m, "banner");
  count("the submission listener admits this session rather than refusing it at the door",
    /^220 /m.test(banner), visible(banner));
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  var caps = await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + plainResponse(address, password));
  await session.read(/^235 /m, "authenticated");
  session.capabilities = caps;
  return session;
}

// What the listener says its ceiling is, and what it does when a sender
// declares more than that. RFC 1870 gives SIZE both jobs: the EHLO line
// tells a sender the number before it spends bandwidth, and the MAIL
// FROM parameter lets it declare the message ahead of DATA.
async function theOperatorsMessageCeilingIsAdvertisedAndEnforced(ports, caPem, alice) {
  var session = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-size");

  count("the listener advertises the message ceiling the operator configured",
    new RegExp("SIZE " + MESSAGE_CAP_BYTES + "\\b").test(session.capabilities),
    visible(session.capabilities));

  session.send("MAIL FROM:<" + alice + "> SIZE=" + (MESSAGE_CAP_BYTES * 4));
  var reply = await session.read(/^\d{3} /m, "oversized MAIL FROM answered");

  count("a sender declaring more than the ceiling is refused rather than accepted",
    !/^250 /m.test(reply), visible(reply));
  // RFC 1870 section 6.2 and RFC 5321 both put an over-size refusal at
  // 552. Pinned exactly: the value of a wire code is that an operator
  // and a sending MTA can both act on it.
  count("and the refusal is 552, the code RFC 1870 defines for exactly this",
    /^552 /m.test(reply), visible(reply));

  session.send("QUIT");
  session.close();
}

// RFC 5321 section 4.5.3.1.8 sets one hundred recipients as the floor a
// server must accept on a single message. This is the one number in the
// file that is a minimum to meet rather than a maximum to hold, and a
// server quietly refusing the ninetieth recipient breaks mailing lists
// in a way nobody traces back to the server.
async function theRecipientFloorRfc5321SetsIsMet(ports, caPem, alice) {
  var session = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-rcpt-floor");

  session.send("MAIL FROM:<" + alice + ">");
  await session.read(/^250 /m, "MAIL FROM accepted");

  var accepted = 0;
  var lastReply = "";
  for (var i = 0; i < RFC5321_MINIMUM_RECIPIENTS; i += 1) {
    session.send("RCPT TO:<floor" + i + "@" + DOMAIN + ">");
    lastReply = await session.read(/^\d{3} /m, "RCPT " + i + " answered");
    if (/^250 /m.test(lastReply)) accepted += 1;
  }

  count("the recipient buffer meets the hundred-address floor RFC 5321 sets",
    accepted === RFC5321_MINIMUM_RECIPIENTS,
    accepted + " of " + RFC5321_MINIMUM_RECIPIENTS + " accepted; last: " + visible(lastReply));

  session.send("QUIT");
  session.close();
}

// The message a list sends, addressed to whichever member the peer put
// first. Small enough that the size ceiling above is not what decides
// its fate.
function listMessage(recipient) {
  return "Message-ID: <bounds-list-1@lists.example.net>\r\n" +
    "From: Announcements <" + LIST_SENDER + ">\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: One message for a list with a closed member on it\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" +
    "The list still has live members, so this message still has somewhere to go.\r\n";
}

// The recipient-failure ceiling. It is the one bound on this list an
// operator cannot infer from their own traffic, because the traffic it
// exists to stop is nobody's ordinary mail.
//
// RFC 5321 section 3.5 has RCPT TO answer 250 for a mailbox that exists
// and 550 for one that does not, and that difference is a mailbox
// existence oracle: a stranger with a word list reads this server's
// whole account map for the price of one SMTP greeting. The ceiling is
// how many guesses a minute they get, and until it is the operator's to
// set it is a number nobody here chose.
//
// Three things have to hold at once, and the first two are why the
// number cannot simply be made small.
//
//   - A legitimate sender puts several recipients on one connection and
//     is charged for none of them, because a recipient that exists is
//     not a failure. A ceiling below the recipient count must leave
//     that message alone.
//   - A list expanding to this server carries addresses that have since
//     closed. Those do cost the sender budget, and the message still
//     reaches everyone whose address is live: a refusal is a verdict
//     about one recipient, not about the transaction.
//   - A run of nothing but refusals is stopped, at the number the
//     operator wrote rather than the number the framework ships.
//
// The third is the one that tells a wired ceiling from an unwired one.
// Every listener the framework builds resolves a limiter whether or not
// the caller hands it a specification, so a composition that drops the
// key still stops a scanner. It stops them forty-four probes later, at
// a number no operator chose and none can change, and nothing on the
// wire or in the log says which number is in force.
//
// One connection carries all three, because the budget is per source
// address and per minute: splitting the halves across connections would
// only make the arithmetic below harder to read, and the last half ends
// with the listener closing the socket anyway.
async function theOperatorsRecipientFailureCeilingIsTheOneThatApplies(port, caPem, live) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, label: "mx-rcpt-budget" });

  // An ordinary list message, every address on it live.
  peer.send("MAIL FROM:<" + LIST_SENDER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  var liveReplies = [];
  for (var i = 0; i < live.length; i += 1) {
    peer.send("RCPT TO:<" + live[i] + ">");
    liveReplies.push((await peer.read(/^\d{3} /m, "live recipient " + i + " answered")).trim());
  }
  count("a sender naming more live recipients on one connection than the recipient " +
    "failure ceiling allows is charged for none of them, because a mailbox that " +
    "exists is not a failure",
    live.length > RCPT_FAILURE_CAP &&
      liveReplies.every(function (line) { return /^250 /.test(line); }),
    live.length + " recipients against a ceiling of " + RCPT_FAILURE_CAP + ": " +
      visible(liveReplies.join(" | ")));

  peer.send("RSET");
  await peer.read(/^250 /m, "RSET accepted");

  // The same list a year later, with one member's address closed. The
  // closed one goes first, so a listener that abandoned the transaction
  // on a refusal could not pass the live address that follows it.
  peer.send("MAIL FROM:<" + LIST_SENDER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + CLOSED_MEMBER + ">");
  var closed = (await peer.read(/^\d{3} /m, "the closed member answered")).trim();
  peer.send("RCPT TO:<" + live[0] + ">");
  var stillLive = (await peer.read(/^\d{3} /m, "the live member answered")).trim();

  count("an address on the list that has closed is refused at RCPT with the 550 5.1.1 " +
    "RFC 5321 section 3.3 defines", /^550 5\.1\.1/.test(closed), visible(closed));
  count("and the live address named after it is still accepted, so one closed member " +
    "does not cost the list its message", /^250 /.test(stillLive), visible(stillLive));

  peer.send("DATA");
  var opened = await peer.read(/^\d{3} /m, "DATA answered");
  count("and DATA opens, because the transaction still holds a recipient",
    /^354 /m.test(opened), visible(opened));
  peer.sendRaw(listMessage(live[0]) + "\r\n.\r\n", "<the list message>");
  var accepted = await peer.read(/^\d{3} /m, "the message answered");
  count("and the message is accepted rather than deferred over the member who left",
    /^2\d\d /m.test(accepted), visible(accepted));

  // One refusal charged so far. Everything below is charged too, so the
  // stop arrives at the ceiling counted across the whole connection
  // rather than across this transaction.
  var charged = 1;

  // And now the traffic the ceiling exists for: a word list, walked.
  peer.send("MAIL FROM:<" + LIST_SENDER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  var stopped = null;
  for (var p = 0; p <= FRAMEWORK_RCPT_DEFAULT; p += 1) {
    peer.send("RCPT TO:<probe-" + p + "@" + DOMAIN + ">");
    var reply = (await peer.read(/^\d{3} /m, "probe " + p + " answered")).trim();
    if (/^550 /.test(reply)) { charged += 1; continue; }
    stopped = { at: charged, reply: reply };
    break;
  }

  count("a run of refused recipients from one source is stopped rather than answered " +
    "for as long as the source keeps asking", stopped !== null,
    stopped === null
      ? "every probe up to " + (FRAMEWORK_RCPT_DEFAULT + 1) + " was answered 550"
      : "stopped after " + stopped.at + " refusals");
  count("at the ceiling the operator wrote and not the one the framework ships, which " +
    "is the difference between a configured bound and a default nobody chose",
    stopped !== null && stopped.at === RCPT_FAILURE_CAP,
    stopped === null ? "never stopped"
      : stopped.at + " refusals, operator ceiling " + RCPT_FAILURE_CAP +
        ", framework default " + FRAMEWORK_RCPT_DEFAULT);
  count("and the source is told to come back later rather than handed another verdict " +
    "about a mailbox, so the oracle closes instead of narrowing",
    stopped !== null && /^421 4\.7\.0/.test(stopped.reply),
    stopped === null ? "never stopped" : visible(stopped.reply));

  // The listener closes the connection on that refusal, so there is no
  // QUIT to send.
  peer.close();
}

// A command line that never ends. The reader has to bound what it holds
// while it is still reading, because a peer that never sends CRLF is
// never going to reach the point where a per-command check would run.
// The refusal is the assertion: a reader that simply stopped accepting
// bytes, or dropped the connection without a word, would leave a client
// unable to tell a length refusal from a network fault.
async function anEndlessCommandLineIsRefusedWhileItIsStillBeingRead(port) {
  var session = await Wire.connect(port, "imap-endless");
  await session.read(/^\* OK/m, "greeting");

  // Over the eight-kibibyte line ceiling, and not one CRLF in it. Sized
  // just past the ceiling rather than enormously past it: the assertion
  // is that the reader refuses at the crossing point, and a peer still
  // pushing megabytes when the refusal is written can lose it to the
  // reset that follows, which would make this a test of socket
  // buffering rather than of the bound.
  session.sendRaw("a1 LOGIN " + "A".repeat(12 * 1024), "<12 KiB, no terminator>");

  var reply = await session.read(/^\* (BAD|BYE)/m, "endless line answered");
  count("an unterminated command line is refused rather than accumulated",
    /^\* BAD/m.test(reply), visible(reply));
  count("and the refusal says it was the length, so a client can tell it " +
    "from a network fault",
    /[Ll]ine too long/.test(reply), visible(reply));

  session.close();
}

// An IMAP literal announces its own size before it sends anything. A
// server that took the announcement on trust would allocate whatever
// the peer named, so the number is the thing to refuse, and refusing it
// has to happen before the continuation that invites the payload.
async function anOversizedLiteralIsRefusedOnItsAnnouncement(port, caPem, address) {
  var session = await Wire.connect(port, "imap-literal");
  await session.read(/^\* OK/m, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");

  // A gibibyte, announced and never sent.
  session.send("a2 APPEND INBOX {1073741824}");
  var reply = await session.read(/^(a2 (OK|NO|BAD)|\* BAD|\+)/m, "literal announcement answered");

  // The refusal arrives untagged rather than against the tag, because
  // the command guard rejects the announcement at parse and there is no
  // dispatched command left to answer. Both spellings are a refusal a
  // client acts on, so the assertion is that one of them arrived.
  count("a literal larger than the ceiling is refused on the announcement",
    /^(a2 (NO|BAD)|\* BAD)/m.test(reply), visible(reply));
  count("and the refusal names the size and the ceiling, so the operator " +
    "can see which one was hit",
    /1073741824/.test(reply) && /67108864/.test(reply), visible(reply));
  count("so the continuation that would invite the payload is never sent",
    !/^\+/m.test(reply), visible(reply));

  session.send("a3 LOGOUT");
  session.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("bounds");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "bounds test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // A list wider than the recipient-failure ceiling, built out of
    // aliases rather than accounts: what the recipient check reads is
    // whether the address resolves to somewhere deliverable, and an
    // alias answers that the same way a mailbox does at a fraction of
    // the setup cost.
    var live = [alice.address];
    for (var m = 0; m < LIST_MEMBERS.length; m += 1) {
      var member = LIST_MEMBERS[m] + "@" + DOMAIN;
      await identity.aliases.add({ address: member, destination: alice.address });
      live.push(member);
    }

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
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
        limits:    {
          maxConcurrentConnectionsPerIp: CONCURRENT_CAP,
          maxMessageBytes:               MESSAGE_CAP_BYTES,
          rcptFailuresPerIpPerMinute:    RCPT_FAILURE_CAP,
        },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ports = { submission: sections.submission.port, imap: sections.imap.port };

    // The connection-ceiling case runs last on purpose. It deliberately
    // fills the ceiling, and a slot is released when the listener sees
    // the socket close rather than when this side stops using it, so a
    // case opening a session straight afterwards would be racing that
    // release rather than testing its own subject.
    await theOperatorsMessageCeilingIsAdvertisedAndEnforced(ports, leaf.ca, alice.address);
    await theRecipientFloorRfc5321SetsIsMet(ports, leaf.ca, alice.address);
    await theOperatorsRecipientFailureCeilingIsTheOneThatApplies(
      sections.mx.port, leaf.ca, live);
    await anEndlessCommandLineIsRefusedWhileItIsStillBeingRead(ports.imap);
    await anOversizedLiteralIsRefusedOnItsAnnouncement(ports.imap, leaf.ca, alice.address);
    await theOperatorsConnectionCeilingIsTheOneThatApplies(ports);

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

module.exports = { name: "listener-resource-bounds", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
