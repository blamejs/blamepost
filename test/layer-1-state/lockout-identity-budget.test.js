// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The failure budget an attacker cannot escape by changing address.
 *
 * Every bound this server had before was keyed on the peer: concurrent
 * connections, connection rate, and an authentication-failure count per
 * source address per quarter hour. All of them are per address, so an
 * attacker with a list of addresses and one known mailbox spends one
 * attempt from each and never meets any of them. Argon2id makes each
 * guess expensive, which is a cost, not a bound.
 *
 * What this file drives is the budget keyed on the mailbox instead, over
 * the wire, on every listener a client authenticates against. The claims:
 *
 *   - Spending the budget from FIVE DIFFERENT source addresses, spread
 *     across submission, IMAP, POP3 and ManageSieve, still ends in a
 *     refusal. This is the vector a per-address test would pass without
 *     the budget existing at all, which is why every failure below
 *     arrives from an address the one before it did not use.
 *   - After the budget is spent, the CORRECT password from a sixth,
 *     never-seen address is still refused. A budget that let the right
 *     password through would bound nothing: the attacker is searching
 *     for exactly that password.
 *   - Another mailbox signing in from the very address that was just
 *     refused is accepted. That is what proves the budget is keyed on
 *     the mailbox rather than on the peer; a per-address bound refuses
 *     both.
 *   - The account owner, from an address they have already signed in
 *     from, is still accepted while the budget is spent. Without this an
 *     attacker locks anybody out of their own mail by failing on their
 *     behalf, which is a denial of service dressed as a defense and is
 *     the reason this was not composed until the shape was settled.
 *   - One budget, not one per protocol. The failures below are spread
 *     across four listeners on purpose: an attacker who could spend an
 *     IMAP budget and then start again on POP3 has four budgets, not
 *     one.
 *
 * The budgets can also be read rather than only spent and released,
 * because the operator interface answers from the counters rather than
 * from the record of budgets that have already run out. What that read
 * has to say:
 *
 *   - A mailbox that has never failed a sign in reads as clear, and the
 *     read constructs no counter to say so.
 *   - A budget still running down carries the failures counted so far,
 *     which is the state nothing on the record can show because nothing
 *     is recorded until a budget runs out.
 *   - A budget that has run out reads zero attempts, because the failure
 *     that spends one resets the count. The number is an early warning
 *     and never a diagnosis, and what matters for a held budget is when
 *     it lifts.
 *   - An address with no mailbox here is refused, as a release of one
 *     is. The budgets count addresses with no account exactly as they
 *     count real ones, so answering would report a mailbox's state for
 *     something that is not a mailbox.
 *   - A peer is counted under a key rather than under the address it
 *     connected from, and both the read and the release take that key
 *     back. An IPv6 client is collapsed to its site prefix, which is
 *     what the trail records and what an operator is handed to release;
 *     a release that could not read its own key back would release
 *     nothing and report the mailbox released.
 *
 * A release answers for the two budgets separately, because a caller
 * acts differently on each of them:
 *
 *   - A peer this server cannot read refuses the WHOLE call, before
 *     anything has been released. The peer budget is read first when a
 *     sign in is judged, so releasing the mailbox alone would leave the
 *     account holder refused on exactly the machine that was named,
 *     under an answer that reads as a fix, and would file a trail row
 *     for a peer release that never happened.
 *   - The mailbox budget and the peer budget are each reported on their
 *     own, and a peer that was never named is a different answer from
 *     one that was named and found already clear. The first leaves that
 *     budget unread and still worth trying; the second rules the machine
 *     out. The verdict over both survives beside them, because "was
 *     anything holding this account back" is still a question worth one
 *     answer.
 *   - The key a peer budget was released under comes back with the
 *     verdict, so a caller names what this server acted on rather than
 *     what it was handed.
 *
 * The certificate is issued for this run by the framework's own CA and
 * never leaves the temporary directory, and the client verifies the
 * chain against it. Source addresses are ordinary loopback addresses:
 * the whole of 127.0.0.0/8 is local, so a client can bind a different
 * one per attempt and the listener reports each as a distinct peer.
 *
 * Run standalone: node test/layer-1-state/lockout-identity-budget.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "steady harbour pumpkin 7715";
var WRONG_PASSWORD   = "not the password alice set 8830";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// The addresses the attempts come from. The first is where the account
// owner signs in from, so it is the address that becomes familiar. The
// five after it are the attacker's rotation, one failure each, and the
// last is a peer nothing has ever authenticated from.
var OWNER_SOURCE    = "127.0.0.1";
var ATTACK_SOURCES  = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"];
var UNSEEN_SOURCE   = "127.0.0.7";

// A second rotation, for the guesses spelled with a routing tag, and a
// second address nothing has authenticated from to probe with.
var TAG_SOURCES       = ["127.0.0.8", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.0.12"];
var TAG_PROBE_SOURCE  = "127.0.0.13";

// Where the failures that never reach the threshold come from, so the
// counter read below is one that is still running down.
var COUNTING_SOURCE = "127.0.0.14";

// Where the mailbox budget is spent a second time, so the releases below
// have something to give back. A source of its own, because a rotation
// that reached a peer budget already partway through would be refused by
// that budget before it reached the mailbox one.
var MAILBOX_SPEND_SOURCE = "127.0.0.15";

// A machine that has never failed a sign in against this mailbox, so the
// budget kept against the pair is clear while the mailbox's own is not.
// That is the pair of outcomes one boolean over both cannot express.
var CLEAR_PAIR_SOURCE = "127.0.0.16";

// What an operator writes down when they ask "which device is it?" and
// repeat the answer. Nothing in it reads as an address, so no counter was
// ever kept under it and no release can name one by it.
var UNREADABLE_MACHINE = "alices-phone.local";

// An IPv6 client, which is counted under the prefix its site is
// allocated rather than under the address it dialled from. Written from
// the range RFC 3849 reserves for documentation, so it names nothing.
var V6_PEER = "2001:db8:1a2b:3c4d::9";

// How many wrong passwords a mailbox is worth. It is the framework's
// own default rather than a setting this server offers, and it is
// written down here because a run that spends a different number proves
// nothing about the budget either way.
var BUDGET_ATTEMPTS = 5;

// Wrong passwords that do not spend a budget, so the counter is still
// running down when it is read.
var COUNTING_ATTEMPTS = 2;

// How many other mailboxes are failed against while one is locked, to
// show that their counters do not displace it. Each costs an Argon2id
// verification here exactly as it would cost an attacker, which is why
// this is a burst rather than the number that would fill the cache.
var CROWDING_ATTEMPTS = 60;

var SHUTDOWN_TIMEOUT_MS = 5000;

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// A call that has to be refused. A call that returns is the failure, so
// the assertion is on the throw rather than on the value.
async function refuses(label, call) {
  var threw = null;
  try { await call(); }
  catch (e) { threw = e; }
  count(label, threw !== null, threw === null ? "returned" : threw.message);
}

// A conversation that begins from a named local address. The shared
// helper connects from whatever the operating system picks, which is one
// address for the whole run and therefore cannot express the claim this
// file exists for. Everything after the connect is the shared helper's:
// the same reads, the same transcript, the same TLS upgrade.
function connectFrom(port, source, label) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port, localAddress: source }, function () {
      resolve(new Wire(socket, label + "@" + source));
    });
    socket.once("error", reject);
  });
}

// ---- one authentication attempt, per protocol ------------------------------
//
// Each returns true when the listener accepted the credential and false
// when it refused. The refusal wording differs per protocol and none of
// them says why, which is correct: RFC 9051 section 6.2.2, RFC 4954
// section 6 and RFC 5804 section 1.2 all answer a failed authentication
// with one verdict and no diagnosis. What the wire can show is whether
// the session was let in, and that is what every claim here rests on.

async function imapAttempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "imap-" + label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("x0 STARTTLS");
  await session.read(/^x0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, password));
  var verdict = await session.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  session.close();
  return { ok: /^x1 OK/m.test(verdict), text: verdict };
}

async function submissionAttempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "submission-" + label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + plainResponse(address, password));
  var verdict = await session.read(/^(235|535|501|503)/m, "the verdict");
  session.close();
  return { ok: /^235/m.test(verdict), text: verdict };
}

async function pop3Attempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "pop3-" + label);
  await session.read(/^\+OK /m, "greeting");
  session.send("STLS");
  await session.read(/^\+OK /m, "STLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("AUTH PLAIN " + plainResponse(address, password));
  var verdict = await session.read(/^(\+OK|-ERR)/m, "the verdict");
  session.close();
  return { ok: /^\+OK/m.test(verdict), text: verdict };
}

// The ManageSieve listener consumes the literal's byte count and leaves
// the terminating CRLF in its buffer, where it parses as an empty
// command line and draws a refusal of its own beside the authentication
// verdict. Both orderings are conforming, so the verdict is picked out
// by content rather than by position.
var SIEVE_TERMINATOR_COMPLAINT = "empty command line";

function sieveVerdict(text) {
  var lines = String(text).split("\r\n").filter(function (line) { return line.length > 0; });
  for (var i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i].indexOf(SIEVE_TERMINATOR_COMPLAINT) === -1) return lines[i];
  }
  return "";
}

async function sieveAttempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "managesieve-" + label);
  await session.read(/OK "[^"]*ready"\r\n/, "capability banner and greeting");
  session.send("STARTTLS");
  await session.read(/OK "Begin TLS negotiation now"/, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  await session.read(/OK "TLS negotiation successful"/, "capability banner re-emitted over TLS");
  var response = plainResponse(address, password);
  session.sendRaw('AUTHENTICATE "PLAIN" {' + Buffer.byteLength(response, "utf8") + "+}\r\n" +
    response + "\r\n", 'AUTHENTICATE "PLAIN" <literal>');
  var text = await session.read(/^(OK|NO|BYE)/m, "AUTHENTICATE answered");
  if (sieveVerdict(text) === "") {
    text += await session.read(/^(OK|NO|BYE)/m, "the authentication verdict");
  }
  session.close();
  var verdict = sieveVerdict(text);
  return { ok: /^OK/.test(verdict), text: verdict };
}

// ---- the story -------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("lockout");
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
      // The classical bridge rather than the CA default, because this
      // certificate exists to make a node:tls handshake happen on the
      // loopback interface and node verifies this algorithm everywhere
      // the suite runs.
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK, OWNER_SOURCE, UNSEEN_SOURCE],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_POP3_ENABLED:     "true",
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    // Four listeners a client authenticates against. Inbound mail takes
    // no credentials and stays unbound, which also keeps the DNS posture
    // gate out of a run that is not about it.
    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ports = {
      imap:        sections.imap.port,
      submission:  sections.submission.port,
      pop3:        sections.pop3.port,
      managesieve: sections.managesieve.port,
    };
    var caPem = leaf.ca;

    // The rotation, one protocol per attempt so no single listener sees
    // more than two of them.
    var attempts = [
      { name: "submission",  run: submissionAttempt, port: ports.submission },
      { name: "IMAP",        run: imapAttempt,       port: ports.imap },
      { name: "POP3",        run: pop3Attempt,       port: ports.pop3 },
      { name: "ManageSieve", run: sieveAttempt,      port: ports.managesieve },
      { name: "submission",  run: submissionAttempt, port: ports.submission },
    ];

    // 1. The owner signs in from the address they always sign in from,
    //    so that address is one this server has seen work.
    var ownerFirst = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
      alice.address, ALICE_PASSWORD, "owner-first");
    count("the account owner signs in from their usual address",
      ownerFirst.ok === true, visible(ownerFirst.text));

    // 2. Five wrong passwords for one mailbox, each from a source
    //    address the one before it did not use, across four protocols.
    for (var i = 0; i < attempts.length; i += 1) {
      var attempt = attempts[i];
      var refused = await attempt.run(attempt.port, caPem, ATTACK_SOURCES[i],
        alice.address, WRONG_PASSWORD, "spend-" + i);
      count("a wrong password on " + attempt.name + " from " + ATTACK_SOURCES[i] + " is refused",
        refused.ok === false, visible(refused.text));
    }

    // 3. The claim. A source address nothing has authenticated from,
    //    carrying the RIGHT password, is refused because the mailbox has
    //    no budget left. A bound keyed on the peer passes every check
    //    above and fails this one.
    var afterRotation = await imapAttempt(ports.imap, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-rotation");
    count("the budget still refuses the correct password once it is spent, " +
      "from an address that has spent none of it",
      afterRotation.ok === false, visible(afterRotation.text));
    // The code, not merely the absence of success. RFC 9051 section
    // 6.2.2 gives a failed AUTHENTICATE a tagged NO, and an operator
    // watching for credential abuse filters on that rather than on the
    // English beside it.
    count("and refuses with the tagged NO RFC 9051 defines rather than a protocol error",
      /^x1 NO/m.test(afterRotation.text), visible(afterRotation.text));

    // 4. And it refuses on a second protocol too, so the budget is one
    //    budget rather than one per listener.
    var afterRotationSubmission = await submissionAttempt(ports.submission, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-rotation-submission");
    count("and refuses on submission as well, so the budget is shared across protocols",
      afterRotationSubmission.ok === false, visible(afterRotationSubmission.text));
    count("with 535, the code RFC 4954 section 6 gives a failed AUTH",
      /^535 /m.test(afterRotationSubmission.text), visible(afterRotationSubmission.text));

    var afterRotationPop3 = await pop3Attempt(ports.pop3, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-rotation-pop3");
    count("and on POP3, which is the listener none of the failures above reached twice",
      afterRotationPop3.ok === false, visible(afterRotationPop3.text));
    count("with the -ERR RFC 1939 section 3 defines",
      /^-ERR/m.test(afterRotationPop3.text), visible(afterRotationPop3.text));

    var afterRotationSieve = await sieveAttempt(ports.managesieve, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-rotation-sieve");
    count("and on ManageSieve, so all four listeners read the same budget",
      afterRotationSieve.ok === false, visible(afterRotationSieve.text));
    // RFC 5804 section 1.2 makes NO the refusal. BYE would end the
    // session, which a spent budget does not earn on its own.
    count("with NO rather than BYE, so the session survives the refusal",
      /^NO/.test(afterRotationSieve.text), visible(afterRotationSieve.text));

    // 5. A different mailbox from the address that was just refused is
    //    accepted. This is what separates a budget keyed on the mailbox
    //    from one keyed on the peer: the peer is the same one.
    var otherAccount = await imapAttempt(ports.imap, caPem, UNSEEN_SOURCE,
      bob.address, BOB_PASSWORD, "other-account");
    count("another mailbox signs in from the address that was just refused, " +
      "so the budget is keyed on the mailbox and not on the peer",
      otherAccount.ok === true, visible(otherAccount.text));

    // 6. The owner, from the address they were signed in from before the
    //    rotation began, is still let in. An attacker who could lock
    //    somebody out of their own mail by failing on their behalf has
    //    turned a defense into an outage.
    var ownerAfter = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
      alice.address, ALICE_PASSWORD, "owner-after");
    count("the account owner still signs in from the address this server has " +
      "seen them use, so failing on their behalf does not lock them out",
      ownerAfter.ok === true, visible(ownerAfter.text));

    // 6b. And that sign in does not hand the attacker a fresh budget. A
    //     mail client authenticates constantly, on every poll and every
    //     send, so a budget released by a successful credential is a
    //     budget refilled at whatever rate the account holder's client
    //     happens to run at. The mailbox stays refused from the address
    //     that was refused a moment ago.
    var afterOwnerSuccess = await imapAttempt(ports.imap, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-owner-success");
    count("the account holder signing in does not release the budget whoever is " +
      "guessing at their mailbox is sitting under",
      afterOwnerSuccess.ok === false, visible(afterOwnerSuccess.text));

    // 6c. Which leaves the operator as the way back, since waiting out a
    //     lockout that keeps growing is not one for somebody whose client
    //     was sending a password its owner has since changed.
    var released = await identity.accounts.unlock({
      address: alice.address,
      reason:  "client was sending a stale password",
    });
    count("blamepost.store.accounts.unlock reports that there was a budget to release",
      released.released === true, JSON.stringify(released));
    var afterRelease = await imapAttempt(ports.imap, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "after-release");
    count("and the mailbox signs in again from an address it has never used",
      afterRelease.ok === true, visible(afterRelease.text));

    // 7. A routing tag does not mint a fresh budget. The plus tag is a
    //    suffix the sender chooses and it routes to the same mailbox, so
    //    a counter keyed on the address as written would hand an
    //    attacker an unlimited supply of budgets against one account
    //    without them having to change anything else at all. The budget
    //    was released a moment ago, so a rotation that did not reach it
    //    would leave the probe below signing in.
    for (var t = 0; t < TAG_SOURCES.length; t += 1) {
      var tagged = alice.address.replace("@", "+guess" + t + "@");
      var taggedRefused = await imapAttempt(ports.imap, caPem, TAG_SOURCES[t],
        tagged, WRONG_PASSWORD, "tag-" + t);
      count("a wrong password for " + tagged + " is refused",
        taggedRefused.ok === false, visible(taggedRefused.text));
    }
    var afterTags = await imapAttempt(ports.imap, caPem, TAG_PROBE_SOURCE,
      alice.address, ALICE_PASSWORD, "after-tags");
    count("guesses spelled with a routing tag spend the mailbox's own budget",
      afterTags.ok === false, visible(afterTags.text));

    // 8. Failures against other mailboxes do not release this one. The
    //    counters live in a cache that evicts its least recently used
    //    entry when it is full, and an evicted counter is a counter back
    //    at zero, so a budget held in a cache small enough to fill is a
    //    budget an attacker releases by failing somewhere else. The
    //    burst below is far smaller than the cache this server composes;
    //    what it catches is a capacity that has collapsed, and a
    //    rewrite in which one mailbox's counter overwrites another's.
    for (var e = 0; e < CROWDING_ATTEMPTS; e += 1) {
      var crowd = await identity.accounts.authenticate({
        address:  "nobody" + e + "@" + DOMAIN,
        password: WRONG_PASSWORD,
        source:   ATTACK_SOURCES[e % ATTACK_SOURCES.length],
      });
      if (crowd.ok !== false) {
        count("a failure against another mailbox is refused", false, JSON.stringify(crowd));
      }
    }
    var afterCrowding = await imapAttempt(ports.imap, caPem, TAG_PROBE_SOURCE,
      alice.address, ALICE_PASSWORD, "after-crowding");
    count("a burst of failures against other mailboxes does not release this one",
      afterCrowding.ok === false, visible(afterCrowding.text));

    // 9. The exemption is bounded. A source this mailbox has signed in
    //    from is let past the mailbox budget, so it needs a budget of
    //    its own: otherwise anybody sharing an address with the account
    //    holder, behind one office connection or one carrier, guesses
    //    without limit.
    for (var f = 0; f < BUDGET_ATTEMPTS; f += 1) {
      var familiarRefused = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
        alice.address, WRONG_PASSWORD, "familiar-" + f);
      count("a wrong password from the familiar address is refused (attempt " + f + ")",
        familiarRefused.ok === false, visible(familiarRefused.text));
    }
    var familiarProbe = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
      alice.address, ALICE_PASSWORD, "familiar-probe");
    count("a familiar address that has spent its own budget is refused too",
      familiarProbe.ok === false, visible(familiarProbe.text));

    // The other familiar address is still let in, which is what shows
    // the refusal above came from the budget kept against that one peer
    // rather than from the mailbox budget it was exempt from. Both
    // addresses are exempt; only one of them has spent its own budget.
    var otherFamiliar = await imapAttempt(ports.imap, caPem, UNSEEN_SOURCE,
      alice.address, ALICE_PASSWORD, "other-familiar");
    count("while a different familiar address still signs in, so the refusal " +
      "above was that one peer's budget rather than the mailbox's",
      otherFamiliar.ok === true, visible(otherFamiliar.text));

    // 10. One peer's budget does not come back because another peer
    //     succeeded, and naming the peer is how an operator releases it.
    var stillRefused = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
      alice.address, ALICE_PASSWORD, "still-refused");
    count("a peer's own budget survives a successful sign in from elsewhere",
      stillRefused.ok === false, visible(stillRefused.text));

    var releasedPeer = await identity.accounts.unlock({
      address: alice.address,
      source:  OWNER_SOURCE,
      reason:  "the client on that machine has been reconfigured",
    });
    count("blamepost.store.accounts.unlock releases the budget for one named peer",
      releasedPeer.released === true, JSON.stringify(releasedPeer));
    var afterPeerRelease = await imapAttempt(ports.imap, caPem, OWNER_SOURCE,
      alice.address, ALICE_PASSWORD, "after-peer-release");
    count("and that machine signs in again", afterPeerRelease.ok === true,
      visible(afterPeerRelease.text));

    // 11. Releasing somebody else's budget is an operator action on
    //     somebody else's mailbox, so it is answered for and it is
    //     refused on a typo rather than reporting a mailbox this server
    //     does not host as released.
    await refuses("releasing a budget without a reason is refused", function () {
      return identity.accounts.unlock({ address: alice.address });
    });
    await refuses("releasing a budget for an address with no account is refused",
      function () {
        return identity.accounts.unlock({
          address: "nobody@" + DOMAIN, reason: "typed the wrong address" });
      });

    // 11a. A machine this server cannot read refuses the WHOLE release,
    //      and it refuses before anything has been given back. The budget
    //      kept against one machine is read FIRST when a sign in is
    //      judged, so a release that took an unreadable machine, handed
    //      the mailbox back and released no machine would leave the
    //      account holder refused on the one device they called about,
    //      under an answer that reads as a fix. Refusing after the mailbox
    //      budget has already gone is that same failure with an audit row
    //      recording a release that did not happen, so what is pinned here
    //      is the budget still holding afterwards rather than the refusal
    //      on its own.
    for (var m = 0; m < BUDGET_ATTEMPTS; m += 1) {
      await identity.accounts.authenticate({
        address:  alice.address,
        password: WRONG_PASSWORD,
        source:   MAILBOX_SPEND_SOURCE,
      });
    }
    var spentAgain = await identity.accounts.lockoutState({ address: alice.address });
    count("the mailbox budget is spent again, so the releases below have something to give back",
      spentAgain.mailbox.locked === true, JSON.stringify(spentAgain));

    await refuses("releasing a budget for a machine this server cannot read is refused",
      function () {
        return identity.accounts.unlock({
          address: alice.address,
          source:  UNREADABLE_MACHINE,
          reason:  "the account holder named the device rather than an address",
        });
      });
    var afterRefusal = await identity.accounts.lockoutState({ address: alice.address });
    count("and the mailbox budget is untouched by it, so the refusal came before anything " +
      "was released rather than after half of it had been",
      afterRefusal.mailbox.locked === true, JSON.stringify(afterRefusal));

    // 11b. Two budgets, two answers. A release reports the mailbox budget
    //      and the machine budget separately, because an operator reads
    //      opposite things from them. A machine that was already clear
    //      means whatever refuses that one device is something other than
    //      this; a mailbox that was already clear means the call is about
    //      something other than a spent budget at all. One boolean over
    //      both cannot say either, and the machine below is one that has
    //      never failed a sign in.
    var splitRelease = await identity.accounts.unlock({
      address: alice.address,
      source:  CLEAR_PAIR_SOURCE,
      reason:  "the machine the account holder named had never failed a sign in",
    });
    count("a release reports the mailbox budget it gave back",
      splitRelease.mailbox === true, JSON.stringify(splitRelease));
    count("and reports the machine budget separately, as one that was already clear rather " +
      "than as half of a single verdict over both",
      splitRelease.peer === false, JSON.stringify(splitRelease));
    count("while the verdict over both still answers whether anything was holding that " +
      "account back at all",
      splitRelease.released === true, JSON.stringify(splitRelease));

    // 11c. And a release that named no machine says exactly that, rather
    //      than borrowing the answer a machine found clear earns. The two
    //      send an operator to different places: nothing was read is not
    //      nothing was holding.
    var noMachine = await identity.accounts.unlock({
      address: alice.address,
      reason:  "a second release, this time with no machine named",
    });
    count("a release that named no machine reports no machine budget at all rather than one " +
      "that was found clear",
      noMachine.peer === null, JSON.stringify(noMachine));
    count("and reports the mailbox budget it did read, which the release above left clear",
      noMachine.mailbox === false && noMachine.released === false, JSON.stringify(noMachine));

    // 12. The transitions are on the audit chain. A budget that refuses
    //    and records nothing leaves an operator with an outage and no
    //    way to tell an attack from a broken client.
    //
    //    Polled rather than read once: these rows are emitted on the
    //    drop-silent path, which batches and drains on its own schedule,
    //    so a single read straight after the refusal reports an empty
    //    chain and would have this file assert that the trail is missing.
    var engaged = await helpers.waitUntil(async function () {
      var rows = await b.audit.query({ action: "auth.lockout.engaged", limit: 50 });
      return (Array.isArray(rows) && rows.length > 0) ? rows : false;
    }, {
      timeoutMs: 20000,
      label:     "lockout: the engaged transition reaching the audit chain",
    });
    count("the lockout transition is recorded on the audit chain",
      engaged.length > 0, engaged.length + " row(s)");
    count("and the row names the mailbox the budget was kept against",
      String(engaged[0].resourceId || "").indexOf(alice.address) !== -1,
      JSON.stringify(engaged[0].resourceId));

    // 13. Reading the counters. The rows above are the record and they
    //     carry a budget only once it has run out; the counters are what
    //     actually refuse a password, and the operator interface reads
    //     them so somebody taking a support call is answering from what
    //     is true rather than from what was written down.
    //
    //     A read constructs nothing. A budget that has never seen a
    //     failure has no state at all, and asking about it has to answer
    //     clear rather than bring one into existence, or reading the
    //     page would start counting.
    var neverFailed = await identity.accounts.lockoutState({ address: bob.address });
    count("blamepost.store.accounts.lockoutState reads a mailbox that has never failed a " +
      "sign in as clear rather than refusing",
      neverFailed.mailbox.locked === false && neverFailed.mailbox.attempts === 0 &&
      neverFailed.mailbox.lockedUntil === null, JSON.stringify(neverFailed));
    count("and names no peer budget when no machine was named, rather than reporting one " +
      "that is clear",
      neverFailed.peer === null && neverFailed.source === null, JSON.stringify(neverFailed));

    // 13a. A budget that is running down. This is the state nothing on
    //      the record can show, because nothing is recorded until a
    //      budget runs out, and it is the one an operator can act on
    //      before somebody is locked out.
    for (var c = 0; c < COUNTING_ATTEMPTS; c += 1) {
      await identity.accounts.authenticate({
        address: bob.address, password: WRONG_PASSWORD, source: COUNTING_SOURCE });
    }
    var counting = await identity.accounts.lockoutState({
      address: bob.address, source: COUNTING_SOURCE });
    count("a budget below the threshold reads as clear and carries the failures counted " +
      "so far, which is the early warning",
      counting.mailbox.locked === false && counting.mailbox.attempts === COUNTING_ATTEMPTS,
      JSON.stringify(counting));
    count("and the peer budget beside it counts the same failures",
      counting.peer !== null && counting.peer.locked === false &&
      counting.peer.attempts === COUNTING_ATTEMPTS, JSON.stringify(counting));

    // 13b. And the count is meaningful ONLY below the threshold. The
    //      failure that spends a budget resets it, because the wait that
    //      follows is the answer rather than the number, so a budget
    //      that is holding somebody out reads zero attempts. An
    //      interface printing that number beside a held budget would say
    //      the opposite of what is happening, which is why this is
    //      pinned here rather than left as a note.
    for (var s = COUNTING_ATTEMPTS; s < BUDGET_ATTEMPTS; s += 1) {
      await identity.accounts.authenticate({
        address: bob.address, password: WRONG_PASSWORD, source: COUNTING_SOURCE });
    }
    var spent = await identity.accounts.lockoutState({
      address: bob.address, source: COUNTING_SOURCE });
    count("a budget that has run out reads as locked",
      spent.mailbox.locked === true, JSON.stringify(spent));
    count("and carries when it lifts, which is the number worth acting on",
      typeof spent.mailbox.lockedUntil === "number" && spent.mailbox.lockedUntil > Date.now(),
      JSON.stringify(spent));
    count("and reads zero attempts while it is held, so the count is an early warning " +
      "rather than a diagnosis and nothing may print it beside a held budget",
      spent.mailbox.attempts === 0, JSON.stringify(spent));

    // 13c. Reading is not a way to ask about anything other than a
    //      mailbox here. The budgets count addresses with no account
    //      exactly as they count real ones, which is what stops them
    //      answering which addresses exist, so a read of one has to be
    //      refused the way a release of one is rather than reporting a
    //      mailbox's state for something that is not a mailbox.
    await refuses("reading a budget for an address with no account is refused",
      function () {
        return identity.accounts.lockoutState({ address: "nobody@" + DOMAIN });
      });
    await refuses("reading a budget for a malformed address is refused", function () {
      return identity.accounts.lockoutState({ address: "not an address" });
    });
    await refuses("reading a budget with no options at all is refused", function () {
      return identity.accounts.lockoutState();
    });

    // 14. The key a counter is kept under is the key the operator gets
    //     handed back. A peer is not counted under the address it dialled
    //     from: an IPv6 client is collapsed to the prefix its site is
    //     allocated so that rotating the low bits of its own address does
    //     not mint a fresh budget every attempt, and that collapsed form
    //     carries its prefix length, which makes it something other than
    //     an address.
    //
    //     That key is what the lockout trail records and what the
    //     operator interface offers back for a release. So both verbs
    //     have to take it back. One that could not would release nothing
    //     and report the mailbox released, leaving the account holder
    //     refused on the one machine they were calling about.
    var v6State = await identity.accounts.lockoutState({
      address: alice.address, source: V6_PEER });
    count("a peer is counted under a key rather than under the address it connected from",
      v6State.source !== null && v6State.source !== V6_PEER, JSON.stringify(v6State.source));

    var v6Key = v6State.source;
    for (var v = 0; v < BUDGET_ATTEMPTS; v += 1) {
      await identity.accounts.authenticate({
        address: alice.address, password: WRONG_PASSWORD, source: V6_PEER });
    }
    var v6Held = await identity.accounts.lockoutState({
      address: alice.address, source: v6Key });
    count("and reading that key back finds the budget it names rather than no budget at all",
      v6Held.peer !== null && v6Held.peer.locked === true, JSON.stringify(v6Held));

    var v6Release = await identity.accounts.unlock({
      address: alice.address,
      source:  v6Key,
      reason:  "the key this server recorded, handed straight back to it",
    });
    count("releasing by that key reports the machine budget released, rather than folding it " +
      "into a verdict the mailbox beside it would have earned on its own",
      v6Release.peer === true, JSON.stringify(v6Release));
    count("and hands the key back, so what was released is named by this server rather than " +
      "read off what was typed at it",
      v6Release.source === v6Key, JSON.stringify(v6Release));
    var v6Settled = await identity.accounts.lockoutState({
      address: alice.address, source: v6Key });
    count("and releasing by that key actually releases it, rather than releasing nothing " +
      "while the mailbox beside it is reported released",
      v6Settled.peer !== null && v6Settled.peer.locked === false, JSON.stringify(v6Settled));

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "lockout-identity-budget",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
