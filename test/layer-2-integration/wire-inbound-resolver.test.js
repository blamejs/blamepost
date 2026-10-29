// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which resolver the inbound gates actually ask.
 *
 * An operator who pins a resolver is saying the host's own resolver is
 * not to be trusted with security decisions. Four gates on the MX
 * listener make such a decision from a DNS answer: the HELO identity
 * check resolves the connecting address's reverse name and confirms it
 * forward, and SPF, DKIM verification and DMARC each resolve records
 * that decide whether a message is accepted at all. A gate that reaches
 * a different resolver from the pinned one is a gate the operator did
 * not configure, and nothing about it is visible from reading `lib/`:
 * both paths answer, and only one of them answers from the zone the
 * operator chose.
 *
 * So this run gives the server a resolver of its own and asserts on the
 * questions it was asked. The resolver is `helpers/dns-zone`'s
 * `pinnedResolverOver`, which mirrors the surface
 * `b.network.dns.resolver.create()` returns, typed readers included.
 * `queryPtr` is one of them and is not optional here: the HELO gate's
 * forward-confirmed reverse check REFUSES a resolver that cannot answer
 * a reverse question, rather than reading the missing reader as "no
 * reverse name", so a handle built without it fails every session at
 * EHLO for a reason that belongs to the fixture. A private copy of that
 * handle is how this file came to hold one that did.
 *
 * Four claims:
 *
 *   - The reverse name of the connecting address is asked of the pinned
 *     resolver during EHLO, and the forward confirmation is asked of it
 *     too. The second question only happens if the first was answered,
 *     so both together are the whole forward-confirmed reverse DNS
 *     round trip.
 *   - A sender whose published policy refuses the connecting address is
 *     refused at the end of DATA with `550 5.7.26`, the code RFC 7372
 *     section 3.2 gives a message that failed sender authentication.
 *     That verdict can only come from the pinned zone.
 *   - A sender the same zone authorizes is accepted, and the
 *     `Authentication-Results` header the recipient reads back over
 *     IMAP carries the verdict computed from those answers.
 *   - A resolver that accepts a question and never answers it does not
 *     get to hold the session, at either of the two points where one is
 *     asked with a peer waiting: the identity gate at EHLO and the
 *     sender's published policy at the end of DATA. Pinning a resolver
 *     hands this server a handle whose behavior it does not control. A
 *     path with a bound of its own and a path with none are
 *     indistinguishable against any answer that arrives, so the only way
 *     to tell them apart is an answer that does not.
 *
 * The wire codes are asserted exactly. A refusal an operator cannot
 * filter their logs for is a refusal that only exists in prose, which
 * this repository has shipped before.
 *
 * Message authentication runs in enforce mode here, which is the
 * shipped default and the configuration the roundtrip run deliberately
 * avoids. A gate tested only in monitor mode is a gate whose refusal
 * has never been read off a socket.
 *
 * Run standalone: node test/layer-2-integration/wire-inbound-resolver.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var certs     = require("../helpers/certs");
var dnsZone   = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var listeners = require("../../lib/mail/listeners");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// The peer, as it presents itself and as the zone below describes it.
var PEER_NAME    = "peer.example.net";
var PEER_REVERSE = "1.0.0.127.in-addr.arpa";

// A sender the zone authorizes from the connecting address, and one it
// refuses. Two unrelated parent domains, so neither one's policy can be
// inherited by the other when DMARC walks the tree.
var ALIGNED_SENDER = "sender@partner.example.net";
var SPOOFED_SENDER = "payroll@forged.example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var BODY = "The message the pinned zone authorized. Marker 71b3ce04.";

// The zone the operator pinned. Keys are `<name>|<qtype>`; values are
// resource records in the shape `b.network.dns.resolver.query` returns,
// so a gate reading `rrs[i].decoded` sees what it would see in
// production.
var ZONE = Object.freeze({
  // Forward-confirmed reverse DNS for the connecting address.
  "1.0.0.127.in-addr.arpa|PTR": [{ type: 12, decoded: PEER_NAME, ttl: 60 }],
  "peer.example.net|A":         [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }],

  // The authorized sender: the connecting address is listed, and the
  // policy is strict on both alignment axes so the pass has to be the
  // real one rather than a relaxed match.
  "partner.example.net|TXT": [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ],
  "_dmarc.partner.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject; adkim=s; aspf=s"], ttl: 60 },
  ],

  // The refused sender: a policy authorizing nobody, and an owner who
  // asked for refusal rather than quarantine.
  "forged.example.org|TXT": [
    { type: 16, decoded: ["v=spf1 -all"], ttl: 60 },
  ],
  "_dmarc.forged.example.org|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
  ],
});

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- the pinned resolver ---------------------------------------------------

// One resolver fixture for the whole suite, from `helpers/dns-zone`. It
// derives the typed readers from a single list rather than writing them
// out, records every question for `wasAsked`, and signals a name that
// does not exist the way the shipped resolver signals it. A private copy
// of it here was how this file came to offer a handle with no `queryPtr`
// and to raise `ENOTFOUND` for a name that does not exist, neither of
// which the shipped resolver does: the first refused every session at
// EHLO, and the second performed the absence conversion the server under
// test is supposed to perform.
var pinnedResolverOver = dnsZone.pinnedResolverOver;

// ---- sessions --------------------------------------------------------------

async function mxSession(port, caPem, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO " + PEER_NAME);
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO " + PEER_NAME);
  await session.read(/^250 /m, "EHLO accepted over TLS");
  return session;
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

function resolverMessageFor(sender, recipient, marker) {
  return [
    "From: " + sender,
    "To: " + recipient,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "",
    BODY,
    "",
  ].join("\r\n");
}

// ---- cases -----------------------------------------------------------------

// The HELO identity gate resolves the connecting address's reverse name
// and then confirms it forward. Both questions have to reach the pinned
// resolver: the second only happens when the first was answered, so
// seeing both is the whole round trip rather than an attempt at it.
function theHeloGateAsksThePinnedResolver(resolver) {
  count("the connecting address's reverse name is asked of the pinned resolver",
    resolver.wasAsked(PEER_REVERSE, "PTR"), resolver.asked().join(" "));
  count("and the name it answered is confirmed forward through the same resolver",
    resolver.wasAsked(PEER_NAME, "A"), resolver.asked().join(" "));
}

// A sender whose published policy refuses the connecting address. The
// refusal is the framework's, computed from the pinned zone, and the
// code is the one an operator would build an alert on.
//
// The code on its own does not say which resolver produced it: the
// reserved parent domains this run borrows publish a refusing policy in
// the real zone as well, so a server ignoring the pinned resolver
// entirely would still answer 550 here. The recorded questions are what
// tie the verdict to the pinned zone, and the case that can only come
// out of it is the accepted one below.
async function aSenderThePinnedZoneRefusesIsRefused(ports, caPem, recipient, resolver) {
  var peer = await mxSession(ports.mx, caPem, "mx-spoofed");

  peer.send("MAIL FROM:<" + SPOOFED_SENDER + ">");
  var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
  count("the envelope sender is accepted before the message is seen",
    /^250 /m.test(mailReply), visible(mailReply));

  peer.send("RCPT TO:<" + recipient + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(resolverMessageFor(SPOOFED_SENDER, recipient, "spoofed-71b3ce04") + ".\r\n",
    "<the message and its terminating dot>");

  var verdict = await peer.read(/^\d{3} /m, "message answered");

  count("SPF asked the pinned resolver for the sender's own policy",
    resolver.wasAsked("forged.example.org", "TXT"), resolver.asked().join(" "));
  count("and DMARC asked it for the domain owner's",
    resolver.wasAsked("_dmarc.forged.example.org", "TXT"), resolver.asked().join(" "));

  count("a message the sender's own policy disowns is not accepted",
    !/^250 /m.test(verdict), visible(verdict));
  count("the refusal is permanent rather than an invitation to retry",
    /^5\d\d /m.test(verdict), visible(verdict));
  // Pinned exactly. RFC 7372 section 3.2 gives 5.7.26 to a message that
  // failed multiple authentication checks, and an operator watching for
  // spoofed mail filters on that string.
  count("and it is 550 5.7.26, the code an operator would filter for",
    /^550 5\.7\.26 /m.test(verdict), visible(verdict));

  peer.send("QUIT");
  peer.close();
}

// The other half of the same gate. A sender the pinned zone authorizes
// is delivered, and the verdict computed from those answers is written
// onto the message the recipient reads.
async function aSenderThePinnedZoneAuthorizesIsDelivered(ports, caPem, recipient, resolver) {
  var peer = await mxSession(ports.mx, caPem, "mx-aligned");

  peer.send("MAIL FROM:<" + ALIGNED_SENDER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + recipient + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(resolverMessageFor(ALIGNED_SENDER, recipient, "aligned-71b3ce04") + ".\r\n",
    "<the message and its terminating dot>");

  var accepted = await peer.read(/^\d{3} /m, "message answered");
  count("a sender the pinned zone authorizes is accepted",
    /^250 /m.test(accepted), visible(accepted));
  count("SPF asked the pinned resolver for that sender's policy too",
    resolver.wasAsked("partner.example.net", "TXT"), resolver.asked().join(" "));

  peer.send("QUIT");
  peer.close();

  var client = await imapSession(ports.imap, caPem, recipient, "imap-authresults");
  client.send("a2 SELECT INBOX");
  await client.read(/^a2 (OK|NO|BAD)/m, "SELECT answered");
  client.send("a3 FETCH 1 BODY[]");
  var fetched = await client.read(/^a3 (OK|NO|BAD)/m, "FETCH answered");

  count("the recipient reads the message that was accepted",
    /^a3 OK/m.test(fetched) && fetched.indexOf(BODY) !== -1, visible(fetched));
  // RFC 8601: the receiver stamps its own name and its own verdicts on
  // the message. The verdicts here are computable only from the pinned
  // zone, so the header is the evidence the answers came from it.
  count("and it carries this server's Authentication-Results header",
    fetched.indexOf("Authentication-Results: " + HOSTNAME) !== -1, visible(fetched));
  count("recording the SPF pass the pinned zone authorized",
    /spf=pass/.test(fetched), visible(fetched));
  count("and the DMARC pass that followed from it",
    /dmarc=pass/.test(fetched), visible(fetched));

  client.send("a4 LOGOUT");
  client.close();
}

// A resolver that takes the question and never answers it.
//
// This is the one answer that has no verdict anywhere. Every gate on the
// inbound path knows what to do with a record that is missing and with a
// lookup that failed, because both of those arrive. Nothing arrives here,
// so whatever was waiting on it waits, and what is waiting is a session
// with a peer on the other end of it.
//
// The claim is about the listener composition rather than about the
// whole server, so the listeners are built directly over stand-in stores:
// nothing reaches a mailbox in this case, because the session never gets
// past EHLO. The budget is pinned small so the run reads the bound the
// composition holds rather than the listener's own five minute idle
// timeout, which is the only other thing that would ever end this
// session and which ends it by cutting the socket with nothing said.
var STALLED_BUDGET_MS = 750;

// How much longer than the budget an answer may take and still be that
// budget's doing. Wide enough that a loaded runner does not read as a
// missing bound, and far under the five minute idle timeout, which is
// the only other thing that ends one of these sessions.
var STALLED_SLACK = 6;

// The sender whose own policy record is the one that stalls, for the
// case below that stalls at the end of DATA rather than at EHLO. A
// domain of its own, so the stalled question is the sender's and not one
// the connection already asked.
var STALLED_SENDER = "sender@stalled.example.net";

function _standInStore(deliverable) {
  return {
    resolve:  function (address) {
      if (deliverable && String(address).toLowerCase() === deliverable) {
        return {
          deliverable: true,
          local:       true,
          targets:     [{ local: true, deliverable: true, accountId: "acct", mailbox: deliverable }],
        };
      }
      return { deliverable: false, local: true, reason: "no-such-mailbox", targets: [] };
    },
    accounts: {
      authenticate: async function () { return { ok: false, reason: "credentials-rejected" }; },
      // Read for every command a signed-in session sends, which this
      // file's MX listener never has: inbound mail carries no credential.
      // It answers for the one mailbox `resolve` above calls deliverable
      // and for nothing else, so the two verbs cannot disagree about
      // which addresses exist here.
      get: function (idOrAddress) {
        var asked = String(idOrAddress).toLowerCase();
        if (!deliverable || (asked !== "acct" && asked !== deliverable)) return null;
        return {
          id: "acct", address: deliverable, domain: DOMAIN,
          status: "active", isAdmin: false,
        };
      },
    },
    domains:  {
      list: async function () {
        return [{ domain: DOMAIN, status: "active", dnsAcknowledged: true }];
      },
      get: function (domain) {
        return String(domain).toLowerCase() === DOMAIN
          ? { domain: DOMAIN, status: "active", dnsAcknowledged: true }
          : null;
      },
    },
    aliases:  { list: function () { return []; } },
  };
}

// One MX listener over a zone with a hole in it, built twice: the two
// cases below stall at different points in a session and a zone that
// stalls at EHLO can never reach the second point.
async function _listenersOverStalledZone(leaf, zone, deliverable) {
  var resolver = pinnedResolverOver(zone);
  var port     = await reservePort();
  var handle   = listeners.create({
    config: {
      hostname:        HOSTNAME,
      dnsAcknowledged: true,
      inbound:         { mode: "enforce", onTemperror: "defer" },
      listeners: {
        mx:          { enabled: true,  port: port,               address: LOOPBACK },
        submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
        submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
        imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
        pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
        managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
      },
    },
    store:             _standInStore(deliverable),
    mailStore:         { appendMessage: async function () { return { objectid: "obj_1" }; },
                         sieveScripts: { active: function () { return null; } } },
    certificate:       certs.handle(leaf),
    delivery:          helpers.standInDelivery(),
    resolver:          resolver,
    dnsAnswerBudgetMs: STALLED_BUDGET_MS,
  });
  await handle.start();
  return { port: port, handle: handle, resolver: resolver };
}

// The stall at EHLO, which is the earliest one and the one that costs a
// peer nothing to reach: no credential, no envelope, no message.
async function aStalledReverseLookupDoesNotHoldTheSessionOpen(leaf) {
  var run = await _listenersOverStalledZone(leaf, Object.assign({}, ZONE, {
    "1.0.0.127.in-addr.arpa|PTR": dnsZone.HANGING,
  }), null);

  try {
    var peer = await Wire.connect(run.port, "mx-stalled-ehlo");
    await peer.read(/^220 /m, "banner");
    var askedAt = Date.now();
    peer.send("EHLO " + PEER_NAME);
    // Deliberately wider than what is accepted. An answer has to ARRIVE
    // for this case to say anything: a read waiting on the reply code it
    // wants would report a session that was held open and a session that
    // was answered the wrong thing as the same timeout.
    var answered = await peer.read(/^\d{3} /m, "EHLO answered");
    var waited   = Date.now() - askedAt;

    count("the reverse name was asked of the resolver that never answers",
      run.resolver.wasAsked(PEER_REVERSE, "PTR"), run.resolver.asked().join(" "));
    count("the session is answered rather than held open with nothing said",
      /^\d{3} /m.test(answered), visible(answered));
    // Temporary, because nothing about the peer is wrong. The message
    // stays with the sender, who still has it and retries on their own
    // schedule, which is the right party to be holding it.
    count("and the answer is temporary, so the peer keeps the message and retries",
      /^4\d\d /m.test(answered), visible(answered));
    count("answered inside the budget the composition holds rather than by the idle timeout",
      waited < STALLED_BUDGET_MS * STALLED_SLACK,
      waited + "ms waited on a budget of " + STALLED_BUDGET_MS + "ms");

    peer.close();
  } finally {
    await run.handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  }
}

// The stall at the end of DATA, which is the other place this server
// resolves a name with a peer waiting. The reverse check completes here
// and the sender's own published policy is the question that never comes
// back, so this reads the budget on the message authentication lookups
// rather than the one on the identity gate. Both sites matter and they
// are different code: a bound on one of them proves nothing about the
// other.
async function aStalledPolicyLookupDoesNotHoldTheMessageOpen(leaf) {
  var recipient = "alice@" + DOMAIN;
  var run = await _listenersOverStalledZone(leaf, Object.assign({}, ZONE, {
    "stalled.example.net|TXT":        dnsZone.HANGING,
    "_dmarc.stalled.example.net|TXT": dnsZone.HANGING,
  }), recipient);

  try {
    var peer = await mxSession(run.port, leaf.ca, "mx-stalled-data");
    peer.send("MAIL FROM:<" + STALLED_SENDER + ">");
    await peer.read(/^250 /m, "MAIL FROM accepted");
    peer.send("RCPT TO:<" + recipient + ">");
    await peer.read(/^250 /m, "RCPT TO accepted");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");

    var askedAt = Date.now();
    peer.sendRaw(resolverMessageFor(STALLED_SENDER, recipient, "stalled-71b3ce04") + ".\r\n",
      "<the message and its terminating dot>");
    var answered = await peer.read(/^\d{3} /m, "message answered");
    var waited   = Date.now() - askedAt;

    count("the sender's own policy was asked of the resolver that never answers",
      run.resolver.wasAsked("stalled.example.net", "TXT"), run.resolver.asked().join(" "));
    count("the message is answered rather than left with the peer waiting on a reply",
      /^\d{3} /m.test(answered), visible(answered));
    // A policy nobody could read is not a policy that authorized the
    // message, and it is not a policy that refused it either. Deferring
    // is what leaves the verdict to a later delivery that can reach the
    // record, and it is the shipped answer to a temporary error.
    count("and it is deferred rather than accepted on a policy nobody could read",
      /^4\d\d /m.test(answered), visible(answered));
    count("inside the budget rather than by the listener's idle timeout",
      waited < STALLED_BUDGET_MS * STALLED_SLACK,
      waited + "ms waited on a budget of " + STALLED_BUDGET_MS + "ms");

    peer.send("QUIT");
    peer.close();
  } finally {
    await run.handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("wire-inbound-resolver");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "inbound resolver test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    var resolver = pinnedResolverOver(ZONE);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // Enforce is the shipped default. Naming it here records that
        // the refusal below is the configuration operators run, not one
        // the test turned on to make a point.
        inbound:   { mode: "enforce", onTemperror: "defer" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
      resolver:     resolver,
    });
    await server.start();
    running = true;

    var ports = { mx: sections.mx.port, imap: sections.imap.port };

    await aSenderThePinnedZoneRefusesIsRefused(ports, leaf.ca, alice.address, resolver);
    theHeloGateAsksThePinnedResolver(resolver);
    await aSenderThePinnedZoneAuthorizesIsDelivered(ports, leaf.ca, alice.address, resolver);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    // Last, and each over listeners of its own: the resolvers in these
    // two cases never answer one question apiece, so either would decide
    // every session in the run above rather than the one it is about.
    await aStalledReverseLookupDoesNotHoldTheSessionOpen(leaf);
    await aStalledPolicyLookupDoesNotHoldTheMessageOpen(leaf);

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

module.exports = { name: "wire-inbound-resolver", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
