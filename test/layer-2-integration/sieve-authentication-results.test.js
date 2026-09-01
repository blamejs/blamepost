// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Mail a sender's own domain asked receivers to quarantine, and what an
 * account holder can do about it.
 *
 * This server does not have a quarantine folder. A message whose author
 * domain publishes `p=quarantine` and whose authentication fails is
 * accepted, gets the receiver's own `Authentication-Results` header
 * (RFC 8601), and is delivered. Without a filter, that means INBOX.
 *
 * What the documentation offers instead is the recipient's own Sieve
 * script: the verdict is a header, so a script can read it and file the
 * message where its owner wants it. That is a claim about a path running
 * end to end through four things that were built separately, and reading
 * the code proves none of it. So this drives the whole path: a peer
 * connects, fails authentication against a policy the zone publishes,
 * the receiver writes its verdict into the message, the recipient's
 * script reads that verdict, and the message is where the script said.
 *
 * The forgery case is what makes the rest worth anything. A header is
 * the easiest thing in a message for the sender to write, so a sender
 * that attaches its own `Authentication-Results` claiming this
 * receiver's name would be handing every recipient's filter a verdict of
 * the sender's choosing. RFC 8601 section 5 says to strip those before
 * adding your own, and a message here arrives carrying one so the strip
 * is driven rather than assumed.
 *
 * The passing sender is here for the same reason the failing one is: a
 * script that filed everything would satisfy every assertion about the
 * quarantined message and be useless.
 *
 * The last cases are about ARC (RFC 8617), the chain a forwarder or a
 * mailing list leaves behind to carry the authentication result from
 * before it rewrote the message. This server evaluates the chain and
 * reports what it found; it does not let the finding move a message.
 * Both halves are driven here, because the reporting half is what a
 * recipient can act on and the not-moving half is what stops a stranger
 * from acting on it for them. A chain is only worth what its sealer is
 * worth, and nothing here knows which sealers an operator would vouch
 * for, so a chain that validates buys a sender nothing: the message with
 * a fabricated chain claiming a pass is filed on the failure this server
 * measured, exactly like the one with no chain at all.
 *
 * What would change that is an operator naming the sealers they vouch
 * for. Until there is a way to say that, a chain lifting a DMARC failure
 * would lift it for anyone who registered a domain and published a key,
 * so these assertions are the ones to break first if the answer ever
 * moves.
 *
 * Run standalone: node test/layer-2-integration/sieve-authentication-results.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var dnsZone   = require("../helpers/dns-zone");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var Wire     = wire.Wire;
var LOOPBACK = wire.LOOPBACK;
var visible  = wire.visible;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var PEER_NAME    = "peer.example.net";
var PEER_REVERSE = "1.0.0.127.in-addr.arpa";

// A sender whose zone authorizes nobody, so a message from this address
// fails SPF from any connection at all. It publishes p=quarantine, which
// is what makes the failure a delivery rather than a refusal.
var QUARANTINED_DOMAIN = "asks-for-quarantine.example.net";

// A sender whose zone authorizes the address this run connects from, so
// its mail passes and the script has something to leave alone.
var TRUSTED_DOMAIN = "authorizes-this-peer.example.org";

// The domain named as the sealer on every ARC chain below. Its zone
// publishes no key, so the seals resolve to nothing and the chain reads
// as a failure whatever the headers claim. That is the realistic shape:
// anyone can write ARC headers, and only the key says whether they mean
// anything.
var SEALER_DOMAIN = "seals-nothing.example.net";

var QUARANTINED_MARKER = "quarantined-a71f";
var FORGED_MARKER      = "forged-verdict-b34e";
var TRUSTED_MARKER     = "trusted-c92d";
var BROKEN_CHAIN_MARKER = "broken-chain-d15a";
var CHAIN_SPOOF_MARKER  = "chain-spoof-e60b";

// Where the account holder's script sends what the sender's own domain
// asked receivers not to trust.
var FILED_INTO = "Junk";

// And where it sends mail whose forwarding chain did not hold up. A
// separate folder, because a broken chain and a failed DMARC evaluation
// are separate facts and an owner who wants to look at one is not asking
// to look at the other.
var CHAIN_FILED_INTO = "Archive";

// The script an account holder writes once and then relies on. It reads
// the receiver's verdict out of the message rather than re-deciding
// anything, which is the whole reason the receiver writes it down.
//
// Two rules, in the order that matters. The first `fileinto` a script
// reaches decides the folder, so a message that fails DMARC lands in
// Junk whatever its chain says, and the chain rule only reaches mail
// that authenticated. Written the other way round, a broken chain would
// pull unauthenticated mail out of Junk.
var SIEVE_SCRIPT =
  "require [\"fileinto\"];\n" +
  "if header :contains \"Authentication-Results\" \"dmarc=fail\" {\n" +
  "  fileinto \"" + FILED_INTO + "\";\n" +
  "}\n" +
  "if header :contains \"Authentication-Results\" \"arc=fail\" {\n" +
  "  fileinto \"" + CHAIN_FILED_INTO + "\";\n" +
  "}\n";

// One ARC set (RFC 8617 section 4.1), naming a sealer whose key is not
// published. `cv=none` is what the first hop in a chain carries, so this
// is the shape a real forwarder writes rather than an obviously broken
// one: everything about it is well formed except the part that requires
// holding a private key.
//
// `claim` is what the sealer asserts the message authenticated as before
// it was touched, which is the whole point of the chain and the whole
// reason it cannot be taken at face value from a stranger.
function arcChain(claim) {
  return [
    "ARC-Seal: i=1; a=rsa-sha256; d=" + SEALER_DOMAIN + "; s=arc; t=1766000000; cv=none; " +
      "b=aGVsbG8gdGhlcmUgdGhpcyBpcyBub3QgYSBzaWduYXR1cmU=",
    "ARC-Message-Signature: i=1; a=rsa-sha256; d=" + SEALER_DOMAIN + "; s=arc; " +
      "h=from:to:subject; bh=aGVsbG8=; b=aGVsbG8=",
    "ARC-Authentication-Results: i=1; " + SEALER_DOMAIN + "; " + claim,
  ];
}

// ---- the zone ----------------------------------------------------------------

function policyFor(zone, domain, spf) {
  zone[domain + "|TXT"] = [{ type: 16, decoded: [spf], ttl: 60 }];
  zone["_dmarc." + domain + "|TXT"] = [
    { type: 16, decoded: ["v=DMARC1; p=quarantine; adkim=r; aspf=r"], ttl: 60 },
  ];
  return zone;
}

// ---- messages ----------------------------------------------------------------

function screenedMessageFor(domain, marker, extraHeaders) {
  return [
    "From: sender@" + domain,
    "To: alice@" + DOMAIN,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@" + domain + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
  ].concat(extraHeaders || []).concat([
    "",
    "The body of the message carrying " + marker + ".",
    "",
  ]).join("\r\n");
}

async function deliver(port, caPem, domain, body, label) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, helo: PEER_NAME, label: label,
  });
  try {
    peer.send("MAIL FROM:<sender@" + domain + ">");
    await peer.read(/^250 /m, "MAIL FROM accepted");
    peer.send("RCPT TO:<alice@" + DOMAIN + ">");
    await peer.read(/^250 /m, "RCPT TO accepted");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw(body.replace(/\r\n\./g, "\r\n..") + "\r\n.\r\n",
      "<the message and its terminating dot>");
    return (await peer.read(/^\d{3} /m, "message answered")).trim();
  } finally {
    peer.close();
  }
}

// ---- reading it back ----------------------------------------------------------

async function fetchFolder(port, caPem, folder) {
  var client = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, address: "alice@" + DOMAIN, password: PASSWORD,
    label: "imap-" + folder.toLowerCase(),
  });
  try {
    var selectTag = client.tag();
    client.send(selectTag + " SELECT " + folder);
    var selected = await client.read(
      new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT " + folder + " answered");
    if (!new RegExp("^" + selectTag + " OK", "m").test(selected)) return "";
    if (/^\* 0 EXISTS/m.test(selected)) return "";
    var fetchTag = client.tag();
    client.send(fetchTag + " FETCH 1:* BODY[]");
    return await client.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "FETCH " + folder + " answered");
  } finally {
    client.close();
  }
}

// The receiver's own header for the message carrying `marker`. RFC 8601
// section 2.2 lets it fold, so the continuation lines are joined before
// a token is read off it. It is prepended to the message, so the one
// belonging to a marker is the last one before it.
function authResultsFor(fetched, marker) {
  var at = fetched.indexOf(marker);
  if (at === -1) return null;
  var header = fetched.lastIndexOf("Authentication-Results:", at);
  if (header === -1) return null;
  var end = fetched.indexOf("\r\nFrom:", header);
  if (end === -1 || end > at) end = at;
  return fetched.slice(header, end).replace(/\r\n[ \t]+/g, " ").trim();
}

// ---- cases ---------------------------------------------------------------------

// The half the documentation states plainly: this server has no
// quarantine folder, so the verdict arrives as a header on a delivered
// message. If it did not, everything below would be about a header that
// is not there.
async function theVerdictArrivesAsAHeader(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, QUARANTINED_DOMAIN,
    screenedMessageFor(QUARANTINED_DOMAIN, QUARANTINED_MARKER), "mx-quarantined");
  count("mail its own domain asked receivers to quarantine is accepted rather than refused",
    /^250 /.test(reply), reply);

  var filed = await fetchFolder(ports.imap, caPem, FILED_INTO);
  count("and it reaches the account", filed.indexOf(QUARANTINED_MARKER) !== -1,
    visible(filed).slice(0, 300));

  var results = authResultsFor(filed, QUARANTINED_MARKER);
  count("carrying the receiver's own verdict as a header", results !== null,
    visible(filed).slice(0, 400));
  count("which names this server as the one that decided it",
    String(results).indexOf(HOSTNAME) !== -1, String(results).slice(0, 240));
  count("and records the failure the sender's policy was published for",
    /dmarc=fail/.test(String(results)), String(results).slice(0, 240));
}

// The claim itself: a script can read that verdict and file on it.
async function theScriptFilesOnTheVerdict(ports, caPem) {
  var filed = await fetchFolder(ports.imap, caPem, FILED_INTO);
  count("the account holder's script filed it where the script said",
    filed.indexOf(QUARANTINED_MARKER) !== -1, visible(filed).slice(0, 300));

  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  count("and not in INBOX, which is where it would have gone with no script at all",
    inbox.indexOf(QUARANTINED_MARKER) === -1, visible(inbox).slice(0, 300));
}

// A sender that attaches its own verdict claiming this receiver's name.
// If that survived, every recipient's filter would be reading a verdict
// the sender wrote.
async function aSenderCannotWriteItsOwnVerdict(ports, caPem) {
  var forged = screenedMessageFor(QUARANTINED_DOMAIN, FORGED_MARKER, [
    "Authentication-Results: " + HOSTNAME + "; spf=pass; dkim=pass; dmarc=pass",
  ]);
  var reply = await deliver(ports.mx, caPem, QUARANTINED_DOMAIN, forged, "mx-forged");
  count("a message carrying a verdict the sender wrote is still accepted",
    /^250 /.test(reply), reply);

  var filed = await fetchFolder(ports.imap, caPem, FILED_INTO);
  count("and the script files it anyway, so the sender's own header did not decide " +
    "where it went",
    filed.indexOf(FORGED_MARKER) !== -1, visible(filed).slice(0, 400));

  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  count("and it is not in INBOX, which is where the sender's claim would have put it",
    inbox.indexOf(FORGED_MARKER) === -1, visible(inbox).slice(0, 400));

  var results = authResultsFor(filed, FORGED_MARKER);
  count("the verdict the account reads is the failure this server measured",
    /dmarc=fail/.test(String(results)), String(results).slice(0, 240));
  count("and the sender's claim of a pass under this server's name is not there beside it",
    !/dmarc=pass/.test(String(filed)), visible(filed).slice(0, 400));
}

// The other half of a filter: a script that filed everything would pass
// every assertion above and be worthless.
async function mailThatPassesIsLeftAlone(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, TRUSTED_DOMAIN,
    screenedMessageFor(TRUSTED_DOMAIN, TRUSTED_MARKER), "mx-trusted");
  count("mail from a sender whose zone authorizes this peer is accepted",
    /^250 /.test(reply), reply);

  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  count("and the script leaves it in INBOX", inbox.indexOf(TRUSTED_MARKER) !== -1,
    visible(inbox).slice(0, 300));

  var results = authResultsFor(inbox, TRUSTED_MARKER);
  count("because the verdict on it is a pass rather than a failure",
    /dmarc=pass/.test(String(results)), String(results).slice(0, 240));

  var filed = await fetchFolder(ports.imap, caPem, FILED_INTO);
  count("and nothing filed it away", filed.indexOf(TRUSTED_MARKER) === -1,
    visible(filed).slice(0, 300));
}

// ---- the forwarding chain ------------------------------------------------------

// Mail arrives with no ARC chain far more often than it arrives with
// one, and "no chain" is a different fact from "a chain that did not
// hold up". Both have to reach the account, or a filter cannot tell them
// apart and the documented result is not there to read at all.
async function aChainlessMessageSaysSo(ports, caPem) {
  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  var results = authResultsFor(inbox, TRUSTED_MARKER);
  count("mail that carries no forwarding chain is reported as carrying none, rather " +
    "than being silently unevaluated", /arc=none/.test(String(results)),
    String(results).slice(0, 240));
}

// A chain whose seals do not verify. Upstream reports it as a failure
// and carries on, which is the right answer: the chain is a third
// party's contribution, and refusing the author's mail over some
// intermediary's broken headers punishes whoever did not do it, and
// hands anyone who can inject a header a way to stop mail they are not
// party to. So the assertions are that the failure is REPORTED and that
// it changed nothing about whether the message arrived.
async function aBrokenChainIsReportedAndNotActedOn(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, TRUSTED_DOMAIN,
    screenedMessageFor(TRUSTED_DOMAIN, BROKEN_CHAIN_MARKER, arcChain("spf=pass; dkim=pass; dmarc=pass")),
    "mx-broken-chain");
  count("mail carrying a forwarding chain that does not verify is accepted, because the " +
    "chain is not the sender's to get right", /^250 /.test(reply), reply);

  var filed = await fetchFolder(ports.imap, caPem, CHAIN_FILED_INTO);
  count("and it reaches the account", filed.indexOf(BROKEN_CHAIN_MARKER) !== -1,
    visible(filed).slice(0, 300));

  var results = authResultsFor(filed, BROKEN_CHAIN_MARKER);
  count("carrying the chain verdict beside the rest, so the owner can see it",
    /arc=fail/.test(String(results)), String(results).slice(0, 240));
  count("and the chain failure did not touch the verdict on the sender itself, which " +
    "authenticated",
    /dmarc=pass/.test(String(results)), String(results).slice(0, 240));

  count("the account holder's own script is what acted on the chain verdict, which is " +
    "the only thing that acts on it",
    filed.indexOf(BROKEN_CHAIN_MARKER) !== -1 &&
    (await fetchFolder(ports.imap, caPem, "INBOX")).indexOf(BROKEN_CHAIN_MARKER) === -1,
    visible(filed).slice(0, 300));
}

// The reason a passing chain is not allowed to move anything. A chain is
// a claim signed by whoever sealed it, and a stranger can seal one:
// register a domain, publish a key, and write an
// ARC-Authentication-Results saying the message passed. If a chain that
// validated could lift a DMARC failure, that sequence would be a general
// way past DMARC for any domain at all.
//
// Nothing here knows which sealers an operator would vouch for, so the
// chain buys this sender exactly nothing, and this is the assertion that
// says so.
async function aChainAStrangerSealedBuysNothing(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, QUARANTINED_DOMAIN,
    screenedMessageFor(QUARANTINED_DOMAIN, CHAIN_SPOOF_MARKER,
      arcChain("spf=pass; dkim=pass; dmarc=pass header.from=sender@" + QUARANTINED_DOMAIN)),
    "mx-chain-spoof");
  count("a message whose chain asserts it already passed is accepted like any other",
    /^250 /.test(reply), reply);

  var filed = await fetchFolder(ports.imap, caPem, FILED_INTO);
  count("and it is filed on the failure this server measured, not on the pass the chain " +
    "asserted", filed.indexOf(CHAIN_SPOOF_MARKER) !== -1, visible(filed).slice(0, 400));

  var results = authResultsFor(filed, CHAIN_SPOOF_MARKER);
  count("the verdict the account reads still records the DMARC failure",
    /dmarc=fail/.test(String(results)), String(results).slice(0, 240));
  count("and records that the chain asserting otherwise did not verify",
    /arc=fail/.test(String(results)), String(results).slice(0, 240));

  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  count("the chain did not put it in INBOX, which is what it would have bought if a " +
    "sealed assertion were taken on trust",
    inbox.indexOf(CHAIN_SPOOF_MARKER) === -1, visible(inbox).slice(0, 400));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sieve-authres");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "sieve auth-results run" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD });

    var actor = { id: alice.id, address: alice.address, roles: ["account"] };
    identity.mailbox.sieveScripts.put(actor, "file-unauthenticated", SIEVE_SCRIPT,
      { force: true });
    identity.mailbox.sieveScripts.setActive(actor, "file-unauthenticated");
    count("the account holder's script is stored and active before any mail arrives",
      identity.mailbox.sieveScripts.active(actor) !== null,
      JSON.stringify(identity.mailbox.sieveScripts.active(actor)));

    var zone = {};
    zone[PEER_REVERSE + "|PTR"] = [{ type: 12, decoded: PEER_NAME, ttl: 60 }];
    zone[PEER_NAME + "|A"]      = [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }];
    // Authorizes nobody, so the connection this run makes is not one of
    // the addresses allowed to send for it.
    policyFor(zone, QUARANTINED_DOMAIN, "v=spf1 -all");
    // Authorizes exactly the address this run connects from.
    policyFor(zone, TRUSTED_DOMAIN, "v=spf1 ip4:" + LOOPBACK + " -all");
    var resolver = dnsZone.pinnedResolverOver(zone);

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: names[i] === "mx" || names[i] === "imap",
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
        // The shipped posture, named here so every verdict below is the
        // one an operator runs rather than a permissive setting that
        // would let an unauthenticated message through without a
        // finding attached to it.
        inbound: { mode: "enforce", onTemperror: "defer" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     resolver,
    });
    await server.start();
    running = true;

    var bound = server.mail.listeners.bound();
    var ports = { mx: bound.mx, imap: bound.imap };
    count("the MX and IMAP listeners took their ports",
      typeof ports.mx === "number" && ports.mx > 0 &&
      typeof ports.imap === "number" && ports.imap > 0,
      ports.mx + " and " + ports.imap);

    await theVerdictArrivesAsAHeader(ports, material.caPem);
    await theScriptFilesOnTheVerdict(ports, material.caPem);
    await aSenderCannotWriteItsOwnVerdict(ports, material.caPem);
    await mailThatPassesIsLeftAlone(ports, material.caPem);
    await aChainlessMessageSaysSo(ports, material.caPem);
    await aBrokenChainIsReportedAndNotActedOn(ports, material.caPem);
    await aChainAStrangerSealedBuysNothing(ports, material.caPem);

    count("the policy records were read from the resolver the operator pinned rather " +
      "than from the host's",
      resolver.wasAsked("_dmarc." + QUARANTINED_DOMAIN, "TXT"),
      resolver.asked().join(" ").slice(0, 400));

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
  name: "sieve-authentication-results", run: run, getChecks: helpers.getChecks,
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
