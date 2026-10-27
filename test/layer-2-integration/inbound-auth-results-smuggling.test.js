// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An arriving peer writing this server's own authentication verdict.
 *
 * RFC 8601 section 5 has a receiver remove every `Authentication-Results`
 * header claiming its own authserv-id before it prepends the one it
 * computed. A header that survives is a verdict the sender chose, read by
 * every consumer that trusts this server's name: the recipient's Sieve
 * script, the browser interface, and the report reader.
 *
 * One spelling of that header is already driven elsewhere, the canonical
 * one with the field name at the start of the line and the authserv-id
 * as a bare token after the colon. This file drives the spellings a
 * receiver also has to read, because the removal and the reading are two
 * different pieces of code and only the reading has to match RFC 5322.
 *
 *   - Folded across two lines (RFC 5322 section 2.2.3). The authserv-id
 *     is on the continuation line, so a removal that reads the first
 *     line finds no identity on it.
 *   - The authserv-id written as a quoted string, which RFC 8601
 *     section 2.2 allows beside the bare token.
 *   - Whitespace between the field name and its colon, which RFC 5322
 *     section 4.5.8 carries as obsolete syntax that a parser accepts.
 *
 * `b.safeMime.parse` reads all three as `authentication-results`, and
 * that parser is what `blamepost.mail.listeners` hands the recipient's
 * Sieve script. So the claim under test is not about a header shape a
 * reader might one day accept: it is about the reader this server
 * already runs.
 *
 * The script here files on a pass rather than on a failure, which is the
 * direction that matters. A sender whose own domain publishes a policy
 * its mail then fails is a sender with something to gain from a header
 * saying otherwise, and the two controls at the end are what stop the
 * answer from being "remove every such header":
 *
 *   - A header naming a DIFFERENT authserv-id is a prior hop's record
 *     and RFC 8601 section 5 keeps it. Removing it would erase what a
 *     forwarder found before this server saw the message.
 *   - A sender the pinned zone authorizes reaches the same folder on the
 *     verdict this server computed, so a run where nothing is trusted
 *     would fail here instead of passing quietly.
 *
 * Run standalone: node test/layer-2-integration/inbound-auth-results-smuggling.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var dnsZone   = require("../helpers/dns-zone");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var mailbox   = require("../../lib/mail/mailbox");
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

// A sender whose zone authorizes nobody, so every message from it fails
// SPF from this connection and fails DMARC alignment with it. The policy
// is p=none, so the message is delivered and its headers can be read
// back rather than refused at the wire.
var FAILING_DOMAIN = "allows-no-sender.example.net";

// A sender the same zone authorizes from the address this run connects
// from, which is the only way into the trusted folder that this server
// actually computed.
var PASSING_DOMAIN = "authorizes-this-peer.example.org";

// The name on the prior hop's header, which is not this server and whose
// record is not this server's to remove.
var FORWARDER = "relay.example.org";

// Where the account holder's script sends mail this server said passed.
// One of the folders an account is created with, because a script naming
// a folder the account does not hold delivers to INBOX and logs that it
// did: every assertion below about where a message did NOT go would then
// hold for a reason that has nothing to do with the verdict.
var TRUSTED_FOLDER = "Archive";

var MARKER_CANONICAL = "smuggle-canonical-4a71";
var MARKER_FOLDED    = "smuggle-folded-8c02";
var MARKER_QUOTED    = "smuggle-quoted-15be";
var MARKER_SPACED    = "smuggle-spaced-b36d";
var MARKER_PRIOR_HOP = "prior-hop-e409";
var MARKER_PASSING   = "really-passes-7d5f";

// The verdict a sender would write for itself if it could, in the tag
// spelling RFC 8601 section 2.2 gives each method.
var CLAIMED = "spf=pass; dkim=pass; dmarc=pass";

// The script an account holder writes to act on what this server decided.
// It files on the pass rather than on the failure, so a verdict a sender
// wrote for itself moves the message rather than leaving it where it
// already was.
var SIEVE_SCRIPT =
  "require [\"fileinto\"];\n" +
  "if header :contains \"Authentication-Results\" \"dmarc=pass\" {\n" +
  "  fileinto \"" + TRUSTED_FOLDER + "\";\n" +
  "}\n";

// The caps `blamepost.mail.listeners` parses a delivered message under
// before it hands the headers to a Sieve script. Reused here rather than
// restated, so this file reads the delivered bytes through the same
// reader the server does and cannot be more or less tolerant than it.
var PARSE_CAPS = mailbox.MESSAGE_PARSE_CAPS;

// ---- the zone --------------------------------------------------------------

function policyFor(zone, domain, spf) {
  zone[domain + "|TXT"] = [{ type: 16, decoded: [spf], ttl: 60 }];
  zone["_dmarc." + domain + "|TXT"] = [
    { type: 16, decoded: ["v=DMARC1; p=none; adkim=r; aspf=r"], ttl: 60 },
  ];
  return zone;
}

// ---- messages --------------------------------------------------------------

function messageFor(domain, marker, extraHeaders) {
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
    // Read the reply code rather than waiting for the one that was
    // wanted. A read that waits for `250` reports a listener that
    // answered something else and a listener that answered nothing as
    // the same timeout, which says nothing about either.
    peer.send("MAIL FROM:<sender@" + domain + ">");
    var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
    count("the envelope sender for " + label + " is accepted before the message is seen",
      /^250 /m.test(mailReply), visible(mailReply));
    peer.send("RCPT TO:<alice@" + DOMAIN + ">");
    var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
    count("and the recipient for " + label + " resolves to a mailbox here",
      /^250 /m.test(rcptReply), visible(rcptReply));
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw(body.replace(/\r\n\./g, "\r\n..") + "\r\n.\r\n",
      "<the message and its terminating dot>");
    return (await peer.read(/^\d{3} /m, "message answered")).trim();
  } finally {
    peer.close();
  }
}

// ---- reading it back -------------------------------------------------------

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

// One delivered message, cut out of a FETCH of the whole folder and read
// through the parser the server hands Sieve. The cut runs from the header
// block that carries the marker back to the start of that message, which
// is the `Authentication-Results` this server prepended.
function headersOf(fetched, marker) {
  var at = fetched.indexOf("Subject: " + marker);
  if (at === -1) return null;
  var start = fetched.lastIndexOf("Authentication-Results", at);
  if (start === -1) start = fetched.lastIndexOf("\r\n\r\n", at) + 4;
  var end = fetched.indexOf(marker + ".", at);
  if (end === -1) end = fetched.length;
  var parsed = b.safeMime.parse(
    Buffer.from(fetched.slice(start, end), "latin1"), PARSE_CAPS);
  return (parsed && parsed.headers && parsed.headers.raw) || {};
}

// Every `Authentication-Results` value on the message, as the reader that
// feeds Sieve sees them: folded lines joined, so a header written across
// two lines is one value here exactly as it is one header there.
function authResultsOn(fetched, marker) {
  var raw = headersOf(fetched, marker);
  if (raw === null) return null;
  return raw["authentication-results"] || [];
}

// Which of those values claim to have been written by this server. RFC
// 8601 section 2.2 puts the authserv-id first, optionally quoted and
// optionally followed by a version token.
function claimingThisServer(values) {
  var mine = [];
  for (var i = 0; i < values.length; i += 1) {
    var head = b.structuredFields.splitUnquoted(values[i], ";")[0];
    if (head === undefined) continue;
    head = String(head).trim();
    var space = head.search(/[ \t]/);
    var identity = b.structuredFields.stripDoubleQuotes(
      space === -1 ? head : head.slice(0, space));
    if (identity === HOSTNAME) mine.push(values[i]);
  }
  return mine;
}

// ---- cases -----------------------------------------------------------------

// One forged spelling, driven end to end. The message is accepted,
// because a defect in a sender's headers is not a reason to refuse mail
// its own domain asked nobody to refuse, and then three things are asked
// of what arrived.
async function aSpellingBuysTheSenderNothing(ports, caPem, marker, forgedHeaders, what) {
  var reply = await deliver(ports.mx, caPem, FAILING_DOMAIN,
    messageFor(FAILING_DOMAIN, marker, forgedHeaders), "mx-" + marker);
  count("a message carrying " + what + " is accepted rather than refused",
    /^250 /.test(reply), reply);

  var inbox   = await fetchFolder(ports.imap, caPem, "INBOX");
  var trusted = await fetchFolder(ports.imap, caPem, TRUSTED_FOLDER);

  // The consumer path. A script keyed on this server's verdict must not
  // be reading one the sender wrote.
  count("the account holder's filter does not act on " + what,
    trusted.indexOf(marker) === -1, visible(trusted).slice(0, 400));
  count("and the message is where a failing verdict leaves it",
    inbox.indexOf(marker) !== -1, visible(inbox).slice(0, 400));

  // The bytes underneath it. One verdict under this server's name, and it
  // is the computed one.
  var mine = claimingThisServer(authResultsOn(inbox, marker) || []);
  count("exactly one verdict under this server's name survives " + what,
    mine.length === 1, JSON.stringify(mine));
  count("and it is the failure this server measured rather than the pass the sender wrote",
    mine.length === 1 && /dmarc=fail/.test(mine[0]) && !/dmarc=pass/.test(mine[0]),
    JSON.stringify(mine));
}

// A record written by a hop before this one. RFC 8601 section 5 removes
// only the receiver's own, so this one stays: it is what a forwarder
// found, and a receiver that deleted it would destroy the evidence the
// header exists to carry. This is the control that stops the answer to
// everything above from being "remove every such header".
//
// The claim it makes is `dmarc=fail`, which is what a forwarder writes
// about mail that failed at the forwarder too. A claim of a pass would
// decide nothing extra here and would move the message, because the
// script above tests for a substring and a substring appears in any
// hop's header: which hop a rule means is the account holder's to say,
// and it is not what this file is about.
async function apriorHopsRecordIsKept(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, FAILING_DOMAIN,
    messageFor(FAILING_DOMAIN, MARKER_PRIOR_HOP, [
      "Authentication-Results: " + FORWARDER + "; spf=fail; dmarc=fail",
    ]), "mx-prior-hop");
  count("a message carrying another receiver's verdict is accepted", /^250 /.test(reply), reply);

  var inbox = await fetchFolder(ports.imap, caPem, "INBOX");
  var values = authResultsOn(inbox, MARKER_PRIOR_HOP) || [];
  count("the record the earlier hop wrote is still on the message",
    values.some(function (v) { return v.indexOf(FORWARDER) === 0; }), JSON.stringify(values));
  count("and this server's own verdict is there beside it, exactly once",
    claimingThisServer(values).length === 1, JSON.stringify(values));
}

// The other half. A verdict this server computed as a pass reaches the
// same folder, so a run in which nothing at all was trusted would be
// caught here rather than reading as a clean sweep.
async function averdictThisServerComputedIsActedOn(ports, caPem) {
  var reply = await deliver(ports.mx, caPem, PASSING_DOMAIN,
    messageFor(PASSING_DOMAIN, MARKER_PASSING), "mx-passing");
  count("mail from a sender the pinned zone authorizes is accepted", /^250 /.test(reply), reply);

  var trusted = await fetchFolder(ports.imap, caPem, TRUSTED_FOLDER);
  count("the filter acts on the pass this server computed",
    trusted.indexOf(MARKER_PASSING) !== -1, visible(trusted).slice(0, 400));

  var mine = claimingThisServer(authResultsOn(trusted, MARKER_PASSING) || []);
  count("on a single verdict under this server's name",
    mine.length === 1, JSON.stringify(mine));
  count("which records the pass the zone authorized",
    mine.length === 1 && /dmarc=pass/.test(mine[0]), JSON.stringify(mine));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-authres-smuggling");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "auth-results smuggling run" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD });

    var actor = { id: alice.id, address: alice.address, roles: ["account"] };
    identity.mailbox.sieveScripts.put(actor, "trust-this-servers-verdict", SIEVE_SCRIPT,
      { force: true });
    identity.mailbox.sieveScripts.setActive(actor, "trust-this-servers-verdict");
    count("the account holder's script is stored and active before any mail arrives",
      identity.mailbox.sieveScripts.active(actor) !== null,
      JSON.stringify(identity.mailbox.sieveScripts.active(actor)));

    var zone = {};
    zone[PEER_REVERSE + "|PTR"] = [{ type: 12, decoded: PEER_NAME, ttl: 60 }];
    zone[PEER_NAME + "|A"]      = [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }];
    policyFor(zone, FAILING_DOMAIN, "v=spf1 -all");
    policyFor(zone, PASSING_DOMAIN, "v=spf1 ip4:" + LOOPBACK + " -all");
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
        // The shipped posture. A permissive one would deliver the same
        // messages without ever computing the verdict a sender is trying
        // to overwrite here.
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

    await aSpellingBuysTheSenderNothing(ports, material.caPem, MARKER_CANONICAL,
      ["Authentication-Results: " + HOSTNAME + "; " + CLAIMED],
      "a verdict written the way this server writes one");

    await aSpellingBuysTheSenderNothing(ports, material.caPem, MARKER_FOLDED,
      ["Authentication-Results:", "\t" + HOSTNAME + "; " + CLAIMED],
      "a verdict folded onto a second line");

    await aSpellingBuysTheSenderNothing(ports, material.caPem, MARKER_QUOTED,
      ["Authentication-Results: \"" + HOSTNAME + "\"; " + CLAIMED],
      "a verdict naming this server in a quoted string");

    await aSpellingBuysTheSenderNothing(ports, material.caPem, MARKER_SPACED,
      ["Authentication-Results :" + HOSTNAME + "; " + CLAIMED],
      "a verdict with whitespace before the colon");

    await apriorHopsRecordIsKept(ports, material.caPem);
    await averdictThisServerComputedIsActedOn(ports, material.caPem);

    count("the policy records were read from the resolver the operator pinned rather " +
      "than from the host's",
      resolver.wasAsked("_dmarc." + FAILING_DOMAIN, "TXT"),
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
  name: "inbound-auth-results-smuggling", run: run, getChecks: helpers.getChecks,
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
