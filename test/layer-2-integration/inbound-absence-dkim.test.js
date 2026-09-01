// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A DKIM selector that was never published, told apart from a selector
 * this server could not look up.
 *
 * RFC 6376 section 6.1.2 makes the distinction and makes it binding: a
 * key query that returns no key is PERMFAIL, and a query that fails to
 * respond is a temporary failure the verifier may defer on. The two
 * reach a downstream filter as different instructions. A permanent
 * failure says this signature will never verify and the message should
 * be judged on what else it has; a temporary one says ask again later,
 * which is what a receiver does when its own resolver is unwell.
 *
 * A signature whose selector record does not exist is the ordinary
 * shape of a sender that rotated a key and withdrew the old record, or
 * of a forgery naming a selector nobody published. Reporting either as
 * a temporary failure hands the message a verdict that reads as "not
 * decided yet" forever.
 *
 * So this run signs two messages with real keys this server minted,
 * publishes the selector records for one sender and withholds them for
 * the other, delivers both through the MX listener over a real TLS
 * session, and reads the receiver's own `Authentication-Results`
 * header back over IMAP.
 *
 * The sender that DID publish is the half a careless widening breaks:
 * its signature has to keep verifying, and its record has to keep being
 * read from the resolver the operator pinned.
 *
 * Run standalone: node test/layer-2-integration/inbound-absence-dkim.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var dnsZone   = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
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
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var PEER_NAME    = "peer.example.net";
var PEER_REVERSE = "1.0.0.127.in-addr.arpa";

// Two senders. Both sign; only one publishes what a receiver needs to
// check the signature.
var PUBLISHED_DOMAIN   = "publishing.example.net";
var UNPUBLISHED_DOMAIN = "withholding.example.org";

var PUBLISHED_MARKER   = "dkim-published-9c07";
var UNPUBLISHED_MARKER = "dkim-withheld-9c07";

// One selector name for both senders. The RSA half is named from it the
// way the shipped key lifecycle names it, so the two records under one
// sender cannot collide.
var SELECTOR = "bp2026";

// The resolver over the zone below is
// `test/helpers/dns-zone.js#pinnedResolverOver` rather than one built
// here. It already derives its typed readers from one list, so it
// cannot drift into withholding `queryPtr`, which the HELO gate's
// forward-confirmed reverse check refuses a handle for rather than
// reading as "no reverse name". A session against a handle missing it
// draws a 421 at EHLO, and both cases below then fail for a reason that
// belongs to the fixture.
//
// It also signals absence the way the shipped resolver signals it, not
// with `ENOTFOUND`, which every framework gate already reads as
// absence. A fixture raising that would perform the conversion this
// file is about rather than leaving it to the server.

// The policy records both senders publish. SPF authorizes the
// connecting address and the envelope domain is the author domain, so
// alignment is exact and DMARC's verdict cannot depend on anything this
// run is not asserting.
function policyFor(zone, domain) {
  zone[domain + "|TXT"] = [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ];
  zone["_dmarc." + domain + "|TXT"] = [
    { type: 16, decoded: ["v=DMARC1; p=reject; adkim=r; aspf=s"], ttl: 60 },
  ];
  return zone;
}

// The selector records a dual-signing sender is told to publish, in the
// shape a resolver answers them. An RSA record crosses the RFC 1035
// section 3.3.14 character-string cap, so it arrives split the way a
// real answer arrives split, and a receiver that failed to rejoin the
// pieces would fail here rather than in production.
function selectorsFor(zone, halves) {
  halves.forEach(function (half) {
    var chunks = [];
    for (var i = 0; i < half.dnsTxtValue.length; i += 255) {
      chunks.push(half.dnsTxtValue.slice(i, i + 255));
    }
    zone[String(half.dnsName).toLowerCase() + "|TXT"] = [
      { type: 16, decoded: chunks, ttl: 60 },
    ];
  });
  return zone;
}

function signedMessageFor(domain, marker) {
  return [
    "From: sender@" + domain,
    "To: alice@" + DOMAIN,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@" + domain + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "The body of the message carrying " + marker + ".",
    "",
  ].join("\r\n");
}

async function deliver(port, caPem, opts) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, helo: PEER_NAME, label: opts.label,
  });
  try {
    peer.send("MAIL FROM:<sender@" + opts.domain + ">");
    await peer.read(/^250 /m, "MAIL FROM accepted");
    peer.send("RCPT TO:<" + opts.recipient + ">");
    await peer.read(/^250 /m, "RCPT TO accepted");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw(opts.signed.replace(/\r\n\./g, "\r\n..") + "\r\n.\r\n",
      "<the signed message and its terminating dot>");
    return (await peer.read(/^\d{3} /m, "message answered")).trim();
  } finally {
    peer.close();
  }
}

async function inboxOf(port, caPem, address) {
  var client = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: ALICE_PASSWORD,
    label: "imap-dkim-absence",
  });
  try {
    var selectTag = client.tag();
    client.send(selectTag + " SELECT INBOX");
    await client.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");
    var fetchTag = client.tag();
    client.send(fetchTag + " FETCH 1:* BODY[]");
    return await client.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"), "FETCH answered");
  } finally {
    client.close();
  }
}

// The receiver's own Authentication-Results header for the message
// carrying `marker`. RFC 8601 section 2.2 allows the header to fold, so
// the continuation lines are joined before anything reads a token off
// it. The header is prepended to the message, so the one belonging to a
// marker is the last one before it.
function authResultsFor(fetched, marker) {
  var at = fetched.indexOf(marker);
  if (at === -1) return null;
  var header = fetched.lastIndexOf("Authentication-Results:", at);
  if (header === -1) return null;
  var end = fetched.indexOf("\r\nFrom:", header);
  if (end === -1 || end > at) end = at;
  return fetched.slice(header, end).replace(/\r\n[ \t]+/g, " ").trim();
}

// Every `dkim=` verdict the receiver recorded, in header order.
function dkimVerdicts(results) {
  var out = [];
  var re = /dkim=([a-z]+)/g;
  var m;
  while ((m = re.exec(String(results))) !== null) out.push(m[1]);
  return out;
}

// ---- the cases -------------------------------------------------------------

// The half that has to keep working. A sender whose selector records
// are in the zone gets its signature verified against them, read
// through the resolver the operator pinned.
async function apublishedSelectorStillVerifies(ports, caPem, recipient, signed, resolver, selectors) {
  var verdict = await deliver(ports.mx, caPem, {
    domain: PUBLISHED_DOMAIN, recipient: recipient, signed: signed, label: "mx-dkim-published",
  });
  count("a signed message whose selector records are published is accepted",
    /^250 /.test(verdict), verdict);
  count("and the selector record was read from the resolver the operator pinned",
    resolver.wasAsked(selectors[0].dnsName, "TXT"), resolver.asked().join(" "));

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, PUBLISHED_MARKER);
  count("the recipient reads the message", results !== null, visible(fetched).slice(0, 300));
  var verdicts = dkimVerdicts(results);
  count("and every signature on it verified against the published records",
    verdicts.length > 0 && verdicts.every(function (v) { return v === "pass"; }),
    verdicts.join(",") + " | " + String(results));
}

// A selector nobody published. RFC 6376 section 6.1.2: a key query that
// answers "no such name" is a permanent failure, and reporting it as a
// temporary one tells every downstream filter the verdict is still
// pending on a signature that can never verify.
async function anAbsentSelectorIsAPermanentFailure(ports, caPem, recipient, signed) {
  var verdict = await deliver(ports.mx, caPem, {
    domain: UNPUBLISHED_DOMAIN, recipient: recipient, signed: signed,
    label: "mx-dkim-withheld",
  });
  count("the message still arrives on the strength of its aligned SPF pass",
    /^250 /.test(verdict), verdict);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, UNPUBLISHED_MARKER);
  count("the recipient reads it", results !== null, visible(fetched).slice(0, 300));
  var verdicts = dkimVerdicts(results);
  count("a signature naming a selector that does not exist is a permanent failure",
    verdicts.length > 0 && verdicts.every(function (v) { return v === "permerror"; }),
    verdicts.join(",") + " | " + String(results));
  count("and not a temporary one, which would tell a filter to keep waiting for a " +
    "record nobody ever published",
    verdicts.indexOf("temperror") === -1, verdicts.join(",") + " | " + String(results));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-absence-dkim");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "inbound absence dkim run" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // Two senders' keys. These are peers rather than domains this
    // server hosts, so the material comes from `b.mail.dkim.bootstrap`,
    // the same primitive the shipped key lifecycle composes, and the
    // signatures on the wire are real ones rather than fixtures that
    // agree with each other.
    var publishing = b.mail.dkim.bootstrap({
      domain: PUBLISHED_DOMAIN, selector: SELECTOR, algorithm: "dual" });
    var withholding = b.mail.dkim.bootstrap({
      domain: UNPUBLISHED_DOMAIN, selector: SELECTOR, algorithm: "dual" });
    var publishedSelectors = [publishing.ed25519, publishing.rsa];
    count("the publishing sender has two records to publish, one per algorithm",
      publishedSelectors.length === 2 &&
      publishedSelectors[0].dnsName !== publishedSelectors[1].dnsName,
      publishedSelectors.map(function (r) { return r.dnsName; }).join(", "));

    var signedPublished = publishing.signer().sign(
      signedMessageFor(PUBLISHED_DOMAIN, PUBLISHED_MARKER));
    var signedWithheld = withholding.signer().sign(
      signedMessageFor(UNPUBLISHED_DOMAIN, UNPUBLISHED_MARKER));
    count("both messages carry a signature per algorithm",
      (signedPublished.match(/^DKIM-Signature:/gm) || []).length === 2 &&
      (signedWithheld.match(/^DKIM-Signature:/gm) || []).length === 2,
      visible(signedPublished).slice(0, 160));

    // The zone. Both senders publish a policy; only one publishes the
    // selector records that policy's DKIM half needs.
    var zone = {};
    zone[PEER_REVERSE + "|PTR"] = [{ type: 12, decoded: PEER_NAME, ttl: 60 }];
    zone[PEER_NAME + "|A"]      = [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }];
    policyFor(zone, PUBLISHED_DOMAIN);
    policyFor(zone, UNPUBLISHED_DOMAIN);
    selectorsFor(zone, publishedSelectors);
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
        // one an operator runs.
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

    // The case that holds today runs first, so the one that does not
    // fails on its own account.
    await apublishedSelectorStillVerifies(ports, material.caPem, alice.address,
      signedPublished, resolver, publishedSelectors);
    await anAbsentSelectorIsAPermanentFailure(ports, material.caPem, alice.address,
      signedWithheld);

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

module.exports = { name: "inbound-absence-dkim", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
