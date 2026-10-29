// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A domain that published no policy, told apart from a resolver that
 * could not answer.
 *
 * These are different facts with different remedies, and DNS reports
 * them differently: a name nobody registered answers RCODE 3, while a
 * resolver that timed out answers nothing at all. The inbound gates
 * read the difference and act on it. SPF calls an absent record `none`
 * and a failed lookup `temperror`; DMARC does the same; DKIM calls an
 * absent selector a permanent failure and a failed lookup a temporary
 * one. Blur the two and every domain that never published a record
 * looks like a broken resolver, which under the shipped posture is a
 * `451` at the end of DATA and a peer that keeps trying for days.
 *
 * The reshape between this server's resolver and those gates is where
 * the difference is kept or lost, so this run drives the MX listener
 * over a real socket with a resolver whose answers are the ones the
 * shipped resolver gives, and reads the receiver's own
 * `Authentication-Results` header back over IMAP.
 *
 * Five senders, chosen so a fix that widens absence too far fails here
 * rather than in production:
 *
 *   - one that published nothing, which is `spf=none` and `dmarc=none`
 *     and an accepted message;
 *   - one whose policy authorizes the connecting address, which passes
 *     and is delivered;
 *   - one whose policy refuses it, which is refused with the code RFC
 *     7372 section 3.2 gives a message that failed authentication;
 *   - one whose policy names a host that no longer exists ahead of the
 *     address it authorizes, because absence is not only a TXT question
 *     and SPF's `a`, `mx` and `exists` mechanisms each have a defined
 *     answer for a target that is not there;
 *   - one whose envelope sits on a label under the author domain, which
 *     the published policy's relaxed alignment covers.
 *
 * And the control the whole thing turns on: a resolver that genuinely
 * cannot answer still defers, because a receiver that reads a broken
 * resolver as "no policy published" accepts spoofed mail for every
 * domain on the internet the moment its own DNS goes down.
 *
 * Run standalone: node test/layer-1-state/inbound-absence-verdicts.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var dnsZone   = require("../helpers/dns-zone");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var Wire     = wire.Wire;
var LOOPBACK = wire.LOOPBACK;
var visible  = wire.visible;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// The settings reference an operator reads before starting this server,
// and the row in it that prints what the MX listener does with the
// verdict when the configuration says nothing.
//
// The server below is started with `inbound` absent rather than set,
// which is the configuration an operator gets by changing nothing and
// the only one in which the default can be observed at all. A run that
// wrote the posture in would pass with the shipped default deleted, so
// what it measured would be the line it had just written.
//
// The posture is read out of the document rather than out of the
// module. Every verdict below is one of the two halves that posture
// promises: a published policy that refuses ends in the code RFC 7372
// section 3.2 gives a message that failed authentication, which is
// `enforce`, and a resolver that cannot answer ends in a temporary
// refusal, which is `defer`. A change to either the sentence or the
// server without the other fails here.
var SETTINGS_REFERENCE = "docs/operator-guide.md";
var INBOUND_ROW_RE = /^\|\s*`BLAMEPOST_INBOUND`\s*\|[^|]*\|\s*`([^`]+)`\s*\|/m;

function documentedInboundPosture() {
  var text = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, SETTINGS_REFERENCE), "utf8");
  var matched = INBOUND_ROW_RE.exec(text);
  if (matched === null) return null;
  try { return JSON.parse(matched[1]); }
  catch (_e) { return null; }
}

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The peer, as it presents itself and as the zone describes it.
var PEER_NAME    = "peer.example.net";
var PEER_REVERSE = "1.0.0.127.in-addr.arpa";

// The four senders. Each one is a separate registrable name so no
// policy can be inherited from another's parent while the DMARC tree
// walk climbs.
var SILENT_SENDER     = "nobody@silent.example.net";
var AUTHORIZED_SENDER = "sender@authorizing.example.net";
var REFUSED_SENDER    = "payroll@refusing.example.org";
var RELAXED_SENDER    = "sender@mail.aligning.example.net";
var RELAXED_AUTHOR    = "sender@aligning.example.net";
var PARTIAL_SENDER    = "sender@partial.example.net";
var UNREACHABLE_SENDER = "sender@unreachable.example.org";
var FORWARDED_SENDER  = "sender@forwarding.example.net";

// The hop that sealed the chain on the message below, and the selector
// its seal names. Nothing at that name answers, so the seal cannot be
// checked either way, which is the case RFC 8617 section 5.2 gives the
// same wire token as a seal that was checked and did not hold.
var SEALER_DOMAIN   = "sealer.example.net";
var SEALER_SELECTOR = "arc";

// The marker that ties one delivered message to one assertion. Each is
// distinct so the receiver's header can be found for the right message
// rather than for whichever one happened to be first.
var SILENT_MARKER  = "absence-silent-4d1a";
var ALLOWED_MARKER = "absence-allowed-4d1a";
var RELAXED_MARKER = "absence-relaxed-4d1a";
var PARTIAL_MARKER = "absence-partial-4d1a";
var REFUSED_MARKER = "absence-refused-4d1a";
var FORWARDED_MARKER = "absence-forwarded-4d1a";

// A name whose lookup cannot complete at all, which is neither an
// answer nor an absence. The shared marker rather than a private one:
// the code it raises is the difference this whole file is about, and a
// second definition of it is a second answer to what a broken lookup
// looks like.
var UNREACHABLE = dnsZone.FAILING;

// The zone the operator pinned. Keys are `<name>|<QTYPE>` and values
// are the resource records `b.network.dns.resolver.query` resolves to,
// so a gate reading `rrs[i].decoded` sees what it would see in
// production.
var ZONE = Object.freeze({
  // Forward-confirmed reverse DNS for the connecting address, so the
  // HELO identity gate has something real to confirm and the verdicts
  // below are about the records this run varies.
  [PEER_REVERSE + "|PTR"]: [{ type: 12, decoded: PEER_NAME, ttl: 60 }],
  [PEER_NAME + "|A"]:      [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }],

  // Authorizes the connecting address, on both alignment axes, so the
  // pass has to be the real one rather than a relaxed match.
  "authorizing.example.net|TXT": [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ],
  "_dmarc.authorizing.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject; adkim=s; aspf=s"], ttl: 60 },
  ],

  // Authorizes nobody, and its owner asked for refusal rather than
  // quarantine.
  "refusing.example.org|TXT": [
    { type: 16, decoded: ["v=spf1 -all"], ttl: 60 },
  ],
  "_dmarc.refusing.example.org|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
  ],

  // Names a host in its own SPF record that does not exist, ahead of
  // the address that does. RFC 7208 section 5.3 makes an `a:` whose
  // target has no address record a non-match, and evaluation carries on
  // to the next mechanism; only a lookup that failed is a temperror.
  // The record is written in that order deliberately, because a
  // receiver that stops at the first mechanism never reaches the one
  // that authorizes the mail.
  "partial.example.net|TXT": [
    {
      type:    16,
      decoded: ["v=spf1 a:withdrawn.partial.example.net ip4:" + LOOPBACK + " -all"],
      ttl:     60,
    },
  ],
  "_dmarc.partial.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject; adkim=s; aspf=s"], ttl: 60 },
  ],

  // Publishes at the author domain and leaves alignment relaxed, which
  // is the default. The envelope below sits one label lower, so only
  // relaxed alignment can join the two.
  "mail.aligning.example.net|TXT": [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ],
  "_dmarc.aligning.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
  ],

  // A name whose lookup fails rather than answering. Nothing about this
  // sender is knowable, which is not the same as knowing it published
  // nothing.
  "unreachable.example.org|TXT":         UNREACHABLE,
  "_dmarc.unreachable.example.org|TXT":  UNREACHABLE,

  // Authorizes the connecting address and asks for refusal, so the
  // message carrying an ARC chain earns its acceptance on its own
  // authentication and the only thing the chain can be measured for is
  // the `arc=` token and whether it moved the message.
  "forwarding.example.net|TXT": [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ],
  "_dmarc.forwarding.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
  ],

  // The sealer's key, unreachable rather than absent. A chain whose seal
  // could not be checked and one whose seal did not hold are different
  // facts with opposite remedies, and RFC 8617 section 5.2 gives them
  // the same token, so this is the case that proves the token is coarse
  // rather than wrong.
  [SEALER_SELECTOR + "._domainkey." + SEALER_DOMAIN + "|TXT"]: UNREACHABLE,

  // `silent.example.net` is deliberately absent from this table in
  // every form. A name that does not exist is what an operator who has
  // published nothing actually has.
});

// The resolver is `test/helpers/dns-zone.js#pinnedResolverOver` rather
// than one built here. It already derives its typed readers from one
// list, so it cannot drift into withholding `queryPtr`, which the HELO
// gate's forward-confirmed reverse check refuses a handle for rather
// than reading as "no reverse name". A session against a handle missing
// it draws a 421 at EHLO, and every case below then fails for a reason
// that belongs to the fixture.
//
// It also signals absence the way the shipped resolver signals it,
// which is what this file is about. A fixture raising `ENOTFOUND` would
// perform the conversion the server is supposed to perform, and every
// case here would pass against a server that never made the distinction
// at all.

function inboundMessageFor(author, recipient, marker, prependedHeaders) {
  return (prependedHeaders || []).concat([
    "From: " + author,
    "To: " + recipient,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "",
    "The body of the message carrying " + marker + ".",
    "",
  ]).join("\r\n");
}

// One inbound transaction from a peer. Returns what the peer was told
// after DATA, which is the whole of what a real peer decides its next
// move from.
async function deliver(port, caPem, opts) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, helo: PEER_NAME, label: opts.label,
  });
  try {
    peer.send("MAIL FROM:<" + opts.envelope + ">");
    var mail = await peer.read(/^\d{3} /m, "MAIL FROM answered");
    peer.send("RCPT TO:<" + opts.recipient + ">");
    var rcpt = await peer.read(/^\d{3} /m, "RCPT TO answered");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    var payload = inboundMessageFor(opts.author || opts.envelope, opts.recipient, opts.marker,
      opts.prependedHeaders).replace(/\r\n\./g, "\r\n..");
    peer.sendRaw(payload + "\r\n.\r\n", "<the message and its terminating dot>");
    var data = await peer.read(/^\d{3} /m, "message answered");
    return { mail: mail.trim(), rcpt: rcpt.trim(), data: data.trim() };
  } finally {
    peer.close();
  }
}

// Everything alice can read, as raw message bytes.
async function inboxOf(port, caPem, address) {
  var client = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, address: address, password: ALICE_PASSWORD,
    label: "imap-absence",
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
//
// The name has to be matched at a line start and not as a substring.
// `ARC-Authentication-Results` ends in this header's whole name (RFC
// 8617 section 4.1.1), so a search for the bare string finds a header
// the SENDER wrote in a message carrying a chain, and every token read
// off it afterwards is the forwarder's claim rather than this server's
// finding. That is the confusion the receiver's own header exists to
// end, so a reader that falls for it measures nothing.
//
// The end of the header is the next line that is not a folded
// continuation, rather than the next `From:`. Anything between them is
// a separate header, and folding one run of them into the returned
// string would let a token from a neighbor satisfy an assertion about
// this one.
var AUTH_RESULTS_HEADER = /(^|\r\n)Authentication-Results:/g;

function authResultsFor(fetched, marker) {
  var at = fetched.indexOf(marker);
  if (at === -1) return null;

  var start = -1;
  AUTH_RESULTS_HEADER.lastIndex = 0;
  for (var m = AUTH_RESULTS_HEADER.exec(fetched); m !== null;
       m = AUTH_RESULTS_HEADER.exec(fetched)) {
    var here = m.index + m[1].length;
    if (here > at) break;
    start = here;
  }
  if (start === -1) return null;

  var end = start;
  for (;;) {
    var eol = fetched.indexOf("\r\n", end);
    if (eol === -1) { end = fetched.length; break; }
    var next = fetched.charAt(eol + 2);
    if (next !== " " && next !== "\t") { end = eol; break; }
    end = eol + 2;
  }
  return fetched.slice(start, end).replace(/\r\n[ \t]+/g, " ").trim();
}

// ---- the cases -------------------------------------------------------------

// A sender that published nothing at all. Every name the gates ask
// about answers RCODE 3, which is the ordinary state of a domain whose
// operator never wrote a TXT record, and it is a settled answer rather
// than a lookup that has to be tried again.
async function aSenderThatPublishedNothingIsAcceptedAsUnauthenticated(ports, caPem, recipient) {
  var outcome = await deliver(ports.mx, caPem, {
    envelope: SILENT_SENDER, recipient: recipient,
    marker: SILENT_MARKER, label: "mx-silent",
  });
  count("a sender whose domain publishes no policy is accepted rather than told to " +
    "come back later, because there is nothing to come back for",
    /^250 /.test(outcome.data), outcome.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, SILENT_MARKER);
  count("the message reached the recipient", results !== null, visible(fetched).slice(0, 300));
  count("and the receiver recorded that the sender publishes no SPF record",
    results !== null && /spf=none/.test(results), String(results));
  count("and no DMARC policy either", results !== null && /dmarc=none/.test(results),
    String(results));
  count("neither of which is reported as a lookup that failed",
    results !== null && !/spf=temperror/.test(results) && !/dmarc=temperror/.test(results),
    String(results));
}

// The half a careless widening breaks. A published policy still decides
// the outcome, in both directions.
async function apublishedPolicyStillDecides(ports, caPem, recipient, resolver) {
  var allowed = await deliver(ports.mx, caPem, {
    envelope: AUTHORIZED_SENDER, recipient: recipient,
    marker: ALLOWED_MARKER, label: "mx-authorized",
  });
  count("a sender whose published policy authorizes the connecting address is accepted",
    /^250 /.test(allowed.data), allowed.data);
  count("and the policy was read from the resolver the operator pinned",
    resolver.wasAsked("authorizing.example.net", "TXT"), resolver.asked().join(" "));

  var refused = await deliver(ports.mx, caPem, {
    envelope: REFUSED_SENDER, recipient: recipient,
    marker: REFUSED_MARKER, label: "mx-refused",
  });
  // RFC 7372 section 3.2 gives 5.7.26 to a message that failed sender
  // authentication. The code is asserted exactly because the code is
  // what an operator filters their logs on.
  count("a sender whose published policy refuses the connecting address is still " +
    "refused, with the code RFC 7372 section 3.2 gives that refusal",
    /^550 5\.7\.26 /.test(refused.data), refused.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, ALLOWED_MARKER);
  count("the authorized sender's message carries the pass the pinned zone authorized",
    results !== null && /spf=pass/.test(results), String(results));
  count("and the DMARC pass that followed from it",
    results !== null && /dmarc=pass/.test(results), String(results));
  count("and the refused message was never stored",
    fetched.indexOf(REFUSED_MARKER) === -1, visible(fetched).slice(0, 300));
}

// The DMARC tree walk climbs past the record it found, all the way to
// the organizational domain, and a name up there that does not exist is
// the ordinary case. Read as a lookup that could not complete, it marks
// a name as unread, and an unread name withholds relaxed alignment
// because it might have declared an organizational boundary. So a
// message that aligns exactly as its sender's published policy allows
// is refused at the wire, and the sender has published everything
// correctly.
async function mailThatAlignsUnderTheSendersOwnPolicyIsDelivered(ports, caPem, recipient) {
  var outcome = await deliver(ports.mx, caPem, {
    envelope: RELAXED_SENDER, author: RELAXED_AUTHOR, recipient: recipient,
    marker: RELAXED_MARKER, label: "mx-relaxed",
  });
  count("an envelope one label under the author domain is accepted, because the " +
    "author's published policy leaves alignment relaxed",
    /^250 /.test(outcome.data), outcome.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, RELAXED_MARKER);
  count("and the receiver recorded the DMARC pass that relaxed alignment produced",
    results !== null && /dmarc=pass/.test(results), String(results));
}

// Absence is not only a TXT question. SPF's `a`, `mx` and `exists`
// mechanisms resolve address and mail-exchanger names, and RFC 7208
// section 5 gives each of them a defined answer for a target that does
// not exist: no match, carry on to the next mechanism. A host named in
// a policy and since withdrawn is the ordinary way to reach that, and
// reading it as a lookup that failed abandons the evaluation before it
// reaches the mechanism that authorizes the mail.
async function anSpfHostThatDoesNotExistIsNotAMatchRatherThanAFailure(ports, caPem, recipient) {
  var outcome = await deliver(ports.mx, caPem, {
    envelope: PARTIAL_SENDER, recipient: recipient,
    marker: PARTIAL_MARKER, label: "mx-partial",
  });
  count("a policy naming a host that no longer exists still authorizes the address " +
    "it lists after it",
    /^250 /.test(outcome.data), outcome.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, PARTIAL_MARKER);
  count("and the receiver recorded a pass rather than a lookup that failed",
    results !== null && /spf=pass/.test(results), String(results));
}

// The direction that has to hold. A resolver that cannot answer is not
// a domain that published nothing: reading one as the other accepts
// spoofed mail for every domain on the internet for as long as this
// server's own DNS is broken.
async function aResolverThatCannotAnswerStillDefers(ports, caPem, recipient) {
  var outcome = await deliver(ports.mx, caPem, {
    envelope: UNREACHABLE_SENDER, recipient: recipient,
    marker: "absence-unreachable-4d1a", label: "mx-unreachable",
  });
  count("a sender whose policy could not be looked up at all is told to try again " +
    "rather than accepted as having published nothing",
    /^451 /.test(outcome.data), outcome.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  count("and nothing was stored for that retry to duplicate",
    fetched.indexOf("absence-unreachable-4d1a") === -1, visible(fetched).slice(0, 300));
}

// ---- the ARC chain is reported and moves nothing ---------------------------

// One hop's worth of chain, RFC 8617 section 4.1, on a message that
// otherwise authenticates. The signature values are not real and do not
// need to be: the sealer's key is unreachable, so the chain cannot be
// checked either way, which is the case this measures.
//
// Written out rather than produced by the signer. A chain this server
// built with a key this run generated would be a chain that verifies,
// and what is being measured is what happens when one does not.
var ARC_CHAIN_HEADERS = [
  "ARC-Authentication-Results: i=1; " + SEALER_DOMAIN + "; spf=pass " +
    "smtp.mailfrom=" + FORWARDED_SENDER,
  "ARC-Message-Signature: i=1; a=rsa-sha256; d=" + SEALER_DOMAIN + "; s=" +
    SEALER_SELECTOR + "; c=relaxed/relaxed; h=from:to:subject; " +
    "bh=Zm9yd2FyZGVkLWJvZHktaGFzaA==; b=Zm9yd2FyZGVkLW1lc3NhZ2Utc2ln",
  "ARC-Seal: i=1; a=rsa-sha256; d=" + SEALER_DOMAIN + "; s=" + SEALER_SELECTOR +
    "; cv=none; b=Zm9yd2FyZGVkLXNlYWw=",
];

// What an operator is promised about ARC, driven end to end. Three
// claims, and the third is the one worth having a test for.
//
//   - A message carrying no chain is reported `arc=none`, so the token
//     is written on every message rather than only on forwarded ones.
//   - A chain that does not validate is reported `arc=fail`.
//   - Neither moves the message. That is a decision rather than a
//     missing half: the verdict reaches this server's delivery handoff
//     and could be acted on, and acting on it would mean trusting
//     whoever sealed the chain. Nothing here names the sealers an
//     operator vouches for, so a chain lifts nothing and refuses
//     nothing, and a test that pins the delivery is what stops that
//     from drifting into an accidental policy.
//
// The chain here fails because the sealer's key could not be looked up,
// not because a seal was checked and rejected. RFC 8601 has one `arc=`
// token for both, which is why the header cannot be read as evidence
// about the sender on its own.
async function anArcChainIsReportedAndMovesNothing(ports, caPem, recipient) {
  var outcome = await deliver(ports.mx, caPem, {
    envelope: FORWARDED_SENDER, recipient: recipient,
    marker: FORWARDED_MARKER, label: "mx-forwarded",
    prependedHeaders: ARC_CHAIN_HEADERS,
  });
  count("a message carrying a chain that does not validate is accepted, because the " +
    "chain is reported rather than acted on",
    /^250 /.test(outcome.data), outcome.data);

  var fetched = await inboxOf(ports.imap, caPem, recipient);
  var results = authResultsFor(fetched, FORWARDED_MARKER);
  count("and it reached the recipient's mailbox", results !== null,
    visible(fetched).slice(0, 300));
  count("and the receiver recorded the chain as failing",
    results !== null && /arc=fail/.test(results), String(results));
  count("beside the SPF pass the message earned on its own, so the acceptance is not " +
    "the chain's doing", results !== null && /spf=pass/.test(results), String(results));

  // The other half of the token, on a message from this same run that
  // carried no chain at all. Asserted here rather than in the case that
  // delivered it, because the two values are one claim and splitting
  // them across files is how one of them stops being checked.
  var silent = authResultsFor(fetched, SILENT_MARKER);
  count("a message carrying no chain is recorded as having none rather than as failing",
    silent !== null && /arc=none/.test(silent), String(silent));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-absence");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "inbound absence run" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: names[i] === "mx" || names[i] === "imap",
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    var documented = documentedInboundPosture();
    count("the settings reference prints an inbound posture for a configuration that says " +
      "nothing, so the run below is held to a promise rather than to itself",
      documented !== null && documented.mode === "enforce" &&
      documented.onTemperror === "defer", JSON.stringify(documented));
    count("and the configuration this run builds leaves the setting out, so what the " +
      "verdicts measure is that posture rather than one written here",
      cfg.inbound === null || cfg.inbound === undefined, JSON.stringify(cfg.inbound));

    var resolver = dnsZone.pinnedResolverOver(ZONE);

    server = blamepost.create({
      // `inbound` is deliberately absent. Every verdict below is
      // therefore produced by the posture a configuration that says
      // nothing runs at, which is the one the settings reference prints
      // and the one nearly every operator has.
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
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

    // The cases that hold today run first, so the ones that do not fail
    // on their own account rather than on a precondition an earlier
    // failure left behind.
    await apublishedPolicyStillDecides(ports, material.caPem, alice.address, resolver);
    await aResolverThatCannotAnswerStillDefers(ports, material.caPem, alice.address);
    await aSenderThatPublishedNothingIsAcceptedAsUnauthenticated(ports, material.caPem,
      alice.address);
    await anSpfHostThatDoesNotExistIsNotAMatchRatherThanAFailure(ports, material.caPem,
      alice.address);
    await mailThatAlignsUnderTheSendersOwnPolicyIsDelivered(ports, material.caPem,
      alice.address);
    await anArcChainIsReportedAndMovesNothing(ports, material.caPem, alice.address);

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

module.exports = { name: "inbound-absence-verdicts", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
