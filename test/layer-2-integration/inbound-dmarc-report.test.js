// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A DMARC report arrives at this server as ordinary mail, and the rows it
 * produces are what the administration console renders.
 *
 * The store side of that has been live since the tables were declared:
 * `blamepost.store.reports` owns the rows and every writable open builds
 * a handle for it. The reading side has been live too, because the
 * console asks that handle for a rollup on every page it draws. What sat
 * between them is `blamepost.mail.reports`, which decides that a message
 * is a report, opens whatever the reporter wrapped it in, and hands the
 * bytes to the store. A server that composes the store handle and not the
 * reader files report mail into a mailbox, writes no row, and draws a
 * console with nothing in it, and none of the three is visible from the
 * other two.
 *
 * So the cases below post real reports at port 25 and then ask the store
 * what it holds. Nothing here calls the reader: the path under test runs
 * from the MX listener through the filing seam
 * `blamepost.mail.mailbox.onFiled` into `blamepost.mail.reports`, driven
 * the way a receiver drives it.
 *
 * The hostile cases are as much the subject as the working one. A report
 * is a compressed attachment sent by anybody who chooses to send one, so
 * a payload built to expand eight hundred times, an archive this reader
 * does not open, and a report about a domain hosted somewhere else all
 * arrive at the same address as a real report. Each has to end as a named
 * refusal with no row written, and none of them may cost the peer the
 * delivery it is waiting on.
 *
 * Run standalone: node test/layer-2-integration/inbound-dmarc-report.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");
var nodeZlib = require("node:zlib");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var dnsZone   = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME   = "mx.example.com";
var DOMAIN     = "example.com";
var POSTMASTER = "postmaster@" + DOMAIN;
var ALICE      = "alice@" + DOMAIN;

var REPORTER        = "reporter.example";
var UNHOSTED_DOMAIN = "somebody-else.example";

// The name the reporting peer greets as, and the reverse name of the
// address it connects from.
//
// A report carries the empty reverse path RFC 5321 section 4.5.5 requires,
// and RFC 7208 section 2.4 has SPF check the HELO identity when the
// reverse path is empty. So the greeting is what SPF authorizes here, and
// it sits under the reporting organization's own domain, which is what
// lets relaxed DMARC alignment hold between it and the `From` header.
// Without that this run could only ever measure a carrier that failed.
var REPORTER_MTA  = "mta." + REPORTER;
var PEER_REVERSE  = "1.0.0.127.in-addr.arpa";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;
var SETTLE_TIMEOUT_MS   = 8000;

// How long a window with no report in it is watched before the absence is
// taken as the answer. Used only where the case is asserting that NOTHING
// happened, because there is no counter to poll for an event that never
// arrives.
var QUIET_WINDOW_MS = 300;

// The expansion the bomb fixture reaches. Far above the fifty the reader
// defaults to, and the padded report stays well under every byte ceiling
// in the path, so the ratio is the only bound that can refuse it.
var BOMB_PAD_CHARS = 1500000;

var count = helpers.count;

// The window every fixture covers. It is taken from the clock rather than
// written down because the reader measures a report's window against the
// present moment: a fixed range would pass today and be refused as
// implausible once it had aged past the skew the reader allows.
var NOW_SEC        = Math.floor(Date.now() / 1000);
var WINDOW_END_SEC = NOW_SEC - 3600;
var WINDOW_BEGIN_SEC = WINDOW_END_SEC - 86400;

// ---- fixtures ---------------------------------------------------------------

function aggregateXml(opts) {
  opts = opts || {};
  var policyOn = opts.domain || DOMAIN;
  var pad = opts.padChars || 0;
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    (pad > 0 ? "  <!-- " + "A".repeat(pad) + " -->\n" : "") +
    "  <report_metadata>\n" +
    "    <org_name>" + REPORTER + "</org_name>\n" +
    "    <email>dmarc-noreply@" + REPORTER + "</email>\n" +
    "    <report_id>" + (opts.reportId || "0001") + "</report_id>\n" +
    "    <date_range><begin>" + WINDOW_BEGIN_SEC + "</begin>" +
    "<end>" + WINDOW_END_SEC + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + policyOn + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    "  <record>\n" +
    "    <row><source_ip>203.0.113.10</source_ip><count>7</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>pass</dkim><spf>pass</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + policyOn + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + policyOn + "</domain>" +
    "<result>pass</result></spf></auth_results>\n" +
    "  </record>\n" +
    "  <record>\n" +
    "    <row><source_ip>198.51.100.4</source_ip><count>3</count>\n" +
    "      <policy_evaluated><disposition>reject</disposition>" +
    "<dkim>fail</dkim><spf>fail</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + policyOn + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + policyOn + "</domain>" +
    "<result>fail</result></spf></auth_results>\n" +
    "  </record>\n" +
    "</feedback>\n";
}

// The RFC 7489 section 7.2.1.1 filename convention. The reader decides
// what a part is from its bytes, so the name here is what an operator
// reads beside a refusal rather than anything that routes.
function reportFilename(extension) {
  return REPORTER + "!" + DOMAIN + "!" + WINDOW_BEGIN_SEC + "!" + WINDOW_END_SEC +
    "." + extension;
}

// One carrier message with one attachment, in the shape a reporting
// receiver sends. The reverse path is empty on the wire because that is
// what a report carries; the headers here are the message itself.
function carrier(opts) {
  var payload = Buffer.isBuffer(opts.payload)
    ? opts.payload
    : Buffer.from(String(opts.payload), "utf8");
  return "From: dmarc-noreply@" + REPORTER + "\r\n" +
    "To: " + (opts.to || POSTMASTER) + "\r\n" +
    "Subject: Report Domain: " + DOMAIN + "\r\n" +
    "Message-ID: <" + opts.messageId + "@" + REPORTER + ">\r\n" +
    "Content-Type: multipart/mixed; boundary=\"bnd-report\"\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "This is an aggregate report from " + REPORTER + ".\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: " + opts.contentType + "\r\n" +
    "Content-Disposition: attachment; filename=\"" + opts.filename + "\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" +
    payload.toString("base64") + "\r\n" +
    "--bnd-report--\r\n";
}

function plainMessage(to, subject) {
  return "From: someone@third-party.example\r\n" +
    "To: " + to + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "Please stop sending me these.\r\n";
}

// The RFC 6591 section 3.1 shape. The part that makes the message a
// failure report is `message/feedback-report`, and the failing message
// rides inside it because a real one does.
function forensicMessage(messageId) {
  return "From: dmarc-noreply@" + REPORTER + "\r\n" +
    "To: " + POSTMASTER + "\r\n" +
    "Message-ID: <" + messageId + "@" + REPORTER + ">\r\n" +
    "Content-Type: multipart/report; report-type=feedback-report; " +
    "boundary=\"bnd-forensic\"\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "An authentication failure report.\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: message/feedback-report\r\n" +
    "\r\n" +
    "Feedback-Type: auth-failure\r\n" +
    "User-Agent: Reporter/1.0\r\n" +
    "Version: 1\r\n" +
    "Auth-Failure: dmarc\r\n" +
    "Original-Mail-From: stranger@third-party.example\r\n" +
    "Original-Rcpt-To: victim@" + DOMAIN + "\r\n" +
    "Arrival-Date: Mon, 15 Jun 2025 09:00:00 +0000\r\n" +
    "Reported-Domain: " + DOMAIN + "\r\n" +
    "Source-IP: 203.0.113.99\r\n" +
    "Delivery-Result: reject\r\n" +
    "Identity-Alignment: none\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "\r\n" +
    "From: \"Someone Real\" <stranger@third-party.example>\r\n" +
    "To: victim@" + DOMAIN + "\r\n" +
    "Subject: a stranger's subject\r\n" +
    "\r\n" +
    "a stranger's body\r\n" +
    "\r\n" +
    "--bnd-forensic--\r\n";
}

// ---- the wire ---------------------------------------------------------------

// One inbound message over the MX ladder every peer climbs. The reverse
// path is empty because RFC 5321 section 6.1 puts an empty one on a
// report, which is also what keeps this server from answering a refusal
// to the address the report claims to come from.
async function deliver(ctx, to, message, label, helo) {
  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    helo: helo === undefined ? REPORTER_MTA : helo,
  });
  peer.send("MAIL FROM:<>");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + to + ">");
  var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  if (!/^250 /m.test(rcptReply)) {
    peer.send("QUIT");
    peer.close();
    return { rcptReply: rcptReply, accepted: null };
  }
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(message + ".\r\n", "<the message and its terminating dot>");
  var accepted = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return { rcptReply: rcptReply, accepted: accepted };
}

// ---- what the store and the reader say --------------------------------------

// The counting the administration console renders, read through the same
// verb the console calls. `includeUnauthenticated` is on so that a case
// about what the store did with a report is not also a case about whether
// its carrier authenticated; `countedAsEvidence` below is the narrow
// reading, and it is the one a policy decision rests on.
function rollupOf(identity, domain) {
  return identity.reports.rollup({ domain: domain, includeUnauthenticated: true });
}

// The same counting with nothing taken on trust, which is what
// `blamepost reports` answers by default and what the console shows
// unless an operator asks to see the rest. A report counts here only
// where this server authenticated the message that carried it.
function countedAsEvidence(identity, domain) {
  return identity.reports.rollup({ domain: domain });
}

function totalCounted(identity, domain) {
  return rollupOf(identity, domain).reduce(function (sum, row) {
    return sum + row.counted;
  }, 0);
}

// What the reader has done with what it was handed, read off the assembled
// server rather than out of a handle a test built for itself.
function readerOf(server) {
  return (server.mail && server.mail.reports) ? server.mail.reports.describe() : null;
}

async function untilReceived(server, wanted, label) {
  return await helpers.waitUntil(function () {
    var shape = readerOf(server);
    return shape !== null && shape.counts.received >= wanted ? shape : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS, label: label });
}

// ---- the case the whole thing exists for ------------------------------------

// A receiver counted a day of mail claiming a hosted domain and sent the
// account of it back. Every layer of this server was already present and
// nothing joined them, so the measurement is the store's own rows rather
// than a counter the reader keeps.
async function aReportPostedAtPortTwentyFiveReachesTheStore(ctx) {
  var before = totalCounted(ctx.identity, DOMAIN);
  count("nothing has reported on this domain before the first report arrives",
    before === 0, String(before));

  var sent = await deliver(ctx, POSTMASTER, carrier({
    messageId:   "aggregate-gzip",
    contentType: "application/gzip",
    filename:    reportFilename("xml.gz"),
    payload:     nodeZlib.gzipSync(Buffer.from(aggregateXml({ reportId: "wire-0001" }), "utf8")),
  }), "aggregate-gzip");
  count("a report addressed to the reporting address is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var rows = await helpers.waitUntil(function () {
    var found = rollupOf(ctx.identity, DOMAIN);
    return found.length > 0 ? found : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS,
    label: "inbound-dmarc-report: the report reaches the rows the console reads" });

  count("the report the peer posted is counted in the reading the console renders",
    rows.length === 1 && rows[0].domain === DOMAIN && rows[0].counted === 10,
    JSON.stringify(rows));

  // The narrow reading, which is the one a policy decision rests on. This
  // server authenticated the message that carried the report, wrote its
  // verdict onto it, and read that verdict back. Every layer of that has
  // to line up: the header this server writes, the identity it names, and
  // the derivation that turns it into the party the report is attributed
  // to. A run where the carrier could not pass exercises none of it.
  var evidence = countedAsEvidence(ctx.identity, DOMAIN);
  count("and it counts with nothing taken on trust, because this server authenticated " +
    "the message that carried it",
    evidence.length === 1 && evidence[0].domain === DOMAIN && evidence[0].counted === 10,
    JSON.stringify(evidence));
  count("attributed to the organization that sent it rather than to nobody",
    evidence.length === 1 && evidence[0].unauthenticated === 0,
    JSON.stringify(evidence));
  count("and both records in it are separated into aligned and unaligned volume",
    rows[0].aligned === 7 && rows[0].unaligned === 3, JSON.stringify(rows[0]));
  count("the window the reading covers is the one the reporter declared",
    rows[0].windowBegin === WINDOW_BEGIN_SEC * 1000 &&
    rows[0].windowEnd === WINDOW_END_SEC * 1000,
    JSON.stringify({ begin: rows[0].windowBegin, end: rows[0].windowEnd }));

  var heard = ctx.identity.reports.reporters({ domain: DOMAIN, includeUnauthenticated: true });
  count("the organization that sent it is one the console can name",
    heard.reporters.length === 1 && heard.reporters[0].orgName === REPORTER,
    JSON.stringify(heard.reporters));
  count("with the domain that authenticated behind the name it gave itself",
    heard.reporters.length === 1 && heard.reporters[0].organization === REPORTER,
    JSON.stringify(heard.reporters));
  var counted = ctx.identity.reports.reporters({ domain: DOMAIN });
  count("so it counts toward that organization in the reading a policy step reads",
    counted.total === 1 && counted.reporters.length === 1 &&
    counted.reporters[0].organization === REPORTER, JSON.stringify(counted));
}

// The other half, on the same volume. A report whose carrier this server
// could not authenticate is stored and marked rather than discarded, and
// it is left out of the reading a policy step rests on.
//
// The carrier fails because the peer greets as a name the reporting
// organization's zone does not authorize, which is what a stranger posting
// a report about somebody else's domain looks like. Both halves are
// asserted against one volume, so a change that started counting
// everything and a change that stopped counting anything both fail here,
// and neither can be mistaken for the other.
async function acarrierThisServerCouldNotAuthenticateIsMarkedAndLeftOut(ctx) {
  var sent = await deliver(ctx, POSTMASTER, carrier({
    messageId:   "aggregate-stranger",
    contentType: "text/xml",
    filename:    reportFilename("xml"),
    payload:     Buffer.from(aggregateXml({ reportId: "wire-0002" }), "utf8"),
  }), "aggregate-stranger", "mta.not-the-reporter.example");
  count("a report whose carrier this server cannot authenticate is still accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var wide = await helpers.waitUntil(function () {
    var found = rollupOf(ctx.identity, DOMAIN);
    return found.length > 0 && found[0].unauthenticated > 0 ? found : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS,
    label: "inbound-dmarc-report: the unauthenticated report reaches the rows" });
  count("it is stored rather than discarded, so an operator can see what arrived",
    wide[0].unauthenticated === 10, JSON.stringify(wide[0]));

  var evidence = countedAsEvidence(ctx.identity, DOMAIN);
  count("and the reading a policy rests on still counts only the report that authenticated",
    evidence.length === 1 && evidence[0].counted === 10, JSON.stringify(evidence));

  var counted = ctx.identity.reports.reporters({ domain: DOMAIN });
  count("with one organization behind it rather than two",
    counted.reporters.length === 1 && counted.reporters[0].organization === REPORTER,
    JSON.stringify(counted));
}

// The reader is handed the message octets and files rows. It must not be
// a second filing path: the message an operator opens when the numbers say
// something they do not understand is the one copy there is.
async function theReportIsStillInTheMailbox(ctx) {
  var client = await Wire.imap(ctx.ports.imap, {
    caPem:      ctx.caPem,
    servername: HOSTNAME,
    label:      "imap-postmaster",
    address:    POSTMASTER,
    password:   ACCOUNT_PASSWORD,
  });
  var tag = client.tag();
  client.send(tag + " SELECT INBOX");
  var selected = await client.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  count("the reporting address can open its own mailbox",
    new RegExp("^" + tag + " OK", "m").test(selected), visible(selected));
  count("and the report that produced the rows is still filed there",
    /^\* [1-9][0-9]* EXISTS/m.test(selected), visible(selected));

  var fetchTag = client.tag();
  client.send(fetchTag + " FETCH 1 BODY[]");
  var fetched = await client.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH answered");
  count("the attachment is readable exactly as it arrived",
    fetched.indexOf(reportFilename("xml.gz")) !== -1, visible(fetched).slice(0, 400));

  var logout = client.tag();
  client.send(logout + " LOGOUT");
  client.close();
}

// ---- what a stranger can send to a published address ------------------------

// A payload that expands past the ratio the reader runs. The parser
// underneath bounds the expanded bytes and not the ratio, so this is the
// bound the reader adds, driven from the wire rather than asserted.
async function aCompressionBombIsRefusedAndCostsThePeerNothing(ctx) {
  var before = readerOf(ctx.server);
  var countedBefore = totalCounted(ctx.identity, DOMAIN);

  var sent = await deliver(ctx, POSTMASTER, carrier({
    messageId:   "aggregate-bomb",
    contentType: "application/gzip",
    filename:    reportFilename("xml.gz"),
    payload:     nodeZlib.gzipSync(Buffer.from(
      aggregateXml({ reportId: "wire-bomb", padChars: BOMB_PAD_CHARS }), "utf8")),
  }), "aggregate-bomb");
  count("the message still arrives, because a message carrying a hostile attachment is " +
    "still a message this server accepted",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilReceived(ctx.server, before.counts.received + 1,
    "the compression bomb reaches the reader");
  count("the reader refuses it rather than expanding it",
    after.counts.refused === before.counts.refused + 1, JSON.stringify(after.counts));
  count("and the refusal names the ratio rather than a generic failure",
    (ctx.server.mail.reports.recent().slice(-1)[0] || {}).reason ===
      "container-ratio-refused",
    JSON.stringify(ctx.server.mail.reports.recent().slice(-1)[0]));
  count("nothing it carried reached the rows",
    totalCounted(ctx.identity, DOMAIN) === countedBefore,
    countedBefore + " then " + totalCounted(ctx.identity, DOMAIN));
}

// A report about a domain hosted somewhere else. The store refuses it, and
// what this drives is that the refusal reaches the reader as a verdict
// rather than as an exception through the seam holding the delivery.
async function aReportAboutSomebodyElsesDomainIsRefused(ctx) {
  var before = readerOf(ctx.server);

  var sent = await deliver(ctx, POSTMASTER, carrier({
    messageId:   "aggregate-unhosted",
    contentType: "text/xml",
    filename:    reportFilename("xml"),
    payload:     aggregateXml({ reportId: "wire-unhosted", domain: UNHOSTED_DOMAIN }),
  }), "aggregate-unhosted");
  count("a report about a domain this server does not host is still accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilReceived(ctx.server, before.counts.received + 1,
    "the report about an unhosted domain reaches the reader");
  count("the store's refusal reaches the reader in the store's own words",
    (ctx.server.mail.reports.recent().slice(-1)[0] || {}).reason === "domain-not-hosted",
    JSON.stringify(ctx.server.mail.reports.recent().slice(-1)[0]));
  count("and it wrote no row for a domain nobody here answers for",
    rollupOf(ctx.identity, UNHOSTED_DOMAIN).length === 0,
    JSON.stringify(rollupOf(ctx.identity, UNHOSTED_DOMAIN)));
  count("the message-level verdict is a refusal rather than a silence",
    after.counts.refused === before.counts.refused + 1, JSON.stringify(after.counts));
}

// Most of what reaches a published reporting address is not a report. A
// reader that recorded each one as a failure would bury the refusals the
// counters exist to surface.
async function ordinaryMailAtTheReportingAddressIsPassedOver(ctx) {
  var before = readerOf(ctx.server);
  await deliver(ctx, POSTMASTER, plainMessage(POSTMASTER, "a question about the server"),
    "plain-to-postmaster");
  var after = await untilReceived(ctx.server, before.counts.received + 1,
    "the ordinary message reaches the reader");

  count("an ordinary message is passed over rather than refused",
    after.counts.passedOver === before.counts.passedOver + 1 &&
    after.counts.refused === before.counts.refused,
    JSON.stringify(after.counts));

  // An attachment whose name claims a container and whose bytes are
  // neither a container nor a document. The name is the only thing
  // saying report, and the name decides nothing, so this is somebody's
  // attachment rather than a reporter this server cannot read. Counting
  // it as a refusal would put ordinary mail into the number an operator
  // reads to find a broken reporter.
  await deliver(ctx, POSTMASTER, carrier({
    messageId:   "aggregate-not-a-container",
    contentType: "application/octet-stream",
    filename:    reportFilename("xml.gz"),
    payload:     Buffer.from("this is not a container and it is not a document either", "utf8"),
  }), "aggregate-not-a-container");
  var settled = await untilReceived(ctx.server, after.counts.received + 1,
    "the attachment that is not a container reaches the reader");

  count("an attachment named like a report whose bytes are not one is passed over on its " +
    "bytes rather than refused on its name",
    settled.counts.passedOver === after.counts.passedOver + 1 &&
    settled.counts.refused === after.counts.refused,
    JSON.stringify(settled.counts));
}

// A report addressed to an account is that account's mail. Reading it on
// the operator's behalf would be this server opening somebody's post.
async function aReportForAnAccountIsLeftAlone(ctx) {
  var before = readerOf(ctx.server);
  var sent = await deliver(ctx, ALICE, carrier({
    to:          ALICE,
    messageId:   "aggregate-for-alice",
    contentType: "application/gzip",
    filename:    reportFilename("xml.gz"),
    payload:     nodeZlib.gzipSync(Buffer.from(aggregateXml({ reportId: "wire-alice" }), "utf8")),
  }), "aggregate-for-alice");
  count("a report addressed to an account is accepted",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilReceived(ctx.server, before.counts.received + 1,
    "the account's message reaches the reader");
  count("it is passed over as an address this reader has no business at",
    after.counts.passedOver === before.counts.passedOver + 1 &&
    after.counts.aggregate === before.counts.aggregate,
    JSON.stringify(after.counts));
}

// ---- the failure report, which is a different shape and the same seam -------

async function aFailureReportReachesTheForensicRows(ctx) {
  var before = readerOf(ctx.server);
  var sent = await deliver(ctx, POSTMASTER, forensicMessage("forensic-wire"), "forensic");
  count("a per-message failure report is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilReceived(ctx.server, before.counts.received + 1,
    "the failure report reaches the reader");
  count("it is recognized by the part RFC 6591 section 3.1 puts the report in",
    after.counts.forensic === before.counts.forensic + 1, JSON.stringify(after.counts));

  var last = ctx.server.mail.reports.recent().slice(-1)[0] || {};
  count("and the row it produced was written rather than refused",
    last.kind === "forensic" && last.ok === true && last.stored === 1,
    JSON.stringify(last));
}

// ---- the name the reader compares against -----------------------------------

// The reader decides whether a report is evidence by finding the one
// `Authentication-Results` header this server wrote, which it recognizes by
// the authserv-id. That name is composed into the MX listener from
// `config.hostname`, and a reader comparing against anything else would
// match no header at all and mark every report as unauthenticated while
// still storing it. The failure is silent on every surface, so it is pinned
// against the listener's own answer rather than against a constant here.
function theReaderKnowsTheNameThisServerWrites(ctx) {
  var shape = readerOf(ctx.server);
  count("the reader is composed onto the assembled server rather than left unwired",
    shape !== null, JSON.stringify(Object.keys(ctx.server.mail)));
  if (shape === null) return;

  count("the name it looks for is the one the MX listener writes",
    shape.authservId === ctx.server.mail.listeners.describe().hostname,
    shape.authservId + " against " + ctx.server.mail.listeners.describe().hostname);
  count("and the address it opens mail for is the one the rua record points at",
    shape.reportingAddresses.length === 1 &&
    shape.reportingAddresses[0] === POSTMASTER,
    JSON.stringify(shape.reportingAddresses));
  count("which is the same address the policy stepper offers in the record it writes",
    ctx.server.describe().dmarcPolicy.reportingAddress === POSTMASTER,
    String(ctx.server.describe().dmarcPolicy.reportingAddress));
}

// The seam is holding a message a peer is waiting on, so nothing the
// reader does may reach it. Driven by delivering a message the reader
// refuses and then delivering an ordinary one, because an observer that
// threw would leave the mailbox layer recording a failure of its own.
async function nothingTheReaderDoesReachesThePeer(ctx) {
  var capture = helpers.auditCapture();
  try {
    // A gzip that opens and holds something no parser will take. It is
    // refused at the parse, which is a verdict this reader records, so the
    // trail row waited for below is a row that has to arrive rather than
    // one that might.
    await deliver(ctx, POSTMASTER, carrier({
      messageId:   "aggregate-unreadable",
      contentType: "application/gzip",
      filename:    reportFilename("xml.gz"),
      payload:     nodeZlib.gzipSync(Buffer.from("this is not a report", "utf8")),
    }), "aggregate-unreadable");
    var sent = await deliver(ctx, POSTMASTER,
      plainMessage(POSTMASTER, "the message after the bad one"), "plain-after-bad");
    count("the delivery after a report the reader could not use is answered normally",
      /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

    // The reader's own row for the message it could not use, waited for
    // rather than assumed. It is what says the capture is capturing: an
    // absence read off a sink that was never installed is the same
    // reading as an absence read off one that was, and only one of them
    // means anything.
    await helpers.waitUntil(function () {
      return capture.forAction("blamepost.mail.reports.refused").length > 0;
    }, { timeoutMs: SETTLE_TIMEOUT_MS,
      label: "inbound-dmarc-report: the reader's refusal reaches the trail" });

    await helpers.passiveObserve(QUIET_WINDOW_MS,
      "no observer failure recorded by the mailbox layer");
    count("and the filing seam recorded no observer failure beside it, so nothing was " +
      "thrown at the call holding the peer's delivery",
      capture.forAction("blamepost.mail.mailbox.filed_observer_failed").length === 0 &&
      capture.forAction("blamepost.mail.reports.reader_failed").length === 0,
      JSON.stringify(capture.forAction("blamepost.mail.mailbox.filed_observer_failed")
        .concat(capture.forAction("blamepost.mail.reports.reader_failed"))));
  } finally {
    capture.release();
  }
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-dmarc-report");
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
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:               HOSTNAME,
        BLAMEPOST_DATA_DIR:               dataDir,
        BLAMEPOST_VAULT_PASSPHRASE:       VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED:       "1",
        // The address this server puts on the mail it sends about itself,
        // which is therefore the address a rua record points at and the
        // one reports come back to.
        BLAMEPOST_POSTMASTER:             POSTMASTER,
        BLAMEPOST_DMARC_FORENSIC_ENABLED: "true",
      },
      cwd: root,
    });

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });
    await identity.accounts.create({ address: POSTMASTER, password: ACCOUNT_PASSWORD });
    await identity.accounts.create({ address: ALICE,      password: ACCOUNT_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    // The zone the reporting peer is measured against. Without one this
    // run resolved nothing, every carrier failed DMARC, and the reading a
    // policy decision rests on could not be exercised at all: the reader
    // that decides whether a report is evidence was driven only down the
    // branch where nothing is.
    var zone = {};
    zone[PEER_REVERSE + "|PTR"]  = [{ type: 12, decoded: REPORTER_MTA, ttl: 60 }];
    zone[REPORTER_MTA + "|A"]    = [{ type: 1,  decoded: LOOPBACK,     ttl: 60 }];
    zone[REPORTER_MTA + "|TXT"]  = [{ type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"],
                                      ttl: 60 }];
    zone[REPORTER + "|TXT"]      = [{ type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"],
                                      ttl: 60 }];
    // p=none, so a carrier this run did not intend to authenticate is
    // delivered and measured rather than refused at the wire.
    zone["_dmarc." + REPORTER + "|TXT"] = [{ type: 16, decoded: ["v=DMARC1; p=none"], ttl: 60 }];
    var resolver = dnsZone.pinnedResolverOver(zone);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The shipped posture, over the pinned zone above.
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

    var ctx = {
      server:   server,
      identity: identity,
      caPem:    leaf.ca,
      ports:    { mx: sections.mx.port, imap: sections.imap.port },
    };

    // The rows first, because that case reads the store alone and says
    // nothing about how the reader is composed. A run against a server
    // with no reader on it therefore fails on the rows that never arrived
    // rather than on the shape of a handle, which is the finding.
    await aReportPostedAtPortTwentyFiveReachesTheStore(ctx);
    await acarrierThisServerCouldNotAuthenticateIsMarkedAndLeftOut(ctx);
    theReaderKnowsTheNameThisServerWrites(ctx);
    await theReportIsStillInTheMailbox(ctx);
    await aCompressionBombIsRefusedAndCostsThePeerNothing(ctx);
    await aReportAboutSomebodyElsesDomainIsRefused(ctx);
    await ordinaryMailAtTheReportingAddressIsPassedOver(ctx);
    await aReportForAnAccountIsLeftAlone(ctx);
    await aFailureReportReachesTheForensicRows(ctx);
    await nothingTheReaderDoesReachesThePeer(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "inbound-dmarc-report", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
