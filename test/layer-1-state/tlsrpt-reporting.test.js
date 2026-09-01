// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The reports this server owes the peers it delivers to.
 *
 * RFC 8460 makes TLS-RPT a two-party arrangement. A receiver publishes
 * `_smtp._tls.<domain>` naming where to send aggregate reports, and
 * every sender that reads it owes that receiver a periodic account of
 * how its transport security actually went. blamepost asks operators to
 * publish that record for their own domains, so it is also a sender
 * that has to honor other people's.
 *
 * Three answers a receiver's zone can give, and the whole file is about
 * keeping them apart:
 *
 *   - It publishes an endpoint. A report is composed from what the
 *     attempts actually did and submitted to it.
 *   - It publishes nothing. Nobody asked for a report, so nothing is
 *     sent and nothing is kept.
 *   - The lookup could not complete. That is not the same as publishing
 *     nothing, and reading it as such throws away evidence a receiver
 *     asked for. The observations stay and the next run asks again.
 *
 * The distinction in the third case is the one this project has already
 * been bitten by from the other direction, where an absent policy record
 * read as a transient resolver failure and mail was deferred at the wire
 * for every domain that never published one.
 *
 * The sharpest case here is the one that would defame a peer. Plenty of
 * delivery failures have nothing to do with transport security: a host
 * that cannot be reached, a domain publishing no mail exchanger, a
 * mailbox that is full. A reporter that counted those would send the
 * receiver a report blaming them for a TLS failure that never happened,
 * signed with this server's name on it.
 *
 * No sockets. The resolver answers from a table and the HTTPS
 * submission goes to a recording client, which is the same posture the
 * outbound policy cases take: what is under test is which question was
 * asked, what was said about the answer, and what the receiver would
 * have read.
 *
 * Run standalone: node test/layer-1-state/tlsrpt-reporting.test.js
 */

var zlib = require("node:zlib");

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");
var b         = require("../../lib/vendor/blamejs");

var check = helpers.check;

var HOSTNAME = "mx.example.com";
var MESSAGE  = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// A receiver that wants reports over HTTPS, and whose MTA-STS record
// cannot be looked up. The second half is what produces an observation
// worth reporting in this build: the policy question is answered before
// any transport is constructed, so it is a real RFC 8460 policy failure
// rather than a local fault.
var WANTS_REPORTS = {
  "example.net":             { mx: ["mx.example.net"] },
  "_mta-sts.example.net":    zone.FAILING,
  "_smtp._tls.example.net":  { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

// The same receiver with no TLS-RPT record at all, which is what most
// of the internet looks like.
var WANTS_NOTHING = {
  "example.org":          { mx: ["mx.example.org"] },
  "_mta-sts.example.org": zone.FAILING,
};

// A receiver whose TLS-RPT record cannot be looked up. Nothing here says
// whether an endpoint exists.
var UNSETTLED = {
  "elsewhere.example":            { mx: ["mx.elsewhere.example"] },
  "_mta-sts.elsewhere.example":   zone.FAILING,
  "_smtp._tls.elsewhere.example": zone.FAILING,
};

// A receiver that wants reports and publishes a perfectly ordinary
// posture, so nothing about its policy fails. What fails is reaching the
// mail exchanger it named, which is a delivery failure with no TLS
// negotiation anywhere in it.
var NO_TLS_NEGOTIATION = {
  "example.net":            { mx: ["mx.example.net"] },
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

// A receiver that wants reports and publishes no mail exchanger at all,
// so delivery to it fails permanently before any transport security is
// in question. RFC 8460 has no result type for it and inventing one
// would tell a receiver their TLS is broken when their MX record is.
var NO_MAIL_EXCHANGER = {
  "example.net":            { mx: [] },
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

// A receiver that takes reports only by mail, which RFC 8460 §5.3
// allows and which this build cannot put on a socket.
var MAIL_ONLY = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=mailto:tls-reports@example.net"] },
};

// The same receiver, having published its report address in another
// case. RFC 4343 says that is not a difference, and the spelling is
// theirs to choose: nothing in RFC 8460 asks them to fold it.
var MAIL_MIXED_CASE = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=mailto:TLS-Reports@EXAMPLE.NET"] },
};

// And having published the absolute form of RFC 1035 §2.3.1, which is
// the same name again. A zone file writes a name that way routinely, so
// a receiver publishing it is asking for a report in a spelling of its
// own choosing rather than making a mistake, and the report is owed.
var MAIL_ABSOLUTE = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=mailto:tls-reports@example.net."] },
};

// A receiver whose report address no spelling can reach. One trailing
// dot is the absolute form of the same name; two is not a name at all,
// and there is no reading of it that yields an address a forward path
// could carry. So the report stays owed and unsent, which is the
// distinction the absolute case is about: the leniency is one fold of a
// legitimate wire form, not a search for something that parses.
var MAIL_UNREADABLE = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=mailto:tls-reports@example.net.."] },
};

function handleOn(dataDir, resolver) {
  return blamepost.mail.delivery.create({
    hostname:   HOSTNAME,
    dataDir:    dataDir,
    postmaster: "postmaster@example.com",
    resolver:   resolver,
    policy:     { mtaSts: "enforce", dane: "off" },
    audit:      false,
  });
}

function sendTo(delivery, recipient) {
  return delivery.send({
    from:   "alice@example.com",
    to:     [recipient],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
}

// The HTTP client `b.network.smtp.tlsRpt.submit` posts through. It
// records every request so a case can read the report a receiver would
// have got rather than the one this server thinks it built.
function recordingClient(statusCode) {
  var posts = [];
  return {
    posts: posts,
    request: async function (opts) {
      posts.push(opts);
      return { statusCode: statusCode === undefined ? 202 : statusCode, headers: {}, body: "" };
    },
  };
}

function reportIn(post) {
  return JSON.parse(zlib.gunzipSync(post.body).toString("utf8"));
}

async function domainRow(delivery, domain) {
  var rows = (await delivery.tlsRpt.observed()).filter(function (r) { return r.domain === domain; });
  return rows.length === 1 ? rows[0] : null;
}

// ---------------------------------------------------------------------------
// The surface, before anything drives it
// ---------------------------------------------------------------------------

async function theReportingSurfaceIsOnTheDeliveryHandle(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  check("the reporter is reachable as blamepost.mail.delivery.tlsRpt",
    typeof delivery.tlsRpt.run === "function" &&
    typeof delivery.tlsRpt.observed === "function");
  check("nothing has been observed before anything was sent",
    (await delivery.tlsRpt.observed()).length === 0);
  check("and no reporting timer runs until the handle is started",
    delivery.describe().tlsRpt.reporting === false);
  delivery.start();
  check("start arms it", delivery.describe().tlsRpt.reporting === true);
  delivery.start();
  check("arming twice keeps the first timer", delivery.describe().tlsRpt.reporting === true);
  delivery.stop();
  check("stop disarms it", delivery.describe().tlsRpt.reporting === false);
}

// ---------------------------------------------------------------------------
// A receiver that published an endpoint gets a report about its own zone
// ---------------------------------------------------------------------------

async function anEndpointDrawsAReportCarryingWhatTheAttemptDid(dataDir) {
  var resolver = zone.resolverOver(WANTS_REPORTS);
  var delivery = handleOn(dataDir, resolver);
  await sendTo(delivery, "bob@example.net");

  var observed = await domainRow(delivery, "example.net");
  check("the attempt left an observation against the receiver's domain",
    observed !== null && observed.failed === 1);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("the run reports on exactly the one receiver that has observations",
    run.ran === 1 && run.results.length === 1);
  check("and it says the report was submitted",
    run.results[0].domain === "example.net" && run.results[0].outcome === "submitted");
  check("the endpoint lookup went to the resolver the operator pinned",
    resolver.calls.indexOf("TXT _smtp._tls.example.net") !== -1);
  check("one request went to the endpoint the receiver published",
    client.posts.length === 1 &&
    client.posts[0].url === "https://reports.example.net/tlsrpt" &&
    String(client.posts[0].method).toUpperCase() === "POST");
  check("carrying the media type RFC 8460 §3 names",
    String(client.posts[0].headers["content-type"]) === "application/tlsrpt+gzip");

  var report = reportIn(client.posts[0]);
  check("the report names this server, so the receiver knows who is telling them",
    report["organization-name"] === HOSTNAME);
  check("and an address they can reply to",
    report["contact-info"] === "postmaster@example.com");
  check("it carries a report id and a period",
    typeof report["report-id"] === "string" && report["report-id"].length > 0 &&
    typeof report["date-range"]["start-datetime"] === "string" &&
    typeof report["date-range"]["end-datetime"] === "string");

  var policy = report.policies[0];
  check("the policy it reports on is the receiver's own domain",
    policy.policy["policy-domain"] === "example.net");
  check("and it is named as an MTA-STS policy, which is what refused the attempt",
    policy.policy["policy-type"] === "sts");
  check("no session succeeded and one failed",
    policy.summary["total-successful-session-count"] === 0 &&
    policy.summary["total-failure-session-count"] === 1);
  check("the failure names the MTA-STS policy fetch, which is what actually went wrong",
    policy["failure-details"].length === 1 &&
    policy["failure-details"][0]["result-type"] === "sts-policy-fetch-error");
  check("and it is counted as one failed session rather than left to be inferred",
    policy["failure-details"][0]["failed-session-count"] === 1);
  // The only address a report may carry is the submitter's own contact,
  // which RFC 8460 §4.4 asks for. Everything describing what happened
  // is counts, hostnames and status text, so a receiver learns which of
  // their mail exchangers is refusing and never which mailbox was
  // being written to.
  check("the one address in the report is this server's own contact",
    JSON.stringify(report.policies).indexOf("@") === -1 &&
    JSON.stringify(report["date-range"]).indexOf("@") === -1 &&
    report["contact-info"] === "postmaster@example.com");

  check("the period is closed once the receiver has the report",
    (await domainRow(delivery, "example.net")) === null);
  check("and the handle counts it",
    delivery.describe().tlsRpt.reportsSubmitted === 1 &&
    delivery.describe().tlsRpt.reportsUnsent === 0);
}

// ---------------------------------------------------------------------------
// A receiver that published nothing is not sent anything
// ---------------------------------------------------------------------------

async function noEndpointDrawsNoReport(dataDir) {
  var resolver = zone.resolverOver(WANTS_NOTHING);
  var delivery = handleOn(dataDir, resolver);
  await sendTo(delivery, "bob@example.org");

  check("the attempt was observed", (await domainRow(delivery, "example.org")) !== null);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("nothing is posted to a receiver that asked for nothing",
    client.posts.length === 0);
  check("and the run says so rather than reporting a failure",
    run.results.length === 1 && run.results[0].outcome === "no-endpoint");
  check("the observations are dropped, because nobody is owed them",
    (await domainRow(delivery, "example.org")) === null);
  check("nothing is counted as unsent, because nothing was owed",
    delivery.describe().tlsRpt.reportsUnsent === 0);
}

// ---------------------------------------------------------------------------
// A lookup that could not complete is not a receiver that published nothing
// ---------------------------------------------------------------------------

async function anUnsettledLookupKeepsTheEvidence(dataDir) {
  var resolver = zone.resolverOver(UNSETTLED);
  var delivery = handleOn(dataDir, resolver);
  await sendTo(delivery, "bob@elsewhere.example");

  var before = await domainRow(delivery, "elsewhere.example");
  check("the attempt was observed", before !== null && before.failed === 1);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("nothing is posted, because where to post is unknown",
    client.posts.length === 0);
  check("and the run tells that apart from a receiver that published nothing",
    run.results.length === 1 && run.results[0].outcome === "unsettled");
  var after = await domainRow(delivery, "elsewhere.example");
  check("the observations are kept for the next run rather than discarded",
    after !== null && after.failed === 1);
}

// ---------------------------------------------------------------------------
// An attempt that negotiated nothing is never reported as a TLS failure
// ---------------------------------------------------------------------------

// RFC 8460 result types all describe something that happened to a
// policy or to a TLS negotiation. An attempt that never got as far as
// one has nothing to say under any of them, and saying it anyway sends
// the receiver a signed accusation about their transport security on the
// strength of a host that could not be reached.
async function anAttemptWithNoNegotiationIsNeverReportedAsTls(dataDir) {
  var resolver = zone.resolverOver(NO_TLS_NEGOTIATION);
  var delivery = handleOn(dataDir, resolver);
  var outcome = await sendTo(delivery, "bob@example.net");

  check("the recipient is waiting on the attempt rather than refused",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  check("the attempt reports what it met rather than a TLS verdict",
    !/tls-upgrade|starttls-rejected/i.test(String(outcome.deferred[0].reason)));
  check("and nothing about it is recorded against the receiver",
    (await domainRow(delivery, "example.net")) === null);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("so a receiver that wants reports is sent none",
    client.posts.length === 0 && run.ran === 0);
}

// The barrier above is one of two, and only this vector reaches the
// second on its own. A refusal that is genuinely the receiver's, and
// genuinely nothing to do with TLS, must not be counted either. RFC
// 8460 has result types for policy and negotiation failures and none
// for a domain with no mail exchanger, and reporting one anyway would
// tell a receiver to go and look at their certificates.
async function aRefusalThatIsNotAboutTransportSecurityIsNotReported(dataDir) {
  var resolver = zone.resolverOver(NO_MAIL_EXCHANGER);
  var delivery = handleOn(dataDir, resolver);
  var outcome = await sendTo(delivery, "bob@example.net");

  check("the message is refused permanently, by the receiver's own zone",
    outcome.failed.length === 1 && outcome.failed[0].reasonCode === "5.1.2");
  check("and no session outcome is recorded against the receiver",
    (await domainRow(delivery, "example.net")) === null);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });
  check("so the receiver is told nothing about their TLS",
    client.posts.length === 0 && run.ran === 0);
}

// ---------------------------------------------------------------------------
// A destination that takes mail takes the report as mail
// ---------------------------------------------------------------------------

async function aMailDestinationGetsTheReportAsMail(dataDir) {
  var resolver = zone.resolverOver(MAIL_ONLY);
  var delivery = handleOn(dataDir, resolver);
  await sendTo(delivery, "bob@example.net");
  check("one message is waiting before the report is composed",
    delivery.queue.count() === 1);

  var client = recordingClient(202);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("nothing goes over HTTPS, because the receiver named no HTTPS destination",
    client.posts.length === 0);
  check("the report goes onto the outbound path rather than being counted as submitted",
    run.results.length === 1 && run.results[0].outcome === "queued");
  check("and the handle counts it as queued rather than as sent or as owed",
    delivery.describe().tlsRpt.reportsQueued === 1 &&
    delivery.describe().tlsRpt.reportsSubmitted === 0 &&
    delivery.describe().tlsRpt.reportsUnsent === 0);

  var waiting = await delivery.queue.list();
  var toReports = waiting.filter(function (e) { return e.recipient === "tls-reports@example.net"; });
  check("the report is in the queue addressed where the receiver asked",
    toReports.length === 1);
  check("sent from the operator's own postmaster address, not the null return path",
    toReports.length === 1 && toReports[0].from === "postmaster@example.com");

  var entry = await delivery.queue.show(toReports[0].id);
  check("the queue can say what happened to it, like any other message",
    entry !== null && entry.attemptsRecorded === 1);

  // What is on disk is what the receiver would open. Reading the
  // message back is the only assertion worth making about the mail
  // form: a report that composes cleanly and gunzips to something else
  // is a report nobody can act on.
  var wire = helpers.fs.readFileSync(
    helpers.path.join(dataDir, "queue", toReports[0].id + ".eml"), "utf8");
  check("the message carries the report as RFC 8460 §5.3 asks",
    /^Content-Type: application\/tlsrpt\+gzip$/m.test(wire) &&
    /^Content-Transfer-Encoding: base64$/m.test(wire) &&
    /^TLS-Report-Domain: example\.net$/m.test(wire) &&
    /^TLS-Report-Submitter: mx\.example\.com$/m.test(wire));
  check("with the receiver's domain in the Report Domain slot, not the submitter's",
    /^Subject: Report Domain: example\.net Submitter: mx\.example\.com Report-ID: </m.test(wire));
  check("and a filename naming both domains and the period",
    /filename="mx\.example\.com!example\.net!\d+!\d+\.json\.gz"/.test(wire));

  var attached = wire.split("\r\n\r\n").slice(1).join("\r\n\r\n");
  var carried = JSON.parse(zlib.gunzipSync(Buffer.from(attached, "base64")).toString("utf8"));
  check("the attachment is the report itself, about the receiver's own domain",
    carried.policies[0].policy["policy-domain"] === "example.net" &&
    carried.policies[0].summary["total-failure-session-count"] === 1);

  // Sending the report is itself an attempt at that domain, so what
  // happened to it belongs in the next period rather than nowhere.
  var after = await domainRow(delivery, "example.net");
  check("the period the report covered is closed, and the report's own attempt opens the next",
    after !== null && after.failed === 1);
}

// What a receiver publishes is a spelling of a mailbox, and what this
// server hands over has to be a forward path RFC 5321 §4.1.2 admits.
// Those are two different questions, so the published value is read
// through the one derivation that answers the second: the envelope and
// the To header are written from the derived name rather than from the
// record, and a report cannot end up addressed one way in the envelope
// and another way in the header.
async function aPublishedReportAddressIsDerivedBeforeItIsUsed(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(MAIL_MIXED_CASE));
  await sendTo(delivery, "bob@example.net");
  var run = await delivery.tlsRpt.run({ httpClient: recordingClient(202) });
  check("a report owed to a receiver that published its address in another case is queued",
    run.results.length === 1 && run.results[0].outcome === "queued");

  var waiting = await delivery.queue.list();
  var toReports = waiting.filter(function (e) {
    return e.recipient === "tls-reports@example.net";
  });
  check("addressed to the mailbox that record names rather than to the bytes it holds",
    toReports.length === 1);

  var wire = helpers.fs.readFileSync(
    helpers.path.join(dataDir, "queue", toReports[0].id + ".eml"), "utf8");
  check("and the To header names the same one address, so the envelope and the header " +
    "cannot disagree about where the report went",
    /^To: tls-reports@example\.net$/m.test(wire));
}

// The other spelling of the same name, and the sibling of the case
// above. A receiver that published its report address absolutely is owed
// a report and gets one, addressed to the mailbox that record names.
//
// Both halves of the fold matter and neither is enough alone. The
// published value is a name, and one trailing dot is RFC 1035 §2.3.1's
// way of writing it whole; what the envelope carries is a forward path,
// and RFC 5321 §4.1.2 has no dot in it. A reader that refused the
// published form would cost the RECEIVER the report they asked for
// under RFC 8460 and cost this sender nothing, which is the direction
// that makes reading it the correct answer rather than the lenient one.
// A reader that passed the published form through would hand the next
// server along a path it refuses.
//
// So the assertion is on the two places one name is written. The
// envelope and the To header come from one derivation, so a report
// cannot leave addressed one way and filed another.
async function aReportAddressPublishedAbsolutelyReachesTheReceiver(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(MAIL_ABSOLUTE));
  await sendTo(delivery, "bob@example.net");
  var run = await delivery.tlsRpt.run({ httpClient: recordingClient(202) });
  check("a receiver that published the absolute form of its report address is owed a " +
    "report and gets one",
    run.results.length === 1 && run.results[0].outcome === "queued");
  check("and the handle counts it as queued rather than as owed",
    delivery.describe().tlsRpt.reportsQueued === 1 &&
    delivery.describe().tlsRpt.reportsUnsent === 0);

  var waiting = await delivery.queue.list();
  var toReports = waiting.filter(function (e) {
    return String(e.recipient).indexOf("tls-reports@") === 0;
  });
  check("addressed to the name that record spells rather than to the bytes it holds, so " +
    "the next server along is handed a forward path it admits",
    toReports.length === 1 && toReports[0].recipient === "tls-reports@example.net");

  var wire = helpers.fs.readFileSync(
    helpers.path.join(dataDir, "queue", toReports[0].id + ".eml"), "utf8");
  check("and the To header names the same one address, so the envelope and the header " +
    "cannot disagree about where the report went",
    /^To: tls-reports@example\.net$/m.test(wire));

  // Sending the report is itself an attempt at that domain, so the
  // period the report covered is closed and the report's own attempt
  // opens the next one, exactly as it does for a relative spelling.
  var after = await domainRow(delivery, "example.net");
  check("the period the report covered is closed behind it",
    after !== null && after.failed === 1);
}

// The same fold, read back off the trail rather than off the queue.
//
// Delivering to the folded spelling is right, and it is also the whole
// reason this needs a record: the address this server wrote to is not
// the address the receiver published, and every other case above ends
// once the report is queued. A receiver who later says no report ever
// arrived is asking which address it went to, and an answer of "the one
// you published" is the one thing that is not true.
//
// So the row carries the two spellings and the arrow between them. The
// relative case is driven beside it because a field that is filled in
// every time says nothing: what makes the value evidence is that it is
// empty when the receiver's own spelling was used unchanged.
//
// The handle is built with audit on, which is what the shipped server
// does and what every other case here turns off. The namespace is
// registered because opening a store is what normally does that, and
// nothing here opens one; without it the row is discarded before it
// reaches any sink and the case would pass by reading nothing.
async function whatTheTrailSaysAboutASpellingThisServerFolded(dataDir) {
  var captured = [];
  b.audit.registerNamespace("blamepost");
  b.audit.useStore({
    replaceChain: true,
    record:       function (row) { captured.push(row); return true; },
  });
  try {
    // Rows the cases above left buffered drain on the first flush of the
    // process, whoever calls it, so the backlog is taken here rather than
    // arriving inside the first reading below and being counted as it.
    await b.audit.flush();
    var rowsFor = async function (zoneMap, dir) {
      captured.length = 0;
      var delivery = blamepost.mail.delivery.create({
        hostname:   HOSTNAME,
        dataDir:    dir,
        postmaster: "postmaster@example.com",
        resolver:   zone.resolverOver(zoneMap),
        policy:     { mtaSts: "enforce", dane: "off" },
        audit:      true,
      });
      await sendTo(delivery, "bob@example.net");
      var run = await delivery.tlsRpt.run({ httpClient: recordingClient(202) });
      await b.audit.flush();
      return {
        run:  run,
        rows: captured.filter(function (r) {
          return r.action === "blamepost.mail.delivery.tls_rpt_sent";
        }),
      };
    };

    var absolute = await rowsFor(MAIL_ABSOLUTE, dataDir);
    helpers.count("a report owed to a receiver that published absolutely is queued and filed",
      absolute.run.results[0].outcome === "queued" && absolute.rows.length === 1,
      JSON.stringify(absolute.run.results) + " rows=" + absolute.rows.length);
    var meta = JSON.parse(absolute.rows[0].metadata);
    check("and the row says which spelling was published and which one was written to, " +
      "so a receiver who says no report arrived can be answered from the trail",
      meta.respelled === "tls-reports@example.net. -> tls-reports@example.net");

    var relative = await rowsFor(MAIL_ONLY, helpers.tempDir("tlsrpt-trail-relative"));
    check("a receiver whose spelling was used unchanged is queued and filed too",
      relative.run.results[0].outcome === "queued" && relative.rows.length === 1);
    check("and its row records no respelling, so the field is evidence rather than decoration",
      JSON.parse(relative.rows[0].metadata).respelled === "");
  } finally {
    b.audit.useStore(null);
  }
}

// The spelling no reading reaches. Folding one trailing dot is reading a
// name a receiver wrote whole; folding until something parses is
// guessing at what they meant, and the guess would put a report on the
// wire addressed to an invention. So a record no derivation can turn
// into an address leaves the report owed and unsent, with the published
// value in the reason, and nothing queued for a path the next server
// along would refuse.
//
// The evidence stays, because an unsent report is one the receiver is
// still owed: a zone corrected tomorrow is a receiver who then gets the
// account of what failed today.
async function aReportAddressNoSpellingReachesIsOwedAndRecorded(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(MAIL_UNREADABLE));
  await sendTo(delivery, "bob@example.net");
  var run = await delivery.tlsRpt.run({ httpClient: recordingClient(202) });
  check("a receiver whose published report address is not a name gets no report",
    run.results.length === 1 && run.results[0].outcome === "unsent");
  check("and the reason names the destination that could not be used, so an operator can " +
    "see which receiver is owed one and what they published",
    String(run.results[0].reason || "").indexOf("tls-reports@example.net..") !== -1);
  check("which the handle counts, so nobody has to notice a log line",
    delivery.describe().tlsRpt.reportsUnsent === 1 &&
    delivery.describe().tlsRpt.reportsQueued === 0);
  check("with nothing queued for it, rather than a message addressed to a path the next " +
    "server along would refuse",
    (await delivery.queue.list()).filter(function (e) {
      return String(e.recipient).indexOf("tls-reports@") === 0;
    }).length === 0);
  check("and the observations survive, so a receiver that corrects its zone is still told " +
    "what failed today",
    (await domainRow(delivery, "example.net")) !== null);
}

async function anEndpointThatRefusesKeepsTheEvidence(dataDir) {
  var resolver = zone.resolverOver(WANTS_REPORTS);
  var delivery = handleOn(dataDir, resolver);
  await sendTo(delivery, "bob@example.net");

  var client = recordingClient(500);
  var run = await delivery.tlsRpt.run({ httpClient: client });

  check("the report was offered to the endpoint the receiver published",
    client.posts.length === 1);
  check("an endpoint that refused it leaves the report unsent",
    run.results.length === 1 && run.results[0].outcome === "unsent");
  check("which the handle counts, so nobody has to notice a log line",
    delivery.describe().tlsRpt.reportsUnsent === 1);
  check("and the observations survive, so the next run tries again",
    (await domainRow(delivery, "example.net")) !== null);
}

// ---------------------------------------------------------------------------
// The timer is what sends the report, so the timer has to run
// ---------------------------------------------------------------------------

// Every case above drives the run by hand. In a running server nobody
// does: the report goes because a timer fires, and a timer armed and
// never firing is a whole feature that works in a test and does
// nothing in production. So one case waits for a report to arrive
// without asking for it.
async function theReportGoesWithoutAnybodyAskingForIt(dataDir) {
  var resolver = zone.resolverOver(WANTS_REPORTS);
  var client = recordingClient(202);
  var delivery = blamepost.mail.delivery.create({
    hostname:         HOSTNAME,
    dataDir:          dataDir,
    postmaster:       "postmaster@example.com",
    resolver:         resolver,
    policy:           { mtaSts: "enforce", dane: "off" },
    tlsRptIntervalMs: 1000,
    tlsRptSubmit:     { httpClient: client },
    audit:            false,
  });
  await sendTo(delivery, "bob@example.net");
  check("the attempt is waiting to be reported",
    (await domainRow(delivery, "example.net")) !== null);

  delivery.start();
  try {
    // Wait for the whole cycle rather than for the post alone. The period
    // closes AFTER the submission resolves, so waiting on the post and
    // then asserting the close reads a state the timer has not reached
    // yet. That passes on a quiet machine and fails under a loaded run,
    // which is the nondeterministic entry in the coverage taxonomy and
    // is exactly how this file behaved: green on its own, red in the
    // suite.
    await helpers.waitUntil(async function () {
      return client.posts.length >= 1 &&
        (await domainRow(delivery, "example.net")) === null;
    }, {
      timeoutMs: 8000,
      label:     "tls-rpt: the reporting timer sends the report and closes the period behind it",
    });
  } finally {
    delivery.stop();
  }
  check("the report reached the receiver's endpoint with nobody driving a run",
    client.posts.length === 1 && client.posts[0].url === "https://reports.example.net/tlsrpt");
  check("and the period closed behind it",
    (await domainRow(delivery, "example.net")) === null);
}

// ---------------------------------------------------------------------------
// Attempts to one receiver at once all survive
// ---------------------------------------------------------------------------

// Every attempt to one receiving domain is a read, a change and a write
// against the same counter, and a server relaying for accounts makes
// several of them at once. Without one queue per domain the last write
// wins and the rest are gone, which reads as a receiver whose TLS is
// almost always fine. Measured at thirty nine of forty lost.
var CONCURRENT_ATTEMPTS = 40;

async function attemptsToOneReceiverAtOnceAllSurvive(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  var jobs = [];
  for (var i = 0; i < CONCURRENT_ATTEMPTS; i += 1) {
    jobs.push(sendTo(delivery, "bob" + i + "@example.net"));
  }
  await Promise.all(jobs);

  var observed = await domainRow(delivery, "example.net");
  check("every attempt made at once is counted, not overwritten by the last one",
    observed !== null && observed.failed === CONCURRENT_ATTEMPTS);
  check("and they collapse into one failure row, because they failed the same way",
    observed !== null && observed.failures.length === 1 &&
    observed.failures[0].count === CONCURRENT_ATTEMPTS);

  var client = recordingClient(202);
  await delivery.tlsRpt.run({ httpClient: client });
  check("so the report tells the receiver how many sessions there really were",
    client.posts.length === 1 &&
    reportIn(client.posts[0]).policies[0].summary["total-failure-session-count"] ===
      CONCURRENT_ATTEMPTS);
}

// ---------------------------------------------------------------------------
// Observations survive a restart
// ---------------------------------------------------------------------------

async function whatWasObservedSurvivesARestart(dataDir) {
  var first = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  await sendTo(first, "bob@example.net");
  check("the first process observed the attempt",
    (await domainRow(first, "example.net")) !== null);

  var second = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  var carried = await domainRow(second, "example.net");
  check("a process that starts over the same data directory sees it too",
    carried !== null && carried.failed === 1);

  var client = recordingClient(202);
  await second.tlsRpt.run({ httpClient: client });
  check("and the report it sends covers the period the first process began",
    client.posts.length === 1 &&
    reportIn(client.posts[0]).policies[0].summary["total-failure-session-count"] === 1);
}

// ---------------------------------------------------------------------------
// The posture check reads the record the way a sender reads it
// ---------------------------------------------------------------------------

// `blamepost doctor` and the sender half have to agree about what a
// usable TLS-RPT record is. RFC 8460 §3 anchors the version tag at the
// start of the record and makes `rua=` required, so a record a sender
// ignores has to read as a finding rather than as a posture that is
// done. A check more forgiving than the senders it is modeling reports
// a healthy zone that nobody will ever send a report to.
var POSTURE_ZONE = {
  "anchored.example":            { mx: [HOSTNAME] },
  "_smtp._tls.anchored.example": { txt: ["prefix v=TLSRPTv1; rua=https://x.example/r"] },

  "norua.example":            { mx: [HOSTNAME] },
  "_smtp._tls.norua.example": { txt: ["v=TLSRPTv1"] },

  "absent.example": { mx: [HOSTNAME] },

  "broken.example":            { mx: [HOSTNAME] },
  "_smtp._tls.broken.example": zone.FAILING,

  "good.example":            { mx: [HOSTNAME] },
  "_smtp._tls.good.example": { txt: ["v=TLSRPTv1; rua=mailto:tls@good.example"] },
};

function tlsRptFinding(report) {
  return report.domains[0].findings.filter(function (f) { return f.record === "TLS-RPT"; })[0];
}

async function thePostureCheckAgreesWithWhatASenderWouldRead() {
  var checker = blamepost.mail.posture.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(POSTURE_ZONE),
  });

  var anchored = tlsRptFinding(await checker.check({ domains: ["anchored.example"] }));
  check("a record that does not begin with the version tag is not an endpoint",
    anchored !== undefined && anchored.ok === false);

  var noRua = tlsRptFinding(await checker.check({ domains: ["norua.example"] }));
  check("a record naming no destination is not an endpoint either",
    noRua !== undefined && noRua.ok === false);

  var absent = tlsRptFinding(await checker.check({ domains: ["absent.example"] }));
  check("a domain that published nothing is told to publish something",
    absent !== undefined && absent.ok === false &&
    /no tls-rpt record/i.test(String(absent.detail)));

  var broken = tlsRptFinding(await checker.check({ domains: ["broken.example"] }));
  check("a lookup that could not complete reads as a lookup problem, not a missing record",
    broken !== undefined && broken.ok === false &&
    /lookup/i.test(String(broken.detail)) && !/no tls-rpt record/i.test(String(broken.detail)));

  var good = tlsRptFinding(await checker.check({ domains: ["good.example"] }));
  check("and a record a sender would act on passes",
    good !== undefined && good.ok === true);
}

// The reader the sender half reaches for, asserted directly as well as
// through a run. Three answers, three remedies, and the pair that must
// never be conflated is absence against a lookup that did not finish.
async function theEndpointReaderKeepsAbsenceAndFailureApart() {
  var lookup = blamepost.mail.posture.txtLookup(zone.resolverOver(POSTURE_ZONE));

  var published = await blamepost.mail.posture.tlsRptEndpoint("good.example", { dnsLookup: lookup });
  check("a published endpoint comes back with the destination on it",
    published.state === "published" && published.rua[0] === "mailto:tls@good.example");

  var absent = await blamepost.mail.posture.tlsRptEndpoint("absent.example", { dnsLookup: lookup });
  check("a domain publishing nothing reads as absent",
    absent.state === "absent" && absent.rua.length === 0);

  var unreadable = await blamepost.mail.posture.tlsRptEndpoint("anchored.example", { dnsLookup: lookup });
  check("a record no sender would act on reads as absent, carrying what was published",
    unreadable.state === "absent" && unreadable.records.length === 1);

  var broken = await blamepost.mail.posture.tlsRptEndpoint("broken.example", { dnsLookup: lookup });
  check("and a lookup that could not complete is its own answer, with the reason on it",
    broken.state === "unsettled" && String(broken.why).length > 0);
}

// ---------------------------------------------------------------------------

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("tls-rpt: the reporting surface is on the delivery handle",
      function () { return theReportingSurfaceIsOnTheDeliveryHandle(freshDir("tlsrpt-surface")); });
    await helpers.withTestTimeout("tls-rpt: an endpoint draws a report carrying what the attempt did",
      function () { return anEndpointDrawsAReportCarryingWhatTheAttemptDid(freshDir("tlsrpt-report")); });
    await helpers.withTestTimeout("tls-rpt: no endpoint draws no report",
      function () { return noEndpointDrawsNoReport(freshDir("tlsrpt-none")); });
    await helpers.withTestTimeout("tls-rpt: an unsettled lookup keeps the evidence",
      function () { return anUnsettledLookupKeepsTheEvidence(freshDir("tlsrpt-unsettled")); });
    await helpers.withTestTimeout("tls-rpt: an attempt that negotiated nothing is never reported as TLS",
      function () { return anAttemptWithNoNegotiationIsNeverReportedAsTls(freshDir("tlsrpt-local")); });
    await helpers.withTestTimeout("tls-rpt: a refusal that is not about transport security is not reported",
      function () { return aRefusalThatIsNotAboutTransportSecurityIsNotReported(freshDir("tlsrpt-nomx")); });
    await helpers.withTestTimeout("tls-rpt: a mail destination gets the report as mail",
      function () { return aMailDestinationGetsTheReportAsMail(freshDir("tlsrpt-mailto")); });
    await helpers.withTestTimeout("tls-rpt: a published report address is derived before it is used",
      function () {
        return aPublishedReportAddressIsDerivedBeforeItIsUsed(freshDir("tlsrpt-case"));
      });
    await helpers.withTestTimeout("tls-rpt: a report address published absolutely reaches the receiver",
      function () {
        return aReportAddressPublishedAbsolutelyReachesTheReceiver(freshDir("tlsrpt-absolute"));
      });
    await helpers.withTestTimeout("tls-rpt: a report address no spelling reaches is owed and recorded",
      function () {
        return aReportAddressNoSpellingReachesIsOwedAndRecorded(freshDir("tlsrpt-unreadable"));
      });
    await helpers.withTestTimeout("tls-rpt: the trail says which spelling a report was sent to",
      function () {
        return whatTheTrailSaysAboutASpellingThisServerFolded(freshDir("tlsrpt-trail"));
      });
    await helpers.withTestTimeout("tls-rpt: an endpoint that refuses keeps the evidence",
      function () { return anEndpointThatRefusesKeepsTheEvidence(freshDir("tlsrpt-refused")); });
    await helpers.withTestTimeout("tls-rpt: the report goes without anybody asking for it",
      function () { return theReportGoesWithoutAnybodyAskingForIt(freshDir("tlsrpt-timer")); });
    await helpers.withTestTimeout("tls-rpt: attempts to one receiver at once all survive",
      function () { return attemptsToOneReceiverAtOnceAllSurvive(freshDir("tlsrpt-concurrent")); });
    await helpers.withTestTimeout("tls-rpt: what was observed survives a restart",
      function () { return whatWasObservedSurvivesARestart(freshDir("tlsrpt-restart")); });
    await helpers.withTestTimeout("tls-rpt: the posture check agrees with what a sender would read",
      function () { return thePostureCheckAgreesWithWhatASenderWouldRead(); });
    await helpers.withTestTimeout("tls-rpt: the endpoint reader keeps absence and failure apart",
      function () { return theEndpointReaderKeepsAbsenceAndFailureApart(); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "tlsrpt-reporting", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
