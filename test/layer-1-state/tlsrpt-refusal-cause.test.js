// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a TLS report says the receiver did wrong.
 *
 * An RFC 8460 aggregate report is an account of somebody else's
 * transport security sent under this server's name, and the two fields a
 * receiver acts on are the result type and the policy type. Both are
 * decided here rather than by the peer, so both can be wrong in a way
 * that reads as a fault at the other end.
 *
 * Two readings are measured.
 *
 * The first is the pair of MTA-STS refusals. The delivery composer
 * answers a policy it could not fetch and a policy whose mail exchanger
 * list covers none of the domain's own with the same enhanced status,
 * RFC 8461 section 10.3, and keeps only its own message beside it. RFC
 * 8460 section 4.3 registers `sts-policy-fetch-error` for the first and
 * `sts-policy-invalid` for the second, and telling a domain its policy
 * is invalid when what happened is that this sender could not read it
 * invites them to change a policy that is correct.
 *
 * WHY THAT HALF IS CALLED RATHER THAN DRIVEN. One of the two conditions
 * is drivable and the other is not, and the separation needs both at
 * once. `test/layer-1-state/outbound-sts-verdict.test.js` reaches the
 * fetch failure for real, by repointing the transport the framework's
 * shared resolver uses at a port nothing listens on, which is why it
 * runs in a process of its own. Nothing reaches the mail exchanger
 * mismatch: it needs the policy document itself, which RFC 8461 section
 * 3.3 puts behind an HTTPS fetch of `mta-sts.<domain>` that the
 * framework's own request guard refuses to direct at a loopback address,
 * and the composer calls `mtaSts.fetch(domain)` with no options at all,
 * so no client or lookup this repository can supply reaches it.
 *
 * So the pair is put in front of the reading at its own entry point.
 * What keeps that from being a test of its author's memory is where the
 * rows come from: every literal in them is read out of the vendored
 * composer's own source and rendered, so a rephrasing there arrives here
 * rather than leaving two files agreeing about a sentence neither writes
 * any more.
 *
 * The second is the policy type, which IS driven. A TLSA lookup that
 * cannot complete under an enforcing DANE posture takes the mail
 * exchanger out before any socket is opened, so the whole refusal
 * happens over a resolver a test supplies. RFC 8460 section 4.4
 * registers `tlsa` for a delivery judged against the records a receiver
 * publishes, and a domain running DANE that is sent `no-policy-found`
 * is being told no policy was applied to the delivery its own records
 * refused.
 *
 * No sockets. The resolver answers from a table and the report
 * submission goes to a recording client.
 *
 * Run standalone: node test/layer-1-state/tlsrpt-refusal-cause.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var zlib     = require("node:zlib");

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var delivery  = require("../../lib/mail/delivery");

var check = helpers.check;
var count = helpers.count;

var HOSTNAME = "mx.example.com";
var MESSAGE  = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

var ROOT     = nodePath.join(__dirname, "..", "..");
var COMPOSER = nodePath.join(ROOT, "lib", "vendor", "blamejs", "lib", "mail-send-deliver.js");
var POLICY   = nodePath.join(ROOT, "lib", "vendor", "blamejs", "lib", "network-smtp-policy.js");

// The receiving domain every rendered row is about, and the values the
// framework interpolates into its own messages. They are ordinary
// values rather than anything a reader has to decode: what is under
// test is which of two sentences a row carries, not what is in the gaps.
var RECEIVER   = "example.net";
var POLICY_URL = "https://mta-sts.example.net/.well-known/mta-sts.txt";
var REFUSED_BY = "503";
var ENFORCING  = "enforce";

// The enhanced status the composer answers an MTA-STS refusal with,
// read off the call that makes it rather than off a line number, and off
// the first `reasonCode` after that call rather than any in the file, so
// a body that grows around it is still read.
//
// The bound is a backstop against a pattern that grows faster than its
// input, set far above the twenty-odd lines the real handler occupies.
// It is not what makes the match precise: the lazy quantifier and the
// required literal after it are.
var REFUSAL_STATUS =
  /_applyMtaStsPolicy\([\s\S]{0,600}?reasonCode:\s*"(\d\.\d\.\d+)"/;

// The message expression one throw carries, bounded the same way and for
// the same reason. The condition name is the anchor, and it is a frozen
// contract: it survives a rename of everything around it and disappears
// when the condition itself goes.
function messageExpression(errorClass, condition) {
  return new RegExp("throw new " + errorClass + "\\(\\s*\"" +
    condition.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&") + "\"\\s*,([\\s\\S]{0,400}?)\\);");
}

function read(file) {
  return nodeFs.readFileSync(file, "utf8");
}

// Every double-quoted piece of one message expression, in source order.
// The gaps between them are where the framework interpolates a value.
function literalsOf(text, pattern) {
  var found = pattern.exec(text);
  if (found === null) return null;
  var literals = [];
  var each = /"([^"]*)"/g;
  var one;
  while ((one = each.exec(found[1])) !== null) literals.push(one[1]);
  return literals.length === 0 ? null : literals;
}

// The sentence the framework would build, from its own pieces and the
// values above.
function render(literals, values) {
  var out = "";
  for (var i = 0; i < literals.length; i += 1) {
    out += literals[i];
    if (i < values.length) out += values[i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// The two MTA-STS refusals, rendered from the composer's own source
// ---------------------------------------------------------------------------

function theTwoMtaStsRefusalsAreToldApart() {
  var composerText = read(COMPOSER);
  var policyText   = read(POLICY);

  var statusFound = REFUSAL_STATUS.exec(composerText);
  count("the composer still answers an MTA-STS refusal with an enhanced status of its own",
    statusFound !== null,
    statusFound === null ? "no reasonCode found after the call" : statusFound[1]);

  var fetchLiterals = literalsOf(composerText,
    messageExpression("DeliverError", "deliver/mta-sts-fetch-failed"));
  var mismatchLiterals = literalsOf(composerText,
    messageExpression("DeliverError", "deliver/mta-sts-mx-mismatch"));
  var innerLiterals = literalsOf(policyText,
    messageExpression("SmtpPolicyError", "smtp/mta-sts-fetch-failed"));

  // Read before either is compared. An extraction that found nothing
  // renders an empty sentence, an empty sentence matches no anchor, and
  // the case below would then report the classification as correct on
  // the strength of having measured nothing at all.
  count("the composer still refuses a policy it could not fetch",
    fetchLiterals !== null, JSON.stringify(fetchLiterals));
  count("and still refuses a policy no mail exchanger matches",
    mismatchLiterals !== null, JSON.stringify(mismatchLiterals));
  count("and the policy reader still says what a non-2xx answer was",
    innerLiterals !== null, JSON.stringify(innerLiterals));
  if (statusFound === null || fetchLiterals === null ||
      mismatchLiterals === null || innerLiterals === null) return;

  var status = statusFound[1];
  var inner  = render(innerLiterals, [REFUSED_BY, POLICY_URL]);
  var fetchRow = {
    reasonCode: status,
    reason:     render(fetchLiterals, [RECEIVER, inner]),
  };
  var mismatchRow = {
    reasonCode: status,
    reason:     render(mismatchLiterals, [RECEIVER, ENFORCING]),
  };

  count("the two refusals arrive under one status, so the status alone cannot separate them",
    fetchRow.reasonCode === mismatchRow.reasonCode && fetchRow.reason !== mismatchRow.reason,
    JSON.stringify([fetchRow.reason, mismatchRow.reason]));

  var forFetch    = delivery.tlsRptResultFor(fetchRow);
  var forMismatch = delivery.tlsRptResultFor(mismatchRow);

  count("a policy this server could not fetch is reported as a fetch error, because the " +
    "receiver's document was never read and nothing about it is known to be wrong",
    forFetch === "sts-policy-fetch-error", String(forFetch) + " for " + fetchRow.reason);
  count("and a policy covering none of the domain's mail exchangers is still reported as " +
    "invalid, which is the reading the fetch case was taking",
    forMismatch === "sts-policy-invalid", String(forMismatch) + " for " + mismatchRow.reason);

  // The anchor separates two sentences, and a receiver's own domain is
  // inside both of them. A domain named after the token would move the
  // mismatch across if the reading looked anywhere but where the
  // composer writes its own words.
  var hostileRow = {
    reasonCode: status,
    reason:     render(mismatchLiterals, ["mta-sts.fetch.for.example", ENFORCING]),
  };
  count("a receiver whose own name reads like the other refusal is still reported as " +
    "invalid, so the separation is the composer's sentence rather than any token in it",
    delivery.tlsRptResultFor(hostileRow) === "sts-policy-invalid",
    String(delivery.tlsRptResultFor(hostileRow)) + " for " + hostileRow.reason);

  // Everything else the reading can answer stays where it was. The
  // status narrows to a pair, and a row that carries neither sentence
  // must not be pulled into either.
  count("a refusal under a different status is untouched by the separation",
    delivery.tlsRptResultFor({ reasonCode: "5.1.1", reason: fetchRow.reason }) === null,
    String(delivery.tlsRptResultFor({ reasonCode: "5.1.1", reason: fetchRow.reason })));
}

// ---------------------------------------------------------------------------
// A DANE refusal, driven, and the policy it is filed under
// ---------------------------------------------------------------------------

// The receiver publishes a mail exchanger and a report endpoint, and the
// TLSA question about that exchanger cannot be looked up at all. Under
// an enforcing posture RFC 7672 section 2.2 takes the host out, which
// happens before any socket, so the whole refusal is over the resolver
// this table builds.
var DANE_UNANSWERABLE = {
  "example.net":                 { mx: ["mx.example.net"] },
  "_25._tcp.mx.example.net":     zone.FAILING,
  "_smtp._tls.example.net":      { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

function recordingClient() {
  var posts = [];
  return {
    posts: posts,
    request: async function (opts) {
      posts.push(opts);
      return { statusCode: 202, headers: {}, body: "" };
    },
  };
}

function reportIn(post) {
  return JSON.parse(zlib.gunzipSync(post.body).toString("utf8"));
}

function policyTypesIn(report) {
  return (report.policies || []).map(function (entry) {
    return entry.policy["policy-type"];
  });
}

async function aDaneRefusalIsFiledUnderTheRecordsThatRefusedIt(dataDir) {
  var resolver = zone.resolverOver(DANE_UNANSWERABLE);
  var handle = delivery.create({
    hostname:   HOSTNAME,
    dataDir:    dataDir,
    postmaster: "postmaster@example.com",
    resolver:   resolver,
    // MTA-STS off, so nothing about a policy document decides this and
    // the only judgement made is the one against the receiver's TLSA
    // records. The assertion beside the enforcing posture is the
    // operator's statement that their resolver validates, which RFC 7672
    // section 1.3 requires before a record may be used at all.
    policy:     { mtaSts: "off", dane: "enforce", dnssecValidated: true },
    audit:      false,
  });

  await handle.send({
    from:   "alice@example.com",
    to:     ["bob@" + RECEIVER],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });

  var rows = (await handle.tlsRpt.observed()).filter(function (r) {
    return r.domain === RECEIVER;
  });
  var observed = rows.length === 1 ? rows[0] : null;

  count("the TLSA question went to the resolver the operator pinned",
    resolver.calls.indexOf("TLSA _25._tcp.mx.example.net") !== -1,
    JSON.stringify(resolver.calls));
  count("the attempt left one observation against the receiver's domain",
    observed !== null && observed.failed === 1,
    JSON.stringify(rows));
  if (observed === null) return;
  count("recorded as DANE having been required and not obtained",
    observed.failures.length === 1 && observed.failures[0].resultType === "dane-required",
    JSON.stringify(observed.failures));
  count("this server read no policy document for the domain, so what it holds for the " +
    "domain itself is still that it found none",
    observed.policyType === "no-policy-found", String(observed.policyType));
  count("and the failure is filed under the records that refused it rather than under " +
    "the domain's own reading",
    observed.failures.length === 1 && observed.failures[0].policyType === "tlsa",
    JSON.stringify(observed.failures));

  var client = recordingClient();
  var run = await handle.tlsRpt.run({ httpClient: client });
  handle.stop();

  count("a report went to the endpoint the receiver published",
    run.ran === 1 && run.results[0].outcome === "submitted" && client.posts.length === 1,
    JSON.stringify(run.results));
  if (client.posts.length !== 1) return;

  var report = reportIn(client.posts[0]);
  count("and the receiver reads it against their TLSA records, which RFC 8460 section " +
    "4.4 spells `tlsa`",
    JSON.stringify(policyTypesIn(report)) === JSON.stringify(["tlsa"]),
    JSON.stringify(policyTypesIn(report)));
  count("the failure is inside that entry rather than beside it",
    report.policies.length === 1 &&
    report.policies[0].summary["total-failure-session-count"] === 1 &&
    report.policies[0]["failure-details"].length === 1 &&
    report.policies[0]["failure-details"][0]["result-type"] === "dane-required",
    JSON.stringify(report.policies));
  count("and no MTA-STS document is quoted back, because none was read",
    report.policies[0].policy["policy-string"].length === 0,
    JSON.stringify(report.policies[0].policy["policy-string"]));
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
    check("the classification is reachable as blamepost.mail.delivery.tlsRptResultFor",
      typeof delivery.tlsRptResultFor === "function");
    theTwoMtaStsRefusalsAreToldApart();
    await helpers.withTestTimeout("tls-rpt: a DANE refusal is filed under the TLSA records",
      function () {
        return aDaneRefusalIsFiledUnderTheRecordsThatRefusedIt(freshDir("tlsrpt-dane"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "tlsrpt-refusal-cause", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
