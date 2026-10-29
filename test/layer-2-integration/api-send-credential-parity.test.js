// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The sending route on the browser port, measured against the submission
 * listener it has to agree with.
 *
 * A domain-scoped sending credential can reach this server two ways: an
 * application that speaks SMTP submission, and an application that posts
 * JSON. Both are the same identity writing the same mail, so every
 * question about what that identity may write has to get the same answer
 * from both. Two surfaces that answer separately drift, and the first
 * configuration where they disagree is the one where a credential writes
 * an address over one transport that the other refuses.
 *
 * ## What this file drives
 *
 * The identity cases are PAIRED. Each one is driven over SMTP submission
 * and over `POST /api/send` in the same run, against the same credential
 * and the same server, and the assertion is that the two verdicts match.
 * Two separate files that happen to agree today is the arrangement that
 * drifts, because nothing in either of them fails when the other moves.
 *
 *   - An ordinary address at the credential's own domain is accepted.
 *   - An address at a SECOND hosted domain is refused.
 *   - An address at a domain this server does not host is refused on the
 *     envelope.
 *   - An outside author under a Sender the credential holds is accepted,
 *     which is the on-behalf-of shape a sending application emits.
 *   - A message naming no address the credential holds is refused.
 *
 * Two more questions are paired the same way, and each is asked by
 * spending something on one transport and reading it back on the other:
 *
 *   - The failure budget. Wrong secrets offered to one transport lock
 *     the credential on the other, because there is one budget rather
 *     than one per surface. A surface that verifies a secret and counts
 *     nothing is a bound an attacker walks around by choosing it.
 *   - The send ceiling, and the STEP at which it is spent. Both
 *     transports run the author binding first, so a message the
 *     credential may not write costs it no slot on either.
 *
 * Beside them, the claims that belong to the HTTP transport alone:
 *
 *   - A request carrying any Cookie header is refused. The route reads
 *     the credential off the `Authorization` header and never off
 *     `req.user`, and a credential path reachable with an ambient
 *     credential is one a page on another site can spend.
 *   - A request over a connection that cannot carry a credential is
 *     refused, through the same reading the sign-in form uses.
 *   - A replayed `Idempotency-Key` answers the first response rather
 *     than sending the message twice.
 *   - The ceiling the submission handoff spends is spent here too, so a
 *     credential cannot walk around its own rate ceiling by changing
 *     transport.
 *
 * Two hosted domains throughout, for the reason
 * sending-credential-scope.test.js hosts two: a scope bug cannot manifest
 * on a server hosting one domain, because there is no second domain to
 * leak into.
 *
 * Run standalone: node test/layer-2-integration/api-send-credential-parity.test.js
 */

var nodeFs    = require("node:fs");
var nodeHttps = require("node:https");
var nodeOs    = require("node:os");
var nodePath  = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var saslPlain   = wire.saslPlain;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var EVERY_INTERFACE = "0.0.0.0";

var HOSTNAME      = "mx.example.com";
var DOMAIN        = "example.com";
var SECOND_DOMAIN = "example.org";
var OUTSIDE_DOMAIN = "notmine.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX        = "postbox@" + DOMAIN;
var SECOND_BOUNCE_MAILBOX = "postbox@" + SECOND_DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// How many wrong secrets a credential absorbs before the failure budget
// locks it. It is `b.auth.lockout`'s own default, which the listener
// composes without naming a number of its own.
//
// Written here rather than read from the server, because a test that
// derived the figure from the same place the server does would agree
// with a budget that had stopped counting. If the default moves, this
// number is what says so.
var CREDENTIAL_BUDGET_ATTEMPTS = 5;

// The private ranges of RFC 1918, preferred over any other address this
// host holds so the listener is dialed on an ordinary local network
// rather than on whatever overlay happens to be enumerated first.
function _privateFirst(rows) {
  var priv = rows.filter(function (a) {
    return /^10\./.test(a) || /^192\.168\./.test(a) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(a);
  });
  return priv.length > 0 ? priv[0] : (rows.length > 0 ? rows[0] : null);
}

// One address of this host that is not loopback, so a request dialed at
// it reaches the listener carrying a peer the server can tell apart from
// its own machine.
function networkAddress() {
  var table = nodeOs.networkInterfaces();
  var found = [];
  Object.keys(table).forEach(function (name) {
    (table[name] || []).forEach(function (row) {
      if (row.family === "IPv4" && row.internal !== true) found.push(row.address);
    });
  });
  return _privateFirst(found);
}

// The reply that says a step was taken. RFC 5321 puts a rejected envelope
// sender at 553 and a message refused after acceptance at 550, so the
// paired cases below record WHICH step refused rather than only that one
// did: a route that refused the envelope where the wire refuses the
// header would agree on the verdict and disagree on the rule.
var SMTP_ACCEPTED = /^250 /m;

// The route's own answers. A send that reached the relay is 202; every
// refusal is an RFC 9457 problem document, so the content type is part of
// the assertion rather than only the code.
var PROBLEM_TYPE = "application/problem+json";

// Every message this file sends carries a marker, so a wire code is
// settled against the recipient's mailbox rather than believed.
var HTTP_OWN_MARKER       = "api-send-own-domain-4f19c7a2";
var HTTP_DELEGATED_MARKER = "api-send-delegated-8ac03e15";
var HTTP_CROSS_MARKER     = "api-send-cross-domain-2d6b90fe";
var HTTP_UNHOSTED_MARKER  = "api-send-unhosted-71e4c8db";
var HTTP_AMBIENT_MARKER   = "api-send-ambient-6c02b98a";
var HTTP_CLEARTEXT_MARKER  = "api-send-cleartext-e37a105b";
var HTTP_CONCURRENT_MARKER = "api-send-concurrent-0b4de921";
var HTTP_BUDGET_MARKER     = "api-send-budget-locked-9d5c71a4";
var SMTP_OWN_MARKER       = "smtp-send-own-domain-90b2fa47";
var SMTP_DELEGATED_MARKER = "smtp-send-delegated-3e57d10c";
var SMTP_CROSS_MARKER     = "smtp-send-cross-domain-c81a4f63";
var SMTP_UNHOSTED_MARKER  = "smtp-send-unhosted-5b90d27e";

// ---- transports ------------------------------------------------------------

// One message over SMTP submission, reported as a verdict rather than as
// a reply string, so the paired assertion below compares two verdicts
// instead of two protocols.
//
// `envelopeFrom` is refused at MAIL FROM and the header is refused after
// the message is accepted for transfer, so the two arrive at different
// moments and the verdict names which of them refused.
async function overSubmission(ports, caPem, token, opts) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "api-parity-" + opts.label,
    address: DOMAIN, password: token,
  });
  try {
    session.send("MAIL FROM:<" + opts.envelopeFrom + ">");
    var envelope = await session.read(/^\d{3} /m, "MAIL FROM answered");
    if (!SMTP_ACCEPTED.test(envelope)) {
      return { accepted: false, at: "envelope", reply: visible(envelope) };
    }

    session.send("RCPT TO:<" + opts.to + ">");
    await session.read(/^\d{3} /m, "RCPT TO answered");
    session.send("DATA");
    await session.read(/^354 /m, "DATA answered");

    var lines = ["From: " + opts.from];
    if (opts.sender) lines.push("Sender: " + opts.sender);
    lines = lines.concat([
      "To: " + opts.to,
      "Subject: " + opts.marker,
      "Date: Mon, 31 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + opts.marker + "@" + DOMAIN + ">",
      "",
      "A message written by an application rather than by a person.",
      "",
      ".",
      "",
    ]);
    session.sendRaw(lines.join("\r\n"), "<" + opts.marker + ">");
    var answered = await session.read(/^\d{3} /m, "message answered");
    return SMTP_ACCEPTED.test(answered)
      ? { accepted: true, at: "accepted", reply: visible(answered) }
      : { accepted: false, at: "header", reply: visible(answered) };
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// The same message over the sending route, reported in the same shape.
//
// The reader holds no cookie and never signs in, which is what the route
// requires: the credential rides on `Authorization` and an ambient
// credential is refused outright.
async function overSendRoute(reader, token, opts) {
  var body = { from: opts.from, to: [opts.to], subject: opts.marker,
    text: "A message written by an application rather than by a person.",
    envelopeFrom: opts.envelopeFrom };
  if (opts.sender) body.sender = opts.sender;

  var answer = await reader.post("/api/send", "application/json", JSON.stringify(body), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": opts.marker,
    "Accept":          "application/json",
  });
  return {
    accepted:    answer.status === 202,
    at:          answer.status === 202 ? "accepted" : String(answer.status),
    reply:       String(answer.body).slice(0, 400),
    status:      answer.status,
    contentType: String(answer.headers["content-type"] || ""),
    body:        answer.body,
  };
}

// One AUTH exchange on the submission listener and nothing else, reported
// as the reply line it drew.
//
// The ladder's own authentication raises on a refusal, which is right for
// a case that needs a session and wrong for one whose subject IS the
// refusal, so the session stops at the TLS upgrade and the exchange is
// driven here.
async function authenticateOverSubmission(ports, caPem, name, secret, label) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "api-parity-" + label,
  });
  try {
    session.send("AUTH PLAIN " + saslPlain(name, secret));
    return await session.read(/^\d{3} /m, "AUTH answered");
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// A token carrying a real credential's identifier and a secret that is
// not that credential's.
//
// This is the guess an attacker actually makes. RFC-shaped or not, the
// identifier half of a token is not a secret: it names the row, it is
// printed in the operator console, and it travels in every request the
// credential's own application sends. What is secret is the half after
// it, so a guess reuses the identifier and varies the tail, and the
// failure has a credential to be counted against.
//
// One hex digit is changed rather than the whole tail replaced, so the
// token keeps the length and the alphabet the format reader accepts and
// the refusal comes from the verifier rather than from the parse.
function wrongSecretFor(token) {
  var parts = String(token).split("_");
  var secret = parts[3] || "";
  var head = secret.charAt(0) === "0" ? "1" : "0";
  parts[3] = head + secret.slice(1);
  return parts.join("_");
}

// ---- the paired identity cases ---------------------------------------------

// One identity question, asked of both transports, asserted as one
// verdict. A case that passed on each transport separately would be two
// assertions about two servers; this is one assertion about one rule.
async function pairedCase(ports, caPem, reader, token, spec) {
  var overWire = await overSubmission(ports, caPem, token, spec.smtp);
  var overHttp = await overSendRoute(reader, token, spec.http);

  count(spec.claim + " over SMTP submission",
    overWire.accepted === spec.accepted, overWire.at + ": " + overWire.reply);
  count(spec.claim + " over the sending route",
    overHttp.accepted === spec.accepted, overHttp.at + ": " + overHttp.reply);
  count("and the two transports reach the SAME verdict about it, which is the only " +
    "assertion a second surface cannot silently drift away from (" + spec.name + ")",
    overWire.accepted === overHttp.accepted,
    "submission " + overWire.at + " / route " + overHttp.at);

  if (!spec.accepted) {
    count("the route's refusal is an RFC 9457 problem document rather than a bare " +
      "status, so a client reads which rule refused it (" + spec.name + ")",
      overHttp.contentType.indexOf(PROBLEM_TYPE) === 0, overHttp.contentType);
    count("and it echoes no part of the credential that was presented (" + spec.name + ")",
      String(overHttp.body).indexOf(token) === -1, "the reply carries no token");
  }
  return { overWire: overWire, overHttp: overHttp };
}

function identityCases(bob) {
  return [
    {
      name:     "own domain",
      claim:    "an ordinary address at the credential's own domain is accepted",
      accepted: true,
      smtp: { label: "own", marker: SMTP_OWN_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "shop@" + DOMAIN },
      http: { marker: HTTP_OWN_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "shop@" + DOMAIN },
    },
    {
      name:     "second hosted domain",
      claim:    "an author at a SECOND hosted domain is refused, because this server holds " +
                "a selector for it and would sign a name the credential does not speak for",
      accepted: false,
      smtp: { label: "cross", marker: SMTP_CROSS_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "shop@" + SECOND_DOMAIN },
      http: { marker: HTTP_CROSS_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "shop@" + SECOND_DOMAIN },
    },
    {
      name:     "unhosted domain on the envelope",
      claim:    "an envelope sender at a domain this server does not host is refused, so a " +
                "credential is a scope rather than a license to relay",
      accepted: false,
      smtp: { label: "unhosted-envelope", marker: SMTP_UNHOSTED_MARKER, to: bob,
        envelopeFrom: "shop@" + OUTSIDE_DOMAIN, from: "shop@" + DOMAIN },
      http: { marker: HTTP_UNHOSTED_MARKER, to: bob,
        envelopeFrom: "shop@" + OUTSIDE_DOMAIN, from: "shop@" + DOMAIN },
    },
    {
      name:     "outside author under an owned Sender",
      claim:    "an outside author under a Sender the credential holds is accepted, which " +
                "is the on-behalf-of shape RFC 5322 section 3.6.2 describes",
      accepted: true,
      smtp: { label: "delegated", marker: SMTP_DELEGATED_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "partner@othercorp.example",
        sender: "shop@" + DOMAIN },
      http: { marker: HTTP_DELEGATED_MARKER, to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "partner@othercorp.example",
        sender: "shop@" + DOMAIN },
    },
    {
      name:     "no owned address anywhere",
      claim:    "a message naming no address the credential holds is refused, because " +
                "nothing in it is attributable to the identity that signed in",
      accepted: false,
      smtp: { label: "unowned", marker: SMTP_UNHOSTED_MARKER + "-b", to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "partner@" + OUTSIDE_DOMAIN },
      http: { marker: HTTP_UNHOSTED_MARKER + "-b", to: bob,
        envelopeFrom: "shop@" + DOMAIN, from: "partner@" + OUTSIDE_DOMAIN },
    },
  ];
}

// ---- the claims that belong to the HTTP transport alone ---------------------

// The route has to be there before anything below says something about
// what it refuses. A 404 answers every refusal assertion in this file
// affirmatively while proving nothing at all.
async function theRouteIsMounted(reader, token, bob) {
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "mounted", text: "one line",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-mounted-probe",
    "Accept":          "application/json",
  });
  count("the sending route answers on the browser port rather than 404, which every " +
    "refusal claim below would otherwise pass against",
    answer.status !== 404, answer.status + ": " + String(answer.body).slice(0, 200));
  count("and it accepted the message", answer.status === 202,
    answer.status + ": " + String(answer.body).slice(0, 200));

  // The route refuses a cookie-bearing request, so a route that HANDED
  // one back would break every application whose HTTP client keeps
  // cookies on its second call, and break it with a refusal that names
  // nothing the application did. The CSRF middleware on the chain above
  // issues its double-submit cookie on every request that arrives without
  // one, which is exactly that shape.
  count("the route sets no cookie, so an application whose client keeps cookies is not " +
    "handed the one thing this route refuses",
    (answer.setCookie || []).length === 0, JSON.stringify(answer.setCookie || []));
  count("and the reader is still holding none, so every request below is the cookieless " +
    "one an application actually sends",
    reader.cookies.names().length === 0, JSON.stringify(reader.cookies.names()));
  return answer;
}

// A request shaped the way a program sends one rather than the way a
// browser does: no Origin header and no Referer. The origin cross-check
// on the chain above is defense against a browser-rendered cross-origin
// fetch spending a cookie, and a request carrying no cookie has none to
// spend, so a headless client has to reach the route.
async function aProgramWithoutAnOriginHeaderReachesTheRoute(origin, caPem, token, bob) {
  var parsed = new URL(origin);
  var body = JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-no-origin",
    text: "a request shaped the way a program sends one",
  });
  var answer = await new Promise(function (resolve, reject) {
    var req = nodeHttps.request({
      host:       parsed.hostname,
      port:       parsed.port,
      path:       "/api/send",
      method:     "POST",
      ca:         [caPem],
      servername: HOSTNAME,
      timeout:    10000,
      headers: {
        "Content-Type":    "application/json",
        "Content-Length":  String(Buffer.byteLength(body, "utf8")),
        "Authorization":   "Bearer " + token,
        "Idempotency-Key": "api-send-no-origin",
        "Accept":          "application/json",
      },
    }, function (res) {
      var text = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { text += chunk; });
      res.on("end", function () { resolve({ status: res.statusCode, body: text }); });
    });
    req.once("timeout", function () { req.destroy(new Error("no answer within 10000ms")); });
    req.once("error", reject);
    req.write(body);
    req.end();
  });
  count("a request carrying no Origin and no Referer, which is every program that is not " +
    "a browser, reaches the route rather than being refused by the origin cross-check",
    answer.status === 202, answer.status + ": " + String(answer.body).slice(0, 200));
}

// The Authorization collision. `attachUser` is mounted `tokenFrom: both`
// and the framework reads `Authorization: Bearer` as a SESSION token
// source, so a request carrying a live session cookie and a credential
// would be authenticated by the cookie. The route refuses a Cookie header
// outright rather than deciding which of the two it meant.
async function anAmbientCredentialIsRefused(origin, caPem, token, bob) {
  // A real browser session, minted by signing in, plus the credential in
  // the Authorization header. This is the collision itself: `attachUser`
  // is mounted `tokenFrom: "both"` and resolves the cookie FIRST, so the
  // request is authenticated by the session while the header nobody read
  // carries the credential the caller meant. A route reading `req.user`
  // here would send this message as the signed-in account.
  //
  // The reader signs in so the request also carries a matching CSRF pair.
  // Without one the token gate refuses it before the route runs, which
  // proves the request was stopped and says nothing about whether this
  // route would have stopped it.
  var cookied = browser.browserAt(origin, { ca: caPem, servername: HOSTNAME });
  var signedIn = await cookied.signIn(bob, BOB_PASSWORD);
  count("the reader holding the ambient credential really is signed in, so the case below " +
    "is about a live session rather than about a cookie nothing resolves",
    signedIn.status === 302 || signedIn.status === 303,
    signedIn.status + ": " + String(signedIn.location));

  var answer = await cookied.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: HTTP_AMBIENT_MARKER,
    text: "a message posted with a session cookie and a credential at once",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-ambient-probe",
    "Accept":          "application/json",
  });
  count("a request carrying a Cookie header is refused, so the sending route is never " +
    "reachable with the ambient credential a page on another site can spend",
    answer.status === 400, answer.status + ": " + String(answer.body).slice(0, 200));
  count("and the refusal is this route's own problem document rather than a redirect to " +
    "the sign-in page, because the caller is an application with no browser to send anywhere",
    String(answer.headers["content-type"] || "").indexOf(PROBLEM_TYPE) === 0,
    String(answer.headers["content-type"] || ""));
  count("and it echoes no part of the credential that was presented",
    String(answer.body).indexOf(token) === -1, "the reply carries no token");
}

// A credential over a connection that cannot carry one, through the same
// reading the sign-in form takes. The secret has already crossed the wire
// by the time the route runs, and what is left to protect is everything
// after it: no verify, no ceiling spent, no message sent.
// The cleartext port has to be reached across a network for this to be
// the vector it claims to be. A request that arrived over loopback
// crossed no network, and this server reads loopback as a transport that
// can carry a credential for the same reason the Secure Contexts standard
// treats `127.0.0.1` as potentially trustworthy: a browser stores and
// returns a Secure cookie there. So the reader dials one of this host's
// own network addresses, and a host holding none cannot drive the case at
// all, which is named and counted as a skip rather than folded into the
// pass count.
async function theCleartextPortRefusesACredential(port, token, bob) {
  var lan = networkAddress();
  if (lan === null) {
    helpers.skip("this host holds no address outside loopback, so the sending route's " +
      "refusal of a credential presented over cleartext could not be driven");
    return;
  }
  var reader = browser.browserAt("http://" + lan + ":" + port);
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: HTTP_CLEARTEXT_MARKER,
    text: "a credential presented where it can be read off the wire",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-cleartext-probe",
    "Accept":          "application/json",
  });
  count("a credential presented over a connection that cannot carry one is refused with " +
    "403, which is the reading the sign-in form already takes of the same transport",
    answer.status === 403, answer.status + ": " + String(answer.body).slice(0, 200));
  count("and the refusal is a problem document naming the transport",
    String(answer.headers["content-type"] || "").indexOf(PROBLEM_TYPE) === 0,
    String(answer.headers["content-type"] || ""));
  count("and it echoes no part of the credential it turned away",
    String(answer.body).indexOf(token) === -1, "the reply carries no token");
}

// No credential at all, and a credential this server did not issue. Both
// draw one refusal: the registry files its own row naming which of
// not-found, revoked, expired or a wrong secret it was, and a caller gets
// one answer to act on.
async function anAbsentOrWrongCredentialIsRefused(reader, bob) {
  var payload = JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "no credential", text: "one line",
  });

  var bare = await reader.post("/api/send", "application/json", payload, {
    "Idempotency-Key": "api-send-bare-probe",
    "Accept":          "application/json",
  });
  count("a request carrying no credential is refused with 401",
    bare.status === 401, bare.status + ": " + String(bare.body).slice(0, 200));
  count("and it names Bearer in WWW-Authenticate, which RFC 9110 section 11.6.1 requires " +
    "of every 401 so a client knows what to present",
    /Bearer/i.test(String(bare.headers["www-authenticate"] || "")),
    String(bare.headers["www-authenticate"] || "(absent)"));

  var wrong = await reader.post("/api/send", "application/json", payload, {
    "Authorization":   "Bearer bp_send_not_a_credential_this_server_ever_issued",
    "Idempotency-Key": "api-send-wrong-probe",
    "Accept":          "application/json",
  });
  count("a credential this server never issued is refused with 401 as well, so nothing " +
    "on the wire tells an unknown secret from an absent one",
    wrong.status === 401, wrong.status + ": " + String(wrong.body).slice(0, 200));
}

// The body is untrusted remote input. A shape this route does not
// recognize is refused at the point of parse rather than carried into the
// composer, and an address this server cannot read is refused before
// anything is signed.
async function amalformedBodyIsRefused(reader, token, bob) {
  // Bytes that are not JSON at all never reach the route: the framework's
  // body parser refuses them at the point of parse and answers in its own
  // shape. That refusal is asserted because it is the one that has to
  // happen, and its content type is the parser's to choose rather than
  // this route's.
  var notJson = await reader.post("/api/send", "application/json", "{not json", {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-malformed-parse",
    "Accept":          "application/json",
  });
  count("a body that is not JSON at all is refused at the point of parse, before the " +
    "route reads a field off it",
    notJson.status === 400, notJson.status + ": " + String(notJson.body).slice(0, 200));

  var cases = [
    { name: "a body naming a field this route does not accept",
      payload: JSON.stringify({ from: "shop@" + DOMAIN, to: [bob], text: "x",
        relayEverything: true }) },
    { name: "a body naming no recipient",
      payload: JSON.stringify({ from: "shop@" + DOMAIN, subject: "x", text: "x" }) },
    { name: "a body naming no author",
      payload: JSON.stringify({ to: [bob], subject: "x", text: "x" }) },
    { name: "a recipient this server cannot read as an address",
      payload: JSON.stringify({ from: "shop@" + DOMAIN, to: ["not an address"],
        subject: "x", text: "x" }) },
    { name: "an author this server cannot read as an address",
      payload: JSON.stringify({ from: "shop at example dot com", to: [bob],
        subject: "x", text: "x" }) },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var answer = await reader.post("/api/send", "application/json", cases[i].payload, {
      "Authorization":   "Bearer " + token,
      "Idempotency-Key": "api-send-malformed-" + i,
      "Accept":          "application/json",
    });
    count("the route refuses " + cases[i].name + " with 400 rather than carrying it into " +
      "the composer",
      answer.status === 400, answer.status + ": " + String(answer.body).slice(0, 200));
    count("and answers it as a problem document (" + cases[i].name + ")",
      String(answer.headers["content-type"] || "").indexOf(PROBLEM_TYPE) === 0,
      String(answer.headers["content-type"] || ""));
  }
}

// The idempotency key. A memory record loses this on restart and the
// failure mode is a duplicate mail to a real person, so the record is
// this server's own and it is keyed per credential.
async function areplayedKeyAnswersTheFirstResponse(reader, token, bob) {
  var key = "api-send-replay-" + Date.now();
  var payload = JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-replay-marker",
    text: "one line, sent once",
  });
  var headers = {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": key,
    "Accept":          "application/json",
  };

  var first  = await reader.post("/api/send", "application/json", payload, headers);
  count("the first request under a fresh key is accepted",
    first.status === 202, first.status + ": " + String(first.body).slice(0, 200));

  var second = await reader.post("/api/send", "application/json", payload, headers);
  count("a replay under the same key answers the first response rather than sending the " +
    "message a second time, which is the failure a retrying client produces",
    second.status === first.status && second.body === first.body,
    second.status + ": " + String(second.body).slice(0, 200));
  count("and it says so, because a replayed answer and a second send are otherwise the " +
    "same line in a client's log",
    String(second.headers["idempotency-replayed"] || "") === "true",
    String(second.headers["idempotency-replayed"] || "(absent)"));
  count("while the first answer carries no such header, so the flag distinguishes the two " +
    "rather than being present on both",
    first.headers["idempotency-replayed"] === undefined,
    String(first.headers["idempotency-replayed"]));

  var changed = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-replay-marker",
    text: "a different line under the same key",
  }), headers);
  count("the same key over a DIFFERENT message is refused rather than answered with the " +
    "first reply, because answering would report a send that never happened",
    changed.status === 422, changed.status + ": " + String(changed.body).slice(0, 200));

  var missing = await reader.post("/api/send", "application/json", payload, {
    "Authorization": "Bearer " + token,
    "Accept":        "application/json",
  });
  count("a request naming no key at all is refused, so every send through this route " +
    "carries a replay record",
    missing.status === 400, missing.status + ": " + String(missing.body).slice(0, 200));

  var hostile = await reader.post("/api/send", "application/json", payload, {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "../../etc/passwd",
    "Accept":          "application/json",
  });
  count("a key carrying a path traversal shape is refused by the guard rather than used " +
    "as a record name",
    hostile.status === 400, hostile.status + ": " + String(hostile.body).slice(0, 200));

  return first;
}

// Two identical requests in flight at once under one key, which is what a
// client with a retry timer shorter than this server's send actually
// produces. The reservation is taken and read with nothing awaited in
// between, so the second request finds the first's record rather than
// starting a second send.
//
// Which answer the second one draws depends on where the first had got
// to, and both are correct: the replay when the first had finished, and
// 409 when it had not. What is NOT allowed to depend on timing is the
// number of messages, so that is what the mailbox is asked about at the
// end of the run.
async function aConcurrentDuplicateSendsOnce(reader, token, bob) {
  var payload = JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: HTTP_CONCURRENT_MARKER,
    text: "one line, sent once even though it was asked for twice at once",
  });
  var headers = {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-concurrent-" + Date.now(),
    "Accept":          "application/json",
  };
  var both = await Promise.all([
    reader.post("/api/send", "application/json", payload, headers),
    reader.post("/api/send", "application/json", payload, headers),
  ]);
  var accepted = both.filter(function (a) { return a.status === 202; });
  var collided = both.filter(function (a) { return a.status === 409; });
  count("two identical requests in flight at once under one key answer 202 twice, which " +
    "is the replay, or 202 and 409, which is the collision; never two separate sends",
    (accepted.length === 2 && collided.length === 0) ||
    (accepted.length === 1 && collided.length === 1),
    both.map(function (a) { return a.status; }).join(" and "));
  if (accepted.length === 2) {
    count("and when both answered 202 they answered with the SAME message, because the " +
      "second was the first's record replayed rather than a second send",
      accepted[0].body === accepted[1].body,
      accepted[0].body + " / " + accepted[1].body);
  }
}

// The ceiling, as a total. One window, shared: messages sent over the
// route fill the same window the wire reads, so a rate limit is not
// something an application walks around by changing transport. Where in
// the sequence each transport spends it is a separate question, measured
// further down.
async function theCeilingBindsOnBothTransports(ports, caPem, reader, identity, bob) {
  // Two, which is room for two messages. The registry counts the message
  // in front of it and refuses it when the count goes past the ceiling,
  // so a credential set to two sends two and is refused on the third.
  // Both transports read that one arithmetic, which is the point: a route
  // that re-derived the comparison would differ by exactly one message
  // and nothing would say so.
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential with room for two messages, for the ceiling parity case",
    maxMessages:   2,
    maxRecipients: 100,
  });

  var reading = await identity.credentials.counters.read(made.id);
  count("the ceiling credential starts its window empty, so what is counted below is this " +
    "file's own traffic rather than an earlier case's",
    reading.messages === 0, JSON.stringify(reading));

  var first = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-ceiling-one", text: "one",
  }), {
    "Authorization":   "Bearer " + made.token,
    "Idempotency-Key": "api-send-ceiling-1",
    "Accept":          "application/json",
  });
  count("the first message through the route is accepted while the window has room",
    first.status === 202, first.status + ": " + String(first.body).slice(0, 200));

  var counted = await identity.credentials.counters.read(made.id);
  count("and the route SPENT the ceiling, counted through the gate the submission handoff " +
    "counts through rather than through a second call of its own, so one message costs one " +
    "slot whichever transport carried it",
    counted.messages === 1, JSON.stringify(counted));

  var second = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-ceiling-two", text: "two",
  }), {
    "Authorization":   "Bearer " + made.token,
    "Idempotency-Key": "api-send-ceiling-2",
    "Accept":          "application/json",
  });
  count("the second message fills the window", second.status === 202,
    second.status + ": " + String(second.body).slice(0, 200));

  var over = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: "api-send-ceiling-three", text: "three",
  }), {
    "Authorization":   "Bearer " + made.token,
    "Idempotency-Key": "api-send-ceiling-3",
    "Accept":          "application/json",
  });
  count("the third is refused with 429, and the refusal is temporary because the window " +
    "is rolling and the same message succeeds once the volume ahead of it falls out",
    over.status === 429, over.status + ": " + String(over.body).slice(0, 200));
  count("and it names Retry-After, so a client waits the window rather than retrying into " +
    "a ceiling it cannot see",
    String(over.headers["retry-after"] || "").length > 0,
    String(over.headers["retry-after"] || "(absent)"));

  var spentAfterRefusal = await identity.credentials.counters.read(made.id);
  count("the refused message is counted, which is what the submission handoff does with " +
    "the one it refuses too: the registry counts first and reads the window afterwards",
    spentAfterRefusal.messages === 3, JSON.stringify(spentAfterRefusal));

  // The same ceiling on the wire, so the two transports are shown to
  // share one counter rather than to keep one each.
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "api-parity-ceiling-smtp",
    address: DOMAIN, password: made.token,
  });
  session.send("MAIL FROM:<shop@" + DOMAIN + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("RCPT TO:<" + bob + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: shop@" + DOMAIN,
    "To: " + bob,
    "Subject: api-send-ceiling-smtp",
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <api-send-ceiling-smtp@" + DOMAIN + ">",
    "",
    "A message over the wire against a ceiling the route already filled.",
    "",
    ".",
    "",
  ].join("\r\n"), "<api-send-ceiling-smtp>");
  var wireReply = await session.read(/^\d{3} /m, "message answered");
  count("the submission listener refuses the same credential against the same full " +
    "window, so the two transports share ONE counter rather than keeping one each",
    /^452 4\.5\.3 /m.test(wireReply), visible(wireReply));
  session.send("QUIT");
  session.close();

  await identity.credentials.remove({ id: made.id, destroy: true,
    reason: "the ceiling credential has served the parity test" });
}

// The failure budget, spent on one transport and read back on the other.
//
// A credential's identifier is not a secret and its secret half is, so
// guessing means holding the identifier and varying the tail. What bounds
// that is the budget the identity layer keeps against the identifier: a
// run of wrong secrets locks the credential, and the lock is what turns
// an unlimited search into one an attacker cannot finish.
//
// The claim is that there is ONE budget rather than one per surface, and
// the only way to say that is to spend it here and read it there. A
// surface that verifies a secret and counts nothing does not fail any
// assertion made about that surface alone: it answers 401 for a wrong
// secret exactly like the surface that counts. It fails here, where the
// correct secret is presented to the OTHER transport and has to be
// refused.
//
// Both directions, because a budget that binds one way and not the other
// is still a surface an attacker picks.
async function theFailureBudgetIsSharedByBothTransports(ports, caPem, reader, identity, bob) {
  // A credential per direction. The budget locks the one it is spent on,
  // so a single credential would carry the first direction's lock into
  // the second and the second would pass without proving anything.
  var spentOnTheRoute = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential whose failure budget is spent through the sending route",
    maxMessages:   50,
    maxRecipients: 100,
  });
  var wrongOverHttp = wrongSecretFor(spentOnTheRoute.token);
  count("the guess carries the credential's own identifier and a different secret, which " +
    "is the shape of a real guess and the only shape a budget can count",
    wrongOverHttp !== spentOnTheRoute.token &&
    wrongOverHttp.split("_").slice(0, 3).join("_") ===
      spentOnTheRoute.token.split("_").slice(0, 3).join("_"),
    wrongOverHttp.split("_").slice(0, 3).join("_") + "_…");

  for (var i = 0; i < CREDENTIAL_BUDGET_ATTEMPTS; i += 1) {
    var guess = await reader.post("/api/send", "application/json", JSON.stringify({
      from: "shop@" + DOMAIN, to: [bob], subject: "api-send-budget-route-" + i,
      text: "a guess at the secret half of a credential whose identifier is not one",
    }), {
      "Authorization":   "Bearer " + wrongOverHttp,
      "Idempotency-Key": "api-send-budget-route-" + i,
      "Accept":          "application/json",
    });
    count("a wrong secret under a real credential identifier is refused by the sending " +
      "route (guess " + (i + 1) + " of " + CREDENTIAL_BUDGET_ATTEMPTS + ")",
      guess.status === 401, guess.status + ": " + String(guess.body).slice(0, 200));
  }

  var afterRouteGuesses = await authenticateOverSubmission(
    ports, caPem, DOMAIN, spentOnTheRoute.token, "budget-route");
  count("and the credential is then refused on SUBMISSION while presenting its CORRECT " +
    "secret, because both transports reach blamepost.mail.listeners.verifySendingCredential " +
    "and the guesses the route took spent the one failure budget it keeps. A surface that " +
    "verifies a secret and counts nothing is a bound an attacker walks around by choosing " +
    "that surface",
    /^535 /m.test(afterRouteGuesses), visible(afterRouteGuesses));

  // The other direction. Guessing on the wire has to lock the route for
  // the same reason, and a budget read on one transport and written on
  // the other is not one budget.
  var spentOnTheWire = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential whose failure budget is spent through the submission listener",
    maxMessages:   50,
    maxRecipients: 100,
  });
  var wrongOverWire = wrongSecretFor(spentOnTheWire.token);
  for (var j = 0; j < CREDENTIAL_BUDGET_ATTEMPTS; j += 1) {
    var refused = await authenticateOverSubmission(
      ports, caPem, DOMAIN, wrongOverWire, "budget-wire-" + j);
    count("a wrong secret under a real credential identifier is refused by the submission " +
      "listener (guess " + (j + 1) + " of " + CREDENTIAL_BUDGET_ATTEMPTS + ")",
      /^535 /m.test(refused), visible(refused));
  }

  var afterWireGuesses = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [bob], subject: HTTP_BUDGET_MARKER,
    text: "the correct secret, presented after the wire spent this credential's budget",
  }), {
    "Authorization":   "Bearer " + spentOnTheWire.token,
    "Idempotency-Key": "api-send-budget-wire-settled",
    "Accept":          "application/json",
  });
  count("and the credential is then refused by the sending ROUTE while presenting its " +
    "CORRECT secret, so the budget binds in both directions rather than in the one the " +
    "wire happens to keep",
    afterWireGuesses.status === 401,
    afterWireGuesses.status + ": " + String(afterWireGuesses.body).slice(0, 200));
  count("and the refusal is the route's own 401 rather than a second answer naming the " +
    "budget, because a spent budget told apart from a wrong secret is a spent budget an " +
    "attacker can measure",
    /Bearer/i.test(String(afterWireGuesses.headers["www-authenticate"] || "")),
    String(afterWireGuesses.headers["www-authenticate"] || "(absent)"));
  count("and it echoes no part of the credential that was presented",
    String(afterWireGuesses.body).indexOf(spentOnTheWire.token) === -1,
    "the reply carries no token");

  await identity.credentials.remove({ id: spentOnTheRoute.id, destroy: true,
    reason: "the budget credential has served the parity test" });
  await identity.credentials.remove({ id: spentOnTheWire.id, destroy: true,
    reason: "the budget credential has served the parity test" });
}

// WHERE each transport spends the ceiling, which is a step rather than a
// count and is the half a total cannot show.
//
// Both run the author binding and THEN spend, so a message the credential
// was never entitled to write costs it no slot on either transport. A
// route that counted first would be a rate ceiling a caller burns down
// with messages the server refuses, and it would burn down at a different
// rate from the wire's over identical traffic.
async function theCeilingIsSpentAfterTheAuthorBinding(ports, caPem, reader, identity, bob) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential for measuring where each transport spends its ceiling",
    maxMessages:   50,
    maxRecipients: 100,
  });

  // The wire first. The envelope is one the credential holds, so the only
  // thing refusing this message is the author binding.
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "api-parity-order-smtp",
    address: DOMAIN, password: made.token,
  });
  session.send("MAIL FROM:<shop@" + DOMAIN + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("RCPT TO:<" + bob + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: shop@" + SECOND_DOMAIN,
    "To: " + bob,
    "Subject: api-send-order-smtp",
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <api-send-order-smtp@" + DOMAIN + ">",
    "",
    "A message the credential may not author.",
    "",
    ".",
    "",
  ].join("\r\n"), "<api-send-order-smtp>");
  var wireReply = await session.read(/^\d{3} /m, "message answered");
  session.send("QUIT");
  session.close();
  count("the wire refuses a message whose author the credential does not hold",
    /^550 5\.7\.1 /m.test(wireReply), visible(wireReply));

  var afterWire = await identity.credentials.counters.read(made.id);
  count("and it spent no ceiling doing so, because the submission handoff binds the " +
    "author before it counts the message",
    afterWire.messages === 0, JSON.stringify(afterWire));

  var routeReply = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + SECOND_DOMAIN, envelopeFrom: "shop@" + DOMAIN, to: [bob],
    subject: "api-send-order-http", text: "A message the credential may not author.",
  }), {
    "Authorization":   "Bearer " + made.token,
    "Idempotency-Key": "api-send-order-http",
    "Accept":          "application/json",
  });
  count("the route refuses the same message", routeReply.status === 403,
    routeReply.status + ": " + String(routeReply.body).slice(0, 200));

  var afterRoute = await identity.credentials.counters.read(made.id);
  count("and it spent no ceiling doing so either, because the route composes through the " +
    "same blamepost.mail.listeners.sendingCredentialGate the wire runs and reaches it in " +
    "the same order. A route that counted first would let a caller burn a ceiling down " +
    "with messages the server never sends, at a rate the wire does not match over " +
    "identical traffic",
    afterRoute.messages === 0, JSON.stringify(afterRoute));

  await identity.credentials.remove({ id: made.id, destroy: true,
    reason: "the ordering credential has served the parity test" });
}

// Where the wire codes and the HTTP codes are both settled. A refusal is
// a claim about what the server did next, and the recipient's mailbox is
// the only place that answers it.
async function onlyThePermittedMessagesReachedTheMailbox(ports, caPem, bob) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "api-parity-settle",
    address: bob, password: BOB_PASSWORD,
  });
  var selectTag = reader.tag();
  reader.send(selectTag + " SELECT INBOX");
  var selected = await reader.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  count("the recipient's mailbox can be read", existing !== null, visible(selected));

  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var seen = "";
  for (var seq = 1; seq <= held; seq += 1) {
    var fetchTag = reader.tag();
    reader.send(fetchTag + " FETCH " + seq + " BODY.PEEK[]");
    seen += await reader.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
  }
  reader.send(reader.tag() + " LOGOUT");
  reader.close();

  count("the message the route was entitled to send reached the mailbox",
    seen.indexOf(HTTP_OWN_MARKER) !== -1, HTTP_OWN_MARKER);
  count("and so did the outside author under the credential's own Sender",
    seen.indexOf(HTTP_DELEGATED_MARKER) !== -1, HTTP_DELEGATED_MARKER);
  count("nothing reached it from the route's message authored at the second hosted domain",
    seen.indexOf(HTTP_CROSS_MARKER) === -1, HTTP_CROSS_MARKER);
  count("nothing from the route's message authored outside every hosted domain",
    seen.indexOf(HTTP_UNHOSTED_MARKER) === -1, HTTP_UNHOSTED_MARKER);
  count("and nothing from the request that carried a session cookie beside its credential, " +
    "so the refusal happened before anything was composed rather than after",
    seen.indexOf(HTTP_AMBIENT_MARKER) === -1, HTTP_AMBIENT_MARKER);
  count("and nothing from the credential presented over cleartext, so that refusal too " +
    "landed before the composer rather than after the message had left",
    seen.indexOf(HTTP_CLEARTEXT_MARKER) === -1, HTTP_CLEARTEXT_MARKER);
  count("and nothing from the credential whose failure budget the wire had already spent, " +
    "which is what a locked credential means: the correct secret sends no mail either",
    seen.indexOf(HTTP_BUDGET_MARKER) === -1, HTTP_BUDGET_MARKER);
  count("and the replayed message is in the mailbox ONCE, which is what an idempotency " +
    "record is for and what a status code alone cannot show",
    seen.split("api-send-replay-marker").length - 1 === 1,
    (seen.split("api-send-replay-marker").length - 1) + " copies");
  count("and so is the message two requests asked for at the same instant, which is the " +
    "claim that cannot depend on which of the two got there first",
    seen.split(HTTP_CONCURRENT_MARKER).length - 1 === 1,
    (seen.split(HTTP_CONCURRENT_MARKER).length - 1) + " copies");
}

// ---- runner ----------------------------------------------------------------

// The route documents a JSON body of up to 1048576 bytes. A text field
// that fills most of it reaches the route and is sent, so the documented
// limit is one a caller can actually use.
async function aBodyInsideTheDocumentedLimitIsTaken(reader, token, to) {
  var text = "a".repeat(1040000);
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [to], subject: "api-send-large-body", text: text,
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "api-send-large-body",
    "Accept":          "application/json",
  });
  count("a text body of 1040000 characters, inside the documented 1048576-byte request, " +
    "is accepted",
    answer.status === 202, answer.status + ": " + String(answer.body).slice(0, 200));
}

async function run() {
  var root    = helpers.tempDir("api-send-credential-parity");
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
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "api send parity test" });
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: SECOND_DOMAIN, by: "api send parity test" });

    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });
    await identity.accounts.create({
      address: SECOND_BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    var made = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts over both transports",
      // Room for every message this file sends through it. The ceiling
      // case below issues a credential of its own with a small ceiling,
      // so the two questions do not share one window.
      maxMessages:   200,
      maxRecipients: 400,
    });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      // Every interface, so the cleartext vector can be dialed at an
      // address this server can tell apart from its own machine. A
      // listener bound on loopback alone reads every request as one that
      // crossed no network, and the case that needs a network peer would
      // pass against the arm it was written to test.
      httpAddress:  EVERY_INTERFACE,
    });
    await server.start();
    running = true;

    var ports = { submission: sections.submission.port, imap: sections.imap.port };
    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only one a credential may " +
      "be presented on",
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));

    var tlsOrigin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(tlsOrigin, { ca: material.caPem, servername: HOSTNAME });

    await theRouteIsMounted(reader, made.token, bob.address);
    await aProgramWithoutAnOriginHeaderReachesTheRoute(
      tlsOrigin, material.caPem, made.token, bob.address);
    await anAbsentOrWrongCredentialIsRefused(reader, bob.address);
    await anAmbientCredentialIsRefused(tlsOrigin, material.caPem, made.token, bob.address);
    await theCleartextPortRefusesACredential(bound.http, made.token, bob.address);
    await amalformedBodyIsRefused(reader, made.token, bob.address);

    var cases = identityCases(bob.address);
    for (var i = 0; i < cases.length; i += 1) {
      await pairedCase(ports, material.caPem, reader, made.token, cases[i]);
    }

    await aBodyInsideTheDocumentedLimitIsTaken(reader, made.token, bob.address);
    await areplayedKeyAnswersTheFirstResponse(reader, made.token, bob.address);
    await aConcurrentDuplicateSendsOnce(reader, made.token, bob.address);
    await theCeilingBindsOnBothTransports(ports, material.caPem, reader, identity, bob.address);
    await theFailureBudgetIsSharedByBothTransports(
      ports, material.caPem, reader, identity, bob.address);
    await theCeilingIsSpentAfterTheAuthorBinding(
      ports, material.caPem, reader, identity, bob.address);
    await onlyThePermittedMessagesReachedTheMailbox(ports, material.caPem, bob.address);

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
  name:      "api-send-credential-parity",
  run:       run,
  getChecks: helpers.getChecks,
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
