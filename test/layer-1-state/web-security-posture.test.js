// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The nine guarantees the browser surface makes, each measured by a
 * request that has to be refused rather than by the presence of the
 * middleware that refuses it.
 *
 * A check that the chain is MOUNTED is cheap and answers nothing. A
 * middleware can be mounted with the option that makes it a
 * pass-through, mounted after the route it was meant to protect,
 * mounted on a router nothing routes through, or mounted correctly and
 * short circuited by a header the caller writes. Every one of those
 * reads as present, and the only thing that tells them apart from a
 * working gate is a request that should be turned away and is. So every
 * assertion here is a status code and a body off the wire, and where the
 * route has an observable effect the effect is read back afterwards:
 * a route that performs the write and then answers 403 has done the
 * damage and hidden it.
 *
 * The nine, and the request each one is measured with:
 *
 *   - CSRF, a state change posted with no token and with a wrong one;
 *   - the origin cross check, a state change posted with a valid token
 *     from another origin, and from an origin that merely begins with
 *     this one;
 *   - fetch metadata, a state change posted with a valid token and this
 *     origin's own Origin header, carrying `Sec-Fetch-Site: cross-site`,
 *     which is the shape a browser attaches and a form cannot forge;
 *   - the bot guard, a request from an automation agent;
 *   - cookie prefixes, the `Set-Cookie` bytes on the wire against every
 *     condition RFC 6265bis section 4.1.3 puts on a `__Host-` name;
 *   - Trusted Types, the `Content-Security-Policy` on every class of
 *     response this application produces, including the refusals and
 *     the one route that writes a policy of its own;
 *   - encrypted sessions, the session token on the wire, which is sealed
 *     rather than the identifier the server keeps;
 *   - sealed storage, every byte under the data directory after the
 *     store closes, against the address, the display name, the subject
 *     and the body that went into it;
 *   - the message body, which is the one value this application
 *     interpolates un-escaped, read off the conversation page a reader
 *     opens after a sender's markup arrived through the store.
 *
 * Three properties of the way those are measured are load bearing.
 *
 * **Each refusal is swept across every state changing route**, not
 * proven on one. A gate on the chain refuses all of them; a gate that
 * has slipped onto one route refuses that one. The two are
 * indistinguishable from a single vector, and this repository has
 * already shipped a defect where a rule held on one resolver over the
 * same mail and not on the other.
 *
 * **Each refusal has a differential beside it.** A surface that refused
 * every request would satisfy all of the above and would also be a
 * mailbox nobody can use, so the same action is driven correctly and has
 * to succeed. The fetch metadata vector is the sharpest case: everything
 * about it is correct except one header, so the gate has to be reading
 * that header rather than turning work away.
 *
 * **The disk scan publishes what it read.** A search that finds nothing
 * because it reached nothing is the failure mode a clean verdict cannot
 * be told apart from, so the scan reports its file and byte counts and
 * proves it can see cleartext by finding the operator's own certificate,
 * which is the one file under the data directory that is not sealed.
 *
 * **The HTTP version is one of the vectors.** The framework binds this
 * listener with `http2.createSecureServer` and offers `["h2",
 * "http/1.1"]` over ALPN, so a browser negotiates h2 and carries the
 * authority in `:authority` with no `Host` header. `node:https` speaks
 * HTTP/1.1 and sends one. Those are different requests, and a gate
 * deriving this server's own origin from `Host` answers them
 * differently, so the journey is driven over both and the two answers
 * have to agree.
 *
 * What is deliberately not here, because it is measured elsewhere and a
 * second copy is a second answer waiting to disagree:
 * `test/layer-1-state/server-console-isolation.test.js` reads the
 * session cookie's own attributes off the wire, so this file asks the
 * same question of the CSRF cookie and asks a different question of the
 * session cookie, which is whether its value is ciphertext.
 *
 * Run standalone: node test/layer-1-state/web-security-posture.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var READER_PASSWORD  = "quiet lantern bicycle 4291";

// Every value below is written once into the account table, the message
// store or the session, and looked for afterwards in every byte on disk.
// They are spelled unusually on purpose: a common word would be absent
// from the volume for reasons that have nothing to do with sealing, and
// a scan that cannot fail is a scan that proves nothing.
var READER_LOCAL   = "quillfeather";
var READER_ADDRESS = READER_LOCAL + "@" + DOMAIN;
var READER_NAME    = "Quill Feather Bramblewood";
var SUBJECT        = "Marchpane ledger for the quarter";
var BODY           = "octarine8812 is the only copy of this sentence";

// The one file under the data directory that is cleartext by design: the
// certificate the operator supplied. Finding it is what proves the scan
// below reached the tree, opened files and can match a string, so a run
// that reports no sealed value on disk is reporting a search that ran.
var CLEARTEXT_CANARY = "BEGIN CERTIFICATE";

// A token of the right shape and the wrong value. The gate compares
// against a 64 character hex string, so a short or malformed submission
// would be refused for being malformed rather than for being wrong, and
// the interesting refusal is the one that reads the value.
var WRONG_TOKEN = "0".repeat(64);

// An origin that begins with this server's own. A gate comparing origins
// by prefix rather than by parsing accepts it, which is the bug class
// this vector exists for.
var LOOKALIKE_SUFFIX = ".attacker.example.net";
var FOREIGN_ORIGIN   = "https://attacker.example.net";

// What a browser attaches to a request that started on another site, and
// what it attaches to one that started here. Neither can be written by a
// cross site form, which is what makes the pair worth reading.
var CROSS_SITE = Object.freeze({
  "Sec-Fetch-Site": "cross-site",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});
var SAME_ORIGIN = Object.freeze({
  "Sec-Fetch-Site": "same-origin",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});

// What a browser attaches to a NATIVE FORM SUBMIT, which is a different
// request from the one above and the one every human user sends. A
// script's `fetch` is mode `cors` and destination `empty`; pressing a
// submit button is a navigation, so the mode is `navigate` and the
// destination is `document`, and the token rides the body rather than a
// header because a form cannot write headers.
//
// Every vector in this file used the `fetch` shape, so nothing measured
// the path a person drives.
var NAVIGATION = Object.freeze({
  "Sec-Fetch-Site": "same-origin",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-User": "?1",
  "Upgrade-Insecure-Requests": "1",
  // A form carries its token in the body. Emptying the header is what
  // makes this the form's request rather than a script's.
  "X-CSRF-Token":  "",
});

// The origin a browser serializes when it is told not to reveal where
// the request came from. It is opaque: it names no site, so it can never
// be shown to be this one, and the origin cross check refuses it.
var OPAQUE_ORIGIN = "null";

// The referrer policy that makes a browser send OPAQUE_ORIGIN on every
// same-origin form submit.
//
// Under the Fetch standard a request whose mode is `navigate` and whose
// method is not GET or HEAD has its serialized origin replaced with
// `null` when the document's referrer policy is `no-referrer`. The
// origin cross check then reads an origin that cannot be this server's
// and refuses, so a policy of `no-referrer` turns every form on this
// surface into a 403 for every browser while leaving every request a
// script or a test client writes by hand untouched.
var ORIGIN_ERASING_POLICY = "no-referrer";

// What this surface serves instead. Cross-origin requests still carry no
// referrer at all, which is the whole of what `no-referrer` bought here,
// and a cross-origin form submit still serializes its origin as `null`
// and is still refused. The difference is that a SAME-origin submit now
// names this server, which is the header the gate reads.
var REFERRER_POLICY = "same-origin";

// A meta element restating the policy inside the document would override
// the response header for that document, so a page carrying one is a
// second place the value lives and the one a browser actually obeys.
var META_REFERRER_RE = /<meta[^>]+name=["']referrer["'][^>]*>/i;

// An automation agent off the framework's own deny list, and the header
// value a request carrying no agent string at all would send.
var AUTOMATION_AGENT = "curl/8.4.0";

var SHUTDOWN_TIMEOUT_MS = 5000;

function messageFor(recipient) {
  return Buffer.from(
    "Message-ID: <posture@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + SUBJECT + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + BODY + "\r\n", "utf8");
}

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

// Every mail listener off. This file is about the browser surface, and a
// port taken is a port another test in the same run cannot have.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = {
      enabled: false,
      port:    await wire.reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

// The flags a message carries right now, read through the store rather
// than through the surface under test. A refusal that answered 403 and
// wrote anyway is only visible from this side.
async function flagsOf(agent, accountId, storeFolder, objectId) {
  var message = await agent.fetch({
    actor:    { id: accountId, roles: ["account"] },
    folder:   storeFolder,
    objectId: objectId,
  });
  return message && Array.isArray(message.flags) ? message.flags : null;
}

// ---- the sweep --------------------------------------------------------------

// Every route on this surface that changes state and that a mailbox
// owner can reach. One refused route proves a gate on that route; the
// set proves a gate on the chain, which is what hard rule four is about.
function stateChangingRoutes(accountId, folder) {
  return [
    "/mail/actions?folder=" + encodeURIComponent(folder),
    "/compose",
    "/prefs/theme",
    "/sign-out",
    "/jmap/api",
    "/jmap/upload/" + accountId,
  ];
}

// The body is the same everywhere on purpose. Each gate refuses before
// the route reads anything, so a payload shaped for one route would
// suggest the refusal depended on it.
var SWEEP_FIELDS = Object.freeze({ action: "flag" });

async function sweepIsRefused(reader, routes, label, send) {
  for (var i = 0; i < routes.length; i += 1) {
    var answer = await send(routes[i]);
    count(label + ", on " + routes[i],
      answer.status === 403, answer.status + " " + answer.body.slice(0, 120));
  }
  // A gate that signed the reader out while refusing would leave every
  // assertion after this one measuring an anonymous request.
  var still = await reader.get("/mail?folder=INBOX");
  count("the reader still holds their session after " + label,
    still.status === 200, still.status + " " + String(still.location));
}

// ---- CSRF -------------------------------------------------------------------

async function testTheCsrfGateRefusesAStateChangeWithoutAToken(reader, routes, target, agent) {
  var before = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("the message under test starts unflagged, so a write would be visible",
    before !== null && before.indexOf("\\Flagged") === -1, JSON.stringify(before));

  await sweepIsRefused(reader, routes, "a state change carrying no token is refused",
    function (path) {
      return reader.post(path, "application/x-www-form-urlencoded",
        "action=flag&objectId=" + encodeURIComponent(target.objectId),
        { "X-CSRF-Token": "" });
    });

  await sweepIsRefused(reader, routes, "a state change carrying a wrong token is refused",
    function (path) {
      return reader.post(path, "application/x-www-form-urlencoded",
        "action=flag&objectId=" + encodeURIComponent(target.objectId),
        { "X-CSRF-Token": WRONG_TOKEN });
    });

  var after = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("no untokened request reached the write it asked for",
    after !== null && after.indexOf("\\Flagged") === -1, JSON.stringify(after));

  // The refusal names the gate that produced it. Two gates on this chain
  // answer 403 and the status alone cannot say which, so a fetch
  // metadata refusal standing in for a token refusal would read as this
  // check passing while the token compare was gone.
  var refusal = await reader.post(routes[0], "application/x-www-form-urlencoded",
    "action=flag", { "X-CSRF-Token": "" });
  count("the refusal is the token compare rather than another gate on the chain",
    refusal.body.indexOf("CSRF token mismatch") !== -1, refusal.body.slice(0, 160));
}

// The differential. Every refusal above is worth nothing unless the same
// action, driven the way the rendered form drives it, goes through and
// writes.
async function testTheSameActionWorksWithItsToken(reader, target, agent) {
  var flagged = await reader.form("/mail/actions?folder=INBOX", {
    action: "flag", objectId: target.objectId,
  });
  count("the same action carrying the form's own token is performed",
    flagged.status === 302, flagged.status + " " + flagged.body.slice(0, 160));
  var after = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("and the flag it asked for is on the message afterwards",
    after !== null && after.indexOf("\\Flagged") !== -1, JSON.stringify(after));

  var cleared = await reader.form("/mail/actions?folder=INBOX", {
    action: "unflag", objectId: target.objectId,
  });
  count("the flag comes back off, so the state is where the next vector expects it",
    cleared.status === 302, cleared.status);
}

// ---- the origin cross check -------------------------------------------------

async function testAForeignOriginIsRefusedWithAValidToken(reader, routes, origin) {
  await sweepIsRefused(reader, routes,
    "a state change from another origin is refused even carrying a valid token",
    function (path) { return reader.form(path, SWEEP_FIELDS, { Origin: FOREIGN_ORIGIN }); });

  await sweepIsRefused(reader, routes,
    "an origin that merely begins with this one is refused",
    function (path) {
      return reader.form(path, SWEEP_FIELDS, { Origin: origin + LOOKALIKE_SUFFIX });
    });

  var refusal = await reader.form(routes[0], SWEEP_FIELDS, { Origin: FOREIGN_ORIGIN });
  count("the refusal is the origin cross check rather than the token compare",
    refusal.body.indexOf("cross-origin request refused") !== -1, refusal.body.slice(0, 160));
}

// ---- fetch metadata ---------------------------------------------------------

async function testACrossSiteStateChangeIsRefused(reader, routes, origin) {
  // Everything about these requests is correct except the one header a
  // browser writes and a cross site form cannot. So a refusal here is
  // this gate and can be nothing else.
  await sweepIsRefused(reader, routes,
    "a state change a browser reports as cross site is refused",
    function (path) {
      return reader.form(path, SWEEP_FIELDS, Object.assign({ Origin: origin }, CROSS_SITE));
    });

  var refusal = await reader.form(routes[0], SWEEP_FIELDS,
    Object.assign({ Origin: origin }, CROSS_SITE));
  count("the refusal is the fetch metadata gate rather than either CSRF check",
    refusal.body.indexOf("Cross-site request refused") !== -1, refusal.body.slice(0, 160));

  // The Storage Access escalation, which is the same header family
  // saying the embedded context can reach unpartitioned cookies.
  var escalated = await reader.form(routes[0], SWEEP_FIELDS,
    Object.assign({ Origin: origin, "Sec-Fetch-Storage-Access": "active" }, CROSS_SITE));
  count("a cross site request claiming storage access is refused",
    escalated.status === 403 &&
    escalated.body.indexOf("Storage Access escalation") !== -1,
    escalated.status + " " + escalated.body.slice(0, 160));

  // The differential for this gate specifically: the identical request
  // with the header a same origin browser would have sent goes through.
  // Without it the three assertions above are satisfied by a route that
  // refuses everything.
  var permitted = await reader.form("/prefs/theme", { theme: "dark" },
    Object.assign({ Origin: origin }, SAME_ORIGIN));
  count("the same request reported as same origin is performed",
    permitted.status === 302, permitted.status + " " + permitted.body.slice(0, 160));
}

// ---- the form a person submits ----------------------------------------------

// The path every human user drives, which no other vector in this file
// drives: a rendered form, a pressed button, a navigation.
//
// Two halves, and both are needed. The first three assertions write the
// browser's headers by hand and prove the gate answers them correctly.
// They cannot see the defect this exists for, because a header written
// by hand is a header the browser was never asked to compute: they pass
// on a server nobody can sign in to. The fourth reads what the response
// TELLS a browser to send, which is the only place the failure is
// visible from this layer.
async function testANativeFormSubmitIsAccepted(reader, routes, origin, target, agent) {
  // Two different routes, so the acceptance is the chain rather than one
  // route that happens not to read the header.
  var themed = await reader.form("/prefs/theme", { theme: "dark" },
    Object.assign({ Origin: origin }, NAVIGATION));
  count("a form submitted the way a browser submits one is performed",
    themed.status === 302, themed.status + " " + themed.body.slice(0, 160));

  var flagged = await reader.form("/mail/actions?folder=INBOX",
    { action: "flag", objectId: target.objectId },
    Object.assign({ Origin: origin }, NAVIGATION));
  count("and so is a submit that writes, on a second route",
    flagged.status === 302, flagged.status + " " + flagged.body.slice(0, 160));
  var after = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("the write the submitted form asked for reached the message",
    after !== null && after.indexOf("\\Flagged") !== -1, JSON.stringify(after));

  // Put the message back, because the vectors after this one read the
  // same flag and would be measuring this write rather than their own.
  var cleared = await reader.form("/mail/actions?folder=INBOX",
    { action: "unflag", objectId: target.objectId },
    Object.assign({ Origin: origin }, NAVIGATION));
  count("and the same submit takes it back off",
    cleared.status === 302, cleared.status);

  // The same navigation carrying the origin a browser serializes when it
  // has been told to reveal nothing. It names no site, so it can never be
  // shown to be this one, and it is refused on every route.
  await sweepIsRefused(reader, routes,
    "a submit carrying an opaque origin is refused",
    function (path) {
      return reader.form(path, SWEEP_FIELDS, Object.assign({ Origin: OPAQUE_ORIGIN },
        NAVIGATION));
    });

  var opaque = await reader.form(routes[0], SWEEP_FIELDS,
    Object.assign({ Origin: OPAQUE_ORIGIN }, NAVIGATION));
  count("the refusal on an opaque origin is the origin cross check",
    opaque.body.indexOf("cross-origin request refused") !== -1, opaque.body.slice(0, 160));

  // And a submit that really did start somewhere else, in the shape a
  // navigation from another site arrives in. Without this the acceptances
  // above would be satisfied by a surface that reads no origin at all.
  await sweepIsRefused(reader, routes,
    "a navigation that started on another site is refused",
    function (path) {
      return reader.form(path, SWEEP_FIELDS, Object.assign({ Origin: FOREIGN_ORIGIN },
        NAVIGATION, { "Sec-Fetch-Site": "cross-site" }));
    });
}

// Whether a browser handed this page would send an origin the gate above
// can read.
//
// This is the assertion the three before it cannot make. A test client
// writes `Origin` itself, so it goes on passing however the response
// tells a real browser to behave; the browser computes it from the
// document's referrer policy and sends `null` when that policy is
// `no-referrer`, which the vector above proves is refused. So the policy
// on the wire is the whole of what decides whether a person can sign in,
// and it is read on a rendered page and on a refusal, because a policy
// set on one class of response and not another is a surface where some
// forms work.
async function testTheServedPolicyLeavesTheOriginReadable(reader, origin, caPem) {
  var pages = [
    { what: "the sign in page", answer: await browser.browserAt(origin,
      { ca: caPem }).get("/sign-in") },
    { what: "a page behind the session", answer: await reader.get("/mail?folder=INBOX") },
    { what: "a refusal", answer: await reader.form("/prefs/theme", { theme: "dark" },
      { Origin: FOREIGN_ORIGIN }) },
  ];

  for (var i = 0; i < pages.length; i += 1) {
    var served = String(pages[i].answer.headers["referrer-policy"] || "");
    count("the referrer policy on " + pages[i].what + " is not the one that makes a " +
      "browser serialize its origin as " + OPAQUE_ORIGIN + " on every form submit",
      served !== ORIGIN_ERASING_POLICY, JSON.stringify(served));
    count("and it is the policy that reveals nothing to another origin while naming " +
      "this one to itself, on " + pages[i].what,
      served === REFERRER_POLICY, JSON.stringify(served));
  }

  // A document may restate the policy in a meta element, and a browser
  // obeys the meta over the header. A page carrying one is a second
  // place this value lives, and the header assertions above would go on
  // passing while every browser read the other copy.
  var rendered = await reader.get("/mail?folder=INBOX");
  var meta = META_REFERRER_RE.exec(rendered.body);
  count("no rendered page restates the referrer policy in a meta element, where it " +
    "would override the header a browser was already sent",
    meta === null, meta === null ? "none" : meta[0]);
}

// The same journey over the HTTP version a browser actually negotiates.
//
// Every vector above rides `node:https`, which speaks HTTP/1.1 and sends a
// `Host` header. The framework binds this listener with
// `http2.createSecureServer` and offers `["h2", "http/1.1"]` over ALPN, so
// no browser ever sends that request: it negotiates h2 and carries the
// authority in `:authority`, with no `Host` header at all. Node does not
// synthesize one, so anything deriving this server's own origin from
// `Host` reads `undefined` over the only version a browser uses.
//
// That is the whole gap this section closes. A reader that writes its own
// headers cannot see it, and neither can one that only ever speaks the
// version a browser does not. So the shape is the shape of the vectors
// above, driven twice, and the two answers have to agree: a rule that
// holds over HTTP/1.1 and not over HTTP/2 is a rule that holds for the
// test client and not for the person.
//
// Sign in is driven first and separately, because it is the one route a
// person cannot route around. Everything else on this surface is behind
// it, so a surface that refuses this POST is a surface with no reachable
// pages at all, whatever the rest of the chain would have done.
async function testTheJourneyHoldsOverTheVersionABrowserNegotiates(origin, caPem, target) {
  var browserSide = browser.browserAt(origin, { ca: caPem, http2: true });
  count("the reader for this section speaks the version a browser negotiates",
    browserSide.http2 === true, String(browserSide.http2));

  var page = await browserSide.readCsrf("/sign-in");
  count("the sign in page is served over HTTP/2",
    page.page.status === 200, page.page.status + " " + page.page.body.slice(0, 120));
  count("and it carries a token for the browser to send back",
    page.token.length === 64, JSON.stringify(page.token));

  // The measurement the whole file exists downstream of: a person filling
  // in the sign in form and pressing the button.
  var landed = await browserSide.signIn(READER_ADDRESS, READER_PASSWORD);
  count("a person can sign in over the HTTP version their browser uses",
    landed.status === 302, landed.status + " " + landed.body.slice(0, 200));
  count("and the session lands them on their mailbox rather than back at the form",
    String(landed.location) === "/mail?folder=INBOX", String(landed.location));

  // A page behind the session, so the cookie the sign in issued is one the
  // next request is actually served on.
  var mailbox = await browserSide.get("/mail?folder=INBOX");
  count("the session issued over HTTP/2 carries to the next page",
    mailbox.status === 200, mailbox.status + " " + String(mailbox.location));

  // A second state-changing route, so the acceptance is the chain rather
  // than the one route sign in happens to take.
  var themed = await browserSide.form("/prefs/theme", { theme: "dark" });
  count("a form on a second route is performed over HTTP/2 too",
    themed.status === 302, themed.status + " " + themed.body.slice(0, 200));

  var flagged = await browserSide.form("/mail/actions?folder=INBOX",
    { action: "flag", objectId: target.objectId });
  count("and so is a submit that writes",
    flagged.status === 302, flagged.status + " " + flagged.body.slice(0, 200));
  var cleared = await browserSide.form("/mail/actions?folder=INBOX",
    { action: "unflag", objectId: target.objectId });
  count("the same submit takes the flag back off, so the state is where the next " +
    "vector expects it", cleared.status === 302, cleared.status);

  // The differential. A surface that accepted everything over HTTP/2 would
  // satisfy every assertion above and would also have no origin check on
  // the version a browser uses, which is the version that needs one.
  var foreign = await browserSide.form("/prefs/theme", { theme: "light" },
    { Origin: FOREIGN_ORIGIN });
  count("a state change from another origin is still refused over HTTP/2",
    foreign.status === 403, foreign.status + " " + foreign.body.slice(0, 200));
  count("and the refusal is the origin cross check rather than a gate that reads " +
    "nothing", foreign.body.indexOf("cross-origin request refused") !== -1,
    foreign.body.slice(0, 200));

  var opaque = await browserSide.form("/prefs/theme", { theme: "light" },
    { Origin: OPAQUE_ORIGIN });
  count("an opaque origin is still refused over HTTP/2",
    opaque.status === 403, opaque.status + " " + opaque.body.slice(0, 200));

  var tokenless = await browserSide.post("/prefs/theme",
    "application/x-www-form-urlencoded", "theme=light", { "X-CSRF-Token": "" });
  count("and a state change carrying no token is still refused over HTTP/2",
    tokenless.status === 403, tokenless.status + " " + tokenless.body.slice(0, 200));
  count("that refusal is the token compare, so both checks run on this version",
    tokenless.body.indexOf("CSRF token mismatch") !== -1, tokenless.body.slice(0, 200));

  // The pair the origin cross-check cannot survive if either half is
  // taken on trust.
  //
  // Over HTTP/2 a caller writes `Origin`, and it can write a `Host`
  // header too. The baseline the cross-check compares against is built
  // from the authority, so a caller that supplies both halves and makes
  // them agree names an origin this server does not serve and satisfies
  // the comparison with it. RFC 9113 section 8.3.1 calls a `Host` that
  // disagrees with `:authority` malformed, and that is what has to
  // happen to it.
  //
  // Driven on the route where being wrong costs the most: a sign in that
  // went through here is a session minted for a request the server
  // believed came from somewhere else.
  var forged = browser.browserAt(origin, { ca: caPem, http2: true });
  await forged.readCsrf("/sign-in");
  var forgedIn = await forged.post("/sign-in", "application/x-www-form-urlencoded",
    "address=" + encodeURIComponent(READER_ADDRESS) +
    "&password=" + encodeURIComponent(READER_PASSWORD) +
    "&_csrf=" + encodeURIComponent(forged.csrf()),
    { Host: "attacker.example.net", Origin: "https://attacker.example.net" });
  count("a request naming one authority in :authority and another in Host is refused, " +
    "so a caller cannot write both halves of the origin comparison",
    forgedIn.status === 400, forgedIn.status + " " + forgedIn.body.slice(0, 200));
  count("and it is refused before it mints anything, so no session came back",
    String(forgedIn.setCookie).indexOf("__Host-bp_session=") === -1,
    JSON.stringify(forgedIn.setCookie));

  // The differential for that refusal. A `Host` that AGREES with the
  // authority is an ordinary request and has to keep working, or the
  // check above would be satisfied by refusing the header outright.
  var agreeing = browser.browserAt(origin, { ca: caPem, http2: true });
  await agreeing.readCsrf("/sign-in");
  var agreed = await agreeing.post("/sign-in", "application/x-www-form-urlencoded",
    "address=" + encodeURIComponent(READER_ADDRESS) +
    "&password=" + encodeURIComponent(READER_PASSWORD) +
    "&_csrf=" + encodeURIComponent(agreeing.csrf()),
    { Host: new URL(origin).host, Origin: origin });
  count("a Host that agrees with the authority is an ordinary request and still signs in",
    agreed.status === 302, agreed.status + " " + agreed.body.slice(0, 200));

  return browserSide;
}

// The cookie posture a browser is told to keep, read over the version a
// browser negotiates.
//
// The `__Host-` prefix is resolved from the request scheme rather than
// from a constant, and the scheme reaches the framework differently over
// the two versions: HTTP/1.1 carries it on the socket, HTTP/2 carries it
// in `:scheme`. A prefix that resolved on one and not the other is a
// cookie a browser silently drops, and a dropped double submit cookie is
// every state change failing for a reason nothing reports.
function testTheCookiePostureHoldsOverHttp2(page, landing) {
  var issued = page.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-csrf=") === 0;
  });
  count("the double submit cookie carries the host prefix over HTTP/2 as well",
    issued.length === 1,
    JSON.stringify(page.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (issued.length === 1) {
    var csrfAttributes = String(issued[0]);
    count("it is Secure over HTTP/2, which the prefix requires",
      /;\s*Secure/i.test(csrfAttributes), csrfAttributes.slice(-140));
    count("it is scoped to the whole origin over HTTP/2",
      /;\s*Path=\/(?:;|$)/i.test(csrfAttributes), csrfAttributes.slice(-140));
    count("it carries no Domain attribute over HTTP/2",
      !/;\s*Domain=/i.test(csrfAttributes), csrfAttributes.slice(-140));
    count("and its value is the full width token the compare accepts",
      /^__Host-csrf=[a-f0-9]{64}(?:;|$)/.test(csrfAttributes), csrfAttributes.slice(0, 90));
  }

  var session = landing.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-bp_session=") === 0;
  });
  count("signing in over HTTP/2 writes exactly one session cookie, under the host " +
    "prefixed name", session.length === 1,
    JSON.stringify(landing.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (session.length !== 1) return;

  var attributes = String(session[0]);
  count("the session cookie is Secure over HTTP/2, which the prefix requires",
    /;\s*Secure/i.test(attributes), attributes.slice(-140));
  count("it is HttpOnly, so no script on the page can read it",
    /;\s*HttpOnly/i.test(attributes), attributes.slice(-140));
  count("it is scoped to the whole origin, which the prefix requires",
    /;\s*Path=\/(?:;|$)/i.test(attributes), attributes.slice(-140));
  count("it carries no Domain attribute, which the prefix also requires",
    !/;\s*Domain=/i.test(attributes), attributes.slice(-140));
  count("and it is same site, so it does not ride a cross site navigation",
    /;\s*SameSite=(Lax|Strict)/i.test(attributes), attributes.slice(-140));
}

// The one shape that reached past the token compare and the origin cross
// check, and the layers that refuse it.
//
// The framework's stateless waiver skips validation for a request that
// carries an Authorization header, on the reasoning that a token
// authenticated caller has no ambient credential to abuse. It reads the
// header's presence and never its value, so `Bearer not-a-real-token`
// satisfies it. The reasoning does not hold at all for a request
// carrying an Authorization header AND this server's session cookie: the
// session layer reads the cookie first and authenticates from it, so
// such a request holds exactly the ambient credential CSRF exists to
// protect, and was waived anyway.
//
// Two neighboring layers held that shut. The fetch metadata gate runs
// before the CSRF gate and refuses the cross site shape whatever headers
// follow it, and no preflight is answered, so a page on another site
// could not get the browser to attach the header in the first place.
// Both are still asserted, because they are what kept the shape off the
// wire and the day either moves is the day the gate behind them is all
// there is.
//
// Then the gate itself, measured with the fetch metadata headers left
// off so nothing in front of it can answer first. Two vectors, because
// a waived request skips two checks and each one has to be seen running
// again: another origin reaches the origin cross check, and this origin
// with no token reaches the token compare. A gate whose correctness
// depends on its neighbors being mounted is not a gate.
//
// The refusal and the write are read separately, as everywhere else in
// this file. A route that answers 403 after performing the flag has done
// the damage and hidden it.
async function testAnAuthorizationHeaderDoesNotOpenACrossSitePath(reader, routes, target, agent) {
  await sweepIsRefused(reader, routes,
    "a cross site state change carrying an Authorization header is still refused",
    function (path) {
      return reader.post(path, "application/x-www-form-urlencoded", "action=flag",
        Object.assign({
          Authorization:  "Bearer not-a-real-token",
          Origin:         FOREIGN_ORIGIN,
          "X-CSRF-Token": "",
        }, CROSS_SITE));
    });

  // A browser issues the request above only if a preflight said it may,
  // because an Authorization header is not one of the values a form can
  // set. So the preflight is the door, and it has to stay shut on every
  // state changing route rather than on the first one asked.
  for (var i = 0; i < routes.length; i += 1) {
    var answer = await reader.preflight(routes[i], {
      origin:  FOREIGN_ORIGIN,
      method:  "POST",
      headers: "authorization,x-csrf-token",
    });
    var allowOrigin      = answer.headers["access-control-allow-origin"];
    var allowCredentials = answer.headers["access-control-allow-credentials"];
    var allowHeaders     = answer.headers["access-control-allow-headers"];
    count("no preflight from another origin is granted on " + routes[i],
      allowOrigin === undefined && allowCredentials === undefined &&
      allowHeaders === undefined,
      answer.status + " " + JSON.stringify([allowOrigin, allowCredentials, allowHeaders]));
  }

  // The same shape with the fetch metadata headers left off. Everything a
  // cross site write needs is present: the reader's session cookie, so
  // the request is ambient credentialed; another origin; no token; and an
  // Authorization header whose value is not a credential this server ever
  // issued.
  var before = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("the message under test is unflagged before the bearer vectors run",
    before !== null && before.indexOf("\\Flagged") === -1, JSON.stringify(before));

  var BEARER = Object.freeze({
    Authorization:  "Bearer not-a-real-token",
    "X-CSRF-Token": "",
  });

  // The write is read back before any status is asserted, so a run where
  // the request went through reports the flag that landed rather than a
  // status code with several possible causes. This is the measurement the
  // waiver failed: it answered 302 and the message came back flagged.
  var attempted = await reader.post(routes[0], "application/x-www-form-urlencoded",
    "action=flag&objectId=" + encodeURIComponent(target.objectId),
    Object.assign({ Origin: FOREIGN_ORIGIN }, BEARER));
  var landed = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("a bearer carrying cross origin write does not reach the message",
    landed !== null && landed.indexOf("\\Flagged") === -1, JSON.stringify(landed));
  count("and the request that asked for it is refused rather than performed",
    attempted.status === 403, attempted.status + " " + attempted.body.slice(0, 160));

  await sweepIsRefused(reader, routes,
    "an unvalidated Authorization header does not waive the origin cross check",
    function (path) {
      return reader.post(path, "application/x-www-form-urlencoded",
        "action=flag&objectId=" + encodeURIComponent(target.objectId),
        Object.assign({ Origin: FOREIGN_ORIGIN }, BEARER));
    });

  await sweepIsRefused(reader, routes,
    "an unvalidated Authorization header does not waive the token compare",
    function (path) {
      return reader.post(path, "application/x-www-form-urlencoded",
        "action=flag&objectId=" + encodeURIComponent(target.objectId),
        Object.assign({}, BEARER));
    });

  var after = await flagsOf(agent, target.accountId, target.storeFolder, target.objectId);
  count("and no request in either sweep reached the write it asked for",
    after !== null && after.indexOf("\\Flagged") === -1, JSON.stringify(after));

  // Which of the two checks answered. A refusal that came from the wrong
  // one would leave the other still waived and read as this passing.
  count("the refusal on the foreign origin vector is the origin cross check",
    attempted.body.indexOf("cross-origin request refused") !== -1,
    attempted.body.slice(0, 160));

  var tokenless = await reader.post(routes[0], "application/x-www-form-urlencoded",
    "action=flag", Object.assign({}, BEARER));
  count("the refusal on this origin's vector is the token compare",
    tokenless.body.indexOf("CSRF token mismatch") !== -1, tokenless.body.slice(0, 160));
}

// The differential for the vectors above, and the reason the waiver they
// close exists at all.
//
// A caller holding no cookie has no ambient credential for a cross site
// page to spend, which is the whole of what CSRF is, and it was never
// issued a token to send back. Asking it for one turns the gate into an
// outage on the JMAP bearer path rather than a defense, so the shape that
// must keep working is measured next to the shape that must not.
//
// Each request comes from its own reader, because a jar that absorbed the
// double submit cookie off one response would send it on the next and the
// caller would stop being cookieless halfway through the check.
async function testACookielessBearerClientIsStillServed(origin, caPem, accountId) {
  var bearer = { Authorization: "Bearer not-a-real-token", "X-CSRF-Token": "" };

  var probed = await browser.browserAt(origin, { ca: caPem })
    .get("/jmap/session", bearer);
  count("a cookieless bearer client is not turned away by the CSRF gate on the session " +
    "document", probed.body.indexOf("CSRF") === -1,
    probed.status + " " + probed.body.slice(0, 120));

  var called = await browser.browserAt(origin, { ca: caPem })
    .post("/jmap/api", "application/json",
      JSON.stringify({ using: [], methodCalls: [["Mailbox/get", { accountId: accountId }, "c0"]] }),
      Object.assign({ Accept: "application/json" }, bearer));
  count("nor on a state changing method call, which is the path the waiver is for",
    called.body.indexOf("CSRF") === -1, called.status + " " + called.body.slice(0, 120));

  var posted = await browser.browserAt(origin, { ca: caPem })
    .post("/prefs/theme", "application/x-www-form-urlencoded", "theme=dark", bearer);
  count("and not on a rendered route either, so the waiver did not narrow to one mount",
    posted.body.indexOf("CSRF") === -1, posted.status + " " + posted.body.slice(0, 120));
}

// What the waiver above must NOT carry with it: the origin cross check.
//
// The two are separate defenses and only one of them is answered by "this
// caller has no ambient credential to spend". The token compare is: a
// client that was never issued a token cannot send one back, so requiring
// it would be an outage rather than a defense, which is the whole reason
// the waiver exists. The origin check is not. It refuses a state change
// arriving from somewhere this server does not serve, and a request
// carrying no cookie is not thereby a request from an origin this server
// should act for.
//
// So the shape here is the cookieless bearer client of the case above with
// one thing changed: it names another site as its origin. Everything that
// made the previous case legitimate still holds, and the request still has
// to be refused, because what it is asking for is a cross origin state
// change and no reading of "stateless" makes one acceptable.
//
// A reader of its own, for the reason the case above gives: a jar holding
// the double submit cookie would make this a cookie-carrying request and it
// would be refused for the ordinary reason instead of the one under test.
async function testACookielessBearerClientIsStillHeldToTheOriginCheck(origin, caPem) {
  var crossOrigin = {
    Authorization:  "Bearer not-a-real-token",
    "X-CSRF-Token": "",
    Origin:         FOREIGN_ORIGIN,
  };

  var posted = await browser.browserAt(origin, { ca: caPem })
    .post("/prefs/theme", "application/x-www-form-urlencoded", "theme=dark", crossOrigin);
  count("a cookieless bearer client asking for a state change from another origin is " +
    "refused, because the waiver covers the token compare and never the origin check",
    posted.status === 403, posted.status + " " + posted.body.slice(0, 160));
  count("and the refusal names the origin cross check rather than the token compare, " +
    "which is the check that has to have answered here",
    posted.body.indexOf("cross-origin request refused") !== -1, posted.body.slice(0, 160));

  // The same on the JMAP mount, because that is the surface the waiver was
  // put in for and a rule that held only on the rendered routes would be
  // absent from exactly the path that needs it.
  var called = await browser.browserAt(origin, { ca: caPem })
    .post("/jmap/api", "application/json",
      JSON.stringify({ using: [], methodCalls: [] }),
      Object.assign({ Accept: "application/json" }, crossOrigin));
  count("and a cross origin JMAP method call is refused on the same terms, so the rule " +
    "reaches the mount the waiver exists for",
    called.status === 403, called.status + " " + called.body.slice(0, 160));
}

// ---- the bot guard ----------------------------------------------------------

async function testAnAutomationAgentIsRefused(origin, caPem) {
  var robot = browser.browserAt(origin, { ca: caPem, userAgent: AUTOMATION_AGENT });
  // Four route classes, because the guard is mounted on the chain and a
  // guard on the rendered pages alone leaves the API and the probe open
  // to exactly the traffic it was mounted for.
  var paths = ["/sign-in", "/mail?folder=INBOX", "/jmap/session", "/healthz"];
  for (var i = 0; i < paths.length; i += 1) {
    var answer = await robot.get(paths[i]);
    count("an automation agent is refused on " + paths[i],
      answer.status === 403, answer.status + " " + answer.body.slice(0, 80));
  }

  // The differential. A guard that refused every agent string would pass
  // every assertion above and would also be a server no browser reaches.
  var human = browser.browserAt(origin, { ca: caPem });
  var served = await human.get("/sign-in");
  count("a browser agent string is served the same page",
    served.status === 200 && served.body.indexOf("_csrf") !== -1,
    served.status + " " + served.body.slice(0, 80));

  // The other differential, and the one that decides whether this guard
  // can stay as strict as it is. The container health check polls the
  // probe from inside the container with the runtime's own client, whose
  // agent string is the runtime's name. If that were ever read as
  // automation the container would report itself unhealthy and be
  // restarted forever, and the repair someone would reach for is an
  // exemption on the probe path, which is a hole in the guard. Pinning
  // it here means the guard is measured against the one caller it must
  // not refuse, so the exemption never becomes tempting.
  var probe = browser.browserAt(origin, { ca: caPem, userAgent: "node" });
  var polled = await probe.get("/healthz");
  count("the runtime's own client still reaches the health probe",
    polled.status === 200, polled.status + " " + polled.body.slice(0, 80));
}

// ---- cookie prefixes --------------------------------------------------------

// RFC 6265bis section 4.1.3 puts three conditions on a `__Host-` name
// and a browser drops the cookie when any of them is missing. A cookie
// issued with the prefix and without them is worse than one issued
// without the prefix: the double submit token silently never persists,
// and the gate that reads it starts refusing requests for a reason
// nothing reports.
//
// The session cookie's own attributes are read in
// test/layer-1-state/server-console-isolation.test.js. This is the other
// cookie on the same response, whose name the framework resolves from
// the request scheme rather than from a constant, so it is the one that
// changes shape when the transport does.
function testTheCsrfCookieCarriesTheHostPrefix(page) {
  var written = page.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-csrf=") === 0;
  });
  count("the sign in page issues the double submit cookie under a host prefixed name",
    written.length === 1,
    JSON.stringify(page.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (written.length !== 1) return;

  var attributes = String(written[0]);
  count("it is Secure, which the prefix requires",
    /;\s*Secure/i.test(attributes), attributes.slice(-120));
  count("it is scoped to the whole origin, which the prefix requires",
    /;\s*Path=\/(?:;|$)/i.test(attributes), attributes.slice(-120));
  count("it carries no Domain attribute, which the prefix also requires",
    !/;\s*Domain=/i.test(attributes), attributes.slice(-120));
  // The value matters as much as the attributes. The gate accepts a
  // sixty four character hex token and refuses anything shorter, so a
  // cookie issued with a truncated value would be a cookie the compare
  // can never match, and every state change would fail for a reason
  // nothing reports.
  count("its value is the full width token the double submit compare accepts",
    /^__Host-csrf=[a-f0-9]{64}(?:;|$)/.test(attributes), attributes.slice(0, 90));
}

// ---- Trusted Types ----------------------------------------------------------

var TRUSTED_TYPES = "require-trusted-types-for 'script'";

function policyCarriesTrustedTypes(response, what) {
  var policy = String(response.headers["content-security-policy"] || "");
  count("the policy on " + what + " requires typed values at every DOM sink",
    policy.indexOf(TRUSTED_TYPES) !== -1,
    response.status + " " + (policy.length === 0 ? "<no policy>" : policy.slice(-140)));
}

// Every class of response this application produces, because the
// directive travels on a header and a route that writes its own headers
// is a route that can write them without this one. The refusal bodies
// are in the list for the same reason: an error path is the one nobody
// looks at, and it renders into the same browser.
// One policy, split into the directives it names, so two policies can be
// compared directive by directive rather than as one string.
function _directives(policy) {
  var out = {};
  String(policy).split(";").forEach(function (part) {
    var text = part.trim();
    if (text.length === 0) return;
    var space = text.indexOf(" ");
    if (space === -1) { out[text] = ""; return; }
    out[text.slice(0, space)] = text.slice(space + 1).trim();
  });
  return out;
}

async function testEveryResponseClassRequiresTrustedTypes(reader, target) {
  policyCarriesTrustedTypes(await reader.get("/sign-in"), "a rendered page");
  var authenticated = await reader.get("/mail?folder=INBOX");
  policyCarriesTrustedTypes(authenticated, "an authenticated page");
  policyCarriesTrustedTypes(await reader.get("/static/blamepost.css"), "a static asset");
  policyCarriesTrustedTypes(await reader.get("/healthz"), "the health probe");
  policyCarriesTrustedTypes(await reader.get("/.well-known/mta-sts.txt"),
    "a well known document");
  policyCarriesTrustedTypes(await reader.get("/nowhere-at-all"), "a not found page");
  policyCarriesTrustedTypes(
    await reader.post("/mail/actions?folder=INBOX", "application/x-www-form-urlencoded",
      "action=flag", { "X-CSRF-Token": "" }),
    "a refusal body");
  policyCarriesTrustedTypes(
    await reader.jmap([["Mailbox/get", { accountId: target.accountId }, "c0"]]),
    "a JMAP answer");

  // The one route in this application that writes a policy of its own,
  // which is where the directive is spelled out by hand and therefore
  // where it can be left out.
  var widened = await reader.get("/mail/" +
    encodeURIComponent(target.objectId) + "?folder=INBOX&images=on");
  policyCarriesTrustedTypes(widened, "the response that widens the image policy");
  var widenedPolicy = String(widened.headers["content-security-policy"] || "");
  count("that response really is the widened one rather than the default",
    widenedPolicy.indexOf("img-src 'self' data: https:") !== -1,
    widenedPolicy.slice(0, 160));

  // The widened policy is written out by hand, one directive at a time,
  // beside a default the framework composes. Two policies written in two
  // places drift, and the drift that matters is not the directive being
  // widened: it is one of the other eleven arriving looser than the
  // default and nobody reading past `img-src`. So the pair is compared
  // directive by directive, and the reader asking to see the images buys
  // exactly the images.
  var defaultPolicy = String(authenticated.headers["content-security-policy"] || "");
  var base = _directives(defaultPolicy);
  var wide = _directives(widenedPolicy);
  var baseNames = Object.keys(base).sort();
  var wideNames = Object.keys(wide).sort();

  count("the default policy was read, so the comparison below answers for something",
    baseNames.length > 0, defaultPolicy.slice(0, 200));
  count("asking for images adds no directive and drops none",
    baseNames.join(" ") === wideNames.join(" "),
    JSON.stringify([baseNames, wideNames]));

  var moved = baseNames.filter(function (name) { return base[name] !== wide[name]; });
  count("and exactly one directive says anything different, which is the image source",
    moved.length === 1 && moved[0] === "img-src", JSON.stringify(moved));
  count("every other directive is the default's, character for character",
    moved.filter(function (name) { return name !== "img-src"; }).length === 0,
    JSON.stringify(moved.map(function (n) { return n + ": " + base[n] + " -> " + wide[n]; })));

  // What the widened `img-src` gained, and what it did not. `https:` is
  // an image loading from wherever the sender pointed, which is what the
  // reader asked for; a source expression admitting script is not.
  count("the image source gained a transport and nothing that can run",
    wide["img-src"] === base["img-src"] + " https:",
    JSON.stringify([base["img-src"], wide["img-src"]]));
  count("neither policy admits inline script, which is the fallback under every " +
    "attribute the message body is screened for",
    String(base["script-src"]).indexOf("unsafe-inline") === -1 &&
    String(wide["script-src"]).indexOf("unsafe-inline") === -1 &&
    String(base["script-src"]).indexOf("unsafe-eval") === -1 &&
    String(wide["script-src"]).indexOf("unsafe-eval") === -1,
    JSON.stringify([base["script-src"], wide["script-src"]]));
}

// ---- the message body a sender wrote ----------------------------------------

// The conversation page is the one place this application interpolates
// markup it did not build. Every other value is escaped on the way out;
// the body of a message is not, because a message that renders as its own
// source is not mail anybody can read. So the screening happens before the
// value reaches the page, and this is where that is measured.
//
// It is measured over the WIRE, on a message that arrived through the
// store, on the route a reader opens. The screening is composed in one
// place and called from another, and every check that reads the policy
// out of the source or calls the framework's sanitizer directly stays
// green if the route stops reaching it: what those pin is the policy, and
// what this pins is that the response carries it. Those are different
// questions and the second is the one a reader is exposed to.
//
// The vectors are the encodings that have carried a scheme past a
// sanitizer folding less than a browser does, plus the two differentials
// that stop this from being satisfied by a page rendering nothing: an
// ordinary off-site link in a body is legitimate mail and survives, and a
// good target beside a dropped handler survives with the handler gone.

var BODY_TAB = String.fromCharCode(9);
var BODY_NUL = String.fromCharCode(0);

// Attribute, value, for every attribute a browser resolves as a URL.
function urlAttrsIn(html) {
  var out = [];
  var re = /\b(href|src|cite|action|formaction|poster|srcdoc|srcset)\s*=\s*"([^"]*)"/gi;
  var m;
  while ((m = re.exec(html)) !== null) out.push(m[1].toLowerCase() + "=" + m[2]);
  return out;
}

// The rendered bodies on a conversation page, lifted out of the element
// the template puts them in.
function letterBodies(page) {
  var html = String(page);
  var out = [];
  var re = /<div class="letter-body[^"]*">/g;
  var m;
  while ((m = re.exec(html)) !== null) {
    var from = m.index + m[0].length;
    var depth = 1;
    var at = from;
    while (depth > 0) {
      var open  = html.indexOf("<div", at);
      var close = html.indexOf("</div>", at);
      if (close === -1) break;
      if (open !== -1 && open < close) { depth += 1; at = open + 4; continue; }
      depth -= 1;
      at = close + 6;
      if (depth === 0) out.push(html.slice(from, close));
    }
  }
  return out;
}

var HOSTILE_BODIES = [
  ["a scripting scheme on a link",
    "<a href=\"javascript:alert(1)\">click</a>", "click"],
  ["a document inlined as a scheme",
    "<a href=\"data:text/html,<script>alert(1)</script>\">click</a>", "click"],
  ["a scripting scheme on an image",
    "<img src=\"javascript:alert(1)\">", ""],
  ["a character reference for a tab inside the scheme",
    "<a href=\"java&#9;script:alert(1)\">click</a>", "click"],
  ["a literal tab inside the scheme",
    "<a href=\"java" + BODY_TAB + "script:alert(1)\">click</a>", "click"],
  ["a null inside the scheme",
    "<a href=\"java" + BODY_NUL + "script:alert(1)\">click</a>", "click"],
  ["a named reference for the colon",
    "<a href=\"javascript&colon;alert(1)\">click</a>", "click"],
  ["a script element of its own",
    "<script>alert(1)</script>", ""],
  ["a document redirected wholesale",
    "<base href=\"https://evil.example/\">", ""],
  ["an animation retargeting a good link",
    "<svg><a href=\"/ok\"><animate attributeName=\"href\" values=\"javascript:alert(1)\"/>" +
    "</a></svg>", ""],
  ["a nested document",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", ""],
];

function htmlBodyMessage(recipient, index, payload) {
  return Buffer.from(
    "Message-ID: <body" + index + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: body vector " + index + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "\r\n" + payload + "\r\n", "utf8");
}

function textBodyMessage(recipient, payload) {
  return Buffer.from(
    "Message-ID: <bodytext@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: body vector text\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" + payload + "\r\n", "utf8");
}

// The markup a plain text body is turned into. It is the SECOND producer
// feeding the same un-escaped tag, it is assembled by concatenation, and
// the only thing between a sender's angle bracket and the page is the
// escape in the middle of that concatenation.
var TEXT_BODY_PAYLOAD =
  "<script>alert(1)</script> & \"quoted\" <a href=\"javascript:alert(2)\">x</a>";

async function testAHostileMessageBodyRendersInert(reader, bodies) {
  count("the vectors reached the store, so this section answers for something",
    bodies.length === HOSTILE_BODIES.length,
    bodies.length + " of " + HOSTILE_BODIES.length);

  for (var i = 0; i < bodies.length; i += 1) {
    var vector = HOSTILE_BODIES[i];
    var at = "/mail/" + encodeURIComponent(bodies[i].objectId) + "?folder=INBOX";

    var page = await reader.get(at);
    var rendered = letterBodies(page.body).join("");
    count("the reader's page carries a rendered body for " + vector[0],
      page.status === 200, page.status + " " + rendered.slice(0, 120));
    count("a message body cannot reach the page with " + vector[0],
      urlAttrsIn(rendered).length === 0, JSON.stringify(rendered));
    count("and nothing the sender wrote survives as markup the browser would run: " +
      vector[0],
      rendered.indexOf("<script") === -1 && rendered.indexOf("javascript:") === -1 &&
      rendered.indexOf("srcdoc") === -1 && rendered.indexOf("<base") === -1,
      JSON.stringify(rendered));
    if (vector[2].length > 0) {
      count("while what the sender actually wrote is still readable: " + vector[0],
        rendered.indexOf(vector[2]) !== -1, JSON.stringify(rendered));
    }

    // The reader asking to see the images widens the tag set. It must not
    // widen the schemes, and this is the route that writes its own
    // response, so it is driven rather than assumed to share the first.
    var shown = await reader.get(at + "?images=on");
    var shownBody = letterBodies(shown.body).join("");
    count("asking for the images does not re-admit " + vector[0],
      urlAttrsIn(shownBody).length === 0, JSON.stringify(shownBody));
  }
}

// The differentials. A surface that rendered every body as nothing would
// satisfy every check above and would also be a mail client that cannot
// show mail.
async function testAnOrdinaryMessageBodyStillRenders(reader, ordinary, handler, textObjectId) {
  var page = await reader.get("/mail/" + encodeURIComponent(ordinary) + "?folder=INBOX");
  var rendered = letterBodies(page.body).join("");
  count("a message may still link off site, which is what ordinary mail does",
    rendered.indexOf("href=\"https://example.net/page\"") !== -1, JSON.stringify(rendered));

  var beside = await reader.get("/mail/" + encodeURIComponent(handler) + "?folder=INBOX");
  var besideBody = letterBodies(beside.body).join("");
  count("a handler beside a good target is dropped and the target is kept",
    besideBody.indexOf("href=\"/ok\"") !== -1 &&
    besideBody.toLowerCase().indexOf("onclick") === -1 &&
    besideBody.indexOf("style") === -1, JSON.stringify(besideBody));

  // The plain text path reaches the same un-escaped tag by another road.
  var text = await reader.get("/mail/" + encodeURIComponent(textObjectId) + "?folder=INBOX");
  var textBody = letterBodies(text.body).join("");
  count("a plain text body reaches the page as text rather than as markup",
    textBody.indexOf("&lt;script&gt;") !== -1 && textBody.indexOf("<script") === -1,
    JSON.stringify(textBody));
  count("and every character the markup parser reads is escaped in it",
    textBody.indexOf("&amp;") !== -1 && textBody.indexOf("&quot;") !== -1 &&
    urlAttrsIn(textBody).length === 0, JSON.stringify(textBody));
}

// ---- encrypted sessions -----------------------------------------------------

// The identifier the server keeps and the value the browser holds are
// not the same bytes. A reader who could read the cookie off a proxy
// log, a browser profile or a shoulder should not be holding anything
// the session table can be looked up by.
async function testTheSessionTokenOnTheWireIsSealed(landing, reader) {
  var written = landing.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-bp_session=") === 0;
  });
  count("signing in writes exactly one session cookie", written.length === 1,
    JSON.stringify(landing.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (written.length !== 1) return;

  var value = decodeURIComponent(String(written[0]).split(";")[0].split("=").slice(1).join("="));
  count("the value the browser carries is sealed rather than the identifier itself",
    value.indexOf("vault:") === 0, value.slice(0, 48));
  count("it is an envelope rather than a token with a label glued to it",
    value.length > 512, String(value.length));
  count("nothing about the account is legible in it",
    value.indexOf(READER_LOCAL) === -1 && value.indexOf(DOMAIN) === -1,
    value.slice(0, 96));

  // And it still authenticates, so the sealing is a property of what
  // ships rather than of a cookie that stopped working.
  var page = await reader.get("/mail?folder=INBOX");
  count("the sealed cookie is what the reader is signed in with",
    page.status === 200, page.status + " " + String(page.location));
}

// ---- sealed storage ---------------------------------------------------------

// Every file under a directory, read whole, with the count of what was
// read carried back. The counts are the point: a search that finds
// nothing because it opened nothing is indistinguishable from a search
// that found nothing because there was nothing to find, and only one of
// those is the guarantee.
function scanTree(dir, needles, found) {
  var entries;
  try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return found; }
  for (var i = 0; i < entries.length; i += 1) {
    var full = nodePath.join(dir, entries[i].name);
    if (entries[i].isDirectory()) { scanTree(full, needles, found); continue; }
    var bytes;
    try { bytes = nodeFs.readFileSync(full); }
    catch (_e) { continue; }
    found.files += 1;
    found.bytes += bytes.length;
    for (var n = 0; n < needles.length; n += 1) {
      if (bytes.indexOf(Buffer.from(needles[n], "utf8")) !== -1) {
        found.hits.push(needles[n].slice(0, 48) + " in " + nodePath.basename(full));
      }
    }
  }
  return found;
}

function emptyScan() { return { files: 0, bytes: 0, hits: [] }; }

// Read while the store is open, so the run knows the values it looks for
// afterwards were really written. A volume that never received them
// holds no cleartext copy of them either, and would pass the scan for
// the wrong reason.
async function testTheSealedValuesWereReallyWritten(identity, accountId) {
  var account = await identity.accounts.get(accountId);
  count("the account holds the address the scan looks for",
    account !== null && account.address === READER_ADDRESS,
    account === null ? "no account" : String(account.address));
  count("and the display name",
    account !== null && account.displayName === READER_NAME,
    account === null ? "no account" : String(account.displayName));
}

// Read after the store closes, so what is measured is the volume an
// operator backs up, copies or loses, rather than a process still
// holding the key.
function testNothingReadableIsLeftOnDisk(dataDir, workDir) {
  var sealed = [READER_ADDRESS, READER_NAME, SUBJECT, BODY];
  var found = scanTree(dataDir, sealed.concat([CLEARTEXT_CANARY]), emptyScan());

  count("the scan read the whole volume rather than an empty directory",
    found.files >= 5 && found.bytes > 100000,
    found.files + " files, " + found.bytes + " bytes");
  count("it can see cleartext, proven on the certificate the operator supplied",
    found.hits.filter(function (h) { return h.indexOf(CLEARTEXT_CANARY) === 0; }).length === 1,
    JSON.stringify(found.hits));

  var leaked = found.hits.filter(function (h) { return h.indexOf(CLEARTEXT_CANARY) !== 0; });
  count("no address, name, subject or body survives in any byte of the volume",
    leaked.length === 0, JSON.stringify(leaked));

  // The framework keeps its working copy of the database outside the
  // volume while the process runs. A copy left behind is the same
  // disclosure by another path, and it is the one an operator would
  // never think to look for.
  var working = scanTree(workDir, sealed, emptyScan());
  count("the decrypted working copy does not outlive the process that opened it",
    working.files === 0 && working.hits.length === 0,
    working.files + " files, " + JSON.stringify(working.hits));
}

// ---- the drive --------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-posture");
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
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var reader = await identity.accounts.create({
      address:     READER_ADDRESS,
      password:    READER_PASSWORD,
      displayName: READER_NAME,
    });
    var stored = identity.mailbox.appendMessage("INBOX", messageFor(READER_ADDRESS),
      { actor: { id: reader.id } });
    var inbox = identity.mailbox.accountFolders({ id: reader.id })
      .filter(function (row) { return row.name === "INBOX"; })[0];
    count("the account holds an inbox with the message the vectors act on",
      inbox !== undefined && typeof stored.objectid === "string",
      JSON.stringify([inbox && inbox.name, stored && stored.objectid]));

    // The bodies the sender wrote, delivered the way any other message
    // arrives, so the page under test renders a row the store sealed
    // rather than a string handed to a renderer.
    var bodies = HOSTILE_BODIES.map(function (vector, index) {
      return {
        objectId: identity.mailbox.appendMessage("INBOX",
          htmlBodyMessage(READER_ADDRESS, index, vector[1]),
          { actor: { id: reader.id } }).objectid,
      };
    });
    var ordinaryObjectId = identity.mailbox.appendMessage("INBOX",
      htmlBodyMessage(READER_ADDRESS, "ordinary",
        "<a href=\"https://example.net/page\">click</a>"),
      { actor: { id: reader.id } }).objectid;
    var handlerObjectId = identity.mailbox.appendMessage("INBOX",
      htmlBodyMessage(READER_ADDRESS, "handler",
        "<a href=\"/ok\" onclick=\"alert(1)\" style=\"width:expression(alert(1))\">click</a>"),
      { actor: { id: reader.id } }).objectid;
    var textObjectId = identity.mailbox.appendMessage("INBOX",
      textBodyMessage(READER_ADDRESS, TEXT_BODY_PAYLOAD),
      { actor: { id: reader.id } }).objectid;

    await testTheSealedValuesWereReallyWritten(identity, reader.id);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only transport the " +
      "session cookie travels over", typeof bound.https === "number" && bound.https > 0,
      JSON.stringify(bound));

    var origin = "https://" + LOOPBACK + ":" + bound.https;
    // Read through the composed server rather than built beside it, so a
    // write the surface refused is checked against the same substrate the
    // surface would have written to.
    var agentHandle = server.mail.agent;
    count("the run holds the mail agent, so a refused write can be read back",
      agentHandle !== undefined && agentHandle !== null &&
      typeof agentHandle.fetch === "function", typeof agentHandle);

    var session = browser.browserAt(origin, { ca: material.caPem });
    var form = await session.readCsrf("/sign-in");
    count("the sign in form carries a token for the reader to send back",
      form.token.length === 64, form.page.status + " " + JSON.stringify(form.token));
    testTheCsrfCookieCarriesTheHostPrefix(form.page);

    var landing = await session.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the reader is signed in", landing.status === 302,
      landing.status + " " + landing.body.slice(0, 160));
    await testTheSessionTokenOnTheWireIsSealed(landing, session);

    var target = {
      accountId:   reader.id,
      storeFolder: inbox.storeName,
      objectId:    stored.objectid,
    };
    var routes = stateChangingRoutes(reader.id, "INBOX");

    await testTheCsrfGateRefusesAStateChangeWithoutAToken(session, routes, target, agentHandle);
    await testAForeignOriginIsRefusedWithAValidToken(session, routes, origin);
    await testACrossSiteStateChangeIsRefused(session, routes, origin);
    await testANativeFormSubmitIsAccepted(session, routes, origin, target, agentHandle);
    await testTheServedPolicyLeavesTheOriginReadable(session, origin, material.caPem);

    // Everything above rides HTTP/1.1. This drives the same journey over
    // the version a browser negotiates against this listener, which is
    // the only version a person's requests ever take.
    var overHttp2 = await testTheJourneyHoldsOverTheVersionABrowserNegotiates(
      origin, material.caPem, target);
    testTheCookiePostureHoldsOverHttp2(
      await browser.browserAt(origin, { ca: material.caPem, http2: true })
        .readCsrf("/sign-in").then(function (r) { return r.page; }),
      await browser.browserAt(origin, { ca: material.caPem, http2: true })
        .signIn(READER_ADDRESS, READER_PASSWORD));
    count("the HTTP/2 reader is still signed in after the differentials, so the " +
      "refusals above did not take the session with them",
      (await overHttp2.get("/mail?folder=INBOX")).status === 200, "checked");

    await testAnAuthorizationHeaderDoesNotOpenACrossSitePath(session, routes, target, agentHandle);
    await testACookielessBearerClientIsStillServed(origin, material.caPem, reader.id);
    await testACookielessBearerClientIsStillHeldToTheOriginCheck(origin, material.caPem);
    await testTheSameActionWorksWithItsToken(session, target, agentHandle);
    await testEveryResponseClassRequiresTrustedTypes(session, target);
    await testAHostileMessageBodyRendersInert(session, bodies);
    await testAnOrdinaryMessageBodyStillRenders(session, ordinaryObjectId, handlerObjectId,
      textObjectId);
    await testAnAutomationAgentIsRefused(origin, material.caPem);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    identity.close();
    identity = null;

    testNothingReadableIsLeftOnDisk(dataDir, workDir);

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

module.exports = { name: "web-security-posture", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
