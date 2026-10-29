// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The public paths, driven as a way around the gates on everything else.
 *
 * Three decisions on the request lifecycle are keyed on a path rather than
 * on a route. The cache middleware skips `/robots.txt`, `/sitemap.xml` and
 * anything under `/static/`. The badge route declares
 * `Cross-Origin-Resource-Policy: cross-origin` where every other response
 * carries `same-origin`. And the front page answers a stranger instead of
 * sending them to sign in. A path decision is a bypass when the string it
 * compares and the route the router dispatches can be made to disagree,
 * so every vector here is a request target built to make them disagree,
 * sent to the real listener, and the answer that comes back is read for
 * which route produced it.
 *
 * What is measured:
 *
 *   - the bot guard refuses an automation agent on every public path, and
 *     a crawler agent is served on every one of them;
 *   - a dot segment, a backslash or a percent-encoded dot after a public
 *     path reaches the authenticated route it names, and that route's own
 *     gate answers;
 *   - an encoded slash, an encoded backslash and an encoded NUL are
 *     refused before any route is chosen;
 *   - a signed-in page reached through a target that begins with an
 *     exempt prefix still carries the per-reader cache directive, so the
 *     cache middleware reads the dispatched path rather than the raw one;
 *   - a page that names the signed-in account and is served under an
 *     exempt path is still kept out of shared caches;
 *   - the cross-origin resource policy is relaxed on the badge alone, on
 *     no spelling of a neighboring path, and not at all while the site is
 *     withdrawn;
 *   - a state change sent to a public path is still refused for its
 *     origin and for a cross-site fetch;
 *   - the crawler documents and the front page name no hosted domain and
 *     no account address.
 *
 * Run standalone: node test/layer-2-integration/public-site-path-exemptions.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var SETTING  = "publicSiteEnabled";

// A hosted domain that shares no label with the MX hostname, so finding
// it in a public document can only mean the document named the domain.
var DOMAIN          = "quillhaven.example.net";
var READER_LOCAL    = "brindlewick";
var READER_ADDRESS  = READER_LOCAL + "@" + DOMAIN;
var READER_PASSWORD = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 5000;

var CRAWLER_AGENT    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
var AUTOMATION_AGENT = "curl/8.4.0";
var FOREIGN_ORIGIN   = "https://attacker.example.net";

var PUBLIC_PATHS = Object.freeze(["/", "/robots.txt", "/sitemap.xml", "/badge.svg"]);

var CROSS_SITE_SUBMIT = Object.freeze({
  "Sec-Fetch-Site": "cross-site",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Dest": "document",
});

function corpOf(answer) {
  return String(answer.headers["cross-origin-resource-policy"] || "");
}

function varyOf(answer) {
  return String(answer.headers.vary || "");
}

function cacheControlOf(answer) {
  return String(answer.headers["cache-control"] || "");
}

function wiringFor(cfg, identity) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent:     b.mail.agent.create({ store: identity.messageStore, dispatch: { mode: "local" } }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.messageStore,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    address:   LOOPBACK,
    httpPort:  0,
    listeners: function () { return []; },
  };
}

async function publish(identity, value) {
  await identity.settings.set({
    name: SETTING, value: value, changedBy: "operator@example.com",
    reason: value ? "publishing the front page for this run" : "withdrawing the front page for this run",
  });
}

// ---- while the site is withdrawn ---------------------------------------------

async function testTheBadgeIsNotRelaxedWhileWithdrawn(origin, when) {
  var badge = await browser.browserAt(origin, { userAgent: CRAWLER_AGENT }).get("/badge.svg");
  count("the badge answers 404 " + when, badge.status === 404, badge.status);
  count("and that answer keeps the same-origin resource policy " + when,
    corpOf(badge) === "same-origin", corpOf(badge));
  count("and it is not the image " + when,
    String(badge.headers["content-type"]).indexOf("image/svg+xml") === -1 &&
    badge.body.indexOf("<svg") === -1,
    String(badge.headers["content-type"]));
}

// The cache middleware skips these paths. The page each one answers a
// signed-in reader with when no route serves it names that reader, so the
// only thing keeping it out of a shared cache is the directive the render
// writes. Both halves are read: the page is personal, and it is private.
async function testAPersonalPageUnderAnExemptPathStaysPrivate(reader) {
  var paths = ["/sitemap.xml", "/static/absent-probe.css", "/static/%252e%252e/mail/INBOX"];
  for (var i = 0; i < paths.length; i += 1) {
    var answer = await reader.get(paths[i]);
    count("a signed-in request for " + paths[i] + " is answered with a page naming the account",
      answer.status === 404 && answer.body.indexOf(READER_ADDRESS) !== -1,
      answer.status + " " + answer.body.slice(0, 80));
    count("and that page forbids a shared cache from storing it",
      /\bprivate\b/.test(cacheControlOf(answer)) && !/\bpublic\b/.test(cacheControlOf(answer)),
      cacheControlOf(answer));
  }
}

// ---- while the site is published ---------------------------------------------

async function testTheBotGuardHasNoPublicPathExemption(origin) {
  var robot   = browser.browserAt(origin, { userAgent: AUTOMATION_AGENT });
  var crawler = browser.browserAt(origin, { userAgent: CRAWLER_AGENT });
  for (var i = 0; i < PUBLIC_PATHS.length; i += 1) {
    var refused = await robot.get(PUBLIC_PATHS[i]);
    count("an automation agent is refused on the public path " + PUBLIC_PATHS[i],
      refused.status === 403, refused.status + " " + refused.body.slice(0, 60));
    var served = await crawler.get(PUBLIC_PATHS[i]);
    count("and a crawler agent is served on it",
      served.status === 200, served.status + " " + served.body.slice(0, 60));
  }
}

async function testTheResourcePolicyIsRelaxedOnTheBadgeAlone(origin) {
  var reader = browser.browserAt(origin, { userAgent: CRAWLER_AGENT });
  var badge = await reader.get("/badge.svg");
  count("the badge is served as an image any site may embed",
    badge.status === 200 && corpOf(badge) === "cross-origin" &&
    String(badge.headers["content-type"]).indexOf("image/svg+xml") === 0,
    badge.status + " " + corpOf(badge) + " " + badge.headers["content-type"]);

  var others = ["/", "/robots.txt", "/sitemap.xml"];
  for (var i = 0; i < others.length; i += 1) {
    var answer = await reader.get(others[i]);
    count("the public document " + others[i] + " keeps the same-origin resource policy",
      answer.status === 200 && corpOf(answer) === "same-origin",
      answer.status + " " + corpOf(answer));
  }

  var neighbors = ["/badge.svg/", "/badge.svg;/admin", "/Badge.svg", "/badge.svg.",
    "/badge.svg/../mail/INBOX"];
  for (var j = 0; j < neighbors.length; j += 1) {
    var near = await reader.get(neighbors[j]);
    count("a target spelled near the badge, " + JSON.stringify(neighbors[j]) +
      ", keeps the same-origin resource policy",
      corpOf(near) === "same-origin" && near.body.indexOf("<svg") === -1,
      near.status + " " + corpOf(near));
  }
}

// A stranger asking for an authenticated route through a public path. The
// route the router dispatches has to be the authenticated one, and its gate
// has to be the thing that answers.
async function testAPublicPathPrefixDoesNotReachPastTheSignInGate(origin) {
  var stranger = browser.browserAt(origin, { userAgent: CRAWLER_AGENT });
  var targets = [
    "/robots.txt/../admin",
    "/sitemap.xml/../mail/INBOX",
    "/badge.svg/../admin/accounts",
    "/robots.txt\\..\\admin",
    "/static/../admin",
    "/static/%2E%2E/mail/INBOX",
    "/static/.%2e/admin/dkim",
  ];
  for (var i = 0; i < targets.length; i += 1) {
    var answer = await stranger.get(targets[i]);
    count("a stranger at " + JSON.stringify(targets[i]) + " is sent to sign in",
      answer.status === 302 && answer.location === "/sign-in",
      answer.status + " " + answer.location + " " + answer.body.slice(0, 60));
  }
}

async function testEncodedSeparatorsAreRefusedBeforeDispatch(origin) {
  var stranger = browser.browserAt(origin, { userAgent: CRAWLER_AGENT });
  var targets = [
    "/robots.txt%2F..%2Fadmin",
    "/sitemap.xml%2f..%2fmail%2fINBOX",
    "/badge.svg%5C..%5Cadmin",
    "/robots.txt%00",
    "/static%2F..%2Fadmin",
  ];
  for (var i = 0; i < targets.length; i += 1) {
    var answer = await stranger.get(targets[i]);
    count("the target " + JSON.stringify(targets[i]) + " is refused as malformed",
      answer.status === 400, answer.status + " " + answer.body.slice(0, 80));
  }
}

// The cache middleware compares `req.pathname`. A signed-in page reached
// through a target that starts with an exempt prefix has to carry the
// per-reader directive the middleware writes, or the exemption followed
// the raw bytes rather than the page that was served.
async function testTheCacheExemptionFollowsTheDispatchedPage(reader) {
  var targets = [
    "/static/%2E%2E/mail?folder=INBOX",
    "/static\\..\\mail?folder=INBOX",
    "/robots.txt/../mail?folder=INBOX",
    "/sitemap.xml/../mail?folder=INBOX",
  ];
  for (var i = 0; i < targets.length; i += 1) {
    var answer = await reader.get(targets[i]);
    count("a signed-in reader at " + JSON.stringify(targets[i]) + " is served their mailbox",
      answer.status === 200 && answer.body.indexOf(READER_ADDRESS) !== -1,
      answer.status + " " + answer.body.slice(0, 60));
    count("and it carries the per-reader cache directive rather than the exemption",
      /\bCookie\b/.test(varyOf(answer)) && /\bprivate\b/.test(cacheControlOf(answer)),
      JSON.stringify([varyOf(answer), cacheControlOf(answer)]));
  }
}

async function testAStateChangeOnAPublicPathIsStillRefused(origin, reader) {
  for (var i = 0; i < PUBLIC_PATHS.length; i += 1) {
    var foreign = await reader.form(PUBLIC_PATHS[i], { theme: "dark" }, { Origin: FOREIGN_ORIGIN });
    count("a post to " + PUBLIC_PATHS[i] + " from another origin is refused by the origin check",
      foreign.status === 403 && foreign.body.indexOf("cross-origin request refused") !== -1,
      foreign.status + " " + foreign.body.slice(0, 80));

    var crossSite = await reader.form(PUBLIC_PATHS[i], { theme: "dark" },
      Object.assign({ Origin: origin }, CROSS_SITE_SUBMIT));
    count("and a post to it that a browser reports as cross site is refused by fetch metadata",
      crossSite.status === 403 && crossSite.body.indexOf("Cross-site request refused") !== -1,
      crossSite.status + " " + crossSite.body.slice(0, 80));
  }
}

async function testThePublicDocumentsNameNoHostedIdentity(origin) {
  var stranger = browser.browserAt(origin, { userAgent: CRAWLER_AGENT });
  var documents = ["/", "/robots.txt", "/sitemap.xml"];
  for (var i = 0; i < documents.length; i += 1) {
    var answer = await stranger.get(documents[i]);
    count(documents[i] + " is served, so the search below reads a real document",
      answer.status === 200 && answer.body.length > 0, answer.status);
    count(documents[i] + " names no hosted domain and no account",
      answer.body.indexOf(DOMAIN) === -1 && answer.body.indexOf(READER_LOCAL) === -1,
      JSON.stringify(answer.body.slice(0, 120)));
  }

  var map = await stranger.get("/sitemap.xml");
  var locs = map.body.match(/<loc>[^<]*<\/loc>/g) || [];
  count("every sitemap entry is an address on the configured hostname",
    locs.length > 0 && locs.every(function (loc) {
      return loc.indexOf("<loc>https://" + HOSTNAME + ":") === 0 ||
        loc.indexOf("<loc>https://" + HOSTNAME + "/") === 0;
    }),
    JSON.stringify(locs));
}

async function run() {
  var root    = helpers.tempDir("pubpaths");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({ address: READER_ADDRESS, password: READER_PASSWORD });

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var reader = browser.browserAt(origin);
    var landed = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the reader signs in, so the signed-in vectors below measure a session",
      landed.status === 302 && landed.location === "/mail?folder=INBOX",
      landed.status + " " + landed.location);

    count("the shipped posture is that the front page is not published",
      cfg.publicSiteEnabled === false, String(cfg.publicSiteEnabled));
    await testTheBadgeIsNotRelaxedWhileWithdrawn(origin, "before the site is published");
    await testAPersonalPageUnderAnExemptPathStaysPrivate(reader);

    await publish(identity, true);
    await testTheBotGuardHasNoPublicPathExemption(origin);
    await testTheResourcePolicyIsRelaxedOnTheBadgeAlone(origin);
    await testAPublicPathPrefixDoesNotReachPastTheSignInGate(origin);
    await testEncodedSeparatorsAreRefusedBeforeDispatch(origin);
    await testTheCacheExemptionFollowsTheDispatchedPage(reader);
    await testAStateChangeOnAPublicPathIsStillRefused(origin, reader);
    await testThePublicDocumentsNameNoHostedIdentity(origin);

    await publish(identity, false);
    await testTheBadgeIsNotRelaxedWhileWithdrawn(origin, "after the site is withdrawn again");

    await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS });
    listener = null;
    return helpers.getChecks();
  } finally {
    if (listener) {
      try { await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS }); }
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

module.exports = { name: "public-site-path-exemptions", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
