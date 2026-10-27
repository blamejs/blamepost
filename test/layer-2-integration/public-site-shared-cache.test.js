// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The published public pages, read the way a shared cache reads them.
 *
 * `Cache-Control: public` tells every cache between a reader and this
 * server that it may store the response and hand the stored copy to the
 * next reader who asks for the same URL. RFC 9111 section 3.1 has such a
 * cache store the header fields along with the body, `Set-Cookie`
 * included, and a cache that honors `Vary: Cookie` still keys every
 * reader who arrives with no cookie at all onto one stored copy.
 *
 * So a response marked `public` has to be the same for every reader. The
 * public pages render the theme form, and that form carries the reader's
 * double submit token, and the request lifecycle issues that token's
 * cookie on the same response. A stored copy of one hands one reader's
 * token and cookie to the next reader, and to whoever primed the cache.
 *
 * The public pages are the front page and every page of the reference
 * wiki, and both render through the same site layout. The case reads the
 * front page and one wiki page of each kind the wiki builds (the index, a
 * module, a primitive, the specification index and one cited document),
 * each with two anonymous readers against the real listener, and compares
 * what the two were served. Every one of those pages is asserted to be
 * marked `private` and never `public`, and every wiki page is asserted to
 * carry the same `Cache-Control` value as the front page.
 *
 * It then signs a third reader in while it holds the first front-page
 * reader's token, and reports whether the pages behind the session still
 * carry that token, which says how long a token served from a stored copy
 * stays useful to whoever else holds it. A fourth reader signs in on its
 * own and reads a wiki page, which is served `private, no-store`, the
 * header every page behind a session carries.
 *
 * Everything observed is printed before anything is asserted, so a
 * failing run still records every value the verdict was taken from.
 *
 * Run standalone: node test/layer-2-integration/public-site-shared-cache.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var wiki      = require("../../lib/web/wiki");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SETTING  = "publicSiteEnabled";

var READER_ADDRESS  = "marrowby@" + DOMAIN;
var READER_PASSWORD = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 5000;

// The kinds of page the wiki builds, one sample of each read below.
var WIKI_KINDS = ["index", "module", "primitive", "specs", "spec"];

var CSRF_FIELD_RE = /name="_csrf" value="([^"]*)"/;

function tokenIn(body) {
  var found = CSRF_FIELD_RE.exec(String(body));
  return found === null ? null : found[1];
}

// The names of the cookies a response sets, without their values.
function cookieNames(setCookie) {
  return (setCookie || []).map(function (line) {
    return String(line).split(";")[0].split("=")[0].trim();
  });
}

// Whether a Cache-Control value lets a shared cache store the response.
// `private` and `no-store` both forbid it (RFC 9111 sections 5.2.2.5 and
// 5.2.2.7); `public` and `s-maxage` both permit it.
function sharedCacheMayStore(cacheControl) {
  var value = String(cacheControl || "").toLowerCase();
  if (/\bprivate\b/.test(value) || /\bno-store\b/.test(value)) return false;
  return /\bpublic\b/.test(value) || /\bs-maxage\s*=/.test(value);
}

// Whether a Cache-Control value carries `private` and does not carry
// `public`.
function markedPrivate(cacheControl) {
  var value = String(cacheControl || "").toLowerCase();
  return /\bprivate\b/.test(value) && !/\bpublic\b/.test(value);
}

// Where two bodies first differ, with a little of each side around it.
function firstDifference(left, right) {
  var limit = Math.min(left.length, right.length);
  var at = 0;
  while (at < limit && left.charAt(at) === right.charAt(at)) at += 1;
  if (at === limit && left.length === right.length) return "none";
  return "offset " + at + ": " + JSON.stringify(left.slice(Math.max(0, at - 40), at + 40)) +
    " against " + JSON.stringify(right.slice(Math.max(0, at - 40), at + 40));
}

// One wiki path for each kind of page, taken from the same build the
// server serves.
function wikiSamples() {
  var site = wiki.build();
  var byKind = {};
  site.paths().forEach(function (p) {
    var kind = site.page(p).kind;
    if (!Object.prototype.hasOwnProperty.call(byKind, kind)) byKind[kind] = p;
  });
  return byKind;
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

// One public page read by two anonymous readers, with everything the
// assertions read printed first.
async function observe(origin, path) {
  var first  = browser.browserAt(origin);
  var second = browser.browserAt(origin);
  var servedFirst  = await first.get(path);
  var servedSecond = await second.get(path);

  var cacheControl = String(servedFirst.headers["cache-control"] || "");
  var firstToken   = tokenIn(servedFirst.body);
  var secondToken  = tokenIn(servedSecond.body);
  var issued       = cookieNames(servedFirst.setCookie);
  var tokenCookie  = issued.length === 1 ? issued[0] : null;

  var masked = function (body, token) {
    return token === null ? body : body.split(token).join("<token>");
  };
  var o = {
    path:         path,
    first:        first,
    servedFirst:  servedFirst,
    servedSecond: servedSecond,
    cacheControl: cacheControl,
    shareable:    sharedCacheMayStore(cacheControl),
    firstToken:   firstToken,
    secondToken:  secondToken,
    issued:       issued,
    tokenCookie:  tokenCookie,
  };

  console.log("OBSERVED " + path + " status: " + servedFirst.status + ", " + servedSecond.status);
  console.log("OBSERVED " + path + " Cache-Control: " + JSON.stringify(cacheControl) +
    " (a shared cache may store it: " + o.shareable + ")");
  console.log("OBSERVED " + path + " Vary: " + JSON.stringify(servedFirst.headers.vary));
  console.log("OBSERVED " + path + " Set-Cookie names on the first reader's page: " +
    JSON.stringify(issued));
  console.log("OBSERVED " + path + " first reader token in body: " + firstToken +
    ", cookie: " + (tokenCookie === null ? null : first.cookies.read(tokenCookie)));
  console.log("OBSERVED " + path + " second reader token in body: " + secondToken +
    ", cookie: " + (tokenCookie === null ? null : second.cookies.read(tokenCookie)));
  console.log("OBSERVED " + path + " bodies identical: " +
    (servedFirst.body === servedSecond.body) + "; identical once each token is masked: " +
    (masked(servedFirst.body, firstToken) === masked(servedSecond.body, secondToken)));
  console.log("OBSERVED " + path + " first difference: " +
    firstDifference(servedFirst.body, servedSecond.body));
  return o;
}

function assertPublicPage(o) {
  var p = o.path;

  count(p + ": both anonymous readers are served the published page",
    o.servedFirst.status === 200 && o.servedSecond.status === 200,
    o.servedFirst.status + " " + o.servedSecond.status);

  count(p + ": the page renders the theme form, so the token question below is about a real field",
    o.firstToken !== null && o.secondToken !== null,
    JSON.stringify([o.firstToken, o.secondToken]));

  count(p + ": the page is marked private and not public, so no shared cache stores it",
    markedPrivate(o.cacheControl) && !o.shareable,
    "Cache-Control " + JSON.stringify(o.cacheControl));

  count(p + ": a page that a shared cache may store sets no cookie, because a stored copy " +
    "replays that cookie to every reader it is handed to",
    !o.shareable || o.issued.length === 0,
    "Cache-Control " + JSON.stringify(o.cacheControl) + ", Set-Cookie " + JSON.stringify(o.issued));

  count(p + ": a page that a shared cache may store is the same bytes for every reader, " +
    "so a stored copy carries no reader's token to another",
    !o.shareable || o.servedFirst.body === o.servedSecond.body,
    "Cache-Control " + JSON.stringify(o.cacheControl) + ", tokens " +
    JSON.stringify([o.firstToken, o.secondToken]) + ", first difference " +
    firstDifference(o.servedFirst.body, o.servedSecond.body));
}

async function run() {
  var root    = helpers.tempDir("pubcache");
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

    await identity.settings.set({
      name: SETTING, value: true, changedBy: "operator@example.com",
      reason: "publishing the front page for this run",
    });

    // ---- observe ----------------------------------------------------------

    var samples = wikiSamples();
    console.log("OBSERVED wiki pages sampled by kind: " + JSON.stringify(samples));

    var front = await observe(origin, "/");
    var wikiPages = [];
    for (var k = 0; k < WIKI_KINDS.length; k += 1) {
      if (!Object.prototype.hasOwnProperty.call(samples, WIKI_KINDS[k])) continue;
      wikiPages.push(await observe(origin, samples[WIKI_KINDS[k]]));
    }

    // A reader holding the token a stored copy of the front page would
    // have handed them, signing in and opening their mailbox.
    var inheritedToken = null;
    var signedIn = null;
    var mailbox = null;
    if (front.tokenCookie !== null && front.firstToken !== null) {
      var inheritor = browser.browserAt(origin);
      inheritor.cookies.set(front.tokenCookie, front.firstToken);
      signedIn = await inheritor.signIn(READER_ADDRESS, READER_PASSWORD);
      mailbox = await inheritor.get("/mail?folder=INBOX");
      inheritedToken = tokenIn(mailbox.body);
      console.log("OBSERVED sign in carrying the first reader's token: " + signedIn.status +
        " to " + signedIn.location + "; cookies set by it: " +
        JSON.stringify(cookieNames(signedIn.setCookie)));
      console.log("OBSERVED mailbox status " + mailbox.status + ", token on the signed-in page: " +
        inheritedToken + " (the first reader's token: " + (inheritedToken === front.firstToken) + ")");
    }

    // A reader with a session of its own, reading the wiki index.
    var member = browser.browserAt(origin);
    var memberSignIn = await member.signIn(READER_ADDRESS, READER_PASSWORD);
    var memberWiki = await member.get(wiki.BASE_PATH);
    var memberCacheControl = String(memberWiki.headers["cache-control"] || "");
    console.log("OBSERVED signed-in reader: sign in " + memberSignIn.status + ", " +
      wiki.BASE_PATH + " status " + memberWiki.status + ", Cache-Control " +
      JSON.stringify(memberCacheControl));

    // ---- assert -----------------------------------------------------------

    count("the wiki build offers a page of every kind, so every kind is read below",
      WIKI_KINDS.every(function (kind) { return Object.prototype.hasOwnProperty.call(samples, kind); }),
      JSON.stringify(samples));

    assertPublicPage(front);
    wikiPages.forEach(function (o) {
      assertPublicPage(o);
      count(o.path + ": the wiki page carries the same Cache-Control as the front page, so " +
        "one decision covers both",
        o.cacheControl === front.cacheControl && o.cacheControl.length > 0,
        JSON.stringify(o.cacheControl) + " against " + JSON.stringify(front.cacheControl));
    });

    count("a signed-in reader is served the wiki",
      memberWiki.status === 200, memberWiki.status);
    count("and that page is private and stored by no cache, like every other page behind " +
      "a session, rather than kept for the anonymous window",
      memberCacheControl === "private, no-store" && markedPrivate(memberCacheControl) &&
        !sharedCacheMayStore(memberCacheControl),
      JSON.stringify(memberCacheControl));

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

module.exports = { name: "public-site-shared-cache", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
