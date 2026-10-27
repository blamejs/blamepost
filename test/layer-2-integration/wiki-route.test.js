// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wiki-route: the reference wiki on a real listener, in each state the
 * public-site setting and a session put it in.
 *
 * The route is driven through three states against one server, in this
 * order, so what is measured is a setting changing rather than two
 * fixtures agreeing:
 *
 *   - the public site not published. A reader with no session is sent to
 *     the sign-in page from every wiki path, a path the wiki has no page
 *     at included, and a caller asking for JSON is answered 401. A
 *     signed-in reader is served the wiki, and a path with no page
 *     answers that reader 404.
 *   - the site published. A reader with no session is served every page
 *     the wiki builds. Each served page names its own path in its
 *     canonical link, links `/wiki` in the site navigation, and carries
 *     only links that are paths on this server or fragments naming an
 *     element on the same page, and every link under `/wiki` in it is a
 *     page the wiki builds. A path the wiki has no page
 *     at answers 404, one segment below `/wiki`, two segments below, and
 *     three.
 *   - the site withdrawn again. A reader with no session is sent to the
 *     sign-in page once more.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/wiki-route.test.js
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

var READER_ADDRESS  = "tallowmere@" + DOMAIN;
var READER_PASSWORD = "copper orchard lantern 7715";

var HTTP_TIMEOUT_MS = 5000;

var INDEX_HEADING = '<h1 class="band-title">blamepost reference</h1>';
var NAV_WIKI_LINK = '<a class="topnav-link" href="/wiki">';

// Paths under /wiki that the wiki builds no page for, at each depth the
// routes cover and one beyond it.
var MISSING = [
  "/wiki/no-such-module",
  "/wiki/config/no-such-primitive",
  "/wiki/specs/no-such-document",
  "/wiki/config/load/extra",
];

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

function isSignInRedirect(res) {
  return (res.status === 302 || res.status === 303) &&
    typeof res.location === "string" && /^\/sign-in(?:\?|$)/.test(res.location);
}

// Every URL attribute value in a document.
function linkTargets(body) {
  var out = [];
  var re = /\b(?:href|src|action)="([^"]*)"/g;
  var m;
  while ((m = re.exec(body)) !== null) out.push(m[1]);
  return out;
}

function canonicalOf(body) {
  var m = /<link rel="canonical" href="([^"]*)">/.exec(body);
  return m === null ? null : m[1];
}

async function withTheSiteUnpublished(origin, samples, member) {
  var stranger = browser.browserAt(origin);
  var redirected = [];
  var paths = [wiki.BASE_PATH, samples.module, samples.primitive, samples.specs, MISSING[0]];
  for (var i = 0; i < paths.length; i += 1) {
    var res = await stranger.get(paths[i]);
    console.log("OBSERVED unpublished, no session: GET " + paths[i] + " -> " + res.status +
      " " + res.location);
    if (!isSignInRedirect(res)) redirected.push(paths[i] + " " + res.status + " " + res.location);
  }
  count("with the site not published, a reader with no session is sent to the sign-in page " +
    "from every wiki path, including one with no page", redirected.length === 0,
    redirected.join(" | ") || paths.length + " paths");

  var asJson = await stranger.get(wiki.BASE_PATH, { Accept: "application/json" });
  console.log("OBSERVED unpublished, no session, JSON: " + asJson.status);
  count("and a caller asking for JSON is answered 401", asJson.status === 401, asJson.status);

  var page = await member.get(wiki.BASE_PATH);
  console.log("OBSERVED unpublished, signed in: GET /wiki -> " + page.status);
  count("with the site not published, a signed-in reader is served the wiki index",
    page.status === 200 && page.body.indexOf(INDEX_HEADING) !== -1,
    page.status + " " + JSON.stringify(page.body.slice(0, 120)));

  var missing = await member.get(MISSING[0]);
  count("and a path with no page answers that reader 404", missing.status === 404, missing.status);
}

async function withTheSitePublished(origin, site, paths) {
  var stranger = browser.browserAt(origin);
  var pageSet = new Set(paths);
  var failures = [];
  var offSite = [];
  var dangling = [];
  var wikiLinks = 0;

  for (var i = 0; i < paths.length; i += 1) {
    var p = paths[i];
    var res = await stranger.get(p);
    if (res.status !== 200) { failures.push(p + " answered " + res.status); continue; }
    var heading = '<h1 class="band-title">';
    if (res.body.indexOf(heading) === -1) failures.push(p + " carries no heading");
    if (canonicalOf(res.body) !== p) failures.push(p + " names " + canonicalOf(res.body) + " as canonical");
    if (res.body.indexOf(NAV_WIKI_LINK) === -1) failures.push(p + " does not link /wiki in its navigation");
    var title = "<title>" + b.template.escapeHtml(site.page(p).documentTitle) + "</title>";
    if (res.body.indexOf(title) === -1) failures.push(p + " does not carry its document title");
    var body = res.body;
    linkTargets(body).forEach(function (target) {
      if (target.charAt(0) === "#") {
        if (body.indexOf("id=\"" + target.slice(1) + "\"") === -1) dangling.push(p + " -> " + target);
        return;
      }
      if (target.charAt(0) !== "/" || b.safeRedirect.resolve(target, { fallback: "" }) !== target) {
        offSite.push(p + " -> " + target);
        return;
      }
      if (target.indexOf(wiki.BASE_PATH) !== 0) return;
      wikiLinks += 1;
      var hash = target.indexOf("#");
      var linked = hash === -1 ? target : target.slice(0, hash);
      if (!pageSet.has(linked)) dangling.push(p + " -> " + target);
    });
  }
  console.log("OBSERVED published, no session: " + paths.length + " pages read, " +
    wikiLinks + " wiki links followed");

  count("with the site published, a reader with no session is served every one of the " +
    paths.length + " pages, each naming itself as canonical and linking /wiki in its navigation",
    failures.length === 0 && paths.length > 0, failures.slice(0, 5).join(" | ") || "none failed");
  count("every link those pages carry is a path on this server or a fragment on the same page",
    offSite.length === 0, offSite.slice(0, 5).join(" | ") || "none off site");
  count("the pages carry wiki links, so the check below read something",
    wikiLinks > 0, wikiLinks + " links");
  count("every wiki link on them is a page the wiki builds, and every fragment-only link " +
    "names an element on its own page",
    dangling.length === 0, dangling.slice(0, 5).join(" | ") || "none dangling");

  var notFound = [];
  for (var j = 0; j < MISSING.length; j += 1) {
    var miss = await stranger.get(MISSING[j]);
    console.log("OBSERVED published, no session: GET " + MISSING[j] + " -> " + miss.status);
    if (miss.status !== 404) notFound.push(MISSING[j] + " " + miss.status);
  }
  count("a wiki path with no page answers 404 at one, two and three segments below /wiki",
    notFound.length === 0, notFound.join(" | ") || MISSING.length + " paths");
}

async function withTheSiteWithdrawn(origin) {
  var stranger = browser.browserAt(origin);
  var res = await stranger.get(wiki.BASE_PATH);
  console.log("OBSERVED withdrawn, no session: GET /wiki -> " + res.status + " " + res.location);
  count("once the site is withdrawn, a reader with no session is sent to the sign-in page again",
    isSignInRedirect(res), res.status + " " + res.location);
}

async function run() {
  var root    = helpers.tempDir("wikiroute");
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
    count("the configuration this run boots with does not publish the site",
      cfg.publicSiteEnabled !== true, cfg.publicSiteEnabled);

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({ address: READER_ADDRESS, password: READER_PASSWORD });

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var site = wiki.build();
    var paths = site.paths();
    var samples = {};
    paths.forEach(function (p) {
      var kind = site.page(p).kind;
      if (!Object.prototype.hasOwnProperty.call(samples, kind)) samples[kind] = p;
    });
    count("the wiki build offers a module, a primitive and the specification index to drive",
      typeof samples.module === "string" && typeof samples.primitive === "string" &&
        typeof samples.specs === "string", JSON.stringify(samples));

    var member = browser.browserAt(origin);
    var signedIn = await member.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the member reader signs in", signedIn.status === 302 || signedIn.status === 303,
      signedIn.status + " " + signedIn.location);

    await withTheSiteUnpublished(origin, samples, member);

    await identity.settings.set({
      name: SETTING, value: true, changedBy: "operator@example.com",
      reason: "publishing the public site for this run",
    });
    await withTheSitePublished(origin, site, paths);

    await identity.settings.set({
      name: SETTING, value: false, changedBy: "operator@example.com",
      reason: "withdrawing the public site for this run",
    });
    await withTheSiteWithdrawn(origin);

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

module.exports = { name: "wiki-route", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
