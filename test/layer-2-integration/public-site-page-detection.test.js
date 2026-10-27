// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The public navigation and the sitemap list a page only while GET on its
 * path reaches a route, and they list it as soon as that route is
 * registered.
 *
 * The web surface's routes are mounted on an application built here, the
 * way `blamepost.web.serve` builds one, and this file keeps the router.
 * Routes are then registered on that live router between requests, so
 * each step measures the same server before and after a registration
 * rather than two servers built differently.
 *
 * These states are driven against `/wiki`. The surface registers the
 * reference wiki's own GET routes when it mounts, so the first two
 * applications are mounted through a router that withholds exactly those
 * registrations and forwards every other call, the route table read
 * included. The case asserts that three registrations were withheld, so
 * a withholding router that stopped matching is refused rather than
 * passing over a wiki that was mounted anyway.
 *
 *   - nothing registered: GET /wiki answers 404, and neither the
 *     navigation nor the sitemap names it;
 *   - routes that are not GET on the path: a POST on `/wiki` and a GET on
 *     `/wiki/:page`. Neither lists the page;
 *   - a GET route on `/wiki`: the navigation links it and the sitemap
 *     names it at this server's origin;
 *   - on a second application, a GET on the parameter pattern `/:slug`
 *     registered before a GET on `/wiki`. The router dispatches GET /wiki
 *     to the first pattern that matches, so the request reaches `/:slug`
 *     and answers 404, and the page is not listed even though a route
 *     for its exact path exists. A route cannot be removed from a live
 *     router, which is why this case has an application of its own;
 *   - on a third application mounted with nothing withheld, the surface
 *     as it ships: GET /wiki answers the reference index, and the
 *     navigation and the sitemap both list it.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/public-site-page-detection.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var SETTING  = "publicSiteEnabled";

// A search engine, spelled the way one arrives: no `Accept-Language` and
// no `Sec-Fetch-Mode`, both of which the bot guard treats as advisory.
var CRAWLER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

var WIKI_LINK = '<a class="topnav-link" href="/wiki">';
var WIKI_LOC  = new RegExp("<loc>https://" + HOSTNAME.replace(/\./g, "\\.") +
  "(?::\\d+)?/wiki</loc>");
var WIKI_INDEX_HEADING = '<h1 class="band-title">blamepost reference</h1>';

// The wiki routes the surface registers when it mounts.
var WIKI_ROUTE_RE = /^\/wiki(?:\/|$)/;

var listenerTable = [
  { name: "mx",   state: "bound", reason: null },
  { name: "imap", state: "bound", reason: null },
];

function wiringFor(cfg, identity, mailStore) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent:     b.mail.agent.create({ store: mailStore, dispatch: { mode: "local" } }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: mailStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: mailStore,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return listenerTable; },
    address:   LOOPBACK,
    httpPort:  0,
  };
}

function get(port, path) {
  return fetch("http://" + LOOPBACK + ":" + port + path, {
    redirect: "manual",
    headers:  { "User-Agent": CRAWLER_AGENT },
  });
}

async function readSurface(port) {
  var page = await get(port, "/");
  var body = await page.text();
  var map = await get(port, "/sitemap.xml");
  var xml = await map.text();
  var wiki = await get(port, "/wiki");
  var wikiBody = await wiki.text();
  return {
    pageStatus: page.status,
    mapStatus:  map.status,
    wikiStatus: wiki.status,
    wikiBody:   wikiBody,
    linked:     body.indexOf(WIKI_LINK) !== -1,
    mapped:     WIKI_LOC.test(xml),
    xml:        xml,
  };
}

function refuse(req, res) {
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("no such page\n");
}

// The router the surface mounts on, with every GET registration under
// `/wiki` withheld and counted. Every other property is the live router's
// own, bound to it, so the route table the surface reads is the live one
// and a route this file registers later on the live router is in it.
function withholdingWikiRoutes(router) {
  var withheld = [];
  var proxy = new Proxy(router, {
    get: function (target, prop) {
      if (prop === "get") {
        return function (pattern) {
          if (typeof pattern === "string" && WIKI_ROUTE_RE.test(pattern)) {
            withheld.push(pattern);
            return undefined;
          }
          return target.get.apply(target, arguments);
        };
      }
      var value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { router: proxy, withheld: withheld };
}

async function testNothingRegisteredListsNothing(port) {
  var s = await readSurface(port);
  count("the published front page and the sitemap both answer",
    s.pageStatus === 200 && s.mapStatus === 200, s.pageStatus + " " + s.mapStatus);
  count("with no route registered for it, GET /wiki answers 404", s.wikiStatus === 404, s.wikiStatus);
  count("with no route registered for it, the navigation does not link /wiki", !s.linked, s.linked);
  count("with no route registered for it, the sitemap does not name /wiki", !s.mapped, s.xml);
}

function serveWiki(req, res) {
  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("wiki\n");
}

async function testOtherRoutesDoNotListThePage(port, router) {
  router.post("/wiki", refuse);
  router.get("/wiki/:page", refuse);

  var s = await readSurface(port);
  count("with only a POST on /wiki and a GET on /wiki/:page registered, GET /wiki answers 404",
    s.wikiStatus === 404, s.wikiStatus);
  count("neither route puts /wiki in the navigation", !s.linked, s.linked);
  count("neither route puts /wiki in the sitemap", !s.mapped, s.xml);
}

async function testAGetRouteListsThePage(port, router) {
  router.get("/wiki", serveWiki);

  var s = await readSurface(port);
  count("once a GET route is registered on /wiki, it answers 200", s.wikiStatus === 200, s.wikiStatus);
  count("the navigation links /wiki as soon as the route is registered", s.linked, s.linked);
  count("the sitemap names /wiki at this server's origin as soon as the route is registered",
    s.mapped, s.xml);
}

async function testAShadowedRouteDoesNotListThePage(port, router) {
  router.get("/:slug", refuse);
  router.get("/wiki", serveWiki);

  var s = await readSurface(port);
  count("with /:slug registered before /wiki, GET /wiki reaches /:slug and answers 404",
    s.wikiStatus === 404, s.wikiStatus);
  count("a /wiki route that GET /wiki never reaches does not put it in the navigation",
    !s.linked, s.linked);
  count("a /wiki route that GET /wiki never reaches does not put it in the sitemap",
    !s.mapped, s.xml);
}

async function testTheShippedMountListsTheWiki(port) {
  var s = await readSurface(port);
  count("mounted as it ships, the surface answers GET /wiki with the reference index",
    s.wikiStatus === 200 && s.wikiBody.indexOf(WIKI_INDEX_HEADING) !== -1,
    s.wikiStatus + " " + JSON.stringify(s.wikiBody.slice(0, 120)));
  count("and the navigation links /wiki", s.linked, s.linked);
  count("and the sitemap names /wiki at this server's origin", s.mapped, s.xml);
}

async function startApplication(cfg, identity, mailStore, dataDir, withhold) {
  var handle = blamepost.web.create(wiringFor(cfg, identity, mailStore));
  var withheld = null;
  var app = await b.createApp({
    dataDir:    dataDir,
    routes:     function (router) {
      if (!withhold) { handle.routes(router); return; }
      var wrapped = withholdingWikiRoutes(router);
      withheld = wrapped.withheld;
      handle.routes(wrapped.router);
    },
    middleware: {
      securityHeaders: { referrerPolicy: "same-origin", protocolResolver: handle.resolveProtocol },
      csrf:            { protocolResolver: handle.resolveProtocol },
    },
  });
  var listening = await app.listen({ port: 0, host: LOOPBACK });
  return { router: app.router, port: listening.port, server: listening.server, withheld: withheld };
}

function assertWithheld(app, label) {
  count("the " + label + " application was mounted with the surface's three wiki routes withheld",
    app.withheld !== null && app.withheld.length === 3,
    JSON.stringify(app.withheld));
}

function closeServer(server) {
  return new Promise(function (resolve) {
    server.close(function () { resolve(); });
    server.closeAllConnections();
  });
}

async function run() {
  var root = helpers.tempDir("publicsitedetect");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var servers = [];
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var identity = await store.open(cfg);
    var mailStore = b.mailStore.create({ backend: b.db });

    await identity.settings.set({
      name: SETTING, value: true, changedBy: "operator@example.com",
      reason: "publishing the front page for this run",
    });

    var first = await startApplication(cfg, identity, mailStore, dataDir, true);
    servers.push(first.server);
    assertWithheld(first, "first");
    await testNothingRegisteredListsNothing(first.port);
    await testOtherRoutesDoNotListThePage(first.port, first.router);
    await testAGetRouteListsThePage(first.port, first.router);

    var second = await startApplication(cfg, identity, mailStore, dataDir, true);
    servers.push(second.server);
    assertWithheld(second, "second");
    await testAShadowedRouteDoesNotListThePage(second.port, second.router);

    var third = await startApplication(cfg, identity, mailStore, dataDir, false);
    servers.push(third.server);
    await testTheShippedMountListsTheWiki(third.port);
  } finally {
    for (var i = 0; i < servers.length; i += 1) {
      await closeServer(servers[i]);
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "public-site-page-detection", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
