// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `Cache-Control` every rendered page is served with, read off a real
 * listener.
 *
 * RFC 9111 section 5.2.2.5 has a cache store no part of a `no-store`
 * response, and section 5.2.2.7 has a shared cache refuse a `private` one.
 * `no-cache` (section 5.2.2.4) lets a browser store the page and only
 * requires revalidation before it is reused, so a mailbox served with
 * `no-cache` can stay in the browser's disk cache after its reader signs
 * out. Every page below is fetched with the reader it is served to and its
 * header is compared with the one expected.
 *
 * The routes are not listed here by hand. The walk reads every GET route
 * off the route table the shipped mount registers, fills each route
 * parameter with a value from this run's fixtures, and requests it:
 *
 *   - as a mailbox owner, or as an operator when the route is part of the
 *     administration console, and every HTML page answered carries
 *     `private, no-store`;
 *   - with no session as well, for the front page and the reference wiki,
 *     which carry `private, max-age=900`, and for the sign-in page, which
 *     carries `private, no-store`.
 *
 * A route that answers something other than HTML (a text document, an
 * image, JSON, a redirect, an event stream) is named in the table with the
 * status, media type and header it answers with. A GET route the table
 * does not classify fails the run, so a page added later is walked the day
 * it is registered. A classified route that is no longer registered fails
 * too. The count of routes walked is printed, and a walk that reached
 * fewer than MIN_GET_ROUTES fails rather than passing over an empty table.
 *
 * Four answers the route table cannot name are asked for directly: a
 * conversation with its images shown, which passes a header of its own; the
 * confirmation page a form post renders; a compose post refused with 400;
 * and the error page a missing folder answers.
 *
 * Every header observed is printed before anything is asserted.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/web-page-cache-directive.test.js
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

var OPERATOR_ADDRESS  = "fenwright@" + DOMAIN;
var OPERATOR_PASSWORD = "copper kettle meadow 5820";
var ACCOUNT_ADDRESS   = "marisol@" + DOMAIN;
var ACCOUNT_PASSWORD  = "harbor lantern thistle 4417";

var HTTP_TIMEOUT_MS = 5000;

var NO_STORE    = "private, no-store";
var PUBLIC_PAGE = "private, max-age=900";

var SEARCH_WORD = "marmalade";

var WIKI_KINDS = ["index", "module", "primitive", "specs", "spec"];

var MESSAGE_LINK_RE = /class="msg-body"\s+href="(\/mail\/[^"]*)"/;
var PART_LINK_RE    = /<a class="part-link" href="(\/mail\/[^"]*)"/;

var JMAP_MAIL = "urn:ietf:params:jmap:mail";

// The floor sits below the number of GET routes the mount registers, so a
// route removed on purpose does not trip it, and far above an empty table.
var MIN_GET_ROUTES = 20;

// ---------------------------------------------------------------------------
// The classification of every GET route, keyed by its pattern exactly as the
// router's table spells it.
//
// `paths(fx)` names the concrete paths a pattern is asked at, filled from
// this run's fixtures. Each entry of `asks` is one request:
//
//   reader   "stranger" (no session), "account" (a mailbox owner) or
//            "operator" (holds the administration console)
//   page     "private" or "public": the route answers HTML with status 200,
//            and carries NO_STORE, or PUBLIC_PAGE for a public page asked by
//            a stranger
//   status, type, cacheControl
//            for an answer that is not a page: the status, the media type
//            the Content-Type begins with, and the exact header
//   accept   the Accept header, when the route answers by it
//   stream   the route holds its response open, so only the head is read
// ---------------------------------------------------------------------------

function _page(reader) { return { reader: reader, page: "private" }; }

var ADMIN = { paths: null, asks: [_page("operator")] };

var ROUTES = {
  "/.well-known/mta-sts.txt": {
    asks: [{ reader: "stranger", status: 200, type: "text/plain", cacheControl: "public, max-age=86400" }],
  },
  "/robots.txt": {
    asks: [{ reader: "stranger", status: 200, type: "text/plain", cacheControl: "public, max-age=3600" }],
  },
  "/sitemap.xml": {
    asks: [{ reader: "stranger", status: 200, type: "application/xml", cacheControl: "public, max-age=3600" }],
  },
  "/badge.svg": {
    asks: [{ reader: "stranger", status: 200, type: "image/svg+xml", cacheControl: "public, max-age=86400" }],
  },
  "/.well-known/jmap": {
    asks: [{ reader: "account", status: 302, type: "", cacheControl: NO_STORE, accept: "application/json" }],
  },
  "/jmap/session": {
    asks: [{ reader: "account", status: 200, type: "application/json", cacheControl: NO_STORE,
      accept: "application/json" }],
  },
  // The framework's event stream handler keeps the request chain's
  // `no-store` rather than writing its own `no-cache` over it.
  "/jmap/eventsource": {
    paths: function () { return ["/jmap/eventsource?types=*&closeafter=no&ping=0"]; },
    asks: [{ reader: "account", status: 200, type: "text/event-stream", cacheControl: NO_STORE,
      stream: true }],
  },
  // A GET without the WebSocket upgrade, answered with 426 and a line of
  // text naming the headers to send.
  "/jmap/ws": {
    asks: [{ reader: "account", status: 426, type: "text/plain", cacheControl: NO_STORE }],
  },
  // One blob off a message, handed back as bytes to save rather than as a
  // page, which is the JMAP half of the browser route further down. The
  // blob id is the one `Email/get` answered for the planted message, so
  // the route resolves it and serves the raw octets under the one type
  // every blob is served as.
  "/jmap/download/:accountId/:blobId/:name": {
    paths: function (fx) {
      return ["/jmap/download/" + fx.jmapAccountId + "/" + fx.blobId + "/message.eml"];
    },
    asks: [{ reader: "account", status: 200, type: "application/octet-stream",
      cacheControl: NO_STORE, accept: "application/json" }],
  },
  "/sign-in": {
    asks: [
      _page("stranger"),
      { reader: "account", status: 302, type: "", cacheControl: NO_STORE },
    ],
  },
  "/": {
    asks: [
      { reader: "stranger", page: "public" },
      { reader: "account", status: 302, type: "", cacheControl: NO_STORE },
    ],
  },
  "/wiki": {
    asks: [{ reader: "stranger", page: "public" }, _page("account")],
  },
  "/wiki/:section": {
    paths: function (fx) { return [fx.wiki.module, fx.wiki.specs]; },
    asks: [{ reader: "stranger", page: "public" }, _page("account")],
  },
  "/wiki/:section/:name": {
    paths: function (fx) { return [fx.wiki.primitive, fx.wiki.spec]; },
    asks: [{ reader: "stranger", page: "public" }, _page("account")],
  },
  "/mail": {
    paths: function (fx) { return [fx.mailbox]; },
    asks: [_page("account")],
  },
  "/mail/:objectId": {
    paths: function (fx) { return [fx.conversation]; },
    asks: [_page("account")],
  },
  // One file off a message, handed back as bytes to save rather than as a
  // page. The planted message carries one, so the route answers 200 with
  // the type every part is served under.
  "/mail/:objectId/parts/:partId": {
    paths: function (fx) { return [fx.part]; },
    asks: [{ reader: "account", status: 200, type: "application/octet-stream",
      cacheControl: NO_STORE }],
  },
  "/search": {
    paths: function () { return ["/search?q=" + SEARCH_WORD]; },
    asks: [_page("account")],
  },
  "/compose": {
    asks: [_page("account")],
  },
  "/admin":             ADMIN,
  "/admin/domains":     ADMIN,
  "/admin/accounts":    ADMIN,
  "/admin/lockouts":    ADMIN,
  "/admin/aliases":     ADMIN,
  "/admin/credentials": ADMIN,
  "/admin/dkim":        ADMIN,
  "/admin/dmarc":       ADMIN,
  "/admin/queue":       ADMIN,
  "/admin/audit":       ADMIN,
};

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

// The planted message carries a file, so the route that serves one has a
// part to answer for. Part 2 under RFC 9051 section 6.4.5 numbering, which
// is what `fixtureValues` fills the route's parameter with.
function message(to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: The " + SEARCH_WORD + " order\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <cache-directive@example.net>\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/mixed; boundary=\"jar\"\r\n" +
    "\r\n--jar\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nThree jars of " + SEARCH_WORD + " for the account holder.\r\n" +
    "--jar\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"order.bin\"\r\n" +
    "\r\nthe order itself\r\n" +
    "--jar--\r\n", "utf8");
}

function wikiSamples() {
  var site = wiki.build();
  var byKind = {};
  site.paths().forEach(function (p) {
    var kind = site.page(p).kind;
    if (!Object.prototype.hasOwnProperty.call(byKind, kind)) byKind[kind] = p;
  });
  return byKind;
}

// The GET patterns the shipped mount registers, read off the table of a
// router it is mounted on. The handle is built from the same wiring as the
// listener under test, so the table is the one that listener serves.
function registeredGetRoutes(wiring) {
  var router = new b.router.Router();
  blamepost.web.create(wiring).routes(router);
  var seen = {};
  return router.inspectRoutes()
    .filter(function (r) { return r.method === "GET"; })
    .map(function (r) { return r.pattern; })
    .filter(function (p) {
      if (Object.prototype.hasOwnProperty.call(seen, p)) return false;
      seen[p] = true;
      return true;
    });
}

// One observation: what was asked, the status, and the header.
function observed(label, res, expectedStatus) {
  var o = {
    label:          label,
    status:         res.status,
    expectedStatus: expectedStatus,
    cacheControl:   String(res.headers["cache-control"] || ""),
    contentType:    String(res.headers["content-type"] || ""),
    headers:        res.headers,
  };
  console.log("OBSERVED " + label + " -> " + o.status + ", Content-Type " +
    JSON.stringify(o.contentType) + ", Cache-Control " + JSON.stringify(o.cacheControl));
  return o;
}

function assertAll(observations, expected, what) {
  var wrongStatus = observations.filter(function (o) { return o.status !== o.expectedStatus; });
  count(what + ": every page answered with the status the case expects",
    wrongStatus.length === 0,
    wrongStatus.map(function (o) { return o.label + " " + o.status; }).join(" | ") ||
      observations.length + " pages");
  var wrongHeader = observations.filter(function (o) { return o.cacheControl !== expected; });
  count(what + ": every page carries Cache-Control " + JSON.stringify(expected),
    wrongHeader.length === 0 && observations.length > 0,
    wrongHeader.map(function (o) { return o.label + " " + JSON.stringify(o.cacheControl); })
      .join(" | ") || observations.length + " pages");
}

// The values the route parameters are filled with: this run's mailbox, the
// planted message, its blob as JMAP names it, and one wiki page of each kind.
async function fixtureValues(account, landing) {
  var mailbox = await account.get(landing);
  var link = MESSAGE_LINK_RE.exec(mailbox.body);
  count("the mailbox lists the planted message, so a conversation is walked below",
    link !== null, JSON.stringify(mailbox.body.slice(0, 160)));

  var session = await account.get("/jmap/session", { Accept: "application/json" });
  var jmapAccountId;
  try { jmapAccountId = JSON.parse(session.body).primaryAccounts[JMAP_MAIL]; }
  catch (_e) { jmapAccountId = null; }
  count("the JMAP session names the mailbox's account, so a download is walked below",
    typeof jmapAccountId === "string" && jmapAccountId.length > 0,
    session.status + " " + JSON.stringify(session.body.slice(0, 160)));

  var emails = await account.jmap([
    ["Email/query", { accountId: jmapAccountId }, "q"],
    ["Email/get", {
      accountId:  jmapAccountId,
      "#ids":     { resultOf: "q", name: "Email/query", path: "/ids" },
      properties: ["blobId"],
    }, "g"],
  ]);
  var got = browser.answer(emails, 1);
  var blobId = got && got[1] && Array.isArray(got[1].list) && got[1].list.length > 0
    ? got[1].list[0].blobId : null;
  count("JMAP names the planted message's blob", typeof blobId === "string" && blobId.length > 0,
    JSON.stringify(got));

  var byKind = wikiSamples();
  count("the wiki build offers a page of every kind, so every kind is walked below",
    WIKI_KINDS.every(function (k) { return Object.prototype.hasOwnProperty.call(byKind, k); }),
    JSON.stringify(byKind));

  var conversation = link[1].replace(/&amp;/g, "&");
  var opened = await account.get(conversation);
  var part = PART_LINK_RE.exec(opened.body);
  count("the conversation lists the planted message's file, so a part is walked below",
    part !== null, opened.status + " " + JSON.stringify(opened.body.slice(0, 160)));

  return {
    mailbox:       landing,
    conversation:  conversation,
    // The folder rides in the query string, so a fallback spelled by hand
    // puts the part number before it rather than after it.
    part:          part === null
      ? conversation.split("?")[0] + "/parts/2" +
        conversation.slice(conversation.split("?")[0].length)
      : part[1],
    jmapAccountId: jmapAccountId,
    blobId:        blobId,
    wiki:          byKind,
  };
}

// Every GET route in the table, asked the way its classification says.
async function walkTheRouteTable(patterns, readers, fx) {
  var unclassified = patterns.filter(function (p) {
    return !Object.prototype.hasOwnProperty.call(ROUTES, p);
  });
  var stale = Object.keys(ROUTES).filter(function (p) { return patterns.indexOf(p) === -1; });

  var findings = [];
  var requests = 0;
  var pages = 0;
  for (var i = 0; i < patterns.length; i += 1) {
    var pattern = patterns[i];
    if (!Object.prototype.hasOwnProperty.call(ROUTES, pattern)) continue;
    var entry = ROUTES[pattern];
    var paths = entry.paths ? entry.paths(fx) : [pattern];
    for (var j = 0; j < paths.length; j += 1) {
      for (var k = 0; k < entry.asks.length; k += 1) {
        var ask = entry.asks[k];
        var reader = readers[ask.reader];
        var extra = ask.accept ? { Accept: ask.accept } : undefined;
        var res = ask.stream ? await reader.head(paths[j], extra) : await reader.get(paths[j], extra);
        requests += 1;
        var label = ask.reader + ": GET " + paths[j] + " (" + pattern + ")";
        var o = observed(label, res, ask.page ? 200 : ask.status);
        var html = o.contentType.indexOf("text/html") === 0;

        if (ask.page) {
          pages += 1;
          var want = ask.page === "public" && ask.reader === "stranger" ? PUBLIC_PAGE : NO_STORE;
          if (o.status !== 200) findings.push(label + " answered " + o.status + ", not a page");
          if (!html) findings.push(label + " answered " + JSON.stringify(o.contentType) + ", not HTML");
          if (o.cacheControl !== want) {
            findings.push(label + " carries " + JSON.stringify(o.cacheControl) + ", not " +
              JSON.stringify(want));
          }
          continue;
        }

        if (o.status !== ask.status) findings.push(label + " answered " + o.status + ", not " + ask.status);
        if (html) {
          findings.push(label + " answered HTML, so it is a page and belongs in the table as one");
        }
        if (ask.type.length > 0 && o.contentType.indexOf(ask.type) !== 0) {
          findings.push(label + " answered " + JSON.stringify(o.contentType) + ", not " + ask.type);
        }
        if (o.cacheControl !== ask.cacheControl) {
          findings.push(label + " carries " + JSON.stringify(o.cacheControl) + ", not " +
            JSON.stringify(ask.cacheControl));
        }
      }
    }
  }

  console.log("ROUTE WALK " + patterns.length + " GET routes read from the router's table, " +
    requests + " requests, " + pages + " HTML pages");

  return {
    unclassified: unclassified,
    stale:        stale,
    findings:     findings,
    requests:     requests,
    pages:        pages,
  };
}

// The answers a GET route table cannot name: a query that changes the
// render, a form post, and a refusal.
async function answersOffTheTable(operator, account, fx) {
  var out = [];

  var withImages = await account.get(fx.conversation + "&images=on");
  out.push(observed("account: conversation with images shown", withImages, 200));
  console.log("OBSERVED conversation with images shown, Content-Security-Policy " +
    JSON.stringify(withImages.headers["content-security-policy"]));

  var confirm = await operator.form("/admin/domains", { action: "enable", domain: DOMAIN });
  out.push(observed("operator: POST /admin/domains confirmation page", confirm, 200));

  var refused = await account.form("/compose", { to: "", subject: "no recipient", text: "body" });
  out.push(observed("account: POST /compose refused", refused, 400));

  out.push(observed("account: error page",
    await account.get("/mail?folder=NoSuchFolder"), 404));

  return { pages: out, confirm: confirm, withImages: withImages };
}

async function run() {
  var root    = helpers.tempDir("cachedirective");
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
    await identity.accounts.create({
      address: OPERATOR_ADDRESS, password: OPERATOR_PASSWORD, isAdmin: true,
    });
    var ownerAccount = await identity.accounts.create({
      address: ACCOUNT_ADDRESS, password: ACCOUNT_PASSWORD,
    });
    identity.mailbox.appendMessage("INBOX", message(ACCOUNT_ADDRESS),
      { actor: { id: ownerAccount.id } });
    await identity.settings.set({
      name: SETTING, value: true, changedBy: OPERATOR_ADDRESS,
      reason: "publishing the public site for this run",
    });

    var wiring = wiringFor(cfg, identity);
    var patterns = registeredGetRoutes(wiring);
    listener = blamepost.web.serve(wiring);
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    // ---- observe ----------------------------------------------------------

    var stranger = browser.browserAt(origin);
    var operator = browser.browserAt(origin);
    var account  = browser.browserAt(origin);
    var operatorIn = await operator.signIn(OPERATOR_ADDRESS, OPERATOR_PASSWORD);
    var accountIn  = await account.signIn(ACCOUNT_ADDRESS, ACCOUNT_PASSWORD);
    console.log("OBSERVED operator sign-in -> " + operatorIn.status + " " + operatorIn.location);
    console.log("OBSERVED account sign-in -> " + accountIn.status + " " + accountIn.location);
    count("the operator signs in", operatorIn.status === 302 || operatorIn.status === 303,
      operatorIn.status + " " + operatorIn.location);
    count("the mailbox owner signs in", accountIn.status === 302 || accountIn.status === 303,
      accountIn.status + " " + accountIn.location);

    var fx = await fixtureValues(account, accountIn.location);
    var walk = await walkTheRouteTable(patterns, {
      stranger: stranger, account: account, operator: operator,
    }, fx);
    var off = await answersOffTheTable(operator, account, fx);

    // ---- assert -----------------------------------------------------------

    count("the walk read at least " + MIN_GET_ROUTES + " GET routes off the router's table, so " +
      "an enumeration that found nothing fails here", patterns.length >= MIN_GET_ROUTES,
      patterns.length + " GET routes, " + walk.requests + " requests");
    count("every GET route the router registers is classified, so a route added later is " +
      "walked rather than passed over", walk.unclassified.length === 0,
      walk.unclassified.join(", ") || patterns.length + " classified");
    count("every classified route is still registered", walk.stale.length === 0,
      walk.stale.join(", ") || "none stale");
    count("the walk asked for HTML pages and answers that are not pages both",
      walk.pages > 0 && walk.requests > walk.pages, walk.pages + " pages of " + walk.requests);
    count("every route in the table answers with the status, media type and Cache-Control its " +
      "classification names, and every HTML page carries " + JSON.stringify(NO_STORE) +
      " or, asked with no session, " + JSON.stringify(PUBLIC_PAGE),
      walk.findings.length === 0, walk.findings.join(" | ") || walk.requests + " requests");

    count("the domain post rendered the confirmation page rather than acting",
      off.confirm.body.indexOf('name="confirm"') !== -1 ||
        off.confirm.body.indexOf('name="reason"') !== -1,
      JSON.stringify(off.confirm.body.slice(0, 200)));
    count("the conversation with images shown still carries the policy its render passes, " +
      "which admits images from any https origin",
      /img-src 'self' data: https:;/.test(
        String(off.withImages.headers["content-security-policy"] || "")),
      JSON.stringify(off.withImages.headers["content-security-policy"]));
    assertAll(off.pages, NO_STORE, "answers off the route table");

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

module.exports = { name: "web-page-cache-directive", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
