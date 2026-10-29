// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every route of the administration console, read off the route table the
 * shipped mount registers, asked by every reader who must be turned away
 * and by every request shape that could route around the gate.
 *
 * The console routes are listed here by method and pattern, and the run
 * fails when the table holds a console route this file does not name or
 * when a named route is no longer registered. A route added later is
 * therefore walked on the day it is registered.
 *
 * Each console POST carries a payload that changes something when it is
 * performed, and a reading that says whether it did. Every refusal below
 * is judged by that reading as well as by the status, and the run ends by
 * sending each payload as the operator and requiring it to land, so no
 * refusal can be satisfied by a payload the route would have ignored.
 *
 * The readers turned away:
 *
 *   - a request with no session, which is sent to the sign-in page;
 *   - a mailbox owner who does not hold the operator role, refused 403;
 *   - an administrator whose session was opened before the account was
 *     suspended, before it was archived, and before the domain its
 *     address belongs to was withdrawn. `authenticate` refuses all three
 *     at sign in, and an open session has to stop at the next request.
 *
 * The request shapes:
 *
 *   - the path spelled with a trailing slash, in other cases, with dot
 *     segments, with a doubled leading slash, and with encoded letters,
 *     separators and a NUL;
 *   - HEAD and OPTIONS, the write methods no console route registers, and
 *     the method-override headers and field some frameworks read;
 *   - a POST method written in lower and mixed case over HTTP/2, which
 *     carries the method as written;
 *   - every console POST as the operator with no token, with a token
 *     minted in another session, from another origin, and reported by the
 *     browser as cross site;
 *   - every console GET as the operator with the POST payload of the same
 *     path in its query string, which must render and change nothing.
 *
 * Run standalone: node test/layer-2-integration/web-admin-route-gate.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";

var DOMAIN           = "example.com";
var WITHDRAWN_DOMAIN = "withdrawn.example";
var UNKEYED_DOMAIN   = "unkeyed.example";
var SEIZED_DOMAIN    = "seized.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 5512";
var OTHER_PASSWORD   = "another operator passphrase 8841";

var OPERATOR        = "adam@" + DOMAIN;
var PLAIN           = "carol@" + DOMAIN;
var VICTIM          = "dana@" + DOMAIN;
var SUSPENDED_ADMIN = "sam@" + DOMAIN;
var ARCHIVED_ADMIN  = "arlo@" + DOMAIN;
var WITHDRAWN_ADMIN = "wren@" + WITHDRAWN_DOMAIN;

var SEIZED_ALIAS  = "seized@" + DOMAIN;
var SEIZED_TARGET = "attacker@example.net";

var FOREIGN_ORIGIN = "https://attacker.example.net";
var CROSS_SITE = Object.freeze({
  "Sec-Fetch-Site": "cross-site",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});

var SETTING = "publicSiteEnabled";

// The row names the landed readings count. Read back by name, because the
// audit chain drops an event whose namespace was never registered.
var LOCKOUT_RELEASED = "account.lockout_released";
var WINDOW_RELEASED  = "domain.sending_credential_ceiling_released";
var QUEUE_FORCED     = "blamepost.mail.queue.run_forced";

// The floors on what the walk reads off the route table. Below the count
// the console registers today, and far above an empty table.
var MIN_CONSOLE_GETS  = 10;
var MIN_CONSOLE_POSTS = 9;

var SHUTDOWN_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// The console routes
// ---------------------------------------------------------------------------

// Every console GET the table registers.
var CONSOLE_GETS = [
  "/admin", "/admin/domains", "/admin/accounts", "/admin/lockouts", "/admin/aliases",
  "/admin/credentials", "/admin/dkim", "/admin/dmarc", "/admin/queue", "/admin/audit",
];

// Every console POST the table registers, each with the payload that
// changes something when it is performed and the reading that says it did.
// `landed` compares against the baseline taken before any request is sent.
// `inert` marks the one route this run cannot make land: a server naming no
// zone provider answers the DMARC publish with 503, so the control reads
// that answer instead of a change.
function consolePosts(fx) {
  return {
    "/admin/site": {
      fields: { action: "publish" },
      landed: function () { return fx.identity.settings.get(SETTING) === true; },
    },
    "/admin/domains": {
      fields: { action: "add", domain: SEIZED_DOMAIN },
      landed: function () { return fx.identity.domains.get(SEIZED_DOMAIN) !== null; },
    },
    "/admin/accounts": {
      fields: { action: "suspend", id: fx.victimId, reason: "seizing the mailbox" },
      landed: function () { return fx.identity.accounts.get(VICTIM).status !== "active"; },
    },
    "/admin/lockouts": {
      fields: { address: VICTIM, reason: "seizing the sign-in budget" },
      landed: async function () {
        return (await rowCount(LOCKOUT_RELEASED)) > fx.baseline[LOCKOUT_RELEASED];
      },
    },
    "/admin/aliases": {
      fields: { action: "add", address: SEIZED_ALIAS, destination: SEIZED_TARGET },
      landed: function () {
        return fx.identity.aliases.list({ address: SEIZED_ALIAS, includeDisabled: true })
          .length > 0;
      },
    },
    "/admin/credentials": {
      fields: { action: "release-window", id: fx.credentialId, confirm: fx.credentialId,
                reason: "seizing the window" },
      landed: async function () {
        return (await rowCount(WINDOW_RELEASED)) > fx.baseline[WINDOW_RELEASED];
      },
    },
    "/admin/dkim": {
      fields: { action: "generate", domain: UNKEYED_DOMAIN },
      landed: function () { return fx.dkim.list(UNKEYED_DOMAIN).length > 0; },
    },
    "/admin/dmarc": {
      fields: { action: "zone-prepare", domain: DOMAIN, level: "reject",
                reason: "seizing the policy" },
      landed: function () { return false; },
      inert:  true,
    },
    "/admin/queue": {
      fields: { action: "run" },
      landed: async function () {
        return (await rowCount(QUEUE_FORCED)) > fx.baseline[QUEUE_FORCED];
      },
    },
  };
}

function _asRows(value) { return Array.isArray(value) ? value : []; }

async function rowCount(action) {
  await b.audit.flush();
  return _asRows(await b.audit.query({ action: action, order: "desc", limit: 500 })).length;
}

// Which payloads have landed, by path. An empty list is the clean answer.
async function landedPaths(posts) {
  var out = [];
  var paths = Object.keys(posts);
  for (var i = 0; i < paths.length; i += 1) {
    if (await posts[paths[i]].landed()) out.push(paths[i]);
  }
  return out;
}

function urlencoded(fields, token) {
  var parts = [];
  var names = Object.keys(fields);
  for (var i = 0; i < names.length; i += 1) {
    parts.push(encodeURIComponent(names[i]) + "=" + encodeURIComponent(fields[names[i]]));
  }
  if (token !== undefined) parts.push("_csrf=" + encodeURIComponent(token));
  return parts.join("&");
}

function carriesConsole(answer) {
  return String(answer.body || "").indexOf("href=\"/admin/domains\"") !== -1;
}

function sentToSignIn(answer) {
  return answer.status === 302 && String(answer.location || "").indexOf("/sign-in") === 0;
}

function notPermitted(answer) {
  return answer.status === 403 && String(answer.body).indexOf("Not your console") !== -1;
}

function describe(answer) {
  return answer.status + " " + String(answer.location) + " " +
    String(answer.body || "").slice(0, 120);
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

function consoleRoutesOf(server) {
  var scratch = new b.router.Router();
  server.web.routes(scratch);
  var gets = [];
  var posts = [];
  var others = [];
  scratch.inspectRoutes().forEach(function (route) {
    if (route.pattern !== "/admin" && route.pattern.indexOf("/admin/") !== 0) return;
    if (route.method === "GET") gets.push(route.pattern);
    else if (route.method === "POST") posts.push(route.pattern);
    else others.push(route.method + " " + route.pattern);
  });
  return { gets: gets, posts: posts, others: others };
}

function testTheTableIsTheOneThisFileWalks(table, posts) {
  count("the walk reads at least " + MIN_CONSOLE_GETS + " console GET routes off the table",
    table.gets.length >= MIN_CONSOLE_GETS, table.gets.join(", "));
  count("and at least " + MIN_CONSOLE_POSTS + " console POST routes",
    table.posts.length >= MIN_CONSOLE_POSTS, table.posts.join(", "));
  count("the console registers no method other than GET and POST, so the gate below " +
    "covers every console route the table holds",
    table.others.length === 0, table.others.join(", ") || "none");

  var unnamedGets = table.gets.filter(function (p) { return CONSOLE_GETS.indexOf(p) === -1; });
  var staleGets = CONSOLE_GETS.filter(function (p) { return table.gets.indexOf(p) === -1; });
  count("every console GET the table registers is walked by this file",
    unnamedGets.length === 0, unnamedGets.join(", ") || "all named");
  count("and every console GET this file names is still registered",
    staleGets.length === 0, staleGets.join(", ") || "none stale");

  var named = Object.keys(posts);
  var unnamedPosts = table.posts.filter(function (p) { return named.indexOf(p) === -1; });
  var stalePosts = named.filter(function (p) { return table.posts.indexOf(p) === -1; });
  count("every console POST the table registers carries a payload and a reading here",
    unnamedPosts.length === 0, unnamedPosts.join(", ") || "all named");
  count("and every console POST this file names is still registered",
    stalePosts.length === 0, stalePosts.join(", ") || "none stale");
}

// ---------------------------------------------------------------------------
// Readers turned away
// ---------------------------------------------------------------------------

// One reader against every console route. `verdict` decides whether an
// answer is the refusal this reader is owed.
async function walkRefused(label, reader, table, posts, verdict) {
  for (var i = 0; i < table.gets.length; i += 1) {
    var page = await reader.get(table.gets[i]);
    count(label + " is refused GET " + table.gets[i], verdict(page), describe(page));
    count(label + " is shown none of the console at GET " + table.gets[i],
      !carriesConsole(page), describe(page));
  }
  for (var j = 0; j < table.posts.length; j += 1) {
    var path = table.posts[j];
    var answer = await reader.form(path, posts[path].fields);
    count(label + " is refused POST " + path, verdict(answer), describe(answer));
    count(label + ": the POST to " + path + " changed nothing",
      !(await posts[path].landed()), describe(answer));
  }
}

async function testAStrangerIsSentToSignIn(stranger, table, posts) {
  var form = await stranger.readCsrf("/sign-in");
  count("the stranger holds a token, so a refusal below is the session gate rather than " +
    "the token compare", form.token.length > 0, form.page.status);
  await walkRefused("a request with no session", stranger, table, posts, sentToSignIn);
}

async function testAMailboxOwnerIsRefused(plain, table, posts) {
  await walkRefused("a mailbox owner without the role", plain, table, posts, notPermitted);
}

// A session opened while the account administered this server, and the
// change that takes the account out of service made afterwards.
async function openConsoleSession(origin, caPem, address, password) {
  var reader = browser.browserAt(origin, { ca: caPem });
  var landed = await reader.signIn(address, password);
  count(address + " signs in while in service", landed.status === 302, describe(landed));
  var page = await reader.get("/admin");
  count("and that session administers this server before anything changes",
    page.status === 200 && carriesConsole(page), describe(page));
  return reader;
}

async function testASuspendedAdministratorsSessionStops(reader, identity, table, posts) {
  var row = identity.accounts.get(SUSPENDED_ADMIN);
  await identity.accounts.suspend({ id: row.id, reason: "the credential was reported stolen" });
  await walkRefused("a session opened before its account was suspended",
    reader, table, posts, sentToSignIn);
}

async function testAnArchivedAdministratorsSessionStops(reader, identity, table, posts) {
  var row = identity.accounts.get(ARCHIVED_ADMIN);
  await identity.accounts["delete"]({ id: row.id, reason: "the owner has left" });
  await walkRefused("a session opened before its account was archived",
    reader, table, posts, sentToSignIn);
}

// The domain an administrator's address belongs to, withdrawn while that
// administrator's session is open. `authenticate` refuses every account on
// a withdrawn domain, and the console's own last-administrator measurement
// counts such an account as unable to sign in, so the session already open
// has to stop at its next request as well. The mailbox and JMAP are asked
// too, because the account the session resolves is the same on all three.
async function testASessionOnAWithdrawnDomainStops(reader, identity, table, posts) {
  await identity.domains.setStatus({
    domain: WITHDRAWN_DOMAIN, status: "disabled", reason: "the domain is under investigation" });
  count("the domain is withdrawn", identity.domains.get(WITHDRAWN_DOMAIN).status === "disabled",
    identity.domains.get(WITHDRAWN_DOMAIN).status);

  await walkRefused("a session opened before its domain was withdrawn",
    reader, table, posts, sentToSignIn);

  var mail = await reader.get("/mail?folder=INBOX");
  count("and that session reaches no mail on the withdrawn domain", sentToSignIn(mail),
    describe(mail));
  var session = await reader.get("/jmap/session", { Accept: "application/json" });
  count("nor a JMAP session document", session.status === 401, describe(session));
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

// The front page switch is the probe. It is one press, it needs no
// confirmation, and a gate this reached past would change the setting.
var PATH_VARIANTS = [
  "/admin/site/",
  "/ADMIN/site",
  "/Admin/Site",
  "/admin/SITE",
  "/%61dmin/site",
  "/admin/%73ite",
  "//admin/site",
  "///admin/site",
  "/admin/./site",
  "/admin/../admin/site",
  "/admin/%2e%2e/admin/site",
  "/static/../admin/site",
  "/admin%2Fsite",
  "/admin%5Csite",
  "/admin/site%00",
  "/admin/site;x",
  "/admin/site%20",
];

async function testNoSpellingOfThePathReachesPastTheGate(label, reader, posts, verdict) {
  var probe = posts["/admin/site"];
  for (var i = 0; i < PATH_VARIANTS.length; i += 1) {
    var body = urlencoded(probe.fields, reader.csrf());
    var answer = await reader.post(PATH_VARIANTS[i], "application/x-www-form-urlencoded", body);
    count(label + " posting to " + PATH_VARIANTS[i] + " is refused or finds no route",
      verdict(answer) || answer.status === 404 || answer.status === 400, describe(answer));
    count(label + ": " + PATH_VARIANTS[i] + " did not publish the front page",
      !(await probe.landed()), describe(answer));
  }
}

async function testNoOtherMethodReachesAConsoleWrite(label, reader, posts) {
  var probes = ["/admin/site", "/admin/accounts"];
  var methods = ["PUT", "PATCH", "DELETE", "OPTIONS"];
  for (var i = 0; i < probes.length; i += 1) {
    for (var m = 0; m < methods.length; m += 1) {
      var answer = await reader.request(methods[m], probes[i], {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin":       reader.origin,
        "X-CSRF-Token": reader.csrf(),
      }, urlencoded(posts[probes[i]].fields, reader.csrf()));
      count(label + ": " + methods[m] + " " + probes[i] + " answers no console page",
        answer.status !== 200 && !carriesConsole(answer), describe(answer));
      count(label + ": " + methods[m] + " " + probes[i] + " changed nothing",
        !(await posts[probes[i]].landed()), describe(answer));
    }
  }
}

async function testHeadDisclosesNoConsolePage(label, reader, table) {
  for (var i = 0; i < table.gets.length; i += 1) {
    var answer = await reader.request("HEAD", table.gets[i], { Accept: "text/html" });
    count(label + ": HEAD " + table.gets[i] + " is not answered as a console page",
      answer.status !== 200, describe(answer));
  }
}

// A GET carrying the method-override headers and field that some frameworks
// read as a request to treat the GET as a POST.
async function testAMethodOverrideIsNotRead(operator, posts) {
  var probe = posts["/admin/accounts"];
  var query = urlencoded(Object.assign({ _method: "POST" }, probe.fields), operator.csrf());
  var answer = await operator.get("/admin/accounts?" + query, {
    "X-HTTP-Method-Override": "POST",
    "X-HTTP-Method":          "POST",
    "X-Method-Override":      "POST",
    "X-CSRF-Token":           operator.csrf(),
  });
  count("a GET asking to be read as a POST is answered as the listing",
    answer.status === 200 && String(answer.location) === "null", describe(answer));
  count("and the account the override named is still active", !(await probe.landed()),
    describe(answer));

  var site = posts["/admin/site"];
  var overridden = await operator.request("GET", "/admin/site?" +
    urlencoded(Object.assign({ _method: "POST" }, site.fields), operator.csrf()), {
    "X-HTTP-Method-Override": "POST",
    "X-CSRF-Token":           operator.csrf(),
  });
  count("a GET to a POST-only console path with an override finds no route",
    overridden.status === 404, describe(overridden));
  count("and the front page was not published", !(await site.landed()), describe(overridden));
}

// HTTP/2 carries `:method` as written. A route matched in a case the
// gates did not read as POST would run with the CSRF gate, the fetch
// metadata gate and the body reader skipped. The CSRF gate upper-cases
// the method before it compares, so a forged request in any spelling is
// refused there with 403; a spelling that no gate reads finds no route
// and gets 404. Either answer is a refusal that reaches no console page.
async function testALowerCaseMethodOverHttp2FindsNoRoute(label, reader, posts) {
  var spellings = ["post", "Post", "pOST"];
  var probes = ["/admin/site", "/admin/accounts"];
  for (var i = 0; i < probes.length; i += 1) {
    for (var s = 0; s < spellings.length; s += 1) {
      var answer = await reader.request(spellings[s], probes[i], {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin":       FOREIGN_ORIGIN,
      }, urlencoded(posts[probes[i]].fields));
      count(label + ": " + spellings[s] + " " + probes[i] + " over HTTP/2 is refused before any " +
        "console route runs",
        (answer.status === 403 || answer.status === 404) && !carriesConsole(answer),
        describe(answer));
      count(label + ": " + spellings[s] + " " + probes[i] + " changed nothing",
        !(await posts[probes[i]].landed()), describe(answer));
    }
  }
}

// ---------------------------------------------------------------------------
// CSRF and cross site, on every console POST
// ---------------------------------------------------------------------------

async function testEveryConsoleWriteRefusesAForgedRequest(operator, elsewhereToken, table, posts,
  origin) {
  for (var i = 0; i < table.posts.length; i += 1) {
    var path = table.posts[i];
    var probe = posts[path];

    var bare = await operator.post(path, "application/x-www-form-urlencoded",
      urlencoded(probe.fields), { "X-CSRF-Token": "" });
    count("the operator's POST to " + path + " with no token is refused",
      bare.status === 403, describe(bare));

    var foreign = await operator.post(path, "application/x-www-form-urlencoded",
      urlencoded(probe.fields, elsewhereToken), { "X-CSRF-Token": elsewhereToken });
    count("the operator's POST to " + path + " with a token minted in another session is " +
      "refused", foreign.status === 403, describe(foreign));

    var offsite = await operator.form(path, probe.fields, { Origin: FOREIGN_ORIGIN });
    count("the operator's POST to " + path + " from another origin is refused",
      offsite.status === 403, describe(offsite));

    var crossSite = await operator.form(path, probe.fields,
      Object.assign({ Origin: origin }, CROSS_SITE));
    count("the operator's POST to " + path + " reported as cross site is refused",
      crossSite.status === 403, describe(crossSite));

    count("and none of the four changed what " + path + " changes", !(await probe.landed()),
      path);
  }
}

// ---------------------------------------------------------------------------
// A GET changes nothing
// ---------------------------------------------------------------------------

async function testEveryConsoleGetChangesNothing(operator, table, posts) {
  var fallback = Object.assign({}, posts["/admin/site"].fields, posts["/admin/accounts"].fields);
  for (var i = 0; i < table.gets.length; i += 1) {
    var path = table.gets[i];
    var fields = Object.prototype.hasOwnProperty.call(posts, path) ? posts[path].fields : fallback;
    var page = await operator.get(path + "?" + urlencoded(fields, operator.csrf()));
    count("the operator's GET " + path + " carrying a write payload renders the page",
      page.status === 200, describe(page));
    var moved = await landedPaths(posts);
    count("and it changed nothing any console write changes", moved.length === 0,
      path + " moved " + moved.join(", "));
  }
}

// ---------------------------------------------------------------------------
// The controls
// ---------------------------------------------------------------------------

async function testTheOperatorIsServedEveryRoute(operator, table, posts) {
  for (var i = 0; i < table.gets.length; i += 1) {
    var page = await operator.get(table.gets[i]);
    count("the operator is served GET " + table.gets[i],
      page.status === 200 && carriesConsole(page), describe(page));
  }
  for (var j = 0; j < table.posts.length; j += 1) {
    var path = table.posts[j];
    var answer = await operator.form(path, posts[path].fields);
    if (posts[path].inert) {
      count("the operator's POST to " + path + " reaches the route, which answers that this " +
        "server edits no zone", answer.status === 503, describe(answer));
      continue;
    }
    count("the operator's POST to " + path + " lands, so every refusal of that payload above " +
      "was a refusal of a live write", answer.status === 302 && (await posts[path].landed()),
      describe(answer));
  }
}

// ---------------------------------------------------------------------------

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

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

async function run() {
  var root    = helpers.tempDir("web-admin-route-gate");
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
  var routesWalked = 0;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: WITHDRAWN_DOMAIN });
    await identity.domains.add({ domain: UNKEYED_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "console route gate run" });

    await identity.accounts.create({ address: OPERATOR, password: ADMIN_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: PLAIN, password: OTHER_PASSWORD });
    var victim = await identity.accounts.create({ address: VICTIM, password: OTHER_PASSWORD });
    await identity.accounts.create({
      address: SUSPENDED_ADMIN, password: OTHER_PASSWORD, isAdmin: true });
    await identity.accounts.create({
      address: ARCHIVED_ADMIN, password: OTHER_PASSWORD, isAdmin: true });
    await identity.accounts.create({
      address: WITHDRAWN_ADMIN, password: OTHER_PASSWORD, isAdmin: true });

    var credential = await identity.credentials.create({
      domain: DOMAIN, bounceMailbox: PLAIN, reason: "the application the route gate run names",
    });

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });

    // Read before the server starts, so the mount the listener serves is
    // the last one made on this handle.
    var table = consoleRoutesOf(server);
    routesWalked = table.gets.length + table.posts.length;

    await server.start();
    running = true;

    var fx = {
      identity:     identity,
      dkim:         server.mail.dkim,
      victimId:     victim.id,
      credentialId: credential.id,
      baseline:     {},
    };
    fx.baseline[LOCKOUT_RELEASED] = await rowCount(LOCKOUT_RELEASED);
    fx.baseline[WINDOW_RELEASED]  = await rowCount(WINDOW_RELEASED);
    fx.baseline[QUEUE_FORCED]     = await rowCount(QUEUE_FORCED);
    var posts = consolePosts(fx);

    testTheTableIsTheOneThisFileWalks(table, posts);
    count("nothing any console write changes has changed before the first request",
      (await landedPaths(posts)).length === 0, (await landedPaths(posts)).join(", "));

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var ca     = material.caPem;

    var operator = browser.browserAt(origin, { ca: ca });
    count("the operator signs in", (await operator.signIn(OPERATOR, ADMIN_PASSWORD)).status === 302);
    var plain = browser.browserAt(origin, { ca: ca });
    count("the mailbox owner signs in", (await plain.signIn(PLAIN, OTHER_PASSWORD)).status === 302);
    var operatorH2 = browser.browserAt(origin, { ca: ca, http2: true });
    count("the operator signs in over HTTP/2",
      (await operatorH2.signIn(OPERATOR, ADMIN_PASSWORD)).status === 302);
    var plainH2 = browser.browserAt(origin, { ca: ca, http2: true });
    count("the mailbox owner signs in over HTTP/2",
      (await plainH2.signIn(PLAIN, OTHER_PASSWORD)).status === 302);
    var elsewhere = browser.browserAt(origin, { ca: ca });
    var elsewhereToken = (await elsewhere.readCsrf("/sign-in")).token;
    count("a second client is issued a token of its own",
      elsewhereToken.length > 0 && elsewhereToken !== operator.csrf(), elsewhereToken.slice(0, 8));

    var suspended = await openConsoleSession(origin, ca, SUSPENDED_ADMIN, OTHER_PASSWORD);
    var archived  = await openConsoleSession(origin, ca, ARCHIVED_ADMIN, OTHER_PASSWORD);
    var withdrawn = await openConsoleSession(origin, ca, WITHDRAWN_ADMIN, OTHER_PASSWORD);

    await testAStrangerIsSentToSignIn(browser.browserAt(origin, { ca: ca }), table, posts);
    await testAMailboxOwnerIsRefused(plain, table, posts);
    await testASuspendedAdministratorsSessionStops(suspended, identity, table, posts);
    await testAnArchivedAdministratorsSessionStops(archived, identity, table, posts);

    await testEveryConsoleWriteRefusesAForgedRequest(operator, elsewhereToken, table, posts,
      origin);
    await testEveryConsoleGetChangesNothing(operator, table, posts);

    var stranger = browser.browserAt(origin, { ca: ca });
    await stranger.readCsrf("/sign-in");
    await testNoSpellingOfThePathReachesPastTheGate("a mailbox owner", plain, posts,
      notPermitted);
    await testNoSpellingOfThePathReachesPastTheGate("a request with no session", stranger, posts,
      sentToSignIn);
    await testNoOtherMethodReachesAConsoleWrite("the operator", operator, posts);
    await testNoOtherMethodReachesAConsoleWrite("a mailbox owner", plain, posts);
    await testHeadDisclosesNoConsolePage("a mailbox owner", plain, table);
    await testHeadDisclosesNoConsolePage("a request with no session", stranger, table);
    await testAMethodOverrideIsNotRead(operator, posts);
    await testALowerCaseMethodOverHttp2FindsNoRoute("the operator", operatorH2, posts);
    await testALowerCaseMethodOverHttp2FindsNoRoute("a mailbox owner", plainH2, posts);

    await testASessionOnAWithdrawnDomainStops(withdrawn, identity, table, posts);

    await testTheOperatorIsServedEveryRoute(operator, table, posts);

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
    console.log("EXAMINED " + routesWalked + " console-routes");
  }
}

module.exports = { name: "web-admin-route-gate", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
