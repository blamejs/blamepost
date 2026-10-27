// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The console is held to the machine and browser it was opened on, and
 * the mailbox is not.
 *
 * Two session readers stand in front of these pages and they read the
 * same cookie under different policies. The one in the request lifecycle
 * resolves an account whatever the device looks like, so a phone moving
 * between wifi and a cell network keeps reading mail. The one the
 * console gate runs is strict: any drift in the address, the agent or
 * the accepted language refuses the request, and the refusal an operator
 * reads says the console is held to the machine it was opened on.
 *
 * That sentence is what this file measures. Until it did, the only thing
 * standing behind the strict policy was a source scan that goes quiet as
 * soon as the option name appears in the file, which answers whether the
 * option is written and not whether a drifted request is turned away.
 *
 * Every vector drives a real signed-in session over a real loopback
 * port, and every refusal is judged by state as well as by status: a
 * route can answer 401 and have written the setting first.
 *
 * What is asked:
 *
 *   - every console route, and the console write, under a session whose
 *     agent has changed, and again under one whose accepted language has
 *     changed;
 *   - the same drifted session against the mailbox, which stays open,
 *     because the split between the two readers is the decision rather
 *     than an accident of where the strict one was mounted;
 *   - the operator's own browser afterwards, which still administers,
 *     because the refusal asks for the password again and does not end
 *     the session somebody else is holding a copy of;
 *   - the session token moved out of the cookie and into the
 *     `Authorization` header, drifted and undrifted, because a gate
 *     reading only the cookie is walked past by moving the token;
 *   - a mailbox owner's session under the same drift, which keeps
 *     reading mail.
 *
 * One reading trips a run driving the header path. A cookie carries its
 * value percent encoded and the `Authorization` header carries the
 * credential as it is, so the string in a `Cookie:` line and the session
 * token are different strings whenever the token holds a character a
 * cookie may not. A vector that lifts the cookie's spelling and presents
 * it as a bearer credential is refused for that reason and not for the
 * binding, and it would report a gate holding when nothing had been
 * asked of it.
 *
 * Run standalone: node test/layer-2-integration/web-console-device-binding.test.js
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
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 4417";
var OTHER_PASSWORD   = "a mailbox owner passphrase 9203";

var OPERATOR = "adam@" + DOMAIN;
var PLAIN    = "carol@" + DOMAIN;

var SESSION_COOKIE = "__Host-bp_session";

// The setting the console write moves, read back off the store rather
// than off the answer, so a refusal is judged by what did not happen.
var SETTING = "publicSiteEnabled";

// The row the console gate files when it turns a drifted request away.
var DEVICE_REFUSED = "blamepost.web.console_device_refused";

// Each of the three signals the framework hashes into the binding that
// this reader can change from one request to the next. The client
// address is the third and it is not one a loopback run can move, so the
// two that are reachable are both driven rather than one standing in for
// the pair.
var DRIFTS = [
  { label: "a browser agent the session was not opened on",
    headers: { "User-Agent": "Mozilla/5.0 (a machine this session was never opened on)" } },
  { label: "an accepted language the session was not opened on",
    headers: { "Accept-Language": "fr-CA" } },
];

var SHUTDOWN_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

function _asRows(value) { return Array.isArray(value) ? value : []; }

async function rowCount(action) {
  await b.audit.flush();
  return _asRows(await b.audit.query({ action: action, order: "desc", limit: 500 })).length;
}

function describe(answer) {
  return answer.status + " " + String(answer.location) + " " +
    String(answer.body || "").slice(0, 120);
}

function carriesConsole(answer) {
  return String(answer.body || "").indexOf("href=\"/admin/domains\"") !== -1;
}

// The page the console gate answers a drifted request with. Matched on
// the headline an operator reads rather than on the status alone,
// because 401 is also what an expired session earns and the two send a
// reader to different places.
function sentToTheDevicePage(answer) {
  return answer.status === 401 &&
    String(answer.body || "").indexOf("Sign in again for the console") !== -1;
}

// Every console route the shipped mount registers, read off the table
// rather than listed here, so a route added later is walked under a
// drifted session on the day it is registered.
function consoleRoutesOf(server) {
  var scratch = new b.router.Router();
  server.web.routes(scratch);
  var gets = [];
  var posts = [];
  scratch.inspectRoutes().forEach(function (route) {
    if (route.pattern !== "/admin" && route.pattern.indexOf("/admin/") !== 0) return;
    if (route.method === "GET") gets.push(route.pattern);
    else if (route.method === "POST") posts.push(route.pattern);
  });
  return { gets: gets, posts: posts };
}

// ---------------------------------------------------------------------------
// The control, before anything drifts
// ---------------------------------------------------------------------------

async function testTheOperatorsOwnDeviceAdministers(operator, table) {
  for (var i = 0; i < table.gets.length; i += 1) {
    var page = await operator.get(table.gets[i]);
    count("the device the session was opened on is served GET " + table.gets[i],
      page.status === 200 && carriesConsole(page), describe(page));
  }
}

// ---------------------------------------------------------------------------
// A drifted session, against every console route
// ---------------------------------------------------------------------------

async function walkDrifted(drift, operator, identity, table) {
  for (var i = 0; i < table.gets.length; i += 1) {
    var page = await operator.get(table.gets[i], drift.headers);
    count(drift.label + " is refused GET " + table.gets[i],
      sentToTheDevicePage(page), describe(page));
    count(drift.label + " is shown none of the console at GET " + table.gets[i],
      !carriesConsole(page), describe(page));
  }

  // The write, judged by the setting rather than by the answer. The
  // front page switch is the probe every gate walk in this suite uses:
  // it is one press, it asks nothing first, and a gate reached past
  // would have published the page.
  count("the front page is not published before the drifted write",
    identity.settings.get(SETTING) !== true, String(identity.settings.get(SETTING)));
  var wrote = await operator.form("/admin/site", { action: "publish" }, drift.headers);
  count(drift.label + " is refused POST /admin/site", sentToTheDevicePage(wrote),
    describe(wrote));
  count(drift.label + ": the refused write did not publish the front page",
    identity.settings.get(SETTING) !== true, String(identity.settings.get(SETTING)));
}

// The refusal an incident is reconstructed from. A gate that turned
// somebody away and recorded nothing leaves the trail showing the
// strangers and not the copied cookie.
async function testEveryRefusalIsOnTheAuditTrail(before, table) {
  var after = await rowCount(DEVICE_REFUSED);
  count("each drifted request left a row naming the console gate that refused it",
    after >= before + (table.gets.length + 1) * DRIFTS.length,
    before + " before, " + after + " after");

  var rows = _asRows(await b.audit.query({ action: DEVICE_REFUSED, order: "desc", limit: 500 }));
  var named = rows.filter(function (row) {
    return String(row.metadata || "").indexOf("/admin/site") !== -1;
  });
  count("and a row names the verb that was refused, which is what an operator can act on",
    named.length > 0, String(rows.length) + " rows");
  count("every row is recorded as a denial rather than as something that happened",
    rows.every(function (row) { return row.outcome === "denied"; }),
    rows.map(function (row) { return row.outcome; }).slice(0, 5).join(", "));
}

// ---------------------------------------------------------------------------
// What the refusal promises the reader
// ---------------------------------------------------------------------------

// "Your mail is untouched and still open." The strict read is mounted on
// the console gate and nowhere else, so the same drifted request reaches
// the mailbox. A change that moved the strict reader into the request
// lifecycle would sign an operator out of their mail on a network
// change, and it would pass every console vector above while doing it.
async function testTheDriftedSessionStillReadsItsMail(operator) {
  for (var i = 0; i < DRIFTS.length; i += 1) {
    var mail = await operator.get("/mail?folder=INBOX", DRIFTS[i].headers);
    count(DRIFTS[i].label + " still reaches the mailbox, which the refusal says is untouched",
      mail.status === 200, describe(mail));
  }
}

// The session row is not destroyed by a refusal. A stranger sending a
// copied cookie from their own machine must not be able to sign the
// operator out by trying.
async function testTheOperatorsOwnDeviceStillAdministers(operator, table) {
  var page = await operator.get("/admin");
  count("the device the session was opened on still administers after the drifted requests",
    page.status === 200 && carriesConsole(page), describe(page));
  var domains = await operator.get(table.gets[1]);
  count("and is still served the rest of the console", domains.status === 200,
    describe(domains));
}

// A mailbox owner is held to no device. The lenient reader is the one in
// front of their pages, and a run where the strict policy had been
// mounted for everybody would refuse them here.
async function testAMailboxOwnerIsHeldToNoDevice(plain) {
  for (var i = 0; i < DRIFTS.length; i += 1) {
    var mail = await plain.get("/mail?folder=INBOX", DRIFTS[i].headers);
    count("a mailbox owner reading mail under " + DRIFTS[i].label + " is not turned away",
      mail.status === 200, describe(mail));
  }
}

// ---------------------------------------------------------------------------
// The token moved out of the cookie
// ---------------------------------------------------------------------------

// Both readers are composed to find the token in the cookie or in the
// `Authorization` header, and the strict one has to read the same two
// places as the lenient one. A gate reading only the cookie is walked
// past by copying the token into a header, so the undrifted half of this
// pair is what proves the header is actually read: without it a refusal
// below would say nothing more than that the header was ignored.
//
// The credential is the session token. A cookie carries it percent
// encoded, and the header carries it as it is, so the two spellings
// differ whenever the token holds a character a cookie may not: a value
// lifted verbatim out of a `Cookie:` line and replayed as a bearer
// credential is not the token and does not authenticate. Reading the
// cookie's spelling here would make every refusal below read as the
// binding when it was the spelling.
async function testTheHeaderPathIsReadAndStillBound(origin, caPem, cookieValue, identity) {
  var token  = decodeURIComponent(cookieValue);
  var bearer = { Authorization: "Bearer " + token };

  count("the token and the cookie's spelling of it are not the same string, which is what " +
    "the reading below has to get right", token !== cookieValue,
    cookieValue.length + " encoded, " + token.length + " as issued");

  var carried = browser.browserAt(origin, { ca: caPem });
  var page = await carried.get("/admin", bearer);
  count("the session token presented in the Authorization header administers, so the " +
    "header is a credential path this gate reads",
    page.status === 200 && carriesConsole(page), describe(page));

  for (var i = 0; i < DRIFTS.length; i += 1) {
    var moved = browser.browserAt(origin, { ca: caPem });
    var refused = await moved.get("/admin",
      Object.assign({}, bearer, DRIFTS[i].headers));
    count("the same token in the header under " + DRIFTS[i].label + " is refused",
      sentToTheDevicePage(refused), describe(refused));
    count("and is shown none of the console", !carriesConsole(refused), describe(refused));
  }

  // The mailbox over the same header path, drifted. The split between
  // the two readers is not a property of the cookie, so it has to hold
  // wherever the token arrives.
  var reading = browser.browserAt(origin, { ca: caPem });
  var mail = await reading.get("/mail?folder=INBOX",
    Object.assign({}, bearer, DRIFTS[0].headers));
  count("the same drifted token still reaches the mailbox over the header path",
    mail.status === 200, describe(mail));

  // The write over the header path, with the drift, judged by the
  // setting. A reader that took the header only for GET would leave the
  // one request that changes something outside the gate.
  var writer = browser.browserAt(origin, { ca: caPem });
  await writer.readCsrf("/sign-in");
  var wrote = await writer.form("/admin/site", { action: "publish" },
    Object.assign({}, bearer, DRIFTS[0].headers));
  count("a console write carrying the token in the header under a changed agent is refused",
    wrote.status === 401 || wrote.status === 403, describe(wrote));
  count("and the front page is still not published",
    identity.settings.get(SETTING) !== true, String(identity.settings.get(SETTING)));
}

// ---------------------------------------------------------------------------
// Fixture
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
  var root    = helpers.tempDir("web-console-device-binding");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "console device binding run" });
    await identity.accounts.create({
      address: OPERATOR, password: ADMIN_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: PLAIN, password: OTHER_PASSWORD });

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
    routesWalked = table.gets.length;
    count("the walk reads the console routes off the table the mount registers",
      table.gets.length >= 10 && table.posts.length >= 9,
      table.gets.length + " GET, " + table.posts.length + " POST");

    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var operator = browser.browserAt(origin, { ca: material.caPem });
    count("the operator signs in",
      (await operator.signIn(OPERATOR, ADMIN_PASSWORD)).status === 302);
    var plain = browser.browserAt(origin, { ca: material.caPem });
    count("the mailbox owner signs in",
      (await plain.signIn(PLAIN, OTHER_PASSWORD)).status === 302);

    var token = operator.cookies.read(SESSION_COOKIE);
    count("the operator's session cookie is the one the console gate reads",
      typeof token === "string" && token.length > 0, String(token).slice(0, 8));

    await testTheOperatorsOwnDeviceAdministers(operator, table);

    var before = await rowCount(DEVICE_REFUSED);
    for (var i = 0; i < DRIFTS.length; i += 1) {
      await walkDrifted(DRIFTS[i], operator, identity, table);
    }
    await testEveryRefusalIsOnTheAuditTrail(before, table);

    await testTheDriftedSessionStillReadsItsMail(operator);
    await testTheOperatorsOwnDeviceStillAdministers(operator, table);
    await testAMailboxOwnerIsHeldToNoDevice(plain);
    await testTheHeaderPathIsReadAndStillBound(origin, material.caPem, token, identity);

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

module.exports = {
  name: "web-console-device-binding", run: run, getChecks: helpers.getChecks,
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
