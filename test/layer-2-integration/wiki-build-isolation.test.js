// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A documentation block the reference wiki cannot build takes the wiki
 * down and leaves the rest of the browser surface running.
 *
 * The wiki is generated from the documentation blocks when the web
 * interface is created, and the builder throws on a block it refuses. This
 * file plants one refused block in a fixture tree, confirms the builder
 * refuses that tree on its own and names the file and line, and then
 * builds the real web surface with the builder pointed at the fixture.
 * The shipped tree is not touched: the builder is the real one, reading
 * the fixture through its own `root` option.
 *
 * Against that server, on a real listener:
 *
 *   - `blamepost.web.serve` returns and the listener starts;
 *   - the sign-in page answers, an operator signs in, the mailbox the
 *     sign-in lands on answers 200, the administration console answers
 *     200, and the JMAP session document answers 200;
 *   - with the public site not published, a reader with no session is
 *     sent to the sign-in page from `/wiki`, the same gate the served wiki
 *     puts in front of that reader;
 *   - a signed-in reader is answered 503 at `/wiki` and below it, and the
 *     page does not carry the builder's message or the fixture path;
 *   - with the site published, a reader with no session is answered 503
 *     at `/wiki` and below it, the front page still answers 200 and does
 *     not link `/wiki`, and the sitemap still answers and does not name
 *     `/wiki`;
 *   - one audit row under `blamepost.web.wiki_unavailable` carries the
 *     builder's message, the file and the line;
 *   - the error log carries a line naming the same message.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/wiki-build-isolation.test.js
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

var OPERATOR_ADDRESS  = "wickham@" + DOMAIN;
var OPERATOR_PASSWORD = "harbor ledger pewter 3318";

var HTTP_TIMEOUT_MS = 5000;

var UNAVAILABLE_ACTION = "blamepost.web.wiki_unavailable";

// The planted file, as the builder names it, and the block in it. The
// block opens on line 2, and its slug is not lowercase letters and digits
// joined by hyphens, which the builder refuses.
var BROKEN_FILE = "lib/broken.js";
var BROKEN_LINE = 2;
var BROKEN_SOURCE = [
  "\"use strict\";",
  "/**",
  " * @module blamepost.fixture.broken",
  " * @title  Broken",
  " * @slug   Not A Slug",
  " *",
  " * @intro",
  " *   A module block whose slug no page can be addressed by.",
  " */",
  "",
].join("\n");

// Paths under `/wiki` at each depth the served wiki answers.
var WIKI_PATHS = ["/wiki", "/wiki/specs", "/wiki/config/load"];

var WIKI_NAV_LINK = 'href="/wiki"';

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

function plantBrokenTree(root) {
  var tree = nodePath.join(root, "tree");
  var file = nodePath.join(tree, BROKEN_FILE);
  nodeFs.mkdirSync(nodePath.dirname(file), { recursive: true });
  nodeFs.writeFileSync(file, BROKEN_SOURCE, "utf8");
  return tree;
}

function isSignInRedirect(res) {
  return (res.status === 302 || res.status === 303) &&
    typeof res.location === "string" && /^\/sign-in(?:\?|$)/.test(res.location);
}

function siteNavOf(body) {
  var nav = /<nav class="sitenav"[\s\S]*?<\/nav>/.exec(body);
  return nav === null ? "" : nav[0];
}

function theBuilderRefusesTheTree(tree) {
  var refusal = null;
  try { wiki.build({ root: tree }); }
  catch (e) { refusal = e; }
  var where = BROKEN_FILE + ":" + BROKEN_LINE;
  count("the builder refuses the planted tree on its own, naming the file and line",
    refusal instanceof TypeError && refusal.message.indexOf(where) !== -1,
    refusal ? refusal.message : "the tree built");
  return refusal.message;
}

async function theSurfaceAnswersWithoutTheWiki(origin) {
  var stranger = browser.browserAt(origin);
  var signInPage = await stranger.get("/sign-in");
  console.log("OBSERVED GET /sign-in -> " + signInPage.status);
  count("the sign-in page answers", signInPage.status === 200, signInPage.status);

  var operator = browser.browserAt(origin);
  var landing = await operator.signIn(OPERATOR_ADDRESS, OPERATOR_PASSWORD);
  console.log("OBSERVED sign-in -> " + landing.status + " " + landing.location);
  count("the operator signs in", landing.status === 302 || landing.status === 303,
    landing.status + " " + landing.location);

  var mailbox = await operator.get(landing.location);
  console.log("OBSERVED GET " + landing.location + " -> " + mailbox.status);
  count("the mailbox the sign-in lands on answers",
    mailbox.status === 200 && mailbox.body.indexOf('<h1 class="pane-title">') !== -1,
    mailbox.status + " " + JSON.stringify(mailbox.body.slice(0, 160)));

  var console_ = await operator.get("/admin");
  console.log("OBSERVED GET /admin -> " + console_.status);
  count("the administration console answers",
    console_.status === 200 && console_.body.indexOf('<h1 class="pane-title">Overview</h1>') !== -1,
    console_.status + " " + JSON.stringify(console_.body.slice(0, 160)));

  var session = await operator.get("/jmap/session", { Accept: "application/json" });
  console.log("OBSERVED GET /jmap/session -> " + session.status);
  var document;
  try { document = JSON.parse(session.body); }
  catch (_e) { document = null; }
  count("the JMAP session document answers",
    session.status === 200 && document !== null && typeof document.apiUrl === "string",
    session.status + " " + JSON.stringify(session.body.slice(0, 160)));

  return operator;
}

async function aStrangerMeetsTheSameGateWhileTheSiteIsWithdrawn(origin) {
  var stranger = browser.browserAt(origin);
  var res = await stranger.get("/wiki");
  console.log("OBSERVED unpublished, no session: GET /wiki -> " + res.status + " " + res.location);
  count("with the site not published, a reader with no session is sent to the sign-in page " +
    "from /wiki", isSignInRedirect(res), res.status + " " + res.location);
}

async function everyWikiPathAnswersUnavailable(reader, label, refusalMessage) {
  var wrong = [];
  var leaked = [];
  for (var i = 0; i < WIKI_PATHS.length; i += 1) {
    var res = await reader.get(WIKI_PATHS[i]);
    console.log("OBSERVED " + label + ": GET " + WIKI_PATHS[i] + " -> " + res.status);
    if (res.status !== 503) wrong.push(WIKI_PATHS[i] + " " + res.status);
    if (res.body.indexOf(BROKEN_FILE) !== -1 || res.body.indexOf(refusalMessage) !== -1) {
      leaked.push(WIKI_PATHS[i]);
    }
  }
  count(label + ", every wiki path answers 503", wrong.length === 0,
    wrong.join(" | ") || WIKI_PATHS.length + " paths");
  count(label + ", the unavailable page carries neither the builder's message nor the file",
    leaked.length === 0, leaked.join(" | ") || "none");
}

async function thePublicSiteStopsListingTheWiki(origin) {
  var stranger = browser.browserAt(origin);
  var front = await stranger.get("/");
  console.log("OBSERVED published, no session: GET / -> " + front.status);
  count("with the site published, the front page answers", front.status === 200, front.status);
  count("and its navigation does not link /wiki",
    siteNavOf(front.body).indexOf(WIKI_NAV_LINK) === -1 && front.body.indexOf(WIKI_NAV_LINK) === -1,
    JSON.stringify(siteNavOf(front.body)));

  var map = await stranger.get("/sitemap.xml");
  console.log("OBSERVED published, no session: GET /sitemap.xml -> " + map.status + " " +
    JSON.stringify(map.body));
  count("the sitemap answers", map.status === 200, map.status);
  count("and does not name /wiki", map.body.indexOf("/wiki</loc>") === -1, JSON.stringify(map.body));
  count("and still names the front page", map.body.indexOf("<loc>https://" + HOSTNAME) !== -1,
    JSON.stringify(map.body));

  return stranger;
}

async function theFailureIsRecorded(refusalMessage, logged) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: UNAVAILABLE_ACTION, limit: 20, offset: 0 });
  rows = Array.isArray(rows) ? rows : (rows && Array.isArray(rows.rows) ? rows.rows : []);
  console.log("OBSERVED audit rows under " + UNAVAILABLE_ACTION + ": " + rows.length);
  count("one audit row records that the wiki is unavailable", rows.length === 1, rows.length);
  if (rows.length !== 1) return;
  var meta = helpers.metadataOf(rows[0]);
  console.log("OBSERVED audit metadata: " + JSON.stringify(meta));
  count("the row is a failure", rows[0].outcome === "failure", rows[0].outcome);
  count("the row carries the builder's message", meta.error === refusalMessage, JSON.stringify(meta));
  count("the row names the file and the line the builder named",
    meta.file === BROKEN_FILE && meta.line === BROKEN_LINE, JSON.stringify(meta));

  var named = logged.filter(function (line) { return line.indexOf(refusalMessage) !== -1; });
  console.log("OBSERVED error log lines naming the refusal: " + named.length);
  count("the error log carries a line naming the builder's message", named.length >= 1,
    JSON.stringify(logged.slice(0, 5)));
}

async function run() {
  var root    = helpers.tempDir("wikiisolation");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var originalBuild = wiki.build;
  var originalConsoleError = console.error;
  var identity = null;
  var listener = null;

  try {
    var tree = plantBrokenTree(root);
    var refusalMessage = theBuilderRefusesTheTree(tree);

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

    // The web surface calls the builder when it is created. Pointing that
    // one call at the fixture is the whole of the substitution: the
    // builder, the block reader and the refusal are the shipped ones.
    wiki.build = function (opts) {
      return originalBuild(Object.assign({}, opts || {}, { root: tree }));
    };
    var logged = [];
    console.error = function () {
      logged.push(Array.prototype.map.call(arguments, String).join(" "));
      return originalConsoleError.apply(console, arguments);
    };

    var built = null;
    try {
      listener = blamepost.web.serve(wiringFor(cfg, identity));
    } catch (e) {
      built = e;
    } finally {
      wiki.build = originalBuild;
      console.error = originalConsoleError;
    }
    count("the web surface is created although the wiki cannot be built",
      built === null && listener !== null, built ? built.message : "created");

    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var operator = await theSurfaceAnswersWithoutTheWiki(origin);
    await aStrangerMeetsTheSameGateWhileTheSiteIsWithdrawn(origin);
    await everyWikiPathAnswersUnavailable(operator, "signed in, site not published", refusalMessage);

    await identity.settings.set({
      name: SETTING, value: true, changedBy: OPERATOR_ADDRESS,
      reason: "publishing the public site for this run",
    });
    var stranger = await thePublicSiteStopsListingTheWiki(origin);
    await everyWikiPathAnswersUnavailable(stranger, "no session, site published", refusalMessage);

    await theFailureIsRecorded(refusalMessage, logged);

    await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS });
    listener = null;
    return helpers.getChecks();
  } finally {
    wiki.build = originalBuild;
    console.error = originalConsoleError;
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

module.exports = { name: "wiki-build-isolation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
