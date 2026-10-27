// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The public front page on a real port, and the two documents a crawler
 * reads before it.
 *
 * The claim under test is that one setting decides three answers at
 * once. With the page withdrawn, the root answers a stranger exactly the
 * way it answered before the page existed, `robots.txt` asks for nothing
 * to be indexed, and there is no sitemap. With it published, the root
 * renders, `robots.txt` names the sitemap and withholds every
 * credentialed prefix, and the sitemap lists the pages that are actually
 * mounted. A run that only drove the published state would pass against
 * a server that had quietly made the root public on every deployment,
 * which is the change this route is most likely to get wrong.
 *
 * Both directions are driven, and in one process against one server, so
 * what is measured is a state change rather than two fixtures agreeing
 * by coincidence.
 *
 * Two things here are about the reader rather than the route. The page
 * is fetched with a search-engine agent that sends no `Accept-Language`
 * and no `Sec-Fetch-Mode`, because the request lifecycle carries a bot
 * guard and a page no crawler can fetch is a page that is published and
 * invisible. And the response is checked for `Vary: Cookie`, because the
 * same URL answers a signed-in reader with a redirect into their own
 * mailbox: a shared cache that did not key on the cookie would hand one
 * reader's redirect to the next stranger.
 *
 * The published page also carries a JSON-LD record of the software. It
 * is read the way a browser reads it: the text between the opening tag
 * and the first closing tag after it, parsed as JSON. Its version is
 * compared with the manifest on disk, and the page is fetched again with
 * the manifest this process loaded holding a value built to close the
 * element early.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/public-site-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var LOOPBACK  = "127.0.0.1";
var HOSTNAME  = "mx.example.com";
var SETTING   = "publicSiteEnabled";

// A search engine, spelled the way one really arrives: no
// `Accept-Language` and no `Sec-Fetch-Mode`. Both are absent from every
// major crawler, and the bot guard treats each as advisory for exactly
// that reason. Sending either would test a request no crawler makes.
var CRAWLER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

var LDJSON_OPEN = '<script type="application/ld+json">';

// A version string written to end the JSON-LD element and open an
// executable one. It carries the lower-case and upper-case closing tags,
// a comment opener, an ampersand and U+2028, which are the characters
// the serializer has to escape.
var HOSTILE_PAYLOAD = "<script>alert(1)</script>";
var LINE_SEPARATOR = String.fromCharCode(0x2028);
var HOSTILE_VALUE = "0.1.0</script>" + HOSTILE_PAYLOAD + "</SCRIPT ><!--&" + LINE_SEPARATOR;

// The manifest as it is on disk, read independently of the copy the
// server loaded, so a comparison between the two is not a value compared
// with itself.
function manifestOnDisk() {
  return JSON.parse(nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, "package.json"), "utf8"));
}

// Every JSON-LD element in a page, as the offset of its opening tag and
// the text a browser hands to a JSON reader. The HTML tokenizer ends a
// script element at the first `</script` followed by whitespace, a slash
// or `>`, in any letter case, so the text runs to the first such match.
function structuredDataElements(body) {
  var out = [];
  var from = 0;
  for (;;) {
    var at = body.indexOf(LDJSON_OPEN, from);
    if (at === -1) return out;
    var start = at + LDJSON_OPEN.length;
    var close = /<\/script[\s/>]/gi;
    close.lastIndex = start;
    var end = close.exec(body);
    out.push({ offset: at, text: end === null ? null : body.slice(start, end.index) });
    from = end === null ? body.length : end.index;
  }
}

function parsed(text) {
  try { return JSON.parse(text); }
  catch (_e) { return null; }
}

function scriptTagCount(body) {
  return (body.match(/<script\b/gi) || []).length;
}

function siteNavOf(body) {
  var nav = /<nav class="sitenav"[\s\S]*?<\/nav>/.exec(body);
  return nav === null ? "" : nav[0];
}

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

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

function urlFor(port, path) {
  return "http://" + LOOPBACK + ":" + port + path;
}

// A reader that follows nothing, so a redirect is a value to assert on
// rather than a hop that hides which route answered.
function get(port, path, agent) {
  return fetch(urlFor(port, path), {
    redirect: "manual",
    headers:  { "User-Agent": agent || CRAWLER_AGENT },
  });
}

async function testTheRootIsPrivateUntilItIsPublished(port) {
  var res = await get(port, "/");
  count("with the front page withdrawn, a stranger at the root is sent to sign in",
    res.status === 302 && res.headers.get("location") === "/sign-in",
    res.status + " " + res.headers.get("location"));

  var robots = await get(port, "/robots.txt");
  var robotsBody = await robots.text();
  count("robots.txt asks for nothing to be indexed while there is no public page",
    robots.status === 200 && /Disallow: \/\s*$/.test(robotsBody.trim()),
    JSON.stringify(robotsBody));

  var map = await get(port, "/sitemap.xml");
  count("there is no sitemap while there is no public page", map.status === 404, map.status);
}

async function testPublishingItRendersTheRoot(port) {
  var res = await get(port, "/");
  count("the published front page answers a crawler that sends no Accept-Language",
    res.status === 200, res.status);

  var body = await res.text();
  check("the page names the software", body.indexOf("blamepost") !== -1);
  // The canonical link is the root-relative path, which a crawler resolves
  // against the page it is on. The preview card cannot be resolved that
  // way, so `og:url` carries the absolute address at this server's origin.
  count("the page carries a canonical link to the root",
    body.indexOf('<link rel="canonical" href="/">') !== -1,
    "canonical link absent");
  count("the preview card names the page at this server's own origin",
    body.indexOf('property="og:url" content="https://' + HOSTNAME) !== -1,
    "og:url does not name this origin");
  count("the page carries a description and a preview card",
    body.indexOf('name="description"') !== -1 &&
    body.indexOf('property="og:image"') !== -1 &&
    body.indexOf('name="twitter:card"') !== -1,
    "one of description, og:image or twitter:card is absent");
  count("the preview image is served from this server rather than off site",
    body.indexOf('property="og:image" content="https://' + HOSTNAME) !== -1,
    "og:image does not name this origin");

  // The page carries the reader's own CSRF token, so no shared cache may
  // store it: a stored copy would replay one reader's token to the next.
  // The reader's own browser may still keep it. It shares its URL with a
  // redirect for a signed-in reader, which is what `Vary` is holding.
  count("the page may be kept by the reader's browser but by no shared cache",
    /private/.test(String(res.headers.get("cache-control"))) &&
      !/public/.test(String(res.headers.get("cache-control"))),
    String(res.headers.get("cache-control")));
  count("and still varies on the cookie, because this URL also answers a session",
    /Cookie/i.test(String(res.headers.get("vary"))),
    String(res.headers.get("vary")));

  return body;
}

async function testThePageCarriesStructuredData(body) {
  var elements = structuredDataElements(body);
  count("the page carries exactly one JSON-LD element", elements.length === 1, elements.length);
  if (elements.length !== 1) return;

  var element = elements[0];
  count("the JSON-LD element is in the document head",
    element.offset < body.indexOf("</head>"), element.offset + " " + body.indexOf("</head>"));
  var record = parsed(element.text);
  count("the JSON-LD element's text parses as JSON", record !== null, element.text);
  if (record === null) return;

  count("the record uses the schema.org vocabulary",
    record["@context"] === "https://schema.org", record["@context"]);
  count("the record describes a SoftwareApplication",
    record["@type"] === "SoftwareApplication", record["@type"]);
  count("the record names the software", record.name === "blamepost", record.name);

  var manifest = manifestOnDisk();
  count("the record's version is the version in package.json",
    record.softwareVersion === manifest.version,
    record.softwareVersion + " " + manifest.version);
  count("the record's license is the SPDX page for the manifest's license",
    record.license === "https://spdx.org/licenses/" + manifest.license + ".html",
    record.license + " " + manifest.license);
  count("the record's runtime requirement is the manifest's Node.js floor",
    record.softwareRequirements ===
      "Node.js " + String(manifest.engines.node).replace(/^[^\d]*/, "") + " or newer",
    record.softwareRequirements + " " + manifest.engines.node);
  count("the record's description is the page's meta description",
    body.indexOf('<meta name="description" content="' + record.description + '">') !== -1,
    record.description);
  count("the record carries no offers, rating or review",
    record.offers === undefined && record.aggregateRating === undefined &&
    record.review === undefined, Object.keys(record).join(","));
}

// The manifest object this process loaded is the one the server reads
// when it renders, so writing a hostile value onto it reaches the real
// render path. It is put back before this returns, whatever happens.
async function testAHostileValueCannotLeaveTheElement(port, baselineScriptTags) {
  var manifest = require("../../package.json");
  var priorVersion = manifest.version;
  var priorEngines = manifest.engines;
  var body;
  try {
    manifest.version = HOSTILE_VALUE;
    manifest.engines = Object.assign({}, priorEngines, { node: ">=" + HOSTILE_VALUE });
    var res = await get(port, "/");
    body = await res.text();
    count("the page renders with the hostile value in the manifest", res.status === 200, res.status);
  } finally {
    manifest.version = priorVersion;
    manifest.engines = priorEngines;
  }

  count("the hostile value opens no script element beyond the page's own",
    scriptTagCount(body) === baselineScriptTags,
    scriptTagCount(body) + " against " + baselineScriptTags);
  count("the executable payload does not appear in the document",
    body.indexOf(HOSTILE_PAYLOAD) === -1, body.slice(0, 400));

  var elements = structuredDataElements(body);
  count("the page still carries exactly one JSON-LD element", elements.length === 1, elements.length);
  if (elements.length !== 1) return;
  var text = elements[0].text;
  count("the element's text holds no angle bracket and no raw U+2028",
    text !== null && !/[<>]/.test(text) && text.indexOf(LINE_SEPARATOR) === -1, text);
  var record = parsed(text);
  count("the element's text still parses as JSON", record !== null, text);
  if (record === null) return;
  count("the hostile version parses back to the exact string written",
    record.softwareVersion === HOSTILE_VALUE, JSON.stringify(record.softwareVersion));
  count("the hostile runtime floor parses back to the exact string written",
    record.softwareRequirements === "Node.js " + HOSTILE_VALUE + " or newer",
    JSON.stringify(record.softwareRequirements));
}

// The wiki is listed in the navigation and in the sitemap only while GET
// on its path reaches a route. Measured against what this server answers
// at `/wiki`, so the assertion holds on either side of the route being
// registered, and `public-site-page-detection` drives both sides.
async function testTheWikiIsListedOnlyWhereItIsServed(port, body) {
  var wiki = await get(port, "/wiki");
  var served = wiki.status !== 404;
  var linked = siteNavOf(body).indexOf('href="/wiki"') !== -1;
  count("the site navigation links to /wiki exactly when /wiki is served",
    linked === served, "status " + wiki.status + ", linked " + linked);
  count("no page link anywhere points at /wiki while it is not served",
    served || body.indexOf('href="/wiki"') === -1, "status " + wiki.status);
}

async function testTheCrawlerDocumentsFollowTheSetting(port) {
  var robots = await get(port, "/robots.txt");
  var body = await robots.text();
  count("robots.txt names the sitemap once the page is published",
    body.indexOf("Sitemap: https://" + HOSTNAME) !== -1, JSON.stringify(body));
  count("robots.txt withholds every surface behind a credential",
    body.indexOf("Disallow: /admin") !== -1 &&
    body.indexOf("Disallow: /mail") !== -1 &&
    body.indexOf("Disallow: /jmap") !== -1 &&
    body.indexOf("Disallow: /api") !== -1,
    JSON.stringify(body));
  count("robots.txt does not withhold the whole server once there is a page on it",
    !/^Disallow: \/$/m.test(body), JSON.stringify(body));

  var map = await get(port, "/sitemap.xml");
  var xml = await map.text();
  count("the sitemap is served as XML", map.status === 200 &&
    /application\/xml/.test(String(map.headers.get("content-type"))),
    map.status + " " + map.headers.get("content-type"));
  count("the sitemap lists the front page at this server's origin",
    xml.indexOf("<loc>https://" + HOSTNAME) !== -1, JSON.stringify(xml.slice(0, 200)));
  // A sitemap naming a path this server answers with a refusal sends a
  // crawler to a 404. The wiki row follows what `/wiki` answers here.
  var wiki = await get(port, "/wiki");
  count("the sitemap names /wiki exactly when /wiki is served",
    (xml.indexOf("/wiki</loc>") !== -1) === (wiki.status !== 404),
    "status " + wiki.status + " " + JSON.stringify(xml));
}

async function testWithdrawingItPutsTheRootBack(port) {
  var res = await get(port, "/");
  count("withdrawing the page returns the root to the sign-in redirect",
    res.status === 302 && res.headers.get("location") === "/sign-in",
    res.status + " " + res.headers.get("location"));

  var map = await get(port, "/sitemap.xml");
  count("and the sitemap goes away with it", map.status === 404, map.status);
}

async function run() {
  var root = helpers.tempDir("publicsite");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var listener = null;
  try {
    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    count("the shipped posture is that the front page is not published",
      cfg.publicSiteEnabled === false, String(cfg.publicSiteEnabled));

    var identity = await store.open(cfg);
    var mailStore = b.mailStore.create({ backend: b.db });

    listener = blamepost.web.serve(wiringFor(cfg, identity, mailStore));
    var ports = await listener.start();

    await testTheRootIsPrivateUntilItIsPublished(ports.http);

    await identity.settings.set({
      name: SETTING, value: true, changedBy: "operator@example.com",
      reason: "publishing the front page for this run",
    });
    var page = await testPublishingItRendersTheRoot(ports.http);
    await testThePageCarriesStructuredData(page);
    await testAHostileValueCannotLeaveTheElement(ports.http, scriptTagCount(page));
    await testTheWikiIsListedOnlyWhereItIsServed(ports.http, page);
    await testTheCrawlerDocumentsFollowTheSetting(ports.http);

    await identity.settings.set({
      name: SETTING, value: false, changedBy: "operator@example.com",
      reason: "withdrawing the front page for this run",
    });
    await testWithdrawingItPutsTheRootBack(ports.http);

    await listener.stop({ timeoutMs: 2000 });
    listener = null;
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: 2000 }); }
      catch (_e) { /* the assertion that failed is the result, not this */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "public-site-surface", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
