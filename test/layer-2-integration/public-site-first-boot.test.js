// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two answers that decide whether the root serves a public page, and
 * the order between them, driven on a real port in all four states.
 *
 * `BLAMEPOST_PUBLIC_SITE_ENABLED` states the posture a volume boots
 * with. The administration console writes the operator's answer to the
 * settings table, and the server reads that row in front of the
 * environment's value. Two inputs with two positions each make four
 * states, and the route answers one of two ways in each of them:
 *
 *   no row, environment on    the public page is served
 *   no row, environment off   a stranger is sent to sign in
 *   row off, environment on   the row wins and the page is withdrawn
 *   row on, environment off   the row wins and the page is served
 *
 * The middle pair is where a mistake hides. Every other file that
 * publishes the page does it by writing the row, so the environment's on
 * position is never the thing under test, and a route that had stopped
 * reading it would answer every one of those runs exactly as it does
 * now. A volume that no operator has opened the console on would then
 * serve the sign-in redirect while the container's own settings said to
 * publish, and nothing would report the difference.
 *
 * Two volumes are used, one per environment position, and each is
 * measured twice: once while its settings table holds no row for the
 * name, and again after a row is written in the position the environment
 * did not take. The absence of the row is read off the store rather than
 * assumed, because a fixture that had inherited a row would drive the
 * stored path twice and report the first-boot answer as covered.
 *
 * `/sitemap.xml` is measured beside the root because the same predicate
 * gates it. A run where the root followed the setting and the sitemap
 * did not would leave a crawler with a document naming pages it cannot
 * fetch.
 *
 * It needs no external service. The ports are ephemeral on the loopback
 * interface and both data directories are temporary.
 *
 * Run standalone: node test/layer-2-integration/public-site-first-boot.test.js
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
var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var SETTING  = "publicSiteEnabled";

// The environment variable the loader declares for the setting, written
// out here rather than derived, so this file names the variable an
// operator writes in their container.
var SETTING_VARIABLE = "BLAMEPOST_PUBLIC_SITE_ENABLED";

// A search engine, spelled the way one really arrives: no
// `Accept-Language` and no `Sec-Fetch-Mode`. Both are absent from every
// major crawler, and the bot guard treats each as advisory for that
// reason.
var CRAWLER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

var SHUTDOWN_TIMEOUT_MS = 2000;

var listenerTable = [
  { name: "mx",   state: "bound", reason: null },
  { name: "imap", state: "bound", reason: null },
];

function envFor(dataDir, settingWord) {
  var env = {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
  env[SETTING_VARIABLE] = settingWord;
  return env;
}

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

// A reader that follows nothing, so a redirect is a value to assert on
// rather than a hop that hides which route answered.
function get(port, path) {
  return fetch("http://" + LOOPBACK + ":" + port + path, {
    redirect: "manual",
    headers:  { "User-Agent": CRAWLER_AGENT },
  });
}

// What the root and the sitemap answer right now, reduced to the one
// word each cell of the table predicts. `page` is the public document,
// `gate` is the sign-in redirect a stranger meets, and anything else
// comes back as the status it answered so a failure names it.
async function observe(port) {
  var res = await get(port, "/");
  var body = await res.text();
  var root;
  if (res.status === 200 && body.indexOf("blamepost") !== -1) root = "page";
  else if (res.status === 302 && res.headers.get("location") === "/sign-in") root = "gate";
  else root = "status " + res.status + " " + String(res.headers.get("location"));

  var map = await get(port, "/sitemap.xml");
  return { root: root, sitemap: map.status };
}

// One volume, measured on both sides of the row being written.
//
// `environment` is the position the variable takes, and the row written
// afterwards takes the other one, so the second measurement is the case
// where the two inputs disagree and the row has to win.
async function driveVolume(root, environment) {
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(dataDir, { recursive: true });

  var word = environment ? "true" : "false";
  var cfg = config.load({ env: envFor(dataDir, word), cwd: root });
  count("the loader carries " + SETTING_VARIABLE + "=" + word + " through to the setting",
    cfg.publicSiteEnabled === environment, String(cfg.publicSiteEnabled));

  var listener = null;
  try {
    var identity = await store.open(cfg);

    // Read rather than assumed. A volume that arrived holding a row
    // would drive the stored path twice and report the first boot's
    // answer as measured.
    count("the volume holds no operator answer for the setting yet",
      identity.settings.get(SETTING) === null,
      String(identity.settings.get(SETTING)));

    var mailStore = b.mailStore.create({ backend: b.db });
    listener = blamepost.web.serve(wiringFor(cfg, identity, mailStore));
    var ports = await listener.start();

    var firstBoot = await observe(ports.http);
    var wanted = environment ? "page" : "gate";
    count("with no row and " + SETTING_VARIABLE + "=" + word +
      ", the root answers " + wanted,
      firstBoot.root === wanted, firstBoot.root);
    count("and the sitemap follows the same setting on a volume with no row",
      firstBoot.sitemap === (environment ? 200 : 404), firstBoot.sitemap);

    await identity.settings.set({
      name: SETTING, value: !environment, changedBy: "operator@example.com",
      reason: "recording the console's answer against the environment for this run",
    });
    count("the stored answer is now the opposite of what the environment said",
      identity.settings.get(SETTING) === !environment,
      String(identity.settings.get(SETTING)));

    var afterRow = await observe(ports.http);
    var wantedAfter = environment ? "gate" : "page";
    count("a stored " + String(!environment) + " over " + SETTING_VARIABLE + "=" + word +
      " answers " + wantedAfter + ", so the operator's answer wins",
      afterRow.root === wantedAfter, afterRow.root);
    count("and the sitemap follows the stored answer rather than the environment",
      afterRow.sitemap === (environment ? 404 : 200), afterRow.sitemap);

    await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    listener = null;

    return { firstBoot: firstBoot.root, afterRow: afterRow.root };
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* the assertion that failed is the result, not this */ }
    }
    if (store.isOpen()) store.close();
  }
}

async function run() {
  var root = helpers.tempDir("publicsitefirstboot");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var onVolume = nodePath.join(root, "on");
    var offVolume = nodePath.join(root, "off");
    nodeFs.mkdirSync(onVolume, { recursive: true });
    nodeFs.mkdirSync(offVolume, { recursive: true });

    var on  = await driveVolume(onVolume, true);
    var off = await driveVolume(offVolume, false);

    // The four states as one assertion, so a run where two cells
    // answered the same way is a failure rather than two passes that
    // happen to agree. A route that had stopped reading the environment
    // would take the first column to `gate` twice and leave the second
    // untouched.
    check("the four states answer page, gate, gate, page in that order",
      on.firstBoot === "page" && on.afterRow === "gate" &&
      off.firstBoot === "gate" && off.afterRow === "page");
    count("the environment's two positions answer differently on a volume with no row",
      on.firstBoot !== off.firstBoot, on.firstBoot + " " + off.firstBoot);
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "public-site-first-boot", run: run, getChecks: helpers.getChecks };

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
