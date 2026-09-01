// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the JMAP session document promises, against what this server
 * mounts.
 *
 * A JMAP client does not read a roadmap. It reads the session resource,
 * which is the machine readable statement of what the server can do,
 * and it then uses whatever that statement offers. RFC 8620 section 2
 * makes some of those fields mandatory, so a server advertises them
 * whether or not a backend stands behind them, and answering a typed
 * refusal there is honest. A capability object is different: RFC 8887
 * section 3 defines `urn:ietf:params:jmap:websocket` as something a
 * server advertises when it supports the transport, and a client that
 * finds it will prefer the push channel over polling.
 *
 * This server advertises that capability and mounts no endpoint for it,
 * so a client that believes the session document is sent to a route
 * that does not exist. The capability is not one the framework forces:
 * it fills the key in only when the composition leaves it out, so
 * naming it is enough to stop the claim, and the endpoint can be
 * mounted later when the push channel is built.
 *
 * The rule this file holds is one sentence, and it covers the next
 * advertisement as well as this one: every route the session document
 * names is a route this server answers on.
 *
 * Run standalone: node test/layer-1-state/jmap-session-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The session fields that name a route. Each carries templated segments
// in braces that a client substitutes before it sends anything, and
// substituting a value the server will refuse is fine and is the point:
// a refusal is an answer, and a route that is not mounted at all is not.
// The four RFC 8620 section 2 makes mandatory. A server advertises them
// whether or not a backend stands behind them, so what matters is that
// each is mounted and answers.
var MANDATORY_URL_FIELDS = ["apiUrl", "downloadUrl", "uploadUrl", "eventSourceUrl"];

// The fifth is the one RFC 8887 section 3 ties to a capability, so it
// is asserted through the capability rather than beside the others.
var URL_FIELDS = MANDATORY_URL_FIELDS.concat(["webSocketUrl"]);

function _concreteUrl(template, accountId) {
  return String(template)
    .replace(/\{accountId\}/g, encodeURIComponent(accountId))
    .replace(/\{blobId\}/g, "blob-that-does-not-exist")
    .replace(/\{name\}/g, "attachment.txt")
    .replace(/\{type\}/g, encodeURIComponent("text/plain"))
    .replace(/\{types\}/g, "*")
    .replace(/\{closeafter\}/g, "state")
    .replace(/\{ping\}/g, "0");
}

function messageFor(recipient, subject, body) {
  return Buffer.from(
    "Message-ID: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

// ---- the cases -------------------------------------------------------------

function testTheDocumentNamesTheRoutesAClientWillUse(session) {
  for (var i = 0; i < URL_FIELDS.length; i += 1) {
    var field = URL_FIELDS[i];
    count("the session document names " + field,
      typeof session[field] === "string" && session[field].length > 0,
      JSON.stringify(session[field]));
  }
}

// A capability is a claim about what this server supports, so a
// capability whose transport is not mounted is a claim it cannot meet.
function testEveryAdvertisedCapabilityIsOneThisServerSupports(session, mounted) {
  var advertised = Object.keys(session.capabilities || {});
  count("the core capability is advertised, which every JMAP server does",
    advertised.indexOf("urn:ietf:params:jmap:core") !== -1, JSON.stringify(advertised));
  count("mail and submission are advertised, which is what this server composes",
    advertised.indexOf("urn:ietf:params:jmap:mail") !== -1 &&
    advertised.indexOf("urn:ietf:params:jmap:submission") !== -1,
    JSON.stringify(advertised));

  var claimsWebSocket = advertised.indexOf("urn:ietf:params:jmap:websocket") !== -1;
  count("the WebSocket push capability is advertised only when the endpoint behind " +
    "it is mounted, because a client that finds it will prefer the push channel " +
    "over polling and be sent to a route that does not exist",
    !claimsWebSocket || mounted.webSocket === true,
    "advertised=" + claimsWebSocket + " mounted=" + mounted.webSocket +
    " (" + JSON.stringify(advertised) + ")");

  // And the other direction, which is the one that fails quietly. RFC
  // 8887 section 3 has a client discover the transport from the session
  // document, so a mounted endpoint nobody advertises is a push channel
  // no client will ever open: every account falls back to polling, the
  // server carries the sweep cost for both, and nothing anywhere reports
  // a fault. The framework suppresses the capability when the transport
  // is declined, which is right, and is exactly what makes the
  // suppression reachable by accident from this side.
  count("and it IS advertised, because this server mounts the transport and a " +
    "client can only find it in the session document",
    !mounted.webSocket || claimsWebSocket,
    "advertised=" + claimsWebSocket + " mounted=" + mounted.webSocket +
    " (" + JSON.stringify(advertised) + ")");
}

// Every route the document names, asked for. A refusal is an answer; a
// 404 means the client was pointed at nothing.
//
// The asking and the asserting are separate passes on purpose. An
// assertion inside the loop stops at the first route that fails, and
// the routes after it are then neither reported nor counted, which
// turns one broken route into an unknown number of untested ones.
async function askEveryAdvertisedRoute(reader, session, accountId) {
  var reached = {};
  for (var i = 0; i < URL_FIELDS.length; i += 1) {
    var field = URL_FIELDS[i];
    var url = _concreteUrl(session[field], accountId);
    // An event source streams, so it is asked for its response head alone.
    // Waiting for the body to end reports no answer for a route that
    // answered at once, and that reading passed only while the endpoint was
    // refusing instantly.
    var answer;
    if (field === "eventSourceUrl") {
      answer = await reader.head(url);
    } else if (field === "apiUrl" || field === "uploadUrl") {
      answer = await reader.post(url, "text/plain", "probe", { Accept: "application/json" });
    } else {
      answer = await reader.get(url, { Accept: "application/json" });
    }
    reached[field] = { status: answer.status, url: url, contentType: answer.contentType };
  }
  return reached;
}

function testEveryAdvertisedRouteAnswers(reached) {
  for (var i = 0; i < MANDATORY_URL_FIELDS.length; i += 1) {
    var field = MANDATORY_URL_FIELDS[i];
    var hit = reached[field];
    count("the route the session document names as " + field + " is mounted, so a " +
      "client following the document reaches this server rather than nothing",
      hit.status !== 404, field + " " + hit.url + " answered " + hit.status);
  }

  // Mounted is the weaker half for the event source. RFC 8620 section 7.3
  // has a client read this as a stream, so a route that answers 200 with
  // any other media type is one no client can consume, and a 503 from an
  // unwired push hook answers without streaming at all.
  var stream = reached.eventSourceUrl;
  count("and the event source answers as a stream rather than merely answering, " +
    "because a client reads it with an event-stream parser or not at all",
    stream.status === 200 && /^text\/event-stream/.test(stream.contentType),
    stream.status + " " + JSON.stringify(stream.contentType));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("jmapsurface");
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
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    identity.mailbox.appendMessage("INBOX",
      messageFor(alice.address, "Something to read", "a body"), { actor: { id: alice.id } });

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(origin, { ca: material.caPem });
    var landing = await reader.signIn(alice.address, ALICE_PASSWORD);
    count("a reader signs in, because the session document is behind the door",
      landing.status === 302, landing.status + " " + String(landing.location));

    var answer = await reader.get("/jmap/session", { Accept: "application/json" });
    count("the session document renders", answer.status === 200,
      answer.status + " " + answer.body.slice(0, 120));
    var session = JSON.parse(answer.body);

    testTheDocumentNamesTheRoutesAClientWillUse(session);

    var reached = await askEveryAdvertisedRoute(reader, session, alice.id);
    // The mandatory routes first. They hold today, and asserting them
    // before the capability keeps the four passes on the record when
    // the fifth claim fails.
    testEveryAdvertisedRouteAnswers(reached);
    testEveryAdvertisedCapabilityIsOneThisServerSupports(session, {
      webSocket: reached.webSocketUrl.status !== 404,
    });

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
  }
}

module.exports = { name: "jmap-session-surface", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
