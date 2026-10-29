// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What this server decides from the transport a request arrived over,
 * measured on the wire from three places at once: the cleartext port
 * reached across a network, the cleartext port reached over loopback,
 * and the cleartext port reached through a TLS terminator that holds
 * the certificate.
 *
 * The three are one question asked three ways. A password is only worth
 * as much as the connection carrying it, and the connection this server
 * can see is the socket in front of it, which behind a terminator is
 * not the connection the browser opened. So the server has to be told
 * which peers may state what the browser's connection was, and it has
 * to refuse a credential when nothing has stated one it can rely on.
 *
 * `trustedProxies` is that setting. It holds the address ranges whose
 * `X-Forwarded-Proto` this server believes, it holds nothing by
 * default, and every assertion below is about what changes between the
 * two states.
 *
 * ## The vectors, and what each one would let through
 *
 *   - A correct password posted to the cleartext port from across a
 *     network. Accepting it puts the password on an unprotected wire,
 *     records a successful sign-in, and mints a session cookie carrying
 *     `Secure` and the `__Host-` prefix, which RFC 6265bis section 4.1.3
 *     has the browser discard on a cleartext response. The reader is
 *     then returned to the form with nothing to read, forever.
 *   - The form itself over the same transport. A refusal that arrives
 *     after the post arrives after the password has already crossed the
 *     wire, so the page has to say so before it offers a password field.
 *   - A session token replayed over the same transport. Minting is one
 *     credential path and presenting is the other, and a gate on one of
 *     them is a gate on half the surface.
 *   - `X-Forwarded-Proto: https` written by a caller no setting names.
 *     Believing it turns a header the client controls into the server's
 *     reading of its own security.
 *   - The same header from the peer the setting does name, which is the
 *     deployment `compose.yml` ships a terminator profile for. The CSRF
 *     cookie has to carry `Secure` and the `__Host-` prefix there, the
 *     origin cross-check has to build its baseline as `https`, and HSTS
 *     has to be sent, because the browser is on TLS whatever the socket
 *     in this process says.
 *
 * ## Loopback is not a hole in this, it is the same rule
 *
 * A request that arrived over loopback never crossed a network, and the
 * Secure Contexts standard treats `127.0.0.1` and `localhost` as
 * potentially trustworthy for exactly that reason: a browser stores and
 * returns a `Secure` cookie there. A server that refused a password
 * over loopback while the browser accepted the cookie would refuse the
 * one cleartext case that works, which is a browser and this process on
 * the same machine, the shape a host install has. So the transport is
 * trustworthy when the socket is TLS, when a named proxy says the
 * browser's was, or when the peer is loopback, and it is nothing else.
 *
 * A published container port is none of those. It is forwarded into the
 * container's own network namespace, so the peer is the bridge gateway
 * and the credential goes to the TLS port instead;
 * container-quickstart.test.js drives both directions of that.
 *
 * This is not the reading the mail listeners take of a TCP terminator
 * in front of 143 or 110, and the difference is what is being claimed.
 * There the address would stand in for a fact about a DIFFERENT hop
 * that the listener has no evidence about. Here it is a fact about this
 * hop and there is no other one.
 *
 * ## What this file binds
 *
 * The vectors that need a peer this server can tell from loopback are
 * driven against a listener bound on every interface, dialed on one of
 * this host's own addresses. The port is ephemeral and the run lasts
 * seconds, and a host holding no address outside loopback cannot drive
 * them at all, which is named and counted rather than folded into the
 * pass count.
 *
 * Run standalone: node test/layer-2-integration/web-transport-trust.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodeHttp   = require("node:http");
var nodeHttps  = require("node:https");
var nodeNet    = require("node:net");
var nodeOs     = require("node:os");
var nodePath   = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var web       = require("../../lib/web");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var EVERY_INTERFACE = "0.0.0.0";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var READER_PASSWORD  = "quiet lantern bicycle 4291";
var READER_ADDRESS   = "quillfeather@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The sentence the refusal carries, matched on the part of it that names
// what happened rather than on the whole. A reader turned away here has
// to be told the transport is the problem, and a page that said nothing
// would be the silent bounce this file exists to close.
var REFUSAL_MARK = "not accept a password";

// The private ranges of RFC 1918, preferred over any other address this
// host holds so the listener is dialed on an ordinary local network
// rather than on whatever overlay happens to be enumerated first.
function _privateFirst(rows) {
  var priv = rows.filter(function (a) {
    return /^10\./.test(a) || /^192\.168\./.test(a) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(a);
  });
  return priv.length > 0 ? priv[0] : (rows.length > 0 ? rows[0] : null);
}

// One address of this host that is not loopback, so a request dialed at
// it reaches the listener carrying a peer the server can tell apart from
// its own machine.
function networkAddress() {
  var table = nodeOs.networkInterfaces();
  var found = [];
  Object.keys(table).forEach(function (name) {
    (table[name] || []).forEach(function (row) {
      if (row.family === "IPv4" && row.internal !== true) found.push(row.address);
    });
  });
  return _privateFirst(found);
}

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

// Every mail listener off. This file is about the browser surface, and a
// port taken is a port another file in the same run cannot have.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = {
      enabled: false,
      port:    await wire.reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

// A TLS terminator of the shape compose.yml's profile brings up: it
// holds the certificate, speaks TLS to the browser, and forwards
// cleartext to the application with the forwarded-protocol header a
// terminator writes. The browser's own authority is passed through
// unchanged, which is what the shipped terminator does, so the only
// thing this server cannot see for itself is the scheme.
function startTerminator(upstreamPort, material, port) {
  return new Promise(function (resolve, reject) {
    var server = nodeHttps.createServer({
      cert: nodeFs.readFileSync(material.certFile, "utf8"),
      key:  nodeFs.readFileSync(material.keyFile, "utf8"),
    }, function (browserReq, browserRes) {
      var headers = Object.assign({}, browserReq.headers);
      headers["x-forwarded-proto"] = "https";
      var upstream = nodeHttp.request({
        host:    LOOPBACK,
        port:    upstreamPort,
        path:    browserReq.url,
        method:  browserReq.method,
        headers: headers,
      }, function (upstreamRes) {
        browserRes.writeHead(upstreamRes.statusCode, upstreamRes.headers);
        upstreamRes.pipe(browserRes);
      });
      upstream.on("error", function (err) {
        browserRes.writeHead(502, { "Content-Type": "text/plain" });
        browserRes.end(String((err && err.message) || err));
      });
      browserReq.pipe(upstream);
    });
    server.once("error", reject);
    server.listen(port, LOOPBACK, function () { resolve(server); });
  });
}

function closeTerminator(server) {
  return new Promise(function (resolve) { server.close(function () { resolve(); }); });
}

function sessionCookieLine(response) {
  var lines = response.setCookie || [];
  for (var i = 0; i < lines.length; i += 1) {
    if (String(lines[i]).indexOf(web.SESSION_COOKIE + "=") === 0) return String(lines[i]);
  }
  return null;
}

function csrfCookieLine(response) {
  var lines = response.setCookie || [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = String(lines[i]);
    if (line.indexOf("csrf=") === 0 || line.indexOf("__Host-csrf=") === 0) return line;
  }
  return null;
}

// ---- the vectors ------------------------------------------------------------

// A correct password, posted across a network to the port that carries
// no TLS. The password is already spent by the time this server reads
// it, so what is measured is everything after: no session row, no
// cookie, and a sentence that names the transport.
async function testACorrectPasswordAcrossTheNetworkIsRefused(origin) {
  var reader = browser.browserAt(origin);
  var landing = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
  count("a correct password posted to the cleartext port from another machine is " +
    "refused rather than answered with a redirect into the mailbox",
    landing.status === 403, landing.status + " " + JSON.stringify(landing.location));
  count("and no session cookie is written, so the sign-in was not recorded as one",
    sessionCookieLine(landing) === null, JSON.stringify(landing.setCookie));
  count("and the reader is told the transport is what refused them",
    landing.body.indexOf(REFUSAL_MARK) !== -1, landing.body.replace(/\s+/g, " ").slice(0, 240));
}

// The form, before a password has been typed into it. A refusal that
// only fires on the post fires after the password is on the wire.
async function testTheFormAcrossTheNetworkOffersNoPasswordField(origin) {
  var reader = browser.browserAt(origin);
  var page = await reader.get("/sign-in");
  count("the sign-in page reached across a network over cleartext refuses rather " +
    "than rendering", page.status === 403, String(page.status));
  count("and it carries no password field, so no password reaches the wire at all",
    page.body.indexOf("type=\"password\"") === -1,
    page.body.replace(/\s+/g, " ").slice(0, 240));
  count("and it says the transport is the reason", page.body.indexOf(REFUSAL_MARK) !== -1,
    page.body.replace(/\s+/g, " ").slice(0, 240));
}

// Presenting a token is the other credential path. A token minted over a
// transport that could carry it, replayed over one that cannot, must not
// authenticate.
async function testAReplayedSessionAcrossTheNetworkDoesNotAuthenticate(loopbackOrigin, networkOrigin) {
  var held = browser.browserAt(loopbackOrigin);
  var landing = await held.signIn(READER_ADDRESS, READER_PASSWORD);
  count("a sign-in over loopback still works, which is a browser on the same machine " +
    "as this process",
    landing.status === 302, landing.status + " " + JSON.stringify(landing.location));
  var token = held.cookies.read(web.SESSION_COOKIE);
  count("and it left a session token this run can replay",
    typeof token === "string" && token.length > 0, typeof token);

  var replay = browser.browserAt(networkOrigin);
  replay.cookies.set(web.SESSION_COOKIE, token || "");
  var mailbox = await replay.get("/mail?folder=INBOX");
  count("the same token sent across a network over cleartext does not open the mailbox",
    mailbox.status !== 200, mailbox.status + " " + JSON.stringify(mailbox.location));
  return token || "";
}

// A header written by a caller no setting names. Believing it would let
// any client declare this server's own transport.
async function testAnUnnamedPeersForwardedProtocolIsIgnored(origin) {
  var reader = browser.browserAt(origin);
  var page = await reader.get("/sign-in", { "X-Forwarded-Proto": "https" });
  count("a caller no setting names cannot declare the transport by writing " +
    "X-Forwarded-Proto, and the sign-in page refuses exactly as without it",
    page.status === 403, String(page.status));

  var loopbackReader = browser.browserAt("http://" + LOOPBACK + ":" + origin.split(":")[2]);
  var served = await loopbackReader.get("/sign-in", { "X-Forwarded-Proto": "https" });
  var cookie = csrfCookieLine(served);
  count("and the double-submit cookie still comes back under the cleartext name " +
    "with no Secure attribute, which is the reading that would have changed if the " +
    "header had been believed",
    cookie !== null && cookie.indexOf("__Host-") !== 0 && !/;\s*Secure/i.test(cookie),
    JSON.stringify(cookie));
}

// The status line an upgrade request gets back, and nothing else.
//
// A WebSocket client is not what this asks for. The question is whether
// the socket was refused before the handshake, so the request is written
// by hand and the first line of the answer is read; anything past that
// belongs to the file that measures frames.
function upgradeStatus(host, port, cookie) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: host, port: port });
    var buffer = "";
    var settled = false;
    function finish(value) {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_e) { /* already closing */ }
      resolve(value);
    }
    socket.setTimeout(5000, function () {
      finish(0);
    });
    socket.once("error", function (err) { if (!settled) { settled = true; reject(err); } });
    socket.once("connect", function () {
      socket.write(
        "GET /jmap/ws HTTP/1.1\r\n" +
        "Host: " + host + ":" + port + "\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: " + nodeCrypto.randomBytes(16).toString("base64") + "\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "Sec-WebSocket-Protocol: jmap\r\n" +
        "Origin: http://" + host + ":" + port + "\r\n" +
        (cookie ? "Cookie: " + cookie + "\r\n" : "") +
        "\r\n");
    });
    socket.on("data", function (chunk) {
      buffer += chunk.toString("latin1");
      var line = buffer.split("\r\n")[0];
      if (buffer.indexOf("\r\n") === -1) return;
      var parts = line.split(" ");
      finish(parseInt(parts[1], 10));
    });
    socket.once("close", function () { finish(0); });
  });
}

// The upgrade path does not travel through the router, so the gate the
// request lifecycle holds has to be held again on it. A token refused on
// every page and accepted on this socket would be the whole mailbox
// reachable by the route nothing was watching.
async function testAWebSocketUpgradeAcrossTheNetworkIsRefused(host, port, token) {
  var status = await upgradeStatus(host, port, web.SESSION_COOKIE + "=" + token);
  count("a JMAP WebSocket upgrade carrying a session token, reached across a network " +
    "over cleartext, is refused rather than completed",
    status === 403, "status " + status);
}

// The container's own health check, and the terminator's. Neither carries
// a credential, and neither may be caught by a gate on credentials.
async function testTheHealthProbeStillAnswersOverCleartext(origin) {
  var reader = browser.browserAt(origin);
  var live = await reader.get("/healthz");
  count("the liveness probe still answers over the cleartext port from another " +
    "machine, because it presents no credential and the container polls it",
    live.status === 200, String(live.status));
}

// The deployment compose.yml ships a profile for, with the terminator's
// range named. Three readings have to move together, because all three
// are the same question about the browser's connection.
async function testTheNamedTerminatorCarriesTheBrowsersTransport(proxyOrigin, caPem) {
  var reader = browser.browserAt(proxyOrigin, { ca: caPem });
  var form = await reader.readCsrf("/sign-in");
  count("through a terminator this configuration names, the sign-in page renders",
    form.page.status === 200, String(form.page.status));

  var cookie = csrfCookieLine(form.page);
  count("and the double-submit cookie carries the __Host- prefix and Secure, because " +
    "the browser's connection is TLS whatever this process's socket is",
    cookie !== null && cookie.indexOf("__Host-csrf=") === 0 && /;\s*Secure/i.test(cookie),
    JSON.stringify(cookie));

  count("and HSTS is sent, which RFC 6797 section 7.2 has a server send only on a " +
    "connection the browser reached over TLS",
    typeof form.page.headers["strict-transport-security"] === "string" &&
    form.page.headers["strict-transport-security"].length > 0,
    JSON.stringify(form.page.headers["strict-transport-security"]));

  var landing = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
  count("and a correct password signs in rather than being refused for an origin " +
    "the server built with the wrong scheme",
    landing.status === 302, landing.status + " " + landing.body.replace(/\s+/g, " ").slice(0, 200));
  var session = sessionCookieLine(landing);
  count("and the session cookie is written",
    session !== null && /;\s*Secure/i.test(String(session)),
    JSON.stringify(session && String(session).slice(0, 80)));
}

// The version a browser negotiates against the TLS port, which is the
// only version a person's requests take there. Every defect this file
// closes was reachable because a reader spoke the other one.
async function testTheTlsPortStillWorksOverTheVersionABrowserNegotiates(origin, caPem) {
  var reader = browser.browserAt(origin, { ca: caPem, http2: true });
  var form = await reader.readCsrf("/sign-in");
  count("the TLS port serves the sign-in form over HTTP/2", form.page.status === 200,
    String(form.page.status));
  var cookie = csrfCookieLine(form.page);
  count("with the double-submit cookie under its secure name",
    cookie !== null && cookie.indexOf("__Host-csrf=") === 0 && /;\s*Secure/i.test(cookie),
    JSON.stringify(cookie));
  var landing = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
  count("and a correct password signs in over HTTP/2", landing.status === 302,
    landing.status + " " + landing.body.replace(/\s+/g, " ").slice(0, 200));
}

// The setting itself, read where an operator sets it. A range with no
// mask matches nothing, which reads like a configured proxy and is not
// one, so it is a boot failure rather than a list that quietly holds
// nobody.
function testTheSettingIsCheckedWhereItIsWritten(dataDir, material, cwd) {
  var refused = null;
  try {
    config.load({
      env: Object.assign(baseEnv(dataDir, material), {
        BLAMEPOST_TRUSTED_PROXIES: "[\"10.0.0.1\"]",
      }),
      cwd: cwd,
    });
  } catch (err) { refused = err; }
  count("an address written without a mask stops the boot rather than sitting in " +
    "the list matching nothing", refused !== null,
    refused === null ? "accepted" : String(refused.message).slice(0, 200));

  var loaded = config.load({ env: baseEnv(dataDir, material), cwd: cwd });
  var empty = loaded.trustedProxies;
  count("and a configuration that says nothing trusts nobody",
    empty === null || (Array.isArray(empty) && empty.length === 0), JSON.stringify(empty));

  var named = config.load({
    env: Object.assign(baseEnv(dataDir, material), {
      BLAMEPOST_TRUSTED_PROXIES: "[\"10.0.0.0/8\",\"127.0.0.1/32\"]",
    }),
    cwd: cwd,
  });
  count("and a list of ranges is carried through to the loaded configuration",
    Array.isArray(named.trustedProxies) && named.trustedProxies.length === 2,
    JSON.stringify(named.trustedProxies));
}

// Every framework middleware on this surface that reads the transport,
// against the number of them that were handed a reading.
//
// The wire cannot answer this one on its own. Both middleware are
// mounted twice, once on the framework's own request lifecycle and once
// on the chain the routes mount, and the two run at different points:
// the first refusal comes from the earlier mount and the last header
// written comes from the later one. So a request measures one of each
// pair and says nothing about the other, while a mount left on the
// default answers from this process's socket while its twin answers
// from the terminator.
//
// Anchored on the framework's own names, which are a contract this
// repository composes against rather than symbols it can rename, and
// counted rather than bounded by a character window, so a mount added
// further down the file is caught wherever it lands.
function testEveryTransportReadingIsComposedFromTheSameResolver() {
  var source = nodeFs.readFileSync(
    nodePath.join(__dirname, "..", "..", "lib", "web", "index.js"), "utf8");
  var direct = (source.match(/b\.middleware\.(securityHeaders|csrfProtect)\(/g) || []).length;
  var viaApp = (source.match(/(?:^|[^\w.])(securityHeaders|csrf):\s*\{/gm) || []).length;
  var wired  = (source.match(/protocolResolver:/g) || []).length;
  count("the browser surface still composes the middleware that read the transport, " +
    "so this count is measuring something", direct > 0 && viaApp > 0,
    direct + " direct, " + viaApp + " through the application factory");
  count("and every one of them is handed this surface's own reading of the transport " +
    "rather than taking the framework default, which is this process's socket",
    wired === direct + viaApp,
    wired + " wired against " + (direct + viaApp) + " mounts");
}

// ---- the drive --------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-transport-trust");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity   = null;
  var server     = null;
  var running    = false;
  var terminator = null;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({
      address:     READER_ADDRESS,
      password:    READER_PASSWORD,
      displayName: "Quill Feather",
    });

    testTheSettingIsCheckedWhereItIsWritten(dataDir, material, root);
    testEveryTransportReadingIsComposedFromTheSameResolver();

    // ---- the state an operator gets by setting nothing ----
    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  EVERY_INTERFACE,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    var loopbackOrigin = "http://" + LOOPBACK + ":" + bound.http;
    var tlsOrigin      = "https://" + LOOPBACK + ":" + bound.https;
    count("the browser surface took both a cleartext and a TLS port",
      typeof bound.http === "number" && bound.http > 0 &&
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));

    var lan = networkAddress();
    if (lan === null) {
      helpers.skip("this host holds no address outside loopback, so the vectors that " +
        "need a peer this server can tell from its own machine could not be driven");
    } else {
      var networkOrigin = "http://" + lan + ":" + bound.http;
      await testTheFormAcrossTheNetworkOffersNoPasswordField(networkOrigin);
      await testACorrectPasswordAcrossTheNetworkIsRefused(networkOrigin);
      var replayed = await testAReplayedSessionAcrossTheNetworkDoesNotAuthenticate(
        loopbackOrigin, networkOrigin);
      await testAWebSocketUpgradeAcrossTheNetworkIsRefused(lan, bound.http, replayed);
      await testAnUnnamedPeersForwardedProtocolIsIgnored(networkOrigin);
      await testTheHealthProbeStillAnswersOverCleartext(networkOrigin);
    }

    await testTheTlsPortStillWorksOverTheVersionABrowserNegotiates(tlsOrigin, material.caPem);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    // ---- the state an operator gets by naming the terminator ----
    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:       0,
        httpsPort:      0,
        listeners:      await listenerSections(),
        trustedProxies: [LOOPBACK + "/32"],
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var upstream   = server.web.bound().http;
    var proxyPort  = await wire.reservePort();
    terminator = await startTerminator(upstream, material, proxyPort);
    await testTheNamedTerminatorCarriesTheBrowsersTransport(
      "https://" + LOOPBACK + ":" + proxyPort, material.caPem);

    await closeTerminator(terminator);
    terminator = null;
    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    identity.close();
    identity = null;

    return helpers.getChecks();
  } finally {
    if (terminator) {
      try { await closeTerminator(terminator); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
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

module.exports = { name: "web-transport-trust", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exit(1);
  });
}
