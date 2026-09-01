// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One budget behind the browser and the mail listeners both.
 *
 * The browser sign in form and the mail listeners are different code
 * reaching different framework primitives, and an attacker does not care
 * which one they use. What this file drives is that they read the SAME
 * failure budget: guesses spent in the browser are gone on IMAP, and
 * guesses spent on IMAP are gone in the browser. A budget per surface is
 * six budgets, which is six times the guesses.
 *
 * Every request here arrives from a source address the one before it did
 * not use, so nothing below can be satisfied by the per address bounds
 * this server already had. The browser form carries a bound of ten posts
 * per address per five minutes and each address below posts once, so
 * that bound never fires; the mail listeners carry ten authentication
 * failures per address per quarter hour and each address below fails at
 * most once.
 *
 * Claims:
 *
 *   - Wrong passwords posted to the sign in form from five different
 *     addresses spend the mailbox's budget, and the CORRECT password
 *     from a sixth address is then refused, with a page that says the
 *     attempts are the reason rather than the credential.
 *   - That same spent budget refuses an IMAP AUTHENTICATE carrying the
 *     correct password, from an address that has posted nothing.
 *   - Another mailbox signs in from the very address that was refused,
 *     so the budget is keyed on the mailbox rather than on the peer.
 *   - The sharing works in the other direction too: guesses spent on
 *     IMAP refuse the browser form.
 *
 * Run standalone: node test/layer-2-integration/lockout-web-signin.test.js
 */

var nodeFs   = require("node:fs");
var nodeHttp = require("node:http");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "steady harbour pumpkin 7715";
var WRONG_PASSWORD   = "not the password that was set 8830";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// The whole of 127.0.0.0/8 is local, so a client can bind a different
// source per attempt and the server reports each as its own peer.
var ALICE_HOME     = "127.0.0.1";
var ALICE_ATTACK   = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"];
var ALICE_PROBE    = "127.0.0.7";
var BOB_ATTACK     = ["127.0.0.8", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.0.12"];
var BOB_PROBE      = "127.0.0.13";

var SHUTDOWN_TIMEOUT_MS = 5000;
var HTTP_TIMEOUT_MS     = 15000;

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- a browser, from a named source address --------------------------------
//
// `fetch` has no way to name the local address it dials out from, and
// naming it is the whole claim, so the requests here are node:http.

function request(opts) {
  return new Promise(function (resolve, reject) {
    var req = nodeHttp.request({
      host:         LOOPBACK,
      port:         opts.port,
      localAddress: opts.source,
      method:       opts.method || "GET",
      path:         opts.path,
      headers:      opts.headers || {},
      timeout:      HTTP_TIMEOUT_MS,
    }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { body += chunk; });
      res.on("end", function () {
        resolve({
          status:   res.statusCode,
          headers:  res.headers,
          setCookie: res.headers["set-cookie"] || [],
          body:     body,
        });
      });
    });
    req.on("timeout", function () { req.destroy(new Error("http timeout")); });
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

function jar() {
  var cookies = Object.create(null);
  return {
    absorb: function (res) {
      for (var i = 0; i < res.setCookie.length; i += 1) {
        var first = res.setCookie[i].split(";")[0];
        var eq = first.indexOf("=");
        if (eq === -1) continue;
        cookies[first.slice(0, eq).trim()] = first.slice(eq + 1).trim();
      }
    },
    header: function () {
      return Object.keys(cookies).map(function (k) { return k + "=" + cookies[k]; }).join("; ");
    },
  };
}

// One sign in, from one source address, with its own cookie jar and its
// own token. Returns the status and the page, because the page is where
// this server tells the reader why.
async function signIn(port, source, address, password) {
  var cookies = jar();
  var form = await request({ port: port, source: source, path: "/sign-in" });
  cookies.absorb(form);
  var found = /name="_csrf" value="([^"]*)"/.exec(form.body);
  if (!found) throw new Error("sign-in form carried no token: " + form.body.slice(0, 300));
  var body = "address=" + encodeURIComponent(address) +
    "&password=" + encodeURIComponent(password) +
    "&_csrf=" + encodeURIComponent(found[1]);
  var posted = await request({
    port:   port,
    source: source,
    method: "POST",
    path:   "/sign-in",
    headers: {
      "Content-Type":   "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(body),
      "Origin":         "http://" + LOOPBACK + ":" + port,
      "Host":           LOOPBACK + ":" + port,
      "Cookie":         cookies.header(),
    },
    body: body,
  });
  return {
    ok:     posted.status === 302 || posted.status === 303,
    status: posted.status,
    page:   posted.body,
  };
}

// ---- an IMAP client, from a named source address ---------------------------

function connectFrom(port, source, label) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port, localAddress: source }, function () {
      resolve(new Wire(socket, label + "@" + source));
    });
    socket.once("error", reject);
  });
}

async function imapAttempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "imap-" + label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("x0 STARTTLS");
  await session.read(/^x0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, password));
  var verdict = await session.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  session.close();
  return { ok: /^x1 OK/m.test(verdict), text: verdict };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("lockout-web");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };
    var httpPort = await reservePort();

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: httpPort, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var imapPort = sections.imap.port;
    var caPem    = leaf.ca;

    // 1. The owner signs in from the address they always use, so that
    //    address is one this server has seen work for this mailbox.
    var home = await signIn(httpPort, ALICE_HOME, alice.address, ALICE_PASSWORD);
    count("the account owner signs in through the browser from their usual address",
      home.ok === true, "status " + home.status);

    // 2. Five wrong passwords, five addresses, all through the browser.
    for (var i = 0; i < ALICE_ATTACK.length; i += 1) {
      var refused = await signIn(httpPort, ALICE_ATTACK[i], alice.address, WRONG_PASSWORD);
      count("a wrong password posted from " + ALICE_ATTACK[i] + " is refused",
        refused.ok === false && refused.status === 401, "status " + refused.status);
    }

    // 3. The correct password from a sixth address is refused, and the
    //    page says the attempts are the reason.
    var probed = await signIn(httpPort, ALICE_PROBE, alice.address, ALICE_PASSWORD);
    count("the correct password is refused from an address that spent none of the budget",
      probed.ok === false, "status " + probed.status);
    count("and the page names too many attempts rather than the credential",
      /too many|try again/i.test(probed.page), probed.page.slice(0, 400));

    // 4. The same budget refuses IMAP, so it is one budget rather than
    //    one per surface.
    var overImap = await imapAttempt(imapPort, caPem, ALICE_PROBE,
      alice.address, ALICE_PASSWORD, "after-browser");
    count("IMAP refuses the correct password too, so the browser and the " +
      "listeners read one budget", overImap.ok === false, visible(overImap.text));

    // 5. Another mailbox from the very address that was refused is let in.
    var other = await signIn(httpPort, ALICE_PROBE, bob.address, BOB_PASSWORD);
    count("another mailbox signs in from the address that was just refused",
      other.ok === true, "status " + other.status);

    // 6. The account owner, from the address the browser signed them in
    //    from before the guessing started, is still let in. This is the
    //    only vector that can show the browser hands the peer to the
    //    identity layer at all: without it the address would never have
    //    become familiar and this would refuse alongside the rest.
    //    It clears the budget, so it runs after everything that reads it.
    var ownerBack = await signIn(httpPort, ALICE_HOME, alice.address, ALICE_PASSWORD);
    count("the account owner signs in from the address the browser already knows them from",
      ownerBack.ok === true, "status " + ownerBack.status);

    // 7. The other direction. Guesses spent on IMAP refuse the browser.
    for (var j = 0; j < BOB_ATTACK.length; j += 1) {
      var wrong = await imapAttempt(imapPort, caPem, BOB_ATTACK[j],
        bob.address, WRONG_PASSWORD, "bob-spend-" + j);
      count("a wrong password on IMAP from " + BOB_ATTACK[j] + " is refused",
        wrong.ok === false, visible(wrong.text));
    }
    var bobBrowser = await signIn(httpPort, BOB_PROBE, bob.address, BOB_PASSWORD);
    count("the browser refuses the correct password after the budget was spent on IMAP",
      bobBrowser.ok === false, "status " + bobBrowser.status);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "lockout-web-signin",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
