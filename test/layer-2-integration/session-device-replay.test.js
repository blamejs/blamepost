// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a session cookie is worth once it has been copied off the machine
 * it was issued to.
 *
 * Signing in binds the session to the shape of the request that opened
 * it: the address it came from, the browser that sent it, the language
 * that browser asked for. The binding is recorded when the session is
 * minted, and the question this file asks is whether anything ever reads
 * it back. A binding that is computed and never compared is not a
 * binding; it is a field in a row, and the cookie it was supposed to
 * qualify is still a bearer token that works from anywhere.
 *
 * The replay below is the whole threat in one move. One reader signs in
 * and is handed a cookie. A second reader on a different address, sending
 * a different browser's agent string, puts that cookie on and asks for
 * the operator console. Nothing else about the second reader is
 * privileged: it knows no password, it passed no credential, and every
 * byte it carries came off the first reader's jar.
 *
 * Claims:
 *
 *   - The console refuses a session replayed from another machine by
 *     another browser, so a copied cookie does not administer this
 *     server.
 *   - The refusal explains itself well enough to act on, and names no
 *     part of the binding. A reader told which signal differed is told
 *     which one to forge next.
 *   - The reader that actually signed in still holds its console. The
 *     refusal re-authenticates rather than revoking: a replay somebody
 *     else attempted must not be a way to sign the operator out.
 *   - A replay against the mailbox surface leaves a record. That surface
 *     admits it, deliberately and for a reason the fix documents, so the
 *     trail is the only thing that would ever tell an operator it
 *     happened, and it has to be there.
 *
 * Both readers dial out from their own address inside 127.0.0.0/8, which
 * is what makes them two peers to the server rather than one client
 * asking twice. A fixture that shared one address would test the opposite
 * of what it claims.
 *
 * Run standalone: node test/layer-2-integration/session-device-replay.test.js
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

var count       = helpers.count;
var reservePort = wire.reservePort;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ROOT_PASSWORD    = "quiet lantern bicycle 4291";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// Two peers, one host. The whole of 127.0.0.0/8 is local, so each reader
// arrives at the server from an address of its own.
var SIGNED_IN_SOURCE = "127.0.0.51";
var REPLAY_SOURCE    = "127.0.0.52";

// The browser the replay claims to be. It differs from the reader default
// in every field the binding reads, which is what a cookie lifted onto
// somebody else's machine looks like.
var REPLAY_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/120.0.0.0 Safari/537.36";

// Nothing in a refusal may name a part of the binding. A reader told that
// the address matched and the agent did not has been handed the shape of
// the next attempt.
var LEAKY_WORDS = [
  "user-agent", "user agent", "useragent", "browser string",
  "ip address", "address changed", "accept-language", "language header",
  "fingerprint", "127.0.0.5",
];

var SHUTDOWN_TIMEOUT_MS = 5000;

// The session cookie's name, taken off the jar rather than copied out of
// the application. A constant repeated here is a constant that goes on
// passing after the application renames it, and this file would then
// replay a cookie that is not the session.
function _sessionCookieName(reader) {
  var names = reader.cookies.names();
  for (var i = 0; i < names.length; i += 1) {
    if (names[i].toLowerCase().indexOf("session") !== -1) return names[i];
  }
  return null;
}

// Did this response hand over the console, or turn the reader away? The
// console renders at 200; every refusal this application writes is either
// a status outside 2xx or a redirect away from the route asked for.
function _admitted(res) {
  return res.status === 200;
}

function _mentionsAnyOf(text, words) {
  var haystack = String(text || "").toLowerCase();
  var found = [];
  for (var i = 0; i < words.length; i += 1) {
    if (haystack.indexOf(words[i]) !== -1) found.push(words[i]);
  }
  return found;
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("session-device-replay");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // Every store this run opens resolves its working copy under here. A
  // run that leaves it unset is refused at the door by the store itself,
  // for a reason that has nothing to do with the binding under test.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

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

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var operator = await identity.accounts.create({
      address:  "root@" + DOMAIN,
      password: ROOT_PASSWORD,
      isAdmin:  true,
    });

    // No mail listener binds a port. What is under test is in front of a
    // browser route, and a listener that binds nothing cannot fail this
    // run for a reason of its own.
    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var n = 0; n < names.length; n += 1) {
      sections[names[n]] = { enabled: false, port: await reservePort(), address: LOOPBACK };
    }
    var httpPort = await reservePort();

    server = blamepost.create({
      config:       Object.assign({}, cfg,
        { httpPort: httpPort, httpsPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var origin = "http://" + LOOPBACK + ":" + httpPort;

    // 1. The operator signs in from their own machine and opens the
    //    console. Everything below is measured against this working.
    var owner = browser.browserAt(origin, { localAddress: SIGNED_IN_SOURCE });
    var signedIn = await owner.signIn(operator.address, ROOT_PASSWORD);
    count("the operator signs in",
      signedIn.status === 302 || signedIn.status === 303,
      "status " + signedIn.status);

    var cookieName = _sessionCookieName(owner);
    count("and is handed a session cookie to hold",
      cookieName !== null, "cookies held: " + JSON.stringify(owner.cookies.names()));

    var consoleOpen = await owner.get("/admin");
    count("which opens the operator console",
      _admitted(consoleOpen), "status " + consoleOpen.status);

    // 2. The replay. A second machine, a second browser, the first
    //    machine's cookie and nothing else.
    var stolen = cookieName === null ? null : owner.cookies.read(cookieName);
    var thief = browser.browserAt(origin, {
      localAddress: REPLAY_SOURCE,
      userAgent:    REPLAY_USER_AGENT,
    });
    if (cookieName !== null && typeof stolen === "string") {
      thief.cookies.set(cookieName, stolen);
    }

    var replayed = await thief.get("/admin");
    count("a session cookie copied to another machine and sent by another browser does not " +
      "open the operator console, so the cookie is bound to what signed in rather than " +
      "being a bearer token that administers this server from anywhere",
      !_admitted(replayed),
      "status " + replayed.status +
        (replayed.location === null ? "" : ", to " + replayed.location));

    // 3. What the refused reader is told. Enough to act on, and nothing
    //    an attacker can aim with.
    var leaked = _mentionsAnyOf(replayed.body, LEAKY_WORDS);
    count("and the refusal names no part of the binding, so a reader who is turned away is " +
      "not told which signal to forge next",
      leaked.length === 0, "named " + JSON.stringify(leaked));

    count("while still saying enough for the operator to know to sign in again rather than " +
      "reading the refusal as a broken console",
      /sign in/i.test(String(replayed.body || "")),
      "body " + JSON.stringify(String(replayed.body || "").slice(0, 220)));

    // 4. The refusal re-authenticates; it does not revoke. A replay
    //    somebody else attempted must not be a way to sign the operator
    //    out of their own console.
    var stillOpen = await owner.get("/admin");
    count("the operator's own console still opens after the replay was refused, so a stranger " +
      "sending a copied cookie cannot sign the operator out by trying",
      _admitted(stillOpen), "status " + stillOpen.status);

    // 5. The mailbox surface. It admits the replay, which is a decision
    //    rather than an oversight, so the trail is the only thing that
    //    would ever tell an operator it happened.
    await thief.get("/");

    // Emits buffer and drain serially, so a read that wants durability
    // asks for it. Polling here would report a flush that had not been
    // asked for as an absence of rows.
    await b.audit.flush();

    var drift = await b.audit.query({
      action: "auth.session.fingerprint_drift", order: "desc", limit: 10 });
    count("a session used from a machine other than the one it was opened from is recorded, " +
      "so a replay the mailbox surface admits is still something an operator can find",
      drift.length >= 1, "rows " + drift.length);

    var refusals = await b.audit.query({
      action: "blamepost.web.console_device_refused", order: "desc", limit: 10 });
    count("and the console refusal is recorded under a name of its own, so an operator " +
      "reading the trail can tell a replayed session from an account that simply holds no " +
      "operator role",
      refusals.length >= 1, "rows " + refusals.length);

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
  name:      "session-device-replay",
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
