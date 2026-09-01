// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The assembled server, built and started the way the command line's
 * serve verb builds and starts it: a real temporary data directory, a
 * real vault, a real encrypted database, the real identity layer, the
 * real protocol facing mailbox adapter, and real ports.
 *
 * Every other file in this layer exercises one module on its own, which
 * leaves a whole class of failure invisible. A server that cannot boot
 * at all still passes a suite where nothing ever calls
 * `blamepost.create`. A listener that refuses at construction, a
 * readiness probe on a port nothing binds, and one mailbox namespace
 * shared by every account are properties of the assembly rather than of
 * any module inside it, and only a boot can observe them.
 *
 * What this file pins:
 *
 *   - `blamepost.create` returns a server rather than throwing.
 *   - Every enabled listener reaches a bound port and answers on it,
 *     POP3 and ManageSieve included. Those two refuse at construction
 *     when the mailbox adapter is absent, so a greeting from either one
 *     proves the adapter arrived.
 *   - `/healthz` answers ok on the running process, which is the
 *     question a container asks it.
 *   - Stopping releases every socket, so a supervisor restart finds the
 *     ports free.
 *   - SELECT reads a real mailbox rather than meeting the framework's
 *     refusal for a listener whose mailbox backend was never wired.
 *   - Two accounts hold two mailboxes. A message delivered to one is
 *     invisible to the other.
 *   - A conforming IMAP client signs in. It reads the greeting,
 *     upgrades with STARTTLS, and authenticates over the encrypted
 *     channel, which is the sequence every mail client performs and the
 *     one nothing else in the suite drives.
 *
 * The certificate is generated into the data directory and named
 * through the configuration, the way an operator names one. That is the
 * whole reason the authentication above can run: the listeners refuse a
 * credential before TLS, so a boot handed a certificate context with no
 * certificate in it can never reach a client sign in, and every session
 * this file opened stopped at the greeting. It also means the
 * certificate loader, the file reads behind it and the TLS port of the
 * browser surface are all on the path this file drives rather than
 * bypassed by an argument.
 *
 * Ports come from the operating system rather than from the operator
 * defaults, so the suite runs unprivileged and two runs on one machine
 * do not collide.
 *
 * Run standalone: node test/layer-1-state/server-boot.test.js
 */

var nodeFs   = require("node:fs");
var nodeHttp = require("node:http");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// The listener set this server runs once the operator turns POP3 on.
// POP3 and ManageSieve are the two the framework refuses to construct
// without a mailbox adapter, so their presence here is the point rather
// than a completeness exercise.
var LISTENER_NAMES = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];

// Wire reads and socket probes are bounded, so a listener that binds and
// then says nothing fails as a named timeout instead of holding the
// runner until the job budget runs out.
var WIRE_TIMEOUT_MS = 5000;

// ---- the certificate -------------------------------------------------------

// The certificate an operator hands this server when ACME is not
// issuing one is built by test/helpers/certs.js and written to disk for
// the configuration to name. It is shared rather than built here
// because more than one file now needs the same pair.
//
// Handing `blamepost.create` a ready made context instead would look
// equivalent and is not. It skips the certificate loader, the capped
// file reads, the sealed key path and the TLS port of the browser
// surface, and a context built with no certificate in it cannot
// complete a handshake at all, which silently costs every test that
// needs an encrypted channel.
function writeCertificatePair(tlsDir) {
  return certs.writePair(tlsDir, { hostname: HOSTNAME });
}

// ---- ports and sockets -----------------------------------------------------

// One port the operating system just handed out and then released. The
// mail listeners take a port number rather than a zero, so a free port
// has to be found before the bind rather than read back after it. It is
// the same reservation every wire test makes, so it comes from the
// shared socket helper.
var reservePort = wire.reservePort;

// The listener sections the composed server binds, one reserved
// loopback port each. Everything is enabled, including the listener an
// operator opts into, because a listener that is off cannot fail to
// construct and this file is about the ones that can.
async function listenerSections() {
  var sections = {};
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    sections[LISTENER_NAMES[i]] = {
      enabled: true,
      port:    await reservePort(),
      address: "127.0.0.1",
    };
  }
  return sections;
}

// Read from a bound port until the pattern matches, the peer closes, or
// the budget runs out. A timeout quotes what the listener did say, so a
// wrong banner reads as a wrong banner rather than as a bare timeout.
function readUntil(port, pattern, label) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: "127.0.0.1", port: port });
    var text = "";
    var settled = false;
    socket.setEncoding("utf8");
    socket.setTimeout(WIRE_TIMEOUT_MS);
    socket.on("data", function (chunk) {
      text += chunk;
      if (settled || !pattern.test(text)) return;
      settled = true;
      socket.end();
      resolve(text);
    });
    socket.once("timeout", function () {
      socket.destroy();
      if (settled) return;
      settled = true;
      reject(new Error(label + ": port " + port + " answered " + JSON.stringify(text) +
        " and then went quiet"));
    });
    socket.once("error", function (e) {
      if (settled) return;
      settled = true;
      reject(e);
    });
    socket.once("close", function () {
      if (settled) return;
      settled = true;
      resolve(text);
    });
  });
}

// One short exchange on the IMAP port: read the greeting, send a
// command, and return everything the listener said. The session stays
// unauthenticated on purpose. The strict profile this server ships
// refuses credentials before TLS, and what is under test here is that
// the port belongs to this server's IMAP listener and that the listener
// answers rather than that a client can sign in.
function imapExchange(port, command) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: "127.0.0.1", port: port });
    var text = "";
    var sentAt = -1;
    var settled = false;
    socket.setEncoding("utf8");
    socket.setTimeout(WIRE_TIMEOUT_MS);
    function finish(value, error) {
      if (settled) return;
      settled = true;
      socket.end();
      if (error) reject(error);
      else resolve(value);
    }
    socket.on("data", function (chunk) {
      text += chunk;
      if (sentAt === -1) {
        if (text.indexOf("\r\n") === -1) return;
        sentAt = text.length;
        socket.write(command + "\r\n");
        return;
      }
      if (text.length > sentAt) finish(text, null);
    });
    socket.once("timeout", function () {
      socket.destroy();
      finish(null, new Error("imap exchange: port " + port + " answered " +
        JSON.stringify(text) + " and then went quiet"));
    });
    socket.once("error", function (e) { finish(null, e); });
    socket.once("close", function () { finish(text, null); });
  });
}

// Whether a connection to a port is refused, which is the wire level
// answer to "is anything still listening there".
function connectionRefused(port) {
  return new Promise(function (resolve) {
    var socket = nodeNet.connect({ host: "127.0.0.1", port: port });
    socket.setTimeout(WIRE_TIMEOUT_MS);
    socket.once("connect", function () { socket.destroy(); resolve(false); });
    socket.once("timeout", function () { socket.destroy(); resolve(false); });
    socket.once("error", function () { socket.destroy(); resolve(true); });
  });
}

function httpGet(port, requestPath) {
  return new Promise(function (resolve, reject) {
    var req = nodeHttp.request({
      host:    "127.0.0.1",
      port:    port,
      path:    requestPath,
      method:  "GET",
      timeout: WIRE_TIMEOUT_MS,
      headers: { Accept: "application/json" },
    }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { body += chunk; });
      res.on("end", function () { resolve({ status: res.statusCode, body: body }); });
    });
    req.once("timeout", function () {
      req.destroy(new Error("GET " + requestPath + " on port " + port + " never answered"));
    });
    req.once("error", reject);
    req.end();
  });
}

// Listening sockets this process still holds. A closed listener leaves
// nothing behind, so anything counted here after a stop is a port the
// next boot will not get back.
function listeningSockets() {
  var active = process.getActiveResourcesInfo();
  var held = 0;
  for (var i = 0; i < active.length; i += 1) {
    if (active[i] === "TCPSERVERWRAP") held += 1;
  }
  return held;
}

// ---- assembly --------------------------------------------------------------

function testCreateAssemblesTheServer(runtimeConfig, identity) {
  var built = null;
  var thrown = null;
  try {
    built = blamepost.create({
      config:       runtimeConfig,
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      // No certificate context is passed. The configuration names the
      // pair on disk, so the server loads it the way it loads an
      // operator's, and what every listener presents is what an operator
      // would have deployed.
      httpAddress:  "127.0.0.1",
    });
  } catch (e) {
    thrown = e;
  }
  count("blamepost.create assembles the server rather than throwing", thrown === null,
    thrown === null ? undefined : thrown.message);
  if (thrown !== null) throw thrown;

  count("the assembled server carries the lifecycle the command line drives",
    typeof built.start === "function" && typeof built.stop === "function");
  count("it carries the protocol listeners",
    built.mail !== undefined && built.mail.listeners !== undefined &&
    typeof built.mail.listeners.bound === "function");
  count("it carries the browser surface the readiness probe answers on",
    built.web !== undefined && typeof built.web.start === "function");
  return built;
}

// A domain the operator has not acknowledged closes the MX listener,
// and closing the MX listener refuses the whole boot sequence. Two
// things are checked here. The refusal names the domain it is waiting
// on, because "acknowledge the DNS" over a server with several domains
// is not an instruction anybody can act on. And the outbound sweep
// timer, which start arms before any listener binds, is disarmed on the
// way out: the command line answers a failed start by closing the
// store, so a timer still armed would sweep against a store that is no
// longer open.
async function testAnUnacknowledgedDomainRefusesTheBoot(runtimeConfig, identity) {
  var refused = blamepost.create({
    config:      runtimeConfig,
    store:       identity,
    mailStore:   identity.mailbox,
    messageStore: identity.messageStore,
    httpAddress: "127.0.0.1",
  });
  var thrown = null;
  try { await refused.start(); }
  catch (e) { thrown = e; }

  count("a domain with no acknowledged posture refuses the boot",
    thrown !== null, thrown === null ? "the boot completed" : thrown.message);
  count("the refusal names the domain it is waiting on",
    thrown !== null && String(thrown.message).indexOf(DOMAIN) !== -1,
    thrown === null ? "" : thrown.message);
  count("the refusal points at the command that clears it",
    thrown !== null && String(thrown.message).indexOf("domain acknowledge") !== -1,
    thrown === null ? "" : thrown.message);
  count("a failed boot leaves no listener bound",
    Object.keys(refused.mail.listeners.bound()).length === 0,
    JSON.stringify(refused.mail.listeners.bound()));
  count("a failed boot disarms the outbound sweep timer",
    refused.mail.delivery.describe().sweeping === false,
    JSON.stringify(refused.mail.delivery.describe()));

  // Releases the certificate watcher this server built at create time.
  // Nothing bound, so there is nothing else to drain.
  await refused.stop({ timeoutMs: WIRE_TIMEOUT_MS });
}

function testEveryListenerIsConfigured(server) {
  var shape = server.describe().listeners;
  count("the MX listener boots behind an acknowledged DNS posture",
    shape.dnsAcknowledged === true);
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    var name = LISTENER_NAMES[i];
    var section = shape.listeners[name];
    count("the " + name + " listener is enabled before the boot",
      section !== undefined && section.enabled === true, JSON.stringify(section));
  }
  count("nothing is bound before start", Object.keys(shape.bound).length === 0,
    JSON.stringify(shape.bound));
}

// ---- the boot --------------------------------------------------------------

function testEveryListenerBound(server, sections) {
  var bound = server.mail.listeners.bound();
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    var name = LISTENER_NAMES[i];
    count("the " + name + " listener was constructed and took its port",
      bound[name] === sections[name].port, JSON.stringify(bound));
  }
  count("POP3 bound, and it refuses to construct at all without the mailbox adapter",
    typeof bound.pop3 === "number", JSON.stringify(bound));
  count("ManageSieve bound, on the same refusal",
    typeof bound.managesieve === "number", JSON.stringify(bound));
}

async function testTheListenersAnswerOnTheirPorts(sections) {
  var imapGreeting = await readUntil(sections.imap.port, /\r\n/, "imap greeting");
  count("the IMAP port carries this server's own greeting",
    /^\* OK \[CAPABILITY/.test(imapGreeting) &&
    imapGreeting.indexOf(HOSTNAME + " IMAP4rev2 blamepost") !== -1,
    imapGreeting);

  var pop3Greeting = await readUntil(sections.pop3.port, /\r\n/, "pop3 greeting");
  count("the POP3 port carries this server's own greeting, so that listener is live",
    /^\+OK /.test(pop3Greeting) &&
    pop3Greeting.indexOf(HOSTNAME + " POP3 blamepost") !== -1,
    pop3Greeting);

  var sieveBanner = await readUntil(sections.managesieve.port, /OK "/,
    "managesieve capability banner");
  count("the ManageSieve port carries its capability banner and greeting",
    sieveBanner.indexOf(HOSTNAME + " ManageSieve blamepost") !== -1, sieveBanner);
}

async function testHealthzAnswersOk(server) {
  var httpPort = server.web.bound().http;
  count("the browser surface took an ephemeral port",
    typeof httpPort === "number" && httpPort > 0, httpPort);

  var answer = await httpGet(httpPort, "/healthz");
  count("the readiness probe answers 200 on the running server",
    answer.status === 200, answer.status + " " + answer.body);

  var payload;
  try { payload = JSON.parse(answer.body); } catch (_e) { payload = null; }
  count("it reports a process fit to carry mail",
    payload !== null && payload.status === "ok", answer.body);
  return httpPort;
}

// The certificate the configuration named, presented on the wire and
// verified against the authority that signed it and the name the server
// answers to. A pair that a browser would refuse fails here instead.
async function testTheBrowserSurfacePresentsTheCertificate(server, caPem) {
  var httpsPort = server.web.bound().https;
  count("the browser surface took a TLS port because a certificate was configured",
    typeof httpsPort === "number" && httpsPort > 0, JSON.stringify(server.web.bound()));

  await new Promise(function (resolve, reject) {
    var socket = nodeTls.connect({
      host:       "127.0.0.1",
      port:       httpsPort,
      servername: HOSTNAME,
      ca:         [caPem],
    });
    socket.setTimeout(WIRE_TIMEOUT_MS);
    socket.once("secureConnect", function () {
      count("a client verifies the presented certificate against the issuing authority",
        socket.authorized === true, String(socket.authorizationError));
      var presented = socket.getPeerCertificate();
      count("the certificate carries the name this server answers to",
        typeof presented.subjectaltname === "string" &&
        presented.subjectaltname.indexOf("DNS:" + HOSTNAME) !== -1,
        presented.subjectaltname);
      socket.end();
      resolve();
    });
    socket.once("timeout", function () {
      socket.destroy();
      reject(new Error("the TLS port accepted a connection and never completed a handshake"));
    });
    socket.once("error", reject);
  });
}

// ---- SELECT reaches a real mailbox -----------------------------------------

// The framework's IMAP listener probes its `mailStore` for
// `selectFolder` and refuses SELECT outright when the method is absent,
// because the sentinel UIDVALIDITY the older fallback returned collides
// with a real one and leaves a client believing a synced state it does
// not have. The refusal is what a server whose adapter never reached
// its listeners answers to every SELECT, so this drives the adapter the
// composed server was built with and the port that listener bound.
async function testSelectReadsARealMailbox(sections, identity, alice) {
  count("the adapter the listeners were built with answers SELECT",
    typeof identity.mailbox.selectFolder === "function");

  var info = null;
  var thrown = null;
  try {
    info = identity.mailbox.selectFolder(alice, "INBOX", { readOnly: false });
  } catch (e) {
    thrown = e;
  }
  count("SELECT on a real folder returns a mailbox rather than refusing",
    thrown === null && info !== null && typeof info === "object",
    thrown === null ? undefined : thrown.message);
  count("the mailbox carries the unique UIDVALIDITY RFC 9051 section 2.3.1.1 requires",
    Number.isInteger(info.uidvalidity) && info.uidvalidity > 0, info.uidvalidity);
  count("it carries the next UID the client will be handed",
    Number.isInteger(info.uidnext) && info.uidnext >= 1, info.uidnext);
  count("it carries a message count rather than a sentinel",
    Number.isInteger(info.exists) && info.exists >= 0, info.exists);

  var transcript = await imapExchange(sections.imap.port, "a1 SELECT INBOX");
  count("the bound IMAP listener answers a SELECT rather than dropping the session",
    transcript.length > 0 && /(BAD|NO)/.test(transcript), transcript);
  count("its answer is about the session and never about an unwired mailbox backend",
    transcript.indexOf("selectFolder is not configured") === -1, transcript);
}

// ---- one mailbox per account -----------------------------------------------

function messageFor(recipient, subject) {
  return Buffer.from(
    "Message-ID: <" + subject + "." + Date.now() + "@" + HOSTNAME + ">\r\n" +
    "From: postmaster@" + DOMAIN + "\r\n" +
    "To: " + recipient + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" +
    "one line of body text\r\n", "utf8");
}

// The regression for a shared INBOX. `b.mailStore` has one flat folder
// namespace with no owner column, so an adapter that passes the wire
// name straight through gives every account on the server the same
// mailbox: one delivery, and everybody reads it.
function testAccountsDoNotShareAMailbox(identity, alice, bob) {
  var aliceFolders = identity.mailbox.listFolders(alice);
  var bobFolders   = identity.mailbox.listFolders(bob);
  count("each account is provisioned with its own folder set",
    Array.isArray(aliceFolders) && aliceFolders.length > 0 &&
    Array.isArray(bobFolders) && bobFolders.length > 0,
    JSON.stringify([aliceFolders.length, bobFolders.length]));

  var stored = identity.mailbox.appendMessage("INBOX", messageFor("alice@" + DOMAIN, "for-alice"),
    { actor: alice });
  count("a message delivered to one account lands in a mailbox",
    stored !== null && typeof stored.objectid === "string" && stored.objectid.length > 0,
    JSON.stringify(stored));

  var aliceInbox = identity.mailbox.selectFolder(alice, "INBOX", {});
  var bobInbox   = identity.mailbox.selectFolder(bob, "INBOX", {});
  count("the account it was addressed to holds it", aliceInbox.exists === 1, aliceInbox.exists);
  count("the other account's INBOX is a different mailbox and stays empty",
    bobInbox.exists === 0, bobInbox.exists);

  identity.mailbox.appendMessage("INBOX", messageFor("bob@" + DOMAIN, "for-bob"), { actor: bob });
  var aliceAfter = identity.mailbox.selectFolder(alice, "INBOX", {});
  var bobAfter   = identity.mailbox.selectFolder(bob, "INBOX", {});
  count("a delivery to the second account does not reach the first",
    aliceAfter.exists === 1, aliceAfter.exists);
  count("the second account sees its own message and only its own",
    bobAfter.exists === 1, bobAfter.exists);

  var aliceFetch = identity.mailbox.fetchRange(alice, "INBOX", "1", "(BODY.PEEK[HEADER])", {});
  count("the message the first account reads is the one addressed to it",
    aliceFetch.length === 1 && aliceFetch[0].payload.indexOf("To: alice@" + DOMAIN) !== -1,
    JSON.stringify(aliceFetch));
}

// ---- a conforming client signs in ------------------------------------------

// RFC 4616 section 2. The authorization identity is left empty, which
// is what a client sends when it is not asking to act as somebody else.
// The shared encoder, so this file cannot disagree with the rest of the
// suite about what a credential looks like on the wire.
var saslPlain = wire.saslPlain;

// One IMAP session, driven the way a mail client drives one. Each step
// waits for the reply it expects rather than for a byte count, so a
// listener that answers something else fails with the transcript quoted
// instead of hanging. `upgrade` hands the plain socket to node's TLS
// client and drops everything buffered with it: bytes held at that
// point belong to the cleartext half of the session, and carrying them
// across is the STARTTLS injection the listener defends against from
// its own side.
function imapSession(port) {
  var socket   = null;
  var buffered = "";
  var waiting  = null;
  var broken   = null;

  function _deliver() {
    if (waiting === null || !waiting.pattern.test(buffered)) return;
    var done = waiting;
    waiting = null;
    clearTimeout(done.timer);
    var captured = buffered;
    buffered = "";
    done.resolve(captured);
  }

  function _breakOff(cause) {
    broken = cause;
    if (waiting === null) return;
    var done = waiting;
    waiting = null;
    clearTimeout(done.timer);
    done.reject(cause);
  }

  function _attach(next) {
    socket = next;
    socket.on("data", function (chunk) {
      buffered += chunk.toString("utf8");
      _deliver();
    });
    socket.on("error", function (cause) { _breakOff(cause); });
    socket.on("close", function () {
      // A peer that closes straight after its last reply is ordinary,
      // and on a TLS socket the close can be seen before the bytes it
      // sent are. Deliver what arrived first, so LOGOUT reads as an
      // answered command rather than as a dropped session.
      _deliver();
      _breakOff(new Error("the IMAP listener closed the session"));
    });
  }

  function expect(pattern, label) {
    return new Promise(function (resolve, reject) {
      if (broken !== null) {
        reject(broken);
        return;
      }
      var timer = setTimeout(function () {
        var held = buffered;
        waiting = null;
        reject(new Error(label + ": the listener answered " + JSON.stringify(held) +
          " and then went quiet"));
      }, WIRE_TIMEOUT_MS);
      waiting = { pattern: pattern, resolve: resolve, reject: reject, timer: timer };
      _deliver();
    });
  }

  function send(line) { socket.write(line + "\r\n"); }

  return {
    open: function () {
      return new Promise(function (resolve, reject) {
        var plain = nodeNet.connect({ host: "127.0.0.1", port: port });
        plain.setTimeout(WIRE_TIMEOUT_MS);
        plain.once("connect", function () {
          _attach(plain);
          resolve();
        });
        plain.once("error", reject);
      });
    },
    expect: expect,
    send:   send,
    ask: function (line, pattern, label) {
      send(line);
      return expect(pattern, label);
    },
    upgrade: function (caPem, servername) {
      return new Promise(function (resolve, reject) {
        var plain = socket;
        plain.removeAllListeners("data");
        plain.removeAllListeners("error");
        plain.removeAllListeners("close");
        buffered = "";
        var secure = nodeTls.connect({
          socket:     plain,
          servername: servername,
          ca:         [caPem],
        });
        secure.once("secureConnect", function () {
          if (secure.authorized !== true) {
            reject(new Error("the certificate the IMAP listener presented did not verify: " +
              String(secure.authorizationError)));
            return;
          }
          _attach(secure);
          resolve();
        });
        secure.once("error", reject);
      });
    },
    close: function () {
      if (socket !== null) socket.destroy();
    },
  };
}

// The sequence every mail client performs, and the one nothing else in
// this suite reaches: greeting, STARTTLS, and a credential over the
// encrypted channel. Both spellings of the credential are driven,
// because they are two different paths through the listener. The inline
// form is answered by a single call into the verifier. The form with no
// initial response makes the listener write a continuation, hold the
// exchange open across a line, and route what comes back into the same
// verifier at the next step, and a server that gets that wrong refuses
// every client which waits to be asked.
async function testAConformingClientAuthenticates(sections, caPem, address, password) {
  var session = imapSession(sections.imap.port);
  try {
    await session.open();
    var greeting = await session.expect(/\r\n/, "imap greeting");
    count("the greeting advertises IMAP4rev2",
      /^\* OK \[CAPABILITY [^\]]*IMAP4rev2/.test(greeting), greeting);
    count("a cleartext session is offered STARTTLS",
      greeting.indexOf("STARTTLS") !== -1, greeting);
    count("the advertised mechanism is the one this server implements",
      greeting.indexOf("AUTH=PLAIN") !== -1, greeting);

    var early = await session.ask("a1 AUTHENTICATE PLAIN", /^a1 /m, "AUTHENTICATE before TLS");
    count("a credential offered before TLS is refused and the reason names TLS",
      /^a1 BAD /m.test(early) && early.indexOf("TLS") !== -1, early);

    var ready = await session.ask("a2 STARTTLS", /^a2 /m, "STARTTLS");
    count("the listener agrees to negotiate TLS", /^a2 OK /m.test(ready), ready);
    // Verified against the authority that signed it and against the
    // name the listener answers to, so a certificate that would fail in
    // a client fails here rather than being waved through.
    await session.upgrade(caPem, HOSTNAME);

    var caps = await session.ask("a3 CAPABILITY", /^a3 /m, "CAPABILITY over TLS");
    count("CAPABILITY completes on the encrypted channel", /^a3 OK /m.test(caps), caps);
    count("STARTTLS is gone from the capability line once TLS is up",
      caps.indexOf("* CAPABILITY") !== -1 && !/\* CAPABILITY[^\r\n]*STARTTLS/.test(caps), caps);
    count("the mechanism is still advertised on the encrypted channel",
      caps.indexOf("AUTH=PLAIN") !== -1, caps);

    // RFC 9051 section 6.2.2 makes the initial response an optional
    // argument of AUTHENTICATE, so a client may leave the credential
    // off the command line and wait to be asked for it. PLAIN is client
    // first, so the ask carries nothing: the listener writes a bare
    // continuation and the credential arrives on the next line.
    session.send("a4 AUTHENTICATE PLAIN");
    var challenge = await session.expect(/^\+ ?\r\n/m, "SASL server challenge");
    count("a client that sends no initial response is challenged rather than refused",
      /^\+ ?\r\n/m.test(challenge) && !/^a4 /m.test(challenge), challenge);

    var verdict = await session.ask(saslPlain(address, password), /^a4 /m, "AUTHENTICATE verdict");
    count("the credential sent in answer to the challenge is accepted",
      /^a4 OK /m.test(verdict), verdict);

    // The session the exchange produced is the account's own, which is
    // the part an OK line alone does not prove.
    var listed = await session.ask("a5 LIST \"\" \"*\"", /^a5 /m, "LIST");
    count("LIST completes for the signed in account", /^a5 OK /m.test(listed), listed);
    count("it names the account's own inbox", listed.indexOf("\"INBOX\"") !== -1, listed);
    count("no store folder name reaches the client", listed.indexOf("mbx_") === -1, listed);

    var selected = await session.ask("a6 SELECT INBOX", /^a6 /m, "SELECT");
    count("SELECT completes on the account's own inbox", /^a6 OK /m.test(selected), selected);
    count("the mailbox holds the one message delivered to this account",
      /^\* 1 EXISTS/m.test(selected), selected);

    var farewell = await session.ask("a7 LOGOUT", /^\* BYE/m, "LOGOUT");
    count("LOGOUT is answered with the untagged BYE RFC 9051 section 6.1.3 requires",
      /^\* BYE/m.test(farewell), farewell);
    // RFC 9051 section 6.1.3 wants a tagged OK after that BYE, and over
    // TLS it never reaches the client. The listener writes both lines and
    // then closes with `end()` followed immediately by `destroy()`, which
    // discards the TLS records still buffered; the same LOGOUT on a
    // cleartext socket delivers both lines. The listener is in the
    // vendored tree, which this repository does not patch, so the gap is
    // recorded here rather than asserted.
    helpers.skip("the tagged OK completing LOGOUT is discarded over TLS by the vendored " +
      "listener's immediate destroy, so only the untagged BYE can be asserted");

    return { greeting: greeting, caps: caps };
  } finally {
    session.close();
  }
}

// The other spelling, on its own connection, because the listener
// refuses a second AUTHENTICATE on a session that already has an actor.
//
// RFC 4959 named SASL-IR for IMAP4rev1, where AUTHENTICATE took no
// initial response argument. IMAP4rev2 carries the argument in its own
// grammar, so a listener advertising IMAP4rev2 needs no atom for it.
// What must hold either way is that the capability line and the
// listener agree: the inline form is legal here only because one of
// those two atoms is on the line, and it has to work.
async function testTheInlineCredentialAlsoWorks(sections, caPem, advertised, address, password) {
  var advertisesSaslIr = advertised.caps.indexOf("SASL-IR") !== -1;
  count("the inline initial response is legal on this listener, by SASL-IR or by IMAP4rev2",
    advertisesSaslIr || advertised.caps.indexOf("IMAP4rev2") !== -1, advertised.caps);
  if (advertisesSaslIr) {
    // A client reads the greeting before it has anywhere to send a
    // CAPABILITY, so an atom that appears only after TLS is an atom
    // half the clients never see.
    count("a listener advertising SASL-IR advertises it in the greeting as well",
      advertised.greeting.indexOf("SASL-IR") !== -1, advertised.greeting);
  }

  var session = imapSession(sections.imap.port);
  try {
    await session.open();
    await session.expect(/\r\n/, "imap greeting");
    var ready = await session.ask("b1 STARTTLS", /^b1 /m, "STARTTLS");
    count("the second session negotiates TLS as well", /^b1 OK /m.test(ready), ready);
    await session.upgrade(caPem, HOSTNAME);

    var verdict = await session.ask(
      "b2 AUTHENTICATE PLAIN " + saslPlain(address, password), /^b2 /m, "inline AUTHENTICATE");
    count("a credential carried on the AUTHENTICATE line is accepted",
      /^b2 OK /m.test(verdict), verdict);

    var selected = await session.ask("b3 SELECT INBOX", /^b3 /m, "SELECT on the inline session");
    count("the inline sign in produced a usable session", /^b3 OK /m.test(selected), selected);
  } finally {
    session.close();
  }
}

// ---- the shutdown ----------------------------------------------------------

async function testStopReleasesEveryPort(server, sections, httpPort) {
  var outcome = await server.stop({ timeoutMs: WIRE_TIMEOUT_MS });
  count("stop reports the listeners it closed",
    outcome !== null && Array.isArray(outcome.closed) && outcome.closed.length > 0,
    JSON.stringify(outcome));

  var stillBound = server.mail.listeners.bound();
  count("the mail listener table is empty after the stop",
    Object.keys(stillBound).length === 0, JSON.stringify(stillBound));
  var webBound = server.web.bound();
  count("the browser surface released its port too",
    Object.keys(webBound).length === 0, JSON.stringify(webBound));

  await helpers.waitUntil(function () {
    return listeningSockets() === 0;
  }, {
    timeoutMs: WIRE_TIMEOUT_MS,
    label:     "server-boot: every listening socket released after stop",
  });
  count("the process holds no listening socket once the server is stopped",
    listeningSockets() === 0, listeningSockets());

  count("a connection to the IMAP port is refused after the stop",
    await connectionRefused(sections.imap.port) === true);
  count("a connection to the browser port is refused after the stop",
    await connectionRefused(httpPort) === true);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("boot");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted at rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    // Written before the configuration is read, because the loader
    // checks that a named certificate exists and refuses the boot when
    // it does not.
    var certificate = await writeCertificatePair(nodePath.join(dataDir, "tls"));

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        // The MX listener refuses to bind without this, which is the
        // posture gate. Turning it on here is what lets the boot reach
        // every listener rather than stopping at the first gate.
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_POP3_ENABLED:     "true",
        // The certificate every listener presents. There is no other
        // source: nothing here issues one, so a configuration that
        // names none has nothing to start.
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: root,
    });
    count("the configuration carries the certificate the listeners present",
      cfg.tlsCert === certificate.certFile && cfg.tlsKey === certificate.keyFile, cfg.tlsCert);

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = actorFor(await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD }));
    var bob = actorFor(await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD }));

    var sections = await listenerSections();
    // The loaded configuration with the ports moved off the operator
    // defaults. Port 25 and port 143 need privileges the runner does not
    // have, and a fixed high port collides with a second run on the same
    // machine; the browser surface takes its own ephemeral port because
    // it accepts a zero and reports back what it got.
    var runtimeConfig = Object.assign({}, cfg, {
      httpPort:  0,
      // The TLS half of the browser surface binds here too, because the
      // certificate is on disk and that is what decides whether it does.
      // It takes an ephemeral port for the same reason the cleartext one
      // does.
      httpsPort: 0,
      listeners: sections,
    });

    // The MX listener wants the domain's own acknowledgement as well as
    // the server's, so this runs before the boot that is expected to
    // succeed and after the one that is expected to refuse.
    await testAnUnacknowledgedDomainRefusesTheBoot(runtimeConfig, identity);
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });

    server = testCreateAssemblesTheServer(runtimeConfig, identity);
    testEveryListenerIsConfigured(server);

    await server.start();
    running = true;

    testEveryListenerBound(server, sections);
    await testTheListenersAnswerOnTheirPorts(sections);
    var httpPort = await testHealthzAnswersOk(server);
    await testTheBrowserSurfacePresentsTheCertificate(server, certificate.caPem);
    await testSelectReadsARealMailbox(sections, identity, alice);
    testAccountsDoNotShareAMailbox(identity, alice, bob);

    var advertised = await testAConformingClientAuthenticates(
      sections, certificate.caPem, "alice@" + DOMAIN, ALICE_PASSWORD);
    await testTheInlineCredentialAlsoWorks(
      sections, certificate.caPem, advertised, "alice@" + DOMAIN, ALICE_PASSWORD);

    await testStopReleasesEveryPort(server, sections, httpPort);
    running = false;
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: WIRE_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

// The actor a listener carries for the rest of a session, in the shape
// the mailbox adapter reads: the account id is what every folder lookup
// resolves against, and a call that cannot name one is refused.
function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   account.isAdmin === true,
    mailboxes: [account.address],
    // The roles the listener issues, and no scopes array beside them.
    // `b.permissions` reads a scopes array in preference to the roles,
    // so an empty one is a grant of nothing rather than a request to
    // decide from the role.
    roles:     account.isAdmin === true ? ["admin", "account"] : ["account"],
  };
}

module.exports = { name: "server-boot", run: run, getChecks: helpers.getChecks };

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
