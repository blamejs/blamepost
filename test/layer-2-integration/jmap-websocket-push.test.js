// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The JMAP push channels, driven the way a client drives them: a real
 * WebSocket upgrade against the running listener, and a real event
 * source stream beside it.
 *
 * RFC 8887 section 3 says a client that discovers
 * `urn:ietf:params:jmap:websocket` in the session document prefers the
 * WebSocket transport over polling the API endpoint. So the session
 * document is a promise, and the only way to keep it is to serve the
 * endpoint it names. The half of that promise this file exists to hold
 * is the last check below: the url the session advertises is the url
 * that upgrades. A server that mounts a push endpoint somewhere else
 * fails on the client as a channel that never opens, and nothing on
 * the server side records that anything went wrong.
 *
 * The upgrade does not travel through the router, so none of the
 * middleware the routed surface relies on has run by the time the
 * handshake is decided. The three properties that matter are therefore
 * asserted here rather than assumed: the connection carries an
 * authenticated account, an origin this server does not serve is
 * refused, and one account's channel never carries another account's
 * state.
 *
 * The push assertion is deliberately about a mutation this client did
 * not make. A channel that only reports the caller's own writes tells a
 * client nothing it did not already know, and new mail arriving from a
 * peer is the event the whole transport exists for.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/jmap-websocket-push.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodeHttp   = require("node:http");
var nodeNet    = require("node:net");
var nodePath   = require("node:path");
var nodeTls    = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var LOOPBACK         = "127.0.0.1";
var HOSTNAME         = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

// An origin no listener in this run answers on. Port 1 is reserved and
// the name is RFC 2606 documentation space, so nothing can resolve it
// into something that happens to work.
var FOREIGN_ORIGIN = "https://attacker.example:1";

// The TLS port the configuration names when BLAMEPOST_HTTPS_PORT is not
// set. The listener in this file binds an ephemeral port, and the
// allowlist is built from the configured port, which is the one a
// browser's Origin names.
var CONFIGURED_HTTPS_PORT = 8443;

// The capability a conforming client looks for before it prefers the
// socket over polling, and the two urls the session document carries
// beside it.
var WS_CAPABILITY = "urn:ietf:params:jmap:websocket";

// How long a push assertion waits for the server to notice a write it
// did not perform. The channel is a connection the client holds open,
// not a poll the client runs, so the budget only has to cover the
// server noticing.
var PUSH_BUDGET_MS = 8000;

// The window a negative push assertion burns to show that nothing
// arrived. Long enough to cover more than one server side sweep,
// because a window shorter than the sweep proves only that the sweep
// had not run yet.
var QUIET_WINDOW_MS = 3000;

function message(subject, to, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

// ---------------------------------------------------------------------------
// A WebSocket client, built from the framework's own frame layer.
//
// `b.websocket` ships the handshake key derivation, the frame
// serializer and the incremental parser, so the only thing written by
// hand here is the request line and the collection of what comes back.
// A second hand rolled frame writer would be a second opinion about
// what a masked text frame looks like, and the one that matters is the
// framework's, because that is what the server parses with.
// ---------------------------------------------------------------------------

function wsConnect(port, opts) {
  opts = opts || {};
  var path = typeof opts.path === "string" ? opts.path : "/jmap/ws";
  var key  = nodeCrypto.randomBytes(16).toString("base64");
  // The Host header a browser sends names the address it dialed, which
  // is the public name rather than the loopback socket this client
  // connects to.
  var host = typeof opts.host === "string" ? opts.host : LOOPBACK + ":" + port;

  var lines = [
    "GET " + path + " HTTP/1.1",
    "Host: " + host,
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Key: " + key,
    "Sec-WebSocket-Version: 13",
  ];
  if (opts.subprotocol !== null) {
    lines.push("Sec-WebSocket-Protocol: " + (opts.subprotocol || "jmap"));
  }
  if (typeof opts.origin === "string" && opts.origin.length > 0) {
    lines.push("Origin: " + opts.origin);
  }
  if (typeof opts.cookie === "string" && opts.cookie.length > 0) {
    lines.push("Cookie: " + opts.cookie);
  }

  return new Promise(function (resolve, reject) {
    // Over TLS when the caller names an authority, because the session
    // cookie carries the `__Host-` prefix and the `Secure` attribute,
    // so TLS is the only transport a browser would ever hold it over.
    // Verification stays on: a client that skipped it would pass
    // against a listener presenting anything at all.
    var socket = opts.ca === undefined
      ? nodeNet.connect({ host: LOOPBACK, port: port })
      : nodeTls.connect({
          host: LOOPBACK, port: port, ca: [opts.ca], servername: opts.servername });
    var settled    = false;
    var header     = Buffer.alloc(0);
    var upgraded   = false;
    var parser     = null;
    var frames     = { text: [], close: null };
    var handle     = null;
    var authorized = null;

    var deadline = setTimeout(function () {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_e) { /* already gone */ }
      reject(new Error("the upgrade at " + path + " never answered within 5000ms"));
    }, 5000);
    if (typeof deadline.unref === "function") deadline.unref();

    function _finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(value);
    }

    function _onFrame(frame) {
      if (frame.opcode === b.websocket.OPCODE_TEXT) {
        var text = frame.payload.toString("utf8");
        var parsed;
        try { parsed = JSON.parse(text); } catch (_e) { parsed = null; }
        frames.text.push({ text: text, json: parsed === undefined ? null : parsed });
        return;
      }
      if (frame.opcode === b.websocket.OPCODE_CLOSE) {
        frames.close = {
          code:   frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : 0,
          reason: frame.payload.length > 2 ? frame.payload.slice(2).toString("utf8") : "",
        };
      }
    }

    socket.on("error", function (err) {
      if (settled) { return; }
      settled = true;
      clearTimeout(deadline);
      reject(err);
    });

    socket.on("close", function () {
      if (handle) handle.closed = true;
      // A refusal written before any body arrives closes without ever
      // completing a header block. Resolving here rather than hanging
      // is what lets the caller assert on the status it was given.
      _finish({ status: 0, headers: {}, upgraded: false, frames: frames, socket: socket });
    });

    // The handshake goes out once the transport is ready, and for TLS
    // that is after the certificate has been verified rather than
    // after the TCP connection is up.
    socket.on(opts.ca === undefined ? "connect" : "secureConnect", function () {
      if (opts.ca !== undefined) authorized = socket.authorized === true;
      socket.write(lines.join("\r\n") + "\r\n\r\n");
    });

    socket.on("data", function (chunk) {
      if (upgraded) {
        try { parser.push(chunk).forEach(_onFrame); }
        catch (_e) { /* a frame this client cannot parse is not the subject */ }
        return;
      }
      header = Buffer.concat([header, chunk]);
      var end = header.indexOf("\r\n\r\n");
      if (end === -1) return;
      var head    = header.slice(0, end).toString("utf8");
      var rest    = header.slice(end + 4);
      var rows    = head.split("\r\n");
      var status  = parseInt(String(rows[0]).split(" ")[1], 10);
      var headers = Object.create(null);
      for (var i = 1; i < rows.length; i += 1) {
        var colon = rows[i].indexOf(":");
        if (colon === -1) continue;
        headers[rows[i].slice(0, colon).trim().toLowerCase()] = rows[i].slice(colon + 1).trim();
      }
      if (status !== 101) {
        try { socket.destroy(); } catch (_e) { /* already gone */ }
        _finish({ status: status, headers: headers, upgraded: false, frames: frames, socket: socket });
        return;
      }
      upgraded = true;
      parser = new b.websocket.FrameParser({ maxFrameBytes: 1024 * 1024 });
      if (rest.length > 0) {
        try { parser.push(rest).forEach(_onFrame); }
        catch (_e) { /* see above */ }
      }
      handle = {
        status:      status,
        headers:     headers,
        upgraded:    true,
        authorized:  authorized,
        acceptKey:   headers["sec-websocket-accept"] || "",
        expectedKey: b.websocket.computeAcceptKey(key),
        subprotocol: headers["sec-websocket-protocol"] || "",
        frames:      frames,
        closed:      false,
        socket:      socket,
        send: function (obj) {
          socket.write(b.websocket.serializeFrame(
            b.websocket.OPCODE_TEXT, JSON.stringify(obj), { mask: true }));
        },
        // Every text frame whose JSON carries this RFC 8887 @type, in
        // arrival order. Reading by type rather than by position is
        // what lets a Response and a StateChange interleave without
        // the assertions depending on which landed first.
        typed: function (type) {
          return frames.text.filter(function (entry) {
            return entry.json !== null && entry.json["@type"] === type;
          }).map(function (entry) { return entry.json; });
        },
        stop: function () { try { socket.destroy(); } catch (_e) { /* already gone */ } },
      };
      _finish(handle);
    });
  });
}

// ---------------------------------------------------------------------------
// An event source client. The response never ends, so the buffering
// reader in test/helpers/browser cannot drive it: this one keeps the
// response open and collects frames as they are written.
// ---------------------------------------------------------------------------

function sseConnect(port, cookie) {
  return new Promise(function (resolve, reject) {
    var req = nodeHttp.request({
      host:    LOOPBACK,
      port:    port,
      path:    "/jmap/eventsource?types=*&closeafter=no&ping=5",
      method:  "GET",
      headers: { Accept: "text/event-stream", Cookie: cookie },
    }, function (res) {
      var buffered = "";
      var events   = [];
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        buffered += chunk;
        var cut = buffered.indexOf("\n\n");
        while (cut !== -1) {
          var block = buffered.slice(0, cut);
          buffered  = buffered.slice(cut + 2);
          var name  = /(^|\n)event: *(\S+)/.exec(block);
          var data  = /(^|\n)data: *(.*)/.exec(block);
          var json  = null;
          if (data !== null) { try { json = JSON.parse(data[2]); } catch (_e) { json = null; } }
          events.push({ event: name === null ? "" : name[2], json: json, raw: block });
          cut = buffered.indexOf("\n\n");
        }
      });
      resolve({
        status:      res.statusCode,
        contentType: String(res.headers["content-type"] || ""),
        events:      events,
        stateEvents: function () {
          return events.filter(function (entry) { return entry.event === "state"; });
        },
        stop: function () { try { req.destroy(); } catch (_e) { /* already gone */ } },
      });
    });
    req.once("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wiringFor(cfg, identity, tls) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({
      store: identity.messageStore, dispatch: { mode: "local" },
    }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return []; },
    address:   LOOPBACK,
    httpPort:  0,
    // The TLS port is taken as well when the caller supplies a
    // certificate, because the session cookie carries the `__Host-`
    // prefix and the `Secure` attribute: cleartext is a convenience for
    // the rest of this file, and TLS is the only transport a browser
    // would ever complete this upgrade over.
    httpsPort: tls === undefined ? undefined : 0,
    tls:       tls,
  };
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

function testSessionAdvertisesTheTransport(session) {
  check("the session document answers a signed in account", session.status === 200);
  var doc = JSON.parse(session.body);

  check("the session document advertises the WebSocket capability",
    Object.prototype.hasOwnProperty.call(doc.capabilities || {}, WS_CAPABILITY));
  count("the capability names the url a client is to upgrade at",
    typeof doc.capabilities[WS_CAPABILITY].url === "string" &&
    doc.capabilities[WS_CAPABILITY].url.length > 0,
    JSON.stringify(doc.capabilities[WS_CAPABILITY]));
  count("the capability url and the top level webSocketUrl are the same url",
    doc.webSocketUrl === doc.capabilities[WS_CAPABILITY].url,
    doc.webSocketUrl + " against " + doc.capabilities[WS_CAPABILITY].url);
  count("the session document advertises an event source url as well",
    typeof doc.eventSourceUrl === "string" && doc.eventSourceUrl.length > 0,
    String(doc.eventSourceUrl));
  return doc;
}

async function testTheAdvertisedUrlIsTheOneThatUpgrades(port, cookie, doc, origin) {
  // The whole point of the file. A path constant written here instead
  // would test that this file and the server agree, which is a much
  // weaker claim than the one a client depends on.
  var advertised = String(doc.webSocketUrl).split("?")[0];
  var conn = await wsConnect(port, { path: advertised, cookie: cookie, origin: origin });
  count("the url the session document advertises answers with a completed upgrade",
    conn.upgraded === true, "status " + conn.status + " at " + advertised);
  if (conn.upgraded !== true) return null;

  count("the handshake key is derived the way RFC 6455 section 4.2.2 requires",
    conn.acceptKey === conn.expectedKey, conn.acceptKey + " against " + conn.expectedKey);
  count("the server selects the jmap subprotocol RFC 8887 section 3.1 requires",
    conn.subprotocol === "jmap", conn.subprotocol);
  return conn;
}

// A WebSocket endpoint answers only an upgrade, so an ordinary request
// to one is how a probe cannot tell a mounted endpoint from an absent
// one: both would be a 404. This is the answer that makes the two
// distinguishable, and RFC 9110 section 15.5.22 requires the header
// naming what to switch to.
async function testAnOrdinaryRequestSaysToUpgrade(reader, advertised) {
  var answer = await reader.get(advertised, { Accept: "text/plain" });
  count("an ordinary request to the WebSocket path is told to upgrade",
    answer.status === 426, String(answer.status));
  count("the refusal names the protocol to switch to",
    String(answer.headers.upgrade || "").toLowerCase() === "websocket",
    String(answer.headers.upgrade));
  count("the answer carries none of this account's mail",
    answer.body.indexOf("@example.com") === -1, answer.body.slice(0, 120));
}

async function testAnUnauthenticatedUpgradeIsRefused(port, advertised, origin) {
  var conn = await wsConnect(port, { path: advertised, origin: origin });
  count("an upgrade carrying no session is refused rather than completed",
    conn.upgraded === false, "status " + conn.status);
  count("the refusal is the unauthorized status, not a socket that simply died",
    conn.status === 401, String(conn.status));
}

async function testAForeignOriginIsRefused(port, cookie, advertised) {
  var conn = await wsConnect(port, {
    path: advertised, cookie: cookie, origin: FOREIGN_ORIGIN });
  count("an upgrade from an origin this server does not serve is refused",
    conn.upgraded === false, "status " + conn.status);
  count("the refusal is the forbidden status, so a session cookie is not enough on its own",
    conn.status === 403, String(conn.status));
}

// A refusal on the upgrade path leaves no response an operator can go
// back and read, so the audit row is the whole record that it happened.
// The namespace has to be asserted rather than assumed: an unregistered
// one drops every row and says nothing while doing it.
async function testRefusalsAreRecorded() {
  var rows = await helpers.waitUntil(async function () {
    var found = await b.audit.query({
      action: "blamepost.jmap.websocket.refused", limit: 50, offset: 0 });
    return Array.isArray(found) && found.length > 0 ? found : false;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the upgrade refusals reach the audit log",
  });
  var reasons = rows.map(function (row) {
    var meta = row.metadata;
    if (typeof meta === "string") { try { meta = JSON.parse(meta); } catch (_e) { meta = {}; } }
    return (meta && meta.reason) || "";
  });
  count("the refusal for an origin this server does not serve is recorded",
    reasons.indexOf("origin-not-served") !== -1, reasons.join(","));
  count("the refusal for an upgrade carrying no account is recorded",
    reasons.indexOf("no-authenticated-account") !== -1, reasons.join(","));
  count("every recorded refusal is a denial rather than a success",
    rows.filter(function (row) { return row.outcome !== "denied"; }).length === 0,
    rows.map(function (row) { return row.outcome; }).join(","));

  // An upgrade never travels through the router, so nothing on this
  // path has an authenticated account to name and the row does not
  // pretend otherwise. What it can stand behind is where the attempt
  // came from, and on a refusal that is the whole question. A row
  // recording that something was refused and not from where sends an
  // operator to the audit page and back with nothing.
  count("and each one records the peer the refused upgrade came from",
    rows.filter(function (row) {
      return typeof row.actorIp === "string" && row.actorIp.length > 0;
    }).length === rows.length,
    rows.map(function (row) { return String(row.actorIp); }).join(","));
}

async function testASocketWithoutTheSubprotocolIsClosed(port, cookie, advertised, origin) {
  var conn = await wsConnect(port, {
    path: advertised, cookie: cookie, origin: origin, subprotocol: null });
  if (conn.upgraded !== true) {
    count("a client offering no subprotocol is refused at the handshake",
      conn.status !== 101, String(conn.status));
    return;
  }
  count("the server does not echo a subprotocol it was never offered",
    conn.subprotocol === "", conn.subprotocol);
  await helpers.waitUntil(function () { return conn.frames.close !== null; }, {
    timeoutMs: 4000,
    label:     "jmap-websocket-push: the server closes a socket that did not offer jmap",
  });
  count("the close code is the protocol error RFC 8887 section 3.1 calls for",
    conn.frames.close.code === b.websocket.CLOSE_PROTOCOL_ERROR,
    conn.frames.close.code + " " + conn.frames.close.reason);
  conn.stop();
}

async function testRequestFramesDispatchOverTheSocket(conn, accountId, otherAccountId) {
  conn.send({
    "@type": "Request",
    id:      "r1",
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: accountId }, "c0"]],
  });
  var replies = await helpers.waitUntil(function () {
    var seen = conn.typed("Response");
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: a Request frame answered with a Response frame",
  });
  count("the Response echoes the requestId the client sent",
    replies[0].requestId === "r1", String(replies[0].requestId));
  var answer = replies[0].methodResponses[0];
  count("the Response carries the mailboxes this account owns",
    answer[0] === "Mailbox/get" && answer[1].list.length === 6,
    answer[0] + " " + (answer[1].list === undefined ? "" : answer[1].list.length));

  // The cross-account gate lives in the dispatcher the HTTP endpoint
  // shares, and a transport that reached dispatch by another door
  // would be the way around it. Driving it here is what proves the
  // socket did not find that door.
  conn.send({
    "@type": "Request",
    id:      "r2",
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: otherAccountId }, "c0"]],
  });
  var second = await helpers.waitUntil(function () {
    var seen = conn.typed("Response").filter(function (r) { return r.requestId === "r2"; });
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: a Request naming another account answered",
  });
  var refused = second[0].methodResponses[0];
  count("a Request naming another account's id is refused over the socket too",
    refused[0] === "error" && refused[1].type === "urn:ietf:params:jmap:error:accountNotFound",
    JSON.stringify(refused));
}

// Enable push and wait until the server has actually acted on it.
//
// The frame is written and forgotten otherwise, and a push subscription
// records the account's state as it stands when the push subscription
// is made, so a write that lands in the gap is folded into the baseline
// and never reported as a change. Frames are processed in order, so a
// Response to a Request sent after the enable is the barrier: the
// dispatch behind it settles later than the subscribe the enable
// started, which makes the arrival of the Response proof that the push
// subscription exists.
async function enablePush(conn, requestId, accountId, dataTypes) {
  conn.send({
    "@type":   "WebSocketPushEnable",
    dataTypes: dataTypes === undefined ? null : dataTypes,
  });
  conn.send({
    "@type": "Request",
    id:      requestId,
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: accountId, ids: [] }, "c0"]],
  });
  await helpers.waitUntil(function () {
    return conn.typed("Response").filter(function (r) {
      return r.requestId === requestId;
    }).length > 0;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the push subscription for " + requestId + " is in place",
  });
}

// Both accounts hold an open channel here, and that is the point. A
// negative assertion driven with only one subscriber proves nothing:
// the other account would be unwatched, so its mail could not have
// produced an event for anybody, and the check passes for a reason
// that has nothing to do with scoping. With both subscribed, the
// arrival that reaches one of them is the same sweep the other has to
// stay silent through.
async function testPushIsScopedToTheAccountThatSubscribed(aliceConn, bobConn, identity, alice, bob) {
  await enablePush(aliceConn, "enable-alice", alice.id);
  await enablePush(bobConn, "enable-bob", bob.id);

  // The other account first. Appending through the store is the same
  // call the delivery path makes when a peer hands this server a
  // message, so this is mail arriving rather than a client acting.
  identity.mailbox.appendMessage("INBOX",
    message("Bobs own arrival", bob.address, "for bob alone"),
    { actor: { id: bob.id } });

  var bobsPush = await helpers.waitUntil(function () {
    var seen = bobConn.typed("StateChange");
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: PUSH_BUDGET_MS,
    label:     "jmap-websocket-push: the other account's own socket hears its own arrival",
  });
  count("the other account's StateChange names the other account",
    Object.keys(bobsPush[0].changed || {}).join(",") === bob.id,
    Object.keys(bobsPush[0].changed || {}).join(","));

  // Arrival of the event above proves a sweep completed after the
  // write, so this socket's silence is a decision rather than a race.
  count("a write in another account produces no StateChange on this socket",
    aliceConn.typed("StateChange").length === 0,
    JSON.stringify(aliceConn.typed("StateChange")));

  identity.mailbox.appendMessage("INBOX",
    message("Arrival this client did not make", alice.address, "pushed rather than polled"),
    { actor: { id: alice.id } });

  var pushed = await helpers.waitUntil(function () {
    var seen = aliceConn.typed("StateChange");
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: PUSH_BUDGET_MS,
    label:     "jmap-websocket-push: a StateChange reaches the client after an arrival it did not make",
  });

  var changed = pushed[0].changed || {};
  count("the StateChange names this account and no other",
    Object.keys(changed).length === 1 && Object.keys(changed)[0] === alice.id,
    Object.keys(changed).join(","));
  count("the StateChange carries the types whose state actually moved",
    typeof changed[alice.id].Mailbox === "string" &&
    typeof changed[alice.id].Email === "string",
    JSON.stringify(changed[alice.id]));
  count("this account's arrival reaches nobody else's socket",
    bobConn.typed("StateChange").length === bobsPush.length,
    bobsPush.length + " before, " + bobConn.typed("StateChange").length + " after");

  // A state string a client cannot act on is a notification with no
  // follow up: the value pushed has to be the value the API answers
  // with, or the client refetches and concludes it is already current.
  aliceConn.send({
    "@type": "Request",
    id:      "r3",
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: alice.id }, "c0"]],
  });
  var after = await helpers.waitUntil(function () {
    var seen = aliceConn.typed("Response").filter(function (r) { return r.requestId === "r3"; });
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the state the API reports after the push",
  });
  count("the pushed state is the state the API answers with",
    after[0].methodResponses[0][1].state === changed[alice.id].Mailbox,
    changed[alice.id].Mailbox + " against " + after[0].methodResponses[0][1].state);
}

async function testPushDisableStopsTheChannel(conn, identity, alice) {
  var before = conn.typed("StateChange").length;
  conn.send({ "@type": "WebSocketPushDisable" });
  // The same barrier the enable needs, for the same reason: a frame
  // this client has written is not a frame the server has read, and an
  // append that lands in that gap would be reported through a push
  // subscription that was still live when it happened.
  conn.send({
    "@type": "Request",
    id:      "after-disable",
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"]],
  });
  await helpers.waitUntil(function () {
    return conn.typed("Response").filter(function (r) {
      return r.requestId === "after-disable";
    }).length > 0;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the disable has been read before the next write",
  });
  identity.mailbox.appendMessage("INBOX",
    message("Arrival after the disable", alice.address, "should reach nobody"),
    { actor: { id: alice.id } });
  await helpers.passiveObserve(QUIET_WINDOW_MS,
    "jmap-websocket-push: no StateChange after a disable");
  count("a disabled channel stops carrying StateChange",
    conn.typed("StateChange").length === before,
    before + " before, " + conn.typed("StateChange").length + " after");
}

async function testEventSourceServesTheSameChannel(port, cookie, identity, alice) {
  var stream = await sseConnect(port, cookie);
  count("the event source url opens a stream rather than refusing",
    stream.status === 200, String(stream.status));
  count("the stream is served as the media type an EventSource client reads",
    stream.contentType.indexOf("text/event-stream") === 0, stream.contentType);
  if (stream.status !== 200) { stream.stop(); return; }

  identity.mailbox.appendMessage("INBOX",
    message("Arrival for the event source reader", alice.address, "sse rather than ws"),
    { actor: { id: alice.id } });
  var seen = await helpers.waitUntil(function () {
    var events = stream.stateEvents();
    return events.length > 0 ? events : false;
  }, {
    timeoutMs: PUSH_BUDGET_MS,
    label:     "jmap-websocket-push: a state event reaches the event source reader",
  });
  count("the state event names this account",
    seen[0].json !== null && Object.keys(seen[0].json.changed || {})[0] === alice.id,
    seen[0].raw.slice(0, 160));
  stream.stop();
}

// `dataTypes` is the only field on this channel a client chooses, so
// it is the only one worth driving with something other than the happy
// value. Narrowing has to actually narrow, and a list naming nothing
// this server tracks has to produce silence rather than a StateChange
// carrying an empty map, which would wake a client to tell it nothing.
async function testTheClientCanNarrowWhatItHearsAbout(port, cookie, advertised, origin, identity, alice) {
  var narrow = await wsConnect(port, { path: advertised, cookie: cookie, origin: origin });
  var quiet  = await wsConnect(port, { path: advertised, cookie: cookie, origin: origin });
  count("a second and third socket for one account both upgrade",
    narrow.upgraded === true && quiet.upgraded === true,
    narrow.status + " and " + quiet.status);

  await enablePush(narrow, "narrow", alice.id, ["Email"]);
  await enablePush(quiet, "quiet", alice.id, ["CalendarEvent"]);

  identity.mailbox.appendMessage("INBOX",
    message("Arrival for a narrowed push subscription", alice.address, "email only"),
    { actor: { id: alice.id } });

  var pushed = await helpers.waitUntil(function () {
    var seen = narrow.typed("StateChange");
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: PUSH_BUDGET_MS,
    label:     "jmap-websocket-push: the narrowed push subscription hears about the arrival",
  });
  var types = Object.keys(pushed[0].changed[alice.id] || {});
  count("a push subscription narrowed to one type is told about that type alone",
    types.join(",") === "Email", types.join(","));
  count("a push subscription naming nothing this server tracks is told nothing",
    quiet.typed("StateChange").length === 0,
    JSON.stringify(quiet.typed("StateChange")));

  narrow.stop();
  quiet.stop();
}

// The same upgrade over TLS, which is the only transport a browser
// would ever complete it on: the session cookie carries the `__Host-`
// prefix and the `Secure` attribute, so a browser refuses to hold it
// otherwise. Every other case here runs on cleartext for convenience,
// and a channel proven only there is a channel proven in the one
// configuration no reader can actually use.
async function testTheUpgradeAlsoCompletesOverTls(port, ca, hostname, alice, password) {
  var reader = browser.browserAt("https://" + LOOPBACK + ":" + port,
    { ca: ca, servername: hostname });
  var landed = await reader.signIn(alice.address, password);
  count("the reader signs in over TLS", landed.status === 302, String(landed.status));

  var conn = await wsConnect(port, {
    path:       "/jmap/ws",
    cookie:     reader.cookies.header(),
    origin:     "https://" + hostname + ":" + CONFIGURED_HTTPS_PORT,
    ca:         ca,
    servername: hostname,
  });
  count("the certificate the TLS listener presented verified against the run's authority",
    conn.authorized === true, String(conn.authorized));
  count("the upgrade completes over TLS as well as over cleartext",
    conn.upgraded === true, "status " + conn.status);
  count("the jmap subprotocol is negotiated over TLS too",
    conn.subprotocol === "jmap", conn.subprotocol);

  conn.send({
    "@type": "Request",
    id:      "tls",
    using:   browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: alice.id }, "c0"]],
  });
  var replies = await helpers.waitUntil(function () {
    var seen = conn.typed("Response").filter(function (r) { return r.requestId === "tls"; });
    return seen.length > 0 ? seen : false;
  }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: a Request frame answered over TLS",
  });
  count("the socket carries this account's own mailboxes over TLS",
    replies[0].methodResponses[0][1].list.length === 6,
    String(replies[0].methodResponses[0][1].list.length));
  conn.stop();
  return reader;
}

// The origins a signed-in browser may open the socket from. The server
// accepts `https://` at BLAMEPOST_HOSTNAME on the default port and on
// BLAMEPOST_HTTPS_PORT, refuses every other Origin with 403, and accepts
// an upgrade that carries no Origin header. Each case sends the Host
// header a browser at that origin would send, so a host-only same-origin
// comparison would accept the two cleartext origins.
async function testOnlyThePublicTlsOriginsMayUpgrade(port, ca, hostname, reader) {
  var cookie = reader.cookies.header();
  var cases = [
    { label: "a cleartext page at the public name and port",
      host: hostname + ":" + CONFIGURED_HTTPS_PORT,
      origin: "http://" + hostname + ":" + CONFIGURED_HTTPS_PORT, upgrades: false },
    { label: "a cleartext page at the public name on the default port",
      host: hostname, origin: "http://" + hostname, upgrades: false },
    { label: "a page on another site",
      host: hostname, origin: "https://evil.example", upgrades: false },
    { label: "the public TLS origin on the configured TLS port",
      host: hostname + ":" + CONFIGURED_HTTPS_PORT,
      origin: "https://" + hostname + ":" + CONFIGURED_HTTPS_PORT, upgrades: true },
    { label: "the public TLS origin on the default port, which a TLS terminator serves",
      host: hostname, origin: "https://" + hostname, upgrades: true },
    { label: "a client that sends no Origin header",
      host: hostname, origin: undefined, upgrades: true },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var conn = await wsConnect(port, {
      path: "/jmap/ws", cookie: cookie, origin: cases[i].origin, host: cases[i].host,
      ca: ca, servername: hostname,
    });
    if (cases[i].upgrades) {
      count("the upgrade completes for " + cases[i].label,
        conn.upgraded === true, "status " + conn.status);
    } else {
      count("the upgrade is refused with 403 for " + cases[i].label,
        conn.upgraded === false && conn.status === 403, "status " + conn.status);
    }
    if (conn.upgraded === true) conn.stop();
  }
}

function threw(fn) {
  try { fn(); return false; }
  catch (_e) { return true; }
}

// The two verbs the composition boundary exposes, driven straight off
// a `blamepost.web.create` handle. `blamepost.web.serve` performs both
// as part of binding and draining, so the operator composing `create`
// by hand is the caller that has to reach them, and a handle missing
// either one is an application that advertises a push channel it
// cannot mount. Both refuse a bad argument where they are called
// rather than at the first upgrade that arrives.
async function testTheMountAndDrainVerbsAreOnTheHandle(handle) {
  check("blamepost.web.create.mountJmapWebSocket is on the handle",
    typeof handle.mountJmapWebSocket === "function");
  check("blamepost.web.create.drainJmapWebSockets is on the handle",
    typeof handle.drainJmapWebSockets === "function");
  check("mountJmapWebSocket refuses something that is not a bound server",
    threw(function () { handle.mountJmapWebSocket({}); }));
  check("drainJmapWebSockets refuses a deadline it cannot spend",
    threw(function () { handle.drainJmapWebSockets(0); }));
  var none = await handle.drainJmapWebSockets(1000);
  count("a drain with nothing open reports nothing closed", none === 0, String(none));
}

// An upgrade detaches its socket from the HTTP server, so the drain
// that closes the routed connections does not reach it. A socket left
// open past the drain holds a live handle: the process that was asked
// to stop keeps running, and an orchestrator that waited for it kills
// it instead.
async function testTheDrainClosesTheSocketsItUpgraded(listener, port, cookie, advertised, origin) {
  var conn = await wsConnect(port, { path: advertised, cookie: cookie, origin: origin });
  count("a socket is open when the drain begins", conn.upgraded === true,
    "status " + conn.status);

  await listener.stop({ timeoutMs: 2000 });
  await helpers.waitUntil(function () { return conn.frames.close !== null; }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the drain closes the sockets the upgrade detached",
  });
  // The code is the whole difference between a shutdown and a fault. A
  // socket cut without one reads to a client as a broken connection; a
  // going-away close is the server saying to come back.
  count("the drain closes a socket the upgrade detached from the server",
    conn.frames.close.code === b.websocket.CLOSE_GOING_AWAY,
    JSON.stringify(conn.frames.close));
  await helpers.waitUntil(function () { return conn.closed === true; }, {
    timeoutMs: 5000,
    label:     "jmap-websocket-push: the socket itself ends after the close frame",
  });
  count("the socket ends rather than lingering past the drain", conn.closed === true,
    String(conn.closed));
  conn.stop();
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("jmapws");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var listener   = null;
  var socket     = null;
  var otherSocket = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: "example.com" });
    var alice = await identity.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@example.com", password: BOB_PASSWORD });

    await testTheMountAndDrainVerbsAreOnTheHandle(
      blamepost.web.create(wiringFor(cfg, identity)));

    var material = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });
    listener = blamepost.web.serve(wiringFor(cfg, identity, {
      certFile: material.certFile, keyFile: material.keyFile }));
    var ports  = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;
    // The Origin a signed-in browser sends on the upgrade. Every upgrade
    // in this file carries the public TLS origin, whichever socket it
    // dials, because the server accepts no other.
    var pageOrigin = "https://" + HOSTNAME + ":" + CONFIGURED_HTTPS_PORT;

    var reader = browser.browserAt(origin);
    var landed = await reader.signIn("alice@example.com", ALICE_PASSWORD);
    check("the reader holds a session before any push is asked for", landed.status === 302);

    var session = await reader.get("/jmap/session", { Accept: "application/json" });
    var doc = testSessionAdvertisesTheTransport(session);
    var advertised = String(doc.webSocketUrl).split("?")[0];
    var cookie = reader.cookies.header();

    await testAnOrdinaryRequestSaysToUpgrade(reader, advertised);
    await testAnUnauthenticatedUpgradeIsRefused(ports.http, advertised, pageOrigin);
    await testAForeignOriginIsRefused(ports.http, cookie, advertised);
    await testASocketWithoutTheSubprotocolIsClosed(ports.http, cookie, advertised, pageOrigin);
    await testRefusalsAreRecorded();

    socket = await testTheAdvertisedUrlIsTheOneThatUpgrades(ports.http, cookie, doc, pageOrigin);
    if (socket !== null) {
      await testRequestFramesDispatchOverTheSocket(socket, alice.id, bob.id);

      // The second account's own channel, so the isolation assertion
      // below runs in the configuration where a leak could actually
      // happen rather than in the one where the other account is not
      // watched at all.
      var otherReader = browser.browserAt(origin);
      var otherLanded = await otherReader.signIn("bob@example.com", BOB_PASSWORD);
      check("the second account holds a session of its own", otherLanded.status === 302);
      otherSocket = await wsConnect(ports.http, {
        path: advertised, cookie: otherReader.cookies.header(), origin: pageOrigin });
      count("the second account completes an upgrade of its own",
        otherSocket.upgraded === true, "status " + otherSocket.status);

      await testPushIsScopedToTheAccountThatSubscribed(
        socket, otherSocket, identity, alice, bob);
      await testPushDisableStopsTheChannel(socket, identity, alice);
      await testTheClientCanNarrowWhatItHearsAbout(
        ports.http, cookie, advertised, pageOrigin, identity, alice);
      otherSocket.stop();
      otherSocket = null;
      socket.stop();
      socket = null;
    }

    await testEventSourceServesTheSameChannel(ports.http, cookie, identity, alice);
    var tlsReader = await testTheUpgradeAlsoCompletesOverTls(
      ports.https, material.caPem, HOSTNAME, alice, ALICE_PASSWORD);
    await testOnlyThePublicTlsOriginsMayUpgrade(
      ports.https, material.caPem, HOSTNAME, tlsReader);

    await testTheDrainClosesTheSocketsItUpgraded(
      listener, ports.http, cookie, advertised, pageOrigin);
    listener = null;
  } finally {
    if (socket !== null) socket.stop();
    if (otherSocket !== null) otherSocket.stop();
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

module.exports = { name: "jmap-websocket-push", run: run, getChecks: helpers.getChecks };

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
