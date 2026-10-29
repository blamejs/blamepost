// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A receiving peer, and this server's composed outbound path driven at
 * it with four messages.
 *
 * It runs as its own process because the transport verifies the peer's
 * certificate, and the only way to make a test authority verifiable to
 * it is `NODE_EXTRA_CA_CERTS`, which node reads at startup. Its caller
 * is `wire-scan-linearity.test.js`, which spawns it with that variable
 * set and reads the `VERDICT` line off its output.
 *
 * The four messages are an ordinary one, one carrying the bare line
 * ending plus SMTP verb the outbound screen exists to refuse, and two
 * whose bodies are runs of carriage returns, the second four times the
 * first. The verdict carries what happened to each and how long each
 * call took, so the caller can assert on both the answers and the cost.
 *
 * Not a test file itself: `smoke.js` discovers `*.test.js`, and this is
 * a fixture the test spawns.
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var delivery = require("../../lib/mail/delivery");

var LOOPBACK  = "127.0.0.1";
var HOSTNAME  = "mx.example.com";
var DOMAIN    = "example.com";
// The name on the peer's certificate. `localhost` is resolvable
// everywhere and is nobody's real domain.
var PEER_NAME = "localhost";

var CR_BODY_SMALL_BYTES = 16 * 1024;
var CR_BODY_LARGE_BYTES = 64 * 1024;

function repeat(ch, n) { return new Array(n + 1).join(ch); }

function elapsedMs(startedAt) {
  return Number(process.hrtime.bigint() - startedAt) / 1e6;
}

// A receiving SMTP peer. It offers STARTTLS on the plaintext leg and
// accepts everything after the upgrade.
function startPeer(material) {
  var seen = { commands: [], accepted: 0 };
  var server = nodeNet.createServer(function (socket) { serve(socket, false); });

  function serve(socket, secure) {
    var buffered = "";
    var inData = false;
    if (!secure) socket.write("220 " + PEER_NAME + " ESMTP\r\n");

    function onData(chunk) {
      buffered += chunk.toString("latin1");
      var end;
      while ((end = buffered.indexOf("\r\n")) !== -1) {
        var command = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        if (inData) {
          if (command === ".") {
            inData = false;
            seen.accepted += 1;
            socket.write("250 2.0.0 Queued\r\n");
          }
          continue;
        }
        seen.commands.push((secure ? "TLS " : "") + command);
        var upper = command.toUpperCase();
        if (upper.indexOf("EHLO") === 0 || upper.indexOf("HELO") === 0) {
          var lines = ["250-" + PEER_NAME, "250-8BITMIME", "250-SIZE 52428800"];
          if (!secure) lines.push("250-STARTTLS");
          lines.push("250 PIPELINING");
          socket.write(lines.join("\r\n") + "\r\n");
        } else if (upper.indexOf("STARTTLS") === 0) {
          // The plaintext reader has to let go before the TLS wrapper
          // takes the socket, or it consumes the ClientHello.
          socket.removeListener("data", onData);
          socket.write("220 Ready to start TLS\r\n");
          var upgraded = new nodeTls.TLSSocket(socket, {
            isServer: true,
            key:      material.key,
            // Leaf then authority, which is the chain a verifying client
            // needs to build a path.
            cert:     material.chain,
          });
          upgraded.on("secure", function () { serve(upgraded, true); });
          upgraded.on("error", function () { /* drop-silent by design: the peer went away */ });
          return;
        } else if (upper.indexOf("MAIL FROM") === 0 || upper.indexOf("RCPT TO") === 0) {
          socket.write("250 OK\r\n");
        } else if (upper.indexOf("DATA") === 0) {
          inData = true;
          socket.write("354 End data with <CRLF>.<CRLF>\r\n");
        } else if (upper.indexOf("QUIT") === 0) {
          socket.write("221 Bye\r\n");
          try { socket.end(); } catch (_e) { /* drop-silent by design: already gone */ }
        } else if (upper.indexOf("RSET") === 0 || upper.indexOf("NOOP") === 0) {
          socket.write("250 OK\r\n");
        } else {
          // allow:todo-fixme-hack-xxx the RFC 5321 §4.2.3 reply text for 502, not a work marker
          socket.write("502 5.5.2 Command not implemented\r\n");
        }
      }
    }

    socket.on("data", onData);
    socket.on("error", function () { /* drop-silent by design: the peer went away */ });
  }

  return new Promise(function (resolve) {
    server.listen(0, LOOPBACK, function () {
      resolve({ port: server.address().port, seen: seen,
                close: function () { server.close(); } });
    });
  });
}

// Every recipient domain resolves to the one peer above, and no policy
// record is published, so the transport reaches the socket rather than
// deciding the outcome from DNS. The MX host is the loopback address
// rather than a name, because a name only this fixture knows about does
// not resolve; for an address literal the transport omits SNI, so the
// peer's certificate is verified against the loopback SAN the test
// authority minted into it.
function pinnedResolver() {
  return {
    resolveMx: function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryMx:   function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryTxt:  function () { return Promise.resolve([]); },
    queryTlsa: function () { return Promise.resolve([]); },
    queryPtr:  function () { return Promise.resolve([]); },
    resolve4:  function () { return Promise.resolve([LOOPBACK]); },
    lookup:    function () { return Promise.resolve({ address: LOOPBACK, family: 4 }); },
  };
}

function messageWithBody(body) {
  return [
    "From: postmaster@" + DOMAIN,
    "To: nobody@example.net",
    "Subject: scan linearity",
    "Date: Tue, 01 Sep 2026 09:00:00 +0000",
    "Message-ID: <scan-linearity@" + DOMAIN + ">",
    "",
    "",
  ].join("\r\n") + body;
}

async function sendAndTime(handle, rfc822) {
  var startedAt = process.hrtime.bigint();
  var outcome = null;
  var threw = null;
  try {
    outcome = await handle.send({
      from:   "postmaster@" + DOMAIN,
      to:     ["nobody@example.net"],
      rfc822: rfc822,
    });
  } catch (e) { threw = String((e && e.message) || e); }
  return {
    ms:        elapsedMs(startedAt),
    threw:     threw,
    reasons:   outcome
      ? (outcome.failed || []).concat(outcome.deferred || [])
          .map(function (r) { return String(r.reason); }).join(",")
      : "",
    delivered: outcome ? (outcome.delivered || []).length : 0,
    bytes:     rfc822.length,
  };
}

async function main() {
  var certDir = process.argv[2];
  var dataDir = process.argv[3];
  if (!certDir || !dataDir) {
    throw new Error("wire-scan-outbound-fixture: certDir and dataDir are required");
  }

  var material = {
    key:   nodeFs.readFileSync(nodePath.join(certDir, "peer.key"), "utf8"),
    chain: nodeFs.readFileSync(nodePath.join(certDir, "peer.chain.pem"), "utf8"),
  };

  var peer = await startPeer(material);
  var handle = delivery.create({
    hostname: HOSTNAME,
    dataDir:  dataDir,
    resolver: pinnedResolver(),
    port:     peer.port,
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 1, backoffMs: [1000] },
  });

  // Sent first so the reading below is not paying for whatever a first
  // connection, a first spool write and a first handshake cost.
  var warm  = await sendAndTime(handle, messageWithBody("Warming the path.\r\n"));
  var plain = await sendAndTime(handle, messageWithBody(
    "An ordinary body with nothing to smuggle.\r\n"));
  var smuggle = await sendAndTime(handle, messageWithBody(
    "body\rMAIL FROM:<attacker@example.net>\r\n"));
  var small = await sendAndTime(handle, messageWithBody(repeat("\r", CR_BODY_SMALL_BYTES)));
  var large = await sendAndTime(handle, messageWithBody(repeat("\r", CR_BODY_LARGE_BYTES)));

  handle.stop();
  peer.close();

  console.log("VERDICT " + JSON.stringify({
    smallBytes: CR_BODY_SMALL_BYTES,
    largeBytes: CR_BODY_LARGE_BYTES,
    warm:       warm,
    plain:      plain,
    smuggle:    smuggle,
    small:      small,
    large:      large,
    accepted:   peer.seen.accepted,
  }));
}

main().then(function () { process.exit(0); }, function (e) {
  console.error((e && e.stack) || e);
  process.exit(1);
});
