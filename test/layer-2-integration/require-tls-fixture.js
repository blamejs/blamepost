// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A receiving peer, and this server's outbound path driven at it.
 *
 * REQUIRETLS is a keyword on the `MAIL FROM` line and a keyword in a
 * peer's EHLO response, so the only place the posture can be measured is
 * the wire between two hosts. Nothing below the socket answers it: the
 * flag is threaded through four layers before the transport decides what
 * to write, and every one of those layers has accepted the value and
 * dropped it at some point in this code's history.
 *
 * This runs in a child process rather than in the test's own, because
 * the outbound transport verifies the peer's certificate against the
 * trust store the process started with. `NODE_EXTRA_CA_CERTS` is read
 * once at startup, so a private authority the test mints has to be in
 * the environment before node begins. Turning verification off instead
 * would measure a delivery this server would never make.
 *
 * Three runs, and the second and third are what stop the first passing
 * by accident:
 *
 *   asked    the peer advertises REQUIRETLS and the keyword has to be on
 *            MAIL FROM
 *   off      the same peer, the posture off, and the keyword has to be
 *            absent. A transport that appended it unconditionally would
 *            satisfy the first run and turn every message this server
 *            sends into one no peer without the extension may receive
 *   refused  a peer that does NOT advertise it, where RFC 8689 section
 *            4.1 makes the message undeliverable rather than deliverable
 *            without the parameter
 *   retried  the peer advertises it and defers the first envelope, so
 *            the recipient reaches the on-disk queue and the sweep sends
 *            it again. The keyword has to be on the second MAIL FROM
 *            line as well, because between the two the posture is
 *            written to a descriptor and read back off it, and a
 *            descriptor that loses the flag delivers in the clear on
 *            every retry while the first attempt looked right
 *   not-a-boolean
 *            the posture is on and the envelope carries a value for it
 *            that is not true or false. An envelope's own posture wins
 *            over the handle's, so this is the reading that decides what
 *            goes on the wire, and the value has to be refused rather
 *            than read as off
 *
 * It prints one JSON object on the last line of stdout. The caller reads
 * that; everything else on the stream is detail for a failure.
 *
 * Run standalone: node test/layer-2-integration/require-tls-fixture.js <mode> <certDir>
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var delivery = require("../../lib/mail/delivery");

var HOSTNAME = "mx.example.com";
var LOOPBACK = "127.0.0.1";

// The MX host, and the name on the peer's certificate.
//
// It has to be a NAME rather than the loopback address, and the reason
// is in the transport. The MX host reaches node's own resolver, so a
// name invented for this fixture does not resolve; and for an address
// literal the transport omits SNI, after which node checks the peer's
// certificate identity against its own default of `localhost` rather
// than against the address, so an address-literal peer cannot verify
// whatever its certificate carries. RFC 6761 section 6.3 reserves this
// name for the loopback address on every host, which makes it the one
// name that is both resolvable everywhere and nobody's real domain.
var PEER_NAME = "localhost";

var MESSAGE = [
  "From: postmaster@example.com",
  "To: nobody@example.org",
  "Subject: transport posture",
  "Date: Mon, 31 Aug 2026 09:00:00 +0000",
  "Message-ID: <require-tls-wire@example.com>",
  "",
  "REQUIRETLS-WIRE-BODY",
  "",
].join("\r\n");

// A receiving SMTP peer. It offers STARTTLS on the plaintext leg and,
// when asked to, REQUIRETLS on the encrypted one, and it records every
// MAIL FROM line it was given.
//
// `deferFirstEnvelope` makes it answer the first envelope with a 4xx and
// take every one after it. RFC 5321 section 4.2.1 makes that a request
// to try again, so the recipient reaches this server's on-disk queue and
// the sweep offers the same message a second time. Recording each line
// rather than the last is what lets the caller compare the two.
function startPeer(material, advertiseRequireTls, deferFirstEnvelope) {
  var seen = { commands: [], mailFrom: null, mailFroms: [] };
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
          if (command === ".") { inData = false; socket.write("250 2.0.0 Queued\r\n"); }
          continue;
        }
        seen.commands.push((secure ? "TLS " : "") + command);
        var upper = command.toUpperCase();
        if (upper.indexOf("EHLO") === 0 || upper.indexOf("HELO") === 0) {
          var lines = ["250-" + PEER_NAME, "250-8BITMIME", "250-SIZE 52428800"];
          if (!secure) lines.push("250-STARTTLS");
          if (secure && advertiseRequireTls) lines.push("250-REQUIRETLS");
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
          upgraded.on("error", function () { /* drop-silent: the peer went away */ });
          return;
        } else if (upper.indexOf("MAIL FROM") === 0) {
          seen.mailFrom = command;
          seen.mailFroms.push(command);
          if (deferFirstEnvelope && seen.mailFroms.length === 1) {
            socket.write("451 4.7.0 Try again later\r\n");
          } else {
            socket.write("250 OK\r\n");
          }
        } else if (upper.indexOf("RCPT TO") === 0) {
          socket.write("250 OK\r\n");
        } else if (upper.indexOf("DATA") === 0) {
          inData = true;
          socket.write("354 End data with <CRLF>.<CRLF>\r\n");
        } else if (upper.indexOf("QUIT") === 0) {
          socket.write("221 Bye\r\n");
          try { socket.end(); } catch (_e) { /* drop-silent: already gone */ }
        } else if (upper.indexOf("RSET") === 0 || upper.indexOf("NOOP") === 0) {
          socket.write("250 OK\r\n");
        } else {
          // allow:todo-fixme-hack-xxx the RFC 5321 §4.2.3 reply text for 502, not a work marker
          socket.write("502 5.5.2 Command not implemented\r\n");
        }
      }
    }

    socket.on("data", onData);
    socket.on("error", function () { /* drop-silent: the peer went away */ });
  }

  return new Promise(function (resolve) {
    server.listen(0, LOOPBACK, function () {
      resolve({ port: server.address().port, seen: seen, close: function () { server.close(); } });
    });
  });
}

// Every recipient domain resolves to the one peer above. MTA-STS and
// DANE are off for this run: what is being measured is the REQUIRETLS
// keyword, and a policy fetch would decide the outcome before the
// transport is reached.
//
// The MX host is the loopback address rather than a name. The transport
// connects to whatever the MX record gives it through the operating
// system's own resolver, so a name only this fixture knows about does
// not resolve; and for an address literal the transport omits SNI, so
// the peer's certificate is verified against the loopback SAN the test
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

// What the on-disk queue recorded for the one entry waiting in it. The
// posture on a descriptor is what the retry reads, so a run measuring the
// second MAIL FROM line reads this beside it: the two together say
// whether the flag survived the write or was restored from somewhere
// else.
function spooledRequireTls(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  var names = nodeFs.readdirSync(dir).filter(function (n) { return n.slice(-5) === ".json"; });
  if (names.length !== 1) return null;
  var descriptor = JSON.parse(nodeFs.readFileSync(nodePath.join(dir, names[0]), "utf8"));
  return descriptor.requireTls === true;
}

async function main() {
  var mode    = process.argv[2];
  var certDir = process.argv[3];
  var dataDir = process.argv[4];
  if (["asked", "off", "refused", "retried", "not-a-boolean"].indexOf(mode) === -1) {
    throw new Error("require-tls-fixture: mode must be asked, off, refused, retried or " +
      "not-a-boolean");
  }

  var material = {
    key:   nodeFs.readFileSync(nodePath.join(certDir, "peer.key"), "utf8"),
    chain: nodeFs.readFileSync(nodePath.join(certDir, "peer.chain.pem"), "utf8"),
  };

  var retried = mode === "retried";
  var peer = await startPeer(material, mode !== "refused", retried);
  var handle = delivery.create({
    hostname:   HOSTNAME,
    dataDir:    dataDir,
    resolver:   pinnedResolver(),
    port:       peer.port,
    policy:     { mtaSts: "off", dane: "off" },
    // A budget of one attempt is enough for the runs that never queue
    // anything. The retry run needs a second, or the deferral it provokes
    // becomes a permanent failure before the sweep can offer the message
    // again.
    retry:      { maxAttempts: retried ? 4 : 1, backoffMs: [1000] },
    requireTls: mode !== "off",
    audit:      false,
  });

  // What the envelope says about the posture, which wins over the
  // handle's. `undefined` is an envelope that says nothing, which is
  // every other run here and every caller in the server. The one run
  // that states it states it as a string, which is the shape the handle
  // itself refuses, so the two readings of one setting are measured
  // against each other on the wire.
  var envelopeRequireTls = mode === "not-a-boolean" ? "yes" : undefined;

  var outcome = null;
  var threw = null;
  try {
    outcome = await handle.send({
      from:       "postmaster@example.com",
      to:         ["nobody@example.org"],
      rfc822:     MESSAGE,
      requireTls: envelopeRequireTls,
    });
  } catch (e) { threw = String((e && e.message) || e); }

  // The descriptor is read before the sweep, because the sweep takes the
  // entry off the volume when the peer accepts the message.
  var spooled = retried ? spooledRequireTls(dataDir) : null;
  var swept = null;
  if (retried) {
    var run = await handle.queue.runDue({ force: true });
    swept = (run.results || []).map(function (row) { return row.outcome; });
  }

  handle.stop();
  peer.close();

  var verdict = {
    mode:            mode,
    mailFrom:        peer.seen.mailFrom,
    mailFroms:       peer.seen.mailFroms,
    commands:        peer.seen.commands,
    keywordOnTheWire: !!(peer.seen.mailFrom && /\bREQUIRETLS\b/.test(peer.seen.mailFrom)),
    keywordOnEachLine: peer.seen.mailFroms.map(function (line) {
      return /\bREQUIRETLS\b/.test(line);
    }),
    spooledRequireTls: spooled,
    swept:           swept,
    delivered:       outcome ? (outcome.delivered || []).length : 0,
    deferred:        outcome ? (outcome.deferred  || []).map(function (r) { return r.reason; }) : [],
    failed:          outcome ? (outcome.failed    || []).map(function (r) { return r.reason; }) : [],
    threw:           threw,
  };
  console.log("VERDICT " + JSON.stringify(verdict));
}

main().then(function () { process.exit(0); }, function (e) {
  console.error((e && e.stack) || e);
  process.exit(1);
});
