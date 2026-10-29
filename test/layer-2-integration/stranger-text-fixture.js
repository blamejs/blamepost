// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A receiving peer whose refusal is written in codepoints a terminal
 * acts on, and this server's outbound path driven at it.
 *
 * What a peer says when it refuses a recipient is the peer's own text.
 * It reaches this server as an SMTP reply line, becomes the `reason` on
 * an outcome row, and is then printed in a console table by
 * `blamepost queue flush` and rendered on the administration queue page.
 * A reply carrying the escape introducer at U+009B repaints the row
 * above the one it is on, a bidirectional override reverses the sentence
 * an operator is deciding on, and a carriage return turns one row into
 * two.
 *
 * The peer has to be real and the reply has to reach this server over a
 * socket. Every layer between the reply line and the outcome row copies
 * the text, and a fixture that hands the string to an internal function
 * measures the copy rather than the wire.
 *
 * It runs in a child process rather than in the caller's, for the reason
 * the other outbound fixtures here do: the transport verifies the peer's
 * certificate against the trust store the process started with, and
 * `NODE_EXTRA_CA_CERTS` is read once at startup, so the authority the
 * caller mints has to be in the environment before node begins. Turning
 * verification off instead would measure a delivery this server never
 * makes.
 *
 * Two runs:
 *
 *   refused   the peer answers RCPT TO with a permanent 5xx whose reply
 *             text carries the four codepoints, so the recipient lands
 *             on the failed list
 *   deferred  the same text on a transient 4xx, so the recipient lands
 *             on the deferred list and on the volume. The two lists are
 *             built on separate paths and a screen on one says nothing
 *             about the other
 *
 * It prints one JSON object on the last line of stdout. The caller reads
 * that; everything else on the stream is detail for a failure.
 *
 * Run standalone: node test/layer-2-integration/stranger-text-fixture.js <mode> <certDir> <dataDir>
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var delivery = require("../../lib/mail/delivery");

var HOSTNAME = "mx.example.com";
var LOOPBACK = "127.0.0.1";

// The MX host, and the name on the peer's certificate. RFC 6761 section
// 6.3 reserves this name for the loopback address on every host, which
// makes it both resolvable by the transport's own lookup and nobody's
// real domain.
var PEER_NAME = "localhost";

// The four codepoints, each chosen for a different thing it does to the
// reader rather than for being unusual.
//
// U+001B opens an escape sequence in two bytes and U+009B opens the same
// sequence in one, so a reply carrying either colors, clears or moves
// whatever prints it as a stream. U+202E reverses the run that follows
// it, so `gpj.exe` is read as `exe.jpg`. A carriage return returns the
// cursor to the start of the line, so the second half of a reply
// overwrites the first and the operator reads a sentence the peer never
// sent.
//
// Built from character codes rather than written out, because a raw C1
// byte does not survive being written into a source file.
var ESC = String.fromCharCode(0x1b);
var CSI = String.fromCharCode(0x9b);
var RLO = String.fromCharCode(0x202e);
var CR  = String.fromCharCode(0x0d);

// The reply text itself. The readable words are here so the caller can
// tell a screen that removed the dangerous codepoints from one that
// threw the whole diagnostic away: an operator who is told nothing is
// no better off than one who is told a lie.
var PEER_WORDS = "mailboxunavailable";
var PEER_REPLY = PEER_WORDS + ESC + "[2K" + CSI + "1A" + RLO + "gpj.exe" + CR + "HELD";

var MESSAGE = [
  "From: postmaster@example.com",
  "To: nobody@example.org",
  "Subject: what a peer says when it refuses",
  "Date: Mon, 31 Aug 2026 09:00:00 +0000",
  "Message-ID: <stranger-text@example.com>",
  "",
  "STRANGER-TEXT-BODY",
  "",
].join("\r\n");

// A receiving SMTP peer. It offers STARTTLS on the plaintext leg,
// because the outbound transport will not hand a message to a peer that
// does not, and answers RCPT TO with the reply above under whichever
// class the mode asks for.
//
// The reply is written as UTF-8 octets rather than as a string, so the
// bidirectional override reaches the socket as the three bytes that
// encode it rather than as whatever the default encoding would make of
// it.
function startPeer(material, replyClass) {
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
            cert:     material.chain,
          });
          upgraded.on("secure", function () { serve(upgraded, true); });
          upgraded.on("error", function () { /* drop-silent: the peer went away */ });
          return;
        } else if (upper.indexOf("MAIL FROM") === 0) {
          socket.write("250 OK\r\n");
        } else if (upper.indexOf("RCPT TO") === 0) {
          socket.write(Buffer.from(replyClass + " " + PEER_REPLY + "\r\n", "utf8"));
        } else if (upper.indexOf("DATA") === 0) {
          inData = true;
          socket.write("354 End data with <CRLF>.<CRLF>\r\n");
        } else if (upper.indexOf("QUIT") === 0) {
          socket.write("221 Bye\r\n");
          try { socket.end(); } catch (_e) { /* drop-silent: already gone */ }
        } else if (upper.indexOf("RSET") === 0 || upper.indexOf("NOOP") === 0) {
          socket.write("250 OK\r\n");
        } else {
          socket.write("502 5.5.2 Command not recognized\r\n");
        }
      }
    }

    socket.on("data", onData);
    socket.on("error", function () { /* drop-silent: the peer went away */ });
  }

  return new Promise(function (resolve) {
    server.listen(0, LOOPBACK, function () {
      resolve({ port: server.address().port, close: function () { server.close(); } });
    });
  });
}

// Every recipient domain resolves to the one peer above, with MTA-STS
// and DANE off: what is being measured is the reply text, and a policy
// fetch would decide the outcome before the transport is reached.
function pinnedResolver() {
  return {
    resolveMx: function () { return Promise.resolve([{ exchange: PEER_NAME, priority: 10 }]); },
    queryMx:   function () { return Promise.resolve([{ exchange: PEER_NAME, priority: 10 }]); },
    queryTxt:  function () { return Promise.resolve([]); },
    queryTlsa: function () { return Promise.resolve([]); },
    queryPtr:  function () { return Promise.resolve([]); },
    resolve4:  function () { return Promise.resolve([LOOPBACK]); },
    lookup:    function () { return Promise.resolve({ address: LOOPBACK, family: 4 }); },
  };
}

// Which codepoints a value still carries, as an object the caller can
// read a field at a time. Named rather than counted, so a failure says
// which one survived instead of how many did.
function carries(value) {
  var text = String(value === undefined || value === null ? "" : value);
  return {
    esc:   text.indexOf(ESC) !== -1,
    csi:   text.indexOf(CSI) !== -1,
    rlo:   text.indexOf(RLO) !== -1,
    cr:    text.indexOf(CR) !== -1,
    words: text.indexOf(PEER_WORDS) !== -1,
    text:  text,
  };
}

async function main() {
  var mode    = process.argv[2];
  var certDir = process.argv[3];
  var dataDir = process.argv[4];
  if (["refused", "deferred"].indexOf(mode) === -1) {
    throw new Error("stranger-text-fixture: mode must be refused or deferred");
  }

  var material = {
    key:   nodeFs.readFileSync(nodePath.join(certDir, "peer.key"), "utf8"),
    chain: nodeFs.readFileSync(nodePath.join(certDir, "peer.chain.pem"), "utf8"),
  };

  var peer = await startPeer(material, mode === "refused" ? "550 5.1.1" : "451 4.7.0");
  var handle = delivery.create({
    hostname: HOSTNAME,
    dataDir:  dataDir,
    resolver: pinnedResolver(),
    port:     peer.port,
    policy:   { mtaSts: "off", dane: "off" },
    // One attempt, so a transient refusal stays transient rather than
    // being converted to a permanent one before the outcome is read.
    retry:    { maxAttempts: 4, backoffMs: [60000] },
    audit:    false,
  });

  var outcome = null;
  var threw = null;
  try {
    outcome = await handle.send({
      from:   "postmaster@example.com",
      to:     ["nobody@example.org"],
      rfc822: MESSAGE,
    });
  } catch (e) { threw = String((e && e.message) || e); }

  peer.close();

  var rows = outcome === null
    ? []
    : (outcome.failed || []).concat(outcome.deferred || []).concat(outcome.delivered || []);

  console.log("VERDICT " + JSON.stringify({
    mode:  mode,
    threw: threw,
    rows:  rows.map(function (row) {
      return {
        recipient:  carries(row.recipient),
        reason:     carries(row.reason),
        reasonCode: carries(row.reasonCode),
        mxHost:     carries(row.mxHost),
      };
    }),
  }));
}

main().catch(function (e) {
  console.error("stranger-text-fixture: " + ((e && e.stack) || e));
  process.exitCode = 1;
});
