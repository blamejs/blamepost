// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A receiving peer that publishes TLSA records, and this server's
 * outbound path driven at it.
 *
 * DANE (RFC 7672) authenticates the peer against records the peer's own
 * zone publishes. The only place that authentication can be observed is
 * the socket: the records are looked up per mail exchanger, handed to the
 * transport, and matched against the certificate chain the peer presents
 * during the handshake. Nothing below that answers whether the records
 * were fetched, whether they were used, or what happened when they did
 * not match.
 *
 * This runs in a child process rather than in the test's own, because
 * three of the runs below need the peer's certificate to verify against
 * the trust store the process started with. `NODE_EXTRA_CA_CERTS` is read
 * once at startup, so the private authority the caller mints has to be in
 * the environment before node begins. The authority is in the environment
 * for every run, not only for the three that need it, so a difference
 * between runs is the DANE posture rather than whether the certificate
 * was trusted.
 *
 * Seven runs. The first two are the claim and the rest are what stop them
 * passing for the wrong reason:
 *
 *   matched      the zone publishes a record that does not match and then
 *                one that does, and the message is delivered. The decoy
 *                is what separates "a record matched" from "records were
 *                present"
 *   mismatched   the same peer publishing only the decoy. The message is
 *                not delivered and the peer is never offered it, because
 *                a peer that fails DANE must not be delivered to in the
 *                clear
 *   opportunistic-mismatched
 *                the same records under the opportunistic posture rather
 *                than the enforcing one. RFC 7672 section 2.2 makes
 *                opportunistic a statement about which peers are asked,
 *                not about what happens to one whose records are in hand
 *                and do not match
 *   default      the same peer and the same non-matching records under
 *                the posture this server ships. The message IS delivered
 *                and the pinned resolver is never asked a TLSA question
 *                at all
 *   off          the posture turned off outright, which has to look the
 *                same as the shipped default
 *   unanswerable the records cannot be looked up, under the enforcing
 *                posture. The mail exchanger is taken out and the
 *                recipient waits
 *   unanswerable-opportunistic
 *                the same lookup failure under the opportunistic posture,
 *                where it is not a refusal and the message is delivered
 *
 * The accumulated TLS-RPT observations are read off the volume at the end
 * of every run, because a failure a receiver is never told about is one
 * they cannot fix.
 *
 * It prints one JSON object on the last line of stdout. The caller reads
 * that; everything else on the stream is detail for a failure.
 *
 * Run standalone:
 *   node test/layer-2-integration/dane-tlsa-fixture.js <mode> <certDir> <dataDir>
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodeNet    = require("node:net");
var nodePath   = require("node:path");
var nodeTls    = require("node:tls");

var delivery = require("../../lib/mail/delivery");

var HOSTNAME = "mx.example.com";
var LOOPBACK = "127.0.0.1";

// The MX host, and the name on the peer's certificate. The reasoning is
// the one `require-tls-fixture.js` records: the transport resolves the
// mail exchanger through the operating system, so a name invented here
// does not resolve, and for an address literal it omits SNI and node
// checks the certificate against the loopback address instead. RFC 6761
// section 6.3 reserves this name for the loopback address everywhere.
var PEER_NAME = "localhost";

var MODES = [
  "matched",
  "mismatched",
  "opportunistic-mismatched",
  "default",
  "off",
  "unanswerable",
  "unanswerable-opportunistic",
];

// RFC 7672 section 3.1.1 recommends this association for SMTP: the peer
// itself is the trust anchor, the record covers the public key rather
// than the whole certificate, and the key is carried as a SHA-256 digest.
// Written as three numbers rather than one label because they are what
// goes in the zone.
var DANE_EE       = 3;
var SELECTOR_SPKI = 1;
var MATCH_SHA256  = 1;

var MESSAGE = [
  "From: postmaster@example.com",
  "To: nobody@example.org",
  "Subject: peer authentication",
  "Date: Mon, 31 Aug 2026 09:00:00 +0000",
  "Message-ID: <dane-tlsa-wire@example.com>",
  "",
  "DANE-TLSA-WIRE-BODY",
  "",
].join("\r\n");

// A receiving SMTP peer. It offers STARTTLS on the plaintext leg and
// presents the certificate the caller minted, and it records whether the
// message body ever arrived.
//
// Whether the body arrived is the measurement that matters here. A run
// that refuses the peer has to refuse it before the message is handed
// over, because a message already on the wire has been delivered over a
// connection this server could not authenticate whatever it decides
// afterwards.
function startPeer(material) {
  var seen = { commands: [], mailFrom: null, body: null };
  var server = nodeNet.createServer(function (socket) { serve(socket, false); });

  function serve(socket, secure) {
    var buffered = "";
    var inData = false;
    var body = "";
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
            seen.body = body;
            socket.write("250 2.0.0 Queued\r\n");
          } else {
            body += command + "\r\n";
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
          upgraded.on("error", function () { /* drop-silent: the peer went away */ });
          return;
        } else if (upper.indexOf("MAIL FROM") === 0) {
          seen.mailFrom = command;
          socket.write("250 OK\r\n");
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

// The association a zone would publish for this certificate, and one it
// would not.
//
// The digest is taken over the SubjectPublicKeyInfo of the leaf, which is
// what selector 1 names. It is computed from the certificate the peer
// actually presents rather than written down, so a run cannot pass
// against a digest that stopped describing the material.
function associations(certPem) {
  var leaf = new nodeCrypto.X509Certificate(certPem);
  var spki = leaf.publicKey.export({ type: "spki", format: "der" });
  return {
    match: nodeCrypto.createHash("sha256").update(spki).digest(),
    // A digest of something that is not this key. It is a real SHA-256
    // rather than a run of zeros, so the record is well formed and the
    // only thing wrong with it is that the peer's key does not hash to it.
    decoy: nodeCrypto.createHash("sha256").update("not this peer's key").digest(),
  };
}

// Every recipient domain resolves to the one peer above, and the TLSA
// question is answered with whatever the run publishes.
//
// MTA-STS is off in every run here: what is being measured is peer
// authentication, and a policy fetch would decide the outcome before the
// transport is reached. The names asked are recorded, because a run where
// the posture makes no lookup at all has to be told apart from one where
// the lookup answered nothing.
function pinnedResolver(records, answerable) {
  var tlsaAsked = [];
  return {
    tlsaAsked: tlsaAsked,
    resolveMx: function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryMx:   function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryTxt:  function () { return Promise.resolve({ rrs: [] }); },
    queryTlsa: function (name) {
      tlsaAsked.push(String(name));
      if (!answerable) {
        var err = new Error("query: upstream lookup failed for " + name + "/52: timed out");
        err.code = "resolver/upstream-failed";
        return Promise.reject(err);
      }
      return Promise.resolve({
        rrs: records.map(function (r) {
          return {
            type:    52,
            decoded: {
              usage:        DANE_EE,
              selector:     SELECTOR_SPKI,
              matchingType: MATCH_SHA256,
              certData:     r,
            },
          };
        }),
      });
    },
    queryPtr:  function () { return Promise.resolve({ rrs: [] }); },
    resolve4:  function () { return Promise.resolve([LOOPBACK]); },
    lookup:    function () { return Promise.resolve({ address: LOOPBACK, family: 4 }); },
  };
}

// What this server accumulated about the receiver's transport security,
// which is what a TLS report would carry. Read through the same surface
// an operator reads it through, rather than off the volume, because the
// accumulation and the reading are separate paths and a report nobody can
// read is the same as one that was never written.
async function tlsRptObservations(handle) {
  var rows = await handle.tlsRpt.observed();
  return rows.map(function (record) {
    return {
      domain:     record.domain,
      policyType: record.policyType,
      successful: record.successful,
      failures:   (record.failures || []).map(function (f) {
        return { resultType: f.resultType, policyType: f.policyType, count: f.count };
      }),
    };
  });
}

// The posture and the records each run publishes, in one table so the
// difference between two runs is readable as one row against another.
function settingsFor(mode, spki) {
  if (mode === "matched") {
    return { policy: { mtaSts: "off", dane: "enforce", dnssecValidated: true },
             records: [spki.decoy, spki.match], answerable: true };
  }
  if (mode === "mismatched") {
    return { policy: { mtaSts: "off", dane: "enforce", dnssecValidated: true },
             records: [spki.decoy], answerable: true };
  }
  if (mode === "opportunistic-mismatched") {
    return { policy: { mtaSts: "off", dane: "opportunistic", dnssecValidated: true },
             records: [spki.decoy], answerable: true };
  }
  if (mode === "default") {
    // The posture as shipped: the composer's own default for DANE, and
    // no statement about the resolver beside it.
    return { policy: { mtaSts: "off" }, records: [spki.decoy], answerable: true };
  }
  if (mode === "off") {
    return { policy: { mtaSts: "off", dane: "off" },
             records: [spki.decoy], answerable: true };
  }
  if (mode === "unanswerable") {
    return { policy: { mtaSts: "off", dane: "enforce", dnssecValidated: true },
             records: [], answerable: false };
  }
  return { policy: { mtaSts: "off", dane: "opportunistic", dnssecValidated: true },
           records: [], answerable: false };
}

async function main() {
  var mode    = process.argv[2];
  var certDir = process.argv[3];
  var dataDir = process.argv[4];
  if (MODES.indexOf(mode) === -1) {
    throw new Error("dane-tlsa-fixture: mode must be one of " + MODES.join(", "));
  }

  var material = {
    key:   nodeFs.readFileSync(nodePath.join(certDir, "peer.key"), "utf8"),
    chain: nodeFs.readFileSync(nodePath.join(certDir, "peer.chain.pem"), "utf8"),
    leaf:  nodeFs.readFileSync(nodePath.join(certDir, "peer.cert.pem"), "utf8"),
  };
  var spki = associations(material.leaf);
  var chosen = settingsFor(mode, spki);

  var peer = await startPeer(material);
  var resolver = pinnedResolver(chosen.records, chosen.answerable);
  var handle = delivery.create({
    hostname: HOSTNAME,
    dataDir:  dataDir,
    resolver: resolver,
    port:     peer.port,
    policy:   chosen.policy,
    // Room for a second attempt, which no run here takes. A budget of one
    // would convert every temporary refusal to a permanent one on the
    // spot, and the report that follows a permanent failure is itself a
    // message this same handle delivers, so the peer would be reached
    // twice and the run would measure the bounce as well as the message.
    retry:    { maxAttempts: 2, backoffMs: [1000] },
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

  var observations = await tlsRptObservations(handle);
  handle.stop();
  peer.close();

  var verdict = {
    mode:           mode,
    policy:         chosen.policy,
    published:      chosen.records.length,
    tlsaAsked:      resolver.tlsaAsked,
    commands:       peer.seen.commands,
    mailFrom:       peer.seen.mailFrom,
    bodyArrived:    peer.seen.body !== null && /DANE-TLSA-WIRE-BODY/.test(String(peer.seen.body)),
    delivered:      outcome ? (outcome.delivered || []).length : 0,
    deferred:       outcome ? (outcome.deferred || []).map(function (r) {
      return { reasonCode: r.reasonCode, reason: r.reason };
    }) : [],
    failed:         outcome ? (outcome.failed || []).map(function (r) {
      return { reasonCode: r.reasonCode, reason: r.reason };
    }) : [],
    tlsRpt:         observations,
    threw:          threw,
  };
  console.log("VERDICT " + JSON.stringify(verdict));
}

main().then(function () { process.exit(0); }, function (e) {
  console.error((e && e.stack) || e);
  process.exit(1);
});
