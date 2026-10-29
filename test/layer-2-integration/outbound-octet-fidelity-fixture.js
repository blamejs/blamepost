// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A receiving peer, and the octets this server's outbound path writes to
 * it.
 *
 * The end of an SMTP `DATA` body is a sequence rather than a count. RFC
 * 5321 section 4.1.1.4 writes it as `<CRLF>.<CRLF>` and then says the
 * first CRLF "is actually the terminator of the previous line", so those
 * two octets belong to the message. A writer holding a message therefore
 * has one question to answer before it can frame the body: does the
 * buffer already end with the CRLF that ends its last line, or does the
 * writer have to supply one. The transport answers it by looking at the
 * last two octets it holds.
 *
 * That is the same shape as a reader that ends the message where the
 * terminator begins, and the reader version of it is a defect: it takes
 * two octets that were the sender's. So the writer version has to be
 * measured rather than reasoned about, and the only place it can be
 * measured is the wire between two hosts.
 *
 * Every fixture below is read by the peer twice, because which of the
 * two readings is right is the whole question.
 *
 *   naive     the body ends where the `<CRLF>.<CRLF>` sequence begins.
 *             This is the reading that costs two octets, and it is here
 *             so the writer cannot be declared correct against a reader
 *             that would forgive it.
 *   counted   the body is everything before the terminating `.\r\n`
 *             line, which keeps the previous line's CRLF where RFC 5321
 *             section 4.1.1.4 puts it.
 *
 * Three modes, and the second and third are what stop the first from
 * answering about a composer rather than about this server.
 *
 *   direct     each fixture handed to the outbound handle, and the
 *              octets the peer received compared against it
 *   roundtrip  a message a peer transmits to the MX listener, forwarded
 *              off this server by an alias, and the octets a second peer
 *              receives compared against what the first peer sent
 *   sent       a message the composer builds, sends and files, with the
 *              octets the peer received compared against the copy in the
 *              Sent folder
 *
 * It runs in a child process rather than in the test's own, because the
 * outbound transport verifies the peer's certificate against the trust
 * store the process started with. `NODE_EXTRA_CA_CERTS` is read once at
 * startup, so a private authority the test mints has to be in the
 * environment before node begins. There is no setting that turns the
 * verification off from this side, and turning it off would measure a
 * delivery this server would never make.
 *
 * The peer offers STARTTLS because the transport requires it. On a
 * cleartext port this server issues `STARTTLS` after its first EHLO
 * whatever the policy says, and a peer that answers anything other than
 * 220 is failed with `starttls-rejected` before an envelope is offered.
 * A plaintext peer therefore measures the refusal rather than the body.
 *
 * It prints one JSON object on the last line of stdout. The caller reads
 * that; everything else on the stream is detail for a failure.
 *
 * Run standalone:
 *   node test/layer-2-integration/outbound-octet-fidelity-fixture.js <mode> <certDir> <dataDir>
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var compose   = require("../../lib/mail/compose");
var delivery  = require("../../lib/mail/delivery");
var listeners = require("../../lib/mail/listeners");

var certs = require("../helpers/certs");
var wire  = require("../helpers/wire");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var imapLiteral = wire.imapLiteral;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// Where a forwarded message and a composed one are addressed. Its mail
// exchanger is the peer this fixture stands up, so nothing leaves the
// loopback interface.
var ELSEWHERE = "example.net";

// The name on the peer's certificate. RFC 6761 section 6.3 reserves it
// for the loopback address on every host, which makes it both
// resolvable and nobody's real domain.
var PEER_NAME = "localhost";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var TERMINATOR = Buffer.from(".\r\n", "ascii");
var SEQUENCE   = Buffer.from("\r\n.\r\n", "ascii");

// ---- the fixtures -----------------------------------------------------------

function headerBlock(subject, messageId, from, to) {
  return [
    "From: " + from,
    "To: " + to,
    "Subject: " + subject,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + messageId + ">",
    "",
  ].join("\r\n") + "\r\n";
}

function outboundFixtures() {
  var from = "postmaster@" + DOMAIN;
  var to   = "nobody@" + ELSEWHERE;
  return {
    // A header block, a body, one CRLF at the end. The ordinary case.
    ordinary: Buffer.from(
      headerBlock("the octets a peer receives", "wire-ordinary@example.com", from, to) +
      "first line of the body\r\n" +
      "second line of the body\r\n", "ascii"),

    // The case the conditional decides differently. A body ending with a
    // blank line already ends with a CRLF, so nothing is added, and the
    // blank line has to survive as content rather than be read as the
    // terminator's own CRLF.
    blankTail: Buffer.from(
      headerBlock("the last line is blank", "wire-blank@example.com", from, to) +
      "one line of body\r\n" +
      "\r\n", "ascii"),

    // Two blank lines, so a reading that loses one is distinguishable
    // from a reading that loses the lot.
    twoBlankTail: Buffer.from(
      headerBlock("the last two lines are blank", "wire-two-blank@example.com", from, to) +
      "one line of body\r\n" +
      "\r\n\r\n", "ascii"),

    // Header fields, the empty line that ends them, and no body. RFC
    // 5322 section 3.5 makes the body optional, and the empty line is
    // the header/body separator every consumer looks for.
    headerOnly: Buffer.from(
      headerBlock("no body at all", "wire-empty@example.com", from, to), "ascii"),

    // A last line with no terminator. This is the one case where the
    // octets on the wire cannot equal the octets held, because RFC 5321
    // section 2.3.8 has every line end with CRLF and an unterminated
    // last line cannot be transmitted as it stands. What is measured is
    // that exactly the missing CRLF is added and nothing else.
    noTrailingCrlf: Buffer.from(
      headerBlock("no terminator on the last line", "wire-open@example.com", from, to) +
      "a last line with no terminator", "ascii"),

    // Lines that open with a dot, which RFC 5321 section 4.5.2 has the
    // sender double and the receiver undo. The count changes on the wire
    // and has to come back to the octets held.
    dotLines: Buffer.from(
      headerBlock("lines that open with a dot", "wire-dots@example.com", from, to) +
      ".\r\n" +
      "..\r\n" +
      ".leading dot\r\n", "ascii"),
  };
}

// What a peer transmits to the MX listener on the round trip. Its last
// line is blank, because that is the fixture the two readings disagree
// about, and the round trip is where a disagreement at either hop shows
// up as a message the second peer receives short.
function roundTripMessage() {
  return Buffer.from(
    headerBlock("through two hops", "wire-roundtrip@example.net",
      "sender@" + ELSEWHERE, "forwards@" + DOMAIN) +
    "one line of body\r\n" +
    "\r\n", "ascii");
}

// ---- the peer ---------------------------------------------------------------

// A receiving SMTP peer that offers STARTTLS and records the raw octets
// of every `DATA` body it is given, terminator included. Nothing is
// interpreted here: the reading is done afterwards, twice, so both
// readings are of the same captured bytes.
function startPeer(material) {
  var seen = { bodies: [], commands: [] };
  var server = nodeNet.createServer(function (socket) { serve(socket, false); });

  function serve(socket, secure) {
    var buffered = Buffer.alloc(0);
    var inData = false;
    var body = Buffer.alloc(0);
    if (!secure) socket.write("220 " + PEER_NAME + " ESMTP\r\n");

    function onData(chunk) {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        if (inData) {
          body = Buffer.concat([body, buffered]);
          buffered = Buffer.alloc(0);
          // The terminating line is `.\r\n`, and it is preceded by the
          // last body line's CRLF unless the body was empty. Both
          // endings are located so a message with no body at all is
          // read rather than waited on.
          var at = body.indexOf(SEQUENCE);
          var opensWithIt = body.length >= TERMINATOR.length &&
            body.subarray(0, TERMINATOR.length).equals(TERMINATOR);
          if (at === -1 && !opensWithIt) return;
          var end = opensWithIt ? TERMINATOR.length : at + SEQUENCE.length;
          seen.bodies.push(body.subarray(0, end));
          buffered = body.subarray(end);
          body = Buffer.alloc(0);
          inData = false;
          socket.write("250 2.0.0 Queued\r\n");
          continue;
        }
        var nl = buffered.indexOf("\r\n", 0, "ascii");
        if (nl === -1) return;
        var command = buffered.subarray(0, nl).toString("latin1");
        buffered = buffered.subarray(nl + 2);
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
        } else if (upper.indexOf("MAIL FROM") === 0 || upper.indexOf("RCPT TO") === 0) {
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
      resolve({
        port:  server.address().port,
        seen:  seen,
        close: function () { server.close(); },
      });
    });
  });
}

// ---- reading what the peer captured ----------------------------------------

// RFC 5321 section 4.5.2: the sender doubles a leading dot and the
// receiver undoes it. Reading the body without this measures the wire
// rather than the message.
function unstuff(bytes) {
  return Buffer.from(bytes.toString("latin1").split("\r\n").map(function (line) {
    return line.charAt(0) === "." ? line.slice(1) : line;
  }).join("\r\n"), "latin1");
}

function bothReadings(raw) {
  var at = raw.indexOf(SEQUENCE);
  return {
    naive:   unstuff(at === -1 ? Buffer.alloc(0) : raw.subarray(0, at)),
    counted: unstuff(raw.subarray(0, raw.length - TERMINATOR.length)),
  };
}

function describe(sent, raw) {
  var read = bothReadings(raw);
  return {
    sentBytes:      sent.length,
    sentTail:       sent.subarray(Math.max(0, sent.length - 12)).toString("hex"),
    wireBytes:      raw.length,
    wireTail:       raw.subarray(Math.max(0, raw.length - 18)).toString("hex"),
    naiveBytes:     read.naive.length,
    naiveTail:      read.naive.subarray(Math.max(0, read.naive.length - 12)).toString("hex"),
    naiveEquals:    read.naive.equals(sent),
    countedBytes:   read.counted.length,
    countedTail:    read.counted.subarray(Math.max(0, read.counted.length - 12)).toString("hex"),
    countedEquals:  read.counted.equals(sent),
  };
}

// ---- the shared arrangement -------------------------------------------------

// Every recipient domain resolves to the one peer above. MTA-STS and
// DANE are off, because a policy fetch would decide the outcome before
// the transport is reached and what is being measured is the body.
function pinnedResolver() {
  return {
    resolveMx: function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryMx:   function () { return Promise.resolve([{ exchange: LOOPBACK, priority: 10 }]); },
    queryTxt:  function () { return Promise.resolve([]); },
    queryTlsa: function () { return Promise.resolve([]); },
    queryPtr:  function () { return Promise.resolve([]); },
    query:     function () { return Promise.resolve([]); },
    resolve4:  function () { return Promise.resolve([LOOPBACK]); },
    lookup:    function () { return Promise.resolve({ address: LOOPBACK, family: 4 }); },
  };
}

function outboundHandle(dataDir, port) {
  return delivery.create({
    hostname: HOSTNAME,
    dataDir:  dataDir,
    resolver: pinnedResolver(),
    port:     port,
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 1, backoffMs: [1000] },
    audit:    false,
  });
}

function loadConfig(dataDir, root) {
  return config.load({
    env: {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    },
    cwd: root,
  });
}

// The certificate the listeners present, in an authority of this mode's
// own. The two modes that bind listeners run one after the other in
// separate processes but under one temporary tree, so an authority named
// for the tree rather than for the mode would be two runs writing one
// directory and the second reading what the first left.
async function serverCertificate(root, mode) {
  var ca = b.mtlsCa.create({
    dataDir:         nodePath.join(root, "ca-" + mode),
    caKeySealedMode: "disabled",
    generation:      1,
    algorithm:       "ECDSA-P384-SHA384",
  });
  await ca.initCA();
  return ca.generateClientCert({
    cn:           HOSTNAME,
    usage:        "server",
    sans:         [HOSTNAME, LOOPBACK],
    validityDays: 1,
  });
}

async function openIdentity(cfg) {
  var identity = await store.open(cfg);
  await identity.domains.add({ domain: DOMAIN });
  await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "outbound octet fidelity" });
  return identity;
}

async function listenerSections(overrides) {
  var sections = {
    mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
    submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
    submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
    imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
    pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
    managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
  };
  var names = Object.keys(overrides || {});
  for (var i = 0; i < names.length; i += 1) sections[names[i]].enabled = overrides[names[i]];
  return sections;
}

// ---- mode: direct -----------------------------------------------------------

async function runDirect(material, dataDir) {
  var peer   = await startPeer(material);
  var handle = outboundHandle(dataDir, peer.port);
  var fixtures = outboundFixtures();
  var names = Object.keys(fixtures);
  var results = {};

  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    var sent = fixtures[name];
    var outcome = null;
    var threw = null;
    try {
      outcome = await handle.send({
        from:   "postmaster@" + DOMAIN,
        to:     ["nobody@" + ELSEWHERE],
        rfc822: sent,
      });
    } catch (e) { threw = String((e && e.message) || e); }

    var raw = peer.seen.bodies[peer.seen.bodies.length - 1];
    results[name] = Object.assign({
      delivered: outcome ? (outcome.delivered || []).length : 0,
      failed:    outcome ? (outcome.failed || []).map(function (r) { return r.reason; }) : [],
      deferred:  outcome ? (outcome.deferred || []).map(function (r) { return r.reason; }) : [],
      threw:     threw,
      captured:  !!raw,
    }, raw ? describe(sent, raw) : {});
  }

  handle.stop();
  peer.close();
  return { mode: "direct", fixtures: results };
}

// ---- mode: roundtrip --------------------------------------------------------

// A peer transmits a message to the MX listener, an alias forwards it
// off this server, and the second peer records what arrived. The two
// hops are separate wires and the message is never recomposed between
// them: `lib/mail/listeners.js` hands the body it received to the same
// outbound handle every other message goes through.
async function runRoundTrip(material, root, dataDir) {
  var peer = await startPeer(material);
  var cfg  = loadConfig(dataDir, root);
  var identity = await openIdentity(cfg);
  await identity.aliases.add({
    address:     "forwards@" + DOMAIN,
    destination: "onward@" + ELSEWHERE,
  });

  var leaf = await serverCertificate(root, "roundtrip");

  var sections = await listenerSections({ mx: true });
  var handle = outboundHandle(dataDir, peer.port);
  var stack = listeners.create({
    config: Object.assign({}, cfg, {
      listeners: sections,
      // The message authentication gate resolves SPF and DMARC at the
      // end of DATA, and the pinned resolver above answers about mail
      // exchangers rather than about policy, so enforce mode would
      // defer and this would measure the absence of DNS.
      inbound:   { mode: "monitor" },
    }),
    store:       identity,
    mailStore:   identity.mailbox,
    certificate: certs.handle({ cert: leaf.cert, key: leaf.key }),
    delivery:    handle,
    resolver:    pinnedResolver(),
  });
  await stack.start();

  var transmitted = roundTripMessage();
  // Assigned inside the exchange below and read after it. A session that
  // throws before the reply never reaches the read, so there is no
  // initial value to carry.
  var accepted;
  var session = await Wire.mx(sections.mx.port, {
    caPem: leaf.ca, servername: HOSTNAME, label: "roundtrip", helo: "peer." + ELSEWHERE });
  try {
    session.send("MAIL FROM:<sender@" + ELSEWHERE + ">");
    await session.read(/^\d{3} /m, "MAIL FROM answered");
    session.send("RCPT TO:<forwards@" + DOMAIN + ">");
    await session.read(/^\d{3} /m, "RCPT TO answered");
    session.send("DATA");
    await session.read(/^354 /m, "DATA answered");
    // No line of this fixture opens with a dot, so nothing needs
    // stuffing on the way in.
    session.sendRaw(Buffer.concat([transmitted, TERMINATOR]),
      "<the message and its terminating dot>");
    accepted = await session.read(/^\d{3} /m, "message answered");
    session.send("QUIT");
  } finally { session.close(); }

  var raw = peer.seen.bodies[peer.seen.bodies.length - 1];
  var read = raw ? bothReadings(raw) : null;

  await stack.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  handle.stop();
  await identity.close();
  peer.close();

  if (!read) {
    return {
      mode: "roundtrip", captured: false,
      accepted: accepted === undefined ? null : accepted.split("\r\n")[0],
      commands: peer.seen.commands,
    };
  }
  // The receiver writes its own `Authentication-Results` header at the
  // front (RFC 8601 section 5), so the claim is a suffix claim: the
  // octets the first peer transmitted occur in what the second peer
  // received once, contiguously, and at the end.
  var at = read.counted.indexOf(transmitted);
  return {
    mode:            "roundtrip",
    captured:        true,
    accepted:        accepted === undefined ? null : accepted.split("\r\n")[0],
    transmittedBytes: transmitted.length,
    transmittedTail:  transmitted.subarray(-12).toString("hex"),
    receivedBytes:    read.counted.length,
    receivedTail:     read.counted.subarray(-12).toString("hex"),
    suffixAt:         at,
    suffixExpectedAt: read.counted.length - transmitted.length,
    naiveBytes:       read.naive.length,
    naiveSuffixAt:    read.naive.indexOf(transmitted),
    prefix:           read.counted.subarray(0, Math.max(0, at)).toString("latin1").slice(0, 200),
  };
}

// ---- mode: sent -------------------------------------------------------------

// The composer builds a message, hands it to the outbound path and
// files a copy. Both are supposed to be the one message, so the octets
// the peer received and the octets an IMAP client is served for the
// filed copy are the two ends of the same claim.
async function runSent(material, root, dataDir) {
  var peer = await startPeer(material);
  var cfg  = loadConfig(dataDir, root);
  var identity = await openIdentity(cfg);
  var alice = await identity.accounts.create({
    address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

  var leaf = await serverCertificate(root, "sent");

  var sections = await listenerSections({ imap: true });
  var handle = outboundHandle(dataDir, peer.port);
  var stack = listeners.create({
    config:      Object.assign({}, cfg, { listeners: sections, inbound: { mode: "monitor" } }),
    store:       identity,
    mailStore:   identity.mailbox,
    certificate: certs.handle({ cert: leaf.cert, key: leaf.key }),
    delivery:    handle,
    resolver:    pinnedResolver(),
  });
  await stack.start();

  var composer = compose.create({
    delivery:  handle,
    hostname:  HOSTNAME,
    mailStore: identity.mailbox,
  });

  var sendOutcome = null;
  var threw = null;
  try {
    sendOutcome = await composer.send({
      from:    alice.address,
      to:      ["nobody@" + ELSEWHERE],
      subject: "the copy and the wire",
      // A body whose last line is blank, so the fixture the readings
      // disagree about travels this path too.
      text:    "one line of body\n\n",
    }, { actor: { id: alice.id, address: alice.address } });
  } catch (e) { threw = String((e && e.message) || e); }

  var raw = peer.seen.bodies[peer.seen.bodies.length - 1];
  var received = raw ? bothReadings(raw).counted : null;

  // The filed copy is read over IMAP rather than out of the store,
  // because what an account holder is served is the claim. All three are
  // assigned inside the session below and read after it; a session that
  // throws before the fetch never reaches the read.
  var served;
  var announced;
  var present;
  var imap = await Wire.imap(sections.imap.port, {
    caPem: leaf.ca, servername: HOSTNAME, address: alice.address,
    password: ALICE_PASSWORD, label: "sent-copy", binary: true });
  try {
    var selectTag = imap.tag();
    imap.send(selectTag + " SELECT Sent");
    await imap.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");
    var fetchTag = imap.tag();
    imap.send(fetchTag + " FETCH 1 (RFC822.SIZE BODY.PEEK[])");
    var response = await imap.readBytes(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "FETCH answered");
    var literal = imapLiteral(response);
    announced = literal.announced;
    present   = literal.present;
    served    = literal.payload;
    imap.send(imap.tag() + " LOGOUT");
  } finally { imap.close(); }

  await stack.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  handle.stop();
  await identity.close();
  peer.close();

  return {
    mode:          "sent",
    threw:         threw,
    delivered:     sendOutcome && sendOutcome.delivery
      ? (sendOutcome.delivery.delivered || []).length : 0,
    filed:         !!(sendOutcome && sendOutcome.filed),
    captured:      !!received,
    receivedBytes: received ? received.length : 0,
    receivedTail:  received ? received.subarray(-12).toString("hex") : "",
    servedBytes:   served ? served.length : 0,
    servedTail:    served ? served.subarray(-12).toString("hex") : "",
    announced:     announced,
    present:       present,
    identical:     !!(received && served && served.equals(received)),
  };
}

// ---- runner -----------------------------------------------------------------

async function main() {
  var mode    = process.argv[2];
  var certDir = process.argv[3];
  var dataDir = process.argv[4];
  if (["direct", "roundtrip", "sent"].indexOf(mode) === -1) {
    throw new Error("outbound-octet-fidelity-fixture: mode must be direct, roundtrip or sent");
  }

  var material = {
    key:   nodeFs.readFileSync(nodePath.join(certDir, "peer.key"), "utf8"),
    chain: nodeFs.readFileSync(nodePath.join(certDir, "peer.chain.pem"), "utf8"),
  };

  var root = nodePath.dirname(dataDir);
  var verdict;
  if (mode === "direct")         verdict = await runDirect(material, dataDir);
  else if (mode === "roundtrip") verdict = await runRoundTrip(material, root, dataDir);
  else                           verdict = await runSent(material, root, dataDir);

  console.log("VERDICT " + JSON.stringify(verdict));
}

main().then(function () { process.exit(0); }, function (e) {
  console.error((e && e.stack) || e);
  process.exit(1);
});
