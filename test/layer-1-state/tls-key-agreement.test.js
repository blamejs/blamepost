// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which key agreement the listeners actually negotiate.
 *
 * This project leads with a post-quantum posture and nothing asserted
 * that it reached the wire. Sealed storage and the release signature
 * carry their own tests; transport is the surface an outside party
 * touches, and it was the one nobody had measured. A headline
 * cryptographic claim with no test under it is a claim about the
 * documentation rather than about the server.
 *
 * The server is assembled the way the serve verb assembles it: a real
 * data directory, a real vault, a real encrypted database, a
 * certificate written to disk and named through the configuration, and
 * every listener on a reserved loopback port. Naming the files is what
 * puts the certificate loader on the path, so the context the mail
 * listeners present is the one an operator's deployment builds rather
 * than one this file handed them.
 *
 * ## Read the group by name, not from the cipher
 *
 * A TLS 1.3 cipher suite says nothing about the key exchange. The two
 * are negotiated separately, and every group below shares one suite, so
 * a test that inferred the exchange from the cipher name would report
 * the same answer for a hybrid and for a classical handshake.
 * `getEphemeralKeyInfo()` names the group outright, and it identifies a
 * post-quantum exchange positively: a hybrid reports
 * `{ type: "TLSGroup", name: "X25519MLKEM768" }` while a classical one
 * reports `{ type: "ECDH", name: "X25519" }`.
 *
 * That call answers on a client socket and returns null on a server
 * one, which is why every measurement here is taken from the client end
 * and why the server has no way to record what a peer negotiated with
 * it. The last case pins that property of the runtime, because it is
 * the thing standing between this server and an audit event for an
 * inbound classical handshake.
 *
 * ## Two clients, because a handshake is an agreement
 *
 * A handshake reports what the two ends settled on, never what the
 * server would have preferred, so one client cannot tell a server that
 * requires a hybrid from a server that merely accepts the one its peer
 * asked for. Every surface is therefore driven three ways: a client
 * that brings the runtime's own defaults, which is what a real peer
 * does; a client that names the framework's hybrid preference; and a
 * client with no post-quantum support at all.
 *
 * The third is the discriminator. It completes, on every listener, over
 * a classical group. So the hybrid the first two negotiate is the
 * client's choice landing on a server that accepts it, and not a floor
 * this server imposes. That is the honest shape of the guarantee, and
 * pinning it here means a runtime whose defaults stop leading with a
 * hybrid, or a vendor refresh that changes what the listeners present,
 * fails a test instead of quietly moving every session onto a classical
 * exchange.
 *
 * ## The accepted set is two tuples, and the separator is the point
 *
 * Every surface presents a context carrying this server's own
 * key-agreement preference, written as two tuples: the ML-KEM hybrids
 * first, then the elliptic curves. A single flat list is only a set of
 * acceptable groups, so a server reading one serves whatever key share
 * the client already sent. Two tuples are an ORDER, so a client that
 * names a hybrid anywhere in its list is retried onto the hybrid with a
 * HelloRetryRequest rather than served the classical group it happened
 * to put first. Both shapes accept the same groups; only one of them
 * decides which group runs.
 *
 * Both halves of that are measured against the control, and both need
 * it. A refusal case would pass equally against a runtime that had
 * stopped supporting the group, and an ordering case would pass equally
 * against a runtime that retried every peer of its own accord. Neither
 * would say anything about what this server asks for.
 *
 * ## What is refused is finite-field Diffie-Hellman, and only that
 *
 * The second tuple names every elliptic-curve group RFC 8446 section
 * 4.2.7 registers, so a conforming peer completes on whichever one it
 * brought: `secp256r1`, which section 9.1 makes mandatory to implement,
 * the two larger NIST curves, X25519, which is only a SHOULD, and X448.
 * The finite-field groups are what is left off, and a peer offering only
 * `ffdhe2048` is refused on every surface while the control accepts it.
 *
 * That is the whole narrowing, and the case measuring it is why the
 * tuple is written out rather than left to the runtime. It is also why
 * the line is drawn there and not one group further in. A peer this
 * server refuses does not fall back to plaintext: port 25 answers
 * `MAIL FROM` with `530 5.7.0 Must issue a STARTTLS command first`
 * until the session is encrypted, so a handshake refused here is a
 * message that never arrives. That refusal is driven on the wire in
 * this file, because it is the fact deciding whether a narrowing costs
 * confidentiality or costs the mail.
 *
 * ## Both halves of the server, and they agree
 *
 * The mail listeners share one context loaded by the certificate
 * loader; the TLS port of the browser surface reads the same two files
 * and hands the PEM bytes to the framework's HTTP listener, which builds
 * its own. Two routes, so the sets they accept are measured separately
 * and then asserted equal. A divergence between them is itself the
 * finding: a measurement taken on one half and assumed to hold for the
 * other is exactly the mistake this arrangement invites.
 *
 * The transport floor is measured alongside, on the same sockets. A
 * change to key agreement that quietly relaxed the version floor would
 * otherwise leave every assertion here passing.
 *
 * Run standalone: node test/layer-1-state/tls-key-agreement.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var listeners = require("../../lib/mail/listeners");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var reservePort = wire.reservePort;
var Wire        = wire.Wire;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var HANDSHAKE_TIMEOUT_MS = 5000;
var SHUTDOWN_TIMEOUT_MS  = 5000;

// Every listener section the composed server knows, all enabled. A
// listener that is off cannot negotiate anything, and the question here
// is asked of the whole surface rather than of a sample of it.
var LISTENER_NAMES = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];

// The classical group a client with no post-quantum support offers in
// the posture table below. It is the one RFC 8446 section 9.1 names as a
// SHOULD, so it is what a modern peer without a hybrid actually brings.
var CLASSICAL_GROUP = "X25519";

// The group RFC 8446 section 9.1 requires every TLS 1.3 implementation
// to support, spelled the way node names it. X25519 beside it is only a
// SHOULD, so a conforming peer may offer this one and nothing else, and
// on port 25 a peer refused at the handshake has no second route.
var MANDATORY_CLASSICAL_GROUP = "prime256v1";

// Every elliptic-curve group RFC 8446 section 4.2.7 registers, each
// offered ALONE. A peer that brings one of these and nothing else is
// conforming, and the second tuple exists so that every one of them
// completes. Spelled with node's names: `prime256v1` is the registry's
// `secp256r1`.
var CURVE_GROUPS = [
  MANDATORY_CLASSICAL_GROUP, "secp384r1", "secp521r1", CLASSICAL_GROUP, "X448",
];

// One group, two spellings. The TLS registry and this server's composed
// preference call it `secp256r1`; node offers it and reports a finished
// handshake under OpenSSL's older `prime256v1`. Both reach the same
// group, so a membership check against the composed string has to fold
// them together rather than compare the two names. Folding is the point:
// dropping the assertion because the strings differ would stop checking
// that the mandatory group is in the list at all, which is the one
// membership this file most needs to hold.
var GROUP_ALIASES = { prime256v1: "secp256r1", secp256r1: "secp256r1" };

function canonicalGroup(name) {
  return Object.prototype.hasOwnProperty.call(GROUP_ALIASES, name)
    ? GROUP_ALIASES[name] : name;
}

// The one class of group deliberately left off. RFC 7919 finite-field
// Diffie-Hellman at 2048 bits is the weakest exchange a TLS 1.3 peer can
// name, and no implementation offers it as its only group without also
// offering the mandatory curve. Refusing it is the whole narrowing this
// server applies, so it is measured against a control that accepts it.
var FINITE_FIELD_GROUP = "ffdhe2048";

// A client that offers X25519 before the hybrid. Both ends support
// both, so what it measures is whose ordering decides.
var CLASSICAL_FIRST_GROUPS = CLASSICAL_GROUP + ":" + "X25519MLKEM768";

// What each client posture brings to the handshake. `groups` of null
// means the client names nothing and takes the runtime's own defaults,
// which is what an ordinary peer does.
var CLIENT_POSTURES = [
  {
    name:   "a client on the runtime's own defaults",
    groups: null,
    hybrid: true,
    why:    "this is what an ordinary peer offers, so it is the posture " +
            "that decides what most sessions actually negotiate",
  },
  {
    name:   "a client naming the framework's hybrid preference",
    groups: b.constants.TLS_GROUP_CURVE_STR,
    hybrid: true,
    why:    "a peer that asks for a post-quantum exchange gets one, which " +
            "is the guarantee that has to hold for a hybrid to be reachable " +
            "at all",
  },
  {
    name:   "a client with no post-quantum support",
    groups: CLASSICAL_GROUP,
    hybrid: false,
    why:    "it completes rather than being refused, which is what tells a " +
            "server that accepts a hybrid apart from one that requires it",
  },
];

// ---- reading the negotiated group ------------------------------------------

// The group a finished handshake settled on, named rather than guessed.
// A post-quantum exchange is identified positively, by the type the
// runtime reports for a named TLS group and by the name appearing in the
// framework's own codepoint table. Both are kept: the type covers a
// hybrid the table has not learned yet, and the table covers a runtime
// that labels a known hybrid differently.
// A throw here is left to reach the caller rather than folded into an
// absent group. The two are different findings and only one of them is
// about the handshake: a runtime that has stopped answering has to read
// as a broken measurement, not as a session that agreed on nothing.
function agreementOn(socket) {
  var info = socket.getEphemeralKeyInfo() || {};
  var name = typeof info.name === "string" ? info.name : null;
  return {
    group:    name,
    type:     info.type || null,
    protocol: socket.getProtocol(),
    cipher:   (socket.getCipher() || {}).name || null,
    hybrid:   info.type === "TLSGroup" ||
              (name !== null &&
               Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name)),
  };
}

function describeAgreement(agreed) {
  return "group " + JSON.stringify(agreed.group) +
         ", type " + JSON.stringify(agreed.type) +
         ", " + agreed.protocol + ", " + agreed.cipher;
}

// One handshake against a port that speaks TLS from the first byte, and
// what it settled on. Used for implicit-TLS submission and for the TLS
// port of the browser surface.
function handshakeDirect(port, caPem, connectOpts) {
  return new Promise(function (resolve, reject) {
    var settled = false;
    var socket = nodeTls.connect(Object.assign({}, connectOpts || {}, {
      host:       LOOPBACK,
      port:       port,
      ca:         [caPem],
      servername: HOSTNAME,
    }));
    socket.setTimeout(HANDSHAKE_TIMEOUT_MS);
    socket.once("secureConnect", function () {
      if (settled) return;
      settled = true;
      var agreed = agreementOn(socket);
      agreed.verified = socket.authorized === true;
      socket.destroy();
      resolve(agreed);
    });
    socket.once("timeout", function () {
      socket.destroy();
      if (settled) return;
      settled = true;
      reject(new Error("port " + port + " accepted a connection and never " +
        "completed a handshake"));
    });
    socket.once("error", function (e) {
      if (settled) return;
      settled = true;
      reject(e);
    });
  });
}

// The node:tls connect options for one client posture. An absent group
// list is left absent rather than spelled as the runtime's default,
// because the two are not the same client: one names a preference and
// the other takes whatever the runtime ships.
function clientOptions(posture) {
  return posture.groups === null ? {} : { ecdhCurve: posture.groups };
}

// Every surface this server presents, each with a way to reach a
// finished TLS socket on it. The ladders come from the shared wire
// helper, so the sequence a real client performs on each protocol is
// the sequence driven here rather than a second idea of it per file.
function surfacesFor(sections, httpsPort, caPem) {
  function ladder(fn, port, label) {
    return async function (posture) {
      var session = await fn(port, {
        caPem:      caPem,
        servername: HOSTNAME,
        label:      label,
        tls:        clientOptions(posture),
      });
      var agreed = agreementOn(session.socket);
      agreed.verified = session.socket.authorized === true;
      session.close();
      return agreed;
    };
  }
  // `mail` marks the surfaces whose context comes from the certificate
  // loader. The browser surface reads the same two files and hands the
  // PEM bytes to the framework's own HTTP listener, which builds its own
  // context, so the preference reaches it by a different route. Every
  // case below runs over both groups of surfaces and asserts the same
  // answer, because a divergence between the two routes is the kind of
  // thing that stays invisible until somebody measures one half and
  // concludes it holds for the other. The flag is kept so the two routes
  // can be named apart when a result differs.
  return [
    { name: "the MX listener, after STARTTLS", mail: true,
      shake: ladder(Wire.mx, sections.mx.port, "mx") },
    { name: "the submission listener, after STARTTLS", mail: true,
      shake: ladder(Wire.submission, sections.submission.port, "submission") },
    { name: "the submission listener in implicit TLS mode", mail: true,
      shake: function (posture) {
        return handshakeDirect(sections.submissions.port, caPem, clientOptions(posture));
      } },
    { name: "the IMAP listener, after STARTTLS", mail: true,
      shake: ladder(Wire.imap, sections.imap.port, "imap") },
    { name: "the POP3 listener, after STLS", mail: true,
      shake: ladder(Wire.pop3, sections.pop3.port, "pop3") },
    { name: "the ManageSieve listener, after STARTTLS", mail: true,
      shake: ladder(Wire.managesieve, sections.managesieve.port, "managesieve") },
    { name: "the TLS port of the browser surface", mail: false,
      shake: function (posture) {
        return handshakeDirect(httpsPort, caPem, clientOptions(posture));
      } },
  ];
}

// ---- what every surface negotiates -----------------------------------------

async function testEverySurfaceNegotiatesTheSameWay(surfaces) {
  for (var s = 0; s < surfaces.length; s += 1) {
    var surface = surfaces[s];
    for (var p = 0; p < CLIENT_POSTURES.length; p += 1) {
      var posture = CLIENT_POSTURES[p];
      var agreed = null;
      var thrown = null;
      try { agreed = await surface.shake(posture); }
      catch (e) { thrown = e; }

      count(surface.name + " completes a handshake with " + posture.name,
        thrown === null && agreed !== null,
        thrown === null ? undefined : (thrown.message || String(thrown)));
      if (thrown !== null || agreed === null) continue;

      count("and " + posture.name + " verified the certificate " + surface.name +
        " presented", agreed.verified === true, describeAgreement(agreed));

      // The floor, read off the same socket that answered the question
      // above. Asserting it here rather than only in its own case means
      // a change to key agreement cannot relax the version underneath
      // it while every group assertion still passes.
      count("the session " + posture.name + " opened against " + surface.name +
        " runs on TLS 1.3", agreed.protocol === "TLSv1.3", describeAgreement(agreed));

      if (posture.hybrid) {
        count(surface.name + " negotiates a post-quantum hybrid with " +
          posture.name + ", because " + posture.why,
          agreed.hybrid === true, describeAgreement(agreed));
        count("and the group it named is one the framework carries a codepoint for",
          agreed.group !== null &&
          Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, agreed.group),
          describeAgreement(agreed));
        continue;
      }

      // The classical vector. Both halves are asserted: that it is not a
      // hybrid, so the case is genuinely measuring the fallback, and
      // that it completed, which is the whole discriminator. A listener
      // that refused this client would be one that requires a hybrid,
      // and that is a different server from the one shipping today.
      count(surface.name + " falls back to a classical exchange for " +
        posture.name + ", because " + posture.why,
        agreed.hybrid === false, describeAgreement(agreed));
      count("and the fallback lands on the classical group the framework " +
        "keeps rather than something weaker",
        agreed.group === CLASSICAL_GROUP, describeAgreement(agreed));
    }
  }
}

// ---- the floor holds against a client that asks for less --------------------

// Every case above ran over TLS 1.3 because both ends offered it. This
// is the other question: a client that will not go above TLS 1.2 has to
// be refused rather than served, and a floor that only holds when
// nobody pushes on it is not a floor.
//
// Kept out of the posture table because a version cap is not a group
// preference. Folding the two together would leave each case asserting
// half of what it says, and the refusal has no negotiated group to
// report at all.
// RFC 8446 section 6.2 gives a version refusal its own alert, and the
// number is the frozen part: the surrounding text belongs to the TLS
// library and moves with it. Asserting on the number means the refusal
// stays readable to a client rather than merely happening.
var PROTOCOL_VERSION_ALERT = /alert number 70\b|tlsv1 alert protocol version/i;

// The one surface that answers a capped client by closing the socket
// instead of sending that alert. Pinned as itself rather than folded in
// under a looser pattern: the floor holds either way, but a client sees
// a bare disconnect rather than a reason, and a test that accepted any
// error here would also accept a timeout or a reset and stop measuring
// the floor at all.
var DROPPED_BEFORE_HANDSHAKE = /disconnected before secure TLS connection/i;

async function testTheFloorRefusesTlsTwelve(sections, httpsPort, caPem) {
  var cappedOpts = { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" };

  var direct = [
    { name:    "the submission listener in implicit TLS mode",
      port:    sections.submissions.port,
      refusal: DROPPED_BEFORE_HANDSHAKE,
      says:    "closes the connection rather than naming the version, which is " +
               "the one surface here that leaves a capped client without a reason" },
    { name:    "the TLS port of the browser surface",
      port:    httpsPort,
      refusal: PROTOCOL_VERSION_ALERT,
      says:    "answers with the protocol version alert" },
  ];
  for (var d = 0; d < direct.length; d += 1) {
    var thrown = null;
    try { await handshakeDirect(direct[d].port, caPem, cappedOpts); }
    catch (e) { thrown = e; }
    count(direct[d].name + " refuses a client that will not go above TLS 1.2",
      thrown !== null, thrown === null ? "the handshake completed" : thrown.message);
    if (thrown === null) continue;
    count("and it " + direct[d].says,
      direct[d].refusal.test(thrown.message), thrown.message);
  }

  var ladders = [
    { name: "the MX listener",          fn: Wire.mx,          port: sections.mx.port },
    { name: "the submission listener",  fn: Wire.submission,  port: sections.submission.port },
    { name: "the IMAP listener",        fn: Wire.imap,        port: sections.imap.port },
    { name: "the POP3 listener",        fn: Wire.pop3,        port: sections.pop3.port },
    { name: "the ManageSieve listener", fn: Wire.managesieve, port: sections.managesieve.port },
  ];
  for (var l = 0; l < ladders.length; l += 1) {
    var failed = null;
    var session = null;
    try {
      session = await ladders[l].fn(ladders[l].port, {
        caPem:      caPem,
        servername: HOSTNAME,
        label:      "floor-" + l,
        tls:        cappedOpts,
      });
    } catch (e) { failed = e; }
    if (session !== null && session !== undefined) session.close();
    count(ladders[l].name + " refuses a client that will not go above TLS 1.2 " +
      "when it upgrades", failed !== null,
      failed === null ? "the upgrade completed" : failed.message);
    if (failed === null) continue;
    // Named rather than merely present. A bare "it threw" would pass on a
    // read timeout or a reset from an unrelated fault, and would keep
    // passing if the listener stopped refusing for the right reason.
    count("and the refusal is the protocol version alert rather than any " +
      "other way a session can end", PROTOCOL_VERSION_ALERT.test(failed.message),
      failed.message);
  }
}

// ---- the accepted set is the framework's, not the runtime's -----------------

// A handshake against a context built from the certificate and key
// alone, naming no key-agreement preference. It is the control every
// refusal below is read against: the same client, the same material,
// the same runtime, and the only difference is whether a group list was
// set. A refusal that reproduced here would be the runtime declining
// the group and would say nothing about this server.
function handshakeAgainstControl(material, connectOpts) {
  return new Promise(function (resolve, reject) {
    var settled = false;
    var server = nodeTls.createServer({ cert: material.chain, key: material.key },
      function (socket) { socket.end("ok"); });
    function finish(fn, value) {
      if (settled) return;
      settled = true;
      server.close();
      fn(value);
    }
    server.once("error", function (e) { finish(reject, e); });
    server.listen(0, LOOPBACK, function () {
      var client = nodeTls.connect(Object.assign({}, connectOpts || {}, {
        host:       LOOPBACK,
        port:       server.address().port,
        ca:         [material.caPem],
        servername: HOSTNAME,
      }));
      client.setTimeout(HANDSHAKE_TIMEOUT_MS);
      client.once("secureConnect", function () {
        var agreed = agreementOn(client);
        client.destroy();
        finish(resolve, agreed);
      });
      client.once("timeout", function () {
        client.destroy();
        finish(reject, new Error("the control server never completed a handshake"));
      });
      client.once("error", function (e) { client.destroy(); finish(reject, e); });
    });
  });
}

// A group the peer offers and the server does not accept ends the
// handshake with RFC 8446 section 6.2's handshake_failure. The number
// is the frozen part; the surrounding text belongs to the TLS library.
// The implicit-TLS surface closes the socket instead of sending an
// alert, the same way it answers a version cap, so that shape is
// accepted alongside rather than folded under a looser pattern.
var GROUP_REFUSAL = /alert number 40\b|handshake failure|no shared (cipher|group)/i;

// Every elliptic curve a conforming TLS 1.3 peer may bring as its only
// group completes on every surface, mail ports and browser port alike.
//
// This is the interoperability half of the posture and the reason the
// preference is written as two tuples rather than one list. A flat list
// naming the hybrids and X25519 refuses `prime256v1`, which RFC 8446
// section 9.1 makes mandatory to implement where X25519 is only a
// SHOULD. On port 25 the peer refused there has no second route, so the
// cost of that narrowing is measured in messages rather than in
// confidentiality, which is what the last case in this file drives.
//
// The control is what makes each result evidence: the same client, the
// same material, the same runtime, and the only difference is whether a
// preference was set. A curve the runtime had stopped supporting would
// fail the control first and be read as a broken measurement rather than
// as a policy this server applies.
async function testEverySurfaceAcceptsEveryCurve(surfaces, material) {
  for (var g = 0; g < CURVE_GROUPS.length; g += 1) {
    var only = { name: "a client offering only " + CURVE_GROUPS[g],
                 groups: CURVE_GROUPS[g] };

    var control = null;
    var controlFailed = null;
    try { control = await handshakeAgainstControl(material, clientOptions(only)); }
    catch (e) { controlFailed = e; }
    count("the runtime itself supports " + CURVE_GROUPS[g] + ", so a refusal below would " +
      "be this server's policy rather than the runtime declining the group",
      controlFailed === null && control !== null && control.group === CURVE_GROUPS[g],
      controlFailed === null ? describeAgreement(control) : controlFailed.message);

    for (var s = 0; s < surfaces.length; s += 1) {
      var surface = surfaces[s];
      var thrown = null;
      var agreed = null;
      try { agreed = await surface.shake(only); }
      catch (e) { thrown = e; }
      count(surface.name + " completes a handshake with " + only.name +
        ", because the trailing tuple names every curve RFC 8446 registers",
        thrown === null && agreed !== null,
        thrown === null ? undefined : thrown.message);
      if (thrown !== null || agreed === null) continue;
      count("and it settles on the group that client brought, on " + surface.name,
        agreed.group === CURVE_GROUPS[g], describeAgreement(agreed));
    }
  }
}

// The one narrowing this server applies, measured as a narrowing: a peer
// offering only finite-field Diffie-Hellman is refused everywhere, and
// the control accepts the same peer.
//
// Both halves are needed. Without the control the case would pass
// against a runtime that had dropped the group, and would say nothing
// about whether this server asks for anything at all. Without the
// refusal there would be no evidence that a preference reaches the wire,
// since every other case here is a group that completes.
async function testEverySurfaceRefusesFiniteFieldDh(surfaces, material) {
  var only = { name: "a client offering only finite-field Diffie-Hellman",
               groups: FINITE_FIELD_GROUP };

  var control = null;
  var controlFailed = null;
  try { control = await handshakeAgainstControl(material, clientOptions(only)); }
  catch (e) { controlFailed = e; }
  count("a context carrying no key-agreement preference completes a handshake with " +
    only.name + ", so the refusals below are this server's policy and not the runtime's",
    controlFailed === null && control !== null,
    controlFailed === null ? describeAgreement(control) : controlFailed.message);

  for (var s = 0; s < surfaces.length; s += 1) {
    var surface = surfaces[s];
    var thrown = null;
    try { await surface.shake(only); }
    catch (e) { thrown = e; }
    count(surface.name + " refuses " + only.name + ", which is the whole of what the " +
      "preference narrows away", thrown !== null,
      thrown === null ? "the handshake completed" : thrown.message);
    if (thrown === null) continue;
    count("and the refusal is a group refusal rather than any other way a session " +
      "can end on " + surface.name,
      GROUP_REFUSAL.test(thrown.message) || DROPPED_BEFORE_HANDSHAKE.test(thrown.message),
      thrown.message);
  }
}

// Whose ordering decides when both ends support both. A client that
// sends its key share for a classical group and names a hybrid behind it
// is retried onto the hybrid, because the preference reaches the
// listener as two tuples rather than one flat list: the hybrids are a
// higher tuple, so the server spends a HelloRetryRequest to reach one
// instead of taking the key share already in hand.
//
// This is the case a flat list gets wrong in the direction nobody
// notices. A flat list accepts the same groups and serves the classical
// one, so every assertion about what is ACCEPTED would keep passing
// while the exchange actually running moved off the hybrid.
async function testAClassicalFirstPeerIsPulledUp(surfaces, material) {
  var posture = { name: "a client offering the classical group before the hybrid",
                  groups: CLASSICAL_FIRST_GROUPS };

  var control;
  try { control = await handshakeAgainstControl(material, clientOptions(posture)); }
  catch (_e) { control = null; }
  count("a context carrying no preference retries that client onto the hybrid, so the " +
    "answer below is a property of the tuples this server carries rather than a " +
    "runtime default reappearing",
    control !== null && control.hybrid === true,
    control === null ? "no handshake" : describeAgreement(control));

  for (var s = 0; s < surfaces.length; s += 1) {
    var surface = surfaces[s];
    var agreed = null;
    var thrown = null;
    try { agreed = await surface.shake(posture); }
    catch (e) { thrown = e; }
    count(surface.name + " completes a handshake with " + posture.name,
      thrown === null && agreed !== null,
      thrown === null ? undefined : thrown.message);
    if (thrown !== null || agreed === null) continue;
    count("and it retries that client onto the hybrid rather than serving the classical " +
      "group the client put first, on " + surface.name,
      agreed.hybrid === true, describeAgreement(agreed));
  }
}

// ---- what the framework still says -----------------------------------------

// The group table the listeners now inherit their accepted set from,
// asserted so a vendor refresh that reorders or empties it is visible
// here. The measurements above would keep passing on a runtime that
// leads with a hybrid regardless of what the framework says, so the two
// halves of the posture need separate assertions or a change to either
// one hides behind the other.
function testTheFrameworkStillLeadsWithAHybrid() {
  var preference = b.constants.TLS_GROUP_PREFERENCE;
  count("the framework still publishes a key agreement preference",
    Array.isArray(preference) && preference.length > 0, JSON.stringify(preference));

  count("and it still leads with a post-quantum hybrid rather than a classical group",
    Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, preference[0]),
    JSON.stringify(preference));

  count("its classical last resort is the strong one rather than a weaker curve",
    preference[preference.length - 1] === CLASSICAL_GROUP, JSON.stringify(preference));

  // Every hybrid the preference names has to carry a codepoint, because
  // the codepoint table is what the assertions above identify a hybrid
  // by. A group offered on the wire and missing from the table would
  // read here as a classical fallback.
  var untabled = preference.filter(function (name) {
    return name !== CLASSICAL_GROUP &&
      !Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name);
  });
  count("every hybrid the preference names carries a codepoint in the table " +
    "this file identifies one by", untabled.length === 0, JSON.stringify(untabled));
}

// The preference this server composes, read from
// `blamepost.mail.listeners.keyAgreementGroups` and checked against the
// framework's own server form rather than against a copy of it. A vendor
// refresh that adds a hybrid has to reach the wire without anyone
// editing a second list here, and the only way to assert that is to
// derive the expected value the same way the shipped code does and
// compare.
//
// The handshakes above cannot answer this on their own. They measure a
// runtime that leads with a hybrid regardless of what either list says,
// so a preference that had silently stopped being composed would leave
// most of them passing.
//
// The shape asserted here is tuples, not a fixed COUNT of them. The
// count is the framework's to choose and it has already changed once:
// the ranking between two hybrids exists only between tuples, so a form
// that packs them together silently stops ranking them. Pinning a number
// would fail on a correct framework and pass on a preference that had
// collapsed into a set, which is backwards in both directions.
function testThePreferenceIsDerivedFromTheFramework() {
  var composed = listeners.keyAgreementGroups();
  count("this server composes a key-agreement preference for its listeners",
    typeof composed === "string" && composed.length > 0, JSON.stringify(composed));

  count("and it takes that preference from the framework's SERVER form rather than " +
    "spelling one out, so the two halves of this server cannot disagree about it",
    composed === b.network.tls.serverKeyAgreementGroups(),
    JSON.stringify(composed) + " against " +
    JSON.stringify(b.network.tls.serverKeyAgreementGroups()));

  var tuples = String(composed).split("/");
  count("it is written as slash-separated tuples, which is what makes it an order " +
    "rather than a set. A server reads a flat colon list as the groups it will " +
    "accept AT ALL", tuples.length > 1, JSON.stringify(composed));
  if (tuples.length < 2) return;

  var leading = tuples[0].trim().split(":");
  count("the leading tuple names a post-quantum hybrid, so a peer that offers " +
    "everything negotiates one rather than a classical group",
    leading.some(function (name) {
      return Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name);
    }), JSON.stringify(leading));

  // Every hybrid has to be RANKED, not merely present. Two hybrids sharing
  // one tuple are a set the handshake resolves in whatever order it reaches
  // them, so the framework's stated order between them stops applying, and
  // the cost is not academic: leading with a less-deployed hybrid spends a
  // HelloRetryRequest on every handshake, across which node delivers an
  // empty stapled OCSP response.
  var hybridTuples = tuples.filter(function (tuple) {
    return tuple.trim().split(":").some(function (name) {
      return Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name);
    });
  });
  var sharedTuple = hybridTuples.filter(function (tuple) {
    return tuple.trim().split(":").filter(function (name) {
      return Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name);
    }).length > 1;
  });
  count("and no tuple carries two hybrids, which would leave the order between them " +
    "to whatever the handshake reached first", sharedTuple.length === 0,
    JSON.stringify(sharedTuple));

  // The accept set is the whole string flattened: tuples order what is
  // accepted, they do not narrow it. This is the assertion that would have
  // caught a listener refusing secp256r1.
  var accepted = String(composed).split("/").join(":").split(":")
    .map(function (name) { return canonicalGroup(name.trim()); });
  var missing = CURVE_GROUPS.filter(function (name) {
    return accepted.indexOf(canonicalGroup(name)) === -1;
  });
  count("the accept set names every curve a conforming peer may bring alone, " +
    "secp256r1 included. RFC 8446 §9.1 makes it mandatory to implement, and a " +
    "listener that refuses it loses the mail rather than downgrading it",
    missing.length === 0, "absent: " + JSON.stringify(missing) +
    " from " + JSON.stringify(composed));

  var duplicated = accepted.filter(function (name, i) {
    return accepted.indexOf(name) !== i;
  });
  count("and no group is named twice, which would make the later ranking unreachable " +
    "for that group", duplicated.length === 0, JSON.stringify(duplicated));

  count("finite-field Diffie-Hellman appears in no tuple, which is what the " +
    "refusals on the wire come from",
    composed.indexOf("ffdhe") === -1, JSON.stringify(composed));
}

// The refusal the accessor exists for now that the framework composes the
// string. A vendored tree that stopped publishing a hybrid, or a caller that
// narrowed the key shares to classical groups, would otherwise compose a
// posture that parses and binds every port while quietly claiming a
// post-quantum guarantee this server states as a property.
//
// Driven through the operator-reachable knob rather than by swapping the
// accessor for a test double, because a refusal proven against a
// replacement is only ever proven about the replacement.
function testAClassicalOnlyPostureIsRefused() {
  var priorGroups = listeners.keyAgreementGroups();
  var threw = null;
  try {
    b.network.tls.pqc.setKeyShares(["X25519", "secp384r1"]);
    try {
      listeners.keyAgreementGroups();
    } catch (err) {
      threw = err;
    }
  } finally {
    b.network.tls.pqc.resetKeyShares();
  }

  count("a key agreement with no hybrid to lead with is refused rather than composed " +
    "into a listener", threw !== null, threw === null ? "returned instead of throwing" : "");
  count("and the refusal names the classical-only posture it will not build",
    threw !== null && /classical-only posture/.test(String(threw && threw.message)),
    String(threw && threw.message).slice(0, 200));

  count("resetting the key shares restores the posture, so the refusal is a gate " +
    "rather than a latch",
    listeners.keyAgreementGroups() === priorGroups,
    JSON.stringify(listeners.keyAgreementGroups()) + " against " + JSON.stringify(priorGroups));
}

// ---- what a refused peer loses ----------------------------------------------

// The fact that decides how much a key-agreement refusal costs. Port 25
// is opportunistic in the sense that a sender may try STARTTLS and give
// up, but this server does not accept an envelope on an unencrypted
// session, so a peer whose handshake is refused cannot retry in the
// clear either. The message stays in the sender's queue and eventually
// bounces.
//
// It is measured here rather than assumed because the two outcomes are
// not close. A narrowing that pushed a peer onto a plaintext delivery
// would trade confidentiality for reach; this one trades the mail for
// nothing, and any future argument for narrowing the set further has to
// be made against that.
async function testARefusedPeerHasNoPlaintextRoute(sections) {
  var session = await Wire.connect(sections.mx.port, "plaintext-mx");
  try {
    await session.read(/^220 /m, "banner");
    session.send("EHLO peer.example.net");
    var greeting = await session.read(/^250 /m, "EHLO accepted");
    count("the MX listener advertises STARTTLS to a peer that has not upgraded, so a " +
      "sender knows an encrypted route exists before it tries one",
      /250[- ]STARTTLS/i.test(greeting), wire.visible(greeting));

    session.send("MAIL FROM:<sender@other.example>");
    var verdict = await session.read(/^\d{3} /m, "MAIL FROM answered");
    count("and it refuses MAIL FROM on the unencrypted session, so a peer whose " +
      "handshake was refused has no second route onto port 25 and its mail is lost " +
      "rather than delivered in the clear",
      /^530 5\.7\.0 /m.test(verdict), wire.visible(verdict));
  } finally {
    session.close();
  }
}

// ---- why the server cannot record any of this -------------------------------

// The runtime property that decides whether an inbound classical
// handshake can ever be audited. The framework records a downgrade on
// the sockets it opens outbound, and nothing equivalent exists for the
// sockets it accepts, because the call that names the group answers only
// on a client socket. This is a fact about the runtime rather than about
// this server, and it is pinned so a runtime that starts answering turns
// the missing audit event from impossible into merely absent.
function testTheServerEndCannotNameTheGroup(observed) {
  count("a server socket cannot report the group it negotiated, which is why " +
    "an inbound classical handshake goes unrecorded",
    observed.serverSide === null,
    "the server end reported " + JSON.stringify(observed.serverSide));
  count("while the client end of the same handshake names it outright",
    observed.clientSide !== null && typeof observed.clientSide === "string",
    "the client end reported " + JSON.stringify(observed.clientSide));
}

// One handshake between two ends this file owns, so both ends can be
// read. The listeners cannot answer this question about themselves:
// reaching their accepted sockets would mean reaching past the composed
// server into the framework, and the property being measured belongs to
// node:tls rather than to either.
//
// The server reads its own end, writes what it saw, and closes. The
// client resolves on that close rather than on its own handshake, so
// the server's read has already happened by the time either value is
// asserted. Resolving on the client handshake instead would race: in
// TLS 1.3 the client is finished a flight before the server is, so a
// client that tore the socket down at that moment could reset the
// connection before the server ever reached its own socket.
function observeBothEnds(material) {
  return new Promise(function (resolve, reject) {
    var server = nodeTls.createServer({ cert: material.chain, key: material.key },
      function (socket) {
        var seen;
        try { seen = socket.getEphemeralKeyInfo(); }
        catch (e) { seen = "threw: " + ((e && e.message) || String(e)); }
        socket.end(JSON.stringify({ serverSide: seen }));
      });
    server.once("error", reject);
    server.listen(0, LOOPBACK, function () {
      var clientSide = null;
      var body = "";
      var client = nodeTls.connect({
        host:       LOOPBACK,
        port:       server.address().port,
        ca:         [material.caPem],
        servername: HOSTNAME,
      });
      client.setEncoding("utf8");
      client.setTimeout(HANDSHAKE_TIMEOUT_MS);
      client.once("secureConnect", function () {
        clientSide = agreementOn(client).group;
      });
      client.on("data", function (chunk) { body += chunk; });
      client.once("timeout", function () {
        client.destroy();
        server.close();
        reject(new Error("the probe server completed a handshake and never reported"));
      });
      client.once("error", function (e) { server.close(); reject(e); });
      client.once("end", function () {
        client.destroy();
        server.close();
        var reported;
        try { reported = JSON.parse(body).serverSide; }
        catch (_e) { reported = body; }
        resolve({ serverSide: reported, clientSide: clientSide });
      });
    });
  });
}

// ---- runner -----------------------------------------------------------------

async function listenerSections() {
  var sections = {};
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    sections[LISTENER_NAMES[i]] = {
      enabled: true,
      port:    await reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

async function run() {
  var root    = helpers.tempDir("tls-groups");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside the run's own temporary tree keeps the encrypted at rest
  // path exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    // Written before the configuration is read, because the loader
    // checks that a named certificate exists and refuses the boot when
    // it does not. Naming the files rather than handing over a ready
    // made context is what puts the certificate loader, the capped file
    // reads and the TLS port of the browser surface on the path this
    // file drives.
    var material = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_POP3_ENABLED:     "true",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });
    await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = await listenerSections();
    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var httpsPort = server.web.bound().https;
    count("the browser surface took a TLS port, so both halves can be measured",
      typeof httpsPort === "number" && httpsPort > 0,
      JSON.stringify(server.web.bound()));

    var surfaces = surfacesFor(sections, httpsPort, material.caPem);
    await testEverySurfaceNegotiatesTheSameWay(surfaces);
    await testEverySurfaceAcceptsEveryCurve(surfaces, material);
    await testEverySurfaceRefusesFiniteFieldDh(surfaces, material);
    await testAClassicalFirstPeerIsPulledUp(surfaces, material);
    await testTheFloorRefusesTlsTwelve(sections, httpsPort, material.caPem);
    await testARefusedPeerHasNoPlaintextRoute(sections);
    testTheFrameworkStillLeadsWithAHybrid();
    testThePreferenceIsDerivedFromTheFramework();
    testAClassicalOnlyPostureIsRefused();
    testTheServerEndCannotNameTheGroup(await observeBothEnds(material));

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

module.exports = { name: "tls-key-agreement", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
