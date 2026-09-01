// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The certificate an operator hands this server, built for one run.
 *
 * Every listener in this project requires TLS and none of them has a
 * plaintext mode, so a test that wants to reach anything past a
 * greeting needs a certificate a client will actually verify. Two
 * shapes are needed and they are not interchangeable:
 *
 *   - `pair()` returns the bytes, for the `tlsContext` the mail
 *     listeners take when the caller builds the context itself.
 *   - `writePair(dir)` writes the same material to disk and returns the
 *     two paths, which is the form `blamepost.create` reads when the
 *     configuration names `tlsCert` and `tlsKey`. That path is the one
 *     an operator drives, and it is the only one that reaches the
 *     certificate loader, the capped file reads, the sealed key unwrap
 *     and the TLS port of the browser surface.
 *
 * A context built with no certificate in it looks equivalent to both
 * and is not: it completes construction, binds a port, and then fails
 * every handshake, so a session opened against it stops at the greeting
 * and every assertion after that point silently never runs.
 *
 * The authority is private to the run and the leaf carries both the
 * name the listeners answer to and the loopback address the suite
 * connects to, so a client can verify the chain either way round.
 * Verification stays on in the tests that use this: a client that
 * skipped it would pass against a listener presenting anything at all.
 *
 * ## The signature algorithm is a choice, and the caller makes it
 *
 * The default is ML-DSA-87, which is the framework's, and it stays the
 * default here. A test that says nothing gets the post-quantum key,
 * because a helper whose quiet answer is the classical one turns every
 * test written against it into a measurement of a posture this project
 * does not hold.
 *
 * It is not the right key for every test, and the reason is on the
 * other end of the socket. `node:tls` verifies ML-DSA-87 on the OpenSSL
 * this runtime carries; the OpenSSL shipped inside Python and the
 * Windows Schannel that backs the system curl do not, and a handshake
 * against a leaf they cannot verify fails before a single byte of the
 * protocol under test is spoken. A test built on the default and driven
 * by one of those clients does not test the thing it was written for:
 * it dies at the handshake and reports whatever that looks like.
 *
 * So the helper mints either, and a caller that wants the classical
 * bridge says so AND says why, in `interopReason`. The requirement is
 * the point. A bare `algorithm` opt would let a test quietly take the
 * weaker key to make itself pass, which is the failure this whole file
 * exists downstream of; a sentence at the call site makes the downgrade
 * a decision somebody wrote down and a reviewer can read. The framework
 * models the same pair for the same reason, and its own label for the
 * classical one is the bridge for a peer that predates OpenSSL 3.5.
 *
 * What this is NOT is a statement about what an operator's server
 * presents. blamepost obtains no certificate: there is no ACME support,
 * `tlsCert` and `tlsKey` name files the operator supplies, and the
 * server refuses to start without them. Whatever a deployment presents
 * was chosen by whoever issued it. This mints a stand-in for that, and
 * the algorithm it picks is a property of the test rather than of the
 * product.
 *
 * Validation posture: these are entry points a test author calls
 * directly, so bad input throws rather than degrading to a default.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var b = require("../../lib/vendor/blamejs");

var DEFAULT_HOSTNAME  = "mx.example.com";
var DEFAULT_LOOPBACK  = "127.0.0.1";
var DEFAULT_AUTHORITY = "blamepost test authority";

// The file names an ACME client leaves behind, so a configuration
// written against a real deployment and one written against a test run
// name the same two things.
var CERT_FILE_NAME = "fullchain.pem";
var KEY_FILE_NAME  = "privkey.pem";

// The two labels the framework's certificate engine accepts, named here
// so a caller picks from a set this file has checked rather than
// spelling a string the engine will reject three calls later.
//
// ML-DSA-87 is the default and the posture. ECDSA-P384-SHA384 is the
// framework's own classical bridge, and its documented reason is a peer
// whose OpenSSL predates 3.5. That describes every client this
// repository reaches for when it wants a parser that is not its own.
var ALGORITHM_PQC     = "ML-DSA-87";
var ALGORITHM_CLASSIC = "ECDSA-P384-SHA384";

var ALGORITHMS = Object.freeze([ALGORITHM_PQC, ALGORITHM_CLASSIC]);

// Reading the choice, and refusing the two ways of getting it wrong: a
// label the engine does not know, and the classical bridge taken
// without a reason written beside it.
//
// The second refusal is the one that matters. The engine accepts the
// classical label from anybody, so nothing downstream would object to a
// test that reached for it because the post-quantum leaf was
// inconvenient. Here is the only place that can ask why, and a test
// that cannot answer is a test taking a weaker key by accident.
function _algorithmOf(opts) {
  if (opts.algorithm === undefined) {
    if (opts.interopReason !== undefined) {
      throw new TypeError("helpers/certs: opts.interopReason was given without opts.algorithm. " +
        "The reason explains a departure from the " + ALGORITHM_PQC + " default; with no " +
        "departure there is nothing for it to explain. Name the algorithm, or drop the reason.");
    }
    return ALGORITHM_PQC;
  }
  if (ALGORITHMS.indexOf(opts.algorithm) === -1) {
    throw new TypeError("helpers/certs: opts.algorithm must be one of " + ALGORITHMS.join(", ") +
      ", got " + JSON.stringify(opts.algorithm));
  }
  if (opts.algorithm === ALGORITHM_PQC) return ALGORITHM_PQC;

  if (typeof opts.interopReason !== "string" || opts.interopReason.trim().length === 0) {
    throw new TypeError("helpers/certs: minting a " + ALGORITHM_CLASSIC + " leaf needs " +
      "opts.interopReason, a sentence saying which client cannot verify the " + ALGORITHM_PQC +
      " default. This project leads with a post-quantum posture, so a test that presents a " +
      "classical certificate is measuring something else and has to say so where the next " +
      "reader will see it. The reason a caller usually has: the client is not this codebase " +
      "and its TLS stack predates the OpenSSL that verifies ML-DSA.");
  }
  return ALGORITHM_CLASSIC;
}

// How much life the leaf is minted with.
//
// The default is the engine's, which is the ordinary case. A caller names
// this when the REMAINING life is the thing under test: a certificate a
// renewal client should already have replaced reads as an ordinary file
// from every angle except the date inside it, so the only way to drive
// what a server says about one is to mint one that says it.
//
// The engine takes positive whole days and nothing else, so a leaf that
// has ALREADY expired cannot be minted here. A case about one measures a
// good certificate at an instant past its expiry instead, which is what
// blamepost.certificateReport takes `now` for.
function _validityDaysOf(opts) {
  if (opts.validityDays === undefined) return undefined;
  if (typeof opts.validityDays !== "number" || !isFinite(opts.validityDays) ||
      Math.floor(opts.validityDays) !== opts.validityDays || opts.validityDays < 1) {
    throw new TypeError("helpers/certs: opts.validityDays must be a whole number of days, " +
      "one or more, got " + JSON.stringify(opts.validityDays));
  }
  return opts.validityDays;
}

function _hostnameOf(opts) {
  if (opts.hostname === undefined) return DEFAULT_HOSTNAME;
  if (typeof opts.hostname !== "string" || opts.hostname.length === 0) {
    throw new TypeError("helpers/certs: opts.hostname must be a non-empty host name");
  }
  return opts.hostname;
}

function _addressesOf(opts) {
  if (opts.addresses === undefined) return [DEFAULT_LOOPBACK];
  if (!Array.isArray(opts.addresses)) {
    throw new TypeError("helpers/certs: opts.addresses must be an array of IP literals");
  }
  for (var i = 0; i < opts.addresses.length; i += 1) {
    if (typeof opts.addresses[i] !== "string" || opts.addresses[i].length === 0) {
      throw new TypeError("helpers/certs: every entry in opts.addresses must be an IP literal");
    }
  }
  return opts.addresses.slice();
}

/**
 * @primitive test.helpers.certs.pair
 * @signature await certs.pair(opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one certificate per run, verifiable by the client that uses it)
 *
 * A private authority and one server certificate under it. Returns
 * `{ cert, key, caPem, chain, hostname, addresses, algorithm, expiresAt }`,
 * where `chain` is the leaf followed by the authority, which is what a
 * server presents, `algorithm` is the label the material was actually
 * minted under so a caller can report what it presented, and `expiresAt`
 * is the leaf's own expiry so a failure can say what was on disk.
 *
 * The authority and the leaf carry the SAME algorithm. A chain that
 * mixes them verifies only where both are verifiable, so a classical
 * leaf under a post-quantum authority would fail for the client the
 * classical leaf was minted for, at a step nobody was looking at.
 *
 * @opts
 *   hostname       the name the leaf answers to. Default mx.example.com.
 *   addresses      IP literals to carry as SANs. Default 127.0.0.1.
 *   authorityName  the private authority's name.
 *   algorithm      ML-DSA-87 (default) or ECDSA-P384-SHA384.
 *   interopReason  required with ECDSA-P384-SHA384, refused without it:
 *                  which client cannot verify the post-quantum default.
 *   validityDays   whole days of life for the leaf. Default is the
 *                  engine's. Name it when the remaining life is the
 *                  thing under test.
 */
async function pair(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("helpers/certs.pair: opts must be an object when supplied");
  }
  var hostname     = _hostnameOf(opts);
  var addresses    = _addressesOf(opts);
  var algorithm    = _algorithmOf(opts);
  var validityDays = _validityDaysOf(opts);

  var authority = await b.mtlsEngine.generateCa({
    name: typeof opts.authorityName === "string" && opts.authorityName.length
      ? opts.authorityName
      : DEFAULT_AUTHORITY,
    algorithm: algorithm,
  });
  var sans = [hostname].concat(addresses.map(function (ip) { return "IP:" + ip; }));
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           hostname,
    usage:        "server",
    sans:         sans,
    caCertPem:    authority.caCertPem,
    caKeyPem:     authority.caKeyPem,
    algorithm:    algorithm,
    validityDays: validityDays,
  });

  return {
    cert:      leaf.cert,
    key:       leaf.key,
    caPem:     authority.caCertPem,
    chain:     leaf.cert + authority.caCertPem,
    hostname:  hostname,
    addresses: addresses,
    algorithm: algorithm,
    expiresAt: leaf.expiresAt,
  };
}

/**
 * @primitive test.helpers.certs.writePair
 * @signature await certs.writePair(dir, opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the operator names files, so the loader is on the path)
 *
 * The same material, written into `dir` and named the way an ACME
 * client names it. Returns everything `pair` returns plus `certFile`
 * and `keyFile`, which is what a configuration points `tlsCert` and
 * `tlsKey` at.
 *
 * Takes the same `opts` as `pair`, including the algorithm choice and
 * the reason a classical one carries.
 */
async function writePair(dir, opts) {
  if (typeof dir !== "string" || dir.length === 0) {
    throw new TypeError("helpers/certs.writePair: dir (non-empty string) required");
  }
  var material = await pair(opts);
  nodeFs.mkdirSync(dir, { recursive: true });
  var certFile = nodePath.join(dir, CERT_FILE_NAME);
  var keyFile  = nodePath.join(dir, KEY_FILE_NAME);
  nodeFs.writeFileSync(certFile, material.chain, "utf8");
  nodeFs.writeFileSync(keyFile, material.key, "utf8");
  return Object.assign({ certFile: certFile, keyFile: keyFile }, material);
}

/**
 * @primitive test.helpers.certs.handle
 * @signature certs.handle(material)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one certificate shape, whether or not a file is watched)
 *
 * The certificate handle `blamepost.mail.listeners.create` takes, built
 * over material this run already holds.
 *
 * The listeners read their certificate through an accessor rather than
 * taking a context, because an operator's certificate client rewrites
 * the two files while the server runs and a listener holding the value
 * from boot would go on presenting the expired one. A test that has no
 * files to watch still has to hand over that shape, and hand-rolling it
 * per file is four spellings of one object waiting to disagree.
 *
 * What this returns cannot rotate, and that is correct: nothing is
 * watching a path behind it. A case about rotation names files and lets
 * `blamepost.create` build the watching handle, which is the only form
 * a renewal reaches.
 *
 * @param material  `{ cert, key }` from `pair()`, or a node:tls
 *                  SecureContext a caller already built.
 */
function handle(material) {
  if (!material || typeof material !== "object") {
    throw new TypeError("helpers/certs.handle: material ({ cert, key }) or a SecureContext " +
      "is required");
  }
  var context = typeof material.cert === "string" && typeof material.key === "string"
    ? nodeTls.createSecureContext({ cert: material.cert, key: material.key })
    : material;
  return { get secureContext() { return context; } };
}

module.exports = {
  pair:             pair,
  writePair:        writePair,
  handle:           handle,
  CERT_FILE_NAME:   CERT_FILE_NAME,
  KEY_FILE_NAME:    KEY_FILE_NAME,
  DEFAULT_HOSTNAME: DEFAULT_HOSTNAME,
  ALGORITHM_PQC:     ALGORITHM_PQC,
  ALGORITHM_CLASSIC: ALGORITHM_CLASSIC,
  ALGORITHMS:        ALGORITHMS,
};
