// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A zone a spawned `blamepost` run really resolves, over the shipped
 * transport.
 *
 * `test/helpers/dns-zone.js` hands a resolver HANDLE to a caller inside
 * this process, which is what a unit of the posture checker takes. A
 * command-line run cannot be given a handle: `blamepost doctor` builds
 * its own resolver through `blamepost.resolver()`, inside a process the
 * caller does not share. The only place a zone can be substituted for
 * that run is the endpoint the resolver fetches from, so this serves one
 * over DNS-over-HTTPS on loopback and points the run at it.
 *
 * What that buys is the difference between measuring the checker and
 * measuring the command. The marks an operator reads, the two counts in
 * the closing summary and the exit status are all decided in
 * `bin/blamepost.js` over a report the checker produced, and none of
 * them is reachable from a handle handed to the checker directly.
 *
 * Responses are assembled as DNS wire messages and parsed by the shipped
 * `b.safeDns.parseResponse`, so a record this file publishes is a record
 * the server decoded for itself rather than one a fixture handed it
 * already decoded.
 *
 * The AD bit is the reason this file can answer a question no handle
 * fixture can. RFC 4035 §3.2.3 makes DNSSEC authentication a property of
 * the RESPONSE, and the resolver reads it off the wire, so a zone here
 * says whether its answers are authenticated and a caller can measure
 * what this server does with a record nobody validated. RFC 7672 §1.3
 * turns that into a real verdict for TLSA: a record that was not
 * validated is one no sender may use.
 *
 * Absence and failure are kept apart here as they are everywhere else.
 * `ABSENT` is RFC 1035 §4.1.1 RCODE 3, a name that does not exist.
 * `FAILING` is RCODE 2, a question nobody answered. An entry present
 * with an empty list for the type asked about is the third: the name
 * exists and publishes nothing of that type.
 */

var nodeFs    = require("node:fs");
var nodeHttps = require("node:https");

var b     = require("../../lib/vendor/blamejs");
var certs = require("./certs");

// The two markers, in the shape the handle fixture beside this file
// offers them, so a caller moving a case from one to the other is
// writing the same word.
var ABSENT  = { absent: true };
var FAILING = { failing: true };

// RFC 1035 §3.2.2 and RFC 6698 §2.1 type numbers, for the types a
// posture report asks about.
var TYPE_A    = 1;
var TYPE_MX   = 15;
var TYPE_TXT  = 16;
var TYPE_TLSA = 52;

var CLASS_IN = 1;
var TTL_SECONDS = 300;

// RFC 1035 §4.1.1 header flags: QR set, RD and RA set, so a response
// reads as one an ordinary recursive resolver produced.
var FLAG_RESPONSE = 0x8180;
// RFC 4035 §3.2.3 AD, the bit the resolver reads to decide whether the
// answer was authenticated.
var FLAG_AUTHENTIC = 0x0020;

// RFC 1035 §3.3.14 splits a TXT record into strings of at most 255
// octets, and a long DKIM key really does arrive that way.
var MAX_CHARACTER_STRING = 255;

// The environment a spawned run reads to find this server. Named here
// and nowhere else, so the preload below and the caller arming it cannot
// disagree about the spelling.
var ARMED_VAR = "BLAMEPOST_DNS_ZONE_ENDPOINT";
var CA_VAR    = "BLAMEPOST_DNS_ZONE_CA_FILE";

function _key(name) {
  return String(name).toLowerCase().replace(/\.$/, "");
}

// A name as the wire carries it: each label prefixed by its length, the
// whole terminated by a zero octet. Written out rather than compressed,
// which is legal everywhere and is what keeps this readable.
function _encodeName(name) {
  var labels = _key(name).split(".").filter(function (l) { return l.length > 0; });
  var parts = [];
  for (var i = 0; i < labels.length; i += 1) {
    var bytes = Buffer.from(labels[i], "ascii");
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

// The question a query carries, read back so the answer names it. The
// header is twelve octets and the question follows it.
function _readQuestion(query) {
  var off = 12;
  var labels = [];
  while (off < query.length) {
    var len = query[off];
    if (len === 0) { off += 1; break; }
    labels.push(query.slice(off + 1, off + 1 + len).toString("ascii"));
    off += 1 + len;
  }
  return {
    id:       query.readUInt16BE(0),
    name:     labels.join("."),
    type:     query.readUInt16BE(off),
    // The question section as it arrived, copied into the answer rather
    // than rebuilt from the name. A response whose question does not
    // repeat the query's is one the parser reads the first answer record
    // as, so the whole message decodes as rubble.
    section:  query.slice(12, off + 4),
  };
}

function _rr(name, type, rdata) {
  var head = Buffer.alloc(10);
  head.writeUInt16BE(type, 0);
  head.writeUInt16BE(CLASS_IN, 2);
  head.writeUInt32BE(TTL_SECONDS, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([_encodeName(name), head, rdata]);
}

function _txtRdata(value) {
  var bytes = Buffer.from(String(value), "utf8");
  var chunks = [];
  for (var at = 0; at < bytes.length; at += MAX_CHARACTER_STRING) {
    var piece = bytes.slice(at, at + MAX_CHARACTER_STRING);
    chunks.push(Buffer.from([piece.length]), piece);
  }
  if (chunks.length === 0) chunks.push(Buffer.from([0]));
  return Buffer.concat(chunks);
}

function _mxRdata(exchange, preference) {
  var pref = Buffer.alloc(2);
  pref.writeUInt16BE(preference, 0);
  return Buffer.concat([pref, _encodeName(exchange)]);
}

function _tlsaRdata(index) {
  // RFC 7672 §3.1 usage 3, selector 1, matching type 1: the shape an
  // operator publishes for a mail exchanger's own certificate. The
  // digest is the index repeated, because nothing here verifies one and
  // a digest that varied between records would read as meaningful.
  return Buffer.concat([Buffer.from([3, 1, 1]), Buffer.alloc(32, index)]);
}

// The records one entry publishes for one question type.
function _answersFor(entry, name, qtype) {
  var out = [];
  var i;
  if (qtype === TYPE_TXT) {
    var rows = entry.txt || [];
    for (i = 0; i < rows.length; i += 1) out.push(_rr(name, TYPE_TXT, _txtRdata(rows[i])));
    return out;
  }
  if (qtype === TYPE_MX) {
    var hosts = entry.mx || [];
    for (i = 0; i < hosts.length; i += 1) {
      out.push(_rr(name, TYPE_MX, _mxRdata(hosts[i], (i + 1) * 10)));
    }
    return out;
  }
  if (qtype === TYPE_TLSA) {
    var count = entry.tlsa || 0;
    for (i = 0; i < count; i += 1) out.push(_rr(name, TYPE_TLSA, _tlsaRdata(i)));
    return out;
  }
  if (qtype === TYPE_A) {
    var addresses = entry.a || [];
    for (i = 0; i < addresses.length; i += 1) {
      out.push(_rr(name, TYPE_A, Buffer.from(addresses[i].split(".").map(Number))));
    }
    return out;
  }
  return out;
}

function _message(question, rcode, authenticated, answers) {
  var header = Buffer.alloc(12);
  header.writeUInt16BE(question.id, 0);
  header.writeUInt16BE(FLAG_RESPONSE | (authenticated ? FLAG_AUTHENTIC : 0) | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  return Buffer.concat([header, question.section].concat(answers));
}

/**
 * Serve one zone over DNS-over-HTTPS on an ephemeral loopback port.
 *
 * `zone` maps a name to `{ txt, mx, tlsa, a, authenticated }`, or to
 * `ABSENT` for a name that does not exist, or to `FAILING` for a
 * question nobody answers. `authenticated` defaults to true and says
 * whether the responses for that name carry the AD bit; a zone with no
 * DNSSEC under it sets it false.
 *
 * Returns `{ url, caPem, caFile, asked, wasAsked, close }`. `caFile` is
 * written only when a caller names a directory to put it in, which is
 * what a spawned run needs: a certificate authority cannot cross a
 * process boundary as an object.
 */
async function start(zone, opts) {
  opts = opts || {};
  var table = Object.create(null);
  Object.keys(zone || {}).forEach(function (name) { table[_key(name)] = zone[name]; });

  var pair = await certs.pair();
  var asked = [];

  var server = nodeHttps.createServer({ cert: pair.cert, key: pair.key },
    function (req, res) {
      var url = new URL(req.url, "https://127.0.0.1");
      var encoded = url.searchParams.get("dns");
      if (encoded === null) { res.writeHead(400); res.end(); return; }
      var query = Buffer.from(encoded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
      var question = _readQuestion(query);
      asked.push(question.name + "|" + question.type);

      var entry = table[question.name];
      var body;
      if (entry === undefined || entry === null || entry === ABSENT) {
        body = _message(question, 3, true, []);                 // RFC 1035 §4.1.1 NXDOMAIN
      } else if (entry === FAILING) {
        body = _message(question, 2, false, []);                // RFC 1035 §4.1.1 SERVFAIL
      } else {
        body = _message(question, 0, entry.authenticated !== false,
          _answersFor(entry, question.name, question.type));
      }
      res.writeHead(200, { "content-type": "application/dns-message" });
      res.end(body);
    });

  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  // A failed assertion throws past the close, and a listening socket
  // would then hold the runner open until something else killed it,
  // which reads as a hang rather than as the failure it is.
  server.unref();

  var caFile = null;
  if (typeof opts.caDir === "string" && opts.caDir.length > 0) {
    caFile = opts.caDir + "/dns-zone-ca.pem";
    nodeFs.writeFileSync(caFile, pair.caPem, "utf8");
  }

  return {
    url:    "https://127.0.0.1:" + server.address().port + "/dns-query",
    caPem:  pair.caPem,
    caFile: caFile,
    asked:  function () { return asked.slice(); },
    wasAsked: function (name, type) {
      return asked.indexOf(_key(name) + "|" + type) !== -1;
    },
    close:  function () { server.close(); },
  };
}

/**
 * The environment a spawned run needs to reach a server started above,
 * as the object a caller merges into the child's environment.
 */
function armedEnv(handle) {
  var env = {};
  env[ARMED_VAR] = handle.url;
  env[CA_VAR]    = handle.caFile;
  return env;
}

// Loaded into the run under test with `--require`, the way the quiet
// endpoint beside this file is. The guard is here so reading this module
// to get at the encoder does not repoint the reader's own resolver.
if (typeof process.env[ARMED_VAR] === "string" && process.env[ARMED_VAR].length > 0) {
  b.network.dns.useDnsOverHttps({
    url: process.env[ARMED_VAR],
    ca:  nodeFs.readFileSync(process.env[CA_VAR], "utf8"),
  });
}

module.exports = {
  // The path to hand `--require`, so a caller names this file by asking
  // it rather than by rebuilding the path and drifting from it.
  PRELOAD:   __filename,
  ARMED_VAR: ARMED_VAR,
  CA_VAR:    CA_VAR,
  ABSENT:    ABSENT,
  FAILING:   FAILING,
  start:     start,
  armedEnv:  armedEnv,
  TYPE:      Object.freeze({ a: TYPE_A, mx: TYPE_MX, txt: TYPE_TXT, tlsa: TYPE_TLSA }),
};
