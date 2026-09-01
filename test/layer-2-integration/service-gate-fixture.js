// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Listeners that are not this server, for the case that proves the
 * service gate can tell.
 *
 * `scripts/check-services.js` decides whether the stack is up. The way
 * it used to be wrong was to accept whatever answered on the right
 * port, so the thing it has to be shown is a port answering with
 * something plausible and foreign: another MTA's SMTP banner, another
 * mailbox server's IMAP greeting, a health endpoint belonging to
 * somebody else, and a bare TLS terminator that completes a handshake
 * and says nothing at all. Each is a real shape that has held one of
 * these ports on a working developer machine.
 *
 * It runs as its own process for a plain reason: a listener bound
 * inside the test process is not reachable from the gate the test
 * spawns on every machine, and a fixture that works in one process
 * layout and hangs in another is a flake waiting for a busy runner. A
 * child binds; the gate is another child; both are ordinary processes
 * connecting over loopback.
 *
 * Not a test file. `test/smoke.js` runs `*.test.js`, so this is picked
 * up by nothing and is spawned by name.
 *
 * Protocol: argv[2] is a JSON array of listener specs. Each is
 *
 *   { kind: "line",  text }   plain TCP, writes `text` on accept
 *   { kind: "tls",   text }   TLS, writes `text` once the handshake is up
 *   { kind: "hush" }          TLS, completes the handshake and says nothing
 *   { kind: "http",  body }   HTTP, answers any request 200 with `body`
 *
 * argv[3] and argv[4] are the certificate and key files the TLS kinds
 * present. `PORTS <json array>` goes to stdout once every listener is
 * bound, in the order the specs were given. The process runs until it
 * is killed.
 *
 * Run standalone: node test/layer-2-integration/service-gate-fixture.js '[{"kind":"line","text":"220 x\r\n"}]'
 */

var nodeFs   = require("node:fs");
var nodeHttp = require("node:http");
var nodeNet  = require("node:net");
var nodeTls  = require("node:tls");

function _tlsOptions() {
  var certFile = process.argv[3];
  var keyFile  = process.argv[4];
  if (!certFile || !keyFile) {
    throw new TypeError("service-gate-fixture: a TLS listener was asked for and no " +
      "certificate and key were named. Pass them as argv[3] and argv[4].");
  }
  return { cert: nodeFs.readFileSync(certFile), key: nodeFs.readFileSync(keyFile) };
}

// A socket error here is the probe hanging up, which is what a probe
// does the moment it has read the greeting. It is the ordinary end of
// every connection this fixture serves, not a fault.
function _ignoreHangup(socket) {
  socket.on("error", function () { /* the probe closed first */ });
}

function _build(spec) {
  if (spec.kind === "line") {
    return nodeNet.createServer(function (socket) {
      _ignoreHangup(socket);
      socket.write(spec.text);
    });
  }
  if (spec.kind === "tls") {
    return nodeTls.createServer(_tlsOptions(), function (socket) {
      _ignoreHangup(socket);
      socket.write(spec.text);
    });
  }
  if (spec.kind === "hush") {
    // The terminator shape. It completes TLS and never speaks the
    // protocol behind it, which is exactly what a gate that stopped at
    // the handshake used to record as a listener that was up.
    return nodeTls.createServer(_tlsOptions(), function (socket) {
      _ignoreHangup(socket);
    });
  }
  if (spec.kind === "http") {
    return nodeHttp.createServer(function (req, res) {
      res.writeHead(200, {
        "Content-Type":   "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(spec.body),
      });
      res.end(spec.body);
    });
  }
  throw new TypeError("service-gate-fixture: unknown listener kind " + JSON.stringify(spec.kind));
}

function main() {
  var specs = JSON.parse(process.argv[2] || "[]");
  if (!Array.isArray(specs) || specs.length === 0) {
    throw new TypeError("service-gate-fixture: argv[2] must be a non-empty JSON array of specs");
  }
  var servers = specs.map(_build);
  var ports = new Array(specs.length);
  var pending = specs.length;
  servers.forEach(function (server, i) {
    server.on("tlsClientError", function () { /* a probe that hung up mid-handshake */ });
    server.listen(0, "127.0.0.1", function () {
      ports[i] = server.address().port;
      pending -= 1;
      // Announced only once EVERY listener is bound. A gate started
      // against a half-bound fixture would report the unbound half as
      // a server that is down, which is a true statement about the
      // fixture and the wrong answer to the question being asked.
      if (pending === 0) console.log("PORTS " + JSON.stringify(ports));
    });
  });
}

main();
