// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-services.js
 *
 * Pre-test gate. Confirms every listener the integration suite talks to is
 * bound and answering AS THIS SERVER before scripts/test-integration.js spawns
 * a single test file. A partial-up state fails loudly here instead of surfacing
 * as a dozen confusing per-file connection errors. That state is a process that
 * started while its MX listener never bound, because the DNS-posture gate was
 * not acknowledged.
 *
 * ## A port that answers is not this server answering
 *
 * Accepting whatever replies on the right port is a bad assumption on a
 * developer machine rather than a pedantic one.
 * Measured here: the http row was answered 200 by another project's container
 * holding the same port, the https row by that container's TLS, and the
 * implicit-TLS row on 993 by a scratch proxy. This server's own browser
 * surface, on a port it had been moved to, was never contacted at all. The gate
 * printed that every required endpoint was responding. Every statement in that
 * report was true about the machine and none of it was about blamepost.
 *
 * A stale copy of this server is the same failure wearing better clothes: an
 * orphaned process from a previous run holds the port, answers the protocol
 * perfectly, and serves a build and a data directory that are not the ones
 * under test.
 *
 * So every probe reads something only THIS server emits, and a probe that
 * cannot identify what answered reports that as a failure rather than as a
 * pass. There are two such signals and they are not interchangeable:
 *
 *   - The mail listeners put the product name into the greeting they compose
 *     in lib/mail/listeners.js, next to the operator's own host name and the
 *     protocol word that differs per listener. Matching the whole shape also
 *     proves the RIGHT listener took the port: a submission listener answering
 *     on 25 is a real misconfiguration and it is one this row can see.
 *   - The browser surface answers its health path with the running build's
 *     version, which is compared against package.json. A stranger cannot
 *     produce it, and a stale copy of this server produces the wrong one,
 *     which is the case a name check alone would miss.
 *
 * An implicit-TLS port is therefore a handshake AND the greeting behind it. A
 * handshake alone proves that something completed TLS, which every reverse
 * proxy, load balancer and terminator on the machine also does.
 *
 * ## Where the ports come from
 *
 * The numbers below are the protocol defaults, so an operator reading this
 * table is reading the same values their firewall rules and DNS records carry.
 * The two an operator routinely moves are the browser surface's, and they are
 * read from the same environment the server reads them from, so a gate pointed
 * at a server told to listen elsewhere follows it rather than probing the port
 * a stranger inherited.
 *
 * Optional listeners are reported but never fail the gate: POP3 ships off by
 * default, the HTTPS port is bound only when TLS terminates in the server
 * rather than in front of it, and nothing in this server binds 993.
 *
 * Environment:
 *   BLAMEPOST_SERVICE_HOST              comma-separated hosts to probe. Default
 *                                       127.0.0.1. Set "127.0.0.1,::1" to prove
 *                                       both address families, or a container
 *                                       name when the suite runs beside the
 *                                       server. Note that the browser surface
 *                                       answers its detailed health only to a
 *                                       loopback peer, so a row probed by name
 *                                       from elsewhere can be reached and not
 *                                       identified, which is reported as a
 *                                       failure and not as a pass.
 *   BLAMEPOST_HTTP_PORT                 the browser surface's port, read from
 *   BLAMEPOST_HTTPS_PORT                the same variables the server reads.
 *   BLAMEPOST_SERVICE_PORTS             per-service override, "name=port" pairs
 *                                       separated by commas, for a deployment
 *                                       that moved a mail port or for a test
 *                                       pointing this gate at a fixture.
 *   BLAMEPOST_SERVICE_PROBE_TIMEOUT_MS  per-probe timeout. Default 4000.
 *
 * Exit codes:
 *   0  every required listener answered and was identified as this server
 *   1  one or more required listeners are down or unidentified (table printed)
 *   2  the gate itself could not run, or ran and identified nothing: an unknown
 *      service name, an unreadable override, a filter combination that left no
 *      endpoint to probe, or a probe list of optional listeners that were all
 *      absent. None of those is a stack that is up, and a run that contacted no
 *      listener must not clear the suite behind it to start.
 *
 * Usage:
 *   node scripts/check-services.js                  every listener
 *   node scripts/check-services.js imap imaps       a named subset
 *   node scripts/check-services.js --plain          skip the implicit-TLS ports
 *   node scripts/check-services.js --tls            only the implicit-TLS ports
 *   node scripts/check-services.js --required       skip the optional listeners
 */

var net  = require("node:net");
var http = require("node:http");
var https = require("node:https");
var tls  = require("node:tls");

var pkg = require("../package.json");

var examinedCounts = require("./examined-counts.js");

// ---------------------------------------------------------------------------
// What only this server says
// ---------------------------------------------------------------------------

// The greeting each mail listener composes in lib/mail/listeners.js, as the
// shape a reply has to match to count as this server.
//
// Written here rather than imported, because importing would pull the whole
// framework and the store into a gate that runs before anything is known to be
// up. The link is kept by test/layer-2-integration/service-gate-identity.test.js,
// which reads the greetings that module actually composes and requires each one
// to satisfy the pattern named here. A greeting reworded on one side and not
// the other is a failing test rather than a gate that quietly stopped
// recognizing its own server.
//
// The host name is matched as "some token" rather than pinned, because it is
// the operator's and this gate does not know it. What is pinned is the pair
// that is ours: the protocol word, which differs per listener, and the product
// name after it.
var GREETING_IDENTITY = Object.freeze({
  mx:          /^220[ -]\S+ ESMTP blamepost\b/m,
  submission:  /^220[ -]\S+ Submission blamepost\b/m,
  submissions: /^220[ -]\S+ Submission blamepost\b/m,
  imap:        /^\* OK (?:\[[^\]]*\] )?\S+ IMAP4rev2 blamepost\b/m,
  imaps:       /^\* OK (?:\[[^\]]*\] )?\S+ IMAP4rev2 blamepost\b/m,
  pop3:        /^\+OK \S+ POP3 blamepost\b/m,
  pop3s:       /^\+OK \S+ POP3 blamepost\b/m,
  managesieve: /^OK "\S+ ManageSieve blamepost\b/m,
});

// What the browser surface has to report for the row to count. The version is
// the build's own, not a setting, so a stale process left holding the port
// answers with the version it was built from and is caught by the comparison
// rather than by nobody.
var EXPECTED_VERSION = pkg.version;

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// One entry per port. `kind` says how much of the protocol the probe speaks;
// every kind except `tcp` ends with something only this server could have
// said.
//
// `imaps` and `pop3s` are not required and never were bindable: this server's
// mailbox listeners negotiate TLS in band, and nothing here takes 993 or 995.
// A required probe for a port this server does not bind can only pass when
// something else is holding it, which is the opposite of what a gate is for.
var BASE_SERVICES = [
  { name: "mx",          port:   25, kind: "smtp",        label: "SMTP 220 greeting",      group: "plain", required: true  },
  { name: "submission",  port:  587, kind: "smtp",        label: "SMTP 220 greeting",      group: "plain", required: true  },
  { name: "submissions", port:  465, kind: "smtps",       label: "implicit TLS + 220",     group: "tls",   required: true  },
  { name: "imap",        port:  143, kind: "imap",        label: "IMAP untagged greeting", group: "plain", required: true  },
  { name: "managesieve", port: 4190, kind: "managesieve", label: "capability greeting",    group: "plain", required: true  },
  { name: "http",        port: 8080, kind: "http",        label: "GET /healthz",           group: "plain", required: true,
    httpPath: "/healthz", portEnv: "BLAMEPOST_HTTP_PORT" },

  // Not bound by this server. Present so an operator who put a terminator in
  // front of a mailbox listener can see what is behind it, and absent is the
  // shipped configuration rather than a fault.
  { name: "imaps",       port:  993, kind: "imaps",       label: "implicit TLS + IMAP",    group: "tls",   required: false },

  // Off by default. Their absence is the shipped configuration, not a fault.
  { name: "pop3",        port:  110, kind: "pop3",        label: "POP3 +OK greeting",      group: "plain", required: false },
  { name: "pop3s",       port:  995, kind: "pop3s",       label: "implicit TLS + POP3",    group: "tls",   required: false },
  { name: "https",       port: 8443, kind: "https",       label: "TLS + GET /healthz",     group: "tls",   required: false,
    httpPath: "/healthz", portEnv: "BLAMEPOST_HTTPS_PORT" },
];

function _hosts() {
  return String(process.env.BLAMEPOST_SERVICE_HOST || "127.0.0.1")
    .split(",")
    .map(function (h) { return h.trim(); })
    .filter(function (h) { return h.length > 0; });
}

// An IPv6 literal has to be bracketed inside a URL, and nowhere else.
function _bracketHost(host) {
  return host.indexOf(":") !== -1 ? "[" + host + "]" : host;
}

// Pin the address family off the host literal. Left to resolution, a name that
// answers on one family and not the other reports whichever the resolver
// returned first, which is not a probe of anything in particular.
function _family(host) { return host.indexOf(":") !== -1 ? 6 : 4; }

function _readPort(text, where) {
  var port = Number(text);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    var err = new Error(where + " must be a TCP port between 1 and 65535, got " +
      JSON.stringify(text));
    err.gateInput = true;
    throw err;
  }
  return port;
}

// The per-service override, read once. Bad input stops the gate rather than
// being ignored: a typo that silently left the default in place would probe
// the port the operator was trying to move away from and report on whatever
// answered there.
function _portOverrides() {
  var raw = process.env.BLAMEPOST_SERVICE_PORTS;
  if (typeof raw !== "string" || raw.trim().length === 0) return {};
  var known = {};
  BASE_SERVICES.forEach(function (s) { known[s.name] = true; });
  var out = {};
  raw.split(",").forEach(function (pair) {
    var text = pair.trim();
    if (text.length === 0) return;
    var at = text.indexOf("=");
    if (at === -1) {
      var err = new Error("BLAMEPOST_SERVICE_PORTS entry " + JSON.stringify(text) +
        " is not a name=port pair");
      err.gateInput = true;
      throw err;
    }
    var name = text.slice(0, at).trim();
    if (!known[name]) {
      var unknown = new Error("BLAMEPOST_SERVICE_PORTS names an unknown service " +
        JSON.stringify(name) + "; valid: " + Object.keys(known).join(", "));
      unknown.gateInput = true;
      throw unknown;
    }
    out[name] = _readPort(text.slice(at + 1).trim(), "BLAMEPOST_SERVICE_PORTS " + name);
  });
  return out;
}

// Where a service actually is: the protocol default, unless the server was
// told otherwise through the same variable it reads, unless this gate was
// pointed somewhere explicitly.
function _portFor(svc, overrides) {
  if (Object.prototype.hasOwnProperty.call(overrides, svc.name)) return overrides[svc.name];
  if (svc.portEnv) {
    var named = process.env[svc.portEnv];
    if (typeof named === "string" && named.trim().length > 0) {
      return _readPort(named.trim(), svc.portEnv);
    }
  }
  return svc.port;
}

function buildServices() {
  var overrides = _portOverrides();
  var services = [];
  BASE_SERVICES.forEach(function (base) {
    _hosts().forEach(function (host) {
      var port = _portFor(base, overrides);
      var entry = {
        name:     base.name,
        host:     host,
        port:     port,
        kind:     base.kind,
        label:    base.label,
        group:    base.group,
        required: base.required,
        identity: GREETING_IDENTITY[base.name] || null,
        family:   _family(host) === 6 ? "v6" : "v4",
        moved:    port !== base.port ? base.port : null,
      };
      if (base.httpPath) {
        entry.httpPath = base.httpPath;
        entry.httpUrl = (base.kind === "https" ? "https://" : "http://") +
          _bracketHost(host) + ":" + port + base.httpPath;
      }
      services.push(entry);
    });
  });
  return services;
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

function probeTcp(host, port, timeoutMs) {
  return new Promise(function (resolve) {
    var sock = net.connect({ host: host, port: port, family: _family(host) });
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) { /* already gone */ }
      resolve({ ok: false, reason: "tcp timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    sock.once("connect", function () {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.end(); } catch (_e) { /* already gone */ }
      resolve({ ok: true });
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ok: false, reason: (err && err.code) || (err && err.message) || String(err) });
    });
  });
}

// One greeting reader for every line-oriented mail protocol, over a socket the
// caller opened. `accept` decides from the bytes received so far: true when the
// greeting is complete and correct FOR THE PROTOCOL, false when it is complete
// and wrong, and undefined while more bytes are still needed. Whether the
// greeting is THIS SERVER'S is decided afterwards, against `identity`, because
// the two failures need different sentences: a wrong protocol is the wrong kind
// of server, and a right protocol with a foreign greeting is somebody else's.
//
// `farewell` is written before the socket closes so the server records a clean
// disconnect rather than an abort. A probe that leaves a torn-down session
// behind pollutes the very logs it is about to be debugged from.
function readGreeting(sock, opts) {
  return new Promise(function (resolve) {
    var text = "";
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) { /* already gone */ }
      resolve({
        ok: false,
        reason: opts.protocol + " greeting timeout after " + opts.timeoutMs + "ms" +
                (text.length > 0 ? " (partial: " + JSON.stringify(text.slice(0, 60)) + ")" : ""),
      });
    }, opts.timeoutMs);
    sock.on("data", function (chunk) {
      if (done) return;
      text += chunk.toString("utf8");
      var verdict = opts.accept(text);
      if (verdict === undefined) return;
      done = true;
      clearTimeout(timer);
      if (verdict && opts.farewell) {
        try { sock.write(opts.farewell); } catch (_e) { /* closing anyway */ }
      }
      try { sock.end(); } catch (_e) { /* already gone */ }
      resolve(_verdict(verdict, text, opts));
    });
    sock.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({
        ok: false,
        reason: opts.protocol + " " + (opts.transport || "tcp") + ": " +
          ((err && err.code) || (err && err.message) || String(err)),
      });
    });
  });
}

function _verdict(protocolOk, text, opts) {
  var first = text.split(/\r?\n/)[0];
  if (!protocolOk) {
    return { ok: false, reason: opts.protocol + " greeting was " + JSON.stringify(first.slice(0, 60)) };
  }
  if (opts.identity && !opts.identity.test(text)) {
    return {
      ok: false,
      reason: "something answered " + opts.protocol + " here and it is not this server. " +
        "Wanted a greeting matching " + String(opts.identity) + ", got " +
        JSON.stringify(first.slice(0, 80)),
    };
  }
  return { ok: true, detail: first.slice(0, 60) };
}

function probeGreeting(opts) {
  var sock = net.connect({ host: opts.host, port: opts.port, family: _family(opts.host) });
  return readGreeting(sock, opts);
}

// The implicit-TLS form: complete the handshake, THEN read the protocol
// greeting behind it. Stopping at the handshake accepts every terminator,
// reverse proxy and unrelated TLS service on the machine.
function probeTlsGreeting(opts) {
  var sock = tls.connect({
    host: opts.host,
    port: opts.port,
    family: _family(opts.host),
    // The gate asks whether the listener is there and whose it is, not whether
    // its certificate chains: a local run against a development certificate is
    // a listener that is up. Chain validation is the integration suite's
    // assertion to make, against a trust anchor it chose. What replaces it here
    // is the greeting behind the handshake, which a stranger cannot forge by
    // presenting any certificate at all.
    rejectUnauthorized: false,
    // SNI is legal for hostnames only, never for an IP literal.
    servername: net.isIP(opts.host) ? undefined : opts.host,
  });
  var reading = readGreeting(sock, Object.assign({ transport: "tls" }, opts));
  return new Promise(function (resolve) {
    sock.once("secureConnect", function () {
      var protocol = sock.getProtocol() || "?";
      var cipher = (sock.getCipher() && sock.getCipher().name) || "?";
      reading.then(function (r) {
        if (!r.ok) return resolve(r);
        resolve({ ok: true, detail: protocol + "/" + cipher + " " + r.detail });
      });
    });
    reading.then(function (r) { if (!r.ok) resolve(r); });
  });
}

// RFC 5321 sec. 3.1 defines the greeting as a 220 reply, possibly multi-line.
// The last line of a reply carries a space after the code; a hyphen means more
// lines follow, so a continuation is a reason to keep reading rather than a
// verdict.
function acceptSmtp(text) {
  if (/^220 [^\r\n]*\r?\n/m.test(text)) return true;
  if (/^220-/.test(text)) return undefined;
  if (/^\d{3}[ -]/.test(text)) return false;   // a reply, but not a greeting
  return undefined;
}

// Under RFC 9051 sec. 7.1.1 the server opens with an untagged OK, PREAUTH or
// BYE. BYE is a server that is up and refusing the connection, which is not a
// listener the suite can use, so it is a failure rather than a pass.
function acceptImap(text) {
  if (/^\* (OK|PREAUTH)\b/.test(text)) return true;
  if (/^\* BYE\b/.test(text)) return false;
  if (/\r?\n/.test(text)) return false;
  return undefined;
}

// Under RFC 1939 sec. 4 the greeting is a +OK status indicator; -ERR is a
// server that answered and declined.
function acceptPop3(text) {
  if (/^\+OK\b/.test(text)) return true;
  if (/^-ERR\b/.test(text)) return false;
  if (/\r?\n/.test(text)) return false;
  return undefined;
}

// Under RFC 5804 sec. 1.7 the server greets with capability lines and closes
// the set with an OK response. Reading through to that OK proves the whole
// greeting arrived; stopping at the first capability line would accept a
// server that started talking and stopped.
function acceptManagesieve(text) {
  if (/^OK\b/m.test(text)) return true;
  if (/^(NO|BYE)\b/m.test(text)) return false;
  return undefined;
}

var GREETINGS = Object.freeze({
  smtp:        { protocol: "smtp",        accept: acceptSmtp,        farewell: "QUIT\r\n" },
  smtps:       { protocol: "smtp",        accept: acceptSmtp,        farewell: "QUIT\r\n" },
  imap:        { protocol: "imap",        accept: acceptImap,        farewell: "a1 LOGOUT\r\n" },
  imaps:       { protocol: "imap",        accept: acceptImap,        farewell: "a1 LOGOUT\r\n" },
  pop3:        { protocol: "pop3",        accept: acceptPop3,        farewell: "QUIT\r\n" },
  pop3s:       { protocol: "pop3",        accept: acceptPop3,        farewell: "QUIT\r\n" },
  managesieve: { protocol: "managesieve", accept: acceptManagesieve, farewell: "LOGOUT\r\n" },
});

var TLS_KINDS = Object.freeze({ smtps: true, imaps: true, pop3s: true });

// The browser surface, identified by the build it reports rather than by
// having answered at all.
//
// The health endpoint returns its detail only to a loopback peer, which is a
// deliberate property of that endpoint and not something to work around here.
// So a minimal answer from a peer that is not on loopback is reported as
// reached-but-unidentified, which is a failure: a gate that cannot tell who
// answered has not gated, and calling it a pass is the exact fault this
// rewrite exists for.
function probeHttp(svc, timeoutMs) {
  var agent = svc.kind === "https" ? https : http;
  return new Promise(function (resolve) {
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      done = true;
      try { req.destroy(); } catch (_e) { /* already gone */ }
      resolve({ ok: false, reason: "http timeout after " + timeoutMs + "ms" });
    }, timeoutMs);
    var options = { rejectUnauthorized: false };
    var req = agent.get(svc.httpUrl, options, function (res) {
      var body = "";
      res.on("data", function (chunk) { body += chunk.toString("utf8"); });
      res.on("end", function () {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(_httpVerdict(svc, res.statusCode, body));
      });
    });
    req.once("error", function (err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ok: false, reason: (err && err.code) || (err && err.message) || String(err) });
    });
  });
}

function _httpVerdict(svc, statusCode, body) {
  var quoted = JSON.stringify(body.slice(0, 120));
  if (!(statusCode >= 200 && statusCode < 400)) {
    return { ok: false, reason: "HTTP " + statusCode + " " + quoted };
  }
  var payload;
  try { payload = JSON.parse(body); }
  catch (_e) { payload = null; }
  if (payload === null || typeof payload !== "object") {
    return {
      ok: false,
      reason: "HTTP " + statusCode + " and the body is not this server's health report: " + quoted,
    };
  }
  if (typeof payload.version !== "string") {
    return {
      ok: false,
      reason: "HTTP " + statusCode + " from something that answered " + svc.httpPath +
        " without saying what it is. This server reports its build there, and reports it " +
        "only to a peer on loopback, so probe from the host the server runs on " +
        "(BLAMEPOST_SERVICE_HOST) rather than by name from elsewhere. Body: " + quoted,
    };
  }
  if (payload.version !== EXPECTED_VERSION) {
    return {
      ok: false,
      reason: "this is blamepost " + payload.version + " and the tree under test is " +
        EXPECTED_VERSION + ". A process left over from an earlier run answers the port " +
        "and serves a different build and data directory.",
    };
  }
  return { ok: true, detail: "HTTP " + statusCode + " blamepost " + payload.version };
}

async function probeService(svc, timeoutMs) {
  if (svc.kind === "tcp") return await probeTcp(svc.host, svc.port, timeoutMs);
  if (svc.kind === "http" || svc.kind === "https") return await probeHttp(svc, timeoutMs);
  var greeting = GREETINGS[svc.kind];
  if (!greeting) return { ok: false, reason: "unknown probe kind: " + svc.kind };
  var opts = {
    host:      svc.host,
    port:      svc.port,
    timeoutMs: timeoutMs,
    protocol:  greeting.protocol,
    accept:    greeting.accept,
    farewell:  greeting.farewell,
    identity:  svc.identity,
  };
  return TLS_KINDS[svc.kind] ? await probeTlsGreeting(opts) : await probeGreeting(opts);
}

function _padEnd(s, w) {
  s = String(s);
  return s.length >= w ? s : s + new Array(w - s.length + 1).join(" ");
}

async function main() {
  var args = process.argv.slice(2);
  var skipTls      = args.indexOf("--plain")    !== -1;
  var onlyTls      = args.indexOf("--tls")      !== -1;
  var onlyRequired = args.indexOf("--required") !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  var services;
  try { services = buildServices(); }
  catch (err) {
    if (!err.gateInput) throw err;
    console.error("[check-services] " + err.message);
    process.exit(2);
    return;
  }

  var targets = services;
  if (skipTls)      targets = targets.filter(function (s) { return s.group !== "tls"; });
  if (onlyTls)      targets = targets.filter(function (s) { return s.group === "tls"; });
  if (onlyRequired) targets = targets.filter(function (s) { return s.required; });
  if (named.length > 0) {
    var validNames = {};
    services.forEach(function (s) { validNames[s.name] = true; });
    var missing = named.filter(function (n) { return !validNames[n]; });
    if (missing.length > 0) {
      console.error("[check-services] unknown service name(s): " + missing.join(", "));
      console.error("[check-services] valid: " + Object.keys(validNames).join(", "));
      process.exit(2);
      return;
    }
    var nameSet = {};
    named.forEach(function (n) { nameSet[n] = true; });
    targets = targets.filter(function (s) { return nameSet[s.name]; });
  }

  // Four filters can empty this list, and an empty list probes nothing and
  // then reports that nothing was down. That verdict is what the interop
  // suite waits on: this gate exists so a partial-up stack fails once here
  // instead of as a dozen connection errors behind it, and a gate that
  // cleared the suite to start having contacted no listener at all hands it
  // exactly the confusing failure it was put in front of.
  //
  // Both ways of getting here are the same refusal. `--tls --plain` is a
  // pair of filters that cannot both be satisfied, which is an operator
  // asking for a contradiction; a service table that no longer produces a
  // row the surviving filter matches is the table having moved out from
  // under the filter. Neither is a stack that is up, so neither reads as one.
  if (targets.length === 0) {
    console.error("[check-services] no endpoint left to probe: the " + services.length +
                  " service(s) this gate knows about were all filtered out.");
    console.error("[check-services] probing nothing and finding nothing down is not a stack " +
                  "that is up. Drop the filter that emptied the list, or name the services to " +
                  "probe. `--tls` and `--plain` select disjoint groups and cannot be combined.");
    process.exit(2);
    return;
  }

  var timeoutMs = Number(process.env.BLAMEPOST_SERVICE_PROBE_TIMEOUT_MS) || 4000;
  console.log("[check-services] probing " + targets.length + " endpoint" +
              (targets.length === 1 ? "" : "s") + " on " + _hosts().join(", ") +
              " as blamepost " + EXPECTED_VERSION + "...");

  var results = await Promise.all(targets.map(function (svc) {
    return probeService(svc, timeoutMs).then(function (r) {
      return { svc: svc, result: r };
    });
  }));

  var down = 0;
  var optionalDown = 0;
  var identified = 0;
  results.forEach(function (entry) {
    var svc = entry.svc;
    var hostStr = svc.family === "v6"
      ? "[" + svc.host + "]:" + svc.port
      : svc.host + ":" + svc.port;
    if (svc.moved !== null) hostStr += " (was " + svc.moved + ")";
    var line = "  " + _padEnd(svc.name + " (" + svc.family + ")", 20) +
               _padEnd(hostStr, 28) +
               _padEnd(svc.label, 26);
    if (entry.result.ok) {
      identified += 1;
      console.log(line + "OK" + (entry.result.detail ? "  " + entry.result.detail : ""));
      return;
    }
    if (!svc.required) {
      optionalDown += 1;
      console.log(line + "absent (optional): " + entry.result.reason);
      return;
    }
    down += 1;
    console.error(line + "DOWN: " + entry.result.reason);
  });

  console.log("");
  // The number that would have to move for this gate to be doing its job is
  // how many endpoints were identified as this server, not how many answered.
  // The old summary counted the latter and that is what let a stranger's
  // container and a scratch proxy be reported as a stack that was up.
  // Nothing down and nothing identified either. `down` counts REQUIRED
  // endpoints that failed, so a probe list made only of optional listeners
  // that are all absent takes it to zero without a single row having been
  // this server: POP3 ships off, 993 and 995 are bound by nothing on any
  // setting, and HTTPS is bound only when TLS terminates in the process. The
  // sentence above then reports that zero endpoints answered as blamepost and
  // exits 0, which is the count contradicting the verdict beside it.
  //
  // The number that has to move is `identified`, which is the number this
  // gate's own summary already chose as the one that matters. Nothing having
  // answered as this server is the same finding whether a required row failed
  // or no required row was probed at all.
  var verdict;
  if (down === 0 && identified === 0) {
    console.error("[check-services] no endpoint answered AS blamepost " + EXPECTED_VERSION +
                  ", and no required endpoint was probed to say so" +
                  (optionalDown > 0 ? " (" + optionalDown + " optional listener(s) absent)" : "") + ".");
    console.error("[check-services] every row probed was optional and absent, so this run " +
                  "identified nothing and proved nothing. Probe a required listener, or bring " +
                  "the stack up with:");
    console.error("  docker compose up -d --wait");
    verdict = 2;
  } else if (down === 0) {
    console.log("[check-services] " + identified + " endpoint(s) answered AS blamepost " +
                EXPECTED_VERSION +
                (optionalDown > 0 ? " (" + optionalDown + " optional listener(s) absent)" : ""));
    verdict = 0;
  } else {
    console.error("[check-services] " + down + " required endpoint(s) unreachable or not this server");
    console.error("[check-services] bring the stack up with:");
    console.error("  docker compose up -d --wait");
    console.error("[check-services] a listener that never bound is usually the DNS-posture gate:");
    console.error("  BLAMEPOST_DNS_ACKNOWLEDGED must be \"1\" before the MX listener binds.");
    console.error("[check-services] a port answered by something else is usually another stack:");
    console.error("  check what already holds it, and move this server's ports with " +
                  "BLAMEPOST_HTTP_PORT / BLAMEPOST_HTTPS_PORT (this gate follows them).");
    verdict = 1;
  }

  // Last, after every line of the report, because the counts are read from
  // the end of what a gate printed. Two units, because they empty for
  // different reasons and only one of them is about the wire: a probe list
  // its own filters emptied never reached a socket, and a list that reached
  // every socket while nothing answered as this server reached the wire and
  // proved nothing about who was on it.
  //
  // The verdict is not overwritten by the publish. A required listener that
  // is down is exit 1 and a run that identified nothing is exit 2, and those
  // ask different things of an operator; collapsing either into the other
  // because a unit came back empty would lose the distinction the codes
  // exist to carry.
  var published = examinedCounts.publish([
    { unit: "probed-endpoints",     n: targets.length },
    { unit: "identified-endpoints", n: identified },
  ], { tag: "[check-services]" });

  process.exit(verdict !== 0 ? verdict : published);
}

module.exports = {
  BASE_SERVICES:     BASE_SERVICES,
  GREETING_IDENTITY: GREETING_IDENTITY,
  buildServices:     buildServices,
};

if (require.main === module) {
  main().catch(function (err) {
    console.error("[check-services] script error: " + ((err && err.stack) || err));
    process.exit(2);
  });
}
