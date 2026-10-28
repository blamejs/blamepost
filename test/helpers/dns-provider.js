// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A stand-in for the hosted DNS provider, on loopback and over TLS.
 *
 * It implements the envelope, the paging block and the error numbers the
 * real provider documents, so a refusal measured against it is the
 * refusal a real response produces rather than one a mock was told to
 * produce. Every response is built through `ok` and `fail`, which is what
 * keeps a test from asserting against a shape the provider never sends.
 *
 * It speaks TLS because the client has no cleartext mode and is not given
 * one for a test. Two ways to reach it are offered and they are not
 * interchangeable. A caller inside this process takes `agent`, which
 * carries the certificate authority directly. A caller that spawns the
 * shipped binary cannot hand an agent to a child process, so it takes
 * `caPem`, writes it to a file, and names that file in the child's
 * `NODE_EXTRA_CA_CERTS`.
 *
 * It records every request it receives, which is what lets a case that
 * asserts nothing was written measure that rather than assume it, and it
 * carries the forced conditions a caller needs to drive one refusal at a
 * time: a throttled reply with the interval the provider names, a server
 * error, a malformed envelope, an unauthorized token, a missing scope, a
 * record conflict, a pager that repeats a page, and a delete that answers
 * about a different record. `onRequest` composes any other reply from the
 * request as it arrived.
 *
 * It is here rather than inside one test file because two files drive it
 * and a second copy would be two answers to what the provider's envelope
 * looks like. Whichever copy somebody corrected, the other would keep
 * passing on the old shape.
 */

var https = require("node:https");

var certs = require("./certs");

// The zone identifier and the domain a caller gets when it names neither.
// Published rather than written into each caller, so the fixture zone and
// the zone the stand-in answers about are one value.
var ZONE_ID = "zone0123456789abcdef0123456789ab";
var DOMAIN  = "example.com";

/**
 * The provider's success envelope. `resultInfo` is the paging block, and
 * it is left off entirely when a caller does not name one, because an
 * absent block and an empty one are different answers to the client.
 */
function ok(result, resultInfo) {
  var body = { success: true, errors: [], messages: [], result: result };
  if (resultInfo) body.result_info = resultInfo;
  return body;
}

/**
 * The provider's failure envelope, carrying one numbered error. The
 * number is the provider's own, so a case that drives a refusal names the
 * number the real provider would attach rather than a code of its own.
 */
function fail(code, message) {
  return { success: false, errors: [{ code: code, message: message }], messages: [],
    result: null };
}

// The provider writes a TLSA record from its four fields in `data`, and
// answers with them there and in a formatted `content`. Returns the
// fields, null for a record of another type, and false for a TLSA write
// that does not carry them.
function tlsaFields(body) {
  if (!body || body.type !== "TLSA") return null;
  var d = body.data;
  if (!d || typeof d !== "object" || typeof d.usage !== "number" ||
      typeof d.selector !== "number" || typeof d.matching_type !== "number" ||
      typeof d.certificate !== "string" || d.certificate.length === 0) {
    return false;
  }
  return { usage: d.usage, selector: d.selector, matching_type: d.matching_type,
    certificate: d.certificate };
}

function tlsaContent(fields) {
  return fields.usage + "\t" + fields.selector + "\t" + fields.matching_type + "\t" +
    fields.certificate;
}

/**
 * Start one stand-in on an ephemeral loopback port.
 *
 * `records` seeds the zone, `zones` replaces the single zone it answers
 * about, and `domain` and `zoneId` name that zone when `zones` is left
 * alone. The returned handle carries the state the forced conditions are
 * set on, the base address, the two ways of trusting its certificate, a
 * reader for the writes it received, and `close`.
 */
async function start(opts) {
  opts = opts || {};
  var pair = await certs.pair();

  var domain = opts.domain || DOMAIN;
  var zoneId = opts.zoneId || ZONE_ID;

  var state = {
    records:   (opts.records || []).slice(),
    zones:     opts.zones || [{ id: zoneId, name: domain }],
    requests:  [],
    nextId:    1,
    mode:      "ok",
    failWrites: 0,
    writeCount: 0,
    onWrite:    null,
    onRequest:  null,
    throttleLeft: 0,
    serverErrorLeft: 0,
    duplicatePages: false,
    perPageCap: null,
  };

  function newId() {
    var id = "rec" + String(state.nextId);
    state.nextId += 1;
    while (id.length < 32) id += "0";
    return id;
  }

  var server = https.createServer({ cert: pair.cert, key: pair.key }, function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var raw = Buffer.concat(chunks).toString("utf8");
      var url = new URL(req.url, "https://127.0.0.1");
      var received = {
        method:  req.method,
        path:    url.pathname,
        query:   Object.fromEntries(url.searchParams.entries()),
        headers: req.headers,
        body:    raw,
      };
      state.requests.push(received);

      function send(status, payload, headers) {
        var text = typeof payload === "string" ? payload : JSON.stringify(payload);
        var head = { "content-type": "application/json" };
        Object.keys(headers || {}).forEach(function (k) { head[k] = headers[k]; });
        res.writeHead(status, head);
        res.end(text);
      }

      // A reply a caller composes from the request itself, for any method.
      // `onWrite` below reaches writes only; a provider that answers a read
      // with its own words, an envelope that contradicts itself, or the
      // caller's credential quoted back is a read as often as a write.
      if (state.onRequest) {
        var composed = state.onRequest(received);
        if (composed) { send(composed.status, composed.body, composed.headers); return; }
      }

      // Forced conditions, checked before the route so any endpoint can
      // be made to produce them.
      // A throttled response carries a body error number like any other,
      // and the number the provider attaches to one is not a number that
      // means "throttled". That is exactly why the client has to read
      // the status before the number.
      if (state.throttleLeft > 0) {
        state.throttleLeft -= 1;
        send(429, fail(10000, "rate limited"), { "retry-after": "1" });
        return;
      }
      if (state.serverErrorLeft > 0) {
        state.serverErrorLeft -= 1;
        send(503, fail(1000, "service unavailable"));
        return;
      }
      if (state.mode === "malformed") { send(200, "{\"nonsense\":true}"); return; }
      if (state.mode === "not-json") { send(200, "<html>not json</html>"); return; }
      if (state.mode === "empty-body") { send(200, ""); return; }
      if (state.mode === "unauthorized") { send(401, fail(10000, "Invalid API Token")); return; }
      if (state.mode === "bad-request") { send(400, fail(6003, "Invalid request headers")); return; }

      var isWrite = req.method === "POST" || req.method === "PUT" || req.method === "DELETE";
      if (state.mode === "no-scope" && isWrite) {
        send(403, fail(9109, "Unauthorized to access requested resource"));
        return;
      }
      if (isWrite && state.mode === "record-conflict" && req.method === "POST") {
        send(400, fail(81057, "Record already exists."));
        return;
      }
      if (isWrite) {
        state.writeCount += 1;
        // A test that needs one write to land and the next to refuse
        // says so here, rather than by reaching into the record array.
        var forced = state.onWrite ? state.onWrite(state.writeCount) : null;
        if (forced) { send(forced.status, forced.body); return; }
      }
      if (isWrite && state.failWrites > 0) {
        state.failWrites -= 1;
        send(500, fail(1000, "internal error"));
        return;
      }

      if (url.pathname === "/client/v4/user/tokens/verify") {
        send(200, ok({ id: "tok0000", status: state.mode === "inactive" ? "disabled" : "active" }));
        return;
      }

      if (url.pathname === "/client/v4/zones") {
        var wanted = url.searchParams.get("name");
        var matched = state.zones.filter(function (z) { return z.name === wanted; });
        send(200, ok(matched));
        return;
      }

      var listMatch = /^\/client\/v4\/zones\/([^/]+)\/dns_records$/.exec(url.pathname);
      if (listMatch) {
        if (req.method === "GET") {
          var type = url.searchParams.get("type");
          var name = url.searchParams.get("name");
          var found = state.records.filter(function (r) {
            if (type && r.type !== type) return false;
            if (name && r.name !== name) return false;
            return true;
          });
          var perPage = state.perPageCap ||
            parseInt(url.searchParams.get("per_page") || "100", 10);
          var page = parseInt(url.searchParams.get("page") || "1", 10);
          var totalPages = Math.max(1, Math.ceil(found.length / perPage));
          var slice = state.duplicatePages
            ? found.slice(0, perPage)
            : found.slice((page - 1) * perPage, page * perPage);
          send(200, ok(slice, {
            page: page, per_page: perPage, count: slice.length,
            total_count: found.length, total_pages: totalPages,
          }));
          return;
        }
        if (req.method === "POST") {
          var wanted2 = JSON.parse(raw);
          var tlsaCreated = tlsaFields(wanted2);
          if (tlsaCreated === false) {
            send(400, fail(1004, "DNS Validation Error: a TLSA record takes its value in data"));
            return;
          }
          var created = {
            id: newId(), type: wanted2.type, name: wanted2.name,
            content: wanted2.content,
            ttl: typeof wanted2.ttl === "number" ? wanted2.ttl : 300,
          };
          if (tlsaCreated) {
            created.data = tlsaCreated;
            created.content = tlsaContent(tlsaCreated);
          }
          if (typeof wanted2.priority === "number") created.priority = wanted2.priority;
          state.records.push(created);
          send(200, ok(created));
          return;
        }
      }

      var oneMatch = /^\/client\/v4\/zones\/([^/]+)\/dns_records\/([^/]+)$/.exec(url.pathname);
      if (oneMatch) {
        var id = oneMatch[2];
        var idx = state.records.findIndex(function (r) { return r.id === id; });
        if (idx === -1) { send(404, fail(81044, "Record does not exist")); return; }
        if (req.method === "PUT") {
          var body2 = JSON.parse(raw);
          var tlsaUpdated = tlsaFields(body2);
          if (tlsaUpdated === false) {
            send(400, fail(1004, "DNS Validation Error: a TLSA record takes its value in data"));
            return;
          }
          var updated = {
            id: id, type: body2.type, name: body2.name, content: body2.content,
            ttl: typeof body2.ttl === "number" ? body2.ttl : 300,
          };
          if (tlsaUpdated) {
            updated.data = tlsaUpdated;
            updated.content = tlsaContent(tlsaUpdated);
          }
          if (typeof body2.priority === "number") updated.priority = body2.priority;
          state.records[idx] = updated;
          send(200, ok(updated));
          return;
        }
        if (req.method === "DELETE") {
          state.records.splice(idx, 1);
          send(200, ok({ id: state.mode === "wrong-delete-id" ? "somethingelse" : id }));
          return;
        }
      }

      send(404, fail(7003, "Could not route to the requested resource"));
    });
  });

  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  var port = server.address().port;
  // A failed assertion throws past the close, and a listening socket
  // would then hold the runner open until something else killed it,
  // which reads as a hang rather than as the failure it is.
  server.unref();

  return {
    state:   state,
    port:    port,
    baseUrl: "https://127.0.0.1:" + port + "/client/v4",
    agent:   new https.Agent({ ca: pair.caPem }),
    // The same trust, in the form a spawned process can be given. An
    // agent cannot cross a process boundary; a file named in
    // NODE_EXTRA_CA_CERTS can.
    caPem:   pair.caPem,
    writes:  function () {
      return state.requests.filter(function (r) {
        return r.method === "POST" || r.method === "PUT" || r.method === "DELETE";
      });
    },
    close:   function () { server.close(); },
  };
}

module.exports = {
  start:   start,
  ok:      ok,
  fail:    fail,
  ZONE_ID: ZONE_ID,
  DOMAIN:  DOMAIN,
};
