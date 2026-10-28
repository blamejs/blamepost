// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One reader holding one session, driving the browser surface the way a
 * browser drives it.
 *
 * Cookies come back on the next request, redirects are followed by hand
 * so a refusal is observed where it happens rather than after a hop,
 * and the CSRF token is taken off the rendered form the way a browser
 * takes it off the page. A reader that never returns its cookies is a
 * reader whose isolation was never tested: it is refused at the door
 * for a reason that has nothing to do with whose mail it asked for.
 *
 * This lives beside the other shared helpers because three files now
 * need it, and because a second copy is how two transcripts start
 * disagreeing about what a sign in looks like.
 *
 * It speaks over `node:http` and `node:https` rather than `fetch` for
 * one reason, and the reason is load bearing. The session cookie
 * carries the `__Host-` prefix and the `Secure` attribute, so the only
 * transport a real browser would keep it over is TLS, and verifying a
 * certificate issued by a run's own authority needs a client that
 * accepts a CA. Verification stays on: a reader that skipped it would
 * pass against a listener presenting anything at all.
 *
 * ## The HTTP version is part of what is being measured
 *
 * `node:https` speaks HTTP/1.1 and sends a `Host` header. The framework
 * binds every TLS listener with `http2.createSecureServer` and
 * `ALPNProtocols: ["h2", "http/1.1"]`, so a browser negotiates h2 and
 * sends `:authority` and NO `Host` header at all. Those are different
 * requests, and a gate that derives this server's own origin from
 * `Host` sees a value over one and `undefined` over the other.
 *
 * So `opts.http2` picks the transport, and a reader measuring anything
 * about origins, hosts or the request lifecycle has to drive both. The
 * default stays HTTP/1.1 because that is what the existing vectors were
 * written against; a case about what a BROWSER gets asks for h2, which
 * is the only version a browser will use here.
 *
 * Every response comes back as `{ status, body, location, headers,
 * setCookie, tls }`. Nothing is followed and nothing is retried, so a
 * 302 is a value to assert on rather than a hop that hides which route
 * answered.
 *
 * Validation posture: these are entry points a test author calls
 * directly, so bad input throws rather than degrading to a default.
 */

var nodeHttp  = require("node:http");
var nodeHttps = require("node:https");
var nodeHttp2 = require("node:http2");

// How long one request may go unanswered before it is reported as a hang.
// A deadline rather than a wait: a request that answers returns at once.
// It is sized for the coverage run, where every request takes 3 to 5
// times as long as it does uninstrumented.
var DEFAULT_TIMEOUT_MS = 20000;

// A user agent string, because the bot guard in the request lifecycle
// reads one and a request carrying none is refused for a reason that
// has nothing to do with the route under test.
var DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) blamepost test reader";

// The capability URNs a JMAP client sends. Mail and submission are both
// advertised by this server's session document, so a client that omits
// one is testing a narrower request than any real client sends.
var DEFAULT_JMAP_USING = Object.freeze([
  "urn:ietf:params:jmap:core",
  "urn:ietf:params:jmap:mail",
  "urn:ietf:params:jmap:submission",
]);

// The hidden field the rendered forms carry, and the header the same
// token is sent in for a request whose body is not a form.
var CSRF_FIELD_RE = /name="_csrf" value="([^"]*)"/;

function _jar() {
  var held = Object.create(null);
  return {
    absorb: function (setCookie) {
      var list = Array.isArray(setCookie) ? setCookie : (setCookie ? [setCookie] : []);
      for (var i = 0; i < list.length; i += 1) {
        var pair = String(list[i]).split(";")[0];
        var eq = pair.indexOf("=");
        if (eq === -1) continue;
        var name  = pair.slice(0, eq).trim();
        var value = pair.slice(eq + 1).trim();
        // An expiry in the past is how a server clears a cookie, and a
        // jar that keeps the empty value instead of dropping the name
        // reports a session that is still held after a sign out.
        if (value.length === 0) delete held[name];
        else held[name] = value;
      }
    },
    header: function () {
      var names = Object.keys(held);
      var out = [];
      for (var i = 0; i < names.length; i += 1) out.push(names[i] + "=" + held[names[i]]);
      return out.join("; ");
    },
    read:  function (name) { return Object.prototype.hasOwnProperty.call(held, name) ? held[name] : null; },
    names: function () { return Object.keys(held); },
    // A cookie a browser holds but this reader should forget, for
    // asserting that a route refuses on the server's own record rather
    // than because the client stopped sending anything.
    forget: function (name) { delete held[name]; },
    // The other half of the same question. Putting a token back after
    // the server cleared it is how a replay is driven: the answer then
    // says whether the session was destroyed on the server or only
    // dropped by the client, and those are very different guarantees.
    set: function (name, value) {
      if (typeof name !== "string" || name.length === 0) {
        throw new TypeError("helpers/browser: cookies.set(name, value) needs a cookie name");
      }
      if (typeof value !== "string") {
        throw new TypeError("helpers/browser: cookies.set(name, value) needs a string value");
      }
      held[name] = value;
    },
  };
}

/**
 * @primitive test.helpers.browser.browserAt
 * @signature browser.browserAt(origin, opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: assert on the route's answer, never on a helper's)
 *
 * A reader bound to one origin. `opts.ca` is required for an `https`
 * origin and refused for an `http` one, because a CA supplied where
 * nothing verifies it is a test that believes it checked a chain and
 * did not.
 *
 * `opts.localAddress` names the address this reader dials out from, so
 * two readers on one host arrive at the server as two different peers.
 * A per address bound, or a source a mailbox has signed in from before,
 * cannot be driven from a single reader, and a fixture that shares one
 * address tests the opposite of what it claims: every request looks
 * like the same client.
 *
 * `opts.http2` speaks HTTP/2, which is the version a browser negotiates
 * against this server. It sends `:authority` and no `Host` header, which
 * is the difference that matters to anything reading this server's own
 * origin. It requires an `https` origin, because the framework offers h2
 * over ALPN and there is no cleartext upgrade path here.
 *
 * opts.ca            PEM of the authority that signed the server certificate
 * opts.servername    SNI name, when the origin is an address rather than a name
 * opts.timeoutMs     per request budget, default 20000
 * opts.userAgent     overrides the default browser agent string
 * opts.localAddress  the source address to dial out from, default the host's own
 * opts.http2         speak HTTP/2 rather than HTTP/1.1, default false
 */
function browserAt(origin, opts) {
  opts = opts || {};
  if (typeof origin !== "string" || !/^https?:\/\/[^/]+$/.test(origin)) {
    throw new TypeError("helpers/browser.browserAt: origin must look like " +
      "http://host:port or https://host:port, with no path");
  }
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("helpers/browser.browserAt: opts must be an object when supplied");
  }
  var parsed = new URL(origin);
  var secure = parsed.protocol === "https:";
  if (secure && (typeof opts.ca !== "string" || opts.ca.length === 0)) {
    throw new TypeError("helpers/browser.browserAt: an https origin needs opts.ca, the " +
      "authority that signed the server certificate. Verification stays on, because a " +
      "reader that skipped it would pass against a listener presenting anything at all.");
  }
  if (!secure && opts.ca !== undefined) {
    throw new TypeError("helpers/browser.browserAt: opts.ca was supplied for an http " +
      "origin, where nothing verifies it. Point the reader at the TLS port instead.");
  }
  var timeoutMs = opts.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : opts.timeoutMs;
  if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("helpers/browser.browserAt: opts.timeoutMs must be a positive " +
      "finite number of milliseconds");
  }
  var userAgent = opts.userAgent === undefined ? DEFAULT_USER_AGENT : opts.userAgent;
  if (typeof userAgent !== "string" || userAgent.length === 0) {
    throw new TypeError("helpers/browser.browserAt: opts.userAgent must be a non-empty string");
  }
  var localAddress = opts.localAddress;
  if (localAddress !== undefined &&
      (typeof localAddress !== "string" || localAddress.length === 0)) {
    throw new TypeError("helpers/browser.browserAt: opts.localAddress must be a non-empty " +
      "string address to dial out from");
  }
  if (opts.http2 !== undefined && typeof opts.http2 !== "boolean") {
    throw new TypeError("helpers/browser.browserAt: opts.http2 must be a boolean when supplied");
  }
  var http2 = opts.http2 === true;
  if (http2 && !secure) {
    throw new TypeError("helpers/browser.browserAt: opts.http2 needs an https origin. The " +
      "framework offers h2 over ALPN and no cleartext upgrade, so an http origin would " +
      "silently speak HTTP/1.1 and the reader would report the version it did not ask for.");
  }

  var jar  = _jar();
  var csrf = "";
  var lastTls = null;

  // `keepCookies` is false for exactly one caller, the preflight below.
  // The Fetch standard has a user agent ignore the `Set-Cookie` of a
  // preflight response, and a jar that kept one would replace the double
  // submit cookie this reader is holding while leaving the token it
  // remembers behind: the next form post would then carry a token that
  // no longer matches its own cookie, and the refusal would read as the
  // gate working when it was the reader that broke.
  function _send(method, path, headers, payload, keepCookies) {
    return http2
      ? _sendH2(method, path, headers, payload, keepCookies)
      : _sendH1(method, path, headers, payload, keepCookies);
  }

  // HTTP/2, which is what a browser negotiates here. The authority rides
  // the `:authority` pseudo-header and NO `Host` header is sent, because
  // that is the request a browser makes and the whole reason this mode
  // exists. RFC 9113 section 8.3.1 has clients use `:authority` in place
  // of `Host`, so a reader that sent both would be measuring a shape no
  // browser produces.
  //
  // One session per request, closed on the way out. A pooled session
  // would be faster and would also mean a refusal on one request could
  // tear down the next one for a reason that has nothing to do with it.
  function _sendH2(method, path, headers, payload, keepCookies) {
    return new Promise(function (resolve, reject) {
      var connectOpts = { ca: [opts.ca] };
      if (typeof opts.servername === "string" && opts.servername.length > 0) {
        connectOpts.servername = opts.servername;
      }
      if (localAddress !== undefined) connectOpts.localAddress = localAddress;

      var session = nodeHttp2.connect(origin, connectOpts);
      var settled = false;
      function fail(e) {
        if (settled) return;
        settled = true;
        try { session.destroy(); } catch (_e) { /* already closing */ }
        reject(e);
      }
      session.once("error", fail);

      var head = Object.assign({
        ":method":    method,
        ":path":      path,
        ":scheme":    "https",
        ":authority": parsed.host,
      }, _lowerCased(headers));

      var req;
      try { req = session.request(head); }
      catch (e) { fail(e); return; }
      req.setTimeout(timeoutMs, function () {
        fail(new Error(method + " " + path + " on " + origin + " never answered within " +
          timeoutMs + "ms over HTTP/2"));
      });
      req.once("error", fail);

      var body = "";
      var resHeaders = {};
      var tlsState = null;
      req.setEncoding("utf8");
      req.on("response", function (h) {
        resHeaders = h;
        var socket = session.socket;
        if (socket && typeof socket.getPeerCertificate === "function") {
          tlsState = {
            authorized:      socket.authorized === true,
            authorizedError: String(socket.authorizationError || ""),
            peerCertificate: socket.getPeerCertificate(),
            protocol:        typeof socket.getProtocol === "function" ? socket.getProtocol() : "",
          };
          lastTls = tlsState;
        }
      });
      req.on("data", function (chunk) { body += chunk; });
      req.on("end", function () {
        if (settled) return;
        settled = true;
        try { session.close(); } catch (_e) { /* already closing */ }
        if (keepCookies !== false) jar.absorb(resHeaders["set-cookie"]);
        resolve({
          status:    resHeaders[":status"],
          body:      body,
          location:  resHeaders.location === undefined ? null : resHeaders.location,
          headers:   resHeaders,
          setCookie: resHeaders["set-cookie"] || [],
          tls:       lastTls,
        });
      });
      if (payload !== undefined && payload !== null) req.write(payload);
      req.end();
    });
  }

  // HTTP/2 refuses an uppercase header name outright, so the names the
  // rest of this file spells the HTTP/1.1 way are folded here rather than
  // at every call site.
  function _lowerCased(headers) {
    var out = {};
    var names = Object.keys(headers || {});
    for (var i = 0; i < names.length; i += 1) {
      // Connection-specific headers are malformed in HTTP/2 (RFC 9113
      // section 8.2.2) and Node refuses the stream rather than dropping
      // them, so a reader carrying one would fail before the route.
      //
      // `host` is NOT in that list and is deliberately left through. No
      // browser sends one over HTTP/2 and nothing here adds one, so it
      // arrives only when a caller wrote it, and a caller writing a
      // `host` that disagrees with `:authority` is driving the malformed
      // pair of RFC 9113 section 8.3.1. Dropping it here would silently
      // turn that vector into an ordinary request and report the refusal
      // it was checking for as absent.
      var lower = names[i].toLowerCase();
      if (lower === "connection" || lower === "keep-alive" || lower === "transfer-encoding" ||
          lower === "upgrade" || lower === "proxy-connection") continue;
      out[lower] = headers[names[i]];
    }
    return out;
  }

  // A GET or HEAD sent on a pooled connection the server closed while it
  // sat idle is reset before any response. A case that blocks this
  // process past the server's keep-alive window leaves a connection in
  // that state, so such a request is sent once more, on a new connection,
  // as a browser does. Node reports the reuse on `req.reusedSocket`.
  function _sendH1(method, path, headers, payload, keepCookies, retried) {
    return new Promise(function (resolve, reject) {
      var transport = secure ? nodeHttps : nodeHttp;
      var requestOpts = {
        host:    parsed.hostname,
        port:    parsed.port,
        path:    path,
        method:  method,
        headers: headers,
        timeout: timeoutMs,
      };
      if (localAddress !== undefined) requestOpts.localAddress = localAddress;
      if (secure) {
        requestOpts.ca = [opts.ca];
        if (typeof opts.servername === "string" && opts.servername.length > 0) {
          requestOpts.servername = opts.servername;
        }
      }
      var req = transport.request(requestOpts, function (res) {
        var socket = res.socket;
        if (secure && socket && typeof socket.getPeerCertificate === "function") {
          lastTls = {
            authorized:      socket.authorized === true,
            authorizedError: String(socket.authorizationError || ""),
            peerCertificate: socket.getPeerCertificate(),
            protocol:        typeof socket.getProtocol === "function" ? socket.getProtocol() : "",
          };
        }
        var body = "";
        res.setEncoding("utf8");
        res.on("data", function (chunk) { body += chunk; });
        res.on("end", function () {
          if (keepCookies !== false) jar.absorb(res.headers["set-cookie"]);
          resolve({
            status:    res.statusCode,
            body:      body,
            location:  res.headers.location === undefined ? null : res.headers.location,
            headers:   res.headers,
            setCookie: res.headers["set-cookie"] || [],
            tls:       lastTls,
          });
        });
      });
      req.once("timeout", function () {
        req.destroy(new Error(method + " " + path + " on " + origin + " never answered " +
          "within " + timeoutMs + "ms"));
      });
      req.once("error", function (e) {
        if (retried !== true && req.reusedSocket === true && e && e.code === "ECONNRESET" &&
            (method === "GET" || method === "HEAD")) {
          resolve(_sendH1(method, path, headers, payload, keepCookies, true));
          return;
        }
        reject(e);
      });
      if (payload !== undefined && payload !== null) req.write(payload);
      req.end();
    });
  }

  // The response head of a route that streams, without waiting for a body
  // that is not going to end.
  //
  // `_send` resolves on the response's `end`, which is right for every
  // ordinary route and wrong for an event source. RFC 8620 section 7.3 has
  // `closeafter=state` close the connection after a state event is PUSHED,
  // and the framework implements exactly that: it waits for a real change
  // rather than emitting one on connect. A quiet account therefore holds
  // the response open, correctly, and a reader waiting for the body reports
  // no answer for a route that answered immediately.
  //
  // That distinction is not academic. Asking a stream with `_send` once made
  // an assertion pass only while the endpoint was BROKEN, because a refusal
  // completes instantly and a working stream does not.
  //
  // Same transport, same pinned authority, same jar as every other request
  // here, because a second client with its own TLS posture is how two
  // readers come to disagree about what this server does.
  function _head(path, headers) {
    return http2 ? _headH2(path, headers) : _headH1(path, headers);
  }

  function _headH2(path, headers) {
    return new Promise(function (resolve, reject) {
      var connectOpts = { ca: [opts.ca] };
      if (typeof opts.servername === "string" && opts.servername.length > 0) {
        connectOpts.servername = opts.servername;
      }
      if (localAddress !== undefined) connectOpts.localAddress = localAddress;
      var session = nodeHttp2.connect(origin, connectOpts);
      var settled = false;
      function fail(e) {
        if (settled) return;
        settled = true;
        try { session.destroy(); } catch (_e) { /* already closing */ }
        reject(e);
      }
      session.once("error", fail);
      var req;
      try {
        req = session.request(Object.assign({
          ":method":    "GET",
          ":path":      path,
          ":scheme":    "https",
          ":authority": parsed.host,
        }, _lowerCased(headers)));
      } catch (e) { fail(e); return; }
      req.setTimeout(timeoutMs, function () {
        fail(new Error("GET " + path + " on " + origin + " sent no response head within " +
          timeoutMs + "ms over HTTP/2"));
      });
      req.once("error", fail);
      req.on("response", function (h) {
        if (settled) return;
        settled = true;
        jar.absorb(h["set-cookie"]);
        var answer = {
          status:      h[":status"],
          headers:     h,
          contentType: String(h["content-type"] || ""),
        };
        try { req.close(); session.close(); } catch (_e) { /* already closing */ }
        resolve(answer);
      });
      req.end();
    });
  }

  function _headH1(path, headers) {
    return new Promise(function (resolve, reject) {
      var transport = secure ? nodeHttps : nodeHttp;
      var requestOpts = {
        host:    parsed.hostname,
        port:    parsed.port,
        path:    path,
        method:  "GET",
        headers: headers,
        timeout: timeoutMs,
      };
      if (localAddress !== undefined) requestOpts.localAddress = localAddress;
      if (secure) {
        requestOpts.ca = [opts.ca];
        if (typeof opts.servername === "string" && opts.servername.length > 0) {
          requestOpts.servername = opts.servername;
        }
      }
      var req = transport.request(requestOpts, function (res) {
        jar.absorb(res.headers["set-cookie"]);
        var answer = {
          status:      res.statusCode,
          headers:     res.headers,
          contentType: String(res.headers["content-type"] || ""),
        };
        res.destroy();
        req.destroy();
        resolve(answer);
      });
      req.once("timeout", function () {
        req.destroy(new Error("GET " + path + " on " + origin + " sent no response head " +
          "within " + timeoutMs + "ms"));
      });
      req.once("error", reject);
      req.end();
    });
  }

  function _headers(extra) {
    var base = {
      "User-Agent":      userAgent,
      "Accept-Language": "en",
    };
    var cookies = jar.header();
    if (cookies.length > 0) base.Cookie = cookies;
    return Object.assign(base, extra || {});
  }

  function get(path, extra) {
    return _send("GET", path, _headers(Object.assign({ Accept: "text/html" }, extra || {})));
  }

  // For a route that streams. Resolves on the response head and closes the
  // socket, so what is asked is whether the route answered rather than what
  // it eventually says.
  function head(path, extra) {
    return _head(path, _headers(Object.assign({ Accept: "text/event-stream" }, extra || {})));
  }

  function post(path, contentType, payload, extra) {
    var body = payload === undefined || payload === null ? "" : String(payload);
    return _send("POST", path, _headers(Object.assign({
      "Content-Type":   contentType,
      "Content-Length": String(Buffer.byteLength(body, "utf8")),
      "Origin":         origin,
      "X-CSRF-Token":   csrf,
      "Accept":         "text/html",
    }, extra || {})), body);
  }

  // One request with any method: HEAD, OPTIONS, a method no route
  // registers, or a method written in lower or mixed case. The cookies
  // this reader holds are sent, and nothing else is added: no token, no
  // Origin and no Accept, so the caller writes every header the vector
  // needs in `extra`.
  //
  // The method reaches the server as written only over HTTP/2. The
  // HTTP/1.1 client in `node:http` converts a method to upper case before
  // it sends the request line.
  function request(method, path, extra, payload) {
    if (typeof method !== "string" || method.length === 0) {
      throw new TypeError("helpers/browser: request(method, path) needs a method string");
    }
    if (typeof path !== "string" || path.charAt(0) !== "/") {
      throw new TypeError("helpers/browser: request(method, path) needs a path beginning with /");
    }
    var body = payload === undefined || payload === null ? null : String(payload);
    var headers = _headers(extra);
    if (body !== null && headers["Content-Length"] === undefined) {
      headers["Content-Length"] = String(Buffer.byteLength(body, "utf8"));
    }
    return _send(method, path, headers, body);
  }

  // The preflight a browser sends before a cross origin request that is
  // not a plain form submission, which is the question "may a page on
  // another site make this request at all".
  //
  // It carries no cookies and no token on purpose, which is not a
  // shortcut but the shape: a browser sends a preflight without
  // credentials, and the answer it gets back decides whether the real
  // request is ever issued. Sending a jar here would ask a different
  // question than the one a browser asks, and the answer to that
  // question is what a cross origin attack has to get past first.
  //
  // `origin` names the site the imagined page is on, so it is required
  // and is never this reader's own: a preflight from here to here is not
  // a preflight.
  function preflight(path, opts2) {
    opts2 = opts2 || {};
    if (typeof opts2.origin !== "string" || opts2.origin.length === 0) {
      throw new TypeError("helpers/browser: preflight(path, opts) needs opts.origin, the " +
        "site the request would come from");
    }
    if (opts2.origin === origin) {
      throw new TypeError("helpers/browser: preflight(path, opts) was given this reader's " +
        "own origin. A browser sends no preflight for a same origin request, so the answer " +
        "would say nothing about cross origin access.");
    }
    return _send("OPTIONS", path, {
      "User-Agent":                     userAgent,
      "Accept-Language":                "en",
      "Origin":                         opts2.origin,
      "Access-Control-Request-Method":  opts2.method  || "POST",
      "Access-Control-Request-Headers": opts2.headers || "content-type",
    }, null, false);
  }

  // A form post, with the hidden token appended the way the rendered
  // form carries it. An array value becomes one field per entry, which
  // is how a bulk action names several messages.
  function form(path, fields, extra) {
    if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
      throw new TypeError("helpers/browser: form(path, fields) needs a plain object of fields");
    }
    var parts = [];
    var names = Object.keys(fields);
    for (var i = 0; i < names.length; i += 1) {
      var value = fields[names[i]];
      var many = Array.isArray(value) ? value : [value];
      for (var j = 0; j < many.length; j += 1) {
        parts.push(encodeURIComponent(names[i]) + "=" + encodeURIComponent(many[j]));
      }
    }
    parts.push("_csrf=" + encodeURIComponent(csrf));
    return post(path, "application/x-www-form-urlencoded", parts.join("&"), extra);
  }

  // The sign in form's token, read off the rendered page. Returned as
  // well as remembered, so a caller can assert the page carried one
  // rather than trusting that it did.
  async function readCsrf(path) {
    var page = await get(path || "/sign-in");
    var found = CSRF_FIELD_RE.exec(page.body);
    csrf = found === null ? "" : found[1];
    return { token: csrf, page: page };
  }

  async function signIn(address, password) {
    if (typeof address !== "string" || typeof password !== "string") {
      throw new TypeError("helpers/browser: signIn(address, password) needs two strings");
    }
    await readCsrf("/sign-in");
    return post("/sign-in", "application/x-www-form-urlencoded",
      "address=" + encodeURIComponent(address) +
      "&password=" + encodeURIComponent(password) +
      "&_csrf=" + encodeURIComponent(csrf));
  }

  function signOut(back) {
    return form("/sign-out", back === undefined ? {} : { back: back });
  }

  function jmap(methodCalls, using) {
    if (!Array.isArray(methodCalls)) {
      throw new TypeError("helpers/browser: jmap(methodCalls) needs an array of method calls");
    }
    return post("/jmap/api", "application/json", JSON.stringify({
      using:       Array.isArray(using) ? using : DEFAULT_JMAP_USING.slice(),
      methodCalls: methodCalls,
    }), { Accept: "application/json" });
  }

  return {
    origin:    origin,
    // Which HTTP version this reader speaks, so a case driving both can
    // name the one that answered rather than assert over a transport it
    // assumed.
    http2:     http2,
    get:       get,
    head:      head,
    post:      post,
    request:   request,
    form:      form,
    preflight: preflight,
    signIn:    signIn,
    signOut:   signOut,
    jmap:      jmap,
    readCsrf:  readCsrf,
    csrf:      function () { return csrf; },
    cookies:   jar,
    tls:       function () { return lastTls; },
  };
}

/**
 * @primitive test.helpers.browser.answer
 * @signature browser.answer(response, index?)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 8620 section 3.3
 *
 * One method response out of a JMAP reply, by position. Throws with the
 * body quoted when the reply is not the JSON a JMAP client expects, so
 * an error page reads as an error page rather than as a missing field.
 */
function answer(response, index) {
  var at = index === undefined ? 0 : index;
  var parsed;
  try { parsed = JSON.parse(response.body); }
  catch (_e) {
    throw new Error("helpers/browser.answer: the reply was not JSON (status " +
      response.status + "): " + String(response.body).slice(0, 200));
  }
  if (!parsed || !Array.isArray(parsed.methodResponses)) {
    throw new Error("helpers/browser.answer: the reply carried no methodResponses (status " +
      response.status + "): " + String(response.body).slice(0, 200));
  }
  return parsed.methodResponses[at];
}

module.exports = {
  browserAt:          browserAt,
  answer:             answer,
  DEFAULT_JMAP_USING: DEFAULT_JMAP_USING,
  DEFAULT_USER_AGENT: DEFAULT_USER_AGENT,
  DEFAULT_TIMEOUT_MS: DEFAULT_TIMEOUT_MS,
};
