// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A client's view of a listener: an ordinary socket, the bytes a real
 * client would write, and the bytes the listener writes back.
 *
 * Everything else in the suite reaches the server through a function
 * call, which is a view no mail client has and which cannot see a wrong
 * reply code, a missing continuation, or a message that never lands.
 * Defects in this project have consistently lived exactly there, so a
 * transcript against a bound port is the evidence that matters.
 *
 * Reads poll a predicate rather than sleeping, so a fast listener does
 * not pay for a slow one's timeout and a hung one fails with what it did
 * say rather than with a bare timeout.
 *
 * This lives beside the other shared helpers because two files now need
 * it. Rolling a second copy is how two transcripts start disagreeing
 * about what a greeting looks like.
 *
 * The session ladders live here for the same reason and it is not a
 * theoretical one. Every listener in this project refuses a credential
 * before TLS, so reaching anything past a greeting means the same
 * sequence every time: read the greeting, upgrade, verify the chain
 * against the run's own authority, authenticate. `Wire.imap`,
 * `Wire.submission`, `Wire.mx`, `Wire.pop3` and `Wire.managesieve` are
 * that sequence, one per protocol, and each throws rather than handing
 * back a session it could not raise. A ladder that returned an
 * unauthenticated wire would let every assertion after it read a
 * refusal about the session instead of about the thing under test,
 * while the file still said the words it was written to say.
 */

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

var helpers = require("./index");

var LOOPBACK        = "127.0.0.1";
var WIRE_TIMEOUT_MS = 10000;
var QUIET_WINDOW_MS = 250;

// CR and LF made visible, so a transcript in a failure message stays on
// one line and a missing terminator is something a reader can see.
function visible(text) {
  return String(text).replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

// One port the operating system handed out and then released. The mail
// listeners take a port number rather than a zero, so a free port has to
// be found before the bind rather than read back after it.
function reservePort() {
  return new Promise(function (resolve, reject) {
    var probe = nodeNet.createServer();
    probe.once("error", reject);
    probe.listen(0, LOOPBACK, function () {
      var port = probe.address().port;
      probe.close(function () { resolve(port); });
    });
  });
}

/**
 * @primitive test.helpers.wire.Wire
 * @signature new Wire(socket, label, opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: assert on the wire, not on internal state)
 *
 * A conversation with one listener. `label` names it in any failure, so
 * a run driving four ports says which one went quiet.
 *
 * `opts.binary` keeps every byte the listener wrote, for the cases that
 * are about octets rather than about text. A message is a sequence of
 * octets and several of the counts the protocols carry are defined on
 * them, so a client that decodes the socket before asserting cannot tell
 * a server that returned the stored bytes from one that returned a
 * lossy re-encoding of them: both decode to the same string. In binary
 * mode `buf` is a latin1 view, which is a lossless one-to-one mapping
 * from bytes to characters, so every ASCII pattern the ladders match on
 * behaves exactly as it does in text mode while `readBytes` still hands
 * back the octets.
 *
 * @opts
 *   binary: boolean,   // optional; keep raw octets, default false
 */
function Wire(socket, label, wireOpts) {
  var self = this;
  var options = wireOpts || {};
  this.socket = socket;
  this.label  = label;
  this.binary = options.binary === true;
  this.buf    = "";
  this.bytes  = Buffer.alloc(0);
  this.log    = [];
  if (this.binary) {
    this.onData = function (chunk) {
      self.bytes = Buffer.concat([self.bytes, chunk]);
      self.buf   = self.bytes.toString("latin1");
    };
  } else {
    this.onData = function (chunk) { self.buf += chunk; };
    socket.setEncoding("utf8");
  }
  socket.on("data", this.onData);
  // A reset by the peer is a legitimate end to a refused session; the
  // assertion on what was already said is the result, not this.
  socket.on("error", function () { /* drop-silent by design: the transcript carries the outcome */ });
}

Wire.connect = function (port, label, opts) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port }, function () {
      resolve(new Wire(socket, label, opts));
    });
    socket.once("error", reject);
  });
};

Wire.prototype.send = function (line) {
  this.log.push("C: " + line);
  this.socket.write(line + "\r\n");
};

// Send bytes with no line terminator added, for a payload the caller
// frames itself: an IMAP literal, or a DATA block and its final dot.
// A Buffer goes out untouched, which is the only way to put an octet
// that is not valid UTF-8 on the wire: a string would be encoded on the
// way out and the sequence would be replaced before the listener saw it.
Wire.prototype.sendRaw = function (bytes, note) {
  this.log.push("C: " + (note === undefined ? visible(bytes) : note));
  this.socket.write(bytes);
};

// Everything the listener has said so far, cleared off both views at
// once so a text read and a byte read can never disagree about what is
// still pending.
Wire.prototype._take = function () {
  var taken = { text: this.buf, bytes: this.bytes };
  this.buf   = "";
  this.bytes = Buffer.alloc(0);
  this.log.push("S: " + visible(taken.text));
  return taken;
};

// Wait for the listener to say something matching `pattern`, then take
// everything said so far off the buffer and return it. `opts.timeoutMs`
// replaces the default wait for an answer that takes longer to produce,
// such as the reply to a message near the size ceiling.
Wire.prototype.read = function (pattern, what, opts) {
  var self = this;
  var timeoutMs = opts && typeof opts.timeoutMs === "number" ? opts.timeoutMs : WIRE_TIMEOUT_MS;
  return helpers.waitUntil(function () {
    if (!pattern.test(self.buf)) return false;
    return self._take();
  }, {
    timeoutMs: timeoutMs,
    label:     self.label + ": " + what,
  }).then(function (hit) { return hit.text; });
};

// `read`, returning the octets rather than the decoded text. Binary mode
// only: a text-mode socket has already decoded and the bytes are gone.
Wire.prototype.readBytes = function (pattern, what) {
  var self = this;
  if (!this.binary) {
    throw new TypeError("helpers/wire.readBytes: open the session with { binary: true }. " +
      "A text-mode socket decodes each chunk as it arrives, so the octets a byte-level " +
      "assertion is about no longer exist by the time this is called.");
  }
  return helpers.waitUntil(function () {
    if (!pattern.test(self.buf)) return false;
    return self._take();
  }, {
    timeoutMs: WIRE_TIMEOUT_MS,
    label:     self.label + ": " + what,
  }).then(function (hit) { return hit.bytes; });
};

// Let the socket run for a fixed window and return everything it said.
// The claim being tested is that nothing FURTHER arrives, which no
// predicate can express.
Wire.prototype.readQuietly = async function (what) {
  await helpers.passiveObserve(QUIET_WINDOW_MS, this.label + ": " + what);
  return this._take().text;
};

// The STARTTLS upgrade, from the client's side. The plaintext socket
// becomes the transport under a TLS socket that verifies the chain
// against the run's own CA. Verification stays on: a test that skipped
// it would pass against a listener presenting anything at all.
//
// `tlsOpts` is merged into the connect options, for a caller that has to
// pin what the CLIENT offers rather than take the runtime's defaults.
// A handshake reports what the two ends agreed on, not what the server
// would have preferred, so a claim about the server is only readable by
// driving the same port from more than one client posture. The socket,
// the authority and the name are set after the merge, because those
// three are what make this an upgrade of THIS session verified against
// the run's own authority, and a caller that overrode them would be
// opening an unrelated connection while the file still said the words
// it was written to say.
Wire.prototype.upgrade = function (caPem, servername, tlsOpts) {
  var self = this;
  var plain = this.socket;
  if (tlsOpts !== undefined &&
      (typeof tlsOpts !== "object" || tlsOpts === null || Array.isArray(tlsOpts))) {
    throw new TypeError("helpers/wire.upgrade: tlsOpts must be an object when supplied");
  }
  plain.removeListener("data", this.onData);
  return new Promise(function (resolve, reject) {
    var upgraded = nodeTls.connect(Object.assign({}, tlsOpts || {}, {
      socket:     plain,
      ca:         caPem,
      servername: servername,
    }), function () {
      self.socket = upgraded;
      self.buf    = "";
      self.bytes  = Buffer.alloc(0);
      // The upgraded socket carries the mode the session was opened
      // with. Setting an encoding here would decode the payload a
      // binary session exists to read, and it would do it silently.
      if (!self.binary) upgraded.setEncoding("utf8");
      upgraded.on("data", self.onData);
      self.log.push("-- TLS established --");
      resolve();
    });
    upgraded.on("error", reject);
  });
};

Wire.prototype.close = function () {
  try { this.socket.destroy(); } catch (_e) { /* drop-silent by design: the session is over */ }
};

Wire.prototype.transcript = function () { return this.log.join("\n"); };

// An IMAP command tag that does not repeat inside one session. A ladder
// that reuses a tag makes the reply to the second command match the
// pattern the first one is still waiting on, which reads as a pass.
Wire.prototype.tag = function () {
  this._tag = (this._tag || 0) + 1;
  return "t" + this._tag;
};

// One IMAP command and everything the listener said up to the tagged
// completion of that command. The tag is the session's own, so a reply
// to an earlier command on the same session cannot satisfy the wait.
//
// The verdict is read off the same text rather than asserted here: a
// case about a refusal and a case about a success both need the whole
// response, and a helper that threw on NO would leave every refusal case
// writing its own reader.
Wire.prototype.imapAsk = async function (command, what) {
  var tag = this.tag();
  this.send(tag + " " + command);
  var text = await this.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what === undefined ? command : what);
  return { tag: tag, text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
};

// The same, with the command's last argument sent as a synchronizing
// literal. RFC 9051 section 4.3 makes that the form a client sends a
// mailbox name a quoted string cannot carry, which on a name outside
// ASCII is every real client.
Wire.prototype.imapAskLiteral = async function (command, payload, what) {
  var tag = this.tag();
  await this.sendLiteral(tag + " " + command, payload,
    what === undefined ? command : what);
  var text = await this.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what === undefined ? command : what);
  return { tag: tag, text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
};

// The mailbox names one LIST reply carries, read off the untagged lines
// rather than out of the store, because the question every caller has is
// what the client was told. The name arrives quoted or as a bare atom,
// and a quoted one has its escapes undone so the value compares equal to
// the name that was sent.
function imapListed(text) {
  var names = [];
  var line = /^\* LIST \(([^)]*)\) "([^"]*)" (?:"((?:[^"\\]|\\.)*)"|(\S+))\r?$/gm;
  var found = line.exec(text);
  while (found !== null) {
    names.push({
      attributes: found[1],
      separator:  found[2],
      name:       found[3] === undefined ? found[4] : found[3].replace(/\\(.)/g, "$1"),
    });
    found = line.exec(text);
  }
  return names;
}

// One entry of that listing by name, or null when the reply did not name
// it. Null rather than undefined so a caller can assert absence without
// distinguishing the two.
function imapListedNamed(text, name) {
  var found = imapListed(text).filter(function (entry) { return entry.name === name; });
  return found.length > 0 ? found[0] : null;
}

// A literal announces an OCTET count and is followed by exactly that
// many octets and a CRLF. Both literal forms need the same two answers:
// how many octets the payload is, and the payload with its terminator
// attached. A Buffer payload has to stay a Buffer through both of them,
// because concatenating a terminator onto one with `+` would decode it
// first, which is how a fixture written to carry a specific octet
// arrives as a replacement character and the case silently stops
// testing what it says it tests.
function _literalBody(payload) {
  if (Buffer.isBuffer(payload)) {
    var withCrlf = Buffer.concat([payload, Buffer.from("\r\n", "ascii")]);
    return { length: payload.length, payload: withCrlf };
  }
  if (typeof payload !== "string") {
    throw new TypeError("helpers/wire: a literal payload is a string or a Buffer");
  }
  return { length: Buffer.byteLength(payload, "utf8"), payload: payload + "\r\n" };
}

// A literal in the non-synchronising form RFC 7888 section 4 defines:
// the payload follows the command line with no continuation in
// between. ManageSieve takes this shape, and so does any IMAP listener
// advertising LITERAL+.
//
// The IMAP listener this project composes does NOT, under the strict
// profile it ships: the guard refuses `{N+}` outright and the reader
// resumes at the next line, so the payload that is already in flight is
// read as a series of commands rather than drained. A line of it that
// is not a command draws its own BAD, and a line of it that IS one is
// answered, subject to the state the session is actually in. Use
// `sendLiteral` there.
Wire.prototype.sendNonSyncLiteral = function (command, payload, note) {
  var body = _literalBody(payload);
  this.send(command + " {" + body.length + "+}");
  this.sendRaw(body.payload, note);
};

// A literal in the synchronising form RFC 9051 section 4.3 defines:
// announce the octet count, wait for the server's `+` continuation,
// then send the payload. This is what an IMAP client does when the
// server has not advertised LITERAL+, which is the shipped posture
// here, so it is the shape an APPEND has to take.
//
// RFC 9051 section 7.5 writes the continuation as a line opening with
// `+`, and that is the only shape accepted as the invitation. An
// untagged response whose text merely happens to begin with a plus is a
// line a conforming client waits through, so a helper that read it as
// the invitation would let every case here pass over an APPEND that no
// real client could complete.
var LITERAL_CONTINUATION_RE = /^\+/m;

Wire.prototype.sendLiteral = async function (command, payload, note) {
  var body = _literalBody(payload);
  this.send(command + " {" + body.length + "}");
  // The wait is deliberately wider than what is accepted: a refusal has
  // to arrive rather than time out, so the caller reads what the
  // listener actually said instead of a stalled socket.
  var ready = await this.read(/^(?:(?:\* )?\+|\* BAD|\S+ (?:NO|BAD))/m, "literal continuation");
  if (!LITERAL_CONTINUATION_RE.test(ready)) {
    throw new Error(this.label + ": the listener refused the literal opener rather than " +
      "asking for the payload: " + visible(ready));
  }
  this.sendRaw(body.payload, note);
};

// ---------------------------------------------------------------------------
// Reading a response as octets
// ---------------------------------------------------------------------------

// The octets of an IMAP literal in a response. A latin1 view of the
// buffer is a one to one mapping from octets to characters, so an index
// into the view is an offset into the buffer and the announced count can
// be applied to the buffer directly.
//
// Both halves are returned because the pair is the claim: a literal that
// announces one count and is followed by a different number of octets
// desynchronizes the client's parser, whatever the payload says.
//
// It lives here rather than beside one case because more than one file
// reads a FETCH response as octets, and two copies of this are two ideas
// about where a literal ends.
function imapLiteral(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError("helpers/wire.imapLiteral: takes the octets a binary session read. " +
      "Open the session with { binary: true } and read it with readBytes.");
  }
  var view  = bytes.toString("latin1");
  var match = /\{(\d+)\}\r\n/.exec(view);
  if (!match) {
    throw new Error("no literal in the FETCH response: " + visible(view.slice(0, 300)));
  }
  var announced = parseInt(match[1], 10);
  var from      = match.index + match[0].length;
  // Everything from the literal to the close of the FETCH response,
  // which is what the announced count is a claim about.
  var closed  = view.lastIndexOf(")\r\n", view.length);
  var present = closed === -1 ? bytes.length - from : closed - from;
  return {
    announced: announced,
    present:   present,
    payload:   bytes.subarray(from, from + announced),
  };
}

// The message body of a POP3 multi-line response: everything between the
// `+OK` line and the terminating dot, with RFC 1939 section 3 dot
// stuffing undone.
function pop3Body(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError("helpers/wire.pop3Body: takes the octets a binary session read. " +
      "Open the session with { binary: true } and read it with readBytes.");
  }
  var view  = bytes.toString("latin1");
  var open  = view.indexOf("\r\n");
  if (open === -1) throw new Error("no +OK line: " + visible(view.slice(0, 300)));
  var end = view.indexOf("\r\n.\r\n", open);
  if (end === -1) throw new Error("no terminating dot: " + visible(view.slice(0, 300)));
  var body = bytes.subarray(open + 2, end + 2);
  // Undoing the stuffing on the octets rather than on a decoded copy,
  // for the same reason the socket is in binary mode.
  var out = [];
  var at  = 0;
  var text = body.toString("latin1");
  for (;;) {
    var dot = text.indexOf("\r\n..", at);
    if (dot === -1) { out.push(body.subarray(at)); break; }
    out.push(body.subarray(at, dot + 3));
    at = dot + 4;
  }
  return Buffer.concat(out);
}

// The message numbers and unique ids a POP3 UIDL listing carries, in the
// order the listener wrote them. Read as a pair rather than as two
// lists, because the claim a caller makes is about which id sits at
// which number.
function pop3Uidl(text) {
  var out = [];
  var lines = String(text).split("\r\n");
  for (var i = 0; i < lines.length; i += 1) {
    var m = /^(\d+) (\S+)$/.exec(lines[i]);
    if (m) out.push({ msgNum: parseInt(m[1], 10), uid: m[2] });
  }
  return out;
}

// The two counts on a POP3 `STAT` line, RFC 1939 section 5. A reply that
// carried no counts answers -1 for both, so a caller comparing against a
// real number reads a refusal as a mismatch rather than as a zero.
function pop3Stat(text) {
  var found = /^\+OK (\d+) (\d+)/m.exec(text);
  return found === null
    ? { messages: -1, bytes: -1 }
    : { messages: parseInt(found[1], 10), bytes: parseInt(found[2], 10) };
}

// ---------------------------------------------------------------------------
// The session ladders
// ---------------------------------------------------------------------------

// RFC 4616 section 2 SASL PLAIN: an empty authorization identity, the
// address, the password, separated by NUL. Written from its code point
// so this file carries no control byte of its own.
var NUL = String.fromCharCode(0);

function saslPlain(address, password) {
  if (typeof address !== "string" || typeof password !== "string") {
    throw new TypeError("helpers/wire.saslPlain: address and password must both be strings");
  }
  return Buffer.from(NUL + address + NUL + password, "utf8").toString("base64");
}

// Every ladder takes the same options, so a file driving four listeners
// spells the arguments once. `caPem` and `servername` are what the
// upgrade verifies against; `address` and `password` authenticate when
// both are present and are skipped when neither is; `tls` is anything
// else the client should bring to the handshake, such as the key
// agreement groups it offers.
//
// A ladder that could not complete throws rather than returning a
// half-raised session. A helper that handed back an unauthenticated
// wire would let every assertion after it read a refusal about the
// session rather than about the thing under test, and the file would
// still say the words it was written to say.
function _ladderOpts(port, opts, who) {
  if (typeof port !== "number" || !isFinite(port) || port <= 0) {
    throw new TypeError("helpers/wire." + who + ": port must be a bound port number");
  }
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("helpers/wire." + who + ": opts must be an object when supplied");
  }
  if (typeof opts.caPem !== "string" || opts.caPem.length === 0) {
    throw new TypeError("helpers/wire." + who + ": opts.caPem is required. Every listener " +
      "here refuses a credential before TLS, so a session that never upgrades cannot " +
      "reach anything past the greeting.");
  }
  if (typeof opts.servername !== "string" || opts.servername.length === 0) {
    throw new TypeError("helpers/wire." + who + ": opts.servername is required, and it is " +
      "the name the certificate carries. Verification stays on.");
  }
  var wantsAuth = opts.address !== undefined || opts.password !== undefined;
  if (wantsAuth && (typeof opts.address !== "string" || typeof opts.password !== "string")) {
    throw new TypeError("helpers/wire." + who + ": opts.address and opts.password go " +
      "together. Supply both to authenticate, or neither to stop at the upgrade.");
  }
  if (opts.tls !== undefined &&
      (typeof opts.tls !== "object" || opts.tls === null || Array.isArray(opts.tls))) {
    throw new TypeError("helpers/wire." + who + ": opts.tls must be an object of node:tls " +
      "connect options when supplied, such as the key agreement groups this client offers.");
  }
  return {
    label:     typeof opts.label === "string" && opts.label.length ? opts.label : who,
    caPem:     opts.caPem,
    servername: opts.servername,
    // What the client brings to the handshake. Carried through the
    // ladder rather than applied afterwards, because the upgrade is over
    // before a caller could reach the session.
    tls:       opts.tls,
    helo:      typeof opts.helo === "string" && opts.helo.length ? opts.helo : "client.example.net",
    address:   wantsAuth ? opts.address : null,
    password:  wantsAuth ? opts.password : null,
    // Carried through every ladder rather than set afterwards: the
    // greeting and the upgrade both arrive before a caller could reach
    // the session, so a mode applied later would already have missed
    // them.
    binary:    opts.binary === true,
  };
}

// IMAP4rev2, RFC 9051: greeting, STARTTLS, upgrade, and AUTHENTICATE
// PLAIN when a credential was supplied.
Wire.imap = async function (port, opts) {
  var o = _ladderOpts(port, opts, "imap");
  var session = await Wire.connect(port, o.label, { binary: o.binary });
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  var startTls = session.tag();
  session.send(startTls + " STARTTLS");
  await session.read(new RegExp("^" + startTls + " OK", "m"), "STARTTLS accepted");
  await session.upgrade(o.caPem, o.servername, o.tls);
  if (o.address === null) return session;
  var auth = session.tag();
  session.send(auth + " AUTHENTICATE PLAIN " + saslPlain(o.address, o.password));
  var verdict = await session.read(new RegExp("^" + auth + " (OK|NO|BAD)", "m"), "authenticated");
  if (!new RegExp("^" + auth + " OK", "m").test(verdict)) {
    session.close();
    throw new Error("helpers/wire.imap: " + o.address + " was not authenticated: " +
      visible(verdict));
  }
  return session;
};

// Submission, RFC 6409 with the RFC 3207 upgrade. EHLO is re-sent after
// the upgrade because the advertised extension set changes.
Wire.submission = async function (port, opts) {
  var o = _ladderOpts(port, opts, "submission");
  var session = await Wire.connect(port, o.label, { binary: o.binary });
  await session.read(/^220 /m, "banner");
  session.send("EHLO " + o.helo);
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(o.caPem, o.servername, o.tls);
  session.send("EHLO " + o.helo);
  await session.read(/^250 /m, "EHLO accepted over TLS");
  if (o.address === null) return session;
  session.send("AUTH PLAIN " + saslPlain(o.address, o.password));
  var verdict = await session.read(/^\d{3} /m, "authenticated");
  if (!/^235 /m.test(verdict)) {
    session.close();
    throw new Error("helpers/wire.submission: " + o.address + " was not authenticated: " +
      visible(verdict));
  }
  return session;
};

// Inbound mail from a peer, RFC 5321. No credential: an MX listener
// that authenticated its peers would be refusing the internet.
Wire.mx = async function (port, opts) {
  var o = _ladderOpts(port, Object.assign({ helo: "peer.example.net" }, opts || {}), "mx");
  if (o.address !== null) {
    throw new TypeError("helpers/wire.mx: an MX session carries no credential. Inbound " +
      "mail arrives from peers this server has never met.");
  }
  var session = await Wire.connect(port, o.label, { binary: o.binary });
  await session.read(/^220 /m, "banner");
  session.send("EHLO " + o.helo);
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(o.caPem, o.servername, o.tls);
  session.send("EHLO " + o.helo);
  await session.read(/^250 /m, "EHLO accepted over TLS");
  return session;
};

// POP3, RFC 1939 with the RFC 2595 STLS upgrade.
Wire.pop3 = async function (port, opts) {
  var o = _ladderOpts(port, opts, "pop3");
  var session = await Wire.connect(port, o.label, { binary: o.binary });
  await session.read(/^\+OK /m, "greeting");
  session.send("STLS");
  await session.read(/^\+OK /m, "STLS accepted");
  await session.upgrade(o.caPem, o.servername, o.tls);
  if (o.address === null) return session;
  session.send("USER " + o.address);
  await session.read(/^(\+OK|-ERR)/m, "USER answered");
  session.send("PASS " + o.password);
  var verdict = await session.read(/^(\+OK|-ERR)/m, "authenticated");
  if (!/^\+OK/m.test(verdict)) {
    session.close();
    throw new Error("helpers/wire.pop3: " + o.address + " was not authenticated: " +
      visible(verdict));
  }
  return session;
};

// The last OK, NO or BYE in what a read took off the socket, which is
// the line carrying the verdict.
//
// One command draws one reply, so this is picking a line out of a buffer
// rather than choosing between answers. It is a line-level read on
// purpose: a pattern run over the whole buffer would match an OK
// anywhere in it, including inside the text of a refusal, and a ladder
// that admitted a session on that would hand every case after it a
// refusal about the session instead of about the thing under test.
function lastManageSieveReply(text) {
  var replies = String(text).split("\r\n").filter(function (line) {
    return /^(?:OK|NO|BYE)/.test(line);
  });
  return replies.length === 0 ? "" : replies[replies.length - 1];
}

// ManageSieve, RFC 5804. The capability banner is re-emitted after the
// upgrade, and a ladder that does not read it leaves those bytes in
// front of the next reply. The SASL response travels as a literal
// rather than as a quoted string, because a base64 payload can carry
// characters the quoted form has to escape.
Wire.managesieve = async function (port, opts) {
  var o = _ladderOpts(port, opts, "managesieve");
  var session = await Wire.connect(port, o.label, { binary: o.binary });
  await session.read(/^OK[^\r\n]*\r\n/m, "capability banner and greeting");
  session.send("STARTTLS");
  await session.read(/^OK/m, "STARTTLS accepted");
  await session.upgrade(o.caPem, o.servername, o.tls);
  await session.read(/^OK/m, "capability banner re-emitted over TLS");
  if (o.address === null) return session;
  session.sendNonSyncLiteral('AUTHENTICATE "PLAIN"',
    saslPlain(o.address, o.password), "<the SASL response>");
  var verdict = await session.read(/^(?:OK|NO|BYE)[^\r\n]*\r\n/m, "authenticated");
  if (!/^OK/.test(lastManageSieveReply(verdict))) {
    session.close();
    throw new Error("helpers/wire.managesieve: " + o.address + " was not authenticated: " +
      visible(verdict));
  }
  return session;
};

module.exports = {
  Wire:            Wire,
  reservePort:     reservePort,
  visible:         visible,
  saslPlain:       saslPlain,
  imapLiteral:     imapLiteral,
  imapListed:      imapListed,
  imapListedNamed: imapListedNamed,
  pop3Body:        pop3Body,
  pop3Uidl:        pop3Uidl,
  pop3Stat:        pop3Stat,
  lastManageSieveReply: lastManageSieveReply,
  LOOPBACK:        LOOPBACK,
  WIRE_TIMEOUT_MS: WIRE_TIMEOUT_MS,
  QUIET_WINDOW_MS: QUIET_WINDOW_MS,
};
