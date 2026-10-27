// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a mail client that is not this codebase can reach a mailbox
 * here at all, asked of the running server rather than reasoned about.
 *
 * The sibling file in this directory proves the octets of a stored
 * message survive a round trip through a foreign parser. It reaches
 * that mailbox with curl. This file asks the question one layer
 * earlier and gets a different answer: for two separate reasons, most
 * of the clients an operator's tooling is written against cannot open a
 * session here.
 *
 * ## The capability line, and Python's imaplib
 *
 * RFC 9051 section 6.1.1 requires the capability list to carry
 * IMAP4rev2, and permits a server to advertise nothing older. This one
 * advertises nothing older, which is conformant.
 *
 * Python's `imaplib` refuses any server whose capability list carries
 * neither IMAP4REV1 nor IMAP4. It refuses in its constructor, before a
 * command is sent, and it closes the socket. That is the client most
 * monitoring scripts, migration jobs and one-off operator tooling are
 * written against, so "conformant" and "reachable" are not the same
 * property here and the difference is worth measuring rather than
 * assuming.
 *
 * The obvious remedy is to advertise IMAP4rev1 beside IMAP4rev2, and
 * the cases below are the reason this server does not. Advertising
 * IMAP4rev1 is a claim to implement RFC 3501, and two of that
 * specification's requirements are ones this server declines under the
 * profile it ships: LOGIN, which RFC 3501 section 6.2.3 defines and
 * this server refuses in favor of AUTHENTICATE, and mailbox names in
 * modified UTF-7, which RFC 3501 section 5.1.3 requires and RFC 9051
 * replaced with raw UTF-8. A server that answers IMAP4rev1 and then
 * refuses LOGIN has lied about which protocol it speaks.
 *
 * It would also not work. `imaplib.login()` sends LOGIN, so a client
 * admitted past the version check arrives at a refused sign-in, and a
 * refused sign-in reads to an operator as a bad password. The failure
 * would move from a place that names the cause to a place that does
 * not. Both halves are measured below rather than asserted.
 *
 * ## The implicit-TLS port
 *
 * Nothing in this server binds 993. The mailbox listeners negotiate TLS
 * in band and the framework's IMAP listener has no implicit-TLS mode,
 * though its submission listener has one for port 465.
 *
 * What an operator is likely to have done instead is put a TLS
 * terminator in front of 143, and that arrangement is measurable from a
 * client without knowing anything about the deployment. Two
 * observations give it away. The greeting inside the established TLS
 * session still advertises STARTTLS, which an implicit-TLS listener
 * does not, because there is nothing left to start. And a credential
 * offered on that session is refused for want of TLS, because the
 * listener behind the terminator was handed a plaintext connection and
 * is answering correctly about the connection it can see.
 *
 * So this file does not assert that 993 is absent, which would be a
 * statement about one machine. It asks what is there and reports which
 * of the two states it found: nothing serving the port, which is what
 * this server ships, or a terminator, which binds the port and admits
 * nobody.
 *
 * ## Reading a failure here
 *
 * Every case below is written to hold while the state it describes
 * holds, and to fail when it changes. That is deliberate and the
 * failures are the point:
 *
 *   - The capability case fails if IMAP4rev1 appears. If the framework
 *     gained a genuine IMAP4rev1 mode, this case is the reminder to
 *     re-derive what else changed rather than to delete a line.
 *   - The imaplib cases fail if it connects. Either the server started
 *     advertising an older revision, or the client caught up with
 *     RFC 9051; the second is the good outcome and retires the first
 *     four cases outright.
 *   - The implicit-TLS cases fail if a real IMAPS listener appears,
 *     because a real one does not advertise STARTTLS and does admit a
 *     credential. That is the day the terminator advice comes out of
 *     the compose file.
 *
 * ## Running it
 *
 * `node scripts/test-integration.js` runs this after
 * `scripts/check-services.js` reports the listeners answering as this
 * server. Nothing here provisions a domain or an account: provisioning
 * is an operator step and a test that did it would be driving this
 * codebase again.
 *
 * Environment:
 *   BLAMEPOST_INTEROP_HOST        must be the loopback address this
 *                                 suite's shared wire client dials.
 *                                 Default 127.0.0.1.
 *   BLAMEPOST_INTEROP_IMAP_PORT   the in-band port. Default 143.
 *   BLAMEPOST_INTEROP_IMAPS_PORT  the implicit-TLS port to ask about.
 *                                 Default 993.
 *   BLAMEPOST_INTEROP_SERVERNAME  the name the listener's certificate
 *                                 carries. Default mx.example.com.
 *   BLAMEPOST_INTEROP_ADDRESS     the account a credential is offered
 *   BLAMEPOST_INTEROP_PASSWORD    for. Both required.
 *   BLAMEPOST_INTEROP_CA          PEM the chain is verified against.
 *                                 Required: every case reads what the
 *                                 server said on an encrypted session,
 *                                 and a session that verified nothing
 *                                 would read the same from anything
 *                                 answering the port.
 *   BLAMEPOST_PYTHON_BIN          an explicit interpreter, for a
 *                                 machine whose python is not on PATH.
 *
 * Run standalone: node test/integration/imap-foreign-client.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers = require("../helpers");
var wire    = require("../helpers/wire");
var foreign = require("../helpers/foreign-client");
var clients = require("./clients");

var count = helpers.count;

var CLIENT_TIMEOUT_MS = 30000;

// How long a probe waits to decide nothing is listening on the
// implicit-TLS port. A refused connection answers immediately; this is
// the ceiling for a port that accepts and then says nothing, which is
// its own answer and not a reason to wait.
var IMPLICIT_TLS_PROBE_MS = 5000;

// The atoms Python's imaplib will accept as proof it is talking to an
// IMAP server. Neither is IMAP4rev2, which is the whole finding.
var IMAPLIB_ACCEPTS = Object.freeze(["IMAP4REV1", "IMAP4"]);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function _required(name, what) {
  var value = process.env[name];
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(
    "interop: " + name + " is not set, and it is " + what + ". This file drives a running " +
    "server as a mailbox owner and cannot invent one. On a stack brought up from " +
    "compose.yml:\n" +
    "  docker compose exec blamepost node bin/blamepost.js domain add example.com\n" +
    "  docker compose exec blamepost node bin/blamepost.js account add alice@example.com " +
    "--password <secret>\n" +
    "then set BLAMEPOST_INTEROP_ADDRESS and BLAMEPOST_INTEROP_PASSWORD to that pair. A skip " +
    "here would report a stack nobody provisioned as a gate that ran.");
}

function _port(name, fallback) {
  var text = process.env[name] || String(fallback);
  var port = Number(text);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new TypeError("interop: " + name + " must be a TCP port, got " + JSON.stringify(text));
  }
  return port;
}

function readConfig() {
  var address  = _required("BLAMEPOST_INTEROP_ADDRESS", "the account a credential is offered for");
  var password = _required("BLAMEPOST_INTEROP_PASSWORD", "that account's password");

  // The shared wire client dials the loopback address it holds, which
  // is what keeps one definition of "the machine under test" across
  // this suite. A host set to anything else is refused rather than
  // ignored: silently probing somewhere other than where the operator
  // pointed is how a report comes back about the wrong server, which is
  // the failure this whole file's sibling gate exists for.
  var host = process.env.BLAMEPOST_INTEROP_HOST || wire.LOOPBACK;
  if (host !== wire.LOOPBACK) {
    throw new Error("interop: BLAMEPOST_INTEROP_HOST is " + JSON.stringify(host) + " and the " +
      "shared wire client in this suite dials " + wire.LOOPBACK + ". Run this file on the host " +
      "the server runs on, or drive the remote one with the octet file, which takes a host.");
  }

  var caFile = process.env.BLAMEPOST_INTEROP_CA;
  if (!caFile) {
    throw new Error("interop: set BLAMEPOST_INTEROP_CA to the PEM the listener's chain is " +
      "verified against. Every case here reads what the server said on an encrypted session, " +
      "and a session that verified nothing would read the same from anything answering the " +
      "port. There is no opt-out in this file for that reason.");
  }
  if (!nodeFs.existsSync(caFile)) {
    throw new Error("interop: BLAMEPOST_INTEROP_CA names " + caFile + ", which is not there.");
  }

  return {
    host:       host,
    imapPort:   _port("BLAMEPOST_INTEROP_IMAP_PORT", 143),
    imapsPort:  _port("BLAMEPOST_INTEROP_IMAPS_PORT", 993),
    servername: process.env.BLAMEPOST_INTEROP_SERVERNAME || "mx.example.com",
    address:    address,
    password:   password,
    caPem:      nodeFs.readFileSync(caFile, "utf8"),
    caFile:     caFile,
  };
}

// ---------------------------------------------------------------------------
// The foreign client
// ---------------------------------------------------------------------------

// The probe asks for the capability rather than the name: an
// interpreter built without `imaplib` answers `--version` perfectly
// well and cannot open a mailbox. It also reports the versions imaplib
// will accept, which is the thing under test, so the case below
// compares the server against the client's own list rather than
// against a list written here.
//
// Claimed from the suite's table rather than written out here, because
// scripts/test-integration.js reads that table to say how many of the
// clients this file needs it actually located. A specification kept
// here as well would let the runner report on a different program than
// the one this file went on to drive.
var PYTHON = clients.spec("python-imaplib");

// What imaplib does when pointed at this server, one line per endpoint.
// It reports the outcome as data rather than as an exit code, because a
// client that connected and a client that refused are both results and
// only one of them is an error in the ordinary sense.
var PROBE_SOURCE = [
  "import imaplib, ssl, sys",
  "ca, host, starttls_port, implicit_port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])",
  "ctx = ssl.create_default_context(cafile=ca)",
  // The CHAIN is verified, against the authority this run was pointed
  // at. Only the name check is off, and only because the client dials
  // a loopback literal while the certificate carries the host name the
  // listener answers to. Verifying nothing would report the same
  // outcome against anything holding the port, which is the one thing
  // this suite must not do.
  "ctx.check_hostname = False",
  "",
  "def report(label, make):",
  "    try:",
  "        m = make()",
  "    except Exception as e:",
  "        print('REFUSED %s %s: %s' % (label, type(e).__name__, str(e).replace(chr(10), ' ')))",
  "        return",
  "    try:",
  "        print('CONNECTED %s %s' % (label, ' '.join(m.capabilities)))",
  "        m.logout()",
  "    except Exception as e:",
  "        print('CONNECTED %s (logout failed: %s)' % (label, type(e).__name__))",
  "",
  "def starttls():",
  "    m = imaplib.IMAP4(host, starttls_port)",
  "    m.starttls(ssl_context=ctx)",
  "    return m",
  "",
  "report('starttls', starttls)",
  "report('implicit', lambda: imaplib.IMAP4_SSL(host, implicit_port, ssl_context=ctx))",
  "",
].join("\n");

// ---------------------------------------------------------------------------
// The capability line
// ---------------------------------------------------------------------------

// Read off a real socket, before and after the upgrade, because the
// server writes it three times on one connection: into the greeting,
// into the answer to CAPABILITY, and into the response code that
// completes an authentication. A file that read one of the three would
// not notice the day they stopped agreeing.
async function theCapabilityLineThisServerAdvertises(cfg) {
  var session = await wire.Wire.connect(cfg.imapPort, "imap-capability");
  try {
    var greeting = await session.read(/\r\n/, "the greeting");
    session.send("a1 CAPABILITY");
    var plain = await session.read(/^a1 /m, "CAPABILITY before the upgrade");

    session.send("a2 STARTTLS");
    await session.read(/^a2 /m, "the STARTTLS response");
    await session.upgrade(cfg.caPem, cfg.servername);

    session.send("a3 CAPABILITY");
    var encrypted = await session.read(/^a3 /m, "CAPABILITY after the upgrade");

    console.log("  greeting:   " + greeting.trim());
    console.log("  capability: " + plain.split(/\r\n/)[0]);

    count("the capability list carries IMAP4rev2, which RFC 9051 section 6.1.1 requires",
      /\bIMAP4rev2\b/.test(plain) && /\bIMAP4rev2\b/.test(encrypted),
      plain.replace(/[\r\n]+/g, " ").trim());

    // The finding, stated as the atoms a foreign client looks for
    // rather than as a sentence about them.
    IMAPLIB_ACCEPTS.forEach(function (atom) {
      var advertised = new RegExp("(^|\\s)" + atom + "(\\s|$)", "i").test(plain);
      count("the capability list does not carry " + atom + ", which is what a client " +
        "written against RFC 3501 looks for",
        advertised === false,
        advertised
          ? "it now advertises " + atom + ". If the framework gained a real IMAP4rev1 mode " +
            "this case is the prompt to re-derive what else changed, starting with LOGIN and " +
            "with modified UTF-7 mailbox names, rather than to delete a line."
          : plain.replace(/[\r\n]+/g, " ").trim());
    });

    // Both halves of the greeting have to agree, or the remedy of
    // overriding one of them would produce a server that says two
    // different things on one connection.
    var greetingCaps  = /\[CAPABILITY ([^\]]*)\]/.exec(greeting);
    var commandCaps   = /^\* CAPABILITY (.*)$/m.exec(plain);
    count("the greeting and the CAPABILITY command advertise the same list",
      greetingCaps !== null && commandCaps !== null &&
        greetingCaps[1].trim() === commandCaps[1].trim(),
      "greeting: " + (greetingCaps && greetingCaps[1]) +
        " / command: " + (commandCaps && commandCaps[1]));
  } finally {
    session.close();
  }
}

// The other half of the reason. RFC 3501 section 6.2.3 defines LOGIN
// and a client written against it uses it; `imaplib.login()` sends it.
// This server refuses it, so the capability atom alone would admit a
// client to a sign-in it cannot complete.
async function loginIsRefusedSoTheAtomAloneWouldNotHelp(cfg) {
  var session = await wire.Wire.connect(cfg.imapPort, "imap-login");
  try {
    await session.read(/\r\n/, "the greeting");
    session.send("a1 STARTTLS");
    await session.read(/^a1 /m, "the STARTTLS response");
    await session.upgrade(cfg.caPem, cfg.servername);

    session.send("a2 LOGIN " + cfg.address + " \"" + cfg.password + "\"");
    var verdict = await session.read(/^a2 /m, "the answer to LOGIN");

    count("LOGIN, the command a client written against RFC 3501 signs in with, is refused " +
      "even on an encrypted session",
      /^a2 (BAD|NO)\b/m.test(verdict),
      verdict.replace(/[\r\n]+/g, " ").trim() +
        " -- if this is now accepted, advertising IMAP4rev1 becomes a question worth " +
        "reopening, because the sign-in a client admitted by it would reach would work.");

    // And the credential itself is good, so the refusal above is about
    // the verb rather than about the account. Without this the case
    // would report the same green for a password nobody had set.
    session.send("a3 AUTHENTICATE PLAIN " + wire.saslPlain(cfg.address, cfg.password));
    var authed = await session.read(/^a3 /m, "the answer to AUTHENTICATE");
    count("canary: the same credential is accepted through AUTHENTICATE, so the refusal " +
      "above is about the verb and not the account",
      /^a3 OK\b/m.test(authed), authed.replace(/[\r\n]+/g, " ").trim());
  } finally {
    session.close();
  }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

async function pythonsStandardClientCannotOpenASession(cfg, client, workDir) {
  var program = nodePath.join(workDir, "imaplib-probe.py");
  nodeFs.writeFileSync(program, PROBE_SOURCE, "utf8");

  var rv = await foreign.run(client.bin, [
    program, cfg.caFile, cfg.host, String(cfg.imapPort), String(cfg.imapsPort),
  ], { timeoutMs: CLIENT_TIMEOUT_MS });
  var said = rv.stdout.toString("utf8") + rv.stderr.toString("utf8");
  var oneLine = said.replace(/[\r\n]+/g, " ").trim();

  console.log("  client:     " + client.bin + " -- " + client.detail);
  console.log("  it said:    " + oneLine.slice(0, 400));

  count("the client ran and reported an outcome for the in-band port",
    /^(REFUSED|CONNECTED) starttls\b/m.test(said),
    "exit " + rv.code + (rv.timedOut ? " (timed out)" : "") + ": " + oneLine.slice(0, 300));

  count("it cannot open a session on the in-band port, and the reason it gives is the " +
    "capability list rather than the transport",
    /^REFUSED starttls .*IMAP4/m.test(said),
    oneLine.slice(0, 300) +
      " -- a CONNECTED here means the client caught up with RFC 9051 or the server started " +
      "advertising an older revision; the first retires this case and the second needs " +
      "the capability cases above read again.");

  count("and the versions it would have accepted are the ones this server does not offer",
    IMAPLIB_ACCEPTS.every(function (atom) {
      return new RegExp("\\b" + atom + "\\b", "i").test(client.detail);
    }),
    "the client described itself as " + JSON.stringify(client.detail));

  return said;
}

// ---------------------------------------------------------------------------
// The implicit-TLS port
// ---------------------------------------------------------------------------

// Open a TLS session directly, the way a client configured for IMAPS
// does. Resolves with null when nothing is serving the port, which is
// this server's shipped state and an answer rather than an error.
function _implicitTlsSession(cfg) {
  return new Promise(function (resolve, reject) {
    var socket = nodeTls.connect({
      host:       cfg.host,
      port:       cfg.imapsPort,
      ca:         cfg.caPem,
      servername: cfg.servername,
      family:     nodeNet.isIPv6(cfg.host) ? 6 : 4,
    });
    var settled = false;
    var ceiling = setTimeout(function () {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_e) { /* already gone */ }
      resolve(null);
    }, IMPLICIT_TLS_PROBE_MS);
    socket.once("secureConnect", function () {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      resolve(new wire.Wire(socket, "imaps"));
    });
    socket.once("error", function (err) {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      // A refused or unreachable port is the shipped state. A handshake
      // that failed for any other reason is a fault worth surfacing,
      // because reading it as absence would hide a real IMAPS listener
      // presenting a certificate this run cannot verify.
      if (err && (err.code === "ECONNREFUSED" || err.code === "ECONNRESET" ||
                  err.code === "EHOSTUNREACH" || err.code === "ETIMEDOUT")) {
        return resolve(null);
      }
      reject(err);
    });
  });
}

async function whateverServesTheImplicitTlsPort(cfg) {
  var session = await _implicitTlsSession(cfg);
  if (session === null) {
    count("nothing serves the implicit-TLS mailbox port, which is what this server ships: " +
      "its mailbox listeners negotiate TLS in band and the framework's IMAP listener has " +
      "no implicit-TLS mode",
      true, "port " + cfg.imapsPort + " on " + cfg.host + " is not answering");
    return;
  }
  try {
    var greeting = await session.read(/\r\n/, "the greeting on the implicit-TLS port");
    console.log("  implicit:   " + greeting.trim());

    count("something answers the implicit-TLS port and it speaks IMAP",
      /^\* (OK|PREAUTH)\b/m.test(greeting), greeting.replace(/[\r\n]+/g, " ").trim());

    // The tell. RFC 8314 section 3 puts implicit TLS on 993 precisely so
    // there is no upgrade to negotiate, and the framework's own
    // submission listener refuses STARTTLS on its implicit-TLS port for
    // that reason. A STARTTLS atom offered inside an established TLS
    // session is a listener that cannot see the TLS it is behind.
    count("it advertises STARTTLS inside an established TLS session, so it is a terminator " +
      "in front of the in-band port rather than an implicit-TLS listener",
      /\bSTARTTLS\b/.test(greeting),
      greeting.replace(/[\r\n]+/g, " ").trim() +
        " -- no STARTTLS here means a real implicit-TLS listener appeared, and the " +
        "terminator advice can come out of the compose file.");

    // And what that costs the operator who followed the advice.
    session.send("b1 AUTHENTICATE PLAIN " + wire.saslPlain(cfg.address, cfg.password));
    var verdict = await session.read(/^b1 /m, "the answer to a credential on the terminator");
    count("and it refuses the credential for want of TLS, so nobody can sign in through it",
      /^b1 (BAD|NO)\b/m.test(verdict) && /TLS/i.test(verdict),
      verdict.replace(/[\r\n]+/g, " ").trim() +
        " -- an OK here means the listener can see the TLS it is behind, which is the " +
        "implicit-TLS mode landing rather than a terminator.");
  } finally {
    session.close();
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  var cfg = readConfig();
  console.log("  endpoint:   " + cfg.host + " ports " + cfg.imapPort + " and " + cfg.imapsPort +
    ", chain verified against " + cfg.caFile);

  await theCapabilityLineThisServerAdvertises(cfg);
  await loginIsRefusedSoTheAtomAloneWouldNotHelp(cfg);
  await whateverServesTheImplicitTlsPort(cfg);

  var client = await foreign.locate(PYTHON);
  if (!client.found) {
    helpers.skip("the client cases need an IMAP client that is not this codebase, and there " +
      "is not one here: " + client.reason + ". What did not run is the evidence that a " +
      "conformant capability list is unreachable in practice; the wire cases above still ran.");
    return helpers.getChecks();
  }

  var workDir = helpers.tempDir("interop-foreign-imap");
  try {
    await pythonsStandardClientCannotOpenASession(cfg, client, workDir);
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(workDir);
  }
}

module.exports = { name: "imap-foreign-client", run: run, getChecks: helpers.getChecks };

// The runner parses `CHECKS <n>` and `SKIPS <n>` out of this file's stdout.
// Both are printed every run: a report that omits the skip line when there
// were none leaves a reader unable to tell a file with nothing skipped from
// one that forgot to say.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
    console.log("SKIPS " + helpers.getSkips());
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
