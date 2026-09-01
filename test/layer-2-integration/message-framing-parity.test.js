// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Where the header block ends, answered the same way by every surface
 * that answers it.
 *
 * RFC 5322 section 2.1 ends the header block at the first empty line,
 * and RFC 5321 section 2.3.8 says that line is a CRLF. A peer that sends
 * bare LF instead is out of spec, and this server neither normalizes it
 * nor refuses it: the DATA reader keeps the octets it was given, so a
 * message separated by a bare LF is stored exactly as it arrived. That
 * is a deliberate fidelity property and not the subject here.
 *
 * The subject here is what happens next. Two different splitters read
 * that stored message. `b.safeMime` scans once and stops at the earlier
 * of CRLFCRLF and LFLF, which is the first empty line however it was
 * written; it is what the store parses a subject out of and what the
 * browser surface renders. `lib/mail/mailbox.js` looks for CRLFCRLF
 * across the whole buffer first and only falls back to LFLF when there
 * is no CRLFCRLF anywhere; it is what IMAP `BODY[HEADER]`,
 * `BODY[TEXT]` and POP3 `TOP` are cut from.
 *
 * On any ordinary message the two agree, because a CRLF-separated
 * message has no earlier LFLF to find. They stop agreeing on a message
 * whose separator is a bare LF and whose body contains a CRLFCRLF later
 * on, such as a quoted forward or a MIME preamble, which is to say most
 * forwarded mail. Then the CRLFCRLF that the second splitter finds is
 * inside the body, and everything between the real separator and it is
 * served to an IMAP client as though it were part of the header block.
 *
 * That hands the choice to whoever wrote the message. A line placed in
 * the body after a bare-LF separator is body text to the store and to
 * the browser, and a header to an IMAP client, so the same message
 * shows a different set of headers depending on which way the account
 * holder reads it, and the sender picks which is which.
 *
 * The message is appended through the same store call the inbound
 * delivery path makes, and then read back over a real IMAP session,
 * because the read side is where the divergence is served.
 *
 * Run standalone: node test/layer-2-integration/message-framing-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// A line the sender puts in the BODY, after a bare-LF separator, shaped
// like a header. Distinctive enough that finding it inside a header
// block is proof of where the split landed rather than a coincidence.
var PLANTED = "X-Planted-By-Sender: marker-7f31c2";

// The real subject, in the real header block, before the bare-LF
// separator. Whatever the split does, this stays a header.
var REAL_SUBJECT = "the quarterly review";

// A message whose header separator is a bare LF and whose body carries a
// CRLFCRLF later on, which is what an ordinary quoted forward looks like
// once one hop has written bare LF.
function bareLfSeparatedMessage() {
  return Buffer.from(
    "Message-ID: <framing-7f31c2@peer.example>\n" +
    "From: Dana Reyes <dana@peer.example>\n" +
    "To: alice@" + DOMAIN + "\n" +
    "Subject: " + REAL_SUBJECT + "\n" +
    "\n" +                                  // the real separator, bare LF
    "Body starts here.\r\n" +
    PLANTED + "\r\n" +
    "\r\n" +                                // a CRLFCRLF inside the body
    "and the rest of the body.\r\n", "utf8");
}

// The ordinary case, all CRLF, which must keep working exactly as it does.
function crlfSeparatedMessage() {
  return Buffer.from(
    "Message-ID: <framing-ordinary@peer.example>\r\n" +
    "From: Dana Reyes <dana@peer.example>\r\n" +
    "To: alice@" + DOMAIN + "\r\n" +
    "Subject: " + REAL_SUBJECT + "\r\n" +
    "\r\n" +
    "Body starts here.\r\n" +
    "\r\n" +
    "and the rest of the body.\r\n", "utf8");
}

// ---- cases -----------------------------------------------------------------

// What the store's own parser says the headers are. This is the answer
// the browser surface renders and the answer the subject column holds,
// so it is the one the IMAP answer has to match.
function theStoreSplitsAtTheFirstEmptyLine(raw, label) {
  var tree = b.safeMime.parse(raw);
  count(label + ": the store reads the real subject out of the header block",
    tree.headers.get("subject") === REAL_SUBJECT,
    JSON.stringify(tree.headers.get("subject")));
  count(label + ": and the sender's planted line is not a header to the store",
    tree.headers.get("x-planted-by-sender") === null ||
    tree.headers.get("x-planted-by-sender") === undefined,
    JSON.stringify(tree.headers.get("x-planted-by-sender")));
}

// The same question over IMAP, which is the surface an account holder's
// client actually asks.
async function imapAgreesWithTheStore(session, seq, label) {
  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " BODY.PEEK[HEADER]");
  var fetched = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "BODY[HEADER] answered");
  count(label + ": the header fetch succeeds",
    new RegExp("^" + tag + " OK", "m").test(fetched), visible(fetched));

  count(label + ": the real subject is in the header block IMAP returns",
    fetched.indexOf(REAL_SUBJECT) !== -1, visible(fetched));

  // The claim. A line the sender wrote into the body must not be served
  // as part of the header block, whatever terminator the separator used.
  count(label + ": a line the sender put in the body is not served as a header",
    fetched.indexOf(PLANTED) === -1, visible(fetched));

  count(label + ": and body text is not served as a header",
    fetched.indexOf("Body starts here") === -1, visible(fetched));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("framing");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "framing test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // Appended through the call the inbound delivery path makes, so the
    // stored octets are the ones a peer would have produced.
    var ordinary = crlfSeparatedMessage();
    var bareLf   = bareLfSeparatedMessage();
    identity.mailbox.appendMessage("INBOX", ordinary, { actor: { id: alice.id } });
    identity.mailbox.appendMessage("INBOX", bareLf,   { actor: { id: alice.id } });

    theStoreSplitsAtTheFirstEmptyLine(ordinary, "CRLF separator");
    theStoreSplitsAtTheFirstEmptyLine(bareLf,   "bare-LF separator");

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var session = await Wire.imap(sections.imap.port, {
      caPem:      leaf.ca,
      servername: HOSTNAME,
      address:    alice.address,
      password:   ALICE_PASSWORD,
      label:      "imap-framing",
    });
    var selectTag = session.tag();
    session.send(selectTag + " SELECT INBOX");
    var selected = await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    count("both messages are in the mailbox", /^\* 2 EXISTS/m.test(selected),
      visible(selected));

    await imapAgreesWithTheStore(session, 1, "CRLF separator");
    await imapAgreesWithTheStore(session, 2, "bare-LF separator");

    var logoutTag = session.tag();
    session.send(logoutTag + " LOGOUT");
    session.close();

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "message-framing-parity",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
