// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A SEARCH term the client sent as a literal never reaches the wire as
 * part of a response line.
 *
 * The refusals this verb writes quote the term they refused, which is
 * what makes them worth reading. Every other IMAP argument arrives on
 * the command line, where the wire guard has already refused CR and LF,
 * so quoting one back cannot forge a line. A literal does not travel on
 * the command line: RFC 9051 §4.3 sends it as a counted octet payload
 * after the command, and its only screen on the way in is that it
 * decodes as UTF-8, which CR and LF both do.
 *
 * A term carrying CRLF that is echoed unchanged ends the response line
 * early and puts whatever follows at the start of the next one. A
 * client reads that continuation as a new untagged response, so the
 * term chooses what the server appears to have said: an `* OK`, a
 * `* BYE`, or a second tagged completion for a command that has not
 * finished. That is the IMAP shape of CWE-93, and RFC 9051 §7 gives the
 * client no way to tell the forged line from a real one.
 *
 * Run standalone: node test/layer-2-integration/imap-search-literal-echo.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var b = helpers.b;

var Wire         = wire.Wire;
var reservePort  = wire.reservePort;
var visible      = wire.visible;
var LOOPBACK     = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE_PASSWORD  = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// A term whose second line is a complete, well-formed untagged IMAP
// response. If the term is echoed unchanged this arrives at the client
// as a line the server never decided to send.
var FORGED = "x\r\n* OK [ALERT] injected";

// The tag-completion shape RFC 9051 §7.1 gives a command's result. A
// forged line is only interesting because a client cannot tell it from
// one of these.
var FORGED_LINE_RE = /^\* OK \[ALERT\] injected/m;

// Every argument position a literal can reach. A refused command can
// leave bytes the next read would pick up, so each vector gets a
// connection of its own: what is being asserted is what the server
// wrote in answer to one command, and a reply read across two of them
// would not be that.
var POSITIONS = [
  { label: "CHARSET",           suffix: " SEARCH CHARSET" },
  { label: "a HEADER field name", suffix: " SEARCH HEADER" },
  { label: "a date key",        suffix: " SEARCH SINCE" },
];

async function aLiteralTermNeverForgesAResponseLine(openSession) {
  for (var i = 0; i < POSITIONS.length; i += 1) {
    var position = POSITIONS[i];
    var session = await openSession(position.label);
    try {
      var selectTag = session.tag();
      session.send(selectTag + " SELECT INBOX");
      await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
        "SELECT answered");

      var tag = session.tag();
      await session.sendLiteral(tag + position.suffix, FORGED, "<the forged term>");
      var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
        position.label + " answered");

      count("a literal in " + position.label + " is answered",
        /(OK|NO|BAD)/.test(reply), visible(reply));
      count("and a literal in " + position.label + " does not forge a response line",
        !FORGED_LINE_RE.test(reply), visible(reply));
    } finally {
      session.close();
    }
  }
}

async function run() {
  var root    = helpers.tempDir("imap-search-literal-echo");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;
  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
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

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "imap literal echo test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

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
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    function openSession(label) {
      return Wire.imap(sections.imap.port, {
        caPem: leaf.ca, servername: HOSTNAME,
        address: alice.address, password: ALICE_PASSWORD,
        label: "imap-search-literal-echo " + label,
      });
    }

    await aLiteralTermNeverForgesAResponseLine(openSession);

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.cleanupTempDirs();
  }
}

module.exports = {
  name: "imap-search-literal-echo", run: run, getChecks: helpers.getChecks,
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
