// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The IMAP ENVELOPE and the submission listener count the addresses in
 * a header the same way.
 *
 * A display name may hold a comma, and RFC 2047 takes the quoting that
 * made it readable away: the MIME parser hands back header values with
 * encoded words already decoded, so `=?UTF-8?B?RG9lLCBKb2hu?=` arrives
 * as `Doe, John` with nothing left to say it was one token. RFC 5322
 * §3.4 puts the addr-spec inside the angle brackets, which is the part
 * a decoder cannot have invented, so a piece carrying none is display
 * text rather than an address.
 *
 * `lib/mail/compose.js` says that in the docstring of the one reader it
 * exports for the job, and `lib/mail/listeners.js` refuses to load
 * without it, because two readers would be two answers to the question
 * of how many addresses a header names, which is the question an
 * address planted in a display name is asked to produce different
 * answers to.
 *
 * The ENVELOPE is the second place that question is answered. A client
 * builds its reply from the ENVELOPE, so a reader here that counts the
 * planted address as a sender of its own puts an attacker's address in
 * front of the person replying, on a message the submission listener
 * already decided had one author.
 *
 * Run standalone: node test/layer-2-integration/imap-envelope-address-reader.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var compose   = require("../../lib/mail/compose");
var blamepost = require("../../lib");

var b = helpers.b;

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE_PASSWORD   = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The display name an attacker writes, encoded so the comma inside it
// survives the wire and is handed back unquoted after decoding.
var PLANTED_NAME = "evil@attacker.test, Real Name";
var AUTHOR       = "real@" + DOMAIN;

function encodedWord(text) {
  return "=?UTF-8?B?" + Buffer.from(text, "utf8").toString("base64") + "?=";
}

async function theEnvelopeCountsTheAuthorTheWayTheSubmissionReaderDoes(session) {
  var decoded = PLANTED_NAME + " <" + AUTHOR + ">";
  // What the one designated reader says about the decoded header. The
  // ENVELOPE has to agree with this number, whatever it is.
  var byTheDesignatedReader = compose.splitAddressHeader(decoded);
  count("the designated reader sees one author in the decoded header",
    byTheDesignatedReader.length === 1, JSON.stringify(byTheDesignatedReader));

  var message = [
    "From: " + encodedWord(PLANTED_NAME) + " <" + AUTHOR + ">",
    "To: alice@" + DOMAIN,
    "Subject: envelope reader",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <envelope-reader@example.net>",
    "",
    "body",
    "",
  ].join("\r\n");

  var appendTag = session.tag();
  await session.sendLiteral(appendTag + " APPEND INBOX", message, "<the message>");
  var appended = await session.read(new RegExp("^" + appendTag + " (OK|NO|BAD)", "m"),
    "APPEND answered");
  count("the message is appended", new RegExp("^" + appendTag + " OK", "m").test(appended),
    visible(appended));

  var selectTag = session.tag();
  session.send(selectTag + " SELECT INBOX");
  await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");

  var fetchTag = session.tag();
  session.send(fetchTag + " FETCH 1 (ENVELOPE)");
  var envelope = await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH ENVELOPE answered");
  count("the ENVELOPE is returned",
    new RegExp("^" + fetchTag + " OK", "m").test(envelope), visible(envelope));

  // RFC 9051 §7.5.2 writes each address as (name route mailbox host).
  // The planted address becomes one of those only if the reader cut the
  // header at the comma inside the display name.
  count("the planted address is not reported as a host of its own",
    envelope.indexOf("\"attacker.test\"") === -1, visible(envelope));
  count("and the author this server accepted is the one the ENVELOPE names",
    envelope.indexOf("\"real\" \"" + DOMAIN + "\"") !== -1, visible(envelope));
}

// A group is the other shape the two readers disagreed about, and the
// one where the reader in use writes a value no client can act on: the
// trailing semicolon RFC 5322 §3.4 ends a group with lands inside the
// host field of the last address.
async function aGroupDoesNotPutItsSyntaxInsideAHostField(session) {
  var message = [
    "From: sender@example.net",
    "To: Team: a@" + DOMAIN + ", b@" + DOMAIN + ";",
    "Subject: group syntax",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <group-syntax@example.net>",
    "",
    "body",
    "",
  ].join("\r\n");

  var appendTag = session.tag();
  await session.sendLiteral(appendTag + " APPEND INBOX", message, "<the group message>");
  await session.read(new RegExp("^" + appendTag + " (OK|NO|BAD)", "m"), "APPEND answered");

  var selectTag = session.tag();
  session.send(selectTag + " SELECT INBOX");
  await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "re-SELECT answered");

  var fetchTag = session.tag();
  session.send(fetchTag + " FETCH 2 (ENVELOPE)");
  var envelope = await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH ENVELOPE for the group message answered");

  count("a group's terminating semicolon does not land inside a host field",
    envelope.indexOf(DOMAIN + ";") === -1, visible(envelope));
  count("and the group label does not land inside a mailbox field",
    envelope.indexOf("\"Team: a\"") === -1, visible(envelope));
}

async function run() {
  var root    = helpers.tempDir("imap-envelope-address-reader");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "envelope reader test" });
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

    var session = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: alice.address, password: ALICE_PASSWORD,
      label: "imap-envelope-address-reader",
    });

    await theEnvelopeCountsTheAuthorTheWayTheSubmissionReaderDoes(session);
    await aGroupDoesNotPutItsSyntaxInsideAHostField(session);

    session.close();
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
  name: "imap-envelope-address-reader", run: run, getChecks: helpers.getChecks,
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
