// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * IMAP SEARCH answers with results or it refuses. It never answers with
 * an empty success.
 *
 * SEARCH is not wired on this listener yet, so today every form of it
 * comes back refused. That is the correct answer while the backend read
 * behind it does not exist, and it is not the interesting part. The
 * interesting part is the answer that must never appear: an untagged
 * `* SEARCH` carrying nothing, followed by a tagged `OK`.
 *
 * A client cannot tell that apart from a mailbox with no matches. It
 * renders an empty result list, the person reading it concludes the mail
 * is not there, and nothing anywhere reports that the query was never
 * run. A refusal is visible; an empty success is a wrong answer wearing
 * a success code.
 *
 * The trap is close at hand rather than hypothetical. The store carries
 * a full-text index that the browser surface already searches, and
 * wiring it under SEARCH looks like the obvious way to answer this verb.
 * It is not: that index holds keyed hashes of whole tokens, so it
 * matches a complete word and nothing else, while RFC 9051 section 6.4.4
 * defines every string key as a substring match. `SEARCH SUBJECT
 * "round"` against a message subject reading "Roundtrip" is a match the
 * RFC requires and the index cannot produce. It also folds FROM and TO
 * into one address column, drops stopwords and one-character tokens, and
 * caps a result set at a thousand rows. Every one of those differences
 * comes back as a match the client never sees, under a tagged `OK`.
 *
 * So the assertion below is deliberately indifferent to whether SEARCH
 * works. It passes while SEARCH refuses, it passes once SEARCH answers,
 * and it fails the moment SEARCH starts reporting a result set it did
 * not actually compute. The mailbox is loaded with a message first, so
 * "no matches" and "did not run" are distinguishable at all: every query
 * below has a correct answer of at least one message.
 *
 * Run standalone: node test/layer-2-integration/imap-search-refusal.test.js
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

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Distinctive enough that a match is the search working rather than
// something plausible matching by accident. The subject carries a word
// with a prefix inside it, because the prefix is the case a token index
// answers wrongly and a substring match answers correctly.
var SUBJECT = "Roundtrip probe 8fa21c";
var BODY    = "The body that was appended, marker 4d91e07b.";

var count = helpers.count;

// Every one of these has at least one correct answer in the mailbox
// below, so an empty result set is never the right answer to any of
// them. `text` and `label` travel together so a failure names the query
// rather than an index into a list.
var QUERIES = [
  { label: "ALL, which every message in the mailbox matches", text: "SEARCH ALL" },
  { label: "UNSEEN, which an appended message matches",       text: "SEARCH UNSEEN" },
  { label: "a subject substring",                             text: "SEARCH SUBJECT \"round\"" },
  { label: "a subject word",                                  text: "SEARCH SUBJECT \"Roundtrip\"" },
  { label: "a body substring",                                text: "SEARCH BODY \"marker\"" },
  { label: "a header and body search",                        text: "SEARCH TEXT \"4d91e07b\"" },
  { label: "a sender search",                                 text: "SEARCH FROM \"sender\"" },
  { label: "a size bound every message clears",               text: "SEARCH SMALLER 1000000" },
  { label: "the UID form RFC 9051 section 6.4.9 defines",     text: "UID SEARCH ALL" },
];

// An untagged SEARCH line carrying no message numbers. RFC 9051 section
// 7.3.4 writes a result set as `* SEARCH` followed by the numbers, so
// the bare form is the server saying it found nothing.
var EMPTY_SEARCH_RESULT_RE = /^\* SEARCH[ \t]*\r?$/m;
var ANY_SEARCH_RESULT_RE   = /^\* SEARCH[ \t]+\d/m;

// ---- the run ---------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-search");
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

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "imap search test" });
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
      label: "imap-search",
    });

    // One message, put there over the wire the client actually speaks.
    // The listener ships without LITERAL+ under its strict profile, so
    // the literal is the synchronising form RFC 9051 section 4.3
    // defines: announce the count, wait to be asked, then send.
    var message = [
      "From: sender@example.net",
      "To: " + alice.address,
      "Subject: " + SUBJECT,
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <search-8fa21c@example.net>",
      "",
      BODY,
      "",
    ].join("\r\n");

    var appendTag = session.tag();
    await session.sendLiteral(appendTag + " APPEND INBOX", message, "<the message>");
    var appended = await session.read(new RegExp("^" + appendTag + " (OK|NO|BAD)", "m"),
      "APPEND answered");
    count("a message is appended to the mailbox, so an empty result is never correct",
      new RegExp("^" + appendTag + " OK", "m").test(appended), visible(appended));

    var selectTag = session.tag();
    session.send(selectTag + " SELECT INBOX");
    var selected = await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    count("INBOX is selected", new RegExp("^" + selectTag + " OK", "m").test(selected),
      visible(selected));
    count("the mailbox reports the message it was given",
      /^\* 1 EXISTS/m.test(selected), visible(selected));

    for (var i = 0; i < QUERIES.length; i += 1) {
      var query = QUERIES[i];
      var tag = session.tag();
      session.send(tag + " " + query.text);
      var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
        query.text + " answered");

      var ok       = new RegExp("^" + tag + " OK", "m").test(reply);
      var refused  = new RegExp("^" + tag + " (NO|BAD)", "m").test(reply);
      var results  = ANY_SEARCH_RESULT_RE.test(reply);
      var emptySet = EMPTY_SEARCH_RESULT_RE.test(reply);

      // The whole of the claim. A success has to carry the message the
      // mailbox holds; anything else has to be a refusal the client can
      // see. The third possibility, a success carrying nothing, is the
      // one that tells a reader their mail is gone.
      count("SEARCH for " + query.label + " either answers with the message or refuses, " +
        "never an empty success",
        (ok && results && !emptySet) || (refused && !results),
        visible(reply));

      if (refused) {
        // A client whose search failed needs to know which command
        // failed. RFC 9051 section 7.1 puts the human readable text
        // after the condition, and a refusal that does not name the
        // verb leaves an operator reading a log that says only "NO".
        count("the refusal of " + query.label + " names the verb that was refused",
          /SEARCH/i.test(reply), visible(reply));
      }
    }

    session.send(session.tag() + " LOGOUT");
    session.close();

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "imap-search-refusal", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
