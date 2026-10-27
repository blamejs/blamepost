// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Opening a reply draft costs time proportional to the message being
 * replied to, and not to the square of it.
 *
 * A reply or forward draft quotes the message it answers. When that
 * message carries an HTML body and no plain-text alternative, the
 * composer reduces the markup to text before it can go into the reply's
 * own text part. The value it does that to is the body of a message
 * somebody else sent, so its shape is chosen by whoever sent it.
 *
 * A run of opening brackets with no closing one is the shape that
 * separates a reading which walks the value once from one that restarts
 * at every bracket: every position holds a bracket, nothing after it
 * ever closes, and the restarting reader reads the whole remainder once
 * per position. Message bodies are bounded by `limits.maxMessageBytes`,
 * which is fifty megabytes by default, so there is a great deal of room
 * above the size used here.
 *
 * The account holder pays for it. The peer that sent the message is
 * gone by then, the message is filed and looks ordinary in the list,
 * and the cost lands on the request that opens the draft, on the same
 * event loop every other account holder is being served from.
 *
 * The verdicts are pinned beside the cost, and they are what the reader
 * of the reply sends onward under their own name. Script source, an
 * attribute value and an unclosed element are all inside the markup and
 * none of them is what the sender wrote to be read, so each is driven
 * here through the route a browser actually asks for.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-1-state/reply-draft-quote-scan.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var DOMAIN   = "example.com";
var HOSTNAME = "mx.example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 5000;

// The reader waits far longer than the ceiling below, so a tree where
// the reduction restarts at every bracket reports the number it took
// rather than a socket that gave up. A request that never answers is a
// failure either way; only one of the two says how far past the ceiling
// it was.
var READER_TIMEOUT_MS = 60000;

// The size the two timed bodies are built at. Small enough that the
// single-pass reading is instant and the request is dominated by the
// rest of the route, and large enough that a reading which restarts at
// every bracket takes seconds.
var TIMED_BODY_BYTES = 128 * 1024;

// The most the hostile body may add to the request that quotes it, over
// an ordinary body of the same size. Measured on this tree, the reading
// that restarts took about 5.5 seconds for this body and the one that
// walks once takes under a millisecond, so the ceiling has room on both
// sides of a loaded runner.
var QUOTE_EXCESS_CEILING_MS = 1500;

// The draft body is rendered into a textarea, which is where a reader
// sees the quoted text and where it is read back from.
var TEXT_FIELD_RE = /<textarea id="text" name="text"[^>]*>([\s\S]*?)<\/textarea>/;

function draftTextOf(page) {
  var found = TEXT_FIELD_RE.exec(page.body);
  return found === null ? null : found[1];
}

// The quoted lines a draft carries, with the "> " marker taken off and
// the HTML escaping the template applied undone, so a vector can be
// compared against the text it should have produced.
function quotedTextOf(page) {
  var text = draftTextOf(page);
  if (text === null) return null;
  return text.split(/\r?\n/)
    .filter(function (line) { return line.indexOf("&gt; ") === 0 || line.indexOf("> ") === 0; })
    .map(function (line) { return line.replace(/^(&gt;|>) /, ""); })
    .join("\n")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

function repeat(ch, n) { return new Array(n + 1).join(ch); }

function elapsedMs(startedAt) {
  return Number(process.hrtime.bigint() - startedAt) / 1e6;
}

// A message offering both alternatives with nothing in the plain-text
// one, which is what leaves the draft with only markup to quote.
//
// The empty part is what makes this the shape rather than a message
// carrying `Content-Type: text/html` alone. A single HTML part is the
// only text part there is, so the store files it as the message's text
// and the draft quotes it with its markup intact; a sender who offers
// both and fills in one is the case where the markup has to be reduced.
var BOUNDARY = "quote-scan-boundary";

function htmlMessage(marker, html) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: Dana Reyes <dana@peer.example>",
    "To: alice@" + DOMAIN,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "MIME-Version: 1.0",
    "Content-Type: multipart/alternative; boundary=\"" + BOUNDARY + "\"",
    "",
    "--" + BOUNDARY,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "--" + BOUNDARY,
    "Content-Type: text/html; charset=utf-8",
    "",
    html,
    "--" + BOUNDARY + "--",
    "",
  ].join("\r\n"), "utf8");
}

async function openReplyDraft(reader, objectId) {
  var startedAt = process.hrtime.bigint();
  var page = await reader.get("/compose?source=" + encodeURIComponent(objectId) +
    "&folder=INBOX&mode=reply");
  return { page: page, ms: elapsedMs(startedAt) };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("reply-draft-quote-scan");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({
      dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });

    // The shapes the reduction has to answer the same way it always
    // has. Each is its own message, so a failure names the shape.
    //
    // What a browser would have SHOWN the reader is the answer each of
    // these is measured against, because the quote is the message the
    // account holder read and is now sending back. An element that
    // never closes swallows the rest of the line in a browser and it
    // swallows it here; an attribute value is markup rather than text
    // and appears in neither; a character reference is resolved so the
    // reader sees an ampersand rather than the five characters that
    // spell one.
    var SHAPES = [
      ["an ordinary element",        "<p>Hello there</p>",        "Hello there"],
      ["a character reference",      "a &amp; b",                 "a & b"],
      ["an empty pair of brackets",  "a<>b",                      "ab"],
      ["a bracket inside a bracket", "a<b<c>d",                   "ad"],
      ["a bracket that never closes", "a<b",                      "a"],
      ["a closing bracket alone",    "a>b",                       "a>b"],
      ["nothing but open brackets",  "<<<<",                      ""],
      ["an attribute holding a bracket", "<a title=\"x>y\">z</a>", "z"],
      // Script source is inside the markup and is not what the sender
      // wrote to be read. Leaving it in the quote puts it in the body
      // of the message the account holder sends onward.
      ["a script element",           "x<script>alert(1)</script>y", "xy"],
    ];

    var seededShapes = SHAPES.map(function (row, i) {
      var stored = identity.mailbox.appendMessage("INBOX",
        htmlMessage("shape" + i, row[1]), { actor: { id: alice.id } });
      return { label: row[0], want: row[2], objectId: stored.objectid };
    });

    // The two timed bodies, the same size and the same message in every
    // respect but the one character their markup is made of.
    var hostile = identity.mailbox.appendMessage("INBOX",
      htmlMessage("hostile", repeat("<", TIMED_BODY_BYTES)),
      { actor: { id: alice.id } });
    var ordinary = identity.mailbox.appendMessage("INBOX",
      htmlMessage("ordinary", repeat("x", TIMED_BODY_BYTES)),
      { actor: { id: alice.id } });

    listener = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   composer,
      dkim:      dkimHandle,
      delivery:  deliveryHandle,
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports = await listener.start();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http,
      { timeoutMs: READER_TIMEOUT_MS });
    await reader.signIn("alice@" + DOMAIN, ALICE_PASSWORD);

    // ---- the answers ------------------------------------------------------

    for (var i = 0; i < seededShapes.length; i += 1) {
      var shape = seededShapes[i];
      var opened = await openReplyDraft(reader, shape.objectId);
      count("the reply draft for " + shape.label + " renders",
        opened.page.status === 200, "HTTP " + opened.page.status);
      // Compared whole rather than by substring. The markup contains
      // the text it reduces to, so a draft that quoted the markup
      // untouched would satisfy a substring check on every vector here
      // and the file would pass without reducing anything.
      var quoted = quotedTextOf(opened.page);
      count("the draft quoting " + shape.label + " carries exactly " +
        JSON.stringify(shape.want),
        quoted !== null && quoted.trim() === shape.want,
        JSON.stringify(quoted));
    }

    // ---- what it costs ----------------------------------------------------

    // Opened once each before the reading, so neither pays for the first
    // fetch of a message, the first render of the page or anything the
    // engine compiles on the way through.
    await openReplyDraft(reader, ordinary.objectid);
    await openReplyDraft(reader, hostile.objectid);

    var ordinaryOpen = await openReplyDraft(reader, ordinary.objectid);
    var hostileOpen  = await openReplyDraft(reader, hostile.objectid);
    var excessMs     = hostileOpen.ms - ordinaryOpen.ms;

    // Printed whether the check passes or fails. A ceiling that holds
    // says nothing about how much room was left.
    console.log("MEASURED reply-draft hostile=" + hostileOpen.ms.toFixed(0) +
      "ms ordinary=" + ordinaryOpen.ms.toFixed(0) + "ms excess=" +
      excessMs.toFixed(0) + "ms at " + TIMED_BODY_BYTES + " bytes of body");

    count("the draft quoting a body of nothing but open brackets renders",
      hostileOpen.page.status === 200, "HTTP " + hostileOpen.page.status);
    count("the draft quoting an ordinary body of the same size renders",
      ordinaryOpen.page.status === 200, "HTTP " + ordinaryOpen.page.status);

    count("a body of " + TIMED_BODY_BYTES + " open brackets costs no more than " +
      QUOTE_EXCESS_CEILING_MS + " ms over an ordinary body of the same size",
      excessMs < QUOTE_EXCESS_CEILING_MS,
      "hostile " + hostileOpen.ms.toFixed(0) + " ms, ordinary " +
      ordinaryOpen.ms.toFixed(0) + " ms, difference " + excessMs.toFixed(0) + " ms");

    return helpers.getChecks();
  } finally {
    if (listener) {
      try { await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS }); }
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
  name:      "reply-draft-quote-scan",
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
