// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The subject and the sender's name, on their way to a person.
 *
 * These two strings are the most attacker-chosen text this server ever
 * shows anybody. They arrive in a header from a stranger, and RFC 2047
 * lets that stranger write them in an encoded word, so what the wire
 * carried and what a reader is shown are different sequences of
 * characters: `b.safeMime` decodes the encoded words while the message
 * is being stored, and the decoded form is what the subject column holds
 * and what every surface renders from.
 *
 * Two controls stand between that and a reader, and they cover different
 * things.
 *
 * The template escapes markup. `{{ }}` runs the engine's default escape
 * on every value, so a subject that decodes to a script tag renders as
 * text. That control is real and it is load bearing, and until now
 * nothing in the suite asserted it, which is the state where a later
 * change to a raw `{{{ }}}` would go unnoticed. The first cases here
 * pin it.
 *
 * The escape does not touch anything that is not markup, and it should
 * not, because a subject in Arabic or Japanese has to arrive intact. An
 * encoded word can also decode to a bidi override or a zero-width
 * character, which are neither markup nor content: they change what the
 * text LOOKS like without changing what it says. A subject that decodes
 * to `Invoice <RLO>gpj.exe` is displayed as `Invoice exe.jpg` by any
 * conforming renderer, and a display name carrying a zero-width space
 * reads as a name it is not. The reader deciding whether to open a
 * message is deciding on the rendering.
 *
 * `b.guardText` is the screen this server already puts in front of
 * untrusted text it shows somebody: the reason a far-side mail server
 * gave for refusing a message goes through it before it reaches the
 * queue view, a DNS record's text goes through it before the posture
 * report, and an account holder's own display name goes through it
 * before it is stored. The subject and the sender's name are the same
 * kind of value from a less trustworthy source, and the cases below say
 * so.
 *
 * The last group is the other half of that claim, and it is the one that
 * makes the screen safe to apply: legitimate international text has to
 * survive it unchanged. A screen that strips Arabic is not a screen, it
 * is an outage for everybody who writes in it.
 *
 * Run standalone: node test/layer-1-state/header-text-screening.test.js
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

// Written from their code points, so this file carries no bidi override
// or invisible character of its own. A source file that contained one
// would render wrong in every editor that opens it, which is the whole
// point of the class.
var RLO = String.fromCharCode(0x202e);   // RIGHT-TO-LEFT OVERRIDE
var ZWS = String.fromCharCode(0x200b);   // ZERO WIDTH SPACE

// One RFC 2047 encoded word carrying whatever bytes the sender chose.
// The base64 form, because it hides the payload from anything that
// screens the raw header rather than the decoded value.
function encodedWord(text) {
  return "=?UTF-8?B?" + Buffer.from(text, "utf8").toString("base64") + "?=";
}

function messageWith(fromHeader, subjectHeader, marker) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: " + fromHeader,
    "To: alice@" + DOMAIN,
    "Subject: " + subjectHeader,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "",
    "Body for " + marker + ".",
    "",
  ].join("\r\n"), "utf8");
}

// ---- cases -----------------------------------------------------------------

// The markup control. A decoded script tag has to arrive as text, on
// every page that renders a subject or a name.
function markupIsEscaped(page, label) {
  count(label + ": the page renders", page.status === 200, "HTTP " + page.status);
  count(label + ": a decoded script tag is not served as markup",
    page.body.indexOf("<script>alert(1)</script>") === -1,
    page.body.slice(0, 200));
  count(label + ": it is served as escaped text instead",
    page.body.indexOf("&lt;script&gt;") !== -1,
    page.body.slice(0, 200));
}

// The screening claim. Neither an override nor a zero-width character
// reaches the reader, because neither is something a subject legitimately
// needs and both change what the rendered line appears to say.
function invisiblesAreScreened(page, label) {
  count(label + ": no bidi override reaches the rendered page",
    page.body.indexOf(RLO) === -1,
    "found at index " + page.body.indexOf(RLO));
  count(label + ": no zero-width character reaches the rendered page",
    page.body.indexOf(ZWS) === -1,
    "found at index " + page.body.indexOf(ZWS));
}

// The other half: a screen that broke legitimate international text
// would be worse than the problem it solves.
function legitimateTextSurvives(page, label, expected) {
  count(label + ": legitimate international text is rendered unchanged",
    page.body.indexOf(expected) !== -1, JSON.stringify(expected));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("hdrscreen");
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

    // A CR or LF inside a decoded encoded word is header smuggling, and
    // the framework's decoder refuses the message rather than folding it
    // into a header block. Asserted here because it is the one case in
    // this family that must never become a screening question: a
    // refusal is the right answer and a sanitized pass would not be.
    var smuggled = null;
    try {
      b.safeMime.parse(messageWith("dana@peer.example",
        encodedWord("Subject\r\nBcc: attacker@evil.example"), "smuggle"));
    } catch (e) { smuggled = e; }
    count("an encoded word decoding to CR or LF is refused outright, not sanitized",
      smuggled !== null &&
      String(smuggled.code || "").indexOf("rfc2047-header-injection") !== -1,
      smuggled === null ? "nothing was thrown" : String(smuggled.code));

    var ARABIC = "تقرير ربع سنوي";
    var CJK    = "四半期レポート";

    var seeded = [
      ["markup",    "Dana Reyes <dana@peer.example>",
        encodedWord("<script>alert(1)</script>")],
      ["override",  encodedWord("Dana" + RLO + "Reyes") + " <dana@peer.example>",
        encodedWord("Invoice " + RLO + "gpj.exe")],
      ["zerowidth", encodedWord("Pay" + ZWS + "Pal") + " <dana@peer.example>",
        encodedWord("Receipt" + ZWS + "attached")],
      ["arabic",    "Dana Reyes <dana@peer.example>", encodedWord(ARABIC)],
      ["cjk",       "Dana Reyes <dana@peer.example>", encodedWord(CJK)],
    ].map(function (row, i) {
      var stored = identity.mailbox.appendMessage("INBOX",
        messageWith(row[1], row[2], "screen" + i),
        { actor: { id: alice.id } });
      return { label: row[0], objectId: stored.objectid };
    });

    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({
      dataDir: cfg.dataDir, store: identity });

    listener = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   blamepost.mail.compose.create({
        delivery:  deliveryHandle,
        hostname:  cfg.hostname,
        dkim:      dkimHandle,
        mailStore: identity.messageStore,
      }),
      dkim:      dkimHandle,
      delivery:  deliveryHandle,
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports = await listener.start();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    await reader.signIn("alice@" + DOMAIN, ALICE_PASSWORD);

    // The folder listing renders every subject and every sender name on
    // one page, which is where a reader decides what to open.
    var list = await reader.get("/mail?folder=INBOX");
    markupIsEscaped(list, "the folder listing");
    invisiblesAreScreened(list, "the folder listing");
    legitimateTextSurvives(list, "the folder listing, Arabic", ARABIC);
    legitimateTextSurvives(list, "the folder listing, Japanese", CJK);

    // And the message page, which renders the same two values again in
    // its title and its heading.
    for (var i = 0; i < seeded.length; i += 1) {
      var page = await reader.get("/mail/" + encodeURIComponent(seeded[i].objectId) +
        "?folder=INBOX");
      if (seeded[i].label === "markup") {
        markupIsEscaped(page, "the message page, markup");
      }
      if (seeded[i].label === "override" || seeded[i].label === "zerowidth") {
        invisiblesAreScreened(page, "the message page, " + seeded[i].label);
      }
      if (seeded[i].label === "arabic") {
        legitimateTextSurvives(page, "the message page, Arabic", ARABIC);
      }
      if (seeded[i].label === "cjk") {
        legitimateTextSurvives(page, "the message page, Japanese", CJK);
      }
    }

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
  name:      "header-text-screening",
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
