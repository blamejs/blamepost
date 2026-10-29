// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a caught fault's own words do on their way onto the browser
 * surface.
 *
 * A refusal this server catches is rarely this server's prose. A JMAP
 * client chooses the keyword and the property name a patch names, and the
 * sentence refusing the patch quotes them back. A receiving peer chooses
 * the reply text a delivery failure carries, and that text becomes the
 * sentence a mailbox owner reads on the compose form, the description a
 * JMAP client renders beside a submission, and the `detail` of the
 * problem document the sending route answers with.
 *
 * So the codepoints in those sentences belong to somebody else. Markup
 * escaping does not answer it: U+202E reverses the reading order of
 * everything after it without being markup at all, U+009B is one code
 * point that opens an escape sequence for anything reading the answer as
 * a stream, U+001B opens the two-byte form of the same thing, and a
 * carriage return with no line feed after it returns the cursor to the
 * start of the line so the second half of a sentence overwrites the
 * first. A reader deciding what to do next is reading a sentence the far
 * side composed.
 *
 * The screen is `blamepost.text.forDisplay`, which the mail listeners and
 * the command line already compose. This file measures the browser
 * surface against the same rule, at every exit a caught fault reaches.
 *
 * ## What this file drives
 *
 *   - `Email/set` naming a keyword this server does not set, where the
 *     keyword is the client's own bytes. The SetError description quotes
 *     them.
 *   - `Email/set` naming a property this server does not set, which is
 *     the second sentence in the same handler built the same way.
 *   - `EmailSubmission/set` over an outbound path that refuses in the far
 *     side's words.
 *   - `POST /api/send` with a sending credential, over the same refusal,
 *     whose answer is an RFC 9457 problem document.
 *   - The compose form, over the same refusal, whose answer is a rendered
 *     page.
 *
 * Every case asks the same question of the answer: does it still carry
 * any of the four. Each is named separately, so a failure says which one
 * survived rather than answering a bare false.
 *
 * The far side is a stand-in for one reason and one only: the four
 * codepoints have to be exactly the four this file wrote. Everything
 * between the request and the answer is real, including the composer, the
 * router, the template engine and the socket.
 *
 * It needs no external service. The ports are ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/web-fault-text-screen.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var OWNER_PASSWORD   = "quiet lantern bicycle 4291";
var BOUNCE_PASSWORD  = "another quiet lantern 7715";

var OWNER          = "alice@" + DOMAIN;
var BOUNCE_MAILBOX = "bounces@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The four codepoints, each built from its character code so this file
// stays plain ASCII: a source file carrying a raw C1 byte is classified
// as binary and drops out of every diff, and the byte does not survive
// being written in the first place.
//
// U+009B is the single-byte control sequence introducer, so a value
// carrying it colors, clears or moves whatever reads the answer as a
// stream. U+001B opens the same sequence in two bytes. U+202E reverses
// the run that follows it, which is how a name reading `Invoice exe.jpg`
// is stored as `gpj.exe`. A carriage return with no line feed ends a line
// for a reader that splits on either.
var CSI = String.fromCharCode(0x9b);
var ESC = String.fromCharCode(0x1b);
var RLO = String.fromCharCode(0x202e);
var CR  = String.fromCharCode(0x0d);

var ACTED_ON = [
  ["the control sequence introducer U+009B", CSI],
  ["the escape U+001B",                      ESC],
  ["the right-to-left override U+202E",      RLO],
  ["a carriage return with no line feed",    CR],
];

// A readable word on either side of the hostile run, so an assertion can
// say the sentence still reached the reader rather than that it was
// emptied. A screen that answered with nothing would satisfy a check that
// only asked whether the four were gone.
var LEADING  = "zebra7741";
var TRAILING = "tapir9930";

function hostile(middle) {
  return LEADING + CSI + "31m" + ESC + "[2K" + RLO + middle + CR + TRAILING;
}

// The keyword a client names in a patch, and the property name in the
// second patch. Both reach the refusal sentence as the client wrote them.
var HOSTILE_KEYWORD  = hostile("gpj.exe");
var HOSTILE_PROPERTY = hostile("subject");

// What the far side says when it refuses a message. A peer's reply text
// is the one piece of a delivery failure this server did not write.
var HOSTILE_REFUSAL = "550 " + hostile("mailbox unavailable");

// A key the sending route does not accept, and an identity the account
// does not hold. Both are fields of a request rather than anything a
// third party sent, which is the shortest path untrusted bytes take to a
// reader: one request in, one sentence back, quoting what was named.
var HOSTILE_UNKNOWN_KEY  = hostile("notAField");
var HOSTILE_IDENTITY_ID  = hostile("identity-nobody-holds");

// Which of the four a value still carries, by name.
function survivors(value) {
  var text = String(value === undefined || value === null ? "" : value);
  var out = [];
  for (var i = 0; i < ACTED_ON.length; i += 1) {
    if (text.indexOf(ACTED_ON[i][1]) !== -1) out.push(ACTED_ON[i][0]);
  }
  return out;
}

// One surface, asked the whole question in two parts: nothing a reader
// acts on survived, and the sentence still says something.
function screened(where, value) {
  var left = survivors(value);
  count(where + " carries none of the four codepoints a reader acts on",
    left.length === 0, left.join(", ") + " in " + JSON.stringify(String(value).slice(0, 200)));
  count(where + " still carries the words around them, so the screen repaired rather " +
    "than emptied the sentence",
    String(value).indexOf(LEADING) !== -1 && String(value).indexOf(TRAILING) !== -1,
    JSON.stringify(String(value).slice(0, 200)));
}

function describe(answer) {
  return answer.status + " " + String(answer.location || "") + " " +
    String(answer.body || "").replace(/\s+/g, " ").slice(0, 240);
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

async function testAKeywordAClientChoseComesBackScreened(reader, accountId, emailId) {
  var patch = {};
  patch.keywords = {};
  patch.keywords[HOSTILE_KEYWORD] = true;
  var update = {};
  update[emailId] = patch;

  var answer = await reader.jmap([["Email/set",
    { accountId: accountId, update: update }, "c0"]]);
  count("Email/set answers a patch naming a keyword this server does not set",
    answer.status === 200, describe(answer));

  var response = browser.answer(answer);
  count("and answers it as a method response rather than a method-level error",
    response[0] === "Email/set", JSON.stringify(response[0]));

  var refusal = response[1] && response[1].notUpdated && response[1].notUpdated[emailId];
  count("the message is reported not updated, with a SetError naming the reason",
    Boolean(refusal) && typeof refusal.description === "string",
    JSON.stringify(response[1] && response[1].notUpdated));
  if (!refusal || typeof refusal.description !== "string") return;

  screened("the Email/set SetError description", refusal.description);
}

async function testAPropertyAClientChoseComesBackScreened(reader, accountId, emailId) {
  var patch = {};
  patch[HOSTILE_PROPERTY] = "anything";
  var update = {};
  update[emailId] = patch;

  var answer = await reader.jmap([["Email/set",
    { accountId: accountId, update: update }, "c1"]]);
  var response = browser.answer(answer);
  var refusal = response[1] && response[1].notUpdated && response[1].notUpdated[emailId];
  count("a patch naming a property this server does not set is refused with a description",
    Boolean(refusal) && typeof refusal.description === "string",
    JSON.stringify(response[1] && response[1].notUpdated));
  if (!refusal || typeof refusal.description !== "string") return;

  screened("the SetError description refusing an unknown property", refusal.description);
}

async function testASubmissionRefusedByTheFarSideComesBackScreened(
  reader, accountId, identityId, draftId) {
  var create = {};
  create.one = { identityId: identityId, emailId: draftId };

  var answer = await reader.jmap([["EmailSubmission/set",
    { accountId: accountId, create: create }, "c2"]]);
  count("EmailSubmission/set answers a submission the outbound path refused",
    answer.status === 200, describe(answer));

  var response = browser.answer(answer);
  var refusal = response[1] && response[1].notCreated && response[1].notCreated.one;
  count("the submission is reported not created, with a SetError naming the far side's reason",
    Boolean(refusal) && typeof refusal.description === "string",
    JSON.stringify(response[1] && response[1].notCreated));
  if (!refusal || typeof refusal.description !== "string") return;

  screened("the EmailSubmission/set SetError description", refusal.description);
}

async function testTheSendingRouteProblemDocumentComesBackScreened(reader, token) {
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from:    "shop@" + DOMAIN,
    to:      ["somebody@example.net"],
    subject: "a receipt the far side would not take",
    text:    "A message written by an application rather than by a person.",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "web-fault-text-screen-one",
    "Accept":          "application/json",
  });

  count("the sending route answers a message the outbound path refused with a refusal",
    answer.status >= 400, describe(answer));
  var problem;
  try { problem = JSON.parse(answer.body); }
  catch (_e) { problem = null; }
  count("and answers it as a problem document carrying a detail",
    Boolean(problem) && typeof problem.detail === "string", describe(answer));
  if (!problem || typeof problem.detail !== "string") return;

  screened("the sending route's problem detail", problem.detail);
  // The document is what a client reads, so the octets it arrived as are
  // asked as well as the field parsed out of them. A screen applied after
  // serialization would leave the wire carrying what the field does not.
  screened("the sending route's problem document as it arrived", answer.body);
}

// The other half of the same exit, and the input is the caller's rather
// than a far side's. A body naming a key this route does not accept is
// refused by the schema, and the sentence saying so quotes the key: the
// caller chose those bytes, and the answer is the same problem document
// the delivery refusal above comes back in.
async function testAKeyTheCallerInventedComesBackScreened(reader, token) {
  var body = {
    from:    "shop@" + DOMAIN,
    to:      ["somebody@example.net"],
    subject: "one with a key this route does not take",
    text:    "a body",
  };
  body[HOSTILE_UNKNOWN_KEY] = "anything";

  var answer = await reader.post("/api/send", "application/json", JSON.stringify(body), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": "web-fault-text-screen-unknown-key",
    "Accept":          "application/json",
  });

  count("the sending route refuses a body naming a key it does not accept",
    answer.status === 400, describe(answer));
  var problem;
  try { problem = JSON.parse(answer.body); }
  catch (_e) { problem = null; }
  count("and answers it as a problem document carrying a detail",
    Boolean(problem) && typeof problem.detail === "string", describe(answer));
  if (!problem || typeof problem.detail !== "string") return;

  screened("the problem detail refusing a key the caller invented", problem.detail);
  screened("that problem document as it arrived", answer.body);
}

// The author a request named, echoed back in the refusal that would not
// take it. It is the caller's own bytes on the shortest path there is:
// one field of one request, quoted into a sentence a person reads.
async function testAnAuthorTheCallerNamedComesBackScreened(reader, accountId, draftId) {
  var create = {};
  create.one = { identityId: HOSTILE_IDENTITY_ID, emailId: draftId };

  var answer = await reader.jmap([["EmailSubmission/set",
    { accountId: accountId, create: create }, "c3"]]);
  var response = browser.answer(answer);
  var refusal = response[1] && response[1].notCreated && response[1].notCreated.one;
  count("a submission naming an identity this account does not hold is refused with a " +
    "description quoting what was named",
    Boolean(refusal) && typeof refusal.description === "string",
    JSON.stringify(response[1] && response[1].notCreated));
  if (!refusal || typeof refusal.description !== "string") return;

  screened("the SetError description quoting the identity the caller named", refusal.description);
}

async function testTheComposeFormComesBackScreened(reader) {
  await reader.readCsrf("/compose");
  var answer = await reader.form("/compose", {
    from:    OWNER,
    to:      "somebody@example.net",
    cc:      "",
    bcc:     "",
    subject: "one the far side would not take",
    text:    "a body",
  });

  count("the compose form answers a send the outbound path refused with the form again",
    answer.status === 502, describe(answer));
  screened("the compose page the mailbox owner is handed back", answer.body);
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

// The far side, refusing in its own words. Only the socket is stood in:
// the composer above it is the shipped one, and the refusal travels the
// path a peer's reply travels.
function refusingDelivery() {
  return helpers.standInDelivery({
    send: function () {
      var refusal = new Error(HOSTILE_REFUSAL);
      refusal.code = "delivery/permanent";
      return Promise.reject(refusal);
    },
  });
}

function wiringFor(cfg, identity, tls) {
  // The browser surface takes the real outbound handle, because it reads
  // the spool for its readiness probe and a stand-in would answer that
  // question instead of the one this file asks. The composer above it is
  // the shipped composer over a far side that refuses, which is the only
  // piece stood in.
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({
      store: identity.messageStore, dispatch: { mode: "local" },
    }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  refusingDelivery(),
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return []; },
    address:   LOOPBACK,
    httpPort:  0,
    // The sending route is reachable over TLS alone, because a credential
    // presented on a cleartext socket is a credential on the wire.
    httpsPort: tls === undefined ? undefined : 0,
    tls:       tls,
  };
}

function draftIn(identity, accountId, wireName) {
  var folder = b.db.from(mailbox.FOLDERS)
    .where({ account: accountId, wireName: wireName }).first().folder;
  var rows = identity.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 10 });
  return rows.length === 0 ? null : rows[rows.length - 1].objectid;
}

function message(id, from, to, subject) {
  return Buffer.from(
    "Message-ID: <" + id + "@" + DOMAIN + ">\r\n" +
    "From: <" + from + ">\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe body of a draft this run submits\r\n", "utf8");
}

async function run() {
  var root    = helpers.tempDir("web-fault-text-screen");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var exitsRead = 0;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "fault text screen test" });

    var owner = await identity.accounts.create({
      address: OWNER, password: OWNER_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    var credential = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "an application posting receipts, for the sending route's refusal shape",
      maxMessages:   50,
      maxRecipients: 50,
    });

    identity.mailbox.appendMessage("INBOX",
      message("held", "sender@example.net", OWNER, "one already filed"),
      { actor: { id: owner.id } });
    identity.mailbox.appendMessage("Drafts",
      message("draft", OWNER, "somebody@example.net", "one to submit"),
      { actor: { id: owner.id } });

    var emailId = draftIn(identity, owner.id, "INBOX");
    var draftId = draftIn(identity, owner.id, "Drafts");
    count("the fixture landed a filed message and a draft to submit",
      typeof emailId === "string" && emailId.length > 0 &&
        typeof draftId === "string" && draftId.length > 0,
      JSON.stringify({ emailId: emailId, draftId: draftId }));

    listener = blamepost.web.serve(wiringFor(cfg, identity, {
      certFile: material.certFile, keyFile: material.keyFile }));
    var ports = await listener.start();
    var origin = "https://" + LOOPBACK + ":" + ports.https;

    var reader = browser.browserAt(origin, { ca: material.caPem, servername: HOSTNAME });
    var landed = await reader.signIn(OWNER, OWNER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));

    var session = await reader.get("/jmap/session", { Accept: "application/json" });
    count("the session document answers a signed in account", session.status === 200,
      describe(session));
    var doc = JSON.parse(session.body);
    var accountId = Object.keys(doc.accounts || {})[0];
    count("the session names the account a JMAP call addresses",
      typeof accountId === "string" && accountId.length > 0, JSON.stringify(doc.accounts));

    var identityAnswer = await reader.jmap([["Identity/get",
      { accountId: accountId, ids: null }, "i0"]]);
    var identityList = browser.answer(identityAnswer)[1].list || [];
    count("the account holds an identity to submit under", identityList.length > 0,
      JSON.stringify(identityList));
    var identityId = identityList.length > 0 ? identityList[0].id : "";

    await testAKeywordAClientChoseComesBackScreened(reader, accountId, emailId);
    await testAPropertyAClientChoseComesBackScreened(reader, accountId, emailId);
    await testASubmissionRefusedByTheFarSideComesBackScreened(
      reader, accountId, identityId, draftId);

    // The sending route holds no cookie, because it reads its credential
    // off the Authorization header and refuses an ambient one.
    var application = browser.browserAt(origin, { ca: material.caPem, servername: HOSTNAME });
    await testTheSendingRouteProblemDocumentComesBackScreened(application, credential.token);
    await testAKeyTheCallerInventedComesBackScreened(application, credential.token);
    await testAnAuthorTheCallerNamedComesBackScreened(reader, accountId, draftId);

    await testTheComposeFormComesBackScreened(reader);
    exitsRead = 7;

    await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    listener = null;

    return helpers.getChecks();
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
    console.log("EXAMINED " + exitsRead + " screened-exits");
  }
}

module.exports = {
  name:      "web-fault-text-screen",
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
