// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The author binding, measured where every surface crosses it.
 *
 * `blamepost.mail.listeners.authorBinding` decides whether the account
 * that signed in may write the `From` and `Sender` a message carries.
 * The submission listener applies it to every message a desktop client
 * hands over. The browser compose form and JMAP `EmailSubmission/set`
 * build their own message and hand it to
 * `blamepost.mail.compose.send`, so the composer is where those two
 * cross the rule, and a composer that trusted its caller left the rule
 * to whichever surface remembered it.
 *
 * What is pinned:
 *
 *   - A composer built with the binding refuses an author the acting
 *     account may not write, whichever verb reaches it: `send`, `reply`
 *     or `forward`. The refusal carries `550`, the RFC 3463 status of
 *     its class, and the audit row an operator queries.
 *   - `5.7.1` is the class for an address at a domain this server signs
 *     for that the account does not hold, and `5.6.0` is the class for a
 *     header block naming no single readable author. The two carry
 *     opposite advice to a peer, so they are asserted apart.
 *   - An author at a domain this server does not host is accepted under
 *     a `Sender` the account holds, because this server's key creates no
 *     alignment for a domain it does not sign for.
 *   - A send that names no account is refused rather than sent
 *     unmeasured, so forgetting to say who a message is for cannot be
 *     the way to send as anybody.
 *   - The browser and JMAP surfaces still accept what they accepted and
 *     still refuse what they refused, with the same status and the same
 *     answer shape. Their own refusals happen first and reach the
 *     composer's binding not at all, which is read off the audit trail
 *     rather than argued from the code.
 *   - The server `blamepost.create` assembles wires the binding into its
 *     composer, so the guarantee belongs to the shipped composition
 *     rather than to a handle a test built.
 *
 * The fixture hosts two domains and holds two accounts, because a
 * single hosted domain is the one arrangement where an author at a
 * hosted domain the account does not hold cannot be written down.
 *
 * It needs no external service. The browser port is ephemeral on the
 * loopback interface, the data directory is temporary, and the outbound
 * path is the shared stand-in with a recorder on its send.
 *
 * Run standalone: node test/layer-1-state/compose-author-binding.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SECOND   = "other.example";
var OUTSIDE  = "partner.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var MALLORY_PASSWORD = "another quiet lantern 7715";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The addresses the fixture builds. `sales` and `press` are aliases the
// acting account holds, `press` at the second hosted domain so nothing
// here passes by reading one domain as the whole of what an account may
// write. `mallory` and `news` are held by the other account, one at each
// hosted domain, so the refusal has a hosted address to be about in both
// places. `partner` is at a domain this server does not host.
var ALICE    = "alice@" + DOMAIN;
var SALES    = "sales@" + DOMAIN;
var PRESS    = "press@" + SECOND;
var MALLORY  = "mallory@" + DOMAIN;
var NEWS     = "news@" + SECOND;
var OUTSIDER = "partner@" + OUTSIDE;

var RECIPIENT = "buyer@peer.example";

// The refusal's own code, which survives a rename of the function that
// throws it and disappears if the throw is deleted.
var FROM_HEADER_NOT_OWNED = "listeners/from-header-not-owned";

// The trail a refusal leaves, one action per layer that refused. The
// browser and JMAP surfaces resolve the identity a request named before
// they compose anything and file their refusals under the web action;
// the binding files its own. Reading both apart is what answers whether
// a request was refused once or twice.
var BINDING_ACTION = "blamepost.mail.listeners.submission_from_not_owned";
var WEB_ACTION     = "blamepost.web.author_not_permitted";

// The compose form's refusal notice, read off the rendered page rather
// than out of the handler, because the handler's answer is not what a
// reader is shown.
var NOTICE_RE = /notice-bad[\s\S]*?<p>([\s\S]*?)<\/p>/;

function noticeOf(page) {
  var found = NOTICE_RE.exec(page.body);
  return found === null ? null : found[1].trim();
}

// One outbound path that records rather than connects. The composer
// requires the whole delivery handle, so the shared stand-in carries the
// queue contract and only `send` is replaced.
function outboundLog() {
  var sent = [];
  return {
    delivery: helpers.standInDelivery({
      send: function (envelope) {
        sent.push({ from: envelope.from, rfc822: envelope.rfc822 });
        return Promise.resolve({
          delivered: (envelope.to || []).slice(), deferred: [], failed: [],
        });
      },
    }),
    count: function () { return sent.length; },
    last:  function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
  };
}

// One header value off a recorded message, read as octets. The message
// never becomes text here: it is about to be compared against an address
// this server decided, and a decode would substitute a replacement
// character for anything the decoder does not recognize.
function headerOf(rfc822, name) {
  var parsed = b.safeMime.parse(rfc822);
  return parsed.headers.get(name) || "";
}

// A message description the vectors vary one field of.
function draft(fields) {
  var message = {
    to:      [RECIPIENT],
    subject: "the quarterly order",
    text:    "Confirming the quantities we discussed.",
  };
  Object.keys(fields).forEach(function (name) { message[name] = fields[name]; });
  return message;
}

// The bytes a reply and a forward are derived from, so those two verbs
// can be driven with a real original rather than a description.
function original() {
  return Buffer.from([
    "Message-ID: <original@peer.example>",
    "From: Dana Reyes <" + RECIPIENT + ">",
    "To: <" + ALICE + ">",
    "Subject: the quarterly order",
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "",
    "How many did you want?",
    "",
  ].join("\r\n"), "utf8");
}

async function refusalOf(fn) {
  try {
    await fn();
    return null;
  } catch (e) {
    return e;
  }
}

// ---- the composer, driven directly -----------------------------------------

// The hole this file exists for. A surface that reached the composer
// without proving the author first sent whatever it was handed, so the
// rule belonged to whichever caller remembered it.
async function anUnownedAuthorIsRefused(composer, actor, log, written, label) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({ from: written }), { actor: actor });
  });

  count(label + ": the composer refuses an author this account may not write",
    refused !== null, "the message was accepted");
  count(label + ": the refusal carries the code the submission listener throws, so one " +
    "reader answers for the wire and the composer alike",
    refused !== null && refused.code === FROM_HEADER_NOT_OWNED,
    refused === null ? "accepted" : String(refused.code));
  count(label + ": it is a permanent refusal rather than one a client retries",
    refused !== null && refused.smtpCode === "550",
    refused === null ? "accepted" : String(refused.smtpCode));
  count(label + ": and it is filed as an authorization fault, which is the class a peer " +
    "reads as the operator's provisioning rather than as its own bug",
    refused !== null && refused.enhancedStatus === "5.7.1",
    refused === null ? "accepted" : String(refused.enhancedStatus));
  count(label + ": nothing reached the outbound path",
    log.count() === before, log.count() + " after " + before);
  count(label + ": the refusal names the address that was rejected",
    refused !== null && refused.message.indexOf(written) !== -1,
    refused === null ? "accepted" : refused.message);
  count(label + ": and names the addresses that would have been accepted, because a " +
    "shared address that was never delegated is the case an operator meets first",
    refused !== null && refused.message.indexOf(SALES) !== -1 &&
    refused.message.indexOf(PRESS) !== -1,
    refused === null ? "accepted" : refused.message);
}

async function aPermittedAuthorIsSent(composer, actor, log, written, label) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({ from: written, envelopeFrom: ALICE }), { actor: actor });
  });

  count(label + ": a message written as an address this account holds is sent",
    refused === null, refused === null ? undefined : refused.message);
  count(label + ": and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);
  var out = log.last();
  count(label + ": its From header names the address that was asked for",
    out !== null && headerOf(out.rfc822, "from").indexOf(written) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
  count(label + ": and the envelope sender stays the account's own address",
    out !== null && out.from === ALICE, out === null ? "nothing sent" : String(out.from));
}

// The allowance the binding is built to keep. This server signs for the
// domains it hosts and for no others, so an author at a domain it does
// not host takes no alignment from its key, and that domain's own policy
// answers for the message. What has to be held is the `Sender`, which is
// the address this account is transmitting under.
async function anOutsideAuthorUnderAnOwnedSenderIsSent(composer, actor, log) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({
      from:         OUTSIDER,
      envelopeFrom: ALICE,
      headers:      { Sender: ALICE },
    }), { actor: actor });
  });

  count("an author at a domain this server does not host is sent when Sender names an " +
    "address this account holds",
    refused === null, refused === null ? undefined : refused.message);
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);
  var out = log.last();
  count("the From header still names the outside author, so nothing was rewritten on the " +
    "way through",
    out !== null && headerOf(out.rfc822, "from").indexOf(OUTSIDER) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
  count("and the Sender header still names the address this account transmitted under",
    out !== null && headerOf(out.rfc822, "sender").indexOf(ALICE) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "sender"));
}

async function anOutsideAuthorAloneIsRefused(composer, actor, log) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({ from: OUTSIDER, envelopeFrom: ALICE }), { actor: actor });
  });

  count("an author at a domain this server does not host, with no Sender beside it, is " +
    "refused, because the message is then attributable to nobody who signed in to send it",
    refused !== null && refused.code === FROM_HEADER_NOT_OWNED,
    refused === null ? "accepted" : String(refused.code));
  count("and it is refused as an authorization fault",
    refused !== null && refused.enhancedStatus === "5.7.1",
    refused === null ? "accepted" : String(refused.enhancedStatus));
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// The other class. RFC 5322 section 3.6.2 gives Sender exactly one
// mailbox, so two is not a delegation, it is an ambiguity, and a peer
// reading `5.6.0` is told the sending client has a bug rather than that
// the operator has provisioning to do.
async function aSenderNamingTwoAddressesIsRefused(composer, actor, log) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({
      from:         OUTSIDER,
      envelopeFrom: ALICE,
      headers:      { Sender: SALES + ", " + PRESS },
    }), { actor: actor });
  });

  count("a From and Sender pair naming no single readable author is refused",
    refused !== null && refused.code === FROM_HEADER_NOT_OWNED,
    refused === null ? "accepted" : String(refused.code));
  count("and it is refused as a content fault rather than as an authorization one, " +
    "because the two carry opposite advice to the client that sent it",
    refused !== null && refused.enhancedStatus === "5.6.0",
    refused === null ? "accepted" : String(refused.enhancedStatus));
  count("it is still a permanent refusal", refused !== null && refused.smtpCode === "550",
    refused === null ? "accepted" : String(refused.smtpCode));
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// Reading an absent actor as permission would make forgetting to name
// the sender the way to send as anybody, which is the arrangement this
// change exists to end.
async function aSendNamingNoAccountIsRefused(composer, log) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return composer.send(draft({ from: MALLORY }), {});
  });

  count("a send that names no account is refused rather than sent unmeasured",
    refused !== null, "the message was accepted");
  count("the refusal says which argument was missing",
    refused !== null && refused.message.indexOf("actor") !== -1,
    refused === null ? "accepted" : refused.message);
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// Reply and forward derive a message and hand it to the same send, so a
// binding that only covered the direct verb would leave two ways past it.
async function theDerivingVerbsAreBoundToo(composer, actor, log) {
  var before = log.count();
  var replyRefused = await refusalOf(function () {
    return composer.reply({
      original: original(), from: MALLORY, text: "Six hundred.", actor: actor,
    });
  });
  count("a reply written as an author this account may not write is refused",
    replyRefused !== null && replyRefused.code === FROM_HEADER_NOT_OWNED,
    replyRefused === null ? "accepted" : String(replyRefused.code));

  var forwardRefused = await refusalOf(function () {
    return composer.forward({
      original: original(), from: MALLORY, to: [RECIPIENT], actor: actor,
    });
  });
  count("and so is a forward",
    forwardRefused !== null && forwardRefused.code === FROM_HEADER_NOT_OWNED,
    forwardRefused === null ? "accepted" : String(forwardRefused.code));

  count("neither reached the outbound path", log.count() === before,
    log.count() + " after " + before);

  var replySent = await refusalOf(function () {
    return composer.reply({
      original: original(), from: SALES, text: "Six hundred.", actor: actor,
    });
  });
  count("a reply written as an address this account holds is still sent, so the binding " +
    "did not close the verb along with the hole",
    replySent === null && log.count() === before + 1,
    replySent === null ? log.count() + " after " + before : replySent.message);
}

// The control. Without it every refusal above would hold against a
// composer that refuses whatever it is handed, and the opt would be
// proving nothing about itself.
async function anUnboundComposerIsWhereTheHoleWas(unbound, actor, log) {
  var before = log.count();
  var refused = await refusalOf(function () {
    return unbound.send(draft({ from: MALLORY, envelopeFrom: ALICE }), { actor: actor });
  });

  count("a composer built with no author binding sends the same message, which is what " +
    "the wiring is what decides here rather than something else in the path",
    refused === null, refused === null ? undefined : refused.message);
  count("and it reaches the outbound path", log.count() === before + 1,
    log.count() + " after " + before);
}

// ---- the trail a refusal leaves --------------------------------------------

async function everyCompositeRefusalLeftARow(capture, expected) {
  // A row reaches the sink through a flush, so it is asked for once at
  // the end rather than beside each refusal, which is how every other
  // file that reads this trail reads it.
  await b.audit.flush();
  var rows = capture.forAction(BINDING_ACTION);
  count("every author the composer refused left a row an operator can find",
    rows.length === expected, rows.length + " rows for " + expected + " refusals");
  count("every row is filed as a denial rather than as something that happened",
    rows.every(function (row) { return row.outcome === "denied"; }),
    JSON.stringify(rows.map(function (row) { return row.outcome; })));
  count("every row names the account that was acting, in the column an auditor filters on",
    rows.every(function (row) {
      return typeof row.actorUserId === "string" && row.actorUserId.length > 0;
    }),
    JSON.stringify(rows.map(function (row) { return row.actorUserId; })));
  count("and every row names the identity that was rejected together with the ones that " +
    "would have been accepted",
    rows.every(function (row) {
      var carried = helpers.metadataOf(row);
      return typeof carried.rejected === "string" && carried.permittedCount > 0;
    }),
    JSON.stringify(rows.map(function (row) { return helpers.metadataOf(row).rejected; })));
}

// ---- the browser and JMAP, with the binding armed --------------------------

// How many refusals one action has produced so far. Asked after a flush
// every time, because a row that has not reached the sink yet reads as a
// refusal that never happened, and every assertion below is phrased as
// an upper bound that such a row would quietly satisfy.
async function refusalsSoFar(capture, action) {
  await b.audit.flush();
  return capture.forAction(action).length;
}

// The binding, with a count of the times the composer reached it.
//
// Whether the browser and JMAP are measured twice is a question about
// what runs rather than about what a refusal looked like afterwards, and
// counting the calls is the only thing that answers it directly. Both
// surfaces resolve the identity a request named before they compose
// anything, so a message they accept is measured a second time here and
// has to pass, and a message they refuse never arrives.
function countingBinding(bound) {
  var calls = 0;
  return {
    run:   function (actor, rfc822) { calls += 1; return bound(actor, rfc822); },
    calls: function () { return calls; },
  };
}

// Both surfaces resolve the identity a request named against the same
// set before they compose anything, so the binding should pass on
// everything they accept and should never be what refuses. Reasoning
// that is not measuring it: a second refusal on a legitimate message
// reaches a person, and a refusal that moved from one layer to another
// changes the status and the wording a reader is shown.
async function theBrowserStillSendsWhatItSent(reader, log, capture, binding, written, label) {
  var before = log.count();
  var rowsBefore = await refusalsSoFar(capture, BINDING_ACTION);
  var callsBefore = binding.calls();
  var fields = {
    to:      RECIPIENT,
    subject: "sent from the browser as " + label,
    text:    "This one should leave.",
  };
  if (written !== null) fields.from = written;
  var sent = await reader.form("/compose", fields);

  count("the compose form still accepts a message written as " + label,
    sent.status === 302, "HTTP " + sent.status + " " + String(noticeOf(sent)));
  count("and it still reaches the outbound path", log.count() === before + 1,
    log.count() + " after " + before);
  count("the composer measured it against the binding, so the rule ran on this surface " +
    "rather than being left to the surface's own reading of the set",
    binding.calls() === callsBefore + 1, binding.calls() + " after " + callsBefore);
  var rowsAfter = await refusalsSoFar(capture, BINDING_ACTION);
  count("the binding refused nothing on the way, so a message this surface accepts is " +
    "not refused a second time behind it",
    rowsAfter === rowsBefore, rowsAfter + " after " + rowsBefore);
}

async function theBrowserStillRefusesWhatItRefused(reader, log, capture, binding, written, label) {
  var before = log.count();
  var rowsBefore = await refusalsSoFar(capture, BINDING_ACTION);
  var webBefore  = await refusalsSoFar(capture, WEB_ACTION);
  var callsBefore = binding.calls();
  var sent = await reader.form("/compose", {
    from: written, to: RECIPIENT, subject: "refused: " + label, text: "This one should not leave.",
  });

  count(label + ": the compose form still answers 400 rather than the 502 a refusal " +
    "arriving from the outbound path would render",
    sent.status === 400, "HTTP " + sent.status);
  count(label + ": the notice still names the identity that was rejected",
    noticeOf(sent) !== null && noticeOf(sent).indexOf(written) !== -1, String(noticeOf(sent)));
  count(label + ": nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
  var webAfter  = await refusalsSoFar(capture, WEB_ACTION);
  var rowsAfter = await refusalsSoFar(capture, BINDING_ACTION);
  count(label + ": the surface filed its own refusal",
    webAfter === webBefore + 1, webAfter + " after " + webBefore);
  count(label + ": the composer was never reached, so the reader is answered by the " +
    "surface that can render a form rather than by a wire refusal behind it",
    binding.calls() === callsBefore, binding.calls() + " after " + callsBefore);
  count(label + ": and the binding filed no refusal of its own, so the message was " +
    "refused once rather than twice",
    rowsAfter === rowsBefore, rowsAfter + " after " + rowsBefore);
}

async function jmapStillSendsWhatItSent(reader, accountId, emailId, identityId, log, capture,
                                        binding) {
  var before = log.count();
  var rowsBefore = await refusalsSoFar(capture, BINDING_ACTION);
  var callsBefore = binding.calls();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: identityId, emailId: emailId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];

  count("EmailSubmission/set still creates a submission naming an identity this account holds",
    Object.prototype.hasOwnProperty.call(result.created || {}, "s0"),
    JSON.stringify(result.notCreated));
  count("and it still reaches the outbound path", log.count() === before + 1,
    log.count() + " after " + before);
  var out = log.last();
  count("its From header still names the identity the client chose",
    out !== null && headerOf(out.rfc822, "from").indexOf(SALES) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
  count("the composer measured it against the binding here too, so a JMAP client and a " +
    "desktop client are held to the rule by the same code",
    binding.calls() === callsBefore + 1, binding.calls() + " after " + callsBefore);
  var rowsAfter = await refusalsSoFar(capture, BINDING_ACTION);
  count("the binding refused nothing on the way",
    rowsAfter === rowsBefore, rowsAfter + " after " + rowsBefore);
}

async function jmapStillRefusesWhatItRefused(reader, accountId, emailId, log, capture, binding) {
  var before = log.count();
  var rowsBefore = await refusalsSoFar(capture, BINDING_ACTION);
  var callsBefore = binding.calls();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: "idt_0000000000000000000000000000000f", emailId: emailId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];
  var refusal = (result.notCreated || {}).s0 || null;

  count("a submission naming an identity this account does not hold is still refused",
    refusal !== null, JSON.stringify(result.created));
  count("and it is still refused as an identity that was not found, which is the error " +
    "RFC 8621 section 7.5 gives that case, rather than as a send the outbound path declined",
    refusal !== null && refusal.type === "identityNotFound",
    refusal === null ? "created" : String(refusal.type));
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
  count("the composer was never reached, so the client is answered in the vocabulary of " +
    "the protocol it is speaking",
    binding.calls() === callsBefore, binding.calls() + " after " + callsBefore);
  var rowsAfter = await refusalsSoFar(capture, BINDING_ACTION);
  count("and the binding filed no refusal of its own",
    rowsAfter === rowsBefore, rowsAfter + " after " + rowsBefore);
}

// ---- the composition an operator actually runs -----------------------------

// Every assertion above holds against a composer this file built. What
// ships is the one `blamepost.create` assembles, and an option left off
// there is a guarantee that exists in the tests and nowhere else.
async function theShippedCompositionCarriesTheBinding(runtimeConfig, identity, actor) {
  var server = blamepost.create({
    config:       runtimeConfig,
    store:        identity,
    mailStore:    identity.mailbox,
    messageStore: identity.messageStore,
    httpAddress:  LOOPBACK,
  });
  try {
    count("the listener handle the server assembles exposes the author binding",
      typeof server.mail.listeners.authorBinding === "function",
      typeof server.mail.listeners.authorBinding);

    // Refused before the signer and before delivery, so this reaches no
    // socket and needs no outbound path standing in for one.
    var refused = await refusalOf(function () {
      return server.mail.compose.send(draft({ from: MALLORY, envelopeFrom: ALICE }),
        { actor: actor });
    });
    count("and the composer it hands every sending surface refuses an author the acting " +
      "account may not write",
      refused !== null && refused.code === FROM_HEADER_NOT_OWNED,
      refused === null ? "the message was accepted" : String(refused.code));
    count("with the same status the wire answers",
      refused !== null && refused.smtpCode === "550" && refused.enhancedStatus === "5.7.1",
      refused === null ? "accepted"
        : String(refused.smtpCode) + " " + String(refused.enhancedStatus));
  } finally {
    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  }
}

// ---- runner ----------------------------------------------------------------

function storedMessage(marker, to) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: Dana Reyes <" + RECIPIENT + ">",
    "To: <" + to + ">",
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "",
    "Body for " + marker + ".",
    "",
  ].join("\r\n"), "utf8");
}

async function run() {
  var root    = helpers.tempDir("composeauthor");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside this run's own temporary tree keeps the encrypted at rest
  // path exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var capture  = null;

  try {
    // Written before the configuration is read, because the loader
    // checks that a named certificate exists and refuses the boot when
    // it does not.
    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: SECOND });

    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });
    await identity.accounts.create({ address: MALLORY, password: MALLORY_PASSWORD });

    await identity.aliases.add({ address: SALES, destination: ALICE });
    await identity.aliases.add({ address: PRESS, destination: ALICE });
    await identity.aliases.add({ address: NEWS,  destination: MALLORY });

    var actor = { id: alice.id, address: alice.address };

    // The one derivation, asked here so every assertion below compares
    // against the answer the server composes rather than against a list
    // restated in this file.
    var allowed = blamepost.mail.listeners.permittedAuthors(identity, actor);
    count("the acting account holds addresses at both hosted domains, which is the " +
      "arrangement a cross-domain author refusal needs to be written down at all",
      allowed.indexOf(SALES) !== -1 && allowed.indexOf(PRESS) !== -1, JSON.stringify(allowed));
    count("and holds neither of the addresses the other account was given",
      allowed.indexOf(MALLORY) === -1 && allowed.indexOf(NEWS) === -1, JSON.stringify(allowed));

    var log = outboundLog();
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    var listenerHandle = blamepost.mail.listeners.create({
      config:      cfg,
      store:       identity,
      mailStore:   identity.mailbox,
      delivery:    log.delivery,
      dkim:        dkimHandle,
      // None of these listeners has a plaintext mode, so the handle is
      // required at construction even though nothing here binds a port.
      certificate: certs.handle({ cert: certificate.chain, key: certificate.key }),
    });
    var binding = countingBinding(listenerHandle.authorBinding);
    var composer = blamepost.mail.compose.create({
      delivery:      log.delivery,
      hostname:      cfg.hostname,
      dkim:          dkimHandle,
      mailStore:     identity.mailbox,
      authorBinding: binding.run,
    });
    var unbound = blamepost.mail.compose.create({
      delivery:  log.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });

    // ---- the composer, driven directly ----
    capture = helpers.auditCapture();
    await anUnownedAuthorIsRefused(composer, actor, log, MALLORY,
      "another account's own address at the first hosted domain");
    await anUnownedAuthorIsRefused(composer, actor, log, NEWS,
      "another account's alias at the second hosted domain");
    await aPermittedAuthorIsSent(composer, actor, log, ALICE, "the account's own address");
    await aPermittedAuthorIsSent(composer, actor, log, SALES, "a shared alias");
    await aPermittedAuthorIsSent(composer, actor, log, PRESS,
      "an alias at the second hosted domain");
    await anOutsideAuthorUnderAnOwnedSenderIsSent(composer, actor, log);
    await anOutsideAuthorAloneIsRefused(composer, actor, log);
    await aSenderNamingTwoAddressesIsRefused(composer, actor, log);
    await aSendNamingNoAccountIsRefused(composer, log);
    await theDerivingVerbsAreBoundToo(composer, actor, log);
    await everyCompositeRefusalLeftARow(capture, 6);
    await anUnboundComposerIsWhereTheHoleWas(unbound, actor, log);
    capture.release();
    capture = null;

    // ---- the browser and JMAP, with the binding armed ----
    var draftRow = identity.mailbox.appendMessage("Drafts", storedMessage("jmap-draft", ALICE),
      { actor: { id: alice.id } });

    listener = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   composer,
      dkim:      dkimHandle,
      // The browser surface reads the outbound queue for the operator
      // console, which the recorder does not answer for. Only the
      // composer's own path is stood in for here, because that is the
      // one these vectors are about.
      delivery:  blamepost.mail.delivery.create({
        hostname: cfg.hostname, dataDir: cfg.dataDir }),
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports  = await listener.start();
    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var landing = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the acting account signs in to the browser surface",
      landing.status === 302, landing.status + " " + String(landing.location));

    capture = helpers.auditCapture();
    await theBrowserStillSendsWhatItSent(reader, log, capture, binding, SALES, "a shared alias");
    await theBrowserStillSendsWhatItSent(reader, log, capture, binding, PRESS,
      "an alias at the second hosted domain");
    await theBrowserStillSendsWhatItSent(reader, log, capture, binding, null,
      "no author field at all");
    await theBrowserStillRefusesWhatItRefused(reader, log, capture, binding, MALLORY,
      "another account's own address");
    await theBrowserStillRefusesWhatItRefused(reader, log, capture, binding, NEWS,
      "another account's alias at the second hosted domain");

    var identities = browser.answer(
      await reader.jmap([["Identity/get", { accountId: alice.id }, "i0"]]), 0)[1];
    var salesIdentity = (identities.list || []).filter(function (held) {
      return held.email === SALES;
    })[0];
    count("Identity/get answers with the shared alias, which is the identity the " +
      "submission below names", salesIdentity !== undefined,
      JSON.stringify((identities.list || []).map(function (held) { return held.email; })));

    await jmapStillSendsWhatItSent(reader, alice.id, draftRow.objectid,
      salesIdentity === undefined ? "" : salesIdentity.id, log, capture, binding);
    await jmapStillRefusesWhatItRefused(reader, alice.id, draftRow.objectid, log, capture,
      binding);
    capture.release();
    capture = null;

    await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    listener = null;

    // ---- the composition an operator actually runs ----
    await theShippedCompositionCarriesTheBinding(
      Object.assign({}, cfg, { httpPort: 0, httpsPort: 0 }), identity, actor);

    return helpers.getChecks();
  } finally {
    if (capture) {
      try { capture.release(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (listener) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
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
  name:      "compose-author-binding",
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
