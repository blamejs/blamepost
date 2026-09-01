// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Answering a message written the way a stranger wrote it.
 *
 * The envelope and the header do not admit the same spellings of a
 * domain, and the difference is a rule rather than a gap. RFC 5321
 * section 4.1.2 writes `Domain = sub-domain *("." sub-domain)`, which has
 * no empty label at the end of it, so the absolute form of RFC 1035
 * section 2.3.1 is a malformed forward path and the command guard refuses
 * it where it is read. A HEADER is read by nobody at the wire: a peer
 * hands over `MAIL FROM:<bob@peer.example.net>` and then writes
 * `From: Bob <bob@PEER.EXAMPLE.NET.>` inside DATA, and that message is
 * accepted, filed, and sits in a mailbox for as long as its owner keeps
 * it.
 *
 * So the spelling arrives whether or not this server would have chosen
 * it, and the surfaces that answer a message read the address out of that
 * header: the browser reply form prefills `To` from it, a forward carries
 * whatever the account holder types, and a JMAP client sends a draft
 * whose `To` it wrote from the same bytes. Each of those hands the
 * address back to the outbound composer, and a composer that measures the
 * bytes rather than deriving the mailbox refuses the account holder's own
 * reply, and does it with a sentence about address syntax, which points
 * them at their draft rather than at the header they are answering.
 *
 * Both halves of the claim are here, and both are failures:
 *
 *   - A spelling a message may legitimately carry must not make the reply
 *     to it unsendable.
 *   - What leaves must still be a form a receiver accepts. Loosening the
 *     guard would send the empty label onward, where the next server
 *     along reads the same grammar and refuses the envelope. The
 *     derivation is what settles that: it removes the DNS root's dot and
 *     folds the case RFC 4343 says is not a difference, and it keeps the
 *     RFC 5233 tag, which belongs to the recipient rather than to this
 *     server.
 *
 * The control beside it is a name that only renders like one. A composer
 * that stopped refusing the absolute form by refusing nothing would pass
 * every case above and send mail to a domain nobody registered, so a
 * confusable recipient and an address with no domain at all are driven on
 * the same surfaces.
 *
 * What existing files already cover, and this one therefore does not: the
 * absolute form in an SMTP envelope and in a submission From header
 * (`test/layer-2-integration/domain-spelling-wire-parity.test.js`), and
 * the same spellings through the signer, the mint and the command line
 * (`test/layer-1-state/domain-identity-parity.test.js`).
 *
 * Run standalone: node test/layer-2-integration/reply-address-spelling-wire.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var address   = require("../../lib/store/address");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;
var count       = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE    = "alice@" + DOMAIN;

// The stranger who wrote the message being answered. The envelope carries
// the only spelling RFC 5321 admits; the header carries one this server
// would never have written and has no say over.
var PEER_DOMAIN     = "peer.example.net";
var PEER_ENVELOPE   = "bob@" + PEER_DOMAIN;
var PEER_HEADER     = "bob@" + PEER_DOMAIN.toUpperCase() + ".";
var PEER_DERIVED    = "bob@" + PEER_DOMAIN;

// A recipient that renders like a name and is a different string: the IDN
// homograph class. Refusing it is what says the cases above are a
// decision about the spelling rather than a composer that stopped
// deciding anything.
var CONFUSABLE_RECIPIENT = "bob@peer.exаmple.net";

// And a string that names no domain at all, which is the other end of
// the same control.
var UNREADABLE_RECIPIENT = "bob@";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// ---- the message being answered ---------------------------------------------

// One inbound message from a peer, handed over the way a peer hands one
// over: an envelope the wire guard admits, and a header block this server
// reads no address out of until something answers it.
function inboundMessage() {
  return [
    "From: Bob <" + PEER_HEADER + ">",
    "To: <" + ALICE + ">",
    "Subject: lunch",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <spelled-absolutely@" + PEER_DOMAIN + ">",
    "",
    "One o'clock?",
    "",
  ].join("\r\n");
}

async function deliverToAlice(mxPort, caPem) {
  var peer = await Wire.mx(mxPort, {
    caPem: caPem, servername: HOSTNAME, label: "mx-peer" });
  peer.send("MAIL FROM:<" + PEER_ENVELOPE + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + ALICE + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(inboundMessage() + "\r\n.\r\n", "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

// The message read back the way its owner reads it. Nothing about the
// reply matters if the header never reaches a mailbox, so this is the
// first claim and the rest rest on it.
async function theMessageIsDeliveredAndReadable(ports, caPem) {
  var reply = await deliverToAlice(ports.mx, caPem);
  count("a peer's message whose From header carries the DNS root's dot is accepted at the " +
    "wire, because a header is not a forward path and nothing reads an address out of one " +
    "at RCPT time",
    /^250 /m.test(reply), visible(reply));

  var session = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "imap-reader",
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    var selectTag = session.tag();
    session.send(selectTag + " SELECT INBOX");
    var selected = await session.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    count("and it is in the mailbox its owner opens",
      /^\* 1 EXISTS/m.test(selected), visible(selected));

    var fetchTag = session.tag();
    session.send(fetchTag + " FETCH 1 BODY.PEEK[HEADER]");
    var fetched = await session.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "FETCH answered");
    count("with the spelling the sender wrote still in its From header, which is the value " +
      "every surface that answers this message reads its recipient out of",
      fetched.indexOf(PEER_HEADER) !== -1, visible(fetched.slice(0, 400)));

    session.send(session.tag() + " LOGOUT");
  } finally {
    session.close();
  }
}

// ---- the outbound path a reply reaches --------------------------------------

function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({
        from:   envelope.from,
        to:     (envelope.to || []).slice(),
        rfc822: Buffer.isBuffer(envelope.rfc822)
          ? envelope.rfc822.toString("utf8")
          : String(envelope.rfc822),
      });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
  };
}

// What has to be true of every message this file gets out of the server.
// One recipient, named in a form the next server along reads under the
// same grammar this one does, in the envelope and in the header both.
function theEnvelopeAndHeaderCarryTheDerivedAddress(out, where) {
  count(where + ": exactly one recipient reached the outbound path, so a spelling did not " +
    "become a second one",
    out !== null && out.to.length === 1,
    out === null ? "nothing sent" : JSON.stringify(out.to));
  if (out === null || out.to.length !== 1) return;

  count(where + ": and it is the address the derivation names, so the next server along " +
    "reads a forward path RFC 5321 section 4.1.2 admits",
    out.to[0] === PEER_DERIVED, JSON.stringify(out.to[0]));

  var headerBlock = out.rfc822.split("\r\n\r\n")[0];
  var toHeader = (headerBlock.match(/^To:[^\r\n]*(?:\r\n[ \t][^\r\n]*)*/m) || [""])[0];
  count(where + ": the To header carries the same derived address rather than the bytes " +
    "the account holder was handed",
    toHeader.indexOf(PEER_DERIVED) !== -1 && toHeader.indexOf(PEER_HEADER) === -1,
    visible(toHeader));
}

// ---- the browser reply form -------------------------------------------------

// The id of the message sitting in the inbox, read the way a client reads
// it rather than out of the store, so the page asked for below is the
// page a reader would have opened.
async function inboxMessageId(reader, accountId) {
  var mailboxes = await reader.jmap([["Mailbox/get", { accountId: accountId }, "m0"]]);
  var list = browser.answer(mailboxes, 0)[1].list || [];
  var inbox = list.filter(function (row) { return row.role === "inbox"; })[0] || list[0];
  var found = await reader.jmap([["Email/query", {
    accountId: accountId,
    filter:    { inMailbox: inbox.id },
  }, "q0"]]);
  var ids = browser.answer(found, 0)[1].ids || [];
  // RFC 8620 leaves the id opaque and this server keys a mailbox on the
  // folder's own name, which is also what the reply link on the rendered
  // conversation carries. Reading it back rather than writing it here
  // keeps this file driving the URL a reader would have followed.
  return { folder: String(inbox.id || ""), emailId: ids[0] || "" };
}

// What a re-rendered compose page says went wrong, which is the sentence
// the account holder reads. Quoted in a failure instead of the page, so a
// refusal names itself rather than arriving as five hundred characters of
// document head.
function problemOn(page) {
  var notice = (String(page.body).match(/notice-bad[\s\S]{0,400}?<p>([\s\S]*?)<\/p>/) || [])[1];
  return notice === undefined ? String(page.body).slice(0, 200) : notice.trim();
}

// The reply and forward links the conversation page hands a reader, built
// the way that page builds them.
function composeHref(located, mode) {
  return "/compose?source=" + encodeURIComponent(located.emailId) +
    "&folder=" + encodeURIComponent(located.folder) +
    "&mode=" + encodeURIComponent(mode);
}

// The reply form as the account holder is handed it. The address in the
// field is the one out of the message's own From header, so this is where
// the spelling stops being the sender's problem and becomes the reply's.
async function theReplyFormIsPrefilledWithTheSenderSpelling(reader, located) {
  var page = await reader.get(composeHref(located, "reply"));
  count("the reply form opens on the message being answered", page.status === 200,
    page.status + " " + String(page.body).slice(0, 200));
  var field = (String(page.body).match(/<input id="to"[^>]*>/) || [""])[0];
  count("and its To field is prefilled from the sender's own From header, spelling and all, " +
    "which is what the account holder posts back unchanged",
    field.indexOf('value="' + PEER_HEADER + '"') !== -1, visible(field));
  return page;
}

// The post. This is the failure the file exists for: the account holder
// answers a message that arrived, and the server refuses their own draft.
async function theReplyIsSent(reader, log) {
  var before = log.count();
  var posted = await reader.form("/compose", {
    from:    ALICE,
    to:      PEER_HEADER,
    subject: "Re: lunch",
    text:    "One o'clock works.",
  });
  count("a reply addressed to the sender exactly as the message named them is sent rather " +
    "than refused, because the composer derives the mailbox instead of measuring the bytes",
    posted.status === 302, posted.status + " " + problemOn(posted));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);
  theEnvelopeAndHeaderCarryTheDerivedAddress(log.last(), "the browser reply");
}

// A forward carries whatever the account holder types, and the address
// they have in front of them is the one the message showed them. Same
// spelling, different surface, and a fix that only reached the reply path
// would leave this one refusing.
async function theForwardIsSent(reader, located, log) {
  var page = await reader.get(composeHref(located, "forward"));
  count("the forward form opens on the message being forwarded", page.status === 200,
    page.status + " " + String(page.body).slice(0, 200));

  var before = log.count();
  var posted = await reader.form("/compose", {
    from:    ALICE,
    to:      PEER_HEADER,
    cc:      "carol@" + PEER_DOMAIN.toUpperCase() + ".",
    subject: "Fwd: lunch",
    text:    "Thought you should see this.",
  });
  count("a forward addressed the same way is sent too, in the To list and in the copy list " +
    "alike, because every recipient list goes through one derivation",
    posted.status === 302, posted.status + " " + problemOn(posted));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);

  var out = log.last();
  count("carrying both recipients, each named in the form the derivation gives it",
    out !== null && out.to.length === 2 &&
      out.to.indexOf(PEER_DERIVED) !== -1 &&
      out.to.indexOf("carol@" + PEER_DOMAIN) !== -1,
    out === null ? "nothing sent" : JSON.stringify(out.to));
}

// The control. A composer that admitted the absolute form by admitting
// everything would pass every case above, so the names that must stay
// refused are driven on the same surface.
async function aNameThatOnlyRendersLikeOneIsStillRefused(reader, log) {
  var vectors = [
    ["a Cyrillic letter standing in for a Latin one", CONFUSABLE_RECIPIENT],
    ["a string naming no domain at all",              UNREADABLE_RECIPIENT],
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var before = log.count();
    var posted = await reader.form("/compose", {
      from:    ALICE,
      to:      vectors[i][1],
      subject: "Re: lunch",
      text:    "One o'clock works.",
    });
    count("a recipient at " + vectors[i][0] + " is still refused, so the spellings accepted " +
      "above are a decision about the name rather than a composer that stopped deciding",
      posted.status !== 302, posted.status + " " + problemOn(posted));
    count("and nothing reached the outbound path", log.count() === before,
      log.count() + " after " + before);
  }
}

// ---- the JMAP client --------------------------------------------------------

// The draft a client writes from the same bytes. `EmailSubmission/set` is
// the verb that hands it to the outbound path, and the refusal it
// produces reaches the client as `forbiddenToSend`, which is a sentence
// about the account holder's draft rather than about the header they are
// answering.
function draftTo(recipient) {
  return Buffer.from([
    "Message-ID: <reply-draft@" + DOMAIN + ">",
    "From: Alice <" + ALICE + ">",
    "To: <" + recipient + ">",
    "Subject: Re: lunch",
    "Date: Mon, 24 Aug 2026 09:05:00 +0000",
    "",
    "One o'clock works.",
    "",
  ].join("\r\n"), "utf8");
}

async function aJmapSubmissionSendsTheSameReply(reader, accountId, identityId, draftId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: identityId, emailId: draftId } },
  }, "e0"]]);
  count("EmailSubmission/set is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  count("a draft whose To header names the sender exactly as they named themselves is " +
    "created rather than refused",
    Object.prototype.hasOwnProperty.call(result.created || {}, "s0"),
    JSON.stringify(result.notCreated));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);
  theEnvelopeAndHeaderCarryTheDerivedAddress(log.last(), "the JMAP submission");
}

async function aJmapSubmissionToAConfusableIsStillRefused(reader, accountId, identityId,
  draftId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: identityId, emailId: draftId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];
  var refusal = (result.notCreated || {}).s0 || null;
  count("a draft naming a recipient at a name that only renders like one is refused",
    refusal !== null, JSON.stringify(result.created));
  count("and nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// ---- the identity set a client is offered -----------------------------------

async function identityFor(reader, accountId, wanted) {
  var answer = await reader.jmap([["Identity/get", { accountId: accountId }, "i0"]]);
  var list = browser.answer(answer, 0)[1].list || [];
  for (var i = 0; i < list.length; i += 1) {
    if (list[i].email === wanted) return list[i].id;
  }
  return "";
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("reply-address-spelling-wire");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  [dataDir, workDir].forEach(function (dir) { nodeFs.mkdirSync(dir, { recursive: true }); });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable, and refuses to open a store
  // without one. Pointing it inside the run's own tree keeps the
  // encrypted at rest path exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  var web      = null;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "reply address spelling" });
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS and this process has no resolver. Everything asserted
        // here is decided before it runs or after the message is filed.
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    await theMessageIsDeliveredAndReadable({
      mx: sections.mx.port, imap: sections.imap.port,
    }, material.caPem);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    server = null;

    // The browser surface, over an outbound path that records rather than
    // delivers. The claim is about the envelope and the header a reply
    // produces, and a real transport would answer about this host's
    // resolver instead.
    var log = recorder();
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  log.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });
    web = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   composer,
      dkim:      dkimHandle,
      delivery:  blamepost.mail.delivery.create({
        hostname: cfg.hostname, dataDir: cfg.dataDir }),
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports = await web.start();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var landed = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the account signs in to the browser surface that mounts JMAP",
      landed.status === 302, landed.status + " " + String(landed.location));

    var located = await inboxMessageId(reader, alice.id);
    count("a client finds the delivered message by asking for it",
      located.emailId.length > 0, JSON.stringify(located));

    await theReplyFormIsPrefilledWithTheSenderSpelling(reader, located);
    await theReplyIsSent(reader, log);
    await theForwardIsSent(reader, located, log);
    await aNameThatOnlyRendersLikeOneIsStillRefused(reader, log);

    var identityId = await identityFor(reader, alice.id, ALICE);
    count("the account holds a sending identity for its own address",
      identityId.length > 0, JSON.stringify(identityId));

    var actor = { id: alice.id };
    var goodDraft = identity.mailbox.appendMessage("Drafts", draftTo(PEER_HEADER),
      { actor: actor });
    await aJmapSubmissionSendsTheSameReply(reader, alice.id, identityId,
      goodDraft.objectid, log);

    var badDraft = identity.mailbox.appendMessage("Drafts", draftTo(CONFUSABLE_RECIPIENT),
      { actor: actor });
    await aJmapSubmissionToAConfusableIsStillRefused(reader, alice.id, identityId,
      badDraft.objectid, log);

    await web.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    web = null;

    // The claim the whole file rests on, asserted rather than assumed: the
    // two strings really are one mailbox, so a refusal of the first is a
    // refusal of the second written differently.
    var derived = address.parse(PEER_HEADER);
    count("the spelling the sender wrote and the address that leaves name one mailbox, read " +
      "through the derivation this server decides mailbox identity with",
      derived.ok && derived.address === PEER_DERIVED,
      derived.ok ? derived.address : String(derived.reason));

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (web) {
      try { await web.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the temporary volume is going anyway */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "reply-address-spelling-wire",
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
