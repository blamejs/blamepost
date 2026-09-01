// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Mail between two accounts on this server, sent from each of the three
 * surfaces an account holder can send from.
 *
 * A desktop client speaks SMTP submission. A browser posts the compose
 * form. A JMAP client calls `EmailSubmission/set`. All three are one
 * account asking this server to send one message to a mailbox this
 * server hosts, so all three have to put it in that mailbox. A surface
 * that hands the recipient to the outbound chain instead sends the
 * message out to DNS and waits for it to arrive back on port 25, which
 * makes mail between two mailboxes here depend on the MX record
 * resolving, on the host being able to reach itself, and on this
 * server's own MTA-STS and DANE policy applied against itself. None of
 * those is involved in moving a message between two folders on one
 * disk.
 *
 * The file is a parity file rather than three separate ones on purpose.
 * The claim is not that any one surface works, it is that the three
 * agree, and a claim about agreement asserted on one surface is the
 * coverage gap that produced this: the submission listener split its
 * recipients and the two surfaces the framework composer serves did
 * not, and every test of either half passed.
 *
 * Everything is asked over the wire an operator's client speaks. The
 * mailbox is read over IMAP, because a message the server believes it
 * filed and the recipient's client cannot see is not delivered, and
 * because reading the store directly would be asserting on the same
 * layer that did the writing.
 *
 * Each vector carries a marker in its subject and is settled by
 * searching for that marker, so the cases can run in any order against
 * one mailbox without counting each other's mail.
 *
 * Run standalone: node test/layer-2-integration/local-delivery-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
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
var SELECTOR = "bp202608";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

// One marker per vector. They are searched for rather than counted from
// a position, so the mailbox can hold everything every other vector put
// there.
var MARK_WIRE    = "parity-wire-4a17c9e2";
var MARK_FORM    = "parity-form-b6d0741f";
var MARK_JMAP    = "parity-jmap-38ce5b90";
var MARK_ALIAS   = "parity-alias-cf2a6d18";
var MARK_SIEVE   = "parity-sieve-70bd4e35";
var MARK_MIXED   = "parity-mixed-91af23c6";

// A recipient at a domain this server does not host, used only by the
// mixed vector. `.example` is reserved by RFC 6761 and resolves for
// nobody, so the outbound half of that envelope reaches the outbound
// chain and stops there.
var OUTSIDER = "outsider@peer.example";

// ---- reading a mailbox over IMAP -------------------------------------------

// The sequence numbers a folder holds for one subject marker. An empty
// array is the answer for a marker that never arrived, which is what
// every vector below is really asking about.
async function found(ports, caPem, address, password, folder, marker, label) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: label,
    address: address, password: password,
  });
  try {
    var select = reader.tag();
    reader.send(select + " SELECT " + folder);
    var selected = await reader.read(new RegExp("^" + select + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    if (!new RegExp("^" + select + " OK", "m").test(selected)) {
      return { hits: [], transcript: visible(selected) };
    }
    var search = reader.tag();
    reader.send(search + " SEARCH SUBJECT \"" + marker + "\"");
    var searched = await reader.read(new RegExp("^" + search + " (OK|NO|BAD)", "m"),
      "SEARCH answered");
    var line = /^\* SEARCH([0-9 ]*)/m.exec(searched);
    var hits = line === null
      ? []
      : line[1].trim().split(/\s+/).filter(function (n) { return n.length > 0; });
    return { hits: hits, transcript: visible(searched) };
  } finally {
    reader.close();
  }
}

// The stored octets of one message, so a claim about what the recipient
// holds is settled on the bytes rather than on the server's own report
// of what it wrote.
async function storedCopy(ports, caPem, address, password, folder, seq, label) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: label,
    address: address, password: password, binary: true,
  });
  try {
    var select = reader.tag();
    reader.send(select + " SELECT " + folder);
    await reader.read(new RegExp("^" + select + " (OK|NO|BAD)", "m"), "SELECT answered");
    var fetch = reader.tag();
    reader.send(fetch + " FETCH " + seq + " BODY.PEEK[]");
    var raw = await reader.readBytes(new RegExp("^" + fetch + " (OK|NO|BAD)", "m"),
      "FETCH answered");
    var view = raw.toString("latin1");
    var literal = /\{(\d+)\}\r\n/.exec(view);
    if (literal === null) return null;
    var from = literal.index + literal[0].length;
    return raw.subarray(from, from + parseInt(literal[1], 10));
  } finally {
    reader.close();
  }
}

function signatureCount(bytes) {
  if (bytes === null) return -1;
  return (bytes.toString("latin1").match(/^DKIM-Signature:/gm) || []).length;
}

// ---- the three surfaces ----------------------------------------------------

// A desktop client. This is the surface that already splits its
// recipients, so it is the reference the other two are measured against.
async function overSubmission(ports, caPem, alice, bob, marker) {
  var sender = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "submission-" + marker,
    address: alice, password: ALICE_PASSWORD,
  });
  try {
    sender.send("MAIL FROM:<" + alice + ">");
    await sender.read(/^250 /m, "MAIL FROM answered");
    sender.send("RCPT TO:<" + bob + ">");
    var rcpt = await sender.read(/^\d{3} /m, "RCPT TO answered");
    count("submission accepts a recipient this server hosts",
      /^250 /m.test(rcpt), visible(rcpt));
    sender.send("DATA");
    await sender.read(/^354 /m, "DATA answered");
    sender.sendRaw([
      "From: " + alice,
      "To: " + bob,
      "Subject: " + marker,
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + marker + "@example.com>",
      "",
      "One o'clock?",
      "",
      ".",
      "",
    ].join("\r\n"), "<the message and its terminating dot>");
    var accepted = await sender.read(/^\d{3} /m, "message answered");
    count("submission accepts the message for delivery",
      /^250 /m.test(accepted), visible(accepted));
    sender.send("QUIT");
  } finally {
    sender.close();
  }
}

// The browser compose form, posted the way the rendered page posts it.
async function overComposeForm(reader, to, marker, extra) {
  var fields = Object.assign({
    to:      to,
    subject: marker,
    text:    "Sent from the compose form.",
  }, extra || {});
  var posted = await reader.form("/compose", fields);
  count("the compose form accepts a message for " + to,
    posted.status === 302, "HTTP " + posted.status + " " +
      String(posted.body || "").replace(/\s+/g, " ").slice(0, 200));
  return posted;
}

// The draft a JMAP client submits. This server refuses `Email/set`
// create, so the message a client names in a submission is one already
// in a folder. Written through the message store rather than over the
// wire because storing it is the fixture and submitting it is the thing
// under test.
async function storeDraft(identity, alice, to, marker) {
  var bytes = Buffer.from([
    "From: " + alice.address,
    "To: " + to,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Sent from a JMAP client.",
    "",
  ].join("\r\n"), "utf8");
  var stored = await identity.mailbox.appendMessage("Drafts", bytes, {
    actor: { id: alice.id, address: alice.address },
    flags: ["\\Draft"],
  });
  return stored && stored.objectid;
}

// A JMAP client, RFC 8621 section 7: it names the identity it is sending
// as and the message it is sending.
async function overJmap(reader, accountId, identityId, emailId) {
  var submitted = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create: { send: { identityId: identityId, emailId: emailId } },
  }, "c1"]]);
  var sendAnswer = browser.answer(submitted);
  var madeIt = sendAnswer && sendAnswer[1] && sendAnswer[1].created &&
    sendAnswer[1].created.send;
  count("a JMAP client's submission is accepted",
    madeIt !== undefined && madeIt !== null,
    JSON.stringify(sendAnswer && sendAnswer[1]).slice(0, 300));
  return madeIt || null;
}

// ---- the vectors -----------------------------------------------------------

// Which handle the surfaces are holding, asked of the assembled server
// rather than inferred from what arrived. The behavior below settles
// whether routing happened; this settles that there is one handle it can
// have happened through, so a second one appearing later is a finding
// here rather than a mailbox somebody notices is empty.
function theSendingSurfacesShareOneOutboundHandle(server) {
  var relay = server.mail.listeners.relay;
  count("blamepost.mail.listeners.relay is built whatever binds, so a surface that sends on " +
    "an account's behalf has something to send through",
    relay !== undefined && relay !== null && typeof relay.send === "function",
    typeof relay);
  count("and it is not the raw outbound handle, whose send hands every recipient to the " +
    "MX lookup whether this server hosts the address or not",
    relay.send !== server.mail.delivery.send,
    String(relay.send === server.mail.delivery.send));
  count("while still carrying the outbound handle's own verbs, so nothing reading another " +
    "one off it finds a handle with half a contract",
    typeof relay.bounce === "function" && relay.queue === server.mail.delivery.queue,
    typeof relay.bounce + " / " + String(relay.queue === server.mail.delivery.queue));
}

async function everySurfaceReachesTheMailbox(ports, caPem, alice, bob, reader, jmapIds) {
  await overSubmission(ports, caPem, alice, bob, MARK_WIRE);
  var wireHit = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_WIRE, "imap-wire");
  count("a message a desktop client submits for an account on this server reaches that " +
    "account's mailbox",
    wireHit.hits.length === 1, wireHit.hits.length + " hit(s): " + wireHit.transcript);

  await overComposeForm(reader, bob, MARK_FORM);
  var formHit = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_FORM, "imap-form");
  count("a message the browser compose form sends to the same account reaches the same " +
    "mailbox, rather than being handed to the outbound chain and sent out to DNS for a " +
    "recipient this server hosts",
    formHit.hits.length === 1, formHit.hits.length + " hit(s): " + formHit.transcript);

  if (jmapIds !== null) {
    await overJmap(reader, jmapIds.accountId, jmapIds.identityId, jmapIds.emailId);
    var jmapHit = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_JMAP, "imap-jmap");
    count("and a message a JMAP client submits for the same account reaches it too, so the " +
      "three surfaces an account holder can send from agree about where a recipient this " +
      "server hosts goes",
      jmapHit.hits.length === 1, jmapHit.hits.length + " hit(s): " + jmapHit.transcript);
  }

  return { wire: wireHit.hits[0], form: formHit.hits[0] };
}

// Signing happens before the message is handed over on the submission
// path, so the copy filed in the recipient's mailbox carries the
// signature. The other surface signs in the same order, and the copy it
// files has to carry it too, or the same account's mail is attributable
// on one surface and not on the other.
async function bothSurfacesFileASignedCopy(ports, caPem, bob, seqs) {
  if (seqs.wire === undefined || seqs.form === undefined) {
    helpers.skip("signature parity needs both delivered copies, and one did not arrive");
    return;
  }
  var wireCopy = await storedCopy(ports, caPem, bob, BOB_PASSWORD, "INBOX",
    seqs.wire, "imap-wire-bytes");
  var formCopy = await storedCopy(ports, caPem, bob, BOB_PASSWORD, "INBOX",
    seqs.form, "imap-form-bytes");
  count("the copy the submission path filed carries both halves of the dual signature",
    signatureCount(wireCopy) === 2, signatureCount(wireCopy) + " signature(s)");
  count("and so does the copy the compose form filed, so a message is attributable to its " +
    "domain whichever surface the account sent it from",
    signatureCount(formCopy) === 2, signatureCount(formCopy) + " signature(s)");
}

// An alias is not a second name for one mailbox, it is a rule that can
// fan one recipient out to several. The submission path resolves the
// address and delivers to what it points at; the compose form has to do
// the same, or an address the operator published works from a desktop
// client and not from the browser.
async function anAliasFansOutFromTheComposeForm(ports, caPem, aliasAddress, bob, reader) {
  await overComposeForm(reader, aliasAddress, MARK_ALIAS);
  var hit = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_ALIAS, "imap-alias");
  count("an alias on a hosted domain resolves to the mailbox behind it when the compose " +
    "form is what sent the message",
    hit.hits.length === 1, hit.hits.length + " hit(s): " + hit.transcript);
}

// The recipient's own filter runs on a message delivered here, whoever
// sent it. A message that reaches the mailbox without running the script
// lands in the wrong folder, which the account holder reads as mail that
// went missing.
async function theRecipientsFilterRunsOnTheComposedMessage(ports, caPem, bob, reader) {
  await overComposeForm(reader, bob, MARK_SIEVE);
  var junk = await found(ports, caPem, bob, BOB_PASSWORD, "Junk", MARK_SIEVE, "imap-sieve-junk");
  var inbox = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_SIEVE, "imap-sieve-inbox");
  count("the recipient's Sieve script files a message the compose form sent, so the filter " +
    "an account holder wrote applies to mail from inside this server as well as to mail " +
    "from outside it",
    junk.hits.length === 1, junk.hits.length + " in Junk: " + junk.transcript);
  count("and the message is not also sitting in the INBOX the script moved it out of",
    inbox.hits.length === 0, inbox.hits.length + " in INBOX: " + inbox.transcript);
}

// One message, one recipient here and one elsewhere. The recipient here
// has to get it without waiting on the one elsewhere, and a message that
// left the building for both is one where a receiver that is down keeps
// mail from crossing between two folders on this disk.
async function amixedEnvelopeReachesTheLocalRecipient(ports, caPem, bob, reader) {
  await overComposeForm(reader, bob + ", " + OUTSIDER, MARK_MIXED);
  var hit = await found(ports, caPem, bob, BOB_PASSWORD, "INBOX", MARK_MIXED, "imap-mixed");
  count("an envelope naming a recipient here and a recipient elsewhere still reaches the " +
    "one here, rather than making mail between two mailboxes on this server depend on a " +
    "receiver somewhere else",
    hit.hits.length === 1, hit.hits.length + " hit(s): " + hit.transcript);
}

// The sender keeps a copy of everything they send, and the local route
// must not cost them one. It is the account holder's own record of what
// left, and its absence is invisible until they go looking for it.
async function theSenderKeepsACopyOfEachOne(ports, caPem, alice) {
  var markers = [MARK_FORM, MARK_ALIAS, MARK_SIEVE, MARK_MIXED];
  for (var i = 0; i < markers.length; i += 1) {
    var hit = await found(ports, caPem, alice, ALICE_PASSWORD, "Sent", markers[i],
      "imap-sent-" + i);
    count("the sender's Sent folder holds the copy of " + markers[i],
      hit.hits.length === 1, hit.hits.length + " hit(s): " + hit.transcript);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("localparity");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "local delivery parity test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    var aliasAddress = "sales@" + DOMAIN;
    await identity.aliases.add({ address: aliasAddress, destination: bob.address });

    // The recipient's own filter, uploaded before anything is sent. It
    // names a folder every account already has, so the vector is about
    // whether the script RAN rather than about folder creation.
    var bobActor = { id: bob.id, address: bob.address, roles: ["account"] };
    identity.mailbox.sieveScripts.put(bobActor, "file-parity",
      "require [\"fileinto\"];\n" +
      "if header :contains \"Subject\" \"" + MARK_SIEVE + "\" { fileinto \"Junk\"; }",
      { force: true });
    identity.mailbox.sieveScripts.setActive(bobActor, "file-parity");

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
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

    // Both surfaces sign, so the domain holds a pair before anything is
    // sent. Without one the parity claim about the delivered copy would
    // be two messages that are equally unsigned.
    await server.mail.dkim.generate({ domain: DOMAIN, selector: SELECTOR });

    var ports = {
      submission: sections.submission.port,
      imap:       sections.imap.port,
    };

    // The port the web listener actually took, not the zero it was asked
    // for. `describe` reports what was configured, and a reader pointed
    // at that fails to connect for a reason that says nothing about the
    // route under test.
    var origin = "http://" + LOOPBACK + ":" + server.web.bound().http;
    var reader = browser.browserAt(origin);
    var landing = await reader.signIn(alice.address, ALICE_PASSWORD);
    count("the sending account signs in to the browser surface",
      landing.status === 302, landing.status + " " + String(landing.location));
    // The token the compose form carries. `signIn` read the one on the
    // sign-in page, and the session it created is a different one.
    await reader.readCsrf("/compose");

    // What a JMAP client needs before it can submit: the account it is
    // acting for, the identity it is sending as, and the folder a draft
    // is stored in. Read from the server rather than guessed, because a
    // guessed id is a vector that fails for a reason that is not the one
    // under test.
    var jmapIds = null;
    var session = await reader.get("/jmap/session", { Accept: "application/json" });
    var accountId = null;
    try {
      var doc = JSON.parse(session.body);
      accountId = Object.keys(doc.accounts || {})[0] || null;
    } catch (_e) { accountId = null; }
    count("the JMAP session document names an account for the signed-in mailbox owner",
      typeof accountId === "string" && accountId.length > 0,
      String(session.status) + " " + String(session.body).slice(0, 200));

    if (typeof accountId === "string" && accountId.length > 0) {
      var lists = await reader.jmap([
        ["Identity/get", { accountId: accountId, ids: null }, "i0"],
      ]);
      var identities = browser.answer(lists, 0);
      var identityId = identities && identities[1] && identities[1].list &&
        identities[1].list[0] && identities[1].list[0].id;
      var emailId = await storeDraft(identity, alice, bob.address, MARK_JMAP);
      count("and the client can read an identity to send as, over a draft it can name",
        typeof identityId === "string" && typeof emailId === "string",
        JSON.stringify({ identityId: identityId, emailId: emailId }));
      if (typeof identityId === "string" && typeof emailId === "string") {
        jmapIds = { accountId: accountId, identityId: identityId, emailId: emailId };
      }
    }
    if (jmapIds === null) {
      helpers.skip("the JMAP surface could not be addressed, so its half of the parity " +
        "claim did not run");
    }

    theSendingSurfacesShareOneOutboundHandle(server);
    var seqs = await everySurfaceReachesTheMailbox(ports, leaf.ca,
      alice.address, bob.address, reader, jmapIds);
    await bothSurfacesFileASignedCopy(ports, leaf.ca, bob.address, seqs);
    await anAliasFansOutFromTheComposeForm(ports, leaf.ca, aliasAddress, bob.address, reader);
    await theRecipientsFilterRunsOnTheComposedMessage(ports, leaf.ca, bob.address, reader);
    await amixedEnvelopeReachesTheLocalRecipient(ports, leaf.ca, bob.address, reader);
    await theSenderKeepsACopyOfEachOne(ports, leaf.ca, alice.address);

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
  name:      "local-delivery-parity",
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
