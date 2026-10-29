// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which domain the signature names, on each surface an account holder
 * sends from, and whether that domain is the one a recipient reads.
 *
 * DKIM alignment is measured between the domain in the `From` header and
 * the `d=` tag on the signature over it, which RFC 9989 defines and a
 * receiver applies before it decides what a DMARC record asks for. So a
 * claim about alignment is a claim about two strings on one delivered
 * message, and both have to be read off that message.
 *
 * The signing domain is chosen by the send path rather than by the
 * signer, and the three surfaces do not reach the signer the same way.
 * The browser compose form and JMAP `EmailSubmission/set` both call
 * `blamepost.mail.compose.send`, which signs for the domain in the `From`
 * it built. The submission listener signs in its relay handoff, for the
 * domain in the envelope sender. A file that called the signer directly
 * would measure neither: it would measure the argument it passed in.
 * Every vector here therefore drives the surface an account holder
 * actually drives, and reads the answer out of the recipient's mailbox
 * over IMAP.
 *
 * The signature is VERIFIED rather than matched as text. A `d=` tag read
 * out of a header says which domain the signature claims, and says
 * nothing about whether a receiver looking that domain up can confirm
 * it. Verification answers both at once: the tag comes back off the
 * verifier's own parse, and it comes back beside a verdict reached
 * against the records this server tells the operator to publish for that
 * domain. A message signed for a domain whose published key does not
 * match is a message that fails DMARC while carrying a `d=` a text match
 * accepts.
 *
 * An alias in the account's own domain is the ordinary case and aligns
 * everywhere. The cases worth pinning are the ones where the `From`
 * domain and the envelope domain are different hosted domains, because
 * that is where the two signing sites can answer differently.
 *
 * Run standalone: node test/layer-2-integration/dkim-alignment-by-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers = require("../helpers");
var browser = require("../helpers/browser");
var dnsZone = require("../helpers/dns-zone");
var wire    = require("../helpers/wire");

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

// Two hosted domains, each holding a pair of its own. One domain cannot
// express the claim at all: every message would align whichever field
// the signer was handed.
var OWN_DOMAIN    = "example.com";
var SECOND_DOMAIN = "second.example";
var OWN_SELECTOR    = "bp202608a";
var SECOND_SELECTOR = "bp202608b";

var ALICE = "alice@" + OWN_DOMAIN;
var BOB   = "bob@" + OWN_DOMAIN;

// An alias in each domain, both landing in the same mailbox. Both are
// addresses the account may write, in `From` and in `MAIL FROM` alike.
var SECOND_ALIAS = "team@" + SECOND_DOMAIN;
var OWN_ALIAS    = "sales@" + OWN_DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

// One marker per vector, searched for rather than counted from a
// position, so every vector can run against one mailbox holding what the
// others put there.
var MARK_FORM_SECOND = "align-form-second-3d71a4c8";
var MARK_JMAP_SECOND = "align-jmap-second-91e0b527";
var MARK_WIRE_SECOND = "align-wire-second-6c8fa310";
var MARK_FORM_OWN    = "align-form-own-2b45de09";
var MARK_WIRE_OWN    = "align-wire-own-f70c1a63";
var MARK_FORM_SELF   = "align-form-self-58ba9d24";
var MARK_WIRE_SPLIT  = "align-wire-split-0e37c6b1";

// ---- reading the delivered message ------------------------------------------

// The sequence numbers a folder holds for one subject marker. An empty
// array is the answer for a message that never arrived, which every
// vector below has to rule out before it reads anything off one.
async function found(ctx, marker, label) {
  var reader = await Wire.imap(ctx.imapPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: BOB, password: BOB_PASSWORD,
  });
  try {
    var select = reader.tag();
    reader.send(select + " SELECT INBOX");
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

// The stored octets of one message. The session stays in binary mode
// because the verifier is handed these bytes: a socket that decoded them
// first would have the verifier check a re-encoding of the message rather
// than the message, and every signature would come back as a body hash
// mismatch that reads like a signer fault.
async function storedCopy(ctx, seq, label) {
  var reader = await Wire.imap(ctx.imapPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: BOB, password: BOB_PASSWORD, binary: true,
  });
  try {
    var select = reader.tag();
    reader.send(select + " SELECT INBOX");
    await reader.read(new RegExp("^" + select + " (OK|NO|BAD)", "m"), "SELECT answered");
    var fetch = reader.tag();
    reader.send(fetch + " FETCH " + seq + " BODY.PEEK[]");
    var raw = await reader.readBytes(new RegExp("^" + fetch + " (OK|NO|BAD)", "m"),
      "FETCH answered");
    var view = raw.toString("latin1");
    var literal = /\{(\d+)\}\r\n/.exec(view);
    if (literal === null) return null;
    var at = literal.index + literal[0].length;
    return raw.subarray(at, at + parseInt(literal[1], 10));
  } finally {
    reader.close();
  }
}

// The domain in the `From` header of a delivered message, which is the
// half of the alignment pair a person is shown. Read off the stored bytes
// rather than remembered from what was sent, because what a surface put
// in the header is one of the two things under test.
function fromDomainOf(bytes) {
  var text = bytes === null ? "" : bytes.toString("latin1");
  var header = /^From:[ \t]*([^\r\n]*(?:\r\n[ \t][^\r\n]*)*)/m.exec(text);
  if (header === null) return "";
  var at = /<([^>]*)>/.exec(header[1]);
  var addr = at === null ? header[1].trim() : at[1].trim();
  var split = addr.lastIndexOf("@");
  return split === -1 ? "" : addr.slice(split + 1).trim().toLowerCase();
}

function signatureCount(bytes) {
  if (bytes === null) return -1;
  return (bytes.toString("latin1").match(/^DKIM-Signature:/gm) || []).length;
}

// ---- the claim, per vector --------------------------------------------------

/**
 * One vector: drive a surface, take the delivered message, and settle
 * which domain signed it and whether that domain is the one displayed.
 *
 * `expected` names the domain the signature has to carry. `aligns` says
 * whether that domain and the `From` domain are the same, which is what
 * a receiver measures. Both are stated rather than derived from each
 * other, so a vector cannot pass by agreeing with itself.
 */
async function theSignatureNames(ctx, what, marker, expectedFromDomain, expected, aligns) {
  var hit = await found(ctx, marker, "imap-" + marker);
  count(what + ": the message reached the recipient's mailbox",
    hit.hits.length === 1, hit.hits.length + " hit(s): " + hit.transcript);
  if (hit.hits.length !== 1) {
    helpers.skip(what + ": the delivered copy did not arrive, so nothing was read off it");
    return;
  }

  var copy = await storedCopy(ctx, hit.hits[0], "bytes-" + marker);
  count(what + ": the delivered copy carries a signature from each algorithm",
    signatureCount(copy) === 2, signatureCount(copy) + " signature(s)");

  var results = await dnsZone.verifyAgainst(copy, ctx.records);
  count(what + ": every signature on it verifies against the records this server tells " +
    "the operator to publish, so the domain it names is one a receiver can confirm rather " +
    "than one the header merely claims",
    dnsZone.allPass(results) && results.length === 2, dnsZone.summarize(results));

  var signing = results.map(function (r) { return String(r.d || "").toLowerCase(); });
  count(what + ": the signing domain the verifier read is " + expected,
    signing.length === 2 && signing.every(function (d) { return d === expected; }),
    JSON.stringify(signing));

  var displayed = fromDomainOf(copy);
  count(what + ": the From a recipient reads is at " + expectedFromDomain,
    displayed === expectedFromDomain, JSON.stringify(displayed));

  var same = signing.length > 0 && signing.every(function (d) { return d === displayed; });
  count(what + (aligns
    ? ": the signing domain and the From domain are the same name, which is what RFC 9989 " +
      "measures DKIM alignment on"
    : ": the signing domain and the From domain are different names, so nothing this " +
      "message carries aligns under DKIM and the displayed domain's own DMARC record is " +
      "what answers for it"),
    same === aligns, "signed " + JSON.stringify(signing) + " over " + JSON.stringify(displayed));
}

// ---- the surfaces -----------------------------------------------------------

// The browser compose form, posted the way the rendered page posts it.
// `from` is a request parameter like any other, resolved against the set
// the store answers with.
async function overComposeForm(reader, author, marker) {
  var posted = await reader.form("/compose", {
    from:    author,
    to:      BOB,
    subject: marker,
    text:    "One o'clock?",
  });
  count("the compose form accepts a message written as " + author,
    posted.status === 302, "HTTP " + posted.status + " " +
      String(posted.body || "").replace(/\s+/g, " ").slice(0, 200));
}

// A desktop client. `sender` is what goes in `MAIL FROM` and `author` is
// what goes in `From`, separately, because a client that puts one address
// in both is only one of the shapes this port accepts.
async function overSubmission(ctx, sender, author, marker) {
  var session = await Wire.submission(ctx.submissionPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "submission-" + marker,
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    session.send("MAIL FROM:<" + sender + ">");
    var accepted = await session.read(/^\d{3} /m, "MAIL FROM answered");
    count("the submission port accepts " + sender + " as the envelope sender",
      /^250 /m.test(accepted), visible(accepted));
    session.send("RCPT TO:<" + BOB + ">");
    var rcpt = await session.read(/^\d{3} /m, "RCPT TO answered");
    count("and a recipient this server hosts", /^250 /m.test(rcpt), visible(rcpt));
    session.send("DATA");
    await session.read(/^354 /m, "DATA answered");
    // RFC 5321 section 4.1.1.4 terminates the mail data with CRLF, a
    // period and CRLF, and the CRLF that opens that sequence is not part
    // of the message.
    session.sendRaw([
      "From: " + author,
      "To: " + BOB,
      "Subject: " + marker,
      "Date: Sat, 23 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + marker + "@" + OWN_DOMAIN + ">",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "One o'clock?",
      "",
      ".",
      "",
    ].join("\r\n"), "<the message and its terminating dot>");
    var verdict = await session.read(/^\d{3} /m, "message answered");
    count("the submission port accepts a message written as " + author +
      " for delivery", /^250 /m.test(verdict), visible(verdict));
    session.send("QUIT");
  } finally {
    session.close();
  }
}

// A JMAP client, RFC 8621 section 7. This server refuses `Email/set`
// create, so the message a submission names is one already in a folder.
async function overJmap(reader, identity, alice, identityId, marker) {
  var draft = await identity.mailbox.appendMessage("Drafts", Buffer.from([
    "From: " + SECOND_ALIAS,
    "To: " + BOB,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@" + SECOND_DOMAIN + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "One o'clock?",
    "",
  ].join("\r\n"), "utf8"), {
    actor: { id: alice.id, address: alice.address },
    flags: ["\\Draft"],
  });

  var submitted = await reader.jmap([["EmailSubmission/set", {
    accountId: alice.id,
    create:    { send: { identityId: identityId, emailId: draft.objectid } },
  }, "c1"]]);
  var result = browser.answer(submitted, 0)[1];
  count("a JMAP client's submission under the alias is created",
    Object.prototype.hasOwnProperty.call(result.created || {}, "send"),
    JSON.stringify(result.notCreated).slice(0, 300));
}

// The identity a JMAP client sends under, read from the set this server
// publishes rather than guessed, because a guessed id is refused for a
// reason that is not the one under test.
async function identityIdFor(reader, accountId, address) {
  var lists = await reader.jmap([["Identity/get", { accountId: accountId, ids: null }, "i0"]]);
  var list = browser.answer(lists, 0)[1].list || [];
  var emails = list.map(function (one) { return one.email; });
  count("the alias in the second hosted domain is published as an identity this account " +
    "may send under",
    emails.indexOf(address) !== -1, JSON.stringify(emails));
  for (var i = 0; i < list.length; i += 1) {
    if (list[i].email === address) return list[i].id;
  }
  return null;
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-alignment");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable, and refuses to open a store
  // without one.
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
    await identity.domains.add({ domain: OWN_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: OWN_DOMAIN, by: "dkim alignment" });
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: SECOND_DOMAIN, by: "dkim alignment" });

    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });
    await identity.accounts.create({ address: BOB, password: BOB_PASSWORD });
    await identity.aliases.add({ address: SECOND_ALIAS, destination: alice.address });
    await identity.aliases.add({ address: OWN_ALIAS, destination: alice.address });

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

    // Both domains hold a pair before anything is sent. Without one, a
    // message from that domain leaves unsigned and every claim below
    // would be made about a message carrying no signature at all.
    await server.mail.dkim.generate({ domain: OWN_DOMAIN, selector: OWN_SELECTOR });
    await server.mail.dkim.generate({ domain: SECOND_DOMAIN, selector: SECOND_SELECTOR });

    var ctx = {
      caPem:          leaf.ca,
      submissionPort: sections.submission.port,
      imapPort:       sections.imap.port,
      // The zone as this server asks for it, both domains at once, so a
      // verifier looking up whichever selector a message names finds the
      // record an operator would have published for it.
      records: server.mail.dkim.dnsRecords(OWN_DOMAIN)
        .concat(server.mail.dkim.dnsRecords(SECOND_DOMAIN)),
    };
    count("this server publishes a record per algorithm for each of the two hosted domains, " +
      "so a signature from either can be confirmed",
      ctx.records.length === 4, ctx.records.length + " record(s)");

    // The port the web listener actually took, not the zero it was asked
    // for.
    var reader = browser.browserAt("http://" + LOOPBACK + ":" + server.web.bound().http);
    var landing = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the sending account signs in to the browser surface",
      landing.status === 302, landing.status + " " + String(landing.location));
    // The token the compose form carries. `signIn` read the one on the
    // sign-in page, and the session it created is a different one.
    await reader.readCsrf("/compose");

    // ---- the sends ----

    await overComposeForm(reader, SECOND_ALIAS, MARK_FORM_SECOND);
    await overComposeForm(reader, OWN_ALIAS, MARK_FORM_OWN);
    await overComposeForm(reader, ALICE, MARK_FORM_SELF);

    await overSubmission(ctx, SECOND_ALIAS, SECOND_ALIAS, MARK_WIRE_SECOND);
    await overSubmission(ctx, OWN_ALIAS, OWN_ALIAS, MARK_WIRE_OWN);
    // The envelope and the author at two different hosted domains, both
    // of them addresses this account may write. A mail client configured
    // with one identity sends the same address in both, so this is the
    // shape a client reaches only when the two are configured apart.
    await overSubmission(ctx, ALICE, SECOND_ALIAS, MARK_WIRE_SPLIT);

    var identityId = await identityIdFor(reader, alice.id, SECOND_ALIAS);
    if (identityId === null) {
      helpers.skip("the alias was not published as a JMAP identity, so the JMAP vector " +
        "did not run");
    } else {
      await overJmap(reader, identity, alice, identityId, MARK_JMAP_SECOND);
    }

    // ---- what each one signed ----

    await theSignatureNames(ctx,
      "the compose form, under an alias in a second hosted domain",
      MARK_FORM_SECOND, SECOND_DOMAIN, SECOND_DOMAIN, true);

    if (identityId !== null) {
      await theSignatureNames(ctx,
        "a JMAP submission, under an alias in a second hosted domain",
        MARK_JMAP_SECOND, SECOND_DOMAIN, SECOND_DOMAIN, true);
    }

    await theSignatureNames(ctx,
      "the submission port, with an alias in a second hosted domain in both fields",
      MARK_WIRE_SECOND, SECOND_DOMAIN, SECOND_DOMAIN, true);

    await theSignatureNames(ctx,
      "the compose form, under an alias in the account's own domain",
      MARK_FORM_OWN, OWN_DOMAIN, OWN_DOMAIN, true);

    await theSignatureNames(ctx,
      "the submission port, with an alias in the account's own domain in both fields",
      MARK_WIRE_OWN, OWN_DOMAIN, OWN_DOMAIN, true);

    await theSignatureNames(ctx,
      "the compose form, under the account's own address",
      MARK_FORM_SELF, OWN_DOMAIN, OWN_DOMAIN, true);

    // The one shape that does not align. The signature on the relay path
    // names the envelope domain, so an envelope and an author at two
    // different hosted domains leave signed for one and displaying the
    // other.
    await theSignatureNames(ctx,
      "the submission port, with the envelope at one hosted domain and the author at another",
      MARK_WIRE_SPLIT, SECOND_DOMAIN, OWN_DOMAIN, false);

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
  name:      "dkim-alignment-by-surface",
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
