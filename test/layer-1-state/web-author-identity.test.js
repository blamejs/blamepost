// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which addresses a signed in account may write as the author of a
 * message, asked of the two surfaces that compose their own outbound
 * mail: the browser compose form and JMAP `EmailSubmission/set`.
 *
 * `blamepost.mail.listeners.permittedAuthors` is the one answer. It is
 * the account's own address plus every active alias that lands in that
 * account's mailbox, canonical, with a catch-all deliberately left out.
 * The authenticated submission listener measures a message's From and
 * Sender against it, so a desktop client on the submission port may
 * already write a shared departmental address. Both surfaces here used
 * to fix the author to the account's own address, which made the
 * browser and JMAP narrower than the wire for no reason a mailbox owner
 * could see or an operator could change.
 *
 * What is pinned:
 *
 *   - The compose form offers a choice only when there is one. An
 *     account holding one address gets the sentence it always got; an
 *     account holding a shared address gets a picker listing exactly the
 *     permitted set.
 *   - The picker is presentation. The set is recomputed from the store
 *     on the POST, so an author posted by hand into an account that was
 *     never shown a picker is measured against the same set and refused
 *     the same way.
 *   - Sending as an alias writes the alias into `From` and leaves the
 *     account's own address in the envelope. That split is the whole
 *     reason these two surfaces can offer this at all: they compose the
 *     envelope themselves, while an ordinary desktop client derives it
 *     from the identity it is configured with and puts the alias in
 *     both, which the envelope binding then refuses.
 *   - A refusal names the identity that was rejected and the ones that
 *     would have been accepted, because a shared mailbox is the case an
 *     operator hits first and a bare refusal sends them to their mail
 *     client.
 *   - `Identity/get` answers with one Identity per permitted author, so
 *     a client conforming to RFC 8621 section 6 reads the set rather
 *     than guessing at it, and its state moves when the set does.
 *   - `EmailSubmission/set` resolves the `identityId` a client supplies
 *     against that same set, and refuses one outside it.
 *
 * Cross-account isolation of the set is pinned in
 * test/layer-1-state/web-isolation.test.js, beside the other vectors
 * that ask what one account can reach of another's. The identity state
 * string is pinned in test/layer-1-state/jmap-state-currency.test.js,
 * beside the other state strings a client caches against.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface, the data directory is temporary, and the outbound path is
 * the shared stand-in with a recorder on its send.
 *
 * Run standalone: node test/layer-1-state/web-author-identity.test.js
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
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SECOND   = "other.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var SOLO_PASSWORD    = "another quiet lantern 7715";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The addresses the fixture builds. `sales` is the shared departmental
// alias this file exists for, `press` is an alias at a second hosted
// domain so nothing here can pass by assuming one domain, and the
// catch-all claims every remaining name at the first domain so the
// assertion that it is not an identity has something to be about.
var ALICE     = "alice@" + DOMAIN;
var SOLO      = "solo@" + DOMAIN;
var SALES     = "sales@" + DOMAIN;
var PRESS     = "press@" + SECOND;
var UNCLAIMED = "nothing-points-here@" + DOMAIN;

// The compose form's author picker, and the values inside it. Read off
// the rendered page rather than out of the handler, because the handler's
// answer is not what a reader is shown or what a browser posts back.
var FROM_SELECT_RE = /<select[^>]*\sname="from"[^>]*>([\s\S]*?)<\/select>/;
var OPTION_VALUE_RE = /<option[^>]*\svalue="([^"]*)"/g;
var SELECTED_OPTION_RE = /<option[^>]*\svalue="([^"]*)"[^>]*\sselected/;

// The refusal a page carries, which is the notice the compose view
// renders above the form. Matching the notice rather than the whole body
// keeps the assertion honest: every permitted address is also printed
// inside the picker, so a search of the whole page would pass for a
// refusal that named nothing at all.
var NOTICE_RE = /notice-bad[\s\S]*?<p>([\s\S]*?)<\/p>/;

function optionValues(page) {
  var block = FROM_SELECT_RE.exec(page.body);
  if (block === null) return null;
  OPTION_VALUE_RE.lastIndex = 0;
  var found = [];
  var hit = OPTION_VALUE_RE.exec(block[1]);
  while (hit !== null) {
    found.push(hit[1]);
    hit = OPTION_VALUE_RE.exec(block[1]);
  }
  return found;
}

function noticeOf(page) {
  var found = NOTICE_RE.exec(page.body);
  return found === null ? null : found[1].trim();
}

// One outbound path that records rather than connects. The composer
// requires the whole delivery handle, so the shared stand-in carries the
// queue contract and only `send` is replaced.
function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({
        from:   envelope.from,
        to:     (envelope.to || []).slice(),
        rfc822: envelope.rfc822,
      });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    all:      function () { return sent.slice(); },
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
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

// ---- the browser surface ---------------------------------------------------

// An account holding one address is offered no choice, because there is
// none to make. A picker there is clutter on the form every mailbox
// owner uses most.
async function anAccountWithOneAddressSeesNoPicker(reader) {
  var page = await reader.get("/compose");
  count("the compose form renders for an account holding one address",
    page.status === 200, "HTTP " + page.status);
  count("an account holding one address is offered no author picker, because there " +
    "is no choice to make",
    optionValues(page) === null, String(page.body.indexOf("name=\"from\"")));
  count("and the form still says which address the message will be sent from",
    page.body.indexOf(SOLO) !== -1);
}

// An account holding a shared address is offered exactly the set, in the
// order the derivation returns it, with its own address the one already
// chosen.
async function anAccountHoldingSeveralSeesThemAll(reader, allowed) {
  var page = await reader.get("/compose");
  count("the compose form renders for an account holding several addresses",
    page.status === 200, "HTTP " + page.status);

  var offered = optionValues(page);
  count("an account holding a shared address is offered an author picker",
    offered !== null, String(offered));
  count("the picker offers exactly the addresses this account may write, in that order",
    offered !== null && offered.join(",") === allowed.join(","),
    JSON.stringify(offered) + " against " + JSON.stringify(allowed));
  count("the shared departmental alias is one of them",
    offered !== null && offered.indexOf(SALES) !== -1, JSON.stringify(offered));
  count("so is an alias at another hosted domain, so nothing here reads one domain " +
    "as the whole of what an account may write",
    offered !== null && offered.indexOf(PRESS) !== -1, JSON.stringify(offered));
  count("a name the catch-all would deliver to this mailbox is not offered, because " +
    "a catch-all claims every name at a domain and is not an identity",
    offered !== null && offered.indexOf(UNCLAIMED) === -1, JSON.stringify(offered));

  var chosen = SELECTED_OPTION_RE.exec(page.body);
  count("the account's own address is the one already chosen, so sending changes " +
    "nothing for a reader who does not touch the picker",
    chosen !== null && chosen[1] === ALICE, chosen === null ? "none" : chosen[1]);
}

async function composingAsAnAliasWritesTheAliasAndKeepsTheEnvelope(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    from:    SALES,
    to:      "buyer@peer.example",
    subject: "the quarterly order",
    text:    "Confirming the quantities we discussed.",
  });
  count("a message written as the shared alias is accepted",
    sent.status === 302, "HTTP " + sent.status + " " + String(noticeOf(sent)));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);

  var out = log.last();
  count("its From header names the alias the reader chose",
    out !== null && headerOf(out.rfc822, "from").indexOf(SALES) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
  count("and the envelope sender stays the account's own address, which is the split " +
    "that lets this surface offer an alias the envelope binding would refuse from a " +
    "client that put the alias in both",
    out !== null && out.from === ALICE, out === null ? "nothing sent" : String(out.from));
}

async function composingAsTheOwnAddressStillWorks(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    from:    ALICE,
    to:      "buyer@peer.example",
    subject: "the same order, under her own name",
    text:    "Same message, own address.",
  });
  count("a message written as the account's own address is accepted",
    sent.status === 302, "HTTP " + sent.status + " " + String(noticeOf(sent)));
  var out = log.last();
  count("its From header names the account's own address",
    log.count() === before + 1 && out !== null &&
    headerOf(out.rfc822, "from").indexOf(ALICE) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
}

async function composingWithNoAuthorFieldStillWorks(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    to:      "buyer@peer.example",
    subject: "no author field at all",
    text:    "A form that never carried the field.",
  });
  count("a post carrying no author field is accepted, because a missing form field " +
    "in a browser request is ordinary rather than hostile",
    sent.status === 302, "HTTP " + sent.status + " " + String(noticeOf(sent)));
  var out = log.last();
  count("and it is sent as the account's own address",
    log.count() === before + 1 && out !== null &&
    headerOf(out.rfc822, "from").indexOf(ALICE) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
}

async function anAuthorOutsideTheSetIsRefused(reader, log, written, label, allowed) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    from:    written,
    to:      "buyer@peer.example",
    subject: "written as " + label,
    text:    "This one should not leave.",
  });
  count(label + ": the message is refused rather than sent",
    sent.status === 400, "HTTP " + sent.status);
  count(label + ": and nothing reached the outbound path",
    log.count() === before, log.count() + " after " + before);

  var notice = noticeOf(sent);
  count(label + ": the refusal names the identity that was rejected",
    notice !== null && notice.indexOf(written) !== -1, String(notice));
  var namesAll = notice !== null && allowed.every(function (entry) {
    return notice.indexOf(entry) !== -1;
  });
  count(label + ": and names every identity that would have been accepted",
    namesAll, String(notice));
}

// The picker is presentation. An account that was never shown one still
// has its post measured against the set, because a hidden field naming
// the author is a request parameter like any other.
async function anAccountShownNoPickerIsStillMeasured(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    from:    SALES,
    to:      "buyer@peer.example",
    subject: "an author this form never offered",
    text:    "Posted by hand into a form that carried no picker.",
  });
  count("an author posted by hand into a form that offered none is refused",
    sent.status === 400, "HTTP " + sent.status);
  count("and nothing reached the outbound path",
    log.count() === before, log.count() + " after " + before);
  var notice = noticeOf(sent);
  count("the refusal names the address this account may write, which is its own",
    notice !== null && notice.indexOf(SOLO) !== -1, String(notice));
}

// ---- JMAP ------------------------------------------------------------------

async function identityGetAnswersWithTheWholeSet(reader, accountId, allowed) {
  var answer = await reader.jmap([["Identity/get", { accountId: accountId }, "i0"]]);
  count("Identity/get is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  var list = Array.isArray(result.list) ? result.list : [];

  count("one Identity is returned for each address this account may write",
    list.length === allowed.length, JSON.stringify(list.map(function (i) { return i.email; })));
  count("and their addresses are exactly that set, in that order",
    list.map(function (i) { return i.email; }).join(",") === allowed.join(","),
    JSON.stringify(list.map(function (i) { return i.email; })));
  count("the account's own identity keeps the account's id, so a client that already " +
    "cached one does not find its sending identity replaced",
    list.length > 0 && list[0].id === accountId,
    JSON.stringify(list.map(function (i) { return i.id; })));

  var ids = list.map(function (i) { return i.id; });
  count("every identity carries a distinct id",
    ids.filter(function (id, at) { return ids.indexOf(id) === at; }).length === ids.length,
    JSON.stringify(ids));
  // RFC 8620 section 1.2 holds an id to the URL and filename safe base64
  // alphabet of RFC 4648 section 5 without the pad character, at most 255
  // octets, so a client may carry one in a path segment without escaping
  // it. An address is not that shape, which is why a derived id exists at
  // all rather than the alias simply naming itself.
  count("every id is one RFC 8620 section 1.2 admits, so a client may put it in a URL",
    ids.every(function (id) { return /^[A-Za-z0-9_-]{1,255}$/.test(id); }),
    JSON.stringify(ids));
  count("no identity is deletable, because this server serves no Identity/set",
    list.every(function (i) { return i.mayDelete === false; }),
    JSON.stringify(list.map(function (i) { return i.mayDelete; })));

  var again = browser.answer(
    await reader.jmap([["Identity/get", { accountId: accountId }, "i1"]]), 0)[1];
  count("asking twice returns the same ids, so an identity a client stored is still " +
    "the one it names on the next request",
    (again.list || []).map(function (i) { return i.id; }).join(",") === ids.join(","),
    JSON.stringify((again.list || []).map(function (i) { return i.id; })));

  var byAddress = {};
  for (var i = 0; i < list.length; i += 1) byAddress[list[i].email] = list[i].id;
  return byAddress;
}

async function submissionSendsAsTheIdentityItNames(reader, accountId, emailId, identityId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: identityId, emailId: emailId } },
  }, "e0"]]);
  count("EmailSubmission/set is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  count("a submission naming the shared alias identity is created",
    Object.prototype.hasOwnProperty.call(result.created || {}, "s0"),
    JSON.stringify(result.notCreated));
  count("and one message reached the outbound path",
    log.count() === before + 1, log.count() + " after " + before);

  var out = log.last();
  count("its From header names the identity the client chose rather than the account",
    out !== null && headerOf(out.rfc822, "from").indexOf(SALES) !== -1,
    out === null ? "nothing sent" : headerOf(out.rfc822, "from"));
  count("and the envelope sender stays the account's own address",
    out !== null && out.from === ALICE, out === null ? "nothing sent" : String(out.from));
}

async function submissionRefusesAnIdentityOutsideTheSet(reader, accountId, emailId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { identityId: "idt_0000000000000000000000000000000f", emailId: emailId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];
  var refusal = (result.notCreated || {}).s0 || null;
  count("a submission naming an identity this account does not hold is refused",
    refusal !== null, JSON.stringify(result.created));
  count("and it is refused as an identity that was not found, which is the error " +
    "RFC 8621 section 7.5 gives that case",
    refusal !== null && refusal.type === "identityNotFound",
    refusal === null ? "created" : String(refusal.type));
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

async function submissionRefusesAnAbsentIdentity(reader, accountId, emailId, log) {
  var before = log.count();
  var answer = await reader.jmap([["EmailSubmission/set", {
    accountId: accountId,
    create:    { s0: { emailId: emailId } },
  }, "e0"]]);
  var result = browser.answer(answer, 0)[1];
  var refusal = (result.notCreated || {}).s0 || null;
  count("a submission naming no identity at all is refused rather than guessed at, " +
    "because RFC 8621 section 7.5 makes the property required",
    refusal !== null && refusal.type === "invalidProperties",
    refusal === null ? "created" : JSON.stringify(refusal));
  count("the refusal names the property that was missing",
    refusal !== null && (refusal.properties || []).indexOf("identityId") !== -1,
    refusal === null ? "created" : JSON.stringify(refusal.properties));
  count("nothing reached the outbound path", log.count() === before,
    log.count() + " after " + before);
}

// ---- the trail a refusal leaves --------------------------------------------

// The submission listener records the author it refuses. An operator
// reading that trail for somebody trying to write as an address they do
// not hold has to see the browser and the JMAP attempts beside the SMTP
// ones, or the trail reads as though only SMTP callers were ever tried.
//
// Read after the vectors above rather than beside each one, because a
// row reaches the chain through a flush and asking once at the end is
// what the other files that read this trail do.
async function everyRefusalLeftARow(surfaces) {
  await b.audit.flush();
  var rows = await b.audit.query({
    action: "blamepost.web.author_not_permitted", limit: 50, order: "desc",
  });
  var list = Array.isArray(rows) ? rows : [];
  count("every author this run refused left a row an operator can find",
    list.length >= surfaces.length, list.length + " rows for " + surfaces.length + " refusals");

  // The chain stores the metadata as text, so it is read back the way
  // every other file that reads this trail reads it.
  var carried = list.map(function (row) { return JSON.parse(row.metadata || "{}"); });
  var seen = carried.map(function (metadata) { return String(metadata.surface || ""); });
  for (var i = 0; i < surfaces.length; i += 1) {
    count("the trail carries the refusal that happened on " + surfaces[i],
      seen.indexOf(surfaces[i]) !== -1, JSON.stringify(seen));
  }
  count("every row is filed as a denial rather than as something that happened",
    list.every(function (row) { return row.outcome === "denied"; }),
    JSON.stringify(list.map(function (row) { return row.outcome; })));
  count("every row names the account that was acting, in the column an auditor filters on",
    list.every(function (row) {
      return typeof row.actorUserId === "string" && row.actorUserId.length > 0;
    }),
    JSON.stringify(list.map(function (row) { return row.actorUserId; })));
  count("and every row names the identity that was rejected",
    carried.every(function (metadata) {
      return typeof metadata.rejected === "string" && metadata.rejected.length > 0;
    }),
    JSON.stringify(carried.map(function (metadata) { return metadata.rejected; })));
}

// ---- runner ----------------------------------------------------------------

function message(marker, to) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: Dana Reyes <dana@peer.example>",
    "To: <" + to + ">",
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "",
    "Body for " + marker + ".",
    "",
  ].join("\r\n"), "utf8");
}

async function run() {
  var root    = helpers.tempDir("webauthor");
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
    await identity.domains.add({ domain: SECOND });

    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });
    var solo  = await identity.accounts.create({ address: SOLO,  password: SOLO_PASSWORD });

    await identity.aliases.add({ address: SALES, destination: ALICE });
    await identity.aliases.add({ address: PRESS, destination: ALICE });
    await identity.aliases.add({ catchAll: true, domain: DOMAIN, destination: ALICE });

    // The one derivation, asked here so every assertion below compares
    // against the same answer the server is supposed to be composing
    // rather than against a list restated in this file.
    var allowed = blamepost.mail.listeners.permittedAuthors(identity,
      { id: alice.id, address: alice.address });
    count("the fixture gives this account more than one address to write as, which is " +
      "the arrangement every assertion below is about",
      allowed.length > 1, JSON.stringify(allowed));
    count("and the catch-all is already excluded by the derivation itself",
      allowed.indexOf(UNCLAIMED) === -1, JSON.stringify(allowed));

    var soloAllowed = blamepost.mail.listeners.permittedAuthors(identity,
      { id: solo.id, address: solo.address });
    count("the other account in the fixture holds one address and no alias",
      soloAllowed.length === 1 && soloAllowed[0] === SOLO, JSON.stringify(soloAllowed));

    var draft = identity.mailbox.appendMessage("Drafts", message("jmap-draft", ALICE),
      { actor: { id: alice.id } });

    var log = recorder();
    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  log.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });

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
    var ports  = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var reader = browser.browserAt(origin);
    var landing = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the account holding several addresses signs in",
      landing.status === 302, landing.status + " " + String(landing.location));

    var lonely = browser.browserAt(origin);
    var soloLanding = await lonely.signIn(SOLO, SOLO_PASSWORD);
    count("the account holding one address signs in",
      soloLanding.status === 302, soloLanding.status + " " + String(soloLanding.location));

    await anAccountWithOneAddressSeesNoPicker(lonely);
    await anAccountHoldingSeveralSeesThemAll(reader, allowed);
    await composingAsAnAliasWritesTheAliasAndKeepsTheEnvelope(reader, log);
    await composingAsTheOwnAddressStillWorks(reader, log);
    await composingWithNoAuthorFieldStillWorks(reader, log);
    await anAuthorOutsideTheSetIsRefused(reader, log, UNCLAIMED,
      "a name the catch-all would deliver here", allowed);
    await anAuthorOutsideTheSetIsRefused(reader, log, "stranger@peer.example",
      "an address at a domain this server does not host", allowed);
    await anAccountShownNoPickerIsStillMeasured(lonely, log);

    var byAddress = await identityGetAnswersWithTheWholeSet(reader, alice.id, allowed);
    await submissionSendsAsTheIdentityItNames(reader, alice.id, draft.objectid,
      byAddress[SALES], log);
    await submissionRefusesAnIdentityOutsideTheSet(reader, alice.id, draft.objectid, log);
    await submissionRefusesAnAbsentIdentity(reader, alice.id, draft.objectid, log);

    await everyRefusalLeftARow(["compose", "jmap-submission"]);

    return helpers.getChecks();
  } finally {
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
  name:      "web-author-identity",
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
