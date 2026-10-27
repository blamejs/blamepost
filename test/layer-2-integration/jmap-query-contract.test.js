// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the session document tells a JMAP client this server does, and
 * what the methods do when the client takes it at its word. Driven over
 * a real loopback port with a signed-in session.
 *
 * Three questions, each asked as a request a client sends:
 *
 *   - the RFC 8621 account capability objects. A client reads
 *     `emailQuerySortOptions`, `mayCreateTopLevelMailbox` and
 *     `maxDelayedSend` before it draws a button, so an empty object
 *     leaves it guessing and it guesses the defaults its author chose.
 *     Every property the two capabilities name is checked against the
 *     answer the matching method gives, so the document and the server
 *     are one statement rather than two.
 *
 *   - `Email/query` over a folder holding more rows than one page.
 *     `position`, `limit` and `calculateTotal` decide which rows a
 *     client can reach and what it is told about the rest, and a `sort`
 *     or a filter condition this server does not read changes which
 *     messages match. An argument accepted and dropped answers a
 *     question the client did not ask.
 *
 *   - `EmailSubmission/set` carrying `sendAt`. A client scheduling mail
 *     for later is asking for something this server does not do, and
 *     the answer it gets decides whether the mail goes out now.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/jmap-query-contract.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

// The separator a mailbox name carries between its levels, read from the
// layer that owns the namespace rather than written here, so a change to
// it moves this reading with it.
var HIERARCHY_DELIMITER = require("../../lib/mail/mailbox").HIERARCHY_DELIMITER;

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var ALICE            = "alice@" + DOMAIN;

// More than one page, so a request for the second page has somewhere to
// go and a truthful total differs from the page it fits in.
var INBOX_MESSAGES = 520;

// The one message a keyword filter would single out. A filter this
// server drops answers with all of them instead.
var FLAGGED_SUBJECT = "the one message carrying a keyword";

var SHUTDOWN_TIMEOUT_MS = 5000;
var READER_TIMEOUT_MS   = 30000;

// RFC 8621 section 1.6.2. The properties the mail account capability
// carries, and what each has to be typed as.
var MAIL_CAPABILITY = "urn:ietf:params:jmap:mail";
var MAIL_PROPERTIES = [
  { name: "maxMailboxesPerEmail",       ok: _unsignedOrNull },
  { name: "maxMailboxDepth",            ok: _unsignedOrNull },
  { name: "maxSizeMailboxName",         ok: _unsigned },
  { name: "maxSizeAttachmentsPerEmail", ok: _unsigned },
  { name: "emailQuerySortOptions",      ok: Array.isArray },
  { name: "mayCreateTopLevelMailbox",   ok: function (v) { return typeof v === "boolean"; } },
];

// RFC 8621 section 7. The submission account capability.
var SUBMISSION_CAPABILITY = "urn:ietf:params:jmap:submission";
var SUBMISSION_PROPERTIES = [
  { name: "maxDelayedSend",       ok: _unsigned },
  { name: "submissionExtensions", ok: function (v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  } },
];

function _unsigned(value) {
  return Number.isInteger(value) && value >= 0;
}

function _unsignedOrNull(value) {
  return value === null || _unsigned(value);
}

function message(lines) {
  return Buffer.from(lines.join("\r\n") + "\r\n", "utf8");
}

// One outbound path that records instead of connecting.
function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({ from: envelope.from, to: (envelope.to || []).slice() });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
  };
}

async function call(reader, methodCalls) {
  var response = await reader.jmap(methodCalls);
  return {
    status: response.status,
    body:   response.body,
    first:  browser.answer(response, 0),
    all:    JSON.parse(response.body).methodResponses,
  };
}

// RFC 8620 section 3.6.2 writes a method-level error type bare, with no
// URN prefix; the prefix belongs to the request-level problem types.
function isMethodError(answer, type) {
  return answer[0] === "error" && answer[1] && answer[1].type === type;
}

function queryArgs(alice, extra) {
  var args = { accountId: alice.id };
  var keys = Object.keys(extra || {});
  for (var i = 0; i < keys.length; i += 1) args[keys[i]] = extra[keys[i]];
  return args;
}

async function query(reader, alice, extra) {
  return (await call(reader, [["Email/query", queryArgs(alice, extra), "c0"]])).first;
}

// ---- the account capabilities ----------------------------------------------

// An account capability object is the only place a client learns what it
// may ask for. RFC 8620 section 2 has it read the document once and
// shape its whole session around what it found, so a property the
// document leaves out is one the client fills in from its own default
// and then acts on.
async function theAccountCapabilitiesNameWhatThisServerServes(reader, alice) {
  var session = await reader.get("/jmap/session", { Accept: "application/json" });
  count("the session document answers", session.status === 200, session.status);
  var doc = JSON.parse(session.body);
  var account = (doc.accounts || {})[alice.id] || {};
  var held = account.accountCapabilities || {};

  var mail = held[MAIL_CAPABILITY];
  count("the account carries the mail capability", mail !== null && typeof mail === "object",
    JSON.stringify(held));
  for (var i = 0; i < MAIL_PROPERTIES.length; i += 1) {
    var property = MAIL_PROPERTIES[i];
    count("the mail account capability names " + property.name + " as RFC 8621 section 1.6.2 types it",
      mail !== null && typeof mail === "object" && property.ok(mail[property.name]),
      property.name + "=" + JSON.stringify(mail && mail[property.name]));
  }

  var submission = held[SUBMISSION_CAPABILITY];
  count("the account carries the submission capability",
    submission !== null && typeof submission === "object", JSON.stringify(held));
  for (var s = 0; s < SUBMISSION_PROPERTIES.length; s += 1) {
    var entry = SUBMISSION_PROPERTIES[s];
    count("the submission account capability names " + entry.name + " as RFC 8621 section 7 types it",
      submission !== null && typeof submission === "object" && entry.ok(submission[entry.name]),
      entry.name + "=" + JSON.stringify(submission && submission[entry.name]));
  }
  return { mail: mail || {}, submission: submission || {} };
}

// Each advertised value, asked of the method that would have to honor
// it. This is the half that catches a document filled in from what the
// author meant rather than from what the server does.
async function eachAdvertisedValueMatchesWhatTheMethodDoes(reader, alice, fixture, capabilities) {
  var mail = capabilities.mail;

  var created = await call(reader, [["Mailbox/set", {
    accountId: alice.id, create: { m: { name: "a new top level mailbox" } },
  }, "c0"]]);
  count("mayCreateTopLevelMailbox is false and Mailbox/set really is not served",
    mail.mayCreateTopLevelMailbox === false && isMethodError(created.first, "unknownMethod"),
    JSON.stringify(mail.mayCreateTopLevelMailbox) + " against " + JSON.stringify(created.first));

  var sorted = await query(reader, alice, {
    sort: [{ property: "receivedAt", isAscending: true }],
  });
  count("emailQuerySortOptions is empty and a query naming a sort is refused unsupportedSort",
    Array.isArray(mail.emailQuerySortOptions) && mail.emailQuerySortOptions.length === 0 &&
    isMethodError(sorted, "unsupportedSort"),
    JSON.stringify(mail.emailQuerySortOptions) + " against " + JSON.stringify(sorted).slice(0, 200));

  var twoMailboxes = {};
  twoMailboxes[fixture.aliceMessage] = { mailboxIds: { INBOX: true, Trash: true } };
  var filed = await call(reader, [["Email/set",
    { accountId: alice.id, update: twoMailboxes }, "c0"]]);
  var notUpdated = (filed.first[1] || {}).notUpdated || {};
  count("maxMailboxesPerEmail is one and a patch naming two mailboxes is refused",
    mail.maxMailboxesPerEmail === 1 &&
    Object.prototype.hasOwnProperty.call(notUpdated, fixture.aliceMessage),
    JSON.stringify(mail.maxMailboxesPerEmail) + " against " + JSON.stringify(filed.first).slice(0, 200));

  var mailboxes = await call(reader, [["Mailbox/get", { accountId: alice.id }, "c0"]]);
  var list = (mailboxes.first[1] || {}).list || [];
  var ids = list.map(function (row) { return row.id; });
  var deepest = ids.reduce(function (most, id) {
    var levels = String(id).split(HIERARCHY_DELIMITER).length;
    return levels > most ? levels : most;
  }, 0);
  count("maxMailboxDepth covers the hierarchy this account holds, or is null for the no " +
    "limit RFC 8621 section 1.6.2 defines",
    mail.maxMailboxDepth === null ||
    (_unsigned(mail.maxMailboxDepth) && mail.maxMailboxDepth >= deepest),
    JSON.stringify(mail.maxMailboxDepth) + " against a namespace " + deepest + " levels deep");

  var dangling = list.filter(function (row) {
    return row.parentId !== null && ids.indexOf(row.parentId) === -1;
  });
  count("and every parentId names a mailbox in the same answer, because a client that " +
    "cannot resolve one drops the mailbox under it",
    dangling.length === 0,
    JSON.stringify(dangling.map(function (row) { return row.id + " -> " + row.parentId; })));

  var longest = list.reduce(function (most, row) {
    return String(row.id).length > most ? String(row.id).length : most;
  }, 0);
  count("maxSizeMailboxName is at least as long as the longest mailbox name this server issues",
    _unsigned(mail.maxSizeMailboxName) && mail.maxSizeMailboxName >= longest,
    JSON.stringify(mail.maxSizeMailboxName) + " against " + longest);

  var upload = await reader.post("/jmap/upload/" + alice.id, "text/plain", "an attachment",
    { Accept: "application/json" });
  count("maxSizeAttachmentsPerEmail is zero and the upload endpoint really accepts nothing",
    mail.maxSizeAttachmentsPerEmail === 0 && upload.status >= 400,
    JSON.stringify(mail.maxSizeAttachmentsPerEmail) + " against " + upload.status);
}

// ---- Email/query ------------------------------------------------------------

async function theQueryAnswersWithinItsOwnLimits(reader, alice, core) {
  var first = await query(reader, alice, {});
  count("a query over a folder holding more rows than one page answers with a page of them",
    first[0] === "Email/query" && Array.isArray(first[1].ids) && first[1].ids.length > 0,
    JSON.stringify(first).slice(0, 200));
  count("and it answers with no more ids than Email/get will take in one call, " +
    "because the two ceilings are one server's",
    first[1].ids.length <= core.maxObjectsInGet,
    first[1].ids.length + " against " + core.maxObjectsInGet);
  count("and it names the limit it applied, which is the only way a client learns " +
    "the page was the server's choice rather than the end of the folder",
    Number.isInteger(first[1].limit) && first[1].limit >= 1, JSON.stringify(first[1]).slice(0, 200));
  count("and it reports the position the page starts at", first[1].position === 0,
    JSON.stringify(first[1].position));
  return first[1].ids;
}

async function aTotalIsReportedOnlyWhenItWasAskedFor(reader, alice) {
  var quiet = await query(reader, alice, {});
  count("a query that did not ask for a total carries none, which RFC 8620 section 5.5 requires",
    !Object.prototype.hasOwnProperty.call(quiet[1], "total"), JSON.stringify(Object.keys(quiet[1])));

  var counted = await query(reader, alice, { calculateTotal: true });
  count("a query that asked for a total is given the folder's count rather than the page's",
    counted[1].total === INBOX_MESSAGES + 1,
    JSON.stringify(counted[1].total) + " against " + (INBOX_MESSAGES + 1) +
    " with " + (counted[1].ids || []).length + " ids in the page");
}

async function positionAndLimitReachTheRestOfTheFolder(reader, alice, firstPage) {
  var smaller = await query(reader, alice, { limit: 5 });
  count("a query naming a limit is given that many ids rather than the server's page",
    smaller[0] === "Email/query" && (smaller[1].ids || []).length === 5,
    (smaller[1].ids || []).length + " ids");
  count("and the limit it reports is the one it applied",
    smaller[1].limit === 5, JSON.stringify(smaller[1].limit));

  var second = await query(reader, alice, { position: firstPage.length, limit: 10 });
  var secondIds = second[1].ids || [];
  count("a query naming a position past the first page reaches rows the first page did not carry",
    second[0] === "Email/query" && secondIds.length === 10 &&
    secondIds.every(function (id) { return firstPage.indexOf(id) === -1; }),
    JSON.stringify(secondIds).slice(0, 200));
  count("and it reports the position it answered from",
    second[1].position === firstPage.length, JSON.stringify(second[1].position));

  var overlapping = await query(reader, alice, { position: 1, limit: 3 });
  count("a position inside the first page answers from that row of it",
    JSON.stringify((overlapping[1].ids || [])) === JSON.stringify(firstPage.slice(1, 4)),
    JSON.stringify((overlapping[1].ids || [])) + " against " + JSON.stringify(firstPage.slice(1, 4)));

  var fromTheEnd = await query(reader, alice, { position: -1 });
  count("a negative position is read as an offset from the end of the results",
    (fromTheEnd[1].ids || []).length === 1, JSON.stringify(fromTheEnd).slice(0, 200));

  var past = await query(reader, alice, { position: INBOX_MESSAGES + 500 });
  count("a position past the end of the folder answers with no ids rather than the first page",
    past[0] === "Email/query" && (past[1].ids || []).length === 0,
    JSON.stringify(past).slice(0, 200));

  var shapes = [
    { label: "a position that is not a whole number", args: { position: 1.5 } },
    { label: "a position that is a string", args: { position: "0" } },
    { label: "a limit that is negative", args: { limit: -1 } },
    { label: "a limit that is a string", args: { limit: "10" } },
    { label: "a sort that is not a list", args: { sort: "receivedAt" } },
  ];
  for (var i = 0; i < shapes.length; i += 1) {
    var shaped = await query(reader, alice, shapes[i].args);
    count("a query given " + shapes[i].label + " is refused invalidArguments",
      isMethodError(shaped, "invalidArguments"), JSON.stringify(shaped).slice(0, 200));
  }
}

async function aFilterThisServerCannotReadIsRefusedRatherThanDropped(reader, alice, fixture) {
  var supported = await query(reader, alice, { filter: { inMailbox: "INBOX" } });
  count("a filter naming a condition this server reads is answered",
    supported[0] === "Email/query" && (supported[1].ids || []).length > 0,
    JSON.stringify(supported).slice(0, 160));

  var conditions = [
    { label: "hasKeyword", filter: { hasKeyword: "$flagged" } },
    { label: "notKeyword", filter: { notKeyword: "$seen" } },
    { label: "inMailboxOtherThan", filter: { inMailboxOtherThan: ["INBOX"] } },
    { label: "before", filter: { before: "2020-01-01T00:00:00Z" } },
    { label: "minSize", filter: { minSize: 1 } },
    { label: "subject", filter: { subject: FLAGGED_SUBJECT } },
    { label: "a condition no specification defines", filter: { noSuchCondition: true } },
    { label: "a FilterOperator", filter: { operator: "AND", conditions: [{ inMailbox: "INBOX" }] } },
  ];
  for (var i = 0; i < conditions.length; i += 1) {
    var answer = await query(reader, alice, { filter: conditions[i].filter });
    count("a filter naming " + conditions[i].label + " is refused unsupportedFilter rather " +
      "than dropped, because a dropped condition answers with mail the client did not ask for",
      isMethodError(answer, "unsupportedFilter"),
      JSON.stringify(answer).slice(0, 200));
    count("and the refusal carries none of the messages it would have matched over",
      (answer[1].ids || []).length === 0, JSON.stringify(answer[1].ids || []).slice(0, 120));
  }

  var anchored = await query(reader, alice, { anchor: fixture.aliceMessage });
  count("a query naming an anchor is refused anchorNotFound rather than answered from the top",
    isMethodError(anchored, "anchorNotFound"), JSON.stringify(anchored).slice(0, 200));

  var collapsed = await query(reader, alice, { collapseThreads: true });
  count("a query asking for collapsed threads is refused rather than answered uncollapsed",
    collapsed[0] === "error", JSON.stringify(collapsed).slice(0, 200));

  var uncollapsed = await query(reader, alice, { collapseThreads: false });
  count("and asking for them uncollapsed, which is what this server does, is answered",
    uncollapsed[0] === "Email/query", JSON.stringify(uncollapsed).slice(0, 160));
}

// ---- EmailSubmission/set ----------------------------------------------------

async function aSubmissionThisServerWillNotDelayIsRefused(reader, alice, fixture, capabilities, log) {
  var sentBefore = log.count();
  var later = new Date(Date.now() + 86400000).toISOString();
  var scheduled = await call(reader, [["EmailSubmission/set", {
    accountId: alice.id,
    create:    { s: { identityId: alice.id, emailId: fixture.draft, sendAt: later } },
  }, "c0"]]);
  var answer = scheduled.first[1] || {};
  var notCreated = answer.notCreated || {};
  count("maxDelayedSend is zero and a submission asking to be sent later is refused",
    capabilities.submission.maxDelayedSend === 0 &&
    Object.prototype.hasOwnProperty.call(notCreated, "s"),
    JSON.stringify(capabilities.submission.maxDelayedSend) + " against " +
    JSON.stringify(scheduled.first).slice(0, 260));
  count("and the refusal names sendAt, so the client knows which property to drop",
    (notCreated.s || {}).type === "invalidProperties" &&
    (notCreated.s.properties || []).indexOf("sendAt") !== -1,
    JSON.stringify(notCreated.s));
  count("and the message the client asked to hold was not sent now instead",
    log.count() === sentBefore, log.count() + " after " + sentBefore);

  var now = await call(reader, [["EmailSubmission/set", {
    accountId: alice.id,
    create:    { s: { identityId: alice.id, emailId: fixture.draft, sendAt: new Date(0).toISOString() } },
  }, "c0"]]);
  var sentNow = (now.first[1] || {}).created || {};
  count("a sendAt this server has already passed is nothing to wait for and the message goes",
    Object.prototype.hasOwnProperty.call(sentNow, "s"), JSON.stringify(now.first).slice(0, 260));

  var unreadable = await call(reader, [["EmailSubmission/set", {
    accountId: alice.id,
    create:    { s: { identityId: alice.id, emailId: fixture.draft, sendAt: "next tuesday" } },
  }, "c0"]]);
  var refused = ((unreadable.first[1] || {}).notCreated || {}).s || {};
  count("a sendAt that is not a date is refused rather than read as now",
    refused.type === "invalidProperties", JSON.stringify(unreadable.first).slice(0, 260));
}

// ---- the result reference the framework resolves ----------------------------

// RFC 8620 section 3.7 has `*` map the rest of the path over an array,
// so `/list/*/id` over a Mailbox/get answer is the list of mailbox ids.
// The invariant this server owns is what happens next: an argument that
// arrived through a back-reference is read by the same validation as one
// the client wrote out. Mailbox ids name no message, so Email/get
// reports each one not found and answers with no mail.
async function aResolvedResultReferenceIsValidatedLikeAnyOtherArgument(reader, alice) {
  var wildcard = await call(reader, [
    ["Mailbox/get", { accountId: alice.id }, "c0"],
    ["Email/get", { accountId: alice.id,
      "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/list/*/id" } }, "c1"],
  ]);
  var mailboxIds = ((wildcard.all[0] || [])[1] || {}).list || [];
  var answered = (wildcard.all[1] || [])[1] || {};
  count("an id list that arrived through a result reference is read like a written one: " +
    "each mailbox id it carries is reported not found",
    wildcard.all[1][0] === "Email/get" && mailboxIds.length > 0 &&
    Array.isArray(answered.notFound) && answered.notFound.length === mailboxIds.length,
    JSON.stringify(wildcard.all[1]).slice(0, 200));
  count("and the answer carries no mail",
    (answered.list || []).length === 0, JSON.stringify(wildcard.all[1]).slice(0, 200));

  var piped = await call(reader, [
    ["Email/query", { accountId: alice.id }, "c0"],
    ["Email/get", { accountId: alice.id,
      "#ids": { resultOf: "c0", name: "Email/query", path: "/ids" } }, "c1"],
  ]);
  count("and the query page this server does answer with feeds Email/get in one request, " +
    "which is the pipe every client builds",
    piped.all[1][0] === "Email/get" &&
    (piped.all[1][1].list || []).length === (piped.all[0][1].ids || []).length,
    JSON.stringify(piped.all[1]).slice(0, 160));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("jmapquery");
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
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });

    for (var i = 0; i < INBOX_MESSAGES; i += 1) {
      identity.mailbox.appendMessage("INBOX", message([
        "Message-ID: <inbox-" + i + "@peer.example>",
        "From: Dana Reyes <dana@peer.example>",
        "To: <" + ALICE + ">",
        "Subject: inbox message " + i,
        "Date: Sat, 22 Aug 2026 09:00:00 +0000",
        "", "body " + i]), { actor: { id: alice.id } });
    }
    var aliceMessage = identity.mailbox.appendMessage("INBOX", message([
      "Message-ID: <alice-flagged@peer.example>",
      "From: Dana Reyes <dana@peer.example>",
      "To: <" + ALICE + ">",
      "Subject: " + FLAGGED_SUBJECT,
      "Date: Sat, 22 Aug 2026 11:00:00 +0000",
      "", "the body of the one flagged message"]),
      { actor: { id: alice.id }, flags: ["\\Flagged"] });
    var draft = identity.mailbox.appendMessage("Drafts", message([
      "Message-ID: <alice-draft@" + DOMAIN + ">",
      "From: <" + ALICE + ">",
      "To: <buyer@peer.example>",
      "Subject: a draft to schedule",
      "Date: Sat, 22 Aug 2026 10:30:00 +0000",
      "", "draft body"]), { actor: { id: alice.id }, flags: ["\\Draft"] });

    var fixture = { aliceMessage: aliceMessage.objectid, draft: draft.objectid };
    count("the fixture's messages were all stored",
      [fixture.aliceMessage, fixture.draft].every(function (id) {
        return typeof id === "string" && id.indexOf("obj_") === 0;
      }), JSON.stringify(fixture));

    var log = recorder();
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    listener = blamepost.web.serve({
      agent:     b.mail.agent.create({ store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   identity.mailbox,
      mailStore: identity.messageStore,
      compose:   blamepost.mail.compose.create({
        delivery: log.delivery, hostname: cfg.hostname, dkim: dkimHandle, mailStore: identity.mailbox,
      }),
      dkim:      dkimHandle,
      delivery:  blamepost.mail.delivery.create({ hostname: cfg.hostname, dataDir: cfg.dataDir }),
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports  = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var reader = browser.browserAt(origin, { timeoutMs: READER_TIMEOUT_MS });
    var landed = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the account signs in", landed.status === 302, landed.status);

    var session = await reader.get("/jmap/session", { Accept: "application/json" });
    var core = (JSON.parse(session.body).capabilities || {})["urn:ietf:params:jmap:core"] || {};

    var capabilities = await theAccountCapabilitiesNameWhatThisServerServes(reader, alice);
    await eachAdvertisedValueMatchesWhatTheMethodDoes(reader, alice, fixture, capabilities);

    var firstPage = await theQueryAnswersWithinItsOwnLimits(reader, alice, core);
    await aTotalIsReportedOnlyWhenItWasAskedFor(reader, alice);
    await positionAndLimitReachTheRestOfTheFolder(reader, alice, firstPage);
    await aFilterThisServerCannotReadIsRefusedRatherThanDropped(reader, alice, fixture);
    await aSubmissionThisServerWillNotDelayIsRefused(reader, alice, fixture, capabilities, log);
    await aResolvedResultReferenceIsValidatedLikeAnyOtherArgument(reader, alice);

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

module.exports = { name: "jmap-query-contract", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
