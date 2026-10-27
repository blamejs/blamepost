// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * JMAP authorization, request limits and request refusals, over a real
 * loopback port with a signed-in session for each of two accounts.
 *
 * Every vector is a request an authenticated account can send to
 * `POST /jmap/api`:
 *
 *   - every method this server serves, called with the other account's
 *     `accountId`, and every method it does not serve;
 *   - the other account's message identifiers under the caller's own
 *     `accountId`, for reads, flag writes, moves, destroys, threads and
 *     submissions;
 *   - `EmailSubmission/set` with an envelope naming an address the account
 *     may not send as, and with recipients that differ from the draft's
 *     header fields;
 *   - the RFC 8620 section 2 limits the session document advertises;
 *   - request bodies that are not a JMAP request.
 *
 * A refusal for another account's object is compared with the refusal
 * for an identifier nobody holds, field by field.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/jmap-authorization.test.js
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var ALICE       = "alice@" + DOMAIN;
var BOB         = "bob@" + DOMAIN;
var ALICE_ALIAS = "alices-desk@" + DOMAIN;

var BOB_SUBJECT = "Bobs private quarterly numbers";
var BOB_BODY    = "zebra7741 belongs to bob and to nobody else";

// The draft the submission vectors send. Its Cc recipient is the one a
// derivation that reads only the To field drops.
var DRAFT_TO = "buyer@peer.example";
var DRAFT_CC = "copy@peer.example";
var BLIND    = "hidden@peer.example";

// An objectid of the store's shape that no append issued, and an
// account id no account carries.
var NEVER_ISSUED   = "obj_00000000000000000000000000000000";
var NOBODY_ACCOUNT = "Anobody0000000000000000";

var JMAP_ERROR = "urn:ietf:params:jmap:error:";
var PROBLEM_TYPES = {
  notJSON:           JMAP_ERROR + "notJSON",
  notRequest:        JMAP_ERROR + "notRequest",
  limit:             JMAP_ERROR + "limit",
  unknownCapability: JMAP_ERROR + "unknownCapability",
};

var SHUTDOWN_TIMEOUT_MS = 5000;
var READER_TIMEOUT_MS   = 30000;

// The methods this server serves, and a sample of the RFC 8620 and RFC
// 8621 methods it does not.
var SERVED = [
  "Mailbox/get", "Mailbox/query", "Email/query", "Email/get", "Email/set",
  "Thread/get", "Identity/get", "EmailSubmission/set",
];
var UNSERVED = [
  "Mailbox/set", "Mailbox/changes", "Mailbox/queryChanges", "Email/changes",
  "Email/queryChanges", "Email/import", "Email/copy", "Email/parse",
  "SearchSnippet/get", "Thread/changes", "Identity/set", "Identity/changes",
  "EmailSubmission/get", "EmailSubmission/query", "EmailSubmission/changes",
  "VacationResponse/get", "VacationResponse/set",
  "PushSubscription/get", "PushSubscription/set",
];

function message(lines) {
  return Buffer.from(lines.join("\r\n") + "\r\n", "utf8");
}

// One outbound path that records instead of connecting. `hold` keeps
// every later send pending until `release`, so a submission can be kept
// in flight for as long as a vector needs.
function recorder() {
  var sent = [];
  var pending = [];
  var holding = false;
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      var entry = {
        from:   envelope.from,
        to:     (envelope.to || []).slice(),
        rfc822: Buffer.isBuffer(envelope.rfc822)
          ? envelope.rfc822.toString("utf8") : String(envelope.rfc822),
      };
      var answer = { delivered: entry.to.slice(), deferred: [], failed: [] };
      if (!holding) {
        sent.push(entry);
        return Promise.resolve(answer);
      }
      return new Promise(function (resolve) {
        pending.push(function () { sent.push(entry); resolve(answer); });
      });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
    hold:     function () { holding = true; },
    held:     function () { return pending.length; },
    release:  function () {
      holding = false;
      pending.splice(0).forEach(function (finish) { finish(); });
    },
  };
}

function headerOf(rfc822, name) {
  return b.safeMime.parse(Buffer.from(rfc822, "utf8")).headers.get(name) || "";
}

async function jmap(reader, methodCalls) {
  var response = await reader.jmap(methodCalls);
  return { status: response.status, body: response.body, first: browser.answer(response, 0),
    all: JSON.parse(response.body).methodResponses };
}

function sameJson(x, y) {
  return JSON.stringify(x) === JSON.stringify(y);
}

function leaksBob(body) {
  return body.indexOf(BOB_SUBJECT) !== -1 || body.indexOf(BOB_BODY) !== -1 ||
    body.indexOf(BOB) !== -1;
}

function ids(count, prefix) {
  var out = [];
  for (var i = 0; i < count; i += 1) {
    out.push("obj_" + (prefix + "00000000000000000000000000000000" + i).slice(-32));
  }
  return out;
}

// ---- account confusion -----------------------------------------------------

async function aForeignAccountIdIsRefusedLikeOneNobodyHolds(reader, bob, fixture, log) {
  var sentBefore = log.count();
  var argsFor = {
    "Mailbox/get":         {},
    "Mailbox/query":       {},
    "Email/query":         { filter: { inMailbox: "INBOX" } },
    "Email/get":           { ids: [fixture.bobMessage] },
    "Email/set":           {
      update:  (function () { var u = {}; u[fixture.bobMessage] = { "keywords/$flagged": true }; return u; }()),
      destroy: [fixture.bobMessage],
    },
    "Thread/get":          { ids: [fixture.bobMessage] },
    "Identity/get":        {},
    "EmailSubmission/set": { create: { s: { identityId: bob.id, emailId: fixture.bobMessage } } },
  };
  for (var i = 0; i < SERVED.length; i += 1) {
    var name = SERVED[i];
    var foreign = await jmap(reader, [[name, Object.assign({ accountId: bob.id }, argsFor[name]), "c0"]]);
    var nobody  = await jmap(reader, [[name, Object.assign({ accountId: NOBODY_ACCOUNT }, argsFor[name]), "c0"]]);
    count(name + " naming the other account's accountId is refused with accountNotFound",
      foreign.first[0] === "error" && foreign.first[1].type === JMAP_ERROR + "accountNotFound",
      JSON.stringify(foreign.first));
    count(name + " answers the other account's accountId exactly as it answers one nobody holds",
      sameJson(foreign.first, nobody.first),
      JSON.stringify(foreign.first) + " against " + JSON.stringify(nobody.first));
    count(name + " carries none of the other account's mail or address in that answer",
      !leaksBob(foreign.body), foreign.body.slice(0, 300));
  }
  count("no call naming the other account's accountId sent anything",
    log.count() === sentBefore, log.count() + " after " + sentBefore);
}

async function unservedMethodsAnswerTheSameForEitherAccount(reader, alice, bob, fixture) {
  for (var i = 0; i < UNSERVED.length; i += 1) {
    var name = UNSERVED[i];
    var own = await jmap(reader, [[name, { accountId: alice.id, fromAccountId: bob.id }, "c0"]]);
    var other = await jmap(reader, [[name, { accountId: bob.id, fromAccountId: bob.id }, "c0"]]);
    count(name + " is answered unknownMethod",
      own.first[0] === "error" && own.first[1].type === JMAP_ERROR + "unknownMethod",
      JSON.stringify(own.first));
    count(name + " answers the same whichever account it names",
      sameJson(own.first, other.first),
      JSON.stringify(own.first) + " against " + JSON.stringify(other.first));
  }

  // The two unserved methods that would remove mail or make this server
  // connect somewhere.
  var before = await jmap(reader, [["Email/query", { accountId: alice.id, filter: { inMailbox: "INBOX" } }, "c0"]]);
  var destroy = await jmap(reader, [["Mailbox/set", {
    accountId: alice.id, destroy: ["INBOX"], onDestroyRemoveEmails: true,
  }, "c0"]]);
  count("Mailbox/set with onDestroyRemoveEmails is answered unknownMethod",
    destroy.first[0] === "error" && destroy.first[1].type === JMAP_ERROR + "unknownMethod",
    JSON.stringify(destroy.first));
  var after = await jmap(reader, [["Email/query", { accountId: alice.id, filter: { inMailbox: "INBOX" } }, "c0"]]);
  count("and the mailbox still holds every message it held",
    sameJson(before.first[1].ids, after.first[1].ids),
    JSON.stringify(before.first[1].ids) + " then " + JSON.stringify(after.first[1].ids));
  count("the fixture put mail in that mailbox, so the comparison has something to compare",
    after.first[1].ids.indexOf(fixture.aliceMessage) !== -1, JSON.stringify(after.first[1].ids));

  var push = await jmap(reader, [["PushSubscription/set", {
    create: { p: { deviceClientId: "d1", url: "https://" + LOOPBACK + ":1/push", types: null } },
  }, "c0"]]);
  count("PushSubscription/set naming a callback url is answered unknownMethod",
    push.first[0] === "error" && push.first[1].type === JMAP_ERROR + "unknownMethod",
    JSON.stringify(push.first));
}

async function anotherAccountsIdentifiersAreRefusedLikeUnissuedOnes(reader, readerAsBob, alice, bob, fixture, log) {
  var sentBefore = log.count();

  var got = await jmap(reader, [["Email/get", { accountId: alice.id, ids: [fixture.bobMessage, NEVER_ISSUED] }, "c0"]]);
  count("Email/get lists none of the other account's messages",
    got.first[1].list.length === 0, JSON.stringify(got.first[1].list).slice(0, 200));
  count("and reports its identifier not found, beside one nobody holds",
    sameJson(got.first[1].notFound, [fixture.bobMessage, NEVER_ISSUED]), JSON.stringify(got.first[1].notFound));
  count("the Email/get answer carries none of that message", !leaksBob(got.body), got.body.slice(0, 300));

  var patches = [
    { label: "a keyword write", patch: { "keywords/$flagged": true } },
    { label: "a move into this account's Trash", patch: { mailboxIds: { Trash: true } } },
  ];
  for (var p = 0; p < patches.length; p += 1) {
    var update = {};
    update[fixture.bobMessage] = patches[p].patch;
    update[NEVER_ISSUED] = patches[p].patch;
    var set = await jmap(reader, [["Email/set", { accountId: alice.id, update: update }, "c0"]]);
    var notUpdated = set.first[1].notUpdated || {};
    count("Email/set " + patches[p].label + " on the other account's message is not updated",
      !Object.prototype.hasOwnProperty.call(set.first[1].updated || {}, fixture.bobMessage) &&
      Object.prototype.hasOwnProperty.call(notUpdated, fixture.bobMessage),
      JSON.stringify(set.first[1]));
    count("Email/set " + patches[p].label + " refuses it with the same SetError as an unissued id",
      sameJson(notUpdated[fixture.bobMessage], notUpdated[NEVER_ISSUED]), JSON.stringify(notUpdated));
  }

  var destroyed = await jmap(reader, [["Email/set", {
    accountId: alice.id, destroy: [fixture.bobMessage, fixture.bobHeld, NEVER_ISSUED],
  }, "c0"]]);
  var notDestroyed = destroyed.first[1].notDestroyed || {};
  count("Email/set destroys none of the other account's messages",
    Array.isArray(destroyed.first[1].destroyed) && destroyed.first[1].destroyed.length === 0,
    JSON.stringify(destroyed.first[1].destroyed));
  count("a message under the other account's legal hold is refused the same way as an ordinary one",
    sameJson(notDestroyed[fixture.bobHeld], notDestroyed[fixture.bobMessage]), JSON.stringify(notDestroyed));
  count("and both the same way as an identifier nobody holds, so a hold is not disclosed",
    sameJson(notDestroyed[fixture.bobMessage], notDestroyed[NEVER_ISSUED]) &&
    notDestroyed[NEVER_ISSUED] && notDestroyed[NEVER_ISSUED].type === "notFound",
    JSON.stringify(notDestroyed));

  var thread = await jmap(reader, [["Thread/get", { accountId: alice.id, ids: [fixture.bobMessage, NEVER_ISSUED] }, "c0"]]);
  count("Thread/get reports the other account's message and an unissued id both not found",
    thread.first[1].list.length === 0 &&
    sameJson(thread.first[1].notFound, [fixture.bobMessage, NEVER_ISSUED]), JSON.stringify(thread.first[1]));

  var mailboxes = await jmap(reader, [["Mailbox/get", { accountId: alice.id, ids: [fixture.bobInbox, "mbx_nobody"] }, "c0"]]);
  count("Mailbox/get reports the other account's store folder and a made-up one both not found",
    mailboxes.first[1].list.length === 0 &&
    sameJson(mailboxes.first[1].notFound, [fixture.bobInbox, "mbx_nobody"]), JSON.stringify(mailboxes.first[1]));

  var theirs = await jmap(reader, [["Email/query", { accountId: alice.id, filter: { inMailbox: fixture.bobInbox } }, "c0"]]);
  var madeUp = await jmap(reader, [["Email/query", { accountId: alice.id, filter: { inMailbox: "mbx_nobody" } }, "c0"]]);
  count("Email/query in the other account's store folder answers as a folder that does not exist",
    sameJson(theirs.first, madeUp.first) && theirs.first[1].ids.length === 0, JSON.stringify(theirs.first));

  var submitted = await jmap(reader, [["EmailSubmission/set", {
    accountId: alice.id,
    create: {
      theirs:  { identityId: alice.id, emailId: fixture.bobMessage },
      unknown: { identityId: alice.id, emailId: NEVER_ISSUED },
    },
  }, "c0"]]);
  var notCreated = submitted.first[1].notCreated || {};
  count("EmailSubmission/set naming the other account's message creates nothing",
    Object.keys(submitted.first[1].created || {}).length === 0, JSON.stringify(submitted.first[1].created));
  count("and refuses it with the same SetError as an unissued id",
    notCreated.theirs !== undefined && sameJson(notCreated.theirs, notCreated.unknown), JSON.stringify(notCreated));

  var asBob = await jmap(reader, [["EmailSubmission/set", {
    accountId: alice.id,
    create: {
      theirs:  { identityId: bob.id, emailId: fixture.draft },
      unknown: { identityId: NOBODY_ACCOUNT, emailId: fixture.draft },
    },
  }, "c0"]]);
  var identityRefusals = asBob.first[1].notCreated || {};
  count("EmailSubmission/set naming the other account's identity is refused identityNotFound, as an unknown one is",
    identityRefusals.theirs && identityRefusals.unknown &&
    identityRefusals.theirs.type === "identityNotFound" && identityRefusals.unknown.type === "identityNotFound",
    JSON.stringify(identityRefusals));
  count("nothing reached the outbound path", log.count() === sentBefore, log.count() + " after " + sentBefore);

  var bobsView = await jmap(readerAsBob, [["Email/get", { accountId: bob.id, ids: [fixture.bobMessage, fixture.bobHeld] }, "c0"]]);
  var bobsList = bobsView.first[1].list || [];
  count("the other account still holds both of its messages", bobsList.length === 2, JSON.stringify(bobsView.first[1].notFound));
  var ordinary = bobsList.filter(function (m) { return m.id === fixture.bobMessage; })[0];
  count("with no keyword written by the refused patch",
    ordinary && !Object.prototype.hasOwnProperty.call(ordinary.keywords || {}, "$flagged"), JSON.stringify(ordinary && ordinary.keywords));
  count("and still in its own inbox",
    ordinary && ordinary.mailboxIds && ordinary.mailboxIds.INBOX === true, JSON.stringify(ordinary && ordinary.mailboxIds));
}

// ---- limits ----------------------------------------------------------------

async function theSessionAdvertisesTheCoreLimits(reader) {
  var session = await reader.get("/jmap/session", { Accept: "application/json" });
  count("the session document answers", session.status === 200, session.status);
  var core = (JSON.parse(session.body).capabilities || {})["urn:ietf:params:jmap:core"] || {};
  var numeric = ["maxSizeUpload", "maxConcurrentUpload", "maxSizeRequest", "maxConcurrentRequests",
    "maxCallsInRequest", "maxObjectsInGet", "maxObjectsInSet"];
  for (var i = 0; i < numeric.length; i += 1) {
    count("the core capability advertises " + numeric[i] + " as a whole number",
      Number.isInteger(core[numeric[i]]) && core[numeric[i]] >= 0, JSON.stringify(core));
  }
  count("the core capability advertises collationAlgorithms as a list",
    Array.isArray(core.collationAlgorithms), JSON.stringify(core));
  count("the advertised request size is the body parser's JSON limit",
    core.maxSizeRequest === b.constants.BYTES.mib(1), String(core.maxSizeRequest));
  count("every limit a request is measured against is at least one",
    core.maxConcurrentRequests >= 1 && core.maxCallsInRequest >= 1 &&
    core.maxObjectsInGet >= 1 && core.maxObjectsInSet >= 1, JSON.stringify(core));
  return core;
}

function isMethodError(answer, type) {
  return answer[0] === "error" && answer[1] && answer[1].type === JMAP_ERROR + type;
}

async function theObjectLimitsAreEnforced(reader, alice, fixture, core, log) {
  var tooMany = ids(core.maxObjectsInGet + 1, "g");
  var getters = ["Email/get", "Mailbox/get", "Thread/get", "Identity/get"];
  for (var i = 0; i < getters.length; i += 1) {
    var over = await jmap(reader, [[getters[i], { accountId: alice.id, ids: tooMany }, "c0"]]);
    count(getters[i] + " naming maxObjectsInGet + 1 ids is refused requestTooLarge",
      isMethodError(over.first, "requestTooLarge"), JSON.stringify(over.first).slice(0, 200));
  }
  var atLimit = await jmap(reader, [["Email/get", { accountId: alice.id, ids: ids(core.maxObjectsInGet, "h") }, "c0"]]);
  count("Email/get naming exactly maxObjectsInGet ids is answered",
    atLimit.first[0] === "Email/get" && atLimit.first[1].notFound.length === core.maxObjectsInGet,
    JSON.stringify(atLimit.first).slice(0, 200));

  var updates = {};
  var overSet = ids(core.maxObjectsInSet + 1, "s");
  for (var u = 0; u < overSet.length; u += 1) updates[overSet[u]] = { "keywords/$seen": true };
  var tooLargeSet = await jmap(reader, [["Email/set", { accountId: alice.id, update: updates }, "c0"]]);
  count("Email/set updating maxObjectsInSet + 1 objects is refused requestTooLarge",
    isMethodError(tooLargeSet.first, "requestTooLarge"), JSON.stringify(tooLargeSet.first).slice(0, 200));

  var split = {};
  split[fixture.aliceMessage] = { "keywords/$flagged": true };
  var mixed = await jmap(reader, [["Email/set", {
    accountId: alice.id, update: split, destroy: ids(core.maxObjectsInSet, "d"),
  }, "c0"]]);
  count("Email/set is measured across update and destroy together",
    isMethodError(mixed.first, "requestTooLarge"), JSON.stringify(mixed.first).slice(0, 200));
  var flagged = await jmap(reader, [["Email/get", { accountId: alice.id, ids: [fixture.aliceMessage] }, "c0"]]);
  count("and the refused call wrote nothing, including the one update inside the limit",
    !Object.prototype.hasOwnProperty.call(flagged.first[1].list[0].keywords || {}, "$flagged"),
    JSON.stringify(flagged.first[1].list[0].keywords));

  var sentBefore = log.count();
  var creates = {};
  for (var c = 0; c <= core.maxObjectsInSet; c += 1) {
    creates["s" + c] = { identityId: alice.id, emailId: fixture.draft };
  }
  var tooManySends = await jmap(reader, [["EmailSubmission/set", { accountId: alice.id, create: creates }, "c0"]]);
  count("EmailSubmission/set creating maxObjectsInSet + 1 submissions is refused requestTooLarge",
    isMethodError(tooManySends.first, "requestTooLarge"), JSON.stringify(tooManySends.first).slice(0, 200));
  count("and nothing reached the outbound path", log.count() === sentBefore, log.count() + " after " + sentBefore);

  var shapes = [
    { label: "an id that is an object", args: { accountId: alice.id, ids: [{ id: 1 }] }, method: "Email/get" },
    { label: "an id that is null", args: { accountId: alice.id, ids: [null] }, method: "Thread/get" },
    { label: "ids that is a string", args: { accountId: alice.id, ids: "INBOX" }, method: "Mailbox/get" },
    { label: "no accountId", args: { ids: [] }, method: "Mailbox/get" },
    { label: "a destroy list naming a number", args: { accountId: alice.id, destroy: [7] }, method: "Email/set" },
  ];
  for (var s = 0; s < shapes.length; s += 1) {
    var shaped = await jmap(reader, [[shapes[s].method, shapes[s].args, "c0"]]);
    count(shapes[s].method + " given " + shapes[s].label + " is refused invalidArguments rather than serverFail",
      isMethodError(shaped.first, "invalidArguments"), JSON.stringify(shaped.first));
  }
}

async function problemOf(response) {
  var parsed;
  try { parsed = JSON.parse(response.body); } catch (_e) { parsed = null; }
  return {
    status:      response.status,
    contentType: String((response.headers && response.headers["content-type"]) || ""),
    doc:         parsed,
  };
}

function isProblem(found, type, status) {
  return found.status === status && found.contentType.indexOf("application/problem+json") === 0 &&
    found.doc !== null && found.doc.type === type && found.doc.status === status;
}

async function theCallLimitAndBackReferences(reader, alice, core) {
  var calls = [];
  for (var i = 0; i <= core.maxCallsInRequest; i += 1) {
    calls.push(["Mailbox/get", { accountId: alice.id, ids: [] }, "c" + i]);
  }
  var over = await problemOf(await reader.jmap(calls));
  count("a request carrying maxCallsInRequest + 1 calls is refused with the limit problem type",
    isProblem(over, PROBLEM_TYPES.limit, 400), JSON.stringify(over));
  count("and the problem names the limit it crossed",
    over.doc !== null && over.doc.limit === "maxCallsInRequest", JSON.stringify(over.doc));
  var atLimit = await reader.jmap(calls.slice(0, core.maxCallsInRequest));
  count("a request carrying exactly maxCallsInRequest calls is answered",
    atLimit.status === 200 && JSON.parse(atLimit.body).methodResponses.length === core.maxCallsInRequest,
    atLimit.status + " " + String(atLimit.body).slice(0, 120));

  var later = await jmap(reader, [
    ["Email/get", { accountId: alice.id, "#ids": { resultOf: "c1", name: "Email/query", path: "/ids" } }, "c0"],
    ["Email/query", { accountId: alice.id }, "c1"],
  ]);
  count("a back-reference to a later call is refused invalidResultReference",
    isMethodError(later.all[0], "invalidResultReference"), JSON.stringify(later.all[0]));
  count("and the later call is still answered", later.all[1][0] === "Email/query", JSON.stringify(later.all[1]).slice(0, 120));

  var nested = { "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/list" } };
  for (var d = 0; d < 12; d += 1) {
    nested = { "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/list", inner: nested } };
  }
  var deep = await problemOf(await reader.jmap([
    ["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"],
    ["Mailbox/get", Object.assign({ accountId: alice.id }, nested), "c1"],
  ]));
  count("a back-reference chain deeper than the guard allows is refused with the limit problem type",
    isProblem(deep, PROBLEM_TYPES.limit, 400), JSON.stringify(deep));

  var wildcard = await jmap(reader, [
    ["Mailbox/get", { accountId: alice.id }, "c0"],
    ["Email/get", { accountId: alice.id, "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/list/*/id" } }, "c1"],
  ]);
  count("a wildcard back-reference path is answered without a server failure",
    !isMethodError(wildcard.all[1], "serverFail"), JSON.stringify(wildcard.all[1]).slice(0, 200));
}

async function aBodyThatIsNotAJmapRequestIsRefused(reader, alice) {
  var valid = JSON.stringify({
    using: browser.DEFAULT_JMAP_USING.slice(),
    methodCalls: [["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"]],
  });
  var accept = { Accept: "application/json" };
  var typed = [
    { label: "a valid request sent as text/plain", type: "text/plain", body: valid, problem: "notJSON" },
    { label: "a form body", type: "application/x-www-form-urlencoded", body: "using=a&methodCalls=b", problem: "notJSON" },
    { label: "an empty JSON body", type: "application/json", body: "", problem: "notJSON" },
    { label: "a JSON array", type: "application/json", body: "[]", problem: "notRequest" },
    { label: "a request with no using", type: "application/json",
      body: JSON.stringify({ methodCalls: [["Mailbox/get", {}, "c0"]] }), problem: "notRequest" },
    { label: "a request whose methodCalls is an object", type: "application/json",
      body: JSON.stringify({ using: browser.DEFAULT_JMAP_USING.slice(), methodCalls: {} }), problem: "notRequest" },
    { label: "a capability this server does not advertise", type: "application/json",
      body: JSON.stringify({ using: ["urn:ietf:params:jmap:core", "urn:example:nope"],
        methodCalls: [["Mailbox/get", {}, "c0"]] }), problem: "unknownCapability" },
  ];
  for (var i = 0; i < typed.length; i += 1) {
    var found = await problemOf(await reader.post("/jmap/api", typed[i].type, typed[i].body, accept));
    count(typed[i].label + " is refused with the " + typed[i].problem + " problem type",
      isProblem(found, PROBLEM_TYPES[typed[i].problem], 400), JSON.stringify(found));
  }

  // Bodies the framework body parser refuses before the route runs. The
  // answer is a client error and it arrives.
  var deep = "";
  for (var d = 0; d < 2000; d += 1) deep += "[";
  for (d = 0; d < 2000; d += 1) deep += "]";
  var parserRefused = [
    { label: "a body that is not JSON", body: "not json at all" },
    { label: "a body that stops parsing part way", body: "{\"using\":" },
    { label: "JSON nested two thousand levels", body: "{\"using\":" + deep + "}" },
    { label: "a body one byte over maxSizeRequest",
      body: JSON.stringify({ using: [], pad: "x".repeat(b.constants.BYTES.mib(1)) }) },
  ];
  for (var p = 0; p < parserRefused.length; p += 1) {
    var refused = await reader.post("/jmap/api", "application/json", parserRefused[p].body, accept);
    count(parserRefused[p].label + " is answered with a client error rather than a server error",
      refused.status >= 400 && refused.status < 500, refused.status + " " + String(refused.body).slice(0, 160));
  }

  var unknown = await jmap(reader, [["Nope/get", { accountId: alice.id }, "c0"]]);
  count("a method this server does not know is answered unknownMethod inside a 200",
    unknown.status === 200 && isMethodError(unknown.first, "unknownMethod"), JSON.stringify(unknown.first));

  var afterwards = await jmap(reader, [["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"]]);
  count("the account's next request is answered after every refusal above",
    afterwards.status === 200 && afterwards.first[0] === "Mailbox/get", afterwards.status);
}

// ---- the submission envelope ------------------------------------------------

async function submit(reader, alice, fixture, envelope) {
  var creation = { identityId: alice.id, emailId: fixture.draft };
  if (envelope !== undefined) creation.envelope = envelope;
  var answer = await jmap(reader, [["EmailSubmission/set", { accountId: alice.id, create: { s: creation } }, "c0"]]);
  return {
    created: (answer.first[1].created || {}).s || null,
    refused: (answer.first[1].notCreated || {}).s || null,
    first:   answer.first,
  };
}

function address(email) { return { email: email, parameters: null }; }

async function theSubmissionEnvelopeIsBoundToTheAccount(reader, alice, fixture, log) {
  var refusedSenders = [
    { label: "an address at a domain this server does not host", email: "stranger@peer.example" },
    { label: "another account's address on this server", email: BOB },
    { label: "a string that is not an address", email: "not an address" },
  ];
  for (var i = 0; i < refusedSenders.length; i += 1) {
    var before = log.count();
    var result = await submit(reader, alice, fixture, {
      mailFrom: address(refusedSenders[i].email), rcptTo: [address(DRAFT_TO), address(DRAFT_CC)],
    });
    count("an envelope MAIL FROM naming " + refusedSenders[i].label + " is refused forbiddenMailFrom",
      result.created === null && result.refused !== null && result.refused.type === "forbiddenMailFrom",
      JSON.stringify(result.first[1]));
    count("and nothing reached the outbound path for " + refusedSenders[i].label,
      log.count() === before, log.count() + " after " + before);
  }

  var beforeParams = log.count();
  var withParams = await submit(reader, alice, fixture, {
    mailFrom: { email: ALICE, parameters: { SIZE: "1000" } }, rcptTo: [address(DRAFT_TO), address(DRAFT_CC)],
  });
  count("an envelope carrying SMTP parameters this server does not apply is refused invalidProperties",
    withParams.refused !== null && withParams.refused.type === "invalidProperties", JSON.stringify(withParams.first[1]));
  count("and nothing reached the outbound path for it", log.count() === beforeParams, String(log.count()));

  var derived = await submit(reader, alice, fixture, undefined);
  count("a submission with no envelope is created", derived.created !== null, JSON.stringify(derived.first[1]));
  var out = log.last();
  count("its envelope sender is the account's own address", out !== null && out.from === ALICE, out && out.from);
  count("its recipients are the draft's To and Cc addresses",
    out !== null && out.to.slice().sort().join(",") === [DRAFT_TO, DRAFT_CC].sort().join(","),
    out && JSON.stringify(out.to));
  count("and the message it sends carries the draft's Cc field",
    out !== null && headerOf(out.rfc822, "cc").indexOf(DRAFT_CC) !== -1, out && headerOf(out.rfc822, "cc"));

  var explicit = await submit(reader, alice, fixture, {
    mailFrom: address(ALICE_ALIAS),
    rcptTo:   [address(DRAFT_TO), address(DRAFT_CC), address(BLIND)],
  });
  count("an envelope naming an alias the account holds and a blind recipient is created",
    explicit.created !== null, JSON.stringify(explicit.first[1]));
  out = log.last();
  count("the envelope sender is the alias the envelope named", out !== null && out.from === ALICE_ALIAS, out && out.from);
  count("the recipients are exactly the envelope's rcptTo",
    out !== null && out.to.slice().sort().join(",") === [DRAFT_CC, BLIND, DRAFT_TO].sort().join(","),
    out && JSON.stringify(out.to));
  count("and the blind recipient appears nowhere in the message that leaves",
    out !== null && out.rfc822.indexOf(BLIND) === -1, out && out.rfc822.slice(0, 300));

  var shapes = [
    { label: "an rcptTo leaving out the draft's Cc recipient", type: "invalidProperties",
      envelope: { mailFrom: address(ALICE), rcptTo: [address(DRAFT_TO)] } },
    { label: "an empty rcptTo", type: "noRecipients",
      envelope: { mailFrom: address(ALICE), rcptTo: [] } },
    { label: "an rcptTo naming something that is not an address", type: "invalidRecipients",
      envelope: { mailFrom: address(ALICE), rcptTo: [address(DRAFT_TO), address(DRAFT_CC), address("nope")] } },
    { label: "an rcptTo over the recipient ceiling", type: "tooManyRecipients",
      envelope: { mailFrom: address(ALICE), rcptTo: (function () {
        var list = [address(DRAFT_TO), address(DRAFT_CC)];
        for (var r = 0; r < 100; r += 1) list.push(address("r" + r + "@peer.example"));
        return list;
      }()) } },
    { label: "an envelope that is not an object", type: "invalidProperties", envelope: "alice" },
  ];
  for (var s = 0; s < shapes.length; s += 1) {
    var beforeShape = log.count();
    var shaped = await submit(reader, alice, fixture, shapes[s].envelope);
    count(shapes[s].label + " is refused " + shapes[s].type,
      shaped.created === null && shaped.refused !== null && shaped.refused.type === shapes[s].type,
      JSON.stringify(shaped.first[1]));
    count("and nothing reached the outbound path for " + shapes[s].label,
      log.count() === beforeShape, log.count() + " after " + beforeShape);
  }

  var lifecycle = await jmap(reader, [["EmailSubmission/set", {
    accountId: alice.id, update: { sub1: { undoStatus: "canceled" } }, destroy: ["sub2"],
  }, "c0"]]);
  var answer = lifecycle.first[1];
  count("an update naming a submission this server does not keep is reported not updated",
    answer.notUpdated && answer.notUpdated.sub1 && answer.notUpdated.sub1.type === "notFound", JSON.stringify(answer));
  count("a destroy naming one is reported not destroyed",
    answer.notDestroyed && answer.notDestroyed.sub2 && answer.notDestroyed.sub2.type === "notFound", JSON.stringify(answer));

  await b.audit.flush();
  var rows = await b.audit.query({ action: "blamepost.web.author_not_permitted", limit: 50, order: "desc" });
  var surfaces = (Array.isArray(rows) ? rows : []).map(function (row) {
    return String(helpers.metadataOf(row).surface || "");
  });
  count("a refused envelope sender leaves an audit row naming the envelope surface",
    surfaces.indexOf("jmap-submission-envelope") !== -1, JSON.stringify(surfaces));
}

// ---- concurrency ------------------------------------------------------------

async function concurrentRequestsBeyondTheLimitAreRefused(reader, readerAsBob, alice, bob, fixture, core, log) {
  log.hold();
  var inFlight = [];
  try {
    for (var i = 0; i < core.maxConcurrentRequests; i += 1) {
      inFlight.push(reader.jmap([["EmailSubmission/set", {
        accountId: alice.id, create: { s: { identityId: alice.id, emailId: fixture.draft } },
      }, "c0"]]));
    }
    await helpers.waitUntil(function () { return log.held() === core.maxConcurrentRequests; }, {
      timeoutMs: 15000,
      label:     "jmap-authorization: maxConcurrentRequests submissions are in flight",
    });
    var over = await problemOf(await reader.jmap([["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"]]));
    count("a request past maxConcurrentRequests for one account is refused with the limit problem type",
      isProblem(over, PROBLEM_TYPES.limit, 400), JSON.stringify(over));
    count("and the problem names maxConcurrentRequests",
      over.doc !== null && over.doc.limit === "maxConcurrentRequests", JSON.stringify(over.doc));
    var other = await jmap(readerAsBob, [["Mailbox/get", { accountId: bob.id, ids: [] }, "c0"]]);
    count("another account's request is answered while the first account is at its limit",
      other.status === 200 && other.first[0] === "Mailbox/get", other.status);
  } finally {
    log.release();
  }
  var settled = await Promise.all(inFlight);
  count("every submission that was in flight is answered once the outbound path moves",
    settled.every(function (response) {
      var first = browser.answer(response, 0);
      return response.status === 200 && first[1].created && first[1].created.s;
    }), settled.map(function (response) { return response.status; }).join(","));
  var after = await jmap(reader, [["Mailbox/get", { accountId: alice.id, ids: [] }, "c0"]]);
  count("the account is answered again once its requests have finished",
    after.status === 200 && after.first[0] === "Mailbox/get", after.status);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("jmapauthz");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var log = null;

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
    var bob   = await identity.accounts.create({ address: BOB, password: BOB_PASSWORD });
    await identity.aliases.add({ address: ALICE_ALIAS, destination: ALICE });

    var bobMessage = identity.mailbox.appendMessage("INBOX", message([
      "Message-ID: <bob-private@peer.example>", "From: Dana Reyes <dana@peer.example>",
      "To: <" + BOB + ">", "Subject: " + BOB_SUBJECT, "Date: Sat, 22 Aug 2026 09:00:00 +0000",
      "", BOB_BODY]), { actor: { id: bob.id } });
    var bobHeld = identity.mailbox.appendMessage("INBOX", message([
      "Message-ID: <bob-held@peer.example>", "From: Dana Reyes <dana@peer.example>",
      "To: <" + BOB + ">", "Subject: held for bob", "Date: Sat, 22 Aug 2026 09:30:00 +0000",
      "", "kept under a hold"]), { actor: { id: bob.id } });
    identity.messageStore.setLegalHold([bobHeld.objectid], { hold: true });
    var aliceMessage = identity.mailbox.appendMessage("INBOX", message([
      "Message-ID: <alice-own@peer.example>", "From: Dana Reyes <dana@peer.example>",
      "To: <" + ALICE + ">", "Subject: Alices own message", "Date: Sat, 22 Aug 2026 10:00:00 +0000",
      "", "alice body"]), { actor: { id: alice.id } });
    var draft = identity.mailbox.appendMessage("Drafts", message([
      "Message-ID: <alice-draft@" + DOMAIN + ">", "From: <" + ALICE + ">",
      "To: <" + DRAFT_TO + ">", "Cc: <" + DRAFT_CC + ">", "Subject: envelope draft",
      "Date: Sat, 22 Aug 2026 10:30:00 +0000", "", "draft body"]),
      { actor: { id: alice.id }, flags: ["\\Draft"] });
    var bobInbox = identity.mailbox.accountFolders({ id: bob.id })
      .filter(function (folder) { return folder.name === "INBOX"; })[0].storeName;

    var fixture = {
      bobMessage:   bobMessage.objectid,
      bobHeld:      bobHeld.objectid,
      bobInbox:     bobInbox,
      aliceMessage: aliceMessage.objectid,
      draft:        draft.objectid,
    };
    count("the fixture's messages were all stored",
      [fixture.bobMessage, fixture.bobHeld, fixture.aliceMessage, fixture.draft].every(function (id) {
        return typeof id === "string" && id.indexOf("obj_") === 0;
      }), JSON.stringify(fixture));

    log = recorder();
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
    count("the first account signs in", landed.status === 302, landed.status);
    var readerAsBob = browser.browserAt(origin, { timeoutMs: READER_TIMEOUT_MS });
    var bobLanded = await readerAsBob.signIn(BOB, BOB_PASSWORD);
    count("the second account signs in", bobLanded.status === 302, bobLanded.status);

    await aForeignAccountIdIsRefusedLikeOneNobodyHolds(reader, bob, fixture, log);
    await unservedMethodsAnswerTheSameForEitherAccount(reader, alice, bob, fixture);
    await anotherAccountsIdentifiersAreRefusedLikeUnissuedOnes(reader, readerAsBob, alice, bob, fixture, log);

    var core = await theSessionAdvertisesTheCoreLimits(reader);
    await theObjectLimitsAreEnforced(reader, alice, fixture, core, log);
    await theCallLimitAndBackReferences(reader, alice, core);
    await aBodyThatIsNotAJmapRequestIsRefused(reader, alice);
    await theSubmissionEnvelopeIsBoundToTheAccount(reader, alice, fixture, log);
    await concurrentRequestsBeyondTheLimitAreRefused(reader, readerAsBob, alice, bob, fixture, core, log);

    return helpers.getChecks();
  } finally {
    if (log !== null) log.release();
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

module.exports = { name: "jmap-authorization", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
