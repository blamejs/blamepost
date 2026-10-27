// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The domain-scoped sending credential registry, driven on a real
 * encrypted store with two hosted domains.
 *
 * Two domains rather than one, because a scope bug cannot appear on a
 * server that hosts a single domain: every answer is right there
 * whether the scope was read or guessed. Every vector below that says
 * anything about scope names one domain and checks the other.
 *
 * Run standalone: node test/layer-1-state/sending-credential-registry.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var auditActor = require("../../lib/store/actor");

var credentials = require("../../lib/store/credentials");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALPHA = "alpha.example";
var ZULU  = "zulu.example";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// Assert a call refuses under one stable code. Both halves matter: a
// refusal under the wrong code is a contract change a caller branching
// on the code would not survive.
async function refuses(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label,
    thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

// The same assertion plus the fragments the message has to carry, for
// the refusals whose whole job is to tell an operator what to do next.
async function refusesNaming(label, code, needles, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  var message = thrown === null ? "" : String(thrown.message);
  var missing = needles.filter(function (n) { return message.indexOf(n) === -1; });
  count(label,
    thrown !== null && thrown.code === code && missing.length === 0,
    thrown === null ? "nothing was thrown"
      : thrown.code + " missing " + JSON.stringify(missing) + " in: " + message);
}

// A clock the ceiling window is measured on, moved by the test rather
// than by waiting. It stands in for the module's own steady clock, which
// is the same kind of function the framework's cache and lockout
// primitives take, so the code under test is the shipped code with a
// different time source rather than a branch written for the suite.
function movableClock(startMs) {
  var at = startMs;
  var fn = function () { return at; };
  fn.advance = function (ms) { at += ms; };
  return fn;
}

// ---------------------------------------------------------------------------

async function seedTwoDomains(handle) {
  await handle.domains.add({ domain: ALPHA });
  await handle.domains.add({ domain: ZULU });

  // One operator-role mailbox per domain, plus an ordinary one. The
  // operator-role local part is what the default refusal list has to
  // pick up, and it differs between the two domains so a list built for
  // one cannot pass for the other.
  await handle.accounts.create({
    address: "root@" + ALPHA, password: ACCOUNT_PASSWORD, isAdmin: true });
  await handle.accounts.create({
    address: "bounces@" + ALPHA, password: ACCOUNT_PASSWORD });
  await handle.accounts.create({
    address: "ops@" + ZULU, password: ACCOUNT_PASSWORD, isAdmin: true });
  await handle.accounts.create({
    address: "bounces@" + ZULU, password: ACCOUNT_PASSWORD });
}

function registryFor(handle, clock) {
  return credentials.create({
    domains:  handle.domains,
    accounts: handle.accounts,
    aliases:  handle.aliases,
    resolve:  handle.resolve,
    clock:    clock,
  });
}

// ---- creation ----

async function testCreationRefusals(reg) {
  await refuses("creating a credential without an options object refuses",
    "store/bad-argument", function () { return reg.create(); });

  await refuses("a credential for a domain this server does not host refuses",
    "store/no-such-domain", function () {
      return reg.create({
        domain: "not-hosted.example", bounceMailbox: "bounces@" + ALPHA,
        reason: "operator asked for it" });
    });

  await refusesNaming("a bounce mailbox with no account refuses, and the refusal names the address",
    "store/no-such-account", ["missing@" + ALPHA], function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "missing@" + ALPHA,
        reason: "operator asked for it" });
    });

  await refuses("a credential created without a reason refuses",
    "store/bad-argument", function () {
      return reg.create({ domain: ALPHA, bounceMailbox: "bounces@" + ALPHA });
    });

  await refuses("a credential created with no bounce mailbox at all refuses",
    "store/bad-argument", function () {
      return reg.create({ domain: ALPHA, reason: "operator asked for it" });
    });

  await refuses("a ceiling written as a fraction refuses",
    "store/bad-argument", function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "operator asked for it", maxRecipients: 10.5 });
    });

  await refuses("a ceiling written as a negative number refuses",
    "store/bad-argument", function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "operator asked for it", maxMessages: -1 });
    });
}

async function testCreationShape(reg, handle) {
  var made = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "bounces@" + ALPHA,
    reason:        "the shop front sends receipts",
  });

  count("a created credential names the domain it is scoped to",
    made.domain === ALPHA, made.domain);
  count("a created credential hands back the token exactly once",
    typeof made.token === "string" && made.token.length > 0);
  count("the token carries the blamepost prefix and the sending namespace",
    made.token.indexOf(credentials.TOKEN_PREFIX + "_" + credentials.TOKEN_NAMESPACE + "_") === 0,
    made.token.replace(/[0-9a-f]/g, "x"));
  count("the token is four underscore-separated parts, so a scanner pattern can pin it",
    made.token.split("_").length === 4, made.token.replace(/[0-9a-f]/g, "x"));
  count("the token's id and secret halves are hex",
    /^[a-z]+_[a-z]+_[0-9a-f]{16}_[0-9a-f]{64}$/.test(made.token),
    made.token.replace(/[0-9a-f]/g, "x"));

  count("the credential names the bounce mailbox it was created against",
    made.bounceMailbox === "bounces@" + ALPHA, made.bounceMailbox);
  count("the credential expires by default rather than living forever",
    typeof made.expiresAt === "number" && made.expiresAt > Date.now(), String(made.expiresAt));

  // The registry must not be a way to read a secret back.
  var shown = await reg.show(made.id);
  count("show never returns the secret",
    JSON.stringify(shown).indexOf(made.token.split("_")[3]) === -1);
  count("show never carries a field named secret or token",
    Object.keys(shown).every(function (k) {
      return k !== "secret" && k !== "token" && k !== "secretHash";
    }), Object.keys(shown).join(", "));

  var listed = await reg.list({ domain: ALPHA });
  count("list never returns the secret",
    JSON.stringify(listed).indexOf(made.token.split("_")[3]) === -1);

  var raw = b.db.from("_blamejs_api_keys").where({ id: "send:" + made.id }).first();
  count("the row on the volume holds no copy of the secret",
    raw !== null && raw !== undefined &&
    JSON.stringify(raw).indexOf(made.token.split("_")[3]) === -1);

  return made;
}

// ---- the refusal list ----

async function testRefusalList(reg, handle) {
  var made = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "bounces@" + ALPHA,
    reason:        "checking what the list starts as",
  });

  var list = made.refusedLocalParts;
  count("the default refusal list holds postmaster", list.indexOf("postmaster") !== -1, list.join(","));
  count("the default refusal list holds abuse", list.indexOf("abuse") !== -1, list.join(","));
  count("the default refusal list holds the operator-role mailbox in that domain",
    list.indexOf("root") !== -1, list.join(","));
  count("the default refusal list does not hold the other domain's operator mailbox",
    list.indexOf("ops") === -1, list.join(","));
  count("the default refusal list does not hold an ordinary mailbox",
    list.indexOf("bounces") === -1, list.join(","));

  var zuluMade = await reg.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "the other domain's list is derived from its own accounts",
  });
  count("the other domain's default list holds its own operator mailbox",
    zuluMade.refusedLocalParts.indexOf("ops") !== -1, zuluMade.refusedLocalParts.join(","));
  count("and not the first domain's",
    zuluMade.refusedLocalParts.indexOf("root") === -1, zuluMade.refusedLocalParts.join(","));

  await refuses("emptying the refusal list without a reason refuses",
    "store/bad-argument", function () {
      return reg.setRefusedLocalParts({ id: made.id, localParts: [] });
    });

  await refuses("setting the refusal list to something that is not an array refuses",
    "store/bad-argument", function () {
      return reg.setRefusedLocalParts({
        id: made.id, localParts: "postmaster", reason: "typed it as a string" });
    });

  var capture = helpers.auditCapture();
  var emptied;
  try {
    emptied = await reg.setRefusedLocalParts({
      id:         made.id,
      localParts: [],
      reason:     "this credential sends the postmaster notices itself",
    });
  } finally { capture.release(); }

  count("an emptied refusal list comes back empty rather than absent",
    Array.isArray(emptied.refusedLocalParts) && emptied.refusedLocalParts.length === 0,
    JSON.stringify(emptied.refusedLocalParts));
  count("the credential still verifies after the list was emptied through the registry",
    (await reg.verify(made.token)).ok === true);

  var rows = capture.forAction("domain.sending_credential_refusals_set");
  count("blamepost.store.credentials.setRefusedLocalParts writes a row",
    rows.length === 1, String(rows.length));
  count("and the row names what was taken off the list",
    rows.length === 1 &&
      JSON.stringify(helpers.metadataOf(rows[0])).indexOf("postmaster") !== -1,
    rows.length === 1 ? JSON.stringify(helpers.metadataOf(rows[0])) : "no row");

  return { alpha: made, zulu: zuluMade };
}

// ---- scope, and what happens when the row is edited behind the registry ----

async function testScopeIsReadFromTheStore(reg, pair) {
  var alphaVerdict = await reg.verify(pair.alpha.token);
  var zuluVerdict  = await reg.verify(pair.zulu.token);

  count("a credential scoped to the first domain verifies as that domain",
    alphaVerdict.ok === true && alphaVerdict.domain === ALPHA,
    JSON.stringify(alphaVerdict));
  count("a credential scoped to the second domain verifies as that domain",
    zuluVerdict.ok === true && zuluVerdict.domain === ZULU,
    JSON.stringify(zuluVerdict));
  count("the verdict carries the bounce mailbox the credential was created against",
    zuluVerdict.bounceMailbox === "bounces@" + ZULU, zuluVerdict.bounceMailbox);
  count("the verdict carries the refusal list rather than leaving the caller to look it up",
    Array.isArray(zuluVerdict.refusedLocalParts), JSON.stringify(zuluVerdict.refusedLocalParts));
  count("a verdict never carries the secret",
    JSON.stringify(alphaVerdict).indexOf(pair.alpha.token.split("_")[3]) === -1);

  count("a token that is not one of ours is refused without a store read",
    (await reg.verify("bk_live_deadbeefdeadbeef_" + "0".repeat(64))).reason === "bad-token");
  count("a token with the right prefix and a wrong secret is refused",
    (await reg.verify(
      pair.alpha.token.slice(0, pair.alpha.token.lastIndexOf("_") + 1) + "0".repeat(64)
    )).reason === "bad-credentials");
  count("an empty token is refused rather than throwing",
    (await reg.verify("")).ok === false);
  count("a token that is not a string is refused rather than throwing",
    (await reg.verify(null)).ok === false);
}

// The vector the whole binding exists for. The sealed scope column is
// relocatable between rows on this table, so a credential's scope is
// pinned by a keyed digest over the row's own identity as well. Lifting
// one credential's scope onto another's row has to stop that credential
// verifying rather than hand it the wrong domain.
async function testALiftedScopeRefuses(reg, pair) {
  // A credential of its own rather than one the rest of the run shares,
  // because the point of the vector is to leave a row damaged and see
  // what the registry then says about it.
  var victim = await reg.create({
    domain: ZULU, bounceMailbox: "bounces@" + ZULU,
    reason: "checking that a scope cannot be lifted between rows" });

  var before = await reg.verify(victim.token);
  count("blamepost.store.credentials.verify names the credential's own domain before " +
    "anything is moved",
    before.ok === true && before.domain === ZULU, JSON.stringify(before));

  var alphaRow = b.db.prepare(
    "SELECT ownerId, ownerIdHash FROM _blamejs_api_keys WHERE id = ?")
    .all("send:" + pair.alpha.id)[0];
  count("the donor row's scope is sealed on the volume rather than stored as a name",
    typeof alphaRow.ownerId === "string" && alphaRow.ownerId.indexOf(ALPHA) === -1,
    String(alphaRow.ownerId).slice(0, 24));

  b.db.prepare("UPDATE _blamejs_api_keys SET ownerId = ?, ownerIdHash = ? WHERE id = ?")
    .run(alphaRow.ownerId, alphaRow.ownerIdHash, "send:" + victim.id);

  var after = await reg.verify(victim.token);
  count("a credential whose scope was lifted from another row is refused",
    after.ok === false, JSON.stringify(after));
  count("and the refusal names no domain rather than the one that was lifted in",
    after.reason === "binding-mismatch" && after.domain === null, JSON.stringify(after));
  count("and it carries none of the policy the lifted row would have supplied",
    after.bounceMailbox === null && after.refusedLocalParts === null &&
    after.maxRecipients === null, JSON.stringify(after));

  // A damaged credential is still something an operator has to clean up,
  // so the verbs that do that have to work on it and the row they file
  // has to name something.
  var shown = await reg.show(victim.id);
  count("blamepost.store.credentials.show reports the broken binding rather than hiding it",
    shown !== null && shown.bindingHolds === false, JSON.stringify(shown));
  count("and it shows which domain the damaged row now claims",
    shown.storedDomain === ALPHA && shown.domain === null,
    shown.storedDomain + "/" + shown.domain);

  var capture = helpers.auditCapture();
  try {
    await reg.remove({
      id: victim.id, destroy: true, reason: "the row was tampered with" });
  } finally { capture.release(); }
  var rows = capture.forAction("domain.sending_credential_removed");
  count("removing a damaged credential files a row that names a domain",
    rows.length === 1 && rows[0].resourceId === ALPHA,
    rows.length === 1 ? String(rows[0].resourceId) : "no row");
  count("and the row says the binding did not hold",
    rows.length === 1 && helpers.metadataOf(rows[0]).bindingHolds === false,
    rows.length === 1 ? JSON.stringify(helpers.metadataOf(rows[0])) : "no row");
  count("and the damaged credential is gone", (await reg.show(victim.id)) === null);
}

// The other half of the same invariant: the refusal list is part of what
// the binding covers, so widening it behind the registry stops the
// credential rather than reading as a shorter list.
async function testAWidenedRefusalListRefuses(reg) {
  var made = await reg.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking that the list cannot be widened behind the registry",
  });
  count("it verifies before the row is edited", (await reg.verify(made.token)).ok === true);

  var rowId = "send:" + made.id;
  var current = b.db.from("_blamejs_api_keys").where({ id: rowId }).first();
  var meta = JSON.parse(current.metadata);
  count("the stored record holds the refusal list",
    Array.isArray(meta.refusedLocalParts) && meta.refusedLocalParts.length > 0,
    JSON.stringify(meta.refusedLocalParts));

  meta.refusedLocalParts = [];
  b.db.from("_blamejs_api_keys").where({ id: rowId })
    .updateOne({ metadata: JSON.stringify(meta) });

  var after = await reg.verify(made.token);
  count("a credential whose refusal list was emptied on the volume is refused",
    after.ok === false && after.reason === "binding-mismatch", JSON.stringify(after));
  count("and it is refused rather than verifying against an empty list",
    after.refusedLocalParts === null, JSON.stringify(after.refusedLocalParts));

  // Metadata that cannot be read at all must land in the same place: a
  // record nothing can parse is not a credential with no restrictions.
  var other = await reg.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking that unreadable storage refuses rather than opening up",
  });
  b.db.from("_blamejs_api_keys").where({ id: "send:" + other.id })
    .updateOne({ metadata: "{not json" });
  var unreadable = await reg.verify(other.token);
  count("a credential whose stored record cannot be read is refused",
    unreadable.ok === false, JSON.stringify(unreadable));
  count("and the refusal is not an empty refusal list",
    unreadable.refusedLocalParts === null, JSON.stringify(unreadable));

  // Replacing the list through the registry is refused too, because the
  // record the new list would be built on top of is the one nothing can
  // read.
  await refuses("blamepost.store.credentials.setRefusedLocalParts refuses a credential whose " +
    "stored record cannot be read",
    "store/no-such-sending-credential", function () {
      return reg.setRefusedLocalParts({
        id: other.id, localParts: ["postmaster"], reason: "trying to repair it in place" });
    });

  // The bounce mailbox is under the same digest. Redirecting it on the
  // volume would send every bounce a domain produces to a mailbox the
  // operator did not name, and bounces carry the recipients that
  // rejected the mail.
  var redirected = await reg.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking that the bounce mailbox cannot be redirected on the volume",
  });
  var redirectedRow = "send:" + redirected.id;
  var redirectedMeta = JSON.parse(
    b.db.from("_blamejs_api_keys").where({ id: redirectedRow }).first().metadata);
  redirectedMeta.bounceMailbox = "ops@" + ZULU;
  b.db.from("_blamejs_api_keys").where({ id: redirectedRow })
    .updateOne({ metadata: JSON.stringify(redirectedMeta) });

  var moved = await reg.verify(redirected.token);
  count("a credential whose bounce mailbox was redirected on the volume is refused",
    moved.ok === false && moved.reason === "binding-mismatch", JSON.stringify(moved));
  count("and it does not hand back the mailbox that was written in",
    moved.bounceMailbox === null, JSON.stringify(moved.bounceMailbox));

  // The ceilings are under it too, so raising them on the volume stops
  // the credential rather than widening what it may send.
  var raised = await reg.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking that a ceiling cannot be raised on the volume",
    maxRecipients: 5,
  });
  var raisedRow = "send:" + raised.id;
  var raisedMeta = JSON.parse(
    b.db.from("_blamejs_api_keys").where({ id: raisedRow }).first().metadata);
  raisedMeta.maxRecipients = 1000000;
  b.db.from("_blamejs_api_keys").where({ id: raisedRow })
    .updateOne({ metadata: JSON.stringify(raisedMeta) });

  var widened = await reg.verify(raised.token);
  count("a credential whose recipient ceiling was raised on the volume is refused",
    widened.ok === false && widened.reason === "binding-mismatch", JSON.stringify(widened));
  await refuses("and its counters refuse rather than measuring against the raised ceiling",
    "store/no-such-sending-credential", function () {
      return reg.counters.record({ id: raised.id, recipients: 1 });
    });

  // Every damaged credential goes, so the listing further down reads a
  // volume where every row is one this registry wrote.
  await reg.remove({ id: made.id, destroy: true, reason: "the row was tampered with" });
  await reg.remove({ id: other.id, destroy: true, reason: "the row was tampered with" });
  await reg.remove({ id: redirected.id, destroy: true, reason: "the row was tampered with" });
  await reg.remove({ id: raised.id, destroy: true, reason: "the row was tampered with" });
}

// ---- the lifecycle a leaked credential goes through ----

async function testRotation(reg) {
  var made = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "checking what rotation does to the prior token" });

  await refuses("rotating without a reason refuses",
    "store/bad-argument", function () { return reg.rotate({ id: made.id }); });

  var rotated = await reg.rotate({ id: made.id, reason: "the token reached a public repository" });
  count("rotation hands back a new token", typeof rotated.token === "string" &&
    rotated.token !== made.token);
  count("rotation keeps the credential's identifier", rotated.id === made.id);
  count("rotation defaults to no grace at all", rotated.graceMs === 0, String(rotated.graceMs));
  count("rotation never hands back the stored digest",
    Object.keys(rotated).every(function (k) { return k !== "secretHash"; }),
    Object.keys(rotated).join(", "));

  count("the prior token stops working the moment a default rotation lands",
    (await reg.verify(made.token)).ok === false);
  count("and the new token works", (await reg.verify(rotated.token)).ok === true);
  count("and it still names the same domain",
    (await reg.verify(rotated.token)).domain === ALPHA);

  await refuses("a grace window that is not a whole number of milliseconds refuses",
    "store/bad-argument", function () {
      return reg.rotate({ id: made.id, reason: "scheduled", graceMs: 1.5 });
    });
  await refuses("a grace window longer than the ceiling refuses",
    "store/bad-argument", function () {
      return reg.rotate({
        id: made.id, reason: "scheduled", graceMs: credentials.MAX_GRACE_MS + 1 });
    });

  var graceful = await reg.rotate({
    id: made.id, reason: "scheduled migration", graceMs: b.constants.TIME.hours(1) });
  count("a named grace window is the one that was named, not the framework's default",
    graceful.graceMs === b.constants.TIME.hours(1), String(graceful.graceMs));
  count("the prior token keeps working inside a named grace window",
    (await reg.verify(rotated.token)).ok === true);
  count("and the verdict says the prior secret was the one that matched",
    (await reg.verify(rotated.token)).usedPriorSecret === true);
  count("the new token works and does not report a prior secret",
    (await reg.verify(graceful.token)).usedPriorSecret === false);

  return graceful;
}

async function testRevokeAndRemove(reg) {
  var made = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "checking revoke and remove" });

  await refuses("revoking without a reason refuses",
    "store/bad-argument", function () { return reg.revoke({ id: made.id }); });
  await refuses("revoking a credential that does not exist refuses",
    "store/no-such-sending-credential", function () {
      return reg.revoke({ id: "0123456789abcdef", reason: "typo" });
    });

  var capture = helpers.auditCapture();
  try {
    await reg.revoke({ id: made.id, reason: "the application was decommissioned" });
  } finally { capture.release(); }
  count("revoking writes a row",
    capture.forAction("domain.sending_credential_revoked").length === 1);

  count("a revoked credential is refused at the next verify",
    (await reg.verify(made.token)).ok === false);
  count("and the revoked credential is still on the volume for the trail",
    (await reg.show(made.id)) !== null);
  count("and show says it is revoked",
    (await reg.show(made.id)).revokedAt !== null);

  await refusesNaming("removing without destroy refuses and names the verb that keeps the trail",
    "store/bad-argument", ["revoke"], function () {
      return reg.remove({ id: made.id, reason: "tidying up" });
    });
  await refuses("removing without a reason refuses",
    "store/bad-argument", function () {
      return reg.remove({ id: made.id, destroy: true });
    });

  var removal = await reg.remove({
    id: made.id, destroy: true, reason: "the operator asked for erasure" });
  count("blamepost.store.credentials.remove reports what the delete answered",
    removal.removed === true, JSON.stringify(removal));
  count("a destroyed credential is gone from the registry", (await reg.show(made.id)) === null);
  count("and its row is off the volume",
    b.db.from("_blamejs_api_keys").where({ id: "send:" + made.id }).first() === undefined ||
    b.db.from("_blamejs_api_keys").where({ id: "send:" + made.id }).first() === null);
  count("and its token no longer verifies", (await reg.verify(made.token)).ok === false);

  // A removal whose row is gone from under it must not report an erasure
  // that did not happen. The credential is revoked either way, and the
  // row still being readable is the answer an operator has to act on, so
  // the verdict is read off the delete rather than written beside it.
  var vanishing = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "checking that a removal reports what the volume did" });
  var vanishingRow = "send:" + vanishing.id;
  var realFrom = b.db.from;
  b.db.from = function (table) {
    var query = realFrom.apply(b.db, arguments);
    if (table !== "_blamejs_api_keys") return query;
    var realDeleteOne = query.deleteOne.bind(query);
    query.deleteOne = function () {
      // Take the row away at the moment the removal has read it and is
      // about to delete it, which is the interleaving the verdict has to
      // survive. What comes back is what the volume actually did.
      b.db.prepare("DELETE FROM _blamejs_api_keys WHERE id = ?").run(vanishingRow);
      return realDeleteOne();
    };
    return query;
  };
  var reported = null;
  try {
    await reg.remove({
      id: vanishing.id, destroy: true, reason: "the row went while the removal was running" });
  } catch (e) {
    reported = e;
  } finally {
    b.db.from = realFrom;
  }
  count("a removal whose row went underneath it refuses rather than reporting an erasure",
    reported !== null && reported.code === "store/sending-credential-not-removed",
    reported === null ? "nothing was thrown" : reported.code + ": " + reported.message);
  count("and the refusal says the credential no longer verifies even so",
    reported !== null && /revoked/.test(String(reported.message)),
    reported === null ? "nothing was thrown" : String(reported.message));
  count("and the credential really does not verify",
    (await reg.verify(vanishing.token)).ok === false);
}

async function testExpiry(reg) {
  var made = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "bounces@" + ALPHA,
    reason:        "checking that an expiry is honored",
    expiresAt:     Date.now() + 60000,
  });
  count("a credential inside its window verifies", (await reg.verify(made.token)).ok === true);

  // Move the stored expiry into the past rather than waiting a minute.
  // The column is not sealed, so this is the same edit an operator's own
  // clock passing the moment would produce.
  b.db.from("_blamejs_api_keys").where({ id: "send:" + made.id })
    .updateOne({ expiresAt: Date.now() - 1000 });
  count("a credential past its expiry is refused",
    (await reg.verify(made.token)).ok === false);

  await refuses("an expiry written as a string refuses",
    "store/bad-argument", function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "typed the date", expiresAt: "next tuesday" });
    });
  await refuses("an expiry already in the past refuses at creation",
    "store/bad-argument", function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "wrong date", expiresAt: Date.now() - 1000 });
    });

  var forever = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "this one is watched by hand", expiresAt: null });
  count("an explicitly non-expiring credential is allowed and says so",
    forever.expiresAt === null);
}

async function testDomainStopsBeingHosted(reg, handle) {
  var made = await reg.create({
    domain: ZULU, bounceMailbox: "bounces@" + ZULU,
    reason: "checking what happens when the domain goes" });
  count("it verifies while the domain is hosted and active",
    (await reg.verify(made.token)).ok === true);

  await handle.domains.setStatus({
    domain: ZULU, status: "disabled", reason: "operator disabled it" });
  var disabled = await reg.verify(made.token);
  count("a credential whose domain is disabled is refused",
    disabled.ok === false && disabled.reason === "domain-disabled", JSON.stringify(disabled));

  await handle.domains.setStatus({
    domain: ZULU, status: "active", reason: "operator enabled it again" });
  count("and it verifies again once the domain is back",
    (await reg.verify(made.token)).ok === true);
}

// ---- the same reading, asked without the secret ----

// `stillSending` is what a caller holding a connection asks between
// messages. It has the identifier the token resolved to and it does not
// have the token, so every vector here is paired against `verify` on the
// same credential in the same state: two doors onto one reading are only
// worth having while they cannot disagree.
async function testStillSending(reg, handle) {
  var absent = await reg.stillSending("0123456789abcdef");
  count("blamepost.store.credentials.stillSending answers rather than throwing for an " +
    "identifier no row carries",
    absent.ok === false && absent.reason === "not-found", JSON.stringify(absent));

  await refuses("it refuses an identifier that is not one at all",
    "store/bad-argument", function () { return reg.stillSending("not-an-id"); });

  var made = await reg.create({
    domain: ZULU, bounceMailbox: "bounces@" + ZULU,
    reason: "checking the reading a held connection makes between messages" });
  var live = await reg.stillSending(made.id);
  count("a live credential is still sending", live.ok === true && live.reason === null,
    JSON.stringify(live));
  count("and `verify` agrees, which is the pairing that keeps the two doors from drifting",
    (await reg.verify(made.token)).ok === live.ok);

  await handle.domains.setStatus({
    domain: ZULU, status: "disabled", reason: "operator disabled it" });
  var withdrawn = await reg.stillSending(made.id);
  count("a credential whose domain has been withdrawn has stopped, named as the domain " +
    "rather than as the credential",
    withdrawn.ok === false && withdrawn.reason === "domain-disabled", JSON.stringify(withdrawn));
  count("and `verify` gives that same reason for that same credential",
    (await reg.verify(made.token)).reason === withdrawn.reason);
  await handle.domains.setStatus({
    domain: ZULU, status: "active", reason: "operator enabled it again" });
  count("and it is sending again once the domain is back",
    (await reg.stillSending(made.id)).ok === true);

  // The same edit the expiry case makes, and for the same reason: the
  // column is not sealed, so moving it is what an operator's own clock
  // reaching the moment would produce.
  b.db.from("_blamejs_api_keys").where({ id: "send:" + made.id })
    .updateOne({ expiresAt: Date.now() - 1000 });
  var lapsed = await reg.stillSending(made.id);
  count("a credential past its expiry has stopped, with nothing having been written for " +
    "that to be true",
    lapsed.ok === false && lapsed.reason === "expired", JSON.stringify(lapsed));

  var revoked = await reg.create({
    domain: ZULU, bounceMailbox: "bounces@" + ZULU,
    reason: "checking that a revoked credential reads as revoked" });
  await reg.revoke({ id: revoked.id, reason: "the application was decommissioned" });
  var stopped = await reg.stillSending(revoked.id);
  count("and a revoked credential reads as revoked rather than as an identifier nobody holds",
    stopped.ok === false && stopped.reason === "revoked", JSON.stringify(stopped));
}

// ---- the two ceilings ----

async function testCeilings(reg, clock, handle) {
  var made = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "bounces@" + ALPHA,
    reason:        "checking the two ceilings",
    maxMessages:   3,
    maxRecipients: 10,
    windowMs:      b.constants.TIME.hours(1),
  });

  var start = await reg.counters.read(made.id);
  count("blamepost.store.credentials.counters.read on a credential nobody has sent through " +
    "reads zero messages", start.messages === 0);
  count("and zero recipients", start.recipients === 0);
  count("and is not over either ceiling", start.exceeded === false);
  count("and it reports the ceilings it is measured against",
    start.maxMessages === 3 && start.maxRecipients === 10,
    start.maxMessages + "/" + start.maxRecipients);

  await refuses("blamepost.store.credentials.counters.record refuses a fractional recipient " +
    "count",
    "store/bad-argument", function () {
      return reg.counters.record({ id: made.id, recipients: 1.5 });
    });
  await refuses("recording against a credential that does not exist refuses",
    "store/no-such-sending-credential", function () {
      return reg.counters.record({ id: "0123456789abcdef", recipients: 1 });
    });

  // Many messages of one recipient each: the message ceiling is what
  // trips, and the recipient ceiling has room left.
  await reg.counters.record({ id: made.id, recipients: 1 });
  await reg.counters.record({ id: made.id, recipients: 1 });
  var third = await reg.counters.record({ id: made.id, recipients: 1 });
  count("the third message against a ceiling of three meets it and is not over it",
    third.messages === 3 && third.exceeded === false, JSON.stringify(third));
  count("and a read of the window then says it is at its ceiling",
    (await reg.counters.read(made.id)).exceeded === true);
  var fourth = await reg.counters.record({ id: made.id, recipients: 1 });
  count("a fourth single-recipient message goes over the message ceiling",
    fourth.messagesExceeded === true, JSON.stringify(fourth));
  count("and leaves the recipient ceiling unspent",
    fourth.recipientsExceeded === false, JSON.stringify(fourth));
  count("and the verdict over both says the message is over",
    fourth.exceeded === true);

  clock.advance(b.constants.TIME.hours(1) + 1000);
  var rolled = await reg.counters.read(made.id);
  count("the window rolls: counts outside it are gone",
    rolled.messages === 0 && rolled.recipients === 0, JSON.stringify(rolled));
  count("and the credential is under both ceilings again", rolled.exceeded === false);

  // The window ROLLS rather than resetting on a boundary, and the two
  // are told apart only by a send on each side of a half window. A fixed
  // window would answer two or zero here; a rolling one drops the older
  // send and keeps the newer.
  var rolling = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "checking that the window rolls rather than resetting",
    maxMessages: 100, maxRecipients: 100, windowMs: b.constants.TIME.hours(1) });
  await reg.counters.record({ id: rolling.id, recipients: 2 });
  clock.advance(b.constants.TIME.minutes(30));
  await reg.counters.record({ id: rolling.id, recipients: 3 });
  var both = await reg.counters.read(rolling.id);
  count("two sends half a window apart are both inside the window",
    both.messages === 2 && both.recipients === 5, JSON.stringify(both));

  clock.advance(b.constants.TIME.minutes(31));
  var one = await reg.counters.read(rolling.id);
  count("a further half window drops the older send and keeps the newer",
    one.messages === 1 && one.recipients === 3, JSON.stringify(one));

  // One message with many recipients: the recipient ceiling is what
  // trips, and the message ceiling has room left. This is the half a
  // single counter cannot see.
  var fanOut = await reg.counters.record({ id: made.id, recipients: 40 });
  count("one message to forty recipients spends the recipient ceiling",
    fanOut.recipientsExceeded === true, JSON.stringify(fanOut));
  count("and leaves the message ceiling unspent",
    fanOut.messagesExceeded === false, JSON.stringify(fanOut));
  count("and the verdict over both says the credential is over",
    fanOut.exceeded === true);

  await refuses("blamepost.store.credentials.counters.release refuses without a reason",
    "store/bad-argument", function () { return reg.counters.release({ id: made.id }); });

  var capture = helpers.auditCapture();
  var released;
  try {
    released = await reg.counters.release({
      id: made.id, reason: "the send was a legitimate announcement" });
  } finally { capture.release(); }
  count("releasing puts both counts back to zero",
    released.messages === 0 && released.recipients === 0, JSON.stringify(released));
  count("and writes a row",
    capture.forAction("domain.sending_credential_ceiling_released").length === 1);

  // Two credentials do not share a counter.
  var other = await reg.create({
    domain: ZULU, bounceMailbox: "bounces@" + ZULU,
    reason: "checking that counters are per credential", maxMessages: 3 });
  await reg.counters.record({ id: other.id, recipients: 1 });
  count("one credential's traffic is not counted against another",
    (await reg.counters.read(made.id)).messages === 0,
    String((await reg.counters.read(made.id)).messages));
  count("and the credential that sent it reads one",
    (await reg.counters.read(other.id)).messages === 1);

  count("a credential created with no ceilings named still has finite ones",
    isFinite((await reg.counters.read((await reg.create({
      domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
      reason: "no ceilings named" })).id)).maxRecipients));

  // Everything above runs on a clock this file moves, so the clock the
  // shipped assembly actually uses is exercised here rather than being
  // the one configuration nothing drives.
  var shipped = credentials.create({
    domains: handle.domains, accounts: handle.accounts,
    aliases: handle.aliases, resolve: handle.resolve });
  try {
    var onShippedClock = await shipped.create({
      domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
      reason: "checking the clock the shipped assembly uses", maxMessages: 2 });
    var first = await shipped.counters.record({ id: onShippedClock.id, recipients: 4 });
    count("the registry built with no clock of its own counts a send",
      first.messages === 1 && first.recipients === 4, JSON.stringify(first));
    var second = await shipped.counters.record({ id: onShippedClock.id, recipients: 1 });
    count("and a second send meets its message ceiling of two without going over it",
      second.messages === 2 && second.messagesExceeded === false, JSON.stringify(second));
    count("and reading it back agrees with what recording answered",
      (await shipped.counters.read(onShippedClock.id)).messages === 2);
    var third2 = await shipped.counters.record({ id: onShippedClock.id, recipients: 1 });
    count("and a third send goes over it",
      third2.messagesExceeded === true, JSON.stringify(third2));

    // A credential allowing one message and one recipient sends exactly
    // that message.
    var single = await shipped.create({
      domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
      reason: "checking a ceiling of one", maxMessages: 1, maxRecipients: 1 });
    var only = await shipped.counters.record({ id: single.id, recipients: 1 });
    count("a ceiling of one message and one recipient allows the one message",
      only.exceeded === false, JSON.stringify(only));

    // Sends recorded together are each counted.
    var busy = await shipped.create({
      domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
      reason: "checking concurrent recording", maxMessages: 100, maxRecipients: 100 });
    var jobs = [];
    for (var j = 0; j < 10; j += 1) {
      jobs.push(shipped.counters.record({ id: busy.id, recipients: 2 }));
    }
    var readings = await Promise.all(jobs);
    var after = await shipped.counters.read(busy.id);
    count("ten sends recorded at once are all counted",
      after.messages === 10 && after.recipients === 20, JSON.stringify(after));
    var seen = readings.map(function (r) { return r.messages; }).sort(function (a, c) {
      return a - c;
    });
    count("and each of them read the window after the ones before it",
      seen.join(",") === "1,2,3,4,5,6,7,8,9,10", seen.join(","));

    // A window length changed on an empty window while sends are being
    // recorded. Each send is counted either before the change, which then
    // refuses because the window is not empty, or after the reset, under
    // the new length. None is erased by the reset.
    var lost = 0;
    for (var round = 0; round < 6; round += 1) {
      var moving = await shipped.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "checking a window change racing a send", maxMessages: 100,
        maxRecipients: 100, windowMs: b.constants.TIME.hours(1) });
      // The order the three start in varies by round, so the change lands
      // before, between and after the two sends' reads and writes.
      var change = function () {
        return shipped.setCeilings({ id: moving.id, windowMs: b.constants.TIME.hours(2),
          reason: "a longer window" }).then(function () { return "set"; },
          function (e) { return e.code; });
      };
      var send = function () {
        return shipped.counters.record({ id: moving.id, recipients: 1 });
      };
      var started = round % 3 === 0 ? [change(), send(), send()]
        : round % 3 === 1 ? [send(), change(), send()] : [send(), send(), change()];
      var settled = await Promise.all(started);
      var outcomes = [settled.filter(function (v) { return typeof v === "string"; })[0]];
      var left = await shipped.counters.read(moving.id);
      if (left.messages !== 2) lost += 1;
      count("a window change racing two sends, round " + round + ", answers set or in use",
        outcomes[0] === "set" || outcomes[0] === "store/sending-credential-window-in-use",
        String(outcomes[0]));
    }
    count("and in every round both sends are still counted afterwards",
      lost === 0, lost + " round(s) lost a send");
  } finally {
    shipped.close();
  }
}

// ---- the stored digest is upgraded when it falls behind ----

async function testStoredDigestUpgrade(reg) {
  var made = await reg.create({
    domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
    reason: "checking the stored digest is upgraded on use" });

  count("the leader gate the upgrade sits behind is satisfied on this server",
    b.cluster.isLeader() === true);

  var secretHex = made.token.split("_")[3];
  var rowId = "send:" + made.id;

  // What the volume actually holds for the secret, read off the row
  // rather than off the constant the registry was built with. The
  // algorithm is named at construction and travels through the framework
  // registry before it reaches these bytes, and a name that is accepted
  // at one end and dropped at the other leaves the digest on whatever
  // the framework's own default happens to be.
  function storedDigest() {
    return b.credentialHash.inspect(
      b.db.prepare("SELECT secretHash FROM _blamejs_api_keys WHERE id = ?")
        .all(rowId)[0].secretHash);
  }

  var asCreated = storedDigest();
  count("the secret is stored under the digest this registry names rather than a framework " +
    "default it inherited",
    asCreated !== null && asCreated.algoName === "shake256",
    JSON.stringify(asCreated));
  count("and the volume holds a digest rather than the secret, so a copy of the data " +
    "directory yields nothing to present",
    b.db.prepare("SELECT secretHash FROM _blamejs_api_keys WHERE id = ?")
      .all(rowId)[0].secretHash.indexOf(secretHex) === -1);

  var short = await b.credentialHash.hash(secretHex, { params: { length: 16 } });
  b.db.prepare("UPDATE _blamejs_api_keys SET secretHash = ? WHERE id = ?").run(short, rowId);

  var beforeBytes = b.credentialHash.inspect(
    b.db.prepare("SELECT secretHash FROM _blamejs_api_keys WHERE id = ?")
      .all(rowId)[0].secretHash).payloadBytes;
  count("the stored digest is behind the current one before the credential is used",
    beforeBytes === 16, String(beforeBytes));

  count("a credential on a behind digest still verifies",
    (await reg.verify(made.token)).ok === true);

  var afterBytes = b.credentialHash.inspect(
    b.db.prepare("SELECT secretHash FROM _blamejs_api_keys WHERE id = ?")
      .all(rowId)[0].secretHash).payloadBytes;
  count("and using it replaces the stored digest with the current one",
    afterBytes > beforeBytes, beforeBytes + " then " + afterBytes);
  count("and the replacement is written under the same digest the credential was created " +
    "under, so the upgrade raises the length without moving the algorithm",
    storedDigest().algoName === asCreated.algoName,
    asCreated.algoName + " then " + storedDigest().algoName);
  count("and the credential still verifies afterwards",
    (await reg.verify(made.token)).ok === true);
}

// ---- listing stays inside one domain ----

async function testListingIsPerDomain(reg) {
  var alpha = await reg.list({ domain: ALPHA });
  var zulu  = await reg.list({ domain: ZULU });

  count("listing one domain returns something", alpha.length > 0, String(alpha.length));
  count("listing the other domain returns something", zulu.length > 0, String(zulu.length));
  count("no credential listed under the first domain is scoped to the second",
    alpha.every(function (r) { return r.domain === ALPHA; }),
    alpha.map(function (r) { return r.domain; }).join(","));
  count("no credential listed under the second domain is scoped to the first",
    zulu.every(function (r) { return r.domain === ZULU; }),
    zulu.map(function (r) { return r.domain; }).join(","));
  count("the two listings share no identifier",
    alpha.every(function (r) {
      return zulu.every(function (z) { return z.id !== r.id; });
    }));
  count("a listed record says whether its binding still holds",
    alpha.every(function (r) { return typeof r.bindingHolds === "boolean"; }));

  await refuses("listing a domain this server does not host refuses",
    "store/no-such-domain", function () {
      return reg.list({ domain: "not-hosted.example" });
    });
  await refuses("listing with no domain at all refuses",
    "store/bad-argument", function () { return reg.list({}); });
}

async function testCreationWritesARow(reg) {
  var OPERATOR = "operator-under-test";
  var capture = helpers.auditCapture();
  var made;
  try {
    // Inside an actor scope, because a row that merely carries the actor
    // columns proves nothing: they are there whether or not the verb
    // passed an actor at all. What has to hold is that whoever was
    // acting reaches the row.
    made = await auditActor.runAs(auditActor.build({ userId: OPERATOR }), function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "bounces@" + ALPHA,
        reason: "checking the trail" });
    });
  } finally { capture.release(); }

  var rows = capture.forAction("domain.sending_credential_created");
  count("blamepost.store.credentials.create writes a row",
    rows.length === 1, String(rows.length));
  count("and the row names whoever was acting",
    rows.length === 1 && rows[0].actorUserId === OPERATOR,
    rows.length === 1 ? "actorUserId=" + JSON.stringify(rows[0].actorUserId) : "no row");
  count("and the row carries the reason it was given",
    rows.length === 1 && String(rows[0].reason).indexOf("checking the trail") !== -1,
    rows.length === 1 ? String(rows[0].reason) : "no row");
  count("and the row names the domain the credential speaks for",
    rows.length === 1 && rows[0].resourceId === ALPHA,
    rows.length === 1 ? String(rows[0].resourceId) : "no row");
  count("and the row holds no secret",
    rows.length === 1 &&
      JSON.stringify(rows[0]).indexOf(made.token.split("_")[3]) === -1);
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-sendcred-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the test's own tree keeps the encrypted-at-rest path
  // exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var registry = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var handle = await store.open(cfg);
    await seedTwoDomains(handle);

    var clock = movableClock(Date.now());
    registry = registryFor(handle, clock);

    count("the registry publishes the token prefix a scanner pattern is written against",
      typeof credentials.TOKEN_PREFIX === "string" &&
      /^[a-z]+$/.test(credentials.TOKEN_PREFIX), credentials.TOKEN_PREFIX);
    count("and it is not the framework's own default, so the two are told apart",
      credentials.TOKEN_PREFIX !== b.apiKey.DEFAULTS.prefix, credentials.TOKEN_PREFIX);

    await testCreationRefusals(registry);
    await testCreationShape(registry, handle);
    await testCreationWritesARow(registry);
    var pair = await testRefusalList(registry, handle);
    await testScopeIsReadFromTheStore(registry, pair);
    await testALiftedScopeRefuses(registry, pair);
    await testAWidenedRefusalListRefuses(registry);
    await testRotation(registry);
    await testRevokeAndRemove(registry);
    await testExpiry(registry);
    await testDomainStopsBeingHosted(registry, handle);
    await testStillSending(registry, handle);
    await testCeilings(registry, clock, handle);
    await testStoredDigestUpgrade(registry);
    await testListingIsPerDomain(registry);
  } finally {
    if (registry !== null) registry.close();
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not a
      // test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = { name: "sending-credential-registry", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count. Keep the token.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
