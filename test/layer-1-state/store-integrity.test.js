// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The identity layer's integrity rules, driven through the same calls a
 * listener and the operator interface make: a real temporary data
 * directory, a real vault, a real encrypted database, real Argon2id
 * hashing and real sealed columns.
 *
 * These are the properties the layer holds BETWEEN its calls rather
 * than inside one of them, and each is written as the failure it
 * prevents:
 *
 *   - a mailbox cannot end up in a domain this server does not host,
 *     even when the domain is removed while the password is hashing;
 *   - a password change either lands or refuses, and never reports
 *     success for a row that is no longer there;
 *   - an address whose alias an operator disabled stops taking mail,
 *     rather than falling through to whatever the domain's catch-all
 *     points at;
 *   - removing a domain cannot silently turn mail that this server was
 *     refusing into mail it forwards off the machine;
 *   - an account whose domain is disabled or no longer hosted cannot
 *     sign in, because every listener behind that verdict would let it
 *     keep sending;
 *   - two alias paths that converge on one mailbox are a fan-out, not a
 *     loop, and the loop report has to tell an operator which it is;
 *   - an append for an account nobody holds is refused rather than
 *     granted an unlimited mailbox.
 *
 * Run standalone: node test/layer-1-state/store-integrity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

// The assertion that quotes the value that produced the verdict, and
// the counter behind it, are both the shared ones. A file that kept its
// own counter reported a total that only covered the assertions made
// through its own wrapper, so a `check` written directly ran and was
// invisible in the number the runner aggregated.
var count = helpers.count;

// Assert a call refuses under one stable code. The code is the contract
// a caller branches on, so a refusal under the wrong one is a change a
// listener's error mapping would not survive.
async function refuses(label, code, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";
var OTHER_PASSWORD   = "steady harbour cable 8820";
var NEW_PASSWORD     = "another quiet lantern 7715";

function message(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\nbody\r\n", "utf8");
}

// ---- a mailbox cannot outlive the domain check that admitted it ----
//
// The hosted-domain lookup runs before the password is hashed, and
// hashing is the slowest thing this layer does. Anything that removes
// the domain during that window has to be visible to the write, or the
// server ends up holding a mailbox in a domain it does not answer for:
// its mail bounces, and it can still sign in and send under a domain
// with no selector to sign with.

async function testDomainCheckSurvivesTheHash(handle) {
  await handle.domains.add({ domain: "race.example" });

  // Calling without awaiting parks the call on the password hash, which
  // is after the domain check and before the insert. Nothing here
  // depends on timing: the domain check has already run by the time
  // this returns a promise.
  var creating = handle.accounts.create({
    address: "ghost@race.example", password: PASSWORD,
  });

  var removeError = null;
  try {
    await handle.domains.remove({ domain: "race.example", reason: "moving to another host" });
  } catch (e) { removeError = e; }

  var createError = null;
  var created = null;
  try { created = await creating; } catch (e) { createError = e; }

  count("one of the two refuses when a domain is removed while a mailbox in it is being created",
    (removeError !== null && removeError.code === "store/domain-in-use") ||
    (createError !== null && createError.code === "store/no-such-domain"),
    "remove: " + (removeError && removeError.code) +
    ", create: " + (createError && createError.code) +
    ", account: " + (created && created.address));

  // The property that matters is the one an operator can check: no row
  // in the accounts table names a domain this server does not host.
  var orphans = handle.accounts.list({ includeArchived: true }).filter(function (account) {
    return handle.domains.get(account.domain) === null;
  });
  count("no account is left in a domain this server does not host",
    orphans.length === 0,
    orphans.map(function (a) { return a.address; }).join(","));

  // Whichever way the refusal fell, leave the fixture clean for the
  // rest of the file.
  if (handle.domains.get("race.example") !== null) {
    var stragglers = handle.accounts.list({ domain: "race.example", includeArchived: true });
    for (var i = 0; i < stragglers.length; i += 1) {
      await handle.accounts.delete({
        id: stragglers[i].id, destroy: true, reason: "clearing the fixture",
      });
    }
    await handle.domains.remove({ domain: "race.example", reason: "clearing the fixture" });
  }
}

// ---- a password change lands or refuses, never neither ----

async function testPasswordChangeCannotVanish(handle) {
  await handle.domains.add({ domain: "vanish.example" });
  var doomed = await handle.accounts.create({
    address: "doomed@vanish.example", password: PASSWORD,
  });

  var settled = false;
  var setting = handle.accounts.setPassword({ id: doomed.id, password: NEW_PASSWORD })
    .then(function (v) { settled = true; return v; },
      function (e) { settled = true; throw e; });

  // Runs to completion, erase included, while the call above is still
  // hashing.
  await handle.accounts.delete({
    id: doomed.id, destroy: true, reason: "erasure requested by the account owner",
  });
  count("the account is erased before the password change resumes",
    handle.accounts.get(doomed.id) === null);

  if (settled) {
    helpers.skip("the password hash finished before the erase, so the window this " +
      "vector needs did not open on this run");
    // Swallow the settled promise either way; the vector did not run.
    try { await setting; } catch (_e) { /* the vector did not run */ }
  } else {
    var result = null;
    var thrown = null;
    try { result = await setting; } catch (e) { thrown = e; }
    count("a password change against a row that was erased mid-flight refuses",
      thrown !== null && thrown.code === "store/no-such-account",
      thrown === null ? "resolved to " + JSON.stringify(result) : thrown.code);
  }

  await handle.domains.remove({ domain: "vanish.example", reason: "clearing the fixture" });
}

// ---- a disabled alias stops taking mail ----
//
// Disabling is the reversible answer to an address being abused. If the
// address then falls through to the domain's catch-all, the abuse
// carries on into somebody else's mailbox and the operator believes
// they stopped it. A suspended account is the comparison: it is
// reported local and undeliverable, and it does not fall through.

async function testDisabledAliasDoesNotFallThrough(handle) {
  await handle.domains.add({ domain: "fall.example" });
  await handle.accounts.create({ address: "keeper@fall.example", password: OTHER_PASSWORD });
  await handle.aliases.add({
    address: "news@fall.example", destination: "elsewhere@example.net",
  });

  count("the alias routes before it is disabled",
    handle.resolve("news@fall.example").targets.length === 1);

  await handle.aliases.setStatus({
    address: "news@fall.example", destination: "elsewhere@example.net",
    status: "disabled", reason: "abuse report",
  });

  var withoutCatchAll = handle.resolve("news@fall.example");
  count("a disabled alias is reported as one rather than as an address nobody holds",
    withoutCatchAll.reason === "alias-disabled", withoutCatchAll.reason);
  count("a disabled alias is local and undeliverable",
    withoutCatchAll.local === true && withoutCatchAll.deliverable === false);

  await handle.aliases.add({
    domain: "fall.example", catchAll: true, destination: "keeper@fall.example",
  });

  count("the catch-all takes an address nobody has claimed",
    handle.resolve("whoever@fall.example").deliverable === true);

  var withCatchAll = handle.resolve("news@fall.example");
  count("a disabled alias does not fall through to the catch-all",
    withCatchAll.deliverable === false, withCatchAll.kind + " -> " +
    withCatchAll.targets.map(function (t) { return t.mailbox; }).join(","));
  count("and none of the catch-all's destinations appear in its targets",
    withCatchAll.targets.every(function (t) { return t.mailbox !== "keeper@fall.example"; }));

  // The account path is the shape the alias path has to match.
  var suspended = await handle.accounts.create({
    address: "quiet@fall.example", password: OTHER_PASSWORD,
  });
  await handle.accounts.suspend({ id: suspended.id, reason: "credential reuse reported" });
  var suspendedVerdict = handle.resolve("quiet@fall.example");
  count("a suspended mailbox does not fall through to the catch-all either",
    suspendedVerdict.kind === "account" && suspendedVerdict.deliverable === false &&
    suspendedVerdict.reason === "account-suspended", suspendedVerdict.reason);

  // A hop in the middle of a chain reports the same reason.
  await handle.aliases.add({ address: "hop@fall.example", destination: "news@fall.example" });
  var chained = handle.resolve("hop@fall.example");
  count("a chain through a disabled alias names the disabled alias",
    chained.targets.length === 1 && chained.targets[0].reason === "alias-disabled",
    chained.targets.map(function (t) { return t.reason; }).join(","));
}

// ---- removing a domain cannot start forwarding mail off the machine ----
//
// An alias aimed at an address in a hosted domain that has no mailbox
// is refused at RCPT. Stop hosting the domain and the same alias reads
// as a forward to somewhere else, so the message is accepted and handed
// to the outbound chain. It usually goes straight back to this server,
// whose MX record the removal did not change.

async function testDomainRemovalDoesNotRedirectAliases(handle) {
  await handle.domains.add({ domain: "src.example" });
  await handle.domains.add({ domain: "dst.example" });
  await handle.aliases.add({
    address: "team@src.example", destination: "nobody@dst.example",
  });

  var before = handle.resolve("team@src.example");
  count("an alias into a hosted domain with no mailbox is refused, not forwarded",
    before.targets.length === 1 && before.targets[0].local === true &&
    before.targets[0].deliverable === false,
    JSON.stringify(before.targets[0]));

  await refuses("blamepost.store.domains.remove refuses while aliases point into the domain",
    "store/domain-in-use", function () {
      return handle.domains.remove({ domain: "dst.example", reason: "moving to another host" });
    });

  var after = handle.resolve("team@src.example");
  count("the alias still refuses after the removal was refused",
    after.targets[0].local === true && after.targets[0].deliverable === false,
    JSON.stringify(after.targets[0]));

  // Repointing the alias is what clears the way, and then the removal
  // goes through: the refusal names a state to fix, not a wall.
  await handle.aliases.remove({
    address: "team@src.example", destination: "nobody@dst.example",
    reason: "domain moving to another host",
  });
  var removed = await handle.domains.remove({
    domain: "dst.example", reason: "moving to another host",
  });
  count("blamepost.store.domains.remove drops a domain nothing points into",
    removed.outcome === "removed");
}

// ---- an account cannot sign in without its domain ----

async function testDomainStatusGatesSignIn(handle) {
  await handle.domains.add({ domain: "off.example" });
  await handle.accounts.create({ address: "mallory@off.example", password: PASSWORD });

  var live = await handle.accounts.authenticate({
    address: "mallory@off.example", password: PASSWORD,
  });
  count("an account on an active domain signs in", live.ok === true, live.reason);

  await handle.domains.setStatus({
    domain: "off.example", status: "disabled", reason: "under investigation",
  });

  var whileDisabled = await handle.accounts.authenticate({
    address: "mallory@off.example", password: PASSWORD,
  });
  count("an account whose domain is disabled cannot sign in",
    whileDisabled.ok === false, whileDisabled.reason);
  count("and the verdict says which of the two refused it",
    whileDisabled.reason === "domain-disabled", whileDisabled.reason);

  await handle.domains.setStatus({
    domain: "off.example", status: "active", reason: "investigation closed",
  });
  var reinstated = await handle.accounts.authenticate({
    address: "mallory@off.example", password: PASSWORD,
  });
  count("re-enabling the domain lets it sign in again", reinstated.ok === true, reinstated.reason);
}

// ---- convergence is a fan-out, not a loop ----

async function testConvergingAliasesAreNotLoops(handle) {
  await handle.domains.add({ domain: "web.example" });
  await handle.accounts.create({ address: "erin@web.example", password: OTHER_PASSWORD });

  await handle.aliases.add({ address: "mid@web.example",   destination: "erin@web.example" });
  await handle.aliases.add({ address: "left@web.example",  destination: "mid@web.example" });
  await handle.aliases.add({ address: "right@web.example", destination: "mid@web.example" });
  await handle.aliases.add({ address: "top@web.example",   destination: "left@web.example" });
  await handle.aliases.add({ address: "top@web.example",   destination: "right@web.example" });

  var diamond = handle.resolve("top@web.example");
  count("two paths onto one mailbox deliver one message",
    diamond.targets.length === 1 && diamond.targets[0].mailbox === "erin@web.example",
    diamond.targets.map(function (t) { return t.mailbox; }).join(","));
  count("and neither path is reported as a loop",
    diamond.loops.length === 0, diamond.loops.join(","));
  count("the fan-out is deliverable", diamond.deliverable === true);

  // A real loop is still a real loop.
  await handle.aliases.add({ address: "ring1@web.example", destination: "ring2@web.example" });
  await handle.aliases.add({ address: "ring2@web.example", destination: "ring1@web.example" });
  var ring = handle.resolve("ring1@web.example");
  count("a cycle is still reported as a loop", ring.loops.length > 0, ring.loops.join(","));
  count("and a cycle is still undeliverable",
    ring.deliverable === false && ring.reason === "alias-loop", ring.reason);
}

// ---- an append for an account nobody holds is refused ----
//
// The cap an operator writes on an account is a byte count where zero
// means no limit, so a reader that answers zero for an account it could
// not find hands an unlimited mailbox to an identity that does not
// exist. Driven through the adapter the listeners append with.

async function testQuotaReaderRefusesAnUnknownAccount(handle) {
  await handle.domains.add({ domain: "quota.example" });
  var owner = await handle.accounts.create({
    address: "owner@quota.example", password: OTHER_PASSWORD, quotaBytes: 0,
  });

  var stored = handle.mailbox.appendMessage("INBOX", message("kept"), {
    actor: { id: owner.id },
  });
  count("an append for a live account with no cap is accepted",
    stored !== null && typeof stored === "object");

  var ownerId = owner.id;
  await handle.accounts.delete({
    id: ownerId, destroy: true, reason: "erasure requested by the account owner",
  });
  count("the account is gone", handle.accounts.get(ownerId) === null);

  await refuses("an append for an account nobody holds is refused rather than left uncapped",
    "store/no-such-account", function () {
      return handle.mailbox.appendMessage("INBOX", message("orphaned"), {
        actor: { id: ownerId },
      });
    });
}

// ---- one domain has one identity in the audit trail ----
//
// `resourceId` is a column an auditor filters on. A domain whose own
// events file under its row id while its selector events file under its
// name splits one history across two identifier spaces, and the auditor
// who filters correctly gets half of it and no sign that half is
// missing.

async function testDomainAuditIdentity(handle) {
  var domain = await handle.domains.add({ domain: "audit.example" });
  await handle.domains.addSelector({
    domain: "audit.example", selector: "bp1", algorithm: "ed25519",
    publicKey: Buffer.from("first key").toString("base64"),
    keyRef: "audit.example.bp1.ed25519.sealed",
  });
  await handle.domains.addSelector({
    domain: "audit.example", selector: "bp2", algorithm: "ed25519",
    publicKey: Buffer.from("second key").toString("base64"),
    keyRef: "audit.example.bp2.ed25519.sealed",
  });
  await handle.domains.retireSelector({
    domain: "audit.example", selector: "bp1", algorithm: "ed25519",
  });
  await handle.domains.removeSelector({
    domain: "audit.example", selector: "bp1", algorithm: "ed25519",
    reason: "private key exposed", immediate: true,
  });

  var actions = ["domain.added", "domain.selector_added",
    "domain.selector_retiring", "domain.selector_removed"];
  for (var i = 0; i < actions.length; i += 1) {
    var rows = await b.audit.query({ action: actions[i], limit: 50 });
    var mine = (rows || []).filter(function (row) {
      var meta = row && row.metadata;
      if (typeof meta === "string") {
        try { meta = JSON.parse(meta); } catch (_e) { meta = null; }
      }
      return meta && meta.domain === "audit.example";
    });
    count(actions[i] + " left a row for this domain", mine.length > 0, mine.length);
    var wrong = mine.filter(function (row) { return row.resourceId !== domain.id; });
    count(actions[i] + " files under the domain's row id, the same one every other " +
      "event for it uses",
      wrong.length === 0,
      wrong.map(function (row) { return String(row.resourceId); }).join(","));
  }
}

// ---- a display name is screened for more than the bytes a header breaks on ----
//
// The field is rendered into the admin views, into webmail and into the
// JMAP `name` of every address a client shows. A bidi override there
// renders an address backwards while reading forwards, which is the
// spoofing the Trojan Source work named, and neither HTML escaping nor
// JSON encoding touches it: the codepoint is legitimate and the renderer
// honours it. Zero-width and Unicode Tags characters hide text in the
// same field.
//
// Built from code points rather than typed, so the bytes under test are
// visible to anyone reading this file.
var BIDI_OVERRIDE   = String.fromCharCode(0x202E);
var ZERO_WIDTH      = String.fromCharCode(0x200B);
var UNICODE_TAG_A   = String.fromCodePoint(0xE0041);
var CARRIAGE_RETURN = String.fromCharCode(13);
var LINE_FEED       = String.fromCharCode(10);

async function testDisplayNameScreening(handle) {
  await handle.domains.add({ domain: "names.example" });

  var hostile = {
    "a bidi override, which renders the name in the other direction":
      "Alice" + BIDI_OVERRIDE + "Example",
    "a zero-width character, which hides text in the rendered name":
      "Alice" + ZERO_WIDTH + "Example",
    "a Unicode Tags character, which carries an invisible copy of ASCII":
      "Alice" + UNICODE_TAG_A + "Example",
    "a carriage return, which is a header break":
      "Alice" + CARRIAGE_RETURN + "Bcc: victim@example.net",
    "a line feed, which is a header break":
      "Alice" + LINE_FEED + "Bcc: victim@example.net",
  };
  var labels = Object.keys(hostile);
  for (var i = 0; i < labels.length; i += 1) {
    await refuses("a display name carrying " + labels[i] + " is refused",
      "store/bad-argument", (function (value, n) {
        return function () {
          return handle.accounts.create({
            address: "hostile" + n + "@names.example",
            password: OTHER_PASSWORD, displayName: value,
          });
        };
      }(hostile[labels[i]], i)));
  }

  // The screen has to leave ordinary names alone. Every one of these
  // mixes scripts, which is what most of the world's names do, and a
  // screen that refuses them is a worse bug than the one it closes.
  var ordinary = ["Alice Example", "Robert 李", "Ольга Smith",
    "Sara سارة", "Γιώργος"];
  for (var k = 0; k < ordinary.length; k += 1) {
    var account = await handle.accounts.create({
      address: "ordinary" + k + "@names.example",
      password: OTHER_PASSWORD, displayName: ordinary[k],
    });
    count("an ordinary display name is kept exactly as the operator wrote it: " + ordinary[k],
      account.displayName === ordinary[k], account.displayName);
  }
}

// ---- a selector's key file name cannot name something that is not a file ----

async function testSelectorKeyRefScreening(handle) {
  await handle.domains.add({ domain: "keys.example" });

  var good = await handle.domains.addSelector({
    domain: "keys.example", selector: "bp1", algorithm: "ed25519",
    publicKey: Buffer.from("classical public key bytes").toString("base64"),
    keyRef: "keys.example.bp1.ed25519.sealed",
  });
  count("the shipped key file naming convention is accepted",
    good.keyRef === "keys.example.bp1.ed25519.sealed", good.keyRef);

  var bad = {
    "a path that leaves the keys folder":      "../../etc/shadow",
    "a path separator":                        "sub/dir.sealed",
    "a backslash separator":                   "sub\\dir.sealed",
    "a reserved device name":                  "CON.sealed",
    "a bare reserved device name":             "nul",
    "a name with a control character in it":   "a b.sealed",
    "an alternate data stream":                "example.sealed:hidden",
  };
  var names = Object.keys(bad);
  for (var i = 0; i < names.length; i += 1) {
    await refuses("a selector naming its key file with " + names[i] + " is refused",
      "store/bad-argument", (function (ref, n) {
        return function () {
          return handle.domains.addSelector({
            domain: "keys.example", selector: "bp" + (n + 2), algorithm: "ed25519",
            publicKey: Buffer.from("x").toString("base64"), keyRef: ref,
          });
        };
      }(bad[names[i]], i)));
  }
}

// ---- an erasure nothing holds back, and how far an order reaches ----
//
// `accounts.delete({ destroy: true })` erases the account's mail, then
// the aliases that pointed at the address, then the account row. Those
// are separate erasures and each is refused on its own, so what this
// vector establishes is the settled case: nothing refuses, the identity
// goes last, the forwarding rules go with it, and the chain carries one
// row saying so.
//
// The order matters because erasure here is a crypto-erase: the per-row
// key is destroyed with the row, so an account row erased ahead of
// something that still names it cannot be read back from the database
// file, from a page cache or from a backup taken afterwards, and the
// aliases that named it would be forwarding rules pointing at a mailbox
// nobody holds.
//
// The audit chain is the second half. It is hash-linked and append-only,
// so an `account.destroyed` row written for an erasure that did not
// destroy the account is a claim no later row can retract. An auditor
// reading the chain is told the mailbox was destroyed on a date it was
// not. What a refusal leaves behind is the next vector's subject, driven
// on a refusal this server can actually meet.
//
// This one also measures the boundary an operator has to know before
// relying on an order: an order is placed on a message and covers the
// message it names, so an account address is not a subject the register
// ever carries and an erasure is not stopped by an order over the
// account's mail. That is measured here rather than assumed, because a
// gate consulting a subject nothing registers reads as a protection.

async function testRefusedErasureDestroysNothing(handle) {
  await handle.domains.add({ domain: "held.example" });
  var held = await handle.accounts.create({
    address: "alice@held.example", password: PASSWORD,
  });
  await handle.aliases.add({
    address: "sales@held.example", destination: "alice@held.example",
  });
  await handle.aliases.add({
    address: "help@held.example", destination: "alice@held.example",
  });

  function aliasesHere() {
    return handle.aliases.list({ domain: "held.example" })
      .map(function (a) { return a.address; }).sort();
  }
  function destroyedRows() {
    return b.db.from("audit_log").where({ action: "account.destroyed" }).count();
  }

  count("the fixture has both aliases before the erasure is attempted",
    aliasesHere().length === 2, aliasesHere().join(","));
  var chainBefore = destroyedRows();

  // What an order placed the way this server places one actually covers,
  // measured rather than assumed. The register is keyed on the exact
  // record an order names and the only thing this server names is a
  // message, so an account address is never a held subject and nothing
  // that asks about one is answered by an order over the account's mail.
  var holds = b.legalHold.create({ db: b.db, audit: b.audit });
  count("an account address is not a subject any order in this server registers",
    holds.isHeld("alice@held.example") === false, "alice@held.example");

  var erased = await handle.accounts.delete({
    id: held.id, destroy: true, reason: "erasure requested by the account owner",
  });

  count("so an erasure nothing is holding back destroys the identity",
    erased.outcome === "destroyed" && handle.accounts.get(held.id) === null,
    JSON.stringify(erased.outcome));
  count("and it answers with nothing refused about the account row itself",
    Array.isArray(erased.identityRefused) && erased.identityRefused.length === 0,
    JSON.stringify(erased.identityRefused));
  count("it takes the aliases that pointed at the mailbox with it, so no forwarding row " +
    "is left pointing at a mailbox nobody holds",
    aliasesHere().length === 0, aliasesHere().join(","));
  count("and it records the destruction that did happen, once",
    destroyedRows() === chainBefore + 1,
    "before " + chainBefore + ", after " + destroyedRows());

  await handle.domains.remove({ domain: "held.example", reason: "clearing the fixture" });
}

// ---- an alias that refuses and an alias that breaks are not the same ----

// Erasing an account erases the aliases pointing at it, and one of those
// erasures can be stopped for two unrelated reasons. A preservation
// order on the alias itself is the system working: the alias stays, the
// operator releases the order or explains why it stands, and nobody is
// paged. An alias that failed for any other reason is a fault: the row
// is still there, still forwarding to a mailbox that no longer exists,
// and somebody has to go and look.
//
// Both used to arrive as one undifferentiated list carrying a bare code,
// and the audit row carried one count covering both. An operator reading
// either could not tell which had happened, and the two need opposite
// responses.
async function testAliasRefusalsAreClassified(handle) {
  await handle.domains.add({ domain: "classify.example" });
  var owner = await handle.accounts.create({
    address: "owner@classify.example", password: PASSWORD,
  });
  await handle.aliases.add({
    address: "preserved@classify.example", destination: "owner@classify.example",
  });
  await handle.aliases.add({
    address: "ordinary@classify.example", destination: "owner@classify.example",
  });

  var holds = b.legalHold.create({ db: b.db, audit: b.audit });
  holds.place("preserved@classify.example", {
    reason: "preservation order 24-cv-02041",
  });

  var destroyed = await handle.accounts.delete({
    id: owner.id, destroy: true, reason: "erasure requested by the account owner",
  });

  count("the account is kept while one of its aliases is preserved, because a forwarding " +
    "row that survives has to point at a mailbox that survives with it",
    destroyed.outcome === "partially-erased" && handle.accounts.get(owner.id) !== null,
    JSON.stringify(destroyed.outcome));
  count("the alias under a preservation order is reported as preserved",
    Array.isArray(destroyed.aliasesPreserved) &&
    destroyed.aliasesPreserved.length === 1 &&
    destroyed.aliasesPreserved[0].address === "preserved@classify.example",
    JSON.stringify(destroyed.aliasesPreserved));
  count("the preserved alias names what preserves it",
    Array.isArray(destroyed.aliasesPreserved) && destroyed.aliasesPreserved[0] &&
    /legal-hold/.test(String(destroyed.aliasesPreserved[0].reason)),
    JSON.stringify(destroyed.aliasesPreserved));
  count("nothing is reported as having failed, because nothing did",
    Array.isArray(destroyed.aliasesFailed) && destroyed.aliasesFailed.length === 0,
    JSON.stringify(destroyed.aliasesFailed));
  count("the alias nothing preserves went with the mailbox",
    destroyed.aliasesErased === 1, JSON.stringify(destroyed));
  count("and the preserved alias is still on the table",
    handle.aliases.list({ domain: "classify.example" }).length === 1,
    JSON.stringify(handle.aliases.list({ domain: "classify.example" })));

  var recorded = b.db.from("audit_log")
    .where({ action: "account.erasure_held" }).all()
    .filter(function (row) {
      var meta = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
      return meta && meta.address === "owner@classify.example";
    });
  var meta = recorded.length === 1
    ? (typeof recorded[0].metadata === "string"
      ? JSON.parse(recorded[0].metadata) : recorded[0].metadata)
    : null;
  count("the erasure is recorded once, under the name for what happened rather than the " +
    "name for a destruction that did not",
    recorded.length === 1, "rows " + recorded.length);
  count("the audit row counts what was preserved separately from what failed",
    meta !== null && meta.aliasesPreserved === 1 && meta.aliasesFailed === 0,
    JSON.stringify(meta));
  count("an erasure where nothing faulted is recorded as a success, because an order " +
    "keeping a record is the system working",
    recorded.length === 1 && recorded[0].outcome === "success",
    recorded.length === 1 ? String(recorded[0].outcome) : "no row");
  // The chain is append-only, so a destruction row written for a
  // destruction that did not happen is a claim no later row can retract.
  count("and no row anywhere says this account was destroyed, because it was not",
    b.db.from("audit_log").where({ action: "account.destroyed" }).all()
      .filter(function (row) {
        var m = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
        return m && m.address === "owner@classify.example";
      }).length === 0, "owner@classify.example");

  holds.release("preserved@classify.example", {
    reason: "the matter closed", approver: "operator@classify.example",
  });
}

// The other branch, and the rule that decides it.
//
// Only the framework's own erase gates announce themselves with a code
// this layer can recognize, and a refusal arriving without one could be
// anything: a constraint, a corrupt page, a full volume, or a gate a
// later framework release added. All of those leave the same wreckage,
// which is a mailbox that is gone and a forwarding row still pointing at
// it, so mail keeps arriving for an address nobody holds. The rule is
// therefore that an unrecognized refusal is surfaced as something to
// investigate rather than filed as something that meant to happen: the
// quiet classification is the one that has to be earned.
//
// The unrecognized refusal is produced here by making the alias table
// append-only, which is a real framework capability and a refusal that
// reaches this layer as a bare database error with no code on it. This
// server declares no such thing, so what the vector pins is the shape of
// an unrecognized refusal rather than a configuration anyone runs.
async function testAliasEraseFaultsAreNotPreservationRefusals(handle) {
  await handle.domains.add({ domain: "faulty.example" });
  var owner = await handle.accounts.create({
    address: "owner@faulty.example", password: PASSWORD,
  });
  await handle.aliases.add({
    address: "one@faulty.example", destination: "owner@faulty.example",
  });
  await handle.aliases.add({
    address: "two@faulty.example", destination: "owner@faulty.example",
  });

  // Append-only from here, so every alias erase below refuses at the
  // database rather than at a gate this layer knows the name of.
  b.db.declareWorm({ tables: ["blamepost_aliases"] });

  var destroyed = await handle.accounts.delete({
    id: owner.id, destroy: true, reason: "erasure requested by the account owner",
  });

  count("the account is kept because its aliases would not go, so no forwarding row is " +
    "left pointing at a mailbox that is not there",
    destroyed.outcome === "partially-erased" && handle.accounts.get(owner.id) !== null,
    JSON.stringify(destroyed.outcome));
  count("an alias that could not be erased is reported as a failure",
    Array.isArray(destroyed.aliasesFailed) && destroyed.aliasesFailed.length === 2,
    JSON.stringify(destroyed.aliasesFailed));
  count("a refusal nothing recognizes is never filed as a preservation order",
    Array.isArray(destroyed.aliasesPreserved) && destroyed.aliasesPreserved.length === 0,
    JSON.stringify(destroyed.aliasesPreserved));
  count("the failure carries what the address was and what went wrong",
    Array.isArray(destroyed.aliasesFailed) && destroyed.aliasesFailed[0] &&
    /@faulty\.example$/.test(String(destroyed.aliasesFailed[0].address)) &&
    typeof destroyed.aliasesFailed[0].detail === "string" &&
    destroyed.aliasesFailed[0].detail.length > 0,
    JSON.stringify(destroyed.aliasesFailed));
  count("and nothing is counted as erased that was not",
    destroyed.aliasesErased === 0, JSON.stringify(destroyed));

  var recorded = b.db.from("audit_log")
    .where({ action: "account.erasure_held" }).all()
    .filter(function (row) {
      var m = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
      return m && m.address === "owner@faulty.example";
    });
  var meta = recorded.length === 1
    ? (typeof recorded[0].metadata === "string"
      ? JSON.parse(recorded[0].metadata) : recorded[0].metadata)
    : null;
  count("the destruction is recorded once", recorded.length === 1, "rows " + recorded.length);
  count("a destruction that left a fault behind is not recorded as a clean success",
    recorded.length === 1 && recorded[0].outcome !== "success",
    recorded.length === 1 ? String(recorded[0].outcome) : "no row");
  count("and the row counts the faults rather than folding them into a refusal total",
    meta !== null && meta.aliasesFailed === 2 && meta.aliasesPreserved === 0,
    JSON.stringify(meta));
}

// ---- runner ----

async function run() {
  var root    = helpers.tempDir("store-integrity");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the run's own temporary tree keeps the encrypted-at-rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

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

    await testDomainCheckSurvivesTheHash(handle);
    await testPasswordChangeCannotVanish(handle);
    await testDisabledAliasDoesNotFallThrough(handle);
    await testDomainRemovalDoesNotRedirectAliases(handle);
    await testDomainStatusGatesSignIn(handle);
    await testConvergingAliasesAreNotLoops(handle);
    await testQuotaReaderRefusesAnUnknownAccount(handle);
    await testDomainAuditIdentity(handle);
    await testDisplayNameScreening(handle);
    await testSelectorKeyRefScreening(handle);
    await testRefusedErasureDestroysNothing(handle);
    await testAliasRefusalsAreClassified(handle);
    await testAliasEraseFaultsAreNotPreservationRefusals(handle);
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "store-integrity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
