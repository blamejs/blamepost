// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The return path a sending credential bounces through, driven on a real
 * encrypted store with two hosted domains.
 *
 * A credential may send as any local part in the domain it is scoped to,
 * and almost none of those addresses hold a mailbox, so a bounce
 * addressed back to one of them has nowhere to land and is refused at
 * the door while the application goes on sending. Each credential
 * therefore carries a return path of its own, `bounces+<tag>@<domain>`,
 * and the domain carries one alias at `bounces@<domain>` pointing at the
 * mailbox the operator named. Routing folds the plus tag away before the
 * alias lookup, so one alias carries the bounces of every credential in
 * the domain and the tag on the delivered message says whose they are.
 *
 * The tag is derived from the credential's identifier under the
 * deployment's vault-sealed key rather than being the identifier. The
 * address goes out on the envelope of everything the credential sends,
 * and the identifier is what the listener's failure budget is keyed on,
 * so this file also measures that the identifier reaches neither the
 * envelope nor the delivered message.
 *
 * Two domains rather than one, because a return path resolved against
 * the wrong domain still looks right on a server hosting a single one.
 * The two carry different shapes on purpose: nothing stands at
 * `bounces@alpha.example`, so a credential there mints the alias, and an
 * ordinary mailbox stands at `bounces@zulu.example`, so a credential
 * there needs no alias at all and one naming any other mailbox is
 * refused.
 *
 * Run standalone: node test/layer-1-state/sending-credential-return-path.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var credentials = require("../../lib/store/credentials");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALPHA = "alpha.example";
var ZULU  = "zulu.example";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The address every return path in a domain folds down to. Written out
// rather than read off the module, so the test pins the string an
// operator's DNS and mailbox layout has to agree with rather than
// echoing whatever the module currently says.
var RETURN_PATH_AT_ALPHA = "bounces@" + ALPHA;
var RETURN_PATH_AT_ZULU  = "bounces@" + ZULU;

async function refuses(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label,
    thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

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

// The actor shape a signed in session carries, which is what the mailbox
// adapter files a delivered message against.
function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// A delivery status notification of the shape RFC 3464 defines,
// addressed to the return path under test. The tag is inside the message
// as well as on the envelope, because the tag surviving into the
// delivered `To` is what lets the bounce mailbox tell one credential's
// bounces from another's.
function deliveryReport(returnPath, refusedRecipient) {
  var boundary = "report-boundary-0001";
  return Buffer.from(
    "From: Mail Delivery Subsystem <MAILER-DAEMON@partner.example.net>\r\n" +
    "To: " + returnPath + "\r\n" +
    "Subject: Returned mail: see transcript for details\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <dsn-" + refusedRecipient.replace(/[^A-Za-z0-9]/g, "") +
      "@partner.example.net>\r\n" +
    "Content-Type: multipart/report; report-type=delivery-status; " +
      "boundary=\"" + boundary + "\"\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/plain; charset=us-ascii\r\n" +
    "\r\n" +
    "The message could not be delivered to " + refusedRecipient + ".\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: message/delivery-status\r\n" +
    "\r\n" +
    "Reporting-MTA: dns; partner.example.net\r\n" +
    "\r\n" +
    "Final-Recipient: rfc822; " + refusedRecipient + "\r\n" +
    "Action: failed\r\n" +
    "Status: 5.1.1\r\n" +
    "\r\n" +
    "--" + boundary + "--\r\n", "utf8");
}

// Deliver one message the way the inbound path does: resolve the
// recipient, keep the targets the store says are deliverable, and append
// to each. Nothing here decides where mail goes, which is the point: the
// answer under test is the store's.
function deliverAsTheMxWould(handle, recipient, body) {
  var verdict = handle.resolve(recipient);
  if (!verdict.deliverable) return { verdict: verdict, landedIn: [] };
  var landed = [];
  verdict.targets.forEach(function (target) {
    if (target.deliverable !== true || target.local !== true) return;
    var account = handle.accounts.get(target.mailbox);
    handle.mailbox.appendMessage("INBOX", body, { actor: actorFor(account), flags: [] });
    landed.push(target.mailbox);
  });
  return { verdict: verdict, landedIn: landed };
}

// Every message sitting in one mailbox, as text.
function inboxOf(handle, mailboxAddress) {
  var actor = actorFor(handle.accounts.get(mailboxAddress));
  var selected = handle.mailbox.selectFolder(actor, "INBOX", {});
  if (selected.exists === 0) return [];
  return handle.mailbox.fetchRange(actor, "INBOX", "1:*", "BODY.PEEK[]", {})
    .map(function (row) { return String(row.payload); });
}

function aliasRowsAt(handle, at) {
  return handle.aliases.list({ address: at, includeDisabled: true });
}

// ---------------------------------------------------------------------------

async function seedTwoDomains(handle) {
  await handle.domains.add({ domain: ALPHA });
  await handle.domains.add({ domain: ZULU });

  // Nothing at bounces@alpha.example, so a credential in that domain has
  // to put the alias there itself.
  await handle.accounts.create({
    address: "root@" + ALPHA, password: ACCOUNT_PASSWORD, isAdmin: true });
  await handle.accounts.create({
    address: "mailops@" + ALPHA, password: ACCOUNT_PASSWORD });
  await handle.accounts.create({
    address: "elsewhere@" + ALPHA, password: ACCOUNT_PASSWORD });

  // An ordinary mailbox standing exactly at bounces@zulu.example, which
  // is the layout where no alias is wanted and where naming any other
  // mailbox cannot be honored.
  await handle.accounts.create({
    address: "ops@" + ZULU, password: ACCOUNT_PASSWORD, isAdmin: true });
  await handle.accounts.create({
    address: "bounces@" + ZULU, password: ACCOUNT_PASSWORD });
  await handle.accounts.create({
    address: "other@" + ZULU, password: ACCOUNT_PASSWORD });
}

function registryFor(handle) {
  return credentials.create({
    domains:  handle.domains,
    accounts: handle.accounts,
    aliases:  handle.aliases,
    resolve:  handle.resolve,
  });
}

// ---- the mechanism this whole design rests on ----

// Before anything is built on the tag fold, prove it. One alias carries
// every credential in a domain only because routing strips the tag before
// it looks the address up. If it did not, each credential would need an
// alias row of its own, and the design everything below rests on would be
// the wrong shape.
async function testTheTagFolds(handle) {
  await handle.aliases.add({
    address: RETURN_PATH_AT_ALPHA, destination: "mailops@" + ALPHA });

  var tagged = handle.resolve("bounces+0123456789abcdef@" + ALPHA);
  count("routing folds an RFC 5233 tag away and looks the mailbox up without it",
    tagged.address === RETURN_PATH_AT_ALPHA, tagged.address);
  count("and it hands the tag back rather than discarding it",
    tagged.tag === "0123456789abcdef", String(tagged.tag));
  count("and the address as written keeps the tag, which is what reaches the delivered To",
    tagged.written === "bounces+0123456789abcdef@" + ALPHA, tagged.written);
  count("a tagged address matches the alias on the untagged one",
    tagged.kind === "alias" && tagged.deliverable === true, JSON.stringify(tagged));
  count("and it delivers to the mailbox that alias names",
    tagged.targets.length === 1 && tagged.targets[0].mailbox === "mailops@" + ALPHA,
    JSON.stringify(tagged.targets));

  count("the tag is folded whatever it says, so one alias carries every credential",
    handle.resolve("bounces+fedcba9876543210@" + ALPHA).targets[0].mailbox ===
      "mailops@" + ALPHA);

  // The address the whole design exists for. An ordinary local part in a
  // domain a credential may send as holds no mailbox, so a bounce
  // addressed there is refused rather than delivered.
  var receipts = handle.resolve("receipts@" + ALPHA);
  count("an address with no mailbox is local and undeliverable",
    receipts.local === true && receipts.deliverable === false, JSON.stringify(receipts));
  count("and the reason is the one a listener answers 550 5.1.1 to",
    receipts.reason === "no-such-mailbox", String(receipts.reason));

  // Fixed resolution order: the alias wins over the catch-all, and the
  // account wins where there is no alias. Both matter here, because the
  // return path is an alias in one domain and an account in the other.
  var atAccount = handle.resolve("bounces+abcdef0123456789@" + ZULU);
  count("with no alias in the way, a tagged address resolves to the account holding it",
    atAccount.kind === "account" && atAccount.deliverable === true, JSON.stringify(atAccount));
  count("and the account it resolves to is the untagged one",
    atAccount.targets.length === 1 && atAccount.targets[0].mailbox === RETURN_PATH_AT_ZULU,
    JSON.stringify(atAccount.targets));

  await handle.aliases.remove({
    address: RETURN_PATH_AT_ALPHA, destination: "mailops@" + ALPHA,
    reason: "the registry mints its own from here on" });
  count("the hand-made alias is gone again", aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 0,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));
}

// ---- construction ----

function testConstructionRefusals(handle) {
  var thrown = null;
  try {
    credentials.create({ domains: handle.domains, accounts: handle.accounts,
      resolve: handle.resolve });
  } catch (e) { thrown = e; }
  count("a registry built with no alias handle refuses at construction",
    thrown !== null && thrown instanceof TypeError,
    thrown === null ? "nothing was thrown" : String(thrown.message));

  var second = null;
  try {
    credentials.create({ domains: handle.domains, accounts: handle.accounts,
      aliases: handle.aliases });
  } catch (e) { second = e; }
  count("a registry built with no way to resolve an address refuses at construction",
    second !== null && second instanceof TypeError,
    second === null ? "nothing was thrown" : String(second.message));
}

// ---- creation mints the alias ----

async function testCreationMintsTheAlias(reg, handle) {
  var made = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "mailops@" + ALPHA,
    reason:        "the shop front sends receipts",
  });

  count("a created credential names the return path its bounces come back to",
    made.returnPath === "bounces+" + made.returnPathTag + "@" + ALPHA, String(made.returnPath));
  count("the return path is at the credential's own domain",
    made.returnPath.indexOf("@" + ALPHA) !== -1, made.returnPath);
  count("and it carries a derived tag, so one alias serves them all",
    made.returnPath.indexOf("+" + made.returnPathTag + "@") !== -1, made.returnPath);
  count("and the tag is not the identifier, which is what the failure budget on the " +
    "listener is keyed on and what a recipient of this credential's mail would otherwise " +
    "be holding",
    made.returnPathTag !== made.id && made.returnPath.indexOf(made.id) === -1,
    made.returnPath + " vs id " + made.id);

  var rows = aliasRowsAt(handle, RETURN_PATH_AT_ALPHA);
  count("creation puts one alias at the domain's return path address",
    rows.length === 1, JSON.stringify(rows));
  count("and it points at the mailbox the credential named",
    rows.length === 1 && rows[0].destinationMailbox === "mailops@" + ALPHA,
    rows.length === 1 ? rows[0].destinationMailbox : "no row");
  count("and it is in service rather than created disabled",
    rows.length === 1 && rows[0].status === "active",
    rows.length === 1 ? rows[0].status : "no row");

  count("the credential's own return path resolves to the mailbox it named",
    handle.resolve(made.returnPath).targets.map(function (t) { return t.mailbox; })
      .join(",") === "mailops@" + ALPHA,
    JSON.stringify(handle.resolve(made.returnPath).targets));

  count("blamepost.store.credentials.verify hands the return path to whoever is sending",
    (await reg.verify(made.token)).returnPath === made.returnPath,
    String((await reg.verify(made.token)).returnPath));
  count("a refused verify names no return path rather than one built from nothing",
    (await reg.verify("")).returnPath === null,
    String((await reg.verify("")).returnPath));

  return made;
}

// ---- the discriminating delivery vector ----

async function testDeliveryLandsInTheNamedMailbox(reg, handle, made) {
  var report = deliveryReport(made.returnPath, "receipts-reader@partner.example.net");
  var delivered = deliverAsTheMxWould(handle, made.returnPath, report);

  count("a delivery report addressed to the return path is deliverable",
    delivered.verdict.deliverable === true, JSON.stringify(delivered.verdict));
  count("and it lands in the mailbox the credential named",
    delivered.landedIn.join(",") === "mailops@" + ALPHA, delivered.landedIn.join(","));

  var inbox = inboxOf(handle, "mailops@" + ALPHA);
  count("the mailbox holds the report",
    inbox.length === 1, String(inbox.length));
  count("and the report still carries the tag, so the mailbox can tell whose bounce it is",
    inbox.length === 1 &&
      inbox[0].indexOf("bounces+" + made.returnPathTag + "@" + ALPHA) !== -1,
    inbox.length === 1 ? inbox[0].slice(0, 200) : "no message");

  // The address the same application sends AS, which holds no mailbox.
  // Every bounce addressed there is refused, which is the whole reason
  // the return path is somewhere else.
  var toTheSendingAddress = deliverAsTheMxWould(handle, "receipts@" + ALPHA, report);
  count("a report addressed to the local part the credential sends as is refused",
    toTheSendingAddress.verdict.deliverable === false,
    JSON.stringify(toTheSendingAddress.verdict));
  count("and nothing is delivered anywhere for it",
    toTheSendingAddress.landedIn.length === 0, toTheSendingAddress.landedIn.join(","));
  count("and the refusal is local rather than a domain this server never heard of",
    toTheSendingAddress.verdict.local === true &&
    toTheSendingAddress.verdict.reason === "no-such-mailbox",
    JSON.stringify(toTheSendingAddress.verdict));
  count("the named mailbox still holds only the one report it was sent",
    inboxOf(handle, "mailops@" + ALPHA).length === 1,
    String(inboxOf(handle, "mailops@" + ALPHA).length));
}

// ---- the tag says which credential ----

async function testTheTagNamesTheCredential(reg, handle, first) {
  var second = await reg.create({
    domain:        ALPHA,
    bounceMailbox: "mailops@" + ALPHA,
    reason:        "the newsletter sends from the same domain",
  });

  count("a second credential in the domain gets a return path of its own",
    second.returnPath !== first.returnPath, second.returnPath + " vs " + first.returnPath);
  count("and the two differ only in the tag, so they share one alias",
    second.returnPath.split("+")[0] === first.returnPath.split("+")[0],
    second.returnPath + " / " + first.returnPath);
  count("the domain still carries exactly one alias for both of them",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));

  deliverAsTheMxWould(handle, second.returnPath,
    deliveryReport(second.returnPath, "newsletter-reader@partner.example.net"));

  var inbox = inboxOf(handle, "mailops@" + ALPHA);
  count("both credentials' reports land in the one mailbox",
    inbox.length === 2, String(inbox.length));

  var carryingFirst = inbox.filter(function (text) {
    return text.indexOf("+" + first.returnPathTag + "@") !== -1;
  });
  var carryingSecond = inbox.filter(function (text) {
    return text.indexOf("+" + second.returnPathTag + "@") !== -1;
  });
  count("and one of them names the first credential",
    carryingFirst.length === 1, String(carryingFirst.length));
  count("and the other names the second",
    carryingSecond.length === 1, String(carryingSecond.length));
  count("and no message carries both tags, so the tag really separates them",
    carryingFirst[0] !== carryingSecond[0]);
  count("and neither carries either credential's identifier, which is the value the " +
    "listener's failure budget is keyed on and is not one to hand a correspondent",
    inbox.every(function (text) {
      return text.indexOf(first.id) === -1 && text.indexOf(second.id) === -1;
    }), String(inbox.length) + " message(s) read");

  // The tag is on the envelope too, which is what a Sieve rule in the
  // bounce mailbox files on.
  count("resolving the second return path reports its tag rather than the first's",
    handle.resolve(second.returnPath).tag === second.returnPathTag,
    String(handle.resolve(second.returnPath).tag));

  count("and the tag on the envelope names the credential it came from, so the operator " +
    "reading the mailbox is not left holding a value nothing resolves",
    (await reg.byReturnPathTag({
      domain: ALPHA, tag: handle.resolve(second.returnPath).tag })).id === second.id,
    second.id);

  return second;
}

// ---- what creation does about an alias that is already there ----

async function testCreationRefusesAConflictingAlias(reg, handle) {
  await refusesNaming("a credential naming a different bounce mailbox than the alias " +
    "already at the return path refuses, and names both",
    "store/return-path-taken", [RETURN_PATH_AT_ALPHA, "mailops@" + ALPHA,
      "elsewhere@" + ALPHA], function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "elsewhere@" + ALPHA,
        reason: "this one wants its own bounce mailbox" });
    });
  count("and the alias that was already there is untouched",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1 &&
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)[0].destinationMailbox === "mailops@" + ALPHA,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));

  // A second leg on the return path sends a copy of every bounce
  // somewhere the operator did not name for this credential, and a
  // bounce carries the recipients that rejected the mail.
  await handle.aliases.add({
    address: RETURN_PATH_AT_ALPHA, destination: "elsewhere@" + ALPHA });
  await refuses("a return path that fans out to a mailbox the credential did not name refuses",
    "store/return-path-taken", function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
        reason: "the fan-out was added behind the registry" });
    });
  await handle.aliases.remove({
    address: RETURN_PATH_AT_ALPHA, destination: "elsewhere@" + ALPHA,
    reason: "putting the return path back to one leg" });

  // A disabled alias delivers nothing and does not fall through to the
  // catch-all, so a credential created against one bounces into a
  // refusal from its first message.
  var row = aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)[0];
  await handle.aliases.setStatus({
    id: row.id, status: "disabled", reason: "operator turned it off" });
  await refusesNaming("a credential created while the return path alias is disabled refuses",
    "store/return-path-disabled", [RETURN_PATH_AT_ALPHA], function () {
      return reg.create({
        domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
        reason: "the alias is off and nobody noticed" });
    });
  await handle.aliases.setStatus({
    id: row.id, status: "active", reason: "operator turned it back on" });

  var reused = await reg.create({
    domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
    reason: "this one shares the return path that is already there" });
  count("a credential naming the mailbox the alias already points at is accepted",
    reused.returnPath === "bounces+" + reused.returnPathTag + "@" + ALPHA,
    String(reused.returnPath));
  count("and no second alias is written for it",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));

  return reused;
}

// ---- a mailbox standing at the return path address ----

async function testAccountAtTheReturnPath(reg, handle) {
  var made = await reg.create({
    domain:        ZULU,
    bounceMailbox: RETURN_PATH_AT_ZULU,
    reason:        "the domain already has a bounce mailbox of its own" });

  count("a credential whose bounce mailbox already stands at the return path is created",
    made.returnPath === "bounces+" + made.returnPathTag + "@" + ZULU, String(made.returnPath));
  count("and no alias is written, because the mailbox is already the thing that answers",
    aliasRowsAt(handle, RETURN_PATH_AT_ZULU).length === 0,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ZULU)));
  count("and the return path still resolves to that mailbox",
    handle.resolve(made.returnPath).targets.map(function (t) { return t.mailbox; })
      .join(",") === RETURN_PATH_AT_ZULU,
    JSON.stringify(handle.resolve(made.returnPath).targets));

  // The mailbox cannot be aliased away and routing reaches it first, so
  // a credential naming anything else would have its bounces delivered
  // to a mailbox the operator chose for something else.
  await refusesNaming("a credential in that domain naming any other bounce mailbox refuses, " +
    "and names the mailbox that is in the way",
    "store/return-path-taken", [RETURN_PATH_AT_ZULU, "other@" + ZULU], function () {
      return reg.create({
        domain: ZULU, bounceMailbox: "other@" + ZULU,
        reason: "this one wants its bounces somewhere else" });
    });
  count("and nothing was written for the refused credential",
    aliasRowsAt(handle, RETURN_PATH_AT_ZULU).length === 0,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ZULU)));

  return made;
}

// ---- the archived bounce mailbox ----

// The worst failure in this area: creation checked the mailbox, the
// mailbox was archived afterwards, and every bounce is refused at the
// door while the application keeps sending. Nothing about the credential
// changed, so only a reading of what the return path resolves to now can
// find it.
async function testArchivedBounceMailboxIsVisible(reg, handle, made) {
  count("the return path is deliverable while the mailbox is in service",
    (await reg.show(made.id)).returnPathDeliverable === true,
    JSON.stringify(await reg.show(made.id)));

  await handle.accounts.delete({
    id:     handle.accounts.get("mailops@" + ALPHA).id,
    reason: "the person who read it left" });

  var routed = handle.resolve(made.returnPath);
  count("an archived bounce mailbox leaves the return path local and undeliverable",
    routed.local === true && routed.deliverable === false, JSON.stringify(routed));

  var shown = await reg.show(made.id);
  count("blamepost.store.credentials.show reports that the return path no longer delivers",
    shown.returnPathDeliverable === false, JSON.stringify(shown));
  count("and it names the return path the bounces are being refused at",
    shown.returnPath === made.returnPath, String(shown.returnPath));
  count("and it says why rather than only that something is wrong",
    typeof shown.returnPathReason === "string" && shown.returnPathReason.length > 0,
    String(shown.returnPathReason));

  var listed = (await reg.list({ domain: ALPHA })).filter(function (r) {
    return r.id === made.id;
  });
  count("blamepost.store.credentials.list carries the same reading, so an operator " +
    "reading the domain sees it without asking per credential",
    listed.length === 1 && listed[0].returnPathDeliverable === false,
    JSON.stringify(listed));

  var report = await reg.returnPathReport({ domain: ALPHA });
  count("blamepost.store.credentials.returnPathReport names the domain's return path address",
    report.returnPathAddress === RETURN_PATH_AT_ALPHA, String(report.returnPathAddress));
  count("and it lists the credential whose bounces are going nowhere",
    report.unreachable.some(function (row) { return row.credentialId === made.id; }),
    JSON.stringify(report.unreachable));
  count("and the finding names the mailbox the credential is still pointing at",
    report.unreachable.some(function (row) {
      return row.bounceMailbox === "mailops@" + ALPHA;
    }), JSON.stringify(report.unreachable));
  count("and the other domain, whose mailbox is fine, reports nothing unreachable",
    (await reg.returnPathReport({ domain: ZULU })).unreachable.length === 0,
    JSON.stringify((await reg.returnPathReport({ domain: ZULU })).unreachable));

  await refuses("a report for a domain this server does not host refuses",
    "store/no-such-domain", function () {
      return reg.returnPathReport({ domain: "not-hosted.example" });
    });
  await refuses("a report with no domain at all refuses",
    "store/bad-argument", function () { return reg.returnPathReport({}); });

  await handle.accounts.reinstate({
    id:     handle.accounts.get("mailops@" + ALPHA).id,
    reason: "somebody else reads it now" });
  count("reinstating the mailbox makes the return path deliverable again",
    (await reg.show(made.id)).returnPathDeliverable === true,
    JSON.stringify(await reg.show(made.id)));

  // A return path that delivers somewhere other than the mailbox the
  // credential names is not a working return path either: a bounce
  // carries the recipients that rejected the mail.
  var row = aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)[0];
  await handle.aliases.remove({
    id: row.id, reason: "pointing the return path somewhere else by hand" });
  await handle.aliases.add({
    address: RETURN_PATH_AT_ALPHA, destination: "elsewhere@" + ALPHA });
  var repointed = await reg.show(made.id);
  count("a return path repointed at another mailbox is reported as not delivering",
    repointed.returnPathDeliverable === false, JSON.stringify(repointed));
  count("and the reading says where it actually lands",
    repointed.returnPathDeliversTo.join(",") === "elsewhere@" + ALPHA,
    repointed.returnPathDeliversTo.join(","));

  await handle.aliases.remove({
    address: RETURN_PATH_AT_ALPHA, destination: "elsewhere@" + ALPHA,
    reason: "putting it back" });
  await handle.aliases.add({
    address: RETURN_PATH_AT_ALPHA, destination: "mailops@" + ALPHA });
}

// ---- withdrawal ----

async function testWithdrawalKeepsAndThenRemovesTheAlias(reg, handle) {
  var live = (await reg.list({ domain: ALPHA }));
  count("the domain has more than one credential before anything is withdrawn",
    live.length > 1, String(live.length));

  var capture = helpers.auditCapture();
  var first;
  try {
    first = await reg.revoke({ id: live[0].id, reason: "the first application went away" });
  } finally { capture.release(); }

  count("revoking one of several credentials leaves the shared alias alone",
    first.returnPathAliasRemoved === false, JSON.stringify(first));
  count("and the alias is still there for the credentials that remain",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));
  var rows = capture.forAction("domain.sending_credential_revoked");
  count("and the audit row says the alias was kept rather than leaving it unrecorded",
    rows.length === 1 && helpers.metadataOf(rows[0]).returnPathAliasRemoved === false,
    rows.length === 1 ? JSON.stringify(helpers.metadataOf(rows[0])) : "no row");

  var remaining = await reg.list({ domain: ALPHA });
  count("the credentials that were not revoked are still listed",
    remaining.length === live.length - 1, String(remaining.length));

  // Withdraw every one that is left. The alias goes with the last of
  // them and not before.
  var last = null;
  for (var i = 0; i < remaining.length; i += 1) {
    count("the alias is still there while credential " + (i + 1) + " of " +
      remaining.length + " has not been withdrawn",
      aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
      JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));
    last = await reg.revoke({
      id: remaining[i].id, reason: "the last application went away" });
  }

  count("withdrawing the last credential in the domain takes the alias with it",
    last !== null && last.returnPathAliasRemoved === true, JSON.stringify(last));
  count("and the return path address holds nothing afterwards",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 0,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));
  count("so a report addressed to the old return path is refused rather than delivered",
    handle.resolve("bounces+0123456789abcdef@" + ALPHA).deliverable === false,
    JSON.stringify(handle.resolve("bounces+0123456789abcdef@" + ALPHA)));
}

// A credential that reuses an alias the operator put there borrowed it.
// Taking it away on withdrawal would stop mail the operator was
// receiving through an address they created for their own reasons.
async function testWithdrawalLeavesAnAliasItDidNotMint(reg, handle) {
  await handle.aliases.add({
    address: RETURN_PATH_AT_ALPHA, destination: "mailops@" + ALPHA });
  var borrowed = await reg.create({
    domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
    reason: "sharing an address the operator already created" });

  var withdrawn = await reg.remove({
    id: borrowed.id, destroy: true, reason: "the application was decommissioned" });
  count("withdrawing the last credential does not remove an alias it did not mint",
    withdrawn.returnPathAliasRemoved === false, JSON.stringify(withdrawn));
  count("and the operator's own alias is still there",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));

  await handle.aliases.remove({
    address: RETURN_PATH_AT_ALPHA, destination: "mailops@" + ALPHA,
    reason: "the operator is done with it" });
}

// Removal takes the row off the volume and has to reach the alias the
// same way revoking does, or the erasure leaves a routing row behind
// naming a mailbox nothing sends to any more.
async function testRemovalReachesTheAlias(reg, handle) {
  var made = await reg.create({
    domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
    reason: "checking that removal reaches the alias too" });
  count("creating again after the alias went mints a fresh one",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 1,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));

  var capture = helpers.auditCapture();
  var removed;
  try {
    removed = await reg.remove({
      id: made.id, destroy: true, reason: "the operator asked for erasure" });
  } finally { capture.release(); }

  count("blamepost.store.credentials.remove reports what happened to the alias",
    removed.returnPathAliasRemoved === true, JSON.stringify(removed));
  count("and the alias is off the volume with the credential",
    aliasRowsAt(handle, RETURN_PATH_AT_ALPHA).length === 0,
    JSON.stringify(aliasRowsAt(handle, RETURN_PATH_AT_ALPHA)));
  var rows = capture.forAction("domain.sending_credential_removed");
  count("and the audit row records the alias going, so the routing change is answerable",
    rows.length === 1 && helpers.metadataOf(rows[0]).returnPathAliasRemoved === true,
    rows.length === 1 ? JSON.stringify(helpers.metadataOf(rows[0])) : "no row");
}

// The account standing at the return path was never this registry's, so
// withdrawing the credential that used it must not reach for it.
async function testWithdrawalLeavesTheAccountAlone(reg, handle, made) {
  var withdrawn = await reg.remove({
    id: made.id, destroy: true, reason: "the application was decommissioned" });
  count("withdrawing a credential whose return path was a mailbox removes no alias",
    withdrawn.returnPathAliasRemoved === false, JSON.stringify(withdrawn));
  count("and the mailbox is still there",
    handle.accounts.get(RETURN_PATH_AT_ZULU) !== null &&
    handle.accounts.get(RETURN_PATH_AT_ZULU).status === "active",
    JSON.stringify(handle.accounts.get(RETURN_PATH_AT_ZULU)));
}

// ---- the two domains do not reach into each other ----

async function testReturnPathsStayInTheirDomain(reg, handle) {
  var alpha = await reg.create({
    domain: ALPHA, bounceMailbox: "mailops@" + ALPHA,
    reason: "checking a return path stays in its own domain" });
  var zulu = await reg.create({
    domain: ZULU, bounceMailbox: RETURN_PATH_AT_ZULU,
    reason: "checking a return path stays in its own domain" });

  count("each credential's return path is at its own domain",
    alpha.returnPath.indexOf("@" + ALPHA) !== -1 &&
    zulu.returnPath.indexOf("@" + ZULU) !== -1,
    alpha.returnPath + " / " + zulu.returnPath);

  count("one domain's return path delivers into its own mailbox",
    handle.resolve(alpha.returnPath).targets[0].mailbox === "mailops@" + ALPHA,
    JSON.stringify(handle.resolve(alpha.returnPath).targets));
  count("and the other's into its own",
    handle.resolve(zulu.returnPath).targets[0].mailbox === RETURN_PATH_AT_ZULU,
    JSON.stringify(handle.resolve(zulu.returnPath).targets));

  // One credential's tag carried to the other domain reaches that
  // domain's mailbox and not the credential's own, which is why the tag
  // alone is never the routing decision.
  count("a credential's tag written at the other domain reaches that domain's mailbox",
    handle.resolve("bounces+" + alpha.returnPathTag + "@" + ZULU).targets[0].mailbox ===
      RETURN_PATH_AT_ZULU,
    JSON.stringify(handle.resolve("bounces+" + alpha.returnPathTag + "@" + ZULU).targets));

  count("and the lookup that names a credential from a tag is scoped to the domain the " +
    "address was written at, so a tag carried to another domain names nothing there",
    (await reg.byReturnPathTag({ domain: ZULU, tag: alpha.returnPathTag })) === null,
    alpha.returnPathTag + " at " + ZULU);

  await reg.remove({ id: alpha.id, destroy: true, reason: "done with it" });
  await reg.remove({ id: zulu.id,  destroy: true, reason: "done with it" });
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-returnpath-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

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

    await testTheTagFolds(handle);
    testConstructionRefusals(handle);

    registry = registryFor(handle);

    var first = await testCreationMintsTheAlias(registry, handle);
    await testDeliveryLandsInTheNamedMailbox(registry, handle, first);
    await testTheTagNamesTheCredential(registry, handle, first);
    await testCreationRefusesAConflictingAlias(registry, handle);
    var atZulu = await testAccountAtTheReturnPath(registry, handle);
    await testArchivedBounceMailboxIsVisible(registry, handle, first);
    await testWithdrawalKeepsAndThenRemovesTheAlias(registry, handle);
    await testWithdrawalLeavesAnAliasItDidNotMint(registry, handle);
    await testRemovalReachesTheAlias(registry, handle);
    await testWithdrawalLeavesTheAccountAlone(registry, handle, atZulu);
    await testReturnPathsStayInTheirDomain(registry, handle);
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

module.exports = {
  name: "sending-credential-return-path", run: run, getChecks: helpers.getChecks,
};

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
