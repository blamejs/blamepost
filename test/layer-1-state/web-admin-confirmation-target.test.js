// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether what an operator confirms on the console is the thing the
 * console acts on, and whether values that came from somebody else reach
 * a console page as text.
 *
 * `test/layer-1-state/web-admin-confirmation.test.js` asks whether each
 * irreversible act asks first. This file asks what the typed value
 * confirms. The value exists to catch a press on the wrong row, so it has
 * to differ between the rows a press can land on by mistake. Two pairs of
 * adjacent rows share their obvious name:
 *
 *   - Signing pairs minted in the same month carry the same selector on
 *     every domain, because the default selector is `bp<YYYYMM>`. The
 *     selector alone confirms the retirement of any of them.
 *   - The legs of a fan-out alias share their source address, and a
 *     catch-all that delivers to several destinations shares its domain.
 *     The address alone confirms the removal of any leg.
 *
 * The same question is asked of the request fields a confirmation carries:
 * an identifier repeated, an action repeated, a JSON body carrying an
 * object where a string belongs, an identifier swapped between the page
 * and the post, and an identifier written as the address it resolves to.
 *
 * Creating an account is asked about separately. Giving an account the
 * operator role asks for a reason and files `account.role_granted`, and
 * the operator guide says the console gives the role to an existing
 * account and nowhere else. The account creation form must not grant it
 * without either.
 *
 * The last section plants values somebody other than the operator
 * controls: a queued message's addresses and the far side's reply, a
 * display name, an author address a mailbox owner typed that lands in the
 * audit trail, and query strings the console echoes. It reads every
 * console page that shows them for markup that was not escaped.
 *
 * Run standalone: node test/layer-1-state/web-admin-confirmation-target.test.js
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

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALPHA    = "alpha.example";
var BRAVO    = "bravo.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 5512";
var OTHER_PASSWORD   = "another operator passphrase 8841";

// The only administrator on this server. Several cases below depend on it
// being the only one.
var OPERATOR = "adam@" + DOMAIN;

var FIRST_SUBJECT  = "fern@" + DOMAIN;
var SECOND_SUBJECT = "gus@" + DOMAIN;
var BY_ADDRESS     = "hana@" + DOMAIN;
var NEW_ACCOUNT    = "ivo@" + DOMAIN;
var NEW_OPERATOR   = "jude@" + DOMAIN;

var TEAM       = "team@" + DOMAIN;
var TEAM_ALICE = "alice@example.net";
var TEAM_BOB   = "bob@example.net";
var SOLO       = "solo@" + DOMAIN;
var SOLO_DEST  = "solo-dest@example.net";
var CATCH_ONE  = "catch-one@example.net";
var CATCH_TWO  = "catch-two@example.net";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Hostile values a stranger controls. Each carries a marker that appears
// nowhere else in a page, so finding the raw marker is the finding.
var HOSTILE_RECIPIENT = "\"><img src=x onerror=alert(101)>@example.net";
var HOSTILE_SENDER    = "x\" onmouseover=\"alert(102)@example.net";
var HOSTILE_REASON    = "550 5.1.1 <script>alert(103)</script> 'quoted'";
var HOSTILE_CODE      = "</code><b>alert(104)</b>";
var HOSTILE_NAME      = "<img src=x onerror=alert(105)>\"'";
var HOSTILE_AUTHOR    = "<svg/onload=alert(106)>@evil.example";
var HOSTILE_FILTER    = "\"><script>alert(107)</script>";
var HOSTILE_LOOKUP    = "<script>alert(108)</script>@example.com";

var RAW_MARKERS = [
  "<img src=x onerror=alert(101)>",
  "onmouseover=\"alert(102)",
  "<script>alert(103)</script>",
  "<b>alert(104)</b>",
  "<img src=x onerror=alert(105)>",
  "<svg/onload=alert(106)>",
  "<script>alert(107)</script>",
  "<script>alert(108)</script>",
];

// The single-byte CSI, built rather than written. A C1 control cannot be
// carried through a source file: an editor writing this file replaces it
// with a space, so a literal here would assert nothing and pass.
var CSI  = String.fromCharCode(0x9b);
var HTAB = String.fromCharCode(0x09);

// A display name carrying one. The console prints account display names,
// and an operator reads console pages in a browser and reads the same
// values back out of `blamepost audit read` in a terminal, where a C1
// control is the start of an escape sequence rather than a character.
var C1_NAME = "Casey" + CSI + "31mRed";
var TAB_NAME = "Casey" + HTAB + "Tabbed";

var HOSTILE_ID = "c0ffee00c0ffee00c0ffee00c0ffee00";

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

// Nothing in this file should reach a socket. A report a cancellation
// causes stops on the outbound spool.
var UNANSWERING = {
  queryMx:   function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTxt:  function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTlsa: function () { return Promise.reject(new Error("no resolver in this test")); },
};

function _asRows(value) { return Array.isArray(value) ? value : []; }

function noticeOf(answer) {
  var location = String(answer.location || "");
  var at = location.indexOf("notice=");
  return at === -1 ? "" : location.slice(at + "notice=".length).split("&")[0];
}

function describe(answer) {
  return answer.status + " " + String(answer.location) + " " +
    String(answer.body || "").slice(0, 160);
}

// ---- retiring a signing pair -----------------------------------------------

function activeEd25519(dkim, domain) {
  return dkim.list(domain).filter(function (row) {
    return row.state === "active" && row.algorithm === "ed25519";
  });
}

function recordNameOf(selector, domain) {
  return selector + "._domainkey." + domain;
}

async function testASelectorNameSharedByTwoDomainsConfirmsNeither(operator, dkim) {
  var alpha = activeEd25519(dkim, ALPHA);
  var bravo = activeEd25519(dkim, BRAVO);
  count("both domains hold one active signing pair", alpha.length === 1 && bravo.length === 1,
    JSON.stringify([alpha.length, bravo.length]));
  var selector = bravo[0].selector;
  count("and the two pairs carry the same selector, which is the default for a pair minted " +
    "this month on any domain", alpha[0].selector === selector,
  alpha[0].selector + " and " + selector);

  var asked = await operator.form("/admin/dkim",
    { action: "retire", domain: BRAVO, selector: selector });
  count("retiring the second domain's pair asks first", asked.status === 200 &&
    noticeOf(asked) === "", describe(asked));
  count("and the page names the record that pair publishes, which names its domain",
    String(asked.body).indexOf(recordNameOf(selector, BRAVO)) !== -1, describe(asked));

  var bySelector = await operator.form("/admin/dkim",
    { action: "retire", domain: BRAVO, selector: selector, confirm: selector });
  count("typing the selector alone, which names the first domain's pair as well, does not " +
    "retire the second domain's pair", noticeOf(bySelector) !== "keys-retiring",
  describe(bySelector));
  count("and the second domain still signs", activeEd25519(dkim, BRAVO).length === 1,
    JSON.stringify(dkim.list(BRAVO)));

  var byOther = await operator.form("/admin/dkim", {
    action: "retire", domain: BRAVO, selector: selector,
    confirm: recordNameOf(selector, ALPHA),
  });
  count("typing the first domain's record name does not retire the second domain's pair",
    noticeOf(byOther) !== "keys-retiring" && activeEd25519(dkim, BRAVO).length === 1,
    describe(byOther));

  var byRecord = await operator.form("/admin/dkim", {
    action: "retire", domain: BRAVO, selector: selector,
    confirm: recordNameOf(selector, BRAVO),
  });
  count("typing the record name the page showed retires that pair",
    byRecord.status === 302 && noticeOf(byRecord) === "keys-retiring", describe(byRecord));
  count("so the second domain no longer signs with it", activeEd25519(dkim, BRAVO).length === 0,
    JSON.stringify(dkim.list(BRAVO)));
  count("and the first domain's pair of the same name is untouched",
    activeEd25519(dkim, ALPHA).length === 1, JSON.stringify(dkim.list(ALPHA)));
}

// The page names what the server holds rather than what the request said.
// A pair the domain does not hold is refused before anything is asked, and
// a domain typed in another case with the root dot names the pair under
// its folded name.
async function testTheRetirePageNamesAPairTheServerHolds(operator, dkim) {
  var none = await operator.form("/admin/dkim",
    { action: "retire", domain: ALPHA, selector: "bp199001" });
  count("a selector the domain does not hold is refused before the page asks anything",
    none.status === 400 && String(none.body).indexOf("name=\"confirm\"") === -1,
    describe(none));

  var selector = activeEd25519(dkim, ALPHA)[0].selector;
  var spelled = "ALPHA.example.";
  var asked = await operator.form("/admin/dkim",
    { action: "retire", domain: spelled, selector: selector });
  count("a domain typed in another case with the root dot is asked about under its folded name",
    asked.status === 200 && String(asked.body).indexOf(recordNameOf(selector, ALPHA)) !== -1,
    describe(asked));
  count("and the typed spelling is not what the page names",
    String(asked.body).indexOf(recordNameOf(selector, spelled)) === -1, describe(asked));
}

// ---- removing one leg of a fan-out -----------------------------------------

function legsOf(identity, source) {
  return identity.aliases.list({ address: source, includeDisabled: true });
}

function catchAllLegs(identity) {
  return identity.aliases.list({ catchAllFor: DOMAIN, includeDisabled: true });
}

async function testAnAddressSharedByTwoLegsConfirmsNeither(operator, identity) {
  var legs = legsOf(identity, TEAM);
  count("the fan-out holds two legs under one address", legs.length === 2,
    JSON.stringify(legs.map(function (l) { return l.destination; })));
  var bobLeg = legs.filter(function (l) { return l.destination === TEAM_BOB; })[0];

  var asked = await operator.form("/admin/aliases", { action: "remove", id: bobLeg.id });
  count("removing one leg asks first", asked.status === 200 && noticeOf(asked) === "",
    describe(asked));
  count("and the page names the destination that leg delivers to",
    String(asked.body).indexOf(TEAM_BOB) !== -1, describe(asked));

  var byAddress = await operator.form("/admin/aliases",
    { action: "remove", id: bobLeg.id, confirm: TEAM, reason: "bob has moved teams" });
  count("typing the address both legs share does not remove either",
    noticeOf(byAddress) !== "alias-removed" && legsOf(identity, TEAM).length === 2,
    describe(byAddress));

  var byOtherLeg = await operator.form("/admin/aliases",
    { action: "remove", id: bobLeg.id, confirm: TEAM_ALICE, reason: "bob has moved teams" });
  count("typing the other leg's destination does not remove this leg",
    noticeOf(byOtherLeg) !== "alias-removed" && legsOf(identity, TEAM).length === 2,
    describe(byOtherLeg));

  var byLeg = await operator.form("/admin/aliases",
    { action: "remove", id: bobLeg.id, confirm: TEAM_BOB, reason: "bob has moved teams" });
  count("typing the destination the page named removes that leg",
    byLeg.status === 302 && noticeOf(byLeg) === "alias-removed", describe(byLeg));
  var left = legsOf(identity, TEAM);
  count("and only that leg", left.length === 1 && left[0].destination === TEAM_ALICE,
    JSON.stringify(left.map(function (l) { return l.destination; })));

  // One leg left, so the address names exactly one row again and is what
  // the page asks for. The count is taken when the post arrives rather than
  // carried from the page.
  var last = await operator.form("/admin/aliases",
    { action: "remove", id: left[0].id, confirm: TEAM, reason: "the team is gone" });
  count("the last leg of an address is confirmed by the address",
    last.status === 302 && noticeOf(last) === "alias-removed" &&
    legsOf(identity, TEAM).length === 0, describe(last));
}

async function testAnAliasWithOneDestinationIsStillConfirmedByItsAddress(operator, identity) {
  var row = legsOf(identity, SOLO)[0];
  var done = await operator.form("/admin/aliases",
    { action: "remove", id: row.id, confirm: SOLO, reason: "no longer used" });
  count("an alias with one destination is removed when its address is typed",
    done.status === 302 && noticeOf(done) === "alias-removed" &&
    legsOf(identity, SOLO).length === 0, describe(done));
}

async function testADomainSharedByTwoCatchAllLegsConfirmsNeither(operator, identity) {
  var legs = catchAllLegs(identity);
  count("the catch-all delivers to two destinations", legs.length === 2,
    JSON.stringify(legs.map(function (l) { return l.destination; })));
  var second = legs.filter(function (l) { return l.destination === CATCH_TWO; })[0];

  var byDomain = await operator.form("/admin/aliases",
    { action: "remove", id: second.id, confirm: DOMAIN, reason: "one catch-all is enough" });
  count("typing the domain both catch-all legs share does not remove either",
    noticeOf(byDomain) !== "alias-removed" && catchAllLegs(identity).length === 2,
    describe(byDomain));

  var byLeg = await operator.form("/admin/aliases",
    { action: "remove", id: second.id, confirm: CATCH_TWO, reason: "one catch-all is enough" });
  count("typing that leg's destination removes that leg and leaves the other",
    noticeOf(byLeg) === "alias-removed" && catchAllLegs(identity).length === 1 &&
    catchAllLegs(identity)[0].destination === CATCH_ONE, describe(byLeg));
}

// ---- the fields a confirmation carries -------------------------------------

function statusOf(identity, address) {
  var row = identity.accounts.get(address);
  return row === null ? null : row.status;
}

async function testARepeatedIdentifierActsOnNothing(operator, identity) {
  var first = identity.accounts.get(FIRST_SUBJECT);
  var second = identity.accounts.get(SECOND_SUBJECT);
  var answer = await operator.form("/admin/accounts", {
    action: "archive", id: [first.id, second.id], confirm: FIRST_SUBJECT,
    reason: "a request naming two accounts",
  });
  count("an archive naming two identifiers is not performed", noticeOf(answer) !== "archived",
    describe(answer));
  count("and neither account moved", statusOf(identity, FIRST_SUBJECT) === "active" &&
    statusOf(identity, SECOND_SUBJECT) === "active",
  statusOf(identity, FIRST_SUBJECT) + " " + statusOf(identity, SECOND_SUBJECT));
}

async function testARepeatedActionActsOnNothing(operator, identity) {
  var first = identity.accounts.get(FIRST_SUBJECT);
  var answer = await operator.form("/admin/accounts", {
    action: ["suspend", "archive"], id: first.id, confirm: FIRST_SUBJECT,
    reason: "a request naming two acts",
  });
  count("a post naming two actions is answered as the listing", answer.status === 200 &&
    noticeOf(answer) === "", describe(answer));
  count("and the account did not move", statusOf(identity, FIRST_SUBJECT) === "active",
    String(statusOf(identity, FIRST_SUBJECT)));
}

async function testAJsonBodyCarryingAnObjectActsOnNothing(operator, identity) {
  var first = identity.accounts.get(FIRST_SUBJECT);
  var shapes = [
    { action: "archive", id: { toString: first.id }, confirm: FIRST_SUBJECT, reason: "object id" },
    { action: "archive", id: [first.id], confirm: FIRST_SUBJECT, reason: "array id" },
    { action: "archive", id: first.id, confirm: [FIRST_SUBJECT], reason: "array confirm" },
    { action: "archive", id: first.id, confirm: FIRST_SUBJECT, reason: ["array reason"] },
  ];
  for (var i = 0; i < shapes.length; i += 1) {
    var answer = await operator.post("/admin/accounts", "application/json",
      JSON.stringify(shapes[i]));
    count("a JSON archive carrying " + shapes[i].reason + " is not performed",
      noticeOf(answer) !== "archived", describe(answer));
  }
  count("and the account did not move", statusOf(identity, FIRST_SUBJECT) === "active",
    String(statusOf(identity, FIRST_SUBJECT)));
}

async function testAnIdentifierSwappedAfterThePageIsRefused(operator, identity) {
  var first = identity.accounts.get(FIRST_SUBJECT);
  var second = identity.accounts.get(SECOND_SUBJECT);
  var asked = await operator.form("/admin/accounts",
    { action: "archive", id: first.id });
  count("the page asks about the first account", asked.status === 200 &&
    String(asked.body).indexOf(FIRST_SUBJECT) !== -1, describe(asked));

  var swapped = await operator.form("/admin/accounts", {
    action: "archive", id: second.id, confirm: FIRST_SUBJECT,
    reason: "the identifier was changed after the page was drawn",
  });
  count("a post carrying another account's identifier beside the first account's address " +
    "is refused", noticeOf(swapped) !== "archived", describe(swapped));
  count("and neither account moved", statusOf(identity, FIRST_SUBJECT) === "active" &&
    statusOf(identity, SECOND_SUBJECT) === "active",
  statusOf(identity, FIRST_SUBJECT) + " " + statusOf(identity, SECOND_SUBJECT));
}

// `accounts.get` resolves an address as well as an identifier, so the
// identifier field may carry an address. The page names the row it
// resolved, and the act reaches that row.
async function testAnIdentifierWrittenAsAnAddressReachesTheRowThePageNamed(operator, identity) {
  var asked = await operator.form("/admin/accounts", { action: "archive", id: BY_ADDRESS });
  count("an archive naming an address in the identifier field asks about that account",
    asked.status === 200 && String(asked.body).indexOf(BY_ADDRESS) !== -1, describe(asked));
  var done = await operator.form("/admin/accounts", {
    action: "archive", id: BY_ADDRESS, confirm: BY_ADDRESS, reason: "the owner has left",
  });
  count("and confirming it archives exactly that account",
    noticeOf(done) === "archived" && statusOf(identity, BY_ADDRESS) === "archived" &&
    statusOf(identity, FIRST_SUBJECT) === "active", describe(done));
}

// The early measurement of who would be left is taken so an operator is not
// asked to type an address for a change that is going to be refused. It has
// to measure the account the act would reach, however the identifier field
// spelled it.
async function testTheSoleAdministratorNamedByAddressIsRefusedBeforeTheQuestion(operator,
  identity) {
  var admins = identity.accounts.list({ status: "active" })
    .filter(function (row) { return row.isAdmin === true; });
  count("this server holds one administrator", admins.length === 1,
    admins.map(function (row) { return row.address; }).join(", "));

  var asked = await operator.form("/admin/accounts", { action: "archive", id: OPERATOR });
  count("archiving the only administrator named by address is refused on the first post " +
    "rather than asking for the address to be typed",
  asked.status === 400 && String(asked.body).indexOf("name=\"confirm\"") === -1,
  describe(asked));
  count("and the refusal says nobody would be left", /no administrator/i.test(asked.body),
    describe(asked));

  var suspended = await operator.form("/admin/accounts",
    { action: "suspend", id: OPERATOR, reason: "stepping away" });
  count("suspending the only administrator named by address is refused",
    suspended.status === 400 && statusOf(identity, OPERATOR) === "active", describe(suspended));
}

// ---- the role, at creation -------------------------------------------------

async function testCreatingAnAccountDoesNotGrantTheRole(operator, identity) {
  var page = await operator.get("/admin/accounts");
  count("the account creation form offers no operator role",
    page.status === 200 && String(page.body).indexOf("name=\"isAdmin\"") === -1,
    describe(page));

  var before = _asRows(await b.audit.query({ action: "account.role_granted", limit: 100 })).length;
  var answer = await operator.form("/admin/accounts", {
    action: "add", address: NEW_OPERATOR, password: OTHER_PASSWORD, isAdmin: "on",
  });
  count("a creation asking for the operator role is refused",
    answer.status === 400 && noticeOf(answer) !== "account-added", describe(answer));
  count("and the refusal says where the role is given",
    String(answer.body).indexOf("Give it the console") !== -1, describe(answer));
  count("and no account was created", identity.accounts.get(NEW_OPERATOR) === null,
    JSON.stringify(identity.accounts.get(NEW_OPERATOR)));
  await b.audit.flush();
  var after = _asRows(await b.audit.query({ action: "account.role_granted", limit: 100 })).length;
  count("and no role was granted without the reason every grant records", after === before,
    before + " before, " + after + " after");

  var plain = await operator.form("/admin/accounts", {
    action: "add", address: NEW_ACCOUNT, password: OTHER_PASSWORD,
  });
  count("creating an ordinary account still works", noticeOf(plain) === "account-added" &&
    identity.accounts.get(NEW_ACCOUNT).isAdmin === false, describe(plain));
}

// ---- values a stranger controls ----------------------------------------------

function rawMarkersIn(body) {
  return RAW_MARKERS.filter(function (marker) { return String(body).indexOf(marker) !== -1; });
}

function plantHostileEntry(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  nodeFs.mkdirSync(dir, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(dir, HOSTILE_ID + ".eml"),
    "From: sender@example.org\r\nTo: someone@example.net\r\nSubject: x\r\n\r\nbody\r\n", "utf8");
  nodeFs.writeFileSync(nodePath.join(dir, HOSTILE_ID + ".json"), JSON.stringify({
    id:               HOSTILE_ID,
    from:             HOSTILE_SENDER,
    recipient:        HOSTILE_RECIPIENT,
    attempt:          1,
    nextAttemptAt:    Date.now() + 3600000,
    reason:           HOSTILE_REASON,
    reasonCode:       HOSTILE_CODE,
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [],
  }, null, 2), "utf8");
}

async function testStrangerValuesRenderAsText(operator, mailboxOwner, identity, dataDir) {
  plantHostileEntry(dataDir);
  var queue = await operator.get("/admin/queue");
  count("the queue page lists the planted entry",
    queue.status === 200 && String(queue.body).indexOf(HOSTILE_ID) !== -1, describe(queue));
  count("and no address or reply text from it reaches the page as markup",
    rawMarkersIn(queue.body).length === 0, rawMarkersIn(queue.body).join(" | "));
  count("the reply text is shown, escaped",
    String(queue.body).indexOf("&lt;script&gt;alert(103)&lt;/script&gt;") !== -1,
    describe(queue));

  var asked = await operator.form("/admin/queue", { action: "cancel", id: HOSTILE_ID });
  count("the cancellation page names the planted entry",
    asked.status === 200 && String(asked.body).indexOf("alert(101)") !== -1, describe(asked));
  count("and names its addresses as text", rawMarkersIn(asked.body).length === 0,
    rawMarkersIn(asked.body).join(" | "));

  await identity.accounts.create({
    address: "kit@" + DOMAIN, password: OTHER_PASSWORD, displayName: HOSTILE_NAME });
  var accounts = await operator.get("/admin/accounts?limit=200");
  count("the account list shows the display name",
    String(accounts.body).indexOf("alert(105)") !== -1, describe(accounts));
  count("and shows it as text", rawMarkersIn(accounts.body).length === 0,
    rawMarkersIn(accounts.body).join(" | "));

  // A display name carrying a control character. This field is written
  // into outbound headers and shown on every surface that names the
  // account, so it is refused where it is stored rather than repaired at
  // each of the places it is read. The refusal covers the C0 range, the
  // delete code point and the C1 range together: a horizontal tab and
  // U+009B are the same kind of byte to a reader that acts on what it
  // prints, and a screen that reached one and not the other left the
  // second to whichever page remembered it.
  for (var v = 0; v < 2; v += 1) {
    var vector = v === 0
      ? { what: "a horizontal tab", name: TAB_NAME, address: "opal@" + DOMAIN }
      : { what: "a C1 control",     name: C1_NAME,  address: "nell@" + DOMAIN };
    var thrown = null;
    try {
      await identity.accounts.create({
        address: vector.address, password: OTHER_PASSWORD, displayName: vector.name });
    } catch (err) { thrown = err; }
    count("a display name carrying " + vector.what + " is refused where it would be stored",
      thrown !== null && String(thrown.message).indexOf("control character") !== -1,
      thrown === null ? "it was accepted" : String(thrown.message));
    count("and no account was created under " + vector.address,
      (await identity.accounts.get(vector.address)) === null, "the row exists");
  }

  // The page screen is a separate control and it is still load bearing,
  // because most of what these pages show is not a field this server
  // accepts and stores. An author address a mailbox owner may not write
  // is recorded exactly as it was typed, in a row whose detail the audit
  // page renders, and that is the value the screen has to take the
  // control off before an operator reads it here and reads it again out
  // of `blamepost audit read` in a terminal.
  var owner = await mailboxOwner.signIn(FIRST_SUBJECT, OTHER_PASSWORD);
  count("a mailbox owner signs in", owner.status === 302, describe(owner));
  var refused = await mailboxOwner.form("/compose", {
    from: HOSTILE_AUTHOR + CSI + "31m", to: "someone@example.net", subject: "x", text: "x",
  });
  count("the owner's compose naming an author it may not write is refused",
    refused.status === 400, describe(refused));
  await b.audit.flush();
  var authorRows = _asRows(await b.audit.query({
    action: "blamepost.web.author_not_permitted", limit: 50,
  })).filter(function (row) { return String(row.metadata || "").indexOf("alert(106)") !== -1; });
  count("the refusal is on the audit trail carrying the author as it was typed",
    authorRows.length > 0, String(authorRows.length));
  var audit = await operator.get("/admin/audit?action=blamepost.web.author_not_permitted");
  count("the audit page shows that row", String(audit.body).indexOf("alert(106)") !== -1,
    describe(audit));
  count("and shows the author as text", rawMarkersIn(audit.body).length === 0,
    rawMarkersIn(audit.body).join(" | "));
  count("and the control the author carried reaches no reader of the page",
    String(audit.body).indexOf(CSI) === -1, "the page carries no U+009B");

  var filtered = await operator.get("/admin/audit?action=" + encodeURIComponent(HOSTILE_FILTER));
  count("the audit filter echoes what was typed as text",
    filtered.status === 200 && rawMarkersIn(filtered.body).length === 0,
    rawMarkersIn(filtered.body).join(" | ") || describe(filtered));

  var lookup = await operator.get("/admin/lockouts?address=" + encodeURIComponent(HOSTILE_LOOKUP));
  count("a lockout lookup for a hostile address is answered",
    lookup.status === 200, describe(lookup));
  count("and whatever it echoes is text", rawMarkersIn(lookup.body).length === 0,
    rawMarkersIn(lookup.body).join(" | "));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-admin-confirmation-target");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: ALPHA });
    await identity.domains.add({ domain: BRAVO });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "confirmation target run" });

    await identity.accounts.create({ address: OPERATOR, password: ADMIN_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: FIRST_SUBJECT, password: OTHER_PASSWORD });
    await identity.accounts.create({ address: SECOND_SUBJECT, password: OTHER_PASSWORD });
    await identity.accounts.create({ address: BY_ADDRESS, password: OTHER_PASSWORD });

    await identity.aliases.add({ address: TEAM, destination: TEAM_ALICE });
    await identity.aliases.add({ address: TEAM, destination: TEAM_BOB });
    await identity.aliases.add({ address: SOLO, destination: SOLO_DEST });
    await identity.aliases.add({ domain: DOMAIN, catchAll: true, destination: CATCH_ONE });
    await identity.aliases.add({ domain: DOMAIN, catchAll: true, destination: CATCH_TWO });

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     UNANSWERING,
    });
    await server.start();
    running = true;

    await server.mail.dkim.generate({ domain: ALPHA });
    await server.mail.dkim.generate({ domain: BRAVO });

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    var landed = await operator.signIn(OPERATOR, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302, describe(landed));
    var mailboxOwner = browser.browserAt(origin, { ca: material.caPem });

    await testTheSoleAdministratorNamedByAddressIsRefusedBeforeTheQuestion(operator, identity);
    await testARepeatedIdentifierActsOnNothing(operator, identity);
    await testARepeatedActionActsOnNothing(operator, identity);
    await testAJsonBodyCarryingAnObjectActsOnNothing(operator, identity);
    await testAnIdentifierSwappedAfterThePageIsRefused(operator, identity);
    await testAnIdentifierWrittenAsAnAddressReachesTheRowThePageNamed(operator, identity);

    await testTheRetirePageNamesAPairTheServerHolds(operator, server.mail.dkim);
    await testASelectorNameSharedByTwoDomainsConfirmsNeither(operator, server.mail.dkim);

    await testAnAddressSharedByTwoLegsConfirmsNeither(operator, identity);
    await testAnAliasWithOneDestinationIsStillConfirmedByItsAddress(operator, identity);
    await testADomainSharedByTwoCatchAllLegsConfirmsNeither(operator, identity);

    await testCreatingAnAccountDoesNotGrantTheRole(operator, identity);

    await testStrangerValuesRenderAsText(operator, mailboxOwner, identity, dataDir);

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
  name: "web-admin-confirmation-target", run: run, getChecks: helpers.getChecks,
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
