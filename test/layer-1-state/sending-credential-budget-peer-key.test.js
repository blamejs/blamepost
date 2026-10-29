// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a sending credential's failure budget is keyed on, and what a
 * return path publishes, driven on a real encrypted store.
 *
 * `blamepost.mail.listeners.verifySendingCredential` is where the budget
 * for the credential identity space is read and spent, and both
 * transports that accept a credential reach it: the submission listener
 * hands it the domain the client named in SASL, and the sending route on
 * the browser port hands it a Bearer token and no domain. Everything
 * below calls that function, because calling it is what both transports
 * do and because the question here is the KEY rather than the protocol.
 *
 * `test/layer-2-integration/sending-credential-budget-key-reach.test.js`
 * drives the same claims over real sockets. It cannot drive all of them:
 * a source address is what the key is half made of, and a run on a host
 * that offers one address can observe one peer. This file supplies the
 * peer directly, so the cases that separate two peers, twelve peers and
 * a caller naming none are measured on every host.
 *
 * ## What this file drives
 *
 * The budget:
 *
 *   - Five wrong secrets from one address lock that address, and the
 *     correct secret from a second address is still accepted. A budget
 *     keyed on the identifier alone is a budget anyone who can name the
 *     credential spends on behalf of every sender it has.
 *   - The correct secret from the second address does not give the first
 *     address its attempts back.
 *   - The two transports still spend ONE counter for one peer: three
 *     guesses in the shape the submission listener sends and two in the
 *     shape the sending route sends add up to the bound rather than to
 *     two separate allowances.
 *   - One peer keys the same whether it is reported as a dotted IPv4
 *     address or as the IPv4-mapped IPv6 form, because the two listeners
 *     bind separately and an operator may give them different families.
 *   - A caller that names no peer is counted against a key of its own
 *     and cannot lock an address out.
 *   - Sixty failures spread across twelve addresses do not refuse the
 *     credential to a thirteenth. The counter that watches a credential
 *     across every peer counts and files a row; refusing on it would put
 *     back the bound one party spends for everybody.
 *
 * The return path:
 *
 *   - The RFC 5233 tag is derived rather than being the identifier, and
 *     the identifier appears nowhere in the address.
 *   - The tag is stable across reads and differs between credentials in
 *     one domain, which is what lets the bounce mailbox tell them apart.
 *   - `byReturnPathTag` resolves a tag back to the credential that owns
 *     it, including one that has been revoked, since a credential's last
 *     bounces arrive after it stops sending.
 *
 * Run standalone:
 *   node test/layer-1-state/sending-credential-budget-peer-key.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var count     = helpers.count;
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var listeners = require("../../lib/mail/listeners");

var verifySendingCredential = listeners.verifySendingCredential;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var DOMAIN           = "alpha.example";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// How many wrong secrets one peer absorbs before the budget locks it. It
// is `b.auth.lockout`'s own default, which the listener composes without
// naming a number of its own. Written here rather than read from the
// server, so a budget that stopped counting is a failure rather than an
// agreement.
var BUDGET_ATTEMPTS = 5;

// Addresses out of the RFC 5737 documentation ranges, so nothing here
// names a host that exists. The peer is a string the caller supplies and
// this file supplies it, which is the whole reason these cases can be
// driven at all.
var PEER_A   = "203.0.113.10";
var PEER_B   = "203.0.113.11";
var PEER_V4  = "198.51.100.7";
var PEER_V46 = "::ffff:198.51.100.7";

// How many addresses the spread case guesses from, and therefore how
// many failures it puts against one credential. Twelve times the per
// peer bound is sixty, which is past the threshold the watch files its
// row at, so a run that reached the threshold and refused would show it
// here.
var SPREAD_PEERS = 12;

async function seed(handle) {
  await handle.domains.add({ domain: DOMAIN });
  await handle.accounts.create({
    address: "bounces@" + DOMAIN, password: ACCOUNT_PASSWORD });
}

function issue(handle, reason) {
  return handle.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: "bounces@" + DOMAIN,
    reason:        reason,
  });
}

// A token carrying the credential's real identifier and a secret this
// file invented. It is the shape of a guess, and the only shape a budget
// can count.
function wrongSecretFor(token, nonce) {
  var parts = token.split("_");
  var secret = "";
  var alphabet = "0123456789abcdef";
  for (var i = 0; i < 64; i += 1) {
    secret += alphabet[(i * 5 + nonce * 11) % alphabet.length];
  }
  return parts.slice(0, 3).join("_") + "_" + secret;
}

// One presentation, in the shape the sending route makes it: a token and
// a peer, and no domain to cross-check.
function asTheRouteDoes(handle, secret, source) {
  return verifySendingCredential(handle.credentials, { secret: secret, source: source });
}

// The same presentation in the shape the submission listener makes it,
// which names the domain the client authenticated under.
function asTheListenerDoes(handle, secret, source) {
  return verifySendingCredential(handle.credentials, {
    secret: secret, source: source, presentedAs: DOMAIN });
}

// ---- the budget ------------------------------------------------------------

async function testOnePeersLockoutIsNotEveryPeers(handle) {
  var made = await issue(handle, "a credential one address guesses at");

  var first = await asTheRouteDoes(handle, made.token, PEER_A);
  count("the credential verifies before anything is spent",
    first.ok === true, JSON.stringify(first.reason));

  for (var i = 0; i < BUDGET_ATTEMPTS; i += 1) {
    var guess = await asTheRouteDoes(handle, wrongSecretFor(made.token, i + 1), PEER_A);
    count("a wrong secret under the credential's real identifier is refused (attempt " +
      (i + 1) + " of " + BUDGET_ATTEMPTS + ")",
      guess.ok === false && guess.reason === "credentials-rejected", JSON.stringify(guess));
  }

  var lockedOut = await asTheRouteDoes(handle, made.token, PEER_A);
  count("the guessing address is then refused even holding the CORRECT secret, so its " +
    "guesses were counted rather than waved through",
    lockedOut.ok === false && lockedOut.reason === "too-many-attempts",
    JSON.stringify(lockedOut));

  var elsewhere = await asTheRouteDoes(handle, made.token, PEER_B);
  count("and a SECOND address holding the same correct secret is accepted, because the " +
    "budget is keyed on the credential AND the peer. The identifier reaches an operator " +
    "through the trail, the command line and a listing, so a bound keyed on it alone is a " +
    "bound anyone who can name the credential spends on every sender it has",
    elsewhere.ok === true, JSON.stringify(elsewhere.reason));

  var stillLocked = await asTheRouteDoes(handle, made.token, PEER_A);
  count("and the first address is STILL refused after the second succeeded, because a " +
    "correct secret from the application's own address says nothing about the address that " +
    "was guessing",
    stillLocked.ok === false && stillLocked.reason === "too-many-attempts",
    JSON.stringify(stillLocked));
}

async function testBothTransportsSpendOneCounter(handle) {
  var made = await issue(handle, "a credential guessed at over both transports");

  var listenerShape = 3;
  for (var i = 0; i < listenerShape; i += 1) {
    var overWire = await asTheListenerDoes(handle, wrongSecretFor(made.token, i + 31), PEER_V4);
    count("a guess in the submission listener's shape is refused (" + (i + 1) + " of " +
      listenerShape + ")",
      overWire.ok === false && overWire.reason === "credentials-rejected",
      JSON.stringify(overWire));
  }

  for (var j = 0; j < BUDGET_ATTEMPTS - listenerShape; j += 1) {
    var overRoute = await asTheRouteDoes(handle, wrongSecretFor(made.token, j + 41), PEER_V4);
    count("a guess in the sending route's shape from the same address is refused (" +
      (j + 1) + " of " + (BUDGET_ATTEMPTS - listenerShape) + ")",
      overRoute.ok === false && overRoute.reason === "credentials-rejected",
      JSON.stringify(overRoute));
  }

  var settled = await asTheRouteDoes(handle, made.token, PEER_V4);
  count("three guesses in one transport's shape and two in the other's add up to the bound " +
    "rather than to two allowances, so a surface that verifies a secret and counts nothing " +
    "is still not a bound an attacker walks around by choosing that surface",
    settled.ok === false && settled.reason === "too-many-attempts", JSON.stringify(settled));

  var mapped = await asTheListenerDoes(handle, made.token, PEER_V46);
  count("and the same address reported in the IPv4-mapped IPv6 form lands on the same key, " +
    "which is what keeps the two transports on one counter when an operator has bound them " +
    "to different address families",
    mapped.ok === false && mapped.reason === "too-many-attempts", JSON.stringify(mapped));

  var elsewhere = await asTheRouteDoes(handle, made.token, PEER_B);
  count("while another address holding the correct secret is accepted throughout",
    elsewhere.ok === true, JSON.stringify(elsewhere.reason));
}

async function testACallerNamingNoPeerIsItsOwnKey(handle) {
  var made = await issue(handle, "a credential presented by a caller that names no peer");

  for (var i = 0; i < BUDGET_ATTEMPTS; i += 1) {
    var guess = await verifySendingCredential(handle.credentials, {
      secret: wrongSecretFor(made.token, i + 51) });
    count("a wrong secret presented with no peer at all is refused (" + (i + 1) + " of " +
      BUDGET_ATTEMPTS + ")",
      guess.ok === false && guess.reason === "credentials-rejected", JSON.stringify(guess));
  }

  var anonymous = await verifySendingCredential(handle.credentials, { secret: made.token });
  count("a caller that names no peer is counted against a key of its own and is locked on " +
    "it, so the absent peer bounds that caller rather than being waved through",
    anonymous.ok === false && anonymous.reason === "too-many-attempts",
    JSON.stringify(anonymous));

  var named = await asTheRouteDoes(handle, made.token, PEER_A);
  count("and an address that named itself is unaffected, so the empty half is a key of its " +
    "own rather than the shared bucket the pairing exists to remove",
    named.ok === true, JSON.stringify(named.reason));
}

async function testTheSpreadWatchCountsAndDoesNotRefuse(handle) {
  var made = await issue(handle, "a credential guessed at from many addresses at once");

  var spent = 0;
  for (var p = 0; p < SPREAD_PEERS; p += 1) {
    var peer = "192.0.2." + (p + 1);
    for (var i = 0; i < BUDGET_ATTEMPTS; i += 1) {
      var guess = await asTheRouteDoes(handle, wrongSecretFor(made.token, p * 7 + i + 61), peer);
      if (guess.ok === false && guess.reason === "credentials-rejected") spent += 1;
    }
  }
  count("every one of the " + (SPREAD_PEERS * BUDGET_ATTEMPTS) + " guesses spread across " +
    SPREAD_PEERS + " addresses was counted rather than short-circuited, so the credential " +
    "really carries that many failures",
    spent === SPREAD_PEERS * BUDGET_ATTEMPTS, String(spent));

  var fresh = await asTheRouteDoes(handle, made.token, "192.0.2.200");
  count("and an address that has guessed at nothing still sends, because the counter that " +
    "watches one credential across every peer files a row and refuses nobody. Any threshold " +
    "low enough to matter is one an attacker holding a handful of addresses crosses on " +
    "purpose, which is the outage this whole arrangement removes",
    fresh.ok === true, JSON.stringify(fresh.reason));

  var sprayed = await asTheRouteDoes(handle, made.token, "192.0.2.1");
  count("while each address that did guess stays locked on its own key",
    sprayed.ok === false && sprayed.reason === "too-many-attempts", JSON.stringify(sprayed));
}

// ---- the return path -------------------------------------------------------

async function testTheTagIsDerivedRatherThanPublished(handle) {
  var first  = await issue(handle, "a credential whose return path is read");
  var second = await issue(handle, "a second credential in the same domain");

  count("blamepost.store.credentials.create hands back the tag beside the address",
    typeof first.returnPathTag === "string" && /^[0-9a-f]{32}$/.test(first.returnPathTag),
    String(first.returnPathTag));

  count("and the address carries that tag rather than the identifier",
    first.returnPath === "bounces+" + first.returnPathTag + "@" + DOMAIN,
    String(first.returnPath));

  count("and the identifier appears nowhere in the address, so a correspondent holding one " +
    "cannot read back the value the failure budget is keyed on",
    first.returnPath.indexOf(first.id) === -1, first.returnPath);

  count("two credentials in one domain derive different tags, which is what lets the bounce " +
    "mailbox tell whose bounce it is reading",
    second.returnPathTag !== first.returnPathTag,
    second.returnPathTag + " vs " + first.returnPathTag);

  count("and they fold to the same local part, so one alias still carries the domain",
    second.returnPath.split("+")[0] === first.returnPath.split("+")[0],
    second.returnPath + " / " + first.returnPath);

  var shown = await handle.credentials.show(first.id);
  count("blamepost.store.credentials.show derives the same tag on a later read, so nothing " +
    "has to be stored beside the row for the address to stay the one already in the wild",
    shown.returnPathTag === first.returnPathTag && shown.returnPath === first.returnPath,
    String(shown.returnPath));

  var verified = await handle.credentials.verify(first.token);
  count("and a verify hands back the same pair, so a sender reads the address off the " +
    "credential it just presented rather than holding a copy",
    verified.returnPathTag === first.returnPathTag && verified.returnPath === first.returnPath,
    String(verified.returnPath));

  return { first: first, second: second };
}

async function testTheTagResolvesBackToItsCredential(handle, made) {
  var found = await handle.credentials.byReturnPathTag({
    domain: DOMAIN, tag: made.first.returnPathTag });
  count("blamepost.store.credentials.byReturnPathTag names the credential a return path " +
    "belongs to, which is how an operator reading the bounce mailbox tells whose bounce a " +
    "message is once the address stopped carrying the identifier",
    found !== null && found.id === made.first.id, JSON.stringify(found && found.id));

  var other = await handle.credentials.byReturnPathTag({
    domain: DOMAIN, tag: made.second.returnPathTag });
  count("and it names the other credential for the other tag rather than the first for both",
    other !== null && other.id === made.second.id, JSON.stringify(other && other.id));

  var absent = await handle.credentials.byReturnPathTag({
    domain: DOMAIN, tag: "00000000000000000000000000000000" });
  count("a tag no credential in the domain derives comes back null rather than naming the " +
    "nearest one",
    absent === null, JSON.stringify(absent));

  var refusedShape = null;
  try {
    await handle.credentials.byReturnPathTag({ domain: DOMAIN, tag: "not-a-tag" });
  } catch (e) { refusedShape = e && e.code; }
  count("and a string that is not the shape this registry derives is refused rather than " +
    "compared against every row",
    refusedShape === "store/bad-argument", String(refusedShape));

  var refusedDomain = null;
  try {
    await handle.credentials.byReturnPathTag({
      domain: "somewhere.else.example", tag: made.first.returnPathTag });
  } catch (e) { refusedDomain = e && e.code; }
  count("and a domain this server does not host is refused rather than answered about",
    refusedDomain === "store/no-such-domain", String(refusedDomain));

  await handle.credentials.revoke({
    id: made.second.id, reason: "the application was decommissioned" });
  var afterRevoke = await handle.credentials.byReturnPathTag({
    domain: DOMAIN, tag: made.second.returnPathTag });
  count("a revoked credential is still named by its tag, because the bounces from its last " +
    "send arrive after it stops sending and an operator holding one of those is asking " +
    "exactly then",
    afterRevoke !== null && afterRevoke.id === made.second.id,
    JSON.stringify(afterRevoke && afterRevoke.id));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-budget-peer-key");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside this run's own tree keeps the encrypted-at-rest path
  // exactly as it ships.
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
    await seed(handle);

    await testOnePeersLockoutIsNotEveryPeers(handle);
    await testBothTransportsSpendOneCounter(handle);
    await testACallerNamingNoPeerIsItsOwnKey(handle);
    await testTheSpreadWatchCountsAndDoesNotRefuse(handle);
    var made = await testTheTagIsDerivedRatherThanPublished(handle);
    await testTheTagResolvesBackToItsCredential(handle, made);
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "sending-credential-budget-peer-key",
  run:       run,
  getChecks: helpers.getChecks,
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
