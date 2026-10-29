// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One domain name, one meaning, wherever this server decides whether two
 * names are the same domain.
 *
 * `test/layer-1-state/address-identity-parity.test.js` asks the question
 * about the local part. This file asks it about the half after the at
 * sign, which is the half that names a hosted domain, keys a selector
 * row, and becomes the file name of a sealed private key.
 *
 * A domain arrives in more than one spelling and every one of them is
 * legitimate on the wire. `example.com.` carries the DNS root's trailing
 * dot, which RFC 1035 section 2.3.1 makes the absolute form of the same
 * name; `EXAMPLE.COM` differs only in case, which RFC 4343 says is not a
 * difference at all. `lib/store/address.js` folds both away, and the
 * identity layer, the routing lookup and the command line all read a
 * name through it, so all three answer about one domain whichever
 * spelling they were handed.
 *
 * A surface that folds the name some other way answers about a different
 * one, and the disagreement is silent in both directions. A name folded
 * only for case still carries the trailing dot into whatever it keys, so
 * a lookup misses the row sitting in front of it and a derived file name
 * gains an empty label. A name not folded at all is admitted by the
 * domain guard, which reads the absolute form as the valid name it is,
 * and then refused further down by a reader that does not. At that
 * point the refusal an operator sees was written for whoever composed
 * the framework rather than for them.
 *
 * What this file pins, over the surfaces an operator actually drives:
 *
 *   - Every signer verb answers about one domain for all four spellings,
 *     including the two that reach the framework's own signer.
 *   - The sealed key file a mint writes is named for the folded domain,
 *     so the name on the volume is the name in the row. The private half
 *     and the row that points at it are found by that name for the whole
 *     life of the key, and a spelling that lands one of them somewhere
 *     else strands the other.
 *   - Signing answers for every spelling. This is the one that is not
 *     cosmetic: a signer that refuses does not stop the message, so a
 *     spelling the signer will not accept sends the mail unsigned, and
 *     the domain's own DMARC policy is what reports it afterwards.
 *   - The browser console reaches the same domain the command line
 *     reaches. The command line already folds the name it was given; a
 *     console that folds it differently is the same server answering two
 *     ways depending on which surface asked.
 *   - A name that only renders like a hosted domain is refused rather
 *     than becoming a second one.
 *
 * Run standalone: node test/layer-1-state/domain-identity-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 3307";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The four spellings of one name. The first is what the store records.
// The second is the absolute form of RFC 1035 section 2.3.1, which the
// domain guard admits under the strict profile every entry point here
// holds a name against. The third and fourth are RFC 4343 case, alone
// and together with the root dot.
function spellingsOf(name) {
  return [
    ["the recorded spelling",     name],
    ["the absolute form",         name + "."],
    ["a difference only in case", name.toUpperCase()],
    ["both at once",              name.toUpperCase() + "."],
  ];
}

// The domains each group of cases works on. Separate names, because a
// mint refuses a domain that already holds an active pair and a shared
// name would make the second case in a group answer about the first.
var SIGNER_DOMAIN  = "signer.example";
var CONSOLE_DOMAIN = "console.example";
var ROOTED_ADD     = "rooted.example";
var LONG_BARE      = longName("a", "b");
var LONG_ROOTED    = longName("c", "d");

// A hosted name at the longest a sealed key file may be named for.
//
// `lib/mail/dkim.js` names that file `<domain>.<selector>.<algorithm>.sealed`
// and the store records at most 128 characters of it. The RSA half is
// the binding one: its selector is the Ed25519 selector plus `-rsa` and
// its algorithm name is the longer of the two, which leaves 97
// characters for the domain. A name of exactly 97 therefore mints, and
// the same name carrying the root dot is 98 and does not, which
// measures which spelling the file name was derived from without
// reading anything private.
//
// The bare spelling minting is asserted below rather than assumed. If
// the selector shape or the ceiling ever moves, that assertion is what
// says so instead of this quietly ceasing to sit on the boundary.
function longName(head, tail) {
  return _repeat(head, 60) + "." + _repeat(tail, 28) + ".example";
}

function _repeat(letter, times) {
  var out = "";
  for (var i = 0; i < times; i += 1) out += letter;
  return out;
}

// A name that renders like a hosted domain and is a different string.
// The first is Cyrillic `а` where the Latin `a` belongs, which is the
// IDN homograph class; the second is the ideographic full stop, which
// reads as a label separator and is not one; the third is the same name
// already encoded as an A-label, which is how the first would arrive if
// something upstream had converted it.
var CONFUSABLES = [
  ["a Cyrillic letter standing in for a Latin one", "exаmple.example"],
  ["an ideographic full stop reading as a dot",     "example。example"],
  ["a fullwidth full stop reading as a dot",        "example．example"],
  ["a halfwidth full stop reading as a dot",        "example｡example"],
  ["an A-label whose decoded form is not this one", "xn--exmple-4nf.example"],
];

// The message the signing cases sign. Nothing about it varies with the
// spelling under test, so a difference in what comes back is a
// difference the spelling made.
function parityMessageFor(domain) {
  return Buffer.from([
    "From: alice@" + domain,
    "To: bob@peer.example",
    "Subject: one domain, one meaning",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <parity@" + domain + ">",
    "",
    "Body.",
    "",
  ].join("\r\n"), "utf8");
}

// Counted the way test/layer-1-state/unsigned-send-trail.test.js counts
// them, so a message this file calls signed and one that file calls
// signed are the same claim.
function signatureCount(rfc822) {
  var text = Buffer.isBuffer(rfc822) ? rfc822.toString("latin1") : String(rfc822 || "");
  return (text.match(/DKIM-Signature:/g) || []).length;
}

// What one call did, whether it answered or refused. Both halves are
// needed here: a case that only reports the refusal cannot say what the
// answer was when there wasn't one, and every assertion below is about
// the answer a second spelling produced.
function outcomeOf(work) {
  return Promise.resolve().then(work).then(
    function (value) { return { ok: true, value: value, error: null }; },
    function (e) { return { ok: false, value: null, error: e }; });
}

// A refusal in one line, for the detail a failing check prints.
function saidWhat(outcome) {
  if (outcome.ok) return "it answered";
  var e = outcome.error;
  return String((e && e.code) || "(no code)") + ": " + String(e && e.message).slice(0, 200);
}

function keyFiles(dataDir) {
  var dir = nodePath.join(dataDir, "keys");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir).sort();
}

// ---- cases -----------------------------------------------------------------

// The signer's read-only verbs, asked in every spelling. These already
// launder the name through the store on their way to the selector rows,
// so they are the control: a group that answered differently here would
// mean the store had stopped folding rather than that the signer had.
function testTheSignerReadsOneDomainInEverySpelling(dkim, name) {
  var recorded = dkim.list(name).map(function (s) { return s.domain + "/" + s.selector; });
  count("the signer holds a pair for " + name + " to ask about",
    recorded.length === 2, JSON.stringify(recorded));

  spellingsOf(name).forEach(function (entry) {
    var label = entry[0];
    var spelling = entry[1];
    var listed = dkim.list(spelling).map(function (s) { return s.domain + "/" + s.selector; });
    count("list answers about the same pair for " + label + " (" + spelling + ")",
      JSON.stringify(listed) === JSON.stringify(recorded), JSON.stringify(listed));

    var records = dkim.dnsRecords(spelling).map(function (r) { return r.dnsName; });
    count("and the records it says the zone must carry name the folded domain for " + label,
      records.length === 2 && records.every(function (dnsName) {
        return dnsName.indexOf("._domainkey." + name) !== -1;
      }), JSON.stringify(records));
  });
}

// Signing, in every spelling. A signer that refuses does not stop the
// message: both surfaces that send catch the refusal, send anyway and
// file a row. So a spelling the signer will not take is a spelling that
// sends the account's mail unsigned, which the receiver reads as a
// domain failing its own DMARC policy.
async function testSigningAnswersForEverySpelling(dkim, name) {
  var spellings = spellingsOf(name);
  for (var i = 0; i < spellings.length; i += 1) {
    var label = spellings[i][0];
    var spelling = spellings[i][1];

    var built = await outcomeOf(function () { return dkim.signerFor(spelling); });
    count("a signer is built for " + label + " (" + spelling + "), so mail from this " +
      "domain is not sent unsigned because of how the name was spelled",
      built.ok, saidWhat(built));

    var signed = await outcomeOf(function () { return dkim.sign(spelling, parityMessageFor(name)); });
    count("and the message it signs carries both signatures for " + label,
      signed.ok && signatureCount(signed.value) === 2,
      signed.ok ? signatureCount(signed.value) + " signature(s)" : saidWhat(signed));
  }
}

// The mint, driven on the absolute form. What the row records and what
// the volume is named have to be the same folded name: the row points at
// the file for the whole life of the key, and a mint that writes one
// under a spelling the row does not carry leaves private key material
// nothing signs with and nothing erases.
async function testAMintOnTheAbsoluteFormLandsOnTheFoldedName(dkim, dataDir, name) {
  var before = keyFiles(dataDir);
  var minted = await outcomeOf(function () { return dkim.generate({ domain: name + "." }); });

  count("minting for the absolute form of " + name + " is the same request as minting " +
    "for the name the operator hosts",
    minted.ok, saidWhat(minted));
  count("and the pair it reports is recorded under the folded name",
    minted.ok && minted.value.domain === name,
    minted.ok ? String(minted.value.domain) : "(refused)");

  var added = keyFiles(dataDir).filter(function (file) { return before.indexOf(file) === -1; });
  count("it wrote both halves of the pair to the volume",
    added.length === 2, JSON.stringify(added));
  count("and each sealed key is named for the folded domain, so the name on the volume " +
    "is the name in the row",
    added.length === 2 && added.every(function (file) { return file.indexOf(name + ".") === 0; }),
    JSON.stringify(added));
  count("with no empty label in it, which is what the root dot becomes once it is inside " +
    "a name built around it",
    added.every(function (file) { return file.indexOf("..") === -1; }),
    JSON.stringify(added));

  var rows = dkim.list(name);
  count("and the row points at a file that is actually there",
    rows.length === 2 && rows.every(function (row) {
      return nodeFs.existsSync(nodePath.join(dataDir, "keys", row.keyRef));
    }), JSON.stringify(rows.map(function (row) { return row.keyRef; })));
}

// The same mint at the length where the derivation is measurable. The
// file name is bounded, so a domain one character from the ceiling mints
// and the same domain one character over it does not. Both spellings of
// one name are the same length only after the root dot has come off, so
// this asks which spelling the name was built from without looking at
// anything the module keeps to itself.
async function testTheDerivedFileNameIsMeasuredOnTheFoldedName(dkim, identity, dataDir) {
  await identity.domains.add({ domain: LONG_BARE });
  await identity.domains.add({ domain: LONG_ROOTED });

  count("the boundary name is as long as a sealed key file leaves room for",
    LONG_BARE.length === 97, LONG_BARE.length + " characters");

  var bare = await outcomeOf(function () { return dkim.generate({ domain: LONG_BARE }); });
  count("a domain at that length mints, so the boundary is where this says it is",
    bare.ok, saidWhat(bare));

  var rooted = await outcomeOf(function () { return dkim.generate({ domain: LONG_ROOTED + "." }); });
  count("and so does the absolute form of a name the same length, because the file name " +
    "is derived from the folded domain rather than from the spelling that arrived",
    rooted.ok, saidWhat(rooted));

  var written = keyFiles(dataDir).filter(function (file) {
    return file.indexOf(LONG_ROOTED + ".") === 0;
  });
  count("the sealed keys for it are named for the folded domain",
    written.length === 2, JSON.stringify(written));
}

// The browser console, driven over a real loopback port with a real
// operator session. The command line folds the name it is given before
// it reaches any of this; a console that folds it differently is the
// same server answering two ways depending on which surface asked.
async function testTheConsoleReachesTheSameDomainTheCommandLineDoes(operator, dkim, name) {
  var answer = await operator.form("/admin/dkim", { action: "generate", domain: name + "." });
  count("the console mints for a domain typed in its absolute form",
    answer.status === 302, answer.status + " " + String(answer.location));

  var rows = dkim.list(name);
  count("and the pair it minted is recorded under the folded name",
    rows.length === 2 && rows.every(function (row) { return row.domain === name; }),
    JSON.stringify(rows.map(function (row) { return row.domain + "/" + row.selector; })));

  // The second request is the same request. A console that had recorded
  // the first under the unfolded spelling would find no active pair and
  // mint a second one on top of the live key.
  var again = await operator.form("/admin/dkim",
    { action: "generate", domain: name.toUpperCase() + "." });
  count("a second mint in another spelling is refused as the same domain already keyed, " +
    "rather than minting a second pair over the live one",
    again.status === 400, again.status + " " + String(again.location));
  count("and the domain still holds exactly the one pair",
    dkim.list(name).length === 2,
    JSON.stringify(dkim.list(name).map(function (row) { return row.selector; })));
}

// Adding a domain from the console, in the absolute form. The identity
// layer folds the name, so the row it writes is the folded one; a
// console that measured the unfolded spelling against the hosted set
// would read an existing domain as a new one.
async function testAddingADomainInTheAbsoluteFormAddsOneDomain(operator, identity) {
  var first = await operator.form("/admin/domains", { action: "add", domain: ROOTED_ADD });
  count("the console hosts a new domain", first.status === 302,
    first.status + " " + String(first.location));

  var again = await operator.form("/admin/domains",
    { action: "add", domain: ROOTED_ADD.toUpperCase() + "." });
  count("and asking again in the absolute form is refused as the domain already hosted",
    again.status === 400, again.status + " " + String(again.location));

  var hosted = identity.domains.list().map(function (d) { return d.domain; })
    .filter(function (d) { return d.indexOf("rooted") === 0; });
  count("so the hosted set holds one domain rather than two spellings of one",
    hosted.length === 1 && hosted[0] === ROOTED_ADD, JSON.stringify(hosted));
}

// A name that only renders like a hosted one. The strict profile refuses
// raw Unicode, an A-label and a mixed-script label outright, which is
// the answer that keeps a homograph from becoming a second hosted domain
// rather than a second spelling of an existing one. Asked at all three
// entry points, because a refusal at one of them is not a refusal.
async function testANameThatOnlyRendersLikeAHostedDomainIsRefused(operator, identity, dkim) {
  for (var i = 0; i < CONFUSABLES.length; i += 1) {
    var label = CONFUSABLES[i][0];
    var name = CONFUSABLES[i][1];

    var added = await outcomeOf(function () { return identity.domains.add({ domain: name }); });
    count("the identity layer refuses " + label,
      !added.ok && added.error.code === "store/bad-domain", saidWhat(added));

    var minted = await outcomeOf(function () { return dkim.generate({ domain: name }); });
    count("the signer refuses " + label + " rather than naming a key file after it",
      !minted.ok, saidWhat(minted));
    count("and the refusal is one this server wrote, not one from underneath it",
      !minted.ok && String(minted.error.code || "").indexOf("store/") === 0,
      saidWhat(minted));

    var answer = await operator.form("/admin/domains", { action: "add", domain: name });
    count("and the console refuses " + label, answer.status === 400,
      answer.status + " " + String(answer.location));
  }

  var hosted = identity.domains.list().map(function (d) { return d.domain; });
  count("so none of them became a hosted domain",
    CONFUSABLES.every(function (entry) { return hosted.indexOf(entry[1]) === -1; }),
    JSON.stringify(hosted));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("domain-identity-parity");
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
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: SIGNER_DOMAIN });
    await identity.domains.add({ domain: CONSOLE_DOMAIN });
    var operatorAccount = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });

    // Every mail listener off. This file is about which domain a name
    // means, and every surface it drives is either the signer handle or
    // a browser route; a bound port would only add a way for the run to
    // fail that has nothing to do with the question.
    var sections = {};
    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var dkim = server.mail.dkim;

    // The pair the read and signing cases ask about, minted on the
    // recorded spelling so those cases measure the reads rather than
    // the mint.
    await dkim.generate({ domain: SIGNER_DOMAIN });

    testTheSignerReadsOneDomainInEverySpelling(dkim, SIGNER_DOMAIN);
    await testSigningAnswersForEverySpelling(dkim, SIGNER_DOMAIN);
    await testAMintOnTheAbsoluteFormLandsOnTheFoldedName(dkim, dataDir, DOMAIN);
    await testTheDerivedFileNameIsMeasuredOnTheFoldedName(dkim, identity, dataDir);

    var bound = server.web.bound();
    var operator = browser.browserAt("https://" + LOOPBACK + ":" + bound.https,
      { ca: material.caPem });
    var landed = await operator.signIn(operatorAccount.address, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    await testTheConsoleReachesTheSameDomainTheCommandLineDoes(operator, dkim, CONSOLE_DOMAIN);
    await testAddingADomainInTheAbsoluteFormAddsOneDomain(operator, identity);
    await testANameThatOnlyRendersLikeAHostedDomainIsRefused(operator, identity, dkim);

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
      catch (_e) { /* drop-silent by design: the temporary volume is going anyway */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "domain-identity-parity",
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
