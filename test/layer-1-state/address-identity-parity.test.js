// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One address, one meaning, wherever this server decides whether two
 * addresses are the same one.
 *
 * `lib/store/address.js` exists to be that single decision: it folds the
 * case of both halves, strips the RFC 5233 plus tag down to the mailbox
 * that owns it, and hands back a canonical form the SMTP, IMAP, JMAP,
 * POP3 and browser paths are all supposed to compare on. Its own module
 * docstring says why: so those paths "cannot disagree about it."
 *
 * They can, wherever a comparison reaches for the raw string instead.
 * `alice@example.com`, `Alice@Example.com` and `alice+list@example.com`
 * are three spellings of one mailbox: the routing layer resolves all
 * three to the same account and delivers to it, and the failure budget
 * the identity layer keeps is deliberately keyed on the canonical form
 * so a plus tag cannot refill it. A comparison that skips the parse
 * disagrees with both, and it does it silently, because a raw `!==` on
 * two spellings of one address is indistinguishable from a correct
 * answer about two different ones.
 *
 * What this file pins is the reply-all author exclusion, on both surfaces
 * that build one. Reply-all is where the divergence is visible to an
 * account holder: the author is dropped from the copy list by comparing
 * her address against each recipient, so a spelling the comparison does
 * not recognize puts her on the copy list of her own reply. That is a
 * small consequence and a precise probe, because it fails exactly when
 * the comparison stopped going through the canonical parse, which is
 * the property worth holding.
 *
 * It also pins the set of authors an account may write, which is the
 * other place one address has to have one meaning. The submission
 * listener measures a message's From and Sender against that set, and
 * it is built here from the same canonical parse routing uses, so a
 * subaddress the MX listener delivers to an account is one that account
 * may write.
 *
 * The divergence this does NOT pin is the envelope half of the same
 * binding, which refuses `MAIL FROM` for an account's own subaddress
 * while the MX listener accepts the same address as a recipient. That
 * one is recorded in ROADMAP.md and driven at the wire in
 * test/layer-2-integration/mail-submission.test.js, because the set the
 * framework compares the envelope against is a fixed list of addresses
 * built inside the framework, and a tag is chosen by whoever writes it,
 * so it cannot be enumerated in advance from here.
 *
 * Run standalone: node test/layer-1-state/address-identity-parity.test.js
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
var DOMAIN   = "example.com";
var HOSTNAME = "mx.example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 5000;

// The third party on every copy list below. Whatever the exclusion does
// with alice, carol has to survive it: a filter that dropped everybody
// would pass an assertion about alice's absence while breaking reply-all
// outright.
var CAROL = "carol@example.com";

// The value of the copy field on the rendered compose form, which is
// what a reader is about to send. Read off the page rather than out of
// the handler, because the handler's answer is not what anybody sends.
var CC_FIELD_RE = /<input id="cc" name="cc" type="text" value="([^"]*)"/;

function ccFieldOf(page) {
  var found = CC_FIELD_RE.exec(page.body);
  return found === null ? null : found[1];
}

// A message addressed to `toHeader`, from somebody outside this server,
// so the reply-all copy list is built from a header a stranger wrote.
function messageAddressedTo(toHeader, marker) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: Dana Reyes <dana@peer.example>",
    "To: " + toHeader,
    "Subject: the quarterly review",
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "",
    "Body for " + marker + ".",
    "",
  ].join("\r\n"), "utf8");
}

// ---- cases -----------------------------------------------------------------

// Each case seeds one message, opens the reply-all draft the browser
// surface builds for it, and asks what is in the copy field.
async function replyAllExcludesTheAuthor(reader, seeded, label, spelling) {
  var page = await reader.get("/compose?source=" + encodeURIComponent(seeded.objectId) +
    "&folder=INBOX&mode=reply-all");
  count(label + ": the reply-all draft renders", page.status === 200,
    "HTTP " + page.status);

  var cc = ccFieldOf(page);
  count(label + ": the draft carries a copy field to read",
    cc !== null, String(cc));

  // The author is on the copy list of her own reply whenever the
  // exclusion did not recognize the spelling the sender used.
  count(label + ": the author is not copied on her own reply, though the " +
    "sender addressed her as " + spelling,
    cc !== null && cc.toLowerCase().indexOf("alice") === -1, JSON.stringify(cc));

  // The other recipient survives, so the assertion above cannot be
  // satisfied by an exclusion that dropped everybody.
  count(label + ": the other recipient is still copied",
    cc !== null && cc.indexOf(CAROL) !== -1, JSON.stringify(cc));
}

// The routing layer's own answer, which is the one the copy list above
// has to agree with. Asserting it here keeps the two claims in one file:
// a change that made routing stop folding a plus tag would make the
// browser assertions above pass for the wrong reason, and this is what
// would catch that.
function routingResolvesEverySpellingToOneMailbox(identity, spellings) {
  var canonical = identity.resolve(spellings[0][1]);
  count("routing resolves the canonical spelling to alice's mailbox",
    canonical.deliverable === true && canonical.address === "alice@" + DOMAIN,
    JSON.stringify({ address: canonical.address, reason: canonical.reason }));

  for (var i = 1; i < spellings.length; i += 1) {
    var verdict = identity.resolve(spellings[i][1]);
    count("routing resolves " + spellings[i][0] + " to the same mailbox, so the " +
      "copy list above is comparing the same two addresses routing does",
      verdict.deliverable === true && verdict.address === canonical.address,
      JSON.stringify({ input: spellings[i][1], address: verdict.address }));
  }
}

// The other place one address has to have one meaning: the set of
// authors an account may write.
//
// The submission listener measures a message's From and Sender against
// this, so it has to agree with routing about which addresses reach the
// account. It is the account's own address plus every alias that lands
// in its mailbox, canonical, and never a catch-all: a catch-all claims
// every name at a domain, so counting one would hand the account
// holding it every address the domain could ever carry, which is the
// forgery the binding exists to refuse rather than a set of identities.
function permittedAuthorsAgreesWithRouting(identity, alice) {
  var actor   = { id: alice.id, address: alice.address };
  var allowed = blamepost.mail.listeners.permittedAuthors(identity, actor);

  count("the account's own address is an author it may write",
    allowed.indexOf("alice@" + DOMAIN) !== -1, JSON.stringify(allowed));
  count("and so is an alias that lands in its mailbox",
    allowed.indexOf("sales@" + DOMAIN) !== -1, JSON.stringify(allowed));
  count("while a catch-all is not an identity and is left out",
    allowed.indexOf("@" + DOMAIN) === -1, JSON.stringify(allowed));

  // Every entry is canonical, which is what lets the listener compare a
  // tagged spelling against it by parsing the tagged spelling once.
  // Holding the written form here instead would refuse an account the
  // subaddress routing already delivers to it.
  var canonical = allowed.every(function (entry) {
    var parsed = identity.address.parse(entry);
    return parsed.ok && parsed.address === entry;
  });
  count("every author address is held in the canonical form routing uses",
    canonical, JSON.stringify(allowed));

  // The pairing that makes this a parity check rather than a list: each
  // address the account may write is one routing sends back to it.
  for (var i = 0; i < allowed.length; i += 1) {
    var verdict = identity.resolve(allowed[i]);
    var reaches = (verdict.targets || []).some(function (target) {
      return target.accountId === alice.id;
    });
    count("routing delivers " + allowed[i] + " to the account that may write it",
      reaches, JSON.stringify({ address: allowed[i], reason: verdict.reason }));
  }

  // The tagged spelling of an address in the set is the same address,
  // which is the property the listener depends on and the one the
  // envelope binding inside the framework still does not have.
  var tagged = identity.address.parse("alice+receipts@" + DOMAIN);
  count("a subaddress of an author it may write folds to that author",
    tagged.ok && allowed.indexOf(tagged.address) !== -1,
    JSON.stringify({ written: tagged.written, folded: tagged.address }));

  // An account with no aliases still holds its own address, so an empty
  // alias table is never read as an empty identity set.
  var stranger = blamepost.mail.listeners.permittedAuthors(identity,
    { id: "acct_absent", address: "nobody@" + DOMAIN });
  count("an account with no aliases still may write its own address",
    stranger.length === 1 && stranger[0] === "nobody@" + DOMAIN,
    JSON.stringify(stranger));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("addrparity");
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
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    // An alias that lands in her mailbox and a catch-all that lands
    // there too. The author set has to take the first and leave the
    // second, so both exist before it is asked.
    await identity.aliases.add({ address: "sales@" + DOMAIN, destination: alice.address });
    await identity.aliases.add({ catchAll: true, domain: DOMAIN, destination: alice.address });

    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({
      dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });

    // The three spellings of one mailbox, each in its own message, so a
    // failure names which spelling the comparison did not recognize.
    var SPELLINGS = [
      ["canonical spelling", "alice@example.com",      "alice@example.com"],
      ["mixed case",         "Alice@Example.com",      "Alice@Example.com"],
      ["a plus tag",         "alice+list@example.com", "alice+list@example.com"],
    ];

    var seeded = SPELLINGS.map(function (row, i) {
      var stored = identity.mailbox.appendMessage("INBOX",
        messageAddressedTo(row[1] + ", " + CAROL, "parity" + i),
        { actor: { id: alice.id } });
      return { label: row[0], spelling: row[2], objectId: stored.objectid };
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
    var ports = await listener.start();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    await reader.signIn("alice@" + DOMAIN, ALICE_PASSWORD);

    for (var i = 0; i < seeded.length; i += 1) {
      await replyAllExcludesTheAuthor(reader, seeded[i],
        "browser reply-all, " + seeded[i].label, seeded[i].spelling);
    }

    routingResolvesEverySpellingToOneMailbox(identity, SPELLINGS);
    permittedAuthorsAgreesWithRouting(identity, alice);

    return helpers.getChecks();
  } finally {
    if (listener) {
      try { await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS }); }
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
  name:      "address-identity-parity",
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
