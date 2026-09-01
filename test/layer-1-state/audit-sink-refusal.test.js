// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an administrative verb tells its caller when the audit sink
 * cannot write.
 *
 * Every verb in the identity and routing store performs its change and
 * then records it. The two are separate writes and the second one can
 * fail on its own: a sink an operator pointed somewhere else, a
 * namespace nothing registered, a disk that filled between them. The
 * change is already on disk by then and no later write can take it back,
 * so the only question left is what the caller is told.
 *
 * There are two honest answers and the failure here is neither of them.
 * Letting the sink's error out of the verb hands the caller a refusal
 * about a sink for an operation that succeeded, which reads as "the
 * domain was not added" and means "the domain was added and the row was
 * not written". Those need opposite responses from an operator and the
 * error tells them apart from nothing. The other answer is that the
 * verb reports its own outcome and the row is lost, which is what the
 * key lifecycle already does one layer up.
 *
 * The damage is not confined to the verb either. A DKIM mint writes the
 * sealed private key, then the selector row that points at it. If
 * writing the row's audit event throws, the mint's own unwind sees a
 * selector it does not believe was added, erases the key file and leaves
 * the row: an active selector naming a key that is no longer there,
 * which is a domain that signs nothing and fails DMARC alignment on
 * everything it sends. An unavailable audit sink turning into a signing
 * outage is the reason this is settled here rather than left to taste.
 *
 * The fault is injected through `b.audit.useStore`, the framework's own
 * external-store seam, in the mode where a store failure reaches the
 * caller. Nothing is monkey-patched, and the sink refuses EVERY event
 * rather than a chosen namespace. A sink scoped to one namespace is what
 * a test has to fall back on while the store breaks first, and scoping
 * it is exactly the reading this file exists to remove.
 *
 * Run standalone: node test/layer-1-state/audit-sink-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var dkimMod = require("../../lib/mail/dkim");

// The shared assertion rather than a copy of it, so a failure line reads
// the same as every other file's and can be grepped for.
var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SPARE    = "spare.example";
var MINTED   = "minted.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var REPLACEMENT_PASSWORD = "another passphrase entirely 7734";

// What the sink says when it refuses. It is checked for by name, because
// the whole claim is that this text never reaches an operator who asked
// for something else.
var SINK_REFUSAL = "the audit sink is unavailable";

// Every row the administrative verbs in this run write, named so the run
// can prove the sink was actually in the way of each of them. Written out
// rather than counted: a total says how many rows were attempted and not
// which, so a verb that quietly stopped emitting would keep the total
// whole as long as some other verb emitted twice.
var ADMINISTRATIVE_ACTIONS = [
  "domain.added",
  "domain.dns_acknowledged",
  "domain.status_changed",
  "domain.removed",
  "domain.selector_added",
  "domain.selector_retiring",
  "domain.selector_removed",
  "account.created",
  "account.suspended",
  "account.reinstated",
  "account.password_changed",
  "account.lockout_released",
  "account.archived",
  "alias.added",
  "alias.status_changed",
  "alias.removed",
  "blamepost.store.blobs.reclaimed",
];

// ---- the sink ----------------------------------------------------------------

// The framework's external-store seam in redirect mode, where a store
// failure propagates to whatever called `record`. It is the shipped way
// to put a sink in front of the chain, so the fault arrives through
// surface this server already composes.
//
// It refuses everything. That is the point: the previous fault injection
// in this tree had to name one namespace and let the rest through,
// because a sink that refused every event broke the store's own writes
// before it reached the verbs under test.
// The actions it refused are reported rather than a count of them. A
// total is not a deterministic number here: the sign-in path emits
// through the buffered fire-and-forget entry point, whose flush can land
// during this run or after it, and a bound that moved with it would be
// the kind of check that passes probabilistically.
function aSinkThatRefusesEverything() {
  var seen = [];
  b.audit.useStore({
    replaceChain: true,
    record:       function (row) {
      seen.push(row && row.action);
      throw new Error(SINK_REFUSAL);
    },
  });
  return function refused() { return seen; };
}

// Which of the actions a run expected never reached the sink. A verb
// whose row was never attempted is a verb the checks above proved
// nothing about, because the sink it was supposed to be running against
// was never in its way.
function unattempted(refused, expected) {
  return expected.filter(function (action) { return refused.indexOf(action) === -1; });
}

// Whether a thrown value is the sink's refusal wearing another verb's
// clothes. A message that carries the sink text is the ambiguity this
// file is about, whatever error class it arrived as.
function isSinkRefusal(e) {
  return e !== null && e !== undefined &&
    String((e && e.message) || e).indexOf(SINK_REFUSAL) !== -1;
}

// Run one verb and report what came back, so a throw is data rather than
// the end of the run.
async function attempt(label, fn) {
  try { return { label: label, ok: true, value: await fn(), error: null }; }
  catch (e) { return { label: label, ok: false, value: null, error: e }; }
}

// The one assertion every verb in this file makes. A verb that performed
// its change reports its own outcome; it never hands back the sink's
// error, because an operator reading that error cannot tell a change
// that did not happen from one that did.
function reportsItsOwnOutcome(outcome) {
  count(outcome.label + " reports its own outcome rather than the audit sink's error",
    outcome.ok === true,
    outcome.ok ? "returned" : (isSinkRefusal(outcome.error)
      ? "threw the sink's refusal: " + String(outcome.error.message)
      : "threw: " + String((outcome.error && outcome.error.message) || outcome.error)));
  return outcome.value;
}

// ---- the hosted-domain verbs ---------------------------------------------------

async function theDomainVerbsSayWhatHappened(identity) {
  var added = reportsItsOwnOutcome(await attempt("domains.add",
    function () { return identity.domains.add({ domain: SPARE }); }));
  count("and the domain it says it added is hosted",
    identity.domains.get(SPARE) !== null,
    JSON.stringify(added));

  var acked = reportsItsOwnOutcome(await attempt("domains.acknowledgeDns",
    function () {
      return identity.domains.acknowledgeDns({
        domain: SPARE, acknowledgedBy: "the zone owner on call",
      });
    }));
  count("and the acknowledgement it reports is the one the MX gate reads",
    acked !== null && acked.dnsAcknowledged === true &&
    identity.domains.get(SPARE).dnsAcknowledged === true,
    JSON.stringify(acked));

  var stopped = reportsItsOwnOutcome(await attempt("domains.setStatus",
    function () {
      return identity.domains.setStatus({
        domain: SPARE, status: "disabled", reason: "moving to another host",
      });
    }));
  count("and the status it reports is the status on the row",
    stopped !== null && stopped.status === "disabled" &&
    identity.domains.get(SPARE).status === "disabled",
    JSON.stringify(stopped));

  var gone = reportsItsOwnOutcome(await attempt("domains.remove",
    function () {
      return identity.domains.remove({ domain: SPARE, reason: "moved to another host" });
    }));
  count("and the removal it reports left nothing hosted under that name",
    gone !== null && gone.outcome === "removed" && identity.domains.get(SPARE) === null,
    JSON.stringify(gone));
}

// ---- the selector verbs --------------------------------------------------------

var SELECTOR_KEY = "MCowBQYDK2VwAyEAnPjNPWnMcpQrEqHFyDvVi6lLL5m9YQ4A0Wm8SgvvR2A=";

async function theSelectorVerbsSayWhatHappened(identity) {
  var published = reportsItsOwnOutcome(await attempt("domains.addSelector",
    function () {
      return identity.domains.addSelector({
        domain:    DOMAIN,
        selector:  "bpsink",
        algorithm: "ed25519",
        publicKey: SELECTOR_KEY,
        keyRef:    DOMAIN + ".bpsink.ed25519.sealed",
      });
    }));
  count("and the selector it reports publishing is in the list a signer reads",
    published !== null &&
    identity.domains.listSelectors({ domain: DOMAIN, status: "active" })
      .some(function (s) { return s.selector === "bpsink"; }),
    JSON.stringify(published));

  // A second selector, so retiring the first one is not the domain's
  // last active key. That refusal is a rule of its own and it is not
  // what this file is measuring.
  reportsItsOwnOutcome(await attempt("domains.addSelector (the replacement)",
    function () {
      return identity.domains.addSelector({
        domain:    DOMAIN,
        selector:  "bpsink2",
        algorithm: "ed25519",
        publicKey: SELECTOR_KEY,
        keyRef:    DOMAIN + ".bpsink2.ed25519.sealed",
      });
    }));

  var retiring = reportsItsOwnOutcome(await attempt("domains.retireSelector",
    function () {
      return identity.domains.retireSelector({
        domain: DOMAIN, selector: "bpsink", algorithm: "ed25519",
      });
    }));
  count("and the selector it reports retiring is retiring on the row",
    retiring !== null && retiring.status === "retiring" &&
    identity.domains.listSelectors({ domain: DOMAIN, status: "retiring" })
      .some(function (s) { return s.selector === "bpsink"; }),
    JSON.stringify(retiring));

  var withdrawn = reportsItsOwnOutcome(await attempt("domains.removeSelector",
    function () {
      return identity.domains.removeSelector({
        domain:    DOMAIN,
        selector:  "bpsink",
        algorithm: "ed25519",
        immediate: true,
        reason:    "the private half was exposed",
      });
    }));
  count("and the selector it reports withdrawing publishes nothing now",
    withdrawn !== null && withdrawn.outcome === "removed" &&
    !identity.domains.listSelectors({ domain: DOMAIN })
      .some(function (s) { return s.selector === "bpsink"; }),
    JSON.stringify(withdrawn));
}

// ---- the account verbs ---------------------------------------------------------

async function theAccountVerbsSayWhatHappened(identity) {
  var made = reportsItsOwnOutcome(await attempt("accounts.create",
    function () {
      return identity.accounts.create({
        address: "sink@" + DOMAIN, password: ALICE_PASSWORD,
      });
    }));
  count("and the account it reports creating can be looked up",
    made !== null && identity.accounts.get(made.id) !== null,
    JSON.stringify(made && made.address));
  if (made === null) return null;

  var stopped = reportsItsOwnOutcome(await attempt("accounts.suspend",
    function () {
      return identity.accounts.suspend({ id: made.id, reason: "credential reuse reported" });
    }));
  count("and the suspension it reports is the status on the row",
    stopped !== null && stopped.status === "suspended" &&
    identity.accounts.get(made.id).status === "suspended",
    JSON.stringify(stopped && stopped.status));

  var back = reportsItsOwnOutcome(await attempt("accounts.reinstate",
    function () { return identity.accounts.reinstate({ id: made.id }); }));
  count("and the reinstatement it reports is the status on the row",
    back !== null && back.status === "active" &&
    identity.accounts.get(made.id).status === "active",
    JSON.stringify(back && back.status));

  reportsItsOwnOutcome(await attempt("accounts.setPassword",
    function () {
      return identity.accounts.setPassword({ id: made.id, password: REPLACEMENT_PASSWORD });
    }));
  var proven = await identity.accounts.authenticate({
    address: "sink@" + DOMAIN, password: REPLACEMENT_PASSWORD,
  });
  count("and the password it reports replacing is the one that now signs in",
    proven.ok === true, JSON.stringify(proven.reason));

  reportsItsOwnOutcome(await attempt("accounts.unlock",
    function () {
      return identity.accounts.unlock({
        address: "sink@" + DOMAIN, reason: "the client was sending a stale password",
      });
    }));

  var archived = reportsItsOwnOutcome(await attempt("accounts.delete (archive)",
    function () {
      return identity.accounts["delete"]({ id: made.id, reason: "the holder left" });
    }));
  count("and the archive it reports is the status on the row",
    archived !== null && archived.outcome === "archived" &&
    identity.accounts.get(made.id).status === "archived",
    JSON.stringify(archived && archived.outcome));

  return made;
}

// An erasure is the one verb where nothing can be read back afterwards
// to check what happened, so what it reports is the whole of what an
// operator has. A sink refusal arriving instead leaves them unable to
// tell an erasure that ran from one that did not, on the one operation
// that cannot be repeated to find out.
async function theErasureSaysWhatHappened(identity) {
  var doomed = await identity.accounts.create({
    address: "erased@" + DOMAIN, password: ALICE_PASSWORD,
  });
  var refused = aSinkThatRefusesEverything();
  var destroyed = reportsItsOwnOutcome(await attempt("accounts.delete (destroy)",
    function () {
      return identity.accounts["delete"]({
        id: doomed.id, reason: "erasure requested by the holder", destroy: true,
      });
    }));
  count("and the erasure it reports left no account at that address",
    destroyed !== null && destroyed.outcome === "destroyed" &&
    identity.accounts.get("erased@" + DOMAIN) === null,
    JSON.stringify(destroyed && destroyed.outcome));
  count("the sink refused the erasure's own row, so the check above ran against a sink " +
    "that really could not write",
    refused().indexOf("account.destroyed") !== -1, JSON.stringify(refused()));
  b.audit.useStore(null);
}

// ---- the alias verbs -----------------------------------------------------------

async function theAliasVerbsSayWhatHappened(identity) {
  var forwarded = reportsItsOwnOutcome(await attempt("aliases.add",
    function () {
      return identity.aliases.add({
        address: "sales@" + DOMAIN, destination: "alice@" + DOMAIN,
      });
    }));
  count("and the alias it reports adding is in the list",
    forwarded !== null &&
    identity.aliases.list({ domain: DOMAIN })
      .some(function (a) { return a.address === "sales@" + DOMAIN; }),
    JSON.stringify(forwarded && forwarded.address));
  if (forwarded === null) return;

  var disabled = reportsItsOwnOutcome(await attempt("aliases.setStatus",
    function () {
      return identity.aliases.setStatus({
        id: forwarded.id, status: "disabled", reason: "abuse report",
      });
    }));
  count("and the status it reports is the status on the row",
    disabled !== null && disabled.status === "disabled",
    JSON.stringify(disabled && disabled.status));

  var dropped = reportsItsOwnOutcome(await attempt("aliases.remove",
    function () {
      return identity.aliases.remove({ id: forwarded.id, reason: "role retired" });
    }));
  count("and the alias it reports removing forwards nothing now",
    dropped !== null && dropped.outcome === "removed" &&
    !identity.aliases.list({ domain: DOMAIN })
      .some(function (a) { return a.address === "sales@" + DOMAIN; }),
    JSON.stringify(dropped && dropped.outcome));
}

// ---- the blob sweep ------------------------------------------------------------

async function theBlobSweepSaysWhatHappened(identity) {
  var swept = reportsItsOwnOutcome(await attempt("blobs.reclaim",
    function () {
      return identity.blobs.reclaim({ reason: "octets stranded by an interrupted append" });
    }));
  count("and the sweep it reports carries the counts an operator acts on",
    swept !== null && Array.isArray(swept.reclaimed) && Array.isArray(swept.heldBack),
    JSON.stringify(swept && { reclaimed: swept.reclaimed.length }));
}

// ---- a refusal is still the caller's own refusal ---------------------------------

// The other half of the same claim. A verb that refuses for its own
// reason has to keep refusing for that reason while the sink is down,
// because a rewritten error sends an operator to fix the wrong thing.
async function aRefusalKeepsItsOwnReason(identity) {
  var taken = await attempt("domains.add (already hosted)",
    function () { return identity.domains.add({ domain: DOMAIN }); });
  count("a domain that is already hosted is still refused for being already hosted",
    taken.ok === false && !isSinkRefusal(taken.error) &&
    String(taken.error && taken.error.code) === "store/domain-taken",
    taken.ok ? "accepted" : String((taken.error && taken.error.code) || taken.error));

  var absent = await attempt("domains.retireSelector (no such selector)",
    function () {
      return identity.domains.retireSelector({
        domain: DOMAIN, selector: "nothingpublishes", algorithm: "ed25519",
      });
    });
  count("a selector nothing publishes is still refused for not being published",
    absent.ok === false && !isSinkRefusal(absent.error) &&
    String(absent.error && absent.error.code) === "store/no-such-selector",
    absent.ok ? "accepted" : String((absent.error && absent.error.code) || absent.error));

  var unnamed = await attempt("accounts.suspend (no reason)",
    function () { return identity.accounts.suspend({ id: "nothing", reason: "" }); });
  count("a verb missing a required argument is still refused for the argument",
    unnamed.ok === false && !isSinkRefusal(unnamed.error),
    unnamed.ok ? "accepted" : String((unnamed.error && unnamed.error.code) || unnamed.error));
}

// ---- the composed path: a key mint across a failing sink -------------------------

// The consequence that reaches an operator's mail rather than their
// trail. `_mintPair` writes the sealed private key and then the selector
// row; a throw between them takes the unwind branch, which erases the
// key file it knows about and leaves the row it does not. What is left
// is an active selector naming a key file that is not there.
async function aKeyMintLeavesNothingHalfDone(identity, dataDir) {
  // A domain of its own, with no selector on it. `dkim.generate` refuses
  // a domain that already has active keys, and the selector checks above
  // left some on the main one, so running there would refuse for that
  // reason and prove nothing about the sink.
  await identity.domains.add({ domain: MINTED });
  var dkim = dkimMod.create({ store: identity, dataDir: dataDir });
  var refused = aSinkThatRefusesEverything();

  var minted = await attempt("dkim.generate",
    function () { return dkim.generate({ domain: MINTED, selector: "bpmint" }); });
  count("a key mint reports its own outcome rather than the audit sink's error",
    minted.ok === true,
    minted.ok ? "returned" : (isSinkRefusal(minted.error)
      ? "threw the sink's refusal: " + String(minted.error.message)
      : "threw: " + String((minted.error && minted.error.message) || minted.error)));

  // Whatever the verb reported, the state it left is the thing an
  // operator's mail depends on, so it is checked either way.
  var keyDir = dkim.describe().keyDir;
  var active = identity.domains.listSelectors({ domain: MINTED, status: "active" });
  var stranded = active.filter(function (s) {
    return !nodeFs.existsSync(nodePath.join(keyDir, s.keyRef));
  });
  count("and no active selector is left naming a sealed key file that is not there, " +
    "which would be a domain signing nothing and failing alignment on everything it sends",
    stranded.length === 0,
    JSON.stringify(stranded.map(function (s) { return s.selector + " -> " + s.keyRef; })));

  count("the sink refused both the selector row and the mint's own row, so the checks " +
    "above ran against a sink that really could not write",
    refused().indexOf("domain.selector_added") !== -1 &&
    refused().indexOf("blamepost.mail.dkim.keys_generated") !== -1,
    JSON.stringify(refused()));
  b.audit.useStore(null);
}

// ---- runner --------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("audit-sink-refusal");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var identity = null;
  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    // Opened before the sink is installed. Boot writes rows of its own
    // and a sink refusing them would fail the open, which would prove
    // something about boot rather than about the verbs.
    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({ address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var refused = aSinkThatRefusesEverything();
    try {
      await theDomainVerbsSayWhatHappened(identity);
      await theSelectorVerbsSayWhatHappened(identity);
      await theAccountVerbsSayWhatHappened(identity);
      await theAliasVerbsSayWhatHappened(identity);
      await theBlobSweepSaysWhatHappened(identity);
      await aRefusalKeepsItsOwnReason(identity);
      var missed = unattempted(refused(), ADMINISTRATIVE_ACTIONS);
      count("every verb above ran against a sink that really could not write, rather than " +
        "against one that was never reached", missed.length === 0, JSON.stringify(missed));
    } finally {
      // Released before anything else runs. The seam is process-wide and
      // a later file sharing this process would write through it.
      b.audit.useStore(null);
    }

    await theErasureSaysWhatHappened(identity);
    await aKeyMintLeavesNothingHalfDone(identity, cfg.paths.dataDir);

    return helpers.getChecks();
  } finally {
    b.audit.useStore(null);
    if (identity !== null) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "audit-sink-refusal", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
