// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The sending-credential registry followed from the open that builds it
 * to the assembly that composes against it.
 *
 * `sending-credential-registry.test.js` drives the registry with the
 * four handles handed straight to it, which answers what the registry
 * does and says nothing about where the handles come from.
 * `sending-credential-scope.test.js` drives a credential on the wire.
 * This file answers the join between them, and it is the join this
 * project gets wrong most often: a subsystem that is complete, tested
 * and reachable from nowhere.
 *
 *   - opening the volume builds the registry, and the four handles it
 *     composes against are the ones this open hands out, measured by
 *     the alias a credential mints turning up in this handle's alias
 *     table and this handle's routing answering for it;
 *   - a server assembled over a store carrying no registry is refused
 *     rather than started with every credential refused at sign-in;
 *   - a registry that verifies and cannot count is refused too, because
 *     the ceiling is enforced at the submission handoff and a server
 *     that authenticates without counting has no ceiling at all;
 *   - closing the store gives the registry's counter cache back, since
 *     it arms a sweep timer at construction;
 *   - and a read-only open carries it, because `credential list`,
 *     `credential show` and `credential bounces` are answered from one.
 *
 * Real database, real vault, no listeners bound: nothing here binds a
 * port, because the claim is about what the assembly refuses and
 * `blamepost.create` decides that before anything listens.
 *
 * Run standalone: node test/layer-1-state/sending-credential-wiring.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The mailbox the credential's bounces are delivered to. Not `bounces`:
// that local part is the address every return path in the domain folds
// down to, so an account standing on it would be a mailbox competing
// with the alias the registry writes there.
var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

// The surface the assembly reads off the registry, and the surface an
// operator drives. Both are named because they fail apart: a registry
// that verifies and cannot count composes a server with no ceiling, and
// a registry that counts and cannot be listed composes a console with
// nothing to show.
var LISTENER_SURFACE = ["verify", "stillSending"];
var OPERATOR_SURFACE = [
  "create", "show", "list", "rotate", "revoke", "remove",
  "setRefusedLocalParts", "returnPathReport", "close",
];

// ---------------------------------------------------------------------------

function theStoreHandsOutTheRegistry(identity) {
  var registry = identity.credentials;

  count("opening the volume hands out the sending-credential registry, so the subsystem is " +
    "reachable from the handle every caller already holds",
    registry !== null && registry !== undefined && typeof registry === "object",
    String(registry));

  var missingListener = LISTENER_SURFACE.filter(function (name) {
    return typeof registry[name] !== "function";
  });
  count("it carries what the submission listener reads",
    missingListener.length === 0, missingListener.join(", "));

  count("and the counters the ceiling is enforced on, which is the half a listener reads " +
    "after the credential has already verified",
    registry.counters !== null && typeof registry.counters === "object" &&
    typeof registry.counters.record === "function" &&
    typeof registry.counters.read === "function" &&
    typeof registry.counters.release === "function",
    JSON.stringify(Object.keys(registry.counters || {})));

  var missingOperator = OPERATOR_SURFACE.filter(function (name) {
    return typeof registry[name] !== "function";
  });
  count("and every verb an operator drives against a credential",
    missingOperator.length === 0, missingOperator.join(", "));
}

// The registry composes against four handles, and the whole reason to
// build it inside the store is that they are the store's own. A registry
// handed a second set would issue credentials whose bounces route
// through an alias table this handle cannot see, and nothing about the
// credential would say so.
async function theRegistryIsComposedAgainstThisOpen(identity) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "the shop front sends receipts",
  });

  count("a credential issued through the store's registry names the domain it speaks for",
    made.domain === DOMAIN, made.domain);
  // The return path is addressed under a keyed tag rather than the
  // credential's identifier. The identifier is what a failed guess is
  // charged against, so publishing it on every message would let anyone
  // who received one lock the credential out.
  count("and carries the return path its bounces come back to, under a tag and not its identifier",
    typeof made.returnPath === "string" &&
    typeof made.returnPathTag === "string" && made.returnPathTag !== made.id &&
    made.returnPath.indexOf("+" + made.returnPathTag + "@") !== -1 &&
    made.returnPath.indexOf(made.id) === -1 &&
    made.returnPath.indexOf("@" + DOMAIN) !== -1,
    made.returnPath);

  // The alias half. Creation writes one alias per domain at the address
  // every return path folds down to, and it goes through the handle the
  // registry was composed with.
  var aliasRows = identity.aliases.list({ address: "bounces@" + DOMAIN });
  count("the alias creation minted is on this open's alias table, so the registry was " +
    "composed against the store's own aliases rather than a second set",
    aliasRows.length === 1 && aliasRows[0].destinationMailbox === BOUNCE_MAILBOX,
    JSON.stringify(aliasRows.map(function (row) { return row.destinationMailbox; })));

  // The routing half. The registry resolves the return path on every
  // operator-facing read, and it resolves it through this handle.
  var routed = identity.resolve(made.returnPath);
  count("this open's routing answers for that return path, so the lookup the registry " +
    "resolves a credential's bounces through is the one the listeners run",
    routed.deliverable === true &&
    routed.targets.length === 1 &&
    routed.targets[0].mailbox === BOUNCE_MAILBOX,
    JSON.stringify(routed.targets.map(function (t) { return t.mailbox; })));

  var shown = await identity.credentials.show(made.id);
  count("and the registry reports the bounces as reaching the mailbox the operator named",
    shown !== null && shown.returnPathDeliverable === true &&
    shown.returnPathDeliversTo.length === 1 &&
    shown.returnPathDeliversTo[0] === BOUNCE_MAILBOX,
    shown === null ? "no such credential" : String(shown.returnPathReason));

  return made;
}

// ---------------------------------------------------------------------------

function assemblyRefusal(runtimeConfig, identity, storeHandle) {
  var refused = null;
  try {
    blamepost.create({
      config:       runtimeConfig,
      store:        storeHandle,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
    });
  } catch (e) { refused = e; }
  return refused;
}

// A store with everything the assembly reads except the registry.
// Wired defensively, that store starts a server which binds every port,
// reports every listener bound, and refuses every credential this server
// issued under the reply a wrong password draws. The refusal is what
// makes the wiring a requirement rather than a convention.
function aStoreWithNoRegistryIsRefused(identity, cfg) {
  var runtimeConfig = Object.assign({}, cfg, { httpPort: 0, httpsPort: 0 });

  var absent = assemblyRefusal(runtimeConfig, identity,
    Object.assign({}, identity, { credentials: undefined }));
  count("a server assembled over a store carrying no credentials handle is refused rather " +
    "than started with every sending credential refused at sign-in",
    absent !== null && /credentials/.test(String(absent.message)),
    absent === null ? "assembled" : String(absent.message).slice(0, 200));
  count("and the refusal names the call that builds one, so an operator reading it has " +
    "somewhere to go",
    absent !== null && String(absent.message).indexOf("blamepost.store.open") !== -1,
    absent === null ? "" : String(absent.message).slice(0, 300));

  // The second half, and the one a shape check alone would let through.
  // The ceiling is enforced at the submission handoff by counting the
  // message, so a registry that verifies and cannot count authenticates
  // every credential and bounds none of them. Nothing on the wire says
  // so: the mail is accepted.
  var cannotCount = assemblyRefusal(runtimeConfig, identity, Object.assign({}, identity, {
    credentials: { verify: identity.credentials.verify },
  }));
  count("a registry that verifies and cannot count is refused too, because a server that " +
    "authenticates a credential without counting its traffic has no ceiling at all",
    cannotCount !== null && /credentials/.test(String(cannotCount.message)),
    cannotCount === null ? "assembled" : String(cannotCount.message).slice(0, 200));

  // The third half, and the one that only shows on a session nobody
  // closed. The scope is settled at AUTH, so a registry that verifies and
  // counts and cannot be asked whether the credential still stands is a
  // server where an expiry passes and a withdrawn domain lands while the
  // connection that authenticated before either goes on sending.
  var cannotAsk = assemblyRefusal(runtimeConfig, identity, Object.assign({}, identity, {
    credentials: {
      verify:   identity.credentials.verify,
      counters: identity.credentials.counters,
    },
  }));
  count("a registry that verifies and counts but cannot say whether a credential is still " +
    "sending is refused, because the scope a session carries is settled at sign-in and " +
    "nothing else would ever re-ask",
    cannotAsk !== null && /credentials/.test(String(cannotAsk.message)),
    cannotAsk === null ? "assembled" : String(cannotAsk.message).slice(0, 200));

  var accepted = assemblyRefusal(runtimeConfig, identity, identity);
  count("and the store this open hands out satisfies the same check, so the requirement is " +
    "one the shipped assembly meets rather than one nothing can",
    accepted === null,
    accepted === null ? "" : String(accepted.message).slice(0, 300));
}

// ---------------------------------------------------------------------------

// The registry keeps its ceiling counters in a cache that arms a sweep
// timer at construction, so something has to give it back. The store
// owns the registry, so the store is what closes it; a caller expected
// to remember is a caller that eventually does not.
function theRegistryGoesBackWithTheStore(identity) {
  var registry = identity.credentials;
  var realClose = registry.close;
  var closed = 0;
  registry.close = function () {
    closed += 1;
    return realClose.call(registry);
  };

  store.close();

  count("closing the store gives the registry back, so no sweep timer is left armed beside " +
    "a database that is gone",
    closed === 1, String(closed));

  count("and closing again is not an error, so a shutdown path does not have to know how " +
    "far the boot got",
    (function () {
      try { store.close(); return true; }
      catch (_e) { return false; }
    })() && closed === 1,
    String(closed));

  registry.close = realClose;
}

// ---------------------------------------------------------------------------

// `credential list`, `credential show` and `credential bounces` are
// declared as verbs a read-only open may answer, and each of them
// resolves where a credential's bounces are landing right now. That
// reading is the only thing that reports a bounce mailbox archived after
// the credential was created, and the moment an operator wants it is a
// moment the server is running, so the registry has to be on the
// read-only handle as well.
async function aReadOnlyOpenCarriesTheRegistry(cfg, made) {
  var copy = await store.openSnapshot(cfg);
  try {
    count("a read-only open carries the registry, because the three credential verbs it " +
      "serves are answered from one",
      copy.credentials !== null && copy.credentials !== undefined &&
      typeof copy.credentials.list === "function",
      String(copy.credentials));

    var listed = await copy.credentials.list({ domain: DOMAIN });
    count("and it answers with the credential that is on the volume",
      listed.some(function (row) { return row.id === made.id; }),
      JSON.stringify(listed.map(function (row) { return row.id; })));

    var report = await copy.credentials.returnPathReport({ domain: DOMAIN });
    count("the return path reading is made from the copy as well, which is the answer an " +
      "operator asks for while the server holds the volume",
      report.domain === DOMAIN && report.credentials >= 1 &&
      report.unreachable.length === 0,
      JSON.stringify({ credentials: report.credentials,
        unreachable: report.unreachable.length }));
  } finally {
    copy.close();
  }
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-wiring");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    // The store refuses to open without this: it decrypts a working copy
    // of the database and will not put one somewhere it was not told to.
    process.env.BLAMEJS_TMPDIR = workDir;

    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: ACCOUNT_PASSWORD });

    theStoreHandsOutTheRegistry(identity);
    var made = await theRegistryIsComposedAgainstThisOpen(identity);
    aStoreWithNoRegistryIsRefused(identity, cfg);
    theRegistryGoesBackWithTheStore(identity);

    // After the close above, because a read-only open and a writable one
    // are the same module singleton and the writable one holds the lock.
    await aReadOnlyOpenCarriesTheRegistry(cfg, made);

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "sending-credential-wiring",
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
