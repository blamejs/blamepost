// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A password reset holds, even against a sign in that is already in
 * flight with the credential being replaced.
 *
 * This is the containment step in the credential-stuffing runbook. An
 * operator sees a mailbox sending, changes its password, and from that
 * moment the credential whoever took it is holding has to be worthless.
 * The window that matters is the one inside a single sign in: the row is
 * read at the top, the credential is verified, and a stored hash below
 * the current Argon2id parameters is rehashed so that raising the cost
 * reaches every account as its owner signs in. Argon2id is deliberately
 * slow, so that rehash is a real suspension rather than a theoretical
 * one, and a reset landing inside it is a reset that has to survive.
 *
 * What it must not do is put the OLD password's hash back over the new
 * one. That is silent: the reset reports success, the operator has
 * positive confirmation they changed the password, and the credential
 * they were containing still opens the mailbox on every listener.
 *
 * The claims:
 *
 *   - A reset that lands while a sign in is suspended inside the rehash
 *     survives it. The new password opens the mailbox and the old one
 *     does not, and the stored hash no longer verifies the old one at
 *     all.
 *   - The sign in that was already in flight still succeeds. It presented
 *     a credential that was correct when it presented it, and the rehash
 *     is an optimization on top of that: abandoning it is free, and
 *     failing the sign in over it would turn a cost saving into an
 *     outage every time two calls overlapped.
 *   - The reset holds on every surface a credential arrives on. All five
 *     reach a mailbox through `blamepost.store.accounts.authenticate`:
 *     the four mail listeners through `lib/mail/listeners.js`, and the
 *     browser sign in through `lib/web/index.js`. The four listeners are
 *     driven here over the wire, and the funnel itself is driven
 *     directly, so a refusal proven here is a refusal on the surface an
 *     operator's client actually speaks.
 *
 * The interleaving is arranged rather than raced. A test that waited for
 * two Argon2id operations to land in the right order would reproduce the
 * failure only sometimes, which is the nondeterministic coverage gap and
 * is worse than no test at all. Instead the framework's hashing
 * primitive is wrapped for the length of the interleaving so that the
 * one call carrying the OLD password parks until this file releases it;
 * every other call, the reset's included, runs the real primitive
 * untouched. Nothing about the code path under test changes: the same
 * store, the same verb, the same Argon2id work, in the same order. Only
 * the moment the rehash finishes is this file's to choose, which is what
 * makes the ordering a fact rather than a hope.
 *
 * Run standalone: node test/layer-1-state/password-reset-durability.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var OLD_PASSWORD     = "quiet lantern bicycle 4291";
var NEW_PASSWORD     = "steady harbour pumpkin 7715";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// Where the sign in that is in flight across the reset arrives from, and
// where the calls that read the outcome afterwards arrive from. Separate
// addresses so neither shares a failure counter with the wire sessions
// below, which all arrive from the loopback address the runtime picks.
var SIGNIN_SOURCE = "127.0.0.3";
var STORE_SOURCE  = "127.0.0.2";

// Argon2id parameters below what this server hashes at today, so the
// account reads as one created before the cost was raised and its next
// sign in rehashes. The numbers are deliberately far below the shipped
// ones rather than one notch under: what this fixture needs is for
// `needsRehash` to answer true, and a value that merely lags by a
// revision would stop doing that the moment the shipped parameters
// moved.
var LEGACY_HASH_PARAMS = { memoryCost: 8192, timeCost: 2, parallelism: 1 };

var SHUTDOWN_TIMEOUT_MS = 5000;

// How long the sign in may stay parked inside the rehash before this
// file gives up on the reset that is supposed to land there. Generous,
// because the reset it is waiting on performs a real Argon2id hash and a
// loaded runner is the case a fixed budget gets wrong.
var PARK_TIMEOUT_MS = 30000;

// The authenticating surfaces this file answers for. Printed at the end
// as the unit examined, because a run that bound one listener and a run
// that bound four both report the same check total otherwise.
var SURFACES_EXAMINED = 5;

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

// The framework's hashing primitive, wrapped so one call parks. Every
// call whose plaintext is not the parked one runs the real primitive, so
// the reset that lands inside the window does its own Argon2id work
// exactly as it would in production.
//
// Installed after the account exists, because creating it hashes the
// same plaintext, and removed as soon as the interleaving is over.
function installHashGate(plaintextToPark) {
  var real = b.auth.password.hash;
  var state = { parked: null, real: real, calls: 0 };
  b.auth.password.hash = function (plain, opts) {
    state.calls += 1;
    if (plain !== plaintextToPark || state.parked !== null) {
      return real.call(b.auth.password, plain, opts);
    }
    return new Promise(function (resolve, reject) {
      state.parked = { plain: plain, opts: opts, resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installHashGate: nothing is parked to release");
    return real.call(b.auth.password, held.plain, held.opts).then(held.resolve, held.reject);
  };
  state.remove = function () { b.auth.password.hash = real; };
  return state;
}

// One credential, offered to one listener, reported as the listener
// answered rather than as this file hoped. The shared ladders throw
// rather than hand back a session they could not raise, so the verdict
// is whether the ladder threw, and its message carries the listener's
// own reply for whoever reads a failure.
async function offerOnWire(ladder, password, label) {
  var threw = null;
  var session = null;
  try {
    session = await ladder.open(ladder.port, Object.assign({}, ladder.opts, {
      password: password,
      label:    ladder.name + "-" + label,
    }));
  } catch (e) { threw = e; }
  if (session) session.close();
  return {
    granted: threw === null,
    detail:  threw === null ? "the listener granted the session" : visible(threw.message),
  };
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("pwreset");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;
  var gate    = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      // The classical bridge rather than the CA default, because this
      // certificate exists to make a node:tls handshake happen on the
      // loopback interface.
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_POP3_ENABLED:     "true",
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: OLD_PASSWORD });

    // 1. Age the stored hash, so the next sign in rehashes it. This is
    //    what an account created before the parameters were raised looks
    //    like on disk, and the rehash it triggers is the suspension the
    //    reset below has to survive.
    var legacyHash = await b.auth.password.hash(OLD_PASSWORD, LEGACY_HASH_PARAMS);
    tables.updateRow(tables.ACCOUNTS, alice.id, {
      passwordHash: legacyHash,
      updatedAt:    Date.now(),
    });
    count("the stored hash now reads as one below the current parameters, so signing in " +
      "rehashes it", b.auth.password.needsRehash(legacyHash) === true, legacyHash.slice(0, 30));

    // How wide the window actually is, measured rather than assumed. It
    // is printed rather than asserted: the number is hardware, and a
    // threshold on it would be a flake on a loaded runner. What the
    // claims below rest on is the ordering, which is arranged.
    var hashStart = Date.now();
    await b.auth.password.hash(OLD_PASSWORD);
    console.log("  one Argon2id hash at the shipped parameters: " +
      (Date.now() - hashStart) + "ms; a sign in that rehashes holds its row across " +
      "two of them");

    // 2. A sign in with the old password, which is correct at the moment
    //    it is presented. It parks inside the rehash.
    gate = installHashGate(OLD_PASSWORD);
    var signIn = identity.accounts.authenticate({
      address:  alice.address,
      password: OLD_PASSWORD,
      source:   SIGNIN_SOURCE,
    });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "password-reset-durability: the sign in reaching its rehash",
    });
    count("the sign in has read the account row and suspended inside the rehash",
      gate.parked !== null, gate.calls + " hash call(s)");

    // 3. The operator's containment step, landing inside that window and
    //    completing before the sign in resumes.
    var reset = await identity.accounts.setPassword({
      id: alice.id, password: NEW_PASSWORD });
    count("the reset completes while the sign in is still suspended",
      reset.id === alice.id && gate.parked !== null, JSON.stringify(reset.id));

    var afterReset = b.db.from(tables.ACCOUNTS).where({ _id: alice.id }).first();
    count("and the stored hash is the one the reset wrote",
      (await b.auth.password.verify(afterReset.passwordHash, NEW_PASSWORD)) === true,
      afterReset.passwordHash.slice(0, 30));

    // 4. Now let the rehash finish. Everything the sign in does from here
    //    is decided against a row that has moved under it.
    await gate.release();
    var verdict = await signIn;
    gate.remove();
    gate = null;

    // The sign in itself still succeeds. The credential was correct when
    // it was presented, and a rehash that cannot be completed is a cost
    // saving that was not taken rather than an authentication failure.
    count("the sign in that was already in flight is still granted",
      verdict.ok === true && verdict.accountId === alice.id, JSON.stringify(verdict));

    // 5. The claim. The reset has to have survived the rehash.
    var storedNow = b.db.from(tables.ACCOUNTS).where({ _id: alice.id }).first();
    count("the stored hash no longer verifies the password the operator replaced",
      (await b.auth.password.verify(storedNow.passwordHash, OLD_PASSWORD)) === false,
      storedNow.passwordHash.slice(0, 30));
    count("and still verifies the one they set",
      (await b.auth.password.verify(storedNow.passwordHash, NEW_PASSWORD)) === true,
      storedNow.passwordHash.slice(0, 30));

    // 6. Through the funnel every authenticating surface reaches, which
    //    is the one the browser sign in calls.
    var newAtFunnel = await identity.accounts.authenticate({
      address: alice.address, password: NEW_PASSWORD, source: STORE_SOURCE });
    count("the new password opens the mailbox", newAtFunnel.ok === true,
      JSON.stringify(newAtFunnel));

    var oldAtFunnel = await identity.accounts.authenticate({
      address: alice.address, password: OLD_PASSWORD, source: STORE_SOURCE });
    count("and the replaced one does not", oldAtFunnel.ok === false,
      JSON.stringify(oldAtFunnel));
    // The reason, not merely the refusal. A mailbox whose failure budget
    // had run out would also be refused, and that refusal would say
    // nothing about the credential; this one has to be the credential.
    count("refused on the credential rather than on a spent failure budget",
      oldAtFunnel.reason === "bad-credentials", JSON.stringify(oldAtFunnel.reason));

    // 6b. A rehash the volume will not take is not an authentication
    //     failure either. The credential has already verified, which is
    //     the question the verb answers, so refusing over a write that
    //     is housekeeping would turn a storage fault into every mailbox
    //     on this server being unable to sign in on any listener. The
    //     write is refused here through the same kind of seam the
    //     interleaving used: one call made to fail, everything else real.
    var agedAgain = await b.auth.password.hash(NEW_PASSWORD, LEGACY_HASH_PARAMS);
    tables.updateRow(tables.ACCOUNTS, alice.id, {
      passwordHash: agedAgain,
      updatedAt:    Date.now(),
    });

    var realUpdateRow = tables.updateRow;
    tables.updateRow = function () { throw new Error("the data volume refused this write"); };
    var withFailedRehash;
    try {
      withFailedRehash = await identity.accounts.authenticate({
        address: alice.address, password: NEW_PASSWORD, source: STORE_SOURCE });
    } finally {
      tables.updateRow = realUpdateRow;
    }
    count("a rehash the volume refuses does not fail the sign in that triggered it",
      withFailedRehash.ok === true, JSON.stringify(withFailedRehash));

    var stillAged = b.db.from(tables.ACCOUNTS).where({ _id: alice.id }).first();
    count("and the stored hash is left as the one that verified, so nothing was half-written",
      b.auth.password.needsRehash(stillAged.passwordHash) === true &&
      (await b.auth.password.verify(stillAged.passwordHash, NEW_PASSWORD)) === true,
      stillAged.passwordHash.slice(0, 30));

    // 7. And on the wire, on every listener a mail client authenticates
    //    against. A rule shared by four listeners and proven on one is a
    //    rule three listeners have not been asked about.
    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    // What every ladder takes, spelled once. Each listener refuses a
    // credential before TLS, so the upgrade and the chain verification
    // are part of reaching the authentication at all.
    var ladderOpts = {
      caPem:      leaf.ca,
      servername: HOSTNAME,
      address:    alice.address,
    };
    var imapLadder = { name: "IMAP", open: Wire.imap, port: sections.imap.port,
      opts: ladderOpts };
    var ladders = [
      { name: "submission",  open: Wire.submission,  port: sections.submission.port,
        opts: ladderOpts },
      imapLadder,
      { name: "POP3",        open: Wire.pop3,        port: sections.pop3.port,
        opts: ladderOpts },
      { name: "ManageSieve", open: Wire.managesieve, port: sections.managesieve.port,
        opts: ladderOpts },
    ];

    for (var i = 0; i < ladders.length; i += 1) {
      var ladder = ladders[i];
      var withNew = await offerOnWire(ladder, NEW_PASSWORD, "new");
      count("the new password authenticates on " + ladder.name, withNew.granted === true,
        withNew.detail);

      var withOld = await offerOnWire(ladder, OLD_PASSWORD, "old");
      count("and the replaced one is refused on " + ladder.name, withOld.granted === false,
        withOld.detail);
    }

    // 8. The mailbox is still the account holder's. Four refusals have
    //    been spent against it above, so this also says the containment
    //    did not turn into an outage.
    var stillTheirs = await offerOnWire(imapLadder, NEW_PASSWORD, "settled");
    count("and the mailbox still signs in with the password its owner now holds",
      stillTheirs.granted === true, stillTheirs.detail);

    // 9. The rehash the volume refused was left for the next sign in
    //    rather than lost, and the sign ins above are that next one. A
    //    replacement that were dropped instead would leave the account
    //    below the current parameters for as long as the password stood.
    var settledHash = b.db.from(tables.ACCOUNTS).where({ _id: alice.id }).first();
    count("a rehash a refused write left behind is taken by a later sign in",
      b.auth.password.needsRehash(settledHash.passwordHash) === false,
      settledHash.passwordHash.slice(0, 30));

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (gate !== null) gate.remove();
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "password-reset-durability",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. The line beside it names what was examined, because a run
// that bound one listener and a run that bound four otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + SURFACES_EXAMINED + " authenticating-surface");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed.
    process.exitCode = 1;
  });
}
