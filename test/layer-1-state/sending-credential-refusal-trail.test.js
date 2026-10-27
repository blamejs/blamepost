// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the audit trail holds when a presented sending credential is
 * refused for a reason the framework registry underneath cannot see.
 *
 * Three of the refusals `blamepost.store.credentials.verify` gives are
 * decided in this layer rather than by the registry: `binding-mismatch`,
 * `domain-not-hosted` and `domain-<status>`. All three are reached AFTER
 * the presented secret matched the stored digest, so the registry has
 * already answered, and what it answered was success. An operator
 * reading the trail for an application that has stopped sending finds a
 * row saying the credential verified and no row saying it was refused.
 *
 * The distinction is advertised rather than incidental. The sending
 * route answers a refused credential with a problem document telling the
 * caller that the trail records which of an unknown secret, a revoked
 * credential, an expired one or a domain no longer hosted here it was,
 * and the submission listener's own refusal rests on the same sentence.
 * A reason that reaches no row is a sentence that cannot be acted on.
 *
 * Two doors are driven for each vector, because a refusal that reaches
 * the trail through one and not the other is a trail that answers for
 * one transport. `blamepost.store.credentials.verify` is where the
 * verdict is decided, and `blamepost.mail.listeners.verifySendingCredential`
 * is the single entry point both SMTP submission and `POST /api/send`
 * present a credential through, so a row written under the first has to
 * survive the second.
 *
 * Run standalone:
 *   node test/layer-1-state/sending-credential-refusal-trail.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var listeners = require("../../lib/mail/listeners");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALPHA = "alpha.example";
var ZULU  = "zulu.example";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The action a refusal decided in this layer is filed under. It is the
// frozen half of the contract: an operator filters the trail on it, so
// it survives a rename of anything around it and disappears only when
// the row stops being written.
var REFUSED_ACTION = "domain.sending_credential_refused";

// What the framework registry files when the presented secret matched.
// It is asserted beside the refusal rather than instead of it, because
// the defect this file pins is not a missing row on its own: it is a
// success row standing alone for a credential that was refused.
var REGISTRY_ACTION = "apikey.verify";

// One verify with the trail captured around it. The capture replaces the
// audit chain for the length of the call and is released whatever the
// call does, so a refusal inside it cannot leave the suite writing rows
// into a test's array.
//
// The queue is drained on both sides of the capture. Both the framework
// registry and this layer write their rows through the fire-and-forget
// door, which queues: draining first is what keeps a row written by an
// earlier call out of this reading, and draining inside is what keeps a
// row written by this one from arriving after the array has been read.
async function verifyWatched(registry, token) {
  await b.audit.flush();
  var capture = helpers.auditCapture();
  var verdict;
  try {
    verdict = await registry.verify(token);
    await b.audit.flush();
  } finally {
    capture.release();
  }
  return { verdict: verdict, rows: capture.rows() };
}

// The same reading through the entry point both wire surfaces present a
// credential to. It answers one refusal whatever the reason was, which
// is the behavior the wire wants; the trail is where the reason has to
// survive.
async function presentWatched(registry, token, peer) {
  await b.audit.flush();
  var capture = helpers.auditCapture();
  var checked;
  try {
    checked = await listeners.verifySendingCredential(registry, {
      secret: token,
      source: peer,
    });
    await b.audit.flush();
  } finally {
    capture.release();
  }
  return { checked: checked, rows: capture.rows() };
}

function rowsFor(rows, action) {
  return rows.filter(function (row) { return row && row.action === action; });
}

// The secret half of a token, which is the part no row may carry. The
// format is `<prefix>_<namespace>_<id>_<secret>`, so the last field is
// the one to look for.
function secretHalf(token) {
  var parts = String(token).split("_");
  return parts[parts.length - 1];
}

// Every assertion one refused presentation owes the trail, asked the
// same way for each reason so a reason that reaches the trail and one
// that does not cannot be told apart by how they were measured.
function assertTheTrailNamesTheRefusal(label, reading, expected) {
  var refusals = rowsFor(reading.rows, REFUSED_ACTION);
  var registryRows = rowsFor(reading.rows, REGISTRY_ACTION);
  var succeeded = registryRows.filter(function (row) {
    return row && row.outcome === "success";
  });

  console.log("  measured: " + label + " reason=" + String(reading.verdict.reason) +
    " refusalRows=" + refusals.length +
    " registrySuccessRows=" + succeeded.length);

  count(label + ": the presentation is refused",
    reading.verdict.ok === false && reading.verdict.reason === expected.reason,
    JSON.stringify(reading.verdict));

  count(label + ": and the registry underneath recorded the secret as matching, which is " +
    "why the refusal needs a row of its own",
    succeeded.length === 1,
    "apikey.verify success rows: " + succeeded.length);

  count(label + ": and the trail carries a row naming the refusal rather than leaving the " +
    "success row to stand alone",
    refusals.length === 1,
    refusals.length + " row(s) under " + REFUSED_ACTION);
  if (refusals.length !== 1) return;

  var row  = refusals[0];
  var meta = helpers.metadataOf(row);

  count(label + ": and the row says the presentation was denied rather than recording it " +
    "as something that happened",
    row.outcome === "denied", String(row.outcome));

  count(label + ": and it names which refusal it was, which is the distinction the sending " +
    "route tells a caller to read off the trail",
    row.reason === expected.reason || meta.reason === expected.reason,
    JSON.stringify({ reason: row.reason, metadata: meta }));

  count(label + ": and it names the credential the token named, so an operator holding the " +
    "row can reach the credential it is about",
    meta.credentialId === expected.credentialId,
    JSON.stringify(meta.credentialId) + " wanted " + JSON.stringify(expected.credentialId));

  count(label + ": and it names the domain the stored row claims, so a refused credential " +
    "is filed against something rather than against nothing",
    row.resourceId === expected.domain || meta.domain === expected.domain,
    JSON.stringify({ resourceId: row.resourceId, domain: meta.domain }) +
      " wanted " + JSON.stringify(expected.domain));

  count(label + ": and no part of the presented secret reached the row",
    JSON.stringify(row).indexOf(expected.secretHalf) === -1);
}

// ---- the reasons -----------------------------------------------------------

// A row edited on the volume. The ceiling is one of the fields the keyed
// binding is taken over, so raising it behind the registry stops the
// credential; the secret is untouched, so the registry still matches it.
async function testABrokenBindingReachesTheTrail(registry) {
  var made = await registry.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking what the trail says about a row somebody edited",
    maxRecipients: 5,
  });
  count("the credential verifies before its row is edited",
    (await registry.verify(made.token)).ok === true);

  var rowId = "send:" + made.id;
  var meta  = JSON.parse(b.db.from("_blamejs_api_keys").where({ id: rowId }).first().metadata);
  meta.maxRecipients = 1000000;
  b.db.from("_blamejs_api_keys").where({ id: rowId })
    .updateOne({ metadata: JSON.stringify(meta) });

  var expected = {
    reason:       "binding-mismatch",
    credentialId: made.id,
    domain:       ZULU,
    secretHalf:   secretHalf(made.token),
  };
  assertTheTrailNamesTheRefusal("a credential whose row was edited on the volume",
    await verifyWatched(registry, made.token), expected);

  // The same refusal through the door both wire surfaces present to. The
  // client answer stays the one refusal every reason collapses to, and
  // the row is what carries the distinction past it.
  var presented = await presentWatched(registry, made.token, "203.0.113.7");
  count("and the wire entry point answers one refusal rather than naming the reason to the " +
    "caller",
    presented.checked.ok === false && presented.checked.reason === "credentials-rejected",
    JSON.stringify(presented.checked));
  count("and the row naming the reason is written on that path too, so the trail answers " +
    "for a credential presented on the wire rather than only for one checked in this layer",
    rowsFor(presented.rows, REFUSED_ACTION).length === 1,
    rowsFor(presented.rows, REFUSED_ACTION).length + " row(s) under " + REFUSED_ACTION);

  await registry.remove({
    id: made.id, destroy: true, reason: "the edited row is cleaned up after the reading" });
}

// The domain withdrawn under a credential that is otherwise intact. The
// admin console writes this through the running server, so it is reached
// by a credential that verified a minute earlier.
async function testAWithdrawnDomainReachesTheTrail(registry, handle) {
  var made = await registry.create({
    domain:        ALPHA,
    bounceMailbox: "bounces@" + ALPHA,
    reason:        "checking what the trail says about a withdrawn domain",
  });
  count("the credential verifies while its domain is in service",
    (await registry.verify(made.token)).ok === true);

  await handle.domains.setStatus({
    domain: ALPHA, status: "disabled", reason: "the operator withdrew it" });

  var expected = {
    reason:       "domain-disabled",
    credentialId: made.id,
    domain:       ALPHA,
    secretHalf:   secretHalf(made.token),
  };
  assertTheTrailNamesTheRefusal("a credential whose domain was withdrawn",
    await verifyWatched(registry, made.token), expected);

  await handle.domains.setStatus({
    domain: ALPHA, status: "active", reason: "the operator put it back" });
  count("and the credential verifies again once the domain is back, so the refusal was " +
    "about the domain rather than about the credential",
    (await registry.verify(made.token)).ok === true);

  await registry.remove({
    id: made.id, destroy: true, reason: "the reading is finished with this credential" });
}

// The refusals the registry DOES see keep their single row. A second row
// written beside the framework's own would be a trail an operator has to
// de-duplicate by hand, and the reason is already on the framework's.
async function testTheRegistrysOwnRefusalsAreNotDoubled(registry) {
  var made = await registry.create({
    domain:        ZULU,
    bounceMailbox: "bounces@" + ZULU,
    reason:        "checking that a refusal the registry can see is filed once",
  });
  await registry.revoke({ id: made.id, reason: "the application was decommissioned" });

  var reading = await verifyWatched(registry, made.token);
  count("a revoked credential is refused",
    reading.verdict.ok === false && reading.verdict.reason === "bad-credentials",
    JSON.stringify(reading.verdict));
  count("and this layer files no second row for it, because the registry already named the " +
    "revocation and two rows for one event is a trail read twice",
    rowsFor(reading.rows, REFUSED_ACTION).length === 0,
    rowsFor(reading.rows, REFUSED_ACTION).length + " row(s) under " + REFUSED_ACTION);

  // A token this server never issued names no credential, so there is
  // nothing to file a row against and a peer offering garbage must not be
  // able to write rows by offering it.
  var garbage = await verifyWatched(registry, "bpk_send_00_deadbeef");
  count("a token that is not one of this server's is refused without a row of its own, so a " +
    "peer cannot write the trail by presenting garbage",
    garbage.verdict.ok === false &&
      rowsFor(garbage.rows, REFUSED_ACTION).length === 0,
    JSON.stringify(garbage.verdict) + " / " +
      rowsFor(garbage.rows, REFUSED_ACTION).length + " row(s)");

  await registry.remove({
    id: made.id, destroy: true, reason: "the reading is finished with this credential" });
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-credtrail-"));
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

    // Two domains, so a row that names one is measured against a volume
    // where the other would have been the wrong answer.
    await handle.domains.add({ domain: ALPHA });
    await handle.domains.add({ domain: ZULU });
    await handle.accounts.create({
      address: "bounces@" + ALPHA, password: ACCOUNT_PASSWORD });
    await handle.accounts.create({
      address: "bounces@" + ZULU, password: ACCOUNT_PASSWORD });

    registry = handle.credentials;

    await testABrokenBindingReachesTheTrail(registry);
    await testAWithdrawnDomainReachesTheTrail(registry, handle);
    await testTheRegistrysOwnRefusalsAreNotDoubled(registry);
  } finally {
    if (registry !== null && typeof registry.close === "function") registry.close();
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
  name:      "sending-credential-refusal-trail",
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
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
