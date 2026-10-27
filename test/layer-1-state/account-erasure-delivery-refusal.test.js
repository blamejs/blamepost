// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether the recipient lookup refuses mail for an account whose erasure
 * is still outstanding.
 *
 * `blamepost.store.resolve` is the lookup every wire listener runs on a
 * recipient, and the MX listener accepts or refuses the RCPT from what it
 * answers. `lib/mail/listeners.js` maps the reason `account-erasing` onto
 * a 550 with the enhanced code 5.1.1, so an account part-way through an
 * erasure is a recipient this server declines.
 *
 * An erasure records itself on the account row twice, and the two columns
 * are read together everywhere else: `lib/store/tables.js` says so above
 * the marker column, and the account layer's own reader lets the marker
 * outrank the status column. The reason there are two is that the status
 * transition is one write and a records-retention posture can refuse it,
 * which leaves the marker standing alone on a row whose status column
 * still reads `active`.
 *
 * So the same account answers two different ways depending on which
 * reader is asked, and only one of the two decides whether mail is
 * accepted. This drives both postures through the shipped lookup:
 *
 *   - the erasure whose status transition landed, which is the posture
 *     the bug cannot appear in and is here as the control;
 *   - the erasure whose status transition was refused and whose marker
 *     landed, which is the posture a records-retention trigger produces.
 *
 * Both are driven at the address itself and through an alias pointing at
 * it, because the lookup reads the account row in two places and a case
 * that drove one of them would leave the other unmeasured.
 *
 * Mail accepted for such a mailbox is mail nobody can ever read: the
 * owner cannot sign in, the erasure that destroyed the rest of the
 * mailbox is still outstanding, and the sender was told 250.
 *
 * Run standalone: node test/layer-1-state/account-erasure-delivery-refusal.test.js
 */

var helpers   = require("../helpers");
var writeFault = require("../helpers/account-status-write-fault");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var OWNER_PASSWORD   = "quiet lantern bicycle 4291";
var DOMAIN           = "example.com";
var ERASURE_REASON   = "erasure requested by the account holder";

function heldMail(address) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + address + ">\r\n" +
    "Subject: held\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <held-" + address.slice(0, address.indexOf("@")) + "@example.net>\r\n" +
    "\r\nBody.\r\n", "utf8");
}

// One account whose erasure destroyed what it could and left the row
// behind, with a message a preservation order holds so the row survives.
// `armFault` is the volume fault to run the erasure under, or null for a
// volume that takes every write.
async function anOutstandingErasure(identity, address, armFault) {
  var doomed = await identity.accounts.create({ address: address, password: OWNER_PASSWORD });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"],
  };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(address), { actor: owner });
  identity.messageStore.setLegalHold([kept.objectid], { hold: true });

  var restore = armFault === null ? function () {} : armFault();
  var outcome;
  try {
    outcome = await identity.accounts["delete"]({
      id: doomed.id, destroy: true, reason: ERASURE_REASON });
  } finally {
    restore();
  }
  return { account: doomed, outcome: outcome };
}

// What the lookup answers about one recipient, in the three fields a
// listener reads.
function lookedUp(identity, recipient) {
  var verdict = identity.resolve(recipient);
  return {
    local:       verdict.local,
    deliverable: verdict.deliverable,
    reason:      verdict.reason,
    targets:     verdict.targets.map(function (target) {
      return { mailbox: target.mailbox, deliverable: target.deliverable,
        reason: target.reason };
    }),
  };
}

// The claim, asked of one posture. `label` names which of the two the
// erasure ran under.
async function testTheLookupRefusesAnOutstandingErasure(identity, label, address, armFault) {
  var raised = await anOutstandingErasure(identity, address, armFault);

  count(label + ": the erasure reports that it could not finish",
    raised.outcome.outcome === "partially-erased", JSON.stringify(raised.outcome.outcome));

  // The identity layer's own reading, established first, so a failure
  // below is one reader disagreeing with the rest rather than a fixture
  // that never reached the state.
  var known = identity.accounts.get(address);
  count(label + ": the account layer reports the account as erasing",
    known !== null && known.status === "erasing",
    known === null ? "no row" : String(known.status));

  var signIn = await identity.accounts.authenticate({
    address: address, password: OWNER_PASSWORD, source: "203.0.113.4" });
  count(label + ": and sign in is refused on the same reading",
    signIn.ok !== true && signIn.reason === "account-erasing",
    JSON.stringify({ ok: signIn.ok, reason: signIn.reason }));

  var direct = lookedUp(identity, address);
  count(label + ": the recipient lookup refuses mail addressed to the mailbox itself",
    direct.local === true && direct.deliverable === false &&
    direct.reason === "account-erasing",
    JSON.stringify(direct));

  // The alias is added after the erasure, because an erasure destroys the
  // aliases pointing at the address it is erasing. What it drives is the
  // second place the lookup reads an account row, which is the branch a
  // forward takes.
  var via = "forward-" + address;
  await identity.aliases.add({ address: via, destination: address });
  var forwarded = lookedUp(identity, via);
  count(label + ": and mail an alias forwards into it, which is the second place the " +
    "lookup reads the account row",
  forwarded.deliverable === false &&
    forwarded.targets.length === 1 &&
    forwarded.targets[0].deliverable === false &&
    forwarded.targets[0].reason === "account-erasing",
  JSON.stringify(forwarded));
}

async function run() {
  var root = helpers.tempDir("erasure-delivery");
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
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
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });

    await testTheLookupRefusesAnOutstandingErasure(
      identity, "status transition landed", "settled@example.com", null);
    await testTheLookupRefusesAnOutstandingErasure(
      identity, "status transition refused", "marked@example.com",
      writeFault.refuseErasingStatusWrite);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name: "account-erasure-delivery-refusal",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
