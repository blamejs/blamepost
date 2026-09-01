// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the audit trail says when a message sent from the browser leaves
 * without a DKIM signature.
 *
 * Signing runs on every message, and a signer that refuses does not stop
 * the message: refusing to send an account's own mail over a key problem
 * is a worse outage than sending it unsigned. So the message goes, and
 * the audit row is the only place an operator ever finds out that it
 * went unattributable. That row is consulted at exactly the moment the
 * domain's DMARC policy starts sending failure reports, which is why a
 * row that reads as though nothing was wrong is worse than no row: it
 * answers the operator's question with the wrong answer.
 *
 * The submission listener already files this correctly, and its wire
 * vectors live in test/layer-2-integration/mail-submission.test.js. The
 * browser compose form is the other surface that composes its own
 * outbound mail, and it is the one an ordinary account holder uses. Both
 * have to leave the same kind of trail, or an operator querying it sees
 * only the half that was sent by a desktop client.
 *
 * What is pinned, over the real consumer path a mailbox owner drives:
 *
 *   - A key that will not open sends the message anyway and files the
 *     row as a failure, which is what `b.audit.query` filters on.
 *   - The row carries the signer's own refusal code in a field of its
 *     own, so an operator can tell a key that is damaged from a domain
 *     nobody has finished setting up without reading prose.
 *   - Those two causes are filed under different action names, because
 *     one is repaired by minting a pair and the other by restoring one,
 *     and an operator filters on the action.
 *   - A domain whose key opens draws no such row at all, so all of the
 *     above is about the key rather than about the surface.
 *   - The action names and the row shape line up with the submission
 *     listener's, so one query answers for both surfaces.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface, the data directory is temporary, and the outbound path is
 * the shared stand-in with a recorder on its send.
 *
 * Run standalone: node test/layer-1-state/unsigned-send-trail.test.js
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
var HOSTNAME = "mx.example.com";

// Three hosted domains, one per key state, so every vector runs against
// the same server and the same form and differs only in what is on the
// volume under `keys/`.
var DAMAGED = "damaged.example";
var WORKING = "working.example";
var NO_KEY  = "unkeyed.example";

var SELECTOR = "bp202608";

// Every refusal this server's signer composes, read from the module that
// throws them. The cause on the row has to be one of these rather than
// merely something under the `dkim/` prefix: the framework files its own
// signing faults under that prefix too, and an operator reading the row
// to decide which repair to run needs a code the repair table holds.
var SIGNER_CODES = Object.keys(blamepost.mail.dkim.CODES).map(function (name) {
  return blamepost.mail.dkim.CODES[name];
});

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The two actions the browser surface files an unsigned send under, and
// the two the submission listener files the same pair of causes under.
// Both sets are read here because the claim is that they agree.
var COMPOSE_NO_KEY  = "blamepost.mail.compose.unsigned_no_key";
var COMPOSE_DAMAGED = "blamepost.mail.compose.unsigned";
var WIRE_NO_KEY     = "blamepost.mail.listeners.submission_unsigned_no_key";
var WIRE_DAMAGED    = "blamepost.mail.listeners.submission_unsigned";

// The signer's own refusal codes, which are the contract a caller reads
// to decide what it records.
var CODE_NO_SELECTOR = "dkim/no-active-selector";
var CODE_UNOPENED    = "dkim/key-seal-unopened";

// How much of a sealed key file is left in place. Far enough in to keep
// the marker the vault reads to recognize one of its own, and far short
// of the whole envelope, which is what a copy that stopped part way
// through leaves behind. No key material is written by this file: the
// server mints the pair and a prefix of its own output is what stays.
var TRUNCATED_KEY_BYTES = 64;

// One outbound path that records rather than connects. The composer
// requires the whole delivery handle, so the shared stand-in carries the
// queue contract and only `send` is replaced.
function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({ from: envelope.from, rfc822: envelope.rfc822 });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
  };
}

// The rows one action holds, newest first, after the chain has been
// flushed. Read through the same query an operator types, so a row this
// server writes somewhere the query cannot reach counts as absent.
async function rowsFor(action) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: action, limit: 50, order: "desc" });
  return Array.isArray(rows) ? rows : [];
}

// The chain stores the metadata as text, so it is read back the way
// every other file that reads this trail reads it.
function metadataOf(row) {
  if (!row) return {};
  try { return JSON.parse(row.metadata || "{}"); }
  catch (_e) { return {}; }
}

function signatureCount(rfc822) {
  var text = Buffer.isBuffer(rfc822) ? rfc822.toString("latin1") : String(rfc822 || "");
  return (text.match(/DKIM-Signature:/g) || []).length;
}

// ---- the vectors -----------------------------------------------------------

// The message still goes. Everything below is about what an operator can
// find out afterwards, and none of it is worth anything if the send was
// refused instead.
async function aDamagedKeySendsAnywayAndFilesTheCause(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    to:      "buyer@peer.example",
    subject: "sent while the key was damaged",
    text:    "This one leaves without a signature.",
  });
  count("a message from a domain whose signing key will not open is still sent, because " +
    "refusing an account's own mail over a key problem is the worse outage",
    sent.status === 302, "HTTP " + sent.status);
  count("and it reached the outbound path", log.count() === before + 1,
    log.count() + " after " + before);
  count("carrying no signature, which is the condition the row exists to report",
    log.last() !== null && signatureCount(log.last().rfc822) === 0,
    log.last() === null ? "nothing sent" : signatureCount(log.last().rfc822) + " signature(s)");

  var rows = await rowsFor(COMPOSE_DAMAGED);
  count("the send that could not be signed left a row an operator can find",
    rows.length >= 1, rows.length + " row(s) under " + COMPOSE_DAMAGED);
  count("and the row is filed as a failure, which is the one thing an operator queries an " +
    "audit trail on. Filed as a success it says signing is working at the moment somebody " +
    "is asking why DMARC reports are arriving",
    rows[0] && rows[0].outcome === "failure",
    JSON.stringify(rows[0] && rows[0].outcome));

  var carried = metadataOf(rows[0]);
  count("the row names the domain that could not be signed for",
    carried.domain === DAMAGED, String(carried.domain));
  count("and carries the signer's own code in a field of its own, so a key that will not " +
    "open is distinguishable from a domain nobody has set up yet without reading prose",
    carried.cause === CODE_UNOPENED, String(carried.cause));
  count("and the reason it carries is the signer's message rather than an empty string",
    typeof carried.reason === "string" && carried.reason.length > 0,
    String(carried.reason).slice(0, 120));
  count("which names nothing of the volume's layout, because the same message is shown to " +
    "whoever asked",
    typeof carried.reason === "string" && carried.reason.indexOf(".sealed") === -1,
    String(carried.reason).slice(0, 160));
}

// A domain nobody has finished setting up is a different condition with
// a different repair, and an operator sent to the wrong one runs the
// command that mints a pair the domain already has.
async function aDomainWithNoSelectorIsFiledApart(reader, log) {
  var before = log.count();
  var sent = await reader.form("/compose", {
    to:      "buyer@peer.example",
    subject: "sent from a domain holding no selector",
    text:    "This one leaves without a signature too.",
  });
  count("a message from a domain holding no selector is sent as well",
    sent.status === 302, "HTTP " + sent.status);
  count("and it reached the outbound path", log.count() === before + 1,
    log.count() + " after " + before);

  var rows = await rowsFor(COMPOSE_NO_KEY);
  count("a domain still waiting to be set up is filed under an action of its own",
    rows.length >= 1, rows.length + " row(s) under " + COMPOSE_NO_KEY);
  count("filed as a failure as well, because the mail left unattributable either way",
    rows[0] && rows[0].outcome === "failure",
    JSON.stringify(rows[0] && rows[0].outcome));

  var carried = metadataOf(rows[0]);
  count("naming the domain that is waiting", carried.domain === NO_KEY, String(carried.domain));
  count("and carrying the code a domain with no active selector refuses under",
    carried.cause === CODE_NO_SELECTOR, String(carried.cause));

  var damagedRows = await rowsFor(COMPOSE_DAMAGED);
  count("and the damaged key did not land under this action, so the two causes are " +
    "separable by the field an operator filters on",
    damagedRows.every(function (row) { return metadataOf(row).cause !== CODE_NO_SELECTOR; }),
    JSON.stringify(damagedRows.map(function (row) { return metadataOf(row).cause; })));
}

// The rows above have to be about the key rather than about the browser
// surface, and a domain that signs is what proves it.
async function aWorkingKeyDrawsNoRowAtAll(reader, log) {
  var damagedBefore = (await rowsFor(COMPOSE_DAMAGED)).length;
  var noKeyBefore   = (await rowsFor(COMPOSE_NO_KEY)).length;
  var before = log.count();

  var sent = await reader.form("/compose", {
    to:      "buyer@peer.example",
    subject: "sent from a domain that signs",
    text:    "This one leaves signed.",
  });
  count("a message from a domain whose key opens is sent", sent.status === 302,
    "HTTP " + sent.status);
  count("and it leaves carrying both halves of the dual signature",
    log.count() === before + 1 && log.last() !== null &&
    signatureCount(log.last().rfc822) === 2,
    log.last() === null ? "nothing sent" : signatureCount(log.last().rfc822) + " signature(s)");

  count("and drew no unsigned row of either kind, so the rows above are about the key " +
    "rather than about the compose form",
    (await rowsFor(COMPOSE_DAMAGED)).length === damagedBefore &&
    (await rowsFor(COMPOSE_NO_KEY)).length === noKeyBefore,
    damagedBefore + "/" + noKeyBefore + " before, " +
      (await rowsFor(COMPOSE_DAMAGED)).length + "/" +
      (await rowsFor(COMPOSE_NO_KEY)).length + " after");
}

// One query has to answer for both surfaces that relay unsigned mail, so
// the two file the same causes under names that differ only in the
// module that wrote them, and both put the cause in the same field.
async function bothSurfacesFileTheSameShape() {
  var wireRows = (await rowsFor(WIRE_DAMAGED)).concat(await rowsFor(WIRE_NO_KEY));
  count("nothing sent from the browser this run landed under the submission listener's " +
    "names, so a query naming one surface is not quietly answering for the other",
    wireRows.length === 0, wireRows.length + " row(s)");

  var browserRows = (await rowsFor(COMPOSE_DAMAGED)).concat(await rowsFor(COMPOSE_NO_KEY));
  count("every row the browser surface wrote for an unsigned send is a failure",
    browserRows.length >= 2 && browserRows.every(function (row) {
      return row.outcome === "failure";
    }),
    JSON.stringify(browserRows.map(function (row) { return row.outcome; })));
  count("and every one carries a cause this server's signer composed, which is what the " +
    "submission listener records and what an operator reads to know which repair to run",
    browserRows.length >= 2 && browserRows.every(function (row) {
      return SIGNER_CODES.indexOf(metadataOf(row).cause) !== -1;
    }),
    JSON.stringify(browserRows.map(function (row) { return metadataOf(row).cause; })));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("unsignedtrail");
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
    await identity.domains.add({ domain: DAMAGED });
    await identity.domains.add({ domain: WORKING });
    await identity.domains.add({ domain: NO_KEY });

    var owners = {};
    var names = [DAMAGED, WORKING, NO_KEY];
    for (var i = 0; i < names.length; i += 1) {
      owners[names[i]] = await identity.accounts.create({
        address: "sender@" + names[i], password: PASSWORD,
      });
    }

    // Two of the three domains get a pair. The third is left as a domain
    // an operator added and has not finished setting up, which is the
    // state the second action name exists for.
    var minting = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });
    await minting.generate({ domain: DAMAGED, selector: SELECTOR });
    await minting.generate({ domain: WORKING, selector: SELECTOR });

    // A prefix of the file the server just wrote, which is what a restore
    // that copied part of a volume leaves behind. A seal authenticates
    // what it carries end to end, so a file missing its tail opens for
    // nobody.
    var damagedKeyPath = nodePath.join(dataDir, "keys",
      DAMAGED + "." + SELECTOR + ".ed25519.sealed");
    count("the damaged domain's key file is on the volume before anything is done to it",
      nodeFs.existsSync(damagedKeyPath), damagedKeyPath);
    nodeFs.truncateSync(damagedKeyPath, TRUNCATED_KEY_BYTES);

    // A signer is built once per domain and kept, so the handle that
    // minted the pair answers from what it built rather than from the
    // file above. The server gets a handle that has never signed.
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });

    var log = recorder();
    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var composer = blamepost.mail.compose.create({
      delivery:  log.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
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
    var ports  = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var readers = {};
    for (var r = 0; r < names.length; r += 1) {
      readers[names[r]] = browser.browserAt(origin);
      var landing = await readers[names[r]].signIn("sender@" + names[r], PASSWORD);
      count("the account at " + names[r] + " signs in", landing.status === 302,
        landing.status + " " + String(landing.location));
    }

    await aDamagedKeySendsAnywayAndFilesTheCause(readers[DAMAGED], log);
    await aDomainWithNoSelectorIsFiledApart(readers[NO_KEY], log);
    await aWorkingKeyDrawsNoRowAtAll(readers[WORKING], log);
    await bothSurfacesFileTheSameShape();

    return helpers.getChecks();
  } finally {
    if (listener) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
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
  name:      "unsigned-send-trail",
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
