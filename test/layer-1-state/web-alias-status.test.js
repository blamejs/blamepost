// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An alias can be stopped and started from the operator console, and
 * stopping one is not the same act as removing it.
 *
 * The identity layer has always held both. Resolution reads the status
 * column on every recipient and stops at a disabled alias under the
 * reason `alias-disabled`, deliberately without falling through to the
 * domain's catch-all. Until this console offered the verb, the only way
 * an operator could stop an address that was being abused was to delete
 * the row, which loses the address, the destination and the history of
 * both, and leaves them with nothing to put back but what they
 * remember.
 *
 * So the claims here are about the pair. Stopping refuses the mail and
 * keeps the row; starting puts it back in service; the reason is
 * recorded on the audit trail in both directions; and a stopped alias
 * does not become the catch-all's problem.
 *
 * The console half is driven over the route a browser posts to, because
 * a verb that reaches the identity layer from a test and not from a
 * form is a verb no operator has.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-1-state/web-alias-status.test.js
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

var OPERATOR = "adam@" + DOMAIN;
var HOLDER   = "alice@" + DOMAIN;

// The alias under test, and the catch-all that must not pick its mail
// up once it is stopped.
var ALIAS_SOURCE      = "sales@" + DOMAIN;
var ALIAS_DESTINATION = HOLDER;
var CATCH_ALL_TARGET  = HOLDER;

var STOP_REASON  = "a mailing list is bouncing every message it forwards";
var START_REASON = "the list has been cleaned up";

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var OPERATOR_PASSWORD = "quiet lantern bicycle 4291";
var HOLDER_PASSWORD   = "steady harbor pencil 7734";

var HTTP_TIMEOUT_MS = 10000;

var STATUS_CHANGED = "alias.status_changed";

function noticeOf(answer) {
  var at = String(answer.location || "").indexOf("notice=");
  return at === -1 ? "" : String(answer.location).slice(at + "notice=".length);
}

async function aliasRow(identity) {
  var rows = await identity.aliases.list({ includeDisabled: true });
  var out = [];
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].address === ALIAS_SOURCE) out.push(rows[i]);
  }
  return out[0] || null;
}

async function statusOf(identity) {
  var row = await aliasRow(identity);
  return row === null ? "gone" : row.status;
}

function asRows(value) { return Array.isArray(value) ? value : []; }

// The rows this console writes, counted by action name. The audit path
// queues and lands within the second, so the sink is drained first: a
// count taken before the write reaches disk reads a console that
// recorded nothing.
async function rowCount(action) {
  await b.audit.flush();
  return asRows(await b.audit.query({ action: action, order: "desc", limit: 50 })).length;
}

// The reason on the newest row, which is the sentence an operator typed
// rather than one this console supplied.
async function newestReason(action) {
  await b.audit.flush();
  var rows = asRows(await b.audit.query({ action: action, order: "desc", limit: 20 }));
  return rows.length > 0 ? String(rows[0].reason || "") : "";
}

// ---- cases -----------------------------------------------------------------

// The list page is where the verb has to appear, because an operator who
// cannot see it does not have it.
async function theListOffersTheVerb(operator, expected) {
  var page = await operator.get("/admin/aliases");
  count("the alias list renders", page.status === 200, "HTTP " + page.status);
  count("the list offers a " + expected + " control for the alias",
    page.body.indexOf("value=\"" + expected + "\"") !== -1,
    page.body.slice(0, 200));
  return page;
}

// A first post carries no reason. It has to ask rather than act: the
// identity layer records a reason on the row in both directions, and a
// sentence supplied by this console would be an audit column that reads
// the same on every row.
async function itAsksForTheReasonFirst(operator, identity, id) {
  var bare = await operator.form("/admin/aliases", { action: "disable", id: id });
  count("stopping an alias asks before it acts",
    bare.status === 200 && noticeOf(bare) === "",
    bare.status + " " + String(bare.location));
  count("and the page it answers with names the destination that stops receiving",
    String(bare.body).indexOf(ALIAS_DESTINATION) !== -1, String(bare.body).slice(0, 400));
  count("and the alias is still delivering",
    (await statusOf(identity)) === "active", await statusOf(identity));
}

async function theAliasIsStopped(operator, identity, id) {
  var before = await rowCount(STATUS_CHANGED);
  var done = await operator.form("/admin/aliases",
    { action: "disable", id: id, reason: STOP_REASON });
  count("the reason is what lets the stop through",
    done.status === 302 && noticeOf(done) === "alias-disabled",
    done.status + " " + String(done.location));
  count("the alias is disabled",
    (await statusOf(identity)) === "disabled", await statusOf(identity));
  count("the row is still on this server rather than deleted, which is the whole " +
    "difference between stopping an alias and removing one",
    (await aliasRow(identity)) !== null, JSON.stringify(await aliasRow(identity)));
  count("and it still points where it did",
    (await aliasRow(identity)).destination === ALIAS_DESTINATION,
    JSON.stringify((await aliasRow(identity)).destination));
  count("the change is on the audit trail",
    (await rowCount(STATUS_CHANGED)) > before,
    before + " before, " + (await rowCount(STATUS_CHANGED)) + " after");
  count("carrying the reason the operator typed rather than one this console supplied",
    (await newestReason(STATUS_CHANGED)) === STOP_REASON,
    JSON.stringify(await newestReason(STATUS_CHANGED)));
}

// What the stop is FOR. Routing has to refuse the address rather than
// hand it to whatever the domain's catch-all points at, or an operator
// who believed they had stopped an address being abused has moved the
// abuse somewhere else.
function theMailIsRefusedRatherThanCaught(identity) {
  var verdict = identity.resolve(ALIAS_SOURCE);
  count("mail to a stopped alias is not deliverable",
    verdict.deliverable === false, JSON.stringify(verdict.reason));
  count("and it is refused as a stopped alias rather than falling through to the catch-all",
    verdict.reason === "alias-disabled", JSON.stringify(verdict.reason));
  count("so nothing is routed anywhere",
    verdict.targets.length === 0, JSON.stringify(verdict.targets));
}

async function theAliasIsStarted(operator, identity, id) {
  var before = await rowCount(STATUS_CHANGED);
  var bare = await operator.form("/admin/aliases", { action: "enable", id: id });
  count("starting an alias asks for its reason too",
    bare.status === 200 && noticeOf(bare) === "",
    bare.status + " " + String(bare.location));
  count("and nothing has started yet",
    (await statusOf(identity)) === "disabled", await statusOf(identity));

  var done = await operator.form("/admin/aliases",
    { action: "enable", id: id, reason: START_REASON });
  count("the reason is what lets the start through",
    done.status === 302 && noticeOf(done) === "alias-enabled",
    done.status + " " + String(done.location));
  count("the alias is delivering again",
    (await statusOf(identity)) === "active", await statusOf(identity));
  count("and the start is on the audit trail beside the stop",
    (await rowCount(STATUS_CHANGED)) > before,
    before + " before, " + (await rowCount(STATUS_CHANGED)) + " after");
  count("carrying its own typed reason",
    (await newestReason(STATUS_CHANGED)) === START_REASON,
    JSON.stringify(await newestReason(STATUS_CHANGED)));

  var verdict = identity.resolve(ALIAS_SOURCE);
  count("mail to the alias reaches its destination again",
    verdict.deliverable === true && verdict.targets.length === 1 &&
      verdict.targets[0].mailbox === ALIAS_DESTINATION,
    JSON.stringify(verdict.targets));
}

// An id naming nothing. The console reads the row before it asks
// anything, so a request naming an alias removed from another window
// refuses rather than being confirmed against a page that has gone
// stale.
async function anIdNamingNothingIsRefused(operator, identity) {
  var before = await statusOf(identity);
  var answer = await operator.form("/admin/aliases",
    { action: "disable", id: "no-such-alias-id", reason: STOP_REASON });
  count("an id naming no alias is refused",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the alias this run is driving is untouched",
    (await statusOf(identity)) === before, await statusOf(identity));
}

// A mailbox owner is not an operator. The verb has to be behind the same
// gate every other one on these pages is behind.
async function aMailboxOwnerCannotReachTheVerb(holder, identity, id) {
  var before = await statusOf(identity);
  var answer = await holder.form("/admin/aliases",
    { action: "disable", id: id, reason: STOP_REASON });
  count("an account that does not administer this server is refused the verb",
    answer.status === 403 || answer.status === 404,
    answer.status + " " + String(answer.location));
  count("and the alias is unchanged",
    (await statusOf(identity)) === before, await statusOf(identity));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-alias-status");
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
    await identity.accounts.create({
      address: OPERATOR, password: OPERATOR_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: HOLDER, password: HOLDER_PASSWORD });
    await identity.aliases.add({ address: ALIAS_SOURCE, destination: ALIAS_DESTINATION });
    // The catch-all that must not pick up the stopped alias's mail.
    await identity.aliases.add({
      domain: DOMAIN, catchAll: true, destination: CATCH_ALL_TARGET });

    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    var composer = blamepost.mail.compose.create({
      delivery:  deliveryHandle,
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
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var operator = browser.browserAt(origin, { timeoutMs: HTTP_TIMEOUT_MS });
    var landed = await operator.signIn(OPERATOR, OPERATOR_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    var row = await aliasRow(identity);
    count("the run has an alias to stop", row !== null, JSON.stringify(row));

    await theListOffersTheVerb(operator, "disable");
    await anIdNamingNothingIsRefused(operator, identity);
    await itAsksForTheReasonFirst(operator, identity, row.id);
    await theAliasIsStopped(operator, identity, row.id);
    theMailIsRefusedRatherThanCaught(identity);
    await theListOffersTheVerb(operator, "enable");
    await theAliasIsStarted(operator, identity, row.id);

    var holder = browser.browserAt(origin, { timeoutMs: HTTP_TIMEOUT_MS });
    await holder.signIn(HOLDER, HOLDER_PASSWORD);
    await aMailboxOwnerCannotReachTheVerb(holder, identity, row.id);

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
  name:      "web-alias-status",
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
