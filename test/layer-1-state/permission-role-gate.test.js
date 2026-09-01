// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The role gate behind the mailbox adapter, and the two ways it goes
 * missing.
 *
 * `b.mail.agent` checks a scope on every verb it routes, and it checks
 * nothing at all when the agent it was built into carries no permission
 * table: `_checkPermission` returns on the first line when `ctx
 * .permissions` is absent. So an agent built without that option is not
 * an agent with a permissive gate, it is an agent with no gate, and
 * nothing downstream can tell the difference by looking.
 *
 * The second way is the mirror image and lives in the actor rather than
 * in the agent. `b.permissions` reads `actor.scopes` whenever it is an
 * ARRAY and only falls through to `actor.roles` otherwise, so an empty
 * array is not "work it out from the roles", it is an explicit grant of
 * nothing. An actor carrying both is refused everything its role
 * grants. That precedence is a vendored contract this repository
 * depends on in both directions, so it is pinned here rather than
 * assumed: a refresh that changes it fails on this file instead of
 * quietly opening or closing every mailbox verb.
 *
 * What the two failures look like from outside is identical to a
 * working server, which is why they need assertions rather than a
 * reading. One destroys mail an operator armed a floor against; the
 * other refuses every delete, move and filter upload on three
 * protocols. Both are one option on one call.
 *
 * The wire half is `test/layer-2-integration/permission-wire-gate.test
 * .js`, which drives IMAP, POP3 and ManageSieve sessions against bound
 * listeners. This file covers the adapter the listeners drive, the
 * assembly that hands it its agent, and the sieve verbs the agent has
 * no method for.
 *
 * Run standalone: node test/layer-1-state/permission-role-gate.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

// The assertion that quotes the value that produced the verdict, and
// the counter behind it, are both the shared ones. A file that kept its
// own counter reported a total that only covered the assertions made
// through its own wrapper, so a `check` written directly ran and was
// invisible in the number the runner aggregated.
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var DOMAIN   = "example.com";
var HOSTNAME = "mx.example.com";

// The scope in front of the filter surface, named here so a rename in
// the adapter fails this file rather than passing a check on a string
// nothing looks at any more.
var SIEVE_SCOPE = "mail:sieve";

// Every listener off. This file binds nothing: the adapter and the
// assembly are the whole subject, and a bound port would only add a
// reason for the run to fail that has nothing to do with permissions.
var LISTENERS_OFF = {
  mx:          { enabled: false, port: 2525, address: "127.0.0.1" },
  submission:  { enabled: false, port: 2587, address: "127.0.0.1" },
  submissions: { enabled: false, port: 2465, address: "127.0.0.1" },
  imap:        { enabled: false, port: 2143, address: "127.0.0.1" },
  pop3:        { enabled: false, port: 2110, address: "127.0.0.1" },
  managesieve: { enabled: false, port: 4190, address: "127.0.0.1" },
};

async function refuses(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + " " + thrown.message);
}

async function allows(label, fn) {
  var thrown = null;
  var value = null;
  try { value = await fn(); } catch (e) { thrown = e; }
  count(label, thrown === null,
    thrown === null ? undefined : (thrown.code || "") + " " + thrown.message);
  return value;
}

// The actor an authenticated session carries: an identity plus the
// roles this server issues, and no `scopes` key at all. The wire
// listeners build exactly this shape, and so does the browser surface.
function actorFor(account, roles) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [String(account.address).toLowerCase()],
    roles:     roles,
  };
}

function message(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <alice@" + DOMAIN + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\nBody of " + subject + ".\r\n", "utf8");
}

function plant(handle, actor, wireName, subject) {
  return handle.mailbox.appendMessage(wireName, message(subject), { actor: actor }).objectid;
}

function heldBy(handle, actor, wireName) {
  var folder = handle.mailbox.accountFolders(actor)
    .filter(function (f) { return f.name === wireName; })[0].storeName;
  return b.db.from(mailbox.MESSAGES).where({ folder: folder }).count();
}

// ---- the vendored precedence this repository depends on ---------------------

// Both halves of the fix rest on one contract: an array in `scopes`
// wins outright, and the roles are consulted only when there is no
// array there. Written down as running code because reading it off the
// framework is how it came to be written wrong in the first place.
function theEmptyScopesArrayOutranksEveryRole() {
  var table = b.permissions.create({
    roles: {
      account: ["mail:read", "mail:move", "mail:expunge", "mail:sieve"],
      admin:   { extends: ["account"] },
    },
  });
  var withRoles  = { id: "a1", roles: ["account"] };
  var alsoEmpty  = { id: "a1", roles: ["account"], scopes: [] };
  var onlyEmpty  = { id: "a1", scopes: [] };
  var noneAtAll  = { id: "a1" };

  count("an actor carrying its role is granted what the role grants",
    table.check(withRoles, "mail:expunge") === true);
  count("the same actor with an empty scopes array beside the role is granted nothing",
    table.check(alsoEmpty, "mail:expunge") === false);
  count("an empty scopes array on its own grants nothing",
    table.check(onlyEmpty, "mail:expunge") === false);
  count("and an actor naming neither grants nothing",
    table.check(noneAtAll, "mail:expunge") === false);
  count("an administrator inherits the account role rather than a wider one",
    table.check({ id: "a2", roles: ["admin", "account"] }, "mail:expunge") === true &&
    table.check({ id: "a2", roles: ["admin", "account"] }, "mail:export") === false);
}

// ---- the adapter the wire listeners drive -----------------------------------

// IMAP EXPUNGE, POP3 QUIT and the browser purge all end at
// `expungeObjects`, so the gate in front of it is the gate in front of
// every hard delete on this server.
async function theHardDeleteIsGated(handle, granted, ungated) {
  var doomed = plant(handle, granted, "INBOX", "gated-delete");
  var before = heldBy(handle, granted, "INBOX");

  await refuses("a hard delete by an actor whose role does not carry the scope is refused",
    "mail-agent/permission-denied", function () {
      return handle.mailbox.expungeObjects(ungated, "INBOX", [doomed]);
    });
  count("and the message it named is still in the mailbox",
    heldBy(handle, granted, "INBOX") === before,
    before + " before, " + heldBy(handle, granted, "INBOX") + " after");

  var outcome = await allows("the same delete by an actor whose role carries the scope runs",
    function () { return handle.mailbox.expungeObjects(granted, "INBOX", [doomed]); });
  count("and the message is gone",
    outcome !== null && outcome.deleted.length === 1 &&
    heldBy(handle, granted, "INBOX") === before - 1,
    JSON.stringify(outcome));
}

// Filing into Trash is the soft delete every client performs, and it
// carries its own scope. A gate that refused it would break the most
// ordinary thing a mail client does.
async function theMoveIsGated(handle, granted, ungated) {
  var filed = plant(handle, granted, "INBOX", "gated-move");

  await refuses("a move by an actor whose role does not carry the scope is refused",
    "mail-agent/permission-denied", function () {
      return handle.mailbox.moveObjects(ungated, "INBOX", "Trash", [filed]);
    });
  count("and the message is still in the folder it started in",
    b.db.from(mailbox.MESSAGES)
      .where({ folder: handle.mailbox.accountFolders(granted)
        .filter(function (f) { return f.name === "INBOX"; })[0].storeName,
      objectid: filed }).count() === 1);

  var moved = await allows("the same move by an actor whose role carries the scope runs",
    function () { return handle.mailbox.moveObjects(granted, "INBOX", "Trash", [filed]); });
  count("and the message is in Trash", moved !== null && moved.moved.length === 1,
    JSON.stringify(moved));
  await handle.mailbox.expungeObjects(granted, "Trash", [filed]);
}

// ManageSieve. The agent implements one of these verbs and rejects the
// rest as not routed, so the gate in front of the other three is the
// same permission handle read directly rather than a second table.
async function theSieveWritesAreGated(handle, granted, ungated) {
  var script = "require [\"fileinto\"];\nif header :contains \"X-Category\" \"x\" " +
    "{ fileinto \"Junk\"; }\n";

  await refuses("a filter upload by an actor whose role does not carry the scope is refused",
    "mailbox/permission-denied", function () {
      return handle.mailbox.sieveScripts.put(ungated, "gated", script);
    });
  count("and nothing was stored", handle.mailbox.sieveScripts.get(granted, "gated") === null);

  await allows("the same upload by an actor whose role carries the scope runs", function () {
    return handle.mailbox.sieveScripts.put(granted, "gated", script);
  });
  count("and the script is readable", handle.mailbox.sieveScripts.get(granted, "gated") !== null);

  await refuses("activating a filter is gated the same way", "mailbox/permission-denied",
    function () { return handle.mailbox.sieveScripts.setActive(ungated, "gated"); });
  await refuses("so is renaming one", "mailbox/permission-denied",
    function () { return handle.mailbox.sieveScripts.rename(ungated, "gated", "taken"); });
  await refuses("so is deleting one", "mailbox/permission-denied",
    function () { return handle.mailbox.sieveScripts.delete(ungated, "gated"); });

  await allows("and the account holder can activate their own",
    function () { return handle.mailbox.sieveScripts.setActive(granted, "gated"); });
  count("which is what the listing reports",
    handle.mailbox.sieveScripts.list(granted)[0].active === true);

  // A wire refusal that records nothing is a refusal nobody can review
  // afterwards, and the audit chain drops an event whose namespace was
  // never registered rather than storing it. So the row is read back
  // rather than assumed from the fact that a line of code emits it.
  await b.audit.flush();
  var rows = await b.audit.query({ action: "blamepost.mail.mailbox.sieve_denied", limit: 20 });
  count("every refusal above is on the audit chain, not discarded on the way to it",
    Array.isArray(rows) && rows.length >= 4, String(rows && rows.length));
  var row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
  count("and the row is filed as a denial", row !== null && row.outcome === "denied",
    JSON.stringify(row && row.outcome));
  count("and it names the account that was refused, in the column an auditor filters on",
    row !== null && row.actorUserId === granted.id && row.resourceId === granted.id,
    JSON.stringify(row && { actorUserId: row.actorUserId, resourceId: row.resourceId }));
  count("and it says which verb wanted which scope",
    row !== null && JSON.parse(row.metadata || "{}").scope === SIEVE_SCOPE,
    String(row && row.metadata));
}

// The reads are deliberately outside the gate, and this is the case
// that says why. Delivery reads the recipient's active filter with an
// actor the server built for the occasion, which holds an identity and
// no role, because nobody is signed in when a stranger's message
// arrives. Refusing that read sends every filtered message to INBOX
// and tells nobody. The operator's audited read of an account's filter
// is the same shape for the same reason.
function theSieveReadsStayOpenToTheServersOwnActor(handle, granted, account) {
  var atDelivery = { id: account.id, address: account.address };
  var read = null;
  var thrown = null;
  try { read = handle.mailbox.sieveScripts.active(atDelivery); } catch (e) { thrown = e; }
  count("delivery can read the recipient's active filter with the actor it builds",
    thrown === null && read !== null && read.name === "gated",
    thrown === null ? JSON.stringify(read) : thrown.message);

  thrown = null;
  try { handle.mailbox.sieveScripts.list(atDelivery); } catch (e) { thrown = e; }
  count("and an operator reading the same account's filters is not refused either",
    thrown === null, thrown === null ? undefined : thrown.message);

  count("while a script belonging to somebody else is still invisible",
    handle.mailbox.sieveScripts.get({ id: "no-such-account" }, "gated") === null);
  count("and the account holder's own read still answers",
    handle.mailbox.sieveScripts.get(granted, "gated") !== null);
}

// RFC 1939 section 3 gives one session at a time exclusive access to the
// maildrop, so the commit has to hand the lock back however it ends. It
// did that for a refusal carried on the return value and not for one
// thrown out of the delete gate, which is the shape a role that does not
// carry the delete scope produces on every QUIT: the account holder loses
// their own POP3 access until the stale drop ages out, half an hour
// later, and nothing anywhere says why.
async function arefusedCommitHandsTheMaildropBack(handle, granted, ungated) {
  var doomed = plant(handle, granted, "INBOX", "drop-lock");
  var drop = handle.mailbox.openPop3Drop(granted, {});
  handle.mailbox.markDelete(granted, drop.dropId, 1);

  await refuses("a POP3 commit by an actor whose role does not carry the delete scope " +
    "is refused", "mail-agent/permission-denied", function () {
      return handle.mailbox.commitPop3Drop(ungated, drop.dropId);
    });

  var second = null;
  var thrown = null;
  try { second = handle.mailbox.openPop3Drop(granted, {}); } catch (e) { thrown = e; }
  count("and the next session can still open the maildrop, because the refusal " +
    "released the lock", thrown === null && second !== null,
    thrown === null ? "opened" : thrown.code + " " + thrown.message);

  // Close the second drop the way a client does, so the count this
  // adapter reports is the truth for anything reading it afterwards.
  if (second) {
    handle.mailbox.resetPop3Drop(granted, second.dropId);
    await handle.mailbox.commitPop3Drop(granted, second.dropId);
  }
  count("and no maildrop is left held once both sessions are done",
    handle.mailbox.describe().openDrops === 0,
    String(handle.mailbox.describe().openDrops));
  await handle.mailbox.expungeObjects(granted, "INBOX", [doomed]);
}

// ---- the factory ------------------------------------------------------------

// `blamepost.mail.mailbox.agent` is the one construction site for the
// mailbox access agent, and `blamepost.mail.mailbox.assertRoleGate` is
// what refuses one built anywhere else without a table. Driven here
// directly, because the whole defect was two callers building their own
// and only one of them remembering the option.
async function theFactoryComposesTheTableAndTheAssertionReadsIt(handle, granted, ungated) {
  var built = mailbox.agent({ store: handle.messageStore, posture: null });

  var thrown = null;
  try { mailbox.assertRoleGate(built, "permission-role-gate"); } catch (e) { thrown = e; }
  count("an agent from the factory passes the role gate assertion", thrown === null,
    thrown === null ? undefined : thrown.message);

  await refuses("and it refuses an actor whose role carries none of the mailbox scopes",
    "mail-agent/permission-denied", function () {
      return built.expunge({ actor: ungated, folder: "mbx_nothing", objectIds: ["obj_0"] });
    });

  // The same call by an actor holding the role gets past the gate. It
  // still fails, on a folder that does not exist, and that is the point:
  // the failure has to be about the mailbox rather than about the role,
  // or the table is refusing everybody and the case above proves nothing.
  var second = null;
  try {
    await built.expunge({ actor: granted, folder: "mbx_nothing", objectIds: ["obj_0"] });
  } catch (e) { second = e; }
  count("while an actor holding the role reaches past the gate to the store",
    second === null || second.code !== "mail-agent/permission-denied",
    second === null ? "no error" : second.code + " " + second.message);

  count("and the roles grant exactly the scopes this server names",
    mailbox.MAILBOX_SCOPES.length === 4 &&
    mailbox.MAILBOX_SCOPES.indexOf("mail:expunge") !== -1 &&
    mailbox.MAILBOX_SCOPES.indexOf(SIEVE_SCOPE) !== -1,
    mailbox.MAILBOX_SCOPES.join(", "));
}

// ---- assembly ---------------------------------------------------------------

// An agent with no permission table is the defect itself, so the two
// places that accept one refuse it rather than composing a server whose
// gate is silently absent.
function anAgentWithNoRoleGateIsRefused(handle, cfg) {
  var ungated = b.mail.agent.create({
    store:    handle.messageStore,
    dispatch: { mode: "local" },
  });

  var thrown = null;
  try {
    mailbox.create({
      store:   handle.messageStore,
      dataDir: cfg.paths.dataDir,
      vault:   b.vault,
      agent:   ungated,
    });
  } catch (e) { thrown = e; }
  count("the adapter refuses an agent that carries no role gate",
    thrown !== null && /role gate/.test(String(thrown.message)),
    thrown === null ? "nothing was thrown" : thrown.message);

  thrown = null;
  try {
    blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
      store:        handle,
      mailStore:    handle.mailbox,
      messageStore: handle.messageStore,
      agent:        ungated,
      tlsContext:   nodeTls.createSecureContext({}),
    });
  } catch (e) { thrown = e; }
  count("and so does the server assembly",
    thrown !== null && /role gate/.test(String(thrown.message)),
    thrown === null ? "nothing was thrown" : thrown.message);
}

// The whole defect in one line: two agents built from two option sets.
// The adapter is opened before the server is assembled, so the server
// takes the adapter's agent rather than building a second one that can
// disagree with it about what a delete means and about who may ask.
function theServerDrivesTheAdaptersAgent(handle, cfg) {
  var server = blamepost.create({
    config:       Object.assign({}, cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
    store:        handle,
    mailStore:    handle.mailbox,
    messageStore: handle.messageStore,
    tlsContext:   nodeTls.createSecureContext({}),
  });
  count("the adapter names the agent it drives",
    handle.mailbox.agent !== null && handle.mailbox.agent !== undefined);
  count("and the browser surface is given that same agent rather than a second one",
    server.mail.agent === handle.mailbox.agent);
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-perm-gate-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    theEmptyScopesArrayOutranksEveryRole();

    var handle = await store.open(cfg);
    await handle.domains.add({ domain: DOMAIN });
    var account = await handle.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // Two actors for one account. The difference between them is the
    // only thing under test: one names the role this server issues, the
    // other names a role that carries none of the mailbox scopes.
    var granted = actorFor(account, ["account"]);
    var ungated = actorFor(account, ["visitor"]);

    await theHardDeleteIsGated(handle, granted, ungated);
    await theMoveIsGated(handle, granted, ungated);
    await theSieveWritesAreGated(handle, granted, ungated);
    theSieveReadsStayOpenToTheServersOwnActor(handle, granted, account);

    await arefusedCommitHandsTheMaildropBack(handle, granted, ungated);
    await theFactoryComposesTheTableAndTheAssertionReadsIt(handle, granted, ungated);
    anAgentWithNoRoleGateIsRefused(handle, cfg);
    theServerDrivesTheAdaptersAgent(handle, cfg);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not
      // a test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = {
  name: "permission-role-gate",
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
