// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the browser console owes an operator BEFORE it acts, and what it
 * owes an auditor afterwards.
 *
 * `test/layer-1-state/server-console-isolation.test.js` asks whether the
 * console admits the right caller, and
 * `test/layer-1-state/web-admin-verbs.test.js` asks what the verbs do
 * once the right caller is inside it. This file asks three narrower
 * questions that neither of those covers.
 *
 *   - **Does the console ask?** Four acts on these pages cannot be taken
 *     back from these pages: archiving an account, withdrawing a hosted
 *     domain, removing an alias, and cancelling a message off the
 *     outbound spool. Each of them is one button on a list of rows that
 *     all look alike, and a row is chosen with a mouse. So each of them
 *     is a post that answers with a page naming exactly what it is about
 *     to do, and a second post carrying something the operator has to
 *     read off that page and type: the address, the domain, the
 *     selector, or how many messages are still waiting. A page cannot
 *     supply that value on the operator's behalf, which is the whole
 *     difference between a confirmation and a hidden field.
 *
 *   - **Is the recorded reason the operator's?** The audit row for a
 *     suspension, an archival, a withdrawal, an alias removal and a
 *     cancellation carries a `reason` column, and an incident review
 *     reads it. A reason the page filled in is worse than none: it is
 *     present, it is identical on every row, and it reads like somebody
 *     wrote it. So the verbs that record a reason refuse without one and
 *     record what was typed.
 *
 *   - **Does every act leave a row, and does an act happen only when it
 *     was asked for?** These five routes dispatch on one form field. A
 *     handler that defaults an absent or misspelled field onto a verb
 *     turns a request that named nothing into a queue flush, a key
 *     rotation or a new account, and the operator sees the result of an
 *     act they did not ask for.
 *
 * The fourth question is the role itself. Until now the console could
 * grant the operator interface at account creation and had no way to
 * take it back, so containing an administrator whose credential had been
 * taken meant suspending or archiving their mailbox: mail stops for a
 * person whose account was the problem rather than whose mailbox was.
 * Granting and revoking are both here, both recorded, and the revocation
 * is measured against what would be left exactly as archiving and
 * withdrawing already are.
 *
 * All of it is driven over a real loopback port with a real operator
 * session, because a handle called directly proves what the handle does
 * and not what the route does.
 *
 * Run standalone: node test/layer-1-state/web-admin-confirmation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// A second hosted domain, holding no administrator, so withdrawing it is
// refused by the confirmation and by nothing else. Withdrawing the first
// one is refused before the question is even asked, which would make it
// useless for measuring whether the question gets asked.
var SPARE_DOMAIN = "spare.example";

// A third, for the case where a misspelled action must not quietly add
// the domain a request happened to name.
var UNASKED_DOMAIN = "unasked.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 5512";
var OTHER_PASSWORD   = "another operator passphrase 8841";

// The mailbox owner the reversible verbs are aimed at, and the one the
// irreversible verbs are aimed at. Two accounts rather than one, because
// a suspension and an archival leave different states and a single
// subject would have to be put back between them.
var SUSPENDABLE = "carol@" + DOMAIN;
var ARCHIVABLE  = "dana@" + DOMAIN;

// The account the role is granted to and taken back from.
var DEPUTY = "eve@" + DOMAIN;

// The two subjects the role verb is asked about while their mailboxes
// are out of service: one archived, one part way through an erasure a
// preservation order held back. Each is created holding the role, so
// both directions of the verb have something to measure.
var SHELVED         = "frank@" + DOMAIN;
var ERASING_SUBJECT = "grace@" + DOMAIN;

// What keeps the erasure above from finishing. The order names a record
// and the rule keeping it, which is what an operator answering the
// erasure request has to be able to quote.
var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";

// An address no account should ever exist at: it is only ever named by a
// request carrying a misspelled action, and its absence afterwards is
// what says the misspelling created nothing.
var UNASKED_ACCOUNT = "never@" + DOMAIN;

var ALIAS_SOURCE      = "sales@" + DOMAIN;
var ALIAS_DESTINATION = SUSPENDABLE;

// The alias a misspelled action must not create.
var UNASKED_ALIAS = "unasked@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The rows read back by name. An emit that returned true proves the call
// was made; only a read proves the row is on the chain, because the chain
// drops an event whose namespace was never registered rather than
// storing it.
var ARCHIVED       = "account.archived";
var SUSPENDED      = "account.suspended";
var ALIAS_REMOVED  = "alias.removed";
var DOMAIN_CHANGED = "domain.status_changed";
var QUEUE_REMOVED  = "blamepost.mail.queue.message_removed";
var QUEUE_FORCED   = "blamepost.mail.queue.run_forced";
var ROLE_GRANTED   = "account.role_granted";
var ROLE_REVOKED   = "account.role_revoked";
var LAST_ADMIN_REFUSED = "blamepost.web.last_administrator_removal_not_permitted";

// Ids in the shape the spool mints: lowercase hex, long enough that
// nothing an operator mistypes reaches a file.
var FIRST_ID  = "11112222333344445555666677778888";
var SECOND_ID = "99990000aaaabbbbccccddddeeeeffff";

var SENDER        = "alice@" + DOMAIN;
var FIRST_TARGET  = "first@example.net";
var SECOND_TARGET = "second@example.net";

// The second pair, for the question of who a cancellation is allowed to
// write to. One entry carries a reverse path in a domain this server
// hosts, which is the shape a message relayed after an authenticated
// submission has, because the submission listener binds the envelope
// sender to the account that authenticated. The other carries a reverse
// path this server hosts nothing at: that is the shape an alias forward
// has, where the address came off the inbound wire and whoever sent the
// message chose it.
var HOSTED_ID  = "aaaa1111bbbb2222cccc3333dddd4444";
var FORGED_ID  = "5555eeee6666ffff77770000888899aa";

var HOSTED_SENDER = "relayed@" + DOMAIN;
var FORGED_SENDER = "victim@elsewhere.example";
var HOSTED_TARGET = "hosted-target@example.net";
var FORGED_TARGET = "forged-target@example.net";

var MESSAGE = "From: " + SENDER + "\r\nTo: " + FIRST_TARGET + "\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

// A resolver that answers no question anybody asks it.
//
// Every address in this file is a reserved documentation name, and two
// of them resolve differently from each other, so a verdict about this
// console must not depend on what the network says about somebody
// else's zone. A lookup that could not complete is a transient, so a
// report this console causes gets as far as the outbound spool and stops
// there, which is where the cases below read it. Refusing rather than
// answering emptily is deliberate: a domain publishing no exchanger is a
// permanent failure and the report would end rather than wait.
var UNANSWERING = {
  queryMx:   function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTxt:  function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTlsa: function () { return Promise.reject(new Error("no resolver in this test")); },
};

// The sentences the operator types. Each is distinct, so a row carrying
// one of them cannot be mistaken for a row carrying another, and none of
// them is a phrase any page could have supplied.
var SUSPEND_REASON = "the owner reported their laptop stolen this morning";
var ARCHIVE_REASON = "the owner left the organization on the fourteenth";
var DOMAIN_REASON  = "the registrar transfer completes tonight";
var ALIAS_REASON   = "the team behind this address was dissolved";
var CANCEL_REASON  = "these went out under a credential that was taken";
var GRANT_REASON   = "covering the operator rota while they are away";
var REVOKE_REASON  = "the rota cover has ended";

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

// Every mail listener off. This file is about browser routes, and a
// bound port would only add a reason for the run to fail that has
// nothing to do with them.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

function _asRows(value) { return Array.isArray(value) ? value : []; }

function spoolPath(dataDir, name) { return nodePath.join(dataDir, "queue", name); }

// One entry on the spool, written the way the spool writes it. Planting
// the pair rather than driving a send keeps the run off the network and
// keeps the ids known, which is what the assertions below name.
function plant(dataDir, id, recipient, from) {
  nodeFs.mkdirSync(nodePath.join(dataDir, "queue"), { recursive: true });
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".eml"), MESSAGE, "utf8");
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".json"), JSON.stringify({
    id:               id,
    from:             from === undefined ? SENDER : from,
    recipient:        recipient,
    attempt:          1,
    nextAttemptAt:    Date.now() + 3600000,
    reason:           "451 4.7.0 the receiver asked for this to be tried later",
    reasonCode:       "4.7.0",
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [],
  }, null, 2), "utf8");
}

function spooled(dataDir, id) {
  return nodeFs.existsSync(spoolPath(dataDir, id + ".json")) ||
         nodeFs.existsSync(spoolPath(dataDir, id + ".eml"));
}

function noticeOf(answer) {
  var location = String(answer.location || "");
  var at = location.indexOf("notice=");
  return at === -1 ? "" : location.slice(at + "notice=".length).split("&")[0];
}

// The one delivered message a preservation order is placed over, as the
// octets that arrived. The adapter keeps the bytes it was handed rather
// than a re-encoding, so anything built another way would not be a
// message this server could serve back.
function heldMail() {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + ERASING_SUBJECT + ">\r\n" +
    "Subject: under order\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <underorder@example.net>\r\n" +
    "\r\nthe record the order is keeping\r\n", "utf8");
}

async function statusOf(identity, address) {
  var row = await identity.accounts.get(address);
  return (row === null || row === undefined) ? null : row.status;
}

async function domainStatusOf(identity, domain) {
  var rows = _asRows(await identity.domains.list({}));
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].domain === domain) return rows[i].status;
  }
  return null;
}

async function aliasNamed(identity, address) {
  var rows = _asRows(await identity.aliases.list({ includeDisabled: true }));
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].address === address) return rows[i];
  }
  return null;
}

// The newest row under one action name, with the chain drained first so
// an event queued from a hot path has landed.
async function newestRow(action) {
  await b.audit.flush();
  var rows = _asRows(await b.audit.query({ action: action, order: "desc", limit: 20 }));
  return rows.length > 0 ? rows[0] : null;
}

async function rowCount(action) {
  await b.audit.flush();
  return _asRows(await b.audit.query({ action: action, order: "desc", limit: 50 })).length;
}

// ---- the console asks before it acts ---------------------------------------

// The shape every gated verb shares, asked once per verb so a verb that
// stopped asking is named rather than folded into a total.
//
// Three posts and three readings. The first names no confirmation and
// must change nothing; the second names the wrong one and must change
// nothing; the third names what the page said and must go through. The
// state is read after each, because a status code says what the server
// answered and only the row says what it did.
async function askedBeforeItActs(opts) {
  var bare = await opts.operator.form(opts.path, opts.fields);
  count(opts.label + ": a first post asks rather than acting",
    bare.status === 200 && noticeOf(bare) === "",
    bare.status + " " + String(bare.location));
  count(opts.label + ": and the page it answers with names what is about to happen",
    String(bare.body).indexOf(opts.phrase) !== -1,
    String(bare.body).slice(0, 400));
  count(opts.label + ": nothing has moved yet",
    (await opts.settled()) === opts.before, String(await opts.settled()));

  var wrong = Object.assign({}, opts.fields, { confirm: opts.wrongPhrase });
  var refused = await opts.operator.form(opts.path, wrong);
  count(opts.label + ": a confirmation naming something else is refused",
    refused.status >= 400 && refused.status < 500 && noticeOf(refused) !== opts.notice,
    refused.status + " " + String(refused.location));
  count(opts.label + ": and still nothing has moved",
    (await opts.settled()) === opts.before, String(await opts.settled()));

  var right = Object.assign({}, opts.fields, { confirm: opts.phrase });
  var done = await opts.operator.form(opts.path, right);
  count(opts.label + ": the typed confirmation is what lets it through",
    done.status === 302 && noticeOf(done) === opts.notice,
    done.status + " " + String(done.location));
  count(opts.label + ": and the change is recorded",
    (await opts.settled()) === opts.after, String(await opts.settled()));
}

async function testArchivingAsksBeforeItActs(operator, identity) {
  await askedBeforeItActs({
    operator: operator,
    label:    "archiving an account",
    path:     "/admin/accounts",
    fields:   { action: "archive", id: (await identity.accounts.get(ARCHIVABLE)).id,
                reason: ARCHIVE_REASON },
    phrase:      ARCHIVABLE,
    wrongPhrase: SUSPENDABLE,
    notice:      "archived",
    before:      "active",
    after:       "archived",
    settled:     function () { return statusOf(identity, ARCHIVABLE); },
  });
}

async function testWithdrawingADomainAsksBeforeItActs(operator, identity) {
  await askedBeforeItActs({
    operator: operator,
    label:    "withdrawing a hosted domain",
    path:     "/admin/domains",
    fields:   { action: "disable", domain: SPARE_DOMAIN, reason: DOMAIN_REASON },
    phrase:      SPARE_DOMAIN,
    wrongPhrase: DOMAIN,
    notice:      "domain-saved",
    before:      "active",
    after:       "disabled",
    settled:     function () { return domainStatusOf(identity, SPARE_DOMAIN); },
  });
}

async function testRemovingAnAliasAsksBeforeItActs(operator, identity) {
  var alias = await aliasNamed(identity, ALIAS_SOURCE);
  count("the run has an alias to remove", alias !== null, JSON.stringify(alias));
  await askedBeforeItActs({
    operator: operator,
    label:    "removing an alias",
    path:     "/admin/aliases",
    fields:   { action: "remove", id: alias.id, reason: ALIAS_REASON },
    phrase:      ALIAS_SOURCE,
    wrongPhrase: UNASKED_ALIAS,
    notice:      "alias-removed",
    before:      "present",
    after:       "gone",
    settled:     async function () {
      return (await aliasNamed(identity, ALIAS_SOURCE)) === null ? "gone" : "present";
    },
  });
}

// The selector is the thing withdrawn and the thing an operator gets
// wrong: a domain part way through a rotation holds two pairs and only
// one of them is the one the new records belong to. Retiring the other
// erases private keys nothing puts back.
//
// What is typed is the name the pair's record is published at, which
// carries the domain as well as the selector. The default selector is the
// same on every domain keyed in the same month, so the selector alone
// would confirm a press on another domain's card.
// `test/layer-1-state/web-admin-confirmation-target.test.js` asks that
// question directly.
async function testRetiringASelectorAsksBeforeItActs(operator, server) {
  function activeSelector() {
    var rows = server.mail.dkim.list(DOMAIN);
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].state === "active" && rows[i].algorithm === "ed25519") return rows[i].selector;
    }
    return "";
  }
  var selector = activeSelector();
  count("the run has an active signing selector to retire",
    selector.length > 0, JSON.stringify(server.mail.dkim.list(DOMAIN)));

  await askedBeforeItActs({
    operator: operator,
    label:    "retiring a signing pair",
    path:     "/admin/dkim",
    fields:   { action: "retire", domain: DOMAIN, selector: selector },
    phrase:      selector + "._domainkey." + DOMAIN,
    wrongPhrase: selector,
    notice:      "keys-retiring",
    before:      selector,
    after:       "",
    settled:     function () { return Promise.resolve(activeSelector()); },
  });
}

// The count is the confirmation here, because the subject is a set
// rather than a name. It is read off the page and recomputed at the
// moment of the act, so a selection that went out, ended in a report or
// was cancelled from another window between the two posts no longer
// matches and nothing is erased under a page that has gone stale.
async function testCancellingQueuedMailAsksBeforeItActs(operator, dataDir) {
  var bare = await operator.form("/admin/queue", {
    action: "cancel", id: [FIRST_ID, SECOND_ID], reason: CANCEL_REASON,
  });
  count("cancelling queued mail asks rather than erasing",
    bare.status === 200 && noticeOf(bare) === "",
    bare.status + " " + String(bare.location));
  count("and the page names the recipients whose mail would go",
    String(bare.body).indexOf(FIRST_TARGET) !== -1 &&
    String(bare.body).indexOf(SECOND_TARGET) !== -1,
    String(bare.body).slice(0, 600));
  count("both messages are still on the volume",
    spooled(dataDir, FIRST_ID) && spooled(dataDir, SECOND_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));

  var wrong = await operator.form("/admin/queue", {
    action: "cancel", id: [FIRST_ID, SECOND_ID], reason: CANCEL_REASON, confirm: "1",
  });
  count("a count that does not match what the queue still holds is refused",
    wrong.status >= 400 && wrong.status < 500 && noticeOf(wrong) !== "queue-cancelled",
    wrong.status + " " + String(wrong.location));
  count("and both messages are still there",
    spooled(dataDir, FIRST_ID) && spooled(dataDir, SECOND_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));

  var done = await operator.form("/admin/queue", {
    action: "cancel", id: [FIRST_ID, SECOND_ID], reason: CANCEL_REASON, confirm: "2",
  });
  count("the count read off the page is what lets the cancellation through",
    done.status === 302 && noticeOf(done) === "queue-cancelled",
    done.status + " " + String(done.location));
  count("and both messages are off the volume",
    !spooled(dataDir, FIRST_ID) && !spooled(dataDir, SECOND_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
}

// Who a cancellation is allowed to write to.
//
// Cancelling sends the sender a delivery report, which is right when the
// sender is somebody this server authenticated and wrong when it is not.
// The outbound spool holds both. A message relayed after an
// authenticated submission carries a reverse path bound to the account
// that authenticated, so it is an address here. A message an alias is
// forwarding off this server carries the reverse path that arrived on
// the inbound wire, which whoever sent the message chose and which this
// server has never checked against anything.
//
// Reporting on the second kind mails an address a stranger picked, from
// this server, because an operator pressed a button. The incident
// runbook sends an operator to this page to cancel a compromised
// account's outbound mail, which is the worst moment to turn one press
// into a run of mail to addresses somebody else chose.
//
// Both halves are asserted. Suppressing every report would pass the
// first half and would silently take away the answer a legitimate sender
// is owed, so the entry whose sender IS hosted here has to still produce
// one.
// Who this console's cancellation actually wrote to, read off the
// outbound spool.
//
// The report is composed and addressed inside the queue's own removal
// verb, which is where the decision about telling a sender is stated and
// enforced, so there is nothing above it to intercept. The spool is the
// next thing the report reaches and it is a file on the volume: the
// resolver this server was built with answers nothing, so the report
// gets as far as being queued and no further, and no case in this file
// touches a socket for two reserved documentation domains that resolve
// differently from each other.
//
// Reading it here rather than mocking is also the better assertion. What
// is being measured is which addresses this console causes mail to be
// sent to, and a report that exists on the volume addressed to somebody
// is that, whereas a recorded call is only a request to make one.
function bouncesOn(dataDir) {
  function queued() {
    var dir = nodePath.join(dataDir, "queue");
    if (!nodeFs.existsSync(dir)) return [];
    return nodeFs.readdirSync(dir)
      .filter(function (name) { return name.slice(-5) === ".json"; })
      .map(function (name) {
        try {
          return JSON.parse(nodeFs.readFileSync(nodePath.join(dir, name), "utf8"));
        } catch (_e) {
          return null;
        }
      })
      .filter(function (entry) { return entry !== null; });
  }
  // A report carries the empty reverse path, which is what tells one
  // apart from the ordinary mail the fixtures plant.
  function reports() {
    return queued().filter(function (entry) { return entry.from === ""; });
  }
  return {
    to: function (address) {
      return reports().filter(function (entry) { return entry.recipient === address; });
    },
    all: function () { return reports().map(function (entry) { return entry.recipient; }); },
  };
}

async function testACancellationOnlyReportsToASenderThisServerHosts(
  operator, dataDir, bounces
) {
  plant(dataDir, HOSTED_ID, HOSTED_TARGET, HOSTED_SENDER);
  plant(dataDir, FORGED_ID, FORGED_TARGET, FORGED_SENDER);

  var asked = await operator.form("/admin/queue", {
    action: "cancel", id: [HOSTED_ID, FORGED_ID], reason: CANCEL_REASON,
  });
  count("the page asks before cancelling either of them",
    asked.status === 200 && noticeOf(asked) === "",
    asked.status + " " + String(asked.location));
  count("and it says which of these senders this server will write to and which it " +
    "will not, before the operator decides",
    /no report/i.test(String(asked.body)) &&
    String(asked.body).indexOf(FORGED_SENDER) !== -1,
    String(asked.body).slice(0, 900));

  var done = await operator.form("/admin/queue", {
    action: "cancel", id: [HOSTED_ID, FORGED_ID], reason: CANCEL_REASON, confirm: "2",
  });
  count("both messages are cancelled",
    done.status === 302 && noticeOf(done) === "queue-cancelled" &&
    !spooled(dataDir, HOSTED_ID) && !spooled(dataDir, FORGED_ID),
    done.status + " " + String(done.location));

  // The security half.
  count("nothing is written to the reverse path this server hosts nothing at, so an " +
    "operator cancelling mail cannot be turned into mail to an address a stranger chose",
    bounces.to(FORGED_SENDER).length === 0, JSON.stringify(bounces.all()));

  // The control. Without it, a fix that stopped reporting altogether
  // would pass everything above while taking away the answer the one
  // sender who is owed it gets.
  count("and the sender this server does host is still told, because a message the " +
    "operator cancelled is one its sender would otherwise believe went out",
    bounces.to(HOSTED_SENDER).length === 1, JSON.stringify(bounces.all()));

  await b.audit.flush();
  var rows = _asRows(await b.audit.query({
    action: QUEUE_REMOVED, order: "desc", limit: 20,
  }));
  var byId = Object.create(null);
  rows.forEach(function (row) {
    var meta;
    try { meta = JSON.parse(row.metadata || "{}"); } catch (_e) { meta = {}; }
    byId[String(row.resourceId)] = meta;
  });
  count("the row for the message whose sender is hosted here records that a report went",
    byId[HOSTED_ID] !== undefined && byId[HOSTED_ID].reported === true,
    JSON.stringify(byId[HOSTED_ID]));
  count("and the row for the other one records that none did, so the trail says who was " +
    "not told rather than leaving an operator to assume everybody was",
    byId[FORGED_ID] !== undefined && byId[FORGED_ID].reported === false,
    JSON.stringify(byId[FORGED_ID]));
}

// The control that keeps the confirmation from becoming a habit. A
// console that asked twice for everything would train an operator to
// type through the question, which is the same as not asking. Suspension
// is reversible from the row it is performed on and leaves the mailbox
// untouched, so it takes a reason and no second post.
async function testSuspendingIsOneStepAndStillNeedsAReason(operator, identity) {
  var subject = await identity.accounts.get(SUSPENDABLE);
  var bare = await operator.form("/admin/accounts", { action: "suspend", id: subject.id });
  count("suspending without a reason does not go through",
    bare.status !== 302 || noticeOf(bare) !== "suspended",
    bare.status + " " + String(bare.location));
  count("and the account is untouched",
    (await statusOf(identity, SUSPENDABLE)) === "active",
    String(await statusOf(identity, SUSPENDABLE)));

  var done = await operator.form("/admin/accounts", {
    action: "suspend", id: subject.id, reason: SUSPEND_REASON,
  });
  count("suspending with a reason lands in one post, with no second question",
    done.status === 302 && noticeOf(done) === "suspended",
    done.status + " " + String(done.location));
  count("and the account is suspended",
    (await statusOf(identity, SUSPENDABLE)) === "suspended",
    String(await statusOf(identity, SUSPENDABLE)));

  await operator.form("/admin/accounts", { action: "reinstate", id: subject.id });
  count("and one press puts it back, which is why it is not gated twice",
    (await statusOf(identity, SUSPENDABLE)) === "active",
    String(await statusOf(identity, SUSPENDABLE)));
}

// ---- the recorded reason is the operator's ---------------------------------

// The literal that used to be recorded whatever happened. A row carrying
// it is a row that answers nothing, and it is worse than a row with no
// reason at all, because a field that is present and always identical
// reads like somebody wrote it.
var PAGE_SUPPLIED = "operator request";

function carriesTypedReason(label, row, typed) {
  count(label + ": the row carries what the operator typed",
    row !== null && typeof row.reason === "string" && row.reason.indexOf(typed) !== -1,
    JSON.stringify(row && row.reason));
  count(label + ": and not a sentence the page filled in",
    row !== null && String(row.reason || "").indexOf(PAGE_SUPPLIED) === -1,
    JSON.stringify(row && row.reason));
}

async function testEveryRecordedReasonIsTyped() {
  carriesTypedReason("suspension",   await newestRow(SUSPENDED),      SUSPEND_REASON);
  carriesTypedReason("archival",     await newestRow(ARCHIVED),       ARCHIVE_REASON);
  carriesTypedReason("withdrawal",   await newestRow(DOMAIN_CHANGED), DOMAIN_REASON);
  carriesTypedReason("alias removal", await newestRow(ALIAS_REMOVED), ALIAS_REASON);
  carriesTypedReason("cancellation", await newestRow(QUEUE_REMOVED),  CANCEL_REASON);
}

// The other half of the same rule. A verb that records a reason must
// refuse without one rather than inventing one, and it must refuse
// BEFORE it changes anything.
async function testTheGatedVerbsRefuseWithoutAReason(operator, identity, server) {
  var doomed = await identity.accounts.get(ARCHIVABLE);
  var noReason = await operator.form("/admin/accounts", {
    action: "archive", id: doomed.id, confirm: ARCHIVABLE,
  });
  count("archiving with a confirmation but no reason does not go through",
    noReason.status !== 302 || noticeOf(noReason) !== "archived",
    noReason.status + " " + String(noReason.location));

  var domainNoReason = await operator.form("/admin/domains", {
    action: "disable", domain: UNASKED_DOMAIN, confirm: UNASKED_DOMAIN,
  });
  count("withdrawing a domain with no reason does not go through",
    domainNoReason.status !== 302 || noticeOf(domainNoReason) !== "domain-saved",
    domainNoReason.status + " " + String(domainNoReason.location));
  count("and that domain is still accepting mail",
    (await domainStatusOf(identity, UNASKED_DOMAIN)) === "active",
    String(await domainStatusOf(identity, UNASKED_DOMAIN)));

  // The verbs that record no reason of their own are not asked for one,
  // because a field the console collected and threw away would be the
  // page-supplied reason again with an extra step. The signing verbs
  // record what the signer wrote about the run, and this is the reading
  // that says so.
  var retired = await newestRow("blamepost.mail.dkim.keys_retired");
  count("a signing retirement records the signer's own account of the run rather than " +
    "a sentence collected by a form",
    retired !== null && String(retired.reason || "").indexOf(PAGE_SUPPLIED) === -1,
    JSON.stringify(retired && retired.reason));
  count("and the run it describes is one this console drove",
    retired !== null && retired.outcome === "success",
    JSON.stringify(retired && retired.outcome));
  count("the selector inventory agrees that the pair left signing",
    server.mail.dkim.list(DOMAIN).every(function (row) { return row.state !== "active"; }),
    JSON.stringify(server.mail.dkim.list(DOMAIN).map(function (r) {
      return r.selector + "/" + r.state;
    })));
}

// ---- an act happens only when it was asked for -----------------------------

async function testForcingTheQueueLeavesARow(operator, operatorAccount) {
  var before = await rowCount(QUEUE_FORCED);
  var answer = await operator.form("/admin/queue", { action: "run" });
  count("forcing the queue sends the operator back to it",
    answer.status === 302 && noticeOf(answer) === "queue-ran",
    answer.status + " " + String(answer.location));

  var row = await newestRow(QUEUE_FORCED);
  count("and a forced flush leaves a row, as every other act on this page does",
    (await rowCount(QUEUE_FORCED)) > before, before + " before");
  count("and it names the operator who forced it, in the column an auditor filters on",
    row !== null && row.actorUserId === operatorAccount.id,
    JSON.stringify(row && row.actorUserId));
}

// The field these five routes dispatch on, absent. A handler that
// defaults it onto a verb turns a request naming nothing into an act,
// and the operator sees the result of something they never asked for.
// Each case reads state rather than a status code, because a route can
// answer 302 and have done nothing, or answer 400 and have done
// something.
async function testARequestNamingNoActionActsOnNothing(operator, server) {
  var forcedBefore = await rowCount(QUEUE_FORCED);
  var queue = await operator.form("/admin/queue", {});
  count("a post to the queue naming no action is answered rather than faulting",
    queue.status < 500, String(queue.status));
  count("and it forces no flush",
    (await rowCount(QUEUE_FORCED)) === forcedBefore,
    forcedBefore + " before, " + (await rowCount(QUEUE_FORCED)) + " after");

  var signing = JSON.stringify(server.mail.dkim.list(DOMAIN));
  var keys = await operator.form("/admin/dkim", { domain: DOMAIN });
  count("a post to the selectors page naming no action is answered rather than faulting",
    keys.status < 500, String(keys.status));
  count("and it mints nothing, so the domain signs with what it signed with before",
    JSON.stringify(server.mail.dkim.list(DOMAIN)) === signing,
    JSON.stringify(server.mail.dkim.list(DOMAIN)));
}

// The same field, misspelled. This is the likelier half: a form field
// renamed on one page and not the other, or a request built by hand.
async function testAMisspelledActionActsOnNothing(operator, identity, server) {
  var signing = JSON.stringify(server.mail.dkim.list(DOMAIN));
  var keys = await operator.form("/admin/dkim",
    { action: "retyre", domain: DOMAIN, selector: "anything" });
  count("a misspelled selector action rotates nothing",
    JSON.stringify(server.mail.dkim.list(DOMAIN)) === signing,
    JSON.stringify(server.mail.dkim.list(DOMAIN)));
  count("and it is answered rather than faulting", keys.status < 500, String(keys.status));

  var made = await operator.form("/admin/accounts", {
    action: "archve", address: UNASKED_ACCOUNT, password: OTHER_PASSWORD,
    displayName: "never asked for",
  });
  count("a misspelled account action creates no account",
    (await identity.accounts.get(UNASKED_ACCOUNT)) === null,
    JSON.stringify(await identity.accounts.get(UNASKED_ACCOUNT)));
  count("and it is answered rather than faulting", made.status < 500, String(made.status));

  var hosted = await operator.form("/admin/domains",
    { action: "disble", domain: "misspelled.example" });
  count("a misspelled domain action hosts no domain",
    (await domainStatusOf(identity, "misspelled.example")) === null,
    String(await domainStatusOf(identity, "misspelled.example")));
  count("and it is answered rather than faulting", hosted.status < 500, String(hosted.status));

  var aliased = await operator.form("/admin/aliases",
    { action: "remve", address: UNASKED_ALIAS, destination: ALIAS_DESTINATION });
  count("a misspelled alias action creates no alias",
    (await aliasNamed(identity, UNASKED_ALIAS)) === null,
    JSON.stringify(await aliasNamed(identity, UNASKED_ALIAS)));
  count("and it is answered rather than faulting", aliased.status < 500, String(aliased.status));
}

// ---- the role, granted and taken back --------------------------------------

async function testTheRoleIsGrantedAndRevokedWithAReason(operator, identity) {
  var deputy = await identity.accounts.get(DEPUTY);
  count("the account that is about to be given the role administers nothing yet",
    deputy !== null && deputy.isAdmin === false, JSON.stringify(deputy && deputy.isAdmin));

  var noReason = await operator.form("/admin/accounts",
    { action: "grant-role", id: deputy.id });
  count("granting the console with no reason does not go through",
    noReason.status !== 302,
    noReason.status + " " + String(noReason.location));
  count("and the account still administers nothing",
    (await identity.accounts.get(DEPUTY)).isAdmin === false,
    JSON.stringify((await identity.accounts.get(DEPUTY)).isAdmin));

  var granted = await operator.form("/admin/accounts",
    { action: "grant-role", id: deputy.id, reason: GRANT_REASON });
  count("granting the console with a reason lands",
    granted.status === 302 && noticeOf(granted) === "role-granted",
    granted.status + " " + String(granted.location));
  count("and the account administers this server",
    (await identity.accounts.get(DEPUTY)).isAdmin === true,
    JSON.stringify((await identity.accounts.get(DEPUTY)).isAdmin));
  carriesTypedReason("role grant", await newestRow(ROLE_GRANTED), GRANT_REASON);

  var revoked = await operator.form("/admin/accounts",
    { action: "revoke-role", id: deputy.id, reason: REVOKE_REASON });
  count("and the role can be taken back, which is the containment that did not exist",
    revoked.status === 302 && noticeOf(revoked) === "role-revoked",
    revoked.status + " " + String(revoked.location));
  count("the account administers nothing again",
    (await identity.accounts.get(DEPUTY)).isAdmin === false,
    JSON.stringify((await identity.accounts.get(DEPUTY)).isAdmin));
  carriesTypedReason("role revocation", await newestRow(ROLE_REVOKED), REVOKE_REASON);
  count("and the mailbox is untouched, which is the whole reason for the verb",
    (await statusOf(identity, DEPUTY)) === "active",
    String(await statusOf(identity, DEPUTY)));
}

// The verb underneath, asked directly, because the console can only ever
// reach it with the two answers its own form produces. Everything below
// is an argument the route never sends and something else will: the
// command line when it grows the verb, and any later surface.
async function testTheRoleVerbHoldsItsOwnContract(identity) {
  var deputy = await identity.accounts.get(DEPUTY);
  var refusals = [
    ["an id naming no account",
      { id: "not-an-account", isAdmin: true, reason: "anything" }],
    ["no answer at all about which direction",
      { id: deputy.id, reason: "anything" }],
    ["a direction that is not a boolean",
      { id: deputy.id, isAdmin: "on", reason: "anything" }],
    ["no reason",
      { id: deputy.id, isAdmin: true }],
    ["a reason that is only space",
      { id: deputy.id, isAdmin: true, reason: "   " }],
  ];
  for (var i = 0; i < refusals.length; i += 1) {
    var raised = null;
    try { await identity.accounts.setAdmin(refusals[i][1]); }
    catch (e) { raised = e; }
    count("blamepost.store.accounts.setAdmin refuses " + refusals[i][0],
      raised !== null, JSON.stringify(raised && raised.code));
    count("and it refuses in words written for a person, under this layer's own code",
      raised !== null && typeof raised.code === "string" && raised.code.indexOf("store/") === 0,
      JSON.stringify(raised && raised.code));
  }
  count("and none of those moved the role",
    (await identity.accounts.get(DEPUTY)).isAdmin === false,
    JSON.stringify((await identity.accounts.get(DEPUTY)).isAdmin));

  // Asking for what is already true writes no row. A second grant
  // changes nothing, and a row saying the role was granted would put an
  // event on the chain that did not happen.
  var before = await rowCount(ROLE_GRANTED);
  await identity.accounts.setAdmin({
    id: deputy.id, isAdmin: false, reason: "it already holds nothing",
  });
  count("asking for the state an account is already in records nothing",
    (await rowCount(ROLE_GRANTED)) === before,
    before + " before, " + (await rowCount(ROLE_GRANTED)) + " after");
}

// Two mailbox statuses the role verb never asked about, and the reason
// asking matters even though neither can present a credential.
//
// An account that is archived or part way through an erasure signs in
// nowhere, so a role granted to one is inert the day it is written. It
// is not invisible: an operator reading who administers this server
// finds an account that cannot get in, and has to work out for
// themselves whether that is a mistake or a containment somebody
// started and did not finish.
//
// Archiving is the half that is worse than untidy. It is reversible on
// purpose, because a mailbox deleted by mistake is a support call rather
// than a restore, so a role granted while the mailbox was out of service
// comes back with the mailbox and nobody decided that.
//
// Taking the role BACK stays open in both states, and has to. Revocation
// is the containment the verb exists for, and refusing it here would
// strand the role on exactly the accounts nothing else can reach to take
// it off: an archived account cannot be suspended, and one part way
// through an erasure cannot be suspended or reinstated either.
async function testTheRoleIsNotGrantedToAMailboxOutOfService(identity) {
  var shelved = await identity.accounts.create({
    address: SHELVED, password: OTHER_PASSWORD, isAdmin: true });
  await identity.accounts["delete"]({ id: shelved.id, reason: "the owner has left" });
  count("the archived subject is out of service and still holds the role it was made with",
    (await statusOf(identity, SHELVED)) === "archived" &&
      (await identity.accounts.get(SHELVED)).isAdmin === true,
    JSON.stringify({ status: await statusOf(identity, SHELVED),
      isAdmin: (await identity.accounts.get(SHELVED)).isAdmin }));

  var backOut = null;
  try {
    await identity.accounts.setAdmin({
      id: shelved.id, isAdmin: false, reason: "the owner has left" });
  } catch (e) { backOut = e; }
  count("taking the role back from an archived account is allowed, because revocation is " +
    "the containment and an out of service mailbox is not a reason to leave the role on it",
    backOut === null && (await identity.accounts.get(SHELVED)).isAdmin === false,
    backOut === null ? "revoked" : String(backOut.code));

  var granted = null;
  try {
    await identity.accounts.setAdmin({
      id: shelved.id, isAdmin: true, reason: "cover for the rota" });
  } catch (e) { granted = e; }
  count("but granting it to an archived account is refused, under this layer's own code",
    granted !== null && granted.code === "store/account-archived",
    granted === null ? "granted" : String(granted.code));
  count("and the role did not move, so reinstating the mailbox does not hand back a role " +
    "nobody decided to give it",
    (await identity.accounts.get(SHELVED)).isAdmin === false,
    JSON.stringify((await identity.accounts.get(SHELVED)).isAdmin));

  // The other status, stood up the way an erasure actually stops: a
  // preservation order over a message the erasure was asked to destroy,
  // which keeps the mail and keeps the identity that owns it.
  var doomed = await identity.accounts.create({
    address: ERASING_SUBJECT, password: OTHER_PASSWORD, isAdmin: true });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"] };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(), { actor: owner });
  await identity.mailbox.legalHold.place(owner, "INBOX", [kept.objectid], {
    reason: HOLD_REASON, citation: HOLD_CITATION });

  var partial = await identity.accounts["delete"]({
    id: doomed.id, destroy: true, reason: "erasure requested by the account holder" });
  count("the erasure the order held back leaves the identity behind, marked as erasing",
    partial.outcome === "partially-erased" &&
      (await statusOf(identity, ERASING_SUBJECT)) === "erasing",
    JSON.stringify({ outcome: partial.outcome,
      status: await statusOf(identity, ERASING_SUBJECT) }));

  var handedBack = null;
  try {
    await identity.accounts.setAdmin({
      id: doomed.id, isAdmin: false, reason: "the mailbox is being erased" });
  } catch (e) { handedBack = e; }
  count("taking the role back from an account part way through an erasure is allowed too",
    handedBack === null && (await identity.accounts.get(ERASING_SUBJECT)).isAdmin === false,
    handedBack === null ? "revoked" : String(handedBack.code));

  var onErasing = null;
  try {
    await identity.accounts.setAdmin({
      id: doomed.id, isAdmin: true, reason: "cover for the rota" });
  } catch (e) { onErasing = e; }
  count("and granting it to one is refused, under this layer's own code, because its mail " +
    "is already destroyed and nothing puts the mailbox back",
    onErasing !== null && onErasing.code === "store/account-erasing",
    onErasing === null ? "granted" : String(onErasing.code));

  count("neither subject is left administering this server",
    (await identity.accounts.get(SHELVED)).isAdmin === false &&
      (await identity.accounts.get(ERASING_SUBJECT)).isAdmin === false,
    JSON.stringify({ shelved: (await identity.accounts.get(SHELVED)).isAdmin,
      erasing: (await identity.accounts.get(ERASING_SUBJECT)).isAdmin }));
}

// The half that decides whether revocation is containment at all.
// Whoever took the credential already holds a session, so refusing the
// next sign-in answers nothing: what matters is whether the session
// already open stops administering the server.
async function testARevokedRoleStopsAnOpenSession(operator, identity, origin, caPem) {
  var deputy = await identity.accounts.get(DEPUTY);
  var granted = await operator.form("/admin/accounts",
    { action: "grant-role", id: deputy.id, reason: GRANT_REASON });
  count("the role is granted again, to the account whose session is about to be measured",
    granted.status === 302, granted.status + " " + String(granted.location));

  var held = browser.browserAt(origin, { ca: caPem });
  var landed = await held.signIn(DEPUTY, OTHER_PASSWORD);
  count("that account opens a session while it still holds the role",
    landed.status === 302, landed.status + " " + String(landed.location));
  var before = await held.get("/admin/accounts");
  count("and the session administers this server", before.status === 200, String(before.status));

  var taken = await operator.form("/admin/accounts",
    { action: "revoke-role", id: deputy.id, reason: REVOKE_REASON });
  count("the operator takes the role back", taken.status === 302 &&
    (await identity.accounts.get(DEPUTY)).isAdmin === false,
    taken.status + " " + JSON.stringify((await identity.accounts.get(DEPUTY)).isAdmin));

  var after = await held.get("/admin/accounts");
  count("the session that was already open stops administering, because containment " +
    "that waits for a session to expire is not containment",
    after.status !== 200, String(after.status));

  var subject = await identity.accounts.get(SUSPENDABLE);
  await held.form("/admin/accounts",
    { action: "suspend", id: subject.id, reason: "still here" });
  count("and a verb driven from it does not land",
    (await statusOf(identity, SUSPENDABLE)) === "active",
    String(await statusOf(identity, SUSPENDABLE)));
}

// Revocation reaches the same wall archiving and withdrawing already
// reach, and by the same measurement rather than a second one. A console
// that let the last role go would be a console nobody can sign in to,
// with nothing left that grants the role back.
async function testTheLastAdministratorsRoleCannotBeRevoked(operator, identity, admin) {
  var before = await rowCount(LAST_ADMIN_REFUSED);
  var answer = await operator.form("/admin/accounts",
    { action: "revoke-role", id: admin.id, reason: "stepping back from the rota" });
  count("taking the role from the last administrator is refused rather than performed",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the refusal says what would be left, which is nobody",
    /no administrator/i.test(String(answer.body)), String(answer.body).slice(0, 600));
  count("that account still administers this server",
    (await identity.accounts.get(admin.address)).isAdmin === true,
    JSON.stringify((await identity.accounts.get(admin.address)).isAdmin));
  count("and the refused attempt is on the audit chain, under the name the other two " +
    "stranding refusals already file",
    (await rowCount(LAST_ADMIN_REFUSED)) > before,
    before + " before, " + (await rowCount(LAST_ADMIN_REFUSED)) + " after");
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-admin-confirmation");
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
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: SPARE_DOMAIN });
    await identity.domains.add({ domain: UNASKED_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "confirmation run" });

    var operatorAccount = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });
    count("the run drives an account that administers this server",
      operatorAccount.isAdmin === true, operatorAccount.isAdmin);

    await identity.accounts.create({ address: SUSPENDABLE, password: OTHER_PASSWORD });
    await identity.accounts.create({ address: ARCHIVABLE,  password: OTHER_PASSWORD });
    await identity.accounts.create({ address: DEPUTY,      password: OTHER_PASSWORD });
    await identity.aliases.add({ address: ALIAS_SOURCE, destination: ALIAS_DESTINATION });

    plant(dataDir, FIRST_ID,  FIRST_TARGET);
    plant(dataDir, SECOND_ID, SECOND_TARGET);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     UNANSWERING,
    });
    await server.start();
    running = true;

    await server.mail.dkim.generate({ domain: DOMAIN });

    // Read off the spool the server was given, which is where a report
    // stops. Nothing in this file reaches a socket: the resolver above
    // answers no question, so every report is queued and none is
    // attempted. Every reverse path a fixture here carries is a reserved
    // documentation name, and two of them resolve differently from each
    // other, which would otherwise make a verdict about this console
    // depend on what the network said about somebody else's zone.
    var bounces = bouncesOn(dataDir);

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    var landed = await operator.signIn(operatorAccount.address, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    await testSuspendingIsOneStepAndStillNeedsAReason(operator, identity);
    await testArchivingAsksBeforeItActs(operator, identity);
    await testWithdrawingADomainAsksBeforeItActs(operator, identity);
    await testRemovingAnAliasAsksBeforeItActs(operator, identity);
    await testCancellingQueuedMailAsksBeforeItActs(operator, dataDir);
    await testACancellationOnlyReportsToASenderThisServerHosts(operator, dataDir, bounces);

    // The dispatch cases run here rather than at the end, and the
    // ordering is the assertion. Both of them measure that a request
    // naming no action or a misspelled one leaves the signing pair
    // exactly as it was, which is only a question while the domain still
    // HAS an active pair: run them after the retirement below and the
    // rotation they are watching for would be refused for having nothing
    // to rotate away from, so both would pass against a console that
    // rotates on every unrecognized word. They run after the queue cases
    // for the same kind of reason: a spool with messages on it turns a
    // flush this file never asked for into real delivery attempts.
    await testForcingTheQueueLeavesARow(operator, operatorAccount);
    await testARequestNamingNoActionActsOnNothing(operator, server);
    await testAMisspelledActionActsOnNothing(operator, identity, server);

    await testRetiringASelectorAsksBeforeItActs(operator, server);
    await testEveryRecordedReasonIsTyped();
    await testTheGatedVerbsRefuseWithoutAReason(operator, identity, server);

    await testTheRoleIsGrantedAndRevokedWithAReason(operator, identity);
    await testTheRoleVerbHoldsItsOwnContract(identity);
    // Ahead of the last-administrator case below, and both of its
    // subjects end holding nothing: an extra administrator left standing
    // here would be one more the measurement down there counts, and the
    // refusal it is asserting would stop being reachable.
    await testTheRoleIsNotGrantedToAMailboxOutOfService(identity);
    await testARevokedRoleStopsAnOpenSession(operator, identity, origin, material.caPem);
    await testTheLastAdministratorsRoleCannotBeRevoked(operator, identity, operatorAccount);

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
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name: "web-admin-confirmation", run: run, getChecks: helpers.getChecks,
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
