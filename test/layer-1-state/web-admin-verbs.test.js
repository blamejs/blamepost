// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two operator verbs the browser console drives that reach past the
 * identity layer, and what each of them owes the operator afterwards.
 *
 * `test/layer-1-state/server-console-isolation.test.js` asks whether the
 * console admits the right caller. This file asks what happens once the
 * right caller is inside it. Every console verb that reaches the
 * identity layer is recorded there, in the same call that changes the
 * row, so the trail is complete for accounts, domains, aliases and
 * sign-in budgets whichever surface drove them. Two verbs do not go
 * through that layer:
 *
 *   - **Cancelling a queued message** erases a body and a descriptor off
 *     the volume. The command line verb for the same act refuses without
 *     a reason, refuses an id the queue does not hold, and files a row
 *     naming what was cancelled. The browser is the surface an operator
 *     actually reaches for during an incident, and an incident is the
 *     moment somebody asks afterwards what was cancelled and by whom.
 *   - **Minting, rotating and retiring a signing selector** answers the
 *     operator with whatever the signer raised. A refusal the signer
 *     wrote for a person is the answer that belongs on the page; a fault
 *     it never wrote for anybody carries the data directory, the key
 *     file naming scheme and the atomic write's temporary suffix, and
 *     putting that on a page is both a disclosure and a fault the error
 *     log never hears about.
 *
 * Two authors compose refusals carrying a `dkim/` code: this server's
 * signer, which words them for the operator reading the page, and the
 * framework underneath it, which words them for whoever composed the
 * framework. The set of codes the signer publishes is what tells them
 * apart, so the page reads membership in that set. A name carrying the
 * DNS root's trailing dot is the shortest route the console ever had to
 * the framework's own vocabulary: the domain guard admits the absolute
 * form as the valid name it is, and the framework's signer holds a name
 * against a shape with no room for it. The name is folded to the domain
 * it means before it gets there, so that route is closed, and the two
 * cases that follow hold the display rule itself against codes no route
 * reaches.
 *
 * The third concern is what the console must not be able to do to
 * itself. Suspending or archiving the last administrator, and disabling
 * the domain that administrator's address belongs to, each leave a
 * server whose console nobody can sign in to. Nothing about that is
 * recoverable from the browser afterwards, and the command line verbs
 * that undo it open the data volume, which the running server holds, so
 * the way back begins with stopping the server. The console therefore
 * measures what would be left and refuses to strand itself, while
 * containment of an administrator whose credential has been taken stays
 * open in both places: from the console while another administrator
 * remains, and from the host once the server is stopped.
 *
 * All of it is driven over a real loopback port with a real operator
 * session, because a handle called directly proves what the handle does
 * and not what the route does.
 *
 * Run standalone: node test/layer-1-state/web-admin-verbs.test.js
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
var tables    = require("../../lib/store/tables");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

// A second hosted domain, so the mint that is made to fail is made to
// fail on a domain that holds no keys yet. Failing the mint on the first
// one would leave the run unable to tell a refusal about an existing
// pair from a refusal about the volume.
var SECOND_DOMAIN = "second.example";

// A third hosted name, and the same name written in the absolute form of
// RFC 1035 section 2.3.1. `b.guardDomain` admits the absolute form under
// the strict profile the signer holds a name against, because it is a
// valid spelling of the name; what it is not is a second domain.
//
// It is a domain of its own rather than the one above because the case
// that drives it mints a pair, and the volume-fault case further down
// needs a domain that still holds none: a mint refused because keys are
// already there never reaches the volume it was made to fail on.
var ABSOLUTE_DOMAIN = "absolute.example";
var ROOTED_DOMAIN   = ABSOLUTE_DOMAIN + ".";

// A fourth hosted name, for the sweep. It needs a domain of its own
// because a sweep with no domain named reaches every retiring selector on
// the volume, so a vector that retired a pair on a domain another case
// reads would change what that case is looking at.
var SWEEP_DOMAIN = "sweep.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 5512";

// A second administrator, and a mailbox owner who administers nothing.
// The first is what makes containment from the console possible at all;
// the second is the control that proves the guard measures what would be
// left rather than refusing every suspension it is shown.
var SECOND_ADMIN   = "eve@" + DOMAIN;
var PLAIN_ACCOUNT  = "carol@" + DOMAIN;
var OTHER_PASSWORD = "another operator passphrase 8841";

// An administrator whose credential has been taken, and a mailbox owner
// the cases below aim a destructive verb at. The second one is never
// meant to move: every case that names it expects to read `active` back
// afterwards, so it is the state that says whether a refusal refused.
var TAKEN_ADMIN = "mallory@" + DOMAIN;
var VICTIM      = "dana@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The row the command line files when it abandons a queued message. The
// browser console cancels the same message off the same spool, so it is
// the same event and takes the same name; a second name for one act is
// two filters an auditor has to know to ask for.
var QUEUE_REMOVED = "blamepost.mail.queue.message_removed";

// The row the console files when it refuses to leave this server with no
// administrator able to sign in. A refused attempt is worth as much to an
// incident review as one that went through: it is somebody, possibly not
// the operator, reaching for the one action that takes the console away.
var LAST_ADMIN_REFUSED = "blamepost.web.last_administrator_removal_not_permitted";

// Ids in the shape the spool mints: lowercase hex, long enough that
// nothing an operator mistypes reaches a file.
var DOOMED_ID  = "0123456789abcdef0123456789abcdef";
var SPARED_ID  = "fedcba9876543210fedcba9876543210";

// The same shape again, for an entry that was never spooled. It has to
// be well formed, because a malformed one is refused on its shape and
// would prove nothing about what happens to a well formed id naming
// nothing.
var ABSENT_ID = "abcdef0123456789abcdef0123456789";

// And one that could never have been minted here. It is the shape that
// becomes a path, which is why the spool refuses it before it does.
var MALFORMED_ID = "../../etc/passwd";

var DOOMED_SENDER    = "alice@" + DOMAIN;
var DOOMED_RECIPIENT = "bob@example.net";
var SPARED_RECIPIENT = "carol@example.net";

var MESSAGE = "From: " + DOOMED_SENDER + "\r\nTo: " + DOOMED_RECIPIENT + "\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

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

// Every mail listener off. This file is about two browser routes, and a
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
function plant(dataDir, id, from, recipient) {
  nodeFs.mkdirSync(nodePath.join(dataDir, "queue"), { recursive: true });
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".eml"), MESSAGE, "utf8");
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".json"), JSON.stringify({
    id:               id,
    from:             from,
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

// ---- cancelling a queued message -------------------------------------------

async function testTheQueuePageListsWhatIsWaiting(operator) {
  var page = await operator.get("/admin/queue");
  count("the operator is served the outbound queue", page.status === 200, page.status);
  count("and it lists both waiting messages",
    page.body.indexOf(DOOMED_RECIPIENT) !== -1 &&
    page.body.indexOf(SPARED_RECIPIENT) !== -1,
    page.status + " " + page.body.length);
}

async function testCancellingErasesTheMessage(operator, dataDir) {
  // Carrying the confirmation and the reason in the same post, which is
  // what the second half of a cancellation looks like on the wire. That
  // the FIRST post asks instead of erasing is
  // test/layer-1-state/web-admin-confirmation.test.js; what this file
  // asks is what happens once the operator has answered.
  var answer = await operator.form("/admin/queue", {
    action: "cancel", id: DOOMED_ID, confirm: "1",
    reason: "the sender asked for this to be pulled back",
  });
  count("cancelling one waiting message sends the operator back to the queue",
    answer.status === 302, answer.status + " " + String(answer.location));
  count("and reports that it was cancelled", noticeOf(answer) === "queue-cancelled",
    String(answer.location));
  count("the message it named is off the volume", !spooled(dataDir, DOOMED_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
  count("and the one it did not name is still waiting", spooled(dataDir, SPARED_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
}

// The row the cancellation owes. Read back by name rather than assumed
// from the fact that a line of code emits it: the audit chain drops an
// event whose namespace was never registered rather than storing it.
async function testCancellingIsOnTheAuditChain(operatorAccount) {
  await b.audit.flush();
  var rows = _asRows(await b.audit.query({ action: QUEUE_REMOVED, order: "desc", limit: 20 }));
  count("cancelling a queued message leaves a row", rows.length >= 1, String(rows.length));

  var row = rows.length > 0 ? rows[0] : null;
  count("and it names the operator who cancelled it, in the column an auditor filters on",
    row !== null && row.actorUserId === operatorAccount.id,
    JSON.stringify(row && row.actorUserId));
  count("and the message it names is the one that was erased",
    row !== null && row.resourceId === DOOMED_ID, JSON.stringify(row && row.resourceId));
  count("and the row carries a reason, which is the column an incident review reads",
    row !== null && typeof row.reason === "string" && row.reason.length > 0,
    JSON.stringify(row && row.reason));

  var held;
  try { held = JSON.parse((row && row.metadata) || "{}"); } catch (_e) { held = {}; }
  count("and it says who the message was for, so the trail answers what was cancelled",
    String(held.recipient || "").indexOf(DOOMED_RECIPIENT) !== -1,
    JSON.stringify(held));
}

// An id the queue does not hold. Reporting it as cancelled tells an
// operator working through a compromised account's outbound mail that a
// message is gone while it is still on disk waiting for its next
// attempt, which is the one answer this page must never give.
async function testAnIdTheQueueDoesNotHoldIsNotReportedAsCancelled(operator) {
  var before = _asRows(await b.audit.query({ action: QUEUE_REMOVED, order: "desc", limit: 50 }));
  var answer = await operator.form("/admin/queue", { action: "cancel", id: ABSENT_ID });
  count("cancelling an id the queue does not hold is answered rather than crashing",
    answer.status >= 200 && answer.status < 500,
    answer.status + " " + String(answer.location));
  count("and it is not reported as a cancellation", noticeOf(answer) !== "queue-cancelled",
    answer.status + " " + String(answer.location));

  await b.audit.flush();
  var after = _asRows(await b.audit.query({ action: QUEUE_REMOVED, order: "desc", limit: 50 }));
  count("and nothing is filed claiming a message was removed",
    after.length === before.length, before.length + " before, " + after.length + " after");
}

// An id that could never have been minted here. The spool refuses it
// before it becomes a path, and the refusal has to reach the operator as
// an answer rather than as a server error: a page that answers 500 tells
// them the server is broken when the server has just protected itself.
async function testAnIdTheSpoolCouldNotHaveMintedIsRefusedAsAnAnswer(operator) {
  var answer = await operator.form("/admin/queue", { action: "cancel", id: MALFORMED_ID });
  count("an id the spool could not have minted is refused rather than faulting",
    answer.status < 500, answer.status + " " + String(answer.location));
  count("and it is not reported as a cancellation either",
    noticeOf(answer) !== "queue-cancelled", answer.status + " " + String(answer.location));
}

// ---- what a selector refusal says ------------------------------------------

// The differential, and it goes first. The signer writes its refusals
// for a person, and a page that answered every one of them with the same
// sentence would pass every disclosure assertion below while telling an
// operator nothing they can act on.
async function testASelectorRefusalWrittenForAPersonReachesTheOperator(operator) {
  var answer = await operator.form("/admin/dkim", { action: "generate", domain: DOMAIN });
  count("minting keys for a domain that already has them is refused",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the page says what is already there and what to do instead",
    answer.body.indexOf("already has active keys") !== -1,
    answer.body.slice(0, 400));
}

// ---- the numbers on the overview -------------------------------------------

// What the front page of the console tells an operator, checked against
// the pages those numbers link to.
//
// A tile is one integer with a word beside it, which is the easiest thing
// on this surface to render wrong and the hardest to notice: it is read at
// a glance, it is believed, and nothing else on the page contradicts it.
// The selector tile is the one that decides whether an operator thinks
// this server can sign mail at all, so a zero there while four selectors
// are live is an operator going to look for a signing problem that does
// not exist, or not publishing records they already need.
//
// So each number is compared against the page it links to rather than
// against a second copy of the query that produced it. A test that
// recomputed the count the same way the route does would agree with the
// route however wrong both were.
async function testTheOverviewCountsAgreeWithThePagesTheyLinkTo(operator, identity) {
  var overview = await operator.get("/admin");
  count("the console's front page is served", overview.status === 200,
    overview.status + " " + overview.body.slice(0, 160));

  function tile(label) {
    // The rendered pair, read off the page rather than off the scope the
    // route handed the template: the template is the last place the
    // number can be dropped, and a scope-level read would not see it.
    var re = new RegExp("<[^>]*>\\s*(\\d+)\\s*<\\/[^>]*>\\s*<[^>]*>\\s*" + label + "\\s*<\\/");
    var found = re.exec(overview.body);
    return found === null ? null : Number(found[1]);
  }

  // What the selector page actually holds, counted through the same
  // reader the console's own selector page renders from.
  var live = _asRows(await identity.domains.listSelectors({}));
  count("the run really does hold signing selectors, so the tile below " +
    "answers for something", live.length > 0, String(live.length));

  var shown = tile("Selectors");
  count("the selector tile carries a number at all", shown !== null,
    String(shown));
  count("and it is the number of selectors this server holds rather than a " +
    "constant zero", shown === live.length, shown + " shown, " + live.length + " held");

  // The neighboring tiles, because a count read off the wrong property
  // is a shape mistake and shape mistakes come in families. Two of the
  // three were right, which is exactly why nobody looked at the third.
  var domains = _asRows(await identity.domains.list({}));
  count("the domain tile is the number of hosted domains",
    tile("Domains") === domains.length,
    tile("Domains") + " shown, " + domains.length + " held");

  var accounts = _asRows(await identity.accounts.list({ includeArchived: true }));
  count("the account tile is the number of accounts",
    tile("Accounts") === accounts.length,
    tile("Accounts") + " shown, " + accounts.length + " held");
}

// ---- the sweep, and the answer nothing had ever driven ---------------------

// The sweep button has three answers and two of them were being taken on
// trust. `keys-swept` is the ordinary one. `keys-swept-stranded` is the
// one that matters: the rows of a pair past its overlap are gone, and a
// sealed private key one of them named is still in the keys folder under
// a name no record points at. Nothing here will ever name it again,
// because the row that could was the thing just deleted, so a page that
// flashed a fixed success would spend the only chance the operator had of
// being told. Whoever holds that file signs mail as the domain.
//
// The volume is what refuses, so the volume is what is faulted: the
// erasure's own asynchronous removal answers EBUSY, which is a file held
// open on a running server rather than a permission an operator would
// have met at boot. Nothing about the route is stood in for.
var OUTGOING_SELECTOR = "bpfirst";

function _isOutgoing(row) {
  return row.selector === OUTGOING_SELECTOR || row.selector === OUTGOING_SELECTOR + "-rsa";
}

async function testASweepThatStrandsAKeyTellsTheOperator(operator, server, identity, dataDir) {
  var keyDir = nodePath.join(dataDir, "keys");

  await server.mail.dkim.generate({ domain: SWEEP_DOMAIN, selector: "bpfirst" });
  await server.mail.dkim.rotate({ domain: SWEEP_DOMAIN, selector: "bpsecond" });
  count("the domain is part way through a rotation, so withdrawing the outgoing pair " +
    "leaves it still signing",
  identity.domains.listSelectors({ domain: SWEEP_DOMAIN }).length === 4,
  String(identity.domains.listSelectors({ domain: SWEEP_DOMAIN }).length));

  // A pair is two rows under two names: the one that was asked for and
  // the RSA half, which the signer names `<selector>-rsa` unless it is
  // given one. Both have to be retired, because a pair holding one
  // algorithm signs nothing.
  var outgoing = identity.domains.listSelectors({ domain: SWEEP_DOMAIN })
    .filter(function (row) { return _isOutgoing(row); });
  count("the outgoing pair is both of its algorithms", outgoing.length === 2,
    outgoing.map(function (r) { return r.selector + ":" + r.algorithm; }).join(", "));

  for (var i = 0; i < outgoing.length; i += 1) {
    await identity.domains.retireSelector({
      domain:    SWEEP_DOMAIN,
      selector:  outgoing[i].selector,
      algorithm: outgoing[i].algorithm,
    });
  }

  // The overlap is a week, and what is under test is the page's answer
  // rather than the clock deciding when a record may leave the zone. So
  // the window is moved into the past on the rows themselves and every
  // other part of the sweep runs the way it runs on a live server: the
  // route reads its own clock, the store applies its own window check,
  // and the erasure meets a volume that will not take the removal.
  var elapsed = Date.now() - b.constants.TIME.days(1);
  identity.domains.listSelectors({ domain: SWEEP_DOMAIN, status: "retiring" })
    .forEach(function (row) {
      tables.updateRow(tables.SELECTORS, row.id, { retiresAt: elapsed });
    });

  var held = outgoing[0].keyRef;
  count("the key the volume is about to refuse is on the volume to begin with",
    nodeFs.existsSync(nodePath.join(keyDir, held)), held);

  var fault = helpers.installRemovalFault(held);
  var answer;
  try {
    answer = await operator.form("/admin/dkim", { action: "sweep", domain: SWEEP_DOMAIN });
  } finally {
    fault.remove();
  }

  count("the sweep redirects rather than erroring", answer.status === 302,
    answer.status + " " + String(answer.location));
  count("the volume was actually asked to destroy that key, so the refusal is the one " +
    "being measured rather than a sweep that reached nothing",
  fault.attempts.length > 0, JSON.stringify(fault.attempts));
  count("and the operator is told a sealed private key was left behind, rather than being " +
    "shown the success the other two answers wear",
  noticeOf(answer) === "keys-swept-stranded", noticeOf(answer));

  // The substance behind the notice, because a page that said the right
  // word over the wrong state would pass the line above. The rows are
  // gone and the file is not, which is exactly the state the operator is
  // being sent to go and find.
  count("no selector row for the withdrawn pair is left publishing",
    identity.domains.listSelectors({ domain: SWEEP_DOMAIN })
      .filter(_isOutgoing).length === 0,
    identity.domains.listSelectors({ domain: SWEEP_DOMAIN })
      .map(function (row) { return row.selector + ":" + row.status; }).join(", "));

  var strays = nodeFs.readdirSync(keyDir).filter(function (f) { return f.indexOf(held) === 0; });
  count("and the sealed private key is still in the keys folder under a name nothing " +
    "points at, which is what the notice sends the operator to delete by hand",
  strays.length === 1 && strays[0] !== held, strays.join(", ") || "(none)");

  count("the domain still signs, so the sweep took the outgoing pair and not the live one",
    identity.domains.listSelectors({ domain: SWEEP_DOMAIN, status: "active" }).length === 2,
    identity.domains.listSelectors({ domain: SWEEP_DOMAIN, status: "active" })
      .map(function (row) { return row.selector + ":" + row.algorithm; }).join(", "));
}

// The volume the sealed private halves are written to, made unwritable.
// A directory replaced by a plain file is the shape that fails the same
// way on every platform this server runs on, which a permission bit is
// not.
function sabotageKeyDirectory(dataDir) {
  var keyDir = nodePath.join(dataDir, "keys");
  nodeFs.rmSync(keyDir, { recursive: true, force: true });
  nodeFs.writeFileSync(keyDir, "this is not a directory", "utf8");
  return keyDir;
}

async function testAFaultTheSignerNeverWroteForAnybodyStaysOffThePage(operator, dataDir) {
  var keyDir = sabotageKeyDirectory(dataDir);
  var answer = await operator.form("/admin/dkim",
    { action: "generate", domain: SECOND_DOMAIN });
  count("a mint that cannot reach the volume is refused rather than reported as done",
    answer.status === 400, answer.status + " " + String(answer.location));

  var page = String(answer.body);
  count("the refusal carries no path from this server's volume",
    page.indexOf(dataDir) === -1 && page.indexOf(keyDir) === -1,
    page.slice(Math.max(0, page.indexOf(dataDir) - 80), 200));
  count("nor the naming scheme the sealed private halves are stored under",
    page.indexOf(".sealed") === -1, page.slice(0, 400));
  count("nor the suffix an atomic write gives its temporary file",
    page.indexOf(".tmp-") === -1, page.slice(0, 400));
  count("nor the operating system's own error name",
    page.indexOf("ENOENT") === -1 && page.indexOf("ENOTDIR") === -1, page.slice(0, 400));
  count("and it still tells the operator that the change was not made",
    /could not be made/.test(page), page.slice(0, 400));
}

// The console's shortest route to the framework's own vocabulary, and
// what closes it.
//
// A name ending in the DNS root's dot is the absolute form of RFC 1035
// section 2.3.1, and the domain guard admits it as the valid name it is.
// The framework's signer holds a name against a shape with no room for
// it, so a console that passed the spelling along reached a refusal
// naming `b.mail.dkim.bootstrap` and the option path it validates,
// neither of which is anything an operator calls.
//
// The name is folded to the domain it means before any of that, so the
// request reaches the same domain the command line reaches and there is
// no framework refusal to keep off the page. The two cases below still
// hold the display rule itself, against codes no route reaches.
async function testTheAbsoluteFormReachesTheDomainRatherThanTheFramework(operator, server) {
  var answer = await operator.form("/admin/dkim",
    { action: "generate", domain: ROOTED_DOMAIN });
  count("minting for a domain typed in its absolute form is the same request as minting " +
    "for the name the operator hosts",
    answer.status === 302, answer.status + " " + String(answer.location));

  var rows = server.mail.dkim.list(ABSOLUTE_DOMAIN);
  count("and the pair it minted is recorded under the folded name, so the row and the " +
    "sealed key it points at are keyed on one name",
    rows.length === 2 && rows.every(function (row) { return row.domain === ABSOLUTE_DOMAIN; }),
    JSON.stringify(rows.map(function (row) { return row.domain + "/" + row.selector; })));

  // The same request again, in the spelling that provoked the framework
  // before. It is refused now by this server's own signer, for the
  // reason an operator can act on, rather than by the shape check
  // underneath it.
  var again = await operator.form("/admin/dkim",
    { action: "generate", domain: ROOTED_DOMAIN });
  count("asking twice is refused as the domain already holding keys",
    again.status === 400, again.status + " " + String(again.location));

  var page = String(again.body);
  count("and the refusal names no framework primitive an operator cannot call",
    page.indexOf("b.mail.dkim") === -1,
    page.slice(Math.max(0, page.indexOf("b.mail.dkim") - 120),
      Math.max(0, page.indexOf("b.mail.dkim")) + 200));
  count("nor the option path that primitive holds its argument against",
    page.indexOf("opts.domain") === -1 && page.indexOf("opts.selector") === -1,
    page.slice(0, 400));
}

// The same question asked of a code no route reaches today. What decides
// whether a message may be shown is membership in the set this server's
// signer publishes, so a framework refusal is refused whichever of the
// framework's own codes it carries, including the ones a validation
// change would bring within reach tomorrow.
async function testAFrameworkCodeThisServerNeverRaisesStaysOffThePage(server, operator) {
  var real = server.mail.dkim.generate;
  var wording = "b.mail.dkim.signer: opts.privateKey is required for rsa-sha256";
  server.mail.dkim.generate = function () {
    var raised = new Error(wording);
    raised.code = "dkim/missing-private-key";
    return Promise.reject(raised);
  };
  try {
    var answer = await operator.form("/admin/dkim",
      { action: "generate", domain: SECOND_DOMAIN });
    count("a signing refusal this server never composed is answered rather than shown",
      answer.status === 400, answer.status + " " + String(answer.location));
    count("and the wording the framework wrote does not reach the page",
      String(answer.body).indexOf(wording) === -1, String(answer.body).slice(0, 400));
  } finally {
    server.mail.dkim.generate = real;
  }
}

// ---- the last administrator ------------------------------------------------

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

// The whole console reachable through one account, and that account
// taking itself out of reach. Nothing in the browser can undo it: the
// console grants the role, and once nobody can reach the console there
// is nothing left to grant it from. Both ways back run through the host
// and both open the data volume the running server holds, so either one
// starts by stopping the server. One button press should not cost that.
async function testTheSoleAdministratorCannotArchiveItself(operator, identity, admin) {
  var answer = await operator.form("/admin/accounts",
    { action: "archive", id: admin.id, reason: "tidying up my own mailbox" });
  count("archiving the only administrator is refused rather than performed",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the refusal says what would be left, which is nobody",
    /no administrator/i.test(String(answer.body)), String(answer.body).slice(0, 600));
  count("and it names the way through rather than only the wall",
    /blamepost account/.test(String(answer.body)), String(answer.body).slice(0, 600));
  count("the account it named is still active",
    (await statusOf(identity, admin.address)) === "active",
    String(await statusOf(identity, admin.address)));
}

async function testTheSoleAdministratorCannotSuspendItself(operator, identity, admin) {
  var answer = await operator.form("/admin/accounts",
    { action: "suspend", id: admin.id, reason: "stepping away for a while" });
  count("suspending the only administrator is refused rather than performed",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and that account can still authenticate",
    (await statusOf(identity, admin.address)) === "active",
    String(await statusOf(identity, admin.address)));
}

// The same lockout by a different route. An account is only usable while
// the domain it belongs to is, so withdrawing that domain refuses the
// only administrator exactly as suspending them would.
async function testTheSoleAdministratorCannotDisableItsOwnDomain(operator, identity) {
  var answer = await operator.form("/admin/domains",
    { action: "disable", domain: DOMAIN, reason: "pausing mail for this name" });
  count("disabling the domain holding the only administrator is refused",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the refusal reaches the operator as an answer rather than a fault",
    answer.status < 500, answer.status);
  count("the domain is still active",
    (await domainStatusOf(identity, DOMAIN)) === "active",
    String(await domainStatusOf(identity, DOMAIN)));
}

// A refused attempt is a row. Somebody reaching for the action that
// removes every administrator is the event an incident review asks about
// afterwards, and it is invisible unless the refusal files one.
// The same withdrawal, spelled the way a zone file spells it. The store
// folds a name before it resolves a row, so `example.com.` and
// `example.com` are one domain to the verb that disables it. A guard
// comparing the name as typed against the names the store answers with
// would let this through and disable the domain it was written to keep,
// which is the whole lockout arriving by the spelling nobody guards.
async function testTheRootDotSpellingIsRefusedToo(operator, identity) {
  var answer = await operator.form("/admin/domains",
    { action: "disable", domain: DOMAIN + ".", reason: "pausing mail for this name" });
  count("withdrawing that domain written with the DNS root dot is refused as well",
    answer.status === 400, answer.status + " " + String(answer.location));
  count("and the domain the administrator's address belongs to is still active",
    (await domainStatusOf(identity, DOMAIN)) === "active",
    String(await domainStatusOf(identity, DOMAIN)));
}

async function testTheRefusalIsOnTheAuditChain(admin) {
  await b.audit.flush();
  var rows = _asRows(await b.audit.query({
    action: LAST_ADMIN_REFUSED, order: "desc", limit: 20,
  }));
  count("refusing to strand the console leaves a row", rows.length >= 1, String(rows.length));

  var row = rows.length > 0 ? rows[0] : null;
  count("and it is filed as a denial rather than a failure",
    row !== null && row.outcome === "denied", JSON.stringify(row && row.outcome));
  count("and it names the account that asked, in the column an auditor filters on",
    row !== null && row.actorUserId === admin.id, JSON.stringify(row && row.actorUserId));
  count("and it carries a reason, which is the column an incident review reads",
    row !== null && typeof row.reason === "string" && row.reason.length > 0,
    JSON.stringify(row && row.reason));
}

// The control that keeps the guard honest. A guard that refused every
// suspension would pass every assertion above and would have taken the
// verb away, so an account that administers nothing is suspended exactly
// as it was before.
async function testSuspendingAMailboxOwnerIsUntouched(operator, identity) {
  var plain = await identity.accounts.create({
    address: PLAIN_ACCOUNT, password: OTHER_PASSWORD,
  });
  var answer = await operator.form("/admin/accounts",
    { action: "suspend", id: plain.id, reason: "the owner asked for it" });
  count("suspending an account that administers nothing still goes through",
    answer.status === 302 && noticeOf(answer) === "suspended",
    answer.status + " " + String(answer.location));
  count("and the row records the suspension",
    (await statusOf(identity, PLAIN_ACCOUNT)) === "suspended",
    String(await statusOf(identity, PLAIN_ACCOUNT)));
}

// The same control for the domain verb, on a hosted name that holds no
// administrator. Refusing this one would make the guard a ban on the
// verb rather than a measurement of what the verb would leave.
async function testDisablingADomainWithNoAdministratorIsUntouched(operator, identity) {
  var off = await operator.form("/admin/domains", {
    action: "disable", domain: SECOND_DOMAIN, confirm: SECOND_DOMAIN,
    reason: "no mail expected here yet",
  });
  count("disabling a domain that holds no administrator still goes through",
    off.status === 302 && noticeOf(off) === "domain-saved",
    off.status + " " + String(off.location));
  count("and the domain is recorded as disabled",
    (await domainStatusOf(identity, SECOND_DOMAIN)) === "disabled",
    String(await domainStatusOf(identity, SECOND_DOMAIN)));

  var on = await operator.form("/admin/domains",
    { action: "enable", domain: SECOND_DOMAIN, reason: "putting it back" });
  count("and enabling it again is the reversible other half",
    on.status === 302 && (await domainStatusOf(identity, SECOND_DOMAIN)) === "active",
    on.status + " " + String(await domainStatusOf(identity, SECOND_DOMAIN)));
}

// Containment, which is the case the guard must not close. An
// administrator whose credential has been taken is archived from the
// console while another administrator remains, with no server stopped and
// no mail interrupted.
// The console creates an account and then grants the role on its row,
// which asks for the reason every grant records.
async function addAdministratorFromTheConsole(operator, identity, address, displayName) {
  var added = await operator.form("/admin/accounts", {
    action: "add", address: address, password: OTHER_PASSWORD, displayName: displayName,
  });
  count("the console creates " + address,
    added.status === 302 && noticeOf(added) === "account-added",
    added.status + " " + String(added.location));
  var created = await identity.accounts.get(address);
  var granted = await operator.form("/admin/accounts", {
    action: "grant-role", id: created.id, reason: "a second operator for the rota",
  });
  count("and grants it the role on its row",
    granted.status === 302 && noticeOf(granted) === "role-granted",
    granted.status + " " + String(granted.location));
  return granted;
}

// The one value on an account row that the person holding the account
// wrote. It is rendered into outbound headers, into every admin view and
// into the JMAP name of each address a client shows, so a control
// character in one is read by five modules and repaired by whichever of
// them remembered to. It is refused where it is written instead.
//
// U+009B is the single-byte control sequence introducer: a terminal
// reading it acts on the rest of the line. The guard the store runs
// beside this reports it as clean, because the C1 range is not what that
// guard is about, and the tab and the line feed beside it are ordinary
// in free text and are not ordinary in a name. Written from their code
// points, because a C1 octet does not survive being typed into a source
// file.
var NAMED_WITH_CONTROL = "rafe@" + DOMAIN;
var CONTROL_NAMES = [
  ["the single-byte escape introducer", String.fromCharCode(0x9b)],
  ["a tab",                             String.fromCharCode(0x09)],
  ["a line feed",                       String.fromCharCode(0x0a)],
  ["a null byte",                       String.fromCharCode(0x00)],
  ["the delete code point",             String.fromCharCode(0x7f)],
];

async function testADisplayNameCarryingAControlCharacterIsRefused(operator, identity) {
  for (var i = 0; i < CONTROL_NAMES.length; i += 1) {
    var refused = await operator.form("/admin/accounts", {
      action:      "add",
      address:     NAMED_WITH_CONTROL,
      password:    OTHER_PASSWORD,
      displayName: "Dana" + CONTROL_NAMES[i][1] + "Reyes",
    });
    count("an account named with " + CONTROL_NAMES[i][0] + " is refused rather than created",
      refused.status === 400, refused.status + " " + String(refused.location));
    count("and nothing was created under that address",
      (await identity.accounts.get(NAMED_WITH_CONTROL)) === null,
      JSON.stringify(await identity.accounts.get(NAMED_WITH_CONTROL)));
  }

  // The other half of the claim. A screen that refused an ordinary name
  // in somebody's own writing system would be worse than the problem it
  // closes, so the same form with the same address goes through.
  var made = await operator.form("/admin/accounts", {
    action: "add", address: NAMED_WITH_CONTROL, password: OTHER_PASSWORD,
    displayName: "Dana Reyes",
  });
  count("and the same account with an ordinary name is created",
    made.status === 302 && noticeOf(made) === "account-added",
    made.status + " " + String(made.location));
  var held = await identity.accounts.get(NAMED_WITH_CONTROL);
  count("holding the name as it was written",
    held !== null && held.displayName === "Dana Reyes",
    JSON.stringify(held && held.displayName));
}

async function testAnAdministratorIsStillContainedWhileAnotherRemains(operator, identity) {
  await addAdministratorFromTheConsole(operator, identity, SECOND_ADMIN, "second operator");

  var second = await identity.accounts.get(SECOND_ADMIN);
  count("and the account it created administers this server",
    second !== null && second.isAdmin === true, JSON.stringify(second && second.isAdmin));

  var archived = await operator.form("/admin/accounts", {
    action: "archive", id: second.id, confirm: SECOND_ADMIN,
    reason: "this credential has been taken",
  });
  count("an administrator can still be taken out of reach while another remains",
    archived.status === 302 && noticeOf(archived) === "archived",
    archived.status + " " + String(archived.location));
  count("and the archived account can no longer authenticate",
    (await statusOf(identity, SECOND_ADMIN)) === "archived",
    String(await statusOf(identity, SECOND_ADMIN)));
}

// ---- the three ways in that do not go through the form ----------------------

// Every destructive verb on this console is a POST behind `requireAdmin`
// and a token. Each of the three cases below is somebody arriving by a
// door the rendered page does not offer, and each is asked against real
// state rather than against a status code alone: the question is not
// only what the server answered but whether the account it was asked
// about moved.

// The console's own containment story, followed one step further than
// the case above follows it.
//
// An operator whose administrator credential has been taken archives
// that account, and the account can no longer authenticate. That is
// where the existing case stops, and it is the easy half: it asks
// whether a NEW sign-in is refused. Whoever took the credential already
// has a session, so what decides whether containment worked is whether
// the session they are already holding keeps administering the server.
//
// A console that reads the role off the session record would keep
// serving it until the session expires, and the operator would have
// archived an account while the intruder carried on.
async function testAnArchivedAdministratorsOpenSessionStopsAdministering(
  operator, identity, origin, caPem
) {
  await addAdministratorFromTheConsole(operator, identity, TAKEN_ADMIN,
    "an operator whose credential was taken");

  // The intruder's session, opened while the credential still works.
  var intruder = browser.browserAt(origin, { ca: caPem });
  var landed = await intruder.signIn(TAKEN_ADMIN, OTHER_PASSWORD);
  count("the taken credential opens a session while the account is still active",
    landed.status === 302, landed.status + " " + String(landed.location));
  var console1 = await intruder.get("/admin/accounts");
  count("and that session administers this server",
    console1.status === 200, String(console1.status));

  // The operator responds the only way this server offers.
  var taken = await identity.accounts.get(TAKEN_ADMIN);
  var contained = await operator.form("/admin/accounts", {
    action: "archive", id: taken.id, confirm: TAKEN_ADMIN,
    reason: "this credential has been taken",
  });
  count("the operator archives it", contained.status === 302 &&
    (await statusOf(identity, TAKEN_ADMIN)) === "archived",
    contained.status + " " + String(await statusOf(identity, TAKEN_ADMIN)));

  // The half that decides whether the response worked.
  var console2 = await intruder.get("/admin/accounts");
  count("the session that was already open stops administering the server, because " +
    "containment that waits for a session to expire is not containment",
    console2.status !== 200, String(console2.status));

  var victim = await identity.accounts.get(VICTIM);
  var struck = await intruder.form("/admin/accounts", {
    action: "suspend", id: victim.id, reason: "still here",
  });
  count("and a destructive verb driven from it does not land",
    (await statusOf(identity, VICTIM)) === "active",
    struck.status + " " + String(await statusOf(identity, VICTIM)));
}

// The same verbs reached with the method the form does not use.
//
// The router matches a method with a strict comparison, so a GET to a
// POST-only path falls through to the not-found handler. That is a
// property of the framework rather than of this console, which is
// exactly why it is worth a vector here: nothing in this repository
// would notice if a later registration bound a path for every method,
// and the payloads below are the ones that would land if one did.
async function testADestructiveVerbIsNotReachableByGet(operator, identity) {
  var victim = await identity.accounts.get(VICTIM);
  var attempts = [
    ["/admin/accounts", "action=suspend&id=" + encodeURIComponent(victim.id) +
      "&reason=by+the+wrong+method"],
    ["/admin/accounts", "action=archive&id=" + encodeURIComponent(victim.id) +
      "&reason=by+the+wrong+method"],
    ["/admin/domains",  "action=disable&domain=" + encodeURIComponent(SECOND_DOMAIN) +
      "&reason=by+the+wrong+method"],
    ["/admin/queue",    "action=cancel&id=" + encodeURIComponent(SPARED_ID) +
      "&reason=by+the+wrong+method"],
    ["/admin/dkim",     "action=retire&domain=" + encodeURIComponent(DOMAIN) +
      "&selector=any"],
  ];

  // Each of these paths also answers a GET, because it renders the
  // listing the form is on. So the verdict is not the status on its own:
  // it is that the answer is the PAGE rather than the answer an action
  // gives. A verb that ran redirects to the listing with a notice naming
  // what it did, which is the shape asserted against everywhere else in
  // this file, so its absence is what says the query string was read as
  // a query string.
  for (var i = 0; i < attempts.length; i += 1) {
    var answered = await operator.get(attempts[i][0] + "?" + attempts[i][1]);
    count("a destructive verb named in the query string of a GET to " + attempts[i][0] +
      " is answered as the listing page rather than as an action",
      answered.status === 200 && noticeOf(answered) === "",
      String(answered.status) + " " + String(answered.location));
  }

  count("and nothing it named moved: the account it would have suspended is still active",
    (await statusOf(identity, VICTIM)) === "active",
    String(await statusOf(identity, VICTIM)));
  count("the domain it would have disabled is still active",
    (await domainStatusOf(identity, SECOND_DOMAIN)) === "active",
    String(await domainStatusOf(identity, SECOND_DOMAIN)));
}

// A token minted somewhere else.
//
// The token is a double-submit cookie, so the pairing that has to hold
// is between the token in the request and the cookie in the jar that
// sent it. A token lifted from another client's page is the shape a
// forged request carries, and no destructive console verb is asked this
// question anywhere else in this suite.
async function testATokenMintedInAnotherSessionIsRefused(operator, identity, origin, caPem) {
  var elsewhere = browser.browserAt(origin, { ca: caPem });
  var minted = await elsewhere.readCsrf("/sign-in");
  count("a second client is issued a token of its own",
    typeof minted.token === "string" && minted.token.length > 0 &&
    minted.token !== operator.csrf(), minted.token.slice(0, 12) + "...");

  var victim = await identity.accounts.get(VICTIM);
  var body = "action=suspend&id=" + encodeURIComponent(victim.id) +
    "&reason=with+somebody+else%27s+token" +
    "&_csrf=" + encodeURIComponent(minted.token);
  var forged = await operator.post("/admin/accounts",
    "application/x-www-form-urlencoded", body, { "X-CSRF-Token": minted.token });

  count("a destructive console verb carrying a token minted in another session is refused",
    forged.status >= 400 && forged.status < 500, String(forged.status));
  count("and the account it named is untouched",
    (await statusOf(identity, VICTIM)) === "active",
    String(await statusOf(identity, VICTIM)));

  // The positive control. Without it every assertion above would still
  // pass on a console that refuses this verb for some other reason.
  var honest = await operator.form("/admin/accounts", {
    action: "suspend", id: victim.id, reason: "the same verb with this session's own token",
  });
  count("the same verb with this session's own token still lands, so the refusal above " +
    "was about the token rather than about the verb",
    honest.status === 302 && (await statusOf(identity, VICTIM)) === "suspended",
    honest.status + " " + String(await statusOf(identity, VICTIM)));
  await operator.form("/admin/accounts", { action: "reinstate", id: victim.id });
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-admin-verbs");
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
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.add({ domain: ABSOLUTE_DOMAIN });
    await identity.domains.add({ domain: SWEEP_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "admin verb run" });
    var operatorAccount = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });
    count("the run drives an account that administers this server",
      operatorAccount.isAdmin === true, operatorAccount.isAdmin);

    // The mailbox owner the three cases below aim a destructive verb at.
    // It administers nothing, so nothing about it is protected by the
    // last-administrator guard and every refusal it meets is the one
    // being measured.
    await identity.accounts.create({ address: VICTIM, password: OTHER_PASSWORD });

    plant(dataDir, DOOMED_ID, DOOMED_SENDER, DOOMED_RECIPIENT);
    plant(dataDir, SPARED_ID, DOOMED_SENDER, SPARED_RECIPIENT);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    // The signing pair the differential above is refused against.
    await server.mail.dkim.generate({ domain: DOMAIN });

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    var landed = await operator.signIn(operatorAccount.address, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    await testTheQueuePageListsWhatIsWaiting(operator);
    await testCancellingErasesTheMessage(operator, dataDir);
    await testCancellingIsOnTheAuditChain(operatorAccount);
    await testAnIdTheQueueDoesNotHoldIsNotReportedAsCancelled(operator);
    await testAnIdTheSpoolCouldNotHaveMintedIsRefusedAsAnAnswer(operator);

    await testTheOverviewCountsAgreeWithThePagesTheyLinkTo(operator, identity);
    await testASelectorRefusalWrittenForAPersonReachesTheOperator(operator);
    await testTheAbsoluteFormReachesTheDomainRatherThanTheFramework(operator, server);
    await testAFrameworkCodeThisServerNeverRaisesStaysOffThePage(server, operator);
    await testASweepThatStrandsAKeyTellsTheOperator(operator, server, identity, dataDir);

    await testTheSoleAdministratorCannotArchiveItself(operator, identity, operatorAccount);
    await testTheSoleAdministratorCannotSuspendItself(operator, identity, operatorAccount);
    await testTheSoleAdministratorCannotDisableItsOwnDomain(operator, identity);
    await testTheRootDotSpellingIsRefusedToo(operator, identity);
    await testTheRefusalIsOnTheAuditChain(operatorAccount);
    await testSuspendingAMailboxOwnerIsUntouched(operator, identity);
    await testDisablingADomainWithNoAdministratorIsUntouched(operator, identity);
    await testADisplayNameCarryingAControlCharacterIsRefused(operator, identity);
    await testAnAdministratorIsStillContainedWhileAnotherRemains(operator, identity);

    await testADestructiveVerbIsNotReachableByGet(operator, identity);
    await testATokenMintedInAnotherSessionIsRefused(operator, identity, origin, material.caPem);
    await testAnArchivedAdministratorsOpenSessionStopsAdministering(
      operator, identity, origin, material.caPem);

    // Last, because it replaces the key directory with a plain file and
    // every verb after it would be answering a broken volume rather than
    // the question being asked.
    await testAFaultTheSignerNeverWroteForAnybodyStaysOffThePage(operator, dataDir);

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

module.exports = { name: "web-admin-verbs", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
