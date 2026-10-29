// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether an administrative audit row says who did it.
 *
 * The chain records what happened. SECURITY.md tells an operator to
 * verify it and to read it during an incident, and the first question an
 * incident asks of a suspension, an erasure or a newly hosted domain is
 * who performed it. A row that answers the what and not the who is a log
 * rather than an audit trail, and no amount of hash linking closes that
 * gap: the sequence is provably unaltered and still anonymous.
 *
 * Two surfaces reach the identity layer and each carries a different
 * kind of principal, so each is driven end to end here rather than
 * asserted against an internal helper:
 *
 *   - The command line, spawned as the real binary. A shell user is not
 *     an account, so what the row records is the operating-system user
 *     and host the process ran as, marked so it can never be read as an
 *     account id. The mark matters because one column carries both
 *     kinds and an auditor filtering on it has to know which they hold.
 *   - The browser console, over TLS with a real session. The principal
 *     is the account that signed in, and the row carries the peer
 *     address and the agent string beside it.
 *
 * Two operators sign in separately and each performs one action, which
 * is the vector a single-operator run cannot see: an attribution that is
 * held per process rather than per request labels the second action with
 * the first operator's name, and every check on one operator alone
 * passes while it does.
 *
 * The rows are read back through the shipped paths rather than out of
 * the table: `blamepost audit read` for the command line, and the
 * console's own audit page for the browser. A column populated in the
 * database and dropped on the way to the operator is the same gap one
 * step further along.
 *
 * Reading them back is also where a row can do harm. The reason column
 * holds words somebody typed, and a terminal acts on what a browser
 * renders inertly: the single-byte escape introducer repaints the line
 * above the one it is on, and a right-to-left override prints the rest
 * of the row backwards. The surface those land on is the one an operator
 * opens during an incident, so the command-line half suspends a second
 * mailbox for a reason carrying three such codepoints and reads the
 * trail back.
 *
 * Both renderings are read. This binary screens every value it hands a
 * stream, the machine-readable answer included, so a monitor consuming
 * that form is as much a reader as the operator at the terminal. It also
 * means there is no reading from here of what the volume holds, and this
 * file does not claim one: what it reads is what reaches a stream.
 *
 * Run standalone: node test/layer-1-state/audit-actor-attribution.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var cliHelper = require("../helpers/cli");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var FIRST_PASSWORD   = "an operator passphrase 5512";
var SECOND_PASSWORD  = "another operator passphrase 8836";

// Who the operator told the acknowledgement verb had published the DNS.
// It is a claim about a person, recorded on the domain row, and it is a
// different fact from who ran the command. Both belong on the event and
// neither stands in for the other.
var ACKNOWLEDGED_BY = "the zone owner on call";

// The mark a command-line actor carries. One column holds both kinds of
// principal, so the shell operator has to be distinguishable from an
// account id at a glance and by a filter.
var COMMAND_LINE_MARK = "cli:";

// The three codepoints a reason is driven through, each built from its
// code point so this file carries none of them in its own bytes. The
// first opens an escape sequence in one byte and so colors or moves
// whatever prints it; the second reorders everything after it; the third
// renders as nothing at all. Only the first is a control character, so a
// screen that stops at the control range passes the other two.
var CSI  = String.fromCharCode(0x9b);
var RLO  = String.fromCharCode(0x202e);
var ZWSP = String.fromCharCode(0x200b);

// What the second account is suspended for, with the three codepoints
// laid through it. The words on either side are checked as well: a
// screen that answered by dropping the value would take the reason an
// operator is reading the row for.
var LEGIBLE_REASON = "mailbox shared with a third party";
var HOSTILE_REASON = "mailbox shared" + CSI + " with a" + RLO + " third" + ZWSP + " party";

var SHUTDOWN_TIMEOUT_MS = 5000;

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// The operating-system account this run is executing as. It is read
// defensively because a container with no passwd entry for its uid makes
// the lookup throw, and a run on such a host still checks everything
// that does not need the name.
function osUserName() {
  try { return String(nodeOs.userInfo().username || ""); }
  catch (_e) { return ""; }
}

function rowFor(cli, action) {
  var read = cli(["audit", "read", "--action", action, "--limit", "20", "--json"]);
  var rows = parseJson(read.stdout);
  return {
    ok:     read.status === 0,
    rows:   Array.isArray(rows) ? rows : [],
    stdout: read.stdout,
    both:   read.both,
  };
}

// ---- the command line -------------------------------------------------------

function theOperatorWhoRanTheCommandIsOnTheRow(cli) {
  var actions = [
    "domain.added",
    "account.created",
    "account.suspended",
    "domain.dns_acknowledged",
  ];
  var seen = [];
  for (var i = 0; i < actions.length; i += 1) {
    var found = rowFor(cli, actions[i]);
    count("the trail can be read for " + actions[i], found.ok && found.rows.length >= 1,
      found.both.slice(0, 200));
    if (found.rows.length === 0) continue;
    var row = found.rows[0];
    count(actions[i] + " records who performed it",
      typeof row.actorUserId === "string" && row.actorUserId.length > 0,
      actions[i] + " actorUserId=" + JSON.stringify(row.actorUserId));
    if (typeof row.actorUserId === "string" && row.actorUserId.length > 0) {
      seen.push(row.actorUserId);
    }
  }

  count("every command in the run is attributed to the one operator that ran it",
    seen.length === actions.length &&
    seen.every(function (name) { return name === seen[0]; }),
    JSON.stringify(seen));

  if (seen.length === 0) return "";

  count("the command line's actor is marked as one, so a filter on this column can " +
    "tell a shell operator from an account id",
    seen[0].indexOf(COMMAND_LINE_MARK) === 0, seen[0]);

  var user = osUserName();
  if (user.length === 0) {
    helpers.skip("this host has no readable operating-system user name, so the actor " +
      "cannot be checked against the account that ran the command");
  } else {
    count("and it names the operating-system account the command ran as",
      seen[0].indexOf(user) !== -1, seen[0] + " against " + user);
  }
  return seen[0];
}

// The acknowledgement carries two facts about two people and they are
// not interchangeable. `--by` is the operator's claim about who
// published the zone, and it lives on the domain row. The actor is who
// ran the command. A change that folded one into the other would leave
// the trail unable to answer either question.
function theAcknowledgementKeepsBothFactsApart(cli) {
  var found = rowFor(cli, "domain.dns_acknowledged");
  count("the acknowledgement wrote a row", found.rows.length >= 1, found.both.slice(0, 200));
  if (found.rows.length === 0) return;
  var row = found.rows[0];
  var meta = typeof row.metadata === "string" ? parseJson(row.metadata) : row.metadata;
  count("the person the operator named as having published the DNS is still recorded",
    meta !== null && meta.acknowledgedBy === ACKNOWLEDGED_BY,
    JSON.stringify(row.metadata).slice(0, 200));
  count("and the operator who ran the verb is recorded separately from them",
    typeof row.actorUserId === "string" && row.actorUserId.length > 0 &&
    row.actorUserId !== ACKNOWLEDGED_BY,
    "actorUserId=" + JSON.stringify(row.actorUserId));
}

// The column is only worth populating if the operator reading the trail
// is shown it. The text rendering is what a terminal gets.
function theOperatorReadingTheTrailIsShownWhoActed(cli, expected) {
  var text = cli(["audit", "read", "--action", "account.suspended", "--limit", "5"]);
  count("reading the trail as text succeeds", text.status === 0, text.both.slice(0, 200));
  count("and the line for the suspension names who performed it",
    expected.length > 0 && text.stdout.indexOf("by " + expected) !== -1,
    text.stdout.slice(0, 400));
}

// A reason is words somebody typed, and the trail is read in a terminal.
//
// The volume keeps the value as it arrived, which is what makes the row
// a record of what was actually written, so the screen has to run on the
// way out. If it does not, a reason carrying the escape introducer
// repaints the line above it, and one carrying an override prints the
// rest of the row backwards, on the surface an operator opens during an
// incident.
//
// What the screen may not do is answer by dropping the value: the words
// on either side of the three codepoints are the reason the row is being
// read, so both halves are checked here.
// Both renderings are read, and the second one is the reason this is not
// a check on the table. Every value this binary hands a stream goes
// through the screen, the machine-readable answer included, so there is
// no reading of the row from here that shows what the volume holds. What
// can be read from here is what reaches a stream, which is the surface
// the harm is on, and a monitor consuming the machine-readable form is
// as much a reader as the operator at the terminal.
function theTrailReadsBackWithoutRepaintingTheTerminal(cli) {
  var suspensions = rowFor(cli, "account.suspended");
  count("the suspension reached the trail, so the readings below are made over a row " +
    "that is there",
    suspensions.ok && suspensions.rows.length >= 2,
    suspensions.rows.length + " row(s) " + suspensions.both.slice(0, 200));

  var text = cli(["audit", "read", "--action", "account.suspended", "--limit", "10"]);
  count("reading the trail as text succeeds over a row whose reason carries them",
    text.status === 0, text.both.slice(0, 240));

  var renderings = [
    { name: "the table an operator reads", out: text.stdout },
    { name: "the machine-readable answer a monitor reads", out: suspensions.stdout },
  ];
  for (var i = 0; i < renderings.length; i += 1) {
    var seen = renderings[i];
    count("nothing a terminal would act on rather than print reaches " + seen.name,
      seen.out.indexOf(CSI) === -1, JSON.stringify(seen.out.slice(0, 400)));
    count("nor a codepoint that reorders everything after it, in " + seen.name,
      seen.out.indexOf(RLO) === -1, JSON.stringify(seen.out.slice(0, 400)));
    count("nor one that renders as nothing, in " + seen.name,
      seen.out.indexOf(ZWSP) === -1, JSON.stringify(seen.out.slice(0, 400)));
    count("and the words the operator opened the row for survive in " + seen.name +
      ", because a screen that answered by dropping the value would take the reason " +
      "with them",
      seen.out.indexOf(LEGIBLE_REASON) !== -1, seen.out.slice(0, 600));
  }
}

// Reading the trail is itself recorded, and the row it writes is subject
// to the same rule as every other one.
function readingTheTrailRecordsWhoRead(cli) {
  var found = rowFor(cli, "audit.read");
  count("reading the trail leaves a row saying so", found.rows.length >= 1,
    found.both.slice(0, 200));
  if (found.rows.length === 0) return;
  count("and that row names the operator who read it",
    typeof found.rows[0].actorUserId === "string" && found.rows[0].actorUserId.length > 0,
    "actorUserId=" + JSON.stringify(found.rows[0].actorUserId));
}

// ---- the browser console ----------------------------------------------------

async function rowsFor(action) {
  await b.audit.flush();
  return helpers.waitUntil(async function () {
    var rows = await b.audit.query({ action: action, limit: 20, order: "desc" });
    return Array.isArray(rows) && rows.length > 0 ? rows : false;
  }, {
    timeoutMs: 5000,
    label:     "audit-actor-attribution: a row for " + action + " reaches the chain",
  });
}

async function theSigningInOperatorIsOnTheRow(operator, alice) {
  var suspended = await operator.form("/admin/accounts", {
    action: "suspend", id: alice.id, reason: "credential reuse reported",
  });
  count("the console suspends the account", String(suspended.location || "")
    .indexOf("notice=suspended") !== -1,
    suspended.status + " " + String(suspended.location));

  var rows = await rowsFor("account.suspended");
  var row = rows[0];
  count("the suspension records the operator account that performed it",
    row.actorUserId === operator.accountId,
    "actorUserId=" + JSON.stringify(row.actorUserId) + " expected " + operator.accountId);
  count("and the peer address the request arrived from",
    typeof row.actorIp === "string" && row.actorIp.indexOf(LOOPBACK) !== -1,
    "actorIp=" + JSON.stringify(row.actorIp));
  count("and the agent string the browser sent",
    typeof row.actorUserAgent === "string" &&
    row.actorUserAgent.indexOf("blamepost test reader") !== -1,
    "actorUserAgent=" + JSON.stringify(row.actorUserAgent));
}

// The vector a run with one operator cannot see. An attribution held for
// the process rather than for the request labels this action with the
// first operator, and every check above still passes while it does.
async function theSecondOperatorIsNotTheFirst(second, first, alice) {
  var reinstated = await second.form("/admin/accounts", {
    action: "reinstate", id: alice.id,
  });
  count("the second operator reinstates the account", String(reinstated.location || "")
    .indexOf("notice=reinstated") !== -1,
    reinstated.status + " " + String(reinstated.location));

  var rows = await rowsFor("account.reinstated");
  var row = rows[0];
  count("the reinstatement is attributed to the operator who performed it",
    row.actorUserId === second.accountId,
    "actorUserId=" + JSON.stringify(row.actorUserId) + " expected " + second.accountId);
  count("and not to the operator who was signed in for the action before it",
    row.actorUserId !== first.accountId,
    "actorUserId=" + JSON.stringify(row.actorUserId) + " first=" + first.accountId);
}

// The console's own audit page is what an operator reads during an
// incident, and it has a column for this. A value in the table that the
// page drops answers nobody.
async function theConsolePageShowsWhoActed(operator) {
  var page = await operator.get("/admin/audit?action=account.suspended");
  count("the console serves the audit page", page.status === 200, page.status);
  count("and the row it renders names the operator who suspended the account",
    page.body.indexOf(operator.accountId) !== -1,
    page.body.slice(0, 200));
}

async function readingTheConsolePageRecordsWhoRead(operator) {
  var rows = await rowsFor("audit.read");
  var mine = rows.filter(function (row) { return row.actorUserId === operator.accountId; });
  count("reading the console's audit page records the operator who read it",
    mine.length >= 1,
    "actors seen: " + JSON.stringify(rows.slice(0, 5).map(function (r) {
      return r.actorUserId;
    })));
}

// ---- fixtures ----------------------------------------------------------------

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = {
      enabled: names[i] === "imap",
      port:    await wire.reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

function baseEnv(dataDir, material) {
  var env = {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
  };
  if (material !== null) {
    env.BLAMEPOST_TLS_CERT = material.certFile;
    env.BLAMEPOST_TLS_KEY  = material.keyFile;
  }
  return env;
}

async function signedInOperator(origin, caPem, account, password) {
  var reader = browser.browserAt(origin, { ca: caPem });
  var landed = await reader.signIn(account.address, password);
  count("the operator " + account.address + " signs in", landed.status === 302,
    landed.status + " " + String(landed.location));
  reader.accountId = account.id;
  return reader;
}

// ---- the two halves ----------------------------------------------------------

function theCommandLineHalf(root) {
  var dataDir = nodePath.join(root, "cli-data");
  var workDir = nodePath.join(root, "cli-work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var cli = cliHelper.create({
    dataDir:         dataDir,
    workDir:         workDir,
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  });

  var hosted = cli(["domain", "add", DOMAIN]);
  count("the operator hosts a domain from the command line", hosted.status === 0,
    "exit " + hosted.status + " " + hosted.both.slice(0, 240));

  var made = cli(["account", "add", "alice@" + DOMAIN, "--password", ALICE_PASSWORD]);
  count("and creates an account", made.status === 0,
    "exit " + made.status + " " + made.both.slice(0, 240));

  var stopped = cli(["account", "suspend", "alice@" + DOMAIN,
    "--reason", "credential reuse reported"]);
  count("and suspends it", stopped.status === 0,
    "exit " + stopped.status + " " + stopped.both.slice(0, 240));

  var acked = cli(["domain", "acknowledge", DOMAIN, "--by", ACKNOWLEDGED_BY]);
  count("and records that the zone is published", acked.status === 0,
    "exit " + acked.status + " " + acked.both.slice(0, 240));

  // A second mailbox, suspended for a reason with the three codepoints
  // laid through it. It is a second account rather than a second
  // suspension of the first, because a suspended account cannot be
  // suspended again and the row has to be one the trail actually holds.
  var second = cli(["account", "add", "bob@" + DOMAIN, "--password", ALICE_PASSWORD]);
  count("and creates a second account", second.status === 0,
    "exit " + second.status + " " + second.both.slice(0, 240));

  var stoppedHostile = cli(["account", "suspend", "bob@" + DOMAIN,
    "--reason", HOSTILE_REASON]);
  count("and suspends it for a reason carrying what a terminal would act on",
    stoppedHostile.status === 0,
    "exit " + stoppedHostile.status + " " + stoppedHostile.both.slice(0, 240));

  var actor = theOperatorWhoRanTheCommandIsOnTheRow(cli);
  theAcknowledgementKeepsBothFactsApart(cli);
  theOperatorReadingTheTrailIsShownWhoActed(cli, actor);
  theTrailReadsBackWithoutRepaintingTheTerminal(cli);
  readingTheTrailRecordsWhoRead(cli);
}

async function theBrowserHalf(root) {
  var dataDir = nodePath.join(root, "web-data");
  nodeFs.mkdirSync(dataDir, { recursive: true });

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, acknowledgedBy: ACKNOWLEDGED_BY });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var firstAccount = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: FIRST_PASSWORD, isAdmin: true });
    var secondAccount = await identity.accounts.create({
      address: "erin@" + DOMAIN, password: SECOND_PASSWORD, isAdmin: true });
    count("the run holds two operator accounts that are not the same account",
      firstAccount.id !== secondAccount.id && firstAccount.isAdmin === true &&
      secondAccount.isAdmin === true,
      JSON.stringify([firstAccount.id, secondAccount.id]));

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

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var first  = await signedInOperator(origin, material.caPem, firstAccount, FIRST_PASSWORD);
    var second = await signedInOperator(origin, material.caPem, secondAccount, SECOND_PASSWORD);

    await theSigningInOperatorIsOnTheRow(first, alice);
    await theSecondOperatorIsNotTheFirst(second, first, alice);
    await theConsolePageShowsWhoActed(first);
    await readingTheConsolePageRecordsWhoRead(first);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (server !== null && running) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
    }
    if (identity !== null) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
    }
  }
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("audit-actor");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    // The command line runs first and against a volume of its own. Each
    // half opens a data directory, one process holds a directory at a
    // time, and the spawned binary and this process are two processes.
    theCommandLineHalf(root);
    await theBrowserHalf(root);
    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "audit-actor-attribution", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
