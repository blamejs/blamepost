// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the mailbox page and the administration console tell a reader
 * about how full a mailbox is, measured against what the server does when
 * the next message arrives.
 *
 * A storage cap is enforced on the append path, which receives the
 * account. The reading the browser surface takes is keyed by a wire
 * folder name, and a wire folder name belongs to every account that has
 * one, so it cannot name a mailbox to measure. Those are two different
 * questions and the page was asking the second one: an account holding
 * mail up against its cap read `0 stored, 0 B` with no cap named, while a
 * message arriving on the same account was refused.
 *
 * A page that reports an empty mailbox on a full one is worse than a page
 * that reports nothing, because the reader acts on it: they keep mail
 * they would have filed or deleted, and the first they hear of the cap is
 * a client that will not accept a message.
 *
 * ## What this file drives
 *
 *   - The mailbox page of an account holding mail under a cap: the count,
 *     the bytes and the cap it names, compared with the counters the
 *     store actually holds.
 *   - The meter beside them, which is drawn from the same reading.
 *   - The administration accounts page, where the operator reads the same
 *     account's usage beside the cap they set.
 *   - An account with no cap, whose page states what it holds and names
 *     no limit.
 *   - A second account on the same server holding different mail, so a
 *     reading that summed the whole store rather than one mailbox is
 *     visible.
 *   - The append refusal on the capped account, whose sentence carries
 *     the used and cap figures the page is showing. Two surfaces reading
 *     one mailbox have to agree, and this is the pair that disagreed.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/web-mailbox-quota-reading.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var CAPPED_PASSWORD  = "quiet lantern bicycle 4291";
var OPEN_PASSWORD    = "another quiet lantern 7715";
var ADMIN_PASSWORD   = "a third quiet lantern 8830";

var CAPPED = "alice@" + DOMAIN;
var OPEN   = "bob@" + DOMAIN;
var ADMIN  = "root@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The cap the capped account is created under. Large enough that the
// fixture messages fit inside it, small enough that they are a visible
// fraction of it, so a meter drawn from the reading is not zero and a
// reading that reported the cap as the usage would be obvious.
var CAP_BYTES = b.constants.BYTES.kib(64);

// What the mailbox page prints above the message list.
var PANE_SUB_RE = /<p class="pane-sub">([^<]*)<\/p>/;
// The meter's width class, which is the same reading rendered as a bar.
var METER_FILL_RE = /<div class="meter-fill w(\d+)"><\/div>/;
// One row of the administration accounts table, and the cell carrying the
// cap and the usage beside it.
var ADMIN_ROW_RE = /<tr>\s*<th scope="row"><code>([^<]*)<\/code>[\s\S]*?<\/tr>/g;

function describe(answer) {
  return answer.status + " " + String(answer.location || "") + " " +
    String(answer.body || "").replace(/\s+/g, " ").slice(0, 240);
}

function paneSub(html) {
  var found = PANE_SUB_RE.exec(String(html));
  return found === null ? null : found[1].trim();
}

function meterBucket(html) {
  var found = METER_FILL_RE.exec(String(html));
  return found === null ? null : Number(found[1]);
}

// The administration row for one address, as one run of markup. Read by
// address rather than by position, because the table is ordered by
// address and a fixture that assumed a position would move the moment
// another account was added to this file.
function adminRow(html, address) {
  ADMIN_ROW_RE.lastIndex = 0;
  var hit = ADMIN_ROW_RE.exec(String(html));
  while (hit !== null) {
    if (hit[1] === address) return hit[0].replace(/\s+/g, " ");
    hit = ADMIN_ROW_RE.exec(String(html));
  }
  return null;
}

// ---------------------------------------------------------------------------
// The fixture messages
// ---------------------------------------------------------------------------

function message(id, to, subject, bodyBytes) {
  var filler = new Array(bodyBytes).join("m");
  return Buffer.from(
    "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" + filler + "\r\n", "utf8");
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

async function testTheMailboxPageNamesWhatTheMailboxHolds(reader, held, inboxOnly) {
  var page = await reader.get("/mail?folder=INBOX");
  count("the mailbox page of an account holding mail under a cap renders",
    page.status === 200, describe(page));

  var line = paneSub(page.body);
  count("the page carries a line above the message list saying what the mailbox holds",
    line !== null, describe(page));
  if (line === null) return;

  count("the line names the number of messages the mailbox actually holds, rather than zero",
    line.indexOf(String(held.usedCount) + " stored") === 0,
    JSON.stringify(line) + " for " + JSON.stringify(held));
  count("the line names the bytes the mailbox actually holds, rather than zero",
    line.indexOf(" " + held.usedLabel) !== -1 && line.indexOf("0 stored, 0 B") === -1,
    JSON.stringify(line) + " expecting " + JSON.stringify(held.usedLabel));
  count("and it names the cap the operator set on the account",
    line.indexOf(" of " + held.capLabel) !== -1,
    JSON.stringify(line) + " expecting a cap of " + JSON.stringify(held.capLabel));
  // The cap is set on the ACCOUNT and the append path measures every
  // folder against it, so a figure shown beside that cap has to be the
  // same total. A reading taken per folder is smaller than the thing it
  // is being compared to, and the gap grows with everything filed
  // outside the folder being looked at.
  count("the figure beside the cap is what the cap is measured against, rather than one folder",
    line.indexOf(" " + inboxOnly.usedLabel + " of ") === -1 ||
      inboxOnly.usedLabel === held.usedLabel,
    JSON.stringify(line) + " one folder holds " + JSON.stringify(inboxOnly));

  var bucket = meterBucket(page.body);
  count("the meter beside the line is drawn from the same reading rather than from an empty one",
    bucket !== null && bucket > 0, String(bucket));
}

async function testASecondAccountReadsItsOwnMailbox(reader, ownHeld, othersUsedBytes) {
  var page = await reader.get("/mail?folder=INBOX");
  count("the mailbox page of an account with no cap renders",
    page.status === 200, describe(page));

  var line = paneSub(page.body);
  count("it names what that account holds", line !== null &&
    line.indexOf(String(ownHeld.usedCount) + " stored") === 0,
    JSON.stringify(line) + " for " + JSON.stringify(ownHeld));
  count("and names no cap, because the operator set none on it",
    line !== null && line.indexOf(" of ") === -1, JSON.stringify(line));
  count("the reading is this account's mailbox rather than every mailbox on the server",
    ownHeld.usedBytes !== othersUsedBytes && ownHeld.usedBytes > 0,
    JSON.stringify({ own: ownHeld.usedBytes, other: othersUsedBytes }));
}

async function testTheOperatorReadsTheSameUsage(operator, held) {
  var page = await operator.get("/admin/accounts");
  count("the administration accounts page renders for an operator",
    page.status === 200, describe(page));

  var row = adminRow(page.body, CAPPED);
  count("the page carries a row for the capped account", row !== null,
    String(page.body).replace(/\s+/g, " ").slice(0, 300));
  if (row === null) return;

  count("the row names the cap the operator set", row.indexOf(held.capLabel) !== -1, row);
  count("the row names what the mailbox is holding against that cap, rather than nothing",
    row.indexOf(held.usedLabel) !== -1, row);
  count("and draws the meter, which an account measured as empty leaves out altogether",
    /<span class="meter-fill w(\d+)"><\/span>/.test(row) &&
      Number(/<span class="meter-fill w(\d+)"><\/span>/.exec(row)[1]) > 0, row);
}

// The other half of the pair. The page reports a mailbox, and the append
// path decides whether the next message fits; both read one cap and one
// set of counters, so the figures in the refusal are the figures on the
// page. A page built on a different reading would disagree here and
// nothing else would say so.
function testTheRefusalAgreesWithThePage(identity, accountId, held) {
  var refusal = null;
  try {
    identity.mailbox.appendMessage("INBOX",
      message("overflow", CAPPED, "one too many", CAP_BYTES),
      { actor: { id: accountId } });
  } catch (e) {
    refusal = e;
  }
  count("a message that does not fit under the cap is refused on the append path",
    refusal !== null && refusal.overquota === true,
    refusal === null ? "accepted" : String(refusal.code));
  if (refusal === null) return;

  count("the refusal names the same cap the page names",
    refusal.limit === held.capBytes,
    JSON.stringify({ refusal: refusal.limit, page: held.capBytes }));
  count("and the same used figure the page is built on",
    String(refusal.message).indexOf("holds " + held.usedBytes + " bytes") !== -1,
    String(refusal.message) + " expecting " + held.usedBytes);
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

function wiringFor(cfg, identity) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({
      store: identity.messageStore, dispatch: { mode: "local" },
    }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return []; },
    address:   LOOPBACK,
    httpPort:  0,
  };
}

// What one account's mailbox actually holds, read off the store's own
// per-folder counters rather than off the page the run is measuring. An
// expectation derived from the surface under test proves nothing.
//
// `wireName` narrows the walk to one folder, which is what the second
// expectation in this file needs: the figure a per-folder reading would
// have produced, so the assertion can say which of the two the page is
// showing rather than only that it is not zero.
function heldBy(identity, accountId, capBytes, wireName) {
  var where = { account: accountId };
  if (wireName !== undefined) where.wireName = wireName;
  var rows = b.db.from(mailbox.FOLDERS).where(where).all();
  var usedBytes = 0;
  var usedCount = 0;
  for (var i = 0; i < rows.length; i += 1) {
    var counter = identity.messageStore.quota(rows[i].folder);
    usedBytes += (counter && counter.usedBytes) || 0;
    usedCount += (counter && counter.usedCount) || 0;
  }
  return {
    usedBytes: usedBytes,
    usedCount: usedCount,
    usedLabel: byteLabel(usedBytes),
    capBytes:  capBytes,
    capLabel:  capBytes > 0 ? byteLabel(capBytes) : "",
  };
}

// The same rendering the browser surface uses for a byte figure. Written
// out here rather than imported, because the surface's own helper is
// private to it and a test that reached for it would assert that one
// function agrees with itself.
function byteLabel(bytes) {
  var n = typeof bytes === "number" && isFinite(bytes) ? bytes : 0;
  if (n < b.constants.BYTES.kib(1)) return n + " B";
  if (n < b.constants.BYTES.mib(1)) return (n / b.constants.BYTES.kib(1)).toFixed(0) + " KB";
  if (n < b.constants.BYTES.gib(1)) return (n / b.constants.BYTES.mib(1)).toFixed(1) + " MB";
  return (n / b.constants.BYTES.gib(1)).toFixed(2) + " GB";
}

async function run() {
  var root    = helpers.tempDir("web-mailbox-quota-reading");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var mailboxesRead = 0;
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

    var capped = await identity.accounts.create({
      address: CAPPED, password: CAPPED_PASSWORD, quotaBytes: CAP_BYTES });
    var open = await identity.accounts.create({
      address: OPEN, password: OPEN_PASSWORD });
    var operatorAccount = await identity.accounts.create({
      address: ADMIN, password: ADMIN_PASSWORD, isAdmin: true });

    // Three messages in the capped account's INBOX, one more of a
    // different size in its Archive, and one much smaller message on the
    // uncapped account. Two things follow, and each is load bearing: the
    // two accounts hold different totals, so a reading that summed the
    // whole store would report the same figure on both pages; and the
    // capped account's INBOX holds less than the capped account does, so
    // a reading taken per folder and one taken per mailbox are different
    // numbers.
    identity.mailbox.appendMessage("INBOX",
      message("one", CAPPED, "the first", 4096), { actor: { id: capped.id } });
    identity.mailbox.appendMessage("INBOX",
      message("two", CAPPED, "the second", 4096), { actor: { id: capped.id } });
    identity.mailbox.appendMessage("INBOX",
      message("three", CAPPED, "the third", 4096), { actor: { id: capped.id } });
    identity.mailbox.appendMessage("Archive",
      message("filed", CAPPED, "put away", 9000), { actor: { id: capped.id } });
    identity.mailbox.appendMessage("INBOX",
      message("theirs", OPEN, "not this one", 512), { actor: { id: open.id } });

    var cappedHeld = heldBy(identity, capped.id, CAP_BYTES);
    var cappedInbox = heldBy(identity, capped.id, CAP_BYTES, "INBOX");
    var openHeld   = heldBy(identity, open.id, 0);
    count("the fixture left mail in both mailboxes, and different amounts of it",
      cappedHeld.usedBytes > 0 && openHeld.usedBytes > 0 &&
        cappedHeld.usedBytes !== openHeld.usedBytes,
      JSON.stringify({ capped: cappedHeld, open: openHeld }));
    count("the capped account holds mail outside the folder being looked at, so a per-folder " +
      "reading and a per-mailbox reading are different figures",
      cappedInbox.usedBytes > 0 && cappedInbox.usedBytes < cappedHeld.usedBytes &&
        cappedInbox.usedLabel !== cappedHeld.usedLabel,
      JSON.stringify({ inbox: cappedInbox, mailbox: cappedHeld }));
    count("what the capped mailbox holds is inside its cap, so nothing here is over it yet",
      cappedHeld.usedBytes < CAP_BYTES,
      JSON.stringify({ used: cappedHeld.usedBytes, cap: CAP_BYTES }));

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var cappedReader = browser.browserAt(origin);
    var landed = await cappedReader.signIn(CAPPED, CAPPED_PASSWORD);
    count("the capped mailbox's owner signs in", landed.status === 302, describe(landed));
    await testTheMailboxPageNamesWhatTheMailboxHolds(cappedReader, cappedHeld, cappedInbox);

    var openReader = browser.browserAt(origin);
    var landedOpen = await openReader.signIn(OPEN, OPEN_PASSWORD);
    count("the uncapped mailbox's owner signs in", landedOpen.status === 302, describe(landedOpen));
    await testASecondAccountReadsItsOwnMailbox(openReader, openHeld, cappedHeld.usedBytes);

    var operator = browser.browserAt(origin);
    var landedAdmin = await operator.signIn(ADMIN, ADMIN_PASSWORD);
    count("the operator signs in", landedAdmin.status === 302, describe(landedAdmin));
    count("the operator's own account is the one the console answers for",
      operatorAccount.isAdmin === true, JSON.stringify(operatorAccount.isAdmin));
    await testTheOperatorReadsTheSameUsage(operator, cappedHeld);

    testTheRefusalAgreesWithThePage(identity, capped.id, cappedHeld);
    mailboxesRead = 2;

    await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    listener = null;

    return helpers.getChecks();
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
    console.log("EXAMINED " + mailboxesRead + " measured-mailboxes");
  }
}

module.exports = {
  name:      "web-mailbox-quota-reading",
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
