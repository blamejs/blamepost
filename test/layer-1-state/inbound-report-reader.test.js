// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost.mail.delivery.reports` does with the shapes a real
 * report never has and a hostile one does.
 *
 * The MX case drives whole messages at port 25, which is the path that
 * matters and also the slowest way to ask one question. The questions
 * below are about the reader on its own: an address this server has
 * never sent from, a message far bigger than any report, a report that
 * names more addresses than anybody has, a report that names none, a
 * message carrying a delivery status part without declaring itself a
 * report, and a reporting identity nobody could parse in the first
 * place. Each of them has to end somewhere definite, because the one
 * outcome a reader must never have is to quietly do nothing while the
 * counters say a report was handled.
 *
 * The other half is the seam. `blamepost.mail.mailbox.onFiled` is where
 * the reader hears about a message, and it sits in front of the call an
 * account holder and a peer are both waiting on, so an observer that
 * throws has to cost the filing nothing and a second registration has
 * to be refused rather than quietly replacing the first.
 *
 * Nothing here opens a socket. The reader is handed the octets
 * directly, which is exactly the shape the filing seam hands it.
 *
 * Run standalone: node test/layer-1-state/inbound-report-reader.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var dsn       = require("../helpers/dsn");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var HOSTNAME   = "mx.example.com";
var DOMAIN     = "example.com";
var POSTMASTER = "postmaster@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The C1 range, which carries the single-byte forms of the escape
// sequences a terminal acts on. Built from its numbers so this file's own
// bytes stay ASCII.
var C1_CONTROL_RE = new RegExp("[\\u0080-\\u009f]");

// The reader never asks a resolver anything, and the handle refuses to
// build without one, so this answers nothing and is never called.
var IDLE_RESOLVER = {
  queryMx: function () { return Promise.reject(new Error("no resolver in this case")); },
};

function deliveryOn(dataDir, postmaster) {
  return blamepost.mail.delivery.create({
    hostname:   HOSTNAME,
    dataDir:    dataDir,
    postmaster: postmaster,
    resolver:   IDLE_RESOLVER,
    policy:     { mtaSts: "off", dane: "off" },
    audit:      false,
  });
}

function reportsOf(delivery) { return delivery.describe().reports; }

function oneFailedReport(to) {
  return dsn.report({
    to: to,
    recipients: [{
      address:    "tls-reports@receiver.example.org",
      action:     "failed",
      status:     "5.1.1",
      diagnostic: "550 5.1.1 no such user here",
    }],
  });
}

// ---- the reader on its own -------------------------------------------------

function anAddressThisServerNeverSendsFromIsNotExamined(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var verdict = delivery.reports.receive(oneFailedReport("alice@" + DOMAIN),
    { arrivedFor: "alice@" + DOMAIN });
  count("a report filed for an account is not the operator's to read",
    verdict.read === false && verdict.reason === "not-a-reporting-identity",
    JSON.stringify(verdict));
  count("and nothing about it is counted at all",
    reportsOf(delivery).examined === 0, JSON.stringify(reportsOf(delivery)));

  var noAddress = delivery.reports.receive(oneFailedReport(POSTMASTER), { arrivedFor: null });
  count("a filing that could not say whose mailbox it was is passed over",
    noAddress.read === false && noAddress.reason === "not-a-reporting-identity",
    JSON.stringify(noAddress));
}

// The plus tag of RFC 5233 addresses the same mailbox, so a report that
// comes back to a tagged form of the reporting identity is a report to
// the reporting identity.
function aTaggedFormOfTheReportingIdentityIsTheSameAddress(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var verdict = delivery.reports.receive(oneFailedReport(POSTMASTER),
    { arrivedFor: "postmaster+tls@" + DOMAIN });
  count("a tagged form of the reporting identity is read", verdict.read === true,
    JSON.stringify(verdict));
  count("and the address it names is carried out with it",
    verdict.recipients.length === 1 &&
    verdict.recipients[0].recipient === "tls-reports@receiver.example.org",
    JSON.stringify(verdict.recipients));
}

// A reporting identity the address reader refuses leaves the reader
// with nothing to compare against. The answer has to be that it matches
// nothing, because the other answer is that it matches everything.
function areportingIdentityNothingCanParseLeavesTheReaderOff(dataDir) {
  var delivery = deliveryOn(dataDir, "@" + DOMAIN);
  count("a reporting identity that will not parse is reported as none",
    reportsOf(delivery).identity === null, JSON.stringify(reportsOf(delivery).identity));
  var verdict = delivery.reports.receive(oneFailedReport(POSTMASTER),
    { arrivedFor: POSTMASTER });
  count("and it matches no address rather than every address",
    verdict.read === false && verdict.reason === "not-a-reporting-identity",
    JSON.stringify(verdict));
}

function aMessageTooBigToBeAReportIsRecordedRatherThanParsed(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var body = oneFailedReport(POSTMASTER);
  // Past the ceiling the framework parser refuses at, built by padding
  // the human readable part rather than by inventing a second message
  // shape.
  var padded = body + new Array(1200000).join("x");
  var verdict = delivery.reports.receive(padded, { arrivedFor: POSTMASTER });
  count("a message past the size a report is read up to is refused",
    verdict.read === false && verdict.reason === "unreadable", JSON.stringify(verdict));
  count("and the operator is told something arrived rather than nothing",
    reportsOf(delivery).unreadable === 1 && reportsOf(delivery).examined === 1,
    JSON.stringify(reportsOf(delivery)));
}

function aReportNamingMoreAddressesThanAnybodyHasIsRefused(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var many = [];
  for (var i = 0; i < 200; i += 1) {
    many.push({ address: "r" + i + "@receiver.example.org", action: "failed", status: "5.1.1" });
  }
  var verdict = delivery.reports.receive(dsn.report({ to: POSTMASTER, recipients: many }),
    { arrivedFor: POSTMASTER });
  count("a report naming more recipients than one is read up to is refused",
    verdict.read === false && verdict.reason === "unreadable", JSON.stringify(verdict));
  count("and not one of the addresses it named is counted",
    reportsOf(delivery).recipients === 0, JSON.stringify(reportsOf(delivery)));
}

function aReportThatNamesNoAddressAtAllIsRefused(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var noGroups = delivery.reports.receive(
    dsn.report({ to: POSTMASTER, recipients: [], omitRecipientGroups: true }),
    { arrivedFor: POSTMASTER });
  count("a delivery status part with no per recipient group is refused",
    noGroups.read === false && noGroups.reason === "unreadable", JSON.stringify(noGroups));

  var noRecipient = delivery.reports.receive(
    dsn.report({ to: POSTMASTER, recipients: [{ address: null, action: "failed", status: "5.1.1" }] }),
    { arrivedFor: POSTMASTER });
  count("a group carrying an action and no address is refused",
    noRecipient.read === false && noRecipient.reason === "unreadable",
    JSON.stringify(noRecipient));
  count("neither of them is counted as a failure anybody reported",
    reportsOf(delivery).byAction.failed === 0 && reportsOf(delivery).unreadable === 2,
    JSON.stringify(reportsOf(delivery)));
}

// A message carrying a delivery status part under a top level type that
// does not declare it a report. It is claiming to be a report by
// carrying the part, so it is read as one and refused, rather than
// passed over as ordinary mail.
function aDeliveryStatusPartUnderTheWrongTopLevelTypeIsRefused(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var verdict = delivery.reports.receive(dsn.report({
    to: POSTMASTER,
    topContentType: 'multipart/mixed; boundary="rpt-boundary-1"',
    recipients: [{ address: "someone@receiver.example.org", action: "failed", status: "5.1.1" }],
  }), { arrivedFor: POSTMASTER });
  count("a delivery status part under multipart/mixed is refused rather than believed",
    verdict.read === false && verdict.reason === "unreadable", JSON.stringify(verdict));
}

// RFC 6533 defines the internationalized form of these fields as UTF-8.
// A report carrying anything else has to be refused rather than decoded,
// because a decode substitutes a replacement character for every
// sequence it cannot read and the result is then recorded as what the
// far side said.
function aReportCarryingOctetsThatAreNotUtf8IsRefused(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var text = dsn.report({
    to: POSTMASTER,
    recipients: [{
      address:    "someone@receiver.example.org",
      action:     "failed",
      status:     "5.1.1",
      diagnostic: "550 5.1.1 DIAGNOSTIC",
    }],
  });
  // A lone continuation byte, which no UTF-8 sequence can begin with,
  // put where a peer's own words go. Written from its number so this
  // file's own bytes stay ASCII.
  var split = text.split("DIAGNOSTIC");
  var raw = Buffer.concat([
    Buffer.from(split[0], "utf8"),
    Buffer.from([0x80]),
    Buffer.from(split[1], "utf8"),
  ]);
  var verdict = delivery.reports.receive(raw, { arrivedFor: POSTMASTER });
  count("a report that is not UTF-8 is refused rather than decoded",
    verdict.read === false && verdict.reason === "unreadable", JSON.stringify(verdict));
  count("and nothing it appeared to say is counted",
    reportsOf(delivery).byAction.failed === 0 && reportsOf(delivery).unreadable === 1,
    JSON.stringify(reportsOf(delivery)));
}

// A refusal quotes the far side's own bytes back at an operator, and it
// is read in a terminal and in the browser. The C1 range carries the
// single-byte forms of the escape sequences the C0 range spells with two
// bytes: U+009B is CSI, the one that introduces a cursor movement or a
// color change, so a report that puts one in a header line writes the
// rest of that line into a terminal as a command rather than as text.
//
// The message is refused either way. What is measured here is the
// reason the refusal is recorded and printed under, on the verdict the
// caller is handed and on the row kept for reading back.
function aRefusalQuotingAControlTheTerminalActsOnIsScreened(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  // Written from its number so this file's own bytes stay ASCII.
  var CSI = String.fromCharCode(0x9b);
  var report = "From: MAILER-DAEMON@relay.example.net\r\n" +
    "To: " + POSTMASTER + "\r\n" +
    "Conte" + CSI + "nt-Type multipart/report\r\n\r\nnot a readable structure\r\n";

  var verdict = delivery.reports.receive(Buffer.from(report, "utf8"),
    { arrivedFor: POSTMASTER });
  count("a report whose structure will not read is refused",
    verdict.read === false && verdict.reason === "unreadable", JSON.stringify(verdict.reason));
  count("and the reason it is refused under carries no C1 control",
    !C1_CONTROL_RE.test(String(verdict.detail)), JSON.stringify(verdict.detail));

  var recent = delivery.reports.recent();
  var row = recent[recent.length - 1];
  count("the row kept for reading back carries none either",
    row.unreadable === true && !C1_CONTROL_RE.test(String(row.reason)),
    JSON.stringify(row.reason));
}

// RFC 3464 section 2.3.3 names five actions and only two of them are
// failures. A reader that folded the other three into one bucket would
// put a number under a name the report never used, so each is counted
// under the token it arrived as.
function everyActionIsCountedUnderTheTokenItArrivedAs(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  delivery.reports.receive(dsn.report({
    to: POSTMASTER,
    recipients: [
      { address: "a@receiver.example.org", action: "delivered", status: "2.0.0" },
      { address: "b@receiver.example.org", action: "relayed",   status: "2.0.0" },
      { address: "c@receiver.example.org", action: "expanded",  status: "2.0.0" },
    ],
  }), { arrivedFor: POSTMASTER });

  var byAction = reportsOf(delivery).byAction;
  count("a delivered recipient is counted as delivered", byAction.delivered === 1,
    JSON.stringify(byAction));
  count("a relayed recipient is counted as relayed rather than as delivered",
    byAction.relayed === 1, JSON.stringify(byAction));
  count("an expanded recipient is counted as expanded rather than as delivered",
    byAction.expanded === 1, JSON.stringify(byAction));
  count("and neither of the two failure tokens moved",
    byAction.failed === 0 && byAction.delayed === 0, JSON.stringify(byAction));
}

function ordinaryMailIsNotARecordOfAnything(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var verdict = delivery.reports.receive(
    dsn.plainMessage(POSTMASTER, "a question about the server"), { arrivedFor: POSTMASTER });
  count("ordinary mail to the operator is not a report",
    verdict.read === false && verdict.reason === "not-a-report", JSON.stringify(verdict));
  var shape = reportsOf(delivery);
  count("it is counted as looked at and as nothing else",
    shape.examined === 1 && shape.read === 0 && shape.unreadable === 0,
    JSON.stringify(shape));
}

function readingAReportTouchesNothingOnDisk(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var before = delivery.describe();
  for (var i = 0; i < 3; i += 1) {
    delivery.reports.receive(oneFailedReport(POSTMASTER), { arrivedFor: POSTMASTER });
  }
  var after = delivery.describe();
  count("three reports are read", after.reports.read === 3, JSON.stringify(after.reports));
  count("and the outbound queue is exactly where it was",
    after.waiting === before.waiting && after.spool.messages === before.spool.messages &&
    after.spool.bytes === before.spool.bytes,
    JSON.stringify(before.spool) + " then " + JSON.stringify(after.spool));

  var queueDir = nodePath.join(dataDir, "queue");
  var spooled = nodeFs.existsSync(queueDir) ? nodeFs.readdirSync(queueDir) : [];
  count("nothing was written to the spool directory", spooled.length === 0, spooled.join(","));
}

function whatIsKeptForReadingBackIsBounded(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  for (var i = 0; i < 25; i += 1) {
    delivery.reports.receive(oneFailedReport(POSTMASTER), { arrivedFor: POSTMASTER });
  }
  var shape = reportsOf(delivery);
  count("every report is counted", shape.read === 25, JSON.stringify(shape.read));
  count("and what is kept for reading back has a bottom",
    shape.recent.length > 0 && shape.recent.length < 25, String(shape.recent.length));

  // Handed back as copies down to the rows, so a caller that edits what
  // it read cannot change what the next caller reads. Asserted on a
  // field inside a recipient rather than on the array, because a
  // shallow copy passes the second test and fails the first.
  var first = delivery.reports.recent();
  first[0].recipients = [];
  var second = delivery.reports.recent();
  second[0].recipients[0].recipient = "rewritten@example.net";
  var third = delivery.reports.recent();
  count("replacing the recipient list on a copy leaves the record alone",
    third[0].recipients.length > 0, JSON.stringify(third[0].recipients.length));
  count("and so does rewriting an address inside one",
    third[0].recipients[0].recipient === "tls-reports@receiver.example.org",
    String(third[0].recipients[0].recipient));

  // The same question of the verdict `receive` hands back, which shares
  // its rows with nothing.
  var verdict = delivery.reports.receive(oneFailedReport(POSTMASTER),
    { arrivedFor: POSTMASTER });
  verdict.recipients[0].recipient = "rewritten@example.net";
  var afterEdit = delivery.reports.recent();
  count("editing the verdict a caller was given does not edit the record",
    afterEdit[afterEdit.length - 1].recipients[0].recipient ===
      "tls-reports@receiver.example.org",
    String(afterEdit[afterEdit.length - 1].recipients[0].recipient));
}

function aCallerThatCannotSayWhereItArrivedIsRefused(dataDir) {
  var delivery = deliveryOn(dataDir, POSTMASTER);
  var thrown = null;
  try { delivery.reports.receive(oneFailedReport(POSTMASTER), []); }
  catch (e) { thrown = e; }
  count("opts that are not an object are a caller mistake and throw",
    thrown !== null && thrown instanceof TypeError,
    thrown === null ? "nothing was thrown" : String(thrown.message));
}

// ---- the filing seam -------------------------------------------------------

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// Two observers, one of which fails on every message it sees. That is
// how three claims are made against one filing: the seam carries the
// address and the octets, an observer that dies takes nothing with it,
// and the one registered after it still runs. The alternative to all
// three is a peer told to retry a message that is already in the
// mailbox.
function theSeamCarriesTheFilingAndSurvivesAnObserverThatThrows(handle, actor) {
  var seen = [];
  var alsoSeen = [];
  handle.mailbox.onFiled(function (event) {
    seen.push(event);
    throw new Error("an observer that fails on every message");
  });
  handle.mailbox.onFiled(function (event) { alsoSeen.push(event); });

  var raw = Buffer.from(oneFailedReport(actor.address), "utf8");
  var stored = null;
  var thrown = null;
  try { stored = handle.mailbox.appendMessage("INBOX", raw, { actor: actor, flags: [] }); }
  catch (e) { thrown = e; }

  count("an observer that throws does not reach the caller",
    thrown === null, thrown === null ? "nothing was thrown" : String(thrown.message));
  count("and the message is filed anyway",
    stored !== null && typeof stored.objectid === "string",
    stored === null ? "no message" : String(stored.objectid));
  count("the observer heard about exactly one message", seen.length === 1, String(seen.length));
  count("it was told whose mailbox the message landed in",
    seen[0].address === actor.address, String(seen[0].address));
  count("and it was handed the octets that were filed",
    Buffer.isBuffer(seen[0].raw) && seen[0].raw.equals(raw),
    seen[0].raw && seen[0].raw.length + " bytes");
  count("along with the mailbox it landed in", seen[0].folder === "INBOX",
    String(seen[0].folder));
  count("an observer registered behind one that throws still hears about the message",
    alsoSeen.length === 1, String(alsoSeen.length));

  // The filing is a filing, not a half one. The message the observer
  // failed on is readable back through the ordinary path.
  var selected = handle.mailbox.selectFolder(actor, "INBOX", {});
  count("and the mailbox reports it", selected.exists === 1, JSON.stringify(selected.exists));
}

// Nothing removes an observer, so the two ways of registering one that
// would grow the list without anybody meaning to are both refused at
// the call rather than met later as memory or as a double count.
function theWaysOfRegisteringAnObserverThatGrowTheListAreRefused(handle) {
  var same = function () { return null; };
  handle.mailbox.onFiled(same);
  var twice = null;
  try { handle.mailbox.onFiled(same); }
  catch (e) { twice = e; }
  count("registering the same observer twice is refused",
    twice !== null && twice instanceof TypeError,
    twice === null ? "nothing was thrown" : String(twice.message));

  var notAFunction = null;
  try { handle.mailbox.onFiled("not a function"); }
  catch (e) { notAFunction = e; }
  count("and so is something that is not a function",
    notAFunction !== null && notAFunction instanceof TypeError,
    notAFunction === null ? "nothing was thrown" : String(notAFunction.message));

  var overflowed = null;
  try {
    for (var i = 0; i < 64; i += 1) {
      handle.mailbox.onFiled(function distinctObserver() { return i; });
    }
  } catch (e) { overflowed = e; }
  count("and a caller registering one observer after another meets a ceiling",
    overflowed !== null && overflowed instanceof TypeError,
    overflowed === null ? "the list grew without a bottom" : String(overflowed.message));
}

// ---- runner ----------------------------------------------------------------

async function readerCases() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    anAddressThisServerNeverSendsFromIsNotExamined(freshDir("rpt-not-ours"));
    aTaggedFormOfTheReportingIdentityIsTheSameAddress(freshDir("rpt-tagged"));
    areportingIdentityNothingCanParseLeavesTheReaderOff(freshDir("rpt-no-identity"));
    aMessageTooBigToBeAReportIsRecordedRatherThanParsed(freshDir("rpt-oversize"));
    aReportNamingMoreAddressesThanAnybodyHasIsRefused(freshDir("rpt-many"));
    aReportThatNamesNoAddressAtAllIsRefused(freshDir("rpt-none"));
    aDeliveryStatusPartUnderTheWrongTopLevelTypeIsRefused(freshDir("rpt-wrong-type"));
    aReportCarryingOctetsThatAreNotUtf8IsRefused(freshDir("rpt-not-utf8"));
    aRefusalQuotingAControlTheTerminalActsOnIsScreened(freshDir("rpt-c1-reason"));
    everyActionIsCountedUnderTheTokenItArrivedAs(freshDir("rpt-actions"));
    ordinaryMailIsNotARecordOfAnything(freshDir("rpt-plain"));
    readingAReportTouchesNothingOnDisk(freshDir("rpt-no-write"));
    whatIsKeptForReadingBackIsBounded(freshDir("rpt-bounded"));
    aCallerThatCannotSayWhereItArrivedIsRefused(freshDir("rpt-bad-opts"));
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

async function seamCases() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-report-seam-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
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
    var handle = await store.open(cfg);
    await handle.domains.add({ domain: DOMAIN });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD }));

    theSeamCarriesTheFilingAndSurvivesAnObserverThatThrows(handle, alice);
    theWaysOfRegisteringAnObserverThatGrowTheListAreRefused(handle);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try { nodeFs.rmSync(root, { recursive: true, force: true }); }
    catch (_e) {
      // A temporary directory the platform will not release yet is not a
      // test result. The operating system reclaims it.
    }
  }
}

async function run() {
  await helpers.withTestTimeout("inbound report reader: the reader on its own",
    readerCases, { timeoutMs: 30000 });
  await helpers.withTestTimeout("inbound report reader: the filing seam",
    seamCases, { timeoutMs: 30000 });
  return helpers.getChecks();
}

module.exports = { name: "inbound-report-reader", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
