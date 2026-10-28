// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The command line's destructive verbs, and the flags that are supposed
 * to gate them.
 *
 * Three shapes are covered, all of which were live in this binary and
 * none of which a static check can see.
 *
 * A flag that is declared, described in the help text, documented in the
 * operator guide, and then never read. `domain remove` accepted
 * `--destroy` and passed it nowhere, and its usage line offered an
 * archive that the store has no state for: every removal erased the row
 * and its DKIM selectors, whichever flags were given. An operator
 * reading "archive a domain, or erase it" had no way to tell which one
 * had happened.
 *
 * A refusal that reports success. `queue remove` handed any id to a
 * force-removal and printed "Removed <id>" for one that was never in the
 * queue. The incident runbook sends an operator to that exact verb to
 * cancel mail a stolen credential sent, so a mistyped id read as a
 * cancelled message that was still on disk waiting for its next attempt.
 *
 * A destructive verb with nothing recorded. Abandoning a queued message
 * erases the body and tells the sender nothing, which is the point, but
 * it left no row saying which message, or why.
 *
 * Everything here spawns the real binary. The status comes from the
 * spawn, never from a pipeline, because a pipeline reports the last
 * command's status and would make a correct refusal look like success.
 *
 * Run standalone: node test/layer-1-state/cli-destructive.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SPARE    = "example.net";
var ADDRESS  = "alice@" + DOMAIN;

// The account whose mail is under a preservation order when it is
// erased, which is the partial erasure the command line has to be able
// to describe.
var HELD_ADDRESS = "held@" + DOMAIN;

// The account holding one message whose INTERNALDATE its client chose.
// Separate from the one above because the erasure vectors count the mail
// they destroy, and a third message in that mailbox would change a count
// those vectors are about.
var DATED_ADDRESS  = "dated@" + DOMAIN;
var ESCAPE_ADDRESS = "escaped@" + DOMAIN;

// The date that message asks to show, years before any run of this file.
// RFC 9051 section 6.3.12 lets an APPEND carry it and this server keeps
// what the client sent, so a column filled from it cannot be mistaken for
// a clock reading this server took.
var CLIENT_DATE_MS = Date.UTC(2019, 2, 4);
var CLIENT_DATE    = "2019-03-04";

function isoDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

function parseJson(text) {
  try { return JSON.parse(text); }
  catch (_e) { return null; }
}

function lineNaming(text, objectId) {
  var found = String(text).split("\n").filter(function (line) {
    return line.indexOf(objectId) !== -1;
  });
  return found.length > 0 ? found[0] : "";
}

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// One delivered message, as the bytes that arrived. The adapter keeps
// the original octets rather than a re-encoding, so a fixture built from
// anything else would not be a message this server could serve back.
function mailFrom(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <" + HELD_ADDRESS + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\nthe body of " + subject + "\r\n", "utf8");
}

// A spooled outbound message, written the way the delivery composer
// writes one: a JSON descriptor beside the RFC 822 body, both named for
// the entry's id. `queue list` reads it back through the real reader, so
// a fixture that has drifted from the format shows up as an unreadable
// entry rather than as a passing assertion about nothing.
//
// The id is minted the way the spool mints its own, because an id that
// is not the shape this server produces is refused before the removal
// looks at anything, and a fixture refused for its NAME would not
// exercise the check for whether the message is actually there.
var SPOOL_ID = b.crypto.generateToken(12);

// A second well-formed id that was never spooled. It has to be minted
// the same way rather than derived from the first by appending a
// character. The spool refuses an id outside the alphabet it mints
// before it looks for the message, so a malformed stand-in would prove
// only that the shape check works and never reach the question of
// whether the message exists.
var UNSPOOLED_ID = b.crypto.generateToken(12);

async function seedSpool(dataDir) {
  var spoolDir = nodePath.join(dataDir, "queue");
  b.atomicFile.ensureDir(spoolDir, 0o700);
  await b.atomicFile.write(nodePath.join(spoolDir, SPOOL_ID + ".eml"),
    "From: " + ADDRESS + "\r\n" +
    "To: victim@" + SPARE + "\r\n" +
    "Subject: sent while the credential was stolen\r\n" +
    "\r\n" +
    "body\r\n", { fileMode: 0o600 });
  await b.atomicFile.writeJson(nodePath.join(spoolDir, SPOOL_ID + ".json"), {
    id:            SPOOL_ID,
    from:          ADDRESS,
    recipient:     "victim@" + SPARE,
    attempt:       1,
    nextAttemptAt: Date.now() + 60000,
    reason:        "451 4.7.1 try again later",
    reasonCode:    "4.7.1",
    requireTls:    false,
    queuedAt:      Date.now(),
  }, { fileMode: 0o600 });
}

function spoolFilesPresent(dataDir) {
  var spoolDir = nodePath.join(dataDir, "queue");
  return nodeFs.existsSync(nodePath.join(spoolDir, SPOOL_ID + ".json")) ||
    nodeFs.existsSync(nodePath.join(spoolDir, SPOOL_ID + ".eml"));
}

// Every sealed private key on the volume that belongs to one domain. A
// selector row names its key file by a leaf name built from the domain,
// the selector and the algorithm, so the domain is the prefix. Read off
// the folder rather than off a row on purpose: the whole question here
// is whether the two agree, and a reading taken from the row cannot
// answer it.
function sealedKeysFor(dataDir, domain) {
  var all;
  try { all = nodeFs.readdirSync(nodePath.join(dataDir, "keys")); }
  catch (_e) { return []; }
  return all.filter(function (f) { return f.indexOf(domain + ".") === 0; }).sort();
}

// ---- domain removal --------------------------------------------------------

function removingADomainIsExplicitAndIrreversible(run, dataDir) {
  var noReason = run(["domain", "remove", SPARE]);
  count("removing a domain without a reason is refused",
    noReason.status === 2 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 120));

  // The flag that was declared, described and never read. Without the
  // gate the domain and its DKIM selectors are gone at this point.
  var noDestroy = run(["domain", "remove", SPARE, "--reason", "moved away 2026-08-22"]);
  count("and removing one without --destroy is refused rather than done quietly",
    noDestroy.status === 2 && /--destroy/.test(noDestroy.both),
    "exit " + noDestroy.status + " " + noDestroy.both.slice(0, 160));
  count("and the refusal names the reversible verb instead of leaving it to be found",
    /domain disable/.test(noDestroy.both), noDestroy.both.slice(0, 200));

  var stillThere = run(["domain", "list"]);
  count("the domain is still hosted after both refusals",
    stillThere.stdout.indexOf(SPARE) !== -1, stillThere.stdout.slice(0, 160));

  // The domain being removed is one that signs, which is the ordinary
  // case rather than a contrived one: `domain add` mints a pair as its
  // second step, so every domain an operator hosts through this binary
  // has two sealed private keys under the data directory before it has
  // taken a single message.
  var keysBefore = sealedKeysFor(dataDir, SPARE);
  count("the domain about to be removed holds a sealed private key per algorithm",
    keysBefore.length === 2, keysBefore.join(",") || "(none)");

  var erased = run(["domain", "remove", SPARE,
    "--destroy", "--reason", "moved away 2026-08-22"]);
  count("with both flags it goes", erased.status === 0,
    "exit " + erased.status + " " + erased.both.slice(0, 160));
  // The word matters: there is no archived copy of a removed domain, so
  // a line saying "Archived" would describe a state that cannot exist.
  count("and it says erased rather than archived, because nothing was kept",
    /^Erased /m.test(erased.stdout) && !/Archived/.test(erased.stdout),
    erased.stdout.slice(0, 160));

  // The selector rows are the only thing that names a sealed key file.
  // Nothing walks the keys folder, and the one path that erases a key
  // finds it through a row, so a removal that takes the rows and leaves
  // the files leaves signing material for the domain on this volume and
  // in every backup taken afterwards, with no verb able to name it.
  var keysAfter = sealedKeysFor(dataDir, SPARE);
  count("and the sealed private keys its selector rows named are erased with them",
    keysAfter.length === 0, keysAfter.join(",") || "(none)");
  count("and the operator is told how much signing material went, not only how many rows",
    /2 sealed private key/.test(erased.stdout), erased.stdout.slice(0, 240));

  var gone = run(["domain", "list"]);
  count("and the domain is no longer hosted",
    gone.stdout.indexOf(SPARE) === -1, gone.stdout.slice(0, 160));
}

// ---- disable and enable ----------------------------------------------------

function aDomainCanBeTurnedOffWithoutLosingIt(run) {
  var noReason = run(["domain", "disable", DOMAIN]);
  count("disabling a domain without a reason is refused",
    noReason.status === 2 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 120));

  var off = run(["domain", "disable", DOMAIN, "--reason", "investigating 2026-08-22"]);
  count("disabling with a reason succeeds", off.status === 0,
    "exit " + off.status + " " + off.both.slice(0, 160));

  var listed = run(["domain", "list"]);
  count("and the listing says the domain is disabled",
    /example\.com\s+disabled/.test(listed.stdout), listed.stdout.slice(0, 160));

  // The whole point of disable over remove: nothing it held went away.
  var account = run(["account", "show", ADDRESS]);
  count("the account on a disabled domain is still there",
    account.status === 0 && account.stdout.indexOf(ADDRESS) !== -1,
    "exit " + account.status + " " + account.stdout.slice(0, 120));
  var selectors = run(["dkim", "list", DOMAIN]);
  count("and so are its DKIM selectors",
    selectors.status === 0 && /bp\d{6}/.test(selectors.stdout),
    "exit " + selectors.status + " " + selectors.stdout.slice(0, 160));

  // `doctor --domain` scopes to the active set, so a disabled domain
  // used to come back as one this server does not host, which would send
  // an operator to `domain add` for a name they switched off themselves.
  var checked = run(["doctor", "--domain", DOMAIN]);
  count("doctor says the domain is disabled rather than unknown",
    checked.status !== 0 && /disabled/.test(checked.both),
    "exit " + checked.status + " " + checked.both.slice(0, 200));
  count("and does not tell the operator to add a domain that is already there",
    !/domain add/.test(checked.both), checked.both.slice(0, 200));

  // The domain is left disabled here on purpose. Whether the status the
  // listing prints actually stops mail is asked once, at the end, from
  // the single store handle this file opens.
}

function aDisabledDomainCanBeTurnedBackOn(run) {
  var on = run(["domain", "enable", DOMAIN, "--reason", "investigation closed"]);
  count("enabling puts it back", on.status === 0,
    "exit " + on.status + " " + on.both.slice(0, 160));
  var back = run(["domain", "list"]);
  count("and the listing says active again",
    /example\.com\s+active/.test(back.stdout), back.stdout.slice(0, 160));
}

// ---- queue removal ---------------------------------------------------------

async function abandoningAQueuedMessageIsCheckedAndRecorded(run, dataDir) {
  await seedSpool(dataDir);

  // Reading the fixture back through the real reader first. An entry the
  // reader cannot parse is reported as unreadable, so this check is what
  // stops the rest of the case from asserting against nothing.
  var listed = run(["queue", "list"]);
  count("the seeded message is in the queue and readable",
    listed.status === 0 && listed.stdout.indexOf(SPOOL_ID) !== -1 &&
      !/unreadable/.test(listed.stdout),
    "exit " + listed.status + " " + listed.stdout.slice(0, 200));

  var noReason = run(["queue", "remove", SPOOL_ID]);
  count("abandoning a message without a reason is refused",
    noReason.status === 2 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 140));
  count("and the message is still queued after the refusal",
    spoolFilesPresent(dataDir), "spool files present");

  // The shape that mattered most: a well-formed id that names nothing.
  var typo = run(["queue", "remove", UNSPOOLED_ID, "--reason", "incident 4471"]);
  count("an id that is not in the queue is refused rather than reported removed",
    typo.status === 2, "exit " + typo.status + " " + typo.both.slice(0, 200));
  count("and the refusal says the queue holds nothing under that id",
    /no queued message with id/.test(typo.both), typo.both.slice(0, 200));
  count("and prints no removal line the operator could read as a cancellation",
    !/^Removed /m.test(typo.stdout) && !/^Abandoned /m.test(typo.stdout),
    typo.stdout.slice(0, 140));
  count("and it points at the verb that prints the real ids",
    /queue list/.test(typo.both), typo.both.slice(0, 200));
  count("and the real message is untouched by the mistyped run",
    spoolFilesPresent(dataDir), "spool files present");

  var gone = run(["queue", "remove", SPOOL_ID, "--reason",
    "incident 4471, sent by a stolen credential"]);
  count("with a reason and a real id it goes", gone.status === 0,
    "exit " + gone.status + " " + gone.both.slice(0, 160));
  count("and the answer names the recipient the message was for",
    gone.stdout.indexOf("victim@" + SPARE) !== -1, gone.stdout.slice(0, 200));
  count("and both spool files are gone from disk",
    !spoolFilesPresent(dataDir), "spool files present");

  var empty = run(["queue", "list"]);
  count("and the queue no longer lists it",
    empty.stdout.indexOf(SPOOL_ID) === -1, empty.stdout.slice(0, 160));
}

// The two questions that need the database, asked from one handle.
//
// The handle is opened AFTER every CLI child has exited: the database is
// encrypted at rest and each process decrypts its own working copy, so a
// handle opened first holds the snapshot from before the child wrote.
//
// One handle rather than one per question, and this is not tidiness. A
// third open in a single run of this file collides on the audit chain's
// monotonic counter once CLI children have advanced it, deterministically
// and with a message about a UNIQUE constraint that says nothing about
// the cause. Two opens are stable. Keep it that way: a new question that
// needs the store belongs inside this function, not in a fresh open.
async function theRecordAndTheRoutingVerdict(cfg) {
  var handle = await store.open(cfg);
  try {
    var rows = await b.audit.query({
      action: "blamepost.mail.queue.message_removed",
      limit:  50,
    });
    count("abandoning a queued message left an audit row",
      Array.isArray(rows) && rows.length >= 1,
      Array.isArray(rows) ? rows.length + " row(s)" : String(rows));

    // The reason belongs in the row's own column. `b.audit.query` takes
    // no metadata criteria at all, so a reason buried in the blob is one
    // an auditor cannot filter on.
    var withReason = (rows || []).filter(function (r) {
      return String((r && r.reason) || "").indexOf("incident 4471") !== -1;
    });
    count("and the row carries the reason in its own column",
      withReason.length >= 1, withReason.length + " of " + (rows || []).length);

    // Metadata comes back as the JSON text it went in as.
    var named = withReason.filter(function (r) {
      var meta = r.metadata;
      if (typeof meta === "string") {
        try { meta = JSON.parse(meta); } catch (_e) { return false; }
      }
      return meta && meta.recipient === "victim@" + SPARE;
    });
    count("and names the recipient whose message was canceled",
      named.length >= 1, named.length + " of " + withReason.length);

    // A status the listing prints and nothing acts on would be worse
    // than no verb at all, so the effect of `domain disable` is read off
    // the routing verdict rather than off the row the verb just wrote.
    var refused = await handle.resolve(ADDRESS);
    count("mail for a disabled domain stops being deliverable",
      refused.deliverable === false, JSON.stringify(refused));
    count("and the verdict names the domain rather than the mailbox",
      String(refused.reason || "").indexOf("domain-disabled") !== -1,
      String(refused.reason));
  } finally {
    handle.close();
  }
}

// ---- answering a preservation order ----------------------------------------

// A court's order arrives, and the operator has to be able to act on it
// from the surface every other consequential verb lives on. The gate it
// drives has always worked: every hard delete reads the per-message flag
// and refuses, the retention floor defers to it, and the erasure below
// keeps a held message back. What was missing was any way to SET it, so
// the machinery could only ever be reached from code.
//
// Two failures come out of that, and they are separate. An operator
// served with an order cannot comply. And an operator who believes an
// order is in place has no way to find out that it is not, which is the
// worse of the two because it is silent: the mail goes on the next
// expunge and the paperwork says it was preserved.
//
// So this drives the whole loop at the command line and reads back what
// the operator was told, rather than reaching into the adapter.
function answeringAPreservationOrderAtTheCommandLine(run, objectId) {
  // Finding the records comes before preserving them. An operator served
  // with an order holds a matter and a date range, not an object id, so
  // a hold verb that only accepts ids they have no way to obtain is the
  // same capability gap one step along.
  var noReason = run(["account", "messages", HELD_ADDRESS]);
  count("listing an account's mail without saying why is refused, because it is somebody " +
    "else's correspondence and the audit row is the only record it was read",
    noReason.status === 2 && /give --reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 300));

  var inventory = run(["account", "messages", HELD_ADDRESS,
    "--reason", "identifying the records preservation order 24-cv-01933 covers"]);
  count("an operator can list what an account holds, with the id each message is named by",
    inventory.status === 0 && inventory.stdout.indexOf(objectId) !== -1,
    "exit " + inventory.status + " " + inventory.both.slice(0, 500));
  count("and nothing is marked as under an order yet, so the marker means something when " +
    "it appears",
    !/ {2}HELD$/m.test(inventory.stdout) &&
    /0 messages under a preservation order/.test(inventory.stdout),
    inventory.stdout.slice(0, 600));

  var before = run(["account", "holds", HELD_ADDRESS]);
  count("an account with no order against it says so plainly, rather than printing an " +
    "empty list an operator has to interpret",
    before.status === 0 && /holds no message under a preservation order/.test(before.stdout),
    "exit " + before.status + " " + before.both.slice(0, 300));

  var placed = run(["account", "hold", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", objectId, "--reason", "preservation order 24-cv-01933",
    "--citation", "FRCP-26", "--custodian", "records@example.com"]);
  count("an operator can place a preservation order from the command line",
    placed.status === 0 && placed.stdout.indexOf(objectId) !== -1,
    "exit " + placed.status + " " + placed.both.slice(0, 400));
  count("and is told what the order now does, on every protocol rather than the one they " +
    "happened to be thinking of",
    /refuses them now, on IMAP, POP3, JMAP and webmail/.test(placed.stdout),
    placed.stdout.slice(0, 500));

  // The half that answers "is the order actually in place?". Without it
  // an operator has only the report of the command they ran, which is
  // the same evidence they had before it existed.
  var after = run(["account", "holds", HELD_ADDRESS]);
  count("the order can be read back afterwards, so an operator can prove it is in force " +
    "rather than trusting the command they ran",
    after.status === 0 && after.stdout.indexOf(objectId) !== -1,
    "exit " + after.status + " " + after.both.slice(0, 400));
  count("and it names the matter, the custodian and who placed it, which is what a " +
    "regulator asks for rather than the fact of a flag being set",
    /citation: {2}FRCP-26/.test(after.stdout) &&
    /custodian: records@example\.com/.test(after.stdout) &&
    /reason: {4}preservation order 24-cv-01933/.test(after.stdout),
    after.stdout.slice(0, 600));

  // A message the account does not have is the case that decides whether
  // an operator can be misled. Reporting it clean would leave somebody
  // believing a duty is met over a message no order was placed on.
  var missed = run(["account", "hold", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", "obj_00000000000000000000000000000000",
    "--reason", "an order naming a message this account does not hold"]);
  count("an order naming a message the account does not hold is refused by name and exits " +
    "non-zero, rather than reporting a duty that was never taken on",
    missed.status === 1 && /FAIL {2}obj_0{32} is not in INBOX/.test(missed.stdout),
    "exit " + missed.status + " " + missed.both.slice(0, 400));

  // The listing and the order agree, which is what lets an operator use
  // one command to answer both halves of "what is here, and what is
  // preserved".
  var marked = run(["account", "messages", HELD_ADDRESS,
    "--reason", "confirming the order covers the records it was meant to"]);
  count("the message list marks what is under an order, so the two verbs cannot disagree " +
    "about which records are preserved",
    marked.status === 0 && /1 message under a preservation order/.test(marked.stdout) &&
    new RegExp(objectId + ".*HELD").test(marked.stdout),
    marked.stdout.slice(0, 700));

  var unrecorded = run(["account", "hold", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", objectId]);
  count("and an order with nothing recorded against it is refused, because the reason is " +
    "the column an auditor filters on",
    unrecorded.status === 2 && /give --reason/.test(unrecorded.both),
    "exit " + unrecorded.status + " " + unrecorded.both.slice(0, 300));
}

// Lifting the order is the half that ends a duty rather than starting
// one, and the next hard delete destroys what it protected, so it is
// gated the way every other verb that removes a protection is. The proof
// that it reached the gate is the erasure that follows finishing.
function liftingAPreservationOrderAtTheCommandLine(run, objectId) {
  var unconfirmed = run(["account", "release", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", objectId, "--reason", "matter closed", "--approver", "records@example.com"]);
  count("lifting an order without confirming it is refused, because the next delete on " +
    "those messages destroys them",
    unconfirmed.status === 2 && /give --confirm/.test(unconfirmed.both),
    "exit " + unconfirmed.status + " " + unconfirmed.both.slice(0, 300));

  var noApprover = run(["account", "release", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", objectId, "--reason", "matter closed", "--confirm"]);
  count("and one with no approver is refused, because an order is not lifted by whoever " +
    "happens to be at the keyboard",
    noApprover.status === 2 && /give --approver/.test(noApprover.both),
    "exit " + noApprover.status + " " + noApprover.both.slice(0, 300));

  var lifted = run(["account", "release", HELD_ADDRESS, "--mailbox", "INBOX",
    "--message", objectId, "--reason", "matter closed", "--approver", "records@example.com",
    "--confirm"]);
  count("a confirmed release with an approver lifts the order",
    lifted.status === 0 && lifted.stdout.indexOf(objectId) !== -1,
    "exit " + lifted.status + " " + lifted.both.slice(0, 400));

  var afterward = run(["account", "holds", HELD_ADDRESS]);
  count("and nothing is under an order afterwards, which is the read an operator closing " +
    "a matter has to be able to make",
    afterward.status === 0 &&
    /holds no message under a preservation order/.test(afterward.stdout),
    "exit " + afterward.status + " " + afterward.both.slice(0, 300));

  // The whole point of the loop. The erasure the order held back is the
  // one an operator was told to run again, and now it reaches the mail.
  var finished = run(["account", "remove", HELD_ADDRESS, "--destroy",
    "--reason", "finishing the erasure once the order was lifted"]);
  count("the erasure the order held back now finishes, so releasing the order really was " +
    "the step the operator was told it was",
    finished.status === 0 && /^Erased /m.test(finished.stdout) &&
    !/kept {2}message/.test(finished.stdout),
    "exit " + finished.status + " " + finished.both.slice(0, 500));

  var gone = run(["account", "list", "--json"]);
  var parsed;
  try { parsed = JSON.parse(gone.stdout); } catch (_e) { parsed = null; }
  count("and the identity goes with the last of its mail, because nothing names it any more",
    parsed !== null && parsed.every(function (a) { return a.address !== HELD_ADDRESS; }),
    JSON.stringify(parsed && parsed.map(function (a) { return a.address; })));
}

// ---- the dates in the message listing ---------------------------------------

// The listing an operator answers a preservation order and an erasure
// request from, and which of the two dates on a message row it shows.
//
// A message carries both. INTERNALDATE is the date the message asks to
// show, and RFC 9051 section 6.3.12 lets a client set it on upload, so it
// is a value the account holder's own software chose; the mailbox layer
// keeps it for the client's sake and says in as many words that nothing
// deciding whether a message may be destroyed may read it. Beside it is
// the clock reading this server took when it filed the message, which is
// what the delete path measures a retention window against.
//
// This listing sits in the same table as the `HELD` marker and is the
// table an operator builds an Article 17 answer or a preservation answer
// out of. A date column filled from the first of the two is a date the
// subject's own client chose, so a message can be moved out of a court's
// date range by uploading it with a date of the holder's choosing, and
// the operator has nothing on the page telling them which date they are
// reading.
//
// Both are shown. The arrival stamp is the one an answer is built on, and
// the client's date is what the holder is reading off their own screen
// when they describe a message, so an operator trying to match the two
// needs it on the same line. Neither is any use unlabeled.
function theMessageListingSeparatesArrivalFromTheClientsDate(run, objectId, arrivalDays) {
  var listed = run(["account", "messages", DATED_ADDRESS,
    "--reason", "identifying the records a preservation order covers"]);
  count("an operator can list the mail of the account whose message carries a date its " +
    "client chose",
    listed.status === 0 && listed.stdout.indexOf(objectId) !== -1,
    "exit " + listed.status + " " + listed.both.slice(0, 400));

  var line = lineNaming(listed.stdout, objectId);
  count("the line carries the date this server filed the message, which is the reading it " +
    "took itself and the one a retention window is measured against",
    arrivalDays.some(function (day) { return line.indexOf(day) !== -1; }),
    JSON.stringify({ line: line, arrival: arrivalDays }));
  count("and it still carries the date the client asked for, so a message an account " +
    "holder describes by what their own client shows can be found from this table",
    line.indexOf(CLIENT_DATE) !== -1, JSON.stringify({ line: line, client: CLIENT_DATE }));
  count("with both columns named, because two dates on one line and no heading leaves the " +
    "operator to guess which of them their answer is being built on",
    /\barrived\b/.test(listed.stdout) && /\bclient\b/.test(listed.stdout),
    listed.stdout.slice(0, 900));

  var records = parseJson(run(["account", "messages", DATED_ADDRESS, "--json",
    "--reason", "reading the same listing a script would"]).stdout);
  var record = (Array.isArray(records) ? records : []).filter(function (r) {
    return r.objectId === objectId;
  })[0] || null;
  count("the machine-readable shape carries the two dates under names of their own, so a " +
    "script cannot read one for the other",
    record !== null && arrivalDays.indexOf(String(record.arrived)) !== -1 &&
    String(record.clientDate) === CLIENT_DATE,
    JSON.stringify(record));
}

// A `Subject` is written by whoever sent the message, and this listing
// prints it to an operator's terminal while they decide which records a
// court order covers.
//
// U+009B is CSI, the single-byte form of the escape sequence the C0
// range spells as ESC `[`. A terminal printing it acts on the bytes
// after it rather than showing them, so a subject carrying one can move
// the cursor over the row above, clear the line, or repaint the `HELD`
// marker on a different message. The screen this listing already runs
// leaves the C1 range alone, which is the range that reads as ordinary
// text to a check written for C0.
//
// The byte is built rather than written, because a raw C1 octet does
// not survive being written into a source file.
var CSI_BYTE = String.fromCharCode(0x9b);

// The other half of the same question, and the one a check written for
// escape sequences alone does not ask. A tab is ordinary in free text,
// which is why the framework's screen keeps it, and it is not ordinary in
// a column that a heading is sitting over: an inventory row carrying one
// pushes the identifier and the two dates out from under their headings,
// so the operator matching a record to a court order reads the wrong
// column. Written from its code point for the same reason CSI_BYTE is.
var TAB_BYTE = String.fromCharCode(0x09);

// One RFC 2047 encoded word carrying `text` as UTF-8.
function encodedWord(text) {
  return "=?UTF-8?B?" + Buffer.from(text, "utf8").toString("base64") + "?=";
}
var C1_RANGE = /[-]/;
var ESCAPING_SUBJECT_MARKER = "escaping-subject";

function theListingPrintsASubjectWithoutCarryingATerminalCommand(run) {
  var listed = run(["account", "messages", ESCAPE_ADDRESS,
    "--reason", "identifying the records a preservation order covers"]);
  count("an operator can list the mail of the account whose message carries an escape in " +
    "its subject",
    listed.status === 0, "exit " + listed.status + " " + listed.both.slice(0, 300));

  count("and nothing the listing prints carries a C1 control, so the row reads as a row " +
    "rather than acting on the terminal that prints it",
    !C1_RANGE.test(listed.stdout), JSON.stringify(listed.stdout.slice(0, 400)));

  // The subject is still shown. A screen that dropped the text would
  // leave the operator unable to match the row to the message somebody
  // described to them, which is what the column is for.
  count("and the subject is still there to match a record against",
    listed.stdout.indexOf(ESCAPING_SUBJECT_MARKER) !== -1,
    listed.stdout.slice(0, 400));

  // The column question. The listing pads each column to the width of
  // the widest value in it, and a tab inside a value moves everything
  // after it to the next tab stop of whatever is printing the line, so
  // the heading no longer names the column under it.
  count("and no row carries a tab, so every value stays under the heading that names it",
    listed.stdout.indexOf(TAB_BYTE) === -1,
    JSON.stringify(listed.stdout.slice(0, 400)));

  // The machine-readable shape as well, because a script writes what it
  // reads into a report somebody opens.
  var records = parseJson(run(["account", "messages", ESCAPE_ADDRESS, "--json",
    "--reason", "reading the same listing a script would"]).stdout);
  var carried = (Array.isArray(records) ? records : []).filter(function (r) {
    return C1_RANGE.test(String(r.subject || "")) || C1_RANGE.test(String(r.from || "")) ||
      String(r.subject || "").indexOf(TAB_BYTE) !== -1 ||
      String(r.from || "").indexOf(TAB_BYTE) !== -1;
  });
  count("and the JSON listing carries none either",
    carried.length === 0, JSON.stringify(carried).slice(0, 300));
}

// ---- runner ----------------------------------------------------------------

// ---- erasing an account names what it could not erase ----------------------

// An erasure is the one verb where nothing can be read back afterwards
// to find out what happened, so the lines it prints are the whole of
// what the operator has. It is also partial more often than it looks: a
// message under a preservation order stays, because a court's order to
// keep a record outranks a request to destroy it, and the person
// answering the erasure request has to be able to name the record being
// kept and the rule keeping it.
//
// A bare "Erased <address>" over that state is the failure. It reads as
// a complete erasure, and the operator tells the requester the mail is
// gone while it is still on the volume and still readable.
function erasingAnAccountNamesWhatItKept(run) {
  var erased = run(["account", "remove", HELD_ADDRESS, "--destroy",
    "--reason", "erasure requested by the account holder"]);

  count("erasing an account whose mail is under a preservation order still erases the " +
    "account and reports a clean exit, because a record being kept is not a fault",
    erased.status === 0, "exit " + erased.status + " " + erased.both.slice(0, 300));
  count("and it says how much mail actually went, rather than only that the account did",
    /1 message destroyed across \d+ mailboxes?/.test(erased.stdout),
    erased.stdout.slice(0, 600));
  count("the message the order is keeping is named, with the mailbox it is in and the " +
    "reason it stayed",
    /kept {2}message obj_[0-9a-f]+ in INBOX: legal-hold/.test(erased.stdout),
    erased.stdout.slice(0, 800));
  count("and the operator is told what to do next rather than left with a line that " +
    "only reports",
    /Release the order or obtain the grant/.test(erased.stdout),
    erased.stdout.slice(0, 900));
  // A mailbox row survives anything still bound to it, which is a message
  // the delete path kept here and an annotation the erase would not take
  // elsewhere, so the line names the record rather than the table it is
  // in. It is enumerated above either way, which is where the operator
  // reads which one it was.
  count("the mailbox still holding it keeps its row, and the report says so",
    /1 mailbox still holds a record this erasure could not destroy/.test(erased.stdout),
    erased.stdout.slice(0, 900));

  count("and the report says the account was kept, so the operator is not told the job " +
    "finished when there is a second run still to come",
    /account row was kept/.test(erased.stdout), erased.stdout.slice(0, 900));

  var parsed;
  try {
    parsed = JSON.parse(run(["account", "list", "--json"]).stdout);
  } catch (_e) { parsed = null; }
  var listed = (parsed || []).filter(function (a) { return a.address === HELD_ADDRESS; });
  count("the account is still listed without being asked for, because the record the " +
    "order is keeping is producible only through the identity that owns it",
    listed.length === 1 && listed[0].status === "erasing",
    JSON.stringify(parsed && parsed.map(function (a) { return a.address + ":" + a.status; })));

  // The remediation the erasure printed, taken literally. It is the only
  // route left to the mail the order is keeping, so it has to run rather
  // than answer that there is no such account.
  var again = run(["account", "remove", HELD_ADDRESS, "--destroy",
    "--reason", "finishing the erasure the order held back"]);
  count("running the same command again reaches the account rather than refusing that " +
    "there is no such address, which is what the line above instructs",
    again.status === 0 && /kept {2}message obj_[0-9a-f]+ in INBOX: legal-hold/.test(again.stdout),
    "exit " + again.status + " " + again.both.slice(0, 400));

  var volume = run(["blobs", "report", "--verify"]);
  count("and the volume reader does not call the kept mail unowned, because the erasure " +
    "reported those same rows as preserved and addressable",
    !/no account holds/.test(volume.stdout),
    "exit " + volume.status + " " + volume.stdout.slice(0, 600));
}

async function run() {
  var root    = helpers.tempDir("cli-destructive");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var identity = null;
  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    // Set the fixture up through the library, so a failure here reads as
    // a broken fixture rather than as a failing assertion about a verb.
    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: SPARE });
    await identity.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });

    // A second account holding two messages. Only the mail is planted
    // through the library; the preservation order over one of them is
    // placed at the command line below, because an order an operator
    // cannot place is the defect rather than the fixture.
    var held = await identity.accounts.create({
      address: HELD_ADDRESS, password: ALICE_PASSWORD });
    var holder = {
      id: held.id, address: held.address, domain: held.domain, roles: ["account"] };
    var ordinary = identity.mailbox.appendMessage("INBOX",
      mailFrom("ordinary-mail"), { actor: holder });
    var underOrder = identity.mailbox.appendMessage("INBOX",
      mailFrom("under-order"), { actor: holder });
    count("the fixture account holds two messages before any order is placed",
      typeof ordinary.objectid === "string" && typeof underOrder.objectid === "string",
      underOrder.objectid);

    // A third account holding one message whose INTERNALDATE its client
    // chose. The append is bracketed by two clock readings rather than
    // compared against one taken later, so a run that crosses midnight
    // UTC has both candidate days to match against instead of failing on
    // a boundary nothing to do with the claim.
    var dated = await identity.accounts.create({
      address: DATED_ADDRESS, password: ALICE_PASSWORD });
    var datedHolder = {
      id: dated.id, address: dated.address, domain: dated.domain, roles: ["account"] };
    var seedFrom = Date.now();
    var backdated = identity.mailbox.appendMessage("INBOX",
      mailFrom("client-dated"), { actor: datedHolder, internalDate: CLIENT_DATE_MS });

    // One account holding a message whose subject carries the byte a
    // terminal acts on, so the listing that prints it is driven for
    // real rather than the screen being asserted on its own.
    var escaped = await identity.accounts.create({
      address: ESCAPE_ADDRESS, password: ALICE_PASSWORD });
    //
    // The subject travels as an RFC 2047 encoded word. The store refuses
    // a raw C1 octet in a header at append, and an encoded word is how
    // one arrives from a stranger: it is decoded after that check, so the
    // control reaches the listing.
    identity.mailbox.appendMessage("INBOX",
      mailFrom(encodedWord(ESCAPING_SUBJECT_MARKER + CSI_BYTE + "2K" + CSI_BYTE + "1;31m" +
        TAB_BYTE + "held")),
      { actor: { id: escaped.id, address: escaped.address, domain: escaped.domain,
        roles: ["account"] } });
    var arrivalDays = [isoDay(seedFrom), isoDay(Date.now())].filter(
      function (day, at, all) { return all.indexOf(day) === at; });
    count("the fixture holds a message whose client-set date is years before this run, so " +
      "the two dates on its row cannot be confused for one another",
      typeof backdated.objectid === "string" && arrivalDays.indexOf(CLIENT_DATE) === -1,
      JSON.stringify({ arrival: arrivalDays, client: CLIENT_DATE }));

    // One handle per process on each side, so this one closes before the
    // CLI child opens its own.
    identity.close();
    identity = null;

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    // The DKIM selectors the disable case reads back. `domain add`
    // through the library mints no keys, so the CLI verb does it.
    var minted = cli(["dkim", "generate", "--domain", DOMAIN]);
    count("the fixture domain has signing keys to keep",
      minted.status === 0, "exit " + minted.status + " " + minted.both.slice(0, 160));

    // And the same for the domain the removal case withdraws. Without
    // this the removal runs against the one configuration where the
    // question it is asking cannot arise: a domain with no key material
    // strands none, whatever the verb does with the rows.
    var spareKeys = cli(["dkim", "generate", "--domain", SPARE]);
    count("the domain the removal case withdraws has signing keys to strand",
      spareKeys.status === 0, "exit " + spareKeys.status + " " + spareKeys.both.slice(0, 160));

    removingADomainIsExplicitAndIrreversible(cli, dataDir);
    aDomainCanBeTurnedOffWithoutLosingIt(cli);
    answeringAPreservationOrderAtTheCommandLine(cli, underOrder.objectid);
    theMessageListingSeparatesArrivalFromTheClientsDate(cli, backdated.objectid, arrivalDays);
    theListingPrintsASubjectWithoutCarryingATerminalCommand(cli);
    erasingAnAccountNamesWhatItKept(cli);
    liftingAPreservationOrderAtTheCommandLine(cli, underOrder.objectid);
    await abandoningAQueuedMessageIsCheckedAndRecorded(cli, dataDir);
    await theRecordAndTheRoutingVerdict(cfg);
    aDisabledDomainCanBeTurnedBackOn(cli);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-destructive", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
