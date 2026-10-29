// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `blamepost attachments`, the pass over mail that was filed before this
 * server recorded whether a message carries files.
 *
 * A message records the answer when it is filed, as the IMAP keyword
 * RFC 5788 section 3.1's registry holds for it, and RFC 8621 section
 * 4.1.4's `hasAttachment` is answered from that mark. Mail already on the
 * volume was filed before anything wrote one, so without a verb an
 * operator can run, every message that predates this stays unanswered
 * for as long as the volume lives.
 *
 * `blamepost attachments backfill` drives
 * `blamepost.mail.mailbox.markAttachments` and `blamepost attachments
 * report` drives `blamepost.mail.mailbox.attachmentReport`. Both are
 * exercised through the binary rather than called here, because what has
 * gone wrong on this surface is a flag that is declared and never read
 * and an exit code that reported a refusal as success, and only a
 * spawned process sees either.
 *
 * What is driven:
 *
 *   - The report over a volume whose messages record nothing.
 *   - A run under a limit, which is what turns a volume too large for one
 *     window into several runs, and the report afterwards.
 *   - The rest of the volume, and a second run over the same volume,
 *     which has to be a run that writes nothing.
 *   - A message this server cannot open, which stays unmarked and is
 *     counted apart from the messages the run finished.
 *   - A limit that is not a whole number of messages, refused before the
 *     volume is opened.
 *   - The audit row the run files, read back through the command line.
 *
 * The fixture is built by filing the messages and then taking the marks
 * off through the message store, which is what a volume filed by an
 * earlier build looks like. Nothing else produces one, and asserting
 * against a volume that already records the answer would drive a verb
 * that has nothing to do.
 *
 * Everything here spawns the real binary. The status comes from the
 * spawn, never from a pipeline, because a pipeline reports the last
 * command's status and would make a correct refusal look like success.
 *
 * Run standalone: node test/layer-1-state/cli-attachments.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var ALICE_PASSWORD   = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var ATTACHED = Buffer.from("zebra7741 quarterly totals\n", "utf8");

function headerBlock(id, subject, extra) {
  return "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + ADDRESS + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" + extra;
}

function plainMessage(id) {
  return Buffer.from(headerBlock(id, "an ordinary message",
    "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\nnothing unusual in this one\r\n", "utf8");
}

function filedMessage(id) {
  return Buffer.from(headerBlock(id, "one with a file on it",
    "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe file is on this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"totals.bin\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED.toString("base64") + "\r\n" +
    "--edge--\r\n", "utf8");
}

function oversizeMessage(id) {
  var filler = new Array(1024).join("x");
  var lines = [];
  var wanted = mailbox.MAX_SOURCE_READ_BYTES + b.constants.BYTES.kib(64);
  while (lines.length * (filler.length + 2) < wanted) lines.push(filler);
  return Buffer.from(headerBlock(id, "one too large to open",
    "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\n" + lines.join("\r\n") + "\r\n", "utf8");
}

function answerOf(run) {
  try { return JSON.parse(run.stdout); }
  catch (_e) { return null; }
}

async function run() {
  var root    = helpers.tempDir("cli-attachments");
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

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: ADDRESS, password: ALICE_PASSWORD });
    var actor = { id: alice.id, address: alice.address, domain: alice.domain,
      roles: ["account"] };

    identity.mailbox.appendMessage("INBOX", plainMessage("plain"), { actor: actor });
    identity.mailbox.appendMessage("INBOX", filedMessage("filed"), { actor: actor });
    identity.mailbox.appendMessage("INBOX", oversizeMessage("wide"), { actor: actor });

    var inbox = identity.mailbox.accountFolders({ id: alice.id })
      .filter(function (f) { return f.name === "INBOX"; })[0];
    var rows = identity.messageStore.queryByModseq(inbox.storeName, { sinceModseq: 0 });
    count("the fixture filed three messages", rows.length === 3, String(rows.length));

    // Filing answers for the two this server opens and leaves the third
    // alone, which is the state the backfill below has to reproduce
    // rather than improve on: nothing reads a message above the octet
    // read bound, at filing or afterwards.
    var beforeMarks = identity.mailbox.attachmentReport();
    count("filing recorded the answer for the two messages it could open",
      beforeMarks.present === 1 && beforeMarks.absent === 1 && beforeMarks.unmarked === 1,
      JSON.stringify(beforeMarks));

    // What a volume filed by an earlier build looks like: the messages
    // are there and nothing records what they carry.
    for (var i = 0; i < rows.length; i += 1) {
      identity.messageStore.setFlags(inbox.storeName, [rows[i].objectid], {
        unset: [mailbox.ATTACHMENT_KEYWORDS.present, mailbox.ATTACHMENT_KEYWORDS.absent],
      });
    }
    var stripped = identity.mailbox.attachmentReport();
    count("the fixture volume records nothing about any of them",
      stripped.unmarked === 3 && stripped.present === 0 && stripped.absent === 0,
      JSON.stringify(stripped));

    // One handle per process on each side, so this one closes before the
    // command line opens its own.
    identity.close();
    identity = null;

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    var first = cli(["attachments", "report", "--json"]);
    count("the report runs over a volume that records nothing",
      first.status === 0, first.both.slice(0, 300));
    var firstAnswer = answerOf(first);
    count("and it counts every message as recording neither",
      firstAnswer !== null && firstAnswer.unmarked === 3 && firstAnswer.messages === 3,
      first.stdout.slice(0, 300));

    var told = cli(["attachments", "report"]);
    count("the report sends the operator to the verb that answers for them",
      told.stdout.indexOf("attachments backfill") !== -1, told.both.slice(0, 400));

    // A limit is what turns a volume too large for one window into
    // several runs, so a run under one has to leave the rest reachable
    // rather than reporting a volume that is finished.
    var slice = cli(["attachments", "backfill", "--limit", "1", "--json"]);
    count("a run under a limit is accepted", slice.status === 0, slice.both.slice(0, 300));
    var sliceAnswer = answerOf(slice);
    count("it opens exactly the number of messages the limit named",
      sliceAnswer !== null && sliceAnswer.examined === 1,
      slice.stdout.slice(0, 300));
    count("and says how many it did not reach",
      sliceAnswer !== null && sliceAnswer.remaining === 2,
      slice.stdout.slice(0, 300));

    var midway = answerOf(cli(["attachments", "report", "--json"]));
    count("the volume now records the answer for the message that run reached",
      midway !== null && midway.unmarked === 2, JSON.stringify(midway));

    var rest = cli(["attachments", "backfill", "--json"]);
    count("a run with no limit is accepted", rest.status === 0, rest.both.slice(0, 300));
    var restAnswer = answerOf(rest);
    count("it reaches every message the limited run left",
      restAnswer !== null && restAnswer.examined === 2 && restAnswer.remaining === 0,
      rest.stdout.slice(0, 300));
    // The message above the read bound is the one the run cannot answer
    // for. It stays unmarked, which is what keeps a client from being
    // told it is bare, and it is counted apart from the messages the run
    // finished so an operator is not sent looking for a failure.
    count("the message this server cannot open is counted as unknown rather than marked",
      restAnswer !== null && restAnswer.unknown === 1 && restAnswer.marked === 1,
      rest.stdout.slice(0, 300));
    count("and the operator is told why it was left",
      cli(["attachments", "backfill"]).stdout.indexOf("could not open") !== -1,
      rest.both.slice(0, 400));

    var settled = answerOf(cli(["attachments", "report", "--json"]));
    count("the volume records the answer for every message it could be read for",
      settled !== null && settled.present === 1 && settled.absent === 1 &&
      settled.unmarked === 1,
      JSON.stringify(settled));

    // Running it again is the ordinary case: an operator who does not
    // know whether it finished runs it again.
    var again = answerOf(cli(["attachments", "backfill", "--json"]));
    count("a second run over the same volume writes nothing",
      again !== null && again.marked === 0, JSON.stringify(again));
    count("and it opens only the message nothing has answered for",
      again !== null && again.examined === 1 && again.unknown === 1,
      JSON.stringify(again));

    var zero = cli(["attachments", "backfill", "--limit", "0"]);
    count("a limit of zero messages is refused rather than run",
      zero.status === 2, zero.both.slice(0, 300));
    count("and the refusal says what a limit is",
      zero.both.indexOf("whole number") !== -1, zero.both.slice(0, 300));

    var unread = cli(["attachments", "report", "--limit", "5"]);
    count("a flag the report does not read is refused rather than ignored",
      unread.status === 2, unread.both.slice(0, 300));

    var stray = cli(["attachments", "sweep"]);
    count("a verb this group does not offer prints the usage rather than acting",
      stray.status !== 0 && stray.both.indexOf("Usage: blamepost attachments") !== -1,
      stray.both.slice(0, 300));

    var trail = cli(["audit", "read", "--action",
      "blamepost.mail.mailbox.attachment_marks_recorded", "--limit", "10"]);
    count("the runs are on the audit trail",
      trail.status === 0 &&
      trail.stdout.indexOf("blamepost.mail.mailbox.attachment_marks_recorded") !== -1,
      trail.both.slice(0, 400));

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-attachments", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
