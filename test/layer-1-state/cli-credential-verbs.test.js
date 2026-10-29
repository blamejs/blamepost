// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `credential` verbs, driven through the shipped binary.
 *
 * A sending credential speaks for every local part in one hosted domain,
 * so what is measured here is not whether the registry works. That is
 * measured against the registry. What is measured here is the surface an
 * operator drives, and four things about it are invisible from the
 * module.
 *
 * The secret is printed once. `add` and `rotate` hand back a token that
 * nothing on the volume can return, so a verb that printed something
 * other than the working secret, or that wrote it into an audit row,
 * reads exactly like one that worked. Both tokens are therefore taken off
 * the command's own output and presented to the registry, and the trail
 * is read back to prove neither reached it.
 *
 * The reads answer while the server holds the volume. An operator asking
 * which credentials exist is usually asking during an incident, and being
 * told to stop the mail server first is the wrong instruction at that
 * moment. So the volume is held open in this process while the three
 * reading verbs run.
 *
 * `show` has to report where the bounces actually land. A bounce mailbox
 * archived a month after the credential was created leaves the credential
 * untouched and every bounce refused at the door, so the mailbox is
 * archived mid-run and the same command is asked again.
 *
 * `ceiling` reports across a process boundary. The counters it is named
 * for are held by whichever process is sending, so the window it prints
 * is its own and the account of a running server is the trail. Both
 * halves are driven: one registry spends and gives back a window, which
 * is the shape the submission path has, and the command is then asked
 * what it can see of that from outside. It is also asked while the volume
 * is held, because reading the trail records the read and a read-only
 * handle cannot write that row.
 *
 * And `remove` has to have removed something. The verb's own output is
 * not evidence of that, so the row is read back through an open made
 * after the command exited.
 *
 * Run standalone: node test/layer-1-state/cli-credential-verbs.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b           = require("../../lib/vendor/blamejs");
var config      = require("../../lib/config");
var store       = require("../../lib/store");
var credentials = require("../../lib/store/credentials");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADMIN    = "root@" + DOMAIN;
var BOUNCES  = "mailops@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// A domain nothing hosts, for the refusals that have to arrive before
// anything is written.
var UNHOSTED = "nothosted.example";

// ---- reaching the registry the way a second process would ------------------

// One open, one registry over it, given back together. The registry owns
// a counter cache with a sweep timer on it, so a run that opened one and
// walked away would keep this process alive after its last assertion.
async function withRegistry(cfg, fn) {
  var handle = await store.open(cfg);
  var registry = credentials.create({
    domains:  handle.domains,
    accounts: handle.accounts,
    aliases:  handle.aliases,
    resolve:  handle.resolve,
  });
  try { return await fn(registry, handle); }
  finally {
    registry.close();
    handle.close();
  }
}

// The structured answer a verb printed, or null when it printed something
// that is not one. Every assertion that reads a field goes through this,
// so a command that failed produces a named absence rather than a
// TypeError halfway down the file.
function structured(result) {
  try { return JSON.parse(result.stdout); }
  catch (_e) { return null; }
}

// ---- the reason every changing verb records --------------------------------

// A credential can send as every address in a hosted domain, so each verb
// that changes one is an operator action the trail has to answer for. A
// verb that quietly accepted an absent reason writes a row naming a
// change with no account of why it happened.
function everyChangingVerbRefusesWithoutARecordedReason(run, id) {
  var lines = [
    { label: "credential add",
      argv: ["credential", "add", DOMAIN, "--bounce-to", BOUNCES] },
    { label: "credential rotate",   argv: ["credential", "rotate", id] },
    { label: "credential revoke",   argv: ["credential", "revoke", id] },
    { label: "credential remove",   argv: ["credential", "remove", id, "--destroy"] },
    { label: "credential refusals",
      argv: ["credential", "refusals", id, "--local-part", "postmaster"] },
  ];
  lines.forEach(function (entry) {
    var said = run(entry.argv);
    count("`" + entry.label + "` refuses without --reason rather than changing a credential " +
      "nobody can account for",
      said.status === 2, "exit " + said.status + " " + said.both.slice(0, 200));
    count("and the refusal names the flag it wants",
      /give --reason/.test(said.both), said.both.slice(0, 240));
  });
}

// ---- what add checks before it writes --------------------------------------

function addChecksItsArgumentsBeforeItWrites(run) {
  var noMailbox = run(["credential", "add", DOMAIN,
    "--reason", "the notifications application sends for this domain"]);
  count("`credential add` refuses without --bounce-to", noMailbox.status === 2,
    "exit " + noMailbox.status + " " + noMailbox.both.slice(0, 240));
  count("and says why a credential with nowhere to put its bounces is refused",
    /bounce/i.test(noMailbox.both), noMailbox.both.slice(0, 300));

  var notHosted = run(["credential", "add", UNHOSTED, "--bounce-to", BOUNCES,
    "--reason", "a domain this server does not answer for"]);
  count("a domain this server does not host is refused", notHosted.status !== 0,
    "exit " + notHosted.status + " " + notHosted.both.slice(0, 240));
  count("and the refusal names the domain", notHosted.both.indexOf(UNHOSTED) !== -1,
    notHosted.both.slice(0, 300));

  var noSuchMailbox = run(["credential", "add", DOMAIN,
    "--bounce-to", "nobody@" + DOMAIN,
    "--reason", "naming a mailbox that is not there"]);
  count("a bounce mailbox with no account behind it is refused rather than created",
    noSuchMailbox.status !== 0,
    "exit " + noSuchMailbox.status + " " + noSuchMailbox.both.slice(0, 240));
  count("and the refusal names the address that has no mailbox",
    noSuchMailbox.both.indexOf("nobody@" + DOMAIN) !== -1, noSuchMailbox.both.slice(0, 300));

  var badWindow = run(["credential", "add", DOMAIN, "--bounce-to", BOUNCES,
    "--window-minutes", "4000",
    "--reason", "a window wider than the registry accepts"]);
  count("a rolling window outside the bounds is refused at the argument",
    badWindow.status === 2, "exit " + badWindow.status + " " + badWindow.both.slice(0, 240));
}

// ---- the token, printed once -----------------------------------------------

// The one moment the secret is readable, and the two things that have to
// be true about it: the value printed is the value that verifies, and it
// is nowhere on the volume afterwards.
async function addPrintsATokenThatVerifies(run, cfg) {
  var said = run(["credential", "add", DOMAIN, "--bounce-to", BOUNCES,
    "--reason", "the notifications application sends for this domain"]);
  count("`credential add` issues a credential", said.status === 0,
    "exit " + said.status + " " + said.both.slice(0, 400));
  count("and the operator is told the token is printed once and cannot be read back",
    /cannot be recovered|printed once/i.test(said.both), said.both.slice(0, 500));
  count("and told where it is exposed, which is this terminal and its scrollback",
    /scrollback/i.test(said.both), said.both.slice(0, 500));
  count("and told which verb answers a token that has been lost",
    said.both.indexOf("blamepost credential rotate") !== -1, said.both.slice(0, 600));

  var asJson = run(["credential", "add", DOMAIN, "--bounce-to", BOUNCES,
    "--reason", "a second application on the same domain", "--json"]);
  var made = structured(asJson);
  count("the structured form carries the token as well, so a provisioning run can read it",
    made !== null && typeof made.token === "string" && made.token.length > 0,
    asJson.stdout.slice(0, 200).replace(/[0-9a-f]{8,}/g, "x"));
  count("and it carries the return path to put in the envelope sender",
    made !== null && typeof made.returnPath === "string" &&
      made.returnPath.indexOf("@" + DOMAIN) !== -1,
    made === null ? "no answer" : String(made.returnPath));

  var verdict = await withRegistry(cfg, function (registry) {
    return registry.verify(made === null ? "" : made.token);
  });
  count("the token the verb printed is the token that verifies",
    verdict.ok === true, verdict.reason || "ok");
  count("and it comes back scoped to the domain it was issued for",
    verdict.domain === DOMAIN, String(verdict.domain));
  count("and to the bounce mailbox the operator named",
    verdict.bounceMailbox === BOUNCES, String(verdict.bounceMailbox));

  return made === null ? null : made;
}

function theTrailCarriesTheChangeAndNotTheToken(run, action, reason, token) {
  var read = run(["audit", "read", "--action", action, "--limit", "5", "--json"]);
  count("`" + action + "` is on the audit trail",
    read.status === 0 && read.stdout.indexOf(action) !== -1,
    "exit " + read.status + " " + read.stdout.slice(0, 300));
  count("and the row carries the reason the operator gave",
    read.stdout.indexOf(reason) !== -1, read.stdout.slice(0, 400));
  count("and carries no token",
    token.length > 0 && read.stdout.indexOf(token) === -1,
    "checked " + read.stdout.length + " character(s)");
}

// ---- what show reports about the bounces -----------------------------------

// The failure creation cannot find. Nothing about the credential changes
// when its bounce mailbox is archived, so resolving the return path on
// every read is the only thing that reports it, and an operator who is
// not told keeps an application sending while every bounce is refused at
// the door.
function showReportsWhereTheBouncesActuallyLand(run, id) {
  var healthy = structured(run(["credential", "show", id, "--json"]));
  count("`credential show` reports a live return path as deliverable",
    healthy !== null && healthy.returnPathDeliverable === true,
    JSON.stringify(healthy && healthy.returnPathReason));
  count("and names the mailbox it reaches",
    healthy !== null && Array.isArray(healthy.returnPathDeliversTo) &&
      healthy.returnPathDeliversTo.indexOf(BOUNCES) !== -1,
    JSON.stringify(healthy && healthy.returnPathDeliversTo));

  var archived = run(["account", "remove", BOUNCES,
    "--reason", "the mailbox owner moved on"]);
  count("the bounce mailbox can be archived out from under the credential",
    archived.status === 0, "exit " + archived.status + " " + archived.both.slice(0, 240));

  var broken = structured(run(["credential", "show", id, "--json"]));
  count("`credential show` then reports the return path as not deliverable",
    broken !== null && broken.returnPathDeliverable === false,
    JSON.stringify(broken && broken.returnPathReason));
  count("and the credential itself is untouched, which is why nothing else reports this",
    broken !== null && broken.bounceMailbox === BOUNCES, String(broken && broken.bounceMailbox));

  var text = run(["credential", "show", id]);
  count("the text an operator reads says the bounces are not arriving",
    /not (reaching|arriving|deliverable)|no deliverable/i.test(text.stdout),
    text.stdout.slice(0, 600));

  var report = structured(run(["credential", "bounces", DOMAIN, "--json"]));
  count("`credential bounces` lists the credential whose bounces stopped arriving",
    report !== null && Array.isArray(report.unreachable) &&
      report.unreachable.some(function (entry) { return entry.credentialId === id; }),
    JSON.stringify(report && report.unreachable).slice(0, 300));

  var back = run(["account", "resume", BOUNCES]);
  count("and the mailbox goes back into service, leaving the run as this case found it",
    back.status === 0, "exit " + back.status + " " + back.both.slice(0, 240));

  var mended = structured(run(["credential", "bounces", DOMAIN, "--json"]));
  count("after which nothing is reported unreachable",
    mended !== null && Array.isArray(mended.unreachable) && mended.unreachable.length === 0,
    JSON.stringify(mended && mended.unreachable).slice(0, 300));
}

// ---- the reads answer while the server holds the volume --------------------

async function theReadingVerbsAnswerFromASnapshot(run, cfg, id) {
  var held = await store.open(cfg);
  try {
    // The encrypted file has to carry the credential before a read-only
    // open can find it. A running server flushes periodically; this is
    // that flush, so the copy the child takes is one a real operator
    // would get.
    b.db.flushToDisk();

    [["credential", "list", DOMAIN],
      ["credential", "show", id],
      ["credential", "bounces", DOMAIN]].forEach(function (argv) {
      var result = run(argv);
      var label = argv.join(" ");
      count("`" + label + "` is not refused as a second opener",
        !/already open|store\/volume-in-use/i.test(result.both), result.both.slice(0, 300));
      count("`" + label + "` answers while the server holds the volume",
        result.status === 0, "exit " + result.status + " " + result.both.slice(0, 300));
      count("and the answer says it came off a copy rather than reading as a current one",
        /snapshot/i.test(result.both), result.both.slice(0, 300));
    });

    var listed = run(["credential", "list", DOMAIN]);
    count("`credential list` answers with the credential that is on the volume",
      listed.both.indexOf(id) !== -1, listed.both.slice(0, 400));

    var asJson = structured(run(["credential", "list", DOMAIN, "--json"]));
    count("the structured answer carries the snapshot marker, so automation reads it too",
      asJson !== null && asJson.snapshot !== null && typeof asJson.snapshot === "object",
      JSON.stringify(asJson).slice(0, 300));

    // The credential read off the copy is a readable one. Exiting zero
    // is not that: a record whose keyed binding cannot be checked comes
    // back with every policy field null and prints as a credential this
    // server cannot speak for, which is also an exit of zero. The
    // binding is computed under a vault-sealed key, so this is the
    // assertion that the key is open on a read-only handle.
    var shown = structured(run(["credential", "show", id, "--json"]));
    var record = shown === null ? null : shown.result;
    count("and the credential read off the copy is readable there rather than reported as " +
      "one whose stored policy cannot be checked",
      record !== null && record !== undefined && record.bindingHolds === true &&
        record.domain === DOMAIN,
      JSON.stringify(shown).slice(0, 400));
    count("and the return path reading is resolved off the copy as well",
      record !== null && record !== undefined && record.returnPathDeliverable === true,
      JSON.stringify(record && record.returnPathReason));

    // The other half. A verb that changes a credential must still meet
    // the wall, or the reads above would be evidence of nothing.
    var changed = run(["credential", "revoke", id,
      "--reason", "checking that a change still refuses"]);
    count("a verb that changes a credential still refuses while the volume is held",
      changed.status !== 0 && /already open|open for writing/i.test(changed.both),
      "exit " + changed.status + " " + changed.both.slice(0, 300));
  } finally {
    held.close();
  }
}

// ---- what the ceiling verb can and cannot see ------------------------------

// The two ceilings are enforced in the process that is sending, and this
// verb runs in a different one. So what it has to get right is the line
// between the two: the window it prints is its own, and the account of a
// running server is the trail.
//
// The window is spent and given back through ONE registry here, which is
// the shape the submission path has. Two registries in one process hold
// two windows and neither reaches the ceiling the operator set, so a case
// that opened a second one to check the first would measure nothing.
async function ceilingReportsTheCeilingsAndWhatTheTrailRecorded(run, cfg, id) {
  var spent = await withRegistry(cfg, async function (registry) {
    var first = await registry.counters.record({ id: id, recipients: 4 });
    var second = await registry.counters.record({ id: id, recipients: 6 });
    var readBack = await registry.counters.read(id);
    var released = await registry.counters.release({
      id: id, reason: "the send was a legitimate announcement" });
    var afterRelease = await registry.counters.read(id);
    await b.audit.flush();
    b.db.flushToDisk();
    return { first: first, second: second, readBack: readBack,
      released: released, afterRelease: afterRelease };
  });

  count("the window the submission path spends is the window counters.read answers about",
    spent.readBack.messages === 2 && spent.readBack.recipients === 10,
    JSON.stringify({ m: spent.readBack.messages, r: spent.readBack.recipients }));
  count("and the second record sees the first, so one registry holds one window",
    spent.second.messages === 2, String(spent.second.messages));
  count("releasing it through that same registry puts both counts back to zero",
    spent.afterRelease.messages === 0 && spent.afterRelease.recipients === 0,
    JSON.stringify({ m: spent.afterRelease.messages, r: spent.afterRelease.recipients }));
  count("and the release reports the cleared window rather than the one it found",
    spent.released.messages === 0 && spent.released.exceeded === false,
    JSON.stringify({ m: spent.released.messages, e: spent.released.exceeded }));

  var text = run(["credential", "ceiling", id]);
  count("`credential ceiling` answers", text.status === 0,
    "exit " + text.status + " " + text.both.slice(0, 400));
  count("and names the two ceilings the credential carries",
    /ceilings:\s+\d+ message\(s\) and \d+ recipient\(s\)/.test(text.stdout),
    text.stdout.slice(0, 500));
  count("and says the window it printed is this process's rather than the sending one's",
    /this process's|next start begins/i.test(text.stdout), text.stdout.slice(0, 800));
  count("and reports the release the trail recorded",
    /window given back/i.test(text.stdout), text.stdout.slice(0, 900));
  count("and carries the reason the operator gave for it",
    text.stdout.indexOf("the send was a legitimate announcement") !== -1,
    text.stdout.slice(0, 900));

  var structuredAnswer = structured(run(["credential", "ceiling", id, "--json"]));
  count("the structured answer carries the reading",
    structuredAnswer !== null && structuredAnswer.reading !== undefined &&
      structuredAnswer.reading.credentialId === id,
    JSON.stringify(structuredAnswer && structuredAnswer.reading).slice(0, 300));
  count("and the window it reports is empty, because the counters died with the process " +
    "that held them",
    structuredAnswer !== null && structuredAnswer.reading.messages === 0 &&
      structuredAnswer.reading.recipients === 0,
    JSON.stringify(structuredAnswer && structuredAnswer.reading).slice(0, 300));
  count("and it carries the released rows separately from the crossings, because an " +
    "operator acts differently on each",
    structuredAnswer !== null && Array.isArray(structuredAnswer.released) &&
      structuredAnswer.released.length >= 1 && Array.isArray(structuredAnswer.reached),
    JSON.stringify(structuredAnswer && {
      released: (structuredAnswer.released || []).length,
      reached:  (structuredAnswer.reached || []).length,
    }));
  count("and no message was refused on this credential, so the crossings read as none",
    structuredAnswer !== null && structuredAnswer.reached.length === 0,
    JSON.stringify(structuredAnswer && structuredAnswer.reached).slice(0, 300));
  count("which the text says rather than printing an empty list",
    /No message has been refused/i.test(text.stdout), text.stdout.slice(0, 900));

  var unknown = run(["credential", "ceiling", "0123456789abcdef"]);
  count("an identifier no credential on this volume carries is refused rather than " +
    "answered about with zeros", unknown.status !== 0,
    "exit " + unknown.status + " " + unknown.both.slice(0, 300));
  count("and the refusal says there is no such credential",
    /no sending credential/i.test(unknown.both), unknown.both.slice(0, 400));

  var badLimit = run(["credential", "ceiling", id, "--limit", "0"]);
  count("--limit outside the bounds is refused at the argument", badLimit.status === 2,
    "exit " + badLimit.status + " " + badLimit.both.slice(0, 300));
  count("and the refusal names the bounds in rows rather than in anything else",
    /--limit takes a whole number of rows/.test(badLimit.both), badLimit.both.slice(0, 300));

  var oneRow = structured(run(["credential", "ceiling", id, "--limit", "1", "--json"]));
  count("--limit is read rather than accepted and dropped",
    oneRow !== null && Array.isArray(oneRow.released) && oneRow.released.length === 1,
    JSON.stringify(oneRow && (oneRow.released || []).length));
}

// A crossing is filed by the submission listener, which this layer does
// not bind, so the row is written here in the shape that listener writes
// and the reading verb is asked what it makes of it. What is measured is
// the READER: that it finds a crossing among unrelated rows, matches it
// on the identifier the row carries rather than on the actor, and names
// which of the two ceilings was crossed. That the listener writes such a
// row when a message is refused is the other half and belongs against a
// listener.
//
// A row missing the counts is written beside it, because the field names
// are spelled in the layer that files the row and again in the layer that
// reads it. Two spellings that drift leave a reading that prints the word
// `undefined` beside a real moment, and an operator cannot tell that from
// a message that really was sent an undefined number of times.
async function ceilingRendersACrossingTheTrailCarries(run, cfg, id) {
  var handle = await store.open(cfg);
  try {
    b.audit.registerNamespace("blamepost");
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_ceiling_reached",
      outcome:  "denied",
      actor:    { userId: id },
      metadata: {
        credentialId:       id,
        scopeDomain:        DOMAIN,
        messages:           200,
        recipients:         617,
        maxMessages:        200,
        maxRecipients:      5000,
        windowMs:           3600000,
        messagesExceeded:   true,
        recipientsExceeded: false,
      },
    });
    // A crossing on somebody else's credential, so the match is measured
    // rather than assumed: a reader that filtered on nothing would report
    // this one against the credential being asked about.
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_ceiling_reached",
      outcome:  "denied",
      actor:    { userId: "ffffffffffffffff" },
      metadata: { credentialId: "ffffffffffffffff", scopeDomain: DOMAIN,
        messages: 1, recipients: 1, maxMessages: 1, maxRecipients: 1 },
    });
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_ceiling_reached",
      outcome:  "denied",
      actor:    { userId: id },
      metadata: { credentialId: id, scopeDomain: DOMAIN },
    });
    await b.audit.flush();
    b.db.flushToDisk();
  } finally {
    handle.close();
  }

  var answer = structured(run(["credential", "ceiling", id, "--json"]));
  count("`credential ceiling` finds the crossings the trail holds for this credential",
    answer !== null && Array.isArray(answer.reached) && answer.reached.length === 2,
    JSON.stringify(answer && (answer.reached || []).length));

  var text = run(["credential", "ceiling", id]);
  count("and the text names which of the two ceilings was crossed",
    /message ceiling/.test(text.stdout), text.stdout.slice(0, 1200));
  count("and quotes what had been sent against what was allowed",
    /sent 200 message\(s\) to 617 recipient\(s\) against ceilings of 200 and 5000/
      .test(text.stdout), text.stdout.slice(0, 1200));
  count("and no crossing on another credential is reported against this one",
    text.stdout.indexOf("ffffffffffffffff") === -1, text.stdout.slice(0, 1200));
  count("a row carrying no counts prints as counts nobody recorded rather than as the word " +
    "undefined", /an unrecorded number of message\(s\)/.test(text.stdout) &&
      text.stdout.indexOf("undefined") === -1, text.stdout.slice(0, 1200));
  count("and the operator is told a crossing defers the message rather than losing it",
    /452 4\.5\.3/.test(text.stdout) && /429/.test(text.stdout), text.stdout.slice(0, 1400));
  count("and pointed at the verb that answers a credential crossing a ceiling it never used " +
    "to reach", text.stdout.indexOf("blamepost credential rotate " + id) !== -1,
    text.stdout.slice(0, 1400));
}

// The other half of the line the verb draws. Reading the trail files a
// row before the answer comes back, a read-only handle cannot write one,
// and a read that claims to be recorded and is not is worse than a read
// that refuses. So this verb is deliberately not among the three that
// answer off a copy, and that has to be measured rather than assumed:
// adding it to that set would look exactly like this file passing.
async function ceilingIsNotOneOfTheVerbsThatAnswerOffACopy(run, cfg, id) {
  var held = await store.open(cfg);
  try {
    b.db.flushToDisk();
    var result = run(["credential", "ceiling", id]);
    count("`credential ceiling` refuses while the server holds the volume rather than " +
      "answering off a copy it cannot record the read against",
      result.status !== 0 && /already open|open for writing|volume-in-use/i.test(result.both),
      "exit " + result.status + " " + result.both.slice(0, 400));
  } finally {
    held.close();
  }
}

// ---- revoke keeps the row, remove takes it ---------------------------------

async function revokeKeepsTheRowAndRemoveTakesIt(run, cfg, id) {
  var unasked = run(["credential", "remove", id,
    "--reason", "trying to erase without saying so"]);
  count("`credential remove` refuses without --destroy", unasked.status === 2,
    "exit " + unasked.status + " " + unasked.both.slice(0, 240));
  count("and the refusal names revoke, which is the answer almost every time",
    unasked.both.indexOf("blamepost credential revoke") !== -1, unasked.both.slice(0, 400));

  var revoked = run(["credential", "revoke", id,
    "--reason", "the application was decommissioned"]);
  count("`credential revoke` stops the credential", revoked.status === 0,
    "exit " + revoked.status + " " + revoked.both.slice(0, 300));

  var afterRevoke = await withRegistry(cfg, function (registry) {
    return registry.show(id);
  });
  count("and the row stays, so the identifier on an earlier audit row still resolves",
    afterRevoke !== null && afterRevoke.id === id,
    afterRevoke === null ? "the row is gone" : afterRevoke.id);
  count("with the moment it was revoked recorded on it",
    afterRevoke !== null && typeof afterRevoke.revokedAt === "number",
    JSON.stringify(afterRevoke && afterRevoke.revokedAt));

  var removed = run(["credential", "remove", id, "--destroy",
    "--reason", "the operator asked for erasure"]);
  count("`credential remove --destroy` takes the row off the volume", removed.status === 0,
    "exit " + removed.status + " " + removed.both.slice(0, 300));
  count("and says what became of the domain's shared return path alias",
    /return path/i.test(removed.stdout), removed.stdout.slice(0, 400));

  // Read back through an open made after the command exited. The verb's
  // own output says what it believes it did, which is the one thing that
  // cannot answer whether the row is still there.
  var afterRemove = await withRegistry(cfg, function (registry) {
    return registry.show(id);
  });
  count("the row really is gone, read back through a fresh open rather than off the verb",
    afterRemove === null, JSON.stringify(afterRemove));
}

// ---- rotation --------------------------------------------------------------

async function rotationReplacesTheSecret(run, cfg) {
  var made = structured(run(["credential", "add", DOMAIN, "--bounce-to", BOUNCES,
    "--reason", "a credential to rotate", "--json"]));
  count("there is a credential to rotate", made !== null && typeof made.id === "string",
    made === null ? "no answer" : made.id);
  var id = made === null ? "" : made.id;

  var tooLong = run(["credential", "rotate", id, "--grace-hours", "400",
    "--reason", "a grace window longer than the registry accepts"]);
  count("a grace window past the ceiling is refused at the argument",
    tooLong.status === 2, "exit " + tooLong.status + " " + tooLong.both.slice(0, 240));

  var rotated = structured(run(["credential", "rotate", id,
    "--reason", "the token reached a place it should not have", "--json"]));
  count("`credential rotate` hands back a new token",
    rotated !== null && typeof rotated.token === "string" && rotated.token !== made.token,
    rotated === null ? "no answer" : "a new token");

  var afterHardCutover = await withRegistry(cfg, async function (registry) {
    return {
      old: await registry.verify(made.token),
      now: await registry.verify(rotated === null ? "" : rotated.token),
    };
  });
  count("the new token verifies", afterHardCutover.now.ok === true,
    afterHardCutover.now.reason || "ok");
  count("and the old one stops working immediately, because rotation names no window by " +
    "default", afterHardCutover.old.ok === false, String(afterHardCutover.old.reason));

  var withGrace = structured(run(["credential", "rotate", id, "--grace-hours", "1",
    "--reason", "a migration window the operator asked for", "--json"]));
  count("a rotation may name a window explicitly",
    withGrace !== null && typeof withGrace.priorSecretUntil === "number",
    JSON.stringify(withGrace && withGrace.priorSecretUntil));

  var duringGrace = await withRegistry(cfg, async function (registry) {
    return {
      prior: await registry.verify(rotated.token),
      now:   await registry.verify(withGrace === null ? "" : withGrace.token),
    };
  });
  count("the prior secret keeps working inside the window it named",
    duringGrace.prior.ok === true, String(duringGrace.prior.reason));
  count("and a verdict produced by it says so, so an operator can see whether the " +
    "application has finished migrating",
    duringGrace.prior.usedPriorSecret === true, String(duringGrace.prior.usedPriorSecret));
  count("the new secret works as well", duringGrace.now.ok === true,
    String(duringGrace.now.reason));

  return id;
}

// ---- the refusal list ------------------------------------------------------

async function refusalsNeedsALocalPartOrAnExplicitClear(run, cfg, id) {
  var neither = run(["credential", "refusals", id,
    "--reason", "changing what this credential may write as"]);
  count("`credential refusals` refuses when it is given no list at all",
    neither.status === 2, "exit " + neither.status + " " + neither.both.slice(0, 240));
  count("and the refusal names both ways of giving one",
    neither.both.indexOf("--local-part") !== -1 && neither.both.indexOf("--clear") !== -1,
    neither.both.slice(0, 400));

  var unconfirmed = run(["credential", "refusals", id, "--clear",
    "--reason", "letting it write as every address"]);
  count("clearing the list refuses without --confirm, because what it opens up is not on " +
    "the command line",
    unconfirmed.status === 2, "exit " + unconfirmed.status + " " + unconfirmed.both.slice(0, 240));
  count("and the refusal says what a cleared list leaves the credential able to write as",
    /every (local part|address)/i.test(unconfirmed.both), unconfirmed.both.slice(0, 400));

  var narrowed = run(["credential", "refusals", id,
    "--local-part", "postmaster", "--local-part", "abuse",
    "--reason", "keeping the two a recipient writes to for a person"]);
  count("naming the complete new list is accepted", narrowed.status === 0,
    "exit " + narrowed.status + " " + narrowed.both.slice(0, 300));

  var afterNarrowing = await withRegistry(cfg, function (registry) {
    return registry.show(id);
  });
  count("and the volume holds exactly the list that was named",
    afterNarrowing !== null &&
      afterNarrowing.refusedLocalParts.join(",") === "abuse,postmaster",
    JSON.stringify(afterNarrowing && afterNarrowing.refusedLocalParts));

  var cleared = run(["credential", "refusals", id, "--clear", "--confirm",
    "--reason", "this credential answers the postmaster notices itself"]);
  count("clearing it with --confirm is accepted", cleared.status === 0,
    "exit " + cleared.status + " " + cleared.both.slice(0, 300));

  var afterClearing = await withRegistry(cfg, function (registry) {
    return registry.show(id);
  });
  count("and the list on the volume is empty, which is not the same as a credential with " +
    "no readable list at all",
    afterClearing !== null && Array.isArray(afterClearing.refusedLocalParts) &&
      afterClearing.refusedLocalParts.length === 0 && afterClearing.bindingHolds === true,
    JSON.stringify(afterClearing && afterClearing.refusedLocalParts));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-credential-verbs");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

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

    var seeded = await store.open(cfg);
    await seeded.domains.add({ domain: DOMAIN });
    await seeded.accounts.create({
      address: ADMIN, password: ACCOUNT_PASSWORD, isAdmin: true });
    await seeded.accounts.create({ address: BOUNCES, password: ACCOUNT_PASSWORD });
    seeded.close();

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    addChecksItsArgumentsBeforeItWrites(cli);

    var made = await addPrintsATokenThatVerifies(cli, cfg);
    var id = made === null ? "0000000000000000" : made.id;
    var token = made === null ? "" : made.token;

    everyChangingVerbRefusesWithoutARecordedReason(cli, id);
    theTrailCarriesTheChangeAndNotTheToken(cli, "domain.sending_credential_created",
      "the notifications application sends for this domain", token);

    showReportsWhereTheBouncesActuallyLand(cli, id);
    await theReadingVerbsAnswerFromASnapshot(cli, cfg, id);

    await ceilingReportsTheCeilingsAndWhatTheTrailRecorded(cli, cfg, id);
    await ceilingRendersACrossingTheTrailCarries(cli, cfg, id);
    await ceilingIsNotOneOfTheVerbsThatAnswerOffACopy(cli, cfg, id);

    var rotatedId = await rotationReplacesTheSecret(cli, cfg);
    await refusalsNeedsALocalPartOrAnExplicitClear(cli, cfg, rotatedId);

    await revokeKeepsTheRowAndRemoveTakesIt(cli, cfg, id);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-credential-verbs", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
