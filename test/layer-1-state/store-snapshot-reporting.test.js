// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an operator can still ask while the server is running.
 *
 * One process WRITES the data volume at a time, because the second
 * writer destroys mail: the database is encrypted at rest, so each
 * writer decrypts the whole file into a working copy of its own and
 * writes that copy back over the encrypted file, and whichever writes
 * last overwrites everything the other stored. The refusal that closes
 * that hole is not in question here.
 *
 * Its cost is. `account list`, `domain list`, `dkim list` and `doctor`
 * report rather than change, and all four had to be refused because all
 * four opened the volume to read it. `doctor` is the one that hurts: the
 * moment an operator most wants it is while the server is up and
 * behaving oddly.
 *
 * So a verb that only reports opens the volume read-only instead. That
 * open decrypts a working copy of its own, never writes the encrypted
 * file, never re-seals the database key, never anchors a checkpoint and
 * never advances the record beside the volume, and the database handle
 * itself refuses a write wherever one is issued. The running server
 * never learns it happened: no lock is taken, nothing on the volume is
 * written, and the decrypted copy is gone before the command exits.
 *
 * Four things have to hold for that to be worth having, and each is a
 * case below.
 *
 * The answer is old, and it says so. It is the volume as it was at the
 * server's last flush to disk, which is a measured moment rather than an
 * estimate, and it is reported in the text an operator reads AND in the
 * JSON a script parses. A quietly stale `doctor` is worse than a
 * `doctor` that refuses.
 *
 * The answer is not a moving target. The copy is decrypted once, at the
 * open, and every query is served from it, so a writer committing in the
 * middle of a long report cannot move the rows underneath it. What comes
 * back is one moment of the volume rather than a blend of several.
 *
 * The volume is untouched, byte for byte, and that includes the record
 * the framework keeps beside it of where the audit chain was last
 * anchored. Advancing that record from a copy is not a cosmetic fault:
 * the counter it names would have been flushed only into the copy, so a
 * server killed before its next flush comes back to a volume that
 * refuses to open at all.
 *
 * And a verb whose read is itself recorded does not qualify, however
 * plainly it reports. `audit read` and `account sieve` both write a row
 * saying they ran; a read-only handle cannot write it, and a read that
 * claims to be recorded and is not is worse than a read that refuses.
 *
 * `blobs report` is the case that had to change rather than be listed.
 * It holds the sealed bodies on the live disk against the rows that name
 * them, so against rows frozen at the last flush every message that has
 * arrived since would read as a body nothing references. That is a wrong
 * answer rather than an old one. The rows carry the moment they were
 * frozen, so a body newer than that moment is reported as one the rows
 * had not reached rather than as unreferenced, and the digest check that
 * finds an altered body is unaffected either way.
 *
 * Everything here spawns the real binary. The status comes from the
 * spawn, never from a pipeline, because a pipeline reports the last
 * command's status and would make a refusal read as success.
 *
 * Run standalone: node test/layer-1-state/store-snapshot-reporting.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The verbs that read the database, report what they found, and record
// nothing. Every one of them answers from a read-only open while the
// server holds the volume.
//
// `blobs report` and `audit verify-chain` are here rather than among the
// refusals below, and both are load-bearing. Their exit status is their
// verdict, so an exit of zero here is the assertion that each reached
// one: `blobs report` must not count the body that arrived after the
// last flush as unreferenced, and `audit verify-chain` must be able to
// verify the checkpoint signatures rather than skipping them.
var REPORTING_VERBS = [
  ["account", "list"],
  ["account", "show", ADDRESS],
  ["domain", "list"],
  ["domain", "show", DOMAIN],
  ["dkim", "list", DOMAIN],
  ["dkim", "records", DOMAIN],
  ["blobs", "report", "--verify"],
  ["audit", "verify-chain"],
];

// `doctor` is separated only because it resolves DNS and so is the slow
// one, not because the rule treats it differently. It is the whole
// reason this exists.
var DOCTOR = ["doctor", "--domain", DOMAIN];

// Verbs that read and still refuse, each for its own reason. Grouping
// them here is the point: "it only reads" is not the test.
//
// `backup run` needs a storage directory and a passphrase file that
// exist, because both are read before a store is opened and a missing
// one would refuse for the wrong reason entirely.
function stillRefused(paths) {
  return [
    // Documented as itself recorded. A read-only handle cannot write
    // that row, and a read that claims to be recorded and is not is
    // worse than a read that refuses.
    { verb: ["audit", "read"], because: "the read is recorded" },
    {
      verb: ["account", "sieve", ADDRESS, "--reason", "checking a delivery complaint"],
      because: "the read is recorded",
    },
    // Writes before it copies: it anchors the chain so the bundle can
    // carry a signature over its own last row, and it requires the
    // volume flushed so the bundle is not older than the database it
    // claims to be. Neither is available to a handle that will not
    // write.
    {
      verb: ["backup", "run", "--storage", paths.backupDir,
        "--passphrase-file", paths.passphraseFile],
      because: "it anchors the trail and flushes the volume before it copies anything",
    },
  ];
}

// Verbs that change something. The rule is about what has to outlive the
// process, and a mutation always does.
var MUTATING_VERBS = [
  ["domain", "add", "second.example"],
  ["account", "suspend", ADDRESS, "--reason", "testing the refusal"],
  ["blobs", "reclaim", "--confirm", "--reason", "clearing stranded octets"],
];

function message(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: " + ADDRESS + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "The body of " + subject + ".\r\n", "utf8");
}

// The counter the volume's own record says its audit chain was last
// anchored at. It is read as a number as well as a digest because the
// direction matters: a copy that advances it names a counter that was
// written into the copy and never into the volume, and a server killed
// before its next flush then comes back to a database the rollback check
// refuses to open.
function anchorCounter(dataDir) {
  var anchorPath = nodePath.join(dataDir, "audit.tip");
  if (!nodeFs.existsSync(anchorPath)) return 0;
  try { return Number(JSON.parse(nodeFs.readFileSync(anchorPath, "utf8")).atMonotonicCounter); }
  catch (_e) { return 0; }
}

// A file as a digest, so "was it written" is a fact about bytes rather
// than about a timestamp a filesystem may round.
function digestOf(filePath) {
  if (!nodeFs.existsSync(filePath)) return "<absent>";
  return nodeCrypto.createHash("sha512").update(nodeFs.readFileSync(filePath)).digest("hex");
}

// Every file on the data volume, by name and by content. Naming two
// files and checking those would prove only what was thought of: the
// volume also holds the sealed DKIM keys, the vault's own key material,
// the audit signing key and the lock the server is holding, and a
// reporting verb has no business writing any of them.
function volumeDigest(dataDir) {
  var running = nodeCrypto.createHash("sha512");
  var stack = [{ dir: dataDir, prefix: "" }];
  var listing = [];
  while (stack.length > 0) {
    var here = stack.pop();
    var entries;
    try { entries = nodeFs.readdirSync(here.dir, { withFileTypes: true }); }
    catch (_e) { continue; }
    for (var i = 0; i < entries.length; i += 1) {
      var name = (here.prefix ? here.prefix + "/" : "") + entries[i].name;
      var full = nodePath.join(here.dir, entries[i].name);
      if (entries[i].isDirectory()) {
        stack.push({ dir: full, prefix: name });
        continue;
      }
      listing.push({ name: name, digest: digestOf(full) });
    }
  }
  listing.sort(function (a, z) { return a.name < z.name ? -1 : 1; });
  listing.forEach(function (entry) { running.update(entry.name + "\0" + entry.digest + "\0"); });
  return { digest: running.digest("hex"), files: listing.length };
}

// Everything under the shared memory backed directory, at any depth. A
// private copy is a directory inside it, so a scan that only listed the
// top level would report a decrypted database as cleaned up.
function everythingUnder(root, prefix, into) {
  var entries;
  try { entries = nodeFs.readdirSync(root, { withFileTypes: true }); }
  catch (_e) { return into; }
  for (var i = 0; i < entries.length; i += 1) {
    var here = (prefix ? prefix + "/" : "") + entries[i].name;
    into.push(here);
    if (entries[i].isDirectory()) {
      everythingUnder(nodePath.join(root, entries[i].name), here, into);
    }
  }
  return into;
}

// The plaintext working copies anywhere under the shared directory. The
// running server owns exactly one; anything else is a decrypted database
// of somebody's mail that outlived the command that made it.
function plaintextCopies(workDir) {
  return everythingUnder(workDir, "", []).filter(function (name) {
    return /(^|\/)blamejs-[^/]*\.db$/.test(name);
  }).sort();
}

// ---- cases -----------------------------------------------------------------

// The verbs that report answer while the server holds the volume. They
// are not refused, and they answer with what is actually on the volume
// rather than with an empty listing that would read the same as a clean
// one.
function aReportingVerbAnswersWhileTheServerRuns(cli) {
  for (var i = 0; i < REPORTING_VERBS.length; i += 1) {
    var verb = REPORTING_VERBS[i];
    var label = verb.join(" ");
    var result = cli(verb);
    count("`" + label + "` answers while the server holds the volume",
      result.status === 0, "exit " + result.status + " " + result.both.slice(0, 300));
    count("`" + label + "` is not refused as a second opener",
      !/already open|store\/volume-in-use/i.test(result.both), result.both.slice(0, 300));
  }

  var listed = cli(["account", "list"]);
  count("`account list` answers with the account that is on the volume",
    listed.both.indexOf(ADDRESS) !== -1, listed.both.slice(0, 300));

  var doctored = cli(DOCTOR);
  count("`" + DOCTOR.join(" ") + "` runs rather than refusing",
    !/already open|store\/volume-in-use/i.test(doctored.both), doctored.both.slice(0, 400));
  // Its own exit code is about the zone, which offline is a failing one.
  // What matters here is that it got as far as having an opinion.
  count("`" + DOCTOR.join(" ") + "` reports on the server it was asked about",
    doctored.both.indexOf(HOSTNAME) !== -1, doctored.both.slice(0, 400));
}

// The answer is old, and both readers are told. A script parsing stdout
// is the one that matters most, because it is the reader that cannot
// notice a caveat printed for a person.
function theAnswerSaysItIsASnapshot(cli, flushedAt) {
  var text = cli(["account", "list"]);
  count("the text an operator reads says the answer is a snapshot",
    /snapshot/i.test(text.both), text.both.slice(0, 400));

  var asJson = cli(["account", "list", "--json"]);
  var parsed;
  try { parsed = JSON.parse(asJson.stdout); } catch (_e) { parsed = null; }
  count("`--json` still parses as JSON",
    parsed !== null, asJson.stdout.slice(0, 400));
  count("`--json` carries the snapshot marker, so automation reads it too",
    parsed !== null && typeof parsed.snapshot === "object" && parsed.snapshot !== null,
    JSON.stringify(parsed).slice(0, 400));
  count("the marker names the moment the volume was last written to disk",
    parsed !== null && parsed.snapshot !== undefined && parsed.snapshot !== null &&
      typeof parsed.snapshot.takenAt === "number" &&
      Math.abs(parsed.snapshot.takenAt - flushedAt) < b.constants.TIME.minutes(1),
    JSON.stringify(parsed && parsed.snapshot) + " against " + flushedAt);
  count("and the answer itself is still there beside it",
    parsed !== null && Array.isArray(parsed.result) &&
      parsed.result.some(function (a) { return a && a.address === ADDRESS; }),
    JSON.stringify(parsed && parsed.result).slice(0, 300));
}

// The body that arrived after the last flush is not called
// unreferenced.
//
// This is the wrong answer the whole verb used to be refused over, and
// it is a wrong answer rather than an old one: the rows are frozen at
// the flush, the blob directory is live, and every message delivered in
// between has its octets on disk and its row only in the running
// server's own copy. Reported as an orphan it reads as a volume that is
// diverging, on a server where nothing has gone wrong at all.
//
// So the bound is the moment the rows were frozen, which the answer
// already carries. A body at or after it is one the rows had not
// reached; a body before it and referenced by nothing is the finding
// this verb exists for. The digest check is asserted alongside because
// it is the half that is fully sound either way: a referenced body that
// no longer hashes to its own name is the same finding whenever it is
// read.
function theBodyThatArrivedSinceIsNotCalledUnreferenced(cli, expectedNewer) {
  var result = cli(["blobs", "report", "--verify", "--json"]);
  var parsed;
  try { parsed = JSON.parse(result.stdout); } catch (_e) { parsed = null; }

  count("`blobs report --verify` answers rather than refusing while the server runs",
    result.status === 0, "exit " + result.status + " " + result.both.slice(0, 400));
  count("and its answer parses, inside the envelope that says it is a snapshot",
    parsed !== null && parsed.snapshot !== undefined && parsed.result !== undefined,
    result.stdout.slice(0, 400));

  var body = parsed && parsed.result ? parsed.result : null;
  count("the body that arrived after the last flush is not reported as unreferenced",
    body !== null && Array.isArray(body.orphans) && body.orphans.length === 0,
    JSON.stringify(body && body.orphans).slice(0, 400));
  count("it is reported as newer than the rows that were read, and counted",
    body !== null && Array.isArray(body.newerThanRows) &&
      body.newerThanRows.length === expectedNewer,
    JSON.stringify(body && body.newerThanRows).slice(0, 400));
  count("the answer names the moment the rows were frozen, so the bound is not a guess",
    body !== null && typeof body.rowsAsOf === "number" && body.rowsAsOf > 0,
    JSON.stringify(body && body.rowsAsOf));
  count("every referenced body was unsealed and hashed back against its digest",
    body !== null && body.verified === true && Array.isArray(body.corrupt) &&
      body.corrupt.length === 0,
    JSON.stringify(body && { verified: body.verified, corrupt: body.corrupt }).slice(0, 300));
  count("so the verdict is that nothing has diverged",
    body !== null && body.ok === true, JSON.stringify(body && body.ok));

  // The verb `doctor` runs the same check through, so the two cannot
  // describe one volume differently. It used to report the check as not
  // done and send the operator to a stopped server.
  var doctored = cli(["doctor", "--domain", DOMAIN, "--json"]);
  var seen;
  try { seen = JSON.parse(doctored.stdout); } catch (_e2) { seen = null; }
  function finding(name) {
    return seen && seen.result && Array.isArray(seen.result.local)
      ? seen.result.local.filter(function (f) { return f.check === name; })[0] || null
      : null;
  }
  var bodies = finding("message bodies");
  count("`doctor` reaches a verdict on the message bodies rather than reporting it not done",
    bodies !== null && bodies.ok === true && !/not checked/i.test(String(bodies.detail)),
    JSON.stringify(bodies).slice(0, 400));

  // The sibling check, and the reason it is asserted beside the first
  // one rather than left to itself: both hold rows frozen at the last
  // write to disk against a directory that is live, so a fix that
  // reached one and not the other would leave the same refusal standing
  // under a different name.
  var keys = finding("signing keys");
  count("`doctor` reaches a verdict on the signing keys too",
    keys !== null && keys.ok === true && !/not checked/i.test(String(keys.detail)),
    JSON.stringify(keys).slice(0, 400));
}

// A body that really is referenced by nothing is still reported.
//
// This is the other half of the case above and the half that would go
// unnoticed without it. A bound that swept every body on disk into
// "newer than the rows" would satisfy the assertions above perfectly and
// silence the finding this verb exists for, and a report that never
// finds an orphan is indistinguishable from a volume that has none.
//
// The vector is a body written well before the rows stop, referenced by
// nothing, which is what a delivery interrupted between its two writes
// leaves behind. It is planted and removed inside this case so the
// volume is the same before and after.
function anOrphanOlderThanTheRowsIsStillReported(cli, dataDir, rowsStopAt) {
  var digest = "";
  while (digest.length < 128) digest += "abcdef0123456789";
  var blobPath = nodePath.join(dataDir, "blobs",
    digest.slice(0, 2), digest.slice(2, 4), digest);
  nodeFs.mkdirSync(nodePath.dirname(blobPath), { recursive: true });
  nodeFs.writeFileSync(blobPath, Buffer.from("octets no row has ever named", "utf8"));
  // Two days back, so it is both older than the rows and past the window
  // inside which an unreferenced body and an arriving one look alike.
  var old = (rowsStopAt - b.constants.TIME.hours(48)) / 1000;
  nodeFs.utimesSync(blobPath, old, old);

  try {
    var result = cli(["blobs", "report", "--json"]);
    var parsed;
    try { parsed = JSON.parse(result.stdout); } catch (_e) { parsed = null; }
    var body = parsed && parsed.result ? parsed.result : null;

    count("a body older than the rows and referenced by nothing is still reported",
      body !== null && Array.isArray(body.orphans) && body.orphans.length === 1 &&
        body.orphans[0].digest === digest,
      JSON.stringify(body && body.orphans).slice(0, 300));
    count("and it is not filed as one the rows had not reached",
      body !== null && Array.isArray(body.newerThanRows) &&
        body.newerThanRows.every(function (e) { return e.digest !== digest; }),
      JSON.stringify(body && body.newerThanRows).slice(0, 300));
    count("so the run reports a divergence rather than a clean volume",
      body !== null && body.ok === false && result.status !== 0,
      "exit " + result.status + " ok=" + JSON.stringify(body && body.ok));
  } finally {
    nodeFs.rmSync(blobPath, { force: true });
  }
}

// The trail verifies from a read-only open, signatures included.
//
// This is what the copy could not do before. Opening a copy asked the
// framework not to sign a fresh checkpoint over it, and what that gave
// up was the verification of the signatures over the checkpoints already
// there, which is the half a rewrite cannot recompute. A read-only open
// gives that up for nothing instead: it anchors no checkpoint AND it verifies
// every one it finds, because the audit-signing key is unsealed for
// reading and never established.
//
// What the copy holds is a prefix of the live chain, and a prefix of an
// append-only chain is a chain. The rows written since the last flush
// are not in it, which is what the snapshot label says.
function theTrailVerifiesFromACopyWithItsSignaturesChecked(cli) {
  var result = cli(["audit", "verify-chain", "--json"]);
  var parsed;
  try { parsed = JSON.parse(result.stdout); } catch (_e) { parsed = null; }

  count("`audit verify-chain` answers rather than refusing while the server runs",
    result.status === 0, "exit " + result.status + " " + result.both.slice(0, 400));
  count("and it says the answer came off a copy",
    parsed !== null && parsed.snapshot !== undefined && parsed.snapshot !== null,
    result.stdout.slice(0, 300));

  var verdict = parsed && parsed.result ? parsed.result : null;
  count("the chain's own row hashes verify",
    verdict !== null && verdict.chain !== null && verdict.chain.ok === true,
    JSON.stringify(verdict && verdict.chain).slice(0, 300));
  count("and the checkpoint signatures are verified rather than skipped",
    verdict !== null && verdict.checkpoints !== null && verdict.checkpoints.ok === true &&
      Number(verdict.checkpoints.checkpointsVerified) >= 1,
    JSON.stringify(verdict && verdict.checkpoints).slice(0, 300));
  count("the reading made from outside the database is reported too",
    verdict !== null && verdict.anchor !== null && typeof verdict.anchor === "object",
    JSON.stringify(verdict && verdict.anchor).slice(0, 300));
  count("so the trail is reported as verifying",
    verdict !== null && verdict.ok === true, JSON.stringify(verdict && verdict.ok));
}

// A read whose own record has to outlive the process does not qualify,
// and neither does one that writes before it reads.
function theVerbsThatDoNotQualifyStillRefuse(cli, paths) {
  var refused = stillRefused(paths);
  for (var i = 0; i < refused.length; i += 1) {
    var entry = refused[i];
    var label = entry.verb.join(" ");
    var result = cli(entry.verb);
    count("`" + label + "` still refuses, because " + entry.because,
      result.status !== 0, "exit " + result.status + " " + result.both.slice(0, 300));
    count("`" + label + "` says the volume is already open",
      /already open|another process|store\/volume-in-use/i.test(result.both),
      result.both.slice(0, 400));
  }
}

// The rule is about what has to outlive the process, so a mutation is
// refused however harmless it looks.
function aMutatingVerbStillRefuses(cli) {
  for (var i = 0; i < MUTATING_VERBS.length; i += 1) {
    var verb = MUTATING_VERBS[i];
    var label = verb.join(" ");
    var result = cli(verb);
    count("`" + label + "` still refuses while the server holds the volume",
      result.status !== 0, "exit " + result.status + " " + result.both.slice(0, 300));
    count("`" + label + "` says the volume is already open",
      /already open|another process|store\/volume-in-use/i.test(result.both),
      result.both.slice(0, 400));
  }
}

// Nothing on the volume moved. The encrypted database is the obvious
// half; the record of where the audit chain was last anchored is the
// half that would go unnoticed, and it is the one that turns a report
// into an outage.
function theLiveVolumeIsUntouched(before, after) {
  count("the encrypted database is byte identical after every reporting verb",
    before.enc === after.enc,
    "before " + before.enc.slice(0, 24) + " after " + after.enc.slice(0, 24));
  count("the audit anchor beside it is byte identical too",
    before.tip === after.tip,
    "before " + before.tip.slice(0, 24) + " after " + after.tip.slice(0, 24));
  count("and the counter it names has not been advanced from a copy",
    before.counter === after.counter,
    "before " + before.counter + " after " + after.counter);
  count("nothing else on the volume moved either, across all " + before.volume.files +
    " file(s) it holds",
    before.volume.digest === after.volume.digest,
    "before " + before.volume.digest.slice(0, 24) + " (" + before.volume.files + " files) " +
    "after " + after.volume.digest.slice(0, 24) + " (" + after.volume.files + " files)");
  count("the running server's working copy is still where it was",
    before.copies.length > 0 && before.copies.every(function (name) {
      return after.copies.indexOf(name) !== -1;
    }), "before " + JSON.stringify(before.copies) + " after " + JSON.stringify(after.copies));
}

// A decrypted working copy is somebody's mail in the clear. One that
// outlives the command that made it is a disclosure, and the run that
// leaves it behind is the one that failed part way.
function nothingDecryptedSurvivesTheRun(workDir, serverCopies) {
  var copies = plaintextCopies(workDir);
  var strays = copies.filter(function (name) { return serverCopies.indexOf(name) === -1; });
  count("no decrypted database outlives the commands that made one",
    strays.length === 0, "left behind: " + JSON.stringify(strays));
}

// The record naming the process a working copy belongs to goes with the
// copy it describes.
//
// It carries a process id and nothing else, so one left behind is not a
// disclosure the way a decrypted database is. It is still a file nothing
// will ever reclaim: the sweep that reclaims abandoned copies enumerates
// the databases, so a record whose database is gone is invisible to it
// and accumulates one per occurrence.
//
// Checked only where every open in the window SUCCEEDED. A boot that
// throws part way through leaves one behind whichever way the volume was
// opened, because the shutdown that removes it is the one that runs
// after a successful init, so asserting it around a deliberately broken
// volume would be asserting a fault that is neither this path's nor this
// repository's to fix.
function noOwnershipRecordOutlivesItsCopy(workDir) {
  var copies = plaintextCopies(workDir);
  var orphaned = everythingUnder(workDir, "", []).filter(function (name) {
    if (!/(^|\/)blamejs-[^/]*\.db\.owner$/.test(name)) return false;
    return copies.indexOf(name.replace(/\.owner$/, "")) === -1;
  });
  count("no ownership record outlives the copy it describes",
    orphaned.length === 0, "left behind: " + JSON.stringify(orphaned));
}

// A copy that cannot be read back is refused, and the refusal says the
// volume is untouched. Reporting on a half-decrypted database, or
// falling back to an empty one, are the two answers that must not
// happen.
//
// The vector is the encrypted database on disk, damaged where it lies.
// The running server holds its own working copy and does not re-read
// this file, so the damage reaches only the copy the reporting verb
// takes, which is exactly the torn read being tested.
async function aCopyThatWillNotDecryptIsRefused(cli, dataDir) {
  var encPath = nodePath.join(dataDir, "db.enc");
  var whole = nodeFs.readFileSync(encPath);

  var vectors = [
    { name: "truncated to nothing usable", bytes: whole.slice(0, 20) },
    { name: "cut in half", bytes: whole.slice(0, Math.floor(whole.length / 2)) },
    { name: "altered in place", bytes: (function () {
      var copy = Buffer.from(whole);
      copy[copy.length - 100] ^= 0xff;
      return copy;
    })() },
  ];

  for (var i = 0; i < vectors.length; i += 1) {
    nodeFs.writeFileSync(encPath, vectors[i].bytes);
    var result = cli(["account", "list"]);
    count("a copy " + vectors[i].name + " is refused rather than reported on",
      result.status !== 0, "exit " + result.status + " " + result.both.slice(0, 300));
    count("and the refusal for a copy " + vectors[i].name + " names the volume as unread",
      /could not be read|would not decrypt|snapshot/i.test(result.both),
      result.both.slice(0, 400));
    count("a copy " + vectors[i].name + " never answers with an empty listing",
      result.both.indexOf("0 account") === -1 && result.status !== 0,
      result.both.slice(0, 300));
  }

  nodeFs.writeFileSync(encPath, whole);
}

// A copy older than the volume's own record of where its audit chain
// reached. The framework refuses it, and the refusal has to arrive as
// what it is rather than as the accusation of tampering the same check
// makes about a volume: a copy is expected to be behind, and one that is
// behind the anchor means it was taken as the volume was being opened.
//
// It is also the failure that gets furthest before it fails. The
// database is decrypted before the check that refuses it runs, so this
// is the case where a decrypted copy of somebody's mail is left behind
// by a cleanup that only covers the happy path.
async function aCopyBehindTheVolumesAnchorIsRefused(cli, dataDir, workDir, serverCopies) {
  var anchorPath = nodePath.join(dataDir, "audit.tip");
  var original = nodeFs.readFileSync(anchorPath);
  var moved = JSON.parse(String(original));
  moved.atMonotonicCounter = Number(moved.atMonotonicCounter) + 100000;
  nodeFs.writeFileSync(anchorPath, JSON.stringify(moved, null, 2));

  try {
    var result = cli(["account", "list"]);
    count("a copy behind the volume's audit anchor is refused",
      result.status !== 0, "exit " + result.status + " " + result.both.slice(0, 300));
    count("and the refusal says the copy is out of step rather than that rows were deleted",
      /out of step|older than/i.test(result.both), result.both.slice(0, 500));
    count("and it says the volume itself was not changed",
      /nothing on the volume was changed/i.test(result.both), result.both.slice(0, 500));

    // The same refusal reaching `audit verify-chain`, which is the verb
    // that must not confuse the two. Rows behind the record beside them
    // is what a server starting up looks like; a chain that does not
    // verify is an accusation. This one reports the first and never
    // prints the second, because a transient dressed as tamper evidence
    // during an incident is the reading that sends an operator down the
    // wrong path entirely.
    var chain = cli(["audit", "verify-chain"]);
    count("`audit verify-chain` refuses rather than reporting on rows behind the record",
      chain.status !== 0 && /out of step|older than/i.test(chain.both),
      "exit " + chain.status + " " + chain.both.slice(0, 400));
    count("and it does not report the chain as failing to verify",
      !/does not verify|FAIL/i.test(chain.both), chain.both.slice(0, 400));

    nothingDecryptedSurvivesTheRun(workDir, serverCopies);
  } finally {
    nodeFs.writeFileSync(anchorPath, original);
  }
}

// With the volume free the same verbs open it directly, and the answer
// carries no snapshot marker, because there is nothing stale about it.
function theVerbsReadTheVolumeItselfWhenNothingHoldsIt(cli) {
  var listed = cli(["account", "list"]);
  count("`account list` answers once the volume is free",
    listed.status === 0, "exit " + listed.status + " " + listed.both.slice(0, 300));
  count("and it is not labeled a snapshot, because it is not one",
    !/snapshot/i.test(listed.both), listed.both.slice(0, 300));

  var asJson = cli(["account", "list", "--json"]);
  var parsed;
  try { parsed = JSON.parse(asJson.stdout); } catch (_e) { parsed = null; }
  count("`--json` off a free volume is the answer itself, with no envelope",
    Array.isArray(parsed) && parsed.some(function (a) { return a && a.address === ADDRESS; }),
    asJson.stdout.slice(0, 300));
}

// A write through a reporting handle is refused where it is issued.
//
// Two guards stand here and only one of them is this repository's. The
// verbs that destroy a domain's sealed key check the descriptor first,
// because unlinking a key file is a filesystem write no database can
// stop. Everything else is stopped by the database handle itself, which
// is opened read-only: the write fails at the statement rather than
// succeeding into a copy nobody will ever persist.
//
// The second guard is the one worth a case. Aliases carry no descriptor
// check at all, so a write there is refused by nothing this repository
// wrote, which is the whole difference between a promise that reporting
// verbs will not write and an open that cannot.
async function aWriteThroughAReportingHandleIsRefused(cfg) {
  var copy = await store.openSnapshot(cfg);
  try {
    var aliasThrew = null;
    try {
      await copy.aliases.add({
        address: "sales@" + DOMAIN, destination: ADDRESS,
      });
    } catch (e) { aliasThrew = e; }
    count("a write with no guard of its own is still refused by the handle it went through",
      aliasThrew !== null,
      aliasThrew === null ? "the insert was accepted" : String(aliasThrew.message).slice(0, 200));

    var keyThrew = null;
    try { await copy.domains.remove({ domain: DOMAIN, reason: "testing the refusal" }); }
    catch (e2) { keyThrew = e2; }
    count("and the verb that would unlink a sealed key refuses before reaching the volume",
      keyThrew !== null,
      keyThrew === null ? "the removal was accepted" : String(keyThrew.message).slice(0, 200));
  } finally {
    copy.close();
  }

  // Nothing the refusals above did reached the volume: the alias is not
  // there and the domain still is, read back through an opener that
  // sees the volume itself.
  var live = await store.open(cfg);
  try {
    count("the refused write left nothing behind on the volume",
      live.resolve("sales@" + DOMAIN).deliverable === false &&
        live.domains.get(DOMAIN) !== null,
      JSON.stringify({
        alias:  live.resolve("sales@" + DOMAIN).deliverable,
        domain: live.domains.get(DOMAIN) !== null,
      }));
  } finally {
    live.close();
  }
}

// The opener and the question every printed answer asks, driven
// directly. The cases above go through the binary, which is the path an
// operator drives; this is the seam the binary sits on, and it is what
// says that "is this answer current" has an answer at all.
async function theHandleSaysWhichItIs(cfg, workDir, serverCopies) {
  count("blamepost.store.snapshotInEffect answers null before anything is opened",
    store.snapshotInEffect() === null, JSON.stringify(store.snapshotInEffect()));

  var live = await store.open(cfg);
  count("a handle from blamepost.store.open carries no snapshot",
    live.snapshot === null && store.snapshotInEffect() === null,
    JSON.stringify(live.snapshot));
  live.close();

  var copy = await store.openSnapshot(cfg);
  try {
    count("a handle from blamepost.store.openSnapshot says which it is",
      copy.snapshot !== null && typeof copy.snapshot.takenAt === "number",
      JSON.stringify(copy.snapshot));
    count("and the same descriptor is what anything printing an answer reads",
      store.snapshotInEffect() === copy.snapshot,
      JSON.stringify(store.snapshotInEffect()));
    count("the copy answers with the accounts that are on the volume",
      copy.accounts.list().some(function (a) { return a.address === ADDRESS; }),
      JSON.stringify(copy.accounts.list().map(function (a) { return a.address; })));
  } finally {
    copy.close();
  }

  count("closing it puts the question back to null",
    store.snapshotInEffect() === null, JSON.stringify(store.snapshotInEffect()));
  nothingDecryptedSurvivesTheRun(workDir, serverCopies);
}

// The operator visible consequence, which is the only reason any of this
// matters: mail that arrived around the reporting verbs is still there
// once the server has been restarted.
async function noMailIsLostAcrossTheVerbs(cfg, accountId, expected) {
  var handle = await store.open(cfg);
  try {
    var selected = handle.mailbox.selectFolder({ id: accountId }, "INBOX", {});
    count("every message delivered around the reporting verbs survived the restart",
      selected.exists === expected, "found " + selected.exists + " of " + expected);
  } finally {
    handle.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("snapshot-reporting");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The same memory backed directory for this process and every process
  // it spawns, which is what the container shares as /dev/shm between the
  // server and anything reached with `docker exec`.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;

  try {
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    var seeded = await store.open(cfg);
    await seeded.domains.add({ domain: DOMAIN });
    var alice = await seeded.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    var accountId = alice.id;
    seeded.mailbox.appendMessage("INBOX", message("before the operator looked"), {
      actor: { id: accountId },
    });
    seeded.close();

    // The server: one process, holding the volume for as long as it
    // serves. Mail arrives, and a flush lands the way the periodic one
    // does, so the encrypted volume is current before the verbs run.
    identity = await store.open(cfg);
    identity.mailbox.appendMessage("INBOX", message("while the server was up"), {
      actor: { id: accountId },
    });
    // The audit rows a running server accumulates between one anchoring
    // of its chain and the next. Without them the chain tip is still the
    // one the last checkpoint covers, and a copy opened in that state
    // has nothing to anchor, so the write into the volume this case
    // exists to catch cannot happen and the case passes on a server
    // nobody runs. The chain is anchored when the volume is opened and
    // at no point after it, so this IS the ordinary state.
    await b.audit.flush();
    var anchoredAt = anchorCounter(dataDir);
    var reachedNow = Number(b.db.from("audit_log").orderBy("monotonicCounter", "desc")
      .first().monotonicCounter);
    count("the server has recorded audit rows since its chain was last anchored",
      reachedNow > anchoredAt, "anchored at " + anchoredAt + ", chain reached " + reachedNow);

    b.db.flushToDisk();
    var flushedAt = nodeFs.statSync(nodePath.join(dataDir, "db.enc")).mtimeMs;

    // Mail delivered AFTER that flush, which is the ordinary state of a
    // running server and the one that used to produce a wrong answer.
    // The sealed body is on the volume now; the row naming it is in the
    // server's own working copy and will not reach the encrypted file
    // until the next flush. So a reporting verb reads rows that do not
    // know about a body that is plainly there, and calling that body
    // unreferenced is the failure the bound below fixes.
    identity.mailbox.appendMessage("INBOX", message("after the last flush"), {
      actor: { id: accountId },
    });

    // Where `backup run` would write, and the passphrase it would use.
    // Both are read before a store is opened, so a missing one would
    // make that verb refuse for a reason that has nothing to do with the
    // volume being held.
    var backupDir = nodePath.join(root, "bundles");
    var passphraseFile = nodePath.join(root, "bundle-passphrase");
    nodeFs.mkdirSync(backupDir, { recursive: true });
    nodeFs.writeFileSync(passphraseFile, "a long enough bundle passphrase for one test run\n");

    var before = {
      enc:     digestOf(nodePath.join(dataDir, "db.enc")),
      tip:     digestOf(nodePath.join(dataDir, "audit.tip")),
      counter: anchorCounter(dataDir),
      volume:  volumeDigest(dataDir),
      copies:  plaintextCopies(workDir),
    };

    aReportingVerbAnswersWhileTheServerRuns(cli);
    theAnswerSaysItIsASnapshot(cli, flushedAt);
    theBodyThatArrivedSinceIsNotCalledUnreferenced(cli, 1);
    anOrphanOlderThanTheRowsIsStillReported(cli, dataDir, flushedAt);
    theTrailVerifiesFromACopyWithItsSignaturesChecked(cli);
    theVerbsThatDoNotQualifyStillRefuse(cli,
      { backupDir: backupDir, passphraseFile: passphraseFile });
    aMutatingVerbStillRefuses(cli);

    theLiveVolumeIsUntouched(before, {
      enc:     digestOf(nodePath.join(dataDir, "db.enc")),
      tip:     digestOf(nodePath.join(dataDir, "audit.tip")),
      counter: anchorCounter(dataDir),
      volume:  volumeDigest(dataDir),
      copies:  plaintextCopies(workDir),
    });
    nothingDecryptedSurvivesTheRun(workDir, before.copies);
    noOwnershipRecordOutlivesItsCopy(workDir);

    await aCopyThatWillNotDecryptIsRefused(cli, dataDir);
    nothingDecryptedSurvivesTheRun(workDir, before.copies);

    await aCopyBehindTheVolumesAnchorIsRefused(cli, dataDir, workDir, before.copies);

    // Mail keeps arriving after the operator has been and gone.
    identity.mailbox.appendMessage("INBOX", message("after the operator looked"), {
      actor: { id: accountId },
    });

    identity.close();
    identity = null;

    await noMailIsLostAcrossTheVerbs(cfg, accountId, 4);
    theVerbsReadTheVolumeItselfWhenNothingHoldsIt(cli);

    await theHandleSaysWhichItIs(cfg, workDir, plaintextCopies(workDir));
    await aWriteThroughAReportingHandleIsRefused(cfg);

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

module.exports = { name: "store-snapshot-reporting", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
