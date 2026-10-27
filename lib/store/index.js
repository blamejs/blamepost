// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store
 * @nav    Storage and audit
 * @title  Identity and routing store
 * @order  10
 *
 * The identity and routing layer: accounts, hosted domains, aliases,
 * DKIM selector records, and the address lookup every listener runs on
 * a recipient.
 *
 * It is not the message store. `b.mailStore` already owns folders,
 * messages, flags, sealed message bodies, CONDSTORE sequence numbers,
 * JMAP object identity, threading, quota counters, legal hold and full
 * text search, and it is the substrate the whole mail stack composes.
 * This layer is the part the framework deliberately leaves to the
 * application, and it sits above that substrate rather than beside it.
 *
 * The message store is created here all the same, because there is one
 * database and one process, and the listeners need one handle rather
 * than a handle each. It is created once and handed out as `mailbox`,
 * wrapped in the protocol facing adapter the wire listeners expect,
 * which is what gives each account its own folders above the store's
 * single namespace.
 *
 * Opening it does three things in order, because each needs the one
 * before it: the data directories exist, the vault is unsealed, and the
 * database is open with this layer's schema reconciled. The database is
 * encrypted at rest and the vault holds the key, so the order is not a
 * preference.
 *
 * Everything here is a singleton, because `b.db` is. One process opens
 * one store, and opening a second time hands back the first.
 */

var nodeFs     = require("node:fs");
var nodeOs     = require("node:os");
var nodePath   = require("node:path");
var nodeSqlite = require("node:sqlite");

var b = require("../vendor/blamejs");

var mailbox  = require("../mail/mailbox");

var config   = require("../config");
var accounts = require("./accounts");
var aliases  = require("./aliases");
var addresses = require("./address");
var blobs    = require("./blobs");
var credentials = require("./credentials");
var domains  = require("./domains");
var errors   = require("./errors");
var reports  = require("./reports");
var routing  = require("./routing");
var settings = require("./settings");
var tables   = require("./tables");

var err = errors.err;

// The run-once schema migrations. `b.db.init` applies the ones a volume
// has not recorded yet, in file name order, after it reconciles the
// declared tables.
var MIGRATION_DIR = nodePath.join(__dirname, "migrations");

// The variables the framework's passphrase source reads. The operator
// sets one blamepost passphrase and it unlocks both keys: the vault key
// that seals the database and every sealed column, and the audit
// signing key that signs the checkpoints over the audit chain. One
// secret to hold, one to rotate, one to lose.
var FRAMEWORK_PASSPHRASE_VARS = [
  "BLAMEJS_VAULT_PASSPHRASE",
  "BLAMEJS_AUDIT_SIGNING_PASSPHRASE",
];

// The audit namespaces this server records under. They have to be
// registered before the first event, or the framework refuses the
// action name rather than filing it somewhere unexpected.
//
// `blamepost` is the one every subsystem outside the identity layer
// writes under, from the mailbox role refusals to the delivery and
// filter events. It is registered here because this is the earliest
// point in the boot that runs, and an unregistered namespace does not
// fail loudly: the emit buffers, the drain refuses the action name, and
// the event is gone. A refusal nobody can review afterwards is not a
// refusal that was recorded.
var AUDIT_NAMESPACES = ["account", "domain", "alias", "blamepost"];

// A mail account's password is the credential for a mailbox that holds
// years of correspondence and can send as its owner. Twelve characters
// is above the NIST floor the framework defaults to, and the bundled
// list of common and breached passwords is checked on top of it.
var MIN_PASSWORD_CHARS = 12;

var handle = null;

// ---------------------------------------------------------------------------
// One WRITER per volume
// ---------------------------------------------------------------------------
//
// Opening this database for writing is not a read. It is encrypted at
// rest, so the framework decrypts the whole file into a working copy of
// its own on a memory backed directory, serves every query from that
// copy, and writes the copy back over the encrypted file on a timer and
// again at shutdown.
//
// For one writer that is the design. For two it destroys mail. Each has
// its own working copy and neither can see the other's, so both write
// the whole volume back and whichever writes last overwrites everything
// the other stored. The server keeps accepting mail, keeps answering
// IMAP, and what is left on disk is one process's view of the volume
// with the other's deliveries missing from it. It is internally
// consistent and merely incomplete, so nothing downstream reports it
// either.
//
// So the rule cannot be a rule about which verbs are safe. It is a rule
// about writing the volume: one writer, and the second is refused before
// anything decrypts. A verb that touches the volume at all, such as
// `queue list` reading the outbound spool off disk, never arrives here
// and keeps working while the server runs.
//
// A READER is not a second writer and is not refused. See below: it
// takes no lock, because there is no flush for it to join and nothing
// for the lock to protect it from.
//
// The refusal is a fact rather than a claim. A file records the process
// holding the volume and the process table that PID belongs to; the
// holder is confirmed with a signal that asks the kernel whether the
// process is there. An operator's assurance that the server is stopped
// is not consulted, because a gate that reads an assurance fails open on
// exactly the occasion the assurance is wrong.
var VOLUME_LOCK = "blamepost.lock";

// The directory on the volume `blamepost restore` works in: the bundle is
// decrypted into it, the files a restore replaces are kept in it, and the
// record of a restore that has started and not finished is written in it.
// It is on the volume because in the shipped container nothing else on
// that filesystem is writable, and a file cannot be renamed into a mount
// point from another filesystem.
var RESTORE_WORK_DIR = ".restore";

// The record of a restore or rollback that has moved files and not yet
// reached a verdict. While it exists the volume holds a mixture of two
// volumes, so every open refuses and names the command that undoes it.
var RESTORE_IN_FLIGHT = "in-flight.json";

// The top-level names on a volume that belong to the volume rather than
// to its data. A backup leaves them out and a restore never moves them:
// the lock names the process holding the volume, and the work directory
// holds the rollback points.
var VOLUME_RESERVED = Object.freeze([VOLUME_LOCK, RESTORE_WORK_DIR]);

// The lock this process holds, or null. One process writes one volume,
// so one handle is the whole state.
var volumeLock = null;

// The data directory `holdVolume` took the lock for, or null. While it is
// set, an open of that directory reuses the lock rather than taking it,
// and a close leaves it held, so a restore can open the volume it is
// putting in place and still hold the volume if it has to undo the move.
var volumeHeldApart = null;

// ---------------------------------------------------------------------------
// Reporting from a read-only open
// ---------------------------------------------------------------------------
//
// The rule above is not negotiable, and its cost lands on the verbs that
// only report. `account list`, `domain list`, `dkim list`, `blobs
// report`, `audit verify-chain` and `doctor` change nothing an operator
// asked to change, and all of them were refused while the server runs
// because all of them opened the volume to read it. `doctor` is the one
// that hurts: an operator reaches for it exactly when the server is up
// and behaving oddly.
//
// So a verb that only reports opens the volume READ-ONLY. The framework
// decrypts a working copy of its own, exactly as it does for the server,
// and then does none of the writing: `db.enc` is never written back, the
// sealed database key is never re-sealed, no checkpoint is anchored, the
// record beside the volume is never advanced, and no flush timer is
// armed. SQLite is opened read-only as well, so a write that reaches it
// fails at the statement rather than succeeding into a copy nobody will
// ever persist. No lock is taken and the running server is not
// consulted.
//
// Four properties make that safe rather than merely convenient.
//
// The answer is one moment rather than a blend. The copy is decrypted
// once, at the open, and every query is served from it, so a writer
// committing halfway through a long report cannot move the rows
// underneath it. What a reader cannot see is a splice either: the
// framework replaces the encrypted database by writing a temporary file
// and renaming it over the old one, so a read gets the whole previous
// file or the whole new one, and a read that is torn regardless fails
// the envelope's authentication tag and is refused.
//
// The volume stays byte identical, and that includes the record beside
// it of where the audit chain was last anchored. Anchoring a fresh one
// is the write this open would otherwise make, and it is not cosmetic:
// the anchor would name a counter that reached the copy and never the
// volume, so a server killed before its next flush comes back to a
// volume the rollback check refuses to open at all. A read-only open
// anchors nothing while still VERIFYING every checkpoint signature it
// finds, which is what lets `audit verify-chain` answer from here at
// all: the signatures are the half a rewritten chain cannot recompute.
//
// The answer is old, by a knowable amount. The volume is written on a
// timer, so the rows are the database as it stood at the last flush; the
// modification time of the encrypted file is that moment, measured
// rather than estimated, and every verb reports it. A verb whose answer
// holds those rows against something still moving on disk has to carry
// the bound as well, which is why `blobs.reconcile` takes it: a body
// newer than the rows reads as one the rows had not reached rather than
// as a body nothing references.
//
// And nothing decrypted outlives the command. The working copy is named
// for this process, claimed with an ownership record before any bytes go
// into it, and removed when the handle closes. One left behind by a
// process that died is reclaimed by the next open, which asks the
// operating system whether the recorded owner is still running rather
// than inferring it from a filename.
//
// The commands that may take that open, as the group and verb an
// operator types. It sits here rather than beside the argument parser
// because it is a statement about what this layer serves read-only: the
// refusal below names it and `bin/blamepost.js` reads it to decide
// whether to fall back, so a verb added here reaches both in one edit.
// `doctor` is a whole command rather than a group and a verb, so it is
// listed against the empty string.
//
// The test is not whether a verb changes anything. What disqualifies a
// read is needing to WRITE on the way to its answer, and there are two
// shapes of that.
//
// A read whose own record has to outlive the process. `audit read` is
// documented as itself being recorded and `account sieve` records that
// an administrator opened somebody's filter. A read-only handle cannot
// write that row, and a read that claims to be recorded and is not is
// worse than a read that refuses.
//
// A verb that writes before it reads. `backup run` anchors the chain so
// the bundle carries a signature over its own last row, and requires the
// volume flushed so the bundle is not older than the database it claims
// to be. `audit archive`, `audit export` and `audit purge` are the same.
// None of that is available to a handle that will not write.
//
// `blobs report` is here rather than among those. Its answer holds the
// rows against a blob directory that keeps moving. The rows carry the
// moment they were frozen and `blobs.reconcile` separates a body newer
// than that from a body nothing references, so what it reports is
// bounded by what it read.
//
// `audit verify-chain` is here because a read-only open verifies the
// checkpoint signatures rather than skipping them, which is what it
// could not get from a copy opened with the signing key left sealed. The
// chain is append-only, so what it walks is a verified prefix.
//
// `zone preview`, `zone verify` and `zone verify-token` are here and
// `zone token` is not. All three reads answer about the DNS PROVIDER,
// which is not on this volume at all: `preview` and `verify` read rows
// only to find the domain and its selector records, and `verify-token`
// reads none, because the sealed credential is resolved from the
// configuration and the question is about the account it belongs to. An
// answer computed off a copy is an answer about the same zone and the
// same token. `zone verify-token` is also the verb an operator reaches
// for while zone writes are failing, which is a moment the server is
// running, so refusing it until the server is stopped would withhold the
// answer exactly when it is wanted. `zone token` writes a credential to
// the volume, which a read-only handle cannot do, and it is the one verb
// here where being refused until the server is stopped is the point
// rather than a cost.
//
// `reports list` and `reports show` are here and `reports forget` is
// not. The two readings answer about rows a peer sent days ago, so a
// copy that stops at the server's last write to disk holds all of them
// but the newest, and the moment an operator wants them is the moment a
// domain looks like it is being spoofed. `reports forget` destroys rows
// and writes the trail saying so, which a read-only handle cannot do,
// and the person who asked for the erasure is owed a verb that either
// did it or said it could not.
//
// `credential list`, `credential show` and `credential bounces` are here
// and the five that change a credential are not. The three resolve where
// a credential's bounces are landing right now, and that reading is the
// only thing that reports a bounce mailbox archived after the credential
// was created: the credential is untouched by it, so nothing else can.
// The moment an operator asks is the moment an application's mail is
// going out and nothing is coming back, which is a moment the server is
// running. Each of them records nothing and writes nothing, and a
// credential issued since the last flush is missing from the answer the
// same way a newly added account is.
var SNAPSHOT_VERBS = Object.freeze({
  account:    Object.freeze(["list", "show"]),
  domain:     Object.freeze(["list", "show"]),
  dkim:       Object.freeze(["list", "records"]),
  zone:       Object.freeze(["preview", "verify", "verify-token"]),
  credential: Object.freeze(["list", "show", "bounces"]),
  reports:    Object.freeze(["list", "show"]),
  blobs:      Object.freeze(["report"]),
  audit:      Object.freeze(["verify-chain"]),
  doctor:     Object.freeze([""]),
});

// That table written the way an operator types it, for the refusal that
// has to name it. The empty verb renders as the group on its own.
//
// The refusal reads this rather than spelling the list out beside it, so
// the commands it names are the commands the fall-back actually takes.
// It states no total: the list is the answer to how many, and a numeral
// written next to it is a second thing to keep in step.
function _snapshotVerbList() {
  var names = [];
  Object.keys(SNAPSHOT_VERBS).forEach(function (group) {
    SNAPSHOT_VERBS[group].forEach(function (verb) {
      names.push(verb === "" ? group : group + " " + verb);
    });
  });
  return _listed(names);
}

// Names joined the way a sentence lists them: "a", "a and b", "a, b and c".
function _listed(names) {
  if (names.length < 2) return names.join("");
  return names.slice(0, -1).join(", ") + " and " + names[names.length - 1];
}

// Where the framework puts the decrypted working copy, resolved the same
// way it resolves it: the operator's override first, then the standard
// memory backed mount. A read-only open decrypts into the same root, so
// it inherits whatever the operator chose and never lands on persistent
// storage that a backup or a disk image would pick up.
//
// Whether a directory is a memory backed mount, asked of the kernel
// rather than inferred from the path being there.
//
// The distinction is the whole point of this function. `/dev/shm` exists
// on a machine because something created a directory with that name, and
// on Linux that something is normally the tmpfs mount, but not always.
// A minimal root filesystem, or a container started without shared
// memory, can carry the name as an ordinary directory on the image's own
// disk, and a decrypted copy written there stays after the process exits
// and is picked up by exactly the backup this design says it never
// reaches.
//
// So the answer comes from the kernel's mount table, which names the
// filesystem type actually mounted at the path. A path that is not a
// mount point at all resolves to whatever filesystem contains it, which
// is the correct answer for a directory somebody created by hand.
//
// The table is read and parsed by `b.safeMountInfo`, which is the
// framework's own reader and the one its residency check uses, so this
// server and the framework cannot disagree about what is mounted where.
// It reads `/proc/self/mountinfo` rather than `/proc/mounts`, which is
// the file that carries mount points with escaped bytes in their names.
//
// Off Linux there is nothing to read and nothing to infer, and both this
// server and the framework refuse. This one refuses first and says which
// platform it is on and which variable to set, which is the difference
// between an operator changing one setting and an operator reading about
// a mount type their machine does not have.
function _memoryBackedMount(dir) {
  if (process.platform !== "linux") return false;
  var entries;
  // allow:swallow-unverified reaching this needs /proc/self/mountinfo to be
  // unreadable or unparsable on a Linux host, which no test can arrange. It
  // fails closed: a mount table nobody could read reports no memory backed
  // mount, and the caller then refuses to open rather than decrypting the
  // volume onto a disk a backup would capture.
  try { entries = b.safeMountInfo.parse(nodeFs.readFileSync(b.safeMountInfo.DEFAULT_PATH, "utf8")); }
  catch (_e) { return false; }
  var mount = b.safeMountInfo.bestMatch(entries, dir);
  var fstype = mount && mount.fstype ? String(mount.fstype) : "";
  return fstype === "tmpfs" || fstype === "ramfs";
}

function _workingCopyRoot() {
  // An operator naming a directory is taken at their word here, and the
  // framework checks it afterwards. On Linux it reads the mount table
  // and refuses a path that is not on a tmpfs or ramfs mount, under
  // `db/tmpdir-not-tmpfs`, naming the filesystem it found and where that
  // filesystem is mounted. Off Linux no mount can be classified, so it
  // warns instead and the directory is used: verify that one out of band
  // and treat it as carrying the same secrets the volume does.
  //
  // The path below is the one this file decides, and it asks the kernel
  // the same way.
  var configured = b.safeEnv.readVar("BLAMEJS_TMPDIR");
  if (configured) return String(configured);
  if (_memoryBackedMount("/dev/shm")) return "/dev/shm";
  throw err("store/no-working-copy-mount",
    "there is no memory backed directory to decrypt into. The database is encrypted at " +
    "rest, so reading it means writing a decrypted copy somewhere, and that somewhere has " +
    "to be memory rather than a disk a backup would capture. " +
    (process.platform === "linux"
      ? "/dev/shm is not a tmpfs mount on this host. "
      : "This is " + process.platform + ", which has no tmpfs, and a directory named " +
        "/dev/shm here would be an ordinary one on disk. ") +
    "Set BLAMEJS_TMPDIR to a memory backed directory. The shipped container has one at " +
    "/dev/shm and needs nothing set; off Linux, point it somewhere you accept a decrypted " +
    "copy living, and treat that path as carrying the same secrets the volume does.");
}

// The refusals that are verdicts about the trail rather than about the
// copy. A rewritten chain is the same finding whether it is read from
// the volume or from a copy of it, and softening one into "the copy
// could not be read" would turn tamper evidence into a transient fault.
var CHAIN_VERDICT_CODES = [
  "db/audit-chain-break",
  "db/audit-checkpoint-break",
  "db/consent-chain-break",
  "store/audit-anchor-mismatch",
  "store/audit-anchor-row-missing",
];

function _isChainVerdict(e) {
  return !!(e && typeof e.code === "string" && CHAIN_VERDICT_CODES.indexOf(e.code) !== -1);
}

// ---------------------------------------------------------------------------
// The chain's anchor on disk
// ---------------------------------------------------------------------------
//
// The audit chain is a sequence of rows each carrying the hash of the one
// before it, and every one of those hashes is computed from columns that
// can be read. Nothing secret goes into them. So somebody who can write
// to the table can edit a row, recompute every hash after it, and leave a
// chain that agrees with itself perfectly.
//
// What they cannot recompute is a checkpoint signature. But they do not
// have to: they can DELETE the checkpoints instead, and the next command
// to open the volume signs a fresh one over the rewritten tip. Verifying
// the chain afterwards walks a consistent sequence, verifies a valid
// signature over its end, and reports the trail intact.
//
// The one thing left is the record the framework writes beside the
// database each time it anchors the chain: the counter it anchored and
// the hash the row at that counter carried. It is written before the
// rewrite and it is not part of the database the rewrite happens in, so a
// recomputed chain no longer agrees with it. Holding one against the
// other is what turns a self-consistent forgery back into a refusal.
//
// It raises the bar rather than closing the door, and the shape of what
// is left is worth stating. The record is an unsigned file on the same
// volume, so somebody who thought of it can rewrite it too, and an
// attacker who holds the passphrase holds the audit-signing key with it.
// The guarantee this layer can make is that a rewrite has to reach
// EVERY copy of the tip, in two places with different protections, and
// that missing one of them is a refusal rather than a clean report.
var AUDIT_ANCHOR_FILE = "audit.tip";

// The framework's own chain table. Named rather than derived because the
// read below is the one place in this repository that touches it.
var AUDIT_TABLE = "audit_log";

// The framework's signed checkpoints over that chain. Named here for the
// one read below that asks whether the checkpoint an archive was made
// against is still on the volume.
var CHECKPOINT_TABLE = "audit_checkpoints";

// Where the framework records that a range of rows was archived and then
// deleted on purpose. It carries the last counter the purge removed and
// the hash that row held, and the chain math reads it to walk across the
// gap. It is the only legitimate reason a counter can have no row behind
// it, so it is what tells a purge apart from a deletion.
var PURGE_ANCHOR_TABLE = "_blamejs_audit_purge_anchor";
var PURGE_ANCHOR_SCOPE = "audit";

// ---------------------------------------------------------------------------
// A finding that survives being read
// ---------------------------------------------------------------------------
//
// The other two refusals repeat themselves. A row that fails its own
// hash still fails it on the next boot, and a checkpoint whose signature
// does not verify still does not, because both readings come out of
// rows nothing has changed in between.
//
// The reading made against the record beside the volume does not repeat,
// and the reason is that the boot consumes it. Opening the volume
// anchors the chain again, which writes a fresh record over the one
// being held against the rows, and it does that before this layer gets
// to compare them. So the comparison fires once, and the second run of
// the same command finds a record that agrees with the rewritten rows
// perfectly and reports the volume intact.
//
// That is the worst possible shape for the one finding that catches a
// wholesale rewrite. An operator who sees a refusal during an incident
// runs it again, to be sure, to capture the output, to show somebody,
// and the second run tells them everything is fine. The refusal itself
// tells them to take a copy of the volume before anything else, and
// running the command again is the thing that destroys what the copy was
// supposed to hold.
//
// So the finding is written down where the re-anchoring cannot reach it,
// and every later open reads it and refuses under the code that raised
// it. The volume stops accepting appends until an operator has finished
// with it and removes the file, which is what "refuses further appends"
// has to mean if it means anything.
//
// It raises the bar rather than closing the door, in the same shape as
// the record it protects: somebody who can write to the volume can
// remove this too. What it costs them is having to come back after the
// refusal has already fired.
var AUDIT_DISPUTE_FILE = "audit.disputed";

// The codes a recorded finding may re-raise under. The file sits on the
// volume, so its contents are as rewritable as the rows are, and a code
// read out of it and raised unchecked would let whoever wrote it choose
// which refusal an operator sees. Nothing outside this set is honored.
var DISPUTE_REFUSAL_CODES = ["store/audit-anchor-mismatch", "store/audit-anchor-row-missing"];

// The code a recorded finding is re-REPORTED under, which is a separate
// list because it is a separate decision.
//
// A refusal above is a reading that CONTRADICTED the record beside the
// volume, and a volume that will not open again until an operator has
// looked at it is the proportionate answer to one. This one is a reading
// that could not be made: the row the record names is gone and what
// accounts for it is a boundary in the database saying where a purge
// stopped, rather than any reading of the range behind it. That is not a
// contradiction, and refusing every later boot on it would stop mail
// over something nothing has established. It still may not evaporate,
// because the reading is destroyed by being made, so it is recorded in
// the same file and carried into every later report instead.
var DISPUTE_REPORT_CODES = ["store/audit-anchor-gap-unproven"];

// What the recorded-finding reader admits, which is both lists and
// nothing else.
var DISPUTE_CODES = DISPUTE_REFUSAL_CODES.concat(DISPUTE_REPORT_CODES);

// The one code above, named where the paths that write it and read it
// back can both reach it, so the two cannot drift into disagreeing about
// which finding is standing.
var GAP_CODE = DISPUTE_REPORT_CODES[0];

// What the recorded finding is read back at. The text is this module's
// own, and a longer one is a file somebody else wrote.
var MAX_DISPUTE_CHARS = 4096;

// What the last reading of the record outside the database concluded,
// held for the handle to report. The verbs that answer questions ABOUT
// the trail have to say whether that reading was made, because a check
// nobody could make and a check that passed are the same exit code and
// opposite facts.
var anchorVerdict = null;

// What the volume recorded at its last anchoring, read before anything in
// the framework runs: opening the volume anchors it again and writes a
// new record over this one.
//
// A record that is absent, truncated or unparseable reads as "nothing
// recorded there" rather than throwing, because the framework documents
// removing this file as the way out of an unreadable one, and a refusal
// here would turn that recovery into a volume that never opens again.
// Absence forfeits the check; it does not fail it.
function _anchorOnDisk(dataDir) {
  var anchorPath = nodePath.join(dataDir, AUDIT_ANCHOR_FILE);
  var raw;
  try {
    raw = b.atomicFile.fdSafeReadSync(anchorPath, {
      maxBytes:      b.constants.BYTES.kib(64),
      refuseSymlink: true,
      encoding:      "utf8",
    });
  } catch (_e) { return null; }
  var parsed;
  try { parsed = JSON.parse(String(raw)); }
  catch (_e2) { return null; }
  if (typeof parsed !== "object" || parsed === null) return null;
  var counter = Number(parsed.atMonotonicCounter);
  var rowHash = String(parsed.atRowHash || "");
  if (!isFinite(counter) || counter <= 0) return null;
  if (!/^[0-9a-f]{128}$/.test(rowHash)) return null;
  return { path: anchorPath, counter: counter, rowHash: rowHash };
}

// Where the finding is written, derived in one place for the three
// callers that name it: the write, the read, and the refusal that tells
// an operator which file to remove when they are done. Nothing a caller
// passes becomes a path segment; the directory is the configured data
// volume and the name is the constant above it.
function _disputePath(dataDir) {
  return nodePath.join(dataDir, AUDIT_DISPUTE_FILE);
}

// Write the finding where the next open will read it, before the throw
// that ends this one.
//
// Best effort, and the direction of the compromise matters: this runs
// inside a refusal that is already leaving. A volume that cannot be
// written to must not turn a refusal an operator can act on into a
// different error about the file the refusal was trying to leave behind.
function _recordDispute(dataDir, code, message) {
  try {
    b.atomicFile.writeSync(_disputePath(dataDir),
      JSON.stringify({ version: 1, code: code, finding: message,
        recordedAt: new Date().toISOString() }) + "\n", { fileMode: 0o600 });
  } catch (_e) { /* drop-silent by design: the refusal below is the answer */ }
}

// A finding this volume recorded on an earlier open, or null.
//
// Nothing the file says is trusted, because the file is on the volume
// being reported about. A code outside the set this module raises, a
// missing finding, or a body longer than one of ours reads as nothing
// recorded: the volume opens, and the reading below runs again
// on rows that will produce the same refusal if they still deserve it.
// Refusing on an unparseable file would hand anybody who can write to
// the volume a way to stop the server with a text editor.
function _disputeOnDisk(dataDir) {
  var raw;
  try {
    raw = b.atomicFile.fdSafeReadSync(_disputePath(dataDir), {
      maxBytes:      b.constants.BYTES.kib(64),
      refuseSymlink: true,
      encoding:      "utf8",
    });
  } catch (_e) { return null; }
  var parsed;
  try { parsed = JSON.parse(String(raw)); }
  catch (_e2) { return null; }
  if (typeof parsed !== "object" || parsed === null) return null;
  if (DISPUTE_CODES.indexOf(parsed.code) === -1) return null;
  var finding = String(parsed.finding || "");
  if (finding.length === 0 || finding.length > MAX_DISPUTE_CHARS) return null;
  return { code: parsed.code, finding: finding };
}

// Refuse the open while a finding stands. Called before anything
// decrypts, so a disputed volume is not taken apart into a working copy
// on the way to being refused.
function _refuseWhileDisputed(dataDir) {
  var dispute = _disputeOnDisk(dataDir);
  if (dispute === null) return;
  // A finding that was reported rather than raised is carried into this
  // boot's verdict further down, not thrown here. It stands over a range
  // nothing established either way, and a volume that stops delivering
  // mail on one of those is a check an operator deletes rather than
  // reads.
  if (DISPUTE_REFUSAL_CODES.indexOf(dispute.code) === -1) return;
  throw err(dispute.code,
    dispute.finding + " This was found on an earlier open and recorded in " +
    _disputePath(dataDir) + ", because opening the volume anchors " +
    "the chain again and writes a fresh record over the one that disagreed, so the " +
    "comparison that found this cannot make itself a second time. This server will not " +
    "append to the trail again until that file is gone. Take a copy of the whole data " +
    "directory first if you have not already, then restore from a backup taken before " +
    "the rewrite. Removing the file without doing that leaves the rewritten trail in " +
    "place and stops anything reporting it.");
}

// Refuse the open while a restore or rollback on this volume has moved
// files and not finished. The restore that is running holds the volume
// apart and is the one caller let through, because opening the volume it
// has just put in place is how it reaches its verdict.
function _refuseWhileRestoreInFlight(dataDir) {
  if (volumeHeldApart === dataDir) return;
  var recordPath = nodePath.join(dataDir, RESTORE_WORK_DIR, RESTORE_IN_FLIGHT);
  if (!nodeFs.existsSync(recordPath)) return;
  throw err("store/restore-interrupted",
    "a restore or rollback on the data directory at " + dataDir + " stopped after it had " +
    "started moving files and before it finished, so the directory holds part of one " +
    "volume and part of another. " + recordPath + " records how far it got. Run " +
    "`blamepost restore rollback --confirm --reason <text>` to put back the volume that " +
    "was there before, then run the restore again if it is still wanted.");
}

/**
 * The counter the volume's own record says its audit trail was anchored
 * at, read from the file beside the database without opening anything,
 * or null when there is no readable record. `blamepost restore apply`
 * reads it from the volume it replaces and from the one it puts in place,
 * to say how far a restore rewinds the trail.
 */
function recordedAnchor(dataDir) {
  var anchor = _anchorOnDisk(dataDir);
  return anchor === null ? null : { counter: anchor.counter };
}

// What the database says about a range that was archived and deleted on
// purpose, or null when this volume has never had one.
//
// What comes back is worth what the row it came out of is worth, and
// what that row is worth is a question with three answers rather than
// one. The row carries a signature over the counter it names, over the
// hash the row at that counter held and over the archive it names, and
// the key that signature is made with is sealed under the same
// passphrase as the database. So a row whose signature holds costs
// whoever wrote it what rewriting the rows costs; a row with no
// signature on it costs write access to the database and nothing more;
// and a row carrying a signature that does not cover the fields it now
// holds is neither, and licenses nothing.
//
// The reader asks the framework which of the three it has and hands the
// answer back with the numbers, because a caller given only a counter
// has no way left to say what the counter is. `licensed` is whether the
// row may account for a gap at all, and `signed` is what it cost. A
// caller that only reads `through` is reading a figure this server
// trusted rather than a range it read, and that distance is the whole
// difference between a retention run and an erasure.
//
// The framework refuses to open a database whose purge anchor does not
// verify, so on the shipped path this reader is asked only about a row
// that already verified. It states its own reading anyway: the policy
// that decides which anchors open a volume is set at `b.db.init`, this
// module does not set it, and a reader that assumed the answer would go
// on reporting it after the assumption stopped holding.
//
// `bundleId` is the archive the row names, and naming it is as far as it
// goes: it is the id of the signed checkpoint that covered the archive's
// last row, not a location, and the bundle itself is a directory the
// operator was told to keep somewhere this server cannot reach. No
// signature over the row establishes that the archive still holds those
// rows, so a verified boundary is still a range nothing here read.
//
// This read stands between a legitimate retention run and a refusal, so
// a value it cannot make sense of has to read as "nothing accounts for a
// gap" rather than as a number it half-trusts. A counter that is absent,
// negative or not a number accounts for nothing, which is the same
// answer as no purge at all and the safe direction to be wrong in.
function _purgeRecord() {
  var row;
  try { row = b.db.from(PURGE_ANCHOR_TABLE).where({ scope: PURGE_ANCHOR_SCOPE }).first(); }
  catch (_e) { return null; }
  if (!row) return null;
  var through = Number(row.lastPurgedCounter);
  if (!isFinite(through) || through < 0) return null;
  var bundleId = typeof row.archiveBundleId === "string" && row.archiveBundleId.length > 0
    ? row.archiveBundleId
    : null;

  var verdict;
  // Reaching the catch needs the framework's verifier to throw on a row
  // it documents as returning a status for. It fails closed: a reading
  // nobody could make licenses nothing, which is the same answer this
  // function gives a row it cannot make sense of.
  try { verdict = b.auditChain.verifyPurgeAnchor(row); }
  catch (e) {
    verdict = { status: "corrupt", reason: "the record could not be read at all (" +
      String(e && e.message ? e.message : e) + ")" };
  }
  var status = String(verdict && verdict.status);

  // Written here, beside the read, rather than at the sentence that uses
  // it: the place that knows which of the three records this volume
  // carries is the place that touched it.
  if (status === "valid") {
    return {
      through:  through,
      bundleId: bundleId,
      licensed: true,
      signed:   true,
      reading:  "a purge record in " + PURGE_ANCHOR_TABLE + " says every row up to " +
        "counter " + through + " was archived and deleted, and its signature holds. The " +
        "signature covers that counter, the hash the row at it carried and the archive " +
        "the record names, and the key it was made with is sealed under this server's " +
        "vault passphrase, so moving the boundary costs what rewriting the rows costs. " +
        "What it does not cover is whether the archive still holds those rows.",
    };
  }
  if (status === "unsigned") {
    return {
      through:  through,
      bundleId: bundleId,
      licensed: true,
      signed:   false,
      reading:  "an unsigned purge record in " + PURGE_ANCHOR_TABLE + " says every row up " +
        "to counter " + through + " was archived and deleted. That row carries no " +
        "signature over it, is linked into no chain, is covered by no checkpoint and has " +
        "no append-only trigger over it, so writing it is the whole cost of making a " +
        "deletion read as a retention run. A purge signs the row it writes, so this one " +
        "did not come from a purge this server performed.",
    };
  }
  return {
    through:  through,
    bundleId: bundleId,
    licensed: false,
    signed:   false,
    reading:  "a purge record in " + PURGE_ANCHOR_TABLE + " claims every row up to " +
      "counter " + through + " was archived and deleted, and its signature does not " +
      "stand: " + String(verdict && verdict.reason) + ". A record that does not verify " +
      "accounts for nothing, so the counter with no row behind it is a deletion this " +
      "server cannot explain.",
  };
}

// Which of the readings above stands between the gap and the refusal,
// written as the sentence the refusal carries. Three answers rather than
// two, because a volume that has never been purged, one whose purge
// stopped below the gap and one whose purge record does not verify send
// an operator to three different places.
function _gapAccount(purge, counter) {
  if (purge === null) {
    return "No range has been archived and purged from this volume, so nothing accounts " +
      "for a counter with no row behind it.";
  }
  if (!purge.licensed) return "Nothing accounts for it: " + purge.reading;
  return "The last archive and purge on this volume ended at counter " + purge.through +
    ", so it does not account for counter " + counter + ".";
}

// What this volume can say about the archive the purge record names, and
// the answer is narrower than the question an operator is asking.
//
// It resolves nothing to a bundle, and that is a property of the design
// rather than a gap in it. `archiveBundleId` is the id of the signed
// checkpoint that covered the archive's last row; the bundle is a
// directory, and the verb that writes one tells the operator to keep it
// and its passphrase somewhere this server cannot reach. A check that
// needed the bundle present would refuse exactly the operator who did
// what they were told.
//
// The narrower question is worth asking anyway. An honest purge relinks
// nothing, so every surviving row keeps the hash it had and the
// checkpoints over them keep verifying. A rewrite that deleted rows and
// relinked what was left changes every surviving hash, so it has to
// delete every checkpoint covering them. A checkpoint that is still here
// above the purged range is therefore something the rewrite could not
// have left behind. That says the rows that remain were not relinked,
// and says nothing at all about the rows that are gone.
//
// The one thing this must not do is read a name that resolves to nothing
// as the end of the argument. `_nameResolvesToNothing` carries why: the
// framework's archive and purge bounds are both inclusive and meet on a
// single counter, so an ordinary retention run produces exactly that
// state whenever its cut lands on a checkpoint.
function _coveringCheckpoint(record, verified) {
  if (record.bundleId === null) {
    return { ok: false, reason: "The record names no archive at all, so there is nothing " +
      "here to look for. " };
  }
  var row;
  // allow:swallow-unverified reaching this needs the checkpoint table read
  // to fail on an open database. It fails closed: a read nobody could make
  // reads as no checkpoint, which routes to the unproven verdict below
  // rather than to one that says the trail verified.
  try { row = b.db.from(CHECKPOINT_TABLE).where({ _id: record.bundleId }).first(); }
  catch (_e) { row = null; }
  if (!row) return _nameResolvesToNothing(record, verified);
  var at = Number(row.atMonotonicCounter);
  if (!isFinite(at) || at < record.through) {
    return { ok: false, reason: "The record names " + record.bundleId + ", which is a " +
      "checkpoint standing at counter " + String(row.atMonotonicCounter) + ", below the " +
      "range the record says was deleted, so it covers none of it. " };
  }
  return { ok: true, counter: at, reason: _survivorReading(at, verified, true) };
}

// The record names a checkpoint and nothing on this volume carries that
// id, which reads like the end of the argument and is not.
//
// It was written as one: an archive names the checkpoint that covered its
// last row, that checkpoint outlives the purge, so a name resolving to
// nothing is a record no archive this server wrote would have left. The
// middle step is false, and it is false on the framework's own bounds.
// An archive covers itself with the EARLIEST checkpoint standing at or
// above its last row, and the purge that archive authorizes deletes every
// checkpoint at or below that same counter. Both are inclusive, so they
// meet on one counter: a cut landing exactly on a checkpoint names one
// its own purge then removes.
//
// So this state is what an ordinary retention run leaves whenever the cut
// lands on a checkpoint, and it is also what a rewrite that deleted the
// checkpoints leaves. This reading does not separate them, and saying it
// does hands an operator who has just run a documented retention verb an
// accusation of forgery about it. That is how a check gets deleted rather
// than fixed.
//
// What is still worth reading is whether ANY checkpoint survives above
// the purged range, because the rewrite that would explain this has to
// delete every checkpoint over the rows it relinked. One standing above
// the cut is one that rewrite could not have left, and that is a real
// statement about the rows that remain. It is not a statement about the
// rows that are gone, which is the range this whole verdict is over, so
// the finding stays unproven either way.
function _nameResolvesToNothing(record, verified) {
  var boundary = "The record names " + record.bundleId + " as the archive it was made " +
    "for, and no checkpoint on this volume carries that id. On its own that separates " +
    "nothing: an archive covers itself with the earliest checkpoint standing at or above " +
    "the last row it archived, and the purge deletes every checkpoint at or below that " +
    "same counter, so a cut that landed on a checkpoint names one its own purge removed. " +
    "An ordinary retention run leaves this, and so does a rewrite that deleted the " +
    "checkpoints. ";
  var later;
  try {
    later = b.db.from(CHECKPOINT_TABLE)
      .where("atMonotonicCounter", ">", record.through)
      .orderBy("atMonotonicCounter", "asc")
      .limit(1)
      .first();
    // allow:swallow-unverified reaching this needs the checkpoint table read
    // to fail on an open database. It fails closed the same way the read
    // above does: no surviving checkpoint is the unproven verdict, which is
    // what this function returns for it.
  } catch (_e) { later = null; }
  var at = later ? Number(later.atMonotonicCounter) : NaN;
  if (!later || !isFinite(at)) {
    return { ok: false, reason: boundary + "No checkpoint stands above counter " +
      record.through + " either, so nothing on this volume says the rows that are still " +
      "here were left unrelinked. " };
  }
  return { ok: false, reason: boundary + _survivorReading(at, verified, false) };
}

// What one surviving checkpoint is worth, which is the same reading
// whether it is the one the record named or a later one standing in for
// it.
//
// A rewrite that deleted rows and relinked what was left changes the hash
// of every surviving row, so it has to delete every checkpoint over them.
// One still standing is therefore one that rewrite could not have left
// behind. That is a statement about the rows that remain and about
// nothing else, and the sentence ends by saying so, because the range
// being reported on is exactly the range nothing read.
//
// `verified` is true only when this handle read the volume itself. The
// framework refuses to open a database whose checkpoint signatures do not
// hold, so on the volume a checkpoint that is present is one that
// verified during this open. A private copy is opened with the signing
// key left sealed, so there the row's presence is all that was read and
// the sentence has to say so rather than borrowing the stronger one.
function _survivorReading(at, verified, named) {
  return (named
    ? "What is here is the signed checkpoint that id names, at counter " + at
    : "What is here instead is a later checkpoint, at counter " + at) +
    ", still on this volume" + (verified
      ? " with its signature verified by this open"
      : " though its signature was not read, because a private copy is opened with the " +
        "signing key left sealed") +
    ". A rewrite that deleted rows and relinked what was left changes the hash of every " +
    "surviving row and has to delete every checkpoint over them, so this one surviving " +
    "says the rows that are still here were not relinked. It says nothing about the " +
    "rows that are gone. ";
}

// Hold the record above against the rows that are now in the database,
// and report which of the three things happened.
//
// A row that is still there and hashes differently is the refusal this
// record exists for. The other two are the ones worth being careful
// about, because both look like nothing at all.
//
// A counter with NO row behind it is not an ordinary state, and reading
// it as one is how the whole check is stepped around. Somebody rewriting
// the trail does not have to leave the anchored row hashing differently:
// they can delete it, relink what is left, and put the counter back with
// a row above it, and then the chain agrees with itself, the table has
// not shrunk so the rollback check has nothing to say, and the one
// witness left is a comparison against a row that is no longer there.
// There is exactly one legitimate way for a counter to lose its row,
// which is archiving a range and purging it, and the framework writes
// down where that ended, so a gap at or below the purge point is
// accounted for and a gap above it is a deletion.
//
// What the purge record accounts FOR is narrower than what it looks
// like it accounts for, and the distance between those two is the whole
// of the third verdict below. The record is a row in a table with no
// signature over it, no link into the chain, no checkpoint covering it
// and no append-only trigger guarding it, and the same hands that delete
// the rows can write it. So a gap at or below the counter it names is a
// gap this server may go on running across, and it is not a gap this
// server has checked: the rows in it were never read, and nothing here
// resolved the archive the record names. The verdict says the second,
// because what is reported has to be bounded by what was read.
//
// A record that is absent forfeits the check rather than failing it. The
// framework documents removing the file as the way out of an unreadable
// one and skips its own rollback check without it, so refusing here
// would turn that recovery into a volume that never opens again. What
// absence must not do is pass quietly: the verdict says the reading was
// not made, and the verbs that report on the trail say so rather than
// printing that nothing has been altered.
//
// `record` is true only for the volume itself. A private copy is read
// while the server holds the volume, so its rows are a moment behind the
// record beside them, and a finding raised there is one an operator can
// read and act on but not one this layer may write down: a reporting
// verb that could refuse the running server's next boot is a verb an
// operator learns not to run during an incident.
function _readAnchor(anchor, record) {
  if (anchor === null) {
    return {
      checked: false,
      reason:  "this volume carries no readable record of its last anchoring, so the " +
        "rows were held against nothing outside the database they live in. A trail " +
        "rewritten in full agrees with itself, and the checkpoints over it can be " +
        "deleted rather than forged, so a wholesale rewrite looks exactly like this. " +
        "The record is written again the next time this volume is opened, which is any " +
        "blamepost command at all; on a volume that has been opened before, its absence " +
        "is itself the finding.",
    };
  }

  var row = b.db.from(AUDIT_TABLE).where({ monotonicCounter: anchor.counter }).first();

  if (!row) {
    var purge = _purgeRecord();
    if (purge !== null && purge.licensed && anchor.counter <= purge.through) {
      return _unprovenGap(anchor, record, purge);
    }
    throw _dispute(anchor, record, "store/audit-anchor-row-missing",
      "the audit trail on this volume is missing the row the volume's own record names. " +
      anchor.path + " says the audit row at counter " + anchor.counter + " hashed to " +
      anchor.rowHash.slice(0, 16) + "..., and there is no row at that counter now. " +
      _gapAccount(purge, anchor.counter) +
      " Deleting the anchored row and relinking what is left is what makes a rewritten " +
      "trail agree with itself while leaving the record with nothing to compare against, " +
      "so the chain alone would have reported this volume as intact.");
  }

  if (String(row.rowHash) !== anchor.rowHash) {
    throw _dispute(anchor, record, "store/audit-anchor-mismatch",
      "the audit trail on this volume does not match the volume's own record of it. " +
      anchor.path + " says the audit row at counter " + anchor.counter + " hashed to " +
      anchor.rowHash.slice(0, 16) + "..., and that row now hashes to " +
      String(row.rowHash).slice(0, 16) + ".... The rows have been rewritten since the trail " +
      "was last anchored, and rewriting them all is what makes the chain agree with itself " +
      "again, so the chain alone would have reported this volume as intact.");
  }

  return { checked: true, counter: anchor.counter, purged: false, proven: true };
}

// The third verdict: the anchored row is gone and a purge record in the
// database says a purge took it.
//
// This is not a refusal and it is not a pass, and collapsing it into
// either one is how the check stops meaning anything. Refusing would
// stop a volume that may have been through an ordinary retention run,
// which is the failure that gets a check deleted rather than fixed.
// Passing is what was here before, and what it printed was worse than
// nothing: that a verified archive had removed the range, having
// verified no archive, and that no row had been inserted, altered or
// removed, over a range of rows it did not read. Those two sentences are
// exactly what somebody erasing a trail needs an operator to be told.
//
// So it is a reading that was NOT made, reported as one, with the counter
// named and with what would have to be true for the gap to be sound
// spelled out. An operator holding the archive bundle for that range can
// close it in a minute; an operator who has no such bundle has just been
// handed the finding.
//
// It is written down as well, because this reading is destroyed by being
// made. Opening the volume anchors the chain again over a surviving row,
// so the record that named the vanished counter is gone by the second
// run and every later run sees an ordinary volume. The refusals beside
// it survive that by being recorded; this one has to be recorded for the
// same reason and under its own code, so the file it shares with them
// does not turn an unproven gap into a volume that will not boot.
function _unprovenGap(anchor, record, purge) {
  var dataDir  = nodePath.dirname(anchor.path);
  var covering = _coveringCheckpoint(purge, record);
  var finding =
    "The row this volume's own record of its last anchoring names is not here, and what " +
    "accounts for it is " + (purge.signed ? "a purge boundary" : "an unsigned counter") +
    " rather than anything this server read of the range behind it. " +
    anchor.path + " says the audit row at counter " + anchor.counter + " hashed to " +
    anchor.rowHash.slice(0, 16) + "..., and " + purge.reading + " " + covering.reason +
    "So the rows at or below counter " + purge.through + " were not read by this check, " +
    "and nothing on this volume says what was in them. What would settle it is the archive " +
    "bundle covering that range, which is off this volume by design: read it back with " +
    "`blamepost audit verify-bundle --in <dir> --passphrase-file <path>` and hold its " +
    "counters against " + purge.through + ". If no bundle covers the range, those rows " +
    "were removed rather than archived.";
  // Written once and used twice on purpose. The operator who sees this
  // on the run that found it needs to know a second run will still say
  // it, and the operator who sees it on the tenth run needs to know why
  // the tenth run could still say it. One sentence answers both, and two
  // copies of it would be two chances for the file and the terminal to
  // stop agreeing about what happened.
  var recorded = " This reading is recorded in " + _disputePath(dataDir) + " because " +
    "opening the volume anchors the chain again over a row that is still here, so the " +
    "comparison that found this cannot make itself a second time. Every later run " +
    "reports it from that file. Remove the file once the range is accounted for; the " +
    "volume goes on running either way.";
  if (record) _recordDispute(dataDir, GAP_CODE, finding + recorded);
  return {
    checked:  true,
    counter:  anchor.counter,
    purged:   true,
    proven:   false,
    // What the record holding the gap open cost whoever wrote it, carried
    // so a caller reporting this does not have to read the sentence to
    // find out which of the two it has.
    signed:   purge.signed,
    through:  purge.through,
    bundleId: purge.bundleId,
    covering: covering.ok ? covering.counter : null,
    reason:   record ? finding + recorded : finding,
  };
}

// A gap found on an earlier open, carried into this boot's reading.
//
// Every other verdict on this path can be re-derived, because both sides
// of the comparison are still there to compare. This one cannot: the run
// that found the gap re-anchored the chain over a surviving row on its
// way out, so the second run holds a record that agrees with the rows
// perfectly and has no way back to the question. Reading the finding
// back is what makes the answer the same on the tenth run as on the
// first.
//
// A gap this boot found for itself wins, because it was derived from the
// rows rather than read out of a file on the volume being reported
// about.
function _standingGap(dataDir, verdict) {
  if (verdict && verdict.proven === false) return verdict;
  var recorded = _disputeOnDisk(dataDir);
  if (recorded === null || recorded.code !== GAP_CODE) return verdict;
  // What held the gap open is read again rather than carried in the
  // file. The record is still in the database, unlike the comparison
  // that found the gap, and a verdict that dropped it would answer a
  // monitor one way on the run that found the gap and another way on
  // every run after it, over rows nothing had touched.
  var purge = _purgeRecord();
  var carried = {
    purged:   true,
    proven:   false,
    standing: true,
    reason:   recorded.finding,
  };
  // Only when there is a record to read it from. A run that finds none
  // has not established that the boundary was unsigned, and saying so
  // would put the verdict at odds with the sentence beside it.
  if (purge !== null) carried.signed = purge.signed;
  return Object.assign({}, verdict, carried);
}

// Record the finding beside the volume and hand back the refusal to
// raise. One function because the two findings differ in what they
// found and in nothing else, and because a finding recorded on one path
// and not the other is a refusal that fires once.
//
// The advice is here rather than in each message so the text written to
// the file and the text an operator reads on the first refusal are the
// same words, and so the file cannot drift into carrying a finding with
// no instruction attached to it.
function _dispute(anchor, record, code, finding) {
  var message = finding +
    " Take a copy of the whole data directory before anything else, because the state at " +
    "this moment is the evidence and a restart overwrites some of it, then restore from a " +
    "backup taken before the rewrite.";
  if (record) _recordDispute(nodePath.dirname(anchor.path), code, message);
  return err(code, message);
}

// The same reading, recorded where the handle can report it. It is set
// before anything else reads the database, so a verb that opens and then
// asks what the anchor said gets this boot's answer rather than a stale
// one from a previous open in the same process.
//
// The reading this boot makes is held against the one an earlier boot
// wrote down, because one of the three verdicts cannot be made twice.
// `dataDir` is taken rather than derived from the anchor, since the
// anchor is null on exactly the volume where a finding may still be
// standing.
function _assertAnchorAgrees(dataDir, anchor, record) {
  anchorVerdict = _standingGap(dataDir, _readAnchor(anchor, record === true));
}

// Which process table the lock's PID belongs to.
//
// A container and its host share a kernel and not a process namespace,
// so PID 8 inside a container and PID 8 on the host are unrelated, and
// probing one against the other answers a question nobody asked. The
// namespace link is the fact that tells them apart. Where it cannot be
// read the hostname stands in, which is weaker but still a fact about
// the running system: a container carries its own by default.
function _processNamespace() {
  try { return String(nodeFs.readlinkSync("/proc/self/ns/pid")); }
  catch (_e) { return "host:" + nodeOs.hostname(); }
}

// What the lock file says, or null when there is no readable lock. The
// read is capped and refuses a symlink, because a lock file is never
// legitimately either a large file or a link, and this one is read
// before the vault is open.
//
// A missing, truncated or unparseable lock reads as "nothing recorded
// there" rather than throwing. The decision that follows is made on what
// was recorded, and an absent record leaves the liveness probe to answer.
function _recordedOwner(lockPath) {
  var raw;
  try {
    raw = b.atomicFile.fdSafeReadSync(lockPath, {
      maxBytes:       b.constants.BYTES.kib(1),
      refuseSymlink:  true,
      encoding:       "utf8",
    });
  } catch (_e) { return null; }
  var lines     = String(raw).split("\n");
  var pid       = parseInt(String(lines[0] || "").trim(), 10);
  var namespace = String(lines[1] || "").trim();
  return {
    pid:       isFinite(pid) && pid > 0 ? pid : null,
    namespace: namespace.length > 0 ? namespace : null,
  };
}

// Take the volume, or refuse and say who has it.
//
// Two refusals, because there are two things that can be known. A lock
// recorded in another process namespace cannot be probed from here at
// all, so it is refused without being reaped: reaping it would mean
// deciding a process is dead on the strength of a lookup in the wrong
// table, and that decision is the one that loses mail. A lock in this
// namespace is probed, and a holder that is genuinely gone has its lock
// reaped so a killed server does not lock the operator out of their own
// data.
function _holdVolume(dataDir) {
  var lockPath = nodePath.join(dataDir, VOLUME_LOCK);
  var recorded = _recordedOwner(lockPath);
  var ours     = _processNamespace();

  if (recorded !== null && recorded.namespace !== null && recorded.namespace !== ours) {
    throw err("store/volume-in-use",
      "the data directory at " + dataDir + " is held by process " +
      (recorded.pid === null ? "(unrecorded)" : recorded.pid) + " in a different process " +
      "namespace, so this process cannot tell whether it is still running. That is what a " +
      "server running in a container looks like from the host. Run the command inside the " +
      "same container, with `docker exec <container> blamepost ...`, so the lock is checked " +
      "against the process table that owns it. If that server is gone for good, remove " +
      lockPath + " and run this again.");
  }

  var lock = b.appShutdown.pidLock(lockPath);
  try {
    lock.acquire();
  } catch (e) {
    if (e && e.code === "app-shutdown/pidlock-held") {
      throw err("store/volume-in-use",
        "the data directory at " + dataDir + " is already open for writing in process " +
        (recorded && recorded.pid !== null ? recorded.pid : "(unknown)") + ". blamepost " +
        "decrypts the whole database into a working copy of its own while it is open and " +
        "writes that copy back, so two writers cannot see each other's work and whichever " +
        "writes last overwrites the other, losing every message delivered in between. " +
        "Stop the server and run this again. These verbs answer without stopping it, from a " +
        "read-only open, while the volume's schema is the one this release reads: " +
        _snapshotVerbList() + ". A verb that reports and also records " +
        "that it read is not among them, because recording the read is a write.");
    }
    throw e;
  }

  // Record which process table the PID above belongs to, so the next
  // process to come along can tell whether probing it means anything.
  // A lock that cannot be recorded in full is not a lock this layer can
  // honor, so it is given back rather than left half written.
  try {
    nodeFs.writeFileSync(lockPath, String(process.pid) + "\n" + ours + "\n");
  } catch (e2) {
    // allow:swallow-unverified this is the cleanup on the path where the
    // lock file could not be written, so reaching it needs two filesystem
    // faults in one call; the refusal thrown below is the verdict and a
    // release that refuses must not replace it.
    try { lock.release(); } catch (_e) { /* drop-silent: the throw below is the verdict */ }
    throw err("store/volume-lock-unwritable",
      "the lock at " + lockPath + " could not be written: " +
      ((e2 && e2.message) || String(e2)) + ". The data directory has to be writable by the " +
      "process that serves from it, because the database is decrypted and written back " +
      "there. Check its ownership and permissions.");
  }

  volumeLock = lock;
}

// Give the volume back. Safe when nothing is held, so a shutdown path
// does not need to know how far the boot got. A lock `holdVolume` took is
// given back only by the release that call returned.
function _releaseVolume() {
  if (volumeLock === null || volumeHeldApart !== null) return;
  var lock = volumeLock;
  volumeLock = null;
  // Drop-silent by design: the release runs on the failure path too,
  // where a lock file already removed by a reaper is ordinary, and
  // throwing here would replace whatever sent us down this path.
  // allow:swallow-unverified the release runs on the failure path too, where
  // a lock file a reaper already removed is ordinary rather than a fault, and
  // throwing here would replace whatever sent the caller down this path.
  try { lock.release(); } catch (_e) { /* drop-silent by design */ }
}

/**
 * Take the data directory's lock without opening anything, and hand back
 * `{ release }`. Refused under `store/volume-in-use` exactly as `open`
 * refuses, so a restore meets the same answer a second server does.
 *
 * While the lock is held this way, `open` and `openSnapshot` of the same
 * directory proceed without taking it, and `close` leaves it held. That
 * is what lets `blamepost restore` move the files on a volume, open the
 * result to verify it, and move the files back if it does not verify,
 * with no moment in between at which another process could take the
 * volume. The directory is created at mode 0700 when it does not exist,
 * which is what a restore onto a new host starts from.
 */
function holdVolume(cfg) {
  _requireConfig(cfg, "store.holdVolume");
  if (volumeLock !== null) {
    throw err("store/volume-already-held",
      "store.holdVolume: this process already holds a data directory. Close the store or " +
      "release the earlier hold first.");
  }
  nodeFs.mkdirSync(cfg.paths.dataDir, { recursive: true, mode: 0o700 });
  _holdVolume(cfg.paths.dataDir);
  volumeHeldApart = cfg.paths.dataDir;
  return {
    release: function () {
      if (volumeHeldApart === null) return;
      volumeHeldApart = null;
      _releaseVolume();
    },
  };
}

// Both doors onto a volume are answered here, so `label` is the verb the
// caller actually invoked. A refusal names the call an operator made, and
// a reporting verb refusing under the writing verb's name sends them to a
// call they did not make.
function _requireConfig(cfg, label) {
  if (typeof cfg !== "object" || cfg === null ||
      typeof cfg.paths !== "object" || cfg.paths === null ||
      typeof cfg.vaultPassphrase !== "string") {
    throw err("store/bad-config",
      label + " takes the object config.load returned. It needs the resolved paths and the " +
      "vault passphrase, and neither can be filled in later: the database is encrypted at rest " +
      "and the vault holds its key.");
  }
  // Before the volume is held and before anything is created under it.
  // `load` resolves these, so this speaks for a caller that built the
  // table by hand: a relative base puts the sealed vault key, the sealed
  // audit-signing key and the encrypted database in whichever tree the
  // process was started from, and the subsystems built at the end of the
  // open are too late to be the ones that refuse it.
  //
  // The whole table rather than the two entries this file dereferences by
  // name. The directory maker answers for the rest of them and the
  // reporting open never calls it, so a check limited to those two holds
  // an entry such as `blobs` to the rule at one door and accepts it at
  // the other. This runs at both, and it creates nothing, which is what
  // lets the reporting open run it at all.
  config.assertAbsoluteDataPaths(label + ": cfg.paths", cfg.paths);
  if (typeof cfg.paths.dataDir !== "string" || typeof cfg.paths.database !== "string") {
    throw err("store/bad-config",
      label + " needs cfg.paths.dataDir and cfg.paths.database. The volume is held under the " +
      "first and the encrypted database is read from the second, so a table missing either " +
      "name says nothing about what to open.");
  }
  return cfg;
}

// Hand the operator's passphrase to the framework through the variables
// its passphrase source reads, run the unsealing, and put the
// environment back the way it was. The secret is in the environment only
// while the keys are being unwrapped, rather than sitting there for
// every child process the server ever spawns.
//
// A variable the operator set themselves is left exactly as they set
// it, so an operator keeping the two keys under separate passphrases
// keeps them.
async function _withPassphrase(cfg, unseal) {
  var supplied = [];
  var i;
  for (i = 0; i < FRAMEWORK_PASSPHRASE_VARS.length; i += 1) {
    var name = FRAMEWORK_PASSPHRASE_VARS[i];
    var already = Object.prototype.hasOwnProperty.call(process.env, name) &&
      String(process.env[name]).length > 0;
    supplied.push(already);
    if (!already) process.env[name] = cfg.vaultPassphrase;
  }
  try {
    return await unseal();
  } finally {
    for (i = 0; i < FRAMEWORK_PASSPHRASE_VARS.length; i += 1) {
      if (!supplied[i]) delete process.env[FRAMEWORK_PASSPHRASE_VARS[i]];
    }
  }
}

/**
 * @primitive blamepost.store.open
 * @signature blamepost.store.open(cfg)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: ordered boot of directories, vault and database)
 * @related   blamepost.store.close, blamepost.config.load, blamepost.store.resolve
 *
 * Bring the identity layer up and return its handle. Takes the data
 * directory's lock, creates the data directories, unseals the vault with
 * the configured passphrase, opens the encrypted database, reconciles
 * the identity and mailbox schemas, and registers the audit namespaces
 * the account, domain and alias records file under. Calling it again
 * returns the same handle rather than opening a second one, because the
 * framework's database is a singleton and so is this.
 *
 * One process at a time WRITES the data directory, and the second is
 * refused under `store/volume-in-use` before anything is decrypted. The
 * database is encrypted at rest, so each writer takes the whole file
 * apart into a working copy of its own and writes that copy back; two of
 * them cannot see each other's work, so whichever writes last overwrites
 * everything the other stored. The refusal names the process holding the
 * volume, and it is checked by asking the kernel whether that process is
 * there rather than by taking anyone's word for it. A lock left by a
 * process that has since died is reaped, so a server that was killed
 * does not lock its operator out. A lock recorded in a different process
 * namespace, which is what a containerised server looks like from the
 * host, is refused rather than reaped, because from here there is no
 * process table in which to check it.
 *
 * A reader takes no part in that and takes no lock:
 * `blamepost.store.openSnapshot` opens the same volume read-only, never
 * writes the encrypted file, and so has nothing to lose the race with.
 *
 * The handle carries `accounts`, `domains`, `aliases` and `resolve`,
 * plus `mailbox`, the adapter the wire listeners read and write
 * through, and `messageStore`, the `b.mailStore` underneath it that
 * the mailbox access agent dispatches over. `blobs` is the reader that
 * holds the sealed message octets on disk against the rows naming
 * them, for `blamepost blobs` and for `blamepost doctor`.
 *
 * `credentials` is the sending-credential registry, composed against
 * the four handles above it so a credential is issued, verified and
 * withdrawn through one registry over one volume. It arms a counter
 * cache at construction and `blamepost.store.close` gives that back.
 *
 * It also carries `auditAnchor`, which is what this boot's reading of
 * the record beside the database concluded, in three shapes rather than
 * two. `{ checked: true, counter, purged: false, proven: true }` is the
 * rows held against the record and agreeing with it. `{ checked: false,
 * reason }` is no readable record to hold them against. And
 * `{ checked: true, counter, purged: true, proven: false, signed,
 * through, bundleId, covering, reason }` is the row the record names
 * being gone with a purge boundary in the database across it: a gap this
 * server goes on running over and has NOT checked, since the rows in it
 * were never read and nothing here resolves the archive the boundary
 * names. `signed` is whether the framework's signature over that
 * boundary holds, which is what the record cost whoever wrote it and not
 * a reading of the range behind it. The verbs that report on the trail
 * print all three apart, because a reading nothing could make, a reading
 * trusted on a boundary and a reading that passed are the same exit code
 * and three different facts.
 *
 * Two refusals come out of that reading, both raised before the handle
 * exists. `store/audit-anchor-mismatch` is the row the record names
 * hashing differently now; `store/audit-anchor-row-missing` is that row
 * being gone, with no archive and purge to account for the gap, which
 * covers a purge boundary whose signature does not verify as well as a
 * volume that has never been purged. Both are what a trail rewritten in
 * full with its checkpoints deleted looks like from outside the
 * database, and both are written to `audit.disputed` on the volume
 * before they are raised, because opening the volume anchors the chain
 * again and replaces the record that disagreed. Every later open reads
 * that file and refuses under the same code until an operator removes
 * it.
 *
 * The third verdict is written to the same file under
 * `store/audit-anchor-gap-unproven`, for the same reason and with the
 * opposite consequence: it is re-REPORTED on every later open and never
 * raised. The reading cannot be made twice, because this boot re-anchors
 * the chain over a row that is still there, so without the file the
 * second run reports an ordinary volume. Refusing on it would stop mail
 * over a range nothing has established either way, so the volume keeps
 * running and keeps saying what it could not check until an operator
 * accounts for the range and removes the file.
 *
 * @example
 *   var store = require("./lib/store");
 *   var handle = await store.open(require("./lib/config").load());
 *   handle.resolve("alice@example.com").deliverable;
 */
async function open(cfg) {
  if (handle) return handle;
  _requireConfig(cfg, "store.open");
  if (volumeHeldApart !== null && volumeHeldApart !== cfg.paths.dataDir) {
    throw err("store/volume-already-held",
      "store.open: this process holds the data directory at " + volumeHeldApart +
      " and was asked to open " + cfg.paths.dataDir + ".");
  }

  // Before the directories are created. A volume a restore stopped
  // partway through is missing some of them, and creating them here would
  // put empty directories where the undo has to move the real ones back.
  _refuseWhileRestoreInFlight(cfg.paths.dataDir);

  config.ensureDataDirectories(cfg);

  // Before anything decrypts. Every step below this line writes into the
  // volume or reads a working copy out of it, and both are destructive
  // when a second process is already doing the same.
  if (volumeHeldApart !== cfg.paths.dataDir) _holdVolume(cfg.paths.dataDir);

  try {
    // Inside the block that gives the volume back, because this refuses.
    // A refusal raised between taking the lock and reaching the unwind
    // below would leave the lock held by a process that is on its way
    // out, and the next command would be refused against it.
    //
    // Before anything decrypts, so a volume with a finding standing
    // against it is refused rather than taken apart into a working copy
    // on the way to being refused.
    _refuseWhileDisputed(cfg.paths.dataDir);

    // Read before the framework runs, and after the lock, so nothing else
    // is writing it while it is read. Opening the volume anchors the chain
    // again and writes a new record over this one, so a read placed further
    // down would be a read of what this boot had just written, and would
    // agree with the rows no matter what had been done to them.
    var anchor = _anchorOnDisk(cfg.paths.dataDir);

    return await _openHeldVolume(cfg, anchor);
  } catch (e) {
    // A boot that got part way still holds the volume, and the next
    // attempt would refuse against this process rather than reporting
    // whatever actually went wrong. Put the database and the lock back
    // the way they were, and re-raise what really failed.
    try { b.db.close(); }
    catch (_e) { /* drop-silent by design: nothing had opened, or it is already shut */ }
    _releaseVolume();
    throw e;
  }
}

// The boot itself, with the volume already held. It is a function of its
// own so the lock has one release path rather than one per step that can
// fail, and so the ordering above reads as what it is: take the volume,
// build on it, give it back if the build does not finish.
async function _openHeldVolume(cfg, anchor) {
  await _unsealAndOpen(cfg, {});

  // The framework has walked the chain and verified the checkpoints by
  // now and would not have handed back a database that failed either.
  // Both of those read the database alone, and a chain rewritten in full
  // with its checkpoints removed passes both. This is the reading that
  // comes from outside it, and the volume itself is the one place a
  // finding from it is written down: the boot above has already replaced
  // the record being held against the rows, so nothing would find this
  // again.
  _assertAnchorAgrees(cfg.paths.dataDir, anchor, true);

  return _buildHandle(cfg, null);
}

// Register the namespaces, unseal the vault and open the database, with
// whatever the caller needs to change about where the database is read
// from. One function because the volume and a private copy of it differ
// in three options and in nothing else, and two copies of this ordering
// would be two chances to get it wrong.
async function _unsealAndOpen(cfg, dbOverrides) {
  var readOnly = (dbOverrides || {}).readOnly === true;
  for (var i = 0; i < AUDIT_NAMESPACES.length; i += 1) {
    b.audit.registerNamespace(AUDIT_NAMESPACES[i]);
  }

  await _withPassphrase(cfg, async function () {
    if (b.vault.getMode() === null) {
      await b.vault.init({ dataDir: cfg.paths.dataDir, mode: "wrapped" });
    }
    await b.db.init(Object.assign({
      // The data directory stays the real one even when the database
      // being read is a copy somewhere else. It is not only where the
      // files are: the sealed database key and the envelope around the
      // database are both bound to this path, so a copy opened under any
      // other name fails to decrypt.
      dataDir: cfg.paths.dataDir,
      atRest:  "encrypted",
      // Where the decrypted working copy goes, decided here rather than
      // left to be guessed. The framework's own default tests whether a
      // directory named /dev/shm is present, and off Linux it now infers
      // nothing at all and refuses. On Linux it still reads the name as
      // the mount: a host or image carrying /dev/shm as an ordinary
      // directory passes both the resolution and the residency check
      // that follows it, because that check compares the resolved path
      // against the same name rather than against what is mounted.
      //
      // `_workingCopyRoot` asks the kernel instead, so this refuses on a
      // host with no memory backed mount rather than writing plaintext
      // to a disk. Supplying the value also settles the question ahead
      // of the framework on every platform, so the refusal an operator
      // reads is this server's, naming the setting it wants.
      tmpDir:  _workingCopyRoot(),
      // Two sets of declarations reconciled into one database: the
      // identity tables this layer owns, and the mailbox tables the
      // protocol adapter owns. Each is declared beside the code that
      // reads it, so neither can drift from its reader.
      schema:  _declaredSchema(),
      // The migrations run after the reconcile and each one writes. The
      // framework skips the reconcile on a read-only open and does not
      // skip migrations, so a read-only open is handed none.
      migrationDir: readOnly ? null : MIGRATION_DIR,
    }, dbOverrides || {}));
  });
}

// The members every caller gets, whether this handle can write the
// volume or only read it. `snapshot` is null for a writable open and the
// moment the rows were frozen at otherwise, so a caller can say which it
// has without having to work it out.
function _buildHandle(cfg, snapshot) {
  var policy = b.auth.password.policy({
    minLength:             MIN_PASSWORD_CHARS,
    useBundledCommon:      true,
    denyContextSubstrings: true,
  });

  // The two handles below read each other, so the second one built has
  // to be reachable from the first. The adapter asks the account table
  // for a quota when a message is appended, and the account table asks
  // the adapter to erase an account's mail when the account is erased;
  // each reaches the other through a function called at the moment it is
  // needed rather than a handle captured at construction, so neither has
  // to be built first.
  var mailboxHandle = null;

  var accountsHandle = accounts.create({
    policy:  policy,
    mailbox: function () { return mailboxHandle; },
  });

  // The byte level message store, created once for the process, on the
  // framework database itself. The store wraps its append and its hard
  // delete in a transaction and settles which calling convention this
  // backend offers by whether the body ran, so nothing sits in between;
  // a backend it can get no transaction out of at all is refused rather
  // than written to outside one.
  //
  // Creating it bootstraps: it reconciles its own tables and seeds the
  // default folders, and the seed is an upsert that does nothing on
  // conflict. Doing nothing is still a write as far as SQLite is
  // concerned, so on a read-only handle it is refused at the statement
  // and takes the whole open down with it. `init: false` is what a
  // reader wants anyway: the volume it is reading was bootstrapped by
  // the writable open that created it, so there is nothing here to
  // establish and a reader that could establish it would be writing.
  //
  // The caps are named here for the same reason they are named at the
  // other place this handle is built: the append this store runs parses
  // the message, that parse is what refuses a nesting bomb, and an
  // unnamed one runs on whatever the vendored parser currently defaults
  // to. Both sites pass the same object, so a reader opened here and a
  // server started there agree about which messages are readable.
  //
  // The size ceiling rides beside them and is a separate opt: the store
  // measures the whole message against its own number before it parses,
  // so a handle told the caps alone still refuses at the framework's
  // fifty mebibytes while the listeners advertise whatever the operator
  // set. That gap is a message accepted on the wire, transferred in
  // full, and lost at the append. `maxBodyBytes` is the same number
  // rather than the framework's half of it, because an ordinary
  // single-part message IS its body.
  var messageBytes = config.limitInEffect(cfg.limits, "maxMessageBytes");
  var messageStore = b.mailStore.create({
    backend:         b.db,
    init:            snapshot === null,
    safeMimeOpts:    mailbox.MESSAGE_PARSE_CAPS,
    maxMessageBytes: messageBytes,
    maxBodyBytes:    messageBytes,
  });

  // The protocol facing adapter the wire listeners drive. It is built
  // before the handle rather than inside it because two members read it:
  // the listeners take it as `mailbox`, and the octet reconciliation
  // takes it for the blob directory it reports.
  mailboxHandle = mailbox.create({
    store:   messageStore,
    dataDir: cfg.paths.dataDir,
    vault:   b.vault,
    // The regulatory posture the agent holds in front of a hard
    // delete. `none` is the absence of one rather than the name of
    // one, so it becomes null: the framework refuses a posture it
    // does not know, and would refuse that string.
    posture: cfg.compliancePosture === "none" ? null : cfg.compliancePosture,
    // The cap an operator set on the account, read at the moment a
    // message is appended. The wire call that checks quota carries
    // no account, so the check has to happen where the account is
    // known.
    //
    // Zero is the operator's way of saying no limit, so it cannot
    // also stand for an account that is not there: answering zero for
    // one would hand an unlimited mailbox to an identity nobody
    // holds. An append that cannot name a live account is refused
    // instead.
    quotaBytesFor: function (accountId) {
      var account = accountsHandle.get(accountId);
      if (!account) {
        throw err("store/no-such-account",
          "no account with id " + JSON.stringify(accountId) + " holds a mailbox here, so " +
          "there is no quota to check and nowhere for the message to belong.");
      }
      return account.quotaBytes;
    },
  });

  // The hosted domains. It is built before the handle because the report
  // handle below asks it a question: whether a name a peer sent a report
  // about is one this server answers for. The data directory goes in
  // because a selector row names a sealed private key file under it and
  // the two are destroyed together, and the snapshot goes with it so the
  // destructive verbs can refuse. A private copy of the database is a
  // reading, and unlinking a key on the real volume to satisfy one would
  // break the promise `openSnapshot` makes about leaving the volume
  // alone.
  var domainsHandle = domains.create({
    dataDir:  cfg.paths.dataDir,
    snapshot: snapshot,
  });

  // The alias table and the address lookup over it, built before the
  // handle because the sending-credential registry composes against
  // both. A credential's bounces come back to one address per domain,
  // the registry writes and removes the alias at that address through
  // the first, and the second answers where the address actually
  // delivers on every operator-facing read.
  var aliasesHandle = aliases.create();
  var resolveFor    = routing.create().resolve;

  handle = {
    accounts: accountsHandle,
    domains:  domainsHandle,
    aliases:  aliasesHandle,
    resolve:  resolveFor,
    address:  addresses,
    // The settings an operator changes from the administration console
    // while the server runs. They are read in front of the frozen
    // configuration rather than instead of it: the file answers for a
    // volume nobody has written to, and a row here answers afterwards.
    settings: settings.create(),
    // The protocol facing adapter the wire listeners drive, and the
    // store underneath it. Every listener takes the same pair, so a
    // message appended by inbound delivery is the message an IMAP
    // session selects, and the quota counters are counted once.
    mailbox:      mailboxHandle,
    messageStore: messageStore,
    // The one reader that holds the sealed octets on disk against the
    // rows naming them. Nothing else in the boot path looks at both, so
    // without it a message body written without its row, or a row left
    // pointing at a body that is gone, is a state nothing reports.
    // The descriptor goes with it because this is the reader whose two
    // halves come from different moments when the rows are frozen: the
    // blob directory is live and the rows stop at the last flush, so it
    // needs the bound rather than a call site remembering to pass one.
    blobs:        blobs.create({
      mailbox:      mailboxHandle,
      messageStore: messageStore,
      accounts:     accountsHandle,
      vault:        b.vault,
      snapshot:     snapshot,
    }),
    // What peers report back about mail claiming a hosted domain, and the
    // two windows those rows are destroyed on.
    //
    // The windows arrive as milliseconds because that is what the module
    // acts on, and they are written by the operator as days. The
    // conversion happens once, here, so the module has one unit and the
    // setting has the other; a module that took either would be a module
    // where a number written in the wrong one is a window a thousand
    // times off and nothing says so.
    //
    // The forensic switch is off unless the operator turned it on, and
    // `lib/config` refuses a forensic window longer than the aggregate
    // one before this line runs, so the pair reaching the module is one
    // it can act on.
    //
    // The hosted-domain question is answered by the rows rather than by a
    // list read here. A report is filed minutes or days after the
    // configuration was loaded, and a domain added in between is one this
    // server hosts; a captured list would go on refusing reports about it
    // with nothing to say why.
    reports: reports.create({
      aggregateRetentionMs: b.constants.TIME.days(cfg.dmarcAggregateRetentionDays),
      forensicRetentionMs:  b.constants.TIME.days(cfg.dmarcForensicRetentionDays),
      forensicEnabled:      cfg.dmarcForensicEnabled === true,
      hostedDomain:         function (name) { return domainsHandle.get(name) !== null; },
    }),
    // The sending credentials an application presents to send as a
    // hosted domain. It is built here rather than by each caller,
    // because the registry a credential is issued through and the
    // registry the submission listener verifies against have to be one
    // registry: the two ceilings ride in this process, so a second
    // registry over the same rows counts a credential's traffic
    // separately and neither half reaches the ceiling the operator set.
    //
    // All four handles it composes against come off this same open, so
    // the domain a credential is scoped to, the mailbox its bounces are
    // delivered to, the alias its return path is carried on and the
    // lookup that resolves that address are all the ones this volume
    // holds.
    //
    // It is built on a read-only open as well. `credential list`,
    // `credential show` and `credential bounces` resolve where a
    // credential's bounces are landing, which is the reading an operator
    // wants while the server is running, and none of the three writes.
    credentials: credentials.create({
      domains:  domainsHandle,
      accounts: accountsHandle,
      aliases:  aliasesHandle,
      resolve:  resolveFor,
    }),
    // Null when this handle reads the volume itself. When it reads a
    // private copy this describes the copy, and every verb that prints
    // an answer off it says so: an operator or a script told nothing
    // would read an old answer as a current one, and during an incident
    // that is a new way to be wrong.
    snapshot:     snapshot,
    // What this boot's reading of the record outside the database
    // concluded, for the verbs that report on the trail. `checked` false
    // means the reading could not be made, which is not the same as a
    // reading that passed and must not print as one.
    auditAnchor:  anchorVerdict,
    close:        close,
  };
  return handle;
}

// ---------------------------------------------------------------------------
// The schema a read-only open reads
// ---------------------------------------------------------------------------
//
// A writable open brings the volume's schema up to the release that opens
// it: the framework adds every declared table and column the volume lacks,
// the mail store creates its tables, and the migrations the volume has not
// recorded run. A read-only open does none of that, so it reads the schema
// the volume was last opened for writing with. When an older release did
// that, a statement this code prepares can name a column or a table the
// volume does not have.
//
// `_assertSchemaCurrent` compares the two before anything reads a row, and
// only reads. It checks every column of every table `b.db.init` declares,
// every column of every table the framework's mail store creates on a
// fresh volume, and the migrations in `lib/store/migrations` against the
// ones the volume records. Indexes are not compared: a read works without
// one.
//
// Something declared here that the volume lacks is refused under
// `store/snapshot-schema-behind`. A migration the volume records that is
// not in `lib/store/migrations` means a newer release opened the volume for
// writing, and that is refused under `store/snapshot-schema-ahead`. A
// column the volume has and nothing here declares is not a finding: the
// reconcile never drops a column, so a column a later release stops
// declaring stays on the volume.

var SCHEMA_BEHIND = "store/snapshot-schema-behind";
var SCHEMA_AHEAD  = "store/snapshot-schema-ahead";

var SCHEMA_VERDICT_CODES = [SCHEMA_BEHIND, SCHEMA_AHEAD];

// The framework's audited builders for the statements that list a SQLite
// table's columns and ask whether a table exists.
var sqlCatalog = b.sql.catalog;   // spelling-ok: catalog (the framework's identifier)

// How many missing pieces a refusal names before it counts the rest.
var MAX_NAMED_PIECES = 8;

// The longest recorded migration name a refusal prints. A recorded name
// is a row on the volume, so one longer than this, or not shaped like a
// migration file name, is counted and not printed.
var MAX_MIGRATION_NAME_CHARS = 128;

// The tables the framework's mail store creates, with their columns, read
// once per process off a store created on an in-memory database. Null
// until the first read-only open asks.
var mailStoreTables = null;

// The identity and mailbox declarations `b.db.init` reconciles on a
// writable open, and the declarations the check compares a read-only open
// against.
function _declaredSchema() {
  return tables.TABLES.concat(mailbox.TABLES);
}

// The mail store's tables as it creates them on a fresh volume. The store
// publishes no declaration, so the store is created on a private
// in-memory database and its tables are listed there. Virtual tables are
// kept; the shadow tables SQLite creates behind a full-text index are
// not, because their columns belong to SQLite rather than to the store.
function _mailStoreTables() {
  if (mailStoreTables !== null) return mailStoreTables;
  var scratch = new nodeSqlite.DatabaseSync(":memory:");
  try {
    b.mailStore.create({ backend: scratch, init: true });
    var found = [];
    scratch.prepare("PRAGMA table_list").all().forEach(function (row) {
      if (row.schema !== "main" || (row.type !== "table" && row.type !== "virtual")) return;
      if (/^sqlite_/.test(row.name)) return;
      var info = sqlCatalog.tableInfo(row.name);
      found.push({
        name:    row.name,
        columns: scratch.prepare(info.sql).all().map(function (column) { return column.name; }),
      });
    });
    mailStoreTables = found;
  } finally {
    scratch.close();
  }
  return mailStoreTables;
}

// Every table this code reads, with the columns it declares.
function _tablesThisCodeReads() {
  var declared = [];
  b.db.FRAMEWORK_SCHEMA.concat(_declaredSchema()).forEach(function (table) {
    var columns = b.db.getDeclaredColumns(table.name);
    if (columns !== null) declared.push({ name: table.name, columns: columns });
  });
  return declared.concat(_mailStoreTables());
}

// The columns a table on the open database carries, or null when the
// table is not there.
function _liveColumns(name) {
  var info = sqlCatalog.tableInfo(name);
  var rows = b.db.prepare(info.sql).all();
  if (rows.length === 0) return null;
  return rows.map(function (row) { return row.name; });
}

// The migrations in `lib/store/migrations` that the volume has not
// recorded, and the recorded names that are not in it.
function _migrationStanding() {
  var shipped = b.atomicFile.listDir(MIGRATION_DIR, {
    filter: function (name) { return b.migrations.FILE_RE.test(name); },
  }).map(function (entry) { return entry.name; }).sort();

  // A volume last opened for writing by a release that shipped no
  // migrations has no record table. The framework's status reader creates
  // that table before reading it, which a read-only database refuses, so
  // absence is settled here first.
  var recordTable = b.frameworkSchema.tableName(b.migrations.MIGRATIONS_TABLE);
  var exists = sqlCatalog.tableExists(recordTable);
  var statement = b.db.prepare(exists.sql);
  if (statement.all.apply(statement, exists.params).length === 0) {
    return { pending: shipped, unshipped: [] };
  }

  var status = b.migrations.create({ dir: MIGRATION_DIR }).status();
  return {
    pending:   status.pending,
    unshipped: status.applied.map(function (row) { return row.name; })
      .filter(function (name) { return shipped.indexOf(name) === -1; }),
  };
}

// Pieces named in a refusal, with the rest counted.
function _namedPieces(pieces) {
  if (pieces.length <= MAX_NAMED_PIECES) return _listed(pieces);
  return pieces.slice(0, MAX_NAMED_PIECES).join(", ") + " and " +
    (pieces.length - MAX_NAMED_PIECES) + " more";
}

// Refuse a read-only open whose schema is not the one this code reads.
// Runs on the open database before anything reads a row.
function _assertSchemaCurrent(cfg) {
  var missing = [];
  _tablesThisCodeReads().forEach(function (table) {
    var live = _liveColumns(table.name);
    if (live === null) {
      missing.push("the table " + table.name);
      return;
    }
    table.columns.forEach(function (column) {
      if (live.indexOf(column) === -1) missing.push("the column " + table.name + "." + column);
    });
  });

  var migrations = _migrationStanding();
  migrations.pending.forEach(function (name) { missing.push("the migration " + name); });

  if (missing.length > 0) {
    throw err(SCHEMA_BEHIND,
      "the volume at " + cfg.paths.dataDir + " was last opened for writing by an older release " +
      "of blamepost, and its schema lacks " + _namedPieces(missing) + ". A read-only open does " +
      "not update a schema, so nothing was read and nothing on the volume was changed. Start the " +
      "server once on this release, which updates the schema as it opens the volume, or stop the " +
      "server and run this command again, which opens the volume for writing and updates it the " +
      "same way. After that the reporting verbs answer from a read-only open again while the " +
      "server runs. The refusal code is " + SCHEMA_BEHIND + ".");
  }

  if (migrations.unshipped.length > 0) {
    var printable = migrations.unshipped.filter(function (name) {
      return name.length <= MAX_MIGRATION_NAME_CHARS && b.migrations.FILE_RE.test(name);
    });
    var unprintable = migrations.unshipped.length - printable.length;
    var pieces = printable.map(function (name) { return "the migration " + name; });
    if (unprintable > 0) {
      pieces.push(unprintable === 1
        ? "one name that is not a migration file name"
        : unprintable + " names that are not migration file names");
    }
    throw err(SCHEMA_AHEAD,
      "the volume at " + cfg.paths.dataDir + " records " + _namedPieces(pieces) + " among its " +
      "applied migrations. This release does not ship " +
      (migrations.unshipped.length === 1 ? "it" : "them") + ", so a newer release of blamepost " +
      "last opened the volume for writing. Nothing was read and nothing on the volume was " +
      "changed. Run this command with the release that last opened the volume for writing, or " +
      "with a newer one. The refusal code is " + SCHEMA_AHEAD + ".");
  }
}

// `openSnapshot` hands the framework a working-copy root and a read-only
// open, and lets `b.db` manage the copy.
//
// @removed blamepost.store.snapshotPathFor 0.1.0

/**
 * @primitive blamepost.store.openSnapshot
 * @signature blamepost.store.openSnapshot(cfg)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: reporting verbs open the volume read-only)
 * @related   blamepost.store.open, blamepost.store.close
 *
 * Open the encrypted database read-only and return a handle onto it, for
 * a verb that only reports while the server holds the volume. The
 * volume's lock is neither taken nor waited for, nothing on the volume
 * is written, and everything decrypted is removed before the handle is
 * closed.
 *
 * The framework decrypts a working copy of its own, exactly as it does
 * for the server, and then does none of the writing. `db.enc` is never
 * written back, the sealed database key is never re-sealed, no
 * checkpoint is anchored, the record beside the volume is never
 * advanced, and no flush timer is armed. SQLite is opened read-only as
 * well, so a write that reaches it fails at the statement rather than
 * succeeding into a copy nobody will ever persist. That last part is
 * what makes this an open that CANNOT write rather than a promise that
 * it will not.
 *
 * What it does still do is verify: the chain's row hashes, the consent
 * chain, and every checkpoint signature on the volume. Verifying a
 * signature needs the audit-signing key unsealed and needs to establish
 * nothing, which is what lets `blamepost audit verify-chain` answer from
 * here.
 *
 * The handle is the one `open` returns, with `snapshot` filled in rather
 * than null: `takenAt` is when the server last wrote the volume to disk,
 * measured from the encrypted file rather than estimated, and it is what
 * a caller reports so nobody reads an old answer as a current one.
 * Anything the server has stored since is not in these rows. The rows do
 * not move underneath a long report either, because they are decrypted
 * once, at the open.
 *
 * Only a verb that records nothing may use this. A read that files an
 * audit row cannot file it, because the row is a write, so a verb
 * documented as recording its own reads keeps opening the volume itself.
 * A verb that holds these rows against something still moving on disk
 * has to carry the bound as well rather than assume the two halves came
 * from one moment; `blobs.reconcile` takes `snapshot` for exactly that.
 *
 * Refusals: `store/snapshot-unreadable` when the volume will not decrypt
 * or open, which is where a database damaged on disk lands, and
 * `store/snapshot-out-of-step` when the volume's audit anchor has moved
 * beyond what the encrypted file holds. Neither reports on a partial
 * read, and the volume is untouched under both.
 *
 * The open does not update the volume's schema, so it refuses a schema
 * this release does not read, before any row is read.
 * `store/snapshot-schema-behind` is a volume last opened for writing by
 * an older release: a table or column declared here, a column of the
 * framework's mail store, or a migration in `lib/store/migrations` is
 * missing, and the refusal names up to eight of them. A writable open
 * adds them. `store/snapshot-schema-ahead` is a volume that records a
 * migration this release does not ship, which a newer release wrote. The
 * volume is untouched under both, and the decrypted copy is removed.
 *
 * A finding already recorded against the volume refuses this path too,
 * under the code that raised it, because reading a rewritten trail a
 * second way is still reading a rewritten trail. A finding raised HERE
 * is reported and not recorded: the volume stays byte identical on this
 * path, and rows a moment behind the record beside them are not the
 * reading to shut a running server's next boot on.
 *
 * @example
 *   var store = require("./lib/store");
 *   var handle = await store.openSnapshot(require("./lib/config").load());
 *   handle.snapshot.takenAt;
 */
async function openSnapshot(cfg) {
  if (handle) return handle;
  _requireConfig(cfg, "store.openSnapshot");

  // A reading of a volume a restore stopped partway through is a reading
  // of two volumes at once.
  _refuseWhileRestoreInFlight(cfg.paths.dataDir);

  // The volume's own derivation of where its database is, rather than a
  // second one written here that could drift from it.
  var source = cfg.paths.database;
  if (!nodeFs.existsSync(source)) {
    throw err("store/snapshot-no-source",
      "there is no database at " + source + " to read. A server holding this data " +
      "directory has one; a directory that has never been through `blamepost init` " +
      "does not.");
  }

  // A finding recorded against the volume is a finding about these rows
  // too, since they come out of that volume. Refusing here costs a
  // reporting verb its answer during an incident, and the alternative
  // costs it more: a second reading that reports the trail clean is the
  // same rewritten trail read a second way.
  _refuseWhileDisputed(cfg.paths.dataDir);

  // Read before the open, so the moment reported is the moment the bytes
  // being read were written rather than the moment the open finished.
  var writtenAt = nodeFs.statSync(source).mtimeMs;
  var anchor = _anchorOnDisk(cfg.paths.dataDir);

  try {
    await _unsealAndOpen(cfg, {
      // Everything this path is. The framework decrypts its own working
      // copy and then writes nothing: not the encrypted file, not the
      // sealed database key, not a checkpoint row, not the record
      // beside the volume, and SQLite refuses a write at the statement
      // besides.
      //
      // Anchoring is the write that matters most to withhold, and not
      // because it is untidy. A fresh anchor names a counter that
      // reached this reader's copy and never the volume, so a server
      // killed before its next flush comes back to a database the
      // rollback check refuses to open at all. `readOnly: true`
      // withholds it and keeps the verification of the signatures over
      // the checkpoints already there, which are the half a rewritten
      // chain cannot recompute.
      readOnly: true,
    });

    // The same reading from outside the database that a normal open
    // makes, and it still means something here: the anchor is the
    // volume's, the rows are the encrypted file's, and that file is old
    // enough to hold the row the anchor names. It is reported and not
    // written down: nothing on the volume is written on this path, and
    // rows a moment behind the record beside them are not the reading to
    // refuse a running server's next boot on.
    _assertAnchorAgrees(cfg.paths.dataDir, anchor, false);

    // Before the handle is built. Building it prepares the mail store's
    // statements, and a column those name that the volume lacks fails at
    // the prepare.
    _assertSchemaCurrent(cfg);

    // Inside this block, so a handle that fails to build closes the
    // database and removes the decrypted copy like every refusal above.
    return _buildHandle(cfg, {
      takenAt:    Math.round(writtenAt),
      takenAtIso: new Date(Math.round(writtenAt)).toISOString(),
      source:     source,
      // Why the volume was not read directly, so an answer read out of
      // context still says what happened rather than only that it is old.
      reason:     "another process holds the data directory",
    });
  } catch (e) {
    // Closing is what removes the decrypted working copy, and it runs
    // here rather than being left to the exit hook: a refusal does not
    // have to end the process, and every moment between the two is
    // somebody's mail in the clear on a shared filesystem for no reason.
    try { b.db.close(); }
    catch (_e) { /* drop-silent by design: nothing had opened, or it is already shut */ }
    throw _snapshotFailure(cfg, source, e);
  }
}

// What an operator is told when a read-only open will not read. The
// volume is untouched either way and the refusal says so, because the
// reading an operator makes of an unfamiliar failure during an incident
// is that whatever they just ran caused it.
function _snapshotFailure(cfg, source, cause) {
  // A rewritten chain is a verdict about the trail, not about this open,
  // and it reads the same from either. Softening it here would turn
  // tamper evidence into a transient fault an operator retries past.
  if (_isChainVerdict(cause)) return cause;

  // A schema this release does not read is a verdict about which release
  // last opened the volume for writing, and its refusal names the remedy.
  if (cause && SCHEMA_VERDICT_CODES.indexOf(cause.code) !== -1) return cause;

  if (cause && cause.code === "db/audit-rollback-detected") {
    return err("store/snapshot-out-of-step",
      "the rows in " + source + " are older than this volume's own record of where its " +
      "audit trail had reached, so they were not read: " +
      ((cause && cause.message) || String(cause)) + ". Nothing on the volume was changed. " +
      "The record advances when the volume is opened, so this is what a server starting " +
      "up while this was being read looks like. Run the command again, and if it keeps " +
      "happening stop the server and run it against the volume itself.");
  }

  return err("store/snapshot-unreadable",
    source + " could not be read, so there is nothing to report: " +
    ((cause && cause.message) || String(cause)) + ". Nothing on the volume was changed " +
    "and nothing decrypted was left behind. The database is encrypted with a key " +
    "sealed in " + cfg.paths.dataDir + ", and the envelope is authenticated end to end, " +
    "so this is either a passphrase that does not unseal that key or a database that has " +
    "been damaged where it lies. Stop the server and run `blamepost audit verify-chain` " +
    "against the volume itself, and restore from a backup if it will not open either.");
}

/**
 * @primitive blamepost.store.close
 * @signature blamepost.store.close()
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: ordered boot of directories, vault and database)
 * @related   blamepost.store.open
 *
 * Shut the identity layer down: the database is re-encrypted to disk
 * and its handle released, which is also what frees the file lock on
 * Windows, and the data directory's lock is given back so the next
 * command can open it. Safe to call when nothing is open, so a shutdown
 * path does not need to know whether the boot got this far, and it still
 * releases a lock taken by a boot that failed after taking it.
 *
 * A read-only handle is closed the same way, and closing it is what
 * removes the decrypted working copy and the record naming this process
 * as its owner. There is nothing to re-encrypt on that path, because
 * nothing was written.
 *
 * @example
 *   require("./lib/store").close();
 */
function close() {
  if (handle) {
    var closing = handle;
    handle = null;
    // Before the database goes. The registry keeps its ceiling counters
    // in a cache that arms a sweep timer at construction, and a timer
    // left armed beside a closed store ticks into a database that is
    // gone.
    closing.credentials.close();
    b.db.close();
  }
  // The reading belongs to the open that made it. Left standing, the
  // next verb in the same process to open the volume and find no record
  // on disk would read this one and report a check that was made against
  // a database it never saw.
  anchorVerdict = null;
  // Outside the guard above, because a boot that took the volume and
  // then failed leaves the lock held and no handle to notice it by. A
  // lock nothing gives back would refuse the operator's next command
  // against a process that is still running and is not using the volume.
  _releaseVolume();
}

/**
 * @primitive blamepost.store.isOpen
 * @signature blamepost.store.isOpen()
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: ordered boot of directories, vault and database)
 * @related   blamepost.store.open, blamepost.store.close
 *
 * Whether the identity layer is up. The health endpoint and the command
 * line's shutdown path both ask, and neither should have to open the
 * database to find out.
 *
 * @example
 *   require("./lib/store").isOpen();
 *   // false
 */
function isOpen() {
  return handle !== null;
}

/**
 * @primitive blamepost.store.snapshotInEffect
 * @signature blamepost.store.snapshotInEffect()
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: reporting verbs open the volume read-only)
 * @related   blamepost.store.openSnapshot, blamepost.store.open
 *
 * The moment the open handle's rows were frozen at, or null when it is
 * reading and writing the volume itself. Whatever prints an answer asks
 * this rather than being told, because one process holds one handle and
 * the question "is this answer current" has one answer for the whole
 * run.
 *
 * The alternative is threading the descriptor through every place that
 * prints something, and the way that fails is a call site nobody
 * remembers to change: an answer read off rows frozen minutes ago that
 * says nothing about it. During an incident that is a worse outcome than
 * the refusal a read-only open replaced.
 *
 * @example
 *   require("./lib/store").snapshotInEffect();
 *   // null
 */
function snapshotInEffect() {
  if (handle === null) return null;
  return handle.snapshot || null;
}

/**
 * @primitive blamepost.store.StoreError
 * @signature blamepost.store.StoreError
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: ordered boot of directories, vault and database)
 * @related   blamepost.store.open
 *
 * The error class every refusal from this layer carries, with a stable
 * `code` of the form `store/<reason>`. Branch on the code rather than
 * on the message: the codes are the contract a wire listener maps onto
 * its own reply, and the messages are written for a person reading a
 * terminal.
 *
 * @example
 *   try { await handle.accounts.create({ address: "nope" }); }
 *   catch (e) { e instanceof store.StoreError; }
 */
var StoreError = errors.StoreError;

module.exports = {
  open:         open,
  openSnapshot: openSnapshot,
  close:        close,
  isOpen:       isOpen,
  snapshotInEffect: snapshotInEffect,
  StoreError:   StoreError,
  address:      addresses,
  TABLES:       tables.TABLES,
  SNAPSHOT_VERBS: SNAPSHOT_VERBS,
  MIN_PASSWORD_CHARS: MIN_PASSWORD_CHARS,
  holdVolume:        holdVolume,
  recordedAnchor:    recordedAnchor,
  VOLUME_RESERVED:   VOLUME_RESERVED,
  RESTORE_WORK_DIR:  RESTORE_WORK_DIR,
  RESTORE_IN_FLIGHT: RESTORE_IN_FLIGHT,
};
