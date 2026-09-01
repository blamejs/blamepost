// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.mail.mailbox
 * @title  Protocol facing mailbox adapter
 *
 * @intro
 *   The layer between the wire listeners and `b.mailStore`. The two
 *   speak different shapes: the store is a byte level substrate keyed
 *   by folder name, and IMAP, POP3 and ManageSieve want per session
 *   verbs that carry the account making the call. This file is the
 *   translation, and it is what `b.mail.server.imap.create`,
 *   `b.mail.server.pop3.create` and
 *   `b.mail.server.managesieve.create` receive as their `mailStore`.
 *
 *   ## One account cannot read another
 *
 *   Every listener verb takes the acting account as its first
 *   argument, and that is the only place isolation can happen.
 *   `b.mailStore` has one flat namespace of folders with no owner
 *   column, and the per append options it accepts are not read, so
 *   nothing below this layer can tell one account's INBOX from
 *   another's. This adapter gives every account its own set of store
 *   folders, under opaque names it records in `blamepost_mailbox_
 *   folders`, and resolves the wire name against that record on every
 *   call. A verb that cannot identify its account refuses. It never
 *   falls back to a shared folder, because a fallback here is a
 *   mailbox that silently serves someone else's mail.
 *
 *   ## Deletion has one path
 *
 *   IMAP EXPUNGE, POP3 QUIT and the `expungeObjects` verb the browser
 *   surface and JMAP drive all route through `b.mail.agent.expunge`,
 *   which checks legal hold and the retention floor before any row is
 *   removed and returns a per message refusal reason for the ones it
 *   keeps. `b.mailStore.hardExpunge` is the destructive primitive
 *   underneath the agent and is never called from here.
 *
 *   Driving the agent directly is not the same call. The agent owns the
 *   store's row; this layer owns the row binding a message to a folder,
 *   the UID an IMAP client addresses it by, and the sealed original
 *   octets under `blobs/`. A delete that skips this layer reports the
 *   message destroyed while its body is still on disk and still
 *   readable, and a move that skips it leaves the message in neither
 *   folder on IMAP and POP3 while the browser interface still lists it.
 *
 *   The volume can refuse the body on its own, and the delete answers
 *   for that per message rather than for the set. A message whose octets
 *   stayed has still left every mailbox, so its sequence number is drawn
 *   and the client renumbers around it, and it is reported as one that
 *   did not go, so nothing reads it as destroyed while it is readable on
 *   disk. Every message behind it in the same delete still goes.
 *
 *   Soft delete is a different operation and stays a different call.
 *   Filing a message into Trash goes through `moveObjects`, which
 *   consults no hold and no floor, because nothing has been destroyed
 *   yet. Setting `\Deleted` is `storeFlags`. Only `expungeFolder`,
 *   `commitPop3Drop`, `expungeObjects` and `eraseAccountMail` destroy
 *   anything, and the fourth is the other three's path walked over every
 *   mailbox one account holds, because erasing an account has to reach
 *   its mail and the identity layer's own erase reaches one row in one
 *   table.
 *
 *   What the client is told afterwards is per protocol, because each
 *   specification gives the server a different vocabulary. RFC 9051
 *   section 6.4.3 has no refusal form for EXPUNGE, so a message that
 *   stayed draws no untagged line and the command completes. RFC 1939
 *   section 6 does have one, so a POP3 commit that could not remove
 *   everything it was asked to answers `-ERR` rather than reporting a
 *   success the client would act on.
 *
 *   Legal hold always applies, and this layer is where one is placed:
 *   `legalHold.place` sets the flag the delete path reads and records
 *   the order in `b.legalHold` beside it. The retention floor applies
 *   only when the operator has set a compliance posture, and with none
 *   set the floor is zero and a hold is the only thing that keeps a
 *   message. That is the default, so a server nobody has configured for
 *   a regulator deletes what it is told to delete.
 *
 *   ## What the store does not keep, and this file does
 *
 *   `b.mailStore` parses a message on append and keeps the parts it
 *   indexes: subject, addresses, text and HTML bodies, threading and
 *   quota counters. It does not keep the original octets, and IMAP
 *   `BODY[]` and POP3 `RETR` are both defined on octets: RFC 9051
 *   section 6.4.5 and RFC 1939 section 3 have each return the message
 *   exactly as it arrived, signature intact. So the raw message is
 *   written to the data directory's `blobs/` tree, sealed by the vault
 *   and named by the SHA3-512 of its content, and the row here points
 *   at it. Content addressing means one message delivered to several
 *   accounts is stored once; the file is removed when the last row
 *   referencing it goes.
 *
 *   Both reach an account holder as the bytes that were stored. POP3
 *   `RETR` hands the stored buffer to its listener untouched, and a
 *   FETCH response that carries message content leaves this layer as a
 *   Buffer, which the composed IMAP listener writes through as octets.
 *   The literal count and the payload are therefore both taken from the
 *   stored bytes, so a client walking a large message by the counts it
 *   is given reassembles the message rather than a re-encoding of it.
 *
 *   The trap on this path is a response that is self-consistent and
 *   still wrong: decode the section, count the decoded copy, announce
 *   that count and send it. Nothing in the exchange contradicts itself,
 *   and every octet the decode replaced is gone from the message the
 *   account holder got back. So the assertion worth keeping is not that
 *   the count matches the payload but that both are the stored octets,
 *   which is what `test/layer-2-integration/mail-octet-fidelity`
 *   measures on a bound port, for a whole message and for a window.
 *
 *   IMAP also needs a UID per message and a UIDVALIDITY per folder,
 *   neither of which the store has: its `modseq` moves whenever flags
 *   change, so it cannot serve as a UID. Both are assigned and kept
 *   here, in the same row.
 *
 *   ## The wire surface
 *
 *   IMAP: `selectFolder`, `statusFolder`, `listFolders`, `fetchRange`,
 *   `searchScan`, `storeFlags`, `expungeFolder`, `appendMessage`,
 *   `quota`, `getMetadata`, `setMetadata`.
 *
 *   POP3: `openPop3Drop`, `listMessages`, `getMessage`, `markDelete`,
 *   `resetPop3Drop`, `commitPop3Drop`.
 *
 *   ManageSieve: `sieveScripts.put`, `.list`, `.get`, `.setActive`,
 *   `.delete`, `.rename`, `.haveSpace`.
 *
 *   `searchScan` is the read behind IMAP SEARCH. It is a scan rather
 *   than a query because the store's full text index cannot answer the
 *   question RFC 9051 section 6.4.4 asks: it holds keyed hashes of
 *   whole tokens and every string key there is a substring match. The
 *   search key grammar itself is the listener's, in
 *   `blamepost.mail.listeners`, because it is wire syntax.
 *
 *   Two hooks the IMAP listener probes for are absent, and the
 *   listener answers the client with the refusal its RFC defines when
 *   they are: `subscribeNotify` (RFC 5465 NOTIFY) needs a push channel
 *   from the store to a live connection, and `appendCatenate` (RFC
 *   4469) needs IMAP URL resolution across mailboxes. Each is a body
 *   of work in its own right, and a hook that answers OK without doing
 *   the work is worse than the refusal, because the client believes
 *   it.
 *
 *   The browser surface and JMAP hold no session and speak no wire
 *   grammar, so they read two verbs. `accountFolders` answers with the
 *   folders an account owns and the store folder behind each of them,
 *   and it is the only way any other layer learns which folders belong
 *   to an account. `expungeObjects` destroys messages by identifier and
 *   answers with the reason for anything it kept, which is the shape
 *   JMAP `Email/set` `destroyed` reports back, and `moveObjects` files
 *   them from one folder into another.
 *
 *   An operator responding to a preservation order reads a third:
 *   `legalHold.place`, `.release` and `.status`. The identity layer
 *   reads a fourth, `eraseAccountMail`, when an account is erased rather
 *   than archived.
 *
 *   ## Refusals are loud
 *
 *   Everything here is a wire protocol reader. A malformed sequence
 *   set, an unknown fetch attribute, a mailbox that does not exist or
 *   a Sieve script that does not parse is refused with a `mailbox/`
 *   code the listener turns into the protocol's own error. Nothing is
 *   tolerated for compatibility and nothing is answered with an
 *   approximation: an IMAP client that receives a wrong body
 *   structure renders the wrong bytes and never finds out.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var b = require("../vendor/blamejs");

// The identity behind an audit row, and the write that files one. The
// write drops what it cannot record by design, which is the property
// this file needs: an erasure has already destroyed mail by the time its
// row is written, and a sink that is unavailable must not report the
// destruction as something that did not happen.
var auditActor = require("../store/actor");

// Which refusals from a hard erase mean a row is being kept on purpose.
// It is the identity layer's module because the identity layer erases
// rows too and the distinction has to read the same on both sides of the
// boundary; an erasure answers for an account's aliases and its filter
// scripts in one report, and an operator acting on that report needs the
// two classified by one rule rather than by two copies of one.
var storeErrors = require("../store/errors");

var MailboxError = b.frameworkError.defineClass("MailboxError", { alwaysPermanent: true });
var err = MailboxError.factory;

var BYTES = b.constants.BYTES;
var TIME  = b.constants.TIME;

var FOLDERS  = "blamepost_mailbox_folders";
var MESSAGES = "blamepost_mailbox_messages";
var SCRIPTS  = "blamepost_mailbox_sieve";
var METADATA = "blamepost_mailbox_metadata";

// The folder set every account starts with, taken from the store so
// the two agree on names and on the JMAP role each one carries.
var DEFAULT_FOLDERS = b.mailStore.DEFAULT_FOLDERS;

// The permanent flags this server keeps. RFC 9051 section 2.3.2 lists
// the system flags; `\Recent` is absent because IMAP4rev2 removed it,
// and a client may not set it in any case.
var PERMANENT_FLAGS = ["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"];

// A keyword flag is an atom. RFC 9051 section 4.1 draws it from
// ATOM-CHAR, which excludes the list wrapper characters, the quoting
// characters and every control byte.
var KEYWORD_FLAG_RE = /^[A-Za-z0-9_$.+&#!-]+$/;

// A sequence set with more comma separated parts than this is refused
// rather than expanded. RFC 9051 sets no ceiling, and the listener has
// already capped the line length, so this is the second bound: a
// pathological set should cost a refusal, not a scan per part.
var MAX_SEQ_SET_PARTS = 1024;

// Sieve. RFC 5804 leaves both limits to the server and expects them
// advertised, so they are fixed here rather than guessed per call.
var MAX_SIEVE_SCRIPT_BYTES = BYTES.kib(64);
var MAX_SIEVE_SCRIPTS      = 32;

// RFC 5464 annotations. The entry namespace is small and operator
// facing, and an unbounded one is a write channel into the database
// that no protocol verb ever reads back.
var MAX_METADATA_VALUE_BYTES = BYTES.kib(8);
var MAX_METADATA_ENTRIES     = 64;

// How many things may ask to hear about a message being filed. One
// assembled server registers one, and a process holding a handful of
// them over one adapter is what a test run looks like. Nothing removes
// a registration, so the ceiling is what turns a caller registering per
// request into a refusal rather than into memory that only grows.
var MAX_FILED_OBSERVERS = 16;

// The sealed blob holding one message. The store refuses a message
// above 50 MiB, and base64 plus the seal envelope grows that by
// roughly a third, so the read cap sits above the largest file the
// write path can produce.
var MAX_BLOB_FILE_BYTES = BYTES.mib(96);

// A stored body is named by the hex SHA3-512 of its content. The shape
// is checked in front of the path derivation below and nowhere else,
// because a value that reaches a path decides which file on the volume
// is opened and which file is removed, and a check that is not in front
// of the only derivation is a check something can be routed around.
var BLOB_DIGEST_RE = /^[0-9a-f]{128}$/;

// How much of a digest a refusal quotes. Enough to identify the body in
// a log beside the rows and the files, and short of the whole value: a
// refusal from a read path is answered to whoever asked for the message,
// and the full hash of a stored body is not something a mailbox protocol
// owes its client.
var DIGEST_PREFIX_CHARS = 16;

/**
 * blobPathFor(blobDir, digest) is where the octets named by one digest
 * belong: two levels of fan-out taken from the front of the digest, then
 * the digest itself.
 *
 * This is the single derivation. The adapter writes and reads bodies
 * through it and the reconciliation that holds the files against the
 * rows resolves them through it, because a reconciliation that computed
 * the path differently from the writer would report every message
 * missing and be believed.
 *
 * The digest is checked against its shape before any path is built. The
 * value arrives from a row, and a row that has been rewritten carries
 * whatever was written into it: a value that is not a hash would
 * otherwise be joined onto the blob directory and address a file
 * somewhere else entirely, which the read path opens and the release
 * path removes.
 */
function blobPathFor(blobDir, digest) {
  if (typeof blobDir !== "string" || blobDir.length === 0) {
    throw new TypeError("blamepost.mail.mailbox.blobPathFor: blobDir (non-empty string) required");
  }
  if (typeof digest !== "string" || !BLOB_DIGEST_RE.test(digest)) {
    throw err("mailbox/bad-blob-digest",
      "a stored message body is named by the hex SHA3-512 of its content, and " +
      JSON.stringify(String(digest).slice(0, 80)) + " is not one. A path built from it " +
      "would address something other than a message.");
  }
  return nodePath.join(blobDir, digest.slice(0, 2), digest.slice(2, 4), digest);
}

// A POP3 session holds its account's drop exclusively (RFC 1939
// section 3). A client that drops the connection without QUIT leaves
// the lock behind, so a drop nothing has touched for this long is
// reclaimed at the next open rather than locking the account until the
// process restarts.
//
// Idle rather than age, and the difference is the whole of the rule.
// How long a session has been OPEN says nothing about whether it is
// still there: a POP3 client downloads a whole mailbox in one session,
// so on a slow link the sessions that run longest are the ones working
// hardest. Reclaiming on age takes the maildrop away from those, and
// RFC 1939 section 6 applies a DELE only at QUIT, so the deletions that
// session was holding go with it and the account holder sees the mail
// they deleted come back. Reclaiming on idleness cannot reach a session
// that is issuing commands, because every command it issues is a touch.
//
// What bounds the wait for the other case is the listener's own
// autologout: RFC 1939 section 3 sets a floor of ten minutes on it and
// `b.mail.server.pop3` runs at that floor, so a session silent for
// longer than this has already been closed at the socket and is not
// coming back. The listener reports nothing to this layer when a
// connection dies, which is why a duration is what there is to read.
var POP3_DROP_IDLE_TTL_MS = TIME.minutes(30);

// One millisecond, counted in the nanoseconds the monotonic clock reads
// in. Named rather than written at the call site, so the unit is visible
// where the conversion happens.
var NANOSECONDS_PER_MS = 1000000n;

// How long this process has been running, in milliseconds.
//
// It answers "how long has this been open", which is a different
// question from "what time is it" and needs a different clock.
// `Date.now()` moves when an operator corrects a wrong time, when NTP
// steps a drifted host, and when a container that started before it
// synchronized catches up. A window measured across two readings of it
// is wrong by however far the correction went, in whichever direction it
// went: a step forward past the maildrop TTL reclaims a session that is
// still live and discards the deletes it had marked, and a step
// backwards holds an abandoned one's exclusive lock until the clock has
// climbed back to where it was.
//
// `process.hrtime.bigint()` counts from a fixed point this process
// cannot move and advances only at the rate of real time, so a duration
// measured across two readings is the duration that actually elapsed.
//
// A reading is never stored and never leaves the process. It names no
// instant and means nothing to anybody else: the moment a value has to
// say what time something happened, it is a wall clock reading again.
function _elapsedMs() {
  return Number(process.hrtime.bigint() / NANOSECONDS_PER_MS);
}

// RFC 9051 section 2.3.1.1 gives UIDVALIDITY an unsigned 32 bit field.
var MAX_UIDVALIDITY = 4294967295;

// The delete path's reasons that mean something is deliberately keeping
// a message, as against something being wrong with it.
//
// A preservation order and the regulated retention window are the system
// working: the message stays, the operator is told which one and under
// what, and an erasure request is answered with the exception named.
// Anything else that stops a message going is a fault, and the two need
// opposite responses from whoever reads the result, so they are
// classified here rather than counted together. The classification
// travels on the result, so no caller keeps a second copy of this list
// to drift from it.
var PRESERVATION_REASONS = ["legal-hold", "retention-floor"];

function _isPreservation(reason) {
  return PRESERVATION_REASONS.indexOf(reason) !== -1;
}

/**
 * @primitive blamepost.mail.mailbox.TABLES
 * @signature blamepost.mail.mailbox.TABLES
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9051 (UID and UIDVALIDITY), RFC 5804 (script storage), RFC 5464 (annotations)
 * @related   blamepost.mail.mailbox.create, blamepost.store.open
 *
 * The table declarations this adapter owns, for the caller that opens
 * the database to merge into its schema. They are separate from the
 * identity layer's tables because they describe mailbox state rather
 * than who the accounts are, and they are declared beside the code
 * that reads them so the two cannot drift.
 *
 * Folder names, message octets, Sieve script bodies and annotation
 * values are sealed columns. A stolen database file is ciphertext,
 * and the lookups that need to match on a sealed column carry a
 * derived hash beside it.
 *
 * @example
 *   var mailbox = require("./lib/mail/mailbox");
 *   await b.db.init({ dataDir: dir, schema: tables.TABLES.concat(mailbox.TABLES) });
 */
var TABLES = [
  {
    name: FOLDERS,
    columns: {
      _id:         "TEXT PRIMARY KEY",
      account:     "TEXT NOT NULL",
      folder:      "TEXT NOT NULL",
      wireName:    "TEXT NOT NULL",
      wireNameKey: "TEXT NOT NULL",
      role:        "TEXT",
      uidvalidity: "INTEGER NOT NULL",
      uidnext:     "INTEGER NOT NULL",
      subscribed:  "INTEGER NOT NULL DEFAULT 1",
      createdAt:   "INTEGER NOT NULL",
      updatedAt:   "INTEGER NOT NULL",
    },
    // The name the store knows a folder by is an opaque token, so the
    // store's own folder table carries no account addresses and no
    // folder names. The pair index is what makes one account's Sent
    // a different row from another's.
    indexes: [
      { name: "idx_blamepost_mailbox_folders_name",    columns: ["account", "wireNameKey"], unique: true },
      { name: "idx_blamepost_mailbox_folders_store",   columns: ["folder"], unique: true },
      { name: "idx_blamepost_mailbox_folders_account", columns: ["account"] },
    ],
    sealedFields:  ["wireName"],
    derivedHashes: { wireNameKey: { from: "wireName" } },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
  {
    name: MESSAGES,
    columns: {
      _id:          "TEXT PRIMARY KEY",
      folder:       "TEXT NOT NULL",
      objectid:     "TEXT NOT NULL",
      uid:          "INTEGER NOT NULL",
      blobDigest:   "TEXT NOT NULL",
      sizeBytes:    "INTEGER NOT NULL",
      internalDate: "INTEGER NOT NULL",
      createdAt:    "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_mailbox_messages_object", columns: ["folder", "objectid"], unique: true },
      { name: "idx_blamepost_mailbox_messages_uid",    columns: ["folder", "uid"], unique: true },
      { name: "idx_blamepost_mailbox_messages_blob",   columns: ["blobDigest"] },
    ],
    // The octets are on disk under `blobs/`, sealed, and this row
    // holds the digest that names the file. Nothing about the message
    // content is in the database that the store has not already
    // sealed itself.
    sealedFields:  [],
    rowIdField:    "_id",
    schemaVersion: "1",
  },
  {
    name: SCRIPTS,
    columns: {
      _id:       "TEXT PRIMARY KEY",
      account:   "TEXT NOT NULL",
      name:      "TEXT NOT NULL",
      nameKey:   "TEXT NOT NULL",
      body:      "TEXT NOT NULL",
      active:    "INTEGER NOT NULL DEFAULT 0",
      sizeBytes: "INTEGER NOT NULL",
      createdAt: "INTEGER NOT NULL",
      updatedAt: "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_mailbox_sieve_name",    columns: ["account", "nameKey"], unique: true },
      { name: "idx_blamepost_mailbox_sieve_account", columns: ["account"] },
    ],
    // A filter script names the correspondents its owner sorts on, so
    // it is as revealing as the mail it files.
    sealedFields:  ["name", "body"],
    derivedHashes: { nameKey: { from: "name" } },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
  {
    name: METADATA,
    columns: {
      _id:       "TEXT PRIMARY KEY",
      account:   "TEXT NOT NULL",
      folder:    "TEXT NOT NULL",
      entry:     "TEXT NOT NULL",
      value:     "TEXT",
      createdAt: "INTEGER NOT NULL",
      updatedAt: "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_mailbox_metadata_entry", columns: ["account", "folder", "entry"], unique: true },
    ],
    // The entry name is an RFC 5464 path the client chose and the
    // index matches on; the value is whatever the client stored.
    sealedFields:  ["value"],
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
];

// ---- Wire shapes, no state -------------------------------------------------

// One IMAP quoted string, or NIL for an absent value. Folding
// whitespace has already done its job by the time a header value
// reaches here, so the line breaks inside it are collapsed rather than
// emitted raw into a response the client parses line by line.
function _quoted(value) {
  if (value === null || value === undefined) return "NIL";
  var text = String(value).replace(/\r?\n[ \t]*/g, " ");
  return "\"" + text.replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

// Split a header value that holds an address list, at the commas that
// are not inside a quoted string, an angle addr-spec or a comment.
function _splitAddressList(raw) {
  var out = [];
  var current = "";
  var inQuote = false;
  var angle = 0;
  var paren = 0;
  for (var i = 0; i < raw.length; i += 1) {
    var ch = raw[i];
    if (inQuote) {
      current += ch;
      if (ch === "\\" && i + 1 < raw.length) { current += raw[i + 1]; i += 1; continue; }
      if (ch === "\"") inQuote = false;
      continue;
    }
    if (ch === "\"") { inQuote = true; current += ch; continue; }
    if (ch === "<") { angle += 1; current += ch; continue; }
    if (ch === ">") { if (angle > 0) angle -= 1; current += ch; continue; }
    if (ch === "(") { paren += 1; current += ch; continue; }
    if (ch === ")") { if (paren > 0) paren -= 1; current += ch; continue; }
    if (ch === "," && angle === 0 && paren === 0) {
      if (current.trim().length > 0) out.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim().length > 0) out.push(current.trim());
  return out;
}

// One RFC 9051 section 7.5.2 address structure: name, source route,
// mailbox and host. The source route field is always NIL, because RFC
// 5322 removed the syntax it carried.
function _addressStructure(entry) {
  var name = null;
  var spec = entry;
  var open = entry.lastIndexOf("<");
  var close = entry.lastIndexOf(">");
  if (open !== -1 && close > open) {
    spec = entry.slice(open + 1, close).trim();
    name = entry.slice(0, open).trim();
    if (name.length >= 2 && name[0] === "\"" && name[name.length - 1] === "\"") {
      name = name.slice(1, -1).replace(/\\(.)/g, "$1");
    }
    if (name.length === 0) name = null;
  }
  var at = spec.lastIndexOf("@");
  var mailbox = at === -1 ? spec : spec.slice(0, at);
  var host = at === -1 ? null : spec.slice(at + 1);
  return "(" + _quoted(name) + " NIL " + _quoted(mailbox) + " " + _quoted(host) + ")";
}

function _addressList(raw) {
  if (raw === null || raw === undefined || String(raw).trim().length === 0) return "NIL";
  var entries = _splitAddressList(String(raw));
  if (entries.length === 0) return "NIL";
  var parts = [];
  for (var i = 0; i < entries.length; i += 1) parts.push(_addressStructure(entries[i]));
  return "(" + parts.join("") + ")";
}

// RFC 9051 section 7.5.2 ENVELOPE. Sender and reply-to default to the
// From address when the message carries neither header, which is what
// the specification says a server does.
function _envelope(tree) {
  var from = tree.headers.get("from") || null;
  var fields = [
    _quoted(tree.headers.get("date") || null),
    _quoted(tree.headers.get("subject") || null),
    _addressList(from),
    _addressList(tree.headers.get("sender") || from),
    _addressList(tree.headers.get("reply-to") || from),
    _addressList((tree.headers.getAll("to") || []).join(", ")),
    _addressList((tree.headers.getAll("cc") || []).join(", ")),
    _addressList((tree.headers.getAll("bcc") || []).join(", ")),
    _quoted(tree.headers.get("in-reply-to") || null),
    _quoted(tree.headers.get("message-id") || null),
  ];
  return "(" + fields.join(" ") + ")";
}

// RFC 9051 section 6.4.5 INTERNALDATE, which is fixed width and always
// carries a numeric zone. UTC is the zone this server records in.
var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function _pad(n, width) {
  var s = String(n);
  while (s.length < width) s = "0" + s;
  return s;
}

function _internalDate(ms) {
  var d = new Date(ms);
  return _pad(d.getUTCDate(), 2) + "-" + MONTHS[d.getUTCMonth()] + "-" + d.getUTCFullYear() +
    " " + _pad(d.getUTCHours(), 2) + ":" + _pad(d.getUTCMinutes(), 2) + ":" +
    _pad(d.getUTCSeconds(), 2) + " +0000";
}

// A message is a sequence of octets and every retrieval verb below
// counts in them, so the whole of this path works on buffers and
// converts once, where the bytes leave.
//
// The alternative reads well and is wrong. Decoding the message to a
// string first makes `length` a count of UTF-16 code units, which is
// not the octet count RFC 9051 section 6.4.5 gives to
// `BODY[]<start.count>` and to the `{n}` literal, nor the one RFC 1939
// section 3 gives to a POP3 size. On any message that is not entirely
// ASCII the two disagree, and the decode is lossy besides: an octet
// sequence that is not valid UTF-8 becomes U+FFFD, three octets where
// there was one. Mail carries those routinely, in an 8BITMIME body in a
// legacy charset and in unencoded 8-bit header fields.
var CRLF        = Buffer.from("\r\n", "ascii");
var HEADER_END  = Buffer.from("\r\n\r\n", "ascii");
var HEADER_END_LF = Buffer.from("\n\n", "ascii");
var EMPTY_BYTES = Buffer.alloc(0);
// The separator between two attributes inside one FETCH response, as
// the octet it is, so a response carrying a message can be assembled
// without a string ever standing in for the message.
var SP_BYTE     = Buffer.from(" ", "ascii");

/**
 * @primitive blamepost.mail.mailbox.headerBreak
 * @signature blamepost.mail.mailbox.headerBreak(raw)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5322 §2.1 (the header block ends at the first empty line), RFC 5321 §2.3.8 (CRLF on the wire)
 * @related   blamepost.mail.listeners.create, blamepost.mail.compose.send
 *
 * Where a message's header block ends. Returns
 * `{ at, terminator }` for the first empty line in `raw`, or `null`
 * when the message has none. `at` is the offset of the line ending
 * that closes the last header line, and `terminator` is how many
 * octets that line ending occupies: two for CRLF, one for a bare LF.
 * So the last header line ends at `at + terminator`, and the body
 * starts at `at + terminator * 2`.
 *
 * One forward scan, stopping at the first empty line whichever
 * terminator wrote it. Every surface in this server that has to know
 * where the headers stop asks here, and the reason they all ask one
 * place is that they used not to and disagreed.
 *
 * RFC 5321 section 2.3.8 requires CRLF on the wire, and this server
 * stores the octets a peer actually sent rather than rewriting them,
 * so a message separated by a bare LF arrives here intact. Searching
 * the whole message for the CRLF spelling first finds the wrong empty
 * line on exactly those messages: an ordinary quoted forward carries a
 * CRLF blank line later in its body, and everything between the real
 * separator and that one then reads as though it were part of the
 * header block. A message written entirely with bare LF has no CRLF
 * blank line at all, and a search for one comes back empty, so the
 * caller falls through to treating the whole message as headers.
 *
 * Both mistakes hand the sender the choice of which of its own bytes
 * this server calls a header: a line it wrote into the body becomes a
 * header to whichever surface searched, while the surfaces that scan
 * forward correctly say it is not, about the same stored message.
 *
 * @example
 *   var mailbox = require("./lib/mail/mailbox");
 *   var brk = mailbox.headerBreak(raw);
 *   var headers = brk === null ? raw : raw.subarray(0, brk.at + brk.terminator);
 */
function headerBreak(raw) {
  if (!Buffer.isBuffer(raw)) {
    throw new TypeError("blamepost.mail.mailbox.headerBreak: raw must be a Buffer. A message " +
      "is a sequence of octets and the offsets this returns are offsets into it, so a string " +
      "would answer in UTF-16 code units about a message nobody stored.");
  }
  for (var i = 0; i + 1 < raw.length; i += 1) {
    if (raw[i] === HEADER_END[0] && raw[i + 1] === HEADER_END[1] &&
        i + 3 < raw.length &&
        raw[i + 2] === HEADER_END[2] && raw[i + 3] === HEADER_END[3]) {
      return { at: i, terminator: 2 };
    }
    if (raw[i] === HEADER_END_LF[0] && raw[i + 1] === HEADER_END_LF[1]) {
      return { at: i, terminator: 1 };
    }
  }
  return null;
}

// Header bytes carried into a delivery report. RFC 3462 section 3 wants
// the original headers, not the whole message.
var MAX_REPORTED_HEADER_BYTES = 4096;

// Octets rendered as text for a report, bounded by what the text costs
// rather than by what the octets cost. The two are the same number only
// while the message is ASCII, and a peer picks the charset: an octet no
// decoder can read becomes a replacement character three octets wide, so
// a bound taken before the decode bounds nothing after it.
//
// The budget is spent one code point at a time, which is also what keeps
// the cut off the middle of a character: a report ending in half of one
// is a report a reader cannot render and an encoder cannot write.
function _boundedText(bytes, maxBytes) {
  var points = Array.from(bytes.toString("utf8"));
  var out = "";
  var spent = 0;
  for (var i = 0; i < points.length; i += 1) {
    var cost = Buffer.byteLength(points[i], "utf8");
    if (spent + cost > maxBytes) break;
    out += points[i];
    spent += cost;
  }
  return out;
}

/**
 * @primitive blamepost.mail.mailbox.reportedHeaderBlock
 * @signature blamepost.mail.mailbox.reportedHeaderBlock(body)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 3462 section 3 (the original headers in a delivery report)
 * @related   blamepost.mail.mailbox.headerBreak, blamepost.mail.delivery.bounce
 *
 * The header block of a message, for the report a failed recipient
 * produces. RFC 3462 section 3 puts the original headers in the last
 * part of the report so the sender can tell which message it is about.
 *
 * Text rather than octets, because the report composer this feeds takes
 * `originalHeaders` as a string and concatenates it into a report it
 * builds as a string. Handing it a Buffer would not carry the octets
 * through: the concatenation decodes it as UTF-8, so every octet outside
 * UTF-8 is replaced and the block grows past the cap measured below on
 * the way. Decoding here, under a cap, is what keeps that growth inside
 * a bound. If the composer ever takes octets, this is the first thing to
 * change and the cap is the thing to keep.
 *
 * Where that block ends is `headerBreak`'s answer rather than one taken
 * here, and the difference is what the peer can put in the report. A
 * report goes to whoever an envelope named, which on a forged envelope
 * is somebody who never sent anything, so a scan that finds the wrong
 * empty line copies body text of the peer's choosing into a report this
 * server addresses to a third party and signs its own name to.
 *
 * The cap holds however the message is framed. A block that runs to the
 * end of the message because the peer never sent the separator is the
 * malformed shape and was always bounded; a block that ends where it
 * should is the ordinary one, and it is the peer who decides how long
 * that is. Bounding only the malformed shape leaves the bound applying
 * to nobody, because every real sender writes the separator.
 *
 * Measured in bytes, on the bytes, because the peer chose the encoding
 * too: a block counted in characters and sent as multi-byte text is
 * larger than the count says.
 *
 * The cap is taken twice, and both are load-bearing. The first is on the
 * octets and bounds the work, so a block that runs to the end of a fifty
 * megabyte message is never decoded whole to find out how long it is.
 * The second is on what comes back, because the first stops holding the
 * moment the block is decoded: an octet no decoder can read becomes a
 * character three octets wide, so a peer sending nothing else turns a
 * four kilobyte bound into a twelve kilobyte report, addressed to
 * whoever the envelope named. Reading a cap's worth of octets is always
 * enough to fill the cap after the decode, because the decode only ever
 * grows what it is given.
 *
 * Every report path in this server asks here. A second copy of this
 * reasoning is a second answer to how long a report may be and to which
 * of a peer's bytes count as headers, and the copy is the one that goes
 * stale.
 *
 * @example
 *   var mailbox = require("./lib/mail/mailbox");
 *   await delivery.bounce({
 *     to:              envelope.from,
 *     recipient:       failed,
 *     reason:          "No such mailbox on this server",
 *     originalHeaders: mailbox.reportedHeaderBlock(raw),
 *   });
 */
function reportedHeaderBlock(body) {
  var bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  var brk = headerBreak(bytes);
  // The blank line itself is left out: RFC 3462 section 3 asks for the
  // headers, and the last header line's own terminator is the end of
  // them.
  var end = brk === null ? bytes.length : brk.at + brk.terminator;
  var window = bytes.subarray(0, Math.min(end, MAX_REPORTED_HEADER_BYTES));
  return _boundedText(window, MAX_REPORTED_HEADER_BYTES);
}

// The header block and the body of a message, split at the first blank
// line. RFC 9051 section 6.4.5 counts the blank line as part of
// BODY[HEADER], so the split keeps it on the header side. Both halves
// are views onto the message rather than copies of it.
function _splitMessage(raw) {
  var brk = headerBreak(raw);
  if (brk === null) return { header: raw, body: EMPTY_BYTES };
  var end = brk.at + brk.terminator * 2;
  return { header: raw.subarray(0, end), body: raw.subarray(end) };
}

// Header lines with their folded continuations attached, so selecting
// a field by name returns the whole field. Each line is the stored
// octets of that line, terminator excluded.
function _headerLines(header) {
  var out = [];
  var at  = 0;
  while (at < header.length) {
    var nl = header.indexOf(0x0a, at);
    var end = nl === -1 ? header.length : nl;
    // A CRLF terminator leaves the CR at the end of the line.
    var stop = end > at && header[end - 1] === 0x0d ? end - 1 : end;
    var line = header.subarray(at, stop);
    at = nl === -1 ? header.length : nl + 1;
    if (line.length === 0) continue;
    // RFC 5322 section 2.2.3: a line opening with space or tab
    // continues the field before it.
    if ((line[0] === 0x20 || line[0] === 0x09) && out.length > 0) {
      out[out.length - 1] = Buffer.concat([out[out.length - 1], CRLF, line]);
      continue;
    }
    out.push(line);
  }
  return out;
}

// The first `n` lines of a body, terminators included, as a view onto
// the stored octets. A line boundary is an LF, and the CR before it
// belongs to the line it ends, so a body using either terminator comes
// back exactly as it was written rather than rewritten to one of them.
function _firstLines(body, n) {
  if (n <= 0) return EMPTY_BYTES;
  var at = 0;
  for (var seen = 0; seen < n; seen += 1) {
    var nl = body.indexOf(0x0a, at);
    if (nl === -1) return body;
    at = nl + 1;
  }
  return body.subarray(0, at);
}

// RFC 5322 section 3.6.8 draws a field name from printable US-ASCII
// excluding the colon, so the NAME can be read as text to compare it.
// The value cannot, and is never decoded here.
function _fieldName(line, colon) {
  return line.subarray(0, colon).toString("latin1").trim().toUpperCase();
}

function _selectHeaderFields(header, names, invert) {
  var wanted = {};
  for (var i = 0; i < names.length; i += 1) wanted[names[i].toUpperCase()] = true;
  var lines = _headerLines(header);
  var kept = [];
  for (var j = 0; j < lines.length; j += 1) {
    var colon = lines[j].indexOf(0x3a);
    if (colon === -1) continue;
    var hit = Object.prototype.hasOwnProperty.call(wanted, _fieldName(lines[j], colon));
    if (invert ? !hit : hit) { kept.push(lines[j]); kept.push(CRLF); }
  }
  // RFC 9051 section 6.4.5 ends a header section with the blank line,
  // and a selection that matched nothing is still a section.
  if (kept.length === 0) return CRLF;
  kept.push(CRLF);
  return Buffer.concat(kept);
}

/**
 * @primitive blamepost.mail.mailbox.sequenceSet
 * @signature blamepost.mail.mailbox.sequenceSet(spec, highest)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9051 §9 (seq-number, seq-range, sequence-set)
 * @related   blamepost.mail.mailbox.create, blamepost.mail.listeners.create
 *
 * A comma separated sequence set compiled into a membership test.
 * Returns a function taking one number and answering whether the set
 * holds it. `highest` is what `*` stands for, which RFC 9051 section 9
 * defines as the largest number in use, so the caller supplies the
 * message count for a sequence set and the largest UID for a UID set.
 *
 * A range written in either order is the same range. Anything else is
 * refused with `mailbox/bad-sequence-set` rather than interpreted,
 * because a sequence set the server guesses at addresses the wrong
 * messages, and every verb that takes one either moves them, flags
 * them or destroys them.
 *
 * It is exported because FETCH, STORE and the IMAP SEARCH composition
 * all read the same grammar off the wire. A second reader would be a
 * second answer to what `2:*,7` means, and the two would differ on the
 * day one of them was extended.
 *
 * @example
 *   var inSet = blamepost.mail.mailbox.sequenceSet("2:4,9", 12);
 *   inSet(3);
 *   // true
 */
function sequenceSet(spec, highest) {
  var text = String(spec === undefined || spec === null ? "" : spec).trim();
  if (text.length === 0) {
    throw err("mailbox/bad-sequence-set", "a sequence set is required.");
  }
  var parts = text.split(",");
  if (parts.length > MAX_SEQ_SET_PARTS) {
    throw err("mailbox/bad-sequence-set",
      "that sequence set has more than " + MAX_SEQ_SET_PARTS + " parts.");
  }
  var ranges = [];
  function _point(token) {
    if (token === "*") return highest;
    if (!/^[0-9]{1,10}$/.test(token)) {
      throw err("mailbox/bad-sequence-set", "'" + text + "' is not a sequence set.");
    }
    var n = parseInt(token, 10);
    if (n < 1) {
      throw err("mailbox/bad-sequence-set", "a sequence number starts at 1.");
    }
    return n;
  }
  for (var i = 0; i < parts.length; i += 1) {
    var part = parts[i].trim();
    var colon = part.indexOf(":");
    if (colon === -1) {
      var only = _point(part);
      ranges.push([only, only]);
      continue;
    }
    var lo = _point(part.slice(0, colon));
    var hi = _point(part.slice(colon + 1));
    ranges.push(lo <= hi ? [lo, hi] : [hi, lo]);
  }
  return function (value) {
    for (var r = 0; r < ranges.length; r += 1) {
      if (value >= ranges[r][0] && value <= ranges[r][1]) return true;
    }
    return false;
  };
}

// Collapse a sorted list of numbers into the sequence set form RFC
// 7162 section 3.1.3 expects in a MODIFIED response code.
function _formatSeqSet(values) {
  if (values.length === 0) return "";
  var sorted = values.slice().sort(function (x, y) { return x - y; });
  var out = [];
  var start = sorted[0];
  var prev = sorted[0];
  for (var i = 1; i < sorted.length; i += 1) {
    if (sorted[i] === prev + 1) { prev = sorted[i]; continue; }
    out.push(start === prev ? String(start) : start + ":" + prev);
    start = sorted[i];
    prev = sorted[i];
  }
  out.push(start === prev ? String(start) : start + ":" + prev);
  return out.join(",");
}

// Split a fetch attribute list into its attributes, keeping bracketed
// sections and parenthesised field lists whole.
function _splitAtts(spec) {
  var text = String(spec === undefined || spec === null ? "" : spec).trim();
  if (text.length >= 2 && text[0] === "(" && text[text.length - 1] === ")") {
    text = text.slice(1, -1).trim();
  }
  var out = [];
  var current = "";
  var bracket = 0;
  var paren = 0;
  for (var i = 0; i < text.length; i += 1) {
    var ch = text[i];
    if (ch === "[") bracket += 1;
    else if (ch === "]") { if (bracket > 0) bracket -= 1; }
    else if (ch === "(") paren += 1;
    else if (ch === ")") { if (paren > 0) paren -= 1; }
    if ((ch === " " || ch === "\t") && bracket === 0 && paren === 0) {
      if (current.length > 0) { out.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) out.push(current);
  return out;
}

var FETCH_MACROS = {
  FAST: ["FLAGS", "INTERNALDATE", "RFC822.SIZE"],
  ALL:  ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"],
};

// ---- The mailbox access agent ----------------------------------------------

// The scopes `b.mail.agent` checks on every verb it routes, against the
// two roles this server issues. A mailbox owner reads their mail, files
// it, expunges it and uploads their own filter script. An administrator
// inherits exactly that and gains nothing over anybody else's mailbox:
// the administration console works through the identity layer, not
// through a mailbox, so an operator reading somebody's mail would be a
// separate grant this server does not make.
var MAILBOX_SCOPES = Object.freeze([
  "mail:read", "mail:move", "mail:expunge", "mail:sieve",
]);

// The scope in front of the filter surface. The framework's agent names
// the same one for its own filter verbs, so the four write verbs below
// check the table the agent checks rather than a second one that can be
// narrowed on one surface and not the other.
//
// They check it directly rather than by routing through `agent.sieve
// .put`, and the reason is that routing would change what this server
// accepts. That verb composes `b.guardMailSieve` at the strict profile,
// which caps a script at 2000 lines against the 64 KiB ceiling RFC 5804
// asks this server to advertise, and refuses any name absent from an
// operator-supplied owned-names list. Passing the list this account
// already owns plus the name it is creating satisfies the check without
// deciding anything, and per account row scoping is the ownership rule
// here in any case. Its two siblings, `sieve.list` and `sieve.activate`,
// are not routed upstream at all and reject every call.
var SIEVE_SCOPE = "mail:sieve";

// The scope in front of the hard delete, which is the same one
// `b.mail.agent.expunge` checks. The delete path finishes destructions
// the agent cannot see, so it checks the agent's scope on the agent's
// own table rather than running that half behind nothing.
var EXPUNGE_SCOPE = "mail:expunge";

// One table for the whole process. Both halves of this server resolve
// the same actor against the same roles, which is the property the
// second table existed to break.
var _roleTable = null;
function roleTable() {
  if (_roleTable === null) {
    _roleTable = b.permissions.create({
      roles: {
        account: MAILBOX_SCOPES.slice(),
        admin:   { extends: ["account"] },
      },
      audit: b.audit,
      // Refusals are recorded and granted reads are not. One rendered
      // page is several reads, and a row for each of them buries the
      // denials an operator is actually looking for.
      auditSuccess: false,
    });
  }
  return _roleTable;
}

// The role gate an agent was built with, or a refusal. `b.mail.agent`
// treats a missing permission table as "check nothing", so an agent
// composed without one is not a permissive gate, it is no gate at all,
// and every caller downstream reads exactly the same from both. That is
// the difference this server refuses to assemble across, and reading
// the table back is also how the filter verbs below reach the same one
// the agent checks rather than keeping a second copy.
function _roleGateOf(mailAgent, where) {
  var ctx = mailAgent && mailAgent._ctx;
  if (!ctx || typeof ctx !== "object" || !ctx.permissions ||
      typeof ctx.permissions.check !== "function") {
    throw new TypeError(where + ": the mail agent carries no role gate. b.mail.agent " +
      "checks a scope on every verb it routes and checks nothing at all when it was " +
      "built without a permission table, so a listener driving one runs unguarded " +
      "beside a browser surface that does not. Build it with " +
      "blamepost.mail.mailbox.agent, which composes the table this server issues.");
  }
  return ctx.permissions;
}

/**
 * @primitive blamepost.mail.mailbox.assertRoleGate
 * @signature blamepost.mail.mailbox.assertRoleGate(agent, where)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: an absent permission table is an absent gate)
 * @related   blamepost.mail.mailbox.agent, blamepost.create
 *
 * Refuse a mailbox access agent that carries no role gate. `where`
 * names the caller in the error, so an operator reads which composition
 * step refused.
 *
 * The reason this is a refusal rather than a warning is that the two
 * cases are indistinguishable from every consumer: an agent with a
 * permissive table and an agent with no table both allow every verb, and
 * only the second one also allows the verbs a narrower table would have
 * refused. A server that assembled anyway would run its three wire
 * protocols with no role check beside a browser surface that has one,
 * and nothing about that is visible until somebody uses it.
 *
 * @example
 *   blamepost.mail.mailbox.assertRoleGate(agent, "blamepost.create");
 */
function assertRoleGate(mailAgent, where) {
  _roleGateOf(mailAgent, where);
}

/**
 * @primitive blamepost.mail.mailbox.agent
 * @signature blamepost.mail.mailbox.agent(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one mailbox access agent for every protocol)
 * @related   blamepost.mail.mailbox.create, blamepost.create
 *
 * Build the mailbox access agent. This is the only place in this
 * repository that calls `b.mail.agent.create`, so the compliance
 * posture in front of a hard delete and the role gate in front of every
 * verb are set once rather than per caller.
 *
 * A second agent built beside this one is the failure it exists to
 * prevent. Two agents answer every call and differ only in what they
 * refuse, so the same message is kept on one protocol and destroyed on
 * another, and the same account is checked against a role table on one
 * surface and against nothing on the other. Neither shows up anywhere
 * except in the mail that is missing afterwards.
 *
 * @opts
 *   store:       object,   // required; a b.mailStore handle
 *   posture:     string,   // compliance posture the retention floor is read from
 *   permissions: object,   // a b.permissions table; the shipped roles when absent
 *
 * @example
 *   var agent = blamepost.mail.mailbox.agent({
 *     store:   b.mailStore.create({ backend: b.db }),
 *     posture: config.compliancePosture,
 *   });
 */
function agent(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.mailbox.agent: opts object is required");
  }
  if (!opts.store || typeof opts.store.fetchByObjectId !== "function") {
    throw new TypeError("blamepost.mail.mailbox.agent: opts.store must be a b.mailStore " +
      "handle, the byte level substrate the agent dispatches over.");
  }
  return b.mail.agent.create({
    store:       opts.store,
    posture:     opts.posture || null,
    permissions: opts.permissions || roleTable(),
    // One process, so the work runs where it was asked for. This server
    // has nothing to hand a mailbox read off to and no reason to.
    dispatch:    { mode: "local" },
  });
}

// ---- The adapter -----------------------------------------------------------

/**
 * @primitive blamepost.mail.mailbox.create
 * @signature blamepost.mail.mailbox.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9051 (IMAP4rev2), RFC 7162 (CONDSTORE), RFC 5464 (METADATA), RFC 1939 (POP3), RFC 5804 (ManageSieve)
 * @related   blamepost.mail.listeners.create, blamepost.store.open
 *
 * Build the handle the mailbox listeners take as their `mailStore`.
 * Wraps a `b.mailStore` instance, gives every account its own folders
 * above it, assigns the UIDs IMAP needs, keeps the original message
 * octets the store does not, and routes every hard delete through
 * `b.mail.agent.expunge`.
 *
 * The database must already be open with this module's `TABLES`
 * merged into its schema, and the vault must already be unsealed:
 * message octets are sealed on the way to disk and unsealed on the way
 * back.
 *
 * The handle names the agent it drives as `agent`, so a server built
 * around an already open adapter takes that one rather than composing a
 * second that can disagree with it about what a delete means and about
 * who may ask for one.
 *
 * @opts
 *   store:         object,     // required; a b.mailStore handle
 *   dataDir:       string,     // required; blobs are written under it
 *   vault:         object,     // seal and unseal pair; default b.vault
 *   agent:         object,     // a built agent; blamepost.mail.mailbox.agent builds one when absent
 *   posture:       string,     // compliance posture the agent enforces on expunge
 *   quotaBytesFor: function,   // optional; account id to byte cap, 0 for no cap
 *
 * @example
 *   var mailbox = blamepost.mail.mailbox.create({
 *     store:   b.mailStore.create({ backend: b.db }),
 *     dataDir: config.dataDir,
 *   });
 *   await mailbox.selectFolder({ id: accountId }, "INBOX", {});
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.mailbox.create: opts object is required");
  }
  var store = opts.store;
  if (!store || typeof store.appendMessage !== "function" ||
      typeof store.fetchByObjectId !== "function" ||
      typeof store.hardExpunge !== "function") {
    throw new TypeError("blamepost.mail.mailbox.create: opts.store must be a b.mailStore " +
      "handle. Build it with b.mailStore.create({ backend: b.db }) and pass the same one to " +
      "every listener, so they share the folders and the quota counters.");
  }
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new TypeError("blamepost.mail.mailbox.create: opts.dataDir is required. The " +
      "original message octets are written under it, sealed, because the store keeps the " +
      "parsed message rather than the bytes that arrived.");
  }
  var vault = opts.vault || b.vault;
  if (typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
    throw new TypeError("blamepost.mail.mailbox.create: opts.vault must expose seal and " +
      "unseal (pass b.vault, which is what the running server uses)");
  }
  if (opts.quotaBytesFor !== undefined && opts.quotaBytesFor !== null &&
      typeof opts.quotaBytesFor !== "function") {
    throw new TypeError("blamepost.mail.mailbox.create: opts.quotaBytesFor must be a " +
      "function taking an account id and returning its byte cap");
  }

  var blobDir = nodePath.join(opts.dataDir, "blobs");
  b.atomicFile.ensureDir(blobDir, 0o700);

  // The regulatory posture in force, held once. The agent reads it to
  // decide the retention floor over the message store's rows, and the
  // delete path reads it again over the rows this layer keeps beside
  // them, because a destruction the volume half refused leaves a row the
  // agent can no longer see. Two readers, one value, so the floor cannot
  // be one thing on one layer and another on the other.
  var posture = opts.posture || null;

  var mailAgent = opts.agent || agent({ store: store, posture: posture });

  // The role gate the agent checks, read back rather than kept as a
  // second option. An agent with none is refused here instead of
  // producing an adapter whose three wire protocols run unguarded, and
  // the filter verbs below check the very table the agent's own verbs
  // check rather than a copy that can be narrowed on one and not the
  // other.
  var roleGate = _roleGateOf(mailAgent, "blamepost.mail.mailbox.create");

  var quotaBytesFor = opts.quotaBytesFor || null;
  var provisioned = new Set();
  var drops = new Map();

  // Who is told when a message lands in a mailbox here.
  //
  // A list rather than one slot, and nothing here removes an entry. A
  // registration that replaced the previous one would stop the earlier
  // observer with nobody told, which is the failure that matters: an
  // observer nobody notices has stopped is worse than no observer.
  // Registering the same function twice is refused, because that is a
  // wiring mistake rather than a second interest, and the list has a
  // ceiling so a caller registering one per request shows up as a
  // refusal rather than as memory.
  var filedObservers = [];

  // ---- Accounts and folders ------------------------------------------------

  // The acting account, or a refusal. This is the whole of the per
  // account isolation: nothing below reads a folder without a value
  // from here, and there is no branch that carries on without one.
  function _accountOf(actor, verb) {
    if (!actor || typeof actor !== "object" || Array.isArray(actor) ||
        typeof actor.id !== "string" || actor.id.length === 0) {
      throw err("mailbox/no-actor",
        verb + " arrived without an authenticated account. Every mailbox here belongs to " +
        "one account, so a call that cannot say whose mailbox it is has no mailbox to " +
        "answer with.");
    }
    return actor.id;
  }

  // A wire name is the only handle an account has on one of its
  // mailboxes, and it reaches this layer from a URL path segment, an
  // IMAP command and a JMAP identifier. The rule below is what keeps
  // that namespace from meaning two things at once.
  //
  // No verb exposed today creates a mailbox: `_newFolder` runs only from
  // the default set at first use. The rule is settled anyway, and it is
  // enforced on the way in as well as on the way out, because the moment
  // a create verb lands an unconstrained name is the difference between a
  // mailbox and a message address, and a namespace that admits both is
  // one where a folder can be made to answer for something else. A name
  // already stored is a name that can no longer be taken back.
  //
  // The rule screens for collisions, not for a writing system. Any
  // script passes; what does not is a name that can render as another
  // name or address something else.
  //
  // RFC 9051 section 5.1: INBOX is the one mailbox name matched without
  // regard to case. Everything else is compared as written.
  // The separator between levels of a mailbox name. listFolders derives
  // HasChildren by testing this same boundary, so the two must agree or a
  // parent stops reporting its children.
  var HIERARCHY_DELIMITER = "/";
  var MAX_WIRE_NAME_BYTES = 255;
  var MESSAGE_ADDRESS_RE  = /^obj_[0-9a-f]+$/i;
  // RFC 9051 section 6.3.9 gives LIST two wildcards. A mailbox named for
  // one of them cannot be asked for unambiguously by the command that
  // lists it.
  var LIST_WILDCARDS      = ["*", "%"];

  function _wireName(name) {
    var text = String(name === undefined || name === null ? "" : name);
    if (text.length === 0) {
      throw err("mailbox/bad-mailbox-name", "a mailbox name is required.");
    }
    if (Buffer.byteLength(text, "utf8") > MAX_WIRE_NAME_BYTES) {
      throw err("mailbox/bad-mailbox-name",
        "a mailbox name stops at " + MAX_WIRE_NAME_BYTES + " bytes.");
    }
    // A control character in a name reaches the IMAP and ManageSieve
    // wire as a line the peer never sent, which is the shape every
    // command-injection defect in this protocol family is built from.
    // The listener quotes a name by escaping a quote and a backslash, so
    // a line terminator here is a response line the client parses as its
    // own. Tab, LF and CR are ordinary in free text and are exactly the
    // three that matter here, which is why the screen names them rather
    // than taking the free-text default.
    if (b.codepointClass.firstControlCharOffset(text, { forbidTab: true }) !== -1) {
      throw err("mailbox/bad-mailbox-name",
        "a mailbox name carries no control characters.");
    }
    // The rest of the codepoint threat catalogue: bidi overrides, which
    // render a stored name as a different one; zero-width and invisible
    // formatting characters, which make two names render identically;
    // the Unicode Tags block, which carries an invisible copy of an
    // ASCII string; and a word mixing writing systems, where one letter
    // substituted from another script produces a second Trash that files
    // mail nobody meant to file there.
    var screened = b.guardText.validate(text, { profile: "strict" });
    if (!screened.ok) {
      var issue = (screened.issues && screened.issues[0]) || null;
      throw err("mailbox/bad-mailbox-name",
        "a mailbox name is refused for a character that changes what it reads as: " +
        ((issue && (issue.snippet || issue.kind)) || "unknown") + ".");
    }
    // The hierarchy delimiter separates levels, so it cannot open a
    // name, end one, or appear twice running. Any of those produce an
    // empty level, and an empty level is a name that renders as its
    // parent while addressing something else.
    if (text.charAt(0) === HIERARCHY_DELIMITER ||
        text.charAt(text.length - 1) === HIERARCHY_DELIMITER ||
        text.indexOf(HIERARCHY_DELIMITER + HIERARCHY_DELIMITER) !== -1) {
      throw err("mailbox/bad-mailbox-name",
        "a mailbox name has no empty level, so it neither begins nor ends " +
        "with '" + HIERARCHY_DELIMITER + "' and never repeats it.");
    }
    for (var w = 0; w < LIST_WILDCARDS.length; w += 1) {
      if (text.indexOf(LIST_WILDCARDS[w]) !== -1) {
        throw err("mailbox/bad-mailbox-name",
          "a mailbox name carries no '" + LIST_WILDCARDS[w] + "', because LIST reads it " +
          "as a wildcard and the name could not be asked for on its own.");
      }
    }
    var levels = text.split(HIERARCHY_DELIMITER);
    for (var i = 0; i < levels.length; i += 1) {
      // A message is addressed as obj_<hex> beneath its mailbox. A level
      // spelled the same way would make one path name a mailbox in one
      // reading and a message in another, and the reading that wins is
      // whichever code looked first.
      if (MESSAGE_ADDRESS_RE.test(levels[i])) {
        throw err("mailbox/bad-mailbox-name",
          "a mailbox level cannot be spelled like a message address ('" +
          levels[i] + "'), because the same path would name both.");
      }
      // A level padded with whitespace is a twin of the level without
      // it: the two render the same in every client and address
      // different mailboxes. The wide table matters here rather than the
      // ASCII space alone, because a no-break space is the one a client
      // will not show the owner at all.
      if (b.codepointClass.trimRanges(levels[i],
        b.codepointClass.WHITESPACE_RANGES) !== levels[i]) {
        throw err("mailbox/bad-mailbox-name",
          "a mailbox level neither begins nor ends with a space, because the name " +
          "with the padding and the name without it render the same.");
      }
    }
    if (text.toUpperCase() === "INBOX") return "INBOX";
    return text;
  }

  function _folderRow(account, wireName) {
    return b.db.from(FOLDERS).where({ account: account, wireName: wireName }).first() || null;
  }

  // The UIDVALIDITY a new folder row takes.
  //
  // RFC 9051 section 2.3.1.1: when a mailbox's unique identifiers do not
  // persist into a new session, the server MUST assign a value larger
  // than the one it used before. That value is the whole of what tells
  // an IMAP client its cache is stale. A client handed the same one
  // keeps everything it holds and goes on addressing messages by UID,
  // and a UID space that has restarted at 1 underneath it means every
  // one of those now names a different message.
  //
  // Seconds since the epoch is the value that section suggests, and on
  // its own it is not enough. Provisioning an address, erasing it and
  // provisioning it again gives the mailbox a new row with its UID
  // space back at 1, and two of those inside one second read the same
  // second. A clock corrected backwards produces the same collision
  // across a much wider gap, and a host that boots before it has
  // synchronized does it on every cold start.
  //
  // So the clock proposes and the stored values dispose: whatever the
  // volume has already issued sets the floor, and the new row goes above
  // it. Read across the whole table rather than the rows for one name,
  // because the row that carried the earlier value is gone by the time
  // its name is taken again, and the highest value ever issued here is
  // the one bound that outlives it.
  //
  // The stored rows are that record only while they are there. Erasing
  // an account takes its mailbox rows with it, so the largest value the
  // table can answer with is free to fall, and the same address
  // provisioned again inside the same second would take a value already
  // handed to a client for a different mailbox. So a value is held below
  // as it is issued, and a row's value is held before the row is erased,
  // and the floor is whichever of the two is higher.
  //
  // Across a restart the record is the stored rows again, and the clock
  // is what carries the rest: it has moved forward by at least the
  // length of the restart, so a value it proposes is above every second
  // that has already passed.
  var uidvalidityFloor = 0;

  function _holdUidvalidityFloor(value) {
    if (typeof value === "number" && value > uidvalidityFloor) uidvalidityFloor = value;
  }

  // The values a set of mailbox rows carries, held as the floor before
  // any of them is erased.
  //
  // Synchronous, and called from the verb that suspends rather than
  // written inside it, for the reason the identifier allocator is
  // written that way: a counter read on one side of a suspension and
  // acted on from the other is a counter another caller has had the
  // whole suspension to move.
  function _holdFloorOfRows(rows) {
    for (var i = 0; i < rows.length; i += 1) _holdUidvalidityFloor(rows[i].uidvalidity);
  }

  function _nextUidvalidity(now) {
    var proposed = Math.floor(now / TIME.seconds(1));
    var highest = b.db.from(FOLDERS).orderBy("uidvalidity", "desc").first();
    _holdUidvalidityFloor(highest && highest.uidvalidity);
    var floor = uidvalidityFloor;
    var value = proposed > floor ? proposed : floor + 1;
    // Unreachable while the clock is anywhere near the present: the
    // ceiling is a seconds reading in the year 2106, and the floor only
    // climbs one per recreated mailbox. It is checked rather than
    // assumed because the alternative to refusing is issuing a value the
    // field cannot carry, which a client reads as some other mailbox.
    if (value > MAX_UIDVALIDITY) {
      throw err("mailbox/uidvalidity-exhausted",
        "this volume has issued the highest UIDVALIDITY the unsigned 32 bit field in RFC 9051 " +
        "section 2.3.1.1 can carry, so a new mailbox cannot be told apart from one a client " +
        "already has cached.");
    }
    _holdUidvalidityFloor(value);
    return value;
  }

  function _newFolder(account, wireName, role) {
    // The name is screened here as well as on every read, because this
    // is the only place a name enters the namespace. A row stored
    // unscreened is a folder the rule refuses to open afterwards, which
    // is a mailbox nobody can reach rather than a mailbox nobody can
    // spoof.
    var wire = _wireName(wireName);
    // The store knows the folder by a random token, so its folder
    // table carries neither the account nor the name the owner chose.
    var physical = "mbx_" + b.crypto.generateToken(BYTES.bytes(16));
    store.createFolder(physical, { role: role || null });
    var now = Date.now();
    return b.db.from(FOLDERS).insertOne({
      _id:         b.uuid.v7(),
      account:     account,
      folder:      physical,
      wireName:    wire,
      role:        role || null,
      uidvalidity: _nextUidvalidity(now),
      uidnext:     1,
      subscribed:  1,
      createdAt:   now,
      updatedAt:   now,
    });
  }

  // The default set, created the first time an account is seen. Mail
  // arriving for an account that has never signed in still has an
  // INBOX to land in.
  function _ensureAccount(account) {
    if (provisioned.has(account)) return;
    if (b.db.from(FOLDERS).where({ account: account }).count() === 0) {
      for (var i = 0; i < DEFAULT_FOLDERS.length; i += 1) {
        _newFolder(account, DEFAULT_FOLDERS[i].name, DEFAULT_FOLDERS[i].role);
      }
    }
    provisioned.add(account);
  }

  function _requireFolder(account, name) {
    var wire = _wireName(name);
    _ensureAccount(account);
    var row = _folderRow(account, wire);
    if (!row) {
      throw err("mailbox/no-folder", "no mailbox named '" + wire + "'.");
    }
    return row;
  }

  function _touchFolder(row, changes) {
    var patch = Object.assign({ _id: row._id, updatedAt: Date.now() }, changes);
    b.db.from(FOLDERS).where({ _id: row._id }).updateOne(patch);
  }

  // Message identifiers out of one folder's counter. Every message this
  // layer files into a folder takes its identifier from here, and from
  // nowhere else.
  //
  // The whole of it is one synchronous run: read the counter, record
  // what was taken, hand the values back. That is what makes it
  // indivisible. `b.db` is one synchronous handle in one process, so a
  // statement sequence carrying no `await` cannot be cut in half, and a
  // caller that read the counter above an `await` and spent it below one
  // has handed another caller the whole suspension to spend the same
  // value. Both then write it, and the second write fails on the folder
  // and identifier index after the message store has already been told
  // to move the message: the store holds it in one folder, this layer
  // holds it in another, and a client that reads the intersection of
  // them finds nothing at all.
  //
  // The row is re-read here rather than taken from the caller for the
  // same reason. RFC 9051 section 2.3.1.1 has identifiers ascend within
  // a mailbox and never repeat, so the fresh counter is at least the
  // value the caller saw and never below it, and a caller that files
  // fewer messages than it reserved leaves a gap rather than reusing
  // one, which that section allows and which UIDNEXT still sits above.
  function _takeUids(folderId, howMany) {
    // A count that is not a whole positive number would be written
    // straight into the counter, and a counter carrying one is a folder
    // that hands out an identifier it has already used, for the rest of
    // the mailbox's life. It refuses rather than recording it.
    if (typeof howMany !== "number" || !isFinite(howMany) ||
        howMany < 1 || Math.floor(howMany) !== howMany) {
      throw new TypeError("blamepost.mail.mailbox: _takeUids(folderId, howMany) needs a " +
        "whole number of identifiers, one or more");
    }
    var folder = b.db.from(FOLDERS).where({ _id: folderId }).first();
    if (!folder) {
      throw err("mailbox/no-folder",
        "the mailbox a message was being filed into is no longer there.");
    }
    var first = folder.uidnext;
    _touchFolder(folder, { uidnext: first + howMany });
    return { folder: folder.folder, uidvalidity: folder.uidvalidity, first: first };
  }

  // ---- Message octets ------------------------------------------------------

  function _blobPath(digest) {
    return blobPathFor(blobDir, digest);
  }

  // The fewest bytes a sealed body can occupy on disk, for a message of
  // this many octets.
  //
  // The seal carries a ciphertext of the base64 text of the message, a
  // stream cipher's output is exactly as long as its input, and
  // everything wrapped around that ciphertext only adds to it. So a file
  // shorter than that text is not the sealed form of this message,
  // whatever the envelope happens to look like.
  //
  // Nothing here reads the envelope's own layout, which is what keeps
  // the bound true across a vendor refresh. A framework that changes the
  // envelope changes how much room the bound leaves above a correct
  // file; it can never turn it into a bound a correct file fails.
  function _sealedFloorBytes(messageBytes) {
    return 4 * Math.ceil(messageBytes / 3);
  }

  // What is at a body's path right now, or null when nothing is. A stat
  // that cannot be taken reads as nothing there, because the write below
  // is the answer to both, and a path that genuinely cannot be written
  // refuses there with the reason rather than here with a guess.
  function _blobOnDisk(target) {
    try { return nodeFs.statSync(target); }
    catch (_e) { return null; }
  }

  // A body that had to be written again is a fault on the volume rather
  // than a property of the message, and the delivery that repaired it is
  // the only thing that ever sees it. One repair is a bad sector; a run
  // of them is a volume on its way out, and an operator can read that
  // only off a trail that has them in it. The digest goes in whole,
  // because the row is read by whoever holds the volume and it is what
  // `blobs report --verify` names a file by.
  //
  // Drop-silent by design, through the framework's synchronous emit: the
  // octets are on disk before this runs, so a sink that cannot write
  // must not turn a repaired body into a refused delivery. The identity
  // is the store's, so the row names whoever the surrounding work
  // established and records an absence when nothing did.
  function _recordBodyRepaired(digest, foundBytes, messageBytes) {
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.body_repaired",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   "the stored body was shorter than the message filed under its name, so the " +
        "delivery holding those octets wrote them again",
      resource: { kind: "message_body", id: digest },
      metadata: { foundBytes: foundBytes, messageBytes: messageBytes },
    });
  }

  // A message that left every mailbox it was in while something of it
  // stayed on the volume: the row binding it to a mailbox, or the sealed
  // octets that row names. Either way the octets are still here, because
  // the row is what holds them against the release.
  //
  // This is the one thing the delete path can be told that it cannot pass
  // on to every client that asked. RFC 9051 section 6.4.3 gives EXPUNGE
  // no refusal form, so an IMAP client is told the message went, which is
  // true of the mailbox and not of the volume; POP3 and the sessionless
  // verbs do have a word for it and use it. The trail is where the half
  // no protocol carries has to land, so an operator can find out that
  // mail this server was asked to lose is still here.
  //
  // The digest goes in whole. The row is read by whoever holds the
  // volume, it is what `blobs report --verify` names a file by, and it is
  // what turns "something did not go" into a file somebody can go and
  // look at.
  //
  // Drop-silent by design, through the framework's synchronous emit: the
  // store row is already destroyed by the time this runs, so a sink that
  // cannot write must not turn a partial delete into a refused one.
  // A message the message store moved and this layer could not follow,
  // so the store holds it in the destination and no row here names it.
  //
  // Drop-silent by design, through the framework's synchronous emit: the
  // store's half of the move is already committed by the time this runs,
  // so a sink that cannot write must not turn a half-finished move into
  // a raised one and lose the rest of the set with it.
  function _recordMoveUnbound(objectid, source, destination, detail) {
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.move_unbound",
      outcome:  "failure",
      actor:    auditActor.current(),
      reason:   "the message store moved this message and the row binding it to a mailbox " +
        "did not follow, so the store holds a message no mailbox names and no delete verb " +
        "reaches",
      resource: { kind: "message", id: objectid },
      metadata: {
        fromFolder: source.folder,
        fromName:   source.wireName,
        toFolder:   destination.folder,
        toName:     destination.wireName,
        detail:     detail,
      },
    });
  }

  function _recordDestructionIncomplete(objectid, digest, stayed, detail) {
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.destruction_incomplete",
      outcome:  "failure",
      actor:    auditActor.current(),
      reason:   "the message was destroyed and the volume would not take one of the two " +
        "acts that remove it from this layer, so its octets are still stored here",
      resource: { kind: "message_body", id: digest },
      metadata: { objectid: objectid, stayed: stayed, detail: detail },
    });
  }

  // Put one message's octets on the volume, and answer with the name
  // they are filed under.
  //
  // The name and the octets come from one derivation, here. Nothing can
  // file a message under a name its own content does not produce,
  // because no caller is given the chance to say what the name is. That
  // matters most on the repair below: the only bytes it can ever write
  // over a file other accounts' rows already point at are bytes that
  // hash to the name it writes them under.
  //
  // Content addressing means the second account handed a message this
  // volume already holds writes nothing. That is the ordinary case, it
  // is the whole reason one mailing-list message costs one copy rather
  // than one per recipient, and it stays free.
  //
  // What it hides is the case this checks for. A body that has gone bad
  // on the volume, from a restore that copied a prefix, a write that
  // stopped part way, or a device that gave back less than it was given,
  // is still a file at that path. Every later account handed the same
  // message inherits it, and their mail is unreadable from the moment it
  // arrives: they never had a good copy of their own to lose. The
  // delivery is holding the octets while that is true, which makes it
  // the one point where putting it right costs the write that was about
  // to happen anyway.
  //
  // What is affordable decides what is checked. Unsealing and re-hashing
  // every file a duplicate delivery lands on would put a full read and a
  // full digest of the message on the delivery path for every message
  // this server already holds, which is a cost every delivery pays for a
  // fault almost none of them meet. A length is a stat. So the check is
  // a length, and what it separates is a body cut short from a whole
  // one. What it cannot separate is a body that changed without changing
  // length, which is what a flipped bit leaves: that shape is refused at
  // the read with `mailbox/blob-digest-mismatch` and named by
  // `blobs report --verify`, and it is no worse for not being caught
  // here.
  function _writeBlob(raw) {
    var digest = b.crypto.sha3Hash(raw);
    var target = _blobPath(digest);
    var onDisk = _blobOnDisk(target);

    // Something at the path that is not a file was not put there by this
    // server, and writing over it is a decision about somebody else's
    // data. The message is refused instead, which leaves it with its
    // sender rather than accepting mail this volume cannot store.
    if (onDisk !== null && !onDisk.isFile()) {
      throw err("mailbox/blob-path-not-a-file",
        "the path this message body belongs at holds something that is not a file, so the " +
        "message was not stored. Run `blamepost blobs report` to see what is on the volume.");
    }
    if (onDisk !== null && onDisk.size >= _sealedFloorBytes(raw.length)) return digest;

    b.atomicFile.ensureDir(nodePath.dirname(target), 0o700);
    // Atomic by the same route every other file on this volume is
    // written: a temporary file, an fsync, a rename and an fsync of the
    // directory. A repair that landed in pieces would turn one body that
    // reads short into no body at all, on a path other accounts' rows
    // already point at.
    b.atomicFile.writeSync(target, vault.seal(raw.toString("base64")), { fileMode: 0o600 });
    // Nothing above touches a row, so the count of messages naming this
    // body is exactly what it was. A repair rewrites octets and files
    // nothing.
    if (onDisk !== null) _recordBodyRepaired(digest, onDisk.size, raw.length);
    return digest;
  }

  // The stored octets for one digest, checked against the name they are
  // filed under before they are handed back.
  //
  // The seal answers a different question from the one the reader is
  // asking. It says these octets were written by a server holding this
  // volume's vault key, and every body on the volume is sealed under
  // that same key, so it says nothing about WHICH message they are. The
  // name is what binds a body to the row pointing at it, and the name is
  // a plaintext path while the row is inside a database that is
  // encrypted and authenticated. Moving a file this server sealed itself
  // therefore costs nothing and forging one costs the key, so the cheap
  // half of the binding is the half that has to be checked, and checking
  // it is re-hashing the octets that were just unsealed.
  //
  // The cost is one pass over bytes this call has already unsealed and
  // base64-decoded in full, so it is a constant factor on work already
  // being done rather than a new read of the message.
  function _readBlob(digest) {
    var sealed;
    try {
      sealed = b.atomicFile.readSync(_blobPath(digest), {
        maxBytes: MAX_BLOB_FILE_BYTES,
        encoding: "utf8",
      });
    } catch (readError) {
      // A read that does not produce the octets is a refusal this layer
      // words, not an exception to pass along. Every caller here is a
      // wire handler, and each of them answers its client with the
      // message of whatever reached it: the file layer's own says `file
      // not found` and names the absolute path, so the operator's
      // volume layout and the message's content digest go out to
      // anybody who can authenticate, over a protocol whose vocabulary
      // for the same condition is one line.
      //
      // The condition is ordinary rather than exceptional, which is why
      // it is reachable at all. A POP3 maildrop is a snapshot taken at
      // authentication (RFC 1939 section 3), so a message another
      // protocol destroys mid session stays in the listing the session
      // is reading from, and this is the read that finds the body gone.
      // Outside that race it means the message store has lost octets,
      // so the sentence has to serve both readers.
      //
      // It is kept short enough to survive the reply-line clamp a
      // mailbox listener puts on a refusal, because a sentence cut in
      // half on the wire is one the client's user cannot act on.
      var missing = readError && readError.code === "ENOENT";
      throw err("mailbox/blob-unreadable",
        "the stored body for message " + String(digest).slice(0, DIGEST_PREFIX_CHARS) +
        (missing
          ? "... is no longer on this volume. "
          : "... could not be read from this volume (" +
            ((readError && readError.code) || "unknown") + "). ") +
        "Run `blamepost blobs report --verify` to see how much of the message store is " +
        "affected.");
    }
    // The seal opening and the octets being the right ones are two
    // questions, and a body cut short fails the first rather than the
    // second: the envelope authenticates what it carries end to end, so
    // a file missing its tail does not open at all. What arrives from
    // the vault is an ordinary error carrying no code, which a listener
    // has no reading for and a client would be told to retry forever.
    // It is a permanent verdict about this body, so it is worded as one
    // here.
    //
    // Nothing in the handler reads what it caught, for the same reason
    // the read failure above is not passed along: the message belongs to
    // a layer whose vocabulary is not this protocol's, and it is
    // answered to whoever asked for the message.
    var opened;
    try { opened = vault.unseal(sealed); }
    catch (_sealError) {
      throw err("mailbox/blob-seal-unopened",
        "the stored body for message " + String(digest).slice(0, DIGEST_PREFIX_CHARS) +
        "... did not open, so these octets were altered or cut short after they were " +
        "written. Nothing is returned for it. Run `blamepost blobs report --verify` to see " +
        "how much of the message store is affected.");
    }
    var raw = Buffer.from(opened, "base64");
    var actual = b.crypto.sha3Hash(raw);
    if (actual !== digest) {
      throw err("mailbox/blob-digest-mismatch",
        "the stored body filed under " + digest.slice(0, DIGEST_PREFIX_CHARS) +
        "... holds octets that hash to " + actual.slice(0, DIGEST_PREFIX_CHARS) +
        "..., so it is not the message this row points at. " +
        "Nothing is returned for it: serving it would hand one account another account's " +
        "mail. Run `blamepost blobs report --verify` to see how much of the volume is " +
        "affected, and restore the message store from a backup taken before it happened.");
    }
    return raw;
  }

  // Content addressing means several accounts share one file, so the
  // file goes only when the last row pointing at it goes.
  //
  // It ANSWERS rather than raising, because its caller is walking a set.
  // A removal is refused for reasons that belong to the volume rather
  // than to the message: a mount that has gone read-only, a permission an
  // operator changed, another process holding the file open. `force`
  // guards none of those, and reading it as a guard is the mistake worth
  // naming here: it covers a file that is already gone and nothing else.
  //
  // A refusal allowed to leave would abandon every message behind this
  // one in the same delete, each with its store row already destroyed, so
  // each becomes mail nothing reaches with a body nothing releases. It
  // would also hand a wire handler the file layer's own sentence, which
  // names the volume's layout and the message's content digest, in place
  // of an answer about the account holder's mail.
  //
  // `null` says nothing was left behind, which is the answer both for the
  // removal that was taken and for the body another row is still naming:
  // one shared with a mailbox that is still here stays on purpose, and
  // the last row to go is the one that releases it.
  function _releaseBlob(digest) {
    if (b.db.from(MESSAGES).where({ blobDigest: digest }).count() > 0) return null;
    return _unlinkBlob(digest);
  }

  // The same release, counting every row except one named row of this
  // account's.
  //
  // It exists for exactly one caller: a row this layer could not remove
  // and never will, on a message whose store row went on an earlier run.
  // Nothing resolves that row, because membership served to a reader is
  // this layer's rows intersected with the store's and it is outside the
  // intersection. So as a REFERENCE it holds nothing open, while as a
  // count it pins the octets forever and no verb anywhere frees them.
  // Excluding it releases the message this server was asked to lose and
  // still keeps the file for any OTHER account whose live message shares
  // it, which is the whole reason the release is counted rather than
  // unconditional.
  function _releaseBlobBesides(digest, folderRow, objectid) {
    var naming = b.db.from(MESSAGES).where({ blobDigest: digest }).all();
    for (var i = 0; i < naming.length; i += 1) {
      if (naming[i].folder === folderRow.folder && naming[i].objectid === objectid) continue;
      return null;
    }
    return _unlinkBlob(digest);
  }

  function _unlinkBlob(digest) {
    try {
      nodeFs.rmSync(_blobPath(digest), { force: true });
    } catch (e) {
      return { detail: (e && e.message) || String(e) };
    }
    return null;
  }

  // ---- Folder snapshots ----------------------------------------------------

  // Every row the message store holds for one folder, read whole.
  //
  // The store's folder read is BOUNDED: it answers under a row limit and
  // says nothing about what the limit cut off. So the bound is worth
  // something only when the answer comes back SHORT of it. A read that
  // returned exactly as many rows as it was allowed may have been
  // truncated and there is no second field to ask; a read that returned
  // fewer than it was allowed cannot have been, because a limit only
  // ever removes rows. That is the whole rule this loop is: raise the
  // bound, ask again, and trust the first answer that is short of its
  // own bound.
  //
  // Getting that wrong is what the loop is here to make impossible. The
  // caller can only set a bound from a count it already has, and the
  // only count this layer holds is its own row count, which the store
  // is entitled to disagree with: a message written to the store and
  // not filed here leaves a row on the store side with no partner, and
  // it shortens a bounded read by one. What such a read then drops is
  // NOT the unpaired row but whichever paired message the store orders
  // last, so the mailbox reports a smaller EXISTS than it holds, FETCH
  // 1:* returns fewer messages than are stored, and the hard delete
  // answers for a live message with the reason reserved for an
  // identifier that names nothing. Which message vanishes also MOVES,
  // because the store orders by modification sequence and a flag change
  // rewrites one: marking mail read hides a different message each
  // time.
  //
  // Every read starts from the beginning rather than resuming after the
  // last row of the one before it, and that is not an economy being
  // passed up. The store assigns ONE modification sequence to a whole
  // batch of flag changes, so a cursor reading `modseq > lastSeen`
  // steps over every other row sharing the sequence it stopped on: a
  // client marking twenty messages read gives all twenty the same
  // number, and the resume would carry one of them and lose nineteen.
  // Raising the bound and re-reading whole has no such seam in it.
  //
  // `sinceModseq` is zero and the store's own filter is strictly
  // greater, which reaches every row: the store seeds a folder's
  // counter at zero and assigns from one up, on the append and on every
  // flag change, so no stored message carries a sequence of zero.
  //
  // Termination is by construction rather than by expectation. The
  // folder holds some finite number of rows, the bound only ever grows,
  // and it doubles, so it passes that number after at most log2 of it
  // doublings; a read allowed more rows than the folder holds returns
  // all of them, which is short of its bound. A mailbox of a million
  // messages settles in twenty-one reads at the very worst, and in one
  // for every folder whose two layers agree.
  function _storedRows(folder, firstBound) {
    var bound = firstBound;
    for (;;) {
      var held = store.queryByModseq(folder, { sinceModseq: 0, limit: bound });
      if (held.length < bound) return held;
      bound *= 2;
    }
  }

  // Every message in one folder, in UID order, with the sequence
  // numbers IMAP counts from. Membership is this layer's rows
  // intersected with the store's, so a row on either side without its
  // partner is left out rather than served half.
  //
  // This is the ONE place membership is decided. Everything below is a
  // projection over it, so EXISTS, FETCH, SEARCH and the delete path
  // cannot come to different answers about which messages a mailbox
  // holds.
  //
  // The store side is read in one query that selects the columns it
  // keeps in the clear, so a folder listing unseals nothing. The
  // sealed columns are read one message at a time and only by the
  // caller that needs what is in them.
  //
  // A folder this layer holds no rows for is empty whatever the store
  // holds, so the store is not asked at all. That also keeps a mailbox
  // whose store folder has gone missing answering as empty rather than
  // raising the store's own sentence about its folder table at a client
  // that asked for a message count.
  function _membership(row) {
    var rows = b.db.from(MESSAGES).where({ folder: row.folder }).orderBy("uid", "asc").all();
    var out = [];
    if (rows.length === 0) return out;
    // One more than this layer holds, so the read is short of its own
    // bound on the first pass for every folder the store has not been
    // left holding an extra row for.
    var held = _storedRows(row.folder, rows.length + 1);
    // The identifiers are the store's rather than a client's, and the
    // map is still built without a prototype: a message store that
    // minted `constructor` would otherwise resolve against Object's own
    // and report a message this folder does not hold.
    var stored = Object.create(null);
    for (var s = 0; s < held.length; s += 1) stored[held[s].objectid] = held[s];
    for (var i = 0; i < rows.length; i += 1) {
      var partner = stored[rows[i].objectid];
      if (partner === undefined) continue;
      out.push({
        seq:          out.length + 1,
        uid:          rows[i].uid,
        objectid:     rows[i].objectid,
        modseq:       partner.modseq,
        sizeBytes:    rows[i].sizeBytes,
        internalDate: rows[i].internalDate,
        // Beside the date the message shows, the clock reading this
        // server took when it filed the message. The two are the same
        // for everything a peer delivered and differ for anything a
        // client uploaded with a date of its own, and only this one is
        // this server's own answer to when the record arrived.
        createdAt:    rows[i].createdAt,
        digest:       rows[i].blobDigest,
      });
    }
    return out;
  }

  // The membership list with the message store's own row hanging off
  // each entry, which is what the search scan wants: the flags, the
  // subject and the correspondents as ONE answer about one message
  // rather than two taken a moment apart.
  //
  // This is the read that unseals, and it is the only one. Every entry
  // membership named is kept whether or not the row came back, because
  // dropping one here would leave this list and the one it was built
  // from disagreeing about a mailbox's sequence numbers. A caller that
  // cannot work without the row refuses on the entry instead.
  function _snapshotStored(row) {
    var paired = _membership(row);
    var out = [];
    for (var i = 0; i < paired.length; i += 1) {
      var stored = store.fetchByObjectId(row.folder, paired[i].objectid);
      out.push({
        seq:          paired[i].seq,
        uid:          paired[i].uid,
        objectid:     paired[i].objectid,
        modseq:       paired[i].modseq,
        sizeBytes:    paired[i].sizeBytes,
        internalDate: paired[i].internalDate,
        createdAt:    paired[i].createdAt,
        digest:       paired[i].digest,
        flags:        (stored && stored.flags) || [],
        stored:       stored || null,
      });
    }
    return out;
  }

  // The same membership list without the store's row hanging off each
  // entry, which is what every caller but the search scan wants. `flags`
  // is filled only when the caller asked for it, so an entry carrying
  // null flags reads as a question that was not asked rather than as a
  // message with none.
  //
  // Asking for them is what costs: the store keeps a message's flags
  // beside its sealed subject, correspondents and body, and the only
  // read that returns them opens all four. So a caller that wants the
  // flags pays one such read per message and a caller that does not
  // pays none, which is why the flag is an argument rather than
  // something filled in unconditionally and ignored.
  function _snapshot(row, withFlags) {
    var paired = withFlags ? _snapshotStored(row) : _membership(row);
    var out = [];
    for (var i = 0; i < paired.length; i += 1) {
      out.push({
        seq:          paired[i].seq,
        uid:          paired[i].uid,
        objectid:     paired[i].objectid,
        modseq:       paired[i].modseq,
        sizeBytes:    paired[i].sizeBytes,
        internalDate: paired[i].internalDate,
        digest:       paired[i].digest,
        flags:        withFlags ? paired[i].flags : null,
      });
    }
    return out;
  }

  function _highestModseq(messages) {
    var high = 0;
    for (var i = 0; i < messages.length; i += 1) {
      if (messages[i].modseq > high) high = messages[i].modseq;
    }
    return high;
  }

  function _selected(messages, seqSet, useUid) {
    var highest = 0;
    for (var h = 0; h < messages.length; h += 1) {
      var value = useUid ? messages[h].uid : messages[h].seq;
      if (value > highest) highest = value;
    }
    var inSet = sequenceSet(seqSet, highest);
    var out = [];
    for (var i = 0; i < messages.length; i += 1) {
      if (inSet(useUid ? messages[i].uid : messages[i].seq)) out.push(messages[i]);
    }
    return out;
  }

  // ---- IMAP ----------------------------------------------------------------

  function selectFolder(actor, name, selectOpts) {
    var account = _accountOf(actor, "SELECT");
    var row = _requireFolder(account, name);
    var messages = _snapshot(row, false);
    var info = {
      exists:      messages.length,
      // IMAP4rev2 removed the \Recent flag, so the count the listener
      // prints on the RECENT line is zero rather than a guess.
      recent:      0,
      flags:       PERMANENT_FLAGS.slice(),
      uidvalidity: row.uidvalidity,
      uidnext:     row.uidnext,
      modseq:      _highestModseq(messages),
    };
    return info;
  }

  function statusFolder(actor, name, items) {
    var account = _accountOf(actor, "STATUS");
    var row = _requireFolder(account, name);
    var wanted = {};
    var list = Array.isArray(items) ? items : [];
    for (var i = 0; i < list.length; i += 1) wanted[String(list[i]).toUpperCase()] = true;
    var messages = _snapshot(row, wanted.UNSEEN === true);
    var totalBytes = 0;
    var unseen = 0;
    for (var m = 0; m < messages.length; m += 1) {
      totalBytes += messages[m].sizeBytes;
      if (messages[m].flags && messages[m].flags.indexOf("\\Seen") === -1) unseen += 1;
    }
    return {
      MESSAGES:      messages.length,
      UIDNEXT:       row.uidnext,
      UIDVALIDITY:   row.uidvalidity,
      UNSEEN:        unseen,
      RECENT:        0,
      SIZE:          totalBytes,
      HIGHESTMODSEQ: _highestModseq(messages),
    };
  }

  function listFolders(actor) {
    var account = _accountOf(actor, "LIST");
    _ensureAccount(account);
    var rows = b.db.from(FOLDERS).where({ account: account }).orderBy("createdAt", "asc").all();
    var names = [];
    for (var n = 0; n < rows.length; n += 1) names.push(rows[n].wireName);
    var out = [];
    for (var i = 0; i < rows.length; i += 1) {
      var attributes = [];
      // RFC 6154 special use attributes, so a client puts its sent
      // mail and its drafts where the owner already keeps them.
      if (rows[i].role && rows[i].role !== "inbox") {
        attributes.push(rows[i].role.charAt(0).toUpperCase() + rows[i].role.slice(1));
      }
      var prefix = rows[i].wireName + "/";
      var hasChildren = false;
      for (var c = 0; c < names.length; c += 1) {
        if (names[c].length > prefix.length && names[c].slice(0, prefix.length) === prefix) {
          hasChildren = true;
          break;
        }
      }
      attributes.push(hasChildren ? "HasChildren" : "HasNoChildren");
      out.push({ name: rows[i].wireName, attributes: attributes });
    }
    return out;
  }

  /**
   * @primitive blamepost.mail.mailbox.accountFolders
   * @signature mailbox.accountFolders(actor)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6154 (special use roles), internal (design: one folder namespace, held here)
   * @related   blamepost.mail.mailbox.create, blamepost.store.open
   *
   * The folders one account owns, in the shape an application layer
   * reads them rather than the shape an IMAP LIST reply wants: the name
   * the owner sees, the store folder underneath it, the role it was
   * created with, and the highest modseq the store holds for it, which
   * is where a reader paging backwards starts.
   *
   * The browser surface and JMAP take their folder list from here.
   * `b.mail.agent.folders` is not an alternative: it is handed no
   * account and returns the store's `listFolders()` whole, so a surface
   * that renders those rows renders every account's folders and then
   * accepts a store folder name back as though the caller owned it.
   * Scoping stays in this file because this file holds the only map
   * from an account to its folders.
   *
   * @example
   *   var mine = mailbox.accountFolders({ id: accountId });
   *   mine[0].name;
   *   // "INBOX"
   */
  function accountFolders(actor) {
    var account = _accountOf(actor, "the folder list");
    _ensureAccount(account);
    var rows = b.db.from(FOLDERS).where({ account: account }).orderBy("createdAt", "asc").all();
    // The store counts modseq per folder and offers the counter only on
    // the whole table, so it is read once here and indexed by the token
    // this layer created rather than read again per folder.
    var highest = Object.create(null);
    var stored = store.listFolders();
    for (var s = 0; s < stored.length; s += 1) {
      highest[stored[s].name] = typeof stored[s].modseq_max === "number" ? stored[s].modseq_max : 0;
    }
    var out = [];
    for (var i = 0; i < rows.length; i += 1) {
      out.push({
        name:        rows[i].wireName,
        storeName:   rows[i].folder,
        role:        rows[i].role || "",
        modseqMax:   highest[rows[i].folder] || 0,
        uidvalidity: rows[i].uidvalidity,
      });
    }
    return out;
  }

  // The store keeps quota per folder and this call carries no account,
  // so there is no mailbox for it to measure: the wire name alone
  // belongs to every account that has one. The cap is checked in
  // appendMessage instead, which does receive the account, and the
  // refusal it raises carries the RFC 9208 code the listener prints.
  function quota(name) {
    return { usedBytes: 0, usedCount: 0, capBytes: null, capCount: null };
  }

  function _accountUsedBytes(account) {
    var rows = b.db.from(FOLDERS).where({ account: account }).all();
    var used = 0;
    for (var i = 0; i < rows.length; i += 1) {
      var counter = store.quota(rows[i].folder);
      used += (counter && counter.usedBytes) || 0;
    }
    return used;
  }

  function _checkQuota(account, incomingBytes) {
    if (!quotaBytesFor) return;
    var cap = quotaBytesFor(account);
    if (typeof cap !== "number" || !isFinite(cap) || cap <= 0) return;
    var used = _accountUsedBytes(account);
    if (used + incomingBytes <= cap) return;
    var refusal = err("mailbox/over-quota",
      "the mailbox holds " + used + " bytes of its " + cap + " byte limit, and this " +
      "message needs " + incomingBytes + " more.");
    refusal.overquota = true;
    refusal.limit = cap;
    throw refusal;
  }

  function _validFlags(flags, verb) {
    var list = Array.isArray(flags) ? flags : [];
    var out = [];
    for (var i = 0; i < list.length; i += 1) {
      var flag = String(list[i]);
      if (flag.toLowerCase() === "\\recent") {
        throw err("mailbox/bad-flag",
          verb + ": \\Recent is set by the server, never by a client (RFC 9051 section 2.3.2).");
      }
      var known = false;
      for (var p = 0; p < PERMANENT_FLAGS.length; p += 1) {
        if (PERMANENT_FLAGS[p].toLowerCase() === flag.toLowerCase()) {
          out.push(PERMANENT_FLAGS[p]);
          known = true;
          break;
        }
      }
      if (known) continue;
      if (flag[0] === "\\" || !KEYWORD_FLAG_RE.test(flag)) {
        throw err("mailbox/bad-flag", verb + ": '" + flag + "' is not a flag this server keeps.");
      }
      out.push(flag);
    }
    return out;
  }

  // The date an APPEND asked the message to show, or null when it named
  // none. RFC 9051 section 6.3.12 lets a client set it, so it arrives
  // from the wire and is refused at the point of parse rather than
  // stored and reasoned about later.
  //
  // What is refused is a value that is not a moment: NaN, either
  // infinity, and anything before the epoch. Each of those survives
  // every later arithmetic silently. A comparison against NaN is false
  // whichever way it is written, and a negative value reads as a message
  // older than any window an operator can set. Nothing on this server
  // measures a retention window against this field, and it is still
  // refused here, because a field this layer stores and answers
  // INTERNALDATE from has to hold a date.
  function _validInternalDate(value) {
    if (value === undefined || value === null) return null;
    if (typeof value !== "number" || !isFinite(value) || value < 0 ||
        !Number.isSafeInteger(value)) {
      throw err("mailbox/bad-internaldate",
        "APPEND: the date this message should show has to be a whole number of " +
        "milliseconds since the epoch, and '" + String(value) + "' is not one.");
    }
    return value;
  }

  // Take back the message store's row for a message this layer could not
  // finish filing.
  //
  // The store's row is written first, because the identifier it mints is
  // what this layer's row is filed under. That order leaves one state
  // worth undoing: the store holds a message this layer never recorded,
  // so no folder listing names it and no delete a client can name
  // reaches it, while its subject, its correspondents and its body text
  // stay on the volume. Erasing the account is what destroys it, which is
  // a sweep of the whole mailbox against the store rather than anything
  // that could be aimed at this one message, so taking the row back here
  // is still what keeps it from becoming a record only an erasure ends.
  //
  // The store's own destructive verb rather than the mail agent's, and
  // the reason is the retention floor. The agent measures a message's
  // age against the operator's posture and refuses anything inside the
  // window, so under any posture at all it would refuse a message that
  // arrived a moment ago and leave behind exactly the record this exists
  // to remove. Nothing is being destroyed that any reader ever had: the
  // message reached no mailbox, drew no identifier a client can name and
  // was never served, and the call that filed it is the same call
  // undoing it.
  //
  // A rollback the volume also refuses is recorded rather than raised.
  // The caller is already being told the filing failed, and replacing
  // that with the second failure would leave the record nobody knows is
  // there and cost the reason the message was refused.
  function _rollBackStoredMessage(folderRow, objectid, cause) {
    var said;
    try {
      var undone = store.hardExpunge(folderRow.folder, [objectid]);
      if ((undone.deleted || []).indexOf(objectid) !== -1) return;
      said = "the message store kept the row: " +
        JSON.stringify((undone.refused || []).map(function (entry) { return entry.reason; }));
    } catch (e) {
      said = (e && e.message) || String(e);
    }
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.filing_not_rolled_back",
      outcome:  "failure",
      actor:    auditActor.current(),
      reason:   "a message was written to the message store and could not be filed into a " +
        "mailbox, and the store would not take its row back, so the store holds a message " +
        "no mailbox names. Nothing serves it to a reader and no delete a client can name " +
        "reaches it; erasing the account it was addressed to destroys it",
      resource: { kind: "message", id: objectid },
      metadata: {
        folder: folderRow.folder,
        filing: (cause && cause.message) || String(cause),
        said:   said,
      },
    });
  }

  /**
   * @primitive blamepost.mail.mailbox.onFiled
   * @signature mailbox.onFiled(observer)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one observation point for a message reaching a mailbox)
   * @related   blamepost.mail.mailbox.create, blamepost.mail.delivery.reports
   *
   * Register an observer called after a message has been filed. Every
   * message that reaches a mailbox on this server goes through
   * `appendMessage`, so this is the single point at which something
   * outside the mailbox layer can notice one landing without a second
   * copy of the filing path being written to watch it.
   *
   * The observer is handed `{ address, folder, objectid, sizeBytes,
   * raw }` and its return value is discarded. It runs after the row is
   * committed and inside a catch that swallows whatever it throws:
   * filing is the operation an account holder and a peer are both
   * waiting on, and an observer defect must never be what costs a
   * message its delivery. An observer that needs to refuse something
   * has to do it before the message gets here, which is a different
   * layer's job.
   *
   * What it cannot tell the observer is where the message came from.
   * `appendMessage` is the same call for a message a peer delivered and
   * for one the account holder uploaded with IMAP APPEND, and nothing
   * in the arguments separates them. Anything reading this seam has to
   * treat what it sees as a message that is now in a mailbox, which is
   * all that is actually known, rather than as something that arrived
   * from outside.
   *
   * Nothing removes an observer, so registering the same function twice
   * throws rather than stacking it, and registering past the ceiling
   * throws rather than growing. Both are wiring mistakes worth finding
   * at boot.
   *
   * @example
   *   mailbox.onFiled(function (event) {
   *     if (event.address === reportingIdentity) read(event.raw);
   *   });
   */
  function onFiled(observer) {
    if (typeof observer !== "function") {
      throw new TypeError("blamepost.mail.mailbox.onFiled: observer must be a function " +
        "taking the filed message event");
    }
    if (filedObservers.indexOf(observer) !== -1) {
      throw new TypeError("blamepost.mail.mailbox.onFiled: this observer is already " +
        "registered. Registering it twice would call it twice for one message, which is a " +
        "wiring mistake rather than a second interest in the filing.");
    }
    if (filedObservers.length >= MAX_FILED_OBSERVERS) {
      throw new TypeError("blamepost.mail.mailbox.onFiled: " + MAX_FILED_OBSERVERS +
        " observers are already registered and nothing here removes one, so a caller " +
        "registering an observer per request would grow this list without a bottom. " +
        "Register once where the server is assembled.");
    }
    filedObservers.push(observer);
  }

  // Drop-silent by design: the message is already filed and the caller
  // is a wire handler waiting to answer a peer, so an observer that
  // throws must cost the delivery nothing. The failure is recorded, the
  // filing stands, and every other observer still runs.
  function _notifyFiled(event) {
    for (var i = 0; i < filedObservers.length; i += 1) {
      try { filedObservers[i](event); }
      catch (observerError) {
        try {
          b.audit.safeEmit({
            action:   "blamepost.mail.mailbox.filed_observer_failed",
            outcome:  "failure",
            metadata: { reason: (observerError && observerError.message) || String(observerError) },
          });
        } catch (_e) { /* drop-silent by design: the message is filed either way */ }
      }
    }
  }

  // APPEND, and the path inbound delivery and the composer both take.
  // The acting account rides in the options rather than first, because
  // that is the shape the listener calls with.
  function appendMessage(name, rawBytes, appendOpts) {
    var options = appendOpts || {};
    var account = _accountOf(options.actor, "APPEND");
    var row = _requireFolder(account, name);
    var raw = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(String(rawBytes || ""), "utf8");
    if (raw.length === 0) {
      throw err("mailbox/empty-message", "APPEND: a message needs at least a header block.");
    }
    var flags = _validFlags(options.flags, "APPEND");
    var internalDate = _validInternalDate(options.internalDate);
    _checkQuota(account, raw.length);

    // The octets go down first. A blob nothing references is inert
    // and the next identical message reuses it, whereas a store row
    // whose octets never landed is a message IMAP would list and then
    // fail to return. The name comes back from the write rather than
    // being computed beside it, so the row and the file cannot end up
    // disagreeing about which message this is.
    var digest = _writeBlob(raw);

    var stored = store.appendMessage(row.folder, raw, {});
    // The same allocator the filing path uses. Nothing suspends between
    // here and the insert below, so this call and the row it feeds are
    // one indivisible run, and the identifier pair the client is
    // answered with comes from the one read the allocator made rather
    // than from two reads that can disagree.
    var taken = _takeUids(row._id, 1);
    var uid = taken.first;
    var now = Date.now();
    try {
      b.db.from(MESSAGES).insertOne({
        _id:          b.uuid.v7(),
        folder:       taken.folder,
        objectid:     stored.objectid,
        uid:          uid,
        blobDigest:   digest,
        sizeBytes:    stored.sizeBytes,
        // RFC 9051 section 6.3.12 lets APPEND carry the date the message
        // should show. The store stamps its own clock and does not read
        // the option, so the value the client sent is kept here and
        // INTERNALDATE is answered from this row.
        //
        // It is what the CLIENT said, so nothing that decides whether a
        // message may be destroyed may read it. `createdAt` beside it is
        // this server's own clock at the moment the message was filed,
        // and that is what the delete path measures a retention window
        // against.
        internalDate: internalDate === null ? now : internalDate,
        createdAt:    now,
      });
    } catch (rowError) {
      _rollBackStoredMessage(row, stored.objectid, rowError);
      throw rowError;
    }

    // Flags cannot ride along with the append: the store accepts an
    // options object there and never reads it. They are set as their
    // own step, which is also what bumps the folder modseq to cover
    // them.
    if (flags.length > 0) store.setFlags(row.folder, [stored.objectid], { set: flags });

    // After the row and its flags, so an observer that reads the
    // mailbox back sees the message it was told about. The address is
    // whatever the actor carried and null when it carried none, which
    // an observer reads as an account it cannot name rather than as a
    // match against anything.
    _notifyFiled({
      address:   typeof options.actor.address === "string" ? options.actor.address : null,
      folder:    row.wireName,
      objectid:  stored.objectid,
      sizeBytes: stored.sizeBytes,
      raw:       raw,
    });

    return {
      objectid:    stored.objectid,
      uid:         uid,
      uidvalidity: taken.uidvalidity,
      modseq:      stored.modseq,
      sizeBytes:   stored.sizeBytes,
    };
  }

  // One fetch attribute rendered for one message. A section this
  // server cannot answer exactly is refused rather than approximated.
  function _renderAtt(message, att, state) {
    var upper = att.toUpperCase();
    if (upper === "UID") return "UID " + message.uid;
    if (upper === "FLAGS") return "FLAGS (" + message.flags.join(" ") + ")";
    if (upper === "INTERNALDATE") return "INTERNALDATE \"" + _internalDate(message.internalDate) + "\"";
    if (upper === "RFC822.SIZE") return "RFC822.SIZE " + message.sizeBytes;
    if (upper === "MODSEQ") return "MODSEQ (" + message.modseq + ")";
    if (upper === "ENVELOPE") {
      return "ENVELOPE " + _envelope(b.safeMime.parse(_rawOf(state, message)));
    }
    if (upper === "RFC822") return _renderAtt(message, "BODY[]", state);
    if (upper === "RFC822.HEADER") return _renderAtt(message, "BODY.PEEK[HEADER]", state);
    if (upper === "RFC822.TEXT") return _renderAtt(message, "BODY[TEXT]", state);

    var bodyMatch = att.match(/^BODY(\.PEEK)?\[([^\]]*)\](?:<(\d+)(?:\.(\d+))?>)?$/i);
    if (!bodyMatch) {
      throw err("mailbox/unsupported-fetch",
        "FETCH " + att + " is outside what this server answers exactly. It serves UID, " +
        "FLAGS, INTERNALDATE, RFC822.SIZE, MODSEQ, ENVELOPE, RFC822 and the BODY[] " +
        "sections for the whole message, its header and its text.");
    }
    if (!bodyMatch[1]) state.markSeen = true;
    var section = (bodyMatch[2] || "").trim();
    var bytes = _sectionBytes(state, message, section, att);
    var origin = null;
    // RFC 9051 section 6.4.5 gives `<start.count>` in octets of the
    // section, so the window is taken on the octets. Both numbers are
    // measured on the same thing the client named; a window read off a
    // decoded copy would land at a different place in every message
    // carrying a character wider than one octet, and would come back
    // empty for a window past the character count of a message whose
    // octets run further.
    if (bodyMatch[3] !== undefined) {
      var start = parseInt(bodyMatch[3], 10);
      var count = bodyMatch[4] === undefined ? bytes.length : parseInt(bodyMatch[4], 10);
      bytes = bytes.subarray(start, start + count);
      origin = start;
    }
    var label = "BODY[" + section + "]" + (origin === null ? "" : "<" + origin + ">");
    // No conversion at all. RFC 9051 section 4.3 makes a literal a
    // counted sequence of octets, so the count and the payload are both
    // taken from the stored bytes and the section leaves this layer as
    // the bytes. The listener writes a Buffer payload through as octets,
    // so what it announces is what reaches the socket.
    //
    // Announcing a count measured on a decoded copy would be
    // self-consistent and still wrong: the response would agree with
    // itself while every octet the decode replaced was gone from the
    // message the account holder got back.
    return Buffer.concat([
      Buffer.from(label + " {" + bytes.length + "}\r\n", "utf8"),
      bytes,
    ]);
  }

  // The attributes of one message joined into a single FETCH payload.
  //
  // A row that carries message content leaves as octets, because a
  // string cannot hold one: an octet that is not valid UTF-8 does not
  // survive being encoded on the way to the socket, and the literal
  // count then stops matching the number of octets written, which is
  // what a client uses to find where the response ends. A row that
  // carries only attributes stays a string, which is what the listener
  // expects for `FLAGS (\Seen)` and what keeps a non-ASCII ENVELOPE
  // field encoded the way RFC 9051 section 5.1 asks for.
  function _joinAtts(parts) {
    var carriesOctets = false;
    for (var i = 0; i < parts.length; i += 1) {
      if (Buffer.isBuffer(parts[i])) { carriesOctets = true; break; }
    }
    if (!carriesOctets) return parts.join(" ");
    var pieces = [];
    for (var j = 0; j < parts.length; j += 1) {
      if (j > 0) pieces.push(SP_BYTE);
      pieces.push(Buffer.isBuffer(parts[j]) ? parts[j] : Buffer.from(parts[j], "utf8"));
    }
    return Buffer.concat(pieces);
  }

  function _rawOf(state, message) {
    if (!state.raw[message.objectid]) state.raw[message.objectid] = _readBlob(message.digest);
    return state.raw[message.objectid];
  }

  // One BODY[] section as the octets the message holds for it.
  function _sectionBytes(state, message, section, att) {
    var raw = _rawOf(state, message);
    var split = _splitMessage(raw);
    // The whole message is the message, not its halves put back
    // together: rejoining them would depend on the split having been
    // exact, and there is nothing to gain by finding out.
    if (section.length === 0) return raw;
    var upper = section.toUpperCase();
    if (upper === "HEADER") return split.header;
    if (upper === "TEXT") return split.body;
    var fieldsMatch = section.match(/^HEADER\.FIELDS(\.NOT)?\s*\(([^)]*)\)$/i);
    if (fieldsMatch) {
      var names = fieldsMatch[2].split(/[\s,]+/).filter(Boolean);
      if (names.length === 0) {
        throw err("mailbox/unsupported-fetch", "FETCH " + att + " names no header fields.");
      }
      return _selectHeaderFields(split.header, names, Boolean(fieldsMatch[1]));
    }
    throw err("mailbox/unsupported-fetch",
      "FETCH " + att + " asks for a MIME part by number. This server returns whole " +
      "sections, so a client wanting one part fetches BODY[] and splits it.");
  }

  function fetchRange(actor, mailbox, seqSet, partsSpec, fetchOpts) {
    var account = _accountOf(actor, "FETCH");
    var row = _requireFolder(account, mailbox);
    var options = fetchOpts || {};
    var messages = _snapshot(row, true);
    var picked = _selected(messages, seqSet, options.useUid === true);
    if (typeof options.changedSince === "number") {
      picked = picked.filter(function (m) { return m.modseq > options.changedSince; });
    }

    var atts = _splitAtts(partsSpec);
    var expanded = [];
    for (var a = 0; a < atts.length; a += 1) {
      var macroName = atts[a].toUpperCase();
      if (Object.prototype.hasOwnProperty.call(FETCH_MACROS, macroName)) {
        expanded = expanded.concat(FETCH_MACROS[macroName]);
        continue;
      }
      if (macroName === "FULL") {
        throw err("mailbox/unsupported-fetch",
          "FETCH FULL asks for the body structure, which this server does not describe. " +
          "A client that fetches ENVELOPE and BODY[] gets the same message.");
      }
      expanded.push(atts[a]);
    }
    if (expanded.length === 0) {
      throw err("mailbox/bad-fetch", "FETCH needs at least one attribute.");
    }
    // A UID FETCH always carries UID back, whether or not the client
    // asked for it (RFC 9051 section 6.4.9).
    if (options.useUid === true && expanded.indexOf("UID") === -1) expanded.unshift("UID");

    var state = { raw: {}, markSeen: false };
    var out = [];
    var seen = [];
    for (var i = 0; i < picked.length; i += 1) {
      var parts = [];
      for (var p = 0; p < expanded.length; p += 1) {
        parts.push(_renderAtt(picked[i], expanded[p], state));
      }
      out.push({ seq: picked[i].seq, payload: _joinAtts(parts), modseq: picked[i].modseq });
      if (state.markSeen && picked[i].flags.indexOf("\\Seen") === -1) seen.push(picked[i].objectid);
    }
    // A non peeking BODY[] is a read, and RFC 9051 section 6.4.5 says
    // the server records it.
    if (seen.length > 0) store.setFlags(row.folder, seen, { set: ["\\Seen"] });
    return out;
  }

  /**
   * @primitive blamepost.mail.mailbox.searchScan
   * @signature mailbox.searchScan(actor, mailbox)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9051 §6.4.4 (the fields a SEARCH key is evaluated against), RFC 8474 §1.5.1 (objectid)
   * @related   blamepost.mail.mailbox.create, blamepost.mail.listeners.compileSearch
   *
   * Every message in one of the acting account's folders, in the UID
   * order IMAP counts in, with the values a search key is decided on
   * attached to each: the flags, the internal date, the octet count,
   * and the header and body text the store keeps unsealed.
   *
   * `createdAt` rides beside `internalDate` and is not a search key.
   * INTERNALDATE is the date the message shows, and RFC 9051 section
   * 6.3.12 lets an APPEND set it, so it is a value the client chose;
   * BEFORE, ON and SINCE are evaluated against it because the
   * specification says they are. `createdAt` is the clock reading this
   * server took when it filed the message, which is what the delete path
   * measures a retention window against and the only one of the two an
   * operator can answer a preservation order or an erasure request with.
   * A caller showing a date to an operator wants the second; a caller
   * answering a client wants the first.
   *
   * This is a read verb rather than a query verb, and the difference is
   * the whole reason it exists. The store carries a full text index and
   * it cannot answer an IMAP search: the index holds keyed hashes of
   * whole tokens, so it matches a complete word and nothing else, while
   * RFC 9051 section 6.4.4 makes every string key a SUBSTRING match.
   * `SUBJECT "round"` against a subject reading "Roundtrip" is a match
   * the specification requires and the index cannot produce. The index
   * also folds the From and To addresses into one column, so it cannot
   * tell a sender from a recipient; it drops stopwords and anything
   * outside two to sixty-four codepoints; and it caps a result set.
   * Each of those differences is a message the client never sees, under
   * a tagged OK it has no way to question. So the caller gets the rows
   * and decides, and the index stays where its semantics are the ones
   * its own callers asked for.
   *
   * The membership list is this layer's folder rows intersected with
   * the store's, which is the same list SELECT counted and FETCH
   * numbers against, so a sequence number means the same thing in a
   * search result as it does everywhere else in the session. The octet
   * count and the internal date come from that list for the same
   * reason: LARGER, SMALLER, BEFORE, ON and SINCE then agree with what
   * FETCH reports for the same message rather than with a second
   * measurement of it.
   *
   * There is no cap and no cursor. A search is a question about the
   * whole mailbox, and a scan that stopped early would answer it with a
   * result set that is short by an amount nothing reports.
   *
   * Nothing here decodes message octets. Every field below is text the
   * store already holds as text, so the bytes on disk are never round
   * tripped through a decode that would substitute a replacement
   * character into somebody's mail and count it as three octets where
   * there was one.
   *
   * A message in the folder that cannot be read is a refusal rather
   * than a message left out. Leaving it out would report a result set
   * that is missing a row for a reason nothing carries, and a client
   * reading a short result concludes the mail is not there.
   *
   * ## Why there is no body here
   *
   * The store keeps a body text and a body HTML beside the fields
   * below, and they are deliberately not carried, because they are not
   * the body of the message and a search key wired to them would answer
   * wrongly. `b.safeMime.extractText` returns ONE part: the first
   * `text/plain` leaf, and separately the first `text/html` leaf. A
   * `multipart/mixed` message carrying two text parts, which is what an
   * ordinary message with a text attachment or a `text/calendar` invite
   * beside its body is, keeps only the first of them. Its parser also
   * descends into `multipart/*` and nowhere else, so the text inside a
   * forwarded `message/rfc822` part is opaque bytes. RFC 9051 section
   * 6.4.4 lets a server exclude body parts whose media type is neither
   * TEXT nor MESSAGE from a search and does not let it exclude those,
   * so matching on the stored pair would report a message as not
   * matching when the specification says it does.
   *
   * Surfacing them anyway would leave the next reader a field named
   * body next to a key called BODY, which is the whole of what it takes
   * for the wrong answer to get written. So the field is absent and the
   * key refuses, and reopening it means a body extraction that returns
   * every text and message part rather than the first of two.
   *
   * @example
   *   var rows = mailbox.searchScan(actor, "INBOX");
   *   rows[0].subject;
   *   // "Roundtrip probe"
   */
  function searchScan(actor, mailbox) {
    var account = _accountOf(actor, "SEARCH");
    var row = _requireFolder(account, mailbox);
    var messages = _snapshotStored(row);
    var out = [];
    for (var i = 0; i < messages.length; i += 1) {
      // One read per message, taken by the membership list itself. Every
      // field below comes off that one read, so the flags, the subject
      // and the addresses are one answer about one message rather than
      // two answers taken a moment apart.
      var stored = messages[i].stored;
      if (!stored) {
        throw err("mailbox/search-unreadable",
          "the mailbox holds a message this search cannot read (" + messages[i].objectid +
          "), so the result set would be short by a row and nothing would say so.");
      }
      out.push({
        seq:          messages[i].seq,
        uid:          messages[i].uid,
        objectid:     messages[i].objectid,
        flags:        stored.flags || [],
        internalDate: messages[i].internalDate,
        createdAt:    messages[i].createdAt,
        sizeBytes:    messages[i].sizeBytes,
        subject:      stored.subject   || "",
        from:         stored.from      || "",
        to:           stored.to        || "",
        messageId:    stored.messageId || "",
        inReplyTo:    stored.inReplyTo || "",
        // The stored spelling, which is the message ids of the
        // References header re-joined with commas rather than the text
        // the sender wrote. A caller matching on the header itself has
        // to know that, which is why it is named for what it holds.
        references:   stored.referencesCsv || "",
      });
    }
    return out;
  }

  function storeFlags(actor, mailbox, seqSet, mode, flags, storeOpts) {
    var account = _accountOf(actor, "STORE");
    var row = _requireFolder(account, mailbox);
    var options = storeOpts || {};
    var wanted = _validFlags(flags, "STORE");
    var messages = _snapshot(row, true);
    var picked = _selected(messages, seqSet, options.useUid === true);

    var refused = [];
    if (typeof options.unchangedSince === "number") {
      var allowed = [];
      for (var u = 0; u < picked.length; u += 1) {
        if (picked[u].modseq > options.unchangedSince) {
          refused.push(options.useUid === true ? picked[u].uid : picked[u].seq);
          continue;
        }
        allowed.push(picked[u]);
      }
      picked = allowed;
    }

    for (var i = 0; i < picked.length; i += 1) {
      var change;
      if (mode === "add") change = { set: wanted };
      else if (mode === "remove") change = { unset: wanted };
      else {
        var drop = picked[i].flags.filter(function (f) { return wanted.indexOf(f) === -1; });
        change = { set: wanted, unset: drop };
      }
      var result = store.setFlags(row.folder, [picked[i].objectid], change);
      picked[i].modseq = (result && result.modseq) || picked[i].modseq;
      if (mode === "add") {
        for (var w = 0; w < wanted.length; w += 1) {
          if (picked[i].flags.indexOf(wanted[w]) === -1) picked[i].flags.push(wanted[w]);
        }
      } else if (mode === "remove") {
        picked[i].flags = picked[i].flags.filter(function (f) { return wanted.indexOf(f) === -1; });
      } else {
        picked[i].flags = wanted.slice();
      }
    }

    var rows = [];
    for (var r = 0; r < picked.length; r += 1) {
      rows.push({ seq: picked[r].seq, flags: picked[r].flags, modseq: picked[r].modseq });
    }
    return { rows: rows, modified: _formatSeqSet(refused) };
  }

  // ---- the one hard delete -------------------------------------------------

  // How a refusal on this path classifies, in one word, for a caller
  // that has to decide what to DO about it rather than only print it.
  //
  //   `preserved`: something is deliberately keeping the message. It is
  //     whole, nothing was destroyed, and a rerun reaches it once the
  //     order is released or the window elapses.
  //   `absent`: no row on either layer answers to that identifier.
  //     There was nothing to destroy.
  //   `incomplete`: the message was destroyed and one of the two acts
  //     that remove it from this layer did not happen, so its octets are
  //     still stored here. Which act stayed decides the remedy, and the
  //     two are not the same. A ROW that stayed keeps the record
  //     addressable, so a rerun of this verb reaches it and finishing it
  //     is the remediation. A BODY that stayed after the row had already
  //     gone leaves octets nothing on either layer names, so no rerun of
  //     this verb can find them and `blobs reclaim` is what frees them.
  //     `octets` on the entry says which state it is in.
  //
  // The three carry opposite responses, and the vocabulary is the same
  // one the queue removal and the account erasure use for the same
  // three situations, so an operator reading two reports is reading one
  // word rather than two spellings of it.
  function _refusalOutcome(reason) {
    if (_isPreservation(reason)) return "preserved";
    if (reason === "not-in-folder") return "absent";
    return "incomplete";
  }

  // The role gate in front of the hard delete. It checks the agent's own
  // table on the agent's own scope, so a delete this layer finishes for
  // a row the agent cannot see is refused for the same actor the agent
  // would have refused it for.
  //
  // The agent checks this itself on every set it is handed, and that is
  // not enough on its own: a set made entirely of rows whose message
  // store partner is gone never reaches the agent, so the check has to
  // sit where the path begins rather than where one branch of it ends.
  function _requireExpungeScope(actor, verb) {
    if (roleGate.check(actor, EXPUNGE_SCOPE)) return;
    // `userId` rather than `id`: the chain writer reads `actor.userId`
    // and null-fills anything else, so a row built from the actor's own
    // field name records a refusal that names nobody.
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.expunge_denied",
      outcome:  "denied",
      actor:    { userId: (actor && actor.id) || null },
      resource: { kind: "account", id: (actor && actor.id) || null },
      reason:   "role does not carry " + EXPUNGE_SCOPE,
      metadata: { verb: verb, scope: EXPUNGE_SCOPE },
    });
    // The agent's own code and the agent's own sentence rather than a
    // second pair. It is one refusal over one scope on one table, and
    // which half of the path noticed it is not something a caller
    // mapping the refusal to a wire response should have to know: a set
    // the agent can see and a set it cannot are refused for the same
    // actor and answered in the same words on the same wire.
    throw err("mail-agent/permission-denied",
      verb + ": actor lacks scope '" + EXPUNGE_SCOPE + "', so this account may not " +
      "destroy messages.");
  }

  // The classification stamped onto every refusal on the way out, in one
  // place, so no caller keeps its own copy of the mapping to drift from
  // it and no reason word can reach a caller unclassified.
  function _classified(entries) {
    for (var i = 0; i < entries.length; i += 1) {
      entries[i].outcome = _refusalOutcome(entries[i].reason);
    }
    return entries;
  }

  // The regulated minimum this volume holds mail for, or zero when the
  // operator set no posture. Read through the framework's own verb
  // rather than a table, so a posture the framework does not know
  // refuses here instead of quietly becoming an unbounded delete.
  //
  // This is a SECOND reading of the same floor the mail agent applies,
  // and it exists because of the one row the agent can no longer see.
  // The agent decides from the message store's row; a destruction that
  // took the store row and could not take this layer's leaves a row the
  // agent has no view of at all, so a floor enforced only there would
  // stop governing the record exactly when the record became the
  // problem. Reading it here keeps the floor on the layer that still
  // holds the row.
  function _retentionFloorMs(label) {
    if (typeof posture !== "string" || posture.length === 0) return 0;
    try {
      return b.retention.complianceFloor(posture);
    } catch (e) {
      throw err("mailbox/unknown-posture",
        label + ": the compliance posture '" + posture + "' is not one the framework knows, " +
        "so no retention floor can be established and this delete is refused rather than " +
        "run unbounded: " + ((e && e.message) || String(e)));
    }
  }

  // The two acts that remove a message from THIS layer, in the order
  // that keeps them safe. Answers `{ stayed, destroyed }`: what the
  // volume would not take, and whether the message itself is gone.
  //
  // The order is load-bearing and stays. The row is what pins the body
  // against the reference-counted release, so releasing first would free
  // octets a row still names; stopping at a refused row leaves the two
  // paired instead of leaving octets nothing accounts for.
  //
  // One reader for both callers. The delete the agent has just
  // authorized and the delete that finishes one the volume half refused
  // are the same two acts on the same two records, and two copies of
  // this would be two chances for a later change to reach one order and
  // not the other. What differs is `alreadyStranded`, and it is a
  // difference in the STATE the call found rather than in how many times
  // the operator has run it.
  //
  // A row that refuses on the run that destroyed its store partner
  // stops the removal there. The two records were paired a moment ago,
  // the refusal is the volume speaking now, and the operator is told to
  // go and look at it. The octets stay because the row still names them
  // and a rerun reaches both.
  //
  // A row that was ALREADY stranded when this call started is a
  // different record. Its pairing was broken on an earlier run, no
  // reader resolves it, and the volume has now refused to remove it a
  // second time, which is what a write-once table does on purpose
  // rather than what a fault does once. A write-once MESSAGES table
  // preserves the row, and the row carries no message content: the
  // folder, the identifier, the UID, the digest, the size and the dates.
  // The mail itself is the sealed file the digest names, and what
  // governs whether that may be destroyed is the retention floor and
  // the preservation order, both of which are read before either act
  // runs. So the record is kept, the mail is destroyed, and the caller
  // is told both. Leaving the octets instead answers an erasure request
  // with a file that opens exactly as it did before, in every backup
  // taken afterwards, with no verb anywhere that removes it.
  function _destroyLayerRow(folderRow, objectid, digest, alreadyStranded) {
    try {
      b.db.from(MESSAGES).where({ folder: folderRow.folder, objectid: objectid }).deleteOne();
    } catch (rowError) {
      if (alreadyStranded !== true) {
        return {
          stayed: {
            reason: "row-not-removed",
            octets: "here",
            detail: "the message left the mailbox and the volume would not remove the row " +
              "binding it to one, so it is still stored here.",
            said:   (rowError && rowError.message) || String(rowError),
          },
          destroyed: false,
        };
      }
      var kept = _releaseBlobBesides(digest, folderRow, objectid);
      if (kept !== null) {
        return {
          stayed: {
            reason: "body-not-removed",
            octets: "here",
            detail: "the message left the mailbox, the volume would not remove the row " +
              "binding it to one, and it would not remove the stored body either, so the " +
              "octets are still here.",
            said:   kept.detail,
          },
          destroyed: false,
        };
      }
      return {
        stayed: {
          reason: "row-not-removed",
          octets: "gone",
          detail: "the stored message was destroyed and the volume would not remove the row " +
            "binding it to a mailbox, so a record of the message stays here without it. " +
            "That row holds no message content; the octets it named are gone.",
          said:   (rowError && rowError.message) || String(rowError),
        },
        destroyed: true,
      };
    }
    var held = _releaseBlob(digest);
    if (held !== null) {
      return {
        stayed: {
          reason: "body-not-removed",
          octets: "here",
          detail: "the message left the mailbox and the volume would not remove its " +
            "stored body, so the octets are still here.",
          said:   held.detail,
        },
        destroyed: false,
      };
    }
    return { stayed: null, destroyed: true };
  }

  // This layer's row for a message the message store no longer has.
  //
  // Membership served to a client is this layer's rows intersected with
  // the store's, which is right for every read: a row on either side
  // without its partner is not a message anybody can be shown. It is
  // wrong for the delete path, and only there. The agent destroys the
  // store row before this layer removes its own, so a volume that
  // refuses this layer's removal leaves a row on the OUTSIDE of that
  // intersection, holding a sealed body against the reference counted
  // release, and every verb that resolves through the intersection then
  // answers about it with the reason reserved for an identifier that
  // names nothing. The refusal told the operator to fix the volume and
  // run the verb again; without this the rerun could not reach it, and
  // no repair to the volume would ever change that.
  function _strandedRow(folderRow, objectid) {
    if (store.fetchByObjectId(folderRow.folder, objectid)) return null;
    return b.db.from(MESSAGES)
      .where({ folder: folderRow.folder, objectid: objectid }).first() || null;
  }

  // The message store's row for a message this layer never filed, which
  // is the other side of the same disagreement.
  //
  // Filing writes three records in order: the sealed octets, the store's
  // row, then this layer's row. A process that stops between the second
  // and the third leaves the store holding a message no mailbox row
  // names, and so does a rollback the store refuses, which is what
  // `blamepost.mail.mailbox.filing_not_rolled_back` records. The two
  // routes end in the identical state.
  //
  // Every read a client is served resolves through the intersection, so
  // nothing shows that message to anybody. What the store still holds is
  // the message itself: its subject, its correspondents and its body,
  // sealed in the store's own row and opening exactly as they did
  // before. So the record is invisible and the mail is not, and until
  // this question is asked no verb on this server reaches it: an account
  // erasure walks past it and destroys the identity that would have
  // named it.
  //
  // The local read comes FIRST and decides whether the sealed read is
  // taken at all. A row this layer holds is not unfiled whatever the
  // store says, and answering that from the plaintext column costs a
  // read where the store's answer costs an unseal.
  function _unfiledRow(folderRow, objectid) {
    if (b.db.from(MESSAGES).where({ folder: folderRow.folder, objectid: objectid }).first()) {
      return null;
    }
    return store.fetchByObjectId(folderRow.folder, objectid);
  }

  // Every message the store holds for one folder that this layer has no
  // row for, by identifier.
  //
  // Read from the store's plaintext columns under the same bound-raising
  // loop membership uses, so discovering them costs one query rather
  // than an unseal per message. `_unfiledRow` answers the same question
  // for ONE identifier a caller already has; this answers it for a
  // mailbox nobody has an identifier for, which is the only way an
  // erasure can find them at all.
  // A mailbox the store has no folder for holds no stored message, so
  // the answer is none rather than the store's own sentence about its
  // folder table. Membership settles the same case by not asking at
  // all: it returns early for a folder this layer holds no rows for, so
  // a mailbox whose store folder has gone answers as empty rather than
  // raising at a client that asked for a message count. This has to ask
  // even then, because a folder with no rows here is exactly where an
  // unfiled message hides, so the case is answered rather than avoided.
  // Only that one refusal is read this way; anything else the store says
  // is a volume the caller has to hear about.
  function _unfiledObjectIds(folderRow) {
    var filed = b.db.from(MESSAGES).where({ folder: folderRow.folder }).all();
    var named = Object.create(null);
    for (var f = 0; f < filed.length; f += 1) named[filed[f].objectid] = true;
    var held;
    try {
      held = _storedRows(folderRow.folder, filed.length + 1);
    } catch (e) {
      if (e && e.code === "mail-store/no-folder") return [];
      throw e;
    }
    var out = [];
    for (var s = 0; s < held.length; s += 1) {
      if (named[held[s].objectid] !== true) out.push(held[s].objectid);
    }
    return out;
  }

  // Finish a destruction the agent already authorized and the volume
  // half refused, for the rows that survived it.
  //
  // It runs BEHIND the agent rather than in front of it. This is a
  // destruction, so the gates the agent applies to every other one have
  // to have run first: the actor is validated and its scope checked at
  // the head of the delete path, and the agent has already answered for
  // every identifier it can see by the time anything here removes a row.
  // Running first would have put the destructive half of the path ahead
  // of the checks that decide whether it may happen at all.
  //
  // The agent cannot answer about these: it decides from the message
  // store's row and that row is gone. So the two gates it applies are
  // applied here instead, from what this layer can still see, and both
  // are read fresh rather than assumed to have been settled by the run
  // that stranded the row.
  //
  // The store is asked about every row again, at the moment of the
  // removal, and what the answer decides is which layer this message
  // belongs to. A row the store can still answer for is not stranded any
  // more, so it is handed back rather than destroyed here, and the agent
  // decides it from the copy the agent reads: the per message
  // preservation flag on the store's own row, checked there and checked
  // again by the destructive call underneath it. Nothing on this path
  // may destroy a message that layer can still see.
  //
  // Only once the store has no row left to answer with does the registry
  // decide, and then it decides alone, because it is the only record
  // left and it is the record a regulator asks to see. A preservation
  // order CAN reach a stranded row: the hold verbs ask the same second
  // question of an identifier the intersection does not answer, so an
  // order placed on one is registered even though the flag it would also
  // set has no row to land on.
  //
  // The retention floor is recomputed from the row's own arrival time,
  // which is the clock this server stamped when the message was filed
  // and not the date an APPEND asked the message to show. RFC 9051
  // section 6.3.12 lets a client set the second one, so a floor measured
  // against it would be a floor the client picks. A row that cannot say
  // when it arrived is kept rather than destroyed: the arithmetic reads
  // an absent arrival as the epoch, which clears every window an
  // operator can set, so the one direction a missing value must not fail
  // in is the one it would fail in on its own.
  //
  // A window only ever elapses, so a message that cleared the floor on
  // the run that stranded it still clears it now; what this catches is
  // an operator who has since moved to a stricter posture, which is the
  // one direction the earlier decision cannot answer for.
  async function _completeStranded(folderRow, strandedRows, floorMs, nowMs) {
    var out = { deleted: [], refused: [], regained: [] };
    for (var i = 0; i < strandedRows.length; i += 1) {
      var kept = strandedRows[i];
      var objectid = kept.objectid;

      var live = store.fetchByObjectId(folderRow.folder, objectid);
      if (live !== null) {
        out.regained.push(objectid);
        continue;
      }

      var order = holds.get(_holdSubject(objectid));
      if (order && order.lapsed !== true) {
        _recordStrandedVerdict(folderRow, objectid, "legal-hold");
        out.refused.push({ id: objectid, reason: "legal-hold" });
        continue;
      }
      var arrivedAt = typeof kept.createdAt === "number" && isFinite(kept.createdAt) &&
        kept.createdAt >= 0 ? kept.createdAt : null;
      if (floorMs > 0 && (arrivedAt === null || (nowMs - arrivedAt) < floorMs)) {
        _recordStrandedVerdict(folderRow, objectid, "retention-floor");
        out.refused.push({ id: objectid, reason: "retention-floor" });
        continue;
      }

      var act = _destroyLayerRow(folderRow, objectid, kept.blobDigest, true);
      if (act.stayed !== null) {
        _recordDestructionIncomplete(objectid, kept.blobDigest, act.stayed.reason, act.stayed.said);
        out.refused.push({
          id:     objectid,
          reason: act.stayed.reason,
          // Whether the message itself is still on this volume. The
          // reason names which act the volume refused, and on a row it
          // will not remove that is no longer the same question: the
          // record can stay while the mail it named is destroyed. A
          // caller telling an operator whether mail they were asked to
          // lose is still here reads THIS rather than inferring it from
          // the reason, because the inference was right once and stopped
          // being right without the word changing.
          octets: act.stayed.octets,
          detail: act.stayed.detail,
        });
      }
      // Both lists can carry one identifier, and on this path that is
      // the answer rather than a contradiction: the message is destroyed
      // and a record of it stayed. A caller counting what it erased and
      // a caller naming what it could not remove are asking two
      // questions, and this is the state where the two have different
      // answers about the same message.
      if (act.destroyed === true) {
        _recordStrandedVerdict(folderRow, objectid, "destroyed");
        out.deleted.push(objectid);
      }
    }
    return out;
  }

  // What this path decided about one message the mail agent could not
  // see, filed one row per message.
  //
  // The agent writes the trail for every hard delete it runs, and it
  // never runs on these: it decides from the message store's row and
  // that row is gone. Without this, a delete naming only such rows
  // destroys mail and writes nothing anywhere. Not the agent's row,
  // because the agent was never reached, and not this layer's, because
  // the row it files is for a removal the volume REFUSED. Between them
  // sat the one destruction on this server that left no trail at all.
  //
  // Per message rather than per call, because this is the path with no
  // other record: a count answers how many went and cannot answer
  // whether a named message did, which is the question an erasure
  // request and a preservation order are both settled by. Their number
  // is bounded by an abnormal condition rather than by traffic, because
  // a row only reaches here when a volume refused a removal it had
  // already begun.
  //
  // Drop-silent by design, through the framework's synchronous emit. On
  // the destroyed verdict the message is already gone by the time this
  // runs, so a sink that cannot write must not report a destruction that
  // happened as one that did not.
  function _recordStrandedVerdict(folderRow, objectid, verdict) {
    var where = { kind: "message", id: objectid };
    var about = { folder: folderRow.folder, mailbox: folderRow.wireName, verdict: verdict };
    if (verdict === "destroyed") {
      b.audit.safeEmit({
        action:   "blamepost.mail.mailbox.stranded_destroyed",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   "a destruction the volume had already half taken was finished on the " +
          "layer that could still see the row, which is the one delete path the mail agent " +
          "never runs",
        resource: where,
        metadata: about,
      });
      return;
    }
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.stranded_preserved",
      outcome:  "denied",
      actor:    auditActor.current(),
      reason:   "a destruction the volume had already half taken was refused on the layer " +
        "that could still see the row",
      resource: where,
      metadata: about,
    });
  }

  // Every hard delete on every wire ends here. `b.mail.agent.expunge`
  // decides what may go, because it is the layer holding the legal hold
  // flag and the retention floor, and it answers per message with the
  // reason for each one it kept.
  //
  // What the agent does NOT own is the pair of things this layer keeps
  // beside the store row: the row carrying the IMAP UID, and the sealed
  // original octets under `blobs/` that IMAP BODY[] and POP3 RETR both
  // return. A caller that drives the agent directly destroys the store
  // row and leaves those two behind, so the message is reported
  // destroyed and its body is still on disk and still readable. That is
  // why this is a verb rather than four call sites.
  //
  // `known` is the intersection with the folder the acting account owns,
  // so an object id belonging to somebody else is refused by name rather
  // than passed down to a store that has no account column to check it
  // against.
  async function _expungeResolved(actor, row, requested, snapshot) {
    // The two gates the mail agent puts in front of every verb it
    // routes, applied at the head of the whole path rather than only on
    // the half that reaches the agent. A set made entirely of rows the
    // agent can no longer see never reaches it, so without this the one
    // destructive path on this server that the agent does not run would
    // also be the one with no actor validated and no scope checked. The
    // table is the agent's own, read back from the agent, so this
    // decides what the agent would have decided.
    b.guardMailQuery.validateActor(actor, posture);
    _requireExpungeScope(actor, "the message delete");

    // A caller that has already read the folder passes its own view, so
    // one operation works from one membership list rather than two that
    // can disagree with each other.
    var messages = snapshot || _snapshot(row, false);
    // A message identifier arrives from a client, so the map it is
    // looked up in carries no prototype for a name like `constructor` to
    // resolve against.
    var byObject = Object.create(null);
    for (var m = 0; m < messages.length; m += 1) byObject[messages[m].objectid] = messages[m];

    // The floor is settled in front of everything, so a posture the
    // framework cannot resolve refuses the call rather than letting the
    // stranded path below run with no floor at all. The agent refuses
    // the same way for the same reason, and a set made entirely of
    // stranded rows never reaches the agent.
    var floorMs = _retentionFloorMs("the message delete");
    var nowMs = Date.now();

    var known = [];
    // Rows this layer holds whose partner in the message store is gone.
    // Reaching them is the whole reason this loop asks a second question
    // of an identifier the snapshot did not list: the first answer,
    // `not-in-folder`, is right for an identifier that names nothing and
    // wrong for the one record on this path a refusal can leave behind.
    var stranded = [];
    var strandedSeen = Object.create(null);
    // The mirror of those: a message the store holds that this layer
    // never filed. It goes to the AGENT rather than being finished here,
    // because the record the agent decides from is the one record such a
    // message still has: the per message preservation flag, and the
    // arrival stamp the retention floor is measured against. The
    // stranded path exists only because that record is gone; here it is
    // present, so reaching past the agent would destroy mail a court
    // ordered kept and write no audit row saying so.
    var unfiledSeen = Object.create(null);
    var refused = [];
    for (var r = 0; r < requested.length; r += 1) {
      if (Object.prototype.hasOwnProperty.call(byObject, requested[r])) {
        if (known.indexOf(requested[r]) === -1) known.push(requested[r]);
        continue;
      }
      if (strandedSeen[requested[r]] === true || unfiledSeen[requested[r]] === true) continue;
      if (_unfiledRow(row, requested[r]) !== null) {
        unfiledSeen[requested[r]] = true;
        known.push(requested[r]);
        // No sequence number, because it was never in a membership list
        // any session numbered against, and no digest, because the
        // octets this layer keeps are named by a row that was never
        // written. What is on disk under `blobs/` for such a message is
        // a body no row names, which `blamepost blobs report --verify`
        // lists and `blamepost blobs reclaim` frees.
        byObject[requested[r]] = { seq: null, digest: null, unfiled: true };
        continue;
      }
      var orphanRow = _strandedRow(row, requested[r]);
      if (orphanRow !== null) {
        strandedSeen[requested[r]] = true;
        stranded.push(orphanRow);
        continue;
      }
      refused.push({ id: requested[r], reason: "not-in-folder" });
    }

    // The agent FIRST, and the rows it cannot see afterwards. Both
    // halves destroy mail, and the half the agent runs is the half whose
    // gates are the agent's own, so a set that mixes the two has the
    // agent's answer in hand before anything the agent cannot answer for
    // is touched.
    var verdict = known.length > 0
      ? await mailAgent.expunge({ actor: actor, folder: row.folder, objectIds: known })
      : { deleted: [], refused: [] };
    var removed = (verdict && verdict.deleted) || [];
    // Anything the agent answered about is the agent's verdict, except
    // for one: an identifier this layer's snapshot listed and the store
    // no longer has is a row stranded between the snapshot and this
    // call, which is the same state the loop above reaches and takes the
    // same remedy. Passing the agent's `not-in-folder` straight through
    // would report a record this layer is still holding as one nothing
    // answers to.
    var agentRefused = (verdict && verdict.refused) || [];
    var lateStranded = [];
    for (var a = 0; a < agentRefused.length; a += 1) {
      if (agentRefused[a].reason === "not-in-folder") {
        var lateRow = _strandedRow(row, agentRefused[a].id);
        if (lateRow !== null) { lateStranded.push(lateRow); continue; }
      }
      refused.push(agentRefused[a]);
    }

    var pending = stranded.concat(lateStranded);
    var finished = pending.length > 0
      ? await _completeStranded(row, pending, floorMs, nowMs)
      : { deleted: [], refused: [], regained: [] };

    // A row the message store answered for after all is not stranded and
    // is not this path's to destroy, so it goes to the agent instead of
    // being finished here. One pass: a row the store has lost again by
    // the time the agent looks is reported the way the agent reports it,
    // and the rerun an operator is already told to run reaches it.
    //
    // It carries no sequence number, because it was never in the
    // membership list this session was numbering against, and an
    // untagged EXPUNGE for a message a client never saw renumbers that
    // client's mailbox around nothing.
    if (finished.regained.length > 0) {
      for (var g = 0; g < pending.length; g += 1) {
        if (finished.regained.indexOf(pending[g].objectid) === -1) continue;
        byObject[pending[g].objectid] = { seq: null, digest: pending[g].blobDigest };
      }
      var regainedVerdict = await mailAgent.expunge({
        actor:     actor,
        folder:    row.folder,
        objectIds: finished.regained,
      });
      removed = removed.concat((regainedVerdict && regainedVerdict.deleted) || []);
      refused = refused.concat((regainedVerdict && regainedVerdict.refused) || []);
    }
    refused = refused.concat(finished.refused);

    var expunged = [];
    var deleted = [];
    for (var d = 0; d < removed.length; d += 1) {
      var gone = byObject[removed[d]];
      if (!gone) continue;
      // A message no mailbox row named is finished the moment the agent
      // takes the store's row: there is no row here to remove and no
      // digest here to release, so the two acts below have nothing to
      // act on and running them would ask the volume to delete a row
      // that was never written and unlink a path built from a null
      // digest. It carries no sequence number either, so no client is
      // told to renumber around a message it was never shown.
      if (gone.unfiled === true) {
        deleted.push(removed[d]);
        continue;
      }
      // The message has LEFT THE MAILBOX by this point whatever the
      // volume answers below: the agent destroyed its store row, and
      // membership here is this layer's rows intersected with the
      // store's, so no verb on any protocol reaches it again. Its
      // sequence number is therefore drawn either way, because a client
      // that is not told to renumber around a message that is no longer
      // there addresses the wrong one on its next command.
      if (gone.seq !== null) expunged.push(gone.seq);

      // Whether it was DESTROYED is a second question, and the two acts
      // below are what it turns on. Each can be refused on its own: a
      // records-retention posture puts write-once triggers on the table
      // and a DELETE is refused below the application entirely, and a
      // removal is refused by a mount that has gone read-only, a
      // permission an operator changed or another process holding the
      // file open.
      //
      // Both are answered per message rather than once for the set. The
      // octets are the message, which IMAP BODY[] and POP3 RETR both
      // return, and they are sealed under the volume's key rather than
      // under anything a row erasure reaches, so a body left behind
      // opens exactly as it did before, here and in every backup taken
      // afterwards. Reporting that message destroyed is the failure this
      // layer exists to stop, and letting the refusal leave would
      // abandon every message behind it as well.
      var act = _destroyLayerRow(row, removed[d], gone.digest, false);
      if (act.stayed !== null) {
        // The volume's own words go on the audit row rather than on the
        // entry, because they are what the operator acts on and they name
        // the path and the table the client is not being told about.
        _recordDestructionIncomplete(removed[d], gone.digest, act.stayed.reason, act.stayed.said);
        // No path and no digest on the entry. It reaches whoever asked to
        // delete their own mail, and a mailbox protocol owes its client
        // neither the operator's volume layout nor the content hash of a
        // stored message. Both are on the audit row instead.
        refused.push({
          id:     removed[d],
          reason: act.stayed.reason,
          octets: act.stayed.octets,
          detail: act.stayed.detail,
        });
        continue;
      }
      deleted.push(removed[d]);
    }
    // Descending order, because each untagged EXPUNGE renumbers every
    // message after it and a higher number is unaffected by the
    // removal of a lower one.
    expunged.sort(function (x, y) { return y - x; });
    return {
      deleted:  deleted.concat(finished.deleted),
      refused:  _classified(refused),
      expunged: expunged,
      modseq:   _highestModseq(_snapshot(row, false)),
    };
  }

  /**
   * @primitive blamepost.mail.mailbox.expungeObjects
   * @signature mailbox.expungeObjects(actor, mailbox, objectIds)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 8621 section 4.4 (Email/set destroyed), RFC 9051 section 6.4.3 (EXPUNGE)
   * @related   blamepost.mail.mailbox.create, blamepost.mail.mailbox.legalHold.place
   *
   * Destroy named messages in one of the acting account's folders, and
   * answer with what went and why anything else stayed. This is the verb
   * a surface with no wire session drives: JMAP `Email/set` `destroyed`
   * and the browser interface's purge both name messages rather than
   * flagging them, and both need the refusal reason to report back.
   *
   * The refusal reasons are the mail agent's own vocabulary, so a caller
   * can pass one straight through to its protocol: `legal-hold` for a
   * message under a preservation order, `retention-floor` for one inside
   * the regulated window, and `not-in-folder` for an identifier this
   * account's folder does not hold.
   *
   * `row-not-removed` and `body-not-removed` are the two that are not a
   * decision. The message has left the mailbox and no wire protocol
   * reaches it, and the volume would not take one of the two acts that
   * remove it from this layer: the row binding it to a mailbox, or the
   * sealed octets that row names. Either way its octets are still stored
   * here, so it is reported as a message that did not go rather than as
   * one that did.
   *
   * Every refusal also carries an `outcome` of `preserved`, `absent` or
   * `incomplete`, which is what a caller acts on. A preservation order
   * and the retention floor are something keeping a message on purpose,
   * so nothing was destroyed and a rerun reaches it whole once the order
   * or the window lifts. The other two are a volume to go and look at:
   * the message itself is gone and what stayed is a record of it. Which
   * record stayed decides where the remedy is, and the entry says so in
   * `octets` rather than leaving a caller to infer it from the reason.
   *
   * `row-not-removed` leaves the row this layer keeps, and THIS VERB IS
   * WHAT REACHES IT. Membership served to a reader is this layer's rows
   * intersected with the message store's, and such a row is outside that
   * intersection; the delete path asks a second question of every
   * identifier the intersection does not answer, so the record a refusal
   * here names stays addressable by the verb that named it, and a rerun
   * finishes the removal rather than repeating a delete that has already
   * run.
   *
   * `body-not-removed` is the other way round: the row went and the
   * octets stayed, so nothing on either layer names them and no rerun of
   * this verb can find them. `blamepost blobs report --verify` lists
   * them and `blamepost blobs reclaim` frees them once the volume gives
   * the file up.
   *
   * A stranded row's own preservation gates are read on this layer,
   * because the message store row the agent decides from is already
   * gone: the order registry directly, and the retention floor against
   * the row's own arrival time under the operator's posture. Finishing a
   * destruction is still a destruction, and it answers to the same two
   * gates the run that started it answered to.
   *
   * @example
   *   var outcome = await mailbox.expungeObjects(actor, "INBOX", [emailId]);
   *   outcome.refused[0].reason;
   *   // "legal-hold"
   */
  async function expungeObjects(actor, mailbox, objectIds) {
    var account = _accountOf(actor, "the message delete");
    var row = _requireFolder(account, mailbox);
    var requested = Array.isArray(objectIds) ? objectIds : [];
    var outcome = await _expungeResolved(actor, row, requested.map(function (id) {
      return String(id === undefined || id === null ? "" : id);
    }));
    return { deleted: outcome.deleted, refused: outcome.refused, modseq: outcome.modseq };
  }

  /**
   * @primitive blamepost.mail.mailbox.moveObjects
   * @signature mailbox.moveObjects(actor, fromMailbox, toMailbox, objectIds)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9051 section 6.4.8 (MOVE and the destination's UID), RFC 8621 section 4.6
   * @related   blamepost.mail.mailbox.expungeObjects, blamepost.mail.mailbox.create
   *
   * File named messages from one of the account's folders into another,
   * which is what a client is doing every time it moves a message into
   * Trash. This is a soft delete and stays one: nothing is destroyed,
   * the legal hold flag and the retention floor are not consulted, and
   * `expungeObjects` is still the only thing that removes a message.
   *
   * The store's own move is half the operation. This layer holds the row
   * binding a message to a folder and the UID an IMAP client addresses
   * it by, so a caller that moves the store row alone leaves the message
   * in neither folder on IMAP and POP3 while the browser interface still
   * lists it, and leaves it in a place no delete verb can reach.
   *
   * RFC 9051 section 6.4.8 makes a moved message a new message in the
   * mailbox it arrives in, so it takes that mailbox's next UID rather
   * than carrying the old one across.
   *
   * @example
   *   var filed = await mailbox.moveObjects(actor, "INBOX", "Trash", [emailId]);
   *   filed.moved.length;
   *   // 1
   */
  async function moveObjects(actor, fromMailbox, toMailbox, objectIds) {
    var account = _accountOf(actor, "the message move");
    var source = _requireFolder(account, fromMailbox);
    var destination = _requireFolder(account, toMailbox);
    if (source.folder === destination.folder) {
      throw err("mailbox/bad-move",
        "a message cannot be moved into the mailbox it is already in. Moving it to " +
        "itself would give it a new identifier for no reason a client could follow.");
    }

    var requested = Array.isArray(objectIds) ? objectIds : [];
    var messages = _snapshot(source, false);
    var present = Object.create(null);
    for (var m = 0; m < messages.length; m += 1) present[messages[m].objectid] = true;

    var mine = [];
    var refused = [];
    for (var r = 0; r < requested.length; r += 1) {
      var wanted = String(requested[r] === undefined || requested[r] === null ? "" : requested[r]);
      if (present[wanted] === true) {
        if (mine.indexOf(wanted) === -1) mine.push(wanted);
        continue;
      }
      refused.push({ id: wanted, reason: "not-in-folder" });
    }
    if (mine.length === 0) return { moved: [], refused: refused };

    // `b.mail.agent.move` composes `b.guardMailMove`, which grants a
    // destination through the actor's own `allowedFolders`. A caller
    // that narrowed that list keeps its narrowing; a caller that carries
    // none gets exactly the two folders this layer has just proved the
    // account owns, rather than a second hand-maintained copy of the
    // same ownership fact drifting from the one in the folder table.
    var moveActor = actor;
    if (!Array.isArray(actor.allowedFolders)) {
      moveActor = Object.assign({}, actor, {
        allowedFolders: [source.folder, destination.folder],
      });
    }
    await mailAgent.move({
      actor:      moveActor,
      fromFolder: source.folder,
      toFolder:   destination.folder,
      objectIds:  mine,
    });

    // The adapter's rows follow the store's, and each takes the
    // destination's next identifier.
    //
    // The counter is taken HERE and not from the row read above the
    // await. That row is a copy of the folder as it stood before this
    // call suspended, and a second filing into the same mailbox has had
    // the whole suspension to take the identifier it names. Everything
    // from the allocation to the last row written is one synchronous
    // run, so nothing can land between them.
    var taken = _takeUids(destination._id, mine.length);
    for (var i = 0; i < mine.length; i += 1) {
      var row = b.db.from(MESSAGES)
        .where({ folder: source.folder, objectid: mine[i] }).first();
      // The store's half is already done, so a row this layer cannot
      // follow with is a message the store holds in the destination that
      // no row here names. Nothing lists it and no delete a client can
      // name reaches it, because every read a client is served resolves
      // through this layer's rows. An account erasure DOES reach it: it
      // sweeps each mailbox against the message store as well as against
      // its own rows, so the message is destroyed with the rest of the
      // account's mail rather than outliving the identity that named it.
      // It cannot be undone from here either: the move went through the
      // agent, and putting the message back would be a second move made
      // on a guess about what took the row. So it is recorded, in the one
      // place an operator reading the volume can find it.
      if (!row) {
        _recordMoveUnbound(mine[i], source, destination,
          "the row binding this message to a mailbox was gone by the time the move reached it");
        continue;
      }
      try {
        b.db.from(MESSAGES).where({ _id: row._id }).updateOne({
          _id:    row._id,
          folder: taken.folder,
          uid:    taken.first + i,
        });
      } catch (rowError) {
        _recordMoveUnbound(mine[i], source, destination,
          (rowError && rowError.message) || String(rowError));
      }
    }
    return { moved: mine, refused: refused };
  }

  // EXPUNGE. The candidate set is the messages a client flagged
  // \Deleted. RFC 9051 section 6.4.3 gives the command no refusal form,
  // so a message the agent kept draws no untagged EXPUNGE and the
  // command still completes: saying OK and drawing a line for it would
  // renumber the client's mailbox around a message that is still in it.
  // The reasons ride back on the return value for a caller that has
  // somewhere to put them.
  async function expungeFolder(actor, mailbox) {
    var account = _accountOf(actor, "EXPUNGE");
    var row = _requireFolder(account, mailbox);
    var messages = _snapshot(row, true);
    var candidates = [];
    for (var i = 0; i < messages.length; i += 1) {
      if (messages[i].flags.indexOf("\\Deleted") === -1) continue;
      candidates.push(messages[i].objectid);
    }
    if (candidates.length === 0) {
      return { expunged: [], refused: [], modseq: _highestModseq(messages) };
    }
    var outcome = await _expungeResolved(actor, row, candidates, messages);
    return { expunged: outcome.expunged, refused: outcome.refused, modseq: outcome.modseq };
  }

  // ---- Erasing everything one account holds --------------------------------

  // One row erased rather than deleted, and every row of a set.
  //
  // What the erase adds over a delete is the record and the refusals,
  // not the disposal of the bytes. It files a row in the audit trail
  // carrying the reason this subject's data was destroyed, and it
  // consults the legal-hold and dual-control registries before it
  // proceeds, which is what an erasure under Article 17 has to be able
  // to show afterwards. It also rebuilds the table's indexes, which
  // takes with them the derived-hash entries a filter script's name was
  // indexed under.
  //
  // The bytes themselves are settled a layer down and settled the same
  // way for every delete on this database: the framework opens it with
  // SQLite's secure delete, so content a delete frees is overwritten
  // rather than abandoned in the page until a later write reuses the
  // slot. That is why the ordinary delete paths in this file stay
  // ordinary deletes, which is a script an account holder removes over
  // ManageSieve and an annotation a client clears: routing either
  // through here would buy an erasure record for an operation that is
  // not an erasure, and would rebuild every index on the table on a
  // wire verb.
  // `sieve-script-lifecycle` pins the disposal property against the
  // volume, because it belongs to the vendored framework and nothing
  // else here would notice it going.
  //
  // A set of rows is a set of separate verdicts, and this answers for
  // each of them. The registries the erase consults are consulted per
  // row, so any one row can be refused while the rest go, and a loop that
  // let the first refusal out would stop there: every row behind it
  // abandoned, and the record of the rows already destroyed thrown away
  // with the exception. What the caller does with that report is answer
  // an Article 17 request with it, and the two calls into here sit on
  // either side of the destruction it describes: the annotations go in
  // front of the mailboxes, so a row a gate is holding must not stop the
  // mail being destroyed at all, and the filter scripts go after it, by
  // which time the report is the only record that the mail was ever on
  // the volume.
  //
  // `describe` names the row for the person reading that report. A row id
  // identifies the row and tells nobody which of their filter scripts a
  // gate is holding, and the operator has to know which one in order to
  // go and release it.
  function _eraseRows(table, where, reason, describe) {
    var rows = b.db.from(table).where(where).all();
    var out  = { erased: 0, refused: [] };
    for (var i = 0; i < rows.length; i += 1) {
      try {
        b.db.eraseHard(table, rows[i]._id, { reason: reason });
        out.erased += 1;
      } catch (e) {
        // Not a swallow. The refusal becomes an entry in the report the
        // verb returns, classified by which of the two things stopped it,
        // because a gate wanting a second approver and storage refusing
        // the write need opposite responses from whoever reads it.
        var code = (e && e.code) || "unknown";
        out.refused.push({
          objectid:  null,
          mailbox:   null,
          record:    describe(rows[i]),
          reason:    code,
          preserved: storeErrors.isPreservationRefusal(code),
          detail:    (e && e.message) || String(e),
        });
      }
    }
    return out;
  }

  /**
   * @primitive blamepost.mail.mailbox.eraseAccountMail
   * @signature mailbox.eraseAccountMail(actor, accountId, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      GDPR Article 17 and Article 17(3)(e), RFC 9051 section 6.4.3
   * @related   blamepost.mail.mailbox.expungeObjects, blamepost.store.accounts.delete
   *
   * Destroy everything one account holds here: its messages, the rows
   * binding them to a mailbox, the sealed octets under `blobs/`, its
   * filter scripts, its annotations, the mailbox rows themselves, and
   * any POP3 maildrop a session was still holding.
   *
   * This is the mail half of erasing an account, and it is a verb on
   * this layer because this layer owns those rows. Erasing the account
   * row reaches none of them: that erase is one row in one table and
   * cascades nothing, so a caller that stops there has destroyed an
   * identity and left the mail. Nothing else would remove it afterwards
   * either, because the body release is reference counted and the
   * references are exactly the rows that stayed.
   *
   * Every message goes through the same delete path IMAP EXPUNGE takes,
   * so a preservation order and the retention floor still refuse per
   * message. That is the point rather than a limit on it. A court's
   * order to keep a record outranks a request to destroy it, which
   * Article 17(3)(e) says in as many words, and an operator answering
   * the request has to be able to name the records being kept. Anything
   * that stayed comes back under `refused`, carrying the mailbox it is
   * in, the delete path's own reason, and whether that reason is
   * something deliberately keeping it or something that went wrong.
   *
   * **Nothing here is raised, all of it is reported.** The annotations,
   * the messages, the mailbox rows and the filter scripts are four sets
   * of rows and each one is refused separately: the delete path answers
   * per message, and the hard erase under the other three consults the
   * preservation-order registry and the dual-control gate per row. Every
   * one of those refusals becomes an entry in `refused` and the call
   * still returns. It has to. Once the mail is destroyed a refusal
   * allowed to leave would hand the caller an exception in place of the
   * report, skip the audit row written at the end, and leave nothing
   * anywhere saying the mail had ever been on the volume, so an operator
   * answering an erasure request would have no way to find out that it
   * half ran. Ahead of the mail it is the other way round and the answer
   * is the same: one annotation a gate is holding must not stop the
   * destruction of everything else the request asked for.
   *
   * Each entry names the record rather than only its table: the message
   * and the mailbox it is in, the mailbox row itself, the filter script
   * by the name its owner gave it, or the annotation and the mailbox it
   * was set on. `preserved` says which of the two things stopped it,
   * because the two need opposite responses from whoever reads the
   * report: release the order or obtain the grant and run this again, or
   * go and look at the volume.
   *
   * A mailbox row is erased only once everything bound to it has actually
   * gone, judged on the rows rather than on what the two erases above
   * answered. One still holding a message or an annotation keeps its row,
   * so the record that stayed stays addressable instead of naming a
   * mailbox nothing on the volume answers to. That is why the annotations
   * are erased in front of the mailboxes rather than after them: an
   * annotation carries the opaque token of the mailbox it was set on and
   * no name, so a row erased out from under one leaves it reachable by
   * nothing, and the rerun the operator was told to run can no longer say
   * which of their mailboxes it belonged to.
   *
   * That only holds as far as this layer reaches, and the identity layer
   * applies the same rule one level up for the same reason: an account
   * row erased while a mailbox still names it would leave the kept mail
   * addressable through a mailbox owned by nobody, which is the same
   * failure a level out. So `blamepost.store.accounts.delete` calls this
   * BEFORE it touches the account row and erases that row only when the
   * count of mailboxes naming it has reached zero. A caller driving this
   * verb directly is taking that responsibility on.
   *
   * Bodies go through the reference-counted release, so one shared with
   * an account that is still here stays: content addressing means a
   * single file can be the body of a message in a mailbox being erased
   * and of a message in one that is not.
   *
   * **Mail no mailbox row names is destroyed too.** A message lives on
   * two layers and filing writes them one after the other, so an
   * interruption or a rollback the message store refuses can leave the
   * store holding a message this layer never recorded. Nothing serves it
   * to a reader, which is exactly why an erasure has to go looking for
   * it: the store's row still holds the subject, the correspondents and
   * the body, sealed and opening as they always did, and erasing the
   * account without it would destroy the only identity that could ever
   * have named it. Each mailbox is therefore swept against the message
   * store as well as against its own rows, and both sets go through the
   * one delete path in one call.
   *
   * Those messages answer to the same two gates as every other. The
   * message store's row is the record `b.mail.agent.expunge` decides
   * from, so a preservation order and the retention floor reach them
   * directly, and a mailbox holding one the agent kept keeps its row
   * with it. `unfiledErased` and `unfiledKept` count how much of the
   * destruction and how much of what stayed was mail in that state, and
   * every message entry carries `unfiled` saying which it was. It is
   * worth reading separately: it is the half of the account's mail no
   * other surface on this server can show an operator.
   *
   * Its reach ends at the store's row. Filing writes the sealed octets
   * before either row, so an interruption can also leave a body under
   * `blobs/` that no row names; `blamepost blobs report --verify` lists
   * those and `blamepost blobs reclaim` frees them once they have
   * settled.
   *
   * One thing survives, measured rather than assumed. The message store
   * keeps its own folder row per mailbox, and the surface it exposes has
   * no verb that removes one, so an erased account leaves as many empty
   * rows behind as it had mailboxes. Each carries the opaque token this
   * layer generated, no account, no name the owner chose and no
   * messages, so it holds none of the account's data and answers for
   * none of it; the reconciliation reads this layer's rows and reports
   * the volume clean.
   *
   * @opts
   *   reason: string,   // required, recorded in the audit trail
   *
   * @example
   *   var swept = await mailbox.eraseAccountMail(actor, account.id, {
   *     reason: "erasure requested by the account holder",
   *   });
   *   swept.destroyed.length;
   */
  async function eraseAccountMail(actor, accountId, eraseOpts) {
    _accountOf(actor, "an account mail erasure");
    if (typeof accountId !== "string" || accountId.length === 0) {
      throw err("mailbox/bad-argument",
        "an account mail erasure names the account whose mailboxes it erases. It is an " +
        "argument of its own rather than the acting account, because an erasure is " +
        "somebody acting on an account rather than an account acting on itself.");
    }
    var options = eraseOpts || {};
    if (typeof options.reason !== "string" || options.reason.trim().length === 0) {
      throw err("mailbox/bad-argument",
        "an account mail erasure needs a reason. Once it has run, the audit row carrying " +
        "the reason is the only record that this mail was ever here.");
    }
    var reason = options.reason.trim();

    var folders = b.db.from(FOLDERS).where({ account: accountId }).all();
    // The values these rows carry, held before any of them can go, so
    // the next mailbox provisioned on this volume still climbs past them
    // however far through the loop below the erasure gets.
    _holdFloorOfRows(folders);

    // The name each mailbox is addressed by, taken off the same snapshot
    // and for the same reason. An annotation is filed against the opaque
    // token rather than the name, so nothing that reads an annotation row
    // can say which mailbox it was set on without this map. The operator
    // reading the report needs the mailbox they set it on.
    var wireNameOf = Object.create(null);
    for (var w = 0; w < folders.length; w += 1) {
      wireNameOf[folders[w].folder] = folders[w].wireName;
    }

    var destroyed = [];
    var refused = [];
    var mailboxesErased = 0;
    var unfiledErased = 0;
    var unfiledKept = 0;

    // The annotations FIRST, before any mailbox row can go.
    //
    // An annotation is bound to a mailbox exactly as a message is: its
    // row carries the opaque token and nothing else, and every surface
    // that could produce it resolves that token first. So erasing a
    // mailbox row while an annotation still names it leaves the
    // annotation pointing at a mailbox nothing on the volume answers to,
    // which is the same failure the identity layer avoids one level out
    // by erasing an account row only once nothing it holds still names
    // it. The operator pays for it twice over: no verb reaches the row,
    // and the report of the rerun they were told to run can only say the
    // record was on a mailbox that has already gone.
    //
    // Being first also means an annotation refusal is the one refusal
    // here that arrives before anything has been destroyed. It is still
    // reported rather than raised, for the reason a set is: a single row
    // a gate is holding must not stop the erasure of the mail, which is
    // the part of the request that matters most and the part this whole
    // verb exists to reach.
    var annotations = _eraseRows(METADATA, { account: accountId }, reason,
      function (metaRow) {
        return "the annotation " + metaRow.entry + " on " +
          (metaRow.folder === "" || metaRow.folder === null || metaRow.folder === undefined
            ? "the account"
            : (wireNameOf[metaRow.folder] || "a mailbox this account does not hold"));
      });
    refused = refused.concat(annotations.refused);

    for (var f = 0; f < folders.length; f += 1) {
      var row = folders[f];
      var wireName = row.wireName;
      // The rows THIS layer holds, rather than the intersection with the
      // message store that a client is served from. Those rows are what
      // pins a body against the release, so a row the store has no
      // partner for is exactly the one an erasure must not walk past:
      // the delete path answers for it as absent, the row survives, and
      // the mailbox keeps its own row rather than being erased out from
      // under it.
      var held = b.db.from(MESSAGES).where({ folder: row.folder }).all();
      var ids = [];
      for (var h = 0; h < held.length; h += 1) ids.push(held[h].objectid);

      // And the mail on the other side of the same disagreement: what
      // the message store holds for this mailbox that no row above
      // names. Nothing serves it to a reader and no identifier for it
      // exists anywhere outside the store, so an erasure that asked only
      // the rows above would destroy the account and leave that message
      // sealed on the volume with its subject, its correspondents and
      // its body intact, in every backup taken afterwards, with the
      // identity that would have named it gone.
      //
      // They join the SAME set rather than being swept afterwards. One
      // delete call per mailbox is one membership read, one agent
      // decision and one report, and a second pass beside it would be a
      // second place for the preservation rules to be applied slightly
      // differently.
      var unfiled = _unfiledObjectIds(row);
      var isUnfiled = Object.create(null);
      for (var n = 0; n < unfiled.length; n += 1) {
        isUnfiled[unfiled[n]] = true;
        ids.push(unfiled[n]);
      }

      if (ids.length > 0) {
        var outcome;
        try {
          outcome = await _expungeResolved(actor, row, ids);
        } catch (e) {
          // The delete gate refused the call rather than a message: the
          // acting account may not delete at all, or the agent would not
          // route the verb. Nothing in this mailbox went, and reporting
          // it per message is what lets the caller answer for the whole
          // erasure in one shape. The loop carries on, because the other
          // mailboxes are separate calls and an operator needs to know
          // how much of the request was met.
          for (var x = 0; x < ids.length; x += 1) {
            if (isUnfiled[ids[x]] === true) unfiledKept += 1;
            refused.push({
              objectid:  ids[x],
              mailbox:   wireName,
              record:    "message " + ids[x] + " in " + wireName,
              reason:    (e && e.code) || "unknown",
              preserved: false,
              unfiled:   isUnfiled[ids[x]] === true,
              detail:    (e && e.message) || String(e),
            });
          }
          continue;
        }
        for (var d = 0; d < outcome.deleted.length; d += 1) {
          if (isUnfiled[outcome.deleted[d]] === true) unfiledErased += 1;
          destroyed.push({
            objectid: outcome.deleted[d],
            mailbox:  wireName,
            // Whether any row on this layer ever named it. An operator
            // answering an erasure request reads this to tell a message
            // the account could see from one only the message store
            // knew about, which is the difference between the mail they
            // expected to lose and mail an interrupted filing left.
            unfiled:  isUnfiled[outcome.deleted[d]] === true,
          });
        }
        for (var r = 0; r < outcome.refused.length; r += 1) {
          if (isUnfiled[outcome.refused[r].id] === true) unfiledKept += 1;
          refused.push({
            objectid:  outcome.refused[r].id,
            mailbox:   wireName,
            record:    "message " + outcome.refused[r].id + " in " + wireName,
            reason:    outcome.refused[r].reason,
            preserved: _isPreservation(outcome.refused[r].reason),
            unfiled:   isUnfiled[outcome.refused[r].id] === true,
            // Carried rather than re-derived. Whether the mail itself is
            // still here is decided by the delete path, which is the
            // only thing that saw the volume, and an erasure report is
            // exactly where that answer has to be right.
            octets:    outcome.refused[r].octets || null,
            // What the delete path said, when it said anything. A
            // preservation order and the floor are answered by the reason
            // alone; a volume that would not remove a body has more to
            // say, and the operator reading the report is the one who
            // acts on it.
            detail:    outcome.refused[r].detail || null,
          });
        }
      }

      // Read again rather than inferred from the answer above. What
      // decides whether this mailbox may go is whether anything is still
      // bound to it, and the delete path answers about the messages it
      // was handed rather than about the mailbox.
      //
      // It is also the read that covers the suspension. The delete above
      // yields, and a message filed into this mailbox across that gap is
      // one the delete was never handed: erasing the row on the strength
      // of the earlier answer would leave that message bound to a
      // mailbox nothing can name, which is the state this whole verb
      // exists to stop producing.
      if (b.db.from(MESSAGES).where({ folder: row.folder }).count() > 0) continue;
      // The same question of the other layer, and it has to be asked
      // separately because a message the store still holds may have no
      // row above to be counted by. A preservation order or the
      // retention floor keeps such a message exactly as it keeps any
      // other, and erasing the mailbox row over it would leave the
      // record the operator has to name for the court addressed through
      // a mailbox nothing on this volume answers to, which is the
      // failure the annotations are erased in front of the mailboxes to
      // avoid, one layer over.
      if (_unfiledObjectIds(row).length > 0) continue;
      // Both kinds of row this mailbox holds, counted the same way. An
      // annotation the erase above could not take is as much a record
      // bound to this mailbox as a message the delete path kept, and the
      // rule is about the mailbox rather than about which table the thing
      // that stayed is in.
      if (b.db.from(METADATA).where({ account: accountId, folder: row.folder }).count() > 0) {
        continue;
      }

      try {
        b.db.eraseHard(FOLDERS, row._id, { reason: reason });
        mailboxesErased += 1;
      } catch (e) {
        // Reported rather than raised, for the reason the aliases beside
        // this are: by the time it runs the account is already gone, and
        // a throw would tell the caller the erasure it asked for did not
        // happen when most of it did. An empty mailbox row belonging to
        // nobody holds no mail, so this is the mildest of the outcomes
        // here, and it is still somebody's to look at.
        //
        // Which of the two it is comes from the same rule the rest of
        // this report is classified by. The erase refuses a mailbox row
        // for the same reasons it refuses anything else, and a gate
        // wanting a second approver reported as a fault sends an operator
        // looking for a broken volume over an approval that has not
        // arrived yet, while the trail records a working system as a
        // failure.
        var folderCode = (e && e.code) || "unknown";
        refused.push({
          objectid:  null,
          mailbox:   wireName,
          record:    "the mailbox " + wireName,
          reason:    folderCode,
          preserved: storeErrors.isPreservationRefusal(folderCode),
          detail:    "the mailbox row itself could not be erased: " +
            ((e && e.message) || String(e)),
        });
      }
    }

    // The last of what the account holds on this layer, and the one thing
    // here that names no mailbox. A filter script is the account's own
    // material rather than a mailbox's: it names the correspondents its
    // owner sorts on, and its row carries the account and nothing else.
    // So the container it has to outlive is the account row, which the
    // identity layer erases after this verb returns and only once nothing
    // still names it. That is why it runs here rather than in front of
    // the mailboxes the way the annotations do.
    //
    // It joins the same report the rest is in rather than raising. By the
    // time it runs the mail is already destroyed, so a refusal that left
    // here would take the whole report with it: the caller would be
    // handed an exception instead of the answer, the audit row below
    // would never be written, and there would be no record anywhere that
    // the mail had ever been on the volume. The one thing an erasure
    // cannot do is fail to say what it destroyed.
    var scripts = _eraseRows(SCRIPTS, { account: accountId }, reason,
      function (scriptRow) {
        return "the filter script \"" + scriptRow.name + "\"";
      });
    refused = refused.concat(scripts.refused);
    var annotationsErased = annotations.erased;
    var scriptsErased     = scripts.erased;

    // A POP3 session holding the maildrop of an account that no longer
    // exists holds a listing of messages that are gone, and holds the
    // exclusive lock RFC 1939 section 3 gives it against an address that
    // could be provisioned again. Both end here rather than at the idle
    // sweep, which is a reclaim for an abandoned session rather than for
    // an erased mailbox.
    var dropsClosed = 0;
    drops.forEach(function (drop, id) {
      if (drop.account !== accountId) return;
      drops.delete(id);
      dropsClosed += 1;
    });
    provisioned.delete(accountId);

    var faulted = refused.filter(function (entry) { return entry.preserved !== true; });

    // The message half of the report, separated for the trail. Every
    // entry above is a record this erasure was asked to destroy and did
    // not, but they are not all messages, and a row saying a message was
    // preserved when what stayed was a filter script answers a later
    // question wrongly. The question a trail is read with is which of the
    // subject's records are still on the volume and under what.
    var messageRefusals = refused.filter(function (entry) {
      return entry.objectid !== null && entry.objectid !== undefined;
    });
    var messagesPreserved = messageRefusals.filter(function (entry) {
      return entry.preserved === true;
    }).length;

    // Written once the destruction is settled, and written through the
    // sink that drops what it cannot file. The mail is already gone by
    // the time this runs and no later write takes it back, so letting a
    // sink error out would report an erasure that happened as one that
    // did not. A record something is deliberately keeping leaves a clean
    // row with a count beside it; a record that faulted is somebody's
    // data on a volume that was asked to lose it, and recording that as
    // a clean success is the shape this has to be answered for in.
    await auditActor.record({
      action:   "blamepost.mail.mailbox.account_mail_erased",
      outcome:  faulted.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "account", id: accountId },
      metadata: {
        messagesErased:    destroyed.length,
        messagesPreserved: messagesPreserved,
        messagesFailed:    messageRefusals.length - messagesPreserved,
        // Of those, how many no mailbox row ever named. They are counted
        // inside the totals above rather than beside them, because they
        // are messages and the question the trail is read with is how
        // much of the subject's mail is still on the volume. The split
        // is here because it is the half nothing else on this server can
        // see, so an operator asked to account for it later has this row
        // and nothing else.
        messagesUnfiledErased: unfiledErased,
        messagesUnfiledKept:   unfiledKept,
        mailboxesErased:   mailboxesErased,
        mailboxesKept:     folders.length - mailboxesErased,
        scriptsErased:     scriptsErased,
        scriptsKept:       scripts.refused.length,
        annotationsErased: annotationsErased,
        annotationsKept:   annotations.refused.length,
        dropsClosed:       dropsClosed,
      },
    });

    return {
      accountId:       accountId,
      destroyed:       destroyed,
      refused:         refused,
      unfiledErased:   unfiledErased,
      unfiledKept:     unfiledKept,
      mailboxesErased: mailboxesErased,
      mailboxesKept:   folders.length - mailboxesErased,
      scriptsErased:   scriptsErased,
      scriptsKept:     scripts.refused.length,
      annotationsErased: annotationsErased,
      annotationsKept:   annotations.refused.length,
      dropsClosed:     dropsClosed,
    };
  }

  // ---- Legal hold ----------------------------------------------------------

  // A hold is two records, and mistaking them for one is the failure
  // this section is shaped around. `b.legalHold` is the registry: it
  // carries the reason, the custodian and the citation, and it writes
  // the hash-chained `legalhold.placed` and `legalhold.released` rows a
  // regulator asks to see. The mail store's per message flag is the
  // enforcement point: `b.mail.agent.expunge` reads that flag and
  // nothing else, so a hold recorded in the registry alone stops no
  // delete on any wire.
  //
  // Placing sets the flag first and records second. A record with no
  // flag is a message the interface says is held and every delete path
  // will remove; a flag with no record is a message that will not delete
  // and has no paperwork, which is the safe half of the same failure.
  // Releasing runs the other way round for the same reason: the registry
  // has to accept the release before the flag comes off.
  //
  // No mail protocol has a verb for any of this and none should. A
  // preservation order arrives from a court, so the placement path is an
  // operator's, and the account whose mailbox it is scopes the call the
  // same way every other verb here is scoped.
  var holds = b.legalHold.create({ db: b.db, audit: b.audit });

  function _holdSubject(objectid) { return "message:" + objectid; }

  function _holdArgs(objectIds, holdOpts, verb) {
    var options = holdOpts || {};
    var ids = Array.isArray(objectIds) ? objectIds : [];
    if (ids.length === 0) {
      throw err("mailbox/bad-hold",
        verb + " names no message. A hold is placed on messages, not on a mailbox: a " +
        "mailbox-wide hold would silently cover mail that arrives after the order.");
    }
    if (typeof options.reason !== "string" || options.reason.trim().length === 0) {
      throw err("mailbox/bad-hold",
        verb + " needs a reason. It is the column an auditor filters on, and a hold " +
        "with nothing written against it is not a record of anything.");
    }
    var out = [];
    for (var i = 0; i < ids.length; i += 1) {
      out.push(String(ids[i] === undefined || ids[i] === null ? "" : ids[i]));
    }
    return { ids: out, reason: options.reason };
  }

  // The messages of a named set that are actually in the acting
  // account's folder, and the identifiers that are not. Everything below
  // works from this, so a hold can never reach a message the caller does
  // not own.
  //
  // A row whose message store partner is already gone is in scope here
  // for the same reason it is in scope for the delete path, and the
  // reason is sharper on this one. The delete path reads a preservation
  // order over such a row and refuses for it; if the order could not
  // then be LIFTED, the refusal would be permanent by construction and
  // no verb on this server would ever destroy that message. A hold that
  // cannot be released is not a hold, it is a deadlock, so the second
  // question is asked here too.
  //
  // A message the store holds that this layer never filed is in scope
  // for the mirror of that reason. The delete path can destroy one, so
  // an order has to be able to stop it: mail that can be destroyed and
  // cannot be protected has no preservation order in front of it at
  // all, which is the one direction a court's order must not fail in.
  // The order also has to reach it BEFORE the flag can, since the flag
  // the agent reads sits on the store's own row and the placement path
  // is what sets it.
  function _holdScope(actor, mailbox, ids, verb) {
    var account = _accountOf(actor, verb);
    var row = _requireFolder(account, mailbox);
    var present = Object.create(null);
    var messages = _snapshot(row, false);
    for (var m = 0; m < messages.length; m += 1) present[messages[m].objectid] = true;
    var mine = [];
    var notInFolder = [];
    for (var i = 0; i < ids.length; i += 1) {
      if (present[ids[i]] === true || _strandedRow(row, ids[i]) !== null ||
          _unfiledRow(row, ids[i]) !== null) {
        if (mine.indexOf(ids[i]) === -1) mine.push(ids[i]);
        continue;
      }
      notInFolder.push(ids[i]);
    }
    return { row: row, mine: mine, notInFolder: notInFolder };
  }

  /**
   * @primitive blamepost.mail.mailbox.legalHold.place
   * @signature mailbox.legalHold.place(actor, mailbox, objectIds, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      FRCP 26 / 37(e), GDPR Article 17(3)(e), SEC Rule 17a-4, HIPAA 164.530(j)(2)
   * @related   blamepost.mail.mailbox.legalHold.release, blamepost.mail.mailbox.expungeObjects
   *
   * Put named messages in one of the account's folders under a
   * preservation order. Every hard delete refuses them afterwards, on
   * every wire, until an operator releases the hold explicitly.
   *
   * A hold placed here has no sunset. `retainUntil` is refused rather
   * than accepted and ignored, because nothing in this server sweeps
   * one: an expiry the operator sets and the server never reaches is a
   * hold that reads as lifting itself on a date it does not lift on.
   *
   * @opts
   *   reason:    string,   // required; recorded as its own audit column
   *   citation:  string,   // the rule or matter the order is under
   *   custodian: string,   // who is answerable for the records
   *   placedBy:  string,   // the operator acting on the order
   *
   * @example
   *   mailbox.legalHold.place(actor, "INBOX", [objectId], {
   *     reason:   "preservation order 24-cv-01933",
   *     citation: "FRCP-26",
   *   });
   */
  function placeLegalHold(actor, mailbox, objectIds, holdOpts) {
    var options = holdOpts || {};
    var args = _holdArgs(objectIds, options, "a hold");
    if (options.retainUntil !== undefined && options.retainUntil !== null) {
      throw err("mailbox/bad-hold",
        "a hold placed here carries no expiry date. Nothing sweeps one, so a date " +
        "recorded against it would read as an end this server never acts on. Lift the " +
        "hold with a release when the duty ends.");
    }
    var scope = _holdScope(actor, mailbox, args.ids, "a hold");

    var held = [];
    var alreadyHeld = [];
    for (var i = 0; i < scope.mine.length; i += 1) {
      var objectid = scope.mine[i];
      // The flag first: it is the one the delete path reads.
      store.setLegalHold([objectid], { hold: true });
      var recorded = holds.place(_holdSubject(objectid), {
        reason:    args.reason,
        citation:  options.citation  || null,
        custodian: options.custodian || null,
        placedBy:  options.placedBy  || null,
      });
      if (recorded && recorded.error === "already-held") alreadyHeld.push(objectid);
      else held.push(objectid);
    }
    return { held: held, alreadyHeld: alreadyHeld, notInFolder: scope.notInFolder };
  }

  /**
   * @primitive blamepost.mail.mailbox.legalHold.release
   * @signature mailbox.legalHold.release(actor, mailbox, objectIds, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      FRCP 26 / 37(e), GDPR Article 17(3)(e)
   * @related   blamepost.mail.mailbox.legalHold.place
   *
   * Lift a preservation order and let the ordinary delete path reach
   * those messages again. The approver is required and recorded, because
   * lifting a hold is the half of this that ends a duty rather than
   * starting one.
   *
   * A message whose flag is set but which the registry has no record of
   * is released and reported under `notRegistered`, so a half-written
   * placement cannot leave a message that nothing can ever free.
   *
   * @opts
   *   reason:   string,   // required; why the duty ended
   *   approver: string,   // required; who says so
   *
   * @example
   *   mailbox.legalHold.release(actor, "INBOX", [objectId], {
   *     reason: "matter closed", approver: "records@example.com",
   *   });
   */
  function releaseLegalHold(actor, mailbox, objectIds, holdOpts) {
    var options = holdOpts || {};
    var args = _holdArgs(objectIds, options, "a release");
    if (typeof options.approver !== "string" || options.approver.trim().length === 0) {
      throw err("mailbox/bad-hold-release",
        "a release needs an approver. A preservation order is not lifted by whoever " +
        "happens to be at the keyboard, and the name is what the audit row carries.");
    }
    var scope = _holdScope(actor, mailbox, args.ids, "a release");

    var released = [];
    var notRegistered = [];
    for (var i = 0; i < scope.mine.length; i += 1) {
      var objectid = scope.mine[i];
      var record = holds.release(_holdSubject(objectid), {
        reason:   args.reason,
        approver: options.approver,
      });
      // The flag comes off either way: it is the enforcement point, and
      // a message flagged with no registry row is exactly the state a
      // release has to be able to clear.
      store.setLegalHold([objectid], { hold: false });
      if (record && record.error === "not-held") notRegistered.push(objectid);
      else released.push(objectid);
    }
    return { released: released, notRegistered: notRegistered, notInFolder: scope.notInFolder };
  }

  /**
   * @primitive blamepost.mail.mailbox.legalHold.status
   * @signature mailbox.legalHold.status(actor, mailbox, objectIds)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the flag enforces, the registry explains)
   * @related   blamepost.mail.mailbox.legalHold.place
   *
   * What is holding each named message, for the operator interface and
   * for `blamepost doctor`. `held` is read from the flag the delete path
   * reads, so it answers the question an operator is actually asking;
   * the reason, custodian and citation beside it come from the registry.
   * A message whose flag is set with no record behind it reads as held
   * with an empty reason, which is the state to go looking at.
   *
   * @example
   *   mailbox.legalHold.status(actor, "INBOX", [objectId])[0].citation;
   *   // "FRCP-26"
   */
  function legalHoldStatus(actor, mailbox, objectIds) {
    var ids = Array.isArray(objectIds) ? objectIds : [];
    var scope = _holdScope(actor, mailbox, ids.map(function (id) {
      return String(id === undefined || id === null ? "" : id);
    }), "a hold lookup");
    var out = [];
    for (var i = 0; i < scope.mine.length; i += 1) {
      var objectid = scope.mine[i];
      var meta = store.fetchByObjectId(scope.row.folder, objectid);
      var record = holds.get(_holdSubject(objectid));
      out.push({
        objectid:  objectid,
        held:      Boolean(meta && meta.legalHold),
        placedAt:  record ? record.placedAt : 0,
        placedBy:  record ? record.placedBy : null,
        reason:    record ? record.reason : null,
        custodian: record ? record.custodian : null,
        citation:  record ? record.citation : null,
      });
    }
    return out;
  }

  // ---- IMAP annotations (RFC 5464) ----------------------------------------

  function _metadataScope(account, mailbox) {
    if (mailbox === "" || mailbox === null || mailbox === undefined) return "";
    return _requireFolder(account, mailbox).folder;
  }

  function getMetadata(actor, mailbox, names, metaOpts) {
    var account = _accountOf(actor, "GETMETADATA");
    var scope = _metadataScope(account, mailbox);
    var options = metaOpts || {};
    var list = Array.isArray(names) ? names : [];
    var out = [];
    for (var i = 0; i < list.length; i += 1) {
      var entry = String(list[i]);
      var found = b.db.from(METADATA)
        .where({ account: account, folder: scope, entry: entry }).first();
      var value = found ? found.value : null;
      if (value !== null && typeof options.maxSize === "number" &&
          Buffer.byteLength(String(value), "utf8") > options.maxSize) {
        continue;
      }
      out.push({ entry: entry, value: value });
    }
    return out;
  }

  function setMetadata(actor, mailbox, entries) {
    var account = _accountOf(actor, "SETMETADATA");
    var scope = _metadataScope(account, mailbox);
    var list = Array.isArray(entries) ? entries : [];
    var now = Date.now();
    for (var i = 0; i < list.length; i += 1) {
      var entry = String(list[i].entry || "");
      if (!/^\/(private|shared)\/[A-Za-z0-9./_-]{1,128}$/.test(entry)) {
        throw err("mailbox/bad-annotation",
          "'" + entry + "' is not an annotation name. RFC 5464 section 3.2 puts them under " +
          "/private or /shared.");
      }
      var existing = b.db.from(METADATA)
        .where({ account: account, folder: scope, entry: entry }).first();
      if (list[i].value === null || list[i].value === undefined) {
        if (existing) b.db.from(METADATA).where({ _id: existing._id }).deleteOne();
        continue;
      }
      var value = String(list[i].value);
      if (Buffer.byteLength(value, "utf8") > MAX_METADATA_VALUE_BYTES) {
        throw err("mailbox/annotation-too-large",
          "an annotation value stops at " + MAX_METADATA_VALUE_BYTES + " bytes.");
      }
      if (existing) {
        b.db.from(METADATA).where({ _id: existing._id })
          .updateOne({ _id: existing._id, value: value, updatedAt: now });
        continue;
      }
      var held = b.db.from(METADATA).where({ account: account, folder: scope }).count();
      if (held >= MAX_METADATA_ENTRIES) {
        throw err("mailbox/annotation-limit",
          "a mailbox holds at most " + MAX_METADATA_ENTRIES + " annotations.");
      }
      b.db.from(METADATA).insertOne({
        _id:       b.uuid.v7(),
        account:   account,
        folder:    scope,
        entry:     entry,
        value:     value,
        createdAt: now,
        updatedAt: now,
      });
    }
    return { ok: true };
  }

  // ---- POP3 ----------------------------------------------------------------

  // Reclaim the maildrops nobody is holding any more, which is the ones
  // nothing has touched inside the window.
  //
  // How long a session has been idle is elapsed time, so it is measured
  // on the clock that measures elapsed time. Reading the wall clock here
  // would put both halves of RFC 1939 section 3 at the mercy of a date
  // correction: a step forward past the window reclaims a session that
  // is still live, and because that section applies a DELE only at QUIT,
  // the deletes the session had marked go with it and the account holder
  // sees the mail they deleted come back. A step backwards holds the
  // exclusive lock on an abandoned session until the clock catches up,
  // which is a mailbox its own owner cannot open.
  function _sweepDrops() {
    var cutoff = _elapsedMs() - POP3_DROP_IDLE_TTL_MS;
    drops.forEach(function (drop, id) {
      if (drop.usedAt < cutoff) drops.delete(id);
    });
  }

  // The drop this session is holding, and the point every POP3 verb that
  // reads or marks one passes through.
  //
  // Reading it counts as using it. That is what keeps the sweep above
  // from reclaiming a session in the middle of the download it exists
  // to perform: a client walking a large maildrop reaches this on every
  // command, so the window it is measured against restarts each time and
  // only a session that has stopped talking can age out of it.
  function _dropFor(actor, dropId, verb) {
    var account = _accountOf(actor, verb);
    var drop = drops.get(String(dropId));
    if (!drop || drop.account !== account) {
      throw err("mailbox/no-drop", verb + ": this session has no open maildrop.");
    }
    drop.usedAt = _elapsedMs();
    return drop;
  }

  // RFC 1939 section 3: the maildrop is opened exclusively and every
  // change is a mark, applied together at QUIT and at no other point.
  function openPop3Drop(actor, dropOpts) {
    var account = _accountOf(actor, "USER");
    _sweepDrops();
    var conflict = null;
    drops.forEach(function (drop) {
      if (drop.account === account) conflict = drop;
    });
    if (conflict) {
      throw err("mailbox/drop-locked",
        "another POP3 session holds this maildrop. RFC 1939 gives one session at a time " +
        "exclusive access, so the second waits for the first to quit.");
    }
    var row = _requireFolder(account, "INBOX");
    var messages = _snapshot(row, false);
    var listing = [];
    var totalBytes = 0;
    for (var i = 0; i < messages.length; i += 1) {
      listing.push({
        msgNum:   i + 1,
        size:     messages[i].sizeBytes,
        // The store's object id is the stable cross protocol identity
        // (RFC 8474), and it is printable ASCII inside the 70 byte
        // ceiling RFC 1939 puts on a unique id.
        uid:      messages[i].objectid,
        objectid: messages[i].objectid,
        digest:   messages[i].digest,
        deleted:  false,
      });
      totalBytes += messages[i].sizeBytes;
    }
    var dropId = "drop_" + b.crypto.generateToken(BYTES.bytes(12));
    drops.set(dropId, {
      dropId:   dropId,
      account:  account,
      folder:   row.folder,
      // The folder row the drop was opened against, so the commit
      // deletes from the mailbox this session has been reading rather
      // than re-resolving a name and hoping it lands in the same place.
      folderRow: row,
      // When this drop was last used, which opening it counts as. Every
      // verb that reaches `_dropFor` moves it, so the sweep reads how
      // long the session has been silent rather than how long it has
      // been connected.
      //
      // Elapsed rather than wall clock, and read through the same
      // function the sweep reads: the two are compared against each
      // other and never against a date, so a value that means an instant
      // to anybody else has no business here.
      usedAt: _elapsedMs(),
      messages: listing,
    });
    return { dropId: dropId, count: listing.length, totalBytes: totalBytes };
  }

  function listMessages(actor, dropId) {
    var drop = _dropFor(actor, dropId, "LIST");
    var out = [];
    for (var i = 0; i < drop.messages.length; i += 1) {
      if (drop.messages[i].deleted) continue;
      out.push({
        msgNum: drop.messages[i].msgNum,
        size:   drop.messages[i].size,
        uid:    drop.messages[i].uid,
      });
    }
    return out;
  }

  function _messageIn(drop, msgNum) {
    var n = parseInt(msgNum, 10);
    for (var i = 0; i < drop.messages.length; i += 1) {
      if (drop.messages[i].msgNum === n && !drop.messages[i].deleted) return drop.messages[i];
    }
    return null;
  }

  function getMessage(actor, dropId, msgNum, messageOpts) {
    var drop = _dropFor(actor, dropId, "RETR");
    var entry = _messageIn(drop, msgNum);
    if (!entry) return null;
    var raw = _readBlob(entry.digest);
    var options = messageOpts || {};
    if (options.headersOnly !== true) return { size: raw.length, rawBytes: raw };
    var split = _splitMessage(raw);
    var lines = parseInt(options.headerLines, 10);
    if (!isFinite(lines) || lines < 0) lines = 0;
    // RFC 1939 section 3: TOP is the header block, the blank line, and
    // that many lines of the body. Every one of them is part of the
    // stored message, so every one of them is the stored octets, and the
    // size reported beside them counts the same octets.
    var partial = Buffer.concat([split.header, _firstLines(split.body, lines)]);
    return { size: partial.length, rawBytes: partial };
  }

  function markDelete(actor, dropId, msgNum) {
    var drop = _dropFor(actor, dropId, "DELE");
    var entry = _messageIn(drop, msgNum);
    if (!entry) {
      throw err("mailbox/no-message", "DELE: no message with that number in this maildrop.");
    }
    entry.deleted = true;
    return { msgNum: entry.msgNum, deleted: true };
  }

  function resetPop3Drop(actor, dropId) {
    var drop = _dropFor(actor, dropId, "RSET");
    for (var i = 0; i < drop.messages.length; i += 1) drop.messages[i].deleted = false;
    return { cleared: drop.messages.length };
  }

  // QUIT from the transaction state. The marks become deletions here
  // and nowhere else, through the same delete path IMAP EXPUNGE takes,
  // so a message under legal hold survives a POP3 client exactly as it
  // survives an IMAP one.
  //
  // Where the two protocols differ is what the client is told, and POP3
  // is the one with a word for it. RFC 1939 section 6 puts the deletions
  // in the UPDATE state and gives the server `-ERR some deleted messages
  // not removed` for a commit that could not remove them all, so this
  // refuses rather than answering the ordinary success. A POP3 client
  // told +OK treats the server's copy as gone: it will not fetch the
  // message again, and one configured to delete after download has just
  // been told the only copy it knows about is on the server that in fact
  // still holds it. The messages that could go have already gone by
  // then, which is the partial outcome that section describes.
  async function commitPop3Drop(actor, dropId) {
    var drop = _dropFor(actor, dropId, "QUIT");
    var marked = [];
    for (var i = 0; i < drop.messages.length; i += 1) {
      if (!drop.messages[i].deleted) continue;
      marked.push(drop.messages[i].objectid);
    }
    if (marked.length === 0) {
      drops.delete(drop.dropId);
      return { deleted: 0 };
    }
    // The lock goes before the refusal, so a session that is about to be
    // closed on an error does not leave the maildrop held against the
    // next one. A refusal reaches here two ways and both have to release
    // it: as a per message reason on the outcome, and as a throw from
    // the delete gate when the acting account may not delete at all. The
    // second one skipped the release for as long as this verb has
    // existed, and the account holder paid for it by losing every POP3
    // session until the stale drop aged out.
    var outcome;
    try {
      outcome = await _expungeResolved(actor, drop.folderRow, marked);
    } finally {
      drops.delete(drop.dropId);
    }

    // What the client needs to know is whether the messages it marked
    // are still there, which is not the same as whether this commit is
    // what removed them. Every message in the drop was in the mailbox
    // when the session opened, so an `absent` answer here means
    // something else took it in the meantime: the end state is the one
    // the client asked for, and reporting an error for it would send a
    // client back for a message that has gone.
    //
    // The same reading covers the message the volume kept a RECORD of
    // and destroyed. Its octets are gone, so the end state is again the
    // one the client asked for, and the row that stayed is the
    // operator's business rather than the account holder's: it is on the
    // trail, in the reconciliation and in the erasure's own report. Read
    // off the destroyed list rather than off the reason word, because
    // one identifier can carry both answers and only this one decides
    // what POP3 owes the client.
    var destroyedHere = Object.create(null);
    for (var g = 0; g < outcome.deleted.length; g += 1) destroyedHere[outcome.deleted[g]] = true;
    var kept = outcome.refused.filter(function (entry) {
      if (entry.outcome === "absent") return false;
      return destroyedHere[entry.id] !== true;
    });
    if (kept.length > 0) {
      var reasons = {};
      for (var r = 0; r < kept.length; r += 1) {
        reasons[kept[r].reason] = (reasons[kept[r].reason] || 0) + 1;
      }
      var named = Object.keys(reasons).map(function (reason) {
        return reasons[reason] + " " + reason;
      }).join(", ");
      throw err("mailbox/expunge-refused",
        "some deleted messages not removed (" + named + "); " + outcome.deleted.length +
        " of " + marked.length + " went.");
    }
    return { deleted: outcome.deleted.length };
  }

  // ---- ManageSieve ---------------------------------------------------------

  function _scriptName(name, verb) {
    var text = String(name === undefined || name === null ? "" : name);
    if (text.length === 0 || text.length > 128 ||
        b.codepointClass.firstControlCharOffset(text, { forbidTab: true }) !== -1) {
      throw err("mailbox/bad-script-name",
        verb + ": a script name is between 1 and 128 characters and carries no control " +
        "characters (RFC 5804 section 1.6).");
    }
    return text;
  }

  function _scriptRow(account, name) {
    return b.db.from(SCRIPTS).where({ account: account, name: name }).first() || null;
  }

  // The role gate in front of the filter surface. `b.mail.agent` routes
  // one of these verbs and answers the other three as not routed, so
  // this checks the agent's own table on the agent's own scope rather
  // than putting the surface behind a rejection or behind nothing.
  //
  // Only the writes are gated, and the reads are the reason. Delivery
  // reads the recipient's active filter with an actor the server builds
  // for the occasion, holding an identity and no role, because nobody is
  // signed in when a stranger's message arrives; refusing that read
  // files every filtered message into INBOX and tells nobody. An
  // operator reading an account's filters through the command line is
  // the same shape, audited at that end. Both stay outside the gate,
  // and per account scoping is what keeps them from reaching anybody
  // else's script.
  function _requireSieveScope(actor, verb) {
    if (roleGate.check(actor, SIEVE_SCOPE)) return;
    // `userId` rather than `id`: the chain writer reads `actor.userId`
    // and null-fills anything else, so a row built from the actor's own
    // field name records a refusal that names nobody. `resource` carries
    // the account a second time because that is the column an auditor
    // filters on when they are asking about one mailbox rather than one
    // person.
    b.audit.safeEmit({
      action:   "blamepost.mail.mailbox.sieve_denied",
      outcome:  "denied",
      actor:    { userId: (actor && actor.id) || null },
      resource: { kind: "account", id: (actor && actor.id) || null },
      reason:   "role does not carry " + SIEVE_SCOPE,
      metadata: { verb: verb, scope: SIEVE_SCOPE },
    });
    throw err("mailbox/permission-denied",
      verb + ": this account may not change its filter scripts (the role it holds does " +
      "not carry '" + SIEVE_SCOPE + "').");
  }

  // RFC 5804 section 2.6 requires the server to check a script before
  // accepting it, so a filter that cannot run is refused while the
  // owner is still looking at the error rather than at lost mail.
  function putScript(actor, name, body, putOpts) {
    var account = _accountOf(actor, "PUTSCRIPT");
    _requireSieveScope(actor, "PUTSCRIPT");
    var scriptName = _scriptName(name, "PUTSCRIPT");
    var text = String(body === undefined || body === null ? "" : body);
    var size = Buffer.byteLength(text, "utf8");
    if (size > MAX_SIEVE_SCRIPT_BYTES) {
      throw err("mailbox/script-too-large",
        "a script stops at " + MAX_SIEVE_SCRIPT_BYTES + " bytes and this one is " + size + ".");
    }
    var verdict = b.safeSieve.validate(text, { profile: "strict" });
    if (!verdict.ok) {
      var issue = (verdict.issues && verdict.issues[0]) || null;
      throw err("mailbox/script-refused",
        "the script did not parse: " + ((issue && (issue.snippet || issue.ruleId)) || "unknown"));
    }
    var existing = _scriptRow(account, scriptName);
    var now = Date.now();
    if (existing) {
      b.db.from(SCRIPTS).where({ _id: existing._id }).updateOne({
        _id: existing._id, body: text, sizeBytes: size, updatedAt: now,
      });
      return { ok: true, name: scriptName, requiredCaps: verdict.requiredCaps };
    }
    var held = b.db.from(SCRIPTS).where({ account: account }).count();
    if (held >= MAX_SIEVE_SCRIPTS) {
      throw err("mailbox/script-limit",
        "an account keeps at most " + MAX_SIEVE_SCRIPTS + " scripts.");
    }
    b.db.from(SCRIPTS).insertOne({
      _id:       b.uuid.v7(),
      account:   account,
      name:      scriptName,
      body:      text,
      active:    0,
      sizeBytes: size,
      createdAt: now,
      updatedAt: now,
    });
    return { ok: true, name: scriptName, requiredCaps: verdict.requiredCaps };
  }

  function listScripts(actor) {
    var account = _accountOf(actor, "LISTSCRIPTS");
    var rows = b.db.from(SCRIPTS).where({ account: account }).orderBy("createdAt", "asc").all();
    var out = [];
    for (var i = 0; i < rows.length; i += 1) {
      out.push({ name: rows[i].name, active: rows[i].active === 1 });
    }
    return out;
  }

  function getScript(actor, name) {
    var account = _accountOf(actor, "GETSCRIPT");
    var row = _scriptRow(account, _scriptName(name, "GETSCRIPT"));
    if (!row) return null;
    return { name: row.name, body: row.body, active: row.active === 1 };
  }

  // The one script this account has activated, as `{ name, body }`, or
  // null when it has activated none. RFC 5804 section 2.8 allows at most
  // one, which `setActiveScript` enforces by clearing the rest.
  //
  // Delivery calls this for every message that arrives for the account,
  // so it reads the row directly rather than listing every script and
  // filtering, and it returns the body beside the name because the
  // caller always wants both.
  function activeScript(actor) {
    var account = _accountOf(actor, "the active Sieve script");
    var row = b.db.from(SCRIPTS).where({ account: account, active: 1 }).first();
    if (!row) return null;
    return { name: row.name, body: row.body };
  }

  // RFC 5804 section 2.8: an empty name deactivates whatever is
  // active, and activating one script deactivates the rest.
  function setActiveScript(actor, name) {
    var account = _accountOf(actor, "SETACTIVE");
    _requireSieveScope(actor, "SETACTIVE");
    var rows = b.db.from(SCRIPTS).where({ account: account }).all();
    var target = null;
    var wanted = String(name === undefined || name === null ? "" : name);
    if (wanted.length > 0) {
      var scriptName = _scriptName(wanted, "SETACTIVE");
      for (var t = 0; t < rows.length; t += 1) {
        if (rows[t].name === scriptName) { target = rows[t]; break; }
      }
      if (!target) {
        throw err("mailbox/no-script", "SETACTIVE: no script by that name.");
      }
    }
    var now = Date.now();
    for (var i = 0; i < rows.length; i += 1) {
      var active = target !== null && rows[i]._id === target._id ? 1 : 0;
      if (rows[i].active === active) continue;
      b.db.from(SCRIPTS).where({ _id: rows[i]._id })
        .updateOne({ _id: rows[i]._id, active: active, updatedAt: now });
    }
    return { ok: true, active: target === null ? null : target.name };
  }

  // RFC 5804 section 2.10: the active script cannot be deleted, so a
  // mailbox is never left filtering by a script that is gone.
  function deleteScript(actor, name) {
    var account = _accountOf(actor, "DELETESCRIPT");
    _requireSieveScope(actor, "DELETESCRIPT");
    var row = _scriptRow(account, _scriptName(name, "DELETESCRIPT"));
    if (!row) {
      throw err("mailbox/no-script", "DELETESCRIPT: no script by that name.");
    }
    if (row.active === 1) {
      throw err("mailbox/script-active",
        "that script is the active one. Activate another, or deactivate this one with an " +
        "empty SETACTIVE, and then delete it.");
    }
    b.db.from(SCRIPTS).where({ _id: row._id }).deleteOne();
    return { ok: true };
  }

  function renameScript(actor, oldName, newName) {
    var account = _accountOf(actor, "RENAMESCRIPT");
    _requireSieveScope(actor, "RENAMESCRIPT");
    var from = _scriptName(oldName, "RENAMESCRIPT");
    var to = _scriptName(newName, "RENAMESCRIPT");
    var row = _scriptRow(account, from);
    if (!row) {
      throw err("mailbox/no-script", "RENAMESCRIPT: no script named '" + from + "'.");
    }
    if (_scriptRow(account, to)) {
      throw err("mailbox/script-exists", "RENAMESCRIPT: a script named '" + to + "' is already there.");
    }
    b.db.from(SCRIPTS).where({ _id: row._id })
      .updateOne({ _id: row._id, name: to, updatedAt: Date.now() });
    return { ok: true, name: to };
  }

  function haveSpace(actor, name, size) {
    var account = _accountOf(actor, "HAVESPACE");
    var scriptName = _scriptName(name, "HAVESPACE");
    var wanted = parseInt(size, 10);
    if (!isFinite(wanted) || wanted < 0) {
      throw err("mailbox/bad-argument", "HAVESPACE: the size is a whole number of bytes.");
    }
    if (wanted > MAX_SIEVE_SCRIPT_BYTES) {
      return { ok: false, reason: "a script stops at " + MAX_SIEVE_SCRIPT_BYTES + " bytes" };
    }
    if (_scriptRow(account, scriptName)) return { ok: true };
    if (b.db.from(SCRIPTS).where({ account: account }).count() >= MAX_SIEVE_SCRIPTS) {
      return { ok: false, reason: "an account keeps at most " + MAX_SIEVE_SCRIPTS + " scripts" };
    }
    return { ok: true };
  }

  /**
   * @primitive blamepost.mail.mailbox.describe
   * @signature mailbox.describe()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one readable summary per subsystem)
   * @related   blamepost.mail.mailbox.create
   *
   * What this adapter is holding, for the health endpoint and for
   * `blamepost doctor`. Counts rather than contents: the point is to
   * answer whether mailboxes exist and whether a POP3 session is
   * holding a lock, without unsealing anything.
   *
   * @example
   *   mailbox.describe().openDrops;
   *   // 0
   */
  function describe() {
    return {
      folders:   b.db.from(FOLDERS).count(),
      messages:  b.db.from(MESSAGES).count(),
      scripts:   b.db.from(SCRIPTS).count(),
      openDrops: drops.size,
      blobDir:   blobDir,
      // The regulatory posture in force, or null for none. It decides
      // whether a hard delete is refused for being too recent, so an
      // operator wondering why EXPUNGE keeps a message needs to be able
      // to read it back rather than infer it.
      posture:   posture,
    };
  }

  return {
    // The mailbox access agent this adapter drives. A server assembled
    // around an already open adapter reads it from here rather than
    // composing a second one: two agents answer every call and differ
    // only in what they refuse, so the same message is kept on one
    // protocol and destroyed on another.
    agent:           mailAgent,

    selectFolder:    selectFolder,
    statusFolder:    statusFolder,
    listFolders:     listFolders,
    accountFolders:  accountFolders,
    fetchRange:      fetchRange,
    searchScan:      searchScan,
    storeFlags:      storeFlags,
    expungeFolder:   expungeFolder,
    expungeObjects:  expungeObjects,
    moveObjects:     moveObjects,
    // The mail half of erasing an account. It is on the adapter rather
    // than in the identity layer because the rows it destroys are this
    // layer's, and a second implementation of a delete would be a second
    // answer to what a delete refuses.
    eraseAccountMail: eraseAccountMail,
    appendMessage:   appendMessage,
    onFiled:         onFiled,
    quota:           quota,
    getMetadata:     getMetadata,
    setMetadata:     setMetadata,

    openPop3Drop:    openPop3Drop,
    listMessages:    listMessages,
    getMessage:      getMessage,
    markDelete:      markDelete,
    resetPop3Drop:   resetPop3Drop,
    commitPop3Drop:  commitPop3Drop,

    legalHold: {
      place:   placeLegalHold,
      release: releaseLegalHold,
      status:  legalHoldStatus,
    },

    sieveScripts: {
      put:       putScript,
      list:      listScripts,
      get:       getScript,
      active:    activeScript,
      setActive: setActiveScript,
      "delete":  deleteScript,
      rename:    renameScript,
      haveSpace: haveSpace,
    },

    describe:     describe,
    MailboxError: MailboxError,
  };
}

module.exports = {
  create:         create,
  agent:          agent,
  assertRoleGate: assertRoleGate,
  headerBreak:    headerBreak,
  // The bounded RFC 3462 quote of a message's own headers, read by every
  // path in this server that composes a delivery report: the inbound
  // refusals, the entry the outbound spool gives up on, and the
  // cancellation an operator makes. One reader, because the caps and the
  // choice of which empty line ends the block are a decision about what
  // a peer can put into a report this server signs its name to.
  reportedHeaderBlock: reportedHeaderBlock,
  sequenceSet:    sequenceSet,
  TABLES:         TABLES,
  MAILBOX_SCOPES: MAILBOX_SCOPES,
  // What this server accepts as a keyword flag, read by the IMAP
  // SEARCH composition so KEYWORD and UNKEYWORD screen an atom against
  // the same rule STORE screens one against. Two copies of it would be
  // a keyword a client can set and cannot search for.
  KEYWORD_FLAG_RE: KEYWORD_FLAG_RE,
  MailboxError:   MailboxError,
  FOLDERS:        FOLDERS,
  MESSAGES:       MESSAGES,
  SCRIPTS:        SCRIPTS,
  METADATA:       METADATA,
  // Where a stored body lives, and the shape check in front of it. The
  // adapter above writes and reads through this, and the reconciliation
  // in the store resolves through it too: a second derivation would be a
  // second answer to where a message is, and the reconciliation exists
  // precisely to report when the files and the rows disagree. The shape
  // travels with it, because the reconciliation also has to decide
  // whether a file it found under `blobs/` is a body at all.
  blobPathFor:    blobPathFor,
  BLOB_DIGEST_RE: BLOB_DIGEST_RE,
};
