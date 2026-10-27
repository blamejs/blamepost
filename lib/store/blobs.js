// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.blobs
 * @nav    Storage and audit
 * @title  Blob reconciliation
 * @order  30
 *
 * The content-addressed octet store, and the only thing that holds it
 * against the rows that are supposed to reference it.
 *
 * A delivered message is two writes to two places that cannot be joined.
 * The octets are sealed and written under `blobs/`, named by the
 * SHA3-512 of their content; a row is then inserted naming that digest.
 * A filesystem write is not part of a database transaction and never can
 * be, so a process that stops between the two leaves one half alone, and
 * neither half complains.
 *
 * Five states follow from that, and nothing else in this server reports
 * any of them. The reference-counted release that removes a blob runs
 * only while deleting a message that still has a row, so it never sees a
 * blob whose row was lost.
 *
 *   - **Unreferenced octets.** A blob no row names. Storage that is
 *     never served, never counted and never reclaimed. Harmless to read
 *     around, and it grows.
 *   - **Missing octets.** A row naming a blob that is not on disk. An
 *     IMAP fetch and a POP3 retrieval list the message and then fail to
 *     return its body. Webmail and JMAP render from database columns and
 *     still show it, so this is an outage for one message on two of the
 *     five protocols, and it is invisible until somebody opens it there.
 *   - **Octets that are not what they are filed as.** The file is there
 *     and its seal opens, and the content no longer hashes to the digest
 *     naming it. Same outage, plus a reason to look at the volume rather
 *     than at the mailbox. Existence alone cannot see this, which is why
 *     the digest is checked rather than assumed.
 *   - **Quota charged for messages no protocol can list.** The message
 *     store's own per-folder counters move when it accepts a message.
 *     The row binding that message to a mailbox is written afterwards by
 *     the protocol adapter, so an interrupted append can leave the
 *     counter raised for a message the owner can neither read nor
 *     delete, and their mailbox fills up against nothing.
 *   - **Mail no live account holds.** A mailbox row whose account row is
 *     gone, or a message row whose mailbox row is gone. The rows are
 *     intact, so the release stays reference counted and never fires,
 *     and the bodies they name are held on the volume for as long as it
 *     exists. No protocol lists this mail, and the quota comparison
 *     cannot reach it either, because that walks mailboxes. An erasure
 *     that could not finish is where it comes from: erasing an account
 *     destroys the account row and then walks its mailboxes, and a
 *     message a preservation order or the retention floor is keeping
 *     stays with the mailbox row that holds it. A volume restored from a
 *     copy of the identity tables without the mailbox tables leaves the
 *     same state. Either way the bodies are sealed under the volume's
 *     key rather than under anything that went, so they open exactly as
 *     they did before.
 *
 * ## Reporting is separate from deleting, and deleting is age-bound
 *
 * `reconcile` never removes anything. `reclaim` removes only
 * unreferenced octets, only after they have been on disk longer than
 * `SETTLE_MS`, and only after re-reading the rows immediately before
 * each unlink.
 *
 * The settle window is the whole safety argument, so it is worth
 * stating plainly. On a server that is running, a blob with no row is
 * indistinguishable from a blob whose row is still being written: both
 * are a file on disk that nothing references yet. Deleting the second
 * destroys a message that was arriving normally. Waiting is what tells
 * them apart, because an append writes the octets and inserts the row
 * inside one call, so a blob still unreferenced a day later was not
 * mid-append.
 *
 * The window deliberately has no flag and no setting. What it guards
 * against is bounded by how long one append takes, not by anything an
 * operator decides, so a knob here would exist only to be set to zero on
 * the day somebody is in a hurry. Octets still inside the window are
 * reported as held back, with the moment they become reclaimable, so the
 * answer to "not yet" is to come back rather than to reach for an
 * override.
 *
 * Age is read from the file's modification time, which errs toward
 * keeping: anything that rewrites a file makes it look newer and holds
 * it back for another window.
 *
 * A file under `blobs/` that is not a blob at its own content-addressed
 * path is reported and never removed. Nothing here knows what it is, and
 * a reclaim that deletes what it does not recognize is a reclaim that
 * deletes an operator's note, a partial restore, or the next thing
 * somebody puts there.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var b = require("../vendor/blamejs");

// The protocol adapter owns these tables, and this module reads them
// rather than restating their names. Reading them is the point: the
// reconciliation exists precisely because the octets and these rows can
// disagree, so it has to see both.
var mailbox = require("../mail/mailbox");

var auditActor = require("./actor");
var errors = require("./errors");

var err = errors.err;

var TIME = b.constants.TIME;

// How long an unreferenced blob stays on disk before it may be removed.
// See the module note: this is the window inside which an unreferenced
// blob and an append in flight look identical from outside.
var SETTLE_MS = TIME.hours(24);

// The ceiling on one sealed blob file. A file above it is reported
// rather than read, because a reconciliation must not be the one thing
// on the server willing to pull an unbounded file into memory.
//
// Taken from the adapter that writes those files rather than restated,
// for the reason the digest shape below is taken from there: this walk
// and the read path serving IMAP BODY[] open the same files, and two
// literals would let the walk call a body unreadable while the reader
// serves it, or the reverse.
var MAX_BLOB_FILE_BYTES = mailbox.MAX_BLOB_FILE_BYTES;

// A blob is named by the hex SHA3-512 of its content. Taken from the
// adapter that names them rather than restated, because the walk below
// uses it to decide whether a file it found is a body at all, and a
// second opinion on that would classify files the reader serves as
// files nobody put there.
var DIGEST_RE = mailbox.BLOB_DIGEST_RE;

// `blobs/<first two>/<next two>/<digest>`, so two levels of fan-out and
// then the file. Nothing legitimate sits deeper, and the walk stops
// rather than descending forever into whatever a mount or a symlink
// presents.
var BLOB_FANOUT_LEVELS = 2;

/**
 * @primitive blamepost.store.blobs.pathFor
 * @signature blamepost.store.blobs.pathFor(blobDir, digest)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: content-addressed octet layout)
 * @related   blamepost.store.blobs.reconcile
 *
 * Where the octets named by one digest belong: two levels of fan-out
 * taken from the front of the digest, then the digest itself.
 *
 * The derivation itself belongs to the adapter that writes the files,
 * and this resolves through it rather than restating it. A
 * reconciliation that computed the path differently from the writer
 * would report every message missing and be believed, which is the one
 * failure this whole module exists to avoid producing.
 *
 * The digest is checked against its shape before any path is built, so
 * a value from a row that has been tampered with cannot address
 * anything outside the blob directory.
 *
 * @example
 *   blobs.pathFor("/var/lib/blamepost/blobs", digest);
 *   // /var/lib/blamepost/blobs/3a/7f/3a7f...
 */
function pathFor(blobDir, digest) {
  if (typeof blobDir !== "string" || blobDir.length === 0) {
    throw err("store/bad-argument",
      "blobs.pathFor needs the blob directory the mailbox adapter reports.");
  }
  return mailbox.blobPathFor(blobDir, digest);
}

// Every entry under the blob directory. Each one carries the path the
// directory listing reported rather than one rebuilt here, so what is
// classified below is what was actually found and no name from the
// filesystem is ever joined onto anything.
//
// Bounded rather than recursive-until-done: a directory below the two
// levels of fan-out is reported where it was found instead of being
// descended into, because a walk with no floor is a walk whatever is
// mounted there controls.
function _walk(dir, depth, into) {
  var entries = b.atomicFile.listDir(dir, { includeStat: true });
  for (var i = 0; i < entries.length; i += 1) {
    if (entries[i].isDirectory) {
      if (depth < BLOB_FANOUT_LEVELS) {
        _walk(entries[i].fullPath, depth + 1, into);
        continue;
      }
      into.push({ name: entries[i].name, path: entries[i].fullPath, sizeBytes: 0,
        mtimeMs: entries[i].mtimeMs, isDirectory: true });
      continue;
    }
    if (!entries[i].isFile) continue;
    into.push({
      name:        entries[i].name,
      path:        entries[i].fullPath,
      sizeBytes:   entries[i].sizeBytes,
      mtimeMs:     entries[i].mtimeMs,
      isDirectory: false,
    });
  }
  return into;
}

/**
 * @primitive blamepost.store.blobs.create
 * @signature blamepost.store.blobs.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: reconciling a content-addressed store against its index)
 * @related   blamepost.store.blobs.reconcile, blamepost.store.blobs.reclaim, blamepost.store.open
 *
 * Bind the reconciler to the mailbox adapter, the message store and the
 * account table it reads. Everything it answers comes from those three
 * plus the blob directory the adapter reports, so a handle built here
 * reads exactly the state the listeners are serving from.
 *
 * @opts
 *   mailbox       the protocol facing adapter, for its blob directory
 *   messageStore  the `b.mailStore` handle whose quota counters are compared
 *   accounts      the account table, so drift names an address and not an id
 *   vault         the sealed-storage pair the octets were written through
 *   snapshot      the moment the rows were frozen at, when they are frozen
 *
 * @example
 *   var handle = blobs.create({ mailbox: adapter, messageStore: store,
 *     accounts: accounts, vault: b.vault });
 *   handle.reconcile().ok;
 */
function create(opts) {
  var options = opts || {};
  if (!options.mailbox || typeof options.mailbox.describe !== "function") {
    throw new TypeError("blamepost.store.blobs.create: opts.mailbox must be the mailbox " +
      "adapter, which is what reports the blob directory");
  }
  if (!options.messageStore || typeof options.messageStore.quota !== "function") {
    throw new TypeError("blamepost.store.blobs.create: opts.messageStore must be the " +
      "b.mailStore handle whose quota counters are being compared");
  }
  if (!options.accounts || typeof options.accounts.get !== "function") {
    throw new TypeError("blamepost.store.blobs.create: opts.accounts must be the account " +
      "table, so drift can name an address rather than a row id");
  }
  if (!options.vault || typeof options.vault.unseal !== "function" ||
      !options.vault.aad || typeof options.vault.aad !== "object" ||
      typeof options.vault.aad.unseal !== "function" ||
      typeof options.vault.aad.isAadSealed !== "function") {
    throw new TypeError("blamepost.store.blobs.create: opts.vault must be the sealed " +
      "storage pair the octets were written through, and must carry aad.unseal and " +
      "aad.isAadSealed with it. A body is sealed under the message it belongs to, and the " +
      "plain pair alone cannot open one.");
  }

  var adapter      = options.mailbox;
  var messageStore = options.messageStore;
  var accounts     = options.accounts;
  var vault        = options.vault;

  // When the rows this handle reads stopped, or null when they are the
  // volume's own and the two halves below come from one moment.
  //
  // This is the only reader in the server whose answer holds a database
  // against a directory, so it is the only one a frozen row set can make
  // WRONG rather than merely old. A handle opened read-only while the
  // server runs sees rows as of the last flush and a blob directory that
  // is live, and every message delivered in between has its octets on
  // disk with its row still in the server's own copy. Reported as
  // unreferenced, that is a volume diverging on a server where nothing
  // has gone wrong.
  //
  // It is taken at construction rather than at each call for the reason
  // the descriptor exists at all: a bound a caller has to remember to
  // pass is one a new call site does not pass.
  var rowsAsOf = options.snapshot && typeof options.snapshot.takenAt === "number"
    ? options.snapshot.takenAt
    : null;

  // Every row binding a message to a mailbox, grouped by the digest it
  // names. One digest can carry several rows: identical octets
  // delivered to several accounts are stored once.
  function _referencesByDigest() {
    var rows = b.db.from(mailbox.MESSAGES).all();
    var byDigest = Object.create(null);
    for (var i = 0; i < rows.length; i += 1) {
      var digest = String(rows[i].blobDigest || "");
      if (!byDigest[digest]) byDigest[digest] = [];
      byDigest[digest].push({
        folder:    rows[i].folder,
        objectid:  rows[i].objectid,
        uid:       rows[i].uid,
        sizeBytes: rows[i].sizeBytes,
      });
    }
    return byDigest;
  }

  // Open one blob and answer whether it is the message the row points
  // at. Returns null when it is, and the reason when it is not.
  //
  // Two questions, in the order the read path serving a mailbox asks
  // them, and through the same context derivation, so this walk and that
  // read cannot come to different answers about one file. A body is
  // sealed under the name it is filed as, and the octets that come out
  // are hashed back against that name. A volume also carries bodies
  // sealed before the binding existed, which open under the plain form
  // and are placed by the hash alone, so the form is asked rather than
  // assumed: reporting those as damaged would send an operator to
  // restore a message store that is intact.
  function _digestFault(digest, path) {
    var sealed;
    try {
      sealed = b.atomicFile.readSync(path, {
        maxBytes: MAX_BLOB_FILE_BYTES,
        encoding: "utf8",
      });
    } catch (e) {
      return "the file could not be read: " + ((e && e.message) || String(e));
    }
    var opened;
    if (vault.aad.isAadSealed(sealed)) {
      try {
        opened = vault.aad.unseal(sealed, mailbox.bodySealContext(digest));
      } catch (_boundError) {
        return "it is sealed, and not as this message's body, so it is a value this volume " +
          "sealed for something else, or another message's body filed under this name, or " +
          "its bytes have been cut short or altered where they lie";
      }
    } else {
      try {
        opened = vault.unseal(sealed);
      } catch (_e2) {
        return "the seal did not open, so these octets were written under a different " +
          "vault key or the file has been altered";
      }
    }
    var raw = Buffer.from(opened, "base64");
    var actual = b.crypto.sha3Hash(raw);
    if (actual === digest) return null;
    return "the octets hash to " + actual.slice(0, 16) + "..., not to the digest naming " +
      "the file, so this is not the message the row points at";
  }

  // Whether the account a mailbox row names is still on the table.
  // Read once per mailbox rather than once per message, because the
  // answer is a property of the mailbox and the message rows under one
  // mailbox all share it.
  function _accountIsLive(folderRow) {
    var id = folderRow && folderRow.account;
    if (typeof id !== "string" || id.length === 0) return false;
    return accounts.get(id) !== null;
  }

  // Mail on the volume that no live account holds, grouped by the
  // mailbox the rows name.
  //
  // Two shapes with one consequence. A mailbox row whose account row is
  // gone, and a message row whose mailbox row is gone, which is the same
  // residue one level down. Either way the message rows survive, so the
  // reference-counted release never fires, the bodies they name are
  // never reclaimed, and no protocol lists any of it. The quota
  // comparison below walks mailbox rows, so it separates the two: the
  // mailbox row whose account row is gone is still on that table and is
  // reported there once its counter and its rows disagree, while the
  // message rows whose mailbox row is gone leave nothing on that table
  // for the walk to reach.
  //
  // Neither shape is what an erasure leaves behind. An erasure sweeps the
  // mail first and erases the account row only once nothing still names
  // it, counting every table the mailbox layer files the account's rows in
  // as well as the aliases, so mail a preservation order or the retention
  // floor keeps is mail with a live account holding it, and this reader
  // passes over it exactly as it passes over any other mailbox in service.
  //
  // Only mailboxes actually holding messages are answered for. A mailbox
  // row with nothing in it is residue too, and it pins no octets, so it
  // belongs to whatever reports on account state rather than to the
  // reader that holds the bodies against the rows.
  function _unownedMail() {
    var folders = b.db.from(mailbox.FOLDERS).all();
    var byToken   = Object.create(null);
    var liveToken = Object.create(null);
    for (var f = 0; f < folders.length; f += 1) {
      var token = String(folders[f].folder);
      byToken[token] = folders[f];
      if (_accountIsLive(folders[f])) liveToken[token] = true;
    }

    var rows = b.db.from(mailbox.MESSAGES).all();
    var held  = Object.create(null);
    // Digests already listed for a mailbox, so the distinct set is built
    // by lookup rather than by scanning the list that is being built. A
    // mailbox stranded here can hold every message an account ever
    // received, and a scan per row on that many rows is the reporting
    // verb hanging on the volume that most needs it.
    var seen  = Object.create(null);
    var order = [];
    for (var r = 0; r < rows.length; r += 1) {
      var key = String(rows[r].folder);
      if (liveToken[key] === true) continue;
      if (!held[key]) {
        var owner = byToken[key];
        seen[key] = Object.create(null);
        held[key] = {
          folder:   key,
          account:  owner ? owner.account : null,
          mailbox:  owner ? owner.wireName : null,
          messages: 0,
          // The message bytes the rows carry, which is what the mailbox
          // was charged. It is not the sealed size of the files, and the
          // two are named apart everywhere in this report because an
          // operator reading one as the other frees a volume and leaves
          // a mailbox exactly as full as it was.
          rowBytes: 0,
          digests:  [],
          detail:   owner
            ? "the mailbox is here and the account that held it is not, so nothing " +
              "lists this mail and nothing releases the bodies it names"
            : "no mailbox row holds these messages, so nothing lists them and nothing " +
              "releases the bodies they name",
        };
        order.push(key);
      }
      var entry = held[key];
      entry.messages += 1;
      entry.rowBytes += rows[r].sizeBytes || 0;
      var digest = String(rows[r].blobDigest || "");
      if (seen[key][digest] !== true) {
        seen[key][digest] = true;
        entry.digests.push(digest);
      }
    }

    var out = [];
    for (var i = 0; i < order.length; i += 1) out.push(held[order[i]]);
    return out;
  }

  // The message store counts bytes and messages per folder as it
  // accepts them; the adapter's rows are what every protocol lists. A
  // folder where the two disagree is a mailbox charged for mail nobody
  // can reach, or one serving mail the store has already forgotten.
  function _quotaDrift() {
    var folders = b.db.from(mailbox.FOLDERS).all();
    var rows = b.db.from(mailbox.MESSAGES).all();
    var perFolder = Object.create(null);
    for (var r = 0; r < rows.length; r += 1) {
      var key = String(rows[r].folder);
      if (!perFolder[key]) perFolder[key] = { count: 0, bytes: 0 };
      perFolder[key].count += 1;
      perFolder[key].bytes += rows[r].sizeBytes || 0;
    }

    var drift = [];
    for (var f = 0; f < folders.length; f += 1) {
      var seen = perFolder[String(folders[f].folder)] || { count: 0, bytes: 0 };
      var counter = null;
      var detail = null;
      try {
        counter = messageStore.quota(folders[f].folder);
      } catch (e) {
        detail = "the message store has no folder behind this mailbox, so nothing it " +
          "holds can be listed: " + ((e && e.message) || String(e));
      }
      var storeCount = counter ? counter.usedCount : null;
      var storeBytes = counter ? counter.usedBytes : null;
      if (detail === null && storeCount === seen.count && storeBytes === seen.bytes) continue;

      // How much of the drift is mail the store holds and no row names,
      // which is the part a repair removes. It is read here rather than
      // inferred from the difference above, because the two are not the
      // same number: a mailbox can hold unfiled mail and stranded rows at
      // once, and the difference then understates both. An operator
      // deciding whether to run the repair is agreeing to lose exactly
      // this, so it is the number the report shows them.
      var unfiled = [];
      if (detail === null) {
        try { unfiled = adapter.unfiledIn(folders[f].folder); }
        catch (_e) { unfiled = []; }
      }
      var unfiledBytes = 0;
      for (var u = 0; u < unfiled.length; u += 1) unfiledBytes += unfiled[u].sizeBytes || 0;

      var owner = accounts.get(folders[f].account);
      drift.push({
        account:      (owner && owner.address) || null,
        accountId:    folders[f].account,
        mailbox:      folders[f].wireName,
        folder:       folders[f].folder,
        storeCount:   storeCount,
        rowCount:     seen.count,
        storeBytes:   storeBytes,
        rowBytes:     seen.bytes,
        unfiledCount: unfiled.length,
        unfiledBytes: unfiledBytes,
        detail:       detail,
      });
    }
    return drift;
  }

  /**
   * @primitive blamepost.store.blobs.reconcile
   * @signature blobs.reconcile(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: reconciling a content-addressed store against its index)
   * @related   blamepost.store.blobs.reclaim, blamepost.store.blobs.pathFor
   *
   * Walk the blob directory and the message rows and answer with every
   * way the two disagree. Removes nothing and changes nothing, so it is
   * safe to run on a schedule and safe to run against a server that is
   * serving.
   *
   * Without `verify` a blob counts as present when the file is there,
   * which is a directory walk and a set difference. With it, every
   * referenced blob is unsealed and hashed back against the digest
   * naming it, which is the only way to see octets that have been
   * altered or truncated in place. Unreferenced blobs are not verified:
   * their content decides nothing, since nothing serves them.
   *
   * `ok` is true only when every list is empty. Unreferenced octets
   * count against it: they are not an outage, but they are a state
   * somebody has to decide about, and a report that called them clean
   * would let a crash go unnoticed until the volume filled.
   *
   * So does `unowned`, which is mail whose account row or whose mailbox
   * row is gone while the message rows are not. Those rows are what a
   * reclaim counts, so the bodies under them are held on the volume
   * permanently, and a report that passed over them would let an account
   * erasure that never reached the mail read as one that did.
   *
   * ## Reading it while the server runs
   *
   * The rows and the directory are one moment only when this handle can
   * see the rows the server is writing. Opened read-only against a
   * running server it cannot: the rows stop at the last flush and the
   * directory is live, so a body delivered in between is on disk with
   * its row still in the server's own copy. `rowsAsOf` is where the rows
   * stopped, and a body at or after it goes to `newerThanRows` rather
   * than to `orphans`. It is a body the rows had not reached, which is a
   * different fact from a body nothing references, and it does not count
   * against `ok`.
   *
   * The bound moves only that one list. `missing` is a row naming a body
   * that is not on disk, and an older row is if anything more certain of
   * that. `corrupt` unseals each referenced body and hashes it back, and
   * an altered body is altered whenever it is read. `quotaDrift` and
   * `unowned` compare rows with rows. All four are answers about the
   * volume however old the rows are.
   *
   * @opts
   *   verify  also unseal each referenced blob and re-hash it (default false)
   *   now     the moment ages are measured against (default Date.now())
   *
   * @example
   *   var report = handle.blobs.reconcile({ verify: true });
   *   report.missing.length;
   */
  function reconcile(reconcileOpts) {
    var options2 = reconcileOpts || {};
    if (options2.verify !== undefined && typeof options2.verify !== "boolean") {
      throw new TypeError("blobs.reconcile: opts.verify must be a boolean");
    }
    if (options2.now !== undefined &&
        (typeof options2.now !== "number" || !isFinite(options2.now))) {
      throw new TypeError("blobs.reconcile: opts.now must be a finite number of " +
        "milliseconds since the epoch");
    }
    var verify = options2.verify === true;
    var now = typeof options2.now === "number" ? options2.now : Date.now();

    var blobDir = adapter.describe().blobDir;
    var byDigest = _referencesByDigest();

    var orphans      = [];
    var newerThanRows = [];
    var unexpected   = [];
    var corrupt      = [];
    var onDisk       = Object.create(null);
    var bytesOnDisk  = 0;

    var found = _walk(blobDir, 0, []);
    for (var i = 0; i < found.length; i += 1) {
      var entry = found[i];
      var name = entry.name;
      var atItsOwnPath = DIGEST_RE.test(name) && entry.isDirectory === false &&
        entry.path === pathFor(blobDir, name);
      if (!atItsOwnPath) {
        unexpected.push({
          path:   entry.path,
          detail: entry.isDirectory
            ? "a directory deeper than the two levels of fan-out a blob is filed under"
            : "not a sealed message body at the path its own digest names",
        });
        continue;
      }
      onDisk[name] = entry;
      bytesOnDisk += entry.sizeBytes;

      if (byDigest[name]) {
        if (verify) {
          var fault = _digestFault(name, entry.path);
          if (fault !== null) {
            corrupt.push({ digest: name, path: entry.path, sizeBytes: entry.sizeBytes,
              reason: fault });
          }
        }
        continue;
      }

      var ageMs = now - entry.mtimeMs;
      // A body the rows had not reached yet. The comparison is at or
      // after, so a body written in the same millisecond the rows were
      // frozen reads as newer rather than as unreferenced: being wrong
      // toward "not yet known" costs a line of output, and being wrong
      // the other way tells an operator their volume is diverging.
      if (rowsAsOf !== null && entry.mtimeMs >= rowsAsOf) {
        newerThanRows.push({
          digest:    name,
          path:      entry.path,
          sizeBytes: entry.sizeBytes,
          writtenAt: entry.mtimeMs,
        });
        continue;
      }
      orphans.push({
        digest:         name,
        path:           entry.path,
        sizeBytes:      entry.sizeBytes,
        ageMs:          ageMs,
        reclaimable:    ageMs >= SETTLE_MS,
        reclaimableAt:  entry.mtimeMs + SETTLE_MS,
      });
    }

    var missing = [];
    var referenced = Object.keys(byDigest);
    for (var d = 0; d < referenced.length; d += 1) {
      if (onDisk[referenced[d]]) continue;
      var rows = byDigest[referenced[d]];
      for (var m = 0; m < rows.length; m += 1) {
        missing.push({
          digest:    referenced[d],
          folder:    rows[m].folder,
          objectid:  rows[m].objectid,
          uid:       rows[m].uid,
          sizeBytes: rows[m].sizeBytes,
        });
      }
    }

    var newerThanRowsBytes = 0;
    for (var n = 0; n < newerThanRows.length; n += 1) {
      newerThanRowsBytes += newerThanRows[n].sizeBytes;
    }

    var orphanBytes = 0;
    var reclaimableBytes = 0;
    var heldBackBytes = 0;
    var nextReclaimableAt = null;
    for (var o = 0; o < orphans.length; o += 1) {
      orphanBytes += orphans[o].sizeBytes;
      if (orphans[o].reclaimable) {
        reclaimableBytes += orphans[o].sizeBytes;
        continue;
      }
      heldBackBytes += orphans[o].sizeBytes;
      if (nextReclaimableAt === null || orphans[o].reclaimableAt < nextReclaimableAt) {
        nextReclaimableAt = orphans[o].reclaimableAt;
      }
    }

    var quotaDrift = _quotaDrift();
    var unowned    = _unownedMail();

    return {
      ok: orphans.length === 0 && missing.length === 0 && corrupt.length === 0 &&
        unexpected.length === 0 && quotaDrift.length === 0 && unowned.length === 0,
      verified:          verify,
      blobDir:           blobDir,
      blobsOnDisk:       Object.keys(onDisk).length,
      digestsReferenced: referenced.length,
      bytesOnDisk:       bytesOnDisk,
      orphans:           orphans,
      missing:           missing,
      corrupt:           corrupt,
      unexpected:        unexpected,
      quotaDrift:        quotaDrift,
      unowned:           unowned,
      // Where the rows stopped, and what was on disk after that. Null
      // and empty on the volume itself, where the two halves are one
      // moment and there is nothing to hold apart.
      rowsAsOf:            rowsAsOf,
      newerThanRows:       newerThanRows,
      newerThanRowsBytes:  newerThanRowsBytes,
      orphanBytes:       orphanBytes,
      reclaimableBytes:  reclaimableBytes,
      heldBackBytes:     heldBackBytes,
      nextReclaimableAt: nextReclaimableAt,
      settleMs:          SETTLE_MS,
    };
  }

  // The two fan-out levels a removed blob leaves behind. Emptying them
  // is tidiness rather than correctness, so a directory that is not
  // empty, or that another process is writing into, is left where it is
  // rather than turned into the error the operator reads.
  function _pruneFanOut(path) {
    var dir = nodePath.dirname(path);
    for (var level = 0; level < 2; level += 1) {
      try { nodeFs.rmdirSync(dir); }
      catch (_e) { return; }
      dir = nodePath.dirname(dir);
    }
  }

  /**
   * @primitive blamepost.store.blobs.reclaim
   * @signature blobs.reclaim(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: reconciling a content-addressed store against its index)
   * @related   blamepost.store.blobs.reconcile, blamepost.store.blobs.pathFor
   *
   * Remove the sealed octets no message row references. Only
   * unreferenced blobs, and only those that have been on disk longer
   * than the settle window, because inside that window an unreferenced
   * blob and an append still inserting its row are the same thing seen
   * from outside.
   *
   * Every candidate is re-checked against the rows immediately before
   * its file is unlinked, and one that gained a row since the walk is
   * left alone and reported. Anything still inside the window is
   * reported as held back with the moment it becomes reclaimable, so
   * "not yet" is an answer with a date on it.
   *
   * A removal the volume refuses is reported under `failed` with what it
   * said, and the walk carries on through the rest. This is a set of
   * separate removals, so one file another process holds open or one
   * permission an operator changed must not abandon every candidate
   * behind it, nor the audit row below, which is the only record that
   * the bodies already removed were ever here. Run it again once the
   * volume gives the file up: nothing removed its row, so it is still a
   * candidate.
   *
   * Nothing else is ever removed. A row whose octets are missing is not
   * repaired here, a blob that fails its digest is not deleted, and a
   * file under `blobs/` that is not a blob is left exactly where it is.
   * Each of those is a decision for the operator, and a reclaim that
   * quietly made them would be the second thing to go wrong.
   *
   * The mail `reconcile` reports as unowned is not freed here either,
   * and cannot be. Those bodies have message rows naming them, so they
   * are referenced by the only measure this verb has; deleting them
   * would remove the octets and leave the rows, which is the outage
   * under `missing` rather than a repair. Clearing that state means
   * removing the rows, which is a delete on a mailbox and belongs to the
   * verb that owns mailbox deletes.
   *
   * The reason is required and lands in the audit row's own column,
   * because the only record that these octets existed afterwards is
   * that row. The row carries how many went, how many bytes they held,
   * how many were held back and how many were left in use. It does not
   * carry the digests: a digest names octets nothing referenced and
   * nobody has, so it identifies no message and reconstructs nothing,
   * and a list of them would be unbounded on the volume that most needs
   * this verb.
   *
   * A handle whose rows are frozen refuses outright, under
   * `store/snapshot-is-read-only`. Unlinking a file is not a database
   * write, so nothing below the store can stop it: the bodies would go
   * from the live volume on the strength of rows that stopped at the
   * last flush, and the audit row that is the only record they existed
   * would then fail because the handle cannot write it. That is the one
   * shape where a reporting open destroys mail.
   *
   * @opts
   *   reason  why the octets are being removed, recorded in the audit chain
   *   now     the moment ages are measured against (default Date.now())
   *
   * @example
   *   await handle.blobs.reclaim({ reason: "octets stranded by the crash on 2026-08-22" });
   */
  async function reclaim(reclaimOpts) {
    var options3 = reclaimOpts || {};
    // Before the reason is even read. A handle that cannot record this
    // must not begin it, and the unlinks below are filesystem calls the
    // read-only database handle has no say over.
    if (rowsAsOf !== null) {
      throw err("store/snapshot-is-read-only",
        "blobs.reclaim destroys sealed message bodies on the live volume, and this handle " +
        "reads rows frozen at " + new Date(rowsAsOf).toISOString() + " rather than the " +
        "rows the server is writing. Unlinking a file is not a database write, so the " +
        "bodies would go while every message delivered since stayed unaccounted for, and " +
        "the audit row that is the only record they were here could not be written at " +
        "all. Stop the server and open the volume to reclaim.");
    }
    if (typeof options3.reason !== "string" || options3.reason.trim().length === 0) {
      throw err("store/bad-argument",
        "blobs.reclaim needs a reason. These octets are a message body, and the audit row " +
        "carrying the reason is the only record that they were here.");
    }
    var now = typeof options3.now === "number" ? options3.now : Date.now();
    var report = reconcile({ verify: false, now: now });

    var reclaimed = [];
    var skipped   = [];
    var heldBack  = [];
    var failed    = [];
    var reclaimedBytes = 0;

    for (var i = 0; i < report.orphans.length; i += 1) {
      var orphan = report.orphans[i];
      if (!orphan.reclaimable) {
        heldBack.push({ digest: orphan.digest, sizeBytes: orphan.sizeBytes,
          reclaimableAt: orphan.reclaimableAt });
        continue;
      }

      // Read the rows again, right here. The walk above is a snapshot,
      // and an append that landed since then names octets this loop is
      // about to delete: content addressing means a new message with
      // the same body reuses the file that is already on disk rather
      // than writing it again.
      if (b.db.from(mailbox.MESSAGES).where({ blobDigest: orphan.digest }).count() > 0) {
        skipped.push({ digest: orphan.digest, sizeBytes: orphan.sizeBytes,
          detail: "a message row named these octets after the walk, so they are in use" });
        continue;
      }

      // And its age again, for the same reason: a file that has been
      // rewritten since the walk is a file something is doing
      // something with.
      var stat;
      try { stat = nodeFs.statSync(orphan.path); }
      catch (_e) { stat = null; }
      if (stat === null || stat === undefined) {
        skipped.push({ digest: orphan.digest, sizeBytes: orphan.sizeBytes,
          detail: "the file was gone before it could be removed" });
        continue;
      }
      if (now - stat.mtimeMs < SETTLE_MS) {
        heldBack.push({ digest: orphan.digest, sizeBytes: orphan.sizeBytes,
          reclaimableAt: stat.mtimeMs + SETTLE_MS });
        continue;
      }

      // A verdict per file, because this is a set of separate removals
      // and any one of them can be refused: a mount that has gone
      // read-only, a permission an operator changed, another process
      // holding the file open. `force` is not a guard against those. It
      // covers a file that is already gone and nothing else.
      //
      // A refusal allowed to leave here abandons every candidate behind
      // this one, unlinked and unreported, and takes the audit row below
      // with it, which is the only record that the bodies already removed
      // were ever on the volume. So it is reported and the walk carries
      // on. The remediation is a rerun once the volume gives the file up,
      // and a rerun reaches it because nothing above removed its row.
      try {
        nodeFs.rmSync(orphan.path, { force: true });
      } catch (e) {
        failed.push({
          digest:    orphan.digest,
          sizeBytes: orphan.sizeBytes,
          detail:    "the volume refused to remove these octets: " +
            ((e && e.message) || String(e)),
        });
        continue;
      }
      _pruneFanOut(orphan.path);
      reclaimed.push({ digest: orphan.digest, sizeBytes: orphan.sizeBytes });
      reclaimedBytes += orphan.sizeBytes;
    }

    var heldBackBytes = 0;
    var nextReclaimableAt = null;
    for (var h = 0; h < heldBack.length; h += 1) {
      heldBackBytes += heldBack[h].sizeBytes;
      if (nextReclaimableAt === null || heldBack[h].reclaimableAt < nextReclaimableAt) {
        nextReclaimableAt = heldBack[h].reclaimableAt;
      }
    }

    await auditActor.record({
      action:   "blamepost.store.blobs.reclaimed",
      // A body held back or skipped is this verb declining to remove
      // something, which is the system working. A body the volume refused
      // is storage this server was asked to free and could not, and
      // recording that as a clean success is how a failing volume goes
      // unnoticed until it runs out.
      outcome:  failed.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      // The audit row has a first-class `reason` column. An auditor
      // filtering on it needs a column, not a string to search inside.
      reason:   options3.reason,
      resource: { kind: "blob_store", id: report.blobDir },
      metadata: {
        reclaimed:      reclaimed.length,
        reclaimedBytes: reclaimedBytes,
        heldBack:       heldBack.length,
        skipped:        skipped.length,
        failed:         failed.length,
      },
    });

    return {
      reclaimed:         reclaimed,
      reclaimedBytes:    reclaimedBytes,
      heldBack:          heldBack,
      heldBackBytes:     heldBackBytes,
      skipped:           skipped,
      // Octets that were due to go and are still here, each with what the
      // volume said. Empty on a run where every removal was taken.
      failed:            failed,
      nextReclaimableAt: nextReclaimableAt,
      settleMs:          SETTLE_MS,
    };
  }

  /**
   * @primitive blamepost.store.blobs.repairQuota
   * @signature blobs.repairQuota(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: reconciling a content-addressed store against its index)
   * @related   blamepost.store.blobs.reconcile, blamepost.mail.mailbox.sweepUnfiled
   *
   * End a mailbox being charged for mail no protocol can list, by
   * destroying the messages the message store holds that no mailbox row
   * names.
   *
   * `reconcile` reports the charge and this is what clears it. The
   * counter belongs to the message store and moves when the store accepts
   * a message and again when it removes one, so the repair removes what
   * should not be there and lets that arithmetic move the number.
   * **Nothing here writes a counter.** A number set by hand is one nobody
   * can derive again, and a mailbox would then read as reconciled whether
   * or not it was.
   *
   * Which sets the limit of what it can do. A counter that reads BELOW
   * the rows is the mirror state, a mailbox holding rows the message
   * store has forgotten, and nothing this server removes raises a
   * counter. Those mailboxes come back under `unrepairable` with what is
   * wrong, and the run reports `ok` false rather than claiming the volume
   * is reconciled.
   *
   * Every message goes through the delete path IMAP EXPUNGE takes, so a
   * preservation order and the retention floor refuse per message. A
   * mailbox holding one they kept goes on being charged for it and goes
   * on being reported, because the charge is real for as long as the
   * message is kept. Each entry in `kept` carries the reason and whether
   * it is something deliberately keeping the message.
   *
   * The sealed octets are not freed here. They were written before either
   * row and the row naming them never landed, so what is left under
   * `blobs/` is a body nothing references: `reclaim` frees it once it has
   * settled.
   *
   * A handle whose rows are frozen refuses outright. The removals are
   * decided against rows that stopped at the server's last write to disk,
   * so a message filed since would be invisible to the walk and its
   * mailbox judged on a state that has moved.
   *
   * A run cut off part way leaves the messages it reached destroyed and
   * every other mailbox exactly as it was, so running it again finishes.
   *
   * @opts
   *   reason  why the mail is being destroyed, recorded in the audit chain
   *
   * @example
   *   var repaired = await handle.blobs.repairQuota({
   *     reason: "the mailbox was charged for mail no protocol could list",
   *   });
   *   repaired.removed.length;
   */
  async function repairQuota(repairOpts) {
    var options4 = repairOpts || {};
    if (rowsAsOf !== null) {
      throw err("store/snapshot-is-read-only",
        "blobs.repairQuota destroys mail on the live volume, and this handle reads rows " +
        "frozen at " + new Date(rowsAsOf).toISOString() + " rather than the rows the " +
        "server is writing. A message filed since is one this walk cannot see, so its " +
        "mailbox would be judged on a state that has moved. Stop the server and open the " +
        "volume to repair.");
    }
    if (typeof options4.reason !== "string" || options4.reason.trim().length === 0) {
      throw err("store/bad-argument",
        "blobs.repairQuota needs a reason. It destroys somebody's mail, and the audit row " +
        "carrying the reason is the only record that the mail was ever here.");
    }
    var reason = options4.reason.trim();

    var driftBefore = _quotaDrift();
    var removed = [];
    var kept = [];
    var unrepairable = [];

    for (var i = 0; i < driftBefore.length; i += 1) {
      var entry = driftBefore[i];
      // A mailbox with nothing unfiled under it is the mirror state or a
      // mailbox the message store has no folder for, and neither is
      // closed by removing anything. It is named rather than passed over,
      // because the operator ran a repair and is owed an answer about
      // every mailbox the report listed.
      if (entry.unfiledCount === 0) {
        unrepairable.push({
          account: entry.account,
          mailbox: entry.mailbox,
          detail:  entry.detail !== null
            ? entry.detail
            : "the message store counts " + entry.storeCount + " message(s) and " +
              entry.storeBytes + " bytes against this mailbox and the rows list " +
              entry.rowCount + " and " + entry.rowBytes + ", with nothing under it that " +
              "the store holds and no row names. Removing mail cannot close this, and a " +
              "counter written by hand is one nothing can derive again",
        });
        continue;
      }

      // The account's own identity, which is the narrowest one that can
      // reach exactly this mailbox. Who ASKED is on the audit row, which
      // reads the scope the command opened.
      var owner = accounts.get(entry.accountId);
      if (owner === null || owner === undefined) {
        unrepairable.push({
          account: entry.account,
          mailbox: entry.mailbox,
          detail:  "the account row this mailbox belongs to is gone, so there is no " +
            "identity to destroy its mail under. `blamepost blobs report` lists it as mail " +
            "no live account holds, which is erased with the account rather than here",
        });
        continue;
      }

      var swept;
      try {
        swept = await adapter.sweepUnfiled({
          id:      owner.id,
          address: owner.address,
          domain:  owner.domain,
          roles:   ["account"],
        }, entry.mailbox, { reason: reason });
      } catch (e) {
        // Reported rather than raised, for the reason the per-file
        // verdicts in `reclaim` are: this is a set of separate removals
        // across separate mailboxes, and one refusal must not abandon the
        // mailboxes behind it nor the audit row that is the only record
        // of what already went.
        unrepairable.push({
          account: entry.account,
          mailbox: entry.mailbox,
          detail:  "the delete path refused this mailbox (" + ((e && e.code) || "unknown") +
            "): " + ((e && e.message) || String(e)),
        });
        continue;
      }

      for (var r = 0; r < swept.removed.length; r += 1) {
        removed.push({
          account:   entry.account,
          mailbox:   entry.mailbox,
          objectid:  swept.removed[r].objectid,
          sizeBytes: swept.removed[r].sizeBytes,
        });
      }
      for (var k = 0; k < swept.kept.length; k += 1) {
        kept.push({
          account:   entry.account,
          mailbox:   entry.mailbox,
          objectid:  swept.kept[k].objectid,
          sizeBytes: swept.kept[k].sizeBytes,
          reason:    swept.kept[k].reason,
          preserved: swept.kept[k].preserved,
          detail:    swept.kept[k].detail,
        });
      }
    }

    // Measured again rather than inferred from what went. The counter is
    // the message store's and the rows are this layer's, and the whole
    // reason this verb exists is that the two can disagree, so the answer
    // to whether they still do is a second reading rather than
    // arithmetic over the first.
    var driftAfter = _quotaDrift();

    var removedBytes = 0;
    for (var m = 0; m < removed.length; m += 1) removedBytes += removed[m].sizeBytes;

    await auditActor.record({
      action:   "blamepost.store.blobs.quota_repaired",
      // A message a preservation order or the floor kept is this verb
      // declining to destroy something, which is the system working. A
      // mailbox nothing here repairs is a volume an operator still has to
      // act on, and recording that as a clean success is how it goes
      // unnoticed.
      outcome:  unrepairable.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "mail_store", id: adapter.describe().blobDir },
      metadata: {
        driftBefore:  driftBefore.length,
        driftAfter:   driftAfter.length,
        removed:      removed.length,
        removedBytes: removedBytes,
        kept:         kept.length,
        unrepairable: unrepairable.length,
      },
    });

    return {
      // True only when no mailbox is left disagreeing with its counter.
      // A message kept under a preservation order leaves one, and that is
      // the verb working rather than failing, but the mailbox is still
      // charged and the operator still has to know.
      ok:           driftAfter.length === 0,
      driftBefore:  driftBefore,
      driftAfter:   driftAfter,
      removed:      removed,
      removedBytes: removedBytes,
      kept:         kept,
      unrepairable: unrepairable,
    };
  }

  return {
    reconcile:   reconcile,
    reclaim:     reclaim,
    repairQuota: repairQuota,
  };
}

module.exports = {
  create:    create,
  pathFor:   pathFor,
  SETTLE_MS: SETTLE_MS,
};
