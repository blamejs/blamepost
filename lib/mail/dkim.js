// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.mail.dkim
 * @nav      DNS and domain authentication
 * @title    DKIM signing and selector lifecycle
 * @order    20
 * @featured true
 *
 * @intro
 *   Outbound DKIM signing, plus the rotation procedure that keeps mail
 *   already in flight verifiable.
 *
 *   ## Two signatures per message
 *
 *   Every domain gets a pair of keys and a pair of selectors. The
 *   framework's `b.mail.dkim.dualSigner` emits one `DKIM-Signature`
 *   header per algorithm, which is the RFC 8463 §3 dual signing
 *   pattern: a receiver that verifies `ed25519-sha256` uses the modern
 *   signature, one that only knows RFC 6376 `rsa-sha256` uses the
 *   other, and no per receiver negotiation is needed. Those two are
 *   the algorithms the DKIM-Signature `a=` tag admits today, which is
 *   the same as saying they are the two a receiver can check.
 *
 *   Key material at rest gets the post-quantum answer, because that is
 *   the half of the problem this project can decide on its own: every
 *   private key is sealed through the framework vault, whose envelope
 *   is an ML-KEM-1024 and P-384 hybrid with XChaCha20-Poly1305. A
 *   stolen data volume yields no usable signing key.
 *
 *   Each key is sealed to the selector it belongs to rather than to the
 *   volume at large, so the seal says which key it carries. A value
 *   sealed as anything else, and a key belonging to another selector or
 *   another domain, does not open here at all. `reseal` is the one-time
 *   run that moves a volume whose keys were sealed before that binding
 *   existed, and a key it has not reached yet still signs: such a key is
 *   opened and checked against the public half its own record publishes
 *   exactly as a bound one is.
 *
 *   ## Where the two halves live
 *
 *   The public half is a row in the store's selector table, which is
 *   also what the admin interface renders and what `blamepost doctor`
 *   compares against the live zone. The private half is a sealed file
 *   under `<dataDir>/keys`, named by the `keyRef` on that row. One
 *   record of what exists, one place the secret lives.
 *
 *   ## Rotation without breaking mail already sent
 *
 *   A signing key cannot simply be replaced. Mail signed with the old
 *   key is still in transit, still queued at a receiver, still waiting
 *   out a greylist window. If the old selector's record leaves the
 *   zone the moment a new key starts signing, all of that mail fails
 *   DKIM and lands wherever the domain's DMARC policy sends failures.
 *   So rotation is three moves, each its own operator action:
 *
 *   `rotate` mints a replacement pair and returns its records. Both
 *   pairs are active from that moment, so a message carries all four
 *   signatures: the old two verify immediately, the new two verify as
 *   soon as their records resolve. A receiver needs one aligned pass,
 *   so nothing fails in between.
 *
 *   `retire` moves the previous pair out of signing once the operator
 *   confirms the new records resolve. Its records stay in the zone for
 *   the overlap the store applies, and its private keys are erased at
 *   that moment, because nothing will sign with them again and keeping
 *   them only widens what a stolen volume yields.
 *
 *   `sweep` reports the retired selectors whose overlap has elapsed and
 *   removes their rows. That is the point at which pulling the DNS
 *   record is safe. Nothing here pulls it: `blamepost.dns` publishes a
 *   record when an operator has given this server a hosted-DNS
 *   credential, and it removes none on any setting, so a record that has
 *   finished its overlap is withdrawn by the operator either way.
 *
 *   ## What the trail says about a key
 *
 *   Whoever holds a signing key signs mail as the domain, and the damage
 *   outlives the rotation that ends it, so each verb that touches key
 *   material leaves a row naming the operator who ran it:
 *   `blamepost.mail.dkim.keys_generated`, `keys_rotated`, `keys_retired`,
 *   `selectors_swept` and `keys_resealed`. Together they are the timeline
 *   an incident reads to place a signature: when a selector started
 *   signing, when a replacement joined it, when it stopped, when its
 *   record was allowed to leave the zone, and when the key at rest was
 *   rewritten under a seal of its own.
 *
 *   A rotation row names both sides. The question asked of a signature
 *   is which key was live when the message was signed, and this is the
 *   only moment the outgoing and incoming names are in one place.
 *
 *   A refused attempt is recorded as readily as a completed one. Nothing
 *   in the store is reached by a refusal, so without these rows a
 *   refused mint over a live selector leaves no trace at all, and that
 *   is exactly the attempt an incident goes looking for. The outcome
 *   separates a refusal, which leaves the domain as it was, from a run
 *   that stopped part way and can leave a sealed key on the volume that
 *   nothing will sign with.
 *
 *   What identifies a key in a row is its selector and its algorithm,
 *   which is what a receiver already reads off a signature. No key bytes
 *   and no digest of either half ever reach a row: both are a way to
 *   confirm a guessed private key without a request reaching this
 *   server, and the chain is append-only, so a value written into it
 *   once cannot be taken back out.
 *
 *   Writing the row never decides whether the operation happened. Each
 *   verb runs to its own conclusion first and then records what went, so
 *   an audit sink that cannot write drops the row and leaves the
 *   rotation alone. The identity itself is read through the scope the
 *   entry point established, which hands back a settled shape and cannot
 *   fail here.
 *
 * @card
 *   Signs outbound mail for each hosted domain with an Ed25519 and an
 *   RSA-SHA256 DKIM signature, using private keys sealed in the vault.
 *   `rotate` adds a new key pair beside the current one, `retire` stops
 *   signing with the old pair, and `sweep` lists the retired selectors whose
 *   DNS records can now be removed.
 */

var nodeCrypto = require("node:crypto");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var b = require("../vendor/blamejs");

// The one screen this server puts between text somebody else wrote and a
// person reading it. A selector name arrives from an operator's command
// line, a refusal quotes it back, and both land in an append-only row
// that `blamepost audit read` prints in a terminal. Reading it through
// the shared screen rather than a table of this module's own is what
// keeps one answer to what a terminal acts on.
var displayText = require("../text");

// The identity the surrounding work established, which is what a
// key-lifecycle row has to name. It lives with the identity layer
// because that is where every other emit site reads it from, and one
// mechanism read by every site is the point of it: a second scheme for
// carrying the operator down here would be a second thing to keep in
// step, and the browser surface already reaches across for the same
// reason.
var auditActor = require("../store/actor");

// The one derivation that decides which domain a name means. The
// selector rows this module writes are keyed on what it returns, and so
// is the sealed key file each row points at, so reading the name any
// other way here would key the two halves of one domain on two strings.
var address = require("../store/address");

// The data volume's layout is settled in one place, and the guard that
// refuses a base path nothing can be joined onto safely lives with it.
// It matters most here: this module unlinks the files it names.
var configModule = require("../config");

var BYTES = b.constants.BYTES;

// The namespace every audit action in this file is written under, and
// the first segment `b.audit` reads to decide whether a row may land.
// An action under a namespace nobody registered is refused, and the
// refusal is invisible from here, so the module registers its own
// rather than assuming a composer did. Registration is idempotent, so a
// caller that already did it loses nothing.
//
// Each verb writes its full action name where it emits rather than
// through a constant, so a reader of that line sees which namespace the
// row is filed under without following a name somewhere else. The five
// are `blamepost.mail.dkim.keys_generated`, `keys_rotated`,
// `keys_retired`, `selectors_swept` and `keys_resealed`, and each is what
// an operator types after `--action`, so renaming one breaks a filter
// somebody has written down.
var AUDIT_NAMESPACE = "blamepost";

// The longest run of text copied out of an operator's command line that
// reaches a row. A refusal quotes the name it was given, and a name that
// was refused is a name nothing has bounded yet, so an unbounded copy
// would let whoever typed it choose how large this server's audit rows
// are. The bound is set above the longest refusal this module writes, so
// a legitimate one arrives whole.
var MAX_RECORDED_CHARS = 1024;

// The refusal a caller branches on carries a stable code. `sign` runs
// once per message on the relay path and its caller relays the message
// unsigned when it refuses, so the record that caller writes is the only
// place the cause is visible at all. A domain with no selector is a
// setup state that ends when setup ends, which is what the record has to
// say and what an operator filters on. Codes are part of the contract,
// so renaming one is a breaking change.
//
// The framework ships its own `DkimError` and marks it with an
// `isDkimError` flag, so this class takes a name of its own rather than
// making two unrelated error families answer to one duck-type check.
//
// Every refusal written FOR A PERSON carries a code, and that is what
// makes it one. A caller showing an operator why a selector change was
// not made has to tell a refusal this module composed from a fault it
// never composed at all: a volume that cannot be written raises an error
// whose message carries the data directory, the key file naming scheme
// and the temporary suffix an atomic write appends, and none of that is
// an answer to show anybody. The code is the difference, so a surface can
// show the message it recognizes and log the one it does not, exactly as
// the identity layer's `store/` codes let it. Codes are part of the
// contract, so renaming one is a breaking change.
//
// What stays a plain throw is an argument this module was handed in the
// wrong shape. Those name an option rather than a thing an operator
// typed, and a caller that showed one would be quoting internal
// vocabulary at somebody who cannot act on it.
var DkimSigningError = b.frameworkError.defineClass("DkimSigningError", { alwaysPermanent: true });
var err = DkimSigningError.factory;

// Every code this module composes, each named once and thrown by that
// name, so the exported set below is the vocabulary itself rather than a
// list beside it that somebody has to remember to add to.
//
// The set exists because the prefix does not identify an author. The
// framework's own DKIM errors are coded `dkim/...` as well:
// `dkim/bad-rsa-bits`, `dkim/bad-selector`, `dkim/missing-private-key`,
// `dkim/dual-signer-missing` and the rest of the family it raises while
// generating a key or building a signer. Read as a prefix those cannot
// be told from the refusals here, so a surface matching on `dkim/`
// renders whichever author happened to raise first, in whichever
// vocabulary that author writes for. The framework writes for whoever
// composed the framework: its messages name its own option paths and
// quote its own primitive names, neither of which an operator can act on
// or asked to see.
//
// A longer prefix is not the answer, because it is the same mechanism a
// character further along and the next code either author adds falls
// outside whatever was matched. A closed set is: membership is decided
// by what this module actually throws, and nothing the framework invents
// can enter it.
var NO_ACTIVE_SELECTOR      = "dkim/no-active-selector";
var KEY_UNREADABLE          = "dkim/key-unreadable";
var KEY_NOT_SEALED          = "dkim/key-not-sealed";
var KEY_SEAL_UNOPENED       = "dkim/key-seal-unopened";
var KEY_SEAL_FOREIGN        = "dkim/key-seal-foreign";
var KEY_RECORD_MISMATCH     = "dkim/key-record-mismatch";
var KEYS_NOT_RESEALED       = "dkim/keys-not-resealed";
var SELECTOR_NAME_COLLISION = "dkim/selector-name-collision";
var SELECTOR_TAKEN          = "dkim/selector-taken";
var SELECTOR_NAME_TOO_LONG  = "dkim/selector-name-too-long";
var KEYS_ALREADY_ACTIVE     = "dkim/keys-already-active";
var NO_SUCH_SELECTOR        = "dkim/no-such-selector";
var KEYS_STRANDED           = "dkim/keys-stranded";
var KEY_FILE_HELD           = "dkim/key-file-held";

// Headers that carry the meaning of the message. Signing these binds
// the identity, the routing, the subject and the threading position, so
// a replay that rewrites any of them breaks the signature.
var DEFAULT_HEADERS_TO_SIGN = Object.freeze([
  "from", "to", "cc", "subject", "date", "message-id",
  "in-reply-to", "references", "mime-version", "content-type",
]);

// A sealed private key file is small. Anything larger on disk is
// corruption rather than key material.
var MAX_KEY_FILE_BYTES = BYTES.kib(64);

// What the vault writes in front of everything it seals, read from the
// framework rather than spelled again here. A value without it is passed
// straight back by `unseal` rather than refused, so this is the only
// thing that separates a sealed key from a file that holds whatever
// somebody put in it.
var VAULT_SEAL_PREFIX = b.constants.VAULT_PREFIX;

// What a private signing key is sealed under.
//
// The plain seal above binds a value to the volume and to nothing else,
// so every sealed value one volume holds opens in place of every other:
// the provider token, an account secret and a signing key are one
// another's substitutes as far as the vault is concerned, and the file
// name is the only thing saying which is which. The authenticated-data
// seal binds the value to a context instead, and a value sealed under a
// different one does not open at all.
//
// The context names the purpose and the key. The purpose is the module
// that owns the value and the thing the value is, spelled the way the
// zone credential's is: a constant rather than a path, so moving the
// keys folder does not make every key on every volume unopenable. The
// three fields beside it are the domain, the selector and the algorithm,
// which are exactly what the key file is named from and exactly what the
// selector row carries, so the context is derivable from the row and
// from nothing else on the volume.
//
// The three fields are what the purpose alone cannot do. Two keys this
// server minted carry the same purpose, so a purpose-only seal lets one
// selector's key open as another's, and a key file copied out of a
// second domain TOGETHER with the selector row that names it passes the
// derivation check below as well, because the copied record and the
// copied key agree with each other. Naming the key in its own seal is
// what closes that: the value opens for the selector it was minted for
// and for no other.
//
// Changing this tuple makes every key already on every volume
// unopenable, and a signing key has one copy. It is a wire format for
// the data volume rather than an implementation detail.
var KEY_SEAL_PURPOSE = "blamepost.mail.dkim.signing-key";

function _keySealContext(domain, selector, algorithm) {
  return {
    purpose:   KEY_SEAL_PURPOSE,
    domain:    domain,
    selector:  selector,
    algorithm: algorithm,
  };
}

// The two algorithm names the store records, which differ from the
// values that appear in a signature's a= tag. The store names the key
// family; the signature names the family and the hash.
var ALG_EDDSA = "ed25519";
var ALG_RSA = "rsa-sha256";

// How an Ed25519 public key is published. RFC 8463 §3 puts the raw
// 32-byte key in the `p=` tag rather than the SubjectPublicKeyInfo
// wrapper that RFC 6376 §3.6.1 uses for RSA, and those raw bytes are the
// tail of the SPKI encoding.
var ED25519_PUBLIC_KEY_BYTES = 32;

// The canonicalization forms a DKIM signature can name. RFC 6376 §3.4
// defines exactly two algorithms for the header and two for the body,
// and the `c=` tag names one of each, so these four are the whole of
// what the standard allows rather than a list borrowed from a signer.
// They are stated here for the reason the RSA floor below is: a value
// the signer refuses comes back worded for whoever composed it, naming
// its own option path, and the signer is not built until the first
// message from the first domain. Refusing at the entry point means a
// mistyped form is found when the server starts.
var CANONICALIZATION_FORMS = Object.freeze([
  "relaxed/relaxed", "relaxed/simple", "simple/relaxed", "simple/simple",
]);

// The smallest RSA modulus this server will mint. RFC 8301 §3.2 requires
// signers to use at least 1024 bits and says they SHOULD use at least
// 2048, and the Gmail sender requirements in force since February 2024
// state the same two numbers. This server enforces 2048 as its floor.
// The generator underneath still admits 1024 bits as an opt-in; this
// server does not, so the number is stated here rather than inherited.
var MIN_RSA_BITS = 2048;

// One DNS label, which is what RFC 1035 §2.3.1 allows and what RFC 6376
// §3.1 needs a selector to be for `<selector>._domainkey.<domain>` to be
// publishable. The store records the same shape and folds the name to
// lower case, so a selector is folded here before it reaches either the
// key file name or the row. A name that differs only in case is the same
// selector, and finding that out after the key file is written means the
// write has already landed on top of the live one.
var SELECTOR_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// The longest key file name the store will record. A domain and a
// selector that are each inside their own limits can still name a file
// past this, and the store refuses it, so the length is measured here,
// before any key material exists, rather than discovered afterwards.
var MAX_KEY_REF_CHARS = 128;

// What `_keyRef` adds around the domain and the selector: two
// separators, the algorithm, and the suffix. Used to work out the
// longest selector a domain can carry, so a refusal can say what would
// fit instead of only what did not.
function _keyRefOverhead(algorithm) {
  return ".".length + ".".length + algorithm.length + ".sealed".length;
}

// The folder under the data directory where every sealed private key
// lives, and the path one `keyRef` names inside it.
//
// Both sit at module level rather than inside the handle, because the
// selector rows that carry a keyRef are deleted by the identity layer
// and the file each row named has to go with it. One place decides what
// a keyRef resolves to on disk; a second spelling of the folder
// somewhere else would be a second answer to which file a row is talking
// about, and the row is the only thing that can find the file at all.
var KEY_FOLDER = "keys";

function _keyDirOf(dataDir) {
  return nodePath.join(dataDir, KEY_FOLDER);
}

// A keyRef is a leaf name and nothing else. The store screens it on the
// way into the column, and it is screened again here because this is the
// reading that decides which file gets unlinked: a name carrying a
// separator or a traversal segment would reach outside the keys folder,
// and an unlink is the wrong place to find out that a column was written
// by something other than this server.
function _plainKeyRef(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(label + ": every keyRef must be a non-empty file name");
  }
  if (value.indexOf("/") !== -1 || value.indexOf("\\") !== -1 ||
      value === "." || value === ".." || nodePath.isAbsolute(value)) {
    throw new TypeError(label + ": keyRef " + JSON.stringify(value) +
      " is not a plain file name inside the keys folder, so nothing will be erased for it");
  }
  return value;
}

function _keyPathOf(dataDir, keyRef, label) {
  return nodePath.join(_keyDirOf(dataDir), _plainKeyRef(keyRef, label));
}

// What a sealed private key is called while the caller settles the rows
// that name it.
//
// Erasing a key and deleting the row that named it are one change made
// of two writes that nothing spans: the filesystem cannot join a
// database transaction. Whichever one is left alone is the wrong state,
// and they are not equally wrong. A row without its key is a published
// record for a signature the domain can no longer make, so every message
// it sends fails DMARC alignment; a key without its row is signing
// material with nothing able to name it, on this volume and in every
// backup taken afterwards. So the file leaves its place FIRST and comes
// back if the rows are not settled, which is what this name is for: it
// is not the name any row points at, so nothing signs with the file
// while it is here, and it is derived from the name a row DOES point at,
// so a row that is still published still finds it.
//
// It also has to be a name no minted key can already carry, because a
// rename onto an existing file destroys that file on the platforms where
// rename overwrites. Every key this server mints ends in `.sealed`, so a
// name ending here is not one of them; a keyRef that arrived from
// somewhere else and collides is refused rather than renamed over.
var ERASING_SUFFIX = ".erasing";

// One key file moved aside, or the reason it would not move. Written
// once because staging and restoring are the same rename in opposite
// directions, and a second spelling of it would be a second answer to
// what a key is called while it is in neither place.
function _renameKeyFile(from, to) {
  try { b.atomicFile.renameWithRetry(from, to); return null; }
  catch (e) {
    if (e && e.code === "ENOENT") return "absent";
    return (e && e.code) || "unknown";
  }
}

/**
 * @primitive blamepost.mail.dkim.eraseKeyFiles
 * @signature blamepost.mail.dkim.eraseKeyFiles(dataDir, keyRefs, decide?)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 6376 section 3.6.1
 * @related   blamepost.mail.dkim.retire, blamepost.store.domains.remove
 *
 * Erase the sealed private keys that a set of selector rows named, and
 * settle those rows in the same breath.
 *
 * A selector row is the only handle this server has on the file its
 * `keyRef` points at. Nothing walks the keys folder during normal
 * operation, so a row deleted without this leaves a signing key for the
 * domain on the volume permanently, and in every backup bundle taken
 * afterwards. Whoever holds that key signs mail as the domain, which is
 * the whole of what a DKIM signature asserts, and that stays true after
 * the domain is re-hosted somewhere else. So the material leaves its
 * place before the row does, and a file that could not be moved still
 * has the row that names it.
 *
 * Every name is checked before anything is touched, so a set carrying
 * one that does not name a file inside the keys folder is refused whole
 * rather than part way through.
 *
 * `decide` is what makes the two halves one change. Without it the files
 * are simply unlinked, which is what retirement wants: it moves the rows
 * out of signing first and erases after, on purpose, because a retiring
 * selector keeps its record published while nothing signs with it. With
 * it the erasure runs in two moves. Every named file is renamed aside
 * first, `decide` runs, and only then is anything destroyed: a truthy
 * answer unlinks the files, a falsy one puts them back where they were.
 *
 * Both the rename and `decide` run before this suspends, so a caller
 * that settles its rows inside `decide` settles them against the volume
 * as it stands rather than as it stood, with nothing able to run in
 * between. That is the whole point of the hook: a refusal decided before
 * an erasure and raised after it is a refusal about a volume that has
 * already changed, and by then the keys are gone and the rows are not.
 * `decide` therefore has to answer synchronously, and one that returns a
 * promise is refused with everything put back.
 *
 * The answers, because each needs saying separately. `committed` is
 * whether `decide` said to go ahead, and `verdict` is what it answered,
 * so a caller can carry its own refusal out through it. `erased` is what
 * this call destroyed. `absent` is a key that had already gone, which is
 * ordinary rather than a fault, for the retirement reason above.
 * `restored` is a key put back because `decide` refused. `stranded` is a
 * file that would not leave its place, so nothing was destroyed and the
 * rows that name it are untouched. `leftAside` is the one answer that
 * needs somebody to go and look: the file moved but would not finish the
 * journey, so it is sitting under the name in `setAside` and no row will
 * find it there.
 *
 * A key found ALREADY set aside with nothing in its place is one an
 * earlier run left half moved, and this puts it back before staging it
 * again, so the rerun the earlier refusal named actually reaches it.
 * Found set aside with the key ALSO in its place, it refuses with
 * `already-set-aside`: two files, and nothing here can say which one the
 * rows mean, so neither is touched.
 *
 * @example
 *   var swept = await blamepost.mail.dkim.eraseKeyFiles(dataDir, [row.keyRef], function () {
 *     return b.db.transaction(function () { return _deleteRowIfStillOurs(row); });
 *   });
 *   swept.committed;   // false when the decision refused; nothing was destroyed
 */
async function eraseKeyFiles(dataDir, keyRefs, decide) {
  var label = "blamepost.mail.dkim.eraseKeyFiles";
  if (typeof dataDir !== "string" || dataDir.length === 0) {
    throw new TypeError(label + ": dataDir is required " +
      "(sealed private keys live at <dataDir>/" + KEY_FOLDER + ")");
  }
  configModule.assertAbsoluteDataDir(label + ": dataDir", dataDir);
  if (!Array.isArray(keyRefs)) {
    throw new TypeError(label + ": keyRefs must be an array of file names, which is what " +
      "a selector row's keyRef column holds");
  }
  if (decide !== undefined && decide !== null && typeof decide !== "function") {
    throw new TypeError(label + ": decide must be a function when it is given, because it " +
      "is what settles the selector rows these keys belong to");
  }
  // Settled before anything is touched. A name this cannot resolve is a
  // refusal that has erased nothing, rather than one found half way
  // through a set with some of the files already gone.
  var targets = keyRefs.map(function (ref) { return _keyPathOf(dataDir, ref, label); });

  var out = {
    committed: true,
    verdict:   undefined,
    erased:    [],
    absent:    [],
    restored:  [],
    stranded:  [],
    leftAside: [],
  };

  if (decide === undefined || decide === null) {
    for (var i = 0; i < targets.length; i += 1) {
      try {
        await nodeFs.promises.rm(targets[i]);
        out.erased.push(keyRefs[i]);
      } catch (e) {
        if (e && e.code === "ENOENT") { out.absent.push(keyRefs[i]); continue; }
        out.stranded.push({ keyRef: keyRefs[i], reason: (e && e.code) || "unknown" });
      }
    }
    return out;
  }

  // From here to the end of `decide` nothing suspends. The rename is the
  // framework's synchronous one and the decision is required to be
  // synchronous too, so the whole of "move the material aside, settle the
  // rows, commit or put it back" is one run that nothing else in this
  // process can cut in half. That is what makes a refusal inside
  // `decide` a refusal about the volume the erasure is standing on.
  var staged = [];
  var held   = null;
  for (var s = 0; s < targets.length; s += 1) {
    var aside = targets[s] + ERASING_SUFFIX;
    // A file already sitting under the staged name is a previous run
    // that stopped between the two moves.
    //
    // Two states wear that name and they need opposite answers. If the
    // key is ALSO in its place, there are two files and nothing here can
    // say which one the rows mean, so renaming onto it would destroy
    // signing material and this stops and says so instead.
    //
    // If the key is NOT in its place, the previous run moved it out and
    // could not put it back, and its rows were left untouched pointing
    // at a name with nothing under it. That is a stuck state rather than
    // an ambiguous one: putting the file back is the repair, it is the
    // repair the operator was otherwise told to perform by hand, and it
    // overwrites nothing because there is nothing there. Refusing it
    // instead made every later run answer `already-set-aside` for as
    // long as the volume stood, so the refusal that told the operator to
    // run this again was a refusal a rerun could never clear.
    if (nodeFs.existsSync(aside)) {
      if (nodeFs.existsSync(targets[s])) {
        held = { keyRef: keyRefs[s], reason: "already-set-aside" };
        break;
      }
      var recovered = _renameKeyFile(aside, targets[s]);
      if (recovered !== null) {
        held = { keyRef: keyRefs[s], reason: recovered === "absent" ? "unknown" : recovered };
        break;
      }
    }
    var moved = _renameKeyFile(targets[s], aside);
    if (moved === null) { staged.push({ keyRef: keyRefs[s], from: targets[s], to: aside }); continue; }
    if (moved === "absent") { out.absent.push(keyRefs[s]); continue; }
    held = { keyRef: keyRefs[s], reason: moved };
    break;
  }

  if (held !== null) {
    out.committed = false;
    out.stranded.push(held);
    _restoreStaged(staged, out);
    return out;
  }

  var verdict;
  try { verdict = decide(); }
  catch (e) { _restoreStaged(staged, out); throw e; }

  if (verdict !== null && verdict !== undefined && typeof verdict.then === "function") {
    _restoreStaged(staged, out);
    throw new TypeError(label + ": decide answered with a promise. It has to answer " +
      "synchronously, because anything it awaits is a window in which the rows it is " +
      "deciding about can change while these keys are already out of their place");
  }

  out.verdict = verdict;
  if (!verdict) {
    out.committed = false;
    _restoreStaged(staged, out);
    return out;
  }

  // The rows are settled and this is the only thing left. Nothing here
  // decides anything, so nothing here raises: a file that will not go
  // now is reported under the name it is sitting at, because the rows
  // that could have found it are already gone.
  for (var c = 0; c < staged.length; c += 1) {
    try {
      await nodeFs.promises.rm(staged[c].to);
      out.erased.push(staged[c].keyRef);
    } catch (e2) {
      if (e2 && e2.code === "ENOENT") { out.absent.push(staged[c].keyRef); continue; }
      out.leftAside.push({
        keyRef:   staged[c].keyRef,
        setAside: nodePath.basename(staged[c].to),
        reason:   (e2 && e2.code) || "unknown",
      });
    }
  }
  return out;
}

// Every staged key put back where it was, recorded either way.
//
// Synchronous, and it has to be: a restore that suspended would reopen
// the window the staging closed, and it runs on the path where the
// caller has already decided to change nothing. It raises nothing for
// the same reason the commit does not. The caller is on its way to a
// refusal it composed itself, and a fault from here would replace that
// refusal with one about a rename, which answers a question nobody
// asked. A key that would not go back is in `leftAside` under the name
// it is sitting at, which is the one thing an operator can act on.
function _restoreStaged(staged, out) {
  for (var i = 0; i < staged.length; i += 1) {
    var back = _renameKeyFile(staged[i].to, staged[i].from);
    if (back === null) { out.restored.push(staged[i].keyRef); continue; }
    out.leftAside.push({
      keyRef:   staged[i].keyRef,
      setAside: nodePath.basename(staged[i].to),
      reason:   back,
    });
  }
}

// Selector shape this server mints: a stable prefix plus the year and
// month, so a zone's records read as a timeline.
function _defaultSelector(now) {
  var d = new Date(now);
  var month = String(d.getUTCMonth() + 1);
  if (month.length < 2) month = "0" + month;
  return "bp" + d.getUTCFullYear() + month;
}

// Which domain a name means, folded through the one derivation the
// identity layer owns.
//
// Every verb below reaches the selector rows through the store, which
// folds the name it is given, and the key file, the signer cache and
// the framework's own signer are reached with whatever this returns. So
// this has to answer with the same name the store would, or the two
// halves of one domain are keyed on two strings: the row says
// `example.com` while the sealed key it points at is named for
// `example.com.`, and the signer built for one is not the signer found
// for the other.
//
// Folding here rather than in each caller is what makes the answer the
// same whichever surface asked. The command line folds a name before it
// reaches any of this and the browser console does not, and a signer
// that trusted its callers to have done it would answer those two
// differently for the same domain.
//
// It also keeps the framework's own vocabulary off an operator's page.
// The framework's signer holds a name against a shape that has no room
// for the absolute form, and a name that reaches it unfolded comes back
// refused in the words of whoever composed the framework, naming an
// option path an operator cannot act on. Measured here, it never gets
// there, and the refusal an operator reads is this server's own.
function _assertDomain(domain, label) {
  return address.canonicalDomain(domain, label + ": domain");
}

// The `p=` value a receiver resolves for one key, worked out from the
// private half this server signs with.
//
// It is the reading that answers whether the two halves of a selector
// still belong together. The public half is a column on a selector row
// and the private half is a sealed file the row points at, and nothing
// keeps them in step: the row is what `dkim records` prints, what the
// admin interface renders and what `blamepost doctor` compares against
// the live zone, and every one of those readings answers off the row.
// A file that unseals and parses therefore signs without a word, under
// a record carrying somebody else's key, and the only place it shows up
// is the domain's own DMARC failure reports.
//
// The two forms are the two `_txtValue` publishes, so what this returns
// is directly comparable with the column: RFC 8463 §3 publishes an
// Ed25519 key as the raw 32 bytes, which are the tail of its
// SubjectPublicKeyInfo encoding, and RFC 6376 §3.6.1 publishes an RSA
// key as the whole SubjectPublicKeyInfo. The framework computes the same
// two when it mints a pair and exposes no reader for an existing key, so
// the derivation is stated here against the RFCs rather than borrowed.
function _publishedHalfOf(privateKeyPem, algorithm) {
  var spki = nodeCrypto.createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "der" });
  if (algorithm === ALG_EDDSA) {
    return spki.subarray(spki.length - ED25519_PUBLIC_KEY_BYTES).toString("base64");
  }
  return spki.toString("base64");
}

// RFC 6376 §3.6.1 record text for one selector. The `k=` tag names the
// key family, so a receiver refuses a signature whose algorithm
// disagrees with the published key rather than guessing.
function _txtValue(algorithm, publicKeyBase64) {
  return "v=DKIM1; k=" + (algorithm === ALG_EDDSA ? "ed25519" : "rsa") +
    "; p=" + publicKeyBase64;
}

// RFC 1035 §3.3.14 caps one TXT character string at 255 octets, so a
// long RSA record is published as several quoted strings.
function _zoneLine(dnsName, value) {
  var parts = [];
  if (value.length <= 255) parts.push('"' + value + '"');
  else for (var i = 0; i < value.length; i += 255) parts.push('"' + value.slice(i, i + 255) + '"');
  return dnsName + ". IN TXT (" + parts.join(" ") + ")";
}

function _present(row) {
  var dnsName = row.selector + "._domainkey." + row.domain;
  var dnsTxtValue = _txtValue(row.algorithm, row.publicKey);
  return {
    domain:      row.domain,
    selector:    row.selector,
    algorithm:   row.algorithm,
    state:       row.status,
    retiresAt:   row.retiresAt === undefined ? null : row.retiresAt,
    keyRef:      row.keyRef,
    publicKey:   row.publicKey,
    dnsName:     dnsName,
    dnsTxtValue: dnsTxtValue,
    dnsRecord:   _zoneLine(dnsName, dnsTxtValue),
  };
}

// A value copied out of an operator's command line on its way into a
// row: screened for what a terminal would act on rather than print, then
// bounded. A refusal quotes the name it was given, that name is whatever
// was typed, and the row is read back by `blamepost audit read` in a
// terminal. The chain is append-only, so a value written into it once
// cannot be taken back out.
//
// The screen is the shared one rather than a table of this module's own,
// and the difference is the whole point of sharing it. Cutting at the
// first control character leaves a bidirectional override in place, and
// an override redraws every character after it in the opposite
// direction, so an operator reading a refused mint is shown the
// selector, the domain and the verb in an order nobody wrote. It leaves
// a zero-width joiner in place too, and that hides the difference
// between two selector names, which is the difference the row exists to
// record.
//
// Input that is not text at all is recorded as an absence rather than as
// the word "undefined", because an absence is what it is.
function _recordable(value) {
  if (typeof value !== "string") return null;
  var text = displayText.forDisplay(value).trim();
  if (text.length === 0) return null;
  if (text.length > MAX_RECORDED_CHARS) text = text.slice(0, MAX_RECORDED_CHARS);
  return text;
}

// Why an operation stopped, in the words the operator was given for it.
function _refusalText(e) {
  return _recordable((e && e.message) || String(e));
}

// What identifies a key in a row. The selector and the algorithm are
// exactly what a receiver reads off a signature's `s=` and `a=` tags to
// find the key that made it, so they name a key using only what was
// already public.
//
// The published key bytes stay out, and so does any digest of either
// half. A verifier for a candidate private key is what both of those
// are: given a guess, the public half confirms it without a request
// reaching this server, and a digest of the private half confirms it
// directly. The audit chain is append-only and hash-linked, so a value
// written into it once cannot be taken back out, and neither value adds
// anything, because the selector row and the zone already carry the
// public half and nothing at all should carry the private one.
function _keyNames(rows) {
  return (rows || []).map(function (row) {
    var named = { selector: row.selector, algorithm: row.algorithm };
    // A sweep can cross every hosted domain in one run, so an entry that
    // knows which one it belongs to says so. The verbs that work on a
    // single domain carry it once at the top of the event instead.
    if (row.domain) named.domain = row.domain;
    return named;
  });
}

// What an operation has already changed at the moment it stops. A
// refusal that changed nothing and a run that stopped part way are
// different facts for whoever reads the row: the first leaves the
// domain exactly as it was, and the second can leave a sealed private
// key on disk that nothing will sign with and no row points at. Each
// verb marks the point where the first stops being true, and the
// outcome recorded for a failed run is read off that mark.
function _phase() {
  return { committed: false };
}

function _stoppedAt(phase) {
  return phase.committed ? "failure" : "denied";
}

// Which half of a domain's pair is present and which is gone, named the
// way a receiver reads them off a signature's `a=` tag. Callers ask this
// only once they know the pair is incomplete and that the domain holds
// at least one active selector, so there is always a held half to name.
//
// A domain holding neither half and a domain holding one are different
// situations for whoever reads the refusal, and the difference is not
// cosmetic. The first has never been set up, and every verb is open to
// it. The second has a live key, a record in the zone and a receiver
// that could check a signature made with it, so a refusal saying it has
// no key pair describes a state the operator cannot see from where they
// are standing. It is also the state in which every verb that looks
// like a repair is closed: minting refuses because a selector is still
// active, and rotating refuses because there is no pair to rotate away
// from. Naming the half that is gone is what separates the two, and it
// is what tells the operator the way out costs a signing gap rather
// than being a matter of finding the right command.
function _splitPair(eddsa, rsa) {
  var held = eddsa.length === 0 ? rsa : eddsa;
  return {
    held:    eddsa.length === 0 ? ALG_RSA : ALG_EDDSA,
    missing: eddsa.length === 0 ? ALG_EDDSA : ALG_RSA,
    names:   held.map(function (s) { return s.selector; }).join(", "),
  };
}

// The half-pair state in one sentence, shared by the two refusals that
// meet it. What each of them owes the operator after this differs, so
// the remedy stays at the call site rather than being folded in here:
// one is a message that will not be signed, the other is a mint that
// will not be started, and a single sentence covering both would be
// vague about each.
function _splitPairText(domain, split) {
  return domain + " has an active " + split.held + " selector (" + split.names +
    ") and no active " + split.missing + " one. A message from this domain is signed once " +
    "with each, so a pair with a half missing signs nothing at all.";
}

/**
 * @primitive blamepost.mail.dkim.create
 * @signature blamepost.mail.dkim.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 6376 (DKIM), RFC 8463 (Ed25519 DKIM), RFC 8301 §3.2 (RSA key size: 1024 bits required, 2048 recommended)
 *
 * Build the DKIM handle. Returns `{ generate, rotate, retire, sweep,
 * reseal, list, dnsRecords, signerFor, sign, describe }`.
 *
 * `generate` is first setup for a domain with no keys. `rotate`,
 * `retire` and `sweep` are the three moves of rotation. `reseal` is the
 * one-time run that seals the keys already on a volume to the selectors
 * they belong to. `dnsRecords`
 * returns every record that must currently be in the zone, which is
 * what `blamepost doctor` resolves and compares. `sign` returns the
 * message with a signature per active key prepended.
 *
 * Signing refuses for a domain that does not hold one active selector
 * per algorithm, rather than sending unsigned mail from a domain whose
 * DMARC record promises the mail will be signed. A domain holding only
 * one half publishes two records and could satisfy neither receiver
 * reliably, so it is refused on the same footing as one holding none.
 *
 * @opts
 *   dataDir:          string,   // required; sealed private keys live at <dataDir>/keys
 *   store:            object,   // required; the identity store, which owns the selector rows
 *   vault:            object,   // seal and unseal pair; defaults to b.vault
 *   headersToSign:    string[], // the header set a signature binds
 *   canonicalization: string,   // default relaxed/relaxed
 *   rsaBits:          number,   // RSA modulus size; at least 2048, which is the default
 *
 * @example
 *   var dkim = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
 *   var minted = await dkim.generate({ domain: "example.com" });
 *   minted.publish.forEach(function (r) { console.log(r.dnsRecord); });
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.dkim.create: opts object is required");
  }
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new TypeError("blamepost.mail.dkim.create: opts.dataDir is required " +
      "(sealed private keys live at <dataDir>/keys)");
  }
  configModule.assertAbsoluteDataDir(
    "blamepost.mail.dkim.create: opts.dataDir", opts.dataDir);
  if (!opts.store || !opts.store.domains ||
      typeof opts.store.domains.addSelector !== "function" ||
      typeof opts.store.domains.listSelectors !== "function" ||
      typeof opts.store.domains.get !== "function") {
    throw new TypeError("blamepost.mail.dkim.create: opts.store must be the identity store. " +
      "The selector rows live there, so the admin interface and this signer read one record " +
      "of what exists rather than two that drift, and the domain row it answers with is what " +
      "ties a key-lifecycle audit row to the domain rows written for the same operation.");
  }
  // Both of these decide what a signature says, and both are read here
  // rather than where they are used. The signer is built the first time
  // a domain signs, not when the server starts, so a value read only
  // there lets a mistyped setting boot cleanly and then sends every
  // message from every hosted domain unsigned, with the refusal worded
  // for whoever composed the signer and reaching an audit row rather
  // than the operator who typed it.
  if (opts.headersToSign !== undefined &&
      (!Array.isArray(opts.headersToSign) || opts.headersToSign.length === 0 ||
       !opts.headersToSign.every(function (name) {
         return typeof name === "string" && name.trim().length > 0;
       }))) {
    throw new TypeError("blamepost.mail.dkim.create: opts.headersToSign must be a " +
      "non-empty array of header names when supplied. Each entry names a header a " +
      "signature binds, so a message that rewrites one breaks the signature.");
  }
  if (opts.canonicalization !== undefined &&
      CANONICALIZATION_FORMS.indexOf(opts.canonicalization) === -1) {
    throw new TypeError("blamepost.mail.dkim.create: opts.canonicalization must be one of " +
      CANONICALIZATION_FORMS.join(", ") + ". It names how the header block and the body are " +
      "normalized before they are hashed, which RFC 6376 §3.4 defines two forms of each. " +
      "Leave it out to get " + CANONICALIZATION_FORMS[0] + ", which tolerates the whitespace " +
      "and folding changes a relay makes in transit.");
  }
  // Measured here rather than left to the generator underneath, for two
  // reasons. The generator admits the historical 1024 bit floor as an
  // opt-in and this server does not, so a modulus between the two would
  // be accepted there and is refused here. And a value it refuses comes
  // back worded for whoever composed the generator, naming its own
  // option path, which is not a sentence to put in front of an operator
  // reading an administration page. Refusing at the entry point means
  // the value never reaches it.
  if (opts.rsaBits !== undefined &&
      (typeof opts.rsaBits !== "number" || !isFinite(opts.rsaBits) ||
       (opts.rsaBits % 1) !== 0 || opts.rsaBits < MIN_RSA_BITS)) {
    throw new TypeError("blamepost.mail.dkim.create: opts.rsaBits must be a whole number of " +
      "bits, at least " + MIN_RSA_BITS + ". This server signs with no smaller RSA key, which is " +
      "the size RFC 8301 §3.2 recommends. Leave it out to get exactly that.");
  }

  var store = opts.store;
  var vault = opts.vault || b.vault;
  // Both halves of the vault are required. The authenticated-data seal
  // is what every key this server writes goes under; the plain one opens
  // the keys a volume was carrying before that binding existed, and a
  // handle holding only the first cannot read them.
  if (typeof vault.seal !== "function" || typeof vault.unseal !== "function" ||
      !vault.aad || typeof vault.aad !== "object" ||
      typeof vault.aad.seal !== "function" || typeof vault.aad.unseal !== "function" ||
      typeof vault.aad.isAadSealed !== "function") {
    throw new TypeError("blamepost.mail.dkim.create: opts.vault must expose seal, unseal and " +
      "aad.seal, aad.unseal and aad.isAadSealed (pass b.vault, which is what the running " +
      "server uses)");
  }
  var keyDir = _keyDirOf(opts.dataDir);
  b.atomicFile.ensureDir(keyDir, 0o700);

  b.audit.registerNamespace(AUDIT_NAMESPACE);

  var headersToSign = (opts.headersToSign || DEFAULT_HEADERS_TO_SIGN).slice();
  var canonicalization = opts.canonicalization || "relaxed/relaxed";
  var signerCache = new Map();

  // The domain a key-lifecycle row is about, named by the same row id
  // the store puts on the selector rows it writes for the same
  // operation, so an auditor reading one can find the other.
  //
  // `get` answers null for a name this server does not host rather than
  // refusing, which is why the shape check for it is up in `create`:
  // reading it here has to be a read that cannot fail on a store that
  // was never the identity store, and every verb calling this already
  // reads the same handle for its selectors, so a store that has
  // stopped answering has already ended the operation.
  function _domainResource(domain) {
    var row = store.domains.get(domain);
    return { kind: "domain", id: (row && row.id) || null };
  }

  function _keyRef(domain, selector, algorithm) {
    return domain + "." + selector + "." + algorithm + ".sealed";
  }

  function _keyPath(keyRef) {
    return _keyPathOf(opts.dataDir, keyRef, "dkim");
  }

  // One selector's sealed private key, written under a name this call
  // takes before it writes anything under it.
  //
  // Taking the name is the whole of it. A key file is named from the
  // domain, the selector and the algorithm, so two mints asked for the
  // same selector arrive at the same name, and neither can see the
  // other's selector row until it lands: the row is written after the
  // file, and has to be, because a row published for a key that is not
  // there is a domain whose mail leaves unsigned. So the file name is
  // what a mint has to claim, and `wx` claims it in one call the
  // platform cannot cut in half. Whichever mint loses is refused having
  // written nothing, and erases nothing on the way out, which is what
  // leaves the mint that won holding its own key: the unwind below
  // erases the names in `written`, and a name this call never took
  // never reaches that list.
  //
  // A file already sitting under the name is refused rather than
  // written over, and the two ways that happens are one situation from
  // here. It is either another mint holding the name right now, or a
  // run that stopped between writing the file and writing the row, and
  // no reading tells them apart: the selector row that would say which
  // is exactly the row that has not been written yet. So a rule of
  // "take it back when no row names it" would take the other mint's key
  // every time, which is the fault this exists to close. What is under
  // the name is signing material either way and this volume holds the
  // only copy, so the answer is the one `eraseKeyFiles` already gives
  // when a rename would land on a file that is there: stop, and say
  // which file it was.
  //
  // `phase` is the caller's record of whether anything on the volume has
  // been changed yet, and taking the name is the moment it has been. The
  // mark is made here rather than around the call because only this body
  // can tell the two refusals apart: a name that was already held is a
  // refusal with the volume untouched, and everything after the claim
  // has created a file, which the write below replaces and a failing
  // write tries to remove. A volume that will not give that empty file
  // up leaves it under a name no record points at, so a run stopped
  // anywhere past the claim is one with something to go and look at.
  async function _writeKey(keyRef, privateKeyPem, context, label, phase) {
    var target = _keyPath(keyRef);
    var claim;
    try {
      claim = nodeFs.openSync(target, "wx", 0o600);
    } catch (takeError) {
      if (takeError && takeError.code === "EEXIST") {
        throw err(KEY_FILE_HELD, label + ": " + keyRef + " is already in the keys folder on " +
          "this volume, so nothing was minted. Writing over it would destroy the only copy " +
          "of whatever is under that name, and this server puts nothing there but sealed " +
          "private keys, one of which signs mail as the domain it belongs to for whoever " +
          "holds it. Either another mint is writing that pair right now, or one stopped " +
          "before it published the record naming this file. `blamepost dkim list` shows " +
          "what the domain publishes, and `blamepost doctor` reports a key no record names " +
          "under `signing keys`, which is the one to delete from the keys folder by hand. " +
          "Passing --selector with a name of your own mints without touching it at all.");
      }
      throw takeError;
    }
    // The name is taken and nothing is under it yet. The framework's
    // write puts the sealed bytes there and replaces this file as it
    // renames, so the claim costs one empty file for the length of one
    // write.
    phase.committed = true;
    try { nodeFs.closeSync(claim); }
    catch (_closeError) { /* drop-silent by design: the write below decides this call */ }
    try {
      await b.atomicFile.write(target, vault.aad.seal(privateKeyPem, context),
        { fileMode: 0o600 });
    } catch (writeError) {
      // The name is this call's and nothing of value went under it, so
      // it goes back rather than standing in the way of the next mint.
      // A volume that will not give it up leaves an empty file no
      // record names, which `blamepost doctor` reports and this same
      // refusal names on the next attempt.
      // allow:swallow-unverified this is the cleanup on the path where the
      // key file could not be written, so reaching it needs a second
      // filesystem fault in the same call; the write's own refusal is
      // rethrown below and must not be replaced by the undo's.
      try { nodeFs.rmSync(target, { force: true }); }
      catch (_undoError) { /* drop-silent by design: the write's own fault is what leaves */ }
      throw writeError;
    }
  }

  // The private half one selector signs with, opened.
  //
  // Four ways this produces no key material, and all of them are
  // permanent verdicts about the file rather than conditions that pass:
  // the file is not there to read, it is there and carries no seal, it
  // is bound to this selector and does not open, or it carries the plain
  // volume seal and does not open. Each is refused in this layer's own
  // words, because what would otherwise leave belongs to a layer whose
  // vocabulary is not this one's. The file layer's fault names the
  // absolute path it tried; the vault's carries no code at all, and a
  // caller with no code to read has a permanent condition it can only
  // treat as a transient one.
  //
  // The two sealed forms are separated because their repairs are
  // different. A file bound to this selector that will not open is not
  // this selector's key: it was sealed as something else, or for another
  // selector, or its bytes have been damaged, and no command re-derives
  // it. A file carrying the plain volume seal was written before keys
  // were bound to their selectors, so it opens and then answers to the
  // derivation check below like every other key, and the way out of it
  // is `blamepost dkim reseal` rather than a new pair.
  //
  // Signing runs on every message an account submits, so both callers on
  // that path record the refusal and log its message for the operator.
  // A code is also what tells the admin interface a refusal may be shown
  // to whoever asked, so nothing from the fault underneath reaches these
  // messages and the file is named by what it holds and which selector
  // it belongs to rather than by where it is.
  //
  // The pair's Ed25519 selector is what the way out is named with,
  // whichever half is damaged: `dkim retire` names a pair and takes both
  // halves, so pointing an operator at the RSA name would send them to a
  // verb that refuses it.
  function _readKey(entry, pairSelector) {
    var held = entry.domain + " cannot sign, because ";
    var half = "the signing key for its '" + entry.selector + "' selector (" +
      entry.algorithm + ")";
    var mintAfresh = "retire it with `blamepost dkim retire --domain " + entry.domain +
      " --selector " + pairSelector + "`, mint a replacement with `blamepost dkim generate " +
      "--domain " + entry.domain + "`, and publish both records it prints.";
    var sealed;
    try {
      sealed = b.atomicFile.readSync(_keyPath(entry.keyRef), {
        maxBytes: MAX_KEY_FILE_BYTES,
        encoding: "utf8",
      });
    } catch (readError) {
      throw err(KEY_UNREADABLE, "dkim.signerFor: " + held + half +
        (readError && readError.code === "ENOENT"
          ? " is not on this volume."
          : " could not be read from this volume (" +
            ((readError && readError.code) || "unknown") + ").") +
        " Every message from this domain leaves unsigned meanwhile, and fails DMARC wherever " +
        "its policy sends failures. Restore the volume from a backup taken before the key " +
        "went, or replace the pair: " + mintAfresh);
    }
    // The vault hands back a value that carries no seal exactly as it
    // found it, so without this the contents of an unsealed file would
    // be signed with. A key file this server wrote is always sealed, so
    // one that is not was put there by something else, and whatever is
    // in it has been readable to anyone who can read the volume for as
    // long as it has been there.
    var boundToThisKey = vault.aad.isAadSealed(sealed);
    if (!boundToThisKey && sealed.indexOf(VAULT_SEAL_PREFIX) !== 0) {
      throw err(KEY_NOT_SEALED, "dkim.signerFor: " + held + half +
        " is not sealed. This server seals every private key it writes, so nothing is signed " +
        "with a file that is not, and whatever that file holds has been readable to anyone " +
        "who can read this volume. Treat the pair as exposed: " + mintAfresh +
        " Then withdraw the old records now rather than after the usual overlap, with " +
        "`blamepost dkim sweep --domain " + entry.domain + " --immediate`.");
    }
    // A seal authenticates what it carries end to end, so a file missing
    // its tail does not open at all and a file written under another
    // volume's vault key opens for nobody here. The two are the same
    // failure from the outside and the vault reports them the same way,
    // so they are named as the pair they are rather than guessed
    // between. A passphrase that does not fit is a third thing and is
    // not one of them: it is refused when the vault is opened, which
    // happens before any of this runs.
    //
    // A key bound to its selector adds a third cause to that list, and it
    // is the one with a different answer: the value was sealed as
    // something other than this selector's signing key, so nothing
    // repairs it in place and the pair is replaced. It is refused under
    // a code of its own for that reason.
    var opened;
    if (boundToThisKey) {
      try {
        opened = vault.aad.unseal(sealed,
          _keySealContext(entry.domain, entry.selector, entry.algorithm));
      } catch (_boundError) {
        throw err(KEY_SEAL_FOREIGN, "dkim.signerFor: " + held + half +
          " is sealed, and not as this selector's signing key. It is a value this volume " +
          "sealed for something else, or one belonging to another selector or another " +
          "domain, or its bytes have been damaged where they lie. Nothing signs with it " +
          "either way. Every message from this domain leaves unsigned meanwhile, and fails " +
          "DMARC wherever its policy sends failures. Restore the volume from a backup whose " +
          "keys folder and database were taken together, or replace the pair: " + mintAfresh);
      }
    } else {
      try {
        opened = vault.unseal(sealed);
      } catch (_sealError) {
        throw err(KEY_SEAL_UNOPENED, "dkim.signerFor: " + held + half +
          " did not open. It was written under a different volume's vault key, or its bytes " +
          "have been damaged where they lie. Every message from this domain leaves unsigned " +
          "meanwhile, and fails DMARC wherever its policy sends failures. Restore the volume " +
          "from a backup taken before the damage, or replace the pair: " + mintAfresh);
      }
    }
    // The file opened, so this is the last question left: is it the key
    // the selector's own record publishes?
    //
    // A file that opens and parses signs without a word, and every other
    // reading this server has agrees that the domain is correct, because
    // every one of them answers off the row. What leaves is a signature
    // a receiver cannot verify under a selector it resolved without
    // trouble. It is reached by ordinary work rather than by an attack:
    // the keys folder is where the refusals above send an operator by
    // hand, and a restore that brings back a key file older than the row
    // beside it is this exact state.
    //
    // Refused rather than signed with, because a signature no receiver
    // can check is worth less than none: the relay path files an
    // unsigned send under a code an operator can filter on, and a
    // signature that fails at every receiver is reported nowhere at all.
    //
    // It is also the only thing standing between a key file carrying the
    // plain volume seal and whatever else that volume sealed, since a
    // value sealed before keys were bound to their selectors carries
    // nothing saying which value it is. A bound key answers that question
    // at the seal, above; one that has not been through
    // `blamepost dkim reseal` answers it here.
    var derived;
    try { derived = _publishedHalfOf(opened, entry.algorithm); }
    catch (_parseError) { derived = null; }
    if (derived === null || derived !== entry.publicKey) {
      throw err(KEY_RECORD_MISMATCH, "dkim.signerFor: " + held + half +
        (derived === null
          ? " opened but is not a key of the kind its record publishes."
          : " is not the key its record publishes.") +
        " The record at '" + entry.selector + "._domainkey." + entry.domain + "' carries a " +
        "different public half, so a receiver that resolves it cannot verify anything this " +
        "key signs. A key file restored from a backup older than the selector row beside it " +
        "leaves exactly this, and every other reading on this server answers off the row, so " +
        "nothing else reports it. Restore the volume from a backup whose keys folder and " +
        "database were taken together, or replace the pair: " + mintAfresh);
    }
    return opened;
  }

  // One selector's sealed private key, gone. It goes through the
  // module's own eraser rather than reaching the filesystem here, so
  // there is one place that decides what a keyRef resolves to and one
  // place that decides that a file already gone is an answer rather than
  // a fault. Both callers on this path read nothing off the error except
  // that it was raised: each names the file it could not erase from the
  // ref it is already holding.
  async function _eraseKey(keyRef) {
    var swept = await eraseKeyFiles(opts.dataDir, [keyRef]);
    if (swept.stranded.length > 0) {
      throw new Error("the sealed private key " + keyRef + " could not be erased (" +
        swept.stranded[0].reason + ")");
    }
  }

  function _findSelector(known, selector, algorithm) {
    for (var i = 0; i < known.length; i += 1) {
      if (known[i].selector === selector && known[i].algorithm === algorithm) return known[i];
    }
    return null;
  }

  // A selector name is a name in the zone before it is a row, so a
  // second key under it is a second record at one name whichever
  // algorithm the first one was.
  function _selectorNamed(known, selector) {
    for (var i = 0; i < known.length; i += 1) {
      if (known[i].selector === selector) return known[i];
    }
    return null;
  }

  // The selector names a domain holds for one algorithm, so a refusal
  // can show what was there instead of only what was asked for.
  function _namesOf(known, algorithm) {
    return known.filter(function (s) { return s.algorithm === algorithm; })
      .map(function (s) { return s.selector; }).join(", ");
  }

  // A selector name as the store will record it. Folded first, because
  // the store folds it too and two spellings of one name are one
  // selector; refused rather than repaired, because a name that is not a
  // DNS label cannot be published and mail signed under it can never be
  // verified by anyone.
  function _selectorName(value, label, option) {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new TypeError(label + ": " + option + " must be a selector name");
    }
    var name = value.trim().toLowerCase();
    if (!SELECTOR_LABEL_RE.test(name)) {
      throw new TypeError(label + ": " + option + " '" + value + "' is not a single DNS label, " +
        "which is what a DKIM selector has to be for '" + value + "._domainkey.<domain>' to " +
        "be a name anyone can resolve. Letters, digits and hyphens only, at most 63 of them.");
    }
    return name;
  }

  // Everything a mint needs, worked out before it touches anything.
  //
  // Both halves of the pair are settled together here: the folded names,
  // the key file each will use, the length the store will accept, and
  // whether either name is already spoken for. A refusal at this point
  // has changed nothing. A refusal after the first key is written leaves
  // private key material no row points at, which is never signed with,
  // never rotated, never erased when a selector is retired, and still
  // there after the domain is removed.
  function _selectorPair(domain, selector, rsaSelector, label) {
    // The RSA half is named from the Ed25519 one unless the caller
    // supplied its own, so `--selector` is the answer to both halves at
    // the command line and the hint says so either way.
    var halves = [
      { algorithm: ALG_EDDSA, half: "Ed25519",
        hint: "Choose another with --selector.",
        name: _selectorName(selector, label, "opts.selector") },
      { algorithm: ALG_RSA, half: "RSA",
        hint: "The RSA half is named from --selector unless opts.rsaSelector is given, so " +
          "choose another with --selector or name the RSA half yourself.",
        name: _selectorName(rsaSelector, label, "opts.rsaSelector") },
    ];
    if (halves[0].name === halves[1].name) {
      throw err(SELECTOR_NAME_COLLISION, label + ": the Ed25519 and RSA selectors are both '" + halves[0].name +
        "'. One selector name is one key, so publishing both under it puts two records at '" +
        halves[0].name + "._domainkey." + domain + "' and a receiver reading that name gets " +
        "whichever of the two it happens to pick. Give the RSA half a name of its own.");
    }

    var known = _selectors(domain);
    for (var i = 0; i < halves.length; i += 1) {
      var entry = halves[i];
      var taken = _selectorNamed(known, entry.name);
      if (taken) {
        throw err(SELECTOR_TAKEN, label + ": " + domain + " already has a selector named '" + entry.name +
          "' (" + taken.algorithm + ", " + taken.state + ") and its record is still in the " +
          "zone, so a second key under that name would be a second record at '" + entry.name +
          "._domainkey." + domain + "'. " + entry.hint);
      }
      entry.keyRef = _keyRef(domain, entry.name, entry.algorithm);
      if (entry.keyRef.length > MAX_KEY_REF_CHARS) {
        var room = MAX_KEY_REF_CHARS - domain.length - _keyRefOverhead(entry.algorithm);
        throw err(SELECTOR_NAME_TOO_LONG, label + ": the sealed key file for " + domain + " under the " +
          entry.half + " selector '" + entry.name + "' would be named with " +
          entry.keyRef.length + " characters, and the store records at most " +
          MAX_KEY_REF_CHARS + ". " + (room >= 1
            ? "Pass --selector with a name of at most " + room + " characters."
            : "No selector short enough exists for a domain name this long, so this domain " +
              "cannot be signed from here under --selector or any other name."));
      }
    }
    return halves;
  }

  // Undo as much of a failed mint as can be undone, and report what
  // could not be. Selector rows go first and in reverse, because
  // `removeSelector` refuses to drop a domain's last active selector,
  // which is the right rule for an operator withdrawing a key and the
  // wrong one for unwinding a pair that was never completed: moving the
  // row out of signing first takes that branch out of the way.
  async function _unwindMint(domain, added, written) {
    var leftovers = [];
    for (var i = added.length - 1; i >= 0; i -= 1) {
      var row = added[i];
      try {
        await store.domains.retireSelector({
          domain: domain, selector: row.name, algorithm: row.algorithm,
        });
        var taken = await store.domains.removeSelector({
          domain:    domain,
          selector:  row.name,
          algorithm: row.algorithm,
          immediate: true,
          reason:    "the key pair this selector belongs to was not completed",
        });
        // A row that went and a key that could not be destroyed with it
        // is still something left behind, and this list is what names
        // what was left behind. Reaching the catch is not the only way
        // to leave something.
        for (var k = 0; k < taken.keysLeftAside.length; k += 1) {
          leftovers.push("key file " + taken.keysLeftAside[k]);
        }
      } catch (_e) {
        leftovers.push("selector row " + row.name + " (" + row.algorithm + ")");
      }
    }
    for (var j = 0; j < written.length; j += 1) {
      try { await _eraseKey(written[j]); }
      catch (_e) { leftovers.push("key file " + written[j]); }
    }
    return leftovers;
  }

  // Mint one pair and record both halves: the public half as a selector
  // row, the private half as a sealed file the row points at. Neither
  // half survives on its own. A refusal anywhere takes both back out,
  // and anything that could not be taken back out is named in the error
  // rather than left for the operator to find.
  //
  // `phase` is the caller's record of whether anything has been changed
  // yet, and it is what tells its audit row apart from a refusal. The
  // checks above the first write settle both names, both key file names
  // and both collisions, and they can refuse with nothing on disk and no
  // row written; below them a stop can leave either. Generating the
  // material changes nothing either: it is two key pairs in memory until
  // the first write puts one of them on the volume.
  //
  // So the mark is made inside the write, at the moment it takes the
  // file name, rather than by reaching the loop. Taking the name is the
  // last thing that can refuse having changed nothing: a key file
  // already sitting under the name this mint derived is refused before a
  // byte of it is written, and a run marked as having stopped part way
  // over that refusal is filed under the outcome that means a sealed
  // private key may be stranded on the volume. An operator filtering the
  // trail for refused mints would not find it, and one looking for a
  // volume to go and inspect would be sent to a volume with nothing on
  // it.
  async function _mintPair(domain, selector, rsaSelector, label, phase) {
    var halves = _selectorPair(domain, selector, rsaSelector, label);
    var minted = b.mail.dkim.bootstrap({
      domain:      domain,
      selector:    halves[0].name,
      rsaSelector: halves[1].name,
      algorithm:   "dual",
      rsaBits:     opts.rsaBits,
    });
    halves[0].part = minted.ed25519;
    halves[1].part = minted.rsa;

    var written = [];
    var added = [];
    try {
      for (var i = 0; i < halves.length; i += 1) {
        var entry = halves[i];
        await _writeKey(entry.keyRef, entry.part.privateKeyPem,
          _keySealContext(domain, entry.name, entry.algorithm), label, phase);
        written.push(entry.keyRef);
        // The record's p= tag, which the framework already computed in
        // the form each algorithm's receivers expect: raw key bytes for
        // Ed25519 per RFC 8463, SubjectPublicKeyInfo for RSA.
        await store.domains.addSelector({
          domain:    domain,
          selector:  entry.name,
          algorithm: entry.algorithm,
          publicKey: entry.part.dnsTxtValue.split("p=")[1],
          keyRef:    entry.keyRef,
        });
        added.push(entry);
      }
    // The caught error is named for what it is rather than for the
    // module's refusal factory. Both were called `err` here, and the
    // parameter wins inside the block, so the factory every other
    // refusal in this file reaches for was an ordinary error object for
    // the length of this catch. Nothing called it, so nothing broke;
    // the next refusal added here would have been a TypeError thrown
    // while handling a failure, which is the worst place to find one.
    } catch (cause) {
      var leftovers = await _unwindMint(domain, added, written);
      signerCache.delete(domain);
      if (leftovers.length === 0) throw cause;
      // Deliberately uncoded. The fault underneath is a volume that
      // could not be written, and its message carries the data
      // directory, the key file naming scheme and the suffix an atomic
      // write appends. A code is what tells a surface it may show a
      // message to an operator, so giving this one a code would put
      // that path in a browser.
      var stranded = new Error(label + ": minting keys for " + domain + " failed, and what had " +
        "already been written could not all be taken back out. " +
        ((cause && cause.message) || String(cause)) + " Still present: " + leftovers.join("; ") +
        ". Remove them before trying again, because nothing will use them.");
      stranded.cause = cause;
      throw stranded;
    }
    signerCache.delete(domain);
    return halves.map(function (entry) {
      return { selector: entry.name, algorithm: entry.algorithm, keyRef: entry.keyRef };
    });
  }

  function _selectors(domain, status) {
    var query = { domain: domain };
    if (status) query.status = status;
    return store.domains.listSelectors(query).map(_present);
  }

  // Pair the active selectors by algorithm. Two active pairs is what
  // rotation looks like between the moment a replacement is minted and
  // the moment the old one is retired, and both sign during that
  // window so a receiver has a signature that verifies either way.
  function _activePairs(domain, label) {
    var active = _selectors(domain, "active");
    var eddsa = active.filter(function (s) { return s.algorithm === ALG_EDDSA; });
    var rsa = active.filter(function (s) { return s.algorithm === ALG_RSA; });
    // Read off the two algorithm sets rather than off the total, so a row
    // carrying an algorithm this signer does not sign with counts as the
    // absence it is. A domain holding only such a row has no pair in
    // either algorithm a DKIM signature can name, which is what this
    // refusal already says, and the split-pair refusal below would have
    // had no held half to name.
    if (eddsa.length === 0 && rsa.length === 0) {
      throw err(NO_ACTIVE_SELECTOR,
        label + ": " + domain + " has no active DKIM key pair. Run " +
        "`blamepost dkim generate --domain " + domain + "` and publish the records it prints.");
    }
    if (eddsa.length === 0 || rsa.length === 0) {
      // A domain that still holds one half is not a domain waiting to be
      // set up, and sending it to `generate` would be sending it to a
      // verb that refuses on the selector it still has. What is left is
      // withdrawn first and a whole pair minted after, and that order
      // means the domain carries no signature in between, so the refusal
      // says so rather than letting the operator find out from a DMARC
      // report a day later.
      throw err(NO_ACTIVE_SELECTOR,
        label + ": " + _splitPairText(domain, _splitPair(eddsa, rsa)) +
        " Nothing adds the missing half back to a pair that has already lost one: run " +
        "`blamepost dkim list` to see what is left, retire it, and then run " +
        "`blamepost dkim generate --domain " + domain + "` and publish both records it prints. " +
        "Mail sent between those two steps leaves unsigned and fails DMARC wherever this " +
        "domain's policy sends failures.");
    }
    var pairs = [];
    var count = Math.min(eddsa.length, rsa.length);
    for (var i = 0; i < count; i += 1) pairs.push({ eddsa: eddsa[i], rsa: rsa[i] });
    return pairs;
  }

  /**
   * @primitive blamepost.mail.dkim.generate
   * @signature dkim.generate(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.6.1, RFC 8463 §3
   * @related   blamepost.mail.dkim.create, blamepost.mail.dkim.rotate
   *
   * First keys for a domain. Mints the pair, seals both private keys,
   * records both selectors, and returns the zone records to publish.
   * Refuses a domain that already has active keys, so a second run
   * cannot quietly add a third and fourth signature to every message.
   * A domain holding only one algorithm is refused by the same check
   * and told something different, because rotation is the way out of
   * the first and is closed to the second: it reads a pair before it
   * mints and there is no pair to read. That domain signs nothing until
   * the half it still holds is retired and a whole one is minted, and
   * the refusal says so rather than naming a verb that would refuse
   * again.
   *
   * Records the attempt under `blamepost.mail.dkim.keys_generated`
   * whichever way it goes, naming the operator, the domain and the
   * selectors. A refused mint is worth as much to an incident as a
   * successful one: it is somebody trying to put a second key under a
   * domain that already signs.
   *
   * @opts
   *   domain:      string,   // required
   *   selector:    string,   // Ed25519 selector; defaults to bp<YYYYMM>
   *   rsaSelector: string,   // RSA selector; defaults to <selector>-rsa
   *
   * @example
   *   var minted = await dkim.generate({ domain: "example.com" });
   *   minted.publish.length;   // two records, one per algorithm
   */
  async function generate(genOpts) {
    genOpts = genOpts || {};
    var domain = _assertDomain(genOpts.domain, "dkim.generate");
    var resource = _domainResource(domain);
    var now = Date.now();
    var selector = genOpts.selector || _defaultSelector(now);
    var rsaSelector = genOpts.rsaSelector || (selector + "-rsa");

    var phase = _phase();
    var outcome = "success";
    var reason = null;
    var minted = [];
    var stopped = null;
    try {
      var alreadyActive = _selectors(domain, "active");
      if (alreadyActive.length > 0) {
        var eddsaHeld = alreadyActive.filter(function (s) { return s.algorithm === ALG_EDDSA; });
        var rsaHeld = alreadyActive.filter(function (s) { return s.algorithm === ALG_RSA; });
        // A domain holding a whole pair and a domain holding half of one
        // both refuse here, and the way out is not the same. Rotation is
        // the answer to the first and is closed to the second, since it
        // reads the pair before it mints and there is no pair to read,
        // so naming it either way would send half the operators who
        // arrive at this line to a verb that refuses them.
        if (eddsaHeld.length === 0 || rsaHeld.length === 0) {
          throw err(KEYS_ALREADY_ACTIVE, "dkim.generate: " +
            _splitPairText(domain, _splitPair(eddsaHeld, rsaHeld)) +
            " Minting alongside what is left would put a third selector under a domain that " +
            "cannot sign with the two it has, and rotating needs a whole pair to rotate away " +
            "from. Retire the remainder with `blamepost dkim retire --domain " + domain +
            "`, then run this again. The domain carries no signature between the two, which " +
            "is what a split pair costs.");
        }
        throw err(KEYS_ALREADY_ACTIVE, "dkim.generate: " + domain + " already has active keys. Use " +
          "`blamepost dkim rotate` to introduce a replacement, which keeps the current pair " +
          "signing until you retire it.");
      }
      minted = await _mintPair(domain, selector, rsaSelector, "dkim.generate", phase);
    } catch (e) {
      outcome = _stoppedAt(phase);
      reason = _refusalText(e);
      stopped = e;
    }

    try {
      await b.audit.record({
        action:   "blamepost.mail.dkim.keys_generated",
        outcome:  outcome,
        actor:    auditActor.current(),
        resource: resource,
        reason:   reason,
        metadata: {
          domain:    domain,
          requested: [_recordable(selector), _recordable(rsaSelector)],
          minted:    _keyNames(minted),
        },
      });
    } catch (_e) {
      // Drop-silent by design: a mint that has already happened must not
      // be reported as a failure because the row describing it could not
      // be written, and a mint that refused must not turn into a
      // different refusal on the way out.
    }

    if (stopped !== null) throw stopped;
    return { domain: domain, publish: _selectors(domain) };
  }

  /**
   * @primitive blamepost.mail.dkim.rotate
   * @signature dkim.rotate(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.6.1
   * @related   blamepost.mail.dkim.retire, blamepost.mail.dkim.generate
   *
   * Step one of rotation. Mints a replacement pair alongside the
   * current one and returns the records to publish. From this moment a
   * message carries a signature from each pair, so the old signature
   * keeps verifying while the new records propagate and the new one
   * starts verifying the moment they resolve.
   *
   * Records the attempt under `blamepost.mail.dkim.keys_rotated`, and
   * the row names BOTH sides. The question an incident asks of a
   * signature is which key was live when the message was signed, and a
   * row carrying only the replacement answers half of it: the outgoing
   * selector is what ties the row to signatures already on the wire, and
   * this is the only moment both names are in one place.
   *
   * @opts
   *   domain:      string,   // required
   *   selector:    string,   // defaults to bp<YYYYMM>
   *   rsaSelector: string,   // defaults to <selector>-rsa
   *
   * @example
   *   var staged = await dkim.rotate({ domain: "example.com" });
   *   staged.publish.forEach(function (r) { console.log(r.dnsRecord); });
   */
  async function rotate(rotateOpts) {
    rotateOpts = rotateOpts || {};
    var domain = _assertDomain(rotateOpts.domain, "dkim.rotate");
    var resource = _domainResource(domain);
    var now = Date.now();
    var selector = rotateOpts.selector || _defaultSelector(now);
    var rsaSelector = rotateOpts.rsaSelector || (selector + "-rsa");

    var phase = _phase();
    var outcome = "success";
    var reason = null;
    var outgoing = [];
    var minted = [];
    var current = [];
    var stopped = null;
    try {
      current = _activePairs(domain, "dkim.rotate");
      current.forEach(function (pair) { outgoing.push(pair.eddsa, pair.rsa); });
      // The default name carries the month, so rotating twice inside one
      // stops here. `_mintPair` settles both halves of the pair before
      // it writes anything, and names whichever of the two is in the
      // way, so a name that differs from a live one only in case is
      // refused with the zone untouched.
      minted = await _mintPair(domain, selector, rsaSelector, "dkim.rotate", phase);
    } catch (e) {
      outcome = _stoppedAt(phase);
      reason = _refusalText(e);
      stopped = e;
    }

    try {
      await b.audit.record({
        action:   "blamepost.mail.dkim.keys_rotated",
        outcome:  outcome,
        actor:    auditActor.current(),
        resource: resource,
        reason:   reason,
        metadata: {
          domain:    domain,
          outgoing:  _keyNames(outgoing),
          incoming:  _keyNames(minted),
          requested: [_recordable(rotateOpts.selector), _recordable(rotateOpts.rsaSelector)],
        },
      });
    } catch (_e) {
      // Drop-silent by design: a replacement pair that is already
      // signing must not be undone, and a refusal must not become a
      // different one, because the row about either could not be
      // written.
    }

    if (stopped !== null) throw stopped;
    return {
      domain:   domain,
      previous: current.map(function (p) { return [p.eddsa.selector, p.rsa.selector]; }),
      minted:   minted,
      publish:  _selectors(domain),
    };
  }

  /**
   * @primitive blamepost.mail.dkim.retire
   * @signature dkim.retire(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.6.1, RFC 8463 §3
   * @related   blamepost.mail.dkim.rotate, blamepost.mail.dkim.sweep
   *
   * Step two of rotation. Stops signing with one pair and erases its
   * private keys, because nothing will sign with them again. The store
   * keeps the rows and stamps the moment their records may leave the
   * zone, so mail signed before the change still verifies while it is
   * being retried.
   *
   * Names the pair explicitly rather than guessing, since a domain
   * mid rotation has two and only the operator knows which one the new
   * records belong to.
   *
   * Both halves are found before either is touched. A domain whose RSA
   * selector was minted under a name of its own needs that name here,
   * and giving the wrong one is refused with nothing changed rather
   * than retiring the half that matched. A domain that holds no RSA
   * selector at all is a pair that is already broken, and retiring what
   * is left of it is allowed, because a selector nothing can retire is
   * one nothing can rotate away from either.
   *
   * Records the attempt under `blamepost.mail.dkim.keys_retired`. This
   * is the moment private key material is destroyed, so the row carries
   * how many sealed keys were erased alongside the selectors that
   * stopped signing. A run that moved the rows and could not erase a
   * key is recorded as a failure rather than a refusal, because the two
   * leave the volume in different states and only one of them needs
   * somebody to go and look.
   *
   * @opts
   *   domain:      string,   // required
   *   selector:    string,   // required; the Ed25519 selector of the outgoing pair
   *   rsaSelector: string,   // the RSA selector; defaults to <selector>-rsa
   *
   * @example
   *   var out = await dkim.retire({ domain: "example.com", selector: "bp202601" });
   *   out.retired[0].retiresAt;   // keep the record published until this moment
   */
  async function retire(retireOpts) {
    retireOpts = retireOpts || {};
    var domain = _assertDomain(retireOpts.domain, "dkim.retire");
    var resource = _domainResource(domain);

    var phase = _phase();
    var outcome = "success";
    var reason = null;
    var retiredRows = [];
    var erased = 0;
    var stopped = null;
    var rows = [];
    try {
      if (typeof retireOpts.selector !== "string" || retireOpts.selector.length === 0) {
        throw new TypeError("dkim.retire: opts.selector is required. A domain part way " +
          "through a rotation has two active pairs, and only you know which one the newly " +
          "published records belong to.");
      }
      var selector = _selectorName(retireOpts.selector, "dkim.retire", "opts.selector");
      var rsaSelector = retireOpts.rsaSelector
        ? _selectorName(retireOpts.rsaSelector, "dkim.retire", "opts.rsaSelector")
        : selector + "-rsa";
      var known = _selectors(domain);

      // Both halves are found before either is touched. The store records
      // no link between the two, so the RSA half is looked up by the name
      // it was minted under, and a domain whose RSA selector is not the
      // default needs that name supplied. Retiring the half that was found
      // and then discovering the other is missing erases a private key,
      // leaves the domain with no complete pair to sign with, and offers
      // no way back: signing refuses, minting refuses because selectors
      // are still active, and rotating refuses because there is no pair to
      // rotate away from.
      var matches = [];
      var wanted = [
        { selector: selector, algorithm: ALG_EDDSA, option: "opts.selector" },
        { selector: rsaSelector, algorithm: ALG_RSA, option: "opts.rsaSelector" },
      ];
      for (var i = 0; i < wanted.length; i += 1) {
        var match = _findSelector(known, wanted[i].selector, wanted[i].algorithm);
        if (match) { matches.push(match); continue; }
        // A domain holding selectors of this algorithm under other names
        // means the wrong name was given, and going ahead with the half
        // that was found strands the half that was not. A domain holding
        // none at all is a pair that is already broken, and retiring what
        // is left of it is the repair rather than the damage.
        var others = _namesOf(known, wanted[i].algorithm);
        if (others) {
          throw err(NO_SUCH_SELECTOR, "dkim.retire: " + domain + " has no " + wanted[i].algorithm +
            " selector named '" + wanted[i].selector + "'. Its " + wanted[i].algorithm +
            " selectors are " + others + "; name the one that goes with '" + selector +
            "' in " + wanted[i].option + ". Nothing has been retired.");
        }
      }
      if (matches.length === 0) {
        throw err(NO_SUCH_SELECTOR, "dkim.retire: " + domain + " has no selector named '" + selector +
          "' under either algorithm. Run `blamepost dkim list` to see which selectors exist. " +
          "Nothing has been retired.");
      }

      // Rows first, both of them, so the pair leaves signing together.
      // Only then are the private keys erased, because nothing will sign
      // with them again and keeping them widens what a stolen volume
      // yields. An erase that fails leaves the rows consistent and says
      // which file is still there.
      //
      // Everything above this line refuses with the domain as it was.
      // From here a stop leaves a pair out of signing, and possibly a
      // sealed key still on the volume, which is why the row's outcome
      // is read off the mark rather than off the kind of error.
      var retired = [];
      phase.committed = true;
      for (var j = 0; j < matches.length; j += 1) {
        await store.domains.retireSelector({
          domain:    domain,
          selector:  matches[j].selector,
          algorithm: matches[j].algorithm,
        });
        retired.push(matches[j].selector);
        retiredRows.push(matches[j]);
      }
      signerCache.delete(domain);

      // The rows read again, because the erasure below unlinks a file by
      // a name that was read before any of the writes above ran and each
      // of those writes suspends. Every other verb that destroys key
      // material closes that window with the erasure's own decision
      // hook, which settles the rows with nothing able to run between
      // the move and the commit. This one cannot use it: it moves the
      // rows out of signing FIRST on purpose, so that a retiring
      // selector keeps its record published while nothing signs with it,
      // and the hook settles rows inside the erasure. A re-read is what
      // closes the same window for this order. A name that has moved is
      // reported rather than unlinked, because a file this server can no
      // longer account for is a file it must not destroy on the strength
      // of a reading that has expired.
      var settled = _selectors(domain);
      var stranded = [];
      for (var k = 0; k < matches.length; k += 1) {
        var nowRow = _findSelector(settled, matches[k].selector, matches[k].algorithm);
        if (!nowRow || nowRow.keyRef !== matches[k].keyRef) {
          stranded.push(matches[k].keyRef);
          continue;
        }
        try { await _eraseKey(nowRow.keyRef); erased += 1; }
        catch (_e) { stranded.push(nowRow.keyRef); }
      }
      if (stranded.length > 0) {
        throw err(KEYS_STRANDED, "dkim.retire: " + domain + " has stopped signing with " +
          retired.join(" and ") + ", and these sealed private keys could not be erased: " +
          stranded.join("; ") + ". Nothing signs with them, so remove them by hand.");
      }
      rows = _selectors(domain).filter(function (s) {
        return retired.indexOf(s.selector) !== -1;
      });
    } catch (e) {
      outcome = _stoppedAt(phase);
      reason = _refusalText(e);
      stopped = e;
    }

    try {
      await b.audit.record({
        action:   "blamepost.mail.dkim.keys_retired",
        outcome:  outcome,
        actor:    auditActor.current(),
        resource: resource,
        reason:   reason,
        metadata: {
          domain:     domain,
          requested:  [_recordable(retireOpts.selector), _recordable(retireOpts.rsaSelector)],
          retired:    _keyNames(retiredRows),
          keysErased: erased,
        },
      });
    } catch (_e) {
      // Drop-silent by design: the private keys are gone by this point
      // and nothing puts them back, so a row that could not be written
      // must not turn a finished retirement into a reported failure the
      // operator would then try to repeat.
    }

    if (stopped !== null) throw stopped;
    return { domain: domain, retired: rows, publish: _selectors(domain) };
  }

  /**
   * @primitive blamepost.mail.dkim.sweep
   * @signature dkim.sweep(opts?)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.6.1
   * @related   blamepost.mail.dkim.retire
   *
   * Step three of rotation. Removes the rows of retired selectors whose
   * overlap has elapsed and returns them, which is the set of DNS
   * records the operator can now delete. Nothing is removed from the
   * zone by this server.
   *
   * `immediate` withdraws a selector while its overlap is still
   * running. That is the right answer for exactly one situation, a key
   * you believe is exposed, and the wrong answer otherwise: it turns
   * every message signed under that selector and still being retried
   * into a DKIM failure.
   *
   * `keysLeftAside` is empty on every ordinary run and is the one answer
   * that needs somebody to go and look. It names a sealed private key
   * that was moved out of its place, could not be destroyed once its row
   * had gone, and is now sitting under a name no row points at. Nothing
   * here will find it again, so delete it by hand.
   *
   * Records the run under `blamepost.mail.dkim.selectors_swept`, naming
   * the selectors withdrawn and whether their records were pulled early.
   * The store writes its own row per selector; this one is the run that
   * chose to write them, which is the fact an incident needs when the
   * early answer was the one taken.
   *
   * @opts
   *   domain:    string,    // one domain; every domain when omitted
   *   immediate: boolean,   // withdraw before the overlap elapses
   *
   * @example
   *   var swept = await dkim.sweep();
   *   swept.withdrawn.forEach(function (s) { console.log(s.dnsName); });
   */
  async function sweep(sweepOpts) {
    sweepOpts = sweepOpts || {};
    var immediate = sweepOpts.immediate === true;
    var scope = sweepOpts.domain ? _assertDomain(sweepOpts.domain, "dkim.sweep") : null;
    var resource = scope === null ? null : _domainResource(scope);

    var phase = _phase();
    var outcome = "success";
    var reason = immediate
      ? "withdrawn before the overlap elapsed at the operator's request"
      : null;
    var withdrawn = [];
    var leftAside = [];
    var stopped = null;
    try {
      var now = Date.now();
      var query = { status: "retiring" };
      if (scope !== null) query.domain = scope;
      var rows = store.domains.listSelectors(query).map(_present);
      for (var i = 0; i < rows.length; i += 1) {
        var row = rows[i];
        // The store applies the same window check, so reading its own
        // clock here rather than an argument keeps the two from
        // disagreeing about whether a selector is still published.
        if (!immediate && (typeof row.retiresAt !== "number" || row.retiresAt > now)) continue;
        phase.committed = true;
        var taken = await store.domains.removeSelector({
          domain:    row.domain,
          selector:  row.selector,
          algorithm: row.algorithm,
          immediate: immediate,
          reason:    immediate
            ? "withdrawn before the overlap elapsed at the operator's request"
            : "overlap elapsed; the record can leave the zone",
        });
        withdrawn.push(row);
        // Carried up rather than left in the store's audit row alone.
        // A key the volume would not destroy once its row had gone is
        // sitting under a name nothing points at, and this verb is what
        // the operator ran, so this is where they find out.
        leftAside = leftAside.concat(taken.keysLeftAside);
      }
    } catch (e) {
      outcome = _stoppedAt(phase);
      reason = _refusalText(e);
      stopped = e;
    }

    try {
      await b.audit.record({
        action:   "blamepost.mail.dkim.selectors_swept",
        outcome:  outcome,
        actor:    auditActor.current(),
        resource: resource,
        reason:   reason,
        metadata: {
          domain:        scope,
          immediate:     immediate,
          withdrawn:     _keyNames(withdrawn),
          keysLeftAside: leftAside,
        },
      });
    } catch (_e) {
      // Drop-silent by design: the rows are already gone, and reporting
      // a completed sweep as a failure would send the operator to look
      // for records this server has stopped asking them to publish.
    }

    if (stopped !== null) throw stopped;
    return { withdrawn: withdrawn, keysLeftAside: leftAside };
  }

  // One selector's key file, moved from the plain volume seal to a seal
  // bound to the selector it belongs to.
  //
  // Every answer but one leaves the file alone, and the one that writes
  // writes only a value this server has just proved is the key the
  // selector's own record publishes. Binding anything else would take a
  // value that can still be refused, because nothing places it, and turn
  // it into one that cannot, because the seal would then say it belongs
  // here. So a file that does not open, carries no seal, or opens to
  // something other than the record's key is reported and left exactly
  // as it was found.
  //
  // The row is read again immediately before the write. Every selector
  // ahead of this one suspended on its own write, so the row this call
  // was handed was read before any of that ran, and a file unlinked in
  // the meantime is one this server can no longer account for. Writing a
  // key back under a name no row points at is the one outcome worse than
  // stopping: it puts signing material on the volume that nothing will
  // ever find again.
  async function _resealOne(row, phase) {
    var context = _keySealContext(row.domain, row.selector, row.algorithm);
    var target = _keyPath(row.keyRef);

    var sealed;
    try {
      sealed = b.atomicFile.readSync(target, {
        maxBytes: MAX_KEY_FILE_BYTES,
        encoding: "utf8",
      });
    } catch (readError) {
      // A retiring selector keeps its record published and its private
      // key is erased at the moment it stops signing, so a row with no
      // file is ordinary rather than a fault.
      if (readError && readError.code === "ENOENT") return { state: "absent" };
      return { state: "refused", reason: "it could not be read from this volume (" +
        ((readError && readError.code) || "unknown") + ")" };
    }

    if (vault.aad.isAadSealed(sealed)) {
      try { vault.aad.unseal(sealed, context); }
      catch (_boundError) {
        return { state: "refused",
          reason: "it is sealed, and not as this selector's signing key" };
      }
      return { state: "bound" };
    }
    if (sealed.indexOf(VAULT_SEAL_PREFIX) !== 0) {
      return { state: "refused", reason: "it carries no seal at all, so whatever it holds " +
        "has been readable to anyone who can read this volume" };
    }

    var opened;
    try { opened = vault.unseal(sealed); }
    catch (_sealError) {
      return { state: "refused", reason: "it did not open, so it was written under a " +
        "different volume's vault key or its bytes have been damaged where they lie" };
    }

    var derived;
    try { derived = _publishedHalfOf(opened, row.algorithm); }
    catch (_parseError) { derived = null; }
    if (derived === null || derived !== row.publicKey) {
      return { state: "refused", reason: "it is not the key its record publishes, and " +
        "sealing it to this selector would say that it is" };
    }

    var settled = _findSelector(_selectors(row.domain), row.selector, row.algorithm);
    if (!settled || settled.keyRef !== row.keyRef) {
      return { state: "refused",
        reason: "the selector row stopped naming this key while the migration was running" };
    }

    try {
      await b.atomicFile.write(target, vault.aad.seal(opened, context), { fileMode: 0o600 });
    } catch (writeError) {
      // The write puts its bytes under a temporary name and becomes the
      // file with a rename, and removes that temporary file when it does
      // not get there, so a refused write leaves the key that was there
      // and nothing beside it.
      return { state: "refused", reason: "the volume would not take the write (" +
        ((writeError && writeError.code) || "unknown") + "), so the key is as it was" };
    }
    phase.committed = true;
    return { state: "resealed" };
  }

  /**
   * @primitive blamepost.mail.dkim.reseal
   * @signature dkim.reseal(opts?)
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: a signing key is sealed to the selector it belongs to)
   * @related   blamepost.mail.dkim.generate, blamepost.mail.dkim.signerFor
   *
   * Seal the private keys already on the volume to the selectors they
   * belong to. Every key this server mints is sealed that way; a key
   * minted before the binding existed carries the plain volume seal,
   * which opens wherever it is found, and this is the one-time run that
   * moves it.
   *
   * Each key is opened, checked against the public half its own selector
   * row publishes, and written back sealed to that row. A key that does
   * not open, carries no seal, or is not the key its record publishes is
   * left exactly as it was and named in the refusal, because sealing it
   * to a selector would say it belongs there and nothing here can tell
   * whether it does.
   *
   * Safe to run again. A key already bound is reported and not rewritten,
   * so an operator who is not sure whether the run has happened can
   * repeat it, and a run cut off part way is finished by running it
   * again. A key is written by the same atomic write every other file on
   * this volume gets: the bytes go under a temporary name and a rename
   * makes them the file, so a run that stops leaves either the key that
   * was there or the key that replaces it. A signing key has one copy
   * and nothing anywhere holds a second.
   *
   * The server keeps signing throughout. A key still carrying the plain
   * seal opens and is checked against its record exactly as a bound one
   * is, so a volume part way through signs with every key it can place
   * and refuses every key it cannot.
   *
   * Records the run under `blamepost.mail.dkim.keys_resealed`, naming the
   * operator, the domain and each selector whose key was rewritten. Key
   * material at rest changing hands is what a key-lifecycle row exists
   * for, and this is the only verb that rewrites a key without changing
   * which keys exist.
   *
   * @opts
   *   domain: string,   // one domain; every domain when omitted
   *
   * @example
   *   var moved = await dkim.reseal({ domain: "example.com" });
   *   moved.resealed.length;   // how many keys were sealed to their selector
   */
  async function reseal(resealOpts) {
    resealOpts = resealOpts || {};
    var scope = resealOpts.domain ? _assertDomain(resealOpts.domain, "dkim.reseal") : null;
    var resource = scope === null ? null : _domainResource(scope);

    var phase = _phase();
    var outcome = "success";
    var reason = null;
    var resealed = [];
    var alreadyBound = [];
    var absent = [];
    var refused = [];
    var stopped = null;
    try {
      var query = {};
      if (scope !== null) query.domain = scope;
      var rows = store.domains.listSelectors(query).map(_present);
      for (var i = 0; i < rows.length; i += 1) {
        var row = rows[i];
        var verdict = await _resealOne(row, phase);
        if (verdict.state === "resealed") {
          resealed.push(row);
          // The signer holds the key it opened, and the key it opened is
          // still the right one, but the handle was built against a file
          // that has been replaced. Dropping it means the next message
          // reads the file as it now stands.
          signerCache.delete(row.domain);
        } else if (verdict.state === "bound") {
          alreadyBound.push(row);
        } else if (verdict.state === "absent") {
          absent.push(row);
        } else {
          refused.push({
            domain:    row.domain,
            selector:  row.selector,
            algorithm: row.algorithm,
            reason:    verdict.reason,
          });
        }
      }
      // Reported after every key has been reached rather than at the
      // first one, so a volume holding one key this server cannot place
      // still gets the rest of them sealed to their selectors.
      if (refused.length > 0) {
        throw err(KEYS_NOT_RESEALED, "dkim.reseal: these signing keys were left as they " +
          "were, because nothing here can say they belong to the selector that names them: " +
          refused.map(function (one) {
            return one.domain + " '" + one.selector + "' (" + one.algorithm + "), because " +
              one.reason;
          }).join("; ") + ". Every other key on this volume is sealed to its selector now. " +
          "Run `blamepost dkim list` to see what each domain publishes, restore the volume " +
          "from a backup whose keys folder and database were taken together, or retire each " +
          "pair named here and mint a replacement with `blamepost dkim generate`.");
      }
    } catch (e) {
      outcome = _stoppedAt(phase);
      reason = _refusalText(e);
      stopped = e;
    }

    try {
      await b.audit.record({
        action:   "blamepost.mail.dkim.keys_resealed",
        outcome:  outcome,
        actor:    auditActor.current(),
        resource: resource,
        reason:   reason,
        metadata: {
          domain:       scope,
          resealed:     _keyNames(resealed),
          alreadyBound: _keyNames(alreadyBound),
          absent:       _keyNames(absent),
          refused:      _keyNames(refused),
        },
      });
    } catch (_e) {
      // Drop-silent by design: the keys this run rewrote are written and
      // nothing puts them back, so a row that could not be written must
      // not turn a finished migration into a reported failure the
      // operator would then try to repeat.
    }

    if (stopped !== null) throw stopped;
    return { resealed: resealed, alreadyBound: alreadyBound, absent: absent };
  }

  /**
   * @primitive blamepost.mail.dkim.list
   * @signature dkim.list(domain?)
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: selector inventory for the command line and the admin interface)
   * @related   blamepost.mail.dkim.dnsRecords
   *
   * The selectors this server knows and their states. With a domain,
   * that domain's; without one, every domain's. No private key material
   * appears in the result, so the output is safe to print and safe to
   * render.
   *
   * @example
   *   var inventory = await dkim.list("example.com");
   *   inventory[0].state;   // "active"
   */
  function list(domain) {
    if (domain) return _selectors(_assertDomain(domain, "dkim.list"));
    return store.domains.listSelectors({}).map(_present);
  }

  /**
   * @primitive blamepost.mail.dkim.dnsRecords
   * @signature dkim.dnsRecords(domain)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.6.1, RFC 1035 §3.3.14
   * @related   blamepost.mail.dkim.list
   *
   * Every DKIM record that must currently be in the domain's zone: the
   * active selectors and the retiring ones still inside their overlap.
   * This is what `blamepost doctor` resolves and compares, so a record
   * published with a typo or pulled too early is named precisely.
   *
   * @example
   *   var records = await dkim.dnsRecords("example.com");
   *   records[0].dnsName;   // "bp202608._domainkey.example.com"
   */
  function dnsRecords(domain) {
    return _selectors(_assertDomain(domain, "dkim.dnsRecords")).filter(function (s) {
      return s.state !== "retired";
    });
  }

  /**
   * @primitive blamepost.mail.dkim.signerFor
   * @signature dkim.signerFor(domain)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 8463 §3 (dual signing)
   * @related   blamepost.mail.dkim.sign
   *
   * The signer for one domain, built from its active selectors and
   * cached until they change. Each pair composes
   * `b.mail.dkim.dualSigner`, so the header shape, the
   * canonicalization and the signed header set are the framework's.
   * A domain part way through a rotation has two pairs and every pair
   * signs, which is what keeps both the old and the new signature on
   * the message during the changeover.
   *
   * Each sealed key is checked against the public half its own selector
   * row publishes before it signs anything. A key file and the row that
   * names it are two places, and a restore that brings back one without
   * the other leaves a file that opens and parses under a record
   * carrying a different key. Every other reading on this server answers
   * off the row, so without this the domain looks correct everywhere
   * while its signatures fail at every receiver.
   *
   * @example
   *   var signer = dkim.signerFor("example.com");
   *   var signed = signer.sign(rfc822);
   */
  function signerFor(domain) {
    var name = _assertDomain(domain, "dkim.signerFor");
    if (signerCache.has(name)) return signerCache.get(name);
    var signers = _activePairs(name, "dkim.signerFor").map(function (pair) {
      return b.mail.dkim.dualSigner({
        domain:           name,
        headersToSign:    headersToSign,
        canonicalization: canonicalization,
        eddsa: {
          selector:   pair.eddsa.selector,
          privateKey: _readKey(pair.eddsa, pair.eddsa.selector),
        },
        rsa: {
          selector:   pair.rsa.selector,
          privateKey: _readKey(pair.rsa, pair.eddsa.selector),
        },
      });
    });
    var handle = {
      pairs: signers.length,
      sign: function (rfc822) {
        var out = rfc822;
        for (var i = 0; i < signers.length; i += 1) out = signers[i].sign(out);
        return out;
      },
    };
    signerCache.set(name, handle);
    return handle;
  }

  /**
   * @primitive blamepost.mail.dkim.sign
   * @signature dkim.sign(domain, rfc822)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 6376 §3.5, RFC 8463 §3
   * @related   blamepost.mail.dkim.signerFor
   *
   * Sign one message and return it with the signature headers
   * prepended. Accepts a Buffer or a string and returns the same kind,
   * so a caller holding wire bytes keeps holding wire bytes.
   *
   * The octets that come back below the prepended headers are the octets
   * that went in, and the signature covers those same octets. That pair
   * is the whole guarantee, and either half alone is worthless: a signer
   * that returns the message intact but hashes a decoded copy of it
   * emits a signature that fails at every receiver, and one that hashes
   * and returns the same decoded copy emits a signature over a message
   * the sender never wrote. An unencoded 8-bit body in a legacy
   * single-byte charset is the ordinary case that finds the difference,
   * and so is a message whose line endings arrived as bare LF.
   *
   * A domain that does not hold one active selector per algorithm
   * refuses, because sending unsigned mail from a domain whose DMARC
   * record promises a signature is worse than saying so. That covers a
   * domain holding neither half and a domain holding one, and the
   * refusal names which of the two it met, since only one of them has
   * a verb that repairs it in place and neither of them is obvious from
   * the outside. Both callers treat that refusal as an unsigned send:
   * the message goes out unaltered and a row records that it carries no
   * signature.
   *
   * @example
   *   var signed = await dkim.sign("example.com", rfc822Bytes);
   */
  async function sign(domain, rfc822) {
    return signerFor(domain).sign(rfc822);
  }

  function describe() {
    return {
      keyDir:           keyDir,
      canonicalization: canonicalization,
      headersToSign:    headersToSign.slice(),
      selectors:        list().length,
    };
  }

  return {
    generate:   generate,
    rotate:     rotate,
    retire:     retire,
    sweep:      sweep,
    reseal:     reseal,
    list:       list,
    dnsRecords: dnsRecords,
    signerFor:  signerFor,
    sign:       sign,
    describe:   describe,
  };
}

module.exports = {
  create:         create,
  // The one erasure of a sealed private key, exported because the rows
  // that name those files are deleted a layer away. It takes a data
  // directory rather than a handle, so the identity layer can reach it
  // without building a signer it has no other use for.
  eraseKeyFiles:  eraseKeyFiles,
  ALGORITHMS: Object.freeze({ eddsa: ALG_EDDSA, rsa: ALG_RSA }),
  // Every code this module composes, exported so a caller names the same
  // constant this module throws rather than a copy of the string that can
  // drift out of step with it. The code is the contract a caller reads;
  // the error class stays private, because branching on the code is what
  // a caller needs and an exported class is a second thing to keep
  // compatible.
  //
  // Two callers read this for two different questions, and the set has to
  // be complete for the second.
  //
  // The relay and compose paths branch on ONE entry, `noActiveSelector`,
  // to decide which action a message that went out unsigned is filed
  // under: a domain nobody has finished setting up is repaired by minting
  // a pair, and everything else by restoring or replacing one.
  //
  // An operator-facing surface asks the other question, which is whether
  // a refusal was worded for a reader at all and may therefore be shown.
  // The `dkim/` prefix cannot answer that, because the framework codes
  // its own DKIM faults under the same prefix and writes them for
  // whoever composed the framework: `dkim/bad-rsa-bits` names an option
  // path, and the family raised while a signer is built names primitives
  // an operator has no way to act on. Membership in this set is the
  // answer instead. It is decided by what this module actually throws,
  // since every value here is the constant a throw site names, so a code
  // the framework invents can never enter it and a code added here
  // arrives already in it.
  CODES: Object.freeze({
    noActiveSelector:      NO_ACTIVE_SELECTOR,
    keyUnreadable:         KEY_UNREADABLE,
    keyNotSealed:          KEY_NOT_SEALED,
    keySealUnopened:       KEY_SEAL_UNOPENED,
    keySealForeign:        KEY_SEAL_FOREIGN,
    keyRecordMismatch:     KEY_RECORD_MISMATCH,
    keysNotResealed:       KEYS_NOT_RESEALED,
    selectorNameCollision: SELECTOR_NAME_COLLISION,
    selectorTaken:         SELECTOR_TAKEN,
    selectorNameTooLong:   SELECTOR_NAME_TOO_LONG,
    keysAlreadyActive:     KEYS_ALREADY_ACTIVE,
    noSuchSelector:        NO_SUCH_SELECTOR,
    keysStranded:          KEYS_STRANDED,
    keyFileHeld:           KEY_FILE_HELD,
  }),
};
