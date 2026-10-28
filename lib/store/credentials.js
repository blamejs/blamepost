// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.credentials
 * @nav    Sending
 * @title  Sending credentials
 * @order  30
 *
 * Sending credentials: a secret an application presents to send mail as
 * a domain this server hosts. One credential covers every local part in
 * its domain, so what it is scoped to is the domain and never a single
 * address.
 *
 * The secret is printed once, at creation, and nothing here returns it
 * again. What the volume holds is a SHAKE256 envelope over it, so a
 * credential is compared and never recovered, and a copy of the data
 * directory yields digests rather than live credentials. The password
 * hash beside it in the account table is Argon2id because a person
 * chooses a password; this secret is 256 bits the server generated, so
 * memory-hard hashing adds no protection to it, and this server would
 * perform that work on every connection, including each one from anyone
 * spraying the port.
 *
 * The scope is read from the store rather than from the wire. A caller
 * presents a token, and the domain comes back off the row the token
 * names. Two things pin it there. The domain is the framework
 * registry's owner column, which is sealed and carries the indexed hash
 * every per-domain listing is resolved through. And a keyed digest over
 * the row's own identity, its domain, its bounce mailbox, its refusal
 * list and its ceilings is stored beside them and checked on every
 * verify, so a cell copied from another row, a refusal list shortened on
 * the volume, or a record that cannot be parsed at all stops the
 * credential rather than answering with the wrong domain or with no
 * restrictions. The key that digest is computed under is vault-sealed,
 * so write access to the database file is not enough to mint one.
 *
 * A credential must name a mailbox for its bounces, and that mailbox has
 * to exist and be in service before the credential is written. A
 * credential pointing at nothing discards every bounce at the door while
 * the application keeps sending, and nobody is told.
 *
 * The bounces come back to an address of the credential's own rather than
 * to the address it sent as. A credential may write as every local part
 * in its domain, and almost none of them hold a mailbox, so a receiver
 * returning a message to the address it came from reaches an address this
 * server answers `no-such-mailbox` for. Each credential therefore carries
 * a return path, `bounces+<tag>@<domain>`, and the domain carries one
 * alias at `bounces@<domain>` pointing at the mailbox the operator named.
 * Routing folds an RFC 5233 tag away before it looks the alias up, so the
 * one alias carries every credential in the domain, and the tag stays on
 * the envelope and in the delivered `To` so the bounce mailbox can tell
 * whose bounce it is reading.
 *
 * The tag is derived from the identifier under the deployment's
 * vault-sealed derived-hash key and is not the identifier. The return
 * path goes into the envelope sender of everything the credential sends,
 * so the tag reaches every recipient the application writes to, while the
 * identifier is what `blamepost.mail.listeners.verifySendingCredential`
 * keys its failure budget on. Publishing the identifier there would have
 * handed every correspondent of the application a key into that budget.
 * `returnPathTag` is on every record this module hands back and
 * `byReturnPathTag` resolves one to the credential it names, so the
 * operator reading the bounce mailbox still knows whose bounce it is.
 *
 * Creation writes that alias when nothing is standing at the address, and
 * refuses when something is standing there that does not already deliver
 * to the mailbox the credential named. Reusing a stranger's alias would
 * route this credential's bounces to a mailbox chosen for something else,
 * and replacing it would take mail away from wherever it was going, so
 * neither happens without the operator being told which two addresses are
 * in the way.
 *
 * Withdrawal removes the alias with the last credential in the domain and
 * not before, because the alias is shared. It removes only an alias this
 * registry put there: one the operator created for their own reasons is
 * left standing.
 *
 * Whether a return path still reaches its mailbox is asked on every read
 * rather than only at creation. An archived bounce mailbox leaves the
 * credential unchanged and every bounce refused at the door, so `show`,
 * `list` and `returnPathReport` each resolve the return path and report
 * where it actually lands.
 *
 * Rotation replaces the secret with no grace by default, because the
 * reason to rotate is usually that the old secret is in somebody else's
 * hands. A grace window is a number the operator names, and it is
 * bounded.
 *
 * Two ceilings ride on each credential over a rolling window, one on
 * messages and one on recipients. A hundred messages carrying one
 * recipient each and one message carrying a hundred thousand are
 * different events, and the second is the one a leaked credential
 * produces, so a single counter cannot see it. The counters are held in
 * this process on a clock the host cannot step, for the reason the
 * account failure budgets are.
 *
 * The rows are filed under the domain the credential is scoped to,
 * because that is the resource an operator reads the trail against.
 *
 * `create(ctx)` builds the registry. It reaches nothing on its own: the
 * two handles it needs are passed in, so this module composes against
 * them rather than reaching back into the assembly that built it.
 *
 * @opts
 *   domains:  handle,     // required, blamepost.store.domains: which domains are hosted and
 *                         //   in service, asked at creation and again at every verify
 *   accounts: handle,     // required, blamepost.store.accounts: whether the bounce mailbox
 *                         //   exists and is in service, and which mailboxes in a domain
 *                         //   carry the operator role and so start on the refusal list
 *   aliases:  handle,     // required, blamepost.store.aliases: the return path alias is
 *                         //   written, read and removed through it
 *   resolve:  function,   // required, blamepost.store.resolve: where a return path actually
 *                         //   delivers, asked at creation and on every operator-facing read
 *   clock:    function,   // optional, () -> unix ms; the clock the ceiling windows are
 *                         //   measured on. Defaults to a steady one anchored on the wall
 *                         //   clock at load and advanced by a source the host cannot step.
 */

var b          = require("../vendor/blamejs");
var address    = require("./address");
var auditActor = require("./actor");
var errors     = require("./errors");

var err = errors.err;

// The token prefix and namespace. Together they are the first two
// underscore-separated parts of every token this server issues, so a
// leaked one is recognizable on sight and a secret scanner can pin the
// whole shape: <prefix>_<namespace>_<16 hex>_<64 hex>. Neither may carry
// an underscore, because the framework's parser splits on that
// character. They are constants rather than options: an operator who
// could change them would change the string every scanner pattern is
// written against.
var TOKEN_PREFIX    = "bpk";
var TOKEN_NAMESPACE = "send";

// Bytes of randomness in the secret. The framework issues sixteen, which
// is already past brute force; thirty-two costs nothing here because
// verification is a SHAKE256 pass over the presented bytes, and this
// credential speaks for every address in a hosted domain.
var SECRET_BYTES = b.constants.BYTES.bytes(32);

// Bytes of randomness in the identifier. It names a row and is not a
// secret.
var ID_BYTES = b.constants.BYTES.bytes(8);

// The digest algorithm for the stored secret, named here rather than
// inherited. SHAKE256 is the right choice for a machine-generated
// secret and it is what this module's per-connection verify budget is
// sized against, so it should not move because an unrelated framework
// default moved.
var SECRET_HASH_ALGO = "shake256";

// How long a credential lasts when the operator names no expiry. A
// sending credential with no end date is one nobody ever revisits.
var DEFAULT_LIFETIME_MS = b.constants.TIME.days(365);

// The longest grace window a rotation may name. Beyond a week the prior
// secret is not a migration window, it is a second live credential.
var MAX_GRACE_MS = b.constants.TIME.days(7);

// The rolling window the two ceilings are measured over, and the bounds
// an operator may set it to.
var DEFAULT_WINDOW_MS = b.constants.TIME.hours(1);
var MIN_WINDOW_MS     = b.constants.TIME.minutes(1);
var MAX_WINDOW_MS     = b.constants.TIME.days(1);

// The ceilings a credential carries when the operator names none. Both
// are finite, because a ceiling that defaults to no ceiling is a
// protection an operator has to remember to switch on.
var DEFAULT_MAX_MESSAGES   = 1000;
var DEFAULT_MAX_RECIPIENTS = 5000;

// The largest either ceiling may be set to. A number past this is not a
// ceiling, and accepting it would let one stand in for the absence of
// one.
var MAX_CEILING = 10000000;

// How many slices the rolling window is divided into. The counters sum
// the slices still inside the window and drop the rest, so the memory
// one credential costs is this many small records however fast it
// sends.
var WINDOW_SLICES = 60;

// The local parts every credential refuses by default, on top of the
// mailboxes carrying the operator role in its domain. A whole-domain
// scope is a decision about ordinary addresses, and these two are the
// addresses a recipient writes to when they want to reach a person
// rather than the application.
var ALWAYS_REFUSED = ["postmaster", "abuse"];

// How many local parts one refusal list may hold, and how long each may
// be. RFC 5321 caps a local part at 64 octets.
var MAX_REFUSED_ENTRIES   = 200;
var MAX_LOCAL_PART_OCTETS = 64;

// The local part every return path in a domain folds down to. One address
// per domain rather than one per credential, because routing strips the
// RFC 5233 tag before the alias lookup: `bounces+<id>@<domain>` and
// `bounces@<domain>` reach the same alias row, so the tag distinguishes
// the credentials and the alias serves all of them. A local part per
// credential would need an alias row per credential, and withdrawing one
// would leave a row behind pointing at a mailbox nothing sends to.
//
// It is a constant rather than an option. An operator who could move it
// would move the address their DNS, their mailbox layout and every
// already-issued credential's return path all name.
var RETURN_PATH_LOCAL_PART = "bounces";

// The discriminator on the stored record. A row under this namespace
// that does not carry it was written by something other than this
// module, and it is refused rather than read as a credential with no
// restrictions.
var RECORD_KIND    = "blamepost.sending-credential";
var RECORD_VERSION = 1;

// The namespace the row-binding digest is computed under. It is a label
// on the keyed digest rather than a secret; the key itself is the
// deployment's vault-sealed derived-hash key.
var BINDING_NAMESPACE = "blamepost.sending-credential.binding";

// The namespace the return path tag is derived under, and how much of
// the digest the tag keeps.
//
// The tag is what the RFC 5233 tag on a credential's return path is, and
// the return path rides on the envelope of everything the credential
// sends, so the tag reaches every recipient the application writes to.
// It is derived from the identifier under the same vault-sealed
// derived-hash key the binding above is computed under, and it is not
// the identifier. The identifier keys the failure budget that bounds
// guessing at the credential's secret, and a budget key published to
// every correspondent is a budget those correspondents can spend.
//
// Sixteen bytes is thirty-two hexadecimal characters. RFC 5321 caps a
// local part at 64 octets and `bounces+` takes eight of them, so the tag
// fits with room left. What the width has to buy is that two credentials
// in one domain do not derive the same tag, since the bounce reader
// tells them apart by it, and 128 bits buys that against far more
// credentials than a server holds.
var RETURN_PATH_TAG_NAMESPACE = "blamepost.sending-credential.return-path";
var RETURN_PATH_TAG_BYTES     = 16;

// The shape a tag is read back in, for the lookup that resolves one to
// the credential it names. It is the shape the derivation above
// produces, so a string that is not this shape named no credential this
// server issued and is refused rather than compared against every row.
var RETURN_PATH_TAG_RE = /^[0-9a-f]{32}$/;

// Where the ceiling counters live, and how many credentials are counted
// at once. The cache drops its least recently used entry beyond this,
// and a dropped counter is a counter back at zero, so the number is set
// far above the number of sending credentials a server plausibly holds.
var WINDOW_CACHE_NAMESPACE = "blamepost.sending-credential.window";
var WINDOW_CACHE_ENTRIES   = 10000;

// The two readings the clock below is built out of, taken together at
// load so the pair describes one instant.
var WALL_ORIGIN_MS    = Date.now();
var ELAPSED_ORIGIN_MS = b.time.monotonicMs();

// The clock the ceiling windows are measured on: where the wall clock
// stood when this module loaded, advanced from there by a source the
// host cannot move.
//
// Everything a ceiling decides is a duration. `Date.now()` answers what
// time it is, and it moves when an operator corrects a wrong time, when
// NTP steps a drifted host, and when a container starts before it has
// synchronized and then catches up. A window measured against it is one
// the host's clock hands back: a step forward clears a window that has
// not rolled, and a step backwards holds counts past the point they
// should have gone. Neither surfaces as an error anywhere. The account
// failure budgets are measured this way for the same reason.
//
// It is anchored on the wall clock rather than being a bare elapsed
// count, because a reading handed to an operator names an instant. The
// cache underneath takes the SAME clock: a window measured on a steady
// clock and stored against the wall clock is still handed back by a step
// forward, since the arithmetic says the counts stand and the entry they
// were written on is simply gone.
function _steadyNow() {
  return WALL_ORIGIN_MS + (b.time.monotonicMs() - ELAPSED_ORIGIN_MS);
}

function _requireOpts(opts, fn) {
  if (typeof opts !== "object" || opts === null || Array.isArray(opts)) {
    throw err("store/bad-argument", "credentials." + fn + " takes an options object.");
  }
  return opts;
}

// A reason is required on every verb that changes a credential. These
// are operator actions against a secret that speaks for a whole domain,
// and the trail is where they are answered for.
function _requireReason(value, fn) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument",
      "credentials." + fn + " needs a reason. Changing a credential that can send as every " +
      "address in a hosted domain is an operator action, and the audit trail is where it is " +
      "answered for.");
  }
  return value.trim();
}

function _requireId(value, fn) {
  if (typeof value !== "string" || !/^[0-9a-f]{2,64}$/.test(value)) {
    throw err("store/bad-argument",
      "credentials." + fn + ": id must be the hexadecimal identifier this registry issued, " +
      "got " + JSON.stringify(value) + ".");
  }
  return value;
}

// A whole number inside a named range, refused at the call rather than
// carried into arithmetic that cannot tell a value it was never meant to
// receive from one it was.
function _requireWholeNumber(value, fallback, low, high, label) {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !isFinite(value) || Math.floor(value) !== value) {
    throw err("store/bad-argument",
      label + " must be a whole number, got " + JSON.stringify(value) + ".");
  }
  if (value < low || value > high) {
    throw err("store/bad-argument",
      label + " must be between " + low + " and " + high + ", got " + value + ".");
  }
  return value;
}

// The expiry a credential is created with. Absent means the default
// lifetime, an explicit null means the operator has decided to watch
// this one by hand, and a moment already past is refused rather than
// written as a credential that never works.
function _readExpiry(value, nowMs) {
  if (value === undefined) return nowMs + DEFAULT_LIFETIME_MS;
  if (value === null) return null;
  if (typeof value !== "number" || !isFinite(value) || Math.floor(value) !== value) {
    throw err("store/bad-argument",
      "expiresAt must be a whole number of milliseconds since the epoch, or null for a " +
      "credential with no end date, got " + JSON.stringify(value) + ".");
  }
  if (value <= nowMs) {
    throw err("store/bad-argument",
      "expiresAt is already past, so the credential would never verify. Name a moment in " +
      "the future, or null for a credential with no end date.");
  }
  return value;
}

// One local part, checked by building the address it would name in the
// credential's own domain and reading it back. The refusal list is
// compared against the local part of a sender at send time, so an entry
// this server could not parse as one would sit in the list matching
// nothing.
function _readLocalPart(value, domain) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument",
      "a refused local part must be a non-empty string, got " + JSON.stringify(value) + ".");
  }
  var text = value.trim();
  if (Buffer.byteLength(text, "utf8") > MAX_LOCAL_PART_OCTETS) {
    throw err("store/bad-argument",
      "a refused local part is longer than the " + MAX_LOCAL_PART_OCTETS +
      " octets a local part may carry: " + JSON.stringify(text) + ".");
  }
  var verdict = address.parse(text + "@" + domain);
  if (!verdict.ok) {
    throw err("store/bad-argument",
      JSON.stringify(text) + " does not read as a local part, so it would sit in the " +
      "refusal list matching nothing.");
  }
  // A plus tag is a routing suffix a sender chose rather than part of
  // the name a mailbox holds. An entry carrying one would refuse exactly
  // one spelling of an address and admit every other spelling of the
  // same mailbox, so the entry names the mailbox instead.
  if (verdict.tag !== null) {
    throw err("store/bad-argument",
      JSON.stringify(text) + " carries a plus tag, which routes to " + verdict.localPart +
      ". Name " + JSON.stringify(verdict.localPart) + " instead, so every spelling that " +
      "reaches that mailbox is refused rather than one of them.");
  }
  return verdict.localPart;
}

// A refusal list in the one shape it is ever stored and compared in:
// sorted, with no repeats. Sorting is what makes the stored list and a
// list rebuilt from the same entries produce the same binding digest.
function _normalizeRefusedList(values, domain) {
  if (!Array.isArray(values)) {
    throw err("store/bad-argument",
      "the refused local parts must be an array of local parts, got " + typeof values + ".");
  }
  if (values.length > MAX_REFUSED_ENTRIES) {
    throw err("store/bad-argument",
      "a refusal list may hold at most " + MAX_REFUSED_ENTRIES + " local parts, got " +
      values.length + ".");
  }
  var out = [];
  for (var i = 0; i < values.length; i += 1) {
    var part = _readLocalPart(values[i], domain);
    if (out.indexOf(part) === -1) out.push(part);
  }
  out.sort();
  return out;
}

// What the binding digest is taken over. Everything a caller acts on
// after a verify is in here, so a cell moved between rows or edited on
// the volume changes the digest and the credential stops rather than
// answering with whatever the edit put there.
//
// The identifier is in it because that is what makes the digest
// row-specific: the sealed cells on this table are relocatable between
// rows, and a digest over the policy alone would travel with them.
function _bindingPayload(record) {
  return {
    v:                 RECORD_VERSION,
    id:                record.id,
    namespace:         TOKEN_NAMESPACE,
    domain:            record.domain,
    bounceMailbox:     record.bounceMailbox,
    refusedLocalParts: record.refusedLocalParts,
    maxMessages:       record.maxMessages,
    maxRecipients:     record.maxRecipients,
    windowMs:          record.windowMs,
    // Whether this registry is what put the return path alias there. It
    // is in the digest because withdrawal reads it to decide whether to
    // take the alias away, and a cell flipped on the volume would either
    // strand a routing row or delete one the operator created, without
    // either showing up as a change to the credential.
    returnPathAliasMinted: record.returnPathAliasMinted,
    createdAt:         record.createdAt,
  };
}

// The address every return path in one domain folds down to, and the
// address one credential's bounces are addressed to. Both are derived
// rather than stored: the identifier and the domain are already in the
// binding, so a stored copy would be a second answer that could disagree
// with the first.
function _returnPathAddressFor(domain) {
  return RETURN_PATH_LOCAL_PART + "@" + domain;
}

// The tag one credential's bounces are addressed under. Keyed, so the
// identifier cannot be read back out of an address a recipient holds,
// and deterministic, so the same credential derives the same tag on
// every read and nothing has to be stored beside the row.
function _returnPathTagFor(id) {
  return b.cryptoField.computeNamespacedHash(RETURN_PATH_TAG_NAMESPACE, id, {
    mode:          "hmac-shake256",
    truncateBytes: RETURN_PATH_TAG_BYTES,
  });
}

// The address built from a tag. It takes the tag rather than the
// identifier, so there is one place the identifier is turned into the
// value that goes on the wire and no caller can reach this with the
// identifier by accident.
function _returnPathFor(tag, domain) {
  return RETURN_PATH_LOCAL_PART + address.TAG_SEPARATOR + tag + "@" + domain;
}

// The keyed digest itself. The key is the deployment's vault-sealed
// derived-hash key, which is what keeps this from being a checksum
// anybody holding the database file could recompute.
function _binding(record) {
  return b.cryptoField.computeNamespacedHash(
    BINDING_NAMESPACE,
    b.canonicalJson.stringify(_bindingPayload(record)),
    { mode: "hmac-shake256" });
}

// The stored record as it goes into the sealed metadata column.
function _metadataFor(record) {
  return {
    kind:              RECORD_KIND,
    version:           RECORD_VERSION,
    bounceMailbox:     record.bounceMailbox,
    refusedLocalParts: record.refusedLocalParts,
    maxMessages:       record.maxMessages,
    maxRecipients:     record.maxRecipients,
    windowMs:          record.windowMs,
    returnPathAliasMinted: record.returnPathAliasMinted,
    binding:           _binding(record),
  };
}

// Read one framework record back into this module's shape, and say
// whether the binding still holds.
//
// Nothing here throws. A record that cannot be read is a refusal rather
// than a fault, and the two callers want opposite things from it: verify
// stops the credential, and the operator-facing listing shows that the
// binding is broken, which is exactly what an operator needs to see.
//
// A record that is absent, of another kind, of a version this module
// does not write, or whose digest does not match comes back with every
// policy field null. Reading an unparseable record as a credential with
// an empty refusal list and no ceilings is the one interpretation that
// turns a damaged row into a wider credential than the one that was
// created.
//
// `storedDomain` is what the row says its scope is, whether or not the
// binding holds, and `domain` is that same value only once it does. The
// two answer different questions and are kept apart. Nothing decides
// what a credential may send as from `storedDomain`: it is there so an
// operator reading a broken credential sees which domain the row claims,
// and so a verb that revokes or removes one files a row against
// something rather than against nothing.
function _present(raw) {
  var shell = {
    id:                null,
    domain:            null,
    storedDomain:      null,
    bounceMailbox:     null,
    refusedLocalParts: null,
    maxMessages:       null,
    maxRecipients:     null,
    windowMs:          null,
    returnPathTag:     null,
    returnPath:        null,
    returnPathAliasMinted: null,
    createdAt:         null,
    expiresAt:         null,
    revokedAt:         null,
    lastUsedAt:        null,
    priorSecretUntil:  null,
    bindingHolds:      false,
  };
  if (!raw || typeof raw !== "object") return shell;

  shell.id         = typeof raw.id === "string" ? raw.id : null;
  shell.storedDomain =
    typeof raw.ownerId === "string" && raw.ownerId.length > 0 ? raw.ownerId : null;
  shell.createdAt  = typeof raw.createdAt === "number" ? raw.createdAt : null;
  shell.expiresAt  = typeof raw.expiresAt === "number" ? raw.expiresAt : null;
  shell.revokedAt  = typeof raw.revokedAt === "number" ? raw.revokedAt : null;
  shell.lastUsedAt = typeof raw.lastUsedAt === "number" ? raw.lastUsedAt : null;
  shell.priorSecretUntil =
    typeof raw.secondaryExpiresAt === "number" ? raw.secondaryExpiresAt : null;

  var meta = raw.metadata;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return shell;
  if (meta.kind !== RECORD_KIND || meta.version !== RECORD_VERSION) return shell;
  if (typeof raw.ownerId !== "string" || raw.ownerId.length === 0) return shell;
  if (typeof meta.bounceMailbox !== "string") return shell;
  if (!Array.isArray(meta.refusedLocalParts)) return shell;
  if (typeof meta.maxMessages !== "number" || typeof meta.maxRecipients !== "number") return shell;
  if (typeof meta.windowMs !== "number") return shell;
  // A record written before this field existed, or with it removed, is
  // one this module cannot answer the withdrawal question about. It is
  // refused rather than read as a credential that minted nothing, which
  // is the reading that would strand a routing row on the volume.
  if (typeof meta.returnPathAliasMinted !== "boolean") return shell;
  if (typeof meta.binding !== "string" || meta.binding.length === 0) return shell;
  if (shell.id === null || shell.createdAt === null) return shell;

  var candidate = {
    id:                shell.id,
    domain:            raw.ownerId,
    bounceMailbox:     meta.bounceMailbox,
    refusedLocalParts: meta.refusedLocalParts,
    maxMessages:       meta.maxMessages,
    maxRecipients:     meta.maxRecipients,
    windowMs:          meta.windowMs,
    returnPathAliasMinted: meta.returnPathAliasMinted,
    createdAt:         shell.createdAt,
  };
  var expected;
  try { expected = _binding(candidate); }
  catch (_bindingError) {
    // The digest could not be computed, which is a fault on this host
    // rather than an answer about the credential. It lands in the same
    // place as a mismatch, because a credential this server cannot
    // check the binding on is one it cannot say anything about.
    return shell;
  }
  if (!b.crypto.timingSafeEqual(expected, meta.binding)) return shell;

  var tag;
  try { tag = _returnPathTagFor(candidate.id); }
  catch (_tagError) {
    // The tag is derived under the same vault-sealed key the binding
    // above is computed under, so a host that could compute one could
    // compute the other and reaching here means the key went away
    // between the two. It lands where a broken binding lands: a
    // credential whose bounces this server cannot address is one it
    // cannot say anything about.
    return shell;
  }

  shell.domain            = candidate.domain;
  shell.bounceMailbox     = candidate.bounceMailbox;
  shell.refusedLocalParts = candidate.refusedLocalParts.slice();
  shell.maxMessages       = candidate.maxMessages;
  shell.maxRecipients     = candidate.maxRecipients;
  shell.windowMs          = candidate.windowMs;
  shell.returnPathAliasMinted = candidate.returnPathAliasMinted;
  shell.returnPathTag     = tag;
  shell.returnPath        = _returnPathFor(tag, candidate.domain);
  shell.bindingHolds      = true;
  return shell;
}

// The refusal of a credential, in the one shape every caller reads.
// `domain` is null on every refusal, so a caller that branches on `ok`
// and one that reads the domain cannot disagree about what happened.
function _refused(reason) {
  return {
    ok:                false,
    reason:            reason,
    credentialId:      null,
    domain:            null,
    bounceMailbox:     null,
    returnPathTag:     null,
    returnPath:        null,
    refusedLocalParts: null,
    maxMessages:       null,
    maxRecipients:     null,
    windowMs:          null,
    usedPriorSecret:   false,
  };
}

function create(ctx) {
  ctx = _requireOpts(ctx, "create");

  if (!ctx.domains || typeof ctx.domains.get !== "function") {
    throw new TypeError("blamepost.store.credentials.create: ctx.domains must be the hosted " +
      "domain handle. A credential names the domain it may send as, and a credential written " +
      "for a domain this server does not host is one whose mail leaves with no selector to " +
      "sign it and no policy record behind it.");
  }
  if (!ctx.accounts || typeof ctx.accounts.get !== "function" ||
      typeof ctx.accounts.list !== "function") {
    throw new TypeError("blamepost.store.credentials.create: ctx.accounts must be the account " +
      "handle. It answers two questions this layer cannot answer for itself: whether the " +
      "bounce mailbox a credential names exists, and which mailboxes in the domain carry the " +
      "operator role and therefore start on the refusal list.");
  }
  if (!ctx.aliases || typeof ctx.aliases.add !== "function" ||
      typeof ctx.aliases.list !== "function" || typeof ctx.aliases.remove !== "function") {
    throw new TypeError("blamepost.store.credentials.create: ctx.aliases must be the alias " +
      "handle. Every credential's bounces come back to an address the domain carries one alias " +
      "for, and a registry built without the handle would issue credentials whose return path " +
      "routes nowhere while reporting that it had created them.");
  }
  if (typeof ctx.resolve !== "function") {
    throw new TypeError("blamepost.store.credentials.create: ctx.resolve must be the routing " +
      "lookup. It answers where a return path actually delivers, which is asked before an " +
      "alias is written and again on every operator-facing read, because a bounce mailbox " +
      "archived after the credential was created leaves the credential unchanged and every " +
      "bounce refused at the door.");
  }
  if (ctx.clock !== undefined && typeof ctx.clock !== "function") {
    throw new TypeError("blamepost.store.credentials.create: ctx.clock must be a function " +
      "returning milliseconds. It is the clock the ceiling windows are measured on, and it " +
      "defaults to a steady one the host cannot step.");
  }
  // The framework registry dispatches its own reads and writes, and the
  // policy half of a credential is written through the query builder, so
  // the two agree only while both address the same database. On a shared
  // backend the registry's row would live there and the policy beside it
  // here, which is a credential whose scope and refusal list cannot be
  // read at all. This server is one process by construction, so the
  // refusal is at the assembly rather than at the first credential.
  if (b.cluster.isClusterMode()) {
    throw new TypeError("blamepost.store.credentials.create: this registry keeps a " +
      "credential's row and the policy bound to it in one database, and a shared backend " +
      "would put them in two. blamepost runs as a single process against a single volume.");
  }

  var domains  = ctx.domains;
  var accounts = ctx.accounts;
  var aliases  = ctx.aliases;
  var resolve  = ctx.resolve;
  var now      = ctx.clock || _steadyNow;

  // The framework registry underneath. Visibility is left on: every
  // issue, every verify and every refusal files a row, which is the
  // trail an operator reads when a credential turns up somewhere it
  // should not be.
  var registry = b.apiKey.create({
    namespace:       TOKEN_NAMESPACE,
    prefix:          TOKEN_PREFIX,
    idBytes:         ID_BYTES,
    secretBytes:     SECRET_BYTES,
    hashAlgo:        SECRET_HASH_ALGO,
    trackLastUsedAt: true,
    auditFailures:   true,
    auditSuccess:    true,
    audit:           b.audit,
  });

  // The ceiling counters. The cache takes the same clock the window
  // arithmetic does, because an entry stored against one clock and
  // measured against another is handed back by a step in either.
  var windows = b.cache.create({
    namespace:  WINDOW_CACHE_NAMESPACE,
    backend:    "memory",
    clock:      now,
    ttlMs:      MAX_WINDOW_MS,
    maxEntries: WINDOW_CACHE_ENTRIES,
  });

  function _activeDomain(name, fn) {
    var canonical = address.canonicalDomain(name, "domain");
    var row = domains.get(canonical);
    if (!row) {
      throw err("store/no-such-domain",
        canonical + " is not hosted here, so there is nothing for a sending credential to " +
        "speak for. Add the domain before creating one in it.");
    }
    if (row.status !== "active") {
      throw err("store/domain-disabled",
        canonical + " is " + row.status + ", so " + fn + " has no domain in service to work " +
        "against.");
    }
    return canonical;
  }

  // The mailbox a credential's bounces are delivered to, checked before
  // the credential exists. A credential pointing at an address with no
  // mailbox discards every bounce at the door while the application goes
  // on sending, and the first anybody hears of it is a receiver's
  // complaint.
  function _bounceMailbox(value) {
    if (value === undefined || value === null) {
      throw err("store/bad-argument",
        "credentials.create needs a bounceMailbox. A credential with nowhere to put its " +
        "bounces drops every one of them, and nothing reports it.");
    }
    var parsed = address.canonical(value, "bounceMailbox");
    var account = accounts.get(parsed.address);
    if (!account) {
      throw err("store/no-such-account",
        "no account at " + parsed.address + ", so a credential naming it as its bounce " +
        "mailbox would deliver every bounce to nothing. Create the mailbox first.");
    }
    if (account.status !== "active") {
      throw err("store/account-" + account.status,
        parsed.address + " is " + account.status + ", so it is not collecting mail and the " +
        "bounces this credential produces would be lost. Name a mailbox in service.");
    }
    return parsed.address;
  }

  // The list a credential starts with: the mailboxes carrying the
  // operator role in its own domain, plus the two addresses a recipient
  // writes to when they want a person. It is derived from the accounts
  // in that domain and no other, so a list built for one domain cannot
  // pass for another.
  function _defaultRefusedList(domain) {
    var out = ALWAYS_REFUSED.slice();
    var rows = accounts.list({ domain: domain });
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].isAdmin !== true) continue;
      if (out.indexOf(rows[i].localPart) === -1) out.push(rows[i].localPart);
    }
    return _normalizeRefusedList(out, domain);
  }

  // ---- the return path ----

  // Where the domain's return path address actually delivers right now,
  // and whether that is the mailbox the credential named.
  //
  // Two separate questions, and the second is the one that matters. An
  // address that resolves and delivers is not a working return path if it
  // delivers somewhere else: a bounce carries the recipients that rejected
  // the mail, so a return path repointed at another mailbox hands one
  // application's failed recipients to whoever reads that one.
  function _readReturnPath(tag, domain, bounceMailbox) {
    var returnPath = _returnPathFor(tag, domain);
    var verdict    = resolve(returnPath);
    var deliversTo = verdict.targets.map(function (target) { return target.mailbox; });

    var reason = null;
    if (!verdict.deliverable) {
      reason = verdict.reason || "no-deliverable-target";
    } else if (deliversTo.length !== 1 || deliversTo[0] !== bounceMailbox) {
      reason = "delivers-elsewhere";
    }

    return {
      returnPath:           returnPath,
      returnPathAddress:    _returnPathAddressFor(domain),
      returnPathDeliverable: reason === null,
      returnPathReason:     reason,
      returnPathDeliversTo: deliversTo,
    };
  }

  // A presented record with the return path reading folded in. A record
  // whose binding does not hold carries no domain and no bounce mailbox,
  // so there is nothing to resolve and the reading stays null rather than
  // being computed from the fields a damaged row happens to hold.
  function _withReturnPath(record) {
    if (!record.bindingHolds) {
      return Object.assign({}, record, {
        returnPathAddress:     null,
        returnPathDeliverable: false,
        returnPathReason:      "credential-unreadable",
        returnPathDeliversTo:  [],
      });
    }
    return Object.assign({}, record,
      _readReturnPath(record.returnPathTag, record.domain, record.bounceMailbox));
  }

  // Every credential in one domain that is still able to send: not
  // revoked and not expired. Withdrawal reads it to find out whether the
  // one going was the last, and creation reads it to find out whether the
  // alias already at the return path is this registry's own.
  async function _liveInDomain(domain) {
    var rows = await registry.listForOwner(domain, {
      includeRevoked: false, includeExpired: false,
    });
    return rows.map(_present);
  }

  // Whether the alias standing at the domain's return path is one this
  // registry put there.
  //
  // The answer is carried on the credentials rather than on the alias row,
  // because the row itself cannot say. An operator who repoints the
  // return path by deleting the row and adding an identical one leaves a
  // different row holding the same address and the same destination, and
  // an alias an operator created by hand is byte for byte what this
  // registry would have written. So each credential records what it found
  // when it was created, and a credential that found the alias already
  // there inherits the answer from the live credentials that came before
  // it. That keeps withdrawal order-independent: whichever credential
  // happens to be the last one out carries the same answer as the first
  // one in.
  async function _aliasIsOurs(domain) {
    var live = await _liveInDomain(domain);
    return live.some(function (record) {
      return record.bindingHolds && record.returnPathAliasMinted === true;
    });
  }

  function _returnPathTaken(returnPathAddress, deliversTo, wanted) {
    // An alias whose chain comes back on itself reaches no mailbox at
    // all, so there is no address to name in the advice and the reading
    // that produced the refusal is what the operator has to act on.
    if (deliversTo.length === 0) {
      return err("store/return-path-taken",
        "something already claims " + returnPathAddress + " and it reaches no mailbox, so " +
        "this credential's bounces would arrive there and stop. Every credential in a domain " +
        "shares that one address. Clear what is at " + returnPathAddress + " before creating " +
        "a credential that names " + wanted + " for its bounces.");
    }
    return err("store/return-path-taken",
      returnPathAddress + " already delivers to " + deliversTo.join(", ") + ", and this " +
      "credential names " + wanted + " for its bounces. Every credential in a domain shares " +
      "one return path, so honoring this one would send its bounces to a mailbox somebody " +
      "chose for something else, and repointing it would take mail away from where it is " +
      "going now. Name " + deliversTo.join(", ") + " as the bounce mailbox, or move what is " +
      "at " + returnPathAddress + " before creating this credential.");
  }

  // What creation has to do about the address the domain's bounces come
  // back to, decided before anything is written.
  async function _decideReturnPath(domain, bounceMailbox) {
    var returnPathAddress = _returnPathAddressFor(domain);
    var verdict = resolve(returnPathAddress);

    // A mailbox standing at the address. Routing reaches an account
    // before it reaches a catch-all and an alias cannot be added over
    // one, so this mailbox is the only thing the domain's bounces can
    // ever reach, whatever the credential asks for.
    if (verdict.kind === "account") {
      if (bounceMailbox !== returnPathAddress) {
        throw _returnPathTaken(returnPathAddress, [returnPathAddress], bounceMailbox);
      }
      return { mintAlias: false, returnPathAliasMinted: false };
    }

    // An alias that is off delivers nothing and does not fall through to
    // the catch-all, so a credential created against it bounces into a
    // refusal from its first message.
    if (verdict.kind === "alias" && verdict.reason === "alias-disabled") {
      throw err("store/return-path-disabled",
        "the alias at " + returnPathAddress + " is disabled, so it accepts nothing and does " +
        "not fall through to the catch-all. A credential created now would have every bounce " +
        "refused at the door from its first message. Turn the alias back on, or remove it and " +
        "let this credential write a fresh one.");
    }

    if (verdict.kind === "alias") {
      var deliversTo = verdict.targets.map(function (target) { return target.mailbox; });
      if (deliversTo.length !== 1 || deliversTo[0] !== bounceMailbox) {
        throw _returnPathTaken(returnPathAddress, deliversTo, bounceMailbox);
      }
      return { mintAlias: false, returnPathAliasMinted: await _aliasIsOurs(domain) };
    }

    // Nothing has claimed the address. A catch-all lands here too: it is
    // what the domain does with a name nobody has taken, and an alias on
    // the address is reached before it.
    return { mintAlias: true, returnPathAliasMinted: true };
  }

  // Take the return path alias away when the credential going was the
  // last one using it, and leave it alone otherwise.
  //
  // Three conditions, and all three are needed. The alias is shared, so
  // removing it while another credential is still sending would stop that
  // credential's bounces. It has to be one this registry wrote, or the
  // removal takes an address the operator created for their own reasons.
  // And it has to still point where it did, because an operator who
  // repointed it has made it something else.
  async function _releaseReturnPathAlias(record) {
    if (!record.bindingHolds || record.returnPathAliasMinted !== true) return false;

    var remaining = await _liveInDomain(record.domain);
    if (remaining.length > 0) return false;

    var returnPathAddress = _returnPathAddressFor(record.domain);
    var rows = aliases.list({ address: returnPathAddress, includeDisabled: true })
      .filter(function (row) { return row.destinationMailbox === record.bounceMailbox; });
    if (rows.length !== 1) return false;

    await aliases.remove({
      id:     rows[0].id,
      reason: "the last sending credential in " + record.domain + " was withdrawn, so the " +
              "return path its bounces came back to has nothing left using it",
    });
    return true;
  }

  // One credential as the framework holds it, in this module's shape.
  async function _record(id) {
    return _present(await registry.getById(id));
  }

  // Write the policy half of a credential back, digest and all. The
  // digest is recomputed here rather than carried in, so a caller cannot
  // hand this function a record and a binding that do not describe each
  // other.
  function _writePolicy(id, record) {
    // The row's own identifier rides in the patch: the table is sealed
    // with the row bound in, and the seal needs the identity column.
    var rowId = TOKEN_NAMESPACE + ":" + id;
    var changed = b.db.from("_blamejs_api_keys")
      .where({ id: rowId })
      .updateOne({ id: rowId, metadata: JSON.stringify(_metadataFor(record)) });
    if (!changed) {
      throw err("store/no-such-sending-credential",
        "no sending credential with id " + JSON.stringify(id) + " is on this volume, so " +
        "there was nothing to write.");
    }
    return changed;
  }

  // ---- the ceiling counters ----

  // The slice the given instant falls in. The window is summed over the
  // slices still inside it, so the counts fall off continuously rather
  // than all at once on a boundary.
  function _sliceOf(at, windowMs) {
    return Math.floor(at / Math.floor(windowMs / WINDOW_SLICES));
  }

  function _windowKey(id) {
    return TOKEN_NAMESPACE + ":" + id;
  }

  // Sum the slices still inside the window and drop the rest.
  function _sumWindow(held, at, windowMs) {
    var oldest = _sliceOf(at, windowMs) - (WINDOW_SLICES - 1);
    var kept   = {};
    var totals = { messages: 0, recipients: 0 };
    if (!held || typeof held !== "object" || typeof held.slices !== "object") {
      return { totals: totals, kept: kept };
    }
    Object.keys(held.slices).forEach(function (key) {
      var index = Number(key);
      if (!isFinite(index) || index < oldest) return;
      var slice = held.slices[key];
      if (!slice || typeof slice.m !== "number" || typeof slice.r !== "number") return;
      kept[key] = { m: slice.m, r: slice.r };
      totals.messages   += slice.m;
      totals.recipients += slice.r;
    });
    return { totals: totals, kept: kept };
  }

  // What a window reads. `counted` is true for the reading taken as a
  // message is recorded, whose totals include that message: it is over
  // a ceiling only when the totals go past it, so a ceiling of N lets N
  // messages through. A plain read reports a window that has reached a
  // ceiling as exceeded, because the next message would go past it.
  function _reading(record, totals, counted) {
    var messagesExceeded = counted === true
      ? totals.messages > record.maxMessages : totals.messages >= record.maxMessages;
    var recipientsExceeded = counted === true
      ? totals.recipients > record.maxRecipients : totals.recipients >= record.maxRecipients;
    return {
      credentialId:       record.id,
      domain:             record.domain,
      windowMs:           record.windowMs,
      messages:           totals.messages,
      recipients:         totals.recipients,
      maxMessages:        record.maxMessages,
      maxRecipients:      record.maxRecipients,
      messagesExceeded:   messagesExceeded,
      recipientsExceeded: recipientsExceeded,
      exceeded:           messagesExceeded || recipientsExceeded,
    };
  }

  // One read-modify-write of a credential's window at a time. The window
  // is read and written across awaits, so two sends recorded together
  // would otherwise both read the same totals and the second write would
  // discard the first send's count.
  var windowQueues = new Map();

  function _oneAtATime(id, task) {
    var prior = windowQueues.get(id) || Promise.resolve();
    var run = prior.then(task);
    var tail = run.then(function () {}, function () {});
    windowQueues.set(id, tail);
    tail.then(function () {
      if (windowQueues.get(id) === tail) windowQueues.delete(id);
    });
    return run;
  }

  // The credential a counter is kept against, refused rather than
  // answered about when it is not one this registry can read. A counter
  // held against a credential whose binding is broken would be a ceiling
  // measured against numbers taken off a row somebody edited.
  async function _countableRecord(id, fn) {
    var record = await _record(id);
    if (!record.bindingHolds) {
      throw err("store/no-such-sending-credential",
        "no sending credential with id " + JSON.stringify(id) + " is readable on this " +
        "volume, so counters." + fn + " has no ceilings to measure against.");
    }
    return record;
  }

  /**
   * @primitive blamepost.store.credentials.create
   * @signature blamepost.store.credentials.create(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.verify, blamepost.store.credentials.rotate
   *
   * Issue a sending credential for one hosted domain. The domain has to
   * be hosted here and active, the bounce mailbox has to name an account
   * that is in service, and a reason has to be recorded, all before
   * anything is written.
   *
   * The token comes back once. Nothing else in this module returns it,
   * and the volume holds only a digest of it, so an operator who loses
   * the token rotates rather than reading it back.
   *
   * The refusal list starts as the mailboxes carrying the operator role
   * in this domain together with postmaster and abuse. The two ceilings
   * start finite whether or not the caller names them.
   *
   * The operator mailboxes on that list are the ones that exist at this
   * call. `blamepost.mail.listeners.permittedAuthor` also refuses every
   * mailbox carrying the operator role when it checks a message, reading
   * the role from the account table, so a mailbox given the role after
   * this call is refused as well, whatever the stored list holds.
   *
   * The credential comes back carrying a `returnPath` of
   * `bounces+<tag>@<domain>`, which is the address to put in the envelope
   * sender of everything it sends, and the `returnPathTag` that address
   * carries. The tag is derived from the identifier under the
   * deployment's vault-sealed key and is not the identifier, because the
   * address travels to every recipient the credential writes to. When
   * nothing is standing at `bounces@<domain>`, creation writes one alias
   * there pointing at the bounce mailbox, and every later credential in
   * the domain shares it.
   *
   * Something already standing there that does not deliver to the bounce
   * mailbox this credential named refuses under `store/return-path-taken`,
   * naming both addresses. A disabled alias refuses under
   * `store/return-path-disabled`. Neither reuses nor replaces what is
   * there: one would route these bounces to a mailbox chosen for
   * something else, and the other would take mail away from where it is
   * going.
   *
   * @opts
   *   domain:            string,    // required, a hosted and active domain
   *   bounceMailbox:     string,    // required, an in-service mailbox on this server
   *   reason:            string,    // required, recorded in the audit trail
   *   expiresAt:         number,    // optional, unix ms; null for no end date; default one year
   *   refusedLocalParts: string[],  // optional, replaces the derived default
   *   maxMessages:       number,    // optional, messages per window
   *   maxRecipients:     number,    // optional, recipients per window
   *   windowMs:          number,    // optional, the rolling window both ceilings are measured over
   *
   * @example
   *   var made = await store.credentials.create({
   *     domain:        "example.com",
   *     bounceMailbox: "bounces@example.com",
   *     reason:        "the shop front sends receipts",
   *   });
   *   made.token;
   */
  async function createCredential(opts) {
    _requireOpts(opts, "create");
    var reason = _requireReason(opts.reason, "create");
    var domain = _activeDomain(opts.domain, "credentials.create");
    var bounceMailbox = _bounceMailbox(opts.bounceMailbox);

    var maxMessages = _requireWholeNumber(opts.maxMessages, DEFAULT_MAX_MESSAGES,
      1, MAX_CEILING, "maxMessages");
    var maxRecipients = _requireWholeNumber(opts.maxRecipients, DEFAULT_MAX_RECIPIENTS,
      1, MAX_CEILING, "maxRecipients");
    var windowMs = _requireWholeNumber(opts.windowMs, DEFAULT_WINDOW_MS,
      MIN_WINDOW_MS, MAX_WINDOW_MS, "windowMs");

    var refusedLocalParts = opts.refusedLocalParts === undefined
      ? _defaultRefusedList(domain)
      : _normalizeRefusedList(opts.refusedLocalParts, domain);

    var wallNow   = Date.now();
    var expiresAt = _readExpiry(opts.expiresAt, wallNow);

    // Decided before anything is written, so a credential whose bounces
    // could not come back anywhere is refused rather than created and
    // then unwound.
    var returnPathDecision = await _decideReturnPath(domain, bounceMailbox);

    // Issued next, because the identifier and the creation moment the
    // binding is taken over are the framework's to mint. The policy half
    // is written immediately after, against the row that now exists.
    var issued = await registry.issue({
      ownerId:   domain,
      scopes:    ["mail:send"],
      metadata:  { kind: RECORD_KIND, version: RECORD_VERSION },
      expiresAt: expiresAt,
    });

    var stored = await registry.getById(issued.id);
    var returnPathTag = _returnPathTagFor(issued.id);
    var record = {
      id:                issued.id,
      domain:            domain,
      bounceMailbox:     bounceMailbox,
      refusedLocalParts: refusedLocalParts,
      maxMessages:       maxMessages,
      maxRecipients:     maxRecipients,
      windowMs:          windowMs,
      returnPathAliasMinted: returnPathDecision.returnPathAliasMinted,
      createdAt:         stored.createdAt,
    };
    _writePolicy(issued.id, record);

    // The alias last, and the credential unwound if it cannot be
    // written. Between the decision above and here the volume can have
    // changed, and a credential left behind with no route for its bounces
    // is the failure this whole address exists to prevent.
    if (returnPathDecision.mintAlias) {
      try {
        await aliases.add({
          address:     _returnPathAddressFor(domain),
          destination: bounceMailbox,
        });
      } catch (aliasError) {
        await registry.revoke(issued.id);
        b.db.from("_blamejs_api_keys")
          .where({ id: TOKEN_NAMESPACE + ":" + issued.id })
          .deleteOne();
        throw aliasError;
      }
    }

    await auditActor.record({
      action:   "domain.sending_credential_created",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: domain },
      metadata: {
        credentialId:      issued.id,
        domain:            domain,
        bounceMailbox:     bounceMailbox,
        refusedLocalParts: refusedLocalParts,
        maxMessages:       maxMessages,
        maxRecipients:     maxRecipients,
        windowMs:          windowMs,
        expiresAt:         expiresAt,
        // Both, because they answer different questions from the same
        // row. The address is what the operator compares against a
        // bounce they are holding, and the tag on its own is what they
        // search the trail for.
        returnPathTag:     returnPathTag,
        returnPath:        _returnPathFor(returnPathTag, domain),
        // Whether this credential put the alias there, so the routing row
        // the domain gained is answerable against the credential that
        // caused it.
        returnPathAliasMinted: returnPathDecision.mintAlias,
      },
    });

    return {
      id:                issued.id,
      domain:            domain,
      // The one moment the secret is readable. It is not stored, not
      // logged, and not in the audit row above.
      token:             issued.key,
      prefix:            TOKEN_PREFIX,
      bounceMailbox:     bounceMailbox,
      // The RFC 5233 tag the address below carries. It is derived from
      // the identifier under the deployment's vault-sealed key rather
      // than being the identifier, because the address goes out on the
      // envelope of every message this credential sends and the
      // identifier keys the failure budget that bounds guessing at its
      // secret.
      returnPathTag:     returnPathTag,
      // The address to put in the envelope sender of everything this
      // credential sends, so the bounces come back somewhere that can
      // accept them.
      returnPath:        _returnPathFor(returnPathTag, domain),
      refusedLocalParts: refusedLocalParts.slice(),
      maxMessages:       maxMessages,
      maxRecipients:     maxRecipients,
      windowMs:          windowMs,
      createdAt:         stored.createdAt,
      expiresAt:         expiresAt,
    };
  }

  // Why a credential that once existed is not sending, or null when it
  // still is. One reading, reached from two doors: the token check below
  // and the per-identifier check beside it. A caller holding a token and
  // a caller holding only the identifier the token resolved to have to
  // arrive at the same verdict, and two copies of this list is how they
  // stop doing that.
  //
  // The binding is asked first because every field after it is read off a
  // record whose policy half could not be authenticated, and `domain` on
  // such a record is null.
  //
  // The clock is `Date.now`, matching the one the expiry was written
  // against and the one the framework registry measures it with. The
  // steady clock this module keeps for the ceiling windows answers a
  // different question: a window is an interval, and an expiry is a
  // moment an operator wrote down.
  //
  // The domain is read on every call rather than carried, because the
  // admin console writes a domain's status through the running server and
  // a credential is only usable while the domain it speaks for is. A
  // credential outlives that withdrawal on the volume, so this is the
  // reading that stops it sending under a name this server no longer
  // answers for and holds no selector for.
  function _stopped(record) {
    if (!record.bindingHolds) return "binding-mismatch";
    if (record.revokedAt !== null) return "revoked";
    if (record.expiresAt !== null && record.expiresAt <= Date.now()) return "expired";
    var domainRow = domains.get(record.domain);
    if (!domainRow) return "domain-not-hosted";
    if (domainRow.status !== "active") return "domain-" + domainRow.status;
    return null;
  }

  /**
   * @primitive blamepost.store.credentials.verify
   * @signature blamepost.store.credentials.verify(token)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the scope of a sending credential is read from the store)
   * @related   blamepost.store.credentials.create, blamepost.store.accounts.authenticate
   *
   * Check one token and return a verdict. It never throws on bad input
   * and it never returns the secret, so a listener can hand it whatever
   * arrived on the wire and answer with a single refusal.
   *
   * Everything a caller acts on comes off the stored row rather than out
   * of the token: the domain the credential may send as, the mailbox its
   * bounces go to, the local parts it may not write as, and the two
   * ceilings. A row whose keyed binding does not hold is refused under
   * `binding-mismatch` with every one of those fields null, so a cell
   * copied from another credential, a refusal list shortened on the
   * volume, and a record that cannot be parsed all stop the credential
   * instead of widening it.
   *
   * The refusal reasons are `bad-token` for a string that is not one of
   * this server's, `bad-credentials` for anything the registry refused,
   * `binding-mismatch`, `domain-not-hosted` and `domain-disabled`. The
   * registry files its own row naming which of not-found, revoked,
   * expired or a wrong secret it was, so an operator reads the
   * distinction off the trail while a caller gets one refusal to answer
   * with.
   *
   * The last three are decided here, after the registry has matched the
   * presented secret and filed a row saying it matched, so each files a
   * `domain.sending_credential_refused` row of its own naming the
   * reason, the credential the token named and the domain its row
   * claims. Without it the only trace of a refused credential is the
   * registry's success. The first two file nothing here: `bad-token`
   * names no credential to file against, and the registry has already
   * written the row for `bad-credentials`.
   *
   * A credential whose stored digest has fallen behind the current one
   * is re-hashed in place on a successful check, so raising the digest
   * reaches every credential as its application connects.
   *
   * @example
   *   var verdict = await store.credentials.verify(presented);
   *   verdict.ok;
   */
  async function verify(token) {
    if (typeof token !== "string" || token.length === 0) return _refused("bad-token");
    var parts = b.apiKey.parseFormat(token);
    if (!parts || parts.prefix !== TOKEN_PREFIX || parts.namespace !== TOKEN_NAMESPACE) {
      return _refused("bad-token");
    }

    var raw = await registry.verify(token);
    if (!raw) return _refused("bad-credentials");

    var record = _present(raw);
    var stopped = _stopped(record);
    if (stopped !== null) {
      // The refusals this layer decides, written down.
      //
      // All three are reached AFTER the framework registry matched the
      // presented secret against the stored digest and filed its own row
      // saying so: a binding that does not hold, a domain this server no
      // longer hosts, and a domain that is not in service. None of the
      // three is a fact about the token, so the registry cannot name any
      // of them, and without this the only trace of a refused credential
      // is a row saying it verified. An operator reading that goes and
      // looks at the application.
      //
      // The refusals the registry DOES decide keep the one row it
      // already writes, so nothing is emitted for them here. A second
      // row beside the first records one event twice and leaves an
      // operator de-duplicating the trail by hand, which is why the
      // failure watch beside the per-peer budget files no rows either.
      //
      // The name sits under the namespace every other sending-credential
      // row in this module sits under, so one filter reads the whole
      // life of a credential, and the outcome rather than the name is
      // what separates a refusal from the operator acts beside it. A
      // namespace of its own would have to be registered at the boot,
      // and an unregistered one is refused at the drain with nothing
      // said.
      //
      // Drop-silent by design. A sink this host cannot write to is not
      // an answer about the credential, and raising here would turn a
      // local fault into a refusal a caller could not tell from a
      // verdict about the token it presented.
      b.audit.safeEmit({
        action:   "domain.sending_credential_refused",
        outcome:  "denied",
        // Nothing established a principal. A presentation that was
        // refused proved no identity, and the credential the token
        // named is a claim rather than an actor, so it is recorded
        // below as one of the things that were said.
        actor:    auditActor.current(),
        reason:   stopped,
        resource: { kind: "domain", id: record.storedDomain },
        metadata: {
          credentialId: record.id,
          // What the row says its scope is, whether or not the binding
          // holds. An operator reading this is asking which domain
          // stopped sending, and a refusal filed against nothing
          // answers that for no domain.
          domain:       record.storedDomain,
          // Whether the policy half of the row could be authenticated
          // at all. It separates a credential stopped by an operator's
          // own act from one stopped by an edit to the volume, and the
          // two send them to look at different things.
          bindingHolds: record.bindingHolds,
        },
      });
      return _refused(stopped);
    }

    return {
      ok:                true,
      reason:            null,
      credentialId:      record.id,
      domain:            record.domain,
      bounceMailbox:     record.bounceMailbox,
      returnPathTag:     record.returnPathTag,
      // The envelope sender the caller should put on this credential's
      // mail. It is handed back on every verify rather than only at
      // creation, so a sender reads it off the credential it just
      // presented instead of holding a copy that can fall out of step.
      returnPath:        record.returnPath,
      refusedLocalParts: record.refusedLocalParts,
      maxMessages:       record.maxMessages,
      maxRecipients:     record.maxRecipients,
      windowMs:          record.windowMs,
      // True when the secret that matched was the prior one, inside a
      // rotation's grace window. A caller that wants to know whether an
      // application has finished migrating reads this.
      usedPriorSecret:   raw.usedSecondary === true,
    };
  }

  /**
   * @primitive blamepost.store.credentials.stillSending
   * @signature blamepost.store.credentials.stillSending(id)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the scope of a sending credential is read from the store)
   * @related   blamepost.store.credentials.verify, blamepost.mail.listeners.create
   *
   * Whether the credential behind one identifier may still send, asked
   * without the secret. It answers `{ ok, reason }` and never throws on a
   * missing credential, so a caller holding a connection can ask it on
   * every message.
   *
   * This is what `verify` asks once the token has matched, minus the
   * token. A caller that authenticated a client and is still holding that
   * client's connection has the identifier and does not have the secret,
   * which is the whole reason this door exists: keeping the secret in
   * memory for the life of a session so it could be re-verified is a
   * worse answer than re-reading the row.
   *
   * The refusal reasons are `not-found` for an identifier no row carries,
   * and then the same set `verify` gives: `binding-mismatch`, `revoked`,
   * `expired`, `domain-not-hosted` and `domain-<status>`.
   *
   * @example
   *   var standing = await store.credentials.stillSending(scope.id);
   *   standing.ok;
   */
  async function stillSending(id) {
    _requireId(id, "stillSending");
    var raw = await registry.getById(id);
    if (!raw) return { ok: false, reason: "not-found" };
    var stopped = _stopped(_present(raw));
    return stopped === null ? { ok: true, reason: null } : { ok: false, reason: stopped };
  }

  /**
   * @primitive blamepost.store.credentials.show
   * @signature blamepost.store.credentials.show(id)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.list, blamepost.store.credentials.verify
   *
   * One credential by the identifier it was issued under, or null when
   * there is none. It carries no secret and no digest of one.
   *
   * A credential whose binding does not hold comes back with
   * `bindingHolds` false and its policy fields null, rather than being
   * hidden. An operator looking at a credential that has stopped working
   * needs to see that the row was edited, and the same reading refuses
   * it at `verify`.
   *
   * `returnPathTag` is the RFC 5233 tag the credential's bounces come
   * back under, which is what an operator matches a bounce in the
   * mailbox against. `byReturnPathTag` goes the other way.
   *
   * The return path is resolved on every call rather than being read off
   * the row. `returnPathDeliverable` says whether a bounce sent there
   * right now would reach the mailbox this credential named,
   * `returnPathDeliversTo` says where it actually lands, and
   * `returnPathReason` names what is wrong when the two differ. A bounce
   * mailbox archived after the credential was created changes nothing
   * about the credential, so this reading is the only place it shows.
   *
   * @example
   *   var shown = await store.credentials.show(made.id);
   *   shown.returnPathDeliverable;
   */
  async function show(id) {
    _requireId(id, "show");
    var raw = await registry.getById(id);
    if (!raw) return null;
    return _withReturnPath(_present(raw));
  }

  /**
   * @primitive blamepost.store.credentials.list
   * @signature blamepost.store.credentials.list(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.show, blamepost.store.domains.list
   *
   * Every credential scoped to one hosted domain, newest first. The
   * domain is required and is checked against the hosted list, so this
   * cannot become a way to ask about a name this server does not answer
   * for. Revoked and expired credentials are left out unless asked for,
   * because the common question is which credentials are live.
   *
   * The lookup runs against the indexed hash of the sealed scope column,
   * so a listing for one domain never reads another domain's rows.
   *
   * Every row carries the same return path reading `show` gives, so an
   * operator reading a domain sees which credentials have stopped
   * receiving their bounces without asking about each one.
   *
   * @opts
   *   domain:         string,   // required, a hosted domain
   *   includeRevoked: boolean,  // keep revoked credentials in the result
   *   includeExpired: boolean,  // keep expired credentials in the result
   *
   * @example
   *   (await store.credentials.list({ domain: "example.com" })).length;
   */
  async function list(opts) {
    _requireOpts(opts, "list");
    if (opts.domain === undefined || opts.domain === null) {
      throw err("store/bad-argument",
        "credentials.list needs a domain. A credential speaks for one domain, and a listing " +
        "with no domain would be every credential on this server in one answer.");
    }
    var canonical = address.canonicalDomain(opts.domain, "domain");
    if (!domains.get(canonical)) {
      throw err("store/no-such-domain",
        canonical + " is not hosted here, so there are no sending credentials for it to " +
        "list.");
    }
    var rows = await registry.listForOwner(canonical, {
      includeRevoked: opts.includeRevoked === true,
      includeExpired: opts.includeExpired === true,
    });
    return rows.map(function (row) { return _withReturnPath(_present(row)); });
  }

  /**
   * @primitive blamepost.store.credentials.byReturnPathTag
   * @signature blamepost.store.credentials.byReturnPathTag(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 5233 (the subaddress a return path carries)
   * @related   blamepost.store.credentials.show, blamepost.store.credentials.returnPathReport
   *
   * The credential a return path names, found from the RFC 5233 tag on
   * that address. Returns the same record `show` returns, or null when
   * no credential in the domain derives that tag.
   *
   * This is the reading a bounce is resolved through. A bounce arrives
   * addressed to `bounces+<tag>@<domain>`, the tag is derived from the
   * credential's identifier under the deployment's vault-sealed key and
   * is not the identifier, so the address cannot be read back to a
   * credential by anyone holding it and this is the door that reads it
   * back for the operator.
   *
   * Revoked and expired credentials are searched as well as live ones.
   * The bounces from a credential's last send arrive after it stops
   * sending, and a lookup that could not name a withdrawn credential
   * would leave the operator holding a bounce nothing accounts for at
   * exactly the moment they are asking why it stopped.
   *
   * A tag that is not the shape this registry derives named no credential
   * this server issued and comes back null without a search, and a domain
   * this server does not host is refused rather than answered about.
   *
   * @opts
   *   domain: string,   // required, a hosted domain
   *   tag:    string,   // required, the RFC 5233 tag off the return path
   *
   * @example
   *   var found = await store.credentials.byReturnPathTag({
   *     domain: "example.com", tag: made.returnPathTag });
   *   found.id;
   */
  async function byReturnPathTag(opts) {
    _requireOpts(opts, "byReturnPathTag");
    if (opts.domain === undefined || opts.domain === null) {
      throw err("store/bad-argument",
        "credentials.byReturnPathTag needs a domain. A tag is derived per credential and " +
        "credentials are filed under the domain they speak for, so a lookup with no domain " +
        "would be a search of every credential on this server.");
    }
    var canonical = address.canonicalDomain(opts.domain, "domain");
    if (!domains.get(canonical)) {
      throw err("store/no-such-domain",
        canonical + " is not hosted here, so no return path in it names a credential.");
    }
    if (typeof opts.tag !== "string" || !RETURN_PATH_TAG_RE.test(opts.tag)) {
      throw err("store/bad-argument",
        "credentials.byReturnPathTag: tag must be the tag this registry derives, which is " +
        "thirty-two hexadecimal characters, got " + JSON.stringify(opts.tag) + ".");
    }

    var rows = await registry.listForOwner(canonical, {
      includeRevoked: true, includeExpired: true,
    });
    for (var i = 0; i < rows.length; i += 1) {
      var record = _present(rows[i]);
      if (record.bindingHolds && record.returnPathTag === opts.tag) {
        return _withReturnPath(record);
      }
    }
    return null;
  }

  /**
   * @primitive blamepost.store.credentials.returnPathReport
   * @signature blamepost.store.credentials.returnPathReport(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one return path address per hosted domain)
   * @related   blamepost.store.credentials.show, blamepost.store.credentials.list
   *
   * The return path of one hosted domain, and every live credential whose
   * bounces are not reaching the mailbox it named. The domain is required
   * and is checked against the hosted list.
   *
   * This is the reading that finds the failure creation cannot. Creation
   * refuses a bounce mailbox that does not exist, but a mailbox archived
   * a month later leaves the credential untouched and every bounce
   * refused at the door while the application goes on sending. Nothing
   * about the credential changed, so resolving the return path is the
   * only thing that finds it.
   *
   * `unreachable` is empty on a domain whose credentials are all
   * receiving their bounces, and each entry carries the credential, the
   * mailbox it named, where the return path actually lands, and why the
   * two differ.
   *
   * @opts
   *   domain: string,   // required, a hosted domain
   *
   * @example
   *   var report = await store.credentials.returnPathReport({ domain: "example.com" });
   *   report.unreachable.length;
   */
  async function returnPathReport(opts) {
    _requireOpts(opts, "returnPathReport");
    if (opts.domain === undefined || opts.domain === null) {
      throw err("store/bad-argument",
        "credentials.returnPathReport needs a domain. Every domain has a return path address " +
        "of its own, and a report with no domain would answer about none of them.");
    }
    var canonical = address.canonicalDomain(opts.domain, "domain");
    if (!domains.get(canonical)) {
      throw err("store/no-such-domain",
        canonical + " is not hosted here, so it has no return path to report on.");
    }

    var live = await _liveInDomain(canonical);
    var unreachable = [];
    live.forEach(function (record) {
      var reading = _withReturnPath(record);
      if (reading.returnPathDeliverable === true) return;
      unreachable.push({
        credentialId:         record.id,
        domain:               canonical,
        bounceMailbox:        record.bounceMailbox,
        returnPathTag:        record.returnPathTag,
        returnPath:           reading.returnPath,
        returnPathDeliversTo: reading.returnPathDeliversTo,
        returnPathReason:     reading.returnPathReason,
      });
    });

    return {
      domain:            canonical,
      returnPathAddress: _returnPathAddressFor(canonical),
      credentials:       live.length,
      unreachable:       unreachable,
    };
  }

  /**
   * @primitive blamepost.store.credentials.rotate
   * @signature blamepost.store.credentials.rotate(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.revoke, blamepost.store.credentials.create
   *
   * Replace a credential's secret and hand back the new token once. The
   * identifier, the scope, the bounce mailbox, the refusal list and the
   * ceilings are all unchanged, so the rotation is the secret and
   * nothing else.
   *
   * There is no grace window unless one is named. The reason to rotate
   * is usually that the old secret is in somebody else's hands, and a
   * window that appeared by default would leave it working for a week.
   * `graceMs` names one explicitly and is bounded, and the prior secret
   * keeps verifying until it elapses; a verdict produced by the prior
   * secret says so, so an operator can see whether an application has
   * finished migrating before the window closes.
   *
   * The ceiling counters are not reset. Volume already sent is volume
   * already sent, and `counters.release` is the way to give it back.
   *
   * @opts
   *   id:      string,   // required, the identifier the credential was issued under
   *   reason:  string,   // required, recorded in the audit trail
   *   graceMs: number,   // optional, how long the prior secret keeps working; default none
   *
   * @example
   *   var rotated = await store.credentials.rotate({
   *     id: made.id, reason: "the token reached a public repository" });
   *   rotated.token;
   */
  async function rotate(opts) {
    _requireOpts(opts, "rotate");
    var id     = _requireId(opts.id, "rotate");
    var reason = _requireReason(opts.reason, "rotate");
    var graceMs = _requireWholeNumber(opts.graceMs, 0, 0, MAX_GRACE_MS, "graceMs");

    var before = await _record(id);
    if (before.id === null) {
      throw err("store/no-such-sending-credential",
        "no sending credential with id " + JSON.stringify(id) + " on this server.");
    }

    var rotated = await registry.rotate(id, { gracePeriodMs: graceMs });

    await auditActor.record({
      action:   "domain.sending_credential_rotated",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: before.storedDomain },
      metadata: {
        credentialId: id,
        domain:       before.storedDomain,
        bindingHolds: before.bindingHolds,
        graceMs:      graceMs,
        priorSecretUntil: graceMs > 0 ? rotated.secondaryExpiresAt : null,
      },
    });

    // The framework hands back the stored digest beside the new secret.
    // It is not passed on: this module's surface returns a secret once
    // and never returns anything derived from one.
    return {
      id:               id,
      domain:           before.storedDomain,
      token:            rotated.key,
      prefix:           TOKEN_PREFIX,
      graceMs:          graceMs,
      priorSecretUntil: graceMs > 0 ? rotated.secondaryExpiresAt : null,
    };
  }

  /**
   * @primitive blamepost.store.credentials.revoke
   * @signature blamepost.store.credentials.revoke(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.remove, blamepost.store.credentials.rotate
   *
   * Stop a credential working. The next check refuses it, and the row
   * stays on the volume so the trail still resolves the identifier an
   * earlier row named. Revoking twice is not an error and reports that
   * nothing changed the second time.
   *
   * The framework records who revoked a credential but takes no reason,
   * so this writes its own row beside that one carrying the reason it
   * was given.
   *
   * The domain's return path alias goes with the last credential using it
   * and not before, and `returnPathAliasRemoved` says which happened.
   * Every credential in a domain shares the one alias, so removing it
   * while another is still sending would stop that one's bounces. An
   * alias the operator created rather than this registry is left standing
   * whatever else happens, because taking it away would stop mail
   * arriving at an address they made for their own reasons.
   *
   * @opts
   *   id:     string,   // required, the identifier the credential was issued under
   *   reason: string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.credentials.revoke({
   *     id: made.id, reason: "the application was decommissioned" });
   */
  async function revoke(opts) {
    _requireOpts(opts, "revoke");
    var id     = _requireId(opts.id, "revoke");
    var reason = _requireReason(opts.reason, "revoke");

    var before = await _record(id);
    if (before.id === null) {
      throw err("store/no-such-sending-credential",
        "no sending credential with id " + JSON.stringify(id) + " on this server.");
    }

    var changed = await registry.revoke(id);

    // After the revoke, so the credential going is already out of the
    // count of what is still using the shared return path.
    var aliasRemoved = await _releaseReturnPathAlias(before);

    await auditActor.record({
      action:   "domain.sending_credential_revoked",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: before.storedDomain },
      metadata: {
        credentialId:   id,
        domain:         before.storedDomain,
        bindingHolds:   before.bindingHolds,
        alreadyRevoked: !changed,
        // Recorded either way. The alias is a routing row for the whole
        // domain, so both the removal and the decision to keep it are
        // things an operator reading the trail afterwards has to be able
        // to see.
        returnPathAliasRemoved: aliasRemoved,
      },
    });

    return {
      id:                     id,
      domain:                 before.storedDomain,
      revoked:                changed === true,
      returnPathAliasRemoved: aliasRemoved,
    };
  }

  /**
   * @primitive blamepost.store.credentials.remove
   * @signature blamepost.store.credentials.remove(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.revoke, blamepost.store.accounts.delete
   *
   * Take a credential's row off the volume. It requires `destroy: true`
   * as well as a reason, and refuses without it, naming `revoke` in the
   * refusal. Revoking stops the credential and keeps the row, which is
   * what an operator wants almost every time: the identifier on an
   * earlier audit row still resolves to a credential afterwards, and a
   * removed one leaves that row naming something nothing can look up.
   *
   * The counters kept against the credential go with it, and so does the
   * domain's return path alias when this was the last credential using
   * one this registry wrote. `revoke` describes that rule and `remove`
   * applies the same one.
   *
   * A credential whose binding no longer holds can still be removed,
   * which is what cleaning one up needs. The row it files names the
   * domain the stored row claimed and says the binding was broken, so
   * the removal is answerable even though the record was not readable.
   *
   * @opts
   *   id:      string,    // required, the identifier the credential was issued under
   *   reason:  string,    // required, recorded in the audit trail
   *   destroy: boolean,   // required to be true; without it the call refuses
   *
   * @example
   *   await store.credentials.remove({
   *     id: made.id, destroy: true, reason: "the operator asked for erasure" });
   */
  async function remove(opts) {
    _requireOpts(opts, "remove");
    var id     = _requireId(opts.id, "remove");
    var reason = _requireReason(opts.reason, "remove");

    if (opts.destroy !== true) {
      throw err("store/bad-argument",
        "credentials.remove takes the row off the volume and needs destroy: true to do it. " +
        "The identifier on every audit row this credential produced stops resolving once the " +
        "row is gone. Use revoke to stop the credential working and keep the row.");
    }
    var before = await _record(id);
    if (before.id === null) {
      throw err("store/no-such-sending-credential",
        "no sending credential with id " + JSON.stringify(id) + " on this server.");
    }

    // Revoked first, then removed. A removal the volume refuses halfway
    // then leaves a credential that has stopped working rather than one
    // that is still live with its row half gone.
    var revoked = await registry.revoke(id);
    var removed = b.db.from("_blamejs_api_keys")
      .where({ id: TOKEN_NAMESPACE + ":" + id })
      .deleteOne();
    await _oneAtATime(id, function () { return windows.del(_windowKey(id)); });

    // The alias has to be reached here the same way revoking reaches it.
    // An erasure that takes the credential and leaves the routing row
    // behind leaves an address delivering to a mailbox nothing sends to,
    // and no credential left to explain why it is there.
    var aliasRemoved = await _releaseReturnPathAlias(before);

    await auditActor.record({
      action:   "domain.sending_credential_removed",
      // The verdict on the row is read off the delete rather than
      // written underneath it. A row that was not there and a volume
      // that would not give one up both arrive here as the same false,
      // and a row still on disk under a trail entry saying it is gone is
      // the expensive half of that.
      outcome:  removed ? "success" : "failure",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: before.storedDomain },
      metadata: {
        credentialId:  id,
        domain:        before.storedDomain,
        bindingHolds:  before.bindingHolds,
        rowRemoved:    removed,
        // The credential stops working whether or not its row went, and
        // the two are recorded apart because they leave different work
        // behind. A revoked credential whose row survived needs somebody
        // to go and look at the volume.
        revokedHere:   revoked === true,
        returnPathAliasRemoved: aliasRemoved,
      },
    });

    if (!removed) {
      throw err("store/sending-credential-not-removed",
        "the row for sending credential " + JSON.stringify(id) + " is still on the volume. " +
        "It has been revoked, so the credential no longer verifies, but the erasure that was " +
        "asked for did not happen and the row is still readable.");
    }

    return {
      id:                     id,
      domain:                 before.storedDomain,
      removed:                removed,
      returnPathAliasRemoved: aliasRemoved,
    };
  }

  /**
   * @primitive blamepost.store.credentials.setRefusedLocalParts
   * @signature blamepost.store.credentials.setRefusedLocalParts(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a sending credential scoped to a hosted domain)
   * @related   blamepost.store.credentials.create, blamepost.store.credentials.show
   *
   * Replace the local parts a credential may not write as. An empty
   * array is accepted and is stored as an empty list, which is not the
   * same as a credential with no list: a record this server cannot read
   * refuses the credential outright rather than reading as one that
   * refuses nobody.
   *
   * The reason is required and the audit row names every local part that
   * came off the list, so a widening is answerable afterwards. A
   * widening done anywhere other than here breaks the credential's
   * binding and stops it, because the list is one of the fields the
   * binding is taken over.
   *
   * This list does not decide whether a mailbox carrying the operator
   * role is refused. `blamepost.mail.listeners.permittedAuthor` refuses
   * those from the account table on every check, so an empty list still
   * refuses them.
   *
   * @opts
   *   id:         string,     // required, the identifier the credential was issued under
   *   localParts: string[],   // required, the complete new list
   *   reason:     string,     // required, recorded in the audit trail
   *
   * @example
   *   await store.credentials.setRefusedLocalParts({
   *     id: made.id, localParts: ["postmaster"], reason: "this one sends the abuse replies" });
   */
  async function setRefusedLocalParts(opts) {
    _requireOpts(opts, "setRefusedLocalParts");
    var id     = _requireId(opts.id, "setRefusedLocalParts");
    var reason = _requireReason(opts.reason, "setRefusedLocalParts");

    // Run in the credential's queue, as `setCeilings` is: both replace the
    // whole policy row from a reading of it, so two run together would
    // each overwrite the other's change.
    return await _oneAtATime(id, function () {
      return _changeRefusedLocalParts(id, opts, reason);
    });
  }

  async function _changeRefusedLocalParts(id, opts, reason) {
    var before = await _record(id);
    if (before.id === null || !before.bindingHolds) {
      throw err("store/no-such-sending-credential",
        "no readable sending credential with id " + JSON.stringify(id) + " on this server, " +
        "so there is no refusal list to replace.");
    }
    var next = _normalizeRefusedList(opts.localParts, before.domain);

    var removed = before.refusedLocalParts.filter(function (part) {
      return next.indexOf(part) === -1;
    });
    var added = next.filter(function (part) {
      return before.refusedLocalParts.indexOf(part) === -1;
    });

    _writePolicy(id, {
      id:                before.id,
      domain:            before.domain,
      bounceMailbox:     before.bounceMailbox,
      refusedLocalParts: next,
      maxMessages:       before.maxMessages,
      maxRecipients:     before.maxRecipients,
      windowMs:          before.windowMs,
      // Carried through unchanged. It is one of the fields the binding is
      // taken over, so dropping it here would break the credential this
      // call is editing.
      returnPathAliasMinted: before.returnPathAliasMinted,
      createdAt:         before.createdAt,
    });

    await auditActor.record({
      action:   "domain.sending_credential_refusals_set",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: before.domain },
      metadata: {
        credentialId: id,
        domain:       before.domain,
        // Both directions, because the two are read for opposite
        // reasons: what came off the list is what the credential may now
        // write as, and what went on is what it may not.
        removed:      removed,
        added:        added,
        refusedLocalParts: next,
      },
    });

    return await _record(id);
  }

  // The part of `setCeilings` that reads and writes the credential and
  // its window. It runs inside the credential's window queue.
  async function _changeCeilings(id, opts) {
    var before = await _record(id);
    if (before.id === null || !before.bindingHolds) {
      throw err("store/no-such-sending-credential",
        "no readable sending credential with id " + JSON.stringify(id) + " on this server, " +
        "so there are no ceilings to change.");
    }

    // Absent means unchanged, so each field falls back to what the row
    // already holds and every supplied value is measured against the
    // bounds creation measures against.
    var maxMessages = _requireWholeNumber(opts.maxMessages, before.maxMessages,
      1, MAX_CEILING, "maxMessages");
    var maxRecipients = _requireWholeNumber(opts.maxRecipients, before.maxRecipients,
      1, MAX_CEILING, "maxRecipients");
    var windowMs = _requireWholeNumber(opts.windowMs, before.windowMs,
      MIN_WINDOW_MS, MAX_WINDOW_MS, "windowMs");

    var windowMoves = windowMs !== before.windowMs;
    if (windowMoves) {
      var held = _sumWindow(await windows.get(_windowKey(id)), now(), before.windowMs);
      if (held.totals.messages > 0 || held.totals.recipients > 0) {
        throw err("store/sending-credential-window-in-use",
          "the window on " + id + " still holds " + held.totals.messages + " message(s) to " +
          held.totals.recipients + " recipient(s), and the counters are kept as slices of " +
          "the window, so a count taken at one window length is misread at another. Give " +
          "the window back first, then set the new length.");
      }
    }

    _writePolicy(id, {
      id:                before.id,
      domain:            before.domain,
      bounceMailbox:     before.bounceMailbox,
      refusedLocalParts: before.refusedLocalParts,
      maxMessages:       maxMessages,
      maxRecipients:     maxRecipients,
      windowMs:          windowMs,
      // Carried through unchanged. It is one of the fields the binding is
      // taken over, so dropping it here would break the credential this
      // call is editing.
      returnPathAliasMinted: before.returnPathAliasMinted,
      createdAt:         before.createdAt,
    });

    // After the write rather than before it. The sum above established
    // that the entry holds nothing inside the window, so nothing is
    // handed back by this; what it removes is slices counted at the old
    // length, which the new length would read as current volume. A write
    // that failed would otherwise leave the length unmoved and the
    // slices gone, which is a release nobody asked for.
    if (windowMoves) await windows.del(_windowKey(id));

    return {
      before:        before,
      maxMessages:   maxMessages,
      maxRecipients: maxRecipients,
      windowMs:      windowMs,
      windowMoves:   windowMoves,
    };
  }

  /**
   * @primitive blamepost.store.credentials.setCeilings
   * @signature blamepost.store.credentials.setCeilings(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: two ceilings per sending credential over a rolling window)
   * @related   blamepost.store.credentials.create, blamepost.store.credentials.counters.release
   *
   * Change what a credential may send in one window, after it has been
   * issued. The two ceilings and the window length move independently,
   * and a call naming none of them is refused rather than filing a row
   * for a change nobody made.
   *
   * The bounds are the ones creation enforces, so a value this accepts
   * is one `create` would have accepted. A ceiling set below what the
   * window already holds refuses the credential's next message, which is
   * what an operator holding a credential down during an incident is
   * asking for.
   *
   * The window length is the one field the counters underneath cannot
   * absorb. They are kept as slices of the window, so slices counted at
   * one length are misread at another: a widened window reads volume
   * that should already have rolled off, and a narrowed one drops volume
   * that should still hold. So a window change is refused under
   * `store/sending-credential-window-in-use` while the window holds
   * anything, and `counters.release` is the way to give that volume back
   * first. When the window holds nothing the slices on the entry are
   * dropped with the write, because a slice outside an hour is inside
   * two hours and would read as current volume the moment the length
   * moves.
   *
   * The reason is required and the row carries both readings of every
   * field, so a widening is answerable afterwards.
   *
   * @opts
   *   id:            string,   // required, the identifier the credential was issued under
   *   reason:        string,   // required, recorded in the audit trail
   *   maxMessages:   number,   // optional, messages per window
   *   maxRecipients: number,   // optional, recipients per window
   *   windowMs:      number,   // optional, the rolling window both ceilings are measured over
   *
   * @example
   *   await store.credentials.setCeilings({
   *     id: made.id, maxMessages: 5000, reason: "the announcement run was checked" });
   */
  async function setCeilings(opts) {
    _requireOpts(opts, "setCeilings");
    var id     = _requireId(opts.id, "setCeilings");
    var reason = _requireReason(opts.reason, "setCeilings");

    var namesAny = [opts.maxMessages, opts.maxRecipients, opts.windowMs]
      .some(function (value) { return value !== undefined && value !== null; });
    if (!namesAny) {
      throw err("store/bad-argument",
        "credentials.setCeilings needs at least one of maxMessages, maxRecipients or " +
        "windowMs. A call naming none of them changes nothing, and filing a row for it " +
        "would put an operator action in the trail that never happened.");
    }

    // The read, the emptiness check, the write and the reset run in the
    // credential's window queue, so a send recorded meanwhile is counted
    // either before the check sees it or after the reset, and is never
    // erased by the reset.
    var changed = await _oneAtATime(id, function () {
      return _changeCeilings(id, opts);
    });
    var before = changed.before;
    var maxMessages = changed.maxMessages;
    var maxRecipients = changed.maxRecipients;
    var windowMs = changed.windowMs;
    var windowMoves = changed.windowMoves;

    await auditActor.record({
      action:   "domain.sending_credential_ceilings_set",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: before.domain },
      metadata: {
        credentialId: id,
        domain:       before.domain,
        // Both readings of all three, because the direction is what the
        // row is read for. A raise widens what a credential in somebody
        // else's hands sends before anything stops it, and a cut is an
        // operator holding one down; a row carrying only the new numbers
        // cannot tell those apart.
        maxMessagesFrom:   before.maxMessages,
        maxMessagesTo:     maxMessages,
        maxRecipientsFrom: before.maxRecipients,
        maxRecipientsTo:   maxRecipients,
        windowMsFrom:      before.windowMs,
        windowMsTo:        windowMs,
        // Whether the slices went with the length. An operator reading
        // the trail afterwards is asking whether a window that reads
        // zero was released or re-measured, and those are different acts.
        slicesDropped:     windowMoves,
      },
    });

    return await _record(id);
  }

  /**
   * @primitive blamepost.store.credentials.counters.record
   * @signature blamepost.store.credentials.counters.record(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: two ceilings per sending credential over a rolling window)
   * @related   blamepost.store.credentials.counters.read, blamepost.store.credentials.verify
   *
   * Count one message and its recipients against a credential's window,
   * and return what the window reads afterwards. Two counts rather than
   * one, because a hundred messages of one recipient each and one
   * message of a hundred thousand are different events and the second is
   * what a leaked credential produces.
   *
   * The ceilings are read off the credential's own row on every call, so
   * a caller cannot supply them. A credential this server cannot read
   * refuses rather than being counted against numbers taken off a row
   * somebody edited.
   *
   * `messagesExceeded` and `recipientsExceeded` answer separately and
   * `exceeded` is the verdict over both. Each says whether this message
   * took the window past a ceiling, so a ceiling of N lets N messages
   * through. Refusing the message on the wire is composed on top of this
   * reading. Sends recorded against one credential at the same time are
   * counted one after another, so each is counted.
   *
   * @opts
   *   id:         string,   // required, the identifier the credential was issued under
   *   recipients: number,   // required, the recipient count of this message
   *
   * @example
   *   var reading = await store.credentials.counters.record({
   *     id: verdict.credentialId, recipients: envelope.rcptTo.length });
   *   reading.exceeded;
   */
  async function recordSend(opts) {
    _requireOpts(opts, "counters.record");
    var id = _requireId(opts.id, "counters.record");
    var recipients = _requireWholeNumber(opts.recipients, undefined, 0, MAX_CEILING,
      "counters.record: recipients");
    if (recipients === undefined) {
      throw err("store/bad-argument",
        "counters.record needs the recipient count of the message being counted.");
    }

    // The ceilings are read inside the queue, so a ceiling change that
    // ran ahead of this send is the one this send is measured against.
    return await _oneAtATime(id, async function () {
      var record = await _countableRecord(id, "record");
      var at   = now();
      var key  = _windowKey(id);
      var held = await windows.get(key);
      var summed = _sumWindow(held, at, record.windowMs);
      var slice  = String(_sliceOf(at, record.windowMs));

      if (!summed.kept[slice]) summed.kept[slice] = { m: 0, r: 0 };
      summed.kept[slice].m += 1;
      summed.kept[slice].r += recipients;
      summed.totals.messages   += 1;
      summed.totals.recipients += recipients;

      await windows.set(key, { slices: summed.kept }, { ttlMs: record.windowMs });
      return _reading(record, summed.totals, true);
    });
  }

  /**
   * @primitive blamepost.store.credentials.counters.read
   * @signature blamepost.store.credentials.counters.read(id)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: two ceilings per sending credential over a rolling window)
   * @related   blamepost.store.credentials.counters.record, blamepost.store.credentials.counters.release
   *
   * What a credential's window reads right now, without counting
   * anything against it. The counters live in this process, so this is
   * the state that would actually refuse a message rather than a record
   * of one that did.
   *
   * Reading constructs nothing: a credential nothing has been sent
   * through reads zero rather than being brought into existence.
   *
   * @example
   *   var reading = await store.credentials.counters.read(made.id);
   *   reading.recipients;
   */
  async function readCounters(id) {
    _requireId(id, "counters.read");
    var record = await _countableRecord(id, "read");
    var summed = _sumWindow(await windows.get(_windowKey(id)), now(), record.windowMs);
    return _reading(record, summed.totals);
  }

  /**
   * @primitive blamepost.store.credentials.counters.release
   * @signature blamepost.store.credentials.counters.release(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: two ceilings per sending credential over a rolling window)
   * @related   blamepost.store.credentials.counters.read, blamepost.store.accounts.unlock
   *
   * Put a credential's window back to zero. A ceiling spent by a send
   * the operator has looked at and decided was legitimate otherwise
   * holds until the window rolls, and this is the way that does not
   * involve waiting.
   *
   * The reason is required and recorded, because this is an operator
   * lifting a limit off somebody else's traffic.
   *
   * @opts
   *   id:     string,   // required, the identifier the credential was issued under
   *   reason: string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.credentials.counters.release({
   *     id: made.id, reason: "the send was a legitimate announcement" });
   */
  async function releaseCounters(opts) {
    _requireOpts(opts, "counters.release");
    var id     = _requireId(opts.id, "counters.release");
    var reason = _requireReason(opts.reason, "counters.release");

    var record = null;
    var before = await _oneAtATime(id, async function () {
      record = await _countableRecord(id, "release");
      var summed = _sumWindow(await windows.get(_windowKey(id)), now(), record.windowMs);
      await windows.del(_windowKey(id));
      return summed;
    });

    await auditActor.record({
      action:   "domain.sending_credential_ceiling_released",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: record.domain },
      metadata: {
        credentialId: id,
        domain:       record.domain,
        // What the window held when it was released, so the row answers
        // how much was given back rather than only that something was.
        messages:     before.totals.messages,
        recipients:   before.totals.recipients,
      },
    });

    return _reading(record, { messages: 0, recipients: 0 });
  }

  // Give back the counter cache, which owns a sweep timer. A timer left
  // armed beside a closed store ticks into a database that is gone.
  function close() {
    windows.close();
  }

  return {
    create:               createCredential,
    verify:               verify,
    stillSending:         stillSending,
    show:                 show,
    list:                 list,
    rotate:               rotate,
    revoke:               revoke,
    remove:               remove,
    setRefusedLocalParts: setRefusedLocalParts,
    setCeilings:          setCeilings,
    byReturnPathTag:      byReturnPathTag,
    returnPathReport:     returnPathReport,
    counters: {
      record:  recordSend,
      read:    readCounters,
      release: releaseCounters,
    },
    close: close,
  };
}

module.exports = {
  create:          create,
  TOKEN_PREFIX:    TOKEN_PREFIX,
  TOKEN_NAMESPACE: TOKEN_NAMESPACE,
  MAX_GRACE_MS:    MAX_GRACE_MS,
  MAX_CEILING:     MAX_CEILING,
  DEFAULT_WINDOW_MS: DEFAULT_WINDOW_MS,
  // The bounds a window may be set between. The command line takes the
  // window in minutes and this module takes it in milliseconds, so a
  // refusal computed from these is one an operator reads in the unit they
  // typed. Restating them at the caller would be a second copy of a bound
  // that only this module enforces.
  MIN_WINDOW_MS:   MIN_WINDOW_MS,
  MAX_WINDOW_MS:   MAX_WINDOW_MS,
  // The local part every return path in a domain folds down to. The
  // operator guide names the address an operator has to leave free, and
  // `doctor` reads it to check what is standing there.
  RETURN_PATH_LOCAL_PART: RETURN_PATH_LOCAL_PART,
};
