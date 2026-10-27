// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.store.accounts
 * @nav      Accounts and domains
 * @title    Accounts
 * @order    10
 * @featured true
 *
 * Mailbox owners: creation, lookup, credential checking, suspension and
 * deletion. An account is the identity every listener authenticates
 * against and every delivery resolves to.
 *
 * Passwords are hashed with Argon2id through `b.auth.password` and the
 * hash is a sealed column on top of that. No function here returns it,
 * logs it, or puts it in an error, and the plaintext is never written
 * anywhere: it is checked and dropped. A failed sign in for an address
 * that has no account still pays for a verification, so response time
 * does not answer the question of which addresses exist.
 *
 * Every authenticating surface this server runs, the browser sign in
 * form and all five mail listeners, reaches an account through
 * `authenticate` below, so the failure budget lives here rather than on
 * each of them. One budget for the mailbox means guesses spent on IMAP
 * are gone on POP3, and it means an attacker moving between source
 * addresses gains nothing: the counter is keyed on the address being
 * guessed at, not on where the guess arrived from. Argon2id makes each
 * guess expensive, which is a cost rather than a bound.
 *
 * Deletion archives. The mailbox stops accepting mail and stops
 * authenticating, the reason is recorded, and the row stays for the
 * retention the operator owes. Erasing outright is a second, explicit
 * request that names a reason, and it reaches the account row, the
 * aliases pointing at it and everything the account holds in its
 * mailboxes. The mail half runs through the mailbox adapter, because
 * that layer owns the rows and the sealed message bodies and is where
 * every other delete on this server is decided.
 *
 * An erasure destroys the mail first and the identity last. The delete
 * path refuses per message, a governance gate can hold back a filter
 * script or an annotation, and storage can refuse any of them, so an
 * erasure regularly leaves records it was asked to destroy. Those records
 * are producible only through the account that owns them. So the account
 * row goes only once nothing still names it, counting every table the
 * mailbox layer files the account's rows in as well as the aliases; until
 * then the row stays, out of service and marked as erasing, and running
 * the same call again finishes the job.
 *
 * @card
 *   Creates, suspends and deletes mailbox accounts, and checks every
 *   sign-in from the browser and the mail listeners against one failure
 *   budget per address. Deleting an account archives it, and erasing one
 *   takes a separate request with a recorded reason.
 */

var b       = require("../vendor/blamejs");
var address = require("./address");
var auditActor = require("./actor");
var errors  = require("./errors");
var tables  = require("./tables");
// The control-character table every stored field is refused against, in
// the module that also screens text on the way out, so the set a write
// refuses and the set a read repairs are one set.
var displayText = require("../text");
// For the one table name an erasure has to read back: the mailboxes that
// still name the account it is erasing. The reconciliation in this same
// directory reaches the adapter's table names the same way, because a
// second spelling of where a mailbox row lives is a second answer to
// whether the account still owns one.
var mailboxTables = require("../mail/mailbox");

var err = errors.err;

var MAX_DISPLAY_NAME_CHARS = 200;

// How a display name is screened. `b.guardText` owns the codepoint
// threat catalogue: bidi overrides, zero-width and invisible formatting
// characters, the Unicode Tags block and null bytes. Those render as
// nothing and change what a reader sees, and this field is rendered into
// the admin views, into webmail and into the JMAP name of every address
// a client shows.
//
// Confusables are audited rather than refused, which is the guard's own
// default and the reason for it: most of the world's names mix scripts,
// and a screen that refuses "Robert" beside a Han character is a worse
// failure than the one it closes.
//
// The guard deliberately allows tab, carriage return and line feed,
// because they are ordinary in free text, and it reports the C1 range as
// clean. They are not ordinary in a name that is written into a header
// and printed in a table, so `blamepost.text.hasControlChar` refuses all
// of them beside this. Both halves are needed; neither is redundant.
var DISPLAY_NAME_GUARD = { profile: "strict", confusablePolicy: "audit" };

// The stand-in hash a sign in for an unknown address is checked against,
// so the work done on a miss matches the work done on a hit. Built once
// on the first miss from a value nothing can present.
var absentHash = null;

// Where the failure counters live. The two budgets below hold separate
// caches rather than sharing one, because the cache evicts its least
// recently used entry when it is full and an evicted counter is a
// counter back at zero. Sharing would let attempts against one budget
// crowd out the other's live lockouts at half the cost.
var MAILBOX_CACHE_NAMESPACE = "blamepost.auth.lockout.mailbox";
var MAILBOX_PEER_CACHE_NAMESPACE = "blamepost.auth.lockout.mailbox-peer";

// The budget keyed on the mailbox alone. This is the one an attacker
// cannot escape by moving between source addresses.
var MAILBOX_BUDGET = "mailbox";

// The budget keyed on the mailbox and the peer together. It bounds any
// single source, including one this server has seen the account holder
// use, which is what stops the exemption below from becoming a way in.
var MAILBOX_PEER_BUDGET = "mailbox-peer";

// How many counters each budget holds before the least recently used one
// is evicted. The number is a defense rather than a memory setting: an
// eviction hands the evicted mailbox a fresh budget, so an attacker who
// can fill the cache faster than its entries decay can release a lockout
// they are sitting under by failing against enough other addresses.
//
// What makes that unreachable is that every entry costs the attacker an
// Argon2id verification here, whether or not the address they name has a
// mailbox. A counter decays fifteen minutes after its last failure, so
// filling the cache means outrunning that window, and this floor is set
// above the number of verifications this server can perform inside one
// window on hardware it would plausibly run on. An attacker who could
// perform them anyway has saturated the machine, which is a denial of
// service in plain sight rather than a quiet way past the budget.
var BUDGET_ENTRIES = 100000;

// Source addresses a mailbox has actually signed in from. Without this
// the budget is a way to lock somebody out of their own mail: an
// attacker spends the mailbox budget from addresses of their own and the
// account holder, who knows their password, is refused along with them.
// A source this server has seen work for this mailbox is still let in,
// and is still bounded by the pair budget above.
var FAMILIAR_SOURCE_NAMESPACE = "blamepost.auth.familiar-source";

// How long a source stays familiar to a mailbox. Long enough to cover a
// mail client that is left running for weeks between restarts, and short
// enough that an address the account has stopped using stops carrying an
// exemption.
var FAMILIAR_SOURCE_TTL_MS = b.constants.TIME.days(30);

// How many mailbox and source pairs are remembered at once. The cache
// evicts the least recently used beyond this, so the memory a server
// with many accounts spends here is bounded rather than growing with the
// number of clients that have ever connected.
var FAMILIAR_SOURCE_MAX = 20000;

// Which refusals from a hard erase mean a row is being kept on purpose
// is `errors.isPreservationRefusal`, and this layer asks it rather than
// keeping a list of its own.
//
// The distinction matters here because erasing an account erases the
// aliases pointing at it and the account row itself, and either can be
// stopped for two unrelated reasons that need opposite responses. A
// preservation order, or a governance gate wanting a second approver, is
// the system working: the row stays, the operator releases the order or
// obtains the grant, and running the erasure again reaches it. Anything
// else is a fault: the mailbox is gone and a forwarding row is still
// pointing at it, which is mail arriving for an address nobody holds, and
// somebody has to go and look.
//
// It lives in the shared module because the mailbox adapter classifies
// the same refusals over the same account's filter scripts, annotations
// and mailbox rows, and one erasure reports both halves together. Two
// copies of that list is how one report starts calling the same refusal
// two things.

// The two readings the clock below is built out of, taken together at
// load so the pair describes one instant.
var WALL_ORIGIN_MS    = Date.now();
var ELAPSED_ORIGIN_MS = b.time.monotonicMs();

// The clock the failure budgets are measured on: where the wall clock
// stood when this module loaded, advanced from there by a source the
// host cannot move.
//
// Everything the budgets decide is a duration. Five failures inside a
// quarter of an hour spend one; the wait that follows starts at a minute
// and grows with each further run at the same mailbox; the count decays
// a quarter of an hour after the last failure. `Date.now()` answers a
// different question, what time it is, and it moves when an operator
// corrects a wrong time, when NTP steps a drifted host, and when a
// container starts before it has synchronized and then catches up. A
// budget measured against it is one the host's clock hands back: a step
// forward lifts a lockout nobody served and resets a counter that has
// not decayed, and a step backwards stamps a wait in the past, so every
// lockout written on a host running behind lifts together the moment
// somebody fixes the date. None of that surfaces as an error anywhere.
// The maildrop hold and the delivery report budget are measured this way
// for the same reason.
//
// It is anchored on the wall clock rather than being a bare elapsed
// count, and that is the load-bearing part. A lockout writes the instant
// it lifts, `lockedUntil`, into the state it keeps AND into the audit row
// it files when a budget runs out. The console shows the first to an
// operator as a date and reads the second back off disk to decide
// whether a recorded lockout is still standing. A bare elapsed reading
// would put a count of milliseconds since this process started where
// both of those expect an instant, so the console would render 1970 and
// read every recorded lockout as already lifted. Anchoring keeps the
// value an instant on a clock the host cannot step. What it costs is
// that a legitimate correction is not applied to waits already running:
// the server keeps the time it measured. That is
// the direction to be wrong in, because the alternative is a wait an
// attacker can end by getting the host's clock moved.
//
// The cache underneath takes the SAME clock, and passing it to only one
// of the two would fix nothing. The counter is stored for the length of
// the decay window and the cache expires it against whatever clock it
// was built with, so a budget measured on a steady clock and stored
// against the wall clock is still handed back by a step forward: the
// arithmetic says the failures stand and the counter they were written
// on is simply gone.
function _steadyNow() {
  return WALL_ORIGIN_MS + (b.time.monotonicMs() - ELAPSED_ORIGIN_MS);
}

// Built on first use rather than when this file is required, because the
// handles carry a sweep timer and a module that builds one at load time
// builds it in every process that merely reads this file. One set for
// the process, so closing and reopening the store does not hand an
// attacker a fresh budget.
var budgets = null;

function _budgets() {
  if (budgets !== null) return budgets;
  budgets = {
    mailbox: b.auth.lockout.create({
      namespace: MAILBOX_BUDGET,
      clock:     _steadyNow,
      cache:     b.cache.create({
        namespace:  MAILBOX_CACHE_NAMESPACE,
        backend:    "memory",
        clock:      _steadyNow,
        maxEntries: BUDGET_ENTRIES,
      }),
      audit: b.audit,
    }),
    peer: b.auth.lockout.create({
      namespace: MAILBOX_PEER_BUDGET,
      clock:     _steadyNow,
      cache:     b.cache.create({
        namespace:  MAILBOX_PEER_CACHE_NAMESPACE,
        backend:    "memory",
        clock:      _steadyNow,
        maxEntries: BUDGET_ENTRIES,
      }),
      audit: b.audit,
    }),
    // The exemption a mailbox earns for a source it has already signed
    // in from is a window too, and a longer one. A clock stepping
    // backwards would hold an address exempt past the point the mailbox
    // stopped using it, which is the direction that matters here: the
    // exemption is what lets a source through while the budget is spent.
    familiar: b.cache.create({
      namespace:  FAMILIAR_SOURCE_NAMESPACE,
      backend:    "memory",
      clock:      _steadyNow,
      ttlMs:      FAMILIAR_SOURCE_TTL_MS,
      maxEntries: FAMILIAR_SOURCE_MAX,
    }),
  };
  return budgets;
}

// The peer as a counter key. `b.requestHelpers.ipKey` keeps an IPv4
// address exact and collapses an IPv6 one to the prefix its site is
// allocated, so a client that rotates the low bits of its own address
// does not mint a fresh budget every attempt. An address that cannot be
// read at all comes back empty, and an empty key means no pair budget
// and no exemption rather than a bucket everyone shares.
//
// A key already in that form is taken back as itself. This matters
// because the key is not private: it is what the pair budget's audit
// rows are filed under, so an operator surface releasing or reading a
// peer's budget is handing back a string this function produced. The
// collapsed IPv6 form carries its prefix length, which makes it
// something other than an address, and `ipKey` reads no address out of
// it. Without this an operator releasing an IPv6 peer by the key the
// trail showed them would release nothing and be told the mailbox was
// released, which is the worst of both answers.
//
// Round-tripping is what decides, not the shape: the address inside the
// key has to key back to exactly the key that arrived. Nothing else is
// accepted, so this cannot become a way to name a counter by writing
// one. Every caller on the authentication path supplies a peer the
// server read off the socket, never a key, so the two forms never meet
// there.
function _sourceKey(source) {
  if (typeof source !== "string" || source.length === 0) return "";
  var fresh = b.requestHelpers.ipKey(source);
  if (fresh !== "") return fresh;
  var slash = source.lastIndexOf("/");
  if (slash <= 0) return "";
  return b.requestHelpers.ipKey(source.slice(0, slash)) === source ? source : "";
}

// The peer first, because a peer key is a dotted address or a masked
// prefix and carries no vertical bar, while a mailbox address can. Read
// from the left, the split is therefore unambiguous, and two different
// pairs cannot fold into one key.
function _pairKey(identity, sourceKey) {
  return sourceKey + "|" + identity;
}

// Whether this attempt is refused before the password is looked at, and
// under which name. Reading the pair budget first is deliberate: it is
// the tighter of the two, and a source that has spent it is refused even
// when the mailbox budget would have let it through.
async function _budgetRefusal(budget, identity, pairKey) {
  if (pairKey !== null) {
    var pair = await budget.peer.check(pairKey);
    if (pair.locked) return "too-many-attempts";
  }
  var mailbox = await budget.mailbox.check(identity);
  if (!mailbox.locked) return null;
  if (pairKey !== null && (await budget.familiar.get(pairKey))) return null;
  return "too-many-attempts";
}

async function _spendBudget(budget, identity, pairKey) {
  await budget.mailbox.recordFailure(identity);
  if (pairKey !== null) await budget.peer.recordFailure(pairKey);
}

// One budget's reading, in the shape every caller gets back.
//
// `attempts` is the failures counted since this budget last ran out, and
// it is meaningful only BELOW the threshold. The failure that spends a
// budget resets the count to zero, because the wait that follows is the
// answer rather than the count, so a budget that is holding somebody out
// reads zero attempts and so does a mailbox nobody has ever guessed at.
// Anything showing the number has to say which of the two it is showing;
// read on its own it says the opposite of what is happening. What is
// worth reading for a budget that is already holding is how many times
// it has run out, and that is not a number the counter keeps: it is on
// the row the lockout wrote when it engaged.
//
// `lockedUntil` is null rather than absent when a budget is not holding,
// so a caller reads one shape whichever way the answer went.
function _budgetReading(verdict) {
  return {
    locked:      verdict.locked === true,
    attempts:    typeof verdict.attempts === "number" ? verdict.attempts : 0,
    lockedUntil: typeof verdict.lockedUntil === "number" ? verdict.lockedUntil : null,
  };
}

// A credential that verified is not a guess, so the counter kept against
// this peer goes back to zero and the peer becomes one this mailbox is
// known to use.
//
// The counter kept against the mailbox is deliberately left alone. A
// mail client authenticates constantly: a POP3 poll every minute, an
// IMAP session reconnecting, a submission on every send. Releasing the
// mailbox budget on each of those would hand whoever is guessing at that
// mailbox a fresh five attempts at the rate its owner's client happens
// to poll, which is most of the bound given away. It decays on its own
// once the failures stop, and an operator can release it outright.
async function _clearBudget(budget, pairKey) {
  if (pairKey === null) return;
  await budget.peer.recordSuccess(pairKey);
  await budget.familiar.set(pairKey, true, { ttlMs: FAMILIAR_SOURCE_TTL_MS });
}

function _requireOpts(opts, fn) {
  if (typeof opts !== "object" || opts === null) {
    throw err("store/bad-argument", "accounts." + fn + " takes an options object.");
  }
  return opts;
}

function _requireStatus(status, fn) {
  if (tables.ACCOUNT_STATUS.indexOf(status) === -1) {
    throw err("store/bad-argument",
      "accounts." + fn + ": status must be one of " + tables.ACCOUNT_STATUS.join(", ") +
      ", got " + JSON.stringify(status) + ".");
  }
  return status;
}

function _readDisplayName(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw err("store/bad-argument", "displayName must be a string.");
  }
  var text = value.trim();
  if (text.length === 0) return null;
  if (text.length > MAX_DISPLAY_NAME_CHARS) {
    throw err("store/bad-argument",
      "displayName is longer than the " + MAX_DISPLAY_NAME_CHARS + " characters a display name may carry.");
  }
  // A display name is rendered into outbound headers, into the admin
  // views and into the JMAP name of every address a client shows. A
  // control character in one is a header-injection attempt or a mistake,
  // and neither belongs in the database: a row holding one is a row every
  // later reader has to remember to screen, and the readers are in five
  // different modules. It is refused here, once, where it is written.
  if (displayText.hasControlChar(text)) {
    throw err("store/bad-argument", "displayName contains a control character.");
  }
  var verdict = b.guardText.validate(text, DISPLAY_NAME_GUARD);
  if (!verdict.ok) {
    throw err("store/bad-argument",
      "displayName carries a codepoint that renders as nothing and changes what a reader " +
      "sees (" + errors.issueKinds(verdict.issues) + ").");
  }
  return text;
}

function _readQuotaBytes(value) {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw err("store/bad-argument",
      "quotaBytes must be a whole number of bytes, or 0 for no limit.");
  }
  return value;
}

// What state this account is in, which is the row's status column
// unless an erasure was recorded against the row and the column did not
// take it.
//
// One reader for every gate. The status is one write, and a volume that
// refuses it would otherwise leave a row reading `active` while the
// marker beside it says an erasure is outstanding. Asking here instead
// means the answer does not depend on which of the two writes the
// volume took.
//
// Erasing outranks whatever the column says, in that direction only. It
// is the one state nothing returns from, so a row carrying both reads as
// the one that cannot be walked back.
//
// The derivation is the table layer's, beside the two columns it reads,
// because the recipient lookup decides deliverability off the same row
// and a second copy of the rule here is how the two came to disagree.
var _statusOf = tables.accountStatus;

function _present(row) {
  if (!row) return null;
  var at = row.address.lastIndexOf("@");
  return {
    id:                row._id,
    address:           row.address,
    localPart:         row.address.slice(0, at),
    domain:            row.domain,
    displayName:       row.displayName === undefined ? null : row.displayName,
    isAdmin:           row.isAdmin === 1,
    status:            _statusOf(row),
    statusReason:      row.statusReason === undefined ? null : row.statusReason,
    quotaBytes:        row.quotaBytes,
    createdAt:         row.createdAt,
    updatedAt:         row.updatedAt,
    archivedAt:        row.archivedAt === undefined ? null : row.archivedAt,
    passwordChangedAt: row.passwordChangedAt,
  };
}

function _rowById(id) {
  if (typeof id !== "string" || id.length === 0) {
    throw err("store/bad-argument", "an account id must be a non-empty string.");
  }
  return b.db.from(tables.ACCOUNTS).where({ _id: id }).first();
}

function _rowByAddress(canonicalAddress) {
  return b.db.from(tables.ACCOUNTS).where({ address: canonicalAddress }).first();
}

function _requireRow(id) {
  var row = _rowById(id);
  if (!row) {
    throw err("store/no-such-account", "no account with id " + JSON.stringify(id) + ".");
  }
  return row;
}

function _hostedDomain(name) {
  return b.db.from(tables.DOMAINS).where({ domain: name }).first();
}

// The hosted-domain rule, in one place because it is asked twice: once
// before the password is hashed, so an operator typo is refused without
// paying for Argon2id, and again inside the transaction that writes the
// row, because hashing is the longest gap in this layer and a domain can
// be removed across it.
function _requireActiveDomain(name) {
  var row = _hostedDomain(name);
  if (!row) {
    throw err("store/no-such-domain",
      name + " is not hosted here. Add the domain before creating a mailbox in it.");
  }
  if (row.status !== "active") {
    throw err("store/domain-disabled",
      name + " is " + row.status + ", so it cannot take a new mailbox.");
  }
  return row;
}

function _aliasHolding(canonicalAddress) {
  return b.db.from(tables.ALIASES).where({ address: canonicalAddress }).first();
}

// Whether the trail says an erasure ran against this account and did not
// reach the identity.
//
// The row's own markers are writes, and the chain is not. An erasure
// marks the row before it destroys anything and files this row after it
// has settled what it could, so between them the two records answer for
// each other: a row whose markers were later lost still has the chain
// behind it, and a run that stopped before it could file this one had
// already written the markers.
//
// A row surviving beside such an entry is an unfinished erasure, always.
// An erasure that reaches the identity erases the row, so an account
// that still answers to an id one of these was filed against is one
// whose erasure has not finished, whatever its own columns say.
//
// It reads through the framework's own query, which files a row for the
// read. That is the audit-of-audits working as intended: asking whether
// an account is under an outstanding erasure is a question about
// somebody's data, and it is asked by the two operator verbs that return
// an account to service and nowhere else. A credential check does not
// ask it, because that runs on every connection on every protocol and
// would file a row for each one; the row's own markers are what decide
// a sign in.
async function _erasureOutstanding(id) {
  var rows;
  try {
    rows = await b.audit.query({
      action: "account.erasure_held", resourceId: id, limit: 8 });
  } catch (_sinkError) {
    // A sink that cannot answer leaves this reader with nothing, and
    // what it must not do is hand the caller the sink's error: an
    // operator reading that cannot tell a verb that refused from one
    // that could not ask. The row's own markers are the first record and
    // are read without this, so a sink outage costs the second reading
    // and not the gate.
    return false;
  }
  if (!Array.isArray(rows)) return false;
  // The identifier is checked on the rows that come back as well as
  // asked for in the criteria. The column is sealed and the match runs
  // against a derived hash beside it, so a criteria key the framework
  // could not resolve to that column would widen the query rather than
  // narrow it, and a gate answering yes for every account is a gate
  // nobody can use.
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i] && rows[i].resourceId === id) return true;
  }
  return false;
}

// The refusal an account part-way through an erasure draws, minted once
// so the two verbs that raise it and the re-reads inside their own
// writes all raise the same sentence under the same code.
//
// `verb` names what was asked for, because the two need different next
// steps from the operator: archiving would close an erasure this server
// still owes, and reinstating would hand somebody a mailbox that no
// longer holds what they had.
function _erasingRefusal(row, verb) {
  if (verb === "archive") {
    return err("store/account-erasing",
      "account " + row._id + " is part-way through an erasure, so archiving it would put " +
      "a row whose mail is already destroyed back within reach of reinstatement and " +
      "close an erasure this server still owes. Run the erasure again with destroy to " +
      "finish it, once whatever held it back has let go.");
  }
  return err("store/account-erasing",
    "account " + row._id + " is part-way through an erasure and cannot be returned to " +
    "service: the mail it held is already destroyed. Its row is kept only to answer for " +
    "what a preservation order or the retention floor held back, and it goes when the " +
    "erasure is run again and reaches that mail.");
}

// One refusal from the identity step, in the shape every other record an
// erasure could not destroy is reported in.
//
// `step` names which of the two writes it was, because the two leave the
// account in different states and an operator acts differently on each:
// a row that could not be erased is still marked and still listed as
// erasing, and a row that could not be marked is an account in service
// whose mail has gone. Classified by the shared rule rather than a copy
// of it, so a gate wanting a second approver reads the same here as it
// does over a filter script.
function _identityRefusal(address, step, e) {
  var code = (e && e.code) || "unknown";
  return {
    record:    "the account row for " + address + " could not be " + step,
    reason:    code,
    preserved: errors.isPreservationRefusal(code),
    detail:    (e && e.message) || String(e),
  };
}

// Whether one entry of the mailbox layer's refusal report is a MESSAGE.
//
// That report carries four kinds of record and only one of them is mail:
// beside the messages the delete path kept are the mailbox rows something
// is still bound to, the account's filter scripts and its annotations.
// The delete path decides about a message and hands back the identifier
// it decided about, so an entry carrying one is a message and an entry
// carrying none is one of the other three. The mailbox layer applies this
// same test to split its own audit row, and this is the second reader of
// the same list rather than a second rule for it.
function _isMessageRecord(entry) {
  return entry !== null && entry !== undefined &&
    entry.objectid !== null && entry.objectid !== undefined;
}

// Whether something is being kept on purpose. A preservation order, the
// regulated retention window, or a gate wanting a second approver each
// leave the record where it is and leave nothing to repair; anything else
// is a record on a volume that was asked to lose it. The two need
// opposite responses from whoever reads the report, and every list in it
// is split by this one test.
function _wasPreserved(entry) {
  return entry.preserved === true;
}

function _notPreserved(entry) {
  return entry.preserved !== true;
}

function create(ctx) {
  var policy = ctx.policy;

  // How this layer reaches the mailbox adapter, as a function rather
  // than as the handle itself. The two are built in one pass and each
  // reads the other: the adapter asks this layer for an account's quota
  // when a message is appended, and this layer asks the adapter to erase
  // an account's mail when the account is erased. Resolving on the call
  // is what lets whichever is built second be the one the first finds.
  //
  // That it is a function is settled here, at the assembly, because an
  // assembly with no way to reach the adapter is a mistake an operator
  // should meet at boot rather than at the first erasure. What the
  // function answers with can only be checked when it is called, and
  // that check is below.
  if (typeof ctx.mailbox !== "function") {
    throw new TypeError("blamepost.store.accounts.create: ctx.mailbox must be a function " +
      "returning the mailbox adapter. An erasure destroys the account's mail first and the " +
      "account row only after, because the delete path refuses per message and a record a " +
      "preservation order or the retention floor keeps has to still have an account to " +
      "resolve. The two handles are built in one pass reading each other, so the adapter " +
      "is reached through a function rather than captured here.");
  }
  var mailboxFor = ctx.mailbox;

  function _mailbox() {
    var handle = mailboxFor();
    if (!handle || typeof handle.eraseAccountMail !== "function") {
      throw err("store/no-mailbox-adapter",
        "this account layer cannot reach the mailbox adapter, so an erasure would destroy " +
        "the account row and reach none of its mail: the mailboxes, the message rows and " +
        "the sealed message bodies would all stay on the volume, readable, with nothing " +
        "left to release them. Build the two together, the way blamepost.store.open does.");
    }
    return handle;
  }

  async function _hashPassword(plaintext, forAddress, label) {
    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw err("store/bad-password", label + " must be a non-empty string.");
    }
    var verdict = await policy.check(plaintext, { email: forAddress });
    if (!verdict.ok) {
      throw err("store/weak-password", label + " was refused: " + verdict.message);
    }
    return b.auth.password.hash(plaintext);
  }

  /**
   * @primitive blamepost.store.accounts.create
   * @signature blamepost.store.accounts.create(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9106, RFC 5321 section 4.1.2
   * @related   blamepost.store.accounts.authenticate, blamepost.store.domains.add
   *
   * Create a mailbox. The domain has to be hosted here and active, the
   * address has to be free of both accounts and aliases, and the
   * password has to survive the policy check before anything is
   * written. The returned account carries no credential material.
   *
   * An address with a plus tag is refused: the tag is a routing suffix
   * a sender chose, so an account claiming one would own every address
   * that shares its mailbox name.
   *
   * @opts
   *   address:     string,   // required
   *   password:    string,   // required
   *   displayName: string,   // optional, shown in headers and the admin views
   *   quotaBytes:  number,   // optional, 0 for no limit
   *   isAdmin:     boolean,  // optional, grants the operator interface
   *
   * @example
   *   await store.accounts.create({
   *     address:  "alice@example.com",
   *     password: "correct horse battery staple",
   *   });
   */
  async function createAccount(opts) {
    _requireOpts(opts, "create");
    var parsed = address.canonical(opts.address, "address");
    if (parsed.tag !== null) {
      throw err("store/bad-address",
        "an account address cannot carry a plus tag: " + JSON.stringify(opts.address) +
        " routes to " + parsed.address + ", which is the address to create.");
    }

    var displayName = _readDisplayName(opts.displayName);
    var quotaBytes  = _readQuotaBytes(opts.quotaBytes);
    var isAdmin     = opts.isAdmin === true;

    _requireActiveDomain(parsed.domain);

    var passwordHash = await _hashPassword(opts.password, parsed.address, "password");
    var now = Date.now();

    var row = b.db.transaction(function () {
      // Read again, inside the write. The check above ran before the
      // password was hashed, and a domain removed across that gap would
      // otherwise leave a mailbox in a domain this server does not
      // answer for: its mail bounces, and it can still sign in and send
      // under a name with no selector to sign with.
      _requireActiveDomain(parsed.domain);
      if (_rowByAddress(parsed.address)) {
        throw err("store/address-taken", parsed.address + " already has an account.");
      }
      if (_aliasHolding(parsed.address)) {
        throw err("store/address-taken",
          parsed.address + " is already an alias. Remove the alias before giving the address a mailbox.");
      }
      return tables.insertRow(tables.ACCOUNTS, {
        address:           parsed.address,
        domain:            parsed.domain,
        displayName:       displayName,
        passwordHash:      passwordHash,
        isAdmin:           isAdmin ? 1 : 0,
        status:            "active",
        statusReason:      null,
        quotaBytes:        quotaBytes,
        createdAt:         now,
        updatedAt:         now,
        archivedAt:        null,
        passwordChangedAt: now,
      });
    });

    await auditActor.record({
      action:   "account.created",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "account", id: row._id },
      metadata: { address: parsed.address, domain: parsed.domain, isAdmin: isAdmin },
    });

    return _present(row);
  }

  /**
   * @primitive blamepost.store.accounts.get
   * @signature blamepost.store.accounts.get(idOrAddress)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: mailbox identity above the message store)
   * @related   blamepost.store.accounts.list, blamepost.store.resolve
   *
   * One account by id or by address, or null when there is none. An
   * argument containing an at sign is read as an address, folded and
   * tag-stripped first, so the same lookup works from a wire listener
   * and from the admin views. The result never carries the password
   * hash.
   *
   * @example
   *   store.accounts.get("alice@example.com").status;
   *   // "active"
   */
  function get(idOrAddress) {
    if (typeof idOrAddress !== "string" || idOrAddress.length === 0) {
      throw err("store/bad-argument", "accounts.get takes an account id or an address.");
    }
    if (idOrAddress.indexOf("@") === -1) return _present(_rowById(idOrAddress));
    var parsed = address.parse(idOrAddress);
    if (!parsed.ok) return null;
    return _present(_rowByAddress(parsed.address));
  }

  /**
   * @primitive blamepost.store.accounts.list
   * @signature blamepost.store.accounts.list(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: mailbox identity above the message store)
   * @related   blamepost.store.accounts.get
   *
   * Accounts in address order, filtered by domain and status. Archived
   * accounts are left out unless asked for, because the common question
   * is which mailboxes are live. Sorting happens after the rows are
   * read, since the address column is sealed and the database can only
   * order the ciphertext.
   *
   * An account whose erasure could not finish is listed by default even
   * though it authenticates no better than an archived one. It is the
   * one status an operator has an outstanding job against: mail this
   * server was asked to destroy is still on the volume, and leaving the
   * row out of the answer would let an unfinished erasure read as a
   * finished one for as long as the rule keeping that mail lasts.
   *
   * @opts
   *   domain:          string,   // only this hosted domain
   *   status:          string,   // active, suspended, archived or erasing
   *   includeArchived: boolean,  // keep archived rows in the result
   *   limit:           number,   // rows returned, applied after sorting
   *   offset:          number,   // rows skipped, applied after sorting
   *
   * @example
   *   store.accounts.list({ domain: "example.com" }).length;
   */
  function list(opts) {
    opts = opts || {};
    var query = b.db.from(tables.ACCOUNTS);

    if (opts.domain !== undefined && opts.domain !== null) {
      query = query.where({ domain: address.canonicalDomain(opts.domain, "domain") });
    }
    if (opts.status !== undefined && opts.status !== null) {
      query = query.where({ status: _requireStatus(opts.status, "list") });
    } else if (opts.includeArchived !== true) {
      query = query.whereIn("status", ["active", "suspended", "erasing"]);
    }

    var out = query.orderBy("createdAt", "asc").all().map(_present);
    out.sort(function (left, right) {
      return left.address < right.address ? -1 : (left.address > right.address ? 1 : 0);
    });

    var offset = opts.offset === undefined ? 0 : opts.offset;
    var limit  = opts.limit;
    if (typeof offset !== "number" || !Number.isInteger(offset) || offset < 0) {
      throw err("store/bad-argument", "accounts.list: offset must be a whole number of rows.");
    }
    if (limit !== undefined && limit !== null &&
        (typeof limit !== "number" || !Number.isInteger(limit) || limit < 0)) {
      throw err("store/bad-argument", "accounts.list: limit must be a whole number of rows.");
    }
    if (offset > 0) out = out.slice(offset);
    if (limit !== undefined && limit !== null) out = out.slice(0, limit);
    return out;
  }

  /**
   * @primitive blamepost.store.accounts.authenticate
   * @signature blamepost.store.accounts.authenticate(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9106, RFC 4954 section 4
   * @related   blamepost.store.accounts.setPassword, blamepost.store.accounts.unlock
   *
   * Check one credential and return a verdict. It never throws on bad
   * input and never says which half was wrong, so a listener can hand it
   * whatever arrived on the wire and answer with a single refusal. An
   * address with no account still pays for a verification, so timing
   * does not leak which mailboxes exist.
   *
   * The credential is not the only gate. A correct password on an
   * account that is suspended or archived is refused under
   * `account-<status>`, and one whose domain is disabled or no longer
   * hosted is refused under `domain-disabled` or `domain-not-hosted`.
   * Re-enabling the domain restores sign in for every mailbox in it.
   *
   * A successful sign in whose stored hash is below the current Argon2id
   * parameters is rehashed in place, so raising the cost reaches every
   * account as its owner signs in rather than needing a reset. Hashing
   * is slow on purpose, so the stored hash is read again before the
   * replacement is written and the write is abandoned when it has
   * changed: a password reset landing while a sign in is mid-rehash
   * holds, and the sign in that was already in flight still succeeds.
   * A replacement the volume will not take is dropped rather than
   * raised, for the same reason: the credential has already been
   * answered for, and the next sign in tries the replacement again.
   *
   * Wrong credentials spend a failure budget kept against the mailbox,
   * and an attempt made once the budget is gone is refused under
   * `too-many-attempts` before any verification runs. The budget
   * is not keyed on the peer, so moving between source addresses does not
   * refill it, and it is one budget rather than one per protocol. It
   * decays once the failures stop, and `unlock` releases it outright; a
   * correct credential does not, because a mail client authenticating on
   * a poll would otherwise refill it for whoever is guessing.
   *
   * `source` is the peer the attempt arrived from, and passing it is what
   * keeps the budget from becoming a way to lock somebody out of their own
   * mail: a source this mailbox has already signed in from is still let in
   * while the budget is spent, bounded by its own smaller budget. Every
   * listener has the peer to hand and so does the browser surface. An
   * attempt with no source is bounded by the mailbox budget alone.
   *
   * @opts
   *   address:  string,   // as presented on the wire
   *   password: string,   // as presented on the wire
   *   source:   string,   // the peer address the attempt arrived from
   *
   * @example
   *   var verdict = await store.accounts.authenticate({
   *     address: "alice@example.com", password: "correct horse battery staple",
   *   });
   *   verdict.ok;
   */
  async function authenticate(opts) {
    var supplied = (typeof opts === "object" && opts !== null) ? opts : {};
    var password = typeof supplied.password === "string" ? supplied.password : "";
    var parsed = address.parse(supplied.address);

    // An address this server cannot read names no mailbox, so there is
    // nothing to keep a budget against. It still pays for a verification
    // below and is still refused.
    var identity = parsed.ok ? parsed.address : null;
    var budget = _budgets();
    var sourceKey = _sourceKey(supplied.source);
    var pairKey = (identity !== null && sourceKey !== "")
      ? _pairKey(identity, sourceKey)
      : null;

    if (identity !== null) {
      var refusal = await _budgetRefusal(budget, identity, pairKey);
      if (refusal !== null) return _denied(identity, refusal, supplied.source);
    }

    var row = null;
    if (parsed.ok) row = _rowByAddress(parsed.address);

    // An address with no account spends the budget exactly as one with an
    // account does. A budget that only counted real mailboxes would answer
    // the question the burned verification above exists to hide.
    if (!row || password.length === 0) {
      await _burnVerification(password);
      if (identity !== null) await _spendBudget(budget, identity, pairKey);
      return _denied(identity, "bad-credentials", supplied.source);
    }

    var matched = await b.auth.password.verify(row.passwordHash, password);
    if (!matched) {
      await _spendBudget(budget, identity, pairKey);
      return _denied(parsed.address, "bad-credentials", supplied.source);
    }
    await _clearBudget(budget, pairKey);
    var signInStatus = _statusOf(row);
    if (signInStatus !== "active") {
      return _denied(parsed.address, "account-" + signInStatus, supplied.source);
    }

    // An account is only usable while the domain it belongs to is. The
    // verdict here is what every listener authenticates against, and
    // submission binds the sender to the account's own address, so a
    // mailbox on a withdrawn domain that could still sign in could still
    // send under a name this server does not answer for and holds no
    // DKIM selector for.
    var domainRow = _hostedDomain(row.domain);
    if (!domainRow) {
      return _denied(parsed.address, "domain-not-hosted", supplied.source);
    }
    if (domainRow.status !== "active") {
      return _denied(parsed.address, "domain-" + domainRow.status, supplied.source);
    }

    // Raising the Argon2id cost reaches an account as its owner signs
    // in, so a stored hash below the current parameters is replaced
    // here rather than by a reset.
    //
    // The row is read AGAIN inside the write, and the hash it holds now
    // has to be the one this rehash was decided about. Hashing is the
    // longest gap anywhere in this layer, and it is long by design:
    // everything the account row says was read before it and describes
    // the row as it stood then. A password changed across that gap and
    // written back over would be a reset silently undone, which is the
    // worst version of this because it is the containment step for a
    // credential that has been taken: the operator replaces the
    // password, a sign in already in flight with the old one finishes
    // its rehash, and the credential they were containing opens the
    // mailbox again on every listener while the reset reports success.
    //
    // Abandoning the rehash costs nothing and is never an authentication
    // failure. The credential presented here verified, which is the
    // question this verb answers; the rehash is housekeeping on top of
    // that answer, and a row that has moved is a row somebody else has
    // just written a current hash onto.
    if (b.auth.password.needsRehash(row.passwordHash)) {
      try {
        var refreshed = await b.auth.password.hash(password);
        b.db.transaction(function () {
          var current = _rowById(row._id);
          if (!current || current.passwordHash !== row.passwordHash) return;
          tables.updateRow(tables.ACCOUNTS, row._id, {
            passwordHash: refreshed,
            updatedAt:    Date.now(),
          });
        });
      } catch (_rehashError) {
        // drop-silent by design, and the hashing is inside this guard for
        // the same reason the write is. Neither a rehash this host could
        // not compute nor a volume that would not take the write is an
        // answer about the credential, and raising on either would turn a
        // local fault into every mailbox on this server being unable to
        // sign in on any listener. Nothing is lost by leaving it: the
        // stored hash is still the one that just verified, and the next
        // sign in reaches this same line and tries again.
      }
    }

    b.audit.safeEmit({
      action:   "account.authenticated",
      outcome:  "success",
      // The principal is the account that has just proved it holds the
      // credential, whichever surface asked. Reading the surrounding
      // scope instead would record whoever was already signed in, and
      // at a sign in that is nobody, so the row would name nobody for
      // the one event that establishes a name.
      actor:    auditActor.build({ userId: row._id, ip: supplied.source }),
      resource: { kind: "account", id: row._id },
      metadata: { address: parsed.address },
    });

    return {
      ok:        true,
      accountId: row._id,
      address:   row.address,
      domain:    row.domain,
      isAdmin:   row.isAdmin === 1,
      reason:    null,
    };
  }

  function _denied(shownAddress, reason, source) {
    b.audit.safeEmit({
      action:   "account.authentication_refused",
      outcome:  "denied",
      // The peer is a fact and the address is a claim. An attempt that
      // was refused proved no identity, so putting the address it named
      // in the column that answers who acted would let whoever is
      // guessing choose the name an auditor reads back. It stays in the
      // metadata, as one of the things that were said, and where the
      // attempt came from is what the row can stand behind.
      actor:    auditActor.build({ ip: source }),
      reason:   reason,
      metadata: { address: shownAddress },
    });
    return { ok: false, accountId: null, address: null, domain: null, isAdmin: false, reason: reason };
  }

  /**
   * @primitive blamepost.store.accounts.unlock
   * @signature blamepost.store.accounts.unlock(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one failure budget per mailbox, released by the operator)
   * @related   blamepost.store.accounts.authenticate, blamepost.store.accounts.suspend
   *
   * Give a mailbox its failure budget back. The budget refuses a correct
   * password once wrong ones have spent it, and each further spend keeps
   * it refused for longer, so an account holder whose own client was
   * sending a stale password has nothing to do but wait. This is the way
   * back that does not involve waiting.
   *
   * The budget kept against the mailbox is released outright. The
   * smaller one kept against a single peer is released too when the
   * peer is named, which is what an account holder reporting the
   * problem from one machine needs. The peer is named either as the
   * address it connects from or as the key its counter was recorded
   * under, because that key is what the lockout trail shows an operator
   * and an IPv6 one is a masked prefix rather than an address.
   *
   * A peer that resolves to no key refuses the WHOLE call, before
   * anything has been released. The pair budget is read FIRST when a
   * sign in is judged, so releasing the mailbox alone and reporting
   * success would leave the account holder refused on exactly the
   * machine the caller named, and would file an audit row saying a peer
   * budget was released when none was. The refusal names what arrived
   * and what to do instead.
   *
   * The two budgets are answered for separately. `mailbox` and `peer`
   * each say whether that budget was holding, and `peer` is null when no
   * peer was named as against false when one was named and was already
   * clear: nothing was read is not the same answer as nothing was
   * holding, and a caller acts differently on each. `released` is the
   * verdict over both, which answers only whether anything was holding
   * this account back at all. `source` is the key the peer budget was
   * looked up under, so a caller names what this server released rather
   * than what it was handed.
   *
   * This is not a way to reinstate a suspended account: the credential
   * and the status are separate gates and this touches only the first.
   *
   * @opts
   *   address: string,   // required, the mailbox address
   *   reason:  string,   // required, recorded in the audit trail
   *   source:  string,   // optional, a peer address or the key one was recorded under; one this server cannot read refuses the whole call
   *
   * @example
   *   await store.accounts.unlock({
   *     address: "alice@example.com",
   *     reason:  "client was sending a stale password",
   *   });
   */
  async function unlock(opts) {
    _requireOpts(opts, "unlock");
    var parsed = address.canonical(opts.address, "address");
    if (typeof opts.reason !== "string" || opts.reason.trim().length === 0) {
      throw err("store/bad-argument",
        "accounts.unlock needs a reason. Releasing a failure budget is an operator " +
        "action on somebody else's mailbox, and the audit trail is where it is answered for.");
    }
    var reason = opts.reason.trim();
    // A typo here would otherwise read as a settled fact: the budget
    // holds addresses that have no account, so releasing one would
    // report success for a mailbox this server does not host.
    var row = _rowByAddress(parsed.address);
    if (!row) {
      throw err("store/no-such-account",
        "no account at " + parsed.address + ", so there is no mailbox here to release.");
    }

    // The peer is resolved to the key its counter is kept under BEFORE
    // anything is released, and a peer that resolves to none refuses the
    // whole call. Resolving after the mailbox budget had already gone
    // would leave the caller holding a release they did not ask for, on
    // the half of the request they were not calling about: the pair
    // budget is read first when a sign in is judged, so the named machine
    // stays refused while the answer reads as a fix. It would also file
    // an audit row for a peer release that never happened.
    var named = typeof opts.source === "string" ? opts.source.trim() : "";
    var sourceKey = _sourceKey(opts.source);
    if (named.length > 0 && sourceKey === "") {
      throw err("store/bad-argument",
        "accounts.unlock: nothing in " + JSON.stringify(named) + " reads as an address, so " +
        "no failure counter is kept under it and there is no peer budget to release. Nothing " +
        "was released: not that peer, and not the mailbox beside it. Release with no source " +
        "to give the mailbox its budget back on its own, or name the peer by the key the " +
        "lockout trail records it under, which for a client connecting over IPv6 is the " +
        "prefix its site is allocated rather than the address it connected from.");
    }

    var budget = _budgets();
    var releasedMailbox = (await budget.mailbox.unlock(parsed.address, { reason: reason })) === true;
    // Null rather than false while no peer was named, because the two
    // are different answers: one budget was not read, as against read
    // and found clear.
    var releasedPeer = null;
    if (sourceKey !== "") {
      releasedPeer = (await budget.peer.unlock(_pairKey(parsed.address, sourceKey),
        { reason: reason })) === true;
    }
    var releasedAny = releasedMailbox || releasedPeer === true;

    await auditActor.record({
      action:   "account.lockout_released",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "account", id: row._id },
      metadata: {
        address: parsed.address,
        source:  sourceKey === "" ? null : sourceKey,
        // Per budget beside the verdict over both, so a row read back
        // afterwards says WHICH budget was holding rather than only that
        // something was. The trail is the record of an operator action on
        // somebody else's mailbox, and "a budget was released" answers
        // none of the questions asked of it afterwards.
        mailbox: releasedMailbox,
        peer:    releasedPeer,
        hadLock: releasedAny,
      },
    });

    return {
      address:  parsed.address,
      // The key the peer budget was looked up under rather than what
      // arrived, so a caller names what this server released.
      source:   sourceKey === "" ? null : sourceKey,
      mailbox:  releasedMailbox,
      peer:     releasedPeer,
      released: releasedAny,
    };
  }

  /**
   * @primitive blamepost.store.accounts.lockoutState
   * @signature blamepost.store.accounts.lockoutState(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one failure budget per mailbox, released by the operator)
   * @related   blamepost.store.accounts.unlock, blamepost.store.accounts.authenticate
   *
   * What the failure budgets say about one mailbox right now. The
   * budgets are counters in this process, so this is the state that is
   * actually refusing a password, as against the lockout trail on disk,
   * which is a record of budgets that ran out and may name one that is
   * long since free.
   *
   * Two readings come back. `mailbox` is the budget kept against the
   * address from anywhere, and it is always read. `peer` is the smaller
   * one kept against a single source and that mailbox together, and it
   * is read only when `source` names one; it is null otherwise, and null
   * as well when the source is not something this server can read as an
   * address. The keys are derived exactly as `unlock` derives them, so
   * what is read is what a release would release.
   *
   * `attempts` is an early warning and nothing more. The failure that
   * spends a budget resets the count, so a budget whose `locked` is true
   * reads zero attempts, and so does a mailbox nobody has guessed at.
   * Show the number only where `locked` is false, or it says the
   * opposite of what is happening. How many times a budget has run out,
   * which is what sets how long the wait is, is on the lockout trail
   * rather than on the counter.
   *
   * Reading constructs nothing: a budget that has never seen a failure
   * comes back clear rather than being brought into existence. An
   * address this server hosts no mailbox at is refused rather than
   * answered about, exactly as a release of one is, so this cannot
   * become a way to ask about anything other than a mailbox here.
   *
   * @opts
   *   address: string,   // required, the mailbox address
   *   source:  string,   // optional, a peer address or the key one was recorded under
   *
   * @example
   *   var state = await store.accounts.lockoutState({ address: "alice@example.com" });
   *   state.mailbox.locked;
   */
  async function lockoutState(opts) {
    _requireOpts(opts, "lockoutState");
    var parsed = address.canonical(opts.address, "address");
    // The same refusal a release makes, for the same reason: the budgets
    // count addresses that have no account here, so answering about one
    // would report a mailbox's state for something that is not a
    // mailbox, and an operator would read it as one.
    var row = _rowByAddress(parsed.address);
    if (!row) {
      throw err("store/no-such-account",
        "no account at " + parsed.address + ", so there is no mailbox here whose sign-in " +
        "budget can be read.");
    }

    var budget = _budgets();
    var sourceKey = _sourceKey(opts.source);
    var peer = null;
    if (sourceKey !== "") {
      peer = _budgetReading(await budget.peer.check(_pairKey(parsed.address, sourceKey)));
    }

    return {
      address: parsed.address,
      // The key the counter is kept under rather than what was asked
      // about, so a surface naming the machine it answered for names the
      // one this server chose and never the bytes it was handed.
      source:  sourceKey === "" ? null : sourceKey,
      mailbox: _budgetReading(await budget.mailbox.check(parsed.address)),
      peer:    peer,
    };
  }

  // Spend the same Argon2id work a real check would, so a miss and a
  // wrong password are indistinguishable from the outside.
  async function _burnVerification(password) {
    if (absentHash === null) {
      absentHash = await b.auth.password.hash(b.crypto.generateToken(32));
    }
    await b.auth.password.verify(absentHash, password.length === 0 ? "x" : password);
  }

  /**
   * @primitive blamepost.store.accounts.setPassword
   * @signature blamepost.store.accounts.setPassword(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9106
   * @related   blamepost.store.accounts.authenticate
   *
   * Replace an account's password. The new one goes through the same
   * policy check creation uses, so a reset cannot install something
   * weaker than sign up would have accepted. Records when it changed,
   * which is what a rotation requirement is measured against.
   *
   * @opts
   *   id:       string,   // required, the account id
   *   password: string,   // required, the new password
   *
   * @example
   *   await store.accounts.setPassword({ id: account.id, password: "a longer passphrase here" });
   */
  async function setPassword(opts) {
    _requireOpts(opts, "setPassword");
    var row = _requireRow(opts.id);
    if (_statusOf(row) === "archived") {
      throw err("store/account-archived",
        "account " + row._id + " is archived. Reinstate it before changing its password.");
    }
    if (_statusOf(row) === "erasing") {
      throw err("store/account-erasing",
        "account " + row._id + " is part-way through an erasure: its mail has already been " +
        "destroyed and its row is being kept only to answer for what a preservation order " +
        "or the retention floor held back. A credential on it would open a mailbox that no " +
        "longer holds what its owner had.");
    }
    var passwordHash = await _hashPassword(opts.password, row.address, "password");
    var now = Date.now();

    // Read the row again inside the write. Hashing is the longest gap in
    // this layer, and an account erased across it would otherwise take
    // an update that changes nothing while this call returns as though
    // the password had been replaced.
    var updated = b.db.transaction(function () {
      _requireRow(row._id);
      tables.updateRow(tables.ACCOUNTS, row._id, {
        passwordHash:      passwordHash,
        passwordChangedAt: now,
        updatedAt:         now,
      });
      return _rowById(row._id);
    });

    await auditActor.record({
      action:   "account.password_changed",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "account", id: row._id },
      metadata: { address: row.address },
    });
    return _present(updated);
  }

  /**
   * @primitive blamepost.store.accounts.suspend
   * @signature blamepost.store.accounts.suspend(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: mailbox identity above the message store)
   * @related   blamepost.store.accounts.reinstate, blamepost.store.accounts.delete
   *
   * Stop an account authenticating and stop delivery to it, keeping
   * everything it holds. This is the answer to a compromised mailbox or
   * an abuse report: reversible, recorded, and read from one place, so
   * no listener holds an older answer than another.
   *
   * Two halves of it reach different distances, and an operator
   * containing a credential has to know which. Delivery and
   * authentication are decided per message and per credential, so both
   * stop at once: a message already on the wire when this lands is not
   * filed, and no listener admits the password again on any protocol.
   *
   * A mail session that is ALREADY open is the half this does not reach.
   * The listeners read the status when they admit the credential and not
   * again, so a client that authenticated a minute ago keeps the session
   * it holds until it disconnects. The browser surface reads the row on
   * every request instead, and drops the session on the next one. So
   * containing a client that is already connected means suspending the
   * account and closing its connection, and taking the operator
   * interface away is the verb that does reach an open session.
   *
   * @opts
   *   id:     string,   // required, the account id
   *   reason: string,   // required, recorded on the row and in the audit trail
   *
   * @example
   *   await store.accounts.suspend({ id: account.id, reason: "credential reuse reported" });
   */
  async function suspend(opts) {
    _requireOpts(opts, "suspend");
    var row = _requireRow(opts.id);
    if (typeof opts.reason !== "string" || opts.reason.trim().length === 0) {
      throw err("store/bad-argument", "accounts.suspend needs a reason.");
    }
    if (_statusOf(row) === "archived") {
      throw err("store/account-archived",
        "account " + row._id + " is archived, which already refuses mail and sign in.");
    }
    if (_statusOf(row) === "erasing") {
      throw err("store/account-erasing",
        "account " + row._id + " is part-way through an erasure, which already refuses mail " +
        "and sign in. Finish the erasure rather than suspending it.");
    }
    var now = Date.now();
    tables.updateRow(tables.ACCOUNTS, row._id, {
      status:       "suspended",
      statusReason: opts.reason.trim(),
      updatedAt:    now,
    });
    await auditActor.record({
      action:   "account.suspended",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   opts.reason.trim(),
      resource: { kind: "account", id: row._id },
      metadata: { address: row.address },
    });
    return _present(_rowById(row._id));
  }

  /**
   * @primitive blamepost.store.accounts.reinstate
   * @signature blamepost.store.accounts.reinstate(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: mailbox identity above the message store)
   * @related   blamepost.store.accounts.suspend
   *
   * Return a suspended or archived account to service, clearing the
   * recorded reason. Archiving is reversible on purpose: an account
   * deleted by mistake is a support call, not a restore from backup.
   *
   * An account part-way through an erasure is refused rather than
   * returned. Its mail has already been destroyed and cannot come back,
   * so putting it back in service would hand its owner a working mailbox
   * that no longer holds what they had, and hand this server an address
   * that authenticates and takes delivery while an erasure against it is
   * still outstanding.
   *
   * @opts
   *   id: string,   // required, the account id
   *
   * @example
   *   await store.accounts.reinstate({ id: account.id });
   */
  async function reinstate(opts) {
    _requireOpts(opts, "reinstate");
    var row = _requireRow(opts.id);
    if (_statusOf(row) === "erasing" || await _erasureOutstanding(row._id)) {
      throw _erasingRefusal(row, "reinstate");
    }
    if (_statusOf(row) === "active") return _present(row);
    var now = Date.now();
    // Read the row again inside the write. Reading the trail is the
    // longest gap in this verb, and an erasure landing across it would
    // otherwise take an update decided on the row as it stood before the
    // question was asked, which is the one update that must never run:
    // it puts an account whose mail has just been destroyed back into
    // service.
    var restored = b.db.transaction(function () {
      var fresh = _requireRow(row._id);
      if (_statusOf(fresh) === "erasing") throw _erasingRefusal(fresh, "reinstate");
      tables.updateRow(tables.ACCOUNTS, fresh._id, {
        status:       "active",
        statusReason: null,
        archivedAt:   null,
        updatedAt:    now,
      });
      return _rowById(fresh._id);
    });
    await auditActor.record({
      action:   "account.reinstated",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "account", id: row._id },
      metadata: { address: row.address, from: row.status },
    });
    return _present(restored);
  }

  /**
   * @primitive blamepost.store.accounts.setAdmin
   * @signature blamepost.store.accounts.setAdmin(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: mailbox identity above the message store)
   * @related   blamepost.store.accounts.create, blamepost.store.accounts.suspend
   *
   * Give an account the operator interface, or take it back. Both
   * directions need a reason and both are recorded, because this is the
   * column that decides who can read every mailbox owner's address, every
   * hosted domain, the outbound spool and somebody else's audit trail.
   *
   * Taking it back is the half that was missing, and its absence had a
   * cost. An administrator whose credential has been taken could only be
   * contained by suspending or archiving them, so answering a stolen
   * password meant stopping delivery to a mailbox whose owner had done
   * nothing wrong, and the same was true of an operator who simply moved
   * on. Revocation separates the two: the role goes, the mailbox stays.
   *
   * It reaches an open session as well as the next sign in, because
   * every request reads this column off the row rather than off the
   * session record. Containment that waits for a session to expire is
   * not containment.
   *
   * Granting is refused for a mailbox that is out of service, whichever
   * way it left. None of those accounts can present a credential, so the
   * role is inert the day it is written and still reads as an
   * administrator on every listing that shows one. Each of the states is
   * also one the mailbox can come back from, or is meant to be: a role
   * granted while the mailbox was held returns with it, and nobody
   * decided that. The refusal asks about the state rather than listing
   * the states, so a status added later is refused rather than admitted
   * by an omission.
   *
   * A suspended mailbox is the sharpest of them, not the exception. It
   * is the reversible hold an operator applies to an account they have
   * reason to distrust, most often a credential in somebody else's
   * hands, and the grant would take effect the moment the hold is
   * lifted.
   *
   * Revoking stays open in every state, and has to: it is the
   * containment this verb exists for, and refusing it would strand the
   * role on exactly the accounts nothing else can reach to take it off.
   *
   * Nothing here measures what the change would leave behind. A server
   * whose last administrator gives up the role has a console nobody can
   * reach, and that IS a refusal, but it belongs to the surface that
   * offers the button: refusing it here would reach the command line
   * too, and the command line is the way back once the console is gone.
   * The browser console measures it before calling this.
   *
   * @opts
   *   id:      string,    // required, the account id
   *   isAdmin: boolean,   // required, true grants the console, false takes it back
   *   reason:  string,    // required, recorded on the row and in the audit trail
   *
   * @example
   *   await store.accounts.setAdmin({
   *     id: account.id, isAdmin: false, reason: "the rota cover has ended",
   *   });
   */
  async function setAdmin(opts) {
    _requireOpts(opts, "setAdmin");
    var row = _requireRow(opts.id);
    if (typeof opts.isAdmin !== "boolean") {
      throw err("store/bad-argument",
        "accounts.setAdmin needs opts.isAdmin as a boolean: true grants the operator " +
        "interface, false takes it back. There is no third answer, and a missing one is " +
        "not a request to leave the role alone.");
    }
    if (typeof opts.reason !== "string" || opts.reason.trim().length === 0) {
      throw err("store/bad-argument",
        "accounts.setAdmin needs a reason, whether it grants the operator interface or " +
        "takes it back. Both directions are read back during an incident review.");
    }
    var reason = opts.reason.trim();
    var granting = opts.isAdmin === true;
    // A mailbox that is out of service can have the role taken away and
    // cannot be given it. Only the grant is gated, and the asymmetry is
    // the point: revocation is the containment this verb exists for, and
    // refusing it here would strand the role on exactly the accounts
    // nothing else can reach to take it off, since an archived account
    // cannot be suspended and one part way through an erasure cannot be
    // suspended or reinstated either.
    //
    // The question asked is whether the mailbox is in service, not which
    // of the ways out of service it took. None of them can present a
    // credential, so a grant on one is inert the day it is written and
    // visible for as long as it stands: an operator reading who
    // administers this server finds an account that cannot sign in, and
    // has to work out whether that is a mistake or a containment
    // somebody started and did not finish. And each of them either comes
    // back or is meant to, so the role comes back with the mailbox and
    // nobody decided that.
    //
    // Written as a list of states this was two of the three, and the
    // member it left out was the one where a grant is least defensible:
    // suspension is the hold an operator applies to a mailbox whose
    // credential may be in somebody else's hands, and it is lifted on
    // purpose, so the grant would land the moment the account is trusted
    // again. A category asked about by name cannot lose a member that
    // way, and a status added later is refused here rather than admitted
    // by an omission.
    //
    // The sentence is per state because each leaves the operator a
    // different next step, and the fallback is what answers for a status
    // that arrives without one rather than letting it through.
    var roleStatus = _statusOf(row);
    if (granting && roleStatus !== "active") {
      throw err("store/account-" + roleStatus,
        "account " + row._id + " is " + roleStatus + ", so it authenticates nowhere and " +
        "the operator interface it would be given is one it cannot reach. " +
        (roleStatus === "suspended"
          ? "A suspension is lifted rather than left, so the role would be waiting the " +
            "moment the mailbox is back in service. Reinstate it first if the role is " +
            "meant to be there."
          : roleStatus === "archived"
            ? "Archiving is reversible, so the role would come back with the mailbox. " +
              "Reinstate it first if the role is meant to be there."
            : roleStatus === "erasing"
              ? "Its mail is already destroyed and it cannot be returned to service, so " +
                "the row is kept only to answer for what a preservation order or the " +
                "retention floor held back. Nothing it could administer is reachable " +
                "through it."
              : "Return it to service first if the role is meant to be there."));
    }
    // An account that already holds what is being asked for is answered
    // rather than refused, and no row is written. A second grant changes
    // nothing, so a row saying the role was granted would put an event on
    // the chain that did not happen.
    if ((row.isAdmin === 1) === granting) return _present(row);

    tables.updateRow(tables.ACCOUNTS, row._id, {
      isAdmin:   granting ? 1 : 0,
      updatedAt: Date.now(),
    });
    await auditActor.record({
      action:   granting ? "account.role_granted" : "account.role_revoked",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "account", id: row._id },
      metadata: { address: row.address, domain: row.domain },
    });
    return _present(_rowById(row._id));
  }

  /**
   * @primitive blamepost.store.accounts.delete
   * @signature blamepost.store.accounts.delete(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: archive by default, erase only when asked)
   * @related   blamepost.store.accounts.reinstate, blamepost.store.accounts.suspend
   *
   * Archive an account, or erase it outright when asked in as many
   * words. Archiving is the default because a deletion an operator
   * regrets an hour later is common and an erasure nothing can undo is
   * permanent. Both forms need a reason, and both are recorded.
   *
   * Erasure sets `destroy: true` and reaches three things: the account
   * row, the aliases pointing at the address, and everything the account
   * holds in its mailboxes. The last of those is the one that decides
   * whether the word means anything. A message body is sealed under the
   * volume's key rather than under anything the row erasure destroys, so
   * a body left behind opens exactly as it did before, here and on every
   * backup taken afterwards, and nothing would ever remove it: the
   * release is reference counted and the reference is the message row
   * that stayed.
   *
   * An erasure here is a crypto-erase: the sealed columns are nulled and
   * the index pages that held them are rebuilt, so nothing it destroys
   * can be read back from the database file, from a backup taken
   * afterwards, or at all.
   *
   * **The account row goes LAST, and only once nothing still names it.**
   * The delete path refuses per message, which is the point rather than
   * a limit on it, so an erasure regularly finishes with mail still on
   * the volume: a court's preservation order or the regulated retention
   * window kept it, and GDPR Article 17(3)(e) is the exception the
   * operator answers the request with. That mail needs an owner. Every
   * surface that could produce it resolves the account first, whether it
   * is producing the record for the court that ordered it kept, for a
   * regulator, or for the operator running this verb a second time, so
   * an identity erased ahead of its mail leaves records nothing can
   * attribute, list or finish erasing.
   * So the sweep runs first and the identity is erased only when nothing
   * still names it, judged by reading the rows back rather than by what
   * the delete path answered. Everything the mailbox layer keeps counts,
   * not the mailboxes alone: a filter script a governance gate held back
   * and an annotation storage refused each carry this account's id, and
   * each is as unreachable as a kept message once the identity is gone.
   *
   * When something is still naming it, the row stays and the account
   * moves to `erasing`: it authenticates no better than an archived one
   * and takes no delivery, it cannot be reinstated, and it is listed by
   * default so the outstanding job is visible. Running the same call
   * again sweeps what is left, and the row goes on the run that finally
   * reaches it. `outcome` is `partially-erased` for that state and
   * `destroyed` when the identity itself went.
   *
   * Once the mail erasure has begun, nothing that will not go is raised;
   * it is reported, because the mail is already destroyed and a throw
   * would leave the caller unable to tell that the erasure it asked for
   * had happened. Those reports come back in two lists per subject,
   * because they need opposite responses. `aliasesPreserved`,
   * `mailPreserved` and `recordsPreserved` are held back deliberately: a
   * preservation order, the regulated retention window, or a gate wanting
   * a second approver. Nothing is broken and the erasure is partial on
   * purpose. `aliasesFailed`, `mailFailed` and `recordsFailed` are the
   * ones that could not be erased for any other reason, which leaves a
   * forwarding row pointing at a mailbox nobody holds, or somebody's data
   * on a volume that was asked to lose it. The audit row counts each
   * separately, and it records the destruction as a failure only when
   * something faulted: anything held back on purpose is the system
   * working and says so.
   *
   * The three subjects are three lists because they are three different
   * things, and mail is the one a count is most often taken of.
   * `mailPreserved` and `mailFailed` hold MESSAGES and nothing else, each
   * carrying the identifier the delete path decided about.
   * `recordsPreserved` and `recordsFailed` hold what else the account had
   * on the mailbox layer: the mailbox rows something is still bound to,
   * its filter scripts and its annotations. An operator answering an
   * account holder, a preservation order or an Article 17 request counts
   * the first pair, so an annotation folded into it would overstate how
   * much of that person's mail survived, and the erasure leaves nothing
   * behind to correct the figure from.
   *
   * `identityRefused` is the same answer about the last step itself, and
   * it is empty on every run that settled the account row one way or the
   * other. The step is two writes and either can be refused: the erase,
   * which a gate can want a second approver for, and the write that marks
   * the row as erasing, which a volume can refuse outright. Both are
   * reported rather than raised, for the reason above, and the second is
   * the one to act on first, because a row that could not be marked is an
   * account still in service whose mail has gone.
   *
   * A preservation order does not reach this call. An order is placed on
   * a message and covers the message it names, so it stops that message
   * being destroyed and does not extend to the account's filter scripts,
   * its annotations, its aliases or the account row. Where a matter
   * requires the fact that an address existed, hold the erasure until it
   * closes rather than expecting an order over the mail to keep it.
   *
   * The mail erasure is the mailbox adapter's own verb rather than a
   * second delete written here, so the retention floor and the
   * preservation-order gate run exactly as they run for IMAP EXPUNGE, a
   * POP3 commit and a JMAP destroy.
   *
   * @opts
   *   id:      string,    // required, the account id
   *   reason:  string,    // required, recorded in the audit trail
   *   destroy: boolean,   // erase the row instead of archiving it
   *
   * @example
   *   await store.accounts.delete({ id: account.id, reason: "owner left" });
   */
  async function remove(opts) {
    _requireOpts(opts, "delete");
    var row = _requireRow(opts.id);
    if (typeof opts.reason !== "string" || opts.reason.trim().length === 0) {
      throw err("store/bad-argument",
        "accounts.delete needs a reason, whether it archives the account or erases it.");
    }
    var reason = opts.reason.trim();

    // Archiving an account whose erasure could not finish is refused,
    // and the refusal is about what archiving IS rather than about
    // tidiness. Erasing is the one state nothing returns from: the mail
    // is destroyed, reinstatement is refused in as many words, and the
    // row is kept only to answer for what a preservation order or the
    // retention floor held back. Archived is reinstatable. So archiving
    // the row moves it out of the terminal state into a reversible one,
    // and the next press of the button every listing offers hands its
    // owner a working mailbox that no longer holds what they had, while
    // the erasure this server still owes reads as closed.
    //
    // Every other verb here already refuses it, which is what makes the
    // omission a gap rather than a decision: suspending is refused,
    // changing the password is refused, reinstating is refused, and the
    // role cannot be granted. This was the one way back.
    //
    // Erasing it again is a different request and is not caught here: it
    // is how the outstanding job is finished, and it is what the row
    // being kept exists to let an operator run.
    if (opts.destroy !== true &&
        (_statusOf(row) === "erasing" || await _erasureOutstanding(row._id))) {
      throw _erasingRefusal(row, "archive");
    }

    if (opts.destroy !== true) {
      var now = Date.now();
      // The row read again inside the write, for the reason reinstate
      // re-reads: the trail read above is the longest gap in this branch
      // and an erasure landing across it would otherwise be archived out
      // of the one state nothing returns from.
      b.db.transaction(function () {
        var fresh = _requireRow(row._id);
        if (_statusOf(fresh) === "erasing") throw _erasingRefusal(fresh, "archive");
        tables.updateRow(tables.ACCOUNTS, fresh._id, {
          status:       "archived",
          statusReason: reason,
          archivedAt:   now,
          updatedAt:    now,
        });
      });
      await auditActor.record({
        action:   "account.archived",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   reason,
        resource: { kind: "account", id: row._id },
        metadata: { address: row.address },
      });
      return { id: row._id, address: row.address, outcome: "archived" };
    }

    // The row marked as holding an outstanding erasure BEFORE anything
    // is destroyed, rather than only after.
    //
    // The mark is what every verb that holds such an account out of
    // service reads, and made only at the end it is a write attempted at
    // the one moment its failure cannot be acted on: the mail is already
    // gone, so a refusal leaves an account in service with nothing on
    // the row saying why its mailbox is empty. Attempted here as well,
    // the ordinary case is marked before the first message goes, and a
    // run that stops anywhere in the middle stops on a row that already
    // says an erasure is outstanding.
    //
    // It does not refuse the call. A volume that will take no write to
    // this row at all is a volume the erasure still has to run over,
    // because the mail is the part of the request that matters most and
    // the identity step reports per write what it could not do. What
    // covers that row instead is the trail: the chain entry this verb
    // files at the end is read by the two verbs that could otherwise
    // return the account to service, and neither of them depends on a
    // write to the row landing.
    //
    // The status transition rides along and is not what is relied on: a
    // records-retention posture puts a trigger on that column and
    // refuses the transition itself, so the marker is attempted again on
    // its own, which is a change set that trigger is not about.
    //
    // Both attempts read the row again inside the write, because this
    // body has already suspended by the time either runs and a row
    // erased across that gap would otherwise be written back.
    var startedAt = Date.now();
    try {
      b.db.transaction(function () {
        var opening = _requireRow(row._id);
        tables.updateRow(tables.ACCOUNTS, opening._id, {
          status:        "erasing",
          statusReason:  "erasure in progress: " + reason,
          erasureHeldAt: startedAt,
          updatedAt:     startedAt,
        });
      });
    } catch (_statusRefused) {
      try {
        b.db.transaction(function () {
          var opening = _requireRow(row._id);
          tables.updateRow(tables.ACCOUNTS, opening._id, {
            erasureHeldAt: startedAt,
            updatedAt:     startedAt,
          });
        });
      } catch (_markerRefused) {
        // Neither spelling landed. The identity step at the end attempts
        // both again and REPORTS what it could not write, which is where
        // an operator reads it, so nothing is recorded twice here.
      }
    }

    // The aliases to follow the mailbox, read before anything is
    // destroyed, because the column that identifies them is the address
    // on the row about to go.
    var aliasRows = b.db.from(tables.ALIASES).where({ destinationMailbox: row.address }).all();

    // The adapter that owns the mail, resolved before anything is
    // destroyed. A layer assembled without it would otherwise erase the
    // account row and discover on the next line that it cannot reach the
    // mailboxes, which is the half-finished erasure this whole path
    // exists to avoid.
    var mail = _mailbox();

    // Then the mail, before the identity that owns it. The framework's
    // erase is one row in one table and cascades nothing, so without this
    // the mailboxes, the message rows, the message store's rows and the
    // sealed bodies under `blobs/` all survive an erasure that reported
    // success. The bodies are the part that makes it a false report: they
    // are sealed under the volume's key rather than under anything the
    // row erasure destroys, so one left behind opens exactly as it did
    // before, here and on every backup taken afterwards, and nothing
    // would ever release it because the release counts the message rows
    // that stayed.
    //
    // It runs FIRST because it can legitimately leave mail behind. The
    // delete path refuses per message, so a preservation order or the
    // retention floor can keep a record the erasure was asked to
    // destroy, and every surface that could later produce that record
    // resolves its account first. An identity erased ahead of the sweep
    // is an identity that is already gone by the time the floor speaks.
    //
    // The adapter owns that work rather than this file, for the same
    // reason every wire protocol routes its deletes there: a second
    // implementation of a delete would be a second answer to what a
    // delete refuses.
    //
    // The actor it drives the delete path with is the account's own. An
    // erasure destroys that account's mail and nobody else's, so the
    // narrowest identity that can reach exactly the mailboxes about to
    // go is the right one, and it carries the mailbox owner's role and
    // nothing above it. Who ASKED is on the audit row, which reads the
    // scope the command or the request opened.
    var swept = await mail.eraseAccountMail({
      id:      row._id,
      address: row.address,
      domain:  row.domain,
      roles:   ["account"],
    }, row._id, { reason: reason });

    // Split by KIND first and by verdict second.
    //
    // The verdict split is the same one the aliases below are read by, and
    // for the same reason. A record a preservation order or the retention
    // floor is keeping is the system working: the erasure is partial, the
    // operator can name the record being kept and the rule keeping it, and
    // GDPR Article 17(3)(e) is the exception they are answering with. One
    // that could not be erased for any other reason is somebody's data on
    // a volume that was asked to lose it, and the two need opposite
    // responses. Which is which is decided by the adapter and carried on
    // the entry, so this is not a second copy of that list.
    //
    // The kind split is what stops a number that says mail from being a
    // number about something else. The adapter answers with one list
    // holding four kinds of record, and the person reading these counts is
    // answering an account holder, a preservation order or an Article 17
    // request with them. A filter script counted as mail overstates how
    // much of somebody's mail survived the erasure, which is the one
    // direction that cannot be corrected later: the mail is destroyed and
    // there is nothing left to re-read.
    var messageRefusals = swept.refused.filter(_isMessageRecord);
    var recordRefusals  = swept.refused.filter(function (entry) {
      return !_isMessageRecord(entry);
    });
    var mailPreserved    = messageRefusals.filter(_wasPreserved);
    var mailFailed       = messageRefusals.filter(_notPreserved);
    var recordsPreserved = recordRefusals.filter(_wasPreserved);
    var recordsFailed    = recordRefusals.filter(_notPreserved);

    // From here nothing yields, so the window in which an alias points at
    // a mailbox whose mail is already gone is not one any other call can
    // observe.
    var aliasesErased     = 0;
    var aliasesPreserved  = [];
    var aliasesFailed     = [];
    for (var i = 0; i < aliasRows.length; i += 1) {
      try {
        b.db.eraseHard(tables.ALIASES, aliasRows[i]._id, {
          reason:    "destination account erased: " + reason,
          subjectId: aliasRows[i].address,
        });
        aliasesErased += 1;
      } catch (e) {
        // Not a swallow, and not one bucket either. Raising here would
        // report the whole call as failed for a mailbox that is already
        // erased, and send an operator looking for a row that is not
        // there. But the two things that stop an alias erasure need
        // opposite responses from the person reading the result, so they
        // are separated rather than counted together.
        var code = (e && e.code) || "unknown";
        if (errors.isPreservationRefusal(code)) {
          aliasesPreserved.push({ address: aliasRows[i].address, reason: code });
        } else {
          aliasesFailed.push({
            address: aliasRows[i].address,
            reason:  code,
            detail:  (e && e.message) || String(e),
          });
        }
      }
    }

    // And last the identity, but only if nothing still names it. What
    // decides that is read back off the tables rather than inferred from
    // the two answers above, which is the same test the adapter applies
    // to a mailbox row: the delete path answers about the records it was
    // handed, and the question here is whether anything is still bound
    // to this account.
    //
    // Every table the mailbox layer files a row of the account's under is
    // counted, not the mailboxes alone. That layer keeps a mailbox row a
    // message stayed in, a filter script a gate held back and an
    // annotation storage refused, and each of those rows carries this
    // account's id in a column. A row that stayed and a row that can be
    // reached are different claims, and only the second is worth anything
    // to whoever has to produce or finish erasing it: every verb that
    // could reach one resolves the account first, so an identity erased
    // over a script or an annotation leaves a row naming an id nothing
    // answers to, on the volume and in every backup taken afterwards,
    // with no verb anywhere that can reach it again.
    var mailboxRowsLeft =
      b.db.from(mailboxTables.FOLDERS).where({ account: row._id }).count() +
      b.db.from(mailboxTables.SCRIPTS).where({ account: row._id }).count() +
      b.db.from(mailboxTables.METADATA).where({ account: row._id }).count();
    var aliasesLeft   = b.db.from(tables.ALIASES)
      .where({ destinationMailbox: row.address }).count();

    // The identity step is two writes, and by the time either runs the
    // mail is destroyed. So neither may raise: a refusal allowed to leave
    // here hands the caller an exception in place of the report, never
    // reaches the audit row below, and leaves nothing anywhere saying the
    // mail was ever on the volume. Both are answered for the way the
    // aliases above are, and by the same rule, because the erase refuses
    // an account row for the reasons it refuses any other row.
    //
    // `subjectId` names the data subject on the chained row the erase
    // files, and it is what an auditor reads that row back by. It is also
    // the subject the framework's own preservation gate consults, which
    // no order in this server registers: a hold is placed on a message
    // and covers the message it names, so the address is never a held
    // subject and this is not a gate that stands in for one.
    var identityRefused = [];
    var identityErased  = false;
    var result = { rowsDeleted: 0 };
    if (mailboxRowsLeft === 0 && aliasesLeft === 0) {
      try {
        result = b.db.eraseHard(tables.ACCOUNTS, row._id, {
          reason:    reason,
          subjectId: row.address,
        });
        identityErased = true;
      } catch (e) {
        identityRefused.push(_identityRefusal(row.address, "erased", e));
      }
    }
    if (!identityErased) {
      // The identity stays, holding nothing but the answer to whose
      // records those are. It authenticates no better than an archived
      // account and takes no delivery, it refuses reinstatement, and it
      // is listed by default, because an erasure that could not finish
      // reading as one that did is the failure this whole ordering
      // exists to stop producing.
      //
      // On an ordinary run the row is already marked, because the write
      // in front of the destruction put it out of service before the
      // first message went. What is left to write is the reason and the
      // date, so a refusal here costs the operator the sentence
      // explaining why the row is still there and costs the account
      // holder nothing.
      //
      // That write is attempted rather than required, so a run can reach
      // here with the row carrying no mark at all: a volume that will
      // take no write to this row is still a volume the erasure runs
      // over, because the mail is the part of the request that matters
      // most. Both spellings are attempted again below, and what neither
      // of them could write is reported as `marked as erasing`. That is
      // the entry an operator acts on first, because the row it names is
      // an account still in service whose mail has gone. Reporting it is
      // what the caller can act on: by the time this runs the mail is
      // destroyed, and an exception handed back in place of the report
      // would leave nothing anywhere saying the mail was on the volume.
      var heldNow = Date.now();
      var marked = false;
      var markError = null;
      try {
        tables.updateRow(tables.ACCOUNTS, row._id, {
          status:        "erasing",
          statusReason:  "erasure held back: " + reason,
          archivedAt:    heldNow,
          erasureHeldAt: heldNow,
          updatedAt:     heldNow,
        });
        marked = true;
      } catch (e2) {
        markError = e2;
      }
      if (!marked) {
        // The same fact, written again without the status transition in
        // the change set. A volume refuses this write for reasons that
        // belong to the columns being written rather than to the row: a
        // records-retention posture puts a trigger on the status column
        // and refuses the transition itself, and a change set that does
        // not name that column is not the write it refuses. So the
        // second attempt asks for the least it can and still leave the
        // account out of service, because every gate reads this marker
        // beside the status and treats either one as the answer.
        try {
          tables.updateRow(tables.ACCOUNTS, row._id, {
            erasureHeldAt: heldNow,
            updatedAt:     heldNow,
          });
          marked = true;
        } catch (e3) {
          markError = e3;
        }
      }
      if (!marked) {
        identityRefused.push(_identityRefusal(row.address, "marked as erasing", markError));
      }
    }
    var outcome = identityErased ? "destroyed" : "partially-erased";
    // The half of the identity step that is a fault rather than something
    // keeping the row on purpose, split here so the trail and the caller
    // read the same rule the aliases and the mail are read by.
    var identityFailed = identityRefused.filter(_notPreserved);

    // Recorded now that there is something settled to record. The address
    // and the reason are held in locals across the erase, so writing the
    // row afterwards carries exactly what writing it first would have,
    // and it carries the counts as well. The erase is not left unrecorded
    // if this write fails either: the framework files its own chained row
    // for every eraseHard, carrying the same reason and subject.
    await auditActor.record({
      // Two names for two different things that happened, rather than one
      // name and a field a reader has to open to find out which. A row
      // saying an account was destroyed when its identity is still on the
      // table is the trail answering a later question wrongly, and the
      // later question is whether the erasure ever finished.
      action:   identityErased ? "account.destroyed" : "account.erasure_held",
      // An alias or a message something preserves is the system working,
      // so it leaves a clean record with a count beside it. One that
      // faulted is a mailbox that is gone and a forwarding row or a
      // message still sitting behind it, and recording that as a clean
      // success is the shape this call already had to be fixed for once.
      // The identity step answers the same way: a second approver wanted
      // for the account row is the system working, and a volume that
      // would not take the write is not.
      outcome:  (aliasesFailed.length > 0 || mailFailed.length > 0 ||
                 recordsFailed.length > 0 ||
                 identityFailed.length > 0) ? "failure" : "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "account", id: row._id },
      metadata: {
        address:          row.address,
        domain:           row.domain,
        rowsErased:       result.rowsDeleted,
        aliasesErased:    aliasesErased,
        aliasesPreserved: aliasesPreserved.length,
        aliasesFailed:    aliasesFailed.length,
        mailErased:       swept.destroyed.length,
        mailPreserved:    mailPreserved.length,
        mailFailed:       mailFailed.length,
        // The account's other material, counted apart from its mail. The
        // question this row is read back with is how much of one
        // subject's mail is still on the volume, and a filter script or
        // an annotation added to that number answers it wrongly. They are
        // still counted, because each is a record the subject asked to
        // have destroyed and each is still there.
        recordsPreserved: recordsPreserved.length,
        recordsFailed:    recordsFailed.length,
        mailboxesErased:  swept.mailboxesErased,
        mailboxesKept:    swept.mailboxesKept,
        identityRefused:  identityRefused.length,
        identityFailed:   identityFailed.length,
      },
    });

    return {
      id:               row._id,
      address:          row.address,
      outcome:          outcome,
      rowsErased:       result.rowsDeleted,
      aliasesErased:    aliasesErased,
      aliasesPreserved: aliasesPreserved,
      aliasesFailed:    aliasesFailed,
      mailErased:       swept.destroyed.length,
      mailPreserved:    mailPreserved,
      mailFailed:       mailFailed,
      // The filter scripts, the annotations and the mailbox rows that
      // stayed, in the same two shapes and read by the same rule. They
      // are listed apart from the mail because a caller counting an
      // account holder's surviving messages has to be able to count
      // messages, and named individually because the operator has to know
      // which row to go and release.
      recordsPreserved: recordsPreserved,
      recordsFailed:    recordsFailed,
      mailboxesErased:  swept.mailboxesErased,
      mailboxesKept:    swept.mailboxesKept,
      // Empty on every run that reached the identity and settled it,
      // whether it erased the row or kept it because something else still
      // names it. It carries an entry only when a write about the account
      // row was itself refused, which is a different thing from the row
      // being kept on purpose and needs saying separately.
      identityRefused:  identityRefused,
    };
  }

  return {
    create:       createAccount,
    get:          get,
    list:         list,
    authenticate: authenticate,
    unlock:       unlock,
    lockoutState: lockoutState,
    setPassword:  setPassword,
    setAdmin:     setAdmin,
    suspend:      suspend,
    reinstate:    reinstate,
    "delete":     remove,
  };
}

module.exports = { create: create };
