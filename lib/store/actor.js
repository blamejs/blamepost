// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.actor
 * @nav    Storage and audit
 * @title  Audit attribution
 * @order  40
 *
 * Who acted, for the rows the audit chain records.
 *
 * The chain answers what happened. An incident asks who, and the
 * columns that hold the answer are filled from the actor an event
 * carries and null-filled from nothing at all, so an event that names
 * no actor produces a row proving an account was suspended and proving
 * nothing about who suspended it. That is a log rather than an audit
 * trail, and no amount of hash linking closes the difference.
 *
 * Three surfaces reach the identity layer and each holds a different
 * kind of principal:
 *
 *   - The browser and administration surface has an authenticated
 *     session, so the principal is the account behind it, with the peer
 *     address and the agent string beside it.
 *   - The command line has an invoking operator, and a shell user is
 *     not an account. What is true of them is the operating-system
 *     account and the host the process ran as, so that is what the row
 *     records, marked as a command-line operator. One column carries
 *     both kinds and an auditor filtering on it has to be able to tell
 *     them apart; an account id is a UUID and could never be mistaken
 *     for the mark, but the mark still says plainly which kind it is.
 *   - The mail listeners hold whichever of two things the connection
 *     established. A session that authenticated has an account or a
 *     sending credential and the address it arrived from, and both go on
 *     the row. A connection that presented nothing has the address
 *     alone, and so does a credential that was refused: the name a
 *     refused attempt claimed is a name whoever is guessing chose, and
 *     writing it into the column that answers who acted would let them
 *     choose what an auditor reads back. The identity is therefore
 *     absent on those rows by decision rather than by omission, and the
 *     address is still a column rather than a note in the metadata
 *     because what else came from one address is the question asked
 *     after a break-in and `b.audit.query` filters on the columns.
 *
 * The identity is held for the surrounding work rather than passed down
 * through every call, because the callers are not all in one place. A
 * DKIM rotation driven from the console reaches the selector rows
 * through the mail layer, which knows nothing of sessions, and a
 * threading scheme the mail layer has to cooperate with is one a new
 * caller can forget. What cannot be forgotten is a scope the entry
 * point opens, so the entry points open one and the emit sites read it.
 *
 * Validation posture: an actor is built and frozen where a scope is
 * established, and building it is an entry point, so a shape this
 * module did not build is refused there with a throw. That is the whole
 * point of the split. Reading the actor at an emit is a hot-path read
 * inside a drop-silent sink, and it can never throw: it hands back a
 * frozen object whose four fields are always present, and the reading
 * of a process or a request that could not be resolved is recorded as
 * an absence rather than raised.
 *
 * The emit itself is here for the same reason the identity is. A verb
 * changes something and then records it, and the record can fail on its
 * own once the change is already on disk; a sink's error escaping into
 * the verb tells the caller the change did not happen. So the write
 * lives in one place, drops what it cannot file, and lets every verb
 * report its own outcome. What is on the row and whether writing it can
 * break the operation are one question with one answer, and splitting
 * them across modules is how they drift apart.
 */

var nodeAsync = require("node:async_hooks");
var nodeOs    = require("node:os");

var pkg = require("../../package.json");
var b   = require("../vendor/blamejs");

var displayText = require("../text");

// The mark a command-line operator carries in the identity column, so a
// filter on that column can tell a shell user from an account.
var COMMAND_LINE_MARK = "cli:";

// What the row records as the thing the operator was driving. The
// binary's own name rather than the package's, because that is what an
// operator typed and what the row reads back as.
var COMMAND_LINE_AGENT = "blamepost";

// What a field is truncated to. The agent string and the peer address
// arrive from whoever connected, the identity column is sealed and
// every row carries all four, so an unbounded field is a peer choosing
// how large this server's audit rows are. The identity bound is set
// above the longest address RFC 5321 section 4.5.3.1 allows, so nothing
// legitimate reaches it.
var MAX_IDENTITY_CHARS   = 320;
var MAX_ADDRESS_CHARS    = 64;
var MAX_USER_AGENT_CHARS = 256;
var MAX_SESSION_CHARS    = 128;

// The brand an actor built here carries, so a scope can refuse one that
// was assembled somewhere else and the read below can promise its
// fields are there. It is not enumerable, so nothing that serializes or
// redacts the actor on its way to a row ever sees it.
var BUILT_HERE = Symbol("blamepost.store.actor");

// The reading of a process or a host that could not be resolved. A
// container with no passwd entry for its user id is ordinary, and a
// command that refused to run over it would be refusing to run for a
// reason that has nothing to do with what the operator asked for.
var UNRESOLVED = "unknown";

var _scope = new nodeAsync.AsyncLocalStorage();

// The command line's actor, resolved once for the process.
var commandLine = null;

// One field, bounded and free of anything a terminal would act on
// rather than print.
//
// Two of the four come off the wire, and a row is read in a terminal.
// Screening for control characters alone leaves the two codepoints a
// forged row is written with: an override reorders everything after it,
// and a zero-width character renders as nothing, and neither is a
// control character. So the field goes through the one screen the rest
// of this server reads stranger text with, which drops those as well and
// folds a tab into a space. The screen removes what it finds rather than
// cutting the field there, so the legitimate tail of a value survives.
function _field(value, limit) {
  if (typeof value !== "string") return null;
  var text = displayText.forDisplay(value).trim();
  if (text.length === 0) return null;
  if (text.length > limit) text = text.slice(0, limit);
  return text;
}

/**
 * @primitive blamepost.store.actor.build
 * @signature blamepost.store.actor.build(fields)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.forRequest, blamepost.store.actor.current
 *
 * One frozen actor, in the shape the audit chain reads. Every field is
 * optional and an absent one is recorded as an absence, because a
 * column answers with what is known and with nothing standing in for
 * what is not: a command run at a terminal has no peer address, and a
 * refused sign in has a peer and no identity anyone has verified.
 *
 * Fields are trimmed, bounded and cut at the first character a terminal
 * would act on rather than print, since two of them arrive from
 * whoever connected.
 *
 * @opts
 *   userId:    string,   // the principal, an account id or a marked operator
 *   ip:        string,   // the peer the action arrived from
 *   userAgent: string,   // what the principal was driving
 *   sessionId: string,   // the session or process the action belongs to
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   auditActor.build({ userId: account.id, ip: "203.0.113.4" }).userId;
 */
function build(fields) {
  var given = (typeof fields === "object" && fields !== null) ? fields : {};
  var actor = {
    userId:    _field(given.userId,    MAX_IDENTITY_CHARS),
    ip:        _field(given.ip,        MAX_ADDRESS_CHARS),
    userAgent: _field(given.userAgent, MAX_USER_AGENT_CHARS),
    sessionId: _field(given.sessionId, MAX_SESSION_CHARS),
  };
  Object.defineProperty(actor, BUILT_HERE, { value: true, enumerable: false });
  return Object.freeze(actor);
}

// Nobody established, and nothing pretending otherwise. It is what an
// emit reached outside any scope records, which is the truth about such
// an emit rather than a default standing in for one.
var UNATTRIBUTED = build({});

/**
 * @primitive blamepost.store.actor.forRequest
 * @signature blamepost.store.actor.forRequest(req)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.enterAs, blamepost.store.actor.current
 *
 * The actor behind one HTTP request. The account the request lifecycle
 * authenticated, the peer address it arrived from, and the agent string
 * it sent. A request carrying no session still yields an actor: the
 * identity is absent and the peer is not, and where a refusal came from
 * is the question a refusal is read for.
 *
 * The reading of the request itself is the framework's, so a peer
 * address behind a socket, a connection or a proxy-set property is
 * found the same way every other framework surface finds it.
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   b.audit.safeEmit({
 *     action:  "blamepost.jmap.websocket.refused",
 *     outcome: "denied",
 *     actor:   auditActor.forRequest(req),
 *   });
 */
function forRequest(req) {
  var context = b.requestHelpers.extractActorContext(req);
  return build({
    userId:    context.userId,
    ip:        context.ip,
    userAgent: context.userAgent,
    sessionId: context.sessionId,
  });
}

function _operatingSystemUser() {
  var info;
  try { info = nodeOs.userInfo(); }
  catch (_e) { return UNRESOLVED; }
  var name = _field(info && info.username, MAX_IDENTITY_CHARS);
  if (name !== null) return name;
  // A host that answers with a number and no name still answers. The
  // number is the account, and an operator can resolve it on the host.
  if (info && typeof info.uid === "number" && info.uid >= 0) return "uid" + info.uid;
  return UNRESOLVED;
}

function _operatingSystemHost() {
  var name;
  try { name = nodeOs.hostname(); }
  catch (_e) { return UNRESOLVED; }
  var host = _field(name, MAX_IDENTITY_CHARS);
  return host === null ? UNRESOLVED : host;
}

/**
 * @primitive blamepost.store.actor.forCommandLine
 * @signature blamepost.store.actor.forCommandLine()
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.runAs, blamepost.store.actor.current
 *
 * The actor behind a command an operator ran. A shell user is not an
 * account, so what the row records is what the process can establish
 * about itself: the operating-system account it runs as, the host it
 * runs on, the binary and its version, and the process id. The
 * identity carries a mark, so a filter on that column can tell an
 * operator at a terminal from an account that signed in.
 *
 * There is no peer address, and none is invented. A command run at a
 * terminal arrived from nowhere, and a value read out of the
 * environment of the shell that ran it would be a value that shell
 * chose.
 *
 * Resolved once for the process, and resolved defensively: a host with
 * no readable account for its user id records that it could not be
 * read rather than refusing to run the operator's command.
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   auditActor.forCommandLine().userId;
 *   // "cli:root@mail-01"
 */
function forCommandLine() {
  if (commandLine !== null) return commandLine;
  commandLine = build({
    userId:    COMMAND_LINE_MARK + _operatingSystemUser() + "@" + _operatingSystemHost(),
    userAgent: COMMAND_LINE_AGENT + "/" + pkg.version,
    sessionId: "pid:" + process.pid,
  });
  return commandLine;
}

function _requireBuiltHere(actor, verb) {
  if (!actor || actor[BUILT_HERE] !== true) {
    throw new TypeError("blamepost.store.actor." + verb + ": the actor has to be one this " +
      "module built, with blamepost.store.actor.build, forRequest or forCommandLine. The " +
      "shape is settled here so that reading it at an audit emit cannot fail, and an emit " +
      "runs inside a sink that drops what it cannot write.");
  }
  return actor;
}

/**
 * @primitive blamepost.store.actor.runAs
 * @signature blamepost.store.actor.runAs(actor, fn)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.forCommandLine, blamepost.store.actor.current
 *
 * Run `fn` with `actor` as the identity every audit emit inside it
 * records, and hand back whatever `fn` hands back, promise included.
 * The binding follows the work across every await, and it closes when
 * `fn` settles. This is the shape a command takes: one operator, one
 * command, one scope around it.
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   await auditActor.runAs(auditActor.forCommandLine(), function () {
 *     return run(command, flags, positionals);
 *   });
 */
function runAs(actor, fn) {
  _requireBuiltHere(actor, "runAs");
  if (typeof fn !== "function") {
    throw new TypeError("blamepost.store.actor.runAs(actor, fn) needs the work to run inside " +
      "the scope.");
  }
  return _scope.run({ actor: actor }, fn);
}

/**
 * @primitive blamepost.store.actor.enterAs
 * @signature blamepost.store.actor.enterAs(actor)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.forRequest, blamepost.store.actor.current
 *
 * Bind `actor` as the identity for the rest of the current work,
 * without a callback to nest it inside. This is the shape a request
 * takes: the router runs its middleware to completion and then runs
 * the route, so a scope that closed when the middleware returned would
 * close before the handler that needs it ran.
 *
 * Call it once per request, from inside that request's own work, which
 * is what keeps two requests in flight from reading each other's
 * operator.
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   router.use(function (req, res, next) {
 *     auditActor.enterAs(auditActor.forRequest(req));
 *     next();
 *   });
 */
function enterAs(actor) {
  _requireBuiltHere(actor, "enterAs");
  _scope.enterWith({ actor: actor });
  return actor;
}

/**
 * @primitive blamepost.store.actor.current
 * @signature blamepost.store.actor.current()
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one identity shape for every audit row)
 * @related   blamepost.store.actor.runAs, blamepost.store.actor.enterAs
 *
 * The identity the surrounding work established, or one recording that
 * nothing did. It never throws and never returns anything but a frozen
 * actor carrying all four fields, because every caller is an audit emit
 * and an audit emit runs where a throw would end the operation that
 * produced the event.
 *
 * @example
 *   var auditActor = require("./lib/store/actor");
 *   await auditActor.record({
 *     action:  "account.suspended",
 *     outcome: "success",
 *     actor:   auditActor.current(),
 *   });
 */
function current() {
  var held = _scope.getStore();
  return (held && held.actor) || UNATTRIBUTED;
}

/**
 * @primitive blamepost.store.actor.record
 * @signature blamepost.store.actor.record(event)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: writing the row never decides whether the operation happened)
 * @related   blamepost.store.actor.current, blamepost.store.actor.build
 *
 * Write one row for something the store has already done. Drop-silent by
 * design: a sink that cannot write never changes what the caller is
 * told.
 *
 * Every verb in this layer performs its change and then records it, and
 * those are two writes. The change is on disk by the time the second one
 * runs and no later write can take it back, so the only question a
 * failure leaves is what the caller hears. Letting the sink's error out
 * answers it wrongly in the one way that cannot be recovered from: the
 * caller is handed a refusal for an operation that succeeded, and
 * "the domain was not added" and "the domain was added and the row was
 * not written" arrive as the same error while needing opposite responses
 * from an operator.
 *
 * The damage is not confined to the verb that emits. A key mint writes
 * the sealed private half, then the selector row that points at it; a
 * throw between the two takes the mint's unwind branch, which erases the
 * key file it knows about and leaves the row it does not, and what is
 * left is an active selector naming a key that is not there. That is a
 * domain signing nothing and failing alignment on everything it sends,
 * caused by an audit sink being unavailable.
 *
 * Durability is a separate question from failure posture, and this keeps
 * the strict answer to it. The write is still `b.audit.record`, which
 * awaits the row to durability rather than buffering it, so a sink that
 * works has the row before the verb returns. What is given up is only
 * the sink's error, which no caller here could have acted on.
 *
 * The two ways an emit can be wrong in the source rather than in the
 * field, a namespace nothing registered and a row naming no actor, are
 * refused by the static gates instead, where a developer sees them and
 * an operator never has to.
 *
 * Nothing in the catch reads anything: an actor is built and frozen at
 * the scope, so the fields are settled long before here, and a handler
 * that inspected what it caught would be a second way for this to
 * throw.
 *
 * What it hands back is whether the row was written. Dropping the sink's
 * error is not the same as having nowhere to say the row is missing, and
 * the two callers differ: a store verb answers a wire protocol that has
 * no field for it and ignores this, while a command line has an operator
 * reading a terminal and can tell them the act stands and the trail has
 * no entry for it. Reporting it is the caller's decision because only the
 * caller knows whether anybody is listening; refusing on it is nobody's,
 * which is why the answer is a value rather than a throw.
 *
 * @opts
 *   action:   string,   // required, "namespace.verb", the namespace registered at boot
 *   outcome:  string,   // required, success, failure or denied
 *   actor:    object,   // who acted, from current(), forRequest() or build()
 *   reason:   string,   // the first-class column an auditor filters on
 *   resource: object,   // { kind, id }
 *   metadata: object,   // everything else, serialized to JSON
 *
 * @example
 *   var auditActor = require("./actor");
 *   await auditActor.record({
 *     action:   "domain.added",
 *     outcome:  "success",
 *     actor:    auditActor.current(),
 *     resource: { kind: "domain", id: row._id },
 *     metadata: { domain: name },
 *   });
 */
async function record(event) {
  try {
    await b.audit.record(event);
    return true;
  } catch (_e) {
    // Drop-silent by design: the operation this row describes has
    // already happened, and reporting it as a failure would be a worse
    // answer than not recording it. The answer says the row is missing;
    // it does not decide what the caller does about that.
    return false;
  }
}

module.exports = {
  build:             build,
  forRequest:        forRequest,
  forCommandLine:    forCommandLine,
  runAs:             runAs,
  enterAs:           enterAs,
  current:           current,
  record:            record,
  COMMAND_LINE_MARK: COMMAND_LINE_MARK,
};
