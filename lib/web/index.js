// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web
 * @title  Webmail and administration
 *
 * @intro
 *   The browser surface: a mailbox for the account owner and an
 *   administration console for the operator, both server rendered, plus
 *   the JMAP mount, the readiness probe and the well known documents.
 *   One HTTP application carries all of it, so an operator runs one
 *   process and one port.
 *
 *   Every page is a complete HTML document produced on the server. The
 *   opt in scripts under `lib/web/public/islands/` add keyboard
 *   navigation, an instant theme switch and a leave confirmation on the
 *   compose form. Turning them off costs those conveniences and nothing
 *   else: reading, searching, filing, sending, and every administration
 *   action work from plain form submissions. There is no client side
 *   validator anywhere, because the server owns validation and a second
 *   copy in the browser is a second answer waiting to disagree.
 *
 *   ## Composition, not an HTTP layer
 *
 *   `create(opts)` returns the routes and the probe controller. `serve`
 *   is the lifecycle around them: it hands the routes to
 *   `b.createApp({ routes })`, takes the cleartext port and the TLS port,
 *   and drains both on the way down. `lib/index.js` composes `serve`
 *   alongside the mail listeners, which is why the listener table the
 *   readiness probe reports arrives through `opts.listeners` rather than
 *   being read from here.
 *
 *   The routes mount the framework's request lifecycle themselves rather
 *   than trusting the caller to have configured it: request id, security
 *   headers, bot guard, cookies, CSP nonce, fetch metadata, body parsing
 *   and CSRF all go on before the first route. Each of those layers is
 *   idempotent, so mounting them here and in `createApp` costs nothing
 *   and removes the configuration in which they are absent. Session
 *   cookies carry the `__Host-` prefix and the `Secure` attribute
 *   unconditionally, which means the browser surface is served over TLS,
 *   either terminated in the process or by the reverse proxy in front of
 *   it.
 *
 *   ## What this module does not own
 *
 *   Message bytes belong to `b.mailStore`, and every read and every
 *   flag write goes through `b.mail.agent`.
 *
 *   Destroying a message and filing one into another folder do not.
 *   Both are one operation over three pieces of state: the message
 *   store's row, which the agent owns and whose `expunge` holds the
 *   legal hold refusals and the retention floor; the row binding that
 *   message to a folder and to the UID an IMAP client addresses it by;
 *   and the sealed original octets under `blobs/` that IMAP `BODY[]`
 *   and POP3 `RETR` return. The last two belong to the mailbox adapter,
 *   so `mailbox.expungeObjects` and `mailbox.moveObjects` are what the
 *   purge button, the Trash button, the move form and JMAP
 *   `Email/set` all drive. Reaching past them to the agent carries one
 *   of the three and reports success for all of it.
 *
 *   Accounts, domains and aliases belong to `lib/store`. Building and
 *   sending a message belongs to `lib/mail/compose`, because the
 *   agent's own `compose` and `send` verbs refuse and point the caller
 *   at the outbound composer. Selector rotation belongs to
 *   `lib/mail/dkim` and the outbound spool to `lib/mail/delivery`.
 *
 *   All of those arrive through `create(opts)`, whose required method
 *   sets are checked once at construction so a wiring mistake fails the
 *   boot by name rather than the first request that reaches it. Nothing
 *   here reaches sideways into another module of this repository;
 *   `lib/index.js` is where the wiring is visible.
 *
 *   ## Hostile message content
 *
 *   A message body is attacker supplied bytes. The reader sees a
 *   structural subset of HTML: tag and attribute allowlists that drop
 *   `class`, `id`, `style`, every event handler and every scheme outside
 *   `http`, `https`, `mailto` and `tel`, produced by
 *   `b.guardHtml.sanitize`. Nothing from a message can address this
 *   application's stylesheet or execute in it.
 *
 *   Images stay out of the document until the reader asks for them, per
 *   message, which is what keeps a tracking pixel from reporting that the
 *   message was opened. The default render drops the `img` tag entirely
 *   rather than emptying its `src`, so there is no attribute left for a
 *   later rewrite to resurrect. Asking for images widens `img-src` on
 *   that one response and on no other.
 *
 *   ## Paging a store that reads forward
 *
 *   `b.mailStore` returns rows in ascending `modseq` order from a floor,
 *   capped at a thousand rows, and a mailbox reads newest first. The
 *   folder row carries `modseq_max`, so a page is taken by choosing a
 *   floor below the requested cursor, reading the window, reversing it
 *   and keeping a page. When the window comes back short and the floor is
 *   above zero the floor widens and the read repeats, at most
 *   `MAX_PAGE_PROBES` times, so a folder whose modseq is sparse still
 *   fills a page and a folder that is genuinely short terminates.
 *
 *   ## Folder naming
 *
 *   One layer names folders and it is not this one. The mailbox adapter
 *   gives every account its own store folders under opaque names and
 *   keeps the map from the name an owner sees to the folder underneath
 *   it, so `mailbox.accountFolders` answers with that account's folders
 *   and with nothing else. This module composes no folder name, derives
 *   none from an account record and filters none after the fact: a list
 *   that is already the right list has nothing left to filter, and a
 *   second check over it is a second chance to get it wrong.
 *
 *   Every folder in a URL, a form field or a JMAP mailbox id is the name
 *   the account sees, resolved against that list. A name the account
 *   does not own matches nothing and the route answers 404. The store
 *   folder appears in no link and is accepted from no request.
 *
 *   A server side decision holds a folder ROLE rather than a name. Where
 *   a reader lands, where a soft delete files a message: both are the
 *   account's own folder carrying the RFC 6154 role, so nothing here
 *   spells a folder name and nothing hands one to a layer below as a
 *   literal.
 *
 *   ## Message identifiers are resolved, not trusted
 *
 *   A folder name is one identifier a request carries. A message
 *   identifier is the other, and it is the one a caller can hold without
 *   owning anything, because identifiers are global to the store: one
 *   taken from anywhere names the same message everywhere.
 *
 *   So every message identifier a request supplies is resolved inside
 *   the account's own folder before it reaches the agent, and a bulk
 *   action refuses whole when one of them misses. The substrate does not
 *   close that on its own and cannot be relied on to: a move and an
 *   expunge are scoped by folder underneath, a flag write is not, and
 *   which of the three is scoped is an implementation detail of a layer
 *   this one does not own.
 *
 *   The same rule covers JMAP. A thread is looked up in an index keyed
 *   on the identifier alone, with no folder anywhere in the call, so the
 *   chain it answers with spans every account holding a copy of that
 *   conversation. What comes back is filtered to the messages this
 *   account can see, which is what RFC 8621 section 3 defines a thread
 *   to be.
 *
 *   ## Why releasing a sign-in lockout is a page and not a command
 *
 *   Wrong passwords spend a failure budget kept against the mailbox, and
 *   once it is gone the right password is refused as well, on every
 *   protocol at once. Giving it back is an operator action, and the
 *   operator's other account verbs are on the command line, so this one
 *   looks like it belongs there and does not.
 *
 *   The budgets are counters in the running server, and every command
 *   line verb that touches an account opens the data volume, which one
 *   process holds at a time. So the command line runs with the server
 *   stopped, and a stopped server has discarded every counter: a release
 *   issued there would build an empty set and report that nothing was
 *   locked, every time, for reasons nothing on the terminal would show.
 *   The counters and this console are in the same process, which is the
 *   whole of why the release lives here.
 *
 *   The page reads two things and keeps them apart. The lockout trail is
 *   on disk and survives a restart, and it records a budget only once
 *   that budget has run out, so it answers what happened. The counters
 *   are in this process and are what actually refuse a password, so they
 *   answer what is true now, including for a mailbox whose attempts are
 *   running down and which the trail therefore carries nowhere. The two
 *   can disagree, and the disagreement is the answer rather than a
 *   defect: a row written before a restart names a budget that is
 *   already free. Showing one number where they differ would pick a
 *   side, so each row carries both and says which is which.
 *
 *   The budget each listener keeps against a source address is a third
 *   one, held inside the framework listener with no release verb and no
 *   read anywhere, and the page says so rather than leaving an operator
 *   to infer that adding live numbers covered it.
 *
 *   Reading is behind the same gate releasing is. Which mailboxes are
 *   being guessed at and from where is a map of what is under attack on
 *   this server, so it is not a lesser action than the release beside
 *   it.
 */

var nodeFs   = require("node:fs");
var nodeHttp = require("node:http");
var nodePath = require("node:path");
var pkg = require("../../package.json");
var b = require("../vendor/blamejs");

// Two spellings of one mailbox are one mailbox, and `lib/store/address`
// is the single place that decides so. A comparison here that reaches
// for the raw string instead disagrees with the routing layer about who
// a recipient is, and it does it silently.
var address = require("../store/address");

// Who an audit row names, decided in one place for the whole server.
// The identity layer writes the rows this surface's administration
// pages cause, and it is several calls away from the request that
// caused them, so the request opens a scope rather than threading an
// argument through every call that might one day write one.
var auditActor = require("../store/actor");

// Which addresses an account may write as the author of a message.
//
// One derivation, composed rather than repeated. The authenticated
// submission listener measures a message's From and Sender against this
// same set, so a second computation here would be a browser offering an
// address the wire refuses, or a wire accepting one the browser never
// showed. The listener owns it because the listener is where a message
// is refused before it is signed; this file asks the same question of
// the same function.
var permittedAuthors = require("../mail/listeners").permittedAuthors;

// The key agreement this server's TLS port presents, from the module
// that owns listener composition. Same reason as the line above it: the
// mail ports and this one build their contexts by different routes, and
// a second spelling of the list here would be two halves of one server
// accepting different sets.
var keyAgreementGroups = require("../mail/listeners").keyAgreementGroups;

// Every refusal this server's signer composes, read from the module that
// throws them. What this surface needs to know about a signing fault is
// whether anybody worded it for the operator now reading it, and the
// `dkim/` prefix cannot answer that: the framework files its own signing
// faults under the same prefix and words them for whoever composed the
// framework. Membership in this set answers it instead, because every
// value in it is the constant a throw site in that module names, so a
// code the framework invented can never be in it and a code added there
// arrives already in it.
var dkimCodes = require("../mail/dkim").CODES;
var DKIM_REFUSAL_CODES = Object.keys(dkimCodes || {})
  .map(function (name) { return dkimCodes[name]; });

// Read once, at load, so a set that has emptied is a boot failure rather
// than a page that has quietly stopped showing an operator anything. An
// empty set answers every membership question the same way, and the
// answer it gives is the one that hides the fault: every refusal the
// signer wrote for a person would fall through to the generic sentence
// and the operator would be told to read a log that names a domain they
// could have fixed from the page.
if (DKIM_REFUSAL_CODES.length === 0 ||
    DKIM_REFUSAL_CODES.some(function (code) { return typeof code !== "string"; })) {
  throw new TypeError("blamepost.web: the dkim module must export CODES holding the refusal " +
    "codes it throws, which is how this surface tells a signing refusal worded for an " +
    "operator from one the framework worded for whoever composed it. Both carry a 'dkim/' " +
    "prefix, so without the set there is nothing left to tell them apart by.");
}

var VIEWS_DIR  = nodePath.join(__dirname, "views");
var PUBLIC_DIR = nodePath.join(__dirname, "public");
var ASSETS_DIR = nodePath.join(PUBLIC_DIR, "assets");

// The vector marks this application serves. Both are committed files, and
// nothing a request can reach ever writes into the asset directory.
var BRAND_MARKS = Object.freeze(["favicon.svg", "logo-mono.svg"]);

// Session cookie. The `__Host-` prefix binds the cookie to this exact
// origin with no Domain attribute and a root path, which the browser
// enforces rather than trusting the server to get right. It also requires
// `Secure`, so this surface is served over TLS.
var SESSION_COOKIE = "__Host-bp_session";
var THEME_COOKIE   = "__Host-bp_theme";

var SESSION_TTL_MS = b.constants.TIME.hours(12);
var THEME_TTL_MS   = b.constants.TIME.days(365);

// How often one machine may post the sign in form, and over what span.
//
// This is a ceiling on WORK, not on guessing, and the difference decides
// the number. Guessing is bounded per mailbox by the identity layer, at
// five failures in a quarter of an hour, and that budget is keyed on the
// mailbox precisely so that moving between source addresses cannot
// refill it. Nothing here improves on that and nothing here should try.
//
// What is left over is the cost. Every post to the form buys one
// password verification, and buys it whether or not the address named
// has a mailbox: the identity layer burns one on a miss on purpose, so
// that timing cannot be used to ask which addresses exist. That makes
// this the most expensive route on the server that anyone can reach
// without signing in, and one client posting to it flat out is a way to
// spend the server's CPU rather than a way to get in.
//
// Fifty in five minutes is ten a minute. A person signing in makes one
// post, a person who has forgotten which password they used makes five,
// and nothing but a script makes ten a minute for five minutes. The
// ceiling that leaves is ten verifications a minute per source, which is
// a rate this server can absorb while it goes on delivering mail.
//
// The number has to survive the deployment where the source address is
// not the reader's. blamepost reads the peer off the socket and ignores
// X-Forwarded-For everywhere, because a header the client writes is a
// header the client uses to choose whose budget it spends. So with a
// terminator in front of the browser port, which is a shape this
// project ships a profile for, every reader arrives from the
// terminator's own address and this bound is one count for the whole
// server. Fifty sign ins in five minutes is a busy Monday on a server
// with a few dozen mailboxes and it is nowhere near a script, so the
// bound still separates the two cases it has to separate. A tighter one
// would not: it would shut the console for everybody the moment enough
// people opened webmail at once, which is a worse failure than the one
// it was tightened to prevent.
var SIGN_IN_POSTS_PER_WINDOW = 50;
var SIGN_IN_WINDOW_MS        = b.constants.TIME.minutes(5);

// Rows per mailbox page, and the modseq span a first read reaches back
// across to fill one. Folder modseq advances on flag changes as well as
// on arrivals, so the span is deliberately wider than the page.
var PAGE_SIZE       = 50;
var FIRST_PAGE_SPAN = 512;
var WINDOW_CAP      = 1000;
var MAX_PAGE_PROBES = 6;

// Windows a page read walks up from the bottom of a folder when reading
// down from its high-water mark found nothing. Each one covers
// `WINDOW_CAP` rows, so this reaches a folder holding sixty four
// thousand messages. Past that the page is drawn from an older window
// rather than an empty one, which is the honest degradation: the read
// only happens at all for a folder whose sequence numbers have a gap in
// them, and it stops rather than growing without a bound.
var MAX_PAGE_WALK   = 64;

// Rows per administration page, and the ceiling on an operator supplied
// page size.
var ADMIN_PAGE_SIZE = 50;
var ADMIN_PAGE_MAX  = 200;

// How many recorded sign-in lockouts the console reads back. An operator
// opens that page because somebody cannot get in now, so the useful
// window is the recent one; a longer history is the audit page's job and
// this read is charged to the audit trail exactly as that one is.
var LOCKOUT_TRAIL_ROWS = 40;

// The two sign-in lockout events the console reads. `engaged` is the
// moment a budget ran out, and the only one that carries when it lifts;
// `unlock` is a release, so a budget that has already been given back
// stops reading as one still holding somebody out. The third event a
// lockout writes is one row per wrong password, which is the audit
// page's business rather than this one's.
var LOCKOUT_ENGAGED  = "auth.lockout.engaged";
var LOCKOUT_UNLOCKED = "auth.lockout.unlock";

// How the identity layer names the two budgets it keeps, as they reach
// the audit trail. The framework composes a resource id as its lockout
// namespace, a colon, then the counter key, and the identity layer keys
// one budget on the mailbox and the other on the source address and the
// mailbox together with a vertical bar between them.
//
// Nothing here trusts that shape to be right. The address it reads out
// of a key is looked up in the account table before the page calls it a
// mailbox, so a key this parse gets wrong is shown as the bytes it is
// rather than as a mailbox that would then be offered for release.
var LOCKOUT_BUDGET_SEPARATOR = ":";
var LOCKOUT_PAIR_SEPARATOR   = "|";

// Bytes of message text quoted into a reply. A long thread quoted whole
// makes the compose box unusable and the outbound message enormous.
var QUOTE_BYTE_CAP = b.constants.BYTES.kib(64);

// Enhanced status code on a report generated because the operator
// cancelled a message that was still waiting to go out. RFC 3463 5.7.1,
// delivery not authorized.
var CANCELLED_STATUS = "5.7.1";

// The interface the listeners take when the caller names none. Every
// port this application serves is meant to be reachable from outside the
// container, and an operator who wants it narrowed passes an address.
var DEFAULT_BIND_ADDRESS = "0.0.0.0";

// How long a bound listener may spend finishing its in flight requests
// before the connections still open are cut. Kept under the drain budget
// the command line allows, so a stop is a drain rather than a kill.
var HTTP_DRAIN_MS = b.constants.TIME.seconds(8);

// Where the JMAP WebSocket transport answers. RFC 8887 section 3 has
// the client read the endpoint out of the session document rather than
// guess at it, and the framework's session resource writes this same
// default into both the capability object and the top level
// `webSocketUrl`. Changing it here without passing the new value to
// `b.mail.server.jmap.create` would advertise one url and serve
// another, which fails on the client as a channel that never opens and
// records nothing on the server.
var JMAP_WEBSOCKET_PATH = "/jmap/ws";

// The largest frame the JMAP socket accepts. A `Request` frame carries
// the same body as a POST to the API endpoint, so the ceiling is the
// one that endpoint would apply rather than the framework's ten
// megabyte default: an upload travels through the blob endpoint, and a
// method call that needs more than this is a method call built wrong.
var JMAP_WEBSOCKET_MAX_BYTES = b.constants.BYTES.mib(1);

// How often the push channels look for a change. Both transports RFC
// 8620 section 7 defines ride one hook, and the hook watches the
// counter the store already keeps rather than asking every subsystem
// that can move a mailbox to announce it. The cost is one indexed read
// per subscribed account per sweep, and the reason it is a sweep at all
// is that mail arrives from the MX listener, the submission path, IMAP,
// POP3 and this application alike: a notification wired into one of
// them is a channel that stays quiet for the other four.
var PUSH_SWEEP_MS = b.constants.TIME.seconds(1);

// The JMAP types whose state string this server derives from the same
// counter, and which a StateChange may therefore name. `EmailDelivery`
// is deliberately absent: RFC 8621 section 7.1 has it change only when
// mail is delivered, and this counter also moves on a flag change and a
// move, so naming it would tell a client it has new mail when nothing
// arrived.
var PUSH_DATA_TYPES = Object.freeze(["Mailbox", "Email"]);

// Read ceilings on the certificate chain and the private key, matching
// what the mail listeners apply to the same two files. The cap is the
// defense against a file that is enormous by accident or on purpose.
var MAX_CERT_BYTES = b.constants.BYTES.mib(1);
var MAX_KEY_BYTES  = b.constants.BYTES.kib(64);

// What `b.vault.sealPemFile` writes ahead of a sealed private key.
// Anything without it is read as plain PEM.
var SEALED_PEM_PREFIX = "vault:";

// Folder roles the store records, mapped to the order a reader expects.
var ROLE_ORDER = {
  inbox:   0,
  drafts:  1,
  sent:    2,
  archive: 3,
  junk:    4,
  trash:   5,
};

// The mailbox every account has, by the name RFC 9051 section 5.1
// reserves for it. Read when a request names no folder, and resolved
// against the account's own folders like any other name.
var DEFAULT_FOLDER = "INBOX";

// The role every account's first folder carries, and the one a reader
// lands on. Read as a role rather than as a name for the same reason the
// bin is: a role is what a server-side decision holds on to.
var INBOX_ROLE = "inbox";

// Where a soft delete files a message. RFC 6154 names the role rather
// than the folder, which is the handle worth holding: the account's own
// folder carrying it is found the same way its inbox is, so nothing here
// spells a folder name and an account whose Trash is called something
// else is still served.
var TRASH_ROLE = "trash";

// The longest folder name a request may carry. Longer than any name this
// server creates, and short enough that a pathological URL segment is
// refused before it reaches a lookup.
var MAX_FOLDER_NAME_CHARS = 128;

// The most messages one bulk action may name. A folder page shows
// `PAGE_SIZE` rows and a form cannot select more than it shows, so this
// is twice what a browser can produce. Resolving each identifier costs a
// sealed column read, which is why the ceiling is a refusal rather than
// a slice: a request past it is not a reader, and answering the first
// hundred of it would report a partial result as a whole one.
var MAX_ACTION_IDS = PAGE_SIZE * 2;

// RFC 8621 section 4.1.1. Four JMAP keywords name IMAP system flags and
// every other keyword is stored as itself. `\Deleted` and `\Recent` are
// the two the mapping deliberately leaves out: a JMAP client has no verb
// that should reach them, and `\Deleted` is what an IMAP EXPUNGE acts
// on, so a keyword folding onto it would be a delete nobody asked for.
var JMAP_KEYWORD_FLAG = Object.freeze({
  $draft:    "\\Draft",
  $seen:     "\\Seen",
  $flagged:  "\\Flagged",
  $answered: "\\Answered",
});

var FLAG_JMAP_KEYWORD = Object.freeze({
  "\\Draft":    "$draft",
  "\\Seen":     "$seen",
  "\\Flagged":  "$flagged",
  "\\Answered": "$answered",
});

// The keywords that name a flag JMAP does not expose, written the way a
// client would send them. Refused rather than ignored, so a client that
// asked for one is told it did not happen.
var JMAP_UNEXPOSED_KEYWORDS = Object.freeze(["$deleted", "$recent"]);

// A keyword that is not one of the four is stored verbatim, so it has to
// be a flag this server would keep: an IMAP atom, drawn by RFC 9051
// section 4.1 from ATOM-CHAR, which excludes the list wrapper
// characters, the quoting characters and every control byte.
var JMAP_KEYWORD_RE = /^[A-Za-z0-9_$.+&#!-]+$/;

// The longest keyword a request may carry. Well past every keyword the
// IANA registry lists, and short enough that a patch cannot write an
// unbounded string into the flag column.
var MAX_KEYWORD_CHARS = 64;

// How much of the identity digest an Identity state string carries. RFC
// 8620 section 5.1 asks for a short string, and this is a 128 bit
// prefix: far beyond what telling one revision of one account's
// identities from another needs, and short enough to sit in every
// answer without becoming the answer.
var IDENTITY_STATE_CHARS = 32;

// How an identity that is not the account itself is named, and how much
// of the digest the name carries.
//
// RFC 8620 section 1.2 holds an id to the URL and filename safe base64
// alphabet, so an address cannot be its own id: it carries an at sign
// and a dot, and a client is entitled to put an id in a path segment
// unescaped. A digest of the address is the id instead, which is stable
// for as long as the alias is and gone the moment the operator withdraws
// it, with nothing to store and nothing to keep in step. The namespace
// keeps it distinct from every other derived value in this server, and
// 128 bits is far past what telling one of an account's own addresses
// from another needs.
var IDENTITY_ID_NAMESPACE = "blamepost.identity";
var IDENTITY_ID_CHARS     = 32;
var IDENTITY_ID_PREFIX    = "idt_";

// How many identities a refusal names, and how much of a posted author
// it quotes back. Both are values a request chooses, so the bound is on
// the length of what this server repeats rather than on what it was
// sent. The count is reported whole even when the names are not.
var MAX_NAMED_IDENTITIES  = 16;
var MAX_AUTHOR_ECHO_CHARS = 120;

// Message body policy. Two allowlists over one profile: the reading
// default drops `img` outright, and the reader's per message request for
// images restores it. Attributes are the structural set only. `class` and
// `id` are absent by intent, so message markup cannot address the
// application stylesheet, and `style` is absent so it cannot carry its
// own.
var BODY_ATTRS = Object.freeze([
  "title", "lang", "dir", "alt", "href", "src",
  "width", "height", "colspan", "rowspan", "scope", "datetime", "cite",
]);

var BODY_TAGS_WITH_IMAGES = Object.freeze(
  b.guardHtml.BALANCED_ALLOWED_TAGS.slice()
);

var BODY_TAGS_TEXT_ONLY = Object.freeze(
  BODY_TAGS_WITH_IMAGES.filter(function (tag) { return tag !== "img"; })
);

// How a decoded header value is screened before a reader sees it. The
// balanced profile strips bidi overrides, zero-width characters and C0
// controls and leaves every writing system alone, which is what a
// subject needs: the strict profile refuses rather than repairs and
// reports ordinary Japanese as a mixed-script confusable, so it would
// turn hostile mail and legitimate mail into the same outage. The same
// profile screens the other untrusted text this server displays.
var HEADER_TEXT_GUARD = Object.freeze({ profile: "balanced" });

// Content-Security-Policy for the one response that renders images the
// reader asked for. Everything else inherits the framework default, which
// admits neither remote images nor anything else off origin.
var CSP_WITH_IMAGES =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data: https:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "fenced-frame-src 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none'; " +
  "require-trusted-types-for 'script'; " +
  "trusted-types 'allow-duplicates' default;";

// Codes a redirect may carry back to the page that follows it. The code
// travels in the query string and the text is looked up here, so no
// operator or reader supplied string is ever reflected into a URL.
var NOTICES = {
  sent:            { kind: "ok",   text: "Message sent." },
  moved:           { kind: "ok",   text: "Messages moved." },
  "move-refused":  { kind: "warn", text: "Some messages were not moved. Open the folder again to see where they are." },
  flagged:         { kind: "ok",   text: "Flags updated." },
  trashed:         { kind: "ok",   text: "Messages moved to Trash." },
  purged:          { kind: "ok",   text: "Messages permanently removed." },
  "purge-refused": { kind: "warn", text: "Some messages were kept. Retention or legal hold applies." },
  // The other half of a purge that did not finish, and the half the
  // sentence above must never be stretched to cover. Nothing decided to
  // keep these: the data volume would not take one of the two acts that
  // remove a message, so a record of it stays here. Naming a retention
  // rule for it would send the reader to a policy that is not in force
  // and give them nothing to do.
  "purge-faulted": { kind: "warn", text: "Some messages could not be fully removed. Nothing is keeping them on purpose: this server could not complete the removal on its data volume. The operator has been told, and it is theirs to finish." },
  "signed-out":    { kind: "ok",   text: "Signed out." },
  "domain-added":  { kind: "ok",   text: "Domain added. Publish its records, then confirm the DNS posture." },
  "dns-confirmed": { kind: "ok",   text: "DNS posture confirmed for that domain." },
  "domain-saved":  { kind: "ok",   text: "Domain saved." },
  "account-added": { kind: "ok",   text: "Account created." },
  suspended:       { kind: "ok",   text: "Account suspended. Its mail is untouched." },
  reinstated:      { kind: "ok",   text: "Account reinstated." },
  archived:        { kind: "ok",   text: "Account archived. Its mail is retained." },
  "role-granted":  { kind: "ok",   text: "That account now administers this server. It reads every mailbox owner's address, every hosted domain, the outbound spool and this trail." },
  "role-revoked":  { kind: "ok",   text: "That account no longer administers this server. Its mailbox is untouched, and any session it already had stopped administering at once." },
  "alias-added":   { kind: "ok",   text: "Alias added." },
  "alias-removed": { kind: "ok",   text: "Alias removed." },
  "keys-minted":   { kind: "ok",   text: "Key pair minted. Publish both records before mail starts flowing." },
  "keys-rotated":  { kind: "ok",   text: "New pair signing. Publish its records, then retire the outgoing pair." },
  "keys-retiring": { kind: "ok",   text: "Outgoing pair is retiring. Keep its records published until the overlap closes." },
  "keys-swept":    { kind: "ok",   text: "Selectors past their overlap are withdrawn." },
  // The same act with a sealed private key left on the volume. It is a
  // warning rather than a success because the withdrawal is the part
  // that worked and the key is the part somebody has to go and delete: a
  // file no row points at, that nothing here will name again, and that
  // signs mail as the domain for anyone who takes a copy of the volume
  // or a backup of it. The names are not in this text because a notice
  // is looked up by code and carries no operator-supplied value; the
  // server log and `blamepost doctor` both name the files.
  "keys-swept-stranded": { kind: "warn", text: "Selectors past their overlap are withdrawn, and at least one sealed private key could not be destroyed with them. It is still in the keys folder under a name no record points at, and nothing here will name it again. Delete it by hand: whoever holds it signs mail as the domain it belonged to. Run `blamepost doctor` to see which files, or read the server log." },
  "queue-ran":     { kind: "ok",   text: "Everything due has been retried." },
  "queue-cancelled": { kind: "ok", text: "Delivery cancelled. A report goes to the sender." },
  // A cancellation that reached nothing has to say so. An operator
  // working through a compromised account's outbound mail who is told a
  // message was cancelled stops looking for it, and a message that was
  // never on this spool is one that either went out already or is
  // waiting under a different name.
  //
  // Two states end here and the operator's next move differs between
  // them, so both are named. A message that has gone is past cancelling.
  // A message the volume would not give up is still waiting and will be
  // attempted again, which is the one worth acting on.
  "queue-none-held": { kind: "warn", text: "Nothing was cancelled. Either the queue no longer holds any of the messages you selected, because they have gone out, ended in a report, or been cancelled already, or this server could not take them off its data volume and they are still waiting. Reload the queue: anything still listed was not cancelled, and the server log says what the volume refused." },
  // Part of a selection cancelled and part of it not. The rest is not
  // one thing: a message that left this server before the cancellation
  // reached it was never erased and its sender was never written to,
  // and a message the volume kept is still queued and will be attempted
  // again. The trail says which against each one.
  "queue-part-held": { kind: "warn", text: "Some of the messages you selected were cancelled. The rest were not, and their senders were not written to: they either left this server before the cancellation reached them or could not be taken off its data volume. Reload the queue: anything still listed is still going out, and the server log says what the volume refused." },
  // The one answer where reloading the queue tells the operator the
  // wrong thing. A message was taken off the volume and the file that
  // lists it was not, so the entry is still there and the message it
  // names is gone: it can never be sent, its sender was not written to,
  // and the running server will find nothing to send and give up on it.
  // Cancelling it again is what takes the rest.
  "queue-part-destroyed": { kind: "warn", text: "At least one message was destroyed in part. Its own bytes were taken off the data volume and the file listing it was not, so it is still shown in the queue and can never be sent, and its sender was not written to. Nothing later writes to them either: the running server will find nothing to send and give up on the entry, and an entry with no message beside it cannot tell a cancellation from a delivery, so it says nothing to anybody. This is not a cancellation to repeat for the message: clear whatever is holding that file open, then cancel it again to take the rest. The server log names the entry and says what the volume refused." },
  // Six outcomes rather than one, because a release is asked about TWO
  // budgets and the person who cannot sign in is somewhere different
  // under each answer.
  //
  // Whether anything was holding sets the kind. WHICH budget was holding
  // sets the rest, and it is read off what the release actually gave
  // back rather than off what the operator typed into the form. Saying
  // it matters because the budget kept against one machine is read FIRST
  // when a sign in is judged, so a machine that has spent its own
  // allowance stays refused after the mailbox budget has been given
  // back. An operator told only that something was released closes a
  // call that is about to come back.
  //
  // A machine that was named and found already clear is not the same
  // answer as no machine having been named at all. The first rules that
  // device out, so whatever still refuses the account holder there is
  // something else; the second leaves that budget unread and still worth
  // trying. One word over both cannot carry either.
  "lockout-released":         { kind: "ok",   text: "The budget kept against the mailbox is released, so it can sign in again from anywhere. No machine was named, so the smaller budget kept against a single machine is untouched: if the account holder is still refused from one device, release again with that machine filled in." },
  "lockout-released-both":    { kind: "ok",   text: "Both sign-in budgets are released: the mailbox, and the machine you named. Neither of them is holding that account back now." },
  "lockout-released-mailbox": { kind: "ok",   text: "The budget kept against the mailbox is released, so it can sign in again from anywhere. The machine you named was already clear, so the budget kept against it was never what refused the account holder: if they are still refused on that device, whatever is stopping them is something else." },
  "lockout-released-machine": { kind: "ok",   text: "The budget kept against the machine you named is released. The budget kept against the mailbox was already clear, so that machine was the only one of the two holding that account back." },
  "lockout-clear":            { kind: "warn", text: "Nothing was holding that mailbox back: its sign-in budget was already clear. No machine was named, so the budget kept against a single machine was neither read nor released. Whatever is refusing that account is something else." },
  "lockout-clear-both":       { kind: "warn", text: "Nothing was holding that mailbox or that machine back: both sign-in budgets were already clear. Whatever is refusing that account is something else." },
};

// Method sets each injected handle must carry. Checked once, at
// construction, so a wiring mistake fails the boot with the name of the
// thing that is missing instead of the first request that reaches it.
// Each entry is a method this module actually calls.
// Four of the agent's verbs are deliberately absent.
//
// `folders` answers with every folder in the store, for any actor, so
// the folder list comes from the mailbox adapter and the agent is asked
// only about messages.
//
// `delete` files a message into a folder it names itself, as the literal
// `Trash`. That is the right destination for a store holding one folder
// set and the wrong one here, where every account has its own: the mail
// would land in the bootstrap folder of that name, which belongs to no
// account, leaving it gone from the folder it left and absent from the
// folder its owner would look in. A soft delete is composed instead, out
// of a move into the Trash the account actually owns and the flag that
// marks it.
//
// `expunge` and `move` are absent for the reason `REQUIRED_MAILBOX`
// exists. Both are half of an operation: the agent owns the message
// store's row, and the mailbox adapter owns the row binding that
// message to a folder and to the UID an IMAP client addresses it by,
// plus the sealed original octets under `blobs/`. Driving the agent
// from here destroys or moves one of the three and leaves the others,
// which reports success and either strands the message where no folder
// holds it or leaves its body readable on the volume after the reader
// was told it was permanently removed.
//
// @membership blamepost.web.REQUIRED_AGENT constraint
var REQUIRED_AGENT = [
  "search", "fetch", "thread", "quota", "flag",
];
// The adapter verbs that carry a whole delete and a whole move. A
// handle answering `accountFolders` alone is what a partial adapter
// presents, and accepting it is how a surface ends up reaching past the
// verb that would have done the work.
var REQUIRED_MAILBOX = ["accountFolders", "expungeObjects", "moveObjects"];
// @membership blamepost.web.REQUIRED_STORE constraint
var REQUIRED_STORE = [
  "accounts.authenticate", "accounts.get", "accounts.list", "accounts.create",
  "accounts.suspend", "accounts.reinstate", "accounts.delete", "accounts.unlock",
  "accounts.lockoutState", "accounts.setAdmin",
  "domains.add", "domains.list", "domains.acknowledgeDns", "domains.setStatus",
  "aliases.add", "aliases.list", "aliases.remove",
];
// Every one of these five lists names methods a caller's handle MUST carry,
// so growth is what takes something away: a handle that satisfied the last
// release stops being accepted. The direction of the count says the
// opposite, which is how two of them last read as capabilities gained.
//
// @membership blamepost.web.REQUIRED_COMPOSE constraint
var REQUIRED_COMPOSE  = ["send"];
// @membership blamepost.web.REQUIRED_DKIM constraint
var REQUIRED_DKIM     = ["list", "generate", "rotate", "retire", "sweep"];
// `describe` is here for the health probes rather than for a page. It is
// the one reader that answers whether mail is still MOVING, and asking
// the spool a second way would be a second answer to disagree with the
// first about a server that is already in trouble. Counting the files
// under `queue/`, or reading `queue.capacity` beside `queue.held` and
// stitching the two together, are both that second way.
//
// `queue.show` is not that second way and is required for the opposite
// reason. It answers about ONE entry rather than about the shape of the
// pile, and the cancellation route asks it of each message in the turn
// that erases that message, because the selection it is working through
// was read once and the loop suspends on every turn. A handle that
// cannot answer it is one that would let this page report a cancellation
// of a message that had already gone.
//
// @membership blamepost.web.REQUIRED_DELIVERY constraint
var REQUIRED_DELIVERY = [
  "bounce", "describe", "queue.list", "queue.remove", "queue.runDue", "queue.show",
];

// ---------------------------------------------------------------------
// Construction time checks. Bad wiring throws here.
// ---------------------------------------------------------------------

function _resolvePath(root, dotted) {
  var parts = dotted.split(".");
  var cur = root;
  for (var i = 0; i < parts.length; i += 1) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = cur[parts[i]];
  }
  return cur;
}

// The content safety map the static server runs. Every extension keeps the
// framework's strict default; `.svg` is replaced by something stricter.
//
// The default SVG gate refuses this project's own marks, and correctly so
// for an SVG that arrived from outside: they open with an XML processing
// instruction and carry a `<style>` block, which are the injection shapes
// that gate exists to stop. Sanitizing is not the answer either, because
// the sanitizer folds attribute names to lower case and a standalone SVG
// document is parsed as XML, where `viewbox` is not `viewBox`, so the mark
// loses its coordinate system and stops scaling.
//
// So the gate below pins instead of inspecting. It serves an SVG only when
// its bytes hash to one of the marks committed in this repository and
// refuses every other SVG outright, including one that appears in the
// asset directory later. That is a narrower opening than the default, not
// a wider one.
function _brandSvgGate() {
  var pinned = Object.create(null);
  for (var i = 0; i < BRAND_MARKS.length; i += 1) {
    var file = nodePath.join(ASSETS_DIR, BRAND_MARKS[i]);
    if (!nodeFs.existsSync(file)) continue;
    pinned[b.crypto.sha3Hash(nodeFs.readFileSync(file))] = BRAND_MARKS[i];
  }
  return {
    check: function (input) {
      var bytes = input && input.bytes;
      if (!Buffer.isBuffer(bytes)) {
        return { ok: false, action: "refuse", issues: [{ kind: "svg-not-bytes" }] };
      }
      var digest = b.crypto.sha3Hash(bytes);
      if (Object.prototype.hasOwnProperty.call(pinned, digest)) {
        return { ok: true, action: "serve" };
      }
      return {
        ok:     false,
        action: "refuse",
        issues: [{
          kind:     "svg-not-a-pinned-brand-mark",
          severity: "critical",
          ruleId:   "blamepost.svg.pinned",
          snippet:  "only the brand marks committed to this repository are served as SVG",
        }],
      };
    },
  };
}

function _contentSafetyMap() {
  var map = b.guardAll.byExtension({ profile: "strict" });
  map[".svg"] = _brandSvgGate();
  return map;
}

function _requireMethods(handle, label, methods) {
  if (!handle || typeof handle !== "object") {
    throw new TypeError("blamepost.web.create: opts." + label + " is required and must be an object");
  }
  for (var i = 0; i < methods.length; i += 1) {
    if (typeof _resolvePath(handle, methods[i]) !== "function") {
      throw new TypeError(
        "blamepost.web.create: opts." + label + "." + methods[i] + " must be a function; " +
        "the " + label + " handle does not carry the surface the browser interface calls");
    }
  }
}

// ---------------------------------------------------------------------
// Request readers. A missing or malformed query parameter in a browser
// request is ordinary, so these return a usable default rather than
// refusing. A form body carrying a decision an operator or a reader meant
// is validated where the decision is acted on.
// ---------------------------------------------------------------------

function _str(value, fallback) {
  if (typeof value !== "string") return fallback;
  var trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function _int(value, fallback, min, max) {
  var n = typeof value === "number" ? value : parseInt(String(value), 10);
  if (!isFinite(n)) return fallback;
  n = Math.floor(n);
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function _list(value) {
  if (Array.isArray(value)) {
    return value.filter(function (v) { return typeof v === "string" && v.length > 0; });
  }
  if (typeof value === "string" && value.length > 0) return [value];
  return [];
}

// One recipient list, split into recipients.
//
// RFC 5322 section 3.4 lets a display name be a quoted string, and a
// quoted string may hold the separator. So a list is not a list of
// whatever a comma separates: `"Doe, Jane" <jane@example.net>` is one
// recipient, and splitting on the separator alone turns it into two,
// the first of which is a fragment of somebody's name being carried as
// an address. The same is true of a separator inside an angle address.
//
// A browser form delivers a comma separated list; the semicolon and the
// newline are taken as well, because a reader pasting a list from
// somewhere else arrives with one of those.
function _addresses(value) {
  if (typeof value !== "string") return [];
  var out = [];
  var start = 0;
  var inQuote = false;
  var inAngle = false;
  var escaped = false;
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charAt(i);
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (c === "\"" && !inAngle) { inQuote = !inQuote; continue; }
    if (inQuote) continue;
    if (c === "<") { inAngle = true; continue; }
    if (c === ">") { inAngle = false; continue; }
    if (inAngle) continue;
    if (c === "," || c === ";" || c === "\n") {
      var part = value.slice(start, i).trim();
      if (part.length > 0) out.push(part);
      start = i + 1;
    }
  }
  var last = value.slice(start).trim();
  if (last.length > 0) out.push(last);
  return out;
}

// One recipient, split into the name shown and the address underneath.
//
// The angle address is the last angle pair OUTSIDE a quoted display
// name, because a `<` inside quotes is text in somebody's name rather
// than the start of an address (RFC 5322 section 3.4). Reading the first
// one instead takes `"a<b" <real@example.net>` apart in the wrong place
// and produces an address nobody has.
function _splitMailbox(value) {
  var raw = typeof value === "string" ? value : "";
  var inQuote = false;
  var escaped = false;
  var open = -1;
  var close = -1;
  for (var i = 0; i < raw.length; i += 1) {
    var c = raw.charAt(i);
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (c === "\"") { inQuote = !inQuote; continue; }
    if (inQuote) continue;
    if (c === "<") { open = i; close = -1; continue; }
    if (c === ">" && open !== -1 && close === -1) close = i;
  }
  if (open === -1 || close <= open) {
    return { display: "", addrSpec: raw.trim() };
  }
  var display = raw.slice(0, open).trim();
  if (display.length > 1 && display.charAt(0) === "\"" &&
      display.charAt(display.length - 1) === "\"") {
    display = display.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return { display: display, addrSpec: raw.slice(open + 1, close).trim() };
}

function _bodyOf(req) {
  return (req.body && typeof req.body === "object") ? req.body : {};
}

function _queryOf(req) {
  return (req.query && typeof req.query === "object") ? req.query : {};
}

function _asArray(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.rows)) return value.rows;
  return [];
}

// ---------------------------------------------------------------------
// Link targets.
// ---------------------------------------------------------------------

// Every link this application renders and every redirect it answers with
// is a path on this server. A leading slash does not make one: a browser
// reading `//host/x` takes what follows as an authority and leaves the
// origin, and it folds the backslash in `/\host/x` into a second slash
// and does the same. A tab inside the target is stripped before the
// parse, so a control byte can hide the shape from a naive reading of
// it.
//
// `b.safeRedirect.resolve` already knows all of that, so the check is
// its reading rather than a second one: a target it hands back unchanged
// is one it recognized as same origin. Anything else throws where the
// path is BUILT rather than becoming a link somewhere off site, because
// the alternative is an invariant that eleven separate string
// concatenations each have to remember on their own.
function _path(value) {
  if (typeof value === "string" && value.charAt(0) === "/" &&
      b.safeRedirect.resolve(value, { fallback: "" }) === value) {
    return value;
  }
  throw new TypeError(
    "blamepost.web: a link target must be an absolute path on this server. " +
    "'" + String(value).slice(0, 64) + "' is not one, and a browser following it " +
    "would leave this origin.");
}

// ---------------------------------------------------------------------
// Presentation helpers.
// ---------------------------------------------------------------------

function _byteSize(bytes) {
  var n = typeof bytes === "number" && isFinite(bytes) ? bytes : 0;
  if (n < b.constants.BYTES.kib(1)) return n + " B";
  if (n < b.constants.BYTES.mib(1)) return (n / b.constants.BYTES.kib(1)).toFixed(0) + " KB";
  if (n < b.constants.BYTES.gib(1)) return (n / b.constants.BYTES.mib(1)).toFixed(1) + " MB";
  return (n / b.constants.BYTES.gib(1)).toFixed(2) + " GB";
}

function _percent(used, cap) {
  if (typeof cap !== "number" || cap <= 0) return null;
  var pct = Math.round((used / cap) * 100);
  if (pct < 0) return 0;
  if (pct > 100) return 100;
  return pct;
}

// A meter is drawn by a stylesheet class rather than an inline width,
// because an inline style attribute needs `unsafe-inline` in style-src and
// the policy this application serves does not grant it. Twenty one buckets
// read as continuous and cost twenty one rules.
function _bucket(percent) {
  if (typeof percent !== "number") return null;
  return Math.round(percent / 5) * 5;
}

function _when(value, opts) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) return "";
  return b.time.format(value, Object.assign({ timezone: "UTC" }, opts));
}

// The display name for an address, when the header carried one, and the
// local part of the address itself when it did not.
function _displayName(value) {
  var parts = _splitMailbox(value);
  if (parts.display.length > 0) return _headerText(parts.display);
  var at = parts.addrSpec.indexOf("@");
  return _headerText(at > 0 ? parts.addrSpec.slice(0, at) : parts.addrSpec);
}

function _bareAddress(value) {
  return _splitMailbox(value).addrSpec;
}

// Whether two addresses name the same mailbox, decided by the canonical
// form whenever both sides parse. An address this server cannot parse
// names no mailbox here, so the folded strings are all there is to
// compare and the fallback keeps an unreadable header matching nothing
// rather than everything.
function _sameMailbox(left, right) {
  var a = address.parse(left);
  var bb = address.parse(right);
  if (a.ok && bb.ok) return a.address === bb.address;
  return address.fold(left) === address.fold(right);
}

// The addresses a refusal names, as one phrase. A shared mailbox is the
// first thing an operator trips over here, so the ones that would have
// been accepted are said out loud rather than left for them to go and
// look up. The list is bounded and the remainder is counted, because an
// account the operator has given many aliases should not turn one
// refusal into a page of addresses.
function _namedIdentities(addresses) {
  var named = addresses.slice(0, MAX_NAMED_IDENTITIES);
  var rest  = addresses.length - named.length;
  return rest > 0 ? named.join(", ") + ", and " + rest + " more" : named.join(", ");
}

// How much of a posted author a refusal quotes back. The value has been
// through the template's own escaping by the time it is rendered, so
// this bounds the length of what is repeated rather than its content.
function _echoAuthor(value) {
  var text = String(value === undefined || value === null ? "" : value);
  return text.length > MAX_AUTHOR_ECHO_CHARS
    ? text.slice(0, MAX_AUTHOR_ECHO_CHARS) + "..."
    : text;
}

// Header text on its way to a person. The subject and the sender's
// display name are the two strings on a message that an arbitrary
// stranger chooses, and `b.safeMime` has already decoded their RFC 2047
// encoded words by the time they are stored, so what arrives here is
// whatever the sender encoded rather than what the wire carried.
//
// The template escapes markup on every value it renders, which is what
// stops a decoded script tag. It does not touch a bidi override or a
// zero-width character, and neither is markup: they change what the
// rendered line LOOKS like without changing what it says, so a subject
// decoding to `Invoice <RLO>gpj.exe` is shown as `Invoice exe.jpg` to
// the person deciding whether to open it.
//
// `b.guardText` is the screen this server already puts in front of
// untrusted text it shows somebody: a far-side server's refusal
// reason, a DNS record's text, an account holder's own display name.
// The balanced profile strips overrides, zero-width and control
// characters and leaves every script alone, so Arabic, Hebrew, Japanese
// and an emoji all arrive unchanged.
function _headerText(value) {
  if (typeof value !== "string" || value.length === 0) return value;
  return b.guardText.sanitize(value, HEADER_TEXT_GUARD);
}

function _initial(address) {
  var name = _displayName(address);
  return name.length > 0 ? name.charAt(0).toUpperCase() : "?";
}

function _preview(text, cap) {
  if (typeof text !== "string" || text.length === 0) return "";
  var flat = text.replace(/^>.*$/gm, " ").replace(/\s+/g, " ").trim();
  if (flat.length <= cap) return flat;
  return flat.slice(0, cap).replace(/\s+\S*$/, "") + "…";
}

// ---------------------------------------------------------------------
// Folder names as they arrive and as they are shown. Which folders exist
// is the adapter's answer, never composed here.
// ---------------------------------------------------------------------

// A folder name arriving from a URL segment or a form field. It is
// carried as it was sent and matched against the account's own folders,
// which is the only thing that decides whether it names anything. A name
// this module tidied into a different one would answer for a folder the
// reader did not ask for, and a name defaulted on a miss would answer 200
// where the honest reply is 404.
function _folderSegment(value) {
  var name = _str(value, "");
  return name.length > 0 && name.length <= MAX_FOLDER_NAME_CHARS ? name : "";
}

function _folderLabel(role, name) {
  var known = typeof role === "string" ? role.toLowerCase() : "";
  if (known === "inbox")   return "Inbox";
  if (known === "drafts")  return "Drafts";
  if (known === "sent")    return "Sent";
  if (known === "archive") return "Archive";
  if (known === "junk")    return "Junk";
  if (known === "trash")   return "Trash";
  return name;
}

function _folderRank(role) {
  var known = typeof role === "string" ? role.toLowerCase() : "";
  if (Object.prototype.hasOwnProperty.call(ROLE_ORDER, known)) return ROLE_ORDER[known];
  return 100;
}

// ---------------------------------------------------------------------
// Message body rendering.
// ---------------------------------------------------------------------

function _sanitizeHtmlBody(html, withImages) {
  return b.guardHtml.sanitize(html, {
    profile:        "balanced",
    allowedTags:    withImages ? BODY_TAGS_WITH_IMAGES.slice() : BODY_TAGS_TEXT_ONLY.slice(),
    allowedAttrs:   BODY_ATTRS.slice(),
    allowImageData: withImages,
    allowComments:  false,
  });
}

// A plain text body becomes markup here rather than in a template, so the
// escaping is the guard's and quoted lines can be marked up for the
// stylesheet without the message being able to name a class itself.
function _renderTextBody(text) {
  var lines = String(text == null ? "" : text).split(/\r?\n/);
  var out = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var quoted = /^\s*>/.test(line);
    out.push(
      "<p class=\"" + (quoted ? "mb-quote" : "mb-line") + "\">" +
      b.guardHtml.escapeText(line) +
      "</p>"
    );
  }
  return out.join("");
}

// How many images the reading default holds back.
//
// Counted on the source rather than on the render, because the count
// reports what is being withheld. It counts every `img` the message
// carried, which is what the tag allowlist drops: one carried inside the
// message is held back exactly like one pointing off site, so a count
// that read only the off-site ones would leave a message whose images
// are all inline showing none of them and offering no way to ask.
function _heldImageCount(html) {
  if (typeof html !== "string" || html.length === 0) return 0;
  var matches = html.match(/<img\b/gi);
  return matches ? matches.length : 0;
}

function _renderBody(message, withImages) {
  var html = message && typeof message.bodyHtml === "string" ? message.bodyHtml : "";
  if (html.length > 0) {
    return {
      html:         _sanitizeHtmlBody(html, withImages),
      isHtml:       true,
      blockedCount: withImages ? 0 : _heldImageCount(html),
    };
  }
  var text = message && typeof message.bodyText === "string" ? message.bodyText : "";
  return { html: _renderTextBody(text), isHtml: false, blockedCount: 0 };
}

// ---------------------------------------------------------------------
// Reply and forward drafts. The quoting rule lives here because it is
// presentation: the outbound composer receives finished fields.
// ---------------------------------------------------------------------

function _replySubject(subject) {
  var s = _str(subject, "");
  return /^re:/i.test(s) ? s : ("Re: " + s).trim();
}

function _forwardSubject(subject) {
  var s = _str(subject, "");
  return /^fwd?:/i.test(s) ? s : ("Fwd: " + s).trim();
}

function _quoteBody(message) {
  var source = _str(message.bodyText, "");
  if (source.length === 0 && typeof message.bodyHtml === "string") {
    source = message.bodyHtml.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  }
  // The cap is bytes and a character can be four of them, so counting
  // characters lets a message four times the cap through as though it
  // were under it. Cutting on a code point boundary matters as well: a
  // cut through the middle of one leaves half a character in the draft
  // the reader is about to send.
  var bytes = Buffer.from(source, "utf8");
  if (bytes.length > QUOTE_BYTE_CAP) {
    var end = QUOTE_BYTE_CAP;
    while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
    source = bytes.subarray(0, end).toString("utf8");
  }
  return source.split(/\r?\n/).map(function (line) { return "> " + line; }).join("\n");
}

// The first address in a list this server will not accept, written for
// the reader, or null when every one of them is fine.
//
// The identity layer's derivation is what decides, which is the same
// question the outbound composer asks a moment later and the same one
// the routing layer asks of a recipient. Asking the framework's address
// guard here instead would ask about the SPELLING: it refuses the
// absolute form of RFC 1035 section 2.3.1, which is a name a message may
// legitimately arrive carrying. A reader answering such a message would
// then be told that the address in front of them, which is the one this
// server put in the field, is not one it will accept.
function _firstUnacceptable(addresses) {
  for (var i = 0; i < addresses.length; i += 1) {
    if (!address.parse(addresses[i]).ok) {
      return addresses[i] + " is not an address this server will accept.";
    }
  }
  return null;
}

// The References chain a reply carries: whatever the parent listed, then
// the parent itself (RFC 5322 section 3.6.4).
function _references(message) {
  var refs = [];
  if (typeof message.referencesCsv === "string" && message.referencesCsv.length > 0) {
    refs = message.referencesCsv.split(/[,\s]+/).filter(function (r) { return r.length > 0; });
  }
  if (typeof message.messageId === "string" && message.messageId.length > 0) {
    refs.push(message.messageId);
  }
  return refs;
}

// ---------------------------------------------------------------------
// The application.
// ---------------------------------------------------------------------

/**
 * Build the browser interface.
 *
 * `opts.agent`      the `b.mail.agent` handle every message read and
 *                   every message mutation goes through.
 * `opts.mailbox`    the adapter from `lib/mail/mailbox`, which answers
 *                   which folders an account owns, and which carries a
 *                   whole delete and a whole move through
 *                   `expungeObjects` and `moveObjects`. Every folder
 *                   this surface shows or accepts comes from it.
 * `opts.mailStore`  the `b.mailStore` handle, passed to the JMAP
 *                   listener, which requires the store directly.
 * `opts.store`      the identity layer from `lib/store`: accounts,
 *                   domains, aliases.
 * `opts.compose`    the outbound composer from `lib/mail/compose`.
 * `opts.dkim`       the selector lifecycle from `lib/mail/dkim`.
 * `opts.delivery`   the outbound path from `lib/mail/delivery`, read for
 *                   its spool, its report generator, and its `describe`,
 *                   which is what the health probes ask on every poll to
 *                   report whether mail is still moving.
 * `opts.config`     the resolved configuration, read for `hostname` and
 *                   the well known documents.
 * `opts.listeners`  optional, returns the protocol listener inventory as
 *                   `{ name, state, reason }` rows, where `state` is one
 *                   of `blamepost.mail.listeners.LISTENER_STATES`. This
 *                   is what the health probes report alongside the
 *                   store.
 * `opts.certificateReport`
 *                   optional, returns a `blamepost.certificateReport`
 *                   reading of the pair this server presents. The health
 *                   probes call it on every poll, so a renewal that
 *                   stopped running is reported while there is still time
 *                   to act. Leave it out when no certificate terminates
 *                   in this process.
 *
 * Returns `{ routes, health, jmap, mountJmapWebSocket, engine, render,
 * viewsDir, publicDir }`. Hand `routes` to `b.createApp({ routes })`,
 * and hand each bound HTTP server to `mountJmapWebSocket`: the JMAP
 * WebSocket transport arrives on the server's `upgrade` event rather
 * than through the router, so it is a second mounting step and not a
 * route. `blamepost.web.serve` performs both.
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("blamepost.web.create: opts object is required");
  }
  _requireMethods(opts.agent, "agent", REQUIRED_AGENT);
  _requireMethods(opts.store, "store", REQUIRED_STORE);
  _requireMethods(opts.compose, "compose", REQUIRED_COMPOSE);
  _requireMethods(opts.dkim, "dkim", REQUIRED_DKIM);
  _requireMethods(opts.delivery, "delivery", REQUIRED_DELIVERY);
  if (!opts.mailStore || typeof opts.mailStore.listFolders !== "function") {
    throw new TypeError(
      "blamepost.web.create: opts.mailStore must be a b.mailStore handle " +
      "(compose b.mailStore.create({ backend: b.db }))");
  }
  if (!opts.mailbox || typeof opts.mailbox !== "object" || Array.isArray(opts.mailbox)) {
    throw new TypeError(
      "blamepost.web.create: opts.mailbox must be the adapter from lib/mail/mailbox, the " +
      "one the wire listeners take.");
  }
  // Named together rather than one at a time, because a handle short of
  // more than one of them is a partial adapter and the operator wants
  // the whole list at the boot that refused rather than one name per
  // restart.
  var absentVerbs = REQUIRED_MAILBOX.filter(function (verb) {
    return typeof opts.mailbox[verb] !== "function";
  });
  if (absentVerbs.length > 0) {
    throw new TypeError(
      "blamepost.web.create: opts.mailbox must be the adapter from lib/mail/mailbox, the " +
      "one the wire listeners take, and it is missing: " + absentVerbs.join(", ") + ". " +
      "It holds which folders each account owns, and this surface has no other way to " +
      "find out: the store keeps one flat namespace and the mailbox access agent returns " +
      "all of it. It also owns the folder and UID rows and the sealed message octets, so " +
      "expungeObjects and moveObjects are the only verbs that carry a whole delete and a " +
      "whole move rather than half of one.");
  }
  if (!opts.config || typeof opts.config !== "object") {
    throw new TypeError("blamepost.web.create: opts.config is required");
  }
  if (typeof opts.config.hostname !== "string" || opts.config.hostname.length === 0) {
    throw new TypeError("blamepost.web.create: opts.config.hostname is required");
  }
  if (opts.listeners !== undefined && typeof opts.listeners !== "function") {
    throw new TypeError("blamepost.web.create: opts.listeners must be a function returning the listener table");
  }
  if (opts.certificateReport !== undefined && typeof opts.certificateReport !== "function") {
    throw new TypeError("blamepost.web.create: opts.certificateReport must be a function " +
      "returning a blamepost.certificateReport reading. A function rather than a reading, " +
      "because a reading taken here answers for the certificate this process started with, " +
      "and the certificate an operator's client rewrites every renewal is the one the probe " +
      "has to describe.");
  }

  var agent     = opts.agent;
  var store     = opts.store;
  var composer  = opts.compose;
  var dkim      = opts.dkim;
  var delivery  = opts.delivery;
  var mailStore = opts.mailStore;
  var mailbox   = opts.mailbox;
  var config    = opts.config;
  var listeners = opts.listeners || function () { return []; };
  var log       = b.log.boot("web");
  // Absent when nothing named a certificate on disk, which is the shape
  // behind a proxy that terminates TLS and holds the only copy of the
  // key. The probe answers that it read nothing rather than inventing a
  // verdict, because an absent answer is also what a check that failed to
  // register looks like and a reader cannot tell those apart.
  var certificateReading = opts.certificateReport || null;

  var engine   = b.template.create({ viewsDir: VIEWS_DIR });
  var renderer = b.render.create({ engine: engine });
  var jar      = null;

  // -------------------------------------------------------------------
  // Session lifecycle.
  // -------------------------------------------------------------------

  function _cookieJar() {
    if (jar === null) jar = b.cookies.create({ vault: b.vault });
    return jar;
  }

  function _writeSessionCookie(res, token, expiresAt) {
    _cookieJar().write(res, SESSION_COOKIE, token, {
      httpOnly: true,
      secure:   true,
      sameSite: "Strict",
      path:     "/",
      expires:  new Date(expiresAt).toUTCString(),
    });
  }

  function _clearSessionCookie(res) {
    _cookieJar().clear(res, SESSION_COOKIE, {
      httpOnly: true, secure: true, sameSite: "Strict", path: "/",
    });
  }

  // A session outlives a change of account state, so the account is read
  // again on every request and a suspended or archived one stops being
  // signed in without waiting for its session to expire.
  async function _loadAccount(verifiedSession) {
    if (!verifiedSession || typeof verifiedSession.userId !== "string") return null;
    var account = await store.accounts.get(verifiedSession.userId);
    if (!account || account.status !== "active") return null;
    return account;
  }

  // The actor every agent call carries.
  //
  // `folders` is the account's own folder list when the caller already
  // has it. The move guard takes a destination allowlist off the actor
  // and admits a folder outside it only for an actor claiming an
  // administrative mail scope, and it recognizes no folder this server
  // creates: every account's folders are named by the mailbox adapter,
  // and none of those names is one the guard's own table lists. So a
  // move with no allowlist on the actor is refused, and the allowlist
  // that makes it work is the same list the route resolved the folder
  // against. No administrative scope is ever claimed here: an operator
  // administering this server is not thereby entitled to file mail into
  // somebody else's folder.
  function _actorFor(account, folders) {
    var actor = {
      id:    account.id,
      roles: account.isAdmin === true ? ["admin", "account"] : ["account"],
    };
    if (Array.isArray(folders)) {
      actor.allowedFolders = folders.map(function (folder) { return folder.storeName; });
    }
    return actor;
  }

  // -------------------------------------------------------------------
  // Sending identities.
  //
  // Both surfaces that compose their own outbound mail read the set from
  // here, and here reads it from `permittedAuthors`, so the browser, a
  // JMAP client and the submission port answer to one derivation. What
  // is added is presentation: an id a JMAP client can hold, and a name
  // to show beside the address.
  //
  // The set is read from the store on every request rather than kept on
  // the session, because an alias the operator withdraws should stop
  // being a sending identity at the next message rather than at the next
  // sign in. That is also what makes the Identity state string move
  // without anything having to remember to move it: the state is a
  // digest of the answer, and the answer changed.
  //
  // An account's own identity is named by the account, because that is
  // what it is, and because a client stores the id it was given. Giving
  // the primary identity a new name on an upgrade reads on that client
  // as the identity it sends from having disappeared. An alias is not an
  // account and has no record of its own to be named by, so it carries
  // an id derived from the address.
  //
  // The name beside an alias is the alias itself rather than the account
  // holder's display name. A departmental address may be held by several
  // accounts at once, and a message from it that arrives under one
  // holder's personal name tells the recipient something that is not
  // true about who it came from.
  // -------------------------------------------------------------------

  function _identityIdFor(canonicalAddress) {
    return IDENTITY_ID_PREFIX +
      b.crypto.namespaceHash(IDENTITY_ID_NAMESPACE, canonicalAddress).slice(0, IDENTITY_ID_CHARS);
  }

  // One identity out of a set, by the id a client named, or null. The
  // set is always this account's own, so an id belonging to another
  // account misses here exactly as an id belonging to nobody does, and
  // the answer never says which of the two it was.
  function _identityById(held, id) {
    for (var i = 0; i < held.length; i += 1) {
      if (held[i].id === id) return held[i];
    }
    return null;
  }

  function _identitiesFor(account) {
    var mine = address.parse(account.address);
    var self = mine.ok ? mine.address : "";
    var allowed = permittedAuthors(store, { id: account.id, address: account.address });
    var out = [];
    for (var i = 0; i < allowed.length; i += 1) {
      var isSelf = allowed[i] === self;
      out.push({
        id:      isSelf ? account.id : _identityIdFor(allowed[i]),
        name:    isSelf ? (account.displayName || allowed[i]) : allowed[i],
        address: allowed[i],
        isSelf:  isSelf,
      });
    }
    return out;
  }

  // The author a request asked to write as, resolved against the set.
  //
  // What comes back on success is the entry from the set rather than the
  // bytes that arrived, so the address written into the header is one
  // this server chose. A spelling that folds to a permitted mailbox is
  // accepted and sent in the canonical form, and nothing a request wrote
  // reaches the message.
  //
  // An empty field is a request that expressed no preference, which is
  // every compose form an account holding one address ever posts, and it
  // resolves to that account's own address. An empty SET is a different
  // answer entirely and refuses: a set with nothing in it means there is
  // no address this account may write, and reading that as permission to
  // write its own would be an empty collection acting as a grant.
  function _resolveAuthor(account, written) {
    var allowed = permittedAuthors(store, { id: account.id, address: account.address });
    if (written.length === 0) {
      return allowed.length > 0
        ? { ok: true, address: allowed[0], allowed: allowed, rejected: "" }
        : { ok: false, address: "", allowed: allowed, rejected: account.address };
    }
    var asked = address.parse(written);
    var at = asked.ok ? allowed.indexOf(asked.address) : -1;
    if (at === -1) return { ok: false, address: "", allowed: allowed, rejected: written };
    return { ok: true, address: allowed[at], allowed: allowed, rejected: "" };
  }

  // One row for every refused author, whichever surface refused it.
  //
  // An authenticated caller asking to write as an address it does not
  // hold is the event an operator reads this trail for, and the
  // submission listener already records its own. A browser and a JMAP
  // client refusing the same thing silently would leave that trail
  // showing only the callers who came in over SMTP, which reads as the
  // other two surfaces never being tried.
  //
  // Written through `safeEmit`, which is drop-silent by design: a trail
  // that cannot be written is not a reason to answer a refusal with a
  // server error, and the refusal itself has already been decided.
  function _recordAuthorRefusal(surface, rejected, allowed) {
    b.audit.safeEmit({
      action:   "blamepost.web.author_not_permitted",
      outcome:  "denied",
      actor:    auditActor.current(),
      metadata: {
        surface:        surface,
        rejected:       _echoAuthor(rejected),
        permitted:      _namedIdentities(allowed),
        permittedCount: allowed.length,
      },
    });
  }

  // What a reader is told when the author they posted is not one this
  // account may write. It names the address that was rejected and the
  // ones that would have been accepted, and it says what to do about it,
  // because the case an operator meets first is a shared address that
  // was never delegated rather than an attempt at forgery.
  function _authorRefusal(verdict) {
    if (verdict.allowed.length === 0) {
      return "This message was not sent. " + _echoAuthor(verdict.rejected) + " may not write " +
        "any author address at all, which means it has no mailbox assigned to it yet. " +
        "Ask the operator to assign one.";
    }
    return "This message was not sent. " + _echoAuthor(verdict.rejected) + " is not an " +
      "address this account may write. It may write: " + _namedIdentities(verdict.allowed) +
      ". Ask the operator to add the address as an alias for this account if it should be " +
      "one it can write.";
  }

  function _isAdmin(account) {
    return Boolean(account) && account.isAdmin === true;
  }

  // -------------------------------------------------------------------
  // Shared view scope. Everything a layout needs, on every page.
  // -------------------------------------------------------------------

  function _themeOf(req) {
    var raw = _cookieJar().read(req, THEME_COOKIE);
    return (raw === "light" || raw === "dark") ? raw : "";
  }

  function _noticeOf(req) {
    var code = _str(_queryOf(req).notice, "");
    if (!Object.prototype.hasOwnProperty.call(NOTICES, code)) return null;
    return NOTICES[code];
  }

  function _scope(req, extra) {
    var account = req.user || null;
    var view = {
      csrfToken:   req.csrfToken || "",
      theme:       _themeOf(req),
      notice:      _noticeOf(req),
      account:     account,
      accountName: account ? (account.displayName || account.address) : "",
      isAdmin:     _isAdmin(account),
      hostname:    config.hostname,
      // Where the header link and the error page's way back point. This
      // account's own inbox, looked up rather than spelled out: a folder
      // name written into a template is a second place deciding what an
      // account's folders are called, and the layer that decides it is
      // the mailbox adapter.
      inboxHref:   account ? _inboxPath(account) : "",
      // Where a form post that changes a preference sends the reader
      // back to. The path only, so nothing from the query string is
      // reflected into an attribute, and read through the same helper
      // the route reads the field back with: this is the one place a
      // path arrives off a request rather than being built here, and a
      // request line may open `//host` or `/\host`, both of which a
      // browser follows off site.
      backPath:    b.safeRedirect.resolve(req.pathname, { fallback: "/" }),
    };
    if (extra) {
      var keys = Object.keys(extra);
      for (var i = 0; i < keys.length; i += 1) view[keys[i]] = extra[keys[i]];
    }
    return view;
  }

  function _page(req, res, viewName, data, renderOpts) {
    renderer.html(res, viewName, _scope(req, data), renderOpts);
  }

  function _fail(req, res, status, headline, detail) {
    renderer.html(res, "error", _scope(req, {
      status: status, headline: headline, detail: detail,
    }), { status: status });
  }

  function _back(res, path, notice) {
    res.redirect(_path(notice
      ? path + (path.indexOf("?") === -1 ? "?" : "&") + "notice=" + notice
      : path));
  }

  // Every refusal composed for a person carries a code and a message
  // written for one. Showing that message is the whole point of it, so an
  // operator sees why rather than a generic failure; anything without a
  // code is a defect and is logged rather than shown.
  //
  // Two layers compose such refusals and both are read here. What has to
  // be separated is not which module raised the error but whether anybody
  // wrote it for a reader: a volume that cannot be written raises a
  // message carrying the data directory, the key file naming scheme and
  // the suffix an atomic write appends to its temporary file, and putting
  // that on a page hands out the shape of this server's storage while
  // telling the operator nothing they can act on. Passing the message
  // straight through is how that happens, and it also loses the line
  // below, so the one place the fault could still have been read stays
  // empty.
  //
  // The two layers are read differently because a prefix answers the
  // question for one of them and not for the other.
  //
  // The identity layer's refusals carry `store/<reason>`, and this
  // application is the only thing that files a code under that name:
  // nothing in the vendored tree raises one, so the prefix names an
  // author as well as a namespace and a test on it says what it looks
  // like it says.
  //
  // The signer's carry `dkim/<reason>`, and so do the framework's. A
  // domain refused for its shape comes back naming the framework's own
  // primitive and the option path it holds the argument against, which is
  // not a sentence to put in front of an operator: they cannot pass that
  // argument, and the page would be handing them a name from a layer they
  // never call while the log line below went unwritten. So membership in
  // the set the signer publishes decides it, and the set is what that
  // module throws rather than a list beside it.
  function _refusalText(err, fallback) {
    if (err && typeof err.code === "string" &&
        (err.code.indexOf("store/") === 0 ||
         DKIM_REFUSAL_CODES.indexOf(err.code) !== -1)) {
      return err.message;
    }
    log.error("administration action failed: " + ((err && err.message) || String(err)));
    return fallback;
  }

  // -------------------------------------------------------------------
  // Folder and message reads.
  // -------------------------------------------------------------------

  // The folders this account owns, from the layer that holds the map
  // from an account to its folders. Nothing is filtered afterwards,
  // because the list arrives scoped: `mailbox.accountFolders` resolves
  // the account first and answers with its rows or refuses. The label
  // and the order are the only things added here, and both are
  // presentation.
  //
  // `b.mail.agent.folders` is the call this must never go back to. It
  // takes an actor for its audit trail and its scope check and then
  // returns the store's whole folder table, every account's included.
  function _foldersFor(account) {
    var rows = mailbox.accountFolders({ id: account.id });
    var mine = [];
    for (var i = 0; i < rows.length; i += 1) {
      mine.push({
        name:      rows[i].name,
        storeName: rows[i].storeName,
        label:     _folderLabel(rows[i].role, rows[i].name),
        role:      rows[i].role || "",
        modseqMax: rows[i].modseqMax,
        rank:      _folderRank(rows[i].role),
      });
    }
    mine.sort(function (x, y) {
      if (x.rank !== y.rank) return x.rank - y.rank;
      return x.label.localeCompare(y.label);
    });
    return mine;
  }

  function _findFolder(folders, name) {
    for (var i = 0; i < folders.length; i += 1) {
      if (folders[i].name === name) return folders[i];
    }
    return null;
  }

  // The account's folder carrying one of the RFC 6154 roles. A role is
  // what a server-side decision holds on to; a name is what a request
  // carries and a page shows.
  function _findRole(folders, role) {
    for (var i = 0; i < folders.length; i += 1) {
      if (folders[i].role === role) return folders[i];
    }
    return null;
  }

  // Taking a message out of the bin takes the mark off it too.
  //
  // `\Deleted` says a message is waiting in Trash to be purged, and this
  // surface offers no verb that clears it on its own: filing the message
  // back somewhere is how a reader says they want it. Without this, a
  // message brought back out of Trash sits in the inbox struck through
  // forever, and the next purge of whatever folder it landed in takes it
  // for a message its owner had already given up on.
  async function _clearDeletedOutsideTrash(actor, destination, objectIds) {
    if (destination.role === TRASH_ROLE) return;
    await agent.flag({
      actor: actor, folder: destination.storeName, objectIds: objectIds,
      set: [], unset: ["\\Deleted"],
    });
  }

  // Whether every message identifier a request carried is in the folder
  // that request named.
  //
  // A folder name resolving is only half the question a request asks. A
  // message identifier is the other half, and it is the half a caller
  // can hold without owning anything: identifiers are global to the
  // store, so one taken from anywhere names the same message everywhere.
  //
  // The substrate does not close that on its own. A move and an expunge
  // are scoped by folder underneath, so an identifier from elsewhere
  // simply misses; a flag write is not, so the same identifier lands on
  // whichever message carries it, in whatever folder, for whatever
  // account. Relying on which of the three happens to be scoped is
  // relying on an implementation detail of a layer this one does not
  // own, so every identifier is resolved here before any of them reach
  // the agent.
  //
  // A miss refuses the whole request rather than the identifier that
  // missed. Acting on the rest would answer a caller that mixed one of
  // its own messages with somebody else's, and the difference between
  // the two answers is exactly the fact that the other message exists.
  async function _allInFolder(account, folder, objectIds) {
    var actor = _actorFor(account);
    for (var i = 0; i < objectIds.length; i += 1) {
      var message = await agent.fetch({
        actor: actor, folder: folder.storeName, objectId: objectIds[i],
      });
      if (!message) return false;
    }
    return true;
  }

  // Where a signed in account lands, and where a redirect that means
  // "back to the mailbox" goes. The inbox is the account's own folder
  // carrying the inbox role, so the path is built from a row that
  // account owns rather than from a name this module holds.
  //
  // Every path a page or a redirect carries is built by one of the four
  // below, so `_path` sees each of them once rather than the invariant
  // being restated at every concatenation.
  function _folderPath(folder) {
    return _path("/mail/" + encodeURIComponent(folder.name));
  }

  function _actionPath(folder) {
    return _path(_folderPath(folder) + "/actions");
  }

  function _messagePath(folder, objectId) {
    return _path(_folderPath(folder) + "/" + encodeURIComponent(objectId));
  }

  function _composePath(folder, objectId, mode) {
    return _path("/compose?source=" + encodeURIComponent(objectId) +
      "&folder=" + encodeURIComponent(folder.name) +
      "&mode=" + encodeURIComponent(mode));
  }

  function _inboxPathFrom(folders) {
    var inbox = _findRole(folders, INBOX_ROLE);
    if (inbox) return _folderPath(inbox);
    if (folders.length > 0) return _folderPath(folders[0]);
    return _path("/mail/" + encodeURIComponent(DEFAULT_FOLDER));
  }

  function _inboxPath(account) {
    return _inboxPathFrom(_foldersFor(account));
  }

  // One page of rows ending just below `beforeModseq`, newest first.
  //
  // The store reads forward from a floor and caps the read, so a page is
  // a window chosen below the cursor. Two things decide where: the
  // cursor a reader arrived with, and the folder's own high-water mark
  // when they arrived with none.
  //
  // Those two are not always on the same scale, which is the whole
  // reason the walk below exists. Every ordinary write moves the mark by
  // one; a permanent delete moves it to a wall clock reading instead. So
  // one purge leaves a folder whose mark is around a trillion and whose
  // rows are still numbered in the hundreds, and every window sized
  // downward from the mark lands in the gap between them and comes back
  // empty. That is the folder reading as though it held nothing, over
  // the browser and over JMAP alike, for mail that is still there.
  async function _pageBefore(account, folder, beforeModseq, filter) {
    var actor = _actorFor(account);
    // A cursor above everything the folder holds is not a cursor into
    // it, so it reads as the newest page. Left as sent it would also be
    // a way to ask for the walk below on a folder that does not need
    // one, which is a handful of reads a request should not be able to
    // order up.
    var top = folder.modseqMax + 1;
    var ceiling = beforeModseq > 0 && beforeModseq < top ? beforeModseq : top;

    async function _window(floor) {
      var query = { sinceModseq: floor, limit: WINDOW_CAP };
      if (filter) {
        var fkeys = Object.keys(filter);
        for (var fi = 0; fi < fkeys.length; fi += 1) query[fkeys[fi]] = filter[fkeys[fi]];
      }
      var result = await agent.search({
        actor: actor, folder: folder.storeName, filter: query, limit: WINDOW_CAP,
      });
      return Array.isArray(result.rows) ? result.rows : [];
    }

    // The newest rows of a window that sit below the cursor, newest
    // first, and one more than a page so the caller knows there is one.
    function _keep(rows) {
      var out = [];
      for (var i = rows.length - 1; i >= 0 && out.length < PAGE_SIZE + 1; i -= 1) {
        if (rows[i].modseq >= ceiling) continue;
        out.push(rows[i]);
      }
      return out;
    }

    // Downward from the cursor. A folder whose numbers run without a gap
    // fills a page on the first read, which is what this is for.
    var kept = [];
    var floor = 0;
    var span = FIRST_PAGE_SPAN;
    for (var probe = 0; probe < MAX_PAGE_PROBES; probe += 1) {
      floor = ceiling - span > 0 ? ceiling - span : 0;
      kept = _keep(await _window(floor));
      if (kept.length > PAGE_SIZE || floor === 0) break;
      span = span * 4;
    }

    // Upward from the bottom, when the descent found nothing at all. A
    // window that comes back short is the end of the folder, so the last
    // one cannot be guessed wrong. It costs one read per `WINDOW_CAP`
    // rows and runs only for a folder whose numbers have the gap above
    // in them.
    //
    // The window before the last one is carried along, because the last
    // one holds however many rows the folder's count happened to leave
    // over. A folder of a thousand and thirty messages ends on a window
    // of thirty, and a page taken from that alone is thirty rows: not an
    // empty folder any more, but still the read's arithmetic showing
    // through rather than a page.
    if (kept.length === 0 && floor > 0) {
      floor = 0;
      var earlier = [];
      for (var step = 0; step < MAX_PAGE_WALK; step += 1) {
        var window = await _window(floor);
        if (window.length === 0) break;
        kept = _keep(earlier.concat(window));
        if (window.length < WINDOW_CAP) break;
        earlier = window;
        floor = window[window.length - 1].modseq;
      }
    }

    var hasOlder = kept.length > PAGE_SIZE;
    if (hasOlder) kept = kept.slice(0, PAGE_SIZE);
    return {
      rows:      kept,
      hasOlder:  hasOlder || floor > 0,
      olderThan: kept.length > 0 ? kept[kept.length - 1].modseq : 0,
    };
  }

  // Row projection. Subject and addresses live in sealed columns, so a
  // list row is a fetch per message rather than a column on the index.
  async function _summarize(account, folder, rows) {
    var actor = _actorFor(account);
    var out = [];
    for (var i = 0; i < rows.length; i += 1) {
      var message = await agent.fetch({
        actor: actor, folder: folder.storeName, objectId: rows[i].objectid,
      });
      if (!message) continue;
      var flags = Array.isArray(message.flags) ? message.flags : [];
      out.push({
        objectId:  message.objectid,
        subject:   _headerText(_str(message.subject, "(no subject)")),
        from:      _displayName(message.from),
        fromAddr:  _bareAddress(message.from),
        initial:   _initial(message.from),
        preview:   _preview(message.bodyText, 140),
        received:  _when(message.internalDate || message.receivedAt,
          { dateStyle: "medium", timeStyle: "short" }),
        sizeLabel: _byteSize(message.sizeBytes),
        unread:    flags.indexOf("\\Seen") === -1,
        flagged:   flags.indexOf("\\Flagged") !== -1,
        answered:  flags.indexOf("\\Answered") !== -1,
        deleted:   flags.indexOf("\\Deleted") !== -1,
        legalHold: message.legalHold === true,
        href:      _messagePath(folder, message.objectid),
      });
    }
    return out;
  }

  // -------------------------------------------------------------------
  // Middleware chain. Mounted here rather than assumed from the caller,
  // so the posture travels with the routes.
  // -------------------------------------------------------------------

  // The CSRF waiver is the framework's option again, rather than a
  // predicate this file owns.
  //
  // Why it exists at all: a caller holding no cookie has no ambient
  // credential for a page on another site to spend, which is the whole of
  // what CSRF is, and it was never issued a token to send back. The JMAP
  // bearer path is that caller. Asking it for a token is an outage rather
  // than a defense, so the waiver has to reach it.
  //
  // Why it was decided here for a while: the option also fired on an
  // `Authorization` header, reading its PRESENCE and never its value. This
  // application resolves a session from the cookie BEFORE the header, so a
  // request carrying a live session cookie and any Authorization header at
  // all was authenticated by exactly the ambient credential the gate
  // protects, and was waived by a value that authenticates nothing. A
  // literal `Bearer not-a-real-token` bought a cross origin write. Worse,
  // the branch sat above the origin cross-check, so a waived request
  // skipped that too.
  //
  // The option tests the absence of a Cookie header now, and nothing else,
  // and it sits below the origin cross-check so `checkOrigin` is never
  // waived by it. That is the rule the local predicate was written to
  // express, and it holds one line further than the predicate did: a
  // cookieless caller from another origin is refused rather than let
  // through. So the predicate is gone rather than kept beside an option
  // that now says the same thing better. Two spellings of one rule drift,
  // and the one that would drift here is a security decision.
  function _mountSecurity(router) {
    router.use(b.middleware.requestId());
    router.use(b.middleware.securityHeaders());
    router.use(b.middleware.botGuard());
    router.use(b.middleware.cookies());
    router.use(b.middleware.cspNonce({ directives: ["script-src", "style-src"] }));
    router.use(b.middleware.fetchMetadata());
    router.use(b.middleware.bodyParser());
    router.use(b.middleware.csrfProtect({
      cookie:        true,
      checkOrigin:   true,
      skipStateless: true,
    }));
    router.use(b.middleware.attachUser({
      cookieName: SESSION_COOKIE,
      tokenFrom:  "both",
      userLoader: _loadAccount,
    }));
    // After the session has been read, because the account it resolves
    // is the identity every row this request causes will name, and
    // before any route, because the rows are written several calls
    // further in. The scope is bound for the rest of this request
    // rather than around a callback: the router runs its middleware to
    // completion and then runs the route, so a scope that closed when
    // this returned would close before the handler that needs it ran.
    //
    // A request with no session still opens one. The identity is absent
    // and the peer is not, and where a refusal came from is the whole
    // of what a refusal is read for.
    router.use(function (req, res, next) {
      auditActor.enterAs(auditActor.forRequest(req));
      next();
    });
    router.use(b.middleware.noCache({
      when: function (req) { return req.pathname.indexOf("/static/") !== 0; },
    }));
  }

  var requireAccount = b.middleware.requireAuth({ redirectTo: "/sign-in" });

  // The console's own reading of the session, under the device binding
  // the session was minted with.
  //
  // Signing in hands `b.session.create` the request, which folds the
  // client address, the user agent and the accepted language into a
  // hash stored on the session row. Every verify that is given a
  // request recomputes that hash and compares it, and
  // `requireFingerprintMatch` is what turns the comparison into a
  // refusal. The reader in the request lifecycle above does not set it,
  // so a session whose device has changed still resolves an account
  // there, and the drift is recorded rather than acted on.
  //
  // That split is the decision. The binding this framework computes
  // covers the full client address, and the lifecycle reader cannot
  // narrow it: `b.middleware.attachUser` takes no `fingerprintFields`
  // and passes none to `verify`, so the only binding reachable through
  // it is address, agent and language together. A mailbox owner reading
  // mail in a browser on a phone that moves between wifi and a cell
  // network changes address without doing anything unusual, and a
  // mailbox that signs them out for it signs them out several times a
  // day.
  //
  // The console is where that trade runs the other way. The accounts
  // that reach it host domains, mint and retire signing keys, drop
  // queued mail and read every mailbox owner's address, and they are
  // few and mostly sitting at one machine. An operator signing in again
  // after a network change spends a password. A session cookie that
  // administers this server from whatever machine it was copied to
  // spends the server.
  //
  // The reader is composed rather than written here so the token is
  // found the same way the lifecycle reader finds it, the cookie first
  // and then the `Authorization` header. A gate reading only the cookie
  // is walked past by moving the same token into a header.
  var consoleSession = b.middleware.attachUser({
    cookieName:              SESSION_COOKIE,
    tokenFrom:               "both",
    userLoader:              _loadAccount,
    requireFingerprintMatch: true,
  });

  // The console gate, and the row it files when it turns somebody away.
  //
  // A refusal that records nothing is a refusal nobody can review
  // afterwards, and this is the one an incident is reconstructed from: an
  // account holding no operator role asking to archive a mailbox, host a
  // domain, rotate a signing key, drop a queued message or release
  // somebody else's sign-in budget is the whole of what an auditor is
  // looking for. The framework's own session gate already records
  // `auth.required.denied` for a caller carrying no session at all, so a
  // console that recorded nothing here would leave the trail showing the
  // strangers and not the account that signed in and then went looking.
  //
  // Which verb was refused, because "the console" is not something an
  // operator can act on. The path is safe to record unbounded: this
  // middleware runs only after the router has matched one of the console
  // routes, so what reaches the row is one of the fixed strings the route
  // table names rather than anything a caller composed.
  //
  // Written through `safeEmit`, which is drop-silent by design: a trail
  // that cannot be written is not a reason to answer a refusal with a
  // server error, and the refusal itself has already been decided.
  async function requireAdmin(req, res, next) {
    if (_isAdmin(req.user)) {
      // The strict read, for an account that holds the role. It writes
      // nothing to the response and always calls the callback it is
      // given, so the only thing to read afterwards is what it left on
      // the request: the account again when the session still matches
      // the device it was opened on, and null when it does not.
      //
      // A rejection resolves this too. The reader clears `req.user`
      // before it does anything else, so a throw leaves the request
      // carrying no account and arrives at the refusal below. Waiting
      // on a callback that a rejected read never reaches would hang the
      // request instead, which is a worse answer than refusing it.
      await new Promise(function (resolve) {
        consoleSession(req, res, resolve).catch(resolve);
      });
      if (req.user === null) {
        b.audit.safeEmit({
          action:   "blamepost.web.console_device_refused",
          outcome:  "denied",
          actor:    auditActor.current(),
          metadata: { method: req.method, path: req.pathname },
        });
        // What the reader is told names no part of the binding. An
        // operator turned away here has to know to sign in again, and a
        // reader told which of the three signals differed has been
        // handed the one to carry next time.
        //
        // The session row is not deleted. This refusal asks for the
        // password again; it does not end the session, so a stranger
        // sending a copied cookie cannot sign the operator out by
        // trying, and the mailbox this account reads stays open.
        _fail(req, res, 401, "Sign in again for the console",
          "The console is held to the machine and browser it was opened on, and this " +
          "request is not coming from them. Sign in again here and it opens. Your mail is " +
          "untouched and still open.");
        return;
      }
    }
    // Reached with the role confirmed twice, or without it at all. The
    // second reading loads the account again, so a role taken away
    // between the two arrives here as an account that no longer
    // administers rather than as a session that no longer matches.
    if (_isAdmin(req.user)) return next();
    b.audit.safeEmit({
      action:   "blamepost.web.console_not_permitted",
      outcome:  "denied",
      actor:    auditActor.current(),
      metadata: { method: req.method, path: req.pathname },
    });
    _fail(req, res, 403, "Not your console",
      "This account does not administer this server. Ask the operator for the role.");
  }

  // The bound in front of the sign in form. Its size and the reason for
  // it are at SIGN_IN_POSTS_PER_WINDOW; what is decided here is which
  // shape of bound keeps it.
  //
  // The algorithm is named because the framework has two and they read
  // DIFFERENT options. The token bucket, which is what a caller that
  // says nothing gets, takes `burst` and `refillPerSecond` and never
  // looks at `max` or `windowMs`; the fixed window takes the pair
  // written here. Both names pass the primitive's own option check, so a
  // limiter that leaves the algorithm out constructs cleanly, advertises
  // the bucket's defaults, and enforces a ceiling nobody chose while the
  // two numbers beside it are read by nothing.
  //
  // The window is the right shape for this route rather than the
  // default being wrong in general. A bucket is built to smooth bursty
  // traffic: it refuses, then hands a token back a tenth of a second
  // later, so a client that is refused and retries carries on at the
  // refill rate. That is correct for an API somebody is polling and
  // wrong here, where the answer to a refusal has to be a wait the
  // reader actually serves. A window says the same thing to the person
  // who mistyped their password and to the script: come back when this
  // one is over. The tradeoff a window carries is the burst at its
  // boundary, worst case twice the ceiling inside one window, and at
  // this size that is still a rate this server absorbs.
  //
  // `per-route` is the scope, which is how the framework spells "keep
  // this count against the route as well as the peer". It takes exactly
  // two values and treats everything else as the global default, so a
  // name invented to describe the budget reads as no scope at all. What
  // it buys is the key: the count is filed under the method, the path
  // and the peer together, and that key is what reaches the
  // `system.ratelimit.block` row an operator reads during an incident.
  // A row naming the peer alone says a machine was refused somewhere,
  // which is not something to act on, and this server bounds more than
  // one route.
  var signInLimit = b.middleware.rateLimit({
    algorithm: "fixed-window",
    max:       SIGN_IN_POSTS_PER_WINDOW,
    windowMs:  SIGN_IN_WINDOW_MS,
    scope:     "per-route",
  });

  // -------------------------------------------------------------------
  // Health. What a container check, an orchestrator and a reverse proxy
  // all poll, and they are not asking the same question.
  //
  // Liveness answers "is this process worth keeping", and an orchestrator
  // acts on a failure by KILLING it. Readiness answers "should traffic
  // come here", and a load balancer acts on a failure by routing
  // elsewhere. Conflating them is how a condition that no restart can
  // fix turns into a restart loop.
  //
  // Nothing about the listeners is critical on liveness for exactly that
  // reason. A port another process is holding is still held after a
  // kill; a server with no domain hosted still has none; and in both
  // cases the restart takes down the browser surface that was the
  // operator's way of reading why. Readiness is the lever that fits:
  // stop sending traffic, leave the process up and answering.
  // -------------------------------------------------------------------

  var health = b.middleware.health({
    livenessPath:  "/healthz",
    readinessPath: "/readyz",
    startupPath:   "/startupz",
    detailLevel:   "minimal",
    includeMeta:   true,
    // A probe that reports a reduced verdict and no reason for it leaves
    // an operator a failing streak and nothing to act on, which is the
    // same amount of help as no probe at all. So the breakdown is
    // answered to the reader who has that failure in front of them: the
    // container's own health check, which polls this endpoint from
    // inside the container over the loopback interface.
    //
    // Everyone else gets the verdict alone. This endpoint is mounted on
    // the same port as the browser surface, so it is reachable from
    // wherever webmail is, and a per-check breakdown of what a mail
    // server is running is not something to hand out there.
    //
    // The peer is the TCP peer and not a forwarded header:
    // `b.requestHelpers.clientIp` with no options reads only
    // `req.socket.remoteAddress` and ignores `X-Forwarded-For`, which
    // whoever connects can write for themselves. A predicate that throws
    // is read as false by the framework, so the closed answer is also
    // what a surprise produces.
    detailPredicate: function (req) {
      return b.ssrfGuard.isLoopback(b.requestHelpers.clientIp(req));
    },
    // The build's own version, not a setting. What answers a health poll
    // has to be what is running, and a configurable string here would
    // let a stale value outlive the upgrade it was meant to report.
    version:       pkg.version,
  });

  health.registerCheck("mail-store", function () {
    var folders = mailStore.listFolders();
    return { ok: Array.isArray(folders), folders: Array.isArray(folders) ? folders.length : 0 };
  }, { tier: ["liveness", "readiness"], critical: true });

  // The listener inventory, sorted into the states it reports.
  //
  // `null` rather than an empty grouping when the table cannot be read
  // or carries a state this application does not know, and both checks
  // below report that as their own failure. No rows and no answer are
  // different facts: an empty grouping satisfies every question asked of
  // it below, so a table nobody could parse would read as a server with
  // nothing wrong.
  function _listenerStates() {
    var table = listeners();
    if (!Array.isArray(table)) return null;
    var sorted = { bound: [], withheld: [], unbound: [], disabled: [] };
    for (var i = 0; i < table.length; i += 1) {
      var row = table[i];
      if (!row || typeof row.name !== "string") return null;
      if (!Object.prototype.hasOwnProperty.call(sorted, row.state)) return null;
      sorted[row.state].push(row);
    }
    return sorted;
  }

  function _names(rows) {
    return rows.map(function (row) { return row.name; });
  }

  // Did anything that was supposed to take a port fail to?
  //
  // This is the failure, and it is the only one here. Critical on
  // readiness, because traffic aimed at a port nothing holds is the
  // thing this probe exists to prevent.
  function _listenersBound() {
    var sorted = _listenerStates();
    if (sorted === null) {
      return { ok: false, error: "the listener inventory could not be read" };
    }
    return {
      ok:       sorted.unbound.length === 0,
      bound:    sorted.bound.length,
      unbound:  _names(sorted.unbound),
      disabled: _names(sorted.disabled),
    };
  }

  // Is this server holding a listener shut on purpose?
  //
  // Never critical, on either probe: it is not a fault, and a server in
  // this state is serving everything else it has. It is still the reason
  // mail is not arriving, so it is not silence either. A failing
  // non-critical check is what the framework reports as degraded, which
  // is an answer both an operator and a monitoring system can act on
  // without either being told the server is down.
  function _listenersWithheld() {
    var sorted = _listenerStates();
    if (sorted === null) {
      return { ok: false, error: "the listener inventory could not be read" };
    }
    return {
      ok:       sorted.withheld.length === 0,
      withheld: sorted.withheld.map(function (row) {
        return { name: row.name, reason: row.reason };
      }),
    };
  }

  // What this server would present at a handshake, read rather than
  // assumed.
  //
  // Nothing else on either probe can see it. The listeners stay bound,
  // the store stays open and the verdict stays clean for as long as the
  // process runs, so a renewal that stopped running three weeks ago is
  // invisible from every angle until the morning every peer stops talking
  // to this server at once. The pair on disk is the one fact that says so
  // in advance, and it is read on every probe rather than once: a reading
  // taken when this server started answers for the certificate it started
  // with, which is precisely the one that is no longer there.
  //
  // Never critical, on either probe, whatever it finds, because all three
  // levers available make a certificate fault worse. A failing liveness
  // check asks a runtime to restart the process, and this server refuses
  // to boot on a pair it could not present, so the restart ends it rather
  // than repairing it. A failing readiness check withdraws the browser
  // surface, which is both where an operator reads which of the two files
  // went wrong and the one part of this server a certificate fault leaves
  // working: behind a proxy that terminates TLS, the cleartext port
  // serves exactly as before. What is left is the reduced verdict, which
  // is what a monitoring system alerts on and what leaves the operator a
  // server to fix it from.
  //
  // So a certificate inside its renewal window and one that has already
  // run out reach the same verdict deliberately, and the answer separates
  // them rather than the verdict: `expiresInDays` has gone negative on
  // the second, and `usable` is false from the moment no context could be
  // built out of the pair at all, which is the same reading that stops a
  // boot.
  function _certificate() {
    if (certificateReading === null) return { ok: true, read: false };
    var report;
    try { report = certificateReading(); }
    catch (err) {
      return { ok: false, read: false, error: (err && err.message) || String(err) };
    }
    // No findings and no answer are different facts, and an empty list
    // satisfies every question below, so a reading nobody could take
    // would otherwise report a certificate with nothing wrong.
    if (!report || !Array.isArray(report.findings) || report.findings.length === 0) {
      return { ok: false, read: false, error: "the certificate could not be read" };
    }
    var faults = [];
    var usable = true;
    for (var i = 0; i < report.findings.length; i += 1) {
      var finding = report.findings[i];
      if (finding.fatal === true) usable = false;
      // A finding that passed and still carries a severity is the
      // renewal window: serviceable today, and already past the point a
      // certificate client should have replaced it. That is a fault to
      // report rather than a reading to pass over.
      if (finding.ok !== true || finding.severity !== undefined) {
        if (faults.indexOf(finding.check) === -1) faults.push(finding.check);
      }
    }
    return {
      ok:            faults.length === 0,
      read:          true,
      usable:        usable,
      expiresInDays: typeof report.expiresInDays === "number" ? report.expiresInDays : null,
      faults:        faults,
    };
  }

  // Is mail still moving?
  //
  // Every other check on both probes answers about something that is
  // STILL THERE: the store is open, the ports are held, the pair on disk
  // is presentable. A server can pass all of that while the outbound
  // spool fills and nothing leaves it, and from outside that server is
  // indistinguishable from a healthy one until somebody asks why their
  // message never arrived. The spool is the one place the difference is
  // written down.
  //
  // What is NOT a fault is the hard part, and getting it wrong in the
  // noisy direction produces an alert operators learn to ignore, which is
  // worse than no alert. A queue with mail in it is a working mail
  // server: a peer down for an hour is ordinary, and RFC 5321 section
  // 4.5.4.1 has a sender retrying for days before it gives up. So depth
  // alone says nothing, and neither does age.
  //
  // Three readings, each a way for mail to STOP rather than a way for it
  // to be slow:
  //
  //   - The spool has filled past the depth at which it stops taking
  //     mail for forwarding. That number is not a threshold invented
  //     here: it is the reservation `_admitToSpool` already applies, so
  //     crossing it means this server has begun refusing mail it would
  //     otherwise have taken and the operator's own account holders are
  //     next. It also recovers, which the alternative reading of the
  //     same fault does not.
  //   - Mail is waiting and nothing is draining it. The sweep is armed
  //     before the browser surface binds and disarmed after it stops, so
  //     a disarmed sweep on a server that is answering a probe has no
  //     benign reading. Guarded on there being mail, because a drain
  //     with nothing to drain has moved no mail and lost none.
  //   - This build cannot put a message on the wire at all, in which
  //     case every message reaching the spool stays there by
  //     construction. Structural rather than traffic-shaped, so it never
  //     over-reports.
  //
  // `refused` is reported and is deliberately NOT one of them. It counts
  // envelopes this spool turned away since the process started, so it
  // only ever climbs: a check resting on it would go reduced at the first
  // refusal and stay there until a restart, whatever happened to the
  // queue afterwards. A signal that cannot recover is the same failure as
  // a signal that never fires.
  //
  // No mail waiting is not the same as no queue. An empty spool is a
  // clean answer with `read` true; an answer this reader could not take
  // reports `read` false and fails, because otherwise a delivery handle
  // that stopped answering would read as a mail server with nothing
  // wrong. Unlike the certificate there is no third case: the delivery
  // handle is required at construction, so a queue that is absent is a
  // wiring fault rather than a deployment shape.
  function _queue() {
    var report;
    try { report = delivery.describe(); }
    catch (err) {
      return { ok: false, read: false, error: (err && err.message) || String(err) };
    }
    var spool = report && report.spool;
    var reserved = spool && spool.forwarding;
    if (!spool || !reserved || typeof spool.messages !== "number" ||
        typeof reserved.maxMessages !== "number") {
      return { ok: false, read: false, error: "the outbound queue could not be read" };
    }
    // `spool.messages` rather than the `waiting` the same answer also
    // publishes, even though the two count the same files. It is the one
    // the spool COMPARES against the ceiling when it decides whether to
    // take a message, so reading it is reading the decision rather than a
    // second opinion about it, and the number reported is then the number
    // the verdict was reached on rather than a near neighbor of it.
    var waiting   = spool.messages;
    var transport = report.wireDelivery !== null &&
      typeof report.wireDelivery === "object" &&
      report.wireDelivery.available === true;
    var draining  = report.sweeping === true;

    var faults = [];
    if (!transport) faults.push("outbound transport");
    if (!draining && waiting > 0) faults.push("queue drain");
    if (waiting >= reserved.maxMessages) faults.push("queue depth");
    if (typeof spool.bytes === "number" && typeof reserved.maxBytes === "number" &&
        spool.bytes >= reserved.maxBytes) {
      faults.push("queue bytes");
    }
    return {
      ok:                faults.length === 0,
      read:              true,
      waiting:           waiting,
      forwardingStopsAt: reserved.maxMessages,
      draining:          draining,
      transport:         transport,
      refused:           typeof spool.refused === "number" ? spool.refused : 0,
      faults:            faults,
    };
  }

  // Registered per tier rather than across both, because the verdict is
  // the same on each and only what should be done about it differs.
  health.registerCheck("listeners", _listenersBound,
    { tier: "readiness", critical: true });
  health.registerCheck("listeners", _listenersBound,
    { tier: "liveness", critical: false });
  health.registerCheck("listeners-withheld", _listenersWithheld,
    { tier: ["liveness", "readiness"], critical: false });
  health.registerCheck("certificate", _certificate,
    { tier: ["liveness", "readiness"], critical: false });
  // Never critical, on either probe, and each tier says no for its own
  // reason rather than by analogy with the certificate above it.
  //
  // A restart does not drain a queue. The spool is files under
  // `queue/` on the data volume and every descriptor is read back on the
  // next boot exactly as it was written, which is what lets a transient
  // failure survive a restart in the first place. So a failing liveness
  // check would ask a runtime to kill a process, and the process that
  // comes back finds the identical pile, having additionally abandoned
  // whatever attempts were in flight so they are tried again from the
  // beginning. Where the cause is the transport, the restart reproduces
  // it exactly, because that is a property of the build. A restart loop
  // over a stuck queue is strictly worse than leaving it alone.
  //
  // Readiness is the wrong lever for a different reason, and a stronger
  // one. It moves traffic away from this port, and this port is not what
  // fills the spool: the MX and submission listeners are the ones taking
  // mail, on ports of their own, and they go on taking it whatever a
  // proxy decides about the HTTP one. What withdrawing this port DOES
  // reach is the administration console, which is where an operator
  // reads what is waiting and why and cancels what is never going to
  // leave. So the refusal would cost the operator the only surface that
  // can fix the fault and would not reduce the queue by one message.
  // There is nowhere to route to either: one process owns the data
  // volume at a time, so there is no second instance behind a balancer
  // waiting to take the traffic.
  //
  // What is left is the reduced verdict, which is what a monitoring
  // system alerts on and what leaves the operator a server to act from.
  health.registerCheck("queue", _queue,
    { tier: ["liveness", "readiness"], critical: false });

  // -------------------------------------------------------------------
  // JMAP. Mounted inside this application, on this port, with every
  // method routed through the agent so the retention floor and the legal
  // hold refusals hold for a JMAP client exactly as they do for IMAP.
  // -------------------------------------------------------------------

  function _actorId(actor) {
    if (actor && typeof actor === "object" && typeof actor.id === "string") return actor.id;
    return String(actor);
  }

  async function _jmapAccount(actor) {
    var account = await store.accounts.get(_actorId(actor));
    if (!account) throw new Error("accountNotFound");
    return account;
  }

  // The state string a JMAP answer carries.
  //
  // RFC 8620 section 5.1 asks for a string that changes when the objects
  // change and stays the same when they do not, which is what lets a
  // client cache and what a later `/changes` method would compare
  // against. A wall clock reading satisfies neither half: it moves when
  // nothing has happened, so every answer invalidates the client's copy,
  // and two answers inside the same millisecond share a state while the
  // mail between them does not. It can also step backwards, which tells
  // a client the mailbox has been rewound.
  //
  // The store already keeps the numbers this wants. Folder modseq only
  // ever climbs and advances on an arrival, a flag change and a move
  // alike, so the account's folder counters move on exactly the events a
  // state string is supposed to track.
  //
  // What they do not do is move together. RFC 7162 gives every mailbox
  // its own counter, so a folder holding one message sits at one while
  // the inbox sits in the thousands, and a change in the quiet folder
  // moves its counter and no other. A state taken from the HIGHEST of
  // them therefore stands still through every change outside the busiest
  // folder: the client is not failing to refetch, it has been told there
  // is nothing to refetch, and it goes on showing keywords that were
  // cleared and mail in a folder it has left.
  //
  // The total moves on all of them. Every mutation raises at least one
  // counter by at least one and none of them ever falls, so the total
  // rises on every change, holds still when nothing happens, and never
  // returns to a reading a client has already cached.
  function _accountState(folders) {
    var total = 0;
    for (var i = 0; i < folders.length; i += 1) {
      var seen = typeof folders[i].modseqMax === "number" ? folders[i].modseqMax : 0;
      total += seen;
    }
    return String(total);
  }

  // The state string an Identity answer carries.
  //
  // An identity has no counter behind it. It is read off the account
  // record, which carries nothing an answer could quote as a revision,
  // so the state is the content the client was handed, reduced to a
  // fixed width: it differs whenever anything in that content differs
  // and it is the same string for the same identities, which is both
  // halves of what RFC 8620 section 5.1 asks of a state.
  //
  // A digest rather than the content itself, because that section calls
  // the string opaque and a client is entitled to log it, put it in a
  // URL and hand it back as a token. A mailbox owner's name does not
  // belong in a field nothing downstream treats as data.
  //
  // Deriving it from the account's own timestamp would put a clock back
  // into an answer this file took one out of: two edits inside a
  // millisecond share a reading, and the second would never reach a
  // client that had already cached the first.
  function _identityState(list) {
    return b.crypto.sha3Hash(b.canonicalJson.stringify(list)).slice(0, IDENTITY_STATE_CHARS);
  }

  // -------------------------------------------------------------------
  // Push. One hook, both channels.
  //
  // RFC 8620 section 7.3 and RFC 8887 section 5 are two transports over
  // one question, and the framework asks it in one place:
  // `mailStore.subscribePush(actor, dataTypes, emit)`. The event source
  // handler and the WebSocket handler both call it, so wiring it once
  // lights both, and leaving it unwired leaves both refusing with
  // `serverUnavailable` while the session document goes on advertising
  // them.
  //
  // The account a subscription watches comes off the authenticated
  // actor and never off the frame the client sent. `dataTypes` is the
  // only thing a client chooses here, and all it can do is narrow what
  // it is told about its own mailbox.
  //
  // The state a subscription reports is `_accountState`, the same
  // string every JMAP answer carries, because a push carrying a value
  // the API does not agree with is a notification a client cannot act
  // on: it refetches, reads a different state, and concludes nothing
  // changed.
  // -------------------------------------------------------------------

  var pushWatchers = new Map();
  var pushSweeper  = null;

  // The account's current state, or null when it cannot be read. The
  // adapter refuses a folder list for an account that no longer exists,
  // and a subscription outliving its account is a channel with nothing
  // left to say rather than an error to raise at a client that has
  // already lost its session.
  function _pushStateOf(accountId) {
    try { return _accountState(_foldersFor({ id: accountId })); }
    catch (_e) { return null; }
  }

  // The event a subscription is sent, or null when the types it asked
  // for do not include any this server tracks. Null rather than an
  // event carrying an empty type map, because RFC 8620 section 7.4
  // reads that map as the list of what changed, and a client handed an
  // empty one is being woken to be told nothing.
  function _pushEvent(accountId, state, dataTypes) {
    var types = {};
    var named = 0;
    for (var i = 0; i < PUSH_DATA_TYPES.length; i += 1) {
      if (dataTypes !== null && dataTypes.indexOf(PUSH_DATA_TYPES[i]) === -1) continue;
      types[PUSH_DATA_TYPES[i]] = state;
      named += 1;
    }
    if (named === 0) return null;
    var changed = {};
    changed[accountId] = types;
    return { kind: "StateChange", changed: changed };
  }

  // One sweep across every account somebody is listening to. A listener
  // that throws is contained: a browser tab that went away mid write
  // must not take the other subscribers' channel down with it.
  function _pushSweep() {
    pushWatchers.forEach(function (watch, accountId) {
      var now = _pushStateOf(accountId);
      if (now === null || now === watch.state) return;
      watch.state = now;
      watch.listeners.forEach(function (listener) {
        var event = _pushEvent(accountId, now, listener.dataTypes);
        if (event === null) return;
        try { listener.emit(event); }
        catch (err) {
          log.error("a JMAP push subscriber for account " + accountId + " threw: " +
            ((err && err.message) || String(err)));
        }
      });
    });
  }

  // The sweeper runs only while somebody is subscribed, and its timer
  // is unreferenced, so an idle process is not held open by a channel
  // nobody is reading.
  function _pushSweeperUp() {
    if (pushSweeper !== null) return;
    pushSweeper = b.safeAsync.repeating(_pushSweep, PUSH_SWEEP_MS, {
      name:    "blamepost-jmap-push",
      onError: function (err) {
        log.error("the JMAP push sweep threw: " + ((err && err.message) || String(err)));
      },
    });
  }

  function _pushSweeperDown() {
    if (pushSweeper === null || pushWatchers.size > 0) return;
    pushSweeper.stop();
    pushSweeper = null;
  }

  function _subscribePush(actor, dataTypes, emit) {
    var accountId = _actorId(actor);
    if (typeof accountId !== "string" || accountId.length === 0) {
      throw new TypeError("blamepost.web: a push subscription needs an authenticated actor");
    }
    if (typeof emit !== "function") {
      throw new TypeError("blamepost.web: a push subscription needs an emit callback");
    }
    // A wildcard arrives as null from both handlers. A list naming
    // nothing this server pushes narrows to nothing, which is a client
    // asking for silence rather than an error.
    var wanted = Array.isArray(dataTypes) ? dataTypes.slice() : null;
    var watch = pushWatchers.get(accountId);
    if (watch === undefined) {
      // Seeded with the state as it stands, so a subscription reports
      // the next change rather than replaying the account's whole
      // history as one event the moment it opens.
      watch = { state: _pushStateOf(accountId), listeners: new Set() };
      pushWatchers.set(accountId, watch);
    }
    var listener = { dataTypes: wanted, emit: emit };
    watch.listeners.add(listener);
    _pushSweeperUp();

    return function unsubscribe() {
      var held = pushWatchers.get(accountId);
      if (held === undefined) return;
      held.listeners.delete(listener);
      if (held.listeners.size === 0) pushWatchers.delete(accountId);
      _pushSweeperDown();
    };
  }

  function _jmapMailbox(folder) {
    return {
      id:        folder.name,
      name:      folder.label,
      role:      folder.role || null,
      parentId:  null,
      sortOrder: folder.rank,
      myRights: {
        mayReadItems: true, mayAddItems: true, mayRemoveItems: true,
        maySetSeen: true, maySetKeywords: true, mayCreateChild: false,
        mayRename: false, mayDelete: false, maySubmit: true,
      },
    };
  }

  // One keyword as a flag this server keeps, or null when the keyword
  // names something a JMAP client may not set. Null is a refusal the
  // caller turns into a `SetError`: a keyword quietly discarded is a
  // client told its message carries a mark it does not, and a keyword
  // quietly widened is a client reaching a flag its protocol never
  // exposed to it.
  function _flagForKeyword(rawKeyword) {
    var keyword = String(rawKeyword).toLowerCase();
    if (keyword.length === 0 || keyword.length > MAX_KEYWORD_CHARS) return null;
    if (JMAP_UNEXPOSED_KEYWORDS.indexOf(keyword) !== -1) return null;
    if (Object.prototype.hasOwnProperty.call(JMAP_KEYWORD_FLAG, keyword)) {
      return JMAP_KEYWORD_FLAG[keyword];
    }
    if (!JMAP_KEYWORD_RE.test(keyword)) return null;
    return keyword;
  }

  // The keywords a message carries, read off its flags. The four the
  // mapping names come back as those; anything else this server keeps
  // that is not a system flag is an ordinary keyword and comes back as
  // itself, so a client reads what it wrote. A system flag with no
  // keyword is one JMAP does not expose and stays out of the answer.
  function _keywordsOf(flags) {
    var keywords = Object.create(null);
    for (var i = 0; i < flags.length; i += 1) {
      var flag = String(flags[i]);
      if (Object.prototype.hasOwnProperty.call(FLAG_JMAP_KEYWORD, flag)) {
        keywords[FLAG_JMAP_KEYWORD[flag]] = true;
        continue;
      }
      if (flag.charAt(0) === "\\") continue;
      keywords[flag] = true;
    }
    return keywords;
  }

  function _jmapEmail(folderName, message) {
    var flags = Array.isArray(message.flags) ? message.flags : [];
    var keywords = _keywordsOf(flags);
    var mailboxIds = Object.create(null);
    mailboxIds[folderName] = true;
    var chain = _references(message);
    return {
      id:         message.objectid,
      blobId:     message.objectid,
      threadId:   message.threadRootId,
      mailboxIds: mailboxIds,
      keywords:   keywords,
      size:       message.sizeBytes,
      receivedAt: new Date(message.receivedAt || message.internalDate || 0).toISOString(),
      messageId:  message.messageId ? [message.messageId] : null,
      inReplyTo:  message.inReplyTo ? [message.inReplyTo] : null,
      references: chain.slice(0, chain.length - 1),
      subject:    message.subject ? _headerText(message.subject) : null,
      from:       message.from
        ? [{ name: _displayName(message.from), email: _bareAddress(message.from) }]
        : null,
      to: message.to
        ? _addresses(message.to).map(function (a) {
          return { name: _displayName(a), email: _bareAddress(a) };
        })
        : null,
      preview:       _preview(message.bodyText, 256),
      hasAttachment: false,
    };
  }

  async function _locateFolder(account, folders, objectId) {
    var actor = _actorFor(account, folders);
    for (var i = 0; i < folders.length; i += 1) {
      var message = await agent.fetch({
        actor: actor, folder: folders[i].storeName, objectId: objectId,
      });
      if (message) return folders[i];
    }
    return null;
  }

  async function _applyJmapPatch(actorRef, folders, home, objectId, patch) {
    var set = [];
    var unset = [];
    // Where the message is as this patch runs. One request may both
    // file a message and edit its keywords, and the keyword write at
    // the end belongs to the folder the message is in by then rather
    // than the one it started in, so the audit row names where the
    // change actually landed.
    var homeNow = home;
    // The mailbox this patch files the message into, decided while the
    // properties are read and acted on only once every one of them has
    // been accepted.
    var filing = null;
    // The whole-keyword-set form replaces what the message holds, so it
    // needs the held set to know what to take off. Recorded here and
    // read once the patch has been accepted in full.
    var replacing = null;
    var keys = Object.keys(patch);
    for (var i = 0; i < keys.length; i += 1) {
      var key = keys[i];
      var value = patch[key];
      // The whole keyword map, replacing whatever the message carries.
      // Replacing takes both halves: the keywords the patch names go on,
      // and every keyword the message holds that the patch did not name
      // comes off. A system flag with no keyword is not a keyword and is
      // left where it is, so a message an IMAP client marked keeps that
      // mark through a JMAP client's keyword edit.
      if (key === "keywords") {
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          throw new Error("keywords must be a map of keyword to true");
        }
        var wantedFlags = [];
        var named = Object.keys(value);
        for (var w = 0; w < named.length; w += 1) {
          if (value[named[w]] !== true) continue;
          var wantedFlag = _flagForKeyword(named[w]);
          if (wantedFlag === null) {
            throw new Error("keyword '" + named[w] + "' is not one this server sets");
          }
          wantedFlags.push(wantedFlag);
        }
        // Which keywords come OFF depends on which the message holds,
        // and reading that is the one question in this loop that needs
        // the store. It waits with the rest: the loop decides and
        // touches nothing, so a property read after this one can still
        // refuse the whole patch.
        replacing = wantedFlags;
        for (var k = 0; k < wantedFlags.length; k += 1) set.push(wantedFlags[k]);
        continue;
      }
      var single = /^keywords\/(.+)$/.exec(key);
      if (single) {
        var flag = _flagForKeyword(single[1]);
        if (flag === null) {
          throw new Error("keyword '" + single[1] + "' is not one this server sets");
        }
        if (value === true) set.push(flag); else unset.push(flag);
        continue;
      }
      var wholeSet = key === "mailboxIds" && value && typeof value === "object";
      var addTo = /^mailboxIds\/(.+)$/.exec(key);
      if (wholeSet || addTo) {
        // A message is in one folder here and in no others, so taking it
        // out of the one it is in leaves it nowhere. That request is
        // refused rather than accepted and ignored, which would report a
        // move the mailbox never made.
        if (addTo && value !== true) {
          throw new Error("a message is in exactly one mailbox on this server; " +
            "name the mailbox it should be in rather than the one it should leave");
        }
        var wanted = wholeSet
          ? Object.keys(value).filter(function (id) { return value[id] === true; })
          : [addTo[1]];
        if (wholeSet && wanted.length !== 1) {
          throw new Error("mailboxIds must name exactly one mailbox");
        }
        if (wanted.length === 1) {
          var destination = _findFolder(folders, wanted[0]);
          if (!destination) throw new Error("mailboxIds names an unknown mailbox");
          if (filing !== null && filing.storeName !== destination.storeName) {
            throw new Error("mailboxIds names two different mailboxes in one patch");
          }
          filing = destination;
        }
        continue;
      }
      throw new Error("property '" + key + "' cannot be set on Email");
    }

    // Everything above decided; nothing above moved anything. RFC 8621
    // section 5.3 answers a Set per id, so a message reported under
    // `notUpdated` has to be a message nothing happened to, and
    // `Object.keys` decides which property is read first. Filing inside
    // the loop meant a patch that named a mailbox and then named a
    // property this server cannot set filed the message and refused the
    // request that filed it, leaving the client told the update did not
    // happen and the message somewhere else.
    if (replacing !== null) {
      var current = await agent.fetch({
        actor: actorRef, folder: homeNow.storeName, objectId: objectId,
      });
      var held = current && Array.isArray(current.flags) ? current.flags : [];
      for (var h = 0; h < held.length; h += 1) {
        var heldFlag = String(held[h]);
        var isKeyword = heldFlag.charAt(0) !== "\\" ||
          Object.prototype.hasOwnProperty.call(FLAG_JMAP_KEYWORD, heldFlag);
        if (isKeyword && replacing.indexOf(heldFlag) === -1) unset.push(heldFlag);
      }
    }
    if (filing !== null && filing.storeName !== homeNow.storeName) {
      // The adapter's verb rather than the agent's, because the folder
      // and UID rows this move has to carry are the adapter's and the
      // agent does not know about them. A refusal is raised as an error
      // the caller turns into a SetError rather than answered as a
      // silent success.
      var filed = await mailbox.moveObjects(actorRef, homeNow.name,
        filing.name, [objectId]);
      if (filed.moved.indexOf(objectId) === -1) {
        var why = (filed.refused[0] && filed.refused[0].reason) || "not-in-folder";
        throw new Error("the message could not be filed into '" +
          filing.name + "': " + why);
      }
      homeNow = filing;
      await _clearDeletedOutsideTrash(actorRef, filing, [objectId]);
    }
    if (set.length > 0 || unset.length > 0) {
      await agent.flag({
        actor: actorRef, folder: homeNow.storeName, objectIds: [objectId],
        set: set, unset: unset,
      });
    }
  }

  var jmapMethods = {
    "Mailbox/get": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var mailboxes = folders.map(_jmapMailbox);
      var wanted = Array.isArray(args.ids) ? args.ids : null;
      var list = wanted
        ? mailboxes.filter(function (m) { return wanted.indexOf(m.id) !== -1; })
        : mailboxes;
      var found = list.map(function (m) { return m.id; });
      return {
        accountId: args.accountId,
        state:     _accountState(folders),
        list:      list,
        notFound:  wanted ? wanted.filter(function (id) { return found.indexOf(id) === -1; }) : [],
      };
    },

    "Mailbox/query": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var mailboxes = folders.map(_jmapMailbox);
      return {
        accountId:  args.accountId,
        queryState: _accountState(folders),
        canCalculateChanges: false,
        position:   0,
        ids:        mailboxes.map(function (m) { return m.id; }),
        total:      mailboxes.length,
      };
    },

    "Email/query": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var filter = args.filter || {};
      var folderName = typeof filter.inMailbox === "string" ? filter.inMailbox : DEFAULT_FOLDER;
      var folder = _findFolder(folders, folderName);
      if (!folder) {
        return {
          accountId: args.accountId, queryState: "0", position: 0,
          ids: [], total: 0, canCalculateChanges: false,
        };
      }
      var extra = {};
      if (typeof filter.text === "string" && filter.text.length > 0) extra.text = filter.text;
      if (typeof filter.from === "string" && filter.from.length > 0) extra.from = filter.from;
      if (typeof filter.to === "string" && filter.to.length > 0)     extra.to = filter.to;
      if (typeof filter.body === "string" && filter.body.length > 0) extra.body = filter.body;
      var page = await _pageBefore(account, folder, 0, Object.keys(extra).length > 0 ? extra : null);
      var ids = page.rows.map(function (row) { return row.objectid; });
      return {
        accountId:  args.accountId,
        queryState: String(folder.modseqMax),
        canCalculateChanges: false,
        position:   0,
        ids:        ids,
        total:      ids.length,
      };
    },

    "Email/get": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var ids = Array.isArray(args.ids) ? args.ids : [];
      var list = [];
      var notFound = [];
      for (var i = 0; i < ids.length; i += 1) {
        var hit = null;
        for (var f = 0; f < folders.length && hit === null; f += 1) {
          var message = await agent.fetch({
            actor: _actorFor(account), folder: folders[f].storeName, objectId: ids[i],
          });
          if (message) hit = _jmapEmail(folders[f].name, message);
        }
        if (hit) list.push(hit); else notFound.push(ids[i]);
      }
      return {
        accountId: args.accountId,
        state:     _accountState(folders),
        list:      list,
        notFound:  notFound,
      };
    },

    "Email/set": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var actorRef = _actorFor(account, folders);
      var oldState = _accountState(folders);
      var created = {};
      var notCreated = {};
      var updated = {};
      var notUpdated = {};
      var destroyed = [];
      var notDestroyed = {};

      // An Email arrives here by being received or by being sent, and
      // neither is an append a client performs. Answering the request by
      // name is the whole of it: a response carrying neither `created`
      // nor `notCreated` reads as a success to the client and loses
      // whatever it was holding.
      var createKeys = args.create && typeof args.create === "object"
        ? Object.keys(args.create) : [];
      for (var c = 0; c < createKeys.length; c += 1) {
        notCreated[createKeys[c]] = {
          type:        "forbidden",
          description: "This server does not append an Email. Send it through " +
            "EmailSubmission/set and a copy is filed as it goes out.",
        };
      }

      var updateIds = args.update && typeof args.update === "object" ? Object.keys(args.update) : [];
      for (var u = 0; u < updateIds.length; u += 1) {
        var id = updateIds[u];
        var home = await _locateFolder(account, folders, id);
        if (!home) { notUpdated[id] = { type: "notFound" }; continue; }
        try {
          await _applyJmapPatch(actorRef, folders, home, id, args.update[id] || {});
          updated[id] = null;
        } catch (patchErr) {
          notUpdated[id] = { type: "invalidProperties", description: patchErr.message };
        }
      }

      var destroyIds = Array.isArray(args.destroy) ? args.destroy : [];
      for (var d = 0; d < destroyIds.length; d += 1) {
        var target = destroyIds[d];
        var folder = await _locateFolder(account, folders, target);
        if (!folder) { notDestroyed[target] = { type: "notFound" }; continue; }
        // The adapter's verb, not the agent's. The agent decides whether
        // a message may go and destroys the message store's row; the
        // adapter owns the row binding it to this folder and to a UID,
        // and the sealed original octets. Answering `destroyed` on the
        // agent alone tells the client the message was permanently
        // removed while its body is still readable on the volume.
        var outcome = await mailbox.expungeObjects(actorRef, folder.name, [target]);
        var refusals = Array.isArray(outcome.refused) ? outcome.refused : [];
        var went = Array.isArray(outcome.deleted) && outcome.deleted.indexOf(target) !== -1;
        if (refusals.length > 0 && !went) {
          // `Email/set` takes a SetError per id (RFC 8621 section 4.4,
          // over the /set semantics of RFC 8620 section 5.3). A message
          // the adapter no longer holds is not a message the account may
          // not destroy, so the three answer differently: `notFound` for
          // an identifier nothing on either layer holds, `forbidden` for
          // a preservation order or a retention floor that refused it,
          // and `serverFail` for a volume that would not take one of the
          // acts that destroy it, which is neither the client's fault
          // nor a decision anybody made about this message.
          //
          // The first two are in the set RFC 8620 section 5.3 names.
          // `serverFail` is that section's own provision for a type it
          // does not name, taken from the request-level vocabulary of
          // section 3.6.2 rather than invented here, because a client
          // that does not recognize it still reads the identifier under
          // `notDestroyed`, which is the part it has to act on. Calling
          // it `forbidden` would be in the named set and would say
          // something untrue: nothing forbade this message.
          notDestroyed[target] = refusals[0].outcome === "absent"
            ? { type: "notFound" }
            : (refusals[0].outcome === "preserved"
              ? { type: "forbidden", description: refusals[0].reason }
              : { type: "serverFail", description: refusals[0].reason });
        } else {
          // Destroyed, whatever record of it the volume kept. The client
          // asked for the message to be gone and it is; a row the
          // operator's records posture holds back is on the trail and in
          // the reconciliation, and it is not a JMAP answer.
          destroyed.push(target);
        }
      }

      return {
        accountId:    args.accountId,
        oldState:     oldState,
        // Read after the mutations, so the state a client caches is the
        // one the mail is actually in rather than the one it left.
        newState:     _accountState(_foldersFor(account)),
        created:      created,
        notCreated:   notCreated,
        updated:      updated,
        notUpdated:   notUpdated,
        destroyed:    destroyed,
        notDestroyed: notDestroyed,
      };
    },

    // A thread id is a message identifier, and the store's thread index
    // is keyed on it alone: no folder is named anywhere in the lookup,
    // so the chain it answers with spans every account holding a copy of
    // that conversation. RFC 8621 section 3 defines a Thread as the
    // messages in it the account can see, which is what the filter below
    // produces. A thread this account holds no part of is reported not
    // found, because answering it empty would say the thread exists.
    "Thread/get": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var ids = Array.isArray(args.ids) ? args.ids : [];
      var list = [];
      var notFound = [];
      for (var i = 0; i < ids.length; i += 1) {
        var chain = await agent.thread({ actor: _actorFor(account), objectId: ids[i] });
        var members = Array.isArray(chain.thread) ? chain.thread : [];
        var mine = [];
        for (var m = 0; m < members.length; m += 1) {
          var home = await _locateFolder(account, folders, members[m]);
          if (home) mine.push(members[m]);
        }
        if (mine.length === 0) { notFound.push(ids[i]); continue; }
        list.push({ id: ids[i], emailIds: mine });
      }
      return {
        accountId: args.accountId,
        state:     _accountState(folders),
        list:      list,
        notFound:  notFound,
      };
    },

    // RFC 8621 section 6 makes a sending identity a first class object so
    // a client reads which addresses it may write rather than assuming
    // the one it signed in with. This account may write its own address
    // and every alias that lands in its mailbox, so that is what is
    // returned: an answer with one entry in it would be this server
    // knowing about a shared departmental address and not saying so, and
    // a conforming client has no other way to find out.
    "Identity/get": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var held = _identitiesFor(account).map(function (identity) {
        return {
          id:            identity.id,
          name:          identity.name,
          email:         identity.address,
          replyTo:       null,
          bcc:           null,
          textSignature: "",
          htmlSignature: "",
          mayDelete:     false,
        };
      });

      // RFC 8620 section 5.1: a null or absent `ids` asks for every
      // record of the type, and a list asks for those records and
      // reports the rest as not found. Answering everything either way
      // would hand a client asking after one identity a set it did not
      // ask for and never tell it that the one it named is gone.
      var asked = Array.isArray(args.ids) ? args.ids : null;
      var list = held;
      var notFound = [];
      if (asked !== null) {
        list = [];
        for (var i = 0; i < asked.length; i += 1) {
          var found = _identityById(held, asked[i]);
          if (found === null) notFound.push(asked[i]);
          else list.push(found);
        }
      }

      return {
        accountId: args.accountId,
        // Derived from every identity this account holds rather than
        // from the subset one request asked for, because RFC 8620
        // section 5.1 scopes a state to the data of a type and not to
        // the question. Adding or withdrawing an alias changes that
        // data, so it changes the string, with nothing here that has to
        // remember to move it.
        state:     _identityState(held),
        list:      list,
        notFound:  notFound,
      };
    },

    // Submission composes the same outbound handle the compose form uses,
    // so there is one path out of this process and one place the policy
    // chain runs.
    //
    // The identity a submission names is required and is resolved against
    // the set `Identity/get` answered with, which is how RFC 8621 section
    // 7.5 has a client choose who a message is from. Reading it as
    // optional and sending as the account instead would take a client
    // that asked for a shared address and send under a different one
    // without saying so, which is the failure a mailbox owner discovers
    // in the recipient's reply.
    "EmailSubmission/set": async function (actor, args) {
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var identities = _identitiesFor(account);
      var oldState = _accountState(folders);
      var created = {};
      var notCreated = {};
      var requests = args.create && typeof args.create === "object" ? Object.keys(args.create) : [];
      for (var i = 0; i < requests.length; i += 1) {
        var key = requests[i];
        var submission = args.create[key] || {};
        var identityId = _str(submission.identityId, "");
        if (identityId.length === 0) {
          notCreated[key] = { type: "invalidProperties", properties: ["identityId"] };
          continue;
        }
        var identity = _identityById(identities, identityId);
        if (identity === null) {
          _recordAuthorRefusal("jmap-submission", identityId,
            identities.map(function (held) { return held.address; }));
          notCreated[key] = {
            type:        "identityNotFound",
            description: "no identity " + _echoAuthor(identityId) + " for this account",
          };
          continue;
        }
        var emailId = _str(submission.emailId, "");
        var folder = emailId.length > 0 ? await _locateFolder(account, folders, emailId) : null;
        var message = folder ? await agent.fetch({
          actor: _actorFor(account), folder: folder.storeName, objectId: emailId,
        }) : null;
        if (!message) {
          notCreated[key] = { type: "invalidProperties", properties: ["emailId"] };
          continue;
        }
        try {
          var chain = _references(message);
          var sent = await composer.send({
            from:         identity.address,
            // The same split the compose form makes, for the same
            // reason. The author is the identity the client chose and
            // the return path is the account's own address, so a bounce
            // lands in the mailbox of whoever sent the message and the
            // envelope binding has nothing to refuse.
            envelopeFrom: account.address,
            to:           _addresses(message.to).map(_bareAddress),
            subject:      _str(message.subject, ""),
            text:         _str(message.bodyText, ""),
            inReplyTo:    message.inReplyTo || undefined,
            references:   chain.slice(0, chain.length - 1),
          }, { actor: _actorFor(account) });
          // RFC 8620 section 5.3 asks a create response for the
          // properties the client did not send, so the identity and the
          // message it named are not echoed back: the client chose both
          // and already holds them.
          created[key] = {
            id:         sent.messageId || emailId,
            sendAt:     new Date().toISOString(),
            undoStatus: "final",
          };
        } catch (sendErr) {
          notCreated[key] = { type: "forbiddenToSend", description: sendErr.message };
        }
      }
      return {
        accountId:  args.accountId,
        oldState:   oldState,
        // A submission files a copy in Sent, so the state a client
        // caches after one has to be read after the send rather than
        // before it.
        newState:   _accountState(_foldersFor(account)),
        created:    created,
        notCreated: notCreated,
        updated:    {},
        destroyed:  [],
      };
    },
  };

  // The message store the JMAP listener reads its push hook off, which
  // is the store itself plus that one verb. It delegates rather than
  // copies, so a vendor refresh that starts reading another method off
  // the handle finds it. The store is not given the verb directly: it
  // is shared with the wire listeners and the delivery path, and a hook
  // bolted onto it there would be a second place deciding what a
  // message store is.
  var jmapStore = Object.create(mailStore);
  jmapStore.subscribePush = _subscribePush;

  var jmap = b.mail.server.jmap.create({
    mailStore: jmapStore,
    methods:   jmapMethods,
    profile:   "strict",
    // Named rather than left to the framework's default so this
    // application decides what it advertises and what it serves in one
    // place. The upgrade mount below reads the same constant, which is
    // what keeps the session document's promise checkable.
    webSocketUrl:            JMAP_WEBSOCKET_PATH,
    webSocketMaxMessageBytes: JMAP_WEBSOCKET_MAX_BYTES,
    // permessage-deflate stays off, which is the framework's default
    // and the same reasoning that keeps IMAP COMPRESS=DEFLATE off: a
    // channel carrying attacker chosen text beside confidential text
    // through one compressor is a compression oracle.
    webSocketPermessageDeflate: false,
    serverCapabilities: {
      "urn:ietf:params:jmap:mail":       {},
      "urn:ietf:params:jmap:submission": {},
    },
    accountsFor: async function (actor) {
      var account = await store.accounts.get(_actorId(actor));
      if (!account) return { primaryAccounts: {}, accounts: {} };
      var accounts = {};
      accounts[account.id] = {
        name:       account.address,
        isPersonal: true,
        isReadOnly: false,
        accountCapabilities: {
          "urn:ietf:params:jmap:mail":       {},
          "urn:ietf:params:jmap:submission": {},
        },
      };
      var primary = {};
      primary["urn:ietf:params:jmap:mail"] = account.id;
      primary["urn:ietf:params:jmap:submission"] = account.id;
      return { primaryAccounts: primary, accounts: accounts };
    },
  });

  // -------------------------------------------------------------------
  // The JMAP WebSocket transport, RFC 8887.
  //
  // An upgrade is not a route. It arrives on the HTTP server's own
  // `upgrade` event, which is why the event source half of this channel
  // was mounted and this half was not: one is a line in the router and
  // the other is a different mounting step entirely. The consequence
  // that matters is that the middleware chain has not run by the time
  // the handshake is decided, so what still protects this door had to
  // be worked out rather than inherited.
  //
  //   Authentication. The session cookie is read and verified here the
  //   same way `b.middleware.attachUser` reads it on a routed request,
  //   through the same account loader, so a suspended or archived
  //   account loses a socket exactly as it loses a page. The actor is
  //   attached to the request and the framework's own handler writes
  //   the refusal when it is absent.
  //
  //   Origin. `b.websocket.isOriginAllowed` with no allowlist is the
  //   same origin default, and same origin is the whole of the cross
  //   site WebSocket hijacking defense: a page on another site carries
  //   the browser's ambient cookie but cannot forge `Origin`. It is
  //   checked here rather than only inside the handler so a refusal
  //   leaves an audit row, and it is the framework's own predicate
  //   rather than a second opinion about what same origin means.
  //
  //   Account scope. Every frame the socket carries reaches the same
  //   dispatcher the API endpoint uses, with the same actor, so the
  //   cross account gate is one gate rather than a copy. A push
  //   subscription reads its account off the actor and never off a
  //   frame, so the only thing a client chooses is which of its own
  //   types it hears about.
  //
  //   Cross site request forgery. The session cookie carries the
  //   `__Host-` prefix and `SameSite=Strict`, so a cross site upgrade
  //   arrives with no cookie at all, and the origin check refuses it
  //   even if one somehow did.
  //
  // The bot guard, the fetch metadata check and the body parser have no
  // work to do on a handshake: there is no body, and the header checks
  // are written for a navigable document rather than for a subprotocol
  // negotiation. Compression stays off, which is the framework's
  // default and the same compression oracle reasoning that keeps IMAP
  // COMPRESS=DEFLATE off.
  //
  // Each refusal writes an audit row before it answers, because a
  // refused upgrade leaves no response an operator can go back and
  // read. The row is written through `safeEmit`, which drops silent by
  // design: a failed audit write must not become a second failure on
  // top of the one being recorded.
  // -------------------------------------------------------------------

  // Every socket this transport has upgraded, and the drain that
  // closes them.
  //
  // An upgrade detaches its socket from the HTTP server, so the close
  // that ends the routed connections never reaches it: `server.close`
  // waits on requests it can see, and `closeAllConnections` cuts the
  // connections it still tracks. A socket left open past the drain is
  // a live handle on a process that was asked to stop, which an
  // orchestrator reads as a shutdown that hung and answers by killing
  // it, and a client that was never told to reconnect elsewhere.
  var jmapSockets = new Set();
  var jmapDrain   = null;

  function _finishJmapDrain() {
    if (jmapDrain === null) return;
    var running = jmapDrain;
    jmapDrain = null;
    clearTimeout(running.timer);
    running.resolve(running.opened);
  }

  /**
   * @primitive blamepost.web.create.drainJmapWebSockets
   * @signature handle.drainJmapWebSockets(timeoutMs)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6455 section 7.4.1
   * @related   blamepost.web.create.mountJmapWebSocket, blamepost.web.serve.stop
   *
   * Tell every open JMAP socket the server is going away, then cut
   * whatever is still open when the deadline passes. Resolves with the
   * number of sockets the drain started with, so a caller can report
   * what it closed. `blamepost.web.serve.stop` calls it ahead of
   * closing the listeners.
   *
   * The close code is the RFC 6455 section 7.4.1 going-away code, which
   * is what tells a client to reconnect later rather than to treat the
   * connection as broken and give up.
   *
   * @example
   *   await handle.drainJmapWebSockets(8000);
   */
  function drainJmapWebSockets(timeoutMs) {
    if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("blamepost.web.create: drainJmapWebSockets(timeoutMs) needs a " +
        "positive deadline in milliseconds, the one the drain is allowed to spend.");
    }
    var open = Array.from(jmapSockets);
    if (open.length === 0) return Promise.resolve(0);
    return new Promise(function (resolve) {
      jmapDrain = { resolve: resolve, opened: open.length, timer: null };
      jmapDrain.timer = setTimeout(function () {
        for (var i = 0; i < open.length; i += 1) {
          try { open[i].socket.destroy(); }
          catch (_e) { /* drop-silent by design: already gone */ }
        }
        _finishJmapDrain();
      }, timeoutMs);
      if (typeof jmapDrain.timer.unref === "function") jmapDrain.timer.unref();
      for (var i = 0; i < open.length; i += 1) {
        try { open[i].conn.close(b.websocket.CLOSE_GOING_AWAY, "server draining"); }
        catch (_e) { /* drop-silent by design: this one is already closing */ }
      }
    });
  }

  // A refusal on a socket that never became a request. There is no
  // response object on this path, so the status line is written by
  // hand; every refusal below names a code a client can act on rather
  // than dropping the connection and leaving the reason to be guessed.
  function _refuseUpgrade(socket, status, reason) {
    var body = reason + "\r\n";
    try {
      socket.write(
        "HTTP/1.1 " + status + " " + (nodeHttp.STATUS_CODES[status] || "Refused") + "\r\n" +
        "Connection: close\r\n" +
        "Content-Type: text/plain; charset=utf-8\r\n" +
        "Content-Length: " + Buffer.byteLength(body, "utf8") + "\r\n" +
        "\r\n" + body);
    } catch (_e) { /* drop-silent by design: the socket is already gone */ }
    try { socket.destroy(); } catch (_e) { /* drop-silent by design: already destroyed */ }
  }

  // The account behind an upgrade, or null. Mirrors what
  // `b.middleware.attachUser` does on a routed request: read the cookie
  // this application writes, verify the session, load the account
  // again so a status change since sign in is honored.
  async function _upgradeAccount(req) {
    var token = _cookieJar().read(req, SESSION_COOKIE);
    if (typeof token !== "string" || token.length === 0) return null;
    var verified;
    try { verified = await b.session.verify(token, { req: req }); }
    catch (_e) { return null; }
    if (!verified) return null;
    try { return await _loadAccount(verified); }
    catch (_e) { return null; }
  }

  /**
   * @primitive blamepost.web.create.mountJmapWebSocket
   * @signature handle.mountJmapWebSocket(server)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 8887 section 3
   * @related   blamepost.web.serve, blamepost.web.create.drainJmapWebSockets
   *
   * Attach the JMAP WebSocket transport to a bound HTTP server, at the
   * path the session document advertises. Call it once per server the
   * application binds; `blamepost.web.serve` does that as part of
   * binding, so an operator composing `create` by hand is the only
   * caller that needs it.
   *
   * This process serves exactly one upgrade path, so an upgrade aimed
   * anywhere else is refused with a status rather than left hanging. A
   * second WebSocket surface belongs in this dispatcher rather than in
   * a second listener on the same event, because two handlers on one
   * `upgrade` event both see every request and the first one to refuse
   * closes the socket under the other.
   *
   * @example
   *   var handle = blamepost.web.create(wiring);
   *   handle.mountJmapWebSocket(httpServer);
   */
  function mountJmapWebSocket(server) {
    if (!server || typeof server.on !== "function") {
      throw new TypeError("blamepost.web.create: mountJmapWebSocket(server) needs the bound " +
        "HTTP server, the one b.createApp().listen resolves with. The upgrade event is on " +
        "the server rather than on the router, which is why this is a separate mounting " +
        "step from a route.");
    }
    server.on("upgrade", function (req, socket, head) {
      // The socket is held still across the session lookup below, and
      // released once the framework's handler has attached its own
      // reader, so nothing a client sent ahead of the response can
      // arrive while there is nobody listening for it.
      try { socket.pause(); } catch (_e) { /* drop-silent by design: already gone */ }

      var pathname = String(req.url || "/").split("?")[0];
      if (pathname !== JMAP_WEBSOCKET_PATH) {
        b.audit.safeEmit({
          action:   "blamepost.jmap.websocket.refused",
          outcome:  "denied",
          // An upgrade never reaches the router, so the request builds
          // its own actor here rather than reading a scope nothing
          // opened. Nobody is authenticated at this point and the row
          // says so; where the attempt came from is what it can stand
          // behind, and it is the question a refusal is read for.
          actor:    auditActor.forRequest(req),
          metadata: { reason: "no-such-upgrade-path", path: pathname },
        });
        // The path is recorded above rather than echoed here. Nothing a
        // client sent is written back into a response it can read.
        _refuseUpgrade(socket, 404, "This server serves no WebSocket at that path.");
        return;
      }
      if (!b.websocket.isOriginAllowed(req, undefined)) {
        b.audit.safeEmit({
          action:   "blamepost.jmap.websocket.refused",
          outcome:  "denied",
          actor:    auditActor.forRequest(req),
          metadata: {
            reason: "origin-not-served",
            origin: String((req.headers && req.headers.origin) || ""),
          },
        });
        _refuseUpgrade(socket, 403, "This server does not serve that origin.");
        return;
      }

      // Whether the handshake has been handed to the framework. Past
      // that point this socket may already be carrying WebSocket
      // frames, and writing an HTTP status line onto it would push
      // bytes into the middle of a live stream. So a failure before the
      // hand off is answered and a failure after it is cut.
      var handedOff = false;
      _upgradeAccount(req).then(function (account) {
        if (!account) {
          b.audit.safeEmit({
            action:   "blamepost.jmap.websocket.refused",
            outcome:  "denied",
            actor:    auditActor.forRequest(req),
            metadata: { reason: "no-authenticated-account" },
          });
        }
        // Attached whether or not it resolved: the framework's handler
        // owns the unauthenticated refusal, and writing a second one
        // here would be two answers to the same question.
        req.user = account;
        handedOff = true;
        var conn = jmap.webSocketHandler(req, socket, head);
        if (conn !== null && conn !== undefined) {
          var entry = { conn: conn, socket: socket };
          jmapSockets.add(entry);
          conn.once("close", function () {
            jmapSockets.delete(entry);
            if (jmapDrain !== null && jmapSockets.size === 0) _finishJmapDrain();
          });
        }
        try { socket.resume(); } catch (_e) { /* drop-silent by design: already gone */ }
      }).catch(function (err) {
        log.error("a JMAP WebSocket upgrade threw: " + ((err && err.message) || String(err)));
        if (handedOff) {
          try { socket.destroy(); } catch (_e) { /* drop-silent by design: already gone */ }
          return;
        }
        _refuseUpgrade(socket, 500, "The upgrade could not be completed.");
      });
    });
  }

  // -------------------------------------------------------------------
  // Well known documents.
  // -------------------------------------------------------------------

  function _securityTxtExpiry() {
    if (typeof config.securityTxtExpires === "string" && config.securityTxtExpires.length > 0) {
      return config.securityTxtExpires;
    }
    return new Date(Date.now() + b.constants.TIME.days(365)).toISOString();
  }

  var securityTxt = b.middleware.securityTxt({
    contact: _list(config.securityContact).length > 0
      ? _list(config.securityContact)
      : ["mailto:postmaster@" + config.hostname],
    expires:            _securityTxtExpiry(),
    policy:             _list(config.securityPolicyUrl),
    canonical:          ["https://" + config.hostname + "/.well-known/security.txt"],
    preferredLanguages: ["en"],
  });

  // RFC 8461 policy body. Served from this application so an operator
  // points `mta-sts.<domain>` at the same process rather than standing up
  // a second web server for one text file.
  function _mtaStsBody() {
    var mode = config.mtaStsMode === "testing" || config.mtaStsMode === "none"
      ? config.mtaStsMode
      : "enforce";
    var maxAge = _int(config.mtaStsMaxAge, 604800, 86400, 31557600);
    var hosts = _list(config.mtaStsMx).length > 0 ? _list(config.mtaStsMx) : [config.hostname];
    var lines = ["version: STSv1", "mode: " + mode];
    for (var i = 0; i < hosts.length; i += 1) lines.push("mx: " + hosts[i]);
    lines.push("max_age: " + maxAge);
    return lines.join("\r\n") + "\r\n";
  }

  // -------------------------------------------------------------------
  // Row projections for the views. Everything a template shows is
  // finished here, so the template only places values.
  // -------------------------------------------------------------------

  function _decorateFolders(folders, currentName) {
    return folders.map(function (folder) {
      return {
        name:    folder.name,
        label:   folder.label,
        href:    _folderPath(folder),
        current: folder.name === currentName,
      };
    });
  }

  function _adminNav(active) {
    return [
      { href: "/admin",          label: "Overview",  current: active === "overview" },
      { href: "/admin/domains",  label: "Domains",   current: active === "domains" },
      { href: "/admin/accounts", label: "Accounts",  current: active === "accounts" },
      { href: "/admin/lockouts", label: "Lockouts",  current: active === "lockouts" },
      { href: "/admin/aliases",  label: "Aliases",   current: active === "aliases" },
      { href: "/admin/dkim",     label: "Selectors", current: active === "dkim" },
      { href: "/admin/queue",    label: "Queue",     current: active === "queue" },
      { href: "/admin/audit",    label: "Audit",     current: active === "audit" },
    ];
  }

  function _domainRow(domain, counts) {
    var acknowledged = domain.dnsAcknowledged === true;
    return {
      domain:       domain.domain,
      status:       domain.status,
      isActive:     domain.status === "active",
      acknowledged: acknowledged,
      needsAck:     !acknowledged,
      postureLabel: acknowledged ? "Confirmed" : "Awaiting confirmation",
      confirmedBy:  domain.dnsAcknowledgedBy || "",
      confirmedAt:  _when(domain.dnsAcknowledgedAt, { dateStyle: "medium" }),
      accountCount: counts && Object.prototype.hasOwnProperty.call(counts, domain.domain)
        ? counts[domain.domain] : 0,
      created:      _when(domain.createdAt, { dateStyle: "medium" }),
    };
  }

  function _accountRow(account) {
    var percent = _percent(0, account.quotaBytes);
    return {
      id:          account.id,
      address:     account.address,
      displayName: account.displayName || "",
      status:      account.status,
      isActive:    account.status === "active",
      isSuspended: account.status === "suspended",
      // Whether the row carries a way back. The identity layer returns a
      // suspended account and an archived one to service through the same
      // verb, and both take the button, so archiving is reversible from
      // here.
      //
      // An account whose erasure was held back is deliberately not
      // reinstatable. The layer refuses it, because that row is what is
      // left over from an erasure that could not finish rather than an
      // account somebody closed.
      isReinstatable: account.status === "suspended" || account.status === "archived",
      isAdmin:     account.isAdmin === true,
      reason:      account.statusReason || "",
      quotaLabel:  account.quotaBytes > 0 ? _byteSize(account.quotaBytes) : "No cap",
      usedBucket:  _bucket(percent),
      created:     _when(account.createdAt, { dateStyle: "medium" }),
    };
  }

  function _aliasRow(alias) {
    return {
      id:          alias.id,
      address:     alias.isCatchAll ? "everything at " + alias.domain : alias.address,
      destination: alias.destination,
      status:      alias.status,
      isActive:    alias.status === "active",
    };
  }

  // The selector inventory arrives flat, one row per selector across every
  // domain. The page reads per domain, so the rows are grouped here: what
  // is signing now, and what is still published while mail already in
  // flight drains.
  function _dkimCards(rows) {
    var order = [];
    var byDomain = Object.create(null);
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      if (!byDomain[row.domain]) {
        byDomain[row.domain] = {
          domain:      row.domain,
          selectors:   [],
          hasActive:   false,
          hasRetiring: false,
        };
        order.push(row.domain);
      }
      var card = byDomain[row.domain];
      if (row.state === "active")   card.hasActive = true;
      if (row.state === "retiring") card.hasRetiring = true;
      card.selectors.push({
        selector:   row.selector,
        algorithm:  row.algorithm,
        state:      row.state,
        isActive:   row.state === "active",
        isRetiring: row.state === "retiring",
        dnsName:    row.dnsName,
        record:     row.dnsRecord || row.dnsTxtValue || "",
        until:      _when(row.retiresAt, { dateStyle: "medium" }),
      });
    }
    order.sort();
    return order.map(function (domain) {
      var card = byDomain[domain];
      card.count = card.selectors.length;
      // Retiring a pair names its Ed25519 selector, and the RSA half is
      // derived from it, so the button carries the signing selector of
      // whichever pair is active.
      card.activeSelector = "";
      for (var s = 0; s < card.selectors.length; s += 1) {
        if (card.selectors[s].isActive && card.selectors[s].algorithm === "ed25519") {
          card.activeSelector = card.selectors[s].selector;
          break;
        }
      }
      return card;
    });
  }

  function _queueRow(entry) {
    return {
      id:         entry.id,
      unreadable: entry.unreadable === true,
      recipient:  entry.recipient || "",
      sender:     entry.from || "",
      attempts:   typeof entry.attempt === "number" ? entry.attempt : 0,
      reason:     entry.reason || "",
      reasonCode: entry.reasonCode || "",
      nextTry:    _when(entry.nextAttemptAt, { dateStyle: "medium", timeStyle: "short" }),
      queued:     _when(entry.queuedAt, { dateStyle: "medium", timeStyle: "short" }),
    };
  }

  function _auditRow(row) {
    var outcome = row.outcome || "";
    return {
      id:      String(row._id || ""),
      action:  row.action || "",
      outcome: outcome,
      denied:  outcome === "denied" || outcome === "failure",
      actor:   row.actorUserId || "",
      at:      _when(row.recordedAt, { dateStyle: "medium", timeStyle: "medium" }),
      detail:  row.reason || row.metadata || "",
    };
  }

  // The detail an audit row carries, as an object. It is written as JSON
  // and read back as the string it was written as. A row whose detail is
  // absent or unreadable still has to render: the page below is opened
  // during an incident, and one unreadable row is not a reason to answer
  // an operator with nothing.
  function _auditDetail(raw) {
    if (typeof raw !== "string" || raw.length === 0) return {};
    try {
      var parsed = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
      return parsed;
    } catch (_e) {
      return {};
    }
  }

  // What a sign-in lockout was counted against, read back out of the
  // resource id its audit row carries. The framework composes that id as
  // the lockout's namespace, a colon and the counter key; the identity
  // layer keys one budget on the mailbox alone and the other on the
  // source address and the mailbox with a vertical bar between them,
  // source first, because a source key never contains one and a mailbox
  // address may.
  function _lockoutKey(resourceId) {
    var raw = typeof resourceId === "string" ? resourceId : "";
    var colon = raw.indexOf(LOCKOUT_BUDGET_SEPARATOR);
    if (colon === -1) return { key: raw, address: "", source: "" };
    var key = raw.slice(colon + 1);
    var bar = key.indexOf(LOCKOUT_PAIR_SEPARATOR);
    if (bar === -1) return { key: key, address: key, source: "" };
    return { key: key, address: key.slice(bar + 1), source: key.slice(0, bar) };
  }

  // A link that fills the release form in from one recorded lockout.
  // During an incident the operator is copying an address and a source
  // out of a table and into a form, and a mistyped source releases
  // nothing while the mailbox release beside it reports success.
  function _lockoutFillHref(address, source) {
    return _path("/admin/lockouts?address=" + encodeURIComponent(address) +
      "&source=" + encodeURIComponent(source));
  }

  // One budget's counter, as the console shows it.
  //
  // The attempt count is an early warning and is meaningful only below
  // the threshold: the failure that spends a budget resets it, so a
  // budget that is holding somebody out reads zero and so does a mailbox
  // nobody has guessed at. Printing that zero beside a held budget would
  // say the opposite of what is happening, so `counting` is what gates
  // it and a held budget offers the lock count from the recorded row
  // instead.
  function _budgetNow(reading) {
    var held = reading.locked === true;
    return {
      held:     held,
      clear:    !held,
      lifts:    _when(reading.lockedUntil, { dateStyle: "medium", timeStyle: "short" }),
      counting: !held && reading.attempts > 0,
      attempts: reading.attempts,
    };
  }

  // One recorded lockout, as the console shows it.
  //
  // The address is looked up before the page calls it a mailbox, so a key
  // this read gets wrong cannot become a release form aimed at something
  // that is not an account. An address with no account here is shown as
  // what it is: somebody guessing at a mailbox this server does not host,
  // which is worth seeing and is not worth offering to release.
  //
  // `standing` is the recorded window and `live` is the counter, and they
  // are carried separately because they answer different questions and
  // can disagree. The counters live in this process's memory and a
  // restart clears every one of them, while these rows are on disk, so a
  // row from before a restart is standing over a budget that is already
  // free. `stale` is that case named rather than left for an operator to
  // spot, and `newerHold` is its opposite: a budget holding under a
  // lockout more recent than the row being read.
  //
  // A row counted against an address with no mailbox here gets no live
  // reading at all. There is no budget this console can ask about
  // without asking about something that is not an account, and an
  // absent reading is the honest answer rather than a clear one.
  function _lockoutRow(row, now, releasedAt, context) {
    var detail = _auditDetail(row.metadata);
    var parts = _lockoutKey(row.resourceId);
    var account = Object.prototype.hasOwnProperty.call(context.accounts, parts.address)
      ? context.accounts[parts.address]
      : null;
    var engagedAt = typeof row.recordedAt === "number" ? row.recordedAt : 0;
    var liftsAt = typeof detail.lockedUntil === "number" ? detail.lockedUntil : 0;
    var releasedSince = Object.prototype.hasOwnProperty.call(releasedAt, parts.key) &&
      releasedAt[parts.key] >= engagedAt;
    var standing = !releasedSince && liftsAt > now;
    var live = Object.prototype.hasOwnProperty.call(context.live, parts.key)
      ? context.live[parts.key]
      : null;
    return {
      address:   account ? account.address : "",
      unhosted:  account ? "" : parts.address,
      isMailbox: Boolean(account),
      fillHref:  account ? _lockoutFillHref(account.address, parts.source) : "",
      source:    parts.source,
      perSource: parts.source.length > 0,
      engaged:   _when(engagedAt, { dateStyle: "medium", timeStyle: "short" }),
      lifts:     _when(liftsAt, { dateStyle: "medium", timeStyle: "short" }),
      standing:  standing,
      released:  releasedSince,
      // How many times this budget has run out. The wait after each one
      // is longer than the wait after the last, so the count is what
      // tells an operator whether this is a stale client or a run at the
      // mailbox. It is also the number worth reading for a budget that
      // is holding right now, since the counter's own is zero by then.
      runLength: typeof detail.lockNumber === "number" ? detail.lockNumber : 0,
      live:      live,
      stale:     Boolean(live && standing && live.clear),
      newerHold: Boolean(live && !standing && live.held),
    };
  }

  // Accounts per hosted domain, from one read rather than one read per
  // domain, because the address column is sealed and every list call
  // decrypts and sorts the whole table.
  async function _accountCounts() {
    var rows = _asArray(await store.accounts.list({ includeArchived: true }));
    var counts = {};
    for (var i = 0; i < rows.length; i += 1) {
      var domain = rows[i].domain;
      counts[domain] = (counts[domain] || 0) + 1;
    }
    return counts;
  }

  // -------------------------------------------------------------------
  // The administrators a change would leave behind.
  // -------------------------------------------------------------------
  //
  // Three console actions can take this console away from everybody:
  // suspending the last administrator, archiving them, and withdrawing
  // the domain their address belongs to. Nothing in the browser undoes
  // any of them afterwards: the console grants the role, and once nobody
  // can reach the console there is nothing left to grant it from.
  //
  // What is left is narrower than it looks. `blamepost init` grants the
  // role from the host and so does resuming the account that held it, but
  // both of those open the data volume and the running server holds it,
  // so the way back begins with stopping the server:
  // every listener down, mail queued at the sending side, for as long as
  // it takes somebody to notice. One button press should not cost that,
  // so the console measures what would be left and refuses to strand
  // itself.
  //
  // It is a refusal in the console and nowhere else, which is what keeps
  // containment open. An administrator whose credential has been taken is
  // suspended from here while another administrator remains, and from the
  // host once the server is stopped, and stopping the server is itself
  // containment. A refusal in the identity layer would reach both and
  // would leave an operator holding a compromised credential with nothing
  // that answers.

  // Whether an account could sign in as things stand, decided the way
  // `authenticate` decides it: the account is active and the domain it
  // belongs to is active too. `excludeId` and `disablingDomain` are the
  // change being asked about, so the count is of what WOULD be left
  // rather than of what is there now.
  //
  // The name is folded through the same derivation the store folds it
  // through before it resolves a row, because a guard that compares the
  // spelling a form carried against the spelling the store answers with
  // is a guard the other spelling walks past: `example.com.` is a name
  // the domain guard admits and the store reads as `example.com`, so the
  // withdrawal this measures would land on a domain this said nothing
  // about. A name that cannot be folded at all is left as it arrived,
  // since the verb underneath refuses it in the same breath and no
  // domain moves either way.
  //
  // Nothing in here suspends, and that is the whole of what makes the
  // answer usable. Both reads are synchronous, so a caller that puts
  // this beside the write it authorizes gets a run nothing else in this
  // process can cut in half, and the set the refusal is about is the set
  // the write lands on. Awaiting either read would put a suspension
  // inside the measurement, and two requests would each read the pair of
  // administrators the other is on its way to breaking up.
  function _administratorsLeftAfter(excludeId, disablingDomain) {
    var withdrawn = disablingDomain;
    if (withdrawn !== null) {
      try { withdrawn = address.canonicalDomain(withdrawn, "domain"); }
      catch (_e) { /* refused below by the verb that resolves the row */ }
    }
    var live = Object.create(null);
    var domains = _asArray(store.domains.list({ status: "active" }));
    for (var d = 0; d < domains.length; d += 1) {
      if (domains[d].domain !== withdrawn) live[domains[d].domain] = true;
    }
    var accounts = _asArray(store.accounts.list({ status: "active" }));
    var left = [];
    for (var a = 0; a < accounts.length; a += 1) {
      var account = accounts[a];
      if (account.isAdmin !== true) continue;
      if (excludeId !== null && account.id === excludeId) continue;
      if (live[account.domain] !== true) continue;
      left.push(account);
    }
    return left;
  }

  // The sentence a refused change answers with, or null when the change
  // leaves somebody able to sign in.
  //
  // The row is written here rather than at the two call sites, so a
  // refusal cannot be answered without one being filed. Somebody reaching
  // for the action that removes every administrator is the event an
  // incident review asks about afterwards, and it is invisible unless the
  // refusal records it. `safeEmit` is drop-silent by design: a trail that
  // cannot be written is not a reason to let the change through.
  //
  // `cliVerb` is optional, and its absence is a statement rather than an
  // omission. Archiving an account and withdrawing a domain both have a
  // verb on the command line that undoes them from the host, so the
  // refusal names it. Taking the role away does not: this console is the
  // only place the role is granted, so the only way past the refusal is
  // to give it to somebody else first, and naming a host verb that does
  // not exist would send an operator to a terminal to find out.
  //
  // Synchronous, and every caller reaches it without an `await`, for the
  // reason the measurement above gives. Each of the two routes that use
  // it asks TWICE. The first ask sits early, where a refusal still costs
  // nothing, so an operator is never sent to type an address or a domain
  // name back for a change that was going to be refused anyway. The
  // second sits against the write, with nothing between them that can
  // suspend, and that one is the authority: what it measures is a
  // statement about the SET of accounts that could still sign in and
  // reach these pages, and a set cannot be re-checked by looking at the
  // row being changed. The row is unchanged in each of two concurrent
  // demotions, so both read the same pair, both conclude they are not
  // taking the last, and the server they leave has no console.
  function _strandingRefusal(opts) {
    var left = _administratorsLeftAfter(opts.excludeId, opts.disablingDomain);
    if (left.length > 0) return null;

    var reason = opts.what + " would leave this server with no administrator who can sign " +
      "in, and these pages cannot grant the role back once nobody can reach them. Give " +
      "another account the role first" +
      (opts.cliVerb ? ", or stop the server and run `blamepost " + opts.cliVerb +
        "` from the host, which opens the data volume this process is holding." : ".");
    b.audit.safeEmit({
      action:   "blamepost.web.last_administrator_removal_not_permitted",
      outcome:  "denied",
      actor:    auditActor.current(),
      reason:   reason,
      resource: opts.resource,
      metadata: { attempted: opts.attempted },
    });
    return reason;
  }

  // -------------------------------------------------------------------
  // Asking before acting.
  // -------------------------------------------------------------------
  //
  // Five acts on these pages cannot be taken back from these pages:
  // archiving an account, withdrawing a hosted domain, removing an alias,
  // retiring a signing pair, and cancelling a message off the outbound
  // spool. Each is one button on a list of rows that all look alike, and
  // a row is chosen with a mouse.
  //
  // So each of them is two posts. The first resolves what was named,
  // answers with a page saying exactly what is about to happen, and
  // changes nothing. The second carries a value the operator has to have
  // READ off that page and typed back: the address, the domain, the
  // selector, or how many of the messages they picked are still waiting.
  //
  // Which value is not arbitrary. For an act with one named subject it is
  // that subject's own name, because the mistake being guarded against is
  // acting on the row above or below the one intended, and typing the
  // name is the one thing a slipped click cannot produce. For an act on a
  // SET there is no name to type, so it is the size of the set, measured
  // again at the moment of the act rather than carried from the first
  // post: a selection that went out, ended in a report, or was cancelled
  // from another window between the two posts no longer matches, and
  // nothing is erased under a page that has gone stale.
  //
  // What this is NOT is a dialog the browser puts up, and the difference
  // is the whole point. A browser can be told to stop showing those, and
  // nothing about one reaches the server, so a request forged past it
  // arrives indistinguishable from a request somebody meant. This is
  // checked here, against state read here.
  //
  // Everything the second post acts on is resolved by the first and
  // rendered from what the server read, never echoed from the request.
  // The typed reason is the exception in the other direction: it is not
  // carried back into the redrawn form after a mismatch, because a form
  // that fills the reason in is the hidden field this replaced.
  //
  // The reversible verbs are deliberately outside this. Suspending an
  // account is undone by the button beside it, and it keeps everything
  // the mailbox holds even though it stops the mailbox receiving;
  // reinstating, enabling a domain, minting a pair and granting the role
  // are all additive or one press from being undone. A console that
  // asked twice for everything would teach an operator to type through
  // the question, which is the same as not asking.

  // How a typed confirmation is compared with the value the page named.
  // Folded for case and surrounding space, because an operator reading an
  // address off a page and typing it back is answering the question this
  // asks whether or not their keyboard capitalized the first letter, and
  // a refusal over that teaches them to paste instead of read.
  function _confirms(typed, phrase) {
    return typeof phrase === "string" && phrase.length > 0 &&
      _str(typed, "").toLowerCase() === phrase.toLowerCase();
  }

  // The page that names what is about to happen. `pending` is built by
  // the route out of rows it resolved, so nothing off the request is
  // reflected into it.
  function _confirmPage(req, res, pending) {
    _page(req, res, "admin/confirm", { pending: pending },
      { status: pending.problem ? 400 : 200 });
  }

  // One shape for every act that asks first, so a verb added later
  // inherits the page rather than growing a second one beside it.
  //
  // `phrase` empty means there is nothing to type back, which is the
  // shape of a verb that is undone by the button next to it and asks only
  // for the reason it records. `needsReason` false means the layer
  // performing the act records its own account of what happened, and a
  // sentence collected here and thrown away would be worse than nothing.
  function _pending(opts) {
    return {
      postTo:      _path(opts.path),
      backHref:    _path(opts.path),
      action:      opts.action,
      title:       opts.title,
      summary:     opts.summary,
      consequence: opts.consequence,
      subjects:    (opts.subjects && opts.subjects.length > 0) ? opts.subjects : null,
      carry:       opts.carry || [],
      phrase:      opts.phrase || "",
      noun:        opts.noun || "",
      prompt:      opts.prompt || "",
      promptHint:  opts.promptHint || "",
      needsReason: opts.needsReason === true,
      verb:        opts.verb,
      fineprint:   opts.fineprint,
      problem:     null,
    };
  }

  // Whether the page still has to ask. It answers true and renders the
  // page, so a route's next line runs only for a post carrying everything
  // the act needs.
  //
  // Nothing the operator typed is drawn back into the form. A reason the
  // page fills in is the hidden field this whole shape replaced, and a
  // confirmation the page fills in is not a confirmation, so a mismatch
  // costs both fields again. That cost is the point rather than an
  // oversight: this page exists to be slower than the button that
  // reached it.
  function _stillAsking(req, res, body, pending) {
    var missingReason = pending.needsReason && _str(body.reason, "").length === 0;
    var wrongPhrase   = pending.phrase.length > 0 && !_confirms(body.confirm, pending.phrase);
    if (!missingReason && !wrongPhrase) return false;
    // Said only when something was actually typed and did not match.
    // A first post carries nothing, and answering it with a refusal
    // would read as an error rather than as the question it is.
    if (wrongPhrase && _str(body.confirm, "").length > 0) {
      pending.problem = "That is not the " + pending.noun + " named above, which is " +
        pending.phrase + ". Nothing has been changed.";
    }
    _confirmPage(req, res, pending);
    return true;
  }

  // -------------------------------------------------------------------
  // Who a cancellation may write to.
  // -------------------------------------------------------------------
  //
  // Cancelling a queued message sends its sender a delivery report,
  // which is right for one of the two kinds of message on that spool and
  // wrong for the other.
  //
  // A message relayed after an authenticated submission carries a
  // reverse path bound to the account that authenticated: the submission
  // listener refuses a `MAIL FROM` the account does not own, so that
  // address is one this server hosts and its owner is exactly who needs
  // telling that mail they sent is not going to arrive.
  //
  // A message an alias is forwarding off this server is the other kind.
  // Its reverse path arrived on the inbound wire and whoever sent the
  // message chose it; nothing here has ever checked it against anything,
  // and on a run of mail through a forwarding alias it is whatever an
  // attacker wrote. Reporting to it turns one press of a button in this
  // console into mail from this server to addresses somebody else
  // picked, which is backscatter, and the incident runbook sends an
  // operator to this page during exactly the event that produces a spool
  // full of it.
  //
  // The two cannot be told apart from the message, so they are told
  // apart by the only thing that answers: whether this server hosts the
  // domain the reverse path is in. That is a stronger property than a
  // rate bound and it is a simple one to state, which is that a report
  // this console generates never leaves this machine. A hosted reverse
  // path is delivered or refused here; anything else is not written to.
  //
  // What the withheld case is owed instead is a record. The audit row
  // for the cancellation says a report was not sent and why, so an
  // operator who does need to tell a legitimate remote sender has the
  // recipient and the reverse path in front of them rather than an
  // assumption that everybody was told.
  //
  // The empty reverse path lands here too and is withheld for the same
  // reason it is withheld everywhere else: RFC 5321 section 6.1 makes
  // the sender of a report nobody, so there is nobody to tell.
  function _reportableSenders(domains) {
    var hosted = Object.create(null);
    for (var i = 0; i < domains.length; i += 1) {
      if (typeof domains[i].domain === "string") hosted[domains[i].domain] = true;
    }
    return function (from) {
      if (typeof from !== "string" || from.length === 0) return false;
      var parsed;
      try { parsed = address.parse(from); }
      catch (_e) { return false; }
      return Boolean(parsed && parsed.ok === true && hosted[parsed.domain] === true);
    };
  }

  // What taking the role back leaves the account able to do, and how the
  // operator would put the role back.
  //
  // Both halves are stated only while the mailbox is in service. A
  // revocation is most often read on exactly the row where they are
  // false: an operator answering a credential in somebody else's hands
  // takes the role from a mailbox they have already held, and a page
  // telling them it still signs in and sends describes an account nobody
  // is looking at.
  //
  // The second half is the one that costs something to get wrong.
  // Granting the role is refused for any mailbox out of service, so
  // "one press on the row" is an undo that does not exist there, and for
  // a mailbox part way through an erasure it never will: it cannot be
  // returned to service at all. An operator who reads the act as
  // reversible and finds it is not has already taken the role.
  //
  // The question is asked per state rather than as one list, so a status
  // added later reaches the fallback rather than being described by a
  // sentence written before it existed.
  function _roleReturnedTo(subject) {
    if (subject.status === "active") {
      return "It keeps signing in and sending, and giving the role back is one press on " +
        "the row.";
    }
    if (subject.status === "suspended") {
      return "It is suspended, so it was already signing in nowhere. Giving the role back " +
        "means lifting the suspension first.";
    }
    if (subject.status === "archived") {
      return "It is archived, so it was already signing in nowhere. Giving the role back " +
        "means reopening the account first.";
    }
    if (subject.status === "erasing") {
      return "It is part way through an erasure, so it was already signing in nowhere and " +
        "cannot be returned to service. The role cannot be given back.";
    }
    return "It is " + subject.status + ", so it was already signing in nowhere. Giving the " +
      "role back means returning it to service first.";
  }

  // The four acts on the account list, and which of them names itself
  // back. `subject` is the row the route resolved, so every sentence
  // below is written from what the identity layer answered rather than
  // from what the request said.
  //
  // Archiving is the one that types the address. It stops delivery and
  // sign in on every protocol at once, and it leaves the account in the
  // state an erasure is decided from, so a press landing on the wrong
  // line takes a mailbox out of service. Reinstating it is one press on
  // the row it leaves behind, which is the press that lifts a
  // suspension as well. Suspending and the role verbs ask for the
  // reason and nothing else.
  function _accountAsk(action, subject) {
    var granting = action === "grant-role";
    if (action === "archive") {
      return _pending({
        path:    "/admin/accounts",
        action:  action,
        carry:   [{ name: "id", value: subject.id }],
        title:   "Archive " + subject.address + "?",
        summary: "This closes the account and keeps everything it holds.",
        consequence: subject.address + " stops receiving mail and stops signing in, on " +
          "every protocol, as soon as this is saved. Its mail is retained rather than " +
          "erased, and erasing it is a separate decision with a reason of its own. " +
          "Reinstating it is one press on the row this leaves behind.",
        phrase:     subject.address,
        noun:       "address",
        prompt:     "Type the address to confirm",
        promptHint: "Exactly as it is written above. Nothing else confirms this.",
        needsReason: true,
        verb:       "Archive this account",
        fineprint:  "The reason is recorded against this account in the audit trail. " +
          "Leaving this page changes nothing.",
      });
    }
    if (action === "suspend") {
      return _pending({
        path:    "/admin/accounts",
        action:  action,
        carry:   [{ name: "id", value: subject.id }],
        title:   "Suspend " + subject.address + "?",
        summary: "This stops sign in and submission and leaves the mailbox alone.",
        consequence: subject.address + " stops signing in and stops sending, on every " +
          "protocol, as soon as this is saved. It stops receiving as well: mail addressed " +
          "to it is refused rather than filed, and a sending server holds the message and " +
          "retries, so mail sent while the suspension is on arrives only if the account is " +
          "back before that server gives up. Everything the mailbox already holds stays " +
          "where it is. Reinstating it is one press on the row this leaves behind.",
        needsReason: true,
        verb:       "Suspend this account",
        fineprint:  "The reason is recorded against this account in the audit trail, and " +
          "shown beside the account on the list. Leaving this page changes nothing.",
      });
    }
    return _pending({
      path:    "/admin/accounts",
      action:  action,
      carry:   [{ name: "id", value: subject.id }],
      title:   granting
        ? "Give " + subject.address + " the operator interface?"
        : "Take the operator interface from " + subject.address + "?",
      summary: granting
        ? "This is the widest grant this server makes."
        : "This leaves the mailbox exactly as it is.",
      consequence: granting
        ? subject.address + " will read every mailbox owner's address, every hosted " +
          "domain, the outbound spool, the signing keys and this audit trail, and will be " +
          "able to archive accounts and stop a domain taking mail. It does not gain access " +
          "to anybody's messages. Taking the role back is one press on the row."
        : subject.address + " stops administering this server at once, including any " +
          "session it already has open. Its mailbox and everything in it are untouched. " +
          _roleReturnedTo(subject),
      needsReason: true,
      verb:       granting ? "Give it the operator interface" : "Take the operator interface back",
      fineprint:  "The reason is recorded against this account in the audit trail. " +
        "Leaving this page changes nothing.",
    });
  }

  // -------------------------------------------------------------------
  // Routes.
  // -------------------------------------------------------------------

  function mount(router) {
    _mountSecurity(router);

    // Static assets. Hashed names get a year, everything else an hour.
    router.use("/static", b.staticServe.create({
      root:          PUBLIC_DIR,
      mountPath:     "/static",
      contentSafety: _contentSafetyMap(),
    }));

    // Readiness, well known documents and the JMAP mount go on before the
    // authenticated surface so a probe never redirects to a sign in page.
    router.use(health.middleware());
    router.use(securityTxt);

    router.get("/.well-known/mta-sts.txt", function (req, res) {
      b.render.text(res, _mtaStsBody(), {
        headers: { "Cache-Control": "public, max-age=86400" },
      });
    });

    router.get("/.well-known/jmap", jmap.discoveryHandler);
    router.get("/jmap/session", requireAccount, jmap.sessionHandler);
    router.post("/jmap/api", requireAccount, jmap.apiHandler);
    router.get("/jmap/eventsource", requireAccount, jmap.eventSourceHandler);

    // An ordinary request to the WebSocket path, which is a client that
    // read the session document and then spoke the wrong protocol, or
    // an operator checking that the endpoint is there at all. RFC 9110
    // section 15.5.22 has exactly one answer for that and requires it
    // to name the protocol to switch to, so this route makes the
    // endpoint visible to anything that asks instead of letting it read
    // as a path that does not exist. That visibility is what a probe
    // needs: a WebSocket endpoint answers only an upgrade, and a
    // mounted one and an absent one are otherwise the same 404.
    //
    // The upgrade itself never arrives here. It is answered on the
    // server's own upgrade event, which is where the account and the
    // origin are both decided; this route carries no account data and
    // therefore asks for no account.
    router.get(JMAP_WEBSOCKET_PATH, function (req, res) {
      b.render.text(res,
        "This path is the JMAP WebSocket transport of RFC 8887. Connect with " +
        "Upgrade: websocket and Sec-WebSocket-Protocol: jmap.\n", {
          status:  426,
          headers: {
            "Upgrade":               "websocket",
            "Connection":            "Upgrade",
            "Sec-WebSocket-Version": "13",
          },
        });
    });
    router.post("/jmap/upload/:accountId", requireAccount, jmap.uploadHandler);
    router.get("/jmap/download/:accountId/:blobId/:name", requireAccount, jmap.downloadHandler);

    // ---- Sign in ----

    router.get("/sign-in", function (req, res) {
      if (req.user) { res.redirect(_inboxPath(req.user)); return; }
      _page(req, res, "sign-in", { address: "", problem: null });
    });

    router.post("/sign-in", signInLimit, async function (req, res) {
      var body = _bodyOf(req);
      var address = _str(body.address, "");
      var password = typeof body.password === "string" ? body.password : "";
      if (address.length === 0 || password.length === 0) {
        _page(req, res, "sign-in", {
          address: address,
          problem: "Enter the full address and the password for it.",
        }, { status: 400 });
        return;
      }
      // The peer, read from the socket rather than from a forwarded
      // header, because a header a client can write is a header a client
      // can use to choose which failure budget it spends. It reaches the
      // identity layer, which keeps the budget on the mailbox and uses
      // the peer only to recognize a source this account already signs
      // in from.
      var verdict = await store.accounts.authenticate({
        address:  address,
        password: password,
        source:   b.requestHelpers.clientIp(req),
      });
      if (!verdict.ok) {
        // The identity layer distinguishes a wrong credential from a
        // closed account, and telling the difference is the answer that
        // saves an operator a support round. It says nothing about
        // whether an address exists when the credential is wrong.
        //
        // A spent failure budget is told plainly for the same reason. It
        // answers nothing an attacker did not already know, because an
        // address with no account here reaches the same refusal, and it
        // is the difference between a reader who waits and a reader who
        // keeps retyping a password that is already right.
        // One arm per state a mailbox is held in, because an account
        // holder reading "your password is wrong" over a hold somebody
        // else applied resets a password that is already right and then
        // asks why it still will not open. The arms are not
        // interchangeable: two of these states are lifted by the
        // operator and the third is not lifted at all, so a shared
        // sentence would send half the readers to ask for something
        // nobody can do.
        var problem = verdict.reason === "account-suspended"
          ? "That account is suspended. The operator can reinstate it."
          : verdict.reason === "account-archived"
            ? "That account is archived and no longer accepts sign in. The operator " +
              "can reopen it."
            : verdict.reason === "account-erasing"
              ? "That account is being erased and cannot be reopened. Ask the operator " +
                "what is left of it."
              : verdict.reason === "too-many-attempts"
                ? "Too many failed attempts for that address. Try again later, " +
                  "or ask the operator to clear it."
                : "That address and password do not match an account here.";
        _page(req, res, "sign-in", { address: address, problem: problem }, { status: 401 });
        return;
      }
      var session = await b.session.create({
        userId: verdict.accountId,
        data:   { address: verdict.address, isAdmin: verdict.isAdmin },
        ttlMs:  SESSION_TTL_MS,
        req:    req,
      });
      _writeSessionCookie(res, session.token, session.expiresAt);
      // This account's own inbox, looked up rather than spelled out. The
      // message store bootstraps a folder set of its own under the same
      // names, so a redirect built from a constant can land on a mailbox
      // that belongs to nobody and is empty for that reason.
      res.redirect(_inboxPath({ id: verdict.accountId }));
    });

    router.post("/sign-out", async function (req, res) {
      var token = _cookieJar().read(req, SESSION_COOKIE);
      if (typeof token === "string" && token.length > 0) {
        // The token and nothing else. `destroy` takes one argument: it
        // removes the row and records nothing, and there is no reason
        // parameter to hand it. A second argument passed here would be
        // dropped without a word, which is worse than not writing one,
        // because the call would read as though the trail said why this
        // session ended when nothing anywhere does.
        await b.session.destroy(token);
      }
      _clearSessionCookie(res);
      _back(res, "/sign-in", "signed-out");
    });

    // Theme choice. A form post works with scripting off; the island
    // upgrades it to an in page switch.
    router.post("/prefs/theme", function (req, res) {
      var body = _bodyOf(req);
      var choice = _str(body.theme, "system");
      if (choice === "light" || choice === "dark") {
        _cookieJar().write(res, THEME_COOKIE, choice, {
          httpOnly: false, secure: true, sameSite: "Lax", path: "/",
          expires: new Date(Date.now() + THEME_TTL_MS).toUTCString(),
        });
      } else {
        _cookieJar().clear(res, THEME_COOKIE, {
          httpOnly: false, secure: true, sameSite: "Lax", path: "/",
        });
      }
      // Where the reader goes back to. A leading slash is not enough to
      // make a target a path: a browser resolving `/\host` folds the
      // backslash into a second slash and navigates to `host`, and a
      // tab inside the path is stripped before parsing. The redirect
      // helper refuses both shapes outright, so a target this route
      // waved through on a looser reading reached it and threw, and the
      // reader got an error page where a preference change belonged.
      // Composing `b.safeRedirect` puts one reading of a target in front
      // of the helper's, and it is the same reading.
      res.redirect(b.safeRedirect.resolve(_str(body.back, "/"), { fallback: "/" }));
    });

    // ---- Mailbox ----

    router.get("/", requireAccount, function (req, res) {
      res.redirect(_inboxPath(req.user));
    });

    router.get("/mail/:folder", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var name = _folderSegment(req.params.folder);
      var folder = _findFolder(folders, name);
      if (!folder) {
        _fail(req, res, 404, "No such folder", "This account has no folder named " + name + ".");
        return;
      }
      var before = _int(_queryOf(req).before, 0, 0, Number.MAX_SAFE_INTEGER);
      var page = await _pageBefore(account, folder, before, null);
      var messages = await _summarize(account, folder, page.rows);
      var quota = await agent.quota({ actor: _actorFor(account), folder: folder.storeName });
      var percent = _percent(quota.usedBytes, quota.capBytes);
      var base = _folderPath(folder);
      _page(req, res, "mailbox", {
        folders:      _decorateFolders(folders, folder.name),
        folder:       folder,
        messages:     messages,
        empty:        messages.length === 0,
        olderHref:    page.hasOlder && page.olderThan > 0
          ? _path(base + "?before=" + page.olderThan) : "",
        newestHref:   before > 0 ? base : "",
        actionPath:   _actionPath(folder),
        quotaUsed:    _byteSize(quota.usedBytes),
        quotaCount:   quota.usedCount,
        quotaCap:     quota.capBytes ? _byteSize(quota.capBytes) : "",
        quotaPercent: percent,
        quotaBucket:  _bucket(percent),
        searchQuery:  "",
      });
    });

    router.post("/mail/:folder/actions", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var actor = _actorFor(account, folders);
      var name = _folderSegment(req.params.folder);
      var folder = _findFolder(folders, name);
      if (!folder) {
        _fail(req, res, 404, "No such folder", "This account has no folder named " + name + ".");
        return;
      }

      var body = _bodyOf(req);
      var objectIds = _list(body.objectId);
      var action = _str(body.action, "");
      var base = _folderPath(folder);
      if (objectIds.length === 0) { _back(res, base); return; }
      if (objectIds.length > MAX_ACTION_IDS) {
        _fail(req, res, 400, "Too many messages at once",
          "One action carries at most " + MAX_ACTION_IDS + " messages. " +
          "Select fewer and send it again.");
        return;
      }
      var owned = await _allInFolder(account, folder, objectIds);
      if (!owned) {
        _fail(req, res, 404, "No such message",
          "Some of those messages are not in " + folder.label + ". " +
          "Open the folder again and repeat the action on what it shows.");
        return;
      }

      if (action === "read" || action === "unread") {
        await agent.flag({
          actor: actor, folder: folder.storeName, objectIds: objectIds,
          set:   action === "read" ? ["\\Seen"] : [],
          unset: action === "read" ? [] : ["\\Seen"],
        });
        _back(res, base, "flagged");
        return;
      }
      if (action === "flag" || action === "unflag") {
        await agent.flag({
          actor: actor, folder: folder.storeName, objectIds: objectIds,
          set:   action === "flag" ? ["\\Flagged"] : [],
          unset: action === "flag" ? [] : ["\\Flagged"],
        });
        _back(res, base, "flagged");
        return;
      }
      if (action === "move") {
        // The destination is a second folder name off the same request,
        // and it is resolved the same way the first one was. A name that
        // matches nothing must not send the reader back to the folder
        // with no notice, which reads on screen as a move that happened.
        var destination = _findFolder(folders, _folderSegment(body.destination));
        if (!destination) {
          _fail(req, res, 404, "No such folder",
            "This account has no folder to move those messages into. " +
            "Nothing was moved.");
          return;
        }
        // Moving messages into the folder they are already in is
        // nothing to do rather than an error. The page never offers it,
        // because the destination list leaves out the folder being
        // read, so this only answers a request built by hand.
        var filed = { moved: objectIds, refused: [] };
        if (destination.storeName !== folder.storeName) {
          filed = await mailbox.moveObjects(actor, folder.name, destination.name, objectIds);
        }
        // Only what moved, and the reader is told when something did
        // not. A page that says the mail was moved when some of it was
        // left behind is the same failure as one that says a message
        // was destroyed while its body is still on the volume.
        if (filed.moved.length > 0) {
          await _clearDeletedOutsideTrash(actor, destination, filed.moved);
        }
        _back(res, base, filed.refused.length > 0 ? "move-refused" : "moved");
        return;
      }
      if (action === "trash") {
        // A soft delete is a move into this account's own Trash plus the
        // mark that says so, composed here rather than taken from the
        // agent's own `delete`. That verb names its destination `Trash`
        // as a literal, which is right for a store holding one folder
        // set and wrong for one holding a set per account: the mail
        // lands in the bootstrap folder of that name, which belongs to
        // nobody, and it is then gone from the folder it left and absent
        // from the folder its owner would look in.
        var trash = _findRole(folders, TRASH_ROLE);
        if (!trash) {
          _fail(req, res, 404, "No Trash folder",
            "This account has no Trash to file those messages into. " +
            "Nothing was moved.");
          return;
        }
        // Trashing what is already in Trash is the mark alone. A move
        // from a folder to itself is refused, and correctly so.
        //
        // The move goes through the adapter because the folder and UID
        // rows a client addresses the message by are the adapter's. The
        // agent's own move carries the message store's row and leaves
        // those behind, which puts the message in neither folder on
        // IMAP while this page still lists it, and leaves it where no
        // delete verb can reach it.
        var inTrash = objectIds;
        if (trash.storeName !== folder.storeName) {
          inTrash = (await mailbox.moveObjects(actor, folder.name, trash.name, objectIds)).moved;
        }
        // The mark goes on what reached Trash and on nothing else. A
        // message marked deleted in a folder it was never filed into
        // reads as waiting to be purged from somewhere it is not.
        if (inTrash.length > 0) {
          await agent.flag({
            actor: actor, folder: trash.storeName, objectIds: inTrash,
            set: ["\\Deleted"], unset: [],
          });
        }
        _back(res, base, inTrash.length === objectIds.length ? "trashed" : "move-refused");
        return;
      }
      if (action === "purge") {
        // The adapter's verb, because a hard delete is three pieces of
        // state and the agent owns one of them. Driving the agent alone
        // tells the reader the message was permanently removed and
        // leaves its sealed octets on the volume with a row still
        // pointing at them.
        var outcome = await mailbox.expungeObjects(actor, folder.name, objectIds);
        var refused = Array.isArray(outcome.refused) ? outcome.refused : [];
        // Three answers, because the reader's next move differs across
        // all three and only one of them is a rule.
        //
        // Something keeping a message on purpose is a message that is
        // still here and still theirs, and naming the rule is the whole
        // of what they need. A volume that would not take one of the
        // acts that destroy it is not their business to fix and not
        // something reopening the folder explains. And an identifier
        // nothing holds is neither: the message has gone, which is the
        // end state the button asked for, so a page that told them
        // retention applied would name a rule that is not in force over
        // a message that is not there.
        var faulted = 0;
        var preserved = 0;
        for (var p = 0; p < refused.length; p += 1) {
          if (refused[p].outcome === "incomplete") faulted += 1;
          else if (refused[p].outcome === "preserved") preserved += 1;
        }
        _back(res, base, faulted > 0
          ? "purge-faulted"
          : (preserved > 0 ? "purge-refused" : "purged"));
        return;
      }
      _back(res, base);
    });

    router.get("/mail/:folder/:objectId", requireAccount, async function (req, res) {
      var account = req.user;
      var actor = _actorFor(account);
      var folders = _foldersFor(account);
      var name = _folderSegment(req.params.folder);
      var folder = _findFolder(folders, name);
      if (!folder) {
        _fail(req, res, 404, "No such folder", "This account has no folder named " + name + ".");
        return;
      }

      var objectId = _str(req.params.objectId, "");
      var opened = await agent.fetch({ actor: actor, folder: folder.storeName, objectId: objectId });
      if (!opened) {
        _fail(req, res, 404, "No such message", "That message is not in " + folder.label + ".");
        return;
      }

      var showImages = _str(_queryOf(req).images, "") === "on";
      var chain = await agent.thread({ actor: actor, objectId: objectId });
      var ids = Array.isArray(chain.thread) && chain.thread.length > 0 ? chain.thread : [objectId];

      var conversation = [];
      for (var i = 0; i < ids.length; i += 1) {
        var message = ids[i] === objectId
          ? opened
          : await agent.fetch({ actor: actor, folder: folder.storeName, objectId: ids[i] });
        if (!message) continue;
        // Per message, which is what makes the guarantee a guarantee: a
        // reader who asks to see one message's images has not asked to
        // tell every other sender in the conversation that it was open
        // on their screen. Each message that is still holding images
        // carries its own way to ask, which is that message's own page.
        var rendered = _renderBody(message, showImages && message.objectid === objectId);
        conversation.push({
          blockedCount: rendered.blockedCount,
          imagesHref:   rendered.blockedCount > 0
            ? _path(_messagePath(folder, message.objectid) + "?images=on") : "",
          objectId:  message.objectid,
          subject:   _headerText(_str(message.subject, "(no subject)")),
          from:      _displayName(message.from),
          fromAddr:  _bareAddress(message.from),
          initial:   _initial(message.from),
          to:        _str(message.to, ""),
          received:  _when(message.internalDate || message.receivedAt,
            { dateStyle: "full", timeStyle: "short" }),
          sizeLabel: _byteSize(message.sizeBytes),
          bodyHtml:  rendered.html,
          isHtml:    rendered.isHtml,
          legalHold: message.legalHold === true,
          isOpened:  message.objectid === objectId,
        });
      }

      // Opening a message marks it read, which is the reader's intent.
      var flags = Array.isArray(opened.flags) ? opened.flags : [];
      if (flags.indexOf("\\Seen") === -1) {
        await agent.flag({
          actor: actor, folder: folder.storeName, objectIds: [objectId],
          set: ["\\Seen"], unset: [],
        });
      }

      var base = _folderPath(folder);
      _page(req, res, "conversation", {
        folders:      _decorateFolders(folders, folder.name),
        folder:       folder,
        subject:      _headerText(_str(opened.subject, "(no subject)")),
        messages:     conversation,
        threadCount:  conversation.length,
        isThread:     conversation.length > 1,
        showImages:   showImages,
        backHref:     base,
        actionPath:   _actionPath(folder),
        objectId:     objectId,
        replyHref:    _composePath(folder, objectId, "reply"),
        replyAllHref: _composePath(folder, objectId, "reply-all"),
        forwardHref:  _composePath(folder, objectId, "forward"),
        moveTargets:  folders.filter(function (f) { return f.name !== folder.name; }),
      }, showImages ? { headers: { "Content-Security-Policy": CSP_WITH_IMAGES } } : undefined);
    });

    // ---- Search ----

    router.get("/search", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var query = _queryOf(req);
      var term = _str(query.q, "");
      var scope = _folderSegment(query.folder);
      // A search names its folder or it does not. When it names one, the
      // name is resolved like every other folder name a request carries
      // and a miss is a miss: falling back to the inbox would answer a
      // question the reader did not ask and label the results as though
      // it had. When it names none, the inbox is where a search starts.
      var folder;
      if (scope.length > 0) {
        folder = _findFolder(folders, scope);
        if (!folder) {
          _fail(req, res, 404, "No such folder",
            "This account has no folder named " + scope + " to search.");
          return;
        }
      } else {
        folder = _findFolder(folders, DEFAULT_FOLDER) || folders[0] || null;
      }
      var messages = [];
      if (folder && term.length > 0) {
        var page = await _pageBefore(account, folder, 0, { text: term });
        messages = await _summarize(account, folder, page.rows);
      }
      _page(req, res, "search", {
        folders:     _decorateFolders(folders, folder ? folder.name : ""),
        folder:      folder,
        searchQuery: term,
        searched:    term.length > 0,
        messages:    messages,
        hasResults:  messages.length > 0,
        empty:       term.length > 0 && messages.length === 0,
        actionPath:  folder ? _actionPath(folder) : "",
      });
    });

    // ---- Compose ----

    // Everything the compose view renders, for the form and for every
    // re-render of it that carries a refusal.
    //
    // The author picker is offered only when there is a choice to make.
    // An account holding one address is most accounts on most servers,
    // and a control with a single option in it is clutter on the form a
    // mailbox owner uses more than any other. What the browser is shown
    // decides nothing: the set is read from the store again on the post,
    // so an account that was offered no picker is measured against the
    // same set as one that was, and an author typed into the request by
    // hand meets the same refusal.
    function _composeScope(account, folders, draft, chosen, problem) {
      var held = _identitiesFor(account);
      // The address shown and the address selected are the same one, and
      // it is an entry from the set rather than whatever was passed in.
      // The set holds canonical addresses, so a caller naming the same
      // mailbox in another spelling still lands on the entry rather than
      // on a picker with nothing selected and a sentence disagreeing
      // with it. An account's own address leads the set, which is what
      // makes it the fallback.
      var at = 0;
      for (var i = 0; i < held.length; i += 1) {
        if (held[i].address === chosen) { at = i; break; }
      }
      var showing = held.length > 0 ? held[at].address : chosen;
      var authors = held.map(function (identity, index) {
        return { address: identity.address, isChosen: index === at };
      });
      return {
        folders:         _decorateFolders(folders, ""),
        draft:           draft,
        problem:         problem,
        fromAddr:        showing,
        authors:         authors,
        mayChooseAuthor: authors.length > 1,
      };
    }

    router.get("/compose", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var query = _queryOf(req);
      var draft = { to: "", cc: "", bcc: "", subject: "", text: "", inReplyTo: "", references: "" };
      var source = _str(query.source, "");
      var mode = _str(query.mode, "");
      if (source.length > 0) {
        var folder = _findFolder(folders, _folderSegment(query.folder));
        var message = folder ? await agent.fetch({
          actor: _actorFor(account), folder: folder.storeName, objectId: source,
        }) : null;
        if (message) {
          draft.inReplyTo  = message.messageId || "";
          draft.references = _references(message).join(" ");
          if (mode === "forward") {
            draft.subject = _headerText(_forwardSubject(message.subject));
            draft.text = "\n\nForwarded message from " + _bareAddress(message.from) + ":\n\n" +
              _quoteBody(message) + "\n";
          } else {
            draft.subject = _headerText(_replySubject(message.subject));
            draft.to = _bareAddress(message.from);
            if (mode === "reply-all") {
              // The author comes off her own copy list by mailbox, not by
              // spelling. The sender chose how to write her address, and
              // `Alice@Example.com` and `alice+list@example.com` are the
              // same mailbox the routing layer delivered to.
              draft.cc = _addresses(message.to)
                .map(_bareAddress)
                .filter(function (addr) {
                  return addr.length > 0 && !_sameMailbox(addr, account.address);
                })
                .join(", ");
            }
            draft.text = "\n\nOn " +
              _when(message.internalDate, { dateStyle: "long", timeStyle: "short" }) +
              ", " + _displayName(message.from) + " wrote:\n\n" + _quoteBody(message) + "\n";
          }
        }
      }
      _page(req, res, "compose", _composeScope(account, folders, draft, account.address, null));
    });

    router.post("/compose", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var body = _bodyOf(req);
      var draft = {
        to:         _str(body.to, ""),
        cc:         _str(body.cc, ""),
        bcc:        _str(body.bcc, ""),
        subject:    _str(body.subject, ""),
        text:       typeof body.text === "string" ? body.text : "",
        inReplyTo:  _str(body.inReplyTo, ""),
        references: _str(body.references, ""),
      };

      // The author the form posted, measured before anything else is
      // read off the request. A field naming who a message is from is a
      // request parameter like any other, so it is resolved against the
      // set the store answers with rather than trusted for having come
      // off a page this server rendered.
      var author = _resolveAuthor(account, _str(body.from, ""));
      if (!author.ok) {
        _recordAuthorRefusal("compose", author.rejected, author.allowed);
        _page(req, res, "compose",
          _composeScope(account, folders, draft, account.address, _authorRefusal(author)),
          { status: 400 });
        return;
      }

      // All three lists are lists of recipients, so all three are read
      // and checked the same way. A copy list that cannot be read is the
      // reader's to correct on the form: sending it on and reporting
      // whatever the next server along says about it puts a wire refusal
      // in front of somebody who mistyped an address.
      var recipients = _addresses(draft.to).map(_bareAddress);
      var copies     = _addresses(draft.cc).map(_bareAddress);
      var blind      = _addresses(draft.bcc).map(_bareAddress);
      var problem = recipients.length === 0
        ? "Name at least one recipient."
        : _firstUnacceptable(recipients.concat(copies, blind));
      if (problem !== null) {
        _page(req, res, "compose",
          _composeScope(account, folders, draft, author.address, problem), { status: 400 });
        return;
      }

      try {
        await composer.send({
          from:         author.address,
          // The return path stays the account's own address whatever the
          // author is. Bounces belong in the mailbox of whoever sent the
          // message rather than in a shared one nobody reads, and leaving
          // it here is what lets this surface offer an alias at all: an
          // ordinary desktop client derives the envelope from the identity
          // it is configured with and puts the alias in both places, which
          // the submission listener's envelope binding refuses. This one
          // composes the envelope itself. DMARC still lines up, because
          // the message is signed for the domain in From.
          envelopeFrom: account.address,
          to:           recipients,
          cc:           copies,
          bcc:          blind,
          subject:      draft.subject,
          text:         draft.text,
          inReplyTo:    draft.inReplyTo.length > 0 ? draft.inReplyTo : undefined,
          references:   draft.references.length > 0 ? draft.references.split(/\s+/) : undefined,
        }, { actor: _actorFor(account) });
      } catch (sendErr) {
        log.error("outbound refused for " + account.address + ": " + sendErr.message);
        _page(req, res, "compose",
          _composeScope(account, folders, draft, author.address, sendErr.message),
          { status: 502 });
        return;
      }
      _back(res, _inboxPath(account), "sent");
    });

    // ---- Administration ----

    router.get("/admin", requireAccount, requireAdmin, async function (req, res) {
      var domains = _asArray(await store.domains.list({}));
      var accounts = _asArray(await store.accounts.list({ includeArchived: true }));
      var waiting = _asArray(await delivery.queue.list());
      var keyed = _asArray(await dkim.list());
      var pending = domains.filter(function (d) { return d.dnsAcknowledged !== true; });
      var selectorCount = keyed.reduce(function (total, record) {
        return total + (Array.isArray(record.selectors) ? record.selectors.length : 0);
      }, 0);
      _page(req, res, "admin/overview", {
        nav:            _adminNav("overview"),
        domainCount:    domains.length,
        accountCount:   accounts.length,
        queueDepth:     waiting.length,
        selectorCount:  selectorCount,
        pendingDomains: pending.map(function (d) { return { domain: d.domain }; }),
        hasPending:     pending.length > 0,
      });
    });

    async function _renderDomains(req, res, problem, status) {
      var domains = _asArray(await store.domains.list({}));
      var counts = await _accountCounts();
      _page(req, res, "admin/domains", {
        nav:     _adminNav("domains"),
        domains: domains.map(function (d) { return _domainRow(d, counts); }),
        problem: problem || null,
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/domains", requireAccount, requireAdmin, async function (req, res) {
      await _renderDomains(req, res, null, 0);
    });

    router.post("/admin/domains", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      // The verb is read with NO default, and every route on these pages
      // reads it the same way. A default folds the two ways this field
      // can fail to arrive into one of the verbs: a form posted without
      // it, and a value naming something this page does not do, both land
      // on whichever verb the default names. Neither is a request for
      // that verb. An unrecognized word therefore falls through to the
      // listing below, which is the only answer that cannot be wrong.
      var action = _str(body.action, "");
      if (action !== "add" && action !== "confirm-dns" &&
          action !== "enable" && action !== "disable") {
        await _renderDomains(req, res, null, 0);
        return;
      }
      try {
        // Folded once, through the derivation the identity layer owns,
        // and then used for everything this handler records as well as
        // for the verb it calls. The verbs fold what they are given
        // anyway, so a name folded only for case still reaches the
        // right row; what does not is the audit row written here, which
        // would name the spelling the form carried rather than the
        // domain that moved, and the sentence the operator reads back.
        // A name this cannot fold is refused by the same derivation,
        // in this server's own words rather than the guard's.
        var name = address.canonicalDomain(_str(body.domain, ""), "domain");
        if (action === "confirm-dns") {
          await store.domains.acknowledgeDns({
            domain: name, acknowledged: true, acknowledgedBy: req.user.address,
          });
          _back(res, "/admin/domains", "dns-confirmed");
          return;
        }
        if (action === "disable" || action === "enable") {
          if (action === "disable") {
            // Measured here while a refusal still costs nothing, so an
            // operator is never asked to type a name for a change that
            // was going to be refused anyway. The authority is the same
            // question asked again below, beside the write it
            // authorizes.
            var withdrawn = _strandingRefusal({
              excludeId:       null,
              disablingDomain: name,
              what:            "Withdrawing " + name,
              cliVerb:         "domain disable <domain> --reason ...",
              resource:        { kind: "domain", id: name },
              attempted:       "domain-disable",
            });
            if (withdrawn !== null) {
              await _renderDomains(req, res, withdrawn, 400);
              return;
            }
          }
          // Withdrawing is the wider of the two acts on this page by a
          // long way: every mailbox at the domain stops taking mail at
          // once, and none of their owners asked for it or is told. So
          // it names itself back. Putting a domain in service again
          // takes the reason and nothing more, because the button that
          // undoes it is the one beside it.
          var counted = await _accountCounts();
          var held = Object.prototype.hasOwnProperty.call(counted, name) ? counted[name] : 0;
          var domainAsk = _pending({
            path:    "/admin/domains",
            action:  action,
            carry:   [{ name: "domain", value: name }],
            title:   action === "disable"
              ? "Stop accepting mail for " + name + "?"
              : "Accept mail for " + name + " again?",
            summary: "This domain holds " + held + " account(s) on this server.",
            consequence: action === "disable"
              ? "Every mailbox at " + name + " stops receiving mail the moment this is " +
                "saved, and stops signing in. Nothing already delivered is touched, and " +
                "senders get a refusal at the wire rather than a report from here. Putting " +
                "the domain back in service is one press on this page."
              : name + " starts taking mail again, and its accounts sign in again. " +
                "Anything sent while it was withdrawn was refused at the wire and is not " +
                "recoverable from here.",
            phrase:     action === "disable" ? name : "",
            noun:       "domain",
            prompt:     action === "disable" ? "Type the domain to confirm" : "",
            promptHint: "Exactly as it is written above. Nothing else confirms this.",
            needsReason: true,
            verb:       action === "disable" ? "Stop accepting mail" : "Accept mail again",
            fineprint:  "The reason is recorded against this domain in the audit trail. " +
              "Leaving this page changes nothing.",
          });
          if (_stillAsking(req, res, body, domainAsk)) return;
          // The authority, and it sits here rather than above because
          // everything between the two asks suspends: the count the page
          // named, the page itself, and the operator reading it. A
          // second withdrawal that landed in any of those windows read
          // the administrator this one is about to strand, so both
          // measurements are true of a server neither of them will
          // leave behind. This one is taken with nothing between it and
          // the write.
          if (action === "disable") {
            var stranding = _strandingRefusal({
              excludeId:       null,
              disablingDomain: name,
              what:            "Withdrawing " + name,
              cliVerb:         "domain disable <domain> --reason ...",
              resource:        { kind: "domain", id: name },
              attempted:       "domain-disable",
            });
            if (stranding !== null) {
              await _renderDomains(req, res, stranding, 400);
              return;
            }
          }
          await store.domains.setStatus({
            domain: name,
            status: action === "disable" ? "disabled" : "active",
            // No default. The identity layer refuses an empty reason,
            // and a sentence supplied here would answer that refusal
            // with words nobody chose.
            reason: _str(body.reason, ""),
          });
          _back(res, "/admin/domains", "domain-saved");
          return;
        }
        await store.domains.add({ domain: name });
        _back(res, "/admin/domains", "domain-added");
      } catch (err) {
        await _renderDomains(req, res, _refusalText(err, "That change could not be made."), 400);
      }
    });

    async function _renderAccounts(req, res, problem, status, limit, offset) {
      var accounts = _asArray(await store.accounts.list({
        limit: limit, offset: offset, includeArchived: true,
      }));
      var domains = _asArray(await store.domains.list({ status: "active" }));
      _page(req, res, "admin/accounts", {
        nav:      _adminNav("accounts"),
        accounts: accounts.map(_accountRow),
        domains:  domains.map(function (d) { return { domain: d.domain }; }),
        problem:  problem || null,
        nextHref: accounts.length === limit
          ? _path("/admin/accounts?offset=" + (offset + limit) + "&limit=" + limit) : "",
        prevHref: offset > 0
          ? _path("/admin/accounts?offset=" + Math.max(0, offset - limit) + "&limit=" + limit) : "",
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/accounts", requireAccount, requireAdmin, async function (req, res) {
      var query = _queryOf(req);
      await _renderAccounts(req, res, null, 0,
        _int(query.limit, ADMIN_PAGE_SIZE, 1, ADMIN_PAGE_MAX),
        _int(query.offset, 0, 0, Number.MAX_SAFE_INTEGER));
    });

    router.post("/admin/accounts", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      var action = _str(body.action, "");
      var id = _str(body.id, "");
      if (action !== "add" && action !== "suspend" && action !== "reinstate" &&
          action !== "archive" && action !== "grant-role" && action !== "revoke-role") {
        await _renderAccounts(req, res, null, 0, ADMIN_PAGE_SIZE, 0);
        return;
      }
      try {
        // The three verbs that take this console away from somebody are
        // measured against what would be left, and the same measurement
        // answers for an account that administers nothing: excluding one
        // changes no count, so the caller's own row keeps the answer
        // above zero.
        //
        // Revoking the role joins the other two here rather than growing
        // a guard of its own, because it is the same question asked about
        // the same set. It names no command line verb, and the absence is
        // the point: this console is the only place the role is granted,
        // so the way past this refusal is to give it to somebody else.
        if (action === "suspend" || action === "archive" || action === "revoke-role") {
          var stranding = _strandingRefusal({
            excludeId:       id,
            disablingDomain: null,
            what:            action === "suspend"
              ? "Suspending that account"
              : (action === "archive"
                ? "Archiving that account"
                : "Taking the operator interface from that account"),
            cliVerb:         action === "suspend"
              ? "account suspend <address> --reason ..."
              : (action === "archive" ? "account remove <address> --reason ..." : null),
            resource:        { kind: "account", id: id },
            attempted:       "account-" + action,
          });
          if (stranding !== null) {
            await _renderAccounts(req, res, stranding, 400, ADMIN_PAGE_SIZE, 0);
            return;
          }
        }
        if (action === "reinstate") {
          await store.accounts.reinstate({ id: id });
          _back(res, "/admin/accounts", "reinstated");
          return;
        }
        if (action === "suspend" || action === "archive" ||
            action === "grant-role" || action === "revoke-role") {
          // Resolved before anything is asked, so the page names the row
          // this act will actually reach rather than a value off the
          // request. An id naming nothing is refused here, in the
          // identity layer's own words, before an operator is asked to
          // type anything.
          var subject = await store.accounts.get(id);
          if (!subject) {
            await _renderAccounts(req, res,
              "That account is not on this server. Nothing has been changed. Open the list " +
              "again: it may have been archived or erased from another window.",
              400, ADMIN_PAGE_SIZE, 0);
            return;
          }
          var accountAsk = _accountAsk(action, subject);
          if (_stillAsking(req, res, body, accountAsk)) return;

          // The authority, and it sits here rather than above because
          // everything between the two asks suspends: the row being
          // resolved, the page that names it, and the operator reading
          // it. A second demotion that landed in any of those windows
          // read the administrator this one is about to take, so both
          // measurements are true of a server neither of them will leave
          // behind. This one is taken with nothing between it and the
          // write, and it is taken for the three verbs that reduce the
          // set. Granting the role is not one of them: it can only make
          // the answer wider.
          if (action === "suspend" || action === "archive" || action === "revoke-role") {
            var standing = _strandingRefusal({
              excludeId:       subject.id,
              disablingDomain: null,
              what:            action === "suspend"
                ? "Suspending that account"
                : (action === "archive"
                  ? "Archiving that account"
                  : "Taking the operator interface from that account"),
              cliVerb:         action === "suspend"
                ? "account suspend <address> --reason ..."
                : (action === "archive" ? "account remove <address> --reason ..." : null),
              resource:        { kind: "account", id: subject.id },
              attempted:       "account-" + action,
            });
            if (standing !== null) {
              await _renderAccounts(req, res, standing, 400, ADMIN_PAGE_SIZE, 0);
              return;
            }
          }

          if (action === "suspend") {
            // No default on the reason. The identity layer refuses an
            // empty one, and a sentence supplied here would answer that
            // refusal with words nobody chose: an audit column that is
            // present and identical on every row reads like somebody
            // wrote it, and tells a later reader less than an empty one.
            await store.accounts.suspend({ id: subject.id, reason: _str(body.reason, "") });
            _back(res, "/admin/accounts", "suspended");
            return;
          }
          if (action === "archive") {
            // Archive, never erase. Erasing the row is a separate
            // decision with its own recorded reason, and it is not one a
            // single button press on a list page should be able to make.
            await store.accounts.delete({ id: subject.id, reason: _str(body.reason, "") });
            _back(res, "/admin/accounts", "archived");
            return;
          }
          await store.accounts.setAdmin({
            id:      subject.id,
            isAdmin: action === "grant-role",
            reason:  _str(body.reason, ""),
          });
          _back(res, "/admin/accounts",
            action === "grant-role" ? "role-granted" : "role-revoked");
          return;
        }
        await store.accounts.create({
          address:     _str(body.address, "").toLowerCase(),
          displayName: _str(body.displayName, ""),
          password:    typeof body.password === "string" ? body.password : "",
          quotaBytes:  _int(body.quotaBytes, 0, 0, Number.MAX_SAFE_INTEGER),
          isAdmin:     _str(body.isAdmin, "") === "on",
        });
        _back(res, "/admin/accounts", "account-added");
      } catch (err) {
        await _renderAccounts(req, res,
          _refusalText(err, "That account could not be changed."), 400, ADMIN_PAGE_SIZE, 0);
      }
    });

    // The lockouts this server has recorded, newest first, with the
    // releases read alongside them so a budget an operator has already
    // given back stops reading as one still holding somebody out.
    //
    // Two reads rather than one over the whole resource kind: every wrong
    // password writes a row of its own, so a single capped read would
    // come back as a page of individual failures with the lockouts they
    // caused pushed off the end of it.
    async function _lockoutTrail() {
      var now = Date.now();
      // The events a lockout writes are emitted from the authentication
      // path, which cannot afford to wait for a disk write, so they queue
      // and land within the second. An operator opening this page is
      // usually looking for a lockout that happened moments ago, and a
      // page that answered "nothing recorded" about the call they are
      // taking would be worse than useless. Draining first is what makes
      // the answer the current one.
      await b.audit.flush();
      // Each read is charged to the operator who asked for it, exactly as
      // the audit page's is: reading who has been locked out and from
      // where is a read of somebody else's trail.
      var engaged = _asArray(await b.audit.query({
        action: LOCKOUT_ENGAGED,  order: "desc",
        limit:  LOCKOUT_TRAIL_ROWS, actor: auditActor.current(),
      }));
      var unlocked = _asArray(await b.audit.query({
        action: LOCKOUT_UNLOCKED, order: "desc",
        limit:  LOCKOUT_TRAIL_ROWS, actor: auditActor.current(),
      }));
      var releasedAt = Object.create(null);
      for (var i = 0; i < unlocked.length; i += 1) {
        var key = _lockoutKey(unlocked[i].resourceId).key;
        var at = typeof unlocked[i].recordedAt === "number" ? unlocked[i].recordedAt : 0;
        if (!Object.prototype.hasOwnProperty.call(releasedAt, key) || releasedAt[key] < at) {
          releasedAt[key] = at;
        }
      }
      var context = await _lockoutContext(engaged);
      return engaged.map(function (row) { return _lockoutRow(row, now, releasedAt, context); });
    }

    // The account and the counter behind each recorded row, resolved
    // once for the page rather than once per row. A mailbox that has run
    // out several times has a row for each, and the budget kept against
    // a mailbox and the one kept against a machine are two rows naming
    // one address, so a lookup per row reads the same sealed column over
    // and over. Both maps are keyed on what a row carries: the address
    // for the account, the whole counter key for the reading.
    //
    // Each row names ONE budget, the mailbox one or the pair one, and
    // the reading kept for it is that same budget's. Reading both and
    // showing them together would put two numbers in a row that answers
    // for one of them, which is exactly the quiet contradiction this
    // page exists to avoid.
    //
    // A row whose address holds no mailbox here gets no reading. The
    // identity layer refuses to read a budget for one, and correctly, so
    // the row is left with none rather than the page asking anyway and
    // turning an unanswerable question into a failed render.
    async function _lockoutContext(rows) {
      var accounts = Object.create(null);
      var live = Object.create(null);
      for (var i = 0; i < rows.length; i += 1) {
        var parts = _lockoutKey(rows[i].resourceId);
        if (!Object.prototype.hasOwnProperty.call(accounts, parts.address)) {
          accounts[parts.address] = parts.address.indexOf("@") !== -1
            ? store.accounts.get(parts.address)
            : null;
        }
        var account = accounts[parts.address];
        if (!account) continue;
        if (Object.prototype.hasOwnProperty.call(live, parts.key)) continue;
        var state = await store.accounts.lockoutState({
          address: account.address,
          source:  parts.source,
        });
        var reading = parts.source.length > 0 ? state.peer : state.mailbox;
        // A pair budget whose recorded key the identity layer could not
        // read back answers null, and null is not a clear budget. Left
        // absent, the row says so rather than saying clear.
        if (reading !== null) live[parts.key] = _budgetNow(reading);
      }
      return { accounts: accounts, live: live };
    }

    async function _renderLockouts(req, res, problem, status) {
      var rows = await _lockoutTrail();
      var query = _queryOf(req);
      var wantAddress = _str(query.address, "");
      var wantSource  = _str(query.source, "");
      // Filled in from a row this read actually returned rather than from
      // the request, so nothing off the query string is echoed back into
      // the form. A link naming a pair that is no longer listed fills in
      // nothing, which is the honest outcome: the operator is looking at
      // a page that no longer says what the link was written against.
      var filled = { address: "", source: "" };
      rows.forEach(function (row) {
        if (row.isMailbox && row.address === wantAddress && row.source === wantSource) {
          filled = { address: row.address, source: row.source };
        }
      });
      var standing = rows.filter(function (row) { return row.standing; });

      // The counters for one mailbox, asked directly. The table above
      // records a budget only once it has run out, so it carries neither
      // a mailbox whose attempts are running down nor one that has never
      // been touched, and both are what somebody taking a support call
      // is asking about.
      //
      // The address the answer names comes back from the identity layer,
      // which reads it out of its own account table, so nothing off the
      // query string is echoed into the page. A refusal is shown rather
      // than swallowed: a typed address this server hosts no mailbox at
      // has to say so, or an operator reads an empty answer as a clear
      // budget. The table itself still renders, because the operator
      // opened this page during an incident and one bad lookup is not a
      // reason to answer them with nothing.
      var lookup = null;
      var lookupProblem = null;
      if (wantAddress.length > 0) {
        try {
          var state = await store.accounts.lockoutState({
            address: wantAddress,
            source:  wantSource,
          });
          lookup = {
            address: state.address,
            source:  state.source,
            mailbox: _budgetNow(state.mailbox),
            peer:    state.peer === null ? null : _budgetNow(state.peer),
            // A machine was named and no budget could be read for it,
            // which means the identity layer read nothing addressable in
            // it. Said out loud, because an operator who typed a machine
            // and got only the mailbox row back would otherwise read the
            // silence as that machine being clear.
            sourceUnreadable: wantSource.length > 0 && state.peer === null,
          };
        } catch (err) {
          lookupProblem = _refusalText(err, "That mailbox's sign-in budget could not be read.");
        }
      }

      _page(req, res, "admin/lockouts", {
        nav:      _adminNav("lockouts"),
        rows:     rows,
        empty:    rows.length === 0,
        standing: standing.length,
        anyStanding: standing.length > 0,
        filled:   filled,
        lookup:   lookup,
        lookupProblem: lookupProblem,
        problem:  problem || null,
        // The bound the page describes, taken from the value that
        // enforces it. Spelled out in the prose it drifts the moment the
        // ceiling moves, and a page telling an operator a number the
        // server does not hold is worse than a page that says nothing:
        // they wait out a slot that already ended, or reach one they
        // were told they had room inside.
        signInPosts:   SIGN_IN_POSTS_PER_WINDOW,
        signInMinutes: SIGN_IN_WINDOW_MS / b.constants.TIME.minutes(1),
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/lockouts", requireAccount, requireAdmin, async function (req, res) {
      await _renderLockouts(req, res, null, 0);
    });

    // Which notice a release earns, read off what it ACTUALLY gave back
    // rather than off what the operator typed. The identity layer answers
    // for the two budgets separately: `peer` is null when no machine was
    // named, and false when one was named and its budget was found
    // already clear. Those are different answers and they send an
    // operator to different places, so they take different notices.
    function _lockoutNotice(verdict) {
      if (verdict.peer === null) {
        return verdict.mailbox ? "lockout-released" : "lockout-clear";
      }
      if (verdict.mailbox && verdict.peer) return "lockout-released-both";
      if (verdict.mailbox) return "lockout-released-mailbox";
      if (verdict.peer) return "lockout-released-machine";
      return "lockout-clear-both";
    }

    router.post("/admin/lockouts", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      try {
        // Nothing here is defaulted, resolved or pre-checked. The
        // identity layer refuses an address it hosts no mailbox at,
        // refuses an empty reason, and refuses a machine it cannot read
        // as an address, and it refuses that machine BEFORE it releases
        // anything, so a machine it cannot read costs the operator one
        // retype rather than half a release under an answer that reads
        // as a fix. A second copy of any of those rules in this layer is
        // a second answer waiting to disagree with the one that actually
        // decides, and it would answer first: a post carrying both a bad
        // address and a machine would surface the machine's refusal in
        // place of the address's. Every refusal that layer raises is
        // written for a person and is what the page shows.
        var verdict = await store.accounts.unlock({
          address: _str(body.address, ""),
          reason:  _str(body.reason, ""),
          // Naming a machine releases the smaller budget kept against
          // that one source as well; leaving it empty does not touch it,
          // which is why the form asks for it and why the notice says
          // which of the two it is reporting on.
          source:  _str(body.source, ""),
        });
        _back(res, "/admin/lockouts", _lockoutNotice(verdict));
      } catch (err) {
        await _renderLockouts(req, res,
          _refusalText(err, "That mailbox could not be released."), 400);
      }
    });

    async function _renderAliases(req, res, problem, status) {
      var aliases = _asArray(await store.aliases.list({ includeDisabled: true }));
      var domains = _asArray(await store.domains.list({ status: "active" }));
      _page(req, res, "admin/aliases", {
        nav:     _adminNav("aliases"),
        aliases: aliases.map(_aliasRow),
        domains: domains.map(function (d) { return { domain: d.domain }; }),
        problem: problem || null,
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/aliases", requireAccount, requireAdmin, async function (req, res) {
      await _renderAliases(req, res, null, 0);
    });

    router.post("/admin/aliases", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      var action = _str(body.action, "");
      if (action !== "add" && action !== "remove") {
        await _renderAliases(req, res, null, 0);
        return;
      }
      try {
        if (action === "remove") {
          // The row is resolved before anything is asked, because the
          // page has to name what it is about to remove and because an
          // alias removed from another window since this list was drawn
          // is a request that should refuse rather than one that should
          // be confirmed.
          var id = _str(body.id, "");
          var held = _asArray(await store.aliases.list({ includeDisabled: true }))
            .filter(function (row) { return row.id === id; })[0] || null;
          if (held === null) {
            await _renderAliases(req, res,
              "This server holds no such alias. Nothing has been changed. Open the list " +
              "again: it may have been removed from another window.", 400);
            return;
          }
          // A catch-all has no address of its own to type, so the domain
          // it claims is what names it. Both are values the identity
          // layer answered with rather than anything off the request.
          var named = held.isCatchAll ? held.domain : held.address;
          var aliasAsk = _pending({
            path:    "/admin/aliases",
            action:  action,
            carry:   [{ name: "id", value: held.id }],
            title:   held.isCatchAll
              ? "Stop claiming everything at " + held.domain + "?"
              : "Remove the alias for " + held.address + "?",
            summary: "This delivers to " + held.destination + " today.",
            consequence: held.isCatchAll
              ? "Mail to any address at " + held.domain + " that no mailbox and no other " +
                "alias matches will be refused at the wire instead of reaching " +
                held.destination + ". The row is deleted rather than disabled, so putting " +
                "it back means writing it again from what you remember of it."
              : "Mail to " + held.address + " will be refused at the wire instead of " +
                "reaching " + held.destination + ". The row is deleted rather than " +
                "disabled, so putting it back means writing it again.",
            subjects: [{ name: named, detail: "delivers to " + held.destination }],
            phrase:     named,
            noun:       held.isCatchAll ? "domain" : "address",
            prompt:     held.isCatchAll
              ? "Type the domain to confirm" : "Type the address to confirm",
            promptHint: "Exactly as it is written above. Nothing else confirms this.",
            needsReason: true,
            verb:       "Remove this alias",
            fineprint:  "One leg of a fan-out at a time: an address forwarding to several " +
              "people has a row each, and this removes the one named above. The reason is " +
              "recorded in the audit trail. Leaving this page changes nothing.",
          });
          if (_stillAsking(req, res, body, aliasAsk)) return;
          await store.aliases.remove({
            // No default on the reason. The identity layer refuses an
            // empty one, and a sentence supplied here would answer that
            // refusal with words nobody chose.
            id: held.id, reason: _str(body.reason, ""),
          });
          _back(res, "/admin/aliases", "alias-removed");
          return;
        }
        var destinations = _addresses(body.destination).map(function (d) {
          return _bareAddress(d).toLowerCase();
        });
        if (destinations.length === 0) {
          await _renderAliases(req, res, "Name at least one destination for the alias.", 400);
          return;
        }
        // The identity layer stores one destination per row, so a source
        // that fans out to several addresses is several rows. Adding them
        // one at a time means a refusal on the third names the third
        // rather than discarding the two that were already accepted.
        //
        // The domain goes over as it was typed. The identity layer
        // derives it, and that derivation folds the DNS root's trailing
        // dot as well as the case, so a fold written here would agree
        // with it on three spellings of every name and differ on the
        // fourth. Two rules about one name is the drift, whichever of
        // them happens to be reached first.
        var catchAll = _str(body.catchAll, "") === "on";
        for (var i = 0; i < destinations.length; i += 1) {
          var input = { destination: destinations[i] };
          if (catchAll) {
            input.domain = _str(body.domain, "");
            input.catchAll = true;
          } else {
            input.address = _str(body.address, "").toLowerCase();
          }
          await store.aliases.add(input);
        }
        _back(res, "/admin/aliases", "alias-added");
      } catch (err) {
        await _renderAliases(req, res, _refusalText(err, "That alias could not be changed."), 400);
      }
    });

    async function _renderDkim(req, res, problem, status) {
      var cards = _dkimCards(_asArray(await dkim.list()));
      var domains = _asArray(await store.domains.list({ status: "active" }));
      var keyed = Object.create(null);
      cards.forEach(function (card) { keyed[card.domain] = true; });
      _page(req, res, "admin/dkim", {
        nav:     _adminNav("dkim"),
        cards:   cards,
        empty:   cards.length === 0,
        unkeyed: domains
          .filter(function (d) { return keyed[d.domain] !== true; })
          .map(function (d) { return { domain: d.domain }; }),
        problem: problem || null,
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/dkim", requireAccount, requireAdmin, async function (req, res) {
      await _renderDkim(req, res, null, 0);
    });

    router.post("/admin/dkim", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      // As typed. Every verb below hands this to the signer, which reads
      // it through the identity layer's derivation, and that derivation
      // folds the DNS root's trailing dot as well as the case. A fold
      // written here would settle only the case half and leave the
      // signer to settle the rest, which is one name with two rules
      // about it and the second rule already differs by a dot.
      var domain = _str(body.domain, "");
      var action = _str(body.action, "");
      if (action !== "sweep" && action !== "generate" &&
          action !== "retire" && action !== "rotate") {
        await _renderDkim(req, res, null, 0);
        return;
      }
      try {
        if (action === "sweep") {
          // Not gated, and the reason is what it reaches. A sweep
          // removes the rows of selectors whose overlap has ALREADY
          // elapsed, which are the records the operator was told they
          // could delete, and whose private halves were destroyed when
          // the pair was retired. There is nothing here that retirement
          // did not already take. The one form that would need a
          // question, withdrawing a record before its overlap runs out,
          // is not something this page offers.
          // The answer is read rather than assumed. A sweep removes the
          // row of a selector whose overlap has elapsed and then erases
          // the sealed private key that row named, and a volume that
          // takes the row and keeps the key leaves signing material
          // sitting under a name no row points at. Nothing here will
          // ever name it again: the row it was reachable through is
          // gone, so the sweep that ran is the last thing that can say
          // so, and flashing a fixed success is the operator never being
          // told. Whoever holds that file signs mail as the domain.
          //
          // `blamepost doctor` does find it on its next run, which is
          // what decides how loud this has to be rather than whether it
          // has to say anything: the operator is told now, on the page
          // where they acted, and told the same thing again later.
          var swept = await dkim.sweep({});
          if (swept.keysLeftAside.length > 0) {
            // The names go here rather than into the notice. A notice is
            // looked up by code and reflects nothing, which is what keeps
            // an operator-supplied string out of a redirect, so the file
            // names have to land somewhere the operator can read them and
            // this is that place.
            log.error("dkim sweep left " + swept.keysLeftAside.length + " sealed private " +
              "key(s) in the keys folder that no selector record names: " +
              swept.keysLeftAside.join(", ") + ". Nothing here will name them again. Delete " +
              "them by hand: whoever holds one signs mail as the domain it belonged to.");
          }
          _back(res, "/admin/dkim",
            swept.keysLeftAside.length > 0 ? "keys-swept-stranded" : "keys-swept");
          return;
        }
        if (action === "generate") {
          await dkim.generate({ domain: domain });
          _back(res, "/admin/dkim", "keys-minted");
          return;
        }
        if (action === "retire") {
          // Retiring is where a domain stops signing, and it is the one
          // act on this page that erases key material. A domain part way
          // through a rotation holds two pairs and only the operator
          // knows which one the newly published records belong to, so the
          // selector is typed rather than carried by the button that was
          // pressed.
          //
          // No reason is asked for. The signer writes its own account of
          // the run into the row it files, and a sentence collected here
          // would either be thrown away or would overwrite the one an
          // incident review actually needs.
          var selector = _str(body.selector, "");
          var retireAsk = _pending({
            path:    "/admin/dkim",
            action:  action,
            carry:   [
              { name: "domain",   value: domain },
              { name: "selector", value: selector },
            ],
            title:   "Retire the pair signing for " + domain + "?",
            summary: "Both halves of the pair leave signing together.",
            consequence: "The sealed private keys for this pair are erased and nothing " +
              "signs with them again. Their records stay published through the overlap so " +
              "mail already in flight still verifies, and " + domain + " signs with " +
              "whatever pair is left. Retiring the pair a domain is still relying on " +
              "leaves it signing nothing, and there is no way back from this page.",
            subjects: [{ name: selector, detail: "and its RSA half" }],
            phrase:     selector,
            noun:       "selector",
            prompt:     "Type the selector to confirm",
            promptHint: "Exactly as it is written above. Nothing else confirms this.",
            verb:       "Retire this pair",
            fineprint:  "Withdraw the records themselves only after the overlap has run " +
              "out, which is the last step of a rotation rather than the first. Leaving " +
              "this page changes nothing.",
          });
          if (_stillAsking(req, res, body, retireAsk)) return;
          await dkim.retire({ domain: domain, selector: selector });
          _back(res, "/admin/dkim", "keys-retiring");
          return;
        }
        await dkim.rotate({ domain: domain });
        _back(res, "/admin/dkim", "keys-rotated");
      } catch (err) {
        await _renderDkim(req, res,
          _refusalText(err, "That selector change could not be made. The server log says why."),
          400);
      }
    });

    async function _renderQueue(req, res, problem, status) {
      var entries = _asArray(await delivery.queue.list());
      _page(req, res, "admin/queue", {
        nav:     _adminNav("queue"),
        entries: entries.map(_queueRow),
        empty:   entries.length === 0,
        problem: problem || null,
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/queue", requireAccount, requireAdmin, async function (req, res) {
      await _renderQueue(req, res, null, 0);
    });

    router.post("/admin/queue", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      var action = _str(body.action, "");
      if (action !== "run" && action !== "cancel") {
        await _renderQueue(req, res, null, 0);
        return;
      }
      try {
        if (action === "run") {
          // Not gated: this attempts delivery of messages this server
          // already accepted and is going to attempt anyway. It is
          // recorded all the same, by the module that performs it, so a
          // flush an operator forced and one the timer ran are told apart
          // in the trail and the command line files the same row for the
          // same act.
          await delivery.queue.runDue({ force: true });
          _back(res, "/admin/queue", "queue-ran");
          return;
        }
        // Cancelling erases a body and a descriptor off the volume, and
        // three things follow from that rather than one.
        //
        // A sender this server hosts is owed a report rather than being
        // left believing the message is still on its way, and a reverse
        // path this server hosts nothing at is not written to at all
        // (see "Who a cancellation may write to" above). Both reach
        // the audit row, so the trail says who was told as well as what
        // was erased.
        //
        // Only an entry the spool still holds is touched. An id resolves
        // to nothing when the message went out, ended in a report, or was
        // cancelled from another window since this page was drawn, and
        // erasing by name regardless answers all three the same way: the
        // operator is told a message was cancelled, and what they were
        // actually told is that a name they typed no longer exists. The
        // command line verb for this act refuses an id the queue does not
        // hold for that reason, and this is the same act.
        //
        // And it is recorded, under the same action the command line
        // files, because it is the same event whichever surface drove it
        // and a second name for one act is a second filter an auditor has
        // to know to ask for. An incident reaches for this page on mail a
        // stolen credential sent, which is exactly the moment somebody
        // asks afterwards what was cancelled and by whom.
        var ids = _list(body.id);
        // The button pressed with nothing ticked. Nothing to say and
        // nothing to record, which is not the same answer as a selection
        // the queue no longer holds.
        if (ids.length === 0) { _back(res, "/admin/queue"); return; }
        if (ids.length > MAX_ACTION_IDS) {
          await _renderQueue(req, res,
            "One cancellation carries at most " + MAX_ACTION_IDS + " messages. " +
            "Select fewer and send it again. Nothing was cancelled.", 400);
          return;
        }
        var waiting = _asArray(await delivery.queue.list());
        var held = Object.create(null);
        var stillHeld = [];
        for (var w = 0; w < waiting.length; w += 1) {
          if (typeof waiting[w].id === "string") held[waiting[w].id] = waiting[w];
        }
        for (var s = 0; s < ids.length; s += 1) {
          if (Object.prototype.hasOwnProperty.call(held, ids[s])) stillHeld.push(held[ids[s]]);
        }

        // A selection the spool no longer holds is answered rather than
        // confirmed. Asking an operator to confirm cancelling nothing
        // wastes the question, and the answer they need is that these
        // messages have already gone.
        if (stillHeld.length === 0) { _back(res, "/admin/queue", "queue-none-held"); return; }

        // Read once for the whole cancellation, and read before the page
        // is drawn, so what the operator is shown about who gets told is
        // the same answer the loop below acts on.
        var reportable = _reportableSenders(_asArray(await store.domains.list({})));
        var withheld = stillHeld.filter(function (row) { return !reportable(row.from); }).length;

        // The subject here is a set rather than a name, so there is
        // nothing to type back except how big it is. That number is read
        // off the page and measured AGAIN here at the moment of the act,
        // which is what makes it more than a formality: a selection that
        // went out, ended in a report, or was cancelled from another
        // window between the two posts produces a different number and
        // nothing is erased under a page that has gone stale.
        var cancelAsk = _pending({
          path:    "/admin/queue",
          action:  action,
          carry:   stillHeld.map(function (row) { return { name: "id", value: row.id }; }),
          title:   "Cancel " + stillHeld.length + " waiting message(s)?",
          summary: stillHeld.length === ids.length
            ? "The messages below are still on this server's spool."
            : "Of the " + ids.length + " you selected, these are the ones still on this " +
              "server's spool. The rest have gone out, ended in a report, or been " +
              "cancelled already.",
          consequence: "Each message is erased from the volume and will never be " +
            "delivered. Nothing here can be undone, and the message bodies are not " +
            "recoverable afterwards. " +
            (withheld === 0
              ? "Every sender below is one this server hosts, and each is sent a delivery " +
                "report saying the message was not delivered. The report does not say what " +
                "the operator of this server was doing."
              : withheld + " of these came in with a sender this server hosts nothing at, " +
                "which is what a message arriving through a forwarding alias looks like " +
                "and what mail sent under a stolen credential looks like. Those senders " +
                "are NOT written to, because the address came off the wire and whoever " +
                "sent the message chose it. The audit trail records which ones, so you " +
                "can tell anybody who genuinely needs to know."),
          subjects: stillHeld.map(function (row) {
            var told = reportable(row.from);
            return {
              name:   row.recipient || row.id,
              detail: "from " + (row.from || "an empty reverse path") +
                (told ? "; sender is told" : "; sender is not here, so no report is sent"),
            };
          }),
          phrase:     String(stillHeld.length),
          noun:       "number",
          prompt:     "Type how many messages are being cancelled",
          promptHint: "The number above. It is counted again when you send this, so a " +
            "message that leaves the queue in the meantime stops this rather than being " +
            "quietly left out. Each message is checked once more as it is cancelled, and " +
            "one that leaves while this is running is reported back rather than counted.",
          needsReason: true,
          verb:       "Cancel these messages",
          fineprint:  "The reason is recorded against each cancelled message in the audit " +
            "trail, and no sender is ever told it. That trail also records which senders " +
            "were written to and which were not. Leaving this page changes nothing.",
        });
        if (_stillAsking(req, res, body, cancelAsk)) return;
        var reason = _str(body.reason, "");

        var cancelled = 0;
        var missed    = 0;
        // Counted apart from the two above, because it is the one answer
        // where reloading the queue misleads: the entry is still listed
        // and the message it names is already destroyed.
        var destroyedInPart = 0;
        for (var i = 0; i < stillHeld.length; i += 1) {
          var entry = stillHeld[i];
          // Asked again here, inside the turn that acts, because the
          // selection above was read once for the whole cancellation and
          // this loop suspends on every turn: each removal touches the
          // volume and each report is a message going out, so by the
          // time a later entry comes round the reading it was chosen
          // from is several suspensions old. A message that left in one
          // of those windows is one this server would otherwise erase by
          // name regardless, file a row for saying it was cancelled, and
          // then write to its sender to say an operator stopped mail
          // that in fact arrived. That report goes to the reverse path,
          // which on mail arriving through a forwarding alias is a value
          // whoever sent the message chose.
          //
          // Nothing can be done about a message that has gone, and
          // nothing needs to be: it is not a failure to cancel. What is
          // owed is that this server does not claim otherwise, to the
          // operator, to the trail, or to the sender.
          //
          // This reading is a courtesy rather than the authority, and it
          // stays for what a courtesy is worth: it costs one read and it
          // keeps a message that is plainly gone out of the removal
          // path entirely. The authority is the removal's own answer
          // below, which is the last look anything takes at the volume
          // and the only one that can see a removal that did not happen.
          var current = await delivery.queue.show(entry.id);
          if (current === null) {
            missed += 1;
            // Filed under the same action as the cancellation itself,
            // because an auditor asking what an operator reached for
            // during an incident needs both answers under one filter,
            // and the outcome column is what tells them apart.
            await auditActor.record({
              action:   "blamepost.mail.queue.message_removed",
              outcome:  "failure",
              actor:    auditActor.current(),
              reason:   reason,
              resource: { kind: "queued_message", id: entry.id },
              metadata: {
                recipient: entry.recipient || null,
                from:      entry.from || null,
                attempt:   entry.attempt === undefined ? null : entry.attempt,
                removed:   false,
                left:      "no-longer-spooled",
                reported:  false,
                withheld:  "message-not-cancelled",
              },
            });
            continue;
          }
          // The reason and the decision about the sender both travel
          // with the removal rather than being kept here and acted on
          // afterwards. The verb that destroys the message is what
          // requires them, so a surface that collected neither is
          // refused there instead of erasing a message and filing a row
          // that answers half the question.
          //
          // This page cancels routinely, so it asks for the sender to be
          // told: somebody whose message never arrived and never drew a
          // refusal has no other way to find out. Whether there is
          // anybody here to tell is a question about hosted domains,
          // which is this layer's to answer and not the queue's, so the
          // reading stays here and its verdict goes down as the reason
          // no report is owed.
          var erased = await delivery.queue.remove(entry.id, {
            reason: reason,
            notice: reportable(entry.from)
              ? { status: CANCELLED_STATUS }
              : { withheld: "sender-not-hosted" },
          });
          if (erased.removed !== true) {
            // The removal's own answer, which is a reading of the volume
            // rather than of anything read earlier. Two states arrive
            // here. The message left between the reading above and this
            // call, which the reading cannot close: the removal is the
            // last look anything takes. Or the volume kept it, which no
            // reading would have seen at all, and which is the state
            // this page must never report as a cancellation: the message
            // is still on disk and the sweep goes on retrying it, so a
            // row saying it was erased and a report to its sender saying
            // an operator stopped it are both about mail that is still
            // going out.
            missed += 1;
            await auditActor.record({
              action:   "blamepost.mail.queue.message_removed",
              outcome:  "failure",
              actor:    auditActor.current(),
              // The sentence the removal accepted rather than the field
              // as it was read off the form, so this row and the command
              // line's row carry one value for one act.
              reason:   erased.requestedBecause,
              resource: { kind: "queued_message", id: entry.id },
              metadata: {
                recipient: entry.recipient || null,
                from:      entry.from || null,
                attempt:   entry.attempt === undefined ? null : entry.attempt,
                removed:   false,
                left:      erased.outcome === "refused" || erased.outcome === "incomplete"
                  ? erased.left.join(" and ") : "no-longer-spooled",
                destroyed: erased.destroyed.length > 0 ? erased.destroyed.join(" and ") : null,
                cause:     erased.outcome,
                reported:  false,
                // Read off the removal rather than written again here.
                // This branch covers a message that never left, one the
                // volume kept, and one whose body was destroyed while
                // its entry stayed, and only the removal knows which:
                // filing one word over all three says nothing was
                // cancelled about a message whose body is gone.
                withheld:  erased.withheld,
              },
            });
            if (erased.outcome === "refused") {
              log.error("the queued message " + entry.id + " could not be cancelled: the " +
                "volume kept its " + erased.left.join(" and ") + " (" + erased.reason +
                "). Nothing was destroyed. It is still waiting and will be attempted again.");
            }
            // Destroyed in part, which is neither a cancellation nor a
            // refusal to try again. The message itself is gone, so it
            // can never be sent, and the entry is still listed because
            // the file that lists it stayed. The sender was not written
            // to, and there is nothing this page can do about that: the
            // message it would have quoted is off the volume.
            //
            // Nor does the sweep close it later. It reads the entry,
            // finds nothing to send and gives up, and it says nothing to
            // the sender: a descriptor with no message beside it is what
            // a cancellation and a completed delivery both leave, and
            // guessing between them either bounces mail that arrived or
            // undoes a cancellation somebody chose to make quietly.
            if (erased.outcome === "incomplete") {
              destroyedInPart += 1;
              log.error("the queued message " + entry.id + " was destroyed in part: this " +
                "server took its " + erased.destroyed.join(" and ") + " off the volume and " +
                "the volume kept its " + erased.left.join(" and ") + " (" + erased.reason +
                "). The message can never be sent and its sender was not told, and the " +
                "sweep that gives up on the entry will not tell them either. Clear " +
                "whatever is holding that file open and cancel it again to take the rest.");
            }
            continue;
          }
          cancelled += 1;
          // The message went and a file an attempt had written while it
          // held the entry did not. It is not the message and it changes
          // nothing about the cancellation, so this is a log line rather
          // than an answer on the page: nothing reads that file once the
          // entry is gone, and nothing here will ever clear it.
          if (erased.left.length > 0) {
            log.error("the queued message " + entry.id + " was cancelled, and the file an " +
              "attempt writes while it holds an entry could not be removed (" +
              erased.reason + "). Nothing reads it and nothing here will clear it; delete " +
              "it by hand once the volume lets go.");
          }
          // Recorded once the message is gone, the way the identity
          // layer records its own removals, so a row never claims
          // something that did not happen. `record` is drop-silent by
          // design: a trail that cannot be written is not a reason to
          // report a cancellation that has already happened as a
          // failure.
          await auditActor.record({
            action:   "blamepost.mail.queue.message_removed",
            outcome:  "success",
            actor:    auditActor.current(),
            // The audit row has a first-class reason column. An auditor
            // filtering on it needs a column, not a string to search
            // inside. What goes in it is the sentence the removal
            // accepted, so this row and the command line's row carry one
            // value for one act.
            reason:   erased.requestedBecause,
            resource: { kind: "queued_message", id: entry.id },
            metadata: {
              recipient: entry.recipient || null,
              from:      entry.from || null,
              attempt:   entry.attempt === undefined ? null : entry.attempt,
              // Whether this server wrote to the sender, and when it did
              // not, why. An operator reading this trail afterwards is
              // deciding whether anybody still needs telling, and a row
              // that recorded only the erasure would leave them assuming
              // the report went.
              //
              // Read off the removal rather than off what this page
              // asked for. The two come apart: a sender the generation
              // bound refused is one this page asked to tell and did
              // not, and a row built from the request would say the
              // report went.
              reported:  erased.reported,
              withheld:  erased.withheld,
            },
          });
        }
        // Measured against what was actually erased, not against what
        // the confirmation was counted over and not against what the
        // request named. Those three numbers come apart exactly when a
        // message leaves while this is running, which is the case the
        // middle answer exists for: some of the selection went, the rest
        // had already gone, and nobody was told anything about the rest.
        // Destroyed-in-part outranks the other two answers, because the
        // other two both tell the operator to reload the queue and read
        // what is still listed, and that reading is exactly the one that
        // is wrong here.
        _back(res, "/admin/queue", destroyedInPart > 0
          ? "queue-part-destroyed"
          : (cancelled === 0
            ? "queue-none-held"
            : (missed === 0 ? "queue-cancelled" : "queue-part-held")));
      } catch (err) {
        await _renderQueue(req, res,
          _refusalText(err, "That queue change could not be made. The server log says why."),
          400);
      }
    });

    router.get("/admin/audit", requireAccount, requireAdmin, async function (req, res) {
      var query = _queryOf(req);
      var limit = _int(query.limit, ADMIN_PAGE_SIZE, 1, ADMIN_PAGE_MAX);
      var offset = _int(query.offset, 0, 0, Number.MAX_SAFE_INTEGER);
      // The framework records this read before it answers and takes the
      // actor for that row off the criteria, so an operator reading
      // somebody else's trail leaves a row naming them.
      var criteria = { limit: limit, offset: offset, actor: auditActor.current() };
      var action = _str(query.action, "");
      var outcome = _str(query.outcome, "");
      if (action.length > 0) criteria.action = action;
      if (outcome === "success" || outcome === "failure" || outcome === "denied") {
        criteria.outcome = outcome;
      }
      var rows = _asArray(await b.audit.query(criteria));
      _page(req, res, "admin/audit", {
        nav:       _adminNav("audit"),
        rows:      rows.map(_auditRow),
        empty:     rows.length === 0,
        action:    action,
        outcome:   outcome,
        olderHref: rows.length === limit
          ? _path("/admin/audit?limit=" + limit + "&offset=" + (offset + limit)) : "",
        newerHref: offset > 0
          ? _path("/admin/audit?limit=" + limit + "&offset=" + Math.max(0, offset - limit)) : "",
      });
    });

    router.onNotFound(function (req, res) {
      _fail(req, res, 404, "Nothing here", "This server has no page at " + req.pathname + ".");
    });
  }

  return {
    routes:                mount,
    health:                health,
    jmap:                  jmap,
    mountJmapWebSocket:    mountJmapWebSocket,
    drainJmapWebSockets:   drainJmapWebSockets,
    engine:                engine,
    render:                renderer,
    viewsDir:              VIEWS_DIR,
    publicDir:             PUBLIC_DIR,
  };
}

// ---------------------------------------------------------------------
// The listener.
// ---------------------------------------------------------------------

function _assertPort(value, label) {
  if (typeof value !== "number" || !isFinite(value) ||
      Math.floor(value) !== value || value < 0 || value > 65535) {
    throw new TypeError(label + " must be an integer port between 0 and 65535. " +
      "Zero asks the operating system for a free one, which is what a test wants and " +
      "what a server never does.");
  }
  return value;
}

// The certificate, key and key-agreement preference the TLS listener
// presents.
//
// A Node TLS server builds its own context out of PEM bytes and ignores
// a SecureContext handed to it as an option, so this reads the pair
// rather than borrowing the context the mail listeners already hold.
// Passing one anyway produces a listener with no certificate at all,
// which fails every handshake and looks like a client problem.
//
// Because the context is built here rather than borrowed, the group
// preference has to be named here too, and it comes from the module that
// owns listener composition so both halves of this server accept the
// same set. They did not for a while: the mail ports carried a
// preference and this one carried nothing, so an operator measuring the
// administration URL learned nothing about port 25. The preference is
// the group list ALONE and deliberately not `b.network.tls.applyToContext`,
// which also merges the framework trust store in. A `ca` list on a
// SERVER context changes how it treats client certificates, and this
// listener is asking for a key agreement rather than a verification
// posture.
//
// A key sealed with `b.vault.sealPemFile` is unsealed on the way
// through. The plaintext exists only for the duration of the bind.
function _certificatePair(tlsFiles) {
  var certPem;
  try {
    certPem = b.atomicFile.fdSafeReadSync(tlsFiles.certFile, {
      maxBytes: MAX_CERT_BYTES,
      encoding: "utf8",
    });
  } catch (err) {
    throw new TypeError("blamepost.web.serve: cannot read the certificate at " +
      tlsFiles.certFile + ": " + ((err && err.message) || String(err)));
  }
  var keyPem;
  try {
    keyPem = b.atomicFile.fdSafeReadSync(tlsFiles.keyFile, {
      maxBytes: MAX_KEY_BYTES,
      encoding: "utf8",
    });
  } catch (err2) {
    throw new TypeError("blamepost.web.serve: cannot read the private key at " +
      tlsFiles.keyFile + ": " + ((err2 && err2.message) || String(err2)));
  }
  if (keyPem.indexOf(SEALED_PEM_PREFIX) === 0) {
    var vault = tlsFiles.vault || b.vault;
    try {
      keyPem = vault.unseal(keyPem).toString("utf8");
    } catch (err3) {
      // A seal authenticates what it carries end to end, so there are
      // two ways it does not open: the bytes were written under a
      // different volume's vault key, or they have been damaged where
      // they lie. The passphrase is not a third. It opens
      // vault.key.sealed while the vault is being opened, which happens
      // before anything binds and refuses the boot outright when it does
      // not fit, so a bind that runs at all is running under a
      // passphrase that fitted. The certificate reading says the same
      // thing in the same words, because two copies of one sentence
      // drift apart the moment only one of them is corrected.
      throw new TypeError("blamepost.web.serve: the key at " + tlsFiles.keyFile +
        " is sealed and would not open: " + ((err3 && err3.message) || String(err3)) +
        ". It was written under a different volume's vault key, or its bytes have been " +
        "damaged where they lie. Restore the file from a backup taken before the damage, " +
        "or write the unsealed pair to the two paths this server reads.");
    }
  }
  return { cert: certPem, key: keyPem, ecdhCurve: keyAgreementGroups() };
}

// Close one bound server inside a deadline. The close callback fires
// once the last request in flight has finished, so idle connections are
// released immediately and anything still open when the deadline passes
// is cut. One slow reader must not hold a shutdown open.
function _closeServer(server, timeoutMs) {
  return new Promise(function (resolve) {
    var settled = false;
    var timer = null;
    function finish() {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      resolve();
    }
    server.close(finish);
    if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
    timer = setTimeout(function () {
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      finish();
    }, timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
  });
}

/**
 * @primitive blamepost.web.serve
 * @signature blamepost.web.serve(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one application carrying webmail, administration, JMAP and the probes)
 * @related   blamepost.create, blamepost.mail.listeners.create
 *
 * Compose the browser surface into a runnable application and return
 * its lifecycle: `{ start, stop, describe, bound, health, jmap, routes }`.
 *
 * The wiring is checked here, at construction, so a missing handle
 * fails the boot with the name of what is missing rather than the first
 * request that reaches it. Nothing binds and no port is taken until
 * `start`, which takes the cleartext port always and the TLS port when
 * a certificate was named, and reports what each one got. `stop` flips
 * the readiness probe to draining first, so a load balancer stops
 * routing before the sockets close, then closes both inside a deadline.
 *
 * The application is built by `b.createApp`, which mounts the framework
 * request lifecycle around the routes and expects the vault and the
 * database to be open already. Opening the store is what does that, so
 * this runs after it rather than before.
 *
 * The cleartext port is what a container health check and a reverse
 * proxy poll. A session is not reachable over it: the session cookie
 * carries the `__Host-` prefix and the `Secure` attribute, so a browser
 * refuses to store it unless the response arrived over TLS, terminated
 * either here or by the proxy in front.
 *
 * @opts
 *   agent:     object,   // required; the b.mail.agent handle, passed to create
 *   store:     object,   // required; the identity layer, passed to create
 *   mailbox:   object,   // required; the mailbox adapter, passed to create, which owns the folder and UID rows and the sealed octets
 *   mailStore: object,   // required; the message store, passed to create
 *   compose:   object,   // required; the outbound composer, passed to create
 *   dkim:      object,   // required; the selector lifecycle, passed to create
 *   delivery:  object,   // required; the outbound path, passed to create
 *   config:    object,   // required; hostname, ports and the well known documents
 *   listeners: function, // the protocol listener table the readiness probe reports
 *   certificateReport: function, // returns a blamepost.certificateReport reading, polled by the probes
 *   httpPort:  number,   // cleartext port; defaults to config.httpPort
 *   httpsPort: number,   // TLS port; defaults to config.httpsPort
 *   address:   string,   // interface to bind; default 0.0.0.0
 *   tls:       object,   // { certFile, keyFile, vault }; omit to serve cleartext only
 *   certificate: object, // the blamepost.tlsContext handle, so a renewal reaches the TLS port
 *   dataDir:   string,   // where the application anchors; defaults to config.dataDir
 *
 * @example
 *   var listener = blamepost.web.serve({
 *     agent: agent, store: store, mailbox: mailbox, mailStore: mailStore,
 *     compose: composer, dkim: dkim, delivery: delivery, config: config,
 *   });
 *   await listener.start();
 */
function serve(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.web.serve: opts object is required");
  }
  var handle = create(opts);
  var config = opts.config;

  var dataDir = opts.dataDir || config.dataDir ||
    (config.paths && config.paths.dataDir);
  if (typeof dataDir !== "string" || dataDir.length === 0) {
    throw new TypeError("blamepost.web.serve: config.dataDir is required. The application " +
      "anchors its framework tables there, and it is the directory the store already opened.");
  }

  var address = opts.address === undefined ? DEFAULT_BIND_ADDRESS : opts.address;
  if (typeof address !== "string" || address.length === 0) {
    throw new TypeError("blamepost.web.serve: opts.address must be an interface address " +
      "such as 0.0.0.0 or ::");
  }

  var httpPort = _assertPort(
    opts.httpPort === undefined ? config.httpPort : opts.httpPort,
    "blamepost.web.serve: httpPort");

  var tlsFiles = opts.tls === undefined || opts.tls === null ? null : opts.tls;
  if (tlsFiles !== null &&
      (typeof tlsFiles !== "object" || Array.isArray(tlsFiles) ||
       typeof tlsFiles.certFile !== "string" || tlsFiles.certFile.length === 0 ||
       typeof tlsFiles.keyFile !== "string" || tlsFiles.keyFile.length === 0)) {
    throw new TypeError("blamepost.web.serve: opts.tls must be " +
      "{ certFile, keyFile, vault } naming a certificate and a key on disk. Leave it out " +
      "to serve cleartext only, which is the shape behind a proxy that terminates TLS.");
  }
  var httpsPort = tlsFiles === null ? null : _assertPort(
    opts.httpsPort === undefined ? config.httpsPort : opts.httpsPort,
    "blamepost.web.serve: httpsPort");
  if (httpsPort !== null && httpsPort === httpPort && httpPort !== 0) {
    throw new TypeError("blamepost.web.serve: httpPort and httpsPort are both " + httpPort +
      ". One process cannot serve cleartext and TLS on the same port.");
  }

  var certificate = opts.certificate === undefined || opts.certificate === null
    ? null : opts.certificate;
  if (certificate !== null &&
      (typeof certificate !== "object" || Array.isArray(certificate))) {
    throw new TypeError("blamepost.web.serve: opts.certificate must be the loader handle " +
      "blamepost.tlsContext returns, the same one the mail listeners are given. Leave it out " +
      "when nothing is watching the two files, which is the shape that cannot rotate at all.");
  }

  var log = b.log.boot("web");
  var app = null;
  var servers = {};
  var boundPorts = {};
  var drained = false;

  function bound() {
    return Object.assign({}, boundPorts);
  }

  async function _bind(name, port, tlsOptions) {
    var listening = await app.listen({ port: port, host: address, tls: tlsOptions });
    servers[name] = listening.server;
    boundPorts[name] = listening.port;
    // The JMAP WebSocket transport rides the same port as the rest of
    // the application, but it arrives on the server's `upgrade` event
    // rather than through the router, so it is attached to each socket
    // as it binds rather than mounted once with the routes. Both ports
    // get it: a client that reached the session document over one of
    // them reads a relative url and upgrades on the same one.
    handle.mountJmapWebSocket(listening.server);
  }

  // Whether a renewal written to the two files reaches the TLS port
  // while this process runs.
  //
  // The mail listeners read their certificate through an accessor and so
  // answer every connection with whatever is current. This port cannot:
  // a node:tls server builds its own context out of PEM bytes and there
  // is no supported way to hand it one somebody else built, so the
  // material reaches it as a value by construction. What it can be given
  // is replacement material while it is bound, and the loader's reload
  // hook is what says when. Without a handle behind the two files there
  // is nothing to be told, and the port keeps what it read at bind until
  // this process restarts.
  function _followsRenewals() {
    return httpsPort !== null && certificate !== null &&
      typeof certificate.onReload === "function";
  }

  // Hand the bound TLS server the renewed pair when the loader says the
  // two files changed.
  //
  // The hook is told the context the loader built, and this server takes
  // bytes, so the pair is read again here. That second read is also why
  // this can fail on its own: a certificate client rewriting both halves
  // is briefly midway through the second one. A failure keeps the
  // certificate the port already holds and says so out loud, because the
  // framework's reload loop swallows whatever a hook throws, and a port
  // that silently kept an expired certificate while the reload reported
  // success is the exact failure this whole path exists to end.
  //
  // Registered here rather than at the bind, so it is in place before
  // anything can be bound and it no-ops for as long as no TLS server is
  // held. A failed bind and a completed drain both leave nothing to give
  // material to, and both read the same way from inside.
  function _followRenewals() {
    if (!_followsRenewals()) return;
    certificate.onReload(function () {
      var bound = servers.https;
      if (!bound || typeof bound.setSecureContext !== "function") return;
      try {
        bound.setSecureContext(_certificatePair(tlsFiles));
        log.info("the TLS port presents the renewed certificate from " + tlsFiles.certFile);
      } catch (err) {
        log.warn("the renewed certificate at " + tlsFiles.certFile + " could not be given to " +
          "the TLS port, which goes on presenting the one it holds: " +
          ((err && err.message) || String(err)));
      }
    });
  }
  _followRenewals();

  // Close whatever is bound, in the order it was bound. Shared by the
  // drain and by the unwind a failed second bind performs, which must
  // not tell the probe that a shutdown has begun: the boot is failing,
  // not draining.
  async function _close(timeoutMs) {
    var names = Object.keys(servers);
    var closed = [];
    for (var i = 0; i < names.length; i += 1) {
      await _closeServer(servers[names[i]], timeoutMs);
      closed.push(names[i]);
      delete servers[names[i]];
      delete boundPorts[names[i]];
    }
    return closed;
  }

  /**
   * @primitive blamepost.web.serve.start
   * @signature listener.start()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: bind after the store, unwind on a failed bind)
   * @related   blamepost.web.serve, blamepost.web.serve.stop
   *
   * Build the application if it is not built yet, then take the ports.
   * A failed TLS bind closes the cleartext listener before the error
   * reaches the caller, so there is no half started state to reason
   * about afterwards. Returns the ports actually taken, which is what a
   * caller that asked for an ephemeral one needs.
   *
   * A listener that has been drained refuses to start again. Readiness
   * stays refused once a drain begins, on purpose, so restarting this
   * handle would bind a port that the probe goes on calling unfit.
   *
   * @example
   *   var ports = await listener.start();
   *   ports.http;
   */
  async function start() {
    if (drained) {
      throw new Error("blamepost.web.serve.start: this listener has already been drained. " +
        "Its readiness probe stays refused from the moment a drain begins, so starting it " +
        "again would take the port back while every probe kept answering that the process " +
        "cannot serve. Build another listener.");
    }
    if (app === null) {
      app = await b.createApp({ dataDir: dataDir, routes: handle.routes });
    }
    await _bind("http", httpPort, undefined);
    if (httpsPort !== null) {
      try {
        await _bind("https", httpsPort, _certificatePair(tlsFiles));
      } catch (err) {
        await _close(b.constants.TIME.seconds(5));
        throw err;
      }
    }
    log.info("webmail, administration and JMAP on port " + boundPorts.http +
      (boundPorts.https === undefined ? "" : " and port " + boundPorts.https));
    return bound();
  }

  /**
   * @primitive blamepost.web.serve.stop
   * @signature listener.stop(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: readiness flips before the sockets close)
   * @related   blamepost.web.serve.start
   *
   * Drain and close. Readiness answers 503 from the first line, so a
   * load balancer takes this process out of rotation while the requests
   * already in flight finish. Liveness keeps answering, because an
   * orchestrator that reads a draining process as dead kills it in the
   * middle of the drain.
   *
   * The JMAP sockets go first and are told the server is going away
   * rather than cut. An upgrade detaches its socket from the HTTP
   * server, so closing the server does not reach it, and one left open
   * holds the process past the shutdown that was supposed to end it.
   *
   * Returns `{ closed, jmapSockets }`: the listeners that were closed,
   * and how many upgraded sockets the drain started with.
   *
   * @opts
   *   timeoutMs: number,   // deadline per listener; default eight seconds
   *
   * @example
   *   await listener.stop({ timeoutMs: 4000 });
   */
  async function stop(stopOpts) {
    stopOpts = stopOpts || {};
    var timeoutMs = stopOpts.timeoutMs === undefined ? HTTP_DRAIN_MS : stopOpts.timeoutMs;
    drained = true;
    handle.health.markShuttingDown();
    // The JMAP sockets first, because an upgrade detached them from
    // the server and closing the server therefore does not reach them.
    // They are told the server is going away rather than cut, so a
    // client reconnects instead of reading the drain as a fault.
    var sockets = await handle.drainJmapWebSockets(timeoutMs);
    return { closed: await _close(timeoutMs), jmapSockets: sockets };
  }

  /**
   * @primitive blamepost.web.serve.describe
   * @signature listener.describe()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: configured posture beside the running one)
   * @related   blamepost.web.serve.start
   *
   * What this listener is configured to run and what it currently
   * holds. The configured half answers whether TLS terminates in this
   * process; the bound half is empty until `start`.
   *
   * `staleAfterRotation` names the ports here that a certificate renewal
   * does not reach while this process runs, in the same vocabulary the
   * mail listeners use. It is derived from what this listener was
   * actually given rather than declared: a TLS port with a certificate
   * handle behind it takes the renewed material and is named by nothing,
   * and a TLS port with no handle behind it keeps what it read at bind
   * and says so. A caller assembles the whole answer by concatenating
   * this with the mail listeners' own list.
   *
   * @example
   *   listener.describe().httpPort;
   */
  function describe() {
    return {
      address:   address,
      httpPort:  httpPort,
      httpsPort: httpsPort,
      bound:     bound(),
      staleAfterRotation: (httpsPort !== null && !_followsRenewals()) ? ["https"] : [],
    };
  }

  return {
    start:    start,
    stop:     stop,
    describe: describe,
    bound:    bound,
    routes:   handle.routes,
    health:   handle.health,
    jmap:     handle.jmap,
  };
}

module.exports = {
  create:            create,
  serve:             serve,
  VIEWS_DIR:         VIEWS_DIR,
  PUBLIC_DIR:        PUBLIC_DIR,
  SESSION_COOKIE:    SESSION_COOKIE,
  THEME_COOKIE:      THEME_COOKIE,
  PAGE_SIZE:         PAGE_SIZE,
  NOTICES:           NOTICES,
  REQUIRED_AGENT:    REQUIRED_AGENT,
  REQUIRED_STORE:    REQUIRED_STORE,
  REQUIRED_COMPOSE:  REQUIRED_COMPOSE,
  REQUIRED_DKIM:     REQUIRED_DKIM,
  REQUIRED_DELIVERY: REQUIRED_DELIVERY,
};
