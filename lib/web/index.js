// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web
 * @nav    Web interface
 * @title  Webmail and administration
 * @order  10
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
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var pkg = require("../../package.json");
var b = require("../vendor/blamejs");

// Two spellings of one mailbox are one mailbox, and `lib/store/address`
// is the single place that decides so. A comparison here that reaches
// for the raw string instead disagrees with the routing layer about who
// a recipient is, and it does it silently.
var address = require("../store/address");

// The screen between text somebody else wrote and a person reading it.
// The same reader runs over a subject here, over a record value in the
// zone diff, and over a refusal on the command line, so a value that is
// one line on this page is one line everywhere it is printed.
var displayText = require("../text");

// Who an audit row names, decided in one place for the whole server.
// The identity layer writes the rows this surface's administration
// pages cause, and it is several calls away from the request that
// caused them, so the request opens a scope rather than threading an
// argument through every call that might one day write one.
var auditActor = require("../store/actor");

// The data volume's layout is settled in one place, and the guard that
// refuses a base path nothing can be joined onto safely lives with it.
var configModule = require("../config");

// The largest message the mailbox opens to derive a reply or a forward
// from. A draft of a larger message is derived from the stored row, and
// the compose page names this number when it says so.
var MAX_SOURCE_READ_BYTES = require("../mail/mailbox").MAX_SOURCE_READ_BYTES;
var SOURCE_READ_BOUND_TEXT =
  Math.floor(MAX_SOURCE_READ_BYTES / b.constants.BYTES.mib(1)) + " MiB";

// Whether a message carries files, and the walk that lists them.
//
// Both are the mail layer's, composed rather than written again here.
// The mark is derived from a message's octets when it is filed, so this
// surface reads it rather than opening the message: RFC 8621's
// `Email/get` takes a set of identifiers the client chose, and a
// derivation per identifier would let one request order a stored-body
// read and a parse per message it named.
//
// The walk is the same one the mark was derived from, which is what puts
// the file list on the conversation page in step with the answer a JMAP
// client gets. Two readings of what counts as a file would show a reader
// a list of files on a message their client was told carries none.
var leafParts           = require("../mail/mailbox").leafParts;
var attachmentMark      = require("../mail/mailbox").attachmentMark;
var isAttachmentKeyword = require("../mail/mailbox").isAttachmentKeyword;

// How a folder name carries its hierarchy, and the split of one name into
// the levels above it.
//
// Both are the mail layer's, composed rather than written again here. The
// IMAP listing reports the levels of a name from that derivation, and the
// JMAP mailbox answer builds `parentId` and the level-only `name` of RFC
// 8621 section 2 from the same one. A second split here would be a
// hierarchy an account holder sees in one client and not in the other,
// over the same folders.
var HIERARCHY_DELIMITER = require("../mail/mailbox").HIERARCHY_DELIMITER;
var superiorLevels      = require("../mail/mailbox").superiorLevels;

// Two of the three answers `attachmentMark` gives, named once because
// this surface reads the mark in two places: the boolean RFC 8621
// section 4.1.4 calls `hasAttachment`, and the list of parts under it.
// The third answer is every other string, and both readers treat it as
// the message not having been opened.
var ATTACHMENT_PRESENT = "present";
var ATTACHMENT_ABSENT  = "absent";

// The bounds a sending credential's ceilings and window may be set
// between. The registry is the only thing that enforces them, so the
// page reads them off it rather than carrying a second copy to keep in
// step: a form naming a bound this server does not hold sends an
// operator to type a number that is refused after they press the button.
var credentialsModule = require("../store/credentials");

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

// Whether ONE address is one an identity may write, which is the decision
// rather than the display.
//
// The list above cannot answer for a domain-scoped sending credential.
// Such a credential may write every local part at one hosted domain
// except the ones on its own refusal list, and no array says that:
// rendered as a list the scope is empty, and an empty list read as a
// decision refuses the credential every address it exists to write. The
// submission listener's envelope policy asks this same function, so the
// sending route below and the wire reach one decision about one address
// instead of two that agree until one of them moves.
var permittedAuthor = require("../mail/listeners").permittedAuthor;

// The entry point for the sending-credential identity space, composed
// rather than restated. It reads the credential's failure budget, checks
// the secret, spends or clears the budget on the outcome, and builds the
// actor every permission decision below reads.
//
// This surface is the SECOND transport a domain-scoped credential reaches
// this server on, and the budget is what makes a run of guesses cost
// something. A route that asked the registry itself would answer the
// same question with no budget behind it, and the bound the submission
// listener enforces would be one an attacker walks around by choosing
// this route instead of port 587.
var verifySendingCredential = require("../mail/listeners").verifySendingCredential;

// Every refusal the listener's per-message credential gate throws, by
// name. The sending route composes through that gate and has to render
// each class as its own HTTP status, and matching on the message text
// would start answering the wrong status the first time one of those
// sentences is reworded.
var LISTENER_CODES = require("../mail/listeners").CODES;

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

// Every refusal the hosted-DNS write gate and its provider client
// compose, read from the modules that throw them rather than spelled
// again here.
//
// This surface has to answer each class as its own problem type and its
// own status, and matching on the message text would start answering the
// wrong status the first time one of those sentences is reworded. Same
// arrangement as the signer's codes above, and for the same reason.
//
// The full SET matters as well as the individual codes. A message from
// either of those layers was written for the operator now reading it and
// is shown; anything else reaching the same catch is a fault in this
// process, whose message names paths and internals rather than anything
// an operator can act on, so it is logged and answered generically.
var dnsModule = require("../dns");
var dnsCodes  = dnsModule.CODES;
var DNS_REFUSAL_CODES = Object.keys(dnsCodes || {})
  .map(function (name) { return dnsCodes[name]; })
  .concat(Object.keys((dnsModule.cloudflare && dnsModule.cloudflare.CODES) || {})
    .map(function (name) { return dnsModule.cloudflare.CODES[name]; }));

// Read once, at load, for the reason the signer's set is: an empty set
// answers every membership question the same way, and the answer it
// gives is the one that hides the fault. Every refusal the gate wrote
// for a person would fall through to the generic sentence, and the
// operator would be sent to a log for a zone change they could have
// corrected from the page.
if (DNS_REFUSAL_CODES.length === 0 ||
    DNS_REFUSAL_CODES.some(function (code) { return typeof code !== "string"; })) {
  throw new TypeError("blamepost.web: the dns module and its provider client must each " +
    "export CODES holding the refusal codes they throw, which is how this surface tells a " +
    "zone refusal worded for an operator from a fault in this process worded for whoever " +
    "wrote it.");
}

// The reference wiki, built from the documentation blocks in `lib/`. The
// module builds the pages and this surface serves them under `/wiki`.
var wiki = require("./wiki");

// The one reader for a link target. Both surfaces that build links
// compose it, so the rule that decides what may reach an href has a
// single home. See `_path` and `_href` below.
var links = require("./links");

var VIEWS_DIR  = nodePath.join(__dirname, "views");
var PUBLIC_DIR = nodePath.join(__dirname, "public");
var ASSETS_DIR = nodePath.join(PUBLIC_DIR, "assets");

// The vector marks this application serves. Both are committed files, and
// nothing a request can reach ever writes into the asset directory.
var BRAND_MARKS = Object.freeze(["favicon.svg", "logo-mono.svg"]);

// The name the store holds the front-page decision under. One spelling,
// because the console writes it and the route reads it, and two spellings
// of one setting is a toggle that reports success and changes nothing.
var PUBLIC_SITE_SETTING = "publicSiteEnabled";

// The pages an unauthenticated reader may hold, and the one list three
// separate answers are built from: the navigation the public pages render,
// the sitemap a crawler is given, and the paths the cache and robots rules
// name. A page added in one place and forgotten in the others is a page
// that is linked and not indexed, or indexed and not reachable, and those
// are the two failures this table exists to make impossible.
//
// An entry names a path and does not say whether the path is served. The
// navigation and the sitemap list an entry only while the router this
// surface mounted on dispatches a GET request for that path to a route
// registered for exactly that path, read from the router when the page
// or the sitemap is built. An entry with no such route is left out of
// both, and registering the route lists it with no edit to this table or
// to a template.
var PUBLIC_PAGES = Object.freeze([
  Object.freeze({
    path:       "/",
    label:      "Overview",
    inNav:      false,
    changefreq: "monthly",
    priority:   "1.0",
  }),
  Object.freeze({
    path:       "/wiki",
    label:      "Reference",
    inNav:      true,
    changefreq: "weekly",
    priority:   "0.8",
  }),
]);

// The schema.org record the public front page carries as JSON-LD. The
// vocabulary and the category are fixed. Every other value is read from
// the package manifest or from the page when it renders.
var STRUCTURED_DATA_CONTEXT  = "https://schema.org";
var STRUCTURED_DATA_TYPE     = "SoftwareApplication";
var STRUCTURED_DATA_CATEGORY = "CommunicationApplication";
var SPDX_LICENSE_PAGE_BASE   = "https://spdx.org/licenses/";

// The `Cache-Control` values a rendered page is served with. `_renderOpts`
// inside `create` chooses between them, and the `b.middleware.noCache`
// composed on the request chain writes `PAGE_CACHE_CONTROL` as well.
var PUBLIC_PAGE_CACHE_CONTROL = "private, max-age=900";
var PAGE_CACHE_CONTROL        = "private, no-store";

// Where the mailbox surface answers. The folder being read is a query
// parameter on it rather than a segment of it, so this is the whole of
// what the routes and the built links share.
var MAIL_PATH = "/mail";

// The prefixes a crawler is asked to leave alone. Everything an account or
// an operator reaches is behind one of them, and each is a prefix rather
// than a page because the surface under it is generated.
var CRAWLER_DISALLOWED = Object.freeze([
  "/admin", MAIL_PATH, "/compose", "/search", "/jmap", "/api",
  "/sign-in", "/sign-out", "/prefs",
]);

// Session cookie. The `__Host-` prefix binds the cookie to this exact
// origin with no Domain attribute and a root path, which the browser
// enforces rather than trusting the server to get right. It also requires
// `Secure`, so this surface is served over TLS.
var SESSION_COOKIE = "__Host-bp_session";
var THEME_COOKIE   = "__Host-bp_theme";

var SESSION_TTL_MS = b.constants.TIME.hours(12);
var THEME_TTL_MS   = b.constants.TIME.days(365);

// The referrer policy every response on this surface carries.
//
// Under the Fetch standard a request whose mode is `navigate` and whose
// method is not GET or HEAD has its serialized origin replaced with
// `null` when the document's referrer policy is `no-referrer`. Pressing
// the submit button on a rendered form is exactly that request, so a
// document served under `no-referrer` posts an origin that names no
// site, the origin cross-check on the chain below cannot match it
// against this server, and the form is refused.
//
// `same-origin` sends no referrer to any other origin, which is the
// whole of what `no-referrer` was carrying here, and it serializes a
// cross-origin submit's origin as `null` as well, so a form on another
// site is refused exactly as before. What changes is that a request
// from this surface to itself names this surface.
//
// It is a constant because the value is mounted twice, once on the
// framework's own request lifecycle and once on the chain the routes
// mount, and a surface that answers two different policies depending on
// which chain refused the request is a surface where the answer depends
// on how far the request got.
var REFERRER_POLICY = "same-origin";

// What a reader is told when the connection cannot carry a password.
//
// It is shown before the password field rather than after the post,
// because a refusal that waits for the post arrives once the password
// has already crossed the wire. Naming the setting is the operator half
// of the same page: the reader cannot act on it and the person running
// the server can, and a deployment behind a terminator reaches this
// sentence for exactly one reason.
var TRANSPORT_REFUSAL =
  "This connection is not encrypted, so this server will not accept a password over it. " +
  "Open the same address over HTTPS. If a proxy in front of this server terminates TLS, " +
  "its address range has to be named in trustedProxies before this server reads the " +
  "connection as encrypted.";

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

// ---------------------------------------------------------------------
// The sending route.
//
// A domain-scoped sending credential reaches this server two ways, and
// both of them are the same identity writing the same mail: an
// application that speaks SMTP submission, and an application that posts
// JSON here. Every question about what that identity may write is
// therefore answered by the code the submission listener answers it with,
// composed rather than restated. The listener's credential entry point
// checks the secret and spends the failure budget, `permittedAuthor`
// decides the envelope, the composer's author binding decides the header,
// the composer's credential gate re-reads the credential's standing and
// spends its two send ceilings, and the composer's own relay handle
// carries the message.
//
// Nothing here restates any of them, and the failure budget is why that
// matters more on this route than anywhere else: a second surface that
// verified the same secret without spending it would be a bound an
// attacker walks around by choosing this route over port 587.
// ---------------------------------------------------------------------

var API_SEND_PATH = "/api/send";

// The problem types this route answers with, as URNs.
//
// RFC 9457 section 3.1.1 lets `type` be any URI reference and says a
// reader MAY dereference one that looks like a locator. A URL this
// server does not serve is worse than no locator at all, because it
// invites the dereference and answers it with a page that is not there. A
// URN names the problem, locates nothing, and is the stable string a
// client branches on across releases.
var SEND_PROBLEM = Object.freeze({
  transport:    "urn:blamepost:problem:send-transport-cannot-carry-a-credential",
  ambient:      "urn:blamepost:problem:send-ambient-credential-refused",
  credential:   "urn:blamepost:problem:send-credential-refused",
  key:          "urn:blamepost:problem:send-idempotency-key",
  keyConflict:  "urn:blamepost:problem:send-idempotency-key-in-flight",
  keyMismatch:  "urn:blamepost:problem:send-idempotency-key-reused",
  keysFull:     "urn:blamepost:problem:send-idempotency-records-full",
  body:         "urn:blamepost:problem:send-body-refused",
  envelope:     "urn:blamepost:problem:send-envelope-not-permitted",
  author:       "urn:blamepost:problem:send-author-not-permitted",
  ceiling:      "urn:blamepost:problem:send-ceiling-reached",
  // A ceiling that is full and a ceiling that cannot be read are separate
  // types because they ask a client for opposite behavior. The first
  // clears on its own and the client waits out the window; the second
  // clears only when an operator repairs the record, and a client that
  // retries against it sends a message that will not go until someone
  // intervenes. One type for both leaves a client branching on `type`,
  // which is what this table exists for, unable to tell them apart.
  ceilingUnreadable: "urn:blamepost:problem:send-ceiling-unreadable",
  undeliverable: "urn:blamepost:problem:send-not-relayed",
});

// The bounds the request body is read under. Every one of them is a
// ceiling on untrusted remote input, so each is a number rather than
// whatever the composer happens to refuse further in: a body that reaches
// the composer has already been parsed, and the parse is the expensive
// part.
//
// The recipient bound is the count across `to`, `cc` and `bcc` together,
// because that sum is what becomes the envelope and what the credential's
// own recipient ceiling is counted against.
var SEND_MAX_ADDRESS_CHARS    = 320;
var SEND_MAX_RECIPIENTS       = 100;
var SEND_MAX_SUBJECT_CHARS    = 998;
// Each body field's own limit. The request body is read by the JSON body
// parser at JSON_BODY_MAX_BYTES before this route runs, and that limit
// bounds every field together.
var SEND_MAX_BODY_BYTES       = b.constants.BYTES.mib(2);
var SEND_MAX_MESSAGE_ID_CHARS = 998;
var SEND_MAX_REFERENCES       = 20;

// How long a replay record answers for, and how many this server keeps.
//
// The window covers the retry a client actually makes. An application
// whose request timed out retries in seconds; one whose queue drained
// after an outage retries in hours. A day covers both and is the span the
// header's own conventions settled on.
//
// The count is a bound rather than a target. The record is held in this
// process, so an application minting a fresh key per message would grow
// it without one, and the oldest record is the one whose retry has
// already happened or already been given up on.
var SEND_REPLAY_TTL_MS      = b.constants.TIME.hours(24);
var SEND_REPLAY_MAX_RECORDS = 10000;
// How long a request refused because every record is held by a running
// send is told to wait before retrying.
var SEND_REPLAY_FULL_RETRY_SECONDS = 5;

// What separates the credential's identifier from the client's key in a
// record's name.
//
// `b.guardIdempotencyKey` refuses every control character, and the
// identifier the registry issues is hexadecimal, so neither half can
// carry this byte and two records cannot be run together into one name.
// It is BUILT rather than typed: a control character embedded in a source
// file is one no editor renders and no reviewer sees in a diff, and grep
// answers `Binary file matches` and prints nothing at all for the file
// holding it.
var REPLAY_KEY_SEPARATOR = String.fromCharCode(0);

// The shape a request body may take, and nothing else. The schema is
// strict, so a field this route does not accept is refused rather than
// dropped: a caller that spells `bcc` as `bccs` has written a message
// with recipients it believes are on it, and dropping the field sends
// that message without them.
var SEND_BODY_SCHEMA = b.safeSchema.object({
  from:         b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS),
  sender:       b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS).optional(),
  envelopeFrom: b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS).optional(),
  to:           b.safeSchema.array(b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS))
    .max(SEND_MAX_RECIPIENTS).optional(),
  cc:           b.safeSchema.array(b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS))
    .max(SEND_MAX_RECIPIENTS).optional(),
  bcc:          b.safeSchema.array(b.safeSchema.string().min(1).max(SEND_MAX_ADDRESS_CHARS))
    .max(SEND_MAX_RECIPIENTS).optional(),
  subject:      b.safeSchema.string().max(SEND_MAX_SUBJECT_CHARS).optional(),
  text:         b.safeSchema.string().max(SEND_MAX_BODY_BYTES).optional(),
  html:         b.safeSchema.string().max(SEND_MAX_BODY_BYTES).optional(),
  inReplyTo:    b.safeSchema.string().min(1).max(SEND_MAX_MESSAGE_ID_CHARS).optional(),
  references:   b.safeSchema.array(b.safeSchema.string().min(1).max(SEND_MAX_MESSAGE_ID_CHARS))
    .max(SEND_MAX_REFERENCES).optional(),
});

// Rows per mailbox page, and the modseq span a first read reaches back
// across to fill one. Folder modseq advances on flag changes as well as
// on arrivals, so the span is deliberately wider than the page.
var PAGE_SIZE       = 50;
var FIRST_PAGE_SPAN = 512;
var WINDOW_CAP      = 1000;
var MAX_PAGE_PROBES = 6;
// How many times a page read narrows its span after a read came back
// full before reaching the rows already read. Each narrowing divides the
// span by four, so eight take the first span to a single mod-sequence,
// which holds at most `blamepost.mail.mailbox.MAX_STORE_GROUP` rows and
// so fits one read.
var MAX_SPAN_NARROWINGS = 8;

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

// The DMARC reading's window, in days, and the windows an operator is
// offered. The default is a month because a receiver reports a day at a
// time and a policy decision is read off a run of them rather than off
// one.
//
// The ceiling is not here. Aggregate rows are destroyed on the retention
// window the operator configured, so the longest window that can answer
// is that one, and it is read off the report handle at request time
// rather than named as a number this file would then have to keep in
// step. A choice longer than the rows go is dropped from what is offered
// rather than shown and clamped, so nothing on the page names a window
// this server cannot answer over.
var DMARC_DEFAULT_DAYS  = 30;
var DMARC_MIN_DAYS      = 1;
var DMARC_DAY_CHOICES   = Object.freeze([7, 30, 90, 365]);

// Reporting windows rendered per domain. Receivers report a day at a
// time, so this holds a year of daily reports from one receiver and
// bounds the page against a receiver that reports far more often.
var DMARC_WINDOW_ROWS = 400;

// The failing senders and the reporting organizations listed on the page
// narrowed to one domain. Both listings unseal or name something an
// operator acts on one at a time, and both are read only on that page:
// the overview answers which domain needs attention, and a list of
// senders mixed across every hosted domain is not one anybody can act on
// because the fix belongs to a single domain's records.
//
// The store carries its own ceiling and answers how many there are
// alongside how many it listed, so a page showing fewer than exist says
// so rather than reading as the whole picture.
var DMARC_SOURCE_ROWS   = 25;
var DMARC_REPORTER_ROWS = 25;

// When a domain's newest reporting window is old enough to say so. A
// receiver counts a day and sends the report after the day closes, so
// the newest window ending yesterday is the ordinary state and the one
// ending the day before that is the first genuinely late reading.
var DMARC_STALE_DAYS = 2;

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

// The authority this request was addressed to, put where every chain
// looks for it. Returns true when it answered the request itself.
//
// The framework binds every TLS listener with `http2.createSecureServer`
// and offers `["h2", "http/1.1"]` over ALPN, so every browser that
// reaches this surface negotiates HTTP/2. An HTTP/2 request carries its
// authority in the `:authority` pseudo-header and sends no `Host` header
// at all (RFC 9113 section 8.3.1), and Node does not synthesize one, so
// `req.headers.host` is undefined for the whole of the traffic a person
// generates.
//
// Several readers in the request lifecycle ask what origin this server
// was reached on, and every one of them asks `req.headers.host`. The
// origin cross-check is the one that decides whether the surface works:
// it compares the browser's `Origin` against a baseline built from that
// header, so over HTTP/2 it compares a real origin against an empty
// string and refuses. Every form on this surface answers 403 to every
// browser, and no synthetic client sees it, because a test client speaks
// HTTP/1.1 and sends the header the gate was written against.
//
// `:authority` is the same value `Host` carries in HTTP/1.1, so folding
// one into the other hands those readers the request they expect rather
// than relaxing what they check.
//
// Where the two disagree the request is malformed by RFC 9113 section
// 8.3.1 and is refused rather than resolved. The precedence is not a
// style choice: `host` is a header the caller writes, and over HTTP/2 so
// is `Origin`, so a caller sending both names both sides of the origin
// comparison and satisfies it with a name this server does not serve.
// Letting the header win would leave the cross-check agreeing with
// whoever asked. A browser cannot reach this branch, because it sets
// `:authority` from the URL and `Host` is a forbidden header name.
function _normalizeAuthority(req, res) {
  var headers = req.headers || {};
  var authority = headers[":authority"];
  if (typeof authority !== "string" || authority.length === 0) return false;

  var host = headers.host;
  if (typeof host === "string" && host.length > 0 && host !== authority) {
    // Named from the request rather than from the ambient scope. This
    // runs before the session is read, so there is no account to name and
    // `auditActor.current()` would carry whatever the last request left
    // behind. The peer is what a reader of this row has to go on, and the
    // peer is on the request.
    b.audit.safeEmit({
      action:   "blamepost.web.authority_mismatch",
      outcome:  "denied",
      actor:    auditActor.forRequest(req),
      metadata: { method: req.method },
    });
    res.writeHead(400, {
      "Content-Type":  "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    });
    res.end(JSON.stringify({
      error: "The Host header and the :authority of this request name different servers, " +
        "which RFC 9113 section 8.3.1 makes this request malformed.",
    }));
    return true;
  }

  headers.host = authority;
  return false;
}

// Put the reader in front of every chain, including the framework's.
//
// `createApp` mounts its own request lifecycle before the routes mount
// theirs, and its CSRF gate checks the origin, so a request refused for
// its origin is answered there and never reaches anything this file
// mounts. A normalization mounted with the routes would run after the
// gate that needed it, on requests that were already refused.
//
// The seam is the Node server, which is a plain `Http2SecureServer`
// rather than anything internal to the framework: its `request`
// listeners are captured, replaced by one that reads the authority
// first, and called in their original order for every request that is
// not refused. Nothing else registers a `request` listener on these
// servers; the JMAP transport arrives on `upgrade`, which is untouched.
function _interposeAuthority(server) {
  var downstream = server.listeners("request");
  server.removeAllListeners("request");
  server.on("request", function (req, res) {
    if (_normalizeAuthority(req, res)) return;
    for (var i = 0; i < downstream.length; i += 1) downstream[i].call(server, req, res);
  });
}

// Where the JMAP WebSocket transport answers. RFC 8887 section 3 has
// the client read the endpoint out of the session document rather than
// guess at it, and the framework's session resource writes this same
// default into both the capability object and the top level
// `webSocketUrl`. Changing it here without passing the new value to
// `b.mail.server.jmap.create` would advertise one url and serve
// another, which fails on the client as a channel that never opens and
// records nothing on the server.
var JMAP_WEBSOCKET_PATH = "/jmap/ws";

// The RFC 8620 section 2 limits the session document advertises under
// `urn:ietf:params:jmap:core`. Each one is enforced where it is named.
//
// The listener is composed under `b.guardJmap`'s strict profile, and
// `b.mail.server.jmap.create` refuses to start when an advertised core
// limit differs from the one the listener enforces, so the request size
// and the object counts are read from that profile rather than chosen
// here. `maxSizeRequest` is also the JSON body limit of
// `b.middleware.bodyParser`, which reads the POST body before the route
// runs, and the WebSocket frame cap. `maxCallsInRequest` is applied by
// the dispatcher on both transports. `maxObjectsInGet` and
// `maxObjectsInSet` are checked by the dispatcher and again by each
// method handler below. `maxConcurrentRequests` is checked per account
// by the API route.
//
// Blob upload answers 503, because no upload backend is composed. The
// framework refuses a `maxSizeUpload` of 0, so the session advertises 1
// octet, the smallest value it accepts; every upload is refused either
// way. Blob DOWNLOAD is served, and RFC 8620 section 2 gives it no limit
// to name here, so the two halves of section 6 are read separately.
var JMAP_STRICT_LIMITS            = b.guardJmap.limitsFor({ profile: "strict" });
var JMAP_MAX_SIZE_REQUEST         = JMAP_STRICT_LIMITS.maxSizeRequest;
var JMAP_MAX_CALLS_IN_REQUEST     = JMAP_STRICT_LIMITS.maxCallsInRequest;
var JMAP_MAX_OBJECTS_IN_GET       = JMAP_STRICT_LIMITS.maxObjectsInGet;
var JMAP_MAX_OBJECTS_IN_SET       = JMAP_STRICT_LIMITS.maxObjectsInSet;
var JMAP_MAX_CONCURRENT_REQUESTS  = 4;
var JMAP_MAX_SIZE_UPLOAD          = 1;
var JMAP_MAX_CONCURRENT_UPLOAD    = 1;

// The largest frame the JMAP socket accepts. A `Request` frame carries
// the same body as a POST to the API endpoint, so the ceiling is the
// request limit above.
var JMAP_WEBSOCKET_MAX_BYTES = JMAP_MAX_SIZE_REQUEST;

// The JSON body limit every route is read under. It is the JMAP request
// limit, because `/jmap/api` is the route that needs the most.
var JSON_BODY_MAX_BYTES = JMAP_MAX_SIZE_REQUEST;

// The RFC 8621 section 1.6.2 and section 7 account capability values.
// They sit beside the section 2 limits above because they answer the
// same question a client asks once and then shapes its whole session
// around: what this server will accept. Each one is the number the
// matching method already enforces, written where a client can read it.
//
//   `maxMailboxesPerEmail` is one because a message is in exactly one
//   folder here and `_applyJmapPatch` refuses a patch naming two.
//   `maxMailboxDepth` is null, which RFC 8621 section 1.6.2 defines as
//   no limit, because nothing here caps how many levels a mailbox name
//   carries: IMAP CREATE makes every level a name needs, and the
//   answer below reports each of them.
//   `maxSizeMailboxName` is the ceiling a folder name is read against.
//   `maxSizeAttachmentsPerEmail` is zero because blob upload is not
//   served and `Email/set` creates nothing, so a client has no way to
//   put a file on a message through JMAP.
//   `emailQuerySortOptions` is empty because `Email/query` answers
//   newest first and refuses a sort naming anything.
//   `mayCreateTopLevelMailbox` is false because `Mailbox/set` is not
//   served.
//   `maxDelayedSend` is zero because `EmailSubmission/set` hands the
//   message to the outbound path as it runs, and a `sendAt` past that
//   is refused rather than dropped.
var JMAP_MAX_MAILBOXES_PER_EMAIL     = 1;
var JMAP_MAX_MAILBOX_DEPTH           = null;
var JMAP_MAX_ATTACHMENT_BYTES        = 0;
var JMAP_MAY_CREATE_TOP_LEVEL_MAILBOX = false;
var JMAP_MAX_DELAYED_SEND_SECONDS    = 0;

// How far into a folder `Email/query` walks to answer, in pages. The
// pager reads newest first from a modseq cursor, so reaching row N costs
// N / PAGE_SIZE reads. A request reaching past this is refused with the
// row count it may ask for rather than answered short, because a short
// page reads to a client as the end of the folder.
var JMAP_QUERY_MAX_PAGES = 20;
var JMAP_QUERY_MAX_ROWS  = PAGE_SIZE * JMAP_QUERY_MAX_PAGES;

// The most ids one `Email/query` answers with. A page a following
// `Email/get` could not ask for in one call is this server disagreeing
// with its own two ceilings, and the ids exist to be fetched.
var JMAP_QUERY_MAX_LIMIT = JMAP_MAX_OBJECTS_IN_GET;

// The RFC 8621 section 4.4 FilterCondition properties this server reads.
// A filter naming anything else is refused: a condition dropped on the
// way in answers a question the client did not ask, with more mail than
// it asked for, and nothing in the answer says so.
var JMAP_QUERY_CONDITIONS = Object.freeze(["inMailbox", "text", "from", "to", "body"]);

// The blob ids of RFC 8620 section 6.2, as this server spells them.
//
// A blob id is an Id, and RFC 8620 section 1.2 admits only the
// characters below in one. A message identifier is such a string on its
// own and names that message's raw octets, which is what RFC 8621
// section 4.1 has `Email.blobId` answer. One part of that message is
// named by the same identifier, this marker, and the part number RFC
// 9051 section 6.4.5 gives the part with each dot written as a dash,
// because a dot is outside the grammar an Id is read against.
//
// The marker cannot occur inside a message identifier. Those are minted
// as a fixed prefix and hexadecimal, and `p` is not a hexadecimal digit,
// so the split below lands on the marker this server wrote rather than
// inside the identifier. A layer-0 assertion pins that identifier shape,
// so a change to it arrives as a failing assertion rather than as a blob
// id that resolves to a different message.
var BLOB_ID_RE   = /^[A-Za-z0-9_-]{1,255}$/;
var BLOB_PART_RE = /^(.+)-p([0-9-]{1,63})$/;

// The name a whole-message blob is served under. A message carries no
// filename of its own, so this is a name this server chose rather than
// anything a stranger wrote.
var MESSAGE_BLOB_FILENAME = "message.eml";

// The RFC 8620 section 3.6.1 request-level problem types.
var JMAP_PROBLEM = Object.freeze({
  notJSON:           "urn:ietf:params:jmap:error:notJSON",
  notRequest:        "urn:ietf:params:jmap:error:notRequest",
  limit:             "urn:ietf:params:jmap:error:limit",
  unknownCapability: "urn:ietf:params:jmap:error:unknownCapability",
});

// The prefix the framework dispatcher reads on a handler's answer to
// emit it as a method-level error rather than as a result.
var JMAP_ERROR_PREFIX = "urn:ietf:params:jmap:error:";

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

// How a part of a message is named in a path. RFC 9051 section 6.4.5
// numbers the parts of a message `1`, `2`, `2.1`: one number per level of
// nesting, counting from one, joined by dots. It is the numbering an IMAP
// client already uses for the same part of the same message, so a reader
// comparing this surface with their other client is comparing one name.
//
// The bounds are the caps every message parse in this server runs under.
// `MESSAGE_PARSE_CAPS` refuses a message past 64 parts or 16 levels deep,
// so a value outside these names a part no message here can hold, and the
// grammar refuses it before any octets are opened.
var PART_ID_RE = /^[1-9][0-9]{0,2}(?:\.[1-9][0-9]{0,2}){0,15}$/;

// What a part is served under when the sender named it nothing this
// server can write down. RFC 6266 section 4.1 has the `filename`
// parameter carry a name a receiver saves the body under, and a part may
// carry no name at all or one the filename guard refuses whole.
var UNNAMED_PART = "attachment.bin";

// What the reader is told a part is when the sender's claim is not a
// media type. The claim is shown rather than acted on, so a value that is
// not RFC 6838 shaped becomes a phrase rather than a blank column, which
// would read as a part that declared nothing.
var UNREADABLE_MEDIA_TYPE = "an unreadable media type";

// The profile the sender's media-type claim is read under. Balanced
// rather than strict: the strict profile refuses the risky types
// outright, and a part claiming to be a script is exactly the part whose
// claim a reader needs to see. Nothing here acts on the claim, so the
// reading is "is this a media type at all".
var MEDIA_TYPE_GUARD = Object.freeze({ profile: "balanced" });

// Everything an RFC 6266 `filename` parameter may not carry: the C0
// controls, and every code point above printable ASCII. RFC 9110 section
// 5.6.4 holds a quoted-string to HTAB and printable ASCII, and RFC 6266
// section 4.3 has a sender keep the plain parameter to ASCII so a
// receiver that reads nothing else can still save the file. The real name
// travels in `filename*`.
var NON_ASCII_FILENAME_RANGES = Object.freeze([[0x0000, 0x001f], [0x007f, 0x10ffff]]);

// RFC 8187 section 3.2.1 `attr-char`, less the alphanumerics, which are
// asked about separately. Every other octet of an ext-value is
// percent-encoded, the apostrophe included: it is the character the
// ext-value is split on, so a name carrying one would otherwise end the
// value early and hand the rest to a receiver as a different parameter.
var EXT_VALUE_SYMBOLS = "!#$&+-.^_`|~";

// The two characters that end a quoted-string, and the two path
// separators. The filename guard's strip mode leaves a separator alone,
// because it is repairing a name rather than deciding whether it is a
// leaf, and a `Content-Disposition` names one file rather than a place to
// put it.
var FILENAME_REPLACED = "\"\\/";

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

// ---------------------------------------------------------------------
// Publishing a DMARC record into the hosted zone.
//
// The write gate in `lib/dns` computes a change set and performs it, and
// those are two calls with a re-read of the zone between them. This
// surface is where an operator drives both: the DMARC page shows the
// record each policy level would be published as, one post computes what
// publishing a level would change, and a second post performs the set
// that was shown.
//
// It is here rather than on the command line because performing a change
// set needs the data volume, and the running server holds it. A command
// line verb would mean stopping mail to edit a TXT record.
//
// Nothing in this file decides what may be written, re-reads the zone,
// counts the change set against a ceiling or reads a record back
// afterwards. The gate does all of it and refuses by code; what is local
// here is the transport: which operator asked, which change set they
// read, and how a refusal is written as a document.
// ---------------------------------------------------------------------

// The problem types the zone verbs answer with, as URNs.
//
// Same reasoning as the sending route's table above: a URN names the
// problem, locates nothing, and is the stable string a reader branches on
// across releases.
var ZONE_PROBLEM = Object.freeze({
  action:         "urn:blamepost:problem:zone-action-refused",
  writerOff:      "urn:blamepost:problem:zone-writer-not-configured",
  domain:         "urn:blamepost:problem:zone-domain-not-hosted",
  level:          "urn:blamepost:problem:zone-policy-level-refused",
  reason:         "urn:blamepost:problem:zone-reason-required",
  stepNotCarried: "urn:blamepost:problem:zone-policy-step-not-carried",
  notHeld:        "urn:blamepost:problem:zone-change-set-not-held",
  moved:          "urn:blamepost:problem:zone-change-set-moved",
  drift:          "urn:blamepost:problem:zone-record-drift",
  tooMany:        "urn:blamepost:problem:zone-too-many-changes",
  notAllowed:     "urn:blamepost:problem:zone-write-not-allowed",
  // A write that stopped partway is its own type rather than a variety of
  // provider refusal, because it asks the reader for the opposite move. A
  // provider refusal left the zone as it was and the change can be
  // repeated; this one left the zone holding part of the set, and
  // repeating it without reading the zone again writes over whatever the
  // first half produced.
  incomplete:     "urn:blamepost:problem:zone-write-incomplete",
  provider:       "urn:blamepost:problem:zone-provider-refused",
  // A fault in this process rather than a refusal from either layer
  // below. It is separate from the provider type because it asks the
  // reader for a different move: a provider refusal says what the
  // provider would not do, and this one says nothing has been
  // established about the zone at all.
  refused:        "urn:blamepost:problem:zone-change-refused",
});

// ---------------------------------------------------------------------
// The sending-credential ceilings page.
// ---------------------------------------------------------------------
//
// Two ceilings ride on every sending credential over a rolling window,
// and the refusal an application meets at one of them advises two acts:
// raise the ceiling, or give the window back. Both are here rather than
// on the command line, and the reason is the counters. They are held in
// the registry instance in memory, so they exist only while the server
// runs; every mutating `credential` verb needs the data volume, one
// process holds that volume at a time, and stopping the server to reach
// one destroys the window it was going to release. A command line
// release would clear an empty set of counters and report a window given
// back. The console and the counters are in one process, which is what
// makes either act possible at all.
//
// Raising a ceiling is a write to the credential's row, which this
// process can make because it is the process holding the volume. It
// takes effect on the next message: the ceiling is read off the row on
// every count rather than cached anywhere.

// The problem types this page answers with, as URNs. Same reasoning as
// the sending route's table and the zone verbs': the URN names the
// problem, locates nothing, and is the stable string a reader branches
// on across releases.
//
// A refusal here is a document rather than a redrawn form for the reason
// the zone edits are. Both acts change what a credential in somebody
// else's hands can send before anything stops it, and an operator left
// reading a form to work out whether the window moved is an operator who
// presses the button again.
var CREDENTIAL_PROBLEM = Object.freeze({
  action:    "urn:blamepost:problem:credential-action-refused",
  domain:    "urn:blamepost:problem:credential-domain-not-hosted",
  notFound:  "urn:blamepost:problem:credential-not-readable",
  ceiling:   "urn:blamepost:problem:credential-ceiling-refused",
  // The window length asked to move while the window still holds volume.
  // It is its own type rather than a variety of the one above, because
  // it asks the reader for a different move: the ceilings are refused
  // for being outside a bound and this one is refused for an order of
  // operations, and the act that clears it is the other button on the
  // same page.
  windowInUse: "urn:blamepost:problem:credential-window-in-use",
  refused:   "urn:blamepost:problem:credential-change-refused",
});

// How long a computed change set stays available to the post that
// performs it, and how many this process holds at once.
//
// The window covers reading a diff and typing a domain name back. Past
// it the zone has had time to move under the change set, and computing
// it again is the correct answer rather than an inconvenience.
var ZONE_HELD_TTL_MS = b.constants.TIME.minutes(15);
var ZONE_HELD_MAX    = 32;

// The longest reason this surface records against a zone write. It is
// the gate's own bound, restated as a refusal an operator reads on the
// form rather than as a stack trace from the layer underneath.
var ZONE_MAX_REASON_CHARS = 1000;

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
  "site-published": { kind: "ok", text: "The front page is published. Anyone who can reach the web port sees it at the root, and crawlers are told they may index it." },
  "site-hidden":    { kind: "ok", text: "The front page is withdrawn. The root answers with the sign-in page, and crawlers are told to index nothing." },
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
  "alias-disabled": { kind: "ok",  text: "Alias stopped. Mail to it is refused rather than forwarded, and the row is still here." },
  "alias-enabled": { kind: "ok",   text: "Alias started. Mail to it is forwarded again." },
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
  // A zone write, in the three states the two reads afterwards can leave
  // it in. They are separate codes because the operator's next move
  // differs between them and no single word carries all three.
  //
  // The provider holding the record and a resolver answering with it are
  // different facts, and a write that only the provider can see is the
  // one an operator most needs told about: it is invisible to either read
  // on its own, and on a policy record it means receivers are still
  // judging mail by the old value.
  "zone-published": { kind: "ok", text: "The record is published. The provider holds it and a resolver answers with it." },
  "zone-published-pending": { kind: "warn", text: "The record is at the provider and no resolver has answered with it yet. That is ordinary while a previous answer is still cached, and it clears on its own. Read the DMARC page again in a few minutes, or run `blamepost zone verify` to ask both sides." },
  "zone-published-conflict": { kind: "warn", text: "The record is at the provider and a resolver is answering with something else. That does not clear on its own: mail is being judged against a record this server did not write. Check whether another zone holds the same name, or whether something else edits this one." },
  // The fourth state, and the one a success message must never absorb.
  // The write happened and the two reads that say what came of it did
  // not, so nothing here has established that the record is anywhere. An
  // operator told the publish is complete stops looking; this sends them
  // to the verb that asks both sides again.
  "zone-published-unread": { kind: "warn", text: "The record was written and could not be read back. Neither the provider nor a resolver answered, so nothing here says whether the record is in place. The server log says what failed. Run `blamepost zone verify` to ask both sides again." },
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
  // The two acts on a sending credential's ceilings. Neither says how
  // much was given back or where a number moved to: a notice is looked
  // up by code and carries no value read off a request, and the audit
  // row beside the act holds both readings.
  //
  // Each says what the other one did not do, because the two are one
  // press apart on the same row and an operator who reached for the
  // wrong one otherwise reads a success and goes on waiting. Giving the
  // window back leaves the ceilings where they were; moving the ceilings
  // leaves what has already been counted where it was.
  "credential-window-released": { kind: "ok", text: "The window is back to zero, so that credential sends its full allowance again from now. Its ceilings are unchanged, and the mail it already sent has gone." },
  "credential-ceilings-set":    { kind: "ok", text: "Those ceilings are in force from that credential's next message. What it has already sent in the current window still counts against them; the button beside it on the list is what gives that back." },
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
// The adapter verbs that carry a whole delete and a whole move, and the
// read a reply or a forward is derived from. A handle answering
// `accountFolders` alone is what a partial adapter presents, and
// accepting it is how a surface ends up reaching past the verb that
// would have done the work.
//
// `readMessageSource` answers with the message's own octets and the
// `Reply-To` and `Cc` headers. The agent's `fetch` answers with the
// stored row, which carries neither header and no octets.
var REQUIRED_MAILBOX = ["accountFolders", "expungeObjects", "moveObjects", "readMessageSource"];
// @membership blamepost.web.REQUIRED_STORE constraint
var REQUIRED_STORE = [
  "accounts.authenticate", "accounts.get", "accounts.list", "accounts.create",
  "accounts.suspend", "accounts.reinstate", "accounts.delete", "accounts.unlock",
  "accounts.lockoutState", "accounts.setAdmin",
  "domains.add", "domains.list", "domains.acknowledgeDns", "domains.setStatus",
  "aliases.add", "aliases.list", "aliases.remove",
  // The server-wide settings an operator changes from the console rather
  // than from the environment. Named here so a handle without them fails
  // the boot: the front page reads one on every request a stranger makes,
  // and a missing reader would turn that into a fault on the one route
  // whose whole point is that it answers somebody with no account.
  "settings.get", "settings.set",
  // The DMARC reading, and the windows the rows are kept for. `rollup`
  // is the counting the console renders; `describe` is how long those
  // rows survive, which is what bounds the window a request may ask
  // about. A page offering to read further back than the rows go would
  // be offering an emptier answer than the shorter one, and the number
  // that settles it is the one in force rather than a default named
  // here.
  //
  // `failingSources` and `reporters` are the two readings the counting
  // cannot give. The counting answers how many senders are failing and
  // how much arrived; an operator opens the page to find out which
  // senders and who has been heard from, and a handle that cannot answer
  // either leaves the page reporting a number nobody can act on.
  "reports.rollup", "reports.describe", "reports.failingSources", "reports.reporters",
  // The sending-credential registry the route on this surface hands to
  // the mail layer's credential entry point, and the ceiling the
  // composer's gate counts through the same registry. Both halves are
  // named rather than `verify` alone, for the reason `blamepost.create`
  // names both: a registry that verifies and cannot count is a server
  // where every credential authenticates and no ceiling holds, and the
  // ceiling is what stops a leaked secret. A handle short of either is a
  // boot failure rather than a route that refuses every application at
  // the first message.
  "credentials.verify", "credentials.counters.record",
  // What the credentials page reads and what it changes. The reading and
  // the two acts are named together because a page that can show a
  // window and not move it is a page describing a refusal an operator
  // cannot answer: the ceiling message they are reading on the wire
  // names both acts, and a handle short of either leaves one of them
  // advised and impossible.
  //
  // `counters.read` rather than `counters.record`, which is already
  // above for the sending route. They are different questions and only
  // one of them counts the message in front of it; a page that asked the
  // counting one would refuse a credential for having been looked at.
  "credentials.list", "credentials.show", "credentials.setCeilings",
  "credentials.counters.read", "credentials.counters.release",
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
// is a path on this server, and the two readings that decide it live in
// `lib/web/links.js`: `path` for a redirect target, `href` for the value
// a template interpolates after the slash it writes itself. The reference
// wiki builds links under `/wiki` and asks the same pair, so the rule has
// one home rather than one copy per surface.
//
// The names below are this file's names for them. Every target is built
// through one of the two, so a value that would leave this origin is
// refused where the path is BUILT rather than where it becomes a link,
// which is what keeps the invariant off the eleven separate string
// concatenations that would otherwise each have to remember it.
function _path(value) {
  return links.path(value);
}

function _href(value) {
  return links.href(value);
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

// A count and the noun it counts, agreeing. The template engine renders
// what it is handed, so a heading built as a number beside a plural noun
// reads "1 reports" on the one reading an operator is most likely to be
// looking at during an incident.
function _counted(n, one, many) {
  return String(n) + " " + (n === 1 ? one : many);
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

// The same address on its way to a reader's eyes rather than into a
// recipient field.
//
// Those are two questions and they take two answers. `_bareAddress` is
// read by the compose derivation, where the value becomes a mailbox a
// reply is sent to, and a screen there would change the address this
// server addresses. Here the value is printed beside the sender's name
// and in the row title, where a bidirectional override reorders what
// the reader is deciding about. So the screen goes on the reading, and
// nothing it removes reaches an envelope.
function _shownAddress(value) {
  return _headerText(_bareAddress(value));
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
  var bounded = text.length > MAX_AUTHOR_ECHO_CHARS
    ? text.slice(0, MAX_AUTHOR_ECHO_CHARS) + "..."
    : text;
  // Screened after the bound rather than before it, so the ceiling is on
  // the characters the caller sent. What comes back is an address a
  // request named and this server would not take, quoted into a
  // refusal a person reads and into an audit row an operator reads
  // later, so the codepoints in it are the caller's to choose.
  return displayText.forDisplay(bounded);
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
// `blamepost.text` is the one screen this server puts in front of text
// somebody else wrote, and it is shared because these values are not
// read only in a browser: the same subject and the same record content
// reach the server log and `blamepost audit read`, and an operator pipes
// both through a terminal.
//
// A value that is not a string is handed back as it arrived, because the
// callers below pass one through where a column is absent and a column
// that is absent is not the empty string.
function _headerText(value) {
  if (typeof value !== "string" || value.length === 0) return value;
  return displayText.forDisplay(value);
}

// One caught fault, as the words a person may be shown.
//
// A fault reaching this file is rarely this file's prose. A JMAP client
// chooses the keyword and the property name a patch names, and the
// sentence refusing the patch quotes them. A receiving peer chooses the
// reply text a delivery failure carries, and that text becomes the
// sentence on the compose form, the description beside a submission and
// the detail of a problem document. A provider's error body, a
// filesystem refusal quoting a path and a parser quoting the header line
// it could not read are all the same shape.
//
// Markup escaping answers none of it, because none of what does the harm
// is markup: a bidirectional override reverses the reading order of the
// rest of the sentence, the single-byte control sequence introducer at
// U+009B opens an escape sequence for anything reading the answer as a
// stream, and a carriage return with no line feed overwrites the first
// half of the line with the second.
//
// Screened here, where the value is built, rather than at each exit it
// reaches. One fault's words go to a log line, an audit row, a rendered
// page and a client's own display, and the layers after this one cannot
// tell which of those a value is headed for.
function _faultForDisplay(e) {
  return displayText.forDisplay((e && e.message) || String(e));
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

// A folder name arriving from a query value or a form field. It is
// carried as it was sent and matched against the account's own folders,
// which is the only thing that decides whether it names anything. A name
// this module tidied into a different one would answer for a folder the
// reader did not ask for, and a name defaulted on a miss would answer 200
// where the honest reply is 404.
//
// It is never read off a path segment. A mailbox name separates its
// levels with a delimiter a request path also uses, so the framework
// refuses a path carrying it percent-encoded before any route runs.
function _folderName(value) {
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

// A line carrying somebody else's words rather than this server's. Read
// by the body renderer, which marks such a line for the stylesheet, and
// by the draft builder, which leaves such a line unscreened because the
// account holder has already read it as the message. One reading, so the
// two surfaces cannot disagree about which half of a draft is quoted.
var RE_QUOTED_LINE = /^\s*>/;

// A plain text body becomes markup here rather than in a template, so the
// escaping is the guard's and quoted lines can be marked up for the
// stylesheet without the message being able to name a class itself.
function _renderTextBody(text) {
  var lines = String(text == null ? "" : text).split(/\r?\n/);
  var out = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var quoted = RE_QUOTED_LINE.test(line);
    out.push(
      "<p class=\"" + (quoted ? "mb-quote" : "mb-line") + "\">" +
      b.guardHtml.escapeText(line) +
      "</p>"
    );
  }
  return out.join("");
}

// How many images the reading default holds back, counted on the
// rendering the reader would get if they asked for them.
//
// The count is the difference between the two readings, so it is taken
// from the second one. An `img` the message carried is not by itself an
// image being withheld: one written inside a comment is dropped on both
// readings, and one carrying only a source set has its source dropped on
// both, so neither would load whatever the reader decided. Counting the
// source text instead reports those as held back, and the reader who
// presses the button gets a page that looks exactly like the one they
// left and a widened policy they spent for nothing.
//
// One carried INSIDE the message still counts, which is why the count is
// of sources rather than of off-site hosts: an inline image is dropped by
// the reading default like any other, so a message whose images are all
// inline would otherwise show none of them and offer no way to ask.
//
// It costs a second pass over the markup, and only on the reading where
// images are held: a conversation is a handful of messages, and the
// alternative is a number that describes the message rather than the
// decision the reader is being offered.
function _heldImageCount(renderedWithImages) {
  if (typeof renderedWithImages !== "string" || renderedWithImages.length === 0) return 0;
  var matches = renderedWithImages.match(/<img\b[^>]*\ssrc\s*=/gi);
  return matches ? matches.length : 0;
}

function _renderBody(message, withImages) {
  var html = message && typeof message.bodyHtml === "string" ? message.bodyHtml : "";
  if (html.length > 0) {
    return {
      html:         _sanitizeHtmlBody(html, withImages),
      isHtml:       true,
      blockedCount: withImages ? 0 : _heldImageCount(_sanitizeHtmlBody(html, true)),
    };
  }
  var text = message && typeof message.bodyText === "string" ? message.bodyText : "";
  return { html: _renderTextBody(text), isHtml: false, blockedCount: 0 };
}

// ---------------------------------------------------------------------
// The files a message carries.
//
// Two questions run through this section and they take different
// answers, so each function below answers one of them and says which.
//
// A name a reader READS is screened by `blamepost.text`, which is the one
// display screen in this server. A right-to-left override inside a name
// shows `report.exe` as `report.txt` to the person deciding whether to
// open it, and the screen removes the override so the extension reads as
// the bytes say.
//
// A name a file is SERVED under is repaired by `b.guardFilename`, which
// replaces the same override with an underscore rather than removing it,
// and refuses the classes a name written to a filesystem is never
// repaired from. The two functions return different strings for the same
// input, and each comment below says which of the two it answers.
// ---------------------------------------------------------------------

// The name a part is SERVED under. The security floor throws rather than
// repairing: a name carrying a traversal segment, a null byte, a UNC
// prefix, an NTFS alternate data stream or an overlong UTF-8 sequence is
// one a receiver saving it would write somewhere the sender chose, and a
// name past the guard's byte cap is one nothing can hold. Each of those
// answers with this server's own name instead, because a part with an
// unusable name is still a part the reader asked for.
//
// The two path separators are replaced afterwards, because strip mode
// leaves them alone. A `Content-Disposition` names one file, so a name
// that reaches a receiver carrying a separator names a place to put it.
function _servedFilename(raw) {
  if (typeof raw !== "string" || raw.length === 0) return UNNAMED_PART;
  var repaired;
  try {
    repaired = b.guardFilename.sanitize(raw, { profile: "balanced", mode: "strip" });
  } catch (_refused) {
    // Drop-silent by design: the guard refused the name, and the reader
    // asked for the octets. The part is served under the name this
    // server chose.
    return UNNAMED_PART;
  }
  var leaf = b.codepointClass.replaceAny(repaired, FILENAME_REPLACED, "_");
  return leaf.length === 0 ? UNNAMED_PART : leaf;
}

// One name as an RFC 8187 section 3.2.1 ext-value: every octet outside
// `attr-char` percent-encoded, over the UTF-8 encoding of the name.
//
// `encodeURIComponent` leaves `'`, `(`, `)` and `*` unencoded, and none
// of the four is an `attr-char`. An ext-value is split on the
// apostrophe, so a receiver reads a name carrying one as a charset, a
// language and a shorter name than the sender wrote.
function _extValue(name) {
  var bytes = Buffer.from(String(name), "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i += 1) {
    var octet = bytes[i];
    if (b.codepointClass.isAsciiAlnum(octet) ||
        EXT_VALUE_SYMBOLS.indexOf(String.fromCharCode(octet)) !== -1) {
      out += String.fromCharCode(octet);
      continue;
    }
    out += "%" + (octet < 16 ? "0" : "") + octet.toString(16).toUpperCase();
  }
  return out;
}

// The whole `Content-Disposition` value one part is served with, in the
// two forms RFC 6266 section 4.1 asks for.
//
// `filename` carries an ASCII folding of the name, for a receiver that
// reads nothing else; `filename*` carries the name itself. Both are built
// from the SERVED name rather than from what the sender wrote, so the
// header cannot carry a line break, a quote or a backslash whatever
// arrives: the filename guard refuses a null byte and replaces every
// control character, and the fold below replaces everything the
// quoted-string grammar of RFC 9110 section 5.6.4 does not admit.
//
// Every part is disposed `attachment`, and none is disposed `inline`. A
// part is bytes a stranger sent, and a browser showing one in place shows
// it on the origin the reader's session cookie is scoped to. RFC 2183
// section 2.2 defines the `inline` disposition and a sender may set it;
// this server does not serve a part under it.
function _dispositionFor(rawName) {
  var served = _servedFilename(rawName);
  var ascii = b.codepointClass.replaceRanges(served, NON_ASCII_FILENAME_RANGES, "_");
  if (ascii.length === 0) ascii = UNNAMED_PART;
  return "attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + _extValue(served);
}

// One blob id read into the message it names and the part of that
// message, or null when the id names nothing this server can hold.
//
// The Id grammar is checked before the split, because a value outside it
// is one no blob id this server minted can be, so there is nothing to
// look up and nothing to spend a read on. An id carrying no marker names
// the whole message and answers a null part number.
//
// The part number comes back in the spelling RFC 9051 section 6.4.5 uses
// and is checked against the same grammar the browser route reads a part
// number against, so the two surfaces admit one set of part numbers
// rather than two that could come apart.
function _blobRef(rawBlobId) {
  var blobId = _str(rawBlobId, "");
  if (blobId.length === 0 || !BLOB_ID_RE.test(blobId)) return null;
  var split = BLOB_PART_RE.exec(blobId);
  if (split === null) return { objectId: blobId, partNumber: null };
  var number = split[2].split("-").join(".");
  if (!PART_ID_RE.test(number)) return null;
  return { objectId: split[1], partNumber: number };
}

// The blob id one part of one message is served under. This is the write
// side of `_blobRef` above, and the two sit together so the marker and
// the dash spelling of the part number are read in one place. A client
// takes this value out of an `attachments` list and fills it into the
// session document's download template, so the route resolves what this
// builds or the property names octets nothing can fetch.
function _partBlobId(objectId, partNumber) {
  return objectId + "-p" + String(partNumber).split(".").join("-");
}

// One header of one part, screened, with the parameters cut off when the
// property asks for the value without them, or null when the part carried
// no such header.
//
// Null rather than the empty string, because RFC 8621 section 4.1.4 types
// every one of these properties as nullable and a client reads the
// absence: an empty string reads as a value the sender wrote. The screen
// runs because these are header values a stranger chose and a client puts
// them in front of a person.
function _partHeader(headers, name, stripParameters) {
  var raw = headers.get(name);
  if (typeof raw !== "string") return null;
  var value = (stripParameters ? raw.split(";")[0] : raw).trim();
  if (value.length === 0) return null;
  return _headerText(value);
}

// The charset one part declares, as RFC 8621 section 4.1.4 reports it.
//
// A part whose type is not `text/*` answers null. A text part answers the
// charset parameter of its Content-Type, and a text part that named none
// answers the `us-ascii` of RFC 2045 section 5.2, which the parse has
// already applied. A part carrying no Content-Type header at all arrives
// here typed `text/plain` for the same reason, so it answers `us-ascii`
// through the same line rather than through a branch of its own.
//
// The value is folded to lower case by the parse. RFC 2045 section 5.1
// makes a charset name case-insensitive, so that is the same name.
//
// It carries no display screen, unlike the media type beside it. The
// parse refuses a message whose part declares a charset outside its
// allowlist, so a value that reaches here is one of a fixed set of
// ASCII names rather than anything a sender chose to write. A screen
// over that is a line no input can reach.
function _partCharset(part) {
  if (part.leaf.contentType.slice(0, 5) !== "text/") return null;
  return part.leaf.charset;
}

// One leaf part of one message, in the shape RFC 8621 section 4.1.4 gives
// an EmailBodyPart.
//
// WHAT IS ANSWERED. The ten properties that section's default body set
// names: `partId`, `blobId`, `size`, `name`, `type`, `charset`,
// `disposition`, `cid`, `language` and `location`. `partId` is the part
// number RFC 9051 section 6.4.5 gives the part, which is what identifies
// it uniquely within the message here and is the same string the browser
// route takes in its path. `size` is the octet count after transfer
// decoding, which is the length of the body the download route serves for
// the same blob id.
//
// WHAT IS NOT. `headers` and `subParts` are absent. Every part in this
// list is a leaf, so `subParts` would be null on all of them. The header
// list belongs with the `header:*` forms of RFC 8621 section 4.1.3,
// which carry their own parsed readings of the same fields, and this
// server answers none of them. A client that requests either reads its
// absence.
function _bodyPart(objectId, leaf) {
  var headers = leaf.part.headers;
  // RFC 2392 addresses a part by the Content-Id without the angle
  // brackets the header writes it inside. A header holding nothing but
  // the brackets answers null rather than the empty string left over,
  // which is a value no sender wrote.
  var cid = _partHeader(headers, "content-id", false);
  if (cid !== null) {
    cid = cid.replace(/^<|>$/g, "");
    if (cid.length === 0) cid = null;
  }
  var language = _partHeader(headers, "content-language", false);
  var disposition = _partHeader(headers, "content-disposition", true);
  return {
    partId: leaf.number,
    blobId: _partBlobId(objectId, leaf.number),
    size:   leaf.part.leaf.body.length,
    name:   leaf.name.length > 0 ? _headerText(leaf.name) : null,
    // Screened for the reason the name beside it is. A media type is a
    // claim a stranger made, a client shows it to the person deciding
    // whether to open the file, and a reading-order override in one
    // changes what that line says without changing what it is. The
    // browser surface screens the same value before the same decision.
    // Every ordinary media type passes through unchanged.
    type:   _headerText(leaf.part.leaf.contentType),
    charset: _partCharset(leaf.part),
    // Folded, like the media type beside it. RFC 2183 section 2 makes a
    // disposition type case-insensitive, so a client comparing against
    // `attachment` reads the same answer whatever the sender typed.
    disposition: disposition === null ? null : disposition.toLowerCase(),
    cid: cid,
    language: language === null ? null : language.split(",")
      .map(function (tag) { return tag.trim(); })
      .filter(function (tag) { return tag.length > 0; }),
    location: _partHeader(headers, "content-location", false),
  };
}

// The media type a part claims, on its way to a reader's eyes. It is
// shown and never acted on: the response serves one type for every part,
// so what this answers is what the SENDER said rather than what this
// server will do with the bytes.
//
// The value goes through two screens. The media-type guard answers
// whether the claim is RFC 6838 shaped at all, and a claim that is not
// becomes a phrase, because a reader takes a blank column for a part that
// declared nothing. The display screen then runs over what the guard
// admitted, as it does over every other value on the page a stranger
// chose.
function _shownMediaType(claim) {
  var raw = typeof claim === "string" ? claim : "";
  if (raw.length === 0) return UNREADABLE_MEDIA_TYPE;
  if (!b.guardMime.validate(raw, MEDIA_TYPE_GUARD).ok) return UNREADABLE_MEDIA_TYPE;
  return displayText.forDisplay(raw);
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

// The References header a stored message carried, read back out of the
// store's spelling of it. The store joins the ids with commas; the
// header separates them with spaces. Nothing is appended here: this is
// what the message named, and a reply's own chain is derived by the
// outbound composer, which is the one place that decides what
// RFC 5322 section 3.6.4 makes a reply carry.
function _referenceList(message) {
  if (typeof message.referencesCsv !== "string" || message.referencesCsv.length === 0) return [];
  return message.referencesCsv.split(/[,\s]+/).filter(function (r) { return r.length > 0; });
}

// A reply or forward draft on its way into the compose form, with the
// lines the composer WROTE screened and the lines it quoted left alone.
//
// The two halves are not the same kind of text. The attribution line and
// a forward's header block are built out of the sender's display name
// and their subject, which are header values a stranger chose, and every
// other place this server shows one of those screens it: a bidi override
// there changes what the line the account holder is about to send looks
// like without changing what it says.
//
// The quoted lines are the message itself, and the account holder has
// already read them on the conversation page, where `_renderTextBody`
// escapes markup and screens nothing else. Screening them here would
// show them a quotation that differs from the message they are
// answering, and it would damage ordinary text: the balanced profile
// removes zero-width characters, which is what joins the parts of an
// emoji sequence and what separates a Devanagari conjunct, so a quoted
// family emoji comes apart into three people.
//
// A quoted line is one starting with the marker, which is the same
// reading `_renderTextBody` makes when it decides a line is somebody
// else's words.
//
// The split comes first because the screen is for a value shown on one
// line: it folds a line break to a space, which is right for a subject in
// a column and wrong for a draft the account holder is about to edit. A
// caller holding several lines splits them and screens each one, and this
// is that caller.
function _screenedDraftText(text) {
  return String(text == null ? "" : text).split("\n").map(function (line) {
    return RE_QUOTED_LINE.test(line) ? line : _headerText(line);
  }).join("\n");
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
 * `opts.zone`       optional, the handle `blamepost.dns.fromConfig`
 *                   returns, or null when the configuration names no DNS
 *                   provider. With it the administration console can
 *                   publish a DMARC record into the hosted zone.
 * `opts.dmarcPolicy`
 *                   optional, the handle
 *                   `blamepost.mail.dmarcPolicy.create` returns. It
 *                   answers what each policy level would be published as
 *                   and whether the evidence carries a step up. It and
 *                   `opts.zone` are supplied together or not at all.
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
      "whole move rather than half of one, and readMessageSource is the only read that " +
      "returns the Reply-To and Cc headers a reply is addressed from.");
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

  // The zone writer and the policy stepper, which arrive together or not
  // at all.
  //
  // Absent is the whole of what `zoneProvider: "none"` means: the DMARC
  // page reads reports and offers nothing to publish, which is the
  // deployment where the operator holds their own DNS. Present, the page
  // gains the record each policy level would be published as and the two
  // posts that publish one.
  //
  // Half of the pair is refused rather than accepted. A stepper with no
  // writer renders a verdict beside no way to act on it, and a writer
  // with no stepper offers a button with no record to put behind it, so
  // either half alone is a console that shows an operator something it
  // cannot finish.
  if (opts.zone !== undefined && opts.zone !== null &&
      (typeof opts.zone !== "object" || Array.isArray(opts.zone) ||
       typeof opts.zone.forDomain !== "function" ||
       typeof opts.zone.describe !== "function")) {
    throw new TypeError("blamepost.web.create: opts.zone must be the handle " +
      "blamepost.dns.fromConfig returns, which answers forDomain and describe. It is null " +
      "when the configuration names no DNS provider, and this surface then publishes " +
      "nothing.");
  }
  if (opts.dmarcPolicy !== undefined && opts.dmarcPolicy !== null &&
      (typeof opts.dmarcPolicy !== "object" || Array.isArray(opts.dmarcPolicy) ||
       typeof opts.dmarcPolicy.evaluate !== "function" ||
       typeof opts.dmarcPolicy.describe !== "function")) {
    throw new TypeError("blamepost.web.create: opts.dmarcPolicy must be the handle " +
      "blamepost.mail.dmarcPolicy.create returns, which answers evaluate and describe.");
  }
  var zone          = opts.zone === undefined ? null : opts.zone;
  var policyStepper = opts.dmarcPolicy === undefined ? null : opts.dmarcPolicy;
  if ((zone === null) !== (policyStepper === null)) {
    throw new TypeError("blamepost.web.create: opts.zone and opts.dmarcPolicy are wired " +
      "together or not at all, and one of them is missing. The console publishes a DMARC " +
      "record by asking the stepper what each policy level would be published as and " +
      "handing that record to the zone writer, so a console holding one of the two shows " +
      "an operator a step it cannot finish.");
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
  // Whether this process terminates TLS. `serve` passes `create` the
  // same opts, and `opts.tls` names the certificate the TLS port binds.
  var tlsTerminatesHere = opts.tls !== undefined && opts.tls !== null;

  // One reading of the transport, for everything on this surface that
  // decides from it.
  //
  // The connection this process can see is the socket in front of it.
  // Behind a proxy holding the certificate that socket is cleartext
  // while the browser's connection is TLS, and four decisions turn on
  // which of the two is meant: whether the double-submit cookie carries
  // `Secure` and the `__Host-` prefix, which scheme the origin
  // cross-check builds this server's own origin from, whether HSTS is
  // sent, and whether a credential is accepted at all. A proxy states
  // the browser's half in `X-Forwarded-Proto`, which any client can
  // write, so that header is read only from a peer `trustedProxies`
  // names and is ignored from every other one. A configuration naming
  // nobody reads the socket and nothing else.
  //
  // It is built once and handed to each middleware rather than
  // configured on each of them. Two of those middleware are mounted
  // twice, once on the framework's own request lifecycle and once on
  // the chain the routes mount, and a surface that answered one
  // transport on one mount and another on its twin would answer
  // differently depending on how far a request got.
  var transport = b.requestHelpers.trustedProtocol({
    trustedProxies: config.trustedProxies,
  });

  // Whether this request arrived over a connection that can carry a
  // credential.
  //
  // TLS is one answer and a named proxy saying the browser's connection
  // was TLS is the second. Loopback is the third, and it is the same
  // rule rather than an exception to it: a request that arrived over
  // loopback crossed no network, which is why the Secure Contexts
  // standard treats `127.0.0.1` and `localhost` as potentially
  // trustworthy and why a browser stores and returns a `Secure` cookie
  // there. A server that refused a password over loopback would refuse
  // the one cleartext case the browser itself makes work, which is a
  // browser and this process on the same machine.
  //
  // That arm reaches a host install and not the container image. A
  // published port is forwarded into the container's own network
  // namespace, so a request the host sends to `127.0.0.1` arrives here
  // from the bridge gateway and is refused a password like any other
  // off-machine peer. The documents send an operator to the TLS port for
  // that reason. Widening this arm to admit the gateway would hand the
  // exemption to everything else that can reach it.
  //
  // This is not the reading the mail listeners take of a TCP terminator
  // in front of 143 or 110, and the difference is what is being claimed.
  // There the peer address would stand in for a fact about a different
  // hop that the listener has no evidence about. Here it is a fact about
  // this hop, and there is no other one.
  //
  // The peer is read off the socket. `X-Forwarded-For` is ignored here
  // exactly as it is everywhere else on this surface, because a header
  // the client writes cannot be what decides whose connection this is.
  function _transportCarriesCredentials(req) {
    if (transport.resolve(req) === "https") return true;
    return b.ssrfGuard.isLoopback(b.requestHelpers.clientIp(req));
  }

  var engine    = b.template.create({ viewsDir: VIEWS_DIR });
  var renderer  = b.render.create({ engine: engine });
  var jar       = null;
  var reference = _buildReference();

  // The reference wiki, or null when the builder throws.
  //
  // A refusal takes down the wiki and nothing else. Webmail, the
  // administration console and the JMAP mount are created as usual,
  // `mount` answers every GET at or below `/wiki` with 503, and the
  // navigation and the sitemap stop listing `/wiki`. The builder's message
  // is written to the error log and to an audit row under
  // `blamepost.web.wiki_unavailable`, with the block's file and line when
  // the refusal names one.
  function _buildReference() {
    try {
      return wiki.build();
    } catch (err) {
      var message = _faultForDisplay(err);
      log.error("the reference wiki could not be built, and every GET at or below " +
        wiki.BASE_PATH + " answers 503 until the server starts on a tree it can build: " +
        message);
      b.audit.safeEmit({
        action:   "blamepost.web.wiki_unavailable",
        outcome:  "failure",
        // Whoever started the server, when the start established one.
        actor:    auditActor.current(),
        metadata: {
          error: message,
          file:  err && typeof err.file === "string" ? err.file : null,
          line:  err && Number.isInteger(err.line) ? err.line : null,
        },
      });
      return null;
    }
  }

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
  // again on every request. A suspended or archived account stops being
  // signed in at its next request, and so does an account whose domain is
  // disabled or no longer hosted. `blamepost.store.accounts.authenticate`
  // refuses a sign in on the same two readings.
  //
  // The domain is read through `domains.list`, which REQUIRED_STORE
  // already names, filtered to active rows.
  async function _loadAccount(verifiedSession) {
    if (!verifiedSession || typeof verifiedSession.userId !== "string") return null;
    var account = await store.accounts.get(verifiedSession.userId);
    if (!account || account.status !== "active") return null;
    var active = _asArray(await store.domains.list({ status: "active" }));
    for (var i = 0; i < active.length; i += 1) {
      if (active[i].domain === account.domain) return account;
    }
    return null;
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
  // The sending route.
  //
  // Everything here composes the submission listener's answers rather
  // than restating them. What is local to this file is the transport: how
  // a credential arrives over HTTP, what a refusal looks like as a
  // document, and the replay record that stops a retrying client from
  // sending a message twice.
  // -------------------------------------------------------------------

  // One refusal, written as an RFC 9457 problem document.
  //
  // Nothing that reaches here carries the credential that was presented.
  // A refusal is read by whoever asked for it and copied into whatever
  // log the caller keeps, and a secret echoed into either is a secret in
  // a second place.
  function _sendProblem(res, fields) {
    b.problemDetails.send(res, fields);
  }

  // Every address in a request body, derived through the identity layer.
  //
  // The derivation is the one the routing layer and the refusal list are
  // both written against, so a spelling that folds to a permitted mailbox
  // is measured as that mailbox. Reading the raw string instead would
  // disagree with the wire about who a recipient is, and would do it
  // silently.
  //
  // The first unreadable address ends the read. A body naming five
  // recipients of which one cannot be parsed is a body the sender has to
  // correct, and relaying the other four is a message half sent under a
  // reply that says it was refused.
  function _sendAddresses(written, label) {
    var out = [];
    for (var i = 0; i < written.length; i += 1) {
      var parsed = address.parse(written[i]);
      if (!parsed.ok) {
        return { ok: false, at: label + "[" + i + "]", rejected: _echoAuthor(written[i]) };
      }
      out.push(parsed.address);
    }
    return { ok: true, addresses: out };
  }

  // The request body, read under the schema and then under the identity
  // layer. Untrusted remote input, so the shape is refused at the point
  // of parse and every address is derived before anything is composed.
  function _readSendBody(raw) {
    var shape = SEND_BODY_SCHEMA.safeParse(raw);
    if (!shape.ok) {
      var first = shape.errors[0] || {};
      // Both halves are the caller's own bytes. A body naming a key this
      // route does not accept is refused with the key quoted, and the
      // path names it as well, so the sentence handed back is written in
      // whatever codepoints the request was written in.
      return { ok: false, detail: "The request body is not one this route accepts: " +
        (Array.isArray(first.path) && first.path.length > 0
          ? displayText.forDisplay(first.path.join(".")) + " " : "") +
        (first.message ? _faultForDisplay(first) : "the shape was refused") + "." };
    }
    var body = shape.value;

    var author = address.parse(body.from);
    if (!author.ok) {
      return { ok: false, detail: "from " + _echoAuthor(body.from) + " is not an address " +
        "this server will accept." };
    }

    var sender = null;
    if (body.sender !== undefined) {
      var parsedSender = address.parse(body.sender);
      if (!parsedSender.ok) {
        return { ok: false, detail: "sender " + _echoAuthor(body.sender) + " is not an " +
          "address this server will accept." };
      }
      sender = parsedSender.address;
    }

    var lists = { to: body.to || [], cc: body.cc || [], bcc: body.bcc || [] };
    var names = ["to", "cc", "bcc"];
    var recipients = { to: [], cc: [], bcc: [] };
    for (var i = 0; i < names.length; i += 1) {
      var read = _sendAddresses(lists[names[i]], names[i]);
      if (!read.ok) {
        return { ok: false, detail: read.at + " " + read.rejected + " is not an address " +
          "this server will accept." };
      }
      recipients[names[i]] = read.addresses;
    }
    var total = recipients.to.length + recipients.cc.length + recipients.bcc.length;
    if (total === 0) {
      return { ok: false, detail: "A message needs at least one recipient across to, cc " +
        "and bcc." };
    }
    if (total > SEND_MAX_RECIPIENTS) {
      return { ok: false, detail: "A message may name at most " + SEND_MAX_RECIPIENTS +
        " recipients across to, cc and bcc together, and this one names " + total + "." };
    }
    if (body.text === undefined && body.html === undefined) {
      return { ok: false, detail: "A message needs a text body, an html body, or both." };
    }

    var envelopeFrom = null;
    if (body.envelopeFrom !== undefined) {
      var parsedEnvelope = address.parse(body.envelopeFrom);
      if (!parsedEnvelope.ok) {
        return { ok: false, detail: "envelopeFrom " + _echoAuthor(body.envelopeFrom) +
          " is not an address a receiver can return mail to." };
      }
      envelopeFrom = parsedEnvelope.address;
    }

    // No recipient count travels with this. The ceiling is counted
    // against the list the composer built, which is what becomes the
    // envelope, and a second count taken from the request body would be a
    // number that can disagree with the one the message actually carries.
    // `total` above bounds the request and is finished doing so here.
    return {
      ok:           true,
      from:         author.address,
      sender:       sender,
      envelopeFrom: envelopeFrom,
      recipients:   recipients,
      subject:      body.subject,
      text:         body.text,
      html:         body.html,
      inReplyTo:    body.inReplyTo,
      references:   body.references,
    };
  }

  // The envelope decision, asked through the reader the submission
  // listener's sender policy asks.
  //
  // It is the same question `MAIL FROM` is measured against, so a
  // credential cannot be refused an envelope sender on one transport and
  // handed it on the other. The row is the one an operator reads when an
  // application starts failing, and it names the same fields the
  // listener's refusal names so a single audit query answers for both.
  // The replay record, keyed per credential.
  //
  // It is blamepost's own rather than `b.middleware.idempotencyKey`.
  // That middleware exposes `memoryStore` on the surface `b` publishes
  // and keeps its database-backed store behind an underscore-prefixed
  // member, which is not a surface this repository composes against, so
  // the only store reachable through it is the one that forgets
  // everything on a restart. What a forgotten record costs here is a
  // duplicate mail to a real person, which is why the record is written
  // rather than borrowed.
  //
  // The key is the credential's identifier and the client's key together.
  // Two applications on one server pick their own keys and would
  // otherwise collide on any value they both happen to choose, and a
  // collision here answers one application's request with another's
  // reply.
  //
  // The fingerprint is over the body as it arrived. A key reused for a
  // DIFFERENT message is a client bug that a stored answer would hide:
  // replaying the first reply would report a send of the second message
  // that never happened, so it is refused instead.
  //
  // A record is reserved before the message is composed and settled when
  // an answer exists, and the reservation is what a second request
  // arriving while the first is still in flight collides with. Every
  // refusal decided BEFORE the composer releases the reservation, because
  // nothing was sent and a client that fixes its request should be able
  // to keep its key; everything from the composer onwards settles,
  // because by then a message may have left.
  //
  // This record lives in this process, so it does not survive a restart.
  // Closing that needs a table on the data volume, which is the store's
  // to own rather than this file's.
  var sendReplays = new Map();

  function _replayRecordKey(credentialId, key) {
    return credentialId + REPLAY_KEY_SEPARATOR + key;
  }

  // Expired records first, then the oldest settled ones, until the map
  // is inside its bound. A Map hands its keys back in insertion order,
  // so the oldest record is the first one it names. A record whose send
  // is still running is never evicted: a retry under its key would then
  // reserve again and send the message twice, and the first request's
  // settle or release would land on the second's record. When every
  // record left is in flight the map stays full, and the caller refuses
  // the new reservation.
  //
  // It runs only when the bound is reached rather than on every
  // reservation. A record past its window is never an answer either way,
  // because the lookup checks the window before it reads one, so sweeping
  // early buys nothing and costs a walk of the whole map per message.
  function _sweepReplays(at) {
    if (sendReplays.size < SEND_REPLAY_MAX_RECORDS) return;
    var expired = [];
    sendReplays.forEach(function (record, key) {
      if (record.expiresAt <= at) expired.push(key);
    });
    for (var i = 0; i < expired.length; i += 1) sendReplays.delete(expired[i]);
    if (sendReplays.size < SEND_REPLAY_MAX_RECORDS) return;
    var settled = [];
    var excess = sendReplays.size - SEND_REPLAY_MAX_RECORDS + 1;
    sendReplays.forEach(function (record, key) {
      if (settled.length < excess && record.answer !== null) settled.push(key);
    });
    for (var s = 0; s < settled.length; s += 1) sendReplays.delete(settled[s]);
  }

  // Reserve a key, or say what the one already there is.
  //
  // The read and the write happen with nothing awaited between them, so
  // two requests arriving together cannot both reserve: the second sees
  // the first's record and collides with it.
  function _reserveReplay(recordKey, fingerprint) {
    var at = Date.now();
    var held = sendReplays.get(recordKey);
    if (held !== undefined && held.expiresAt <= at) {
      sendReplays.delete(recordKey);
      held = undefined;
    }
    if (held !== undefined) {
      if (held.fingerprint !== fingerprint) return { state: "mismatch" };
      return held.answer === null
        ? { state: "in-flight" }
        : { state: "settled", answer: held.answer };
    }
    _sweepReplays(at);
    if (sendReplays.size >= SEND_REPLAY_MAX_RECORDS) return { state: "full" };
    sendReplays.set(recordKey, {
      fingerprint: fingerprint,
      answer:      null,
      expiresAt:   at + SEND_REPLAY_TTL_MS,
    });
    return { state: "reserved" };
  }

  function _settleReplay(recordKey, answer) {
    var held = sendReplays.get(recordKey);
    if (held === undefined) return;
    held.answer = answer;
  }

  function _releaseReplay(recordKey) {
    sendReplays.delete(recordKey);
  }

  // One answer, written the same way whether this request produced it or
  // a record replayed it. A stored answer is the fields rather than the
  // bytes, and both paths run them through the same writer, so a replay
  // reproduces exactly what the first request sent.
  function _writeSendAnswer(res, answer) {
    if (answer.problem !== undefined) {
      _sendProblem(res, answer.problem);
      return;
    }
    b.render.json(res, answer.json, { status: answer.status });
  }

  function _refuseSendEnvelope(scope, rejected) {
    b.audit.safeEmit({
      action:   "blamepost.web.api_send_envelope_not_permitted",
      outcome:  "denied",
      actor:    { userId: scope.id },
      metadata: {
        credentialId:      scope.id,
        scopeDomain:       scope.domain,
        identityKind:      "sending-credential",
        rejected:          _echoAuthor(rejected),
        refusedLocalParts: scope.refusedLocalParts.slice(),
      },
    });
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
      inboxHref:   account ? _href(_inboxPath(account)) : "",
      // Where a form post that changes a preference sends the reader
      // back to. The path is read through the same helper the route
      // reads the field back with: this is the one place a path arrives
      // off a request rather than being built here, and a request line
      // may open `//host` or `/\host`, both of which a browser follows
      // off site.
      //
      // The folder is carried too, because it is what says which page
      // this is. It is REBUILT rather than reflected: the name is taken
      // back through the same reader every mail route reads it with and
      // encoded again here, so no value a request wrote reaches this
      // attribute as it arrived. A path-only answer sends a reader who
      // is in a folder back to the inbox, and on a page that needs the
      // folder to resolve at all it lands them on a refusal.
      backPath:    _backPath(req),
    };
    if (extra) {
      var keys = Object.keys(extra);
      for (var i = 0; i < keys.length; i += 1) view[keys[i]] = extra[keys[i]];
    }
    return view;
  }

  // The options every page is rendered with, and the one place its
  // `Cache-Control` is decided. `_page`, `_publicPage` and `_fail` all
  // render through this, and so does the text the JMAP WebSocket path
  // answers a request that carries no upgrade. Every option the caller
  // passes is kept, its `headers` included, and `Cache-Control` is set
  // here over any value those headers carry.
  //
  // A public page served to a reader with no session gets
  // `private, max-age=900`. The public pages are the front page and every
  // page of the reference wiki. Each renders the reader's own CSRF token in
  // the theme form, and the first visit sets the matching `csrf` cookie,
  // so `private` keeps a shared cache from storing the page and handing
  // that token and cookie to a later reader. The reader's own browser may
  // keep the page for 900 seconds. The `Vary: Cookie` the request chain
  // put on the response stays, so the browser keeps this copy apart from
  // the one it is served after signing in.
  //
  // Every other page gets `private, no-store`: every page served to a
  // signed-in reader, a public page included, and the sign-in and error
  // pages served to a reader with no session. Under RFC 9111 section
  // 5.2.2.5 no cache keeps a copy of that response, so a mailbox, a message
  // or a console page is not left in the browser's disk cache after the
  // reader signs out, and under section 5.2.2.7 a shared cache refuses it.
  // The `noCache` middleware on the request chain writes the same value
  // from the same constant, and `b.render` writes its own default,
  // `private, no-cache, must-revalidate`, over that header unless the
  // render names one, so the render names it here.
  //
  // `b.render` keeps a `no-store` already on the response over any value
  // the render names, so a public page served to a reader with no session
  // removes the middleware's `Cache-Control` and `Pragma` before it
  // renders. Its `Vary` stays.
  function _renderOpts(req, renderOpts, publicPage) {
    var out = Object.assign({}, renderOpts);
    out.headers = Object.assign({}, out.headers, {
      "Cache-Control": publicPage && !req.user ? PUBLIC_PAGE_CACHE_CONTROL : PAGE_CACHE_CONTROL,
    });
    return out;
  }

  function _page(req, res, viewName, data, renderOpts) {
    renderer.html(res, viewName, _scope(req, data), _renderOpts(req, renderOpts, false));
  }

  // A public page: the front page, or a page of the reference wiki.
  function _publicPage(req, res, viewName, data) {
    if (!req.user) {
      res.removeHeader("Cache-Control");
      res.removeHeader("Pragma");
    }
    renderer.html(res, viewName, _scope(req, data), _renderOpts(req, undefined, true));
  }

  function _fail(req, res, status, headline, detail) {
    renderer.html(res, "error", _scope(req, {
      status: status, headline: headline, detail: detail,
    }), _renderOpts(req, { status: status }, false));
  }

  // The only refusal the route that serves a file answers with.
  //
  // It takes no argument, which is the point rather than a convenience.
  // Every way that route can fail produces this call, so the answers
  // cannot drift apart into an oracle: a folder another account holds, an
  // identifier nothing holds, a part number nothing holds, a number that
  // is not one, a message above the octet read bound and a request for
  // the message's own text body are one response, byte for byte.
  //
  // Nothing the request carried is echoed into it. A detail naming the
  // folder or the identifier would put the asked-for value in the body,
  // and two refusals that differ only by that value are still two
  // refusals a caller can tell apart.
  function _failPart(req, res) {
    _fail(req, res, 404, "No such file",
      "That message carries no file this server serves under that name.");
  }

  function _back(res, path, notice) {
    res.redirect(_path(notice ? _withQuery(path, "notice=" + notice) : path));
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
      return _faultForDisplay(err);
    }
    log.error("administration action failed: " + _faultForDisplay(err));
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
    // Carried beside the list for the state string, which has to move
    // when a mailbox is created, renamed or deleted.
    mine.namespaceRevision = typeof mailbox.namespaceRevision === "function"
      ? mailbox.namespaceRevision({ id: account.id }) : 0;
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
  // Every path a redirect carries, and every path a page link is built
  // from, comes from one of the four below, so `_path` sees each of them
  // once rather than the invariant being restated at every concatenation.
  // A page passes the path to `_href` before a template reads it.
  //
  // HOW A FOLDER IS NAMED IN A URL. As a query parameter, and only
  // through `_folderQuery`, so the rail, the message list, the
  // breadcrumb, the bulk form, the file link, the composer and every
  // redirect after an action all spell it one way.
  //
  // A mailbox name separates its levels with `mailbox.HIERARCHY_DELIMITER`
  // and admits a backslash inside a level, so `Clients/Acme` and
  // `Backups\2026` are both names an account holder's client can make.
  // Percent-encoded into a path segment, each becomes an escape the
  // framework answers 400 for before any route runs, because a gate
  // matching the path and a consumer decoding it would disagree about
  // where the request points. A query value is read after that decision
  // and is never split into segments, so it carries every name the store
  // admits and the refusal on the path stays exactly as it is.
  function _folderQuery(folder) {
    return "folder=" + encodeURIComponent(folder.name);
  }

  // The page a preference form comes back to: this request's own path,
  // resolved against this origin, carrying the folder it was reading when
  // there was one. The name goes back through `_folderName`, which is the
  // reader every mail route screens it with, so what lands in the attribute
  // is a bounded name this server re-encoded rather than the bytes a
  // request sent.
  function _backPath(req) {
    var path = b.safeRedirect.resolve(req.pathname, { fallback: "/" });
    var name = _folderName(_queryOf(req).folder);
    return name.length === 0 ? path : _withQuery(path, "folder=" + encodeURIComponent(name));
  }

  // One more name-and-value pair on a target that may already carry some.
  function _withQuery(path, pair) {
    return path + (path.indexOf("?") === -1 ? "?" : "&") + pair;
  }

  function _folderPath(folder) {
    return _path(_withQuery(MAIL_PATH, _folderQuery(folder)));
  }

  function _actionPath(folder) {
    return _path(_withQuery(MAIL_PATH + "/actions", _folderQuery(folder)));
  }

  function _messagePath(folder, objectId) {
    return _path(_withQuery(MAIL_PATH + "/" + encodeURIComponent(objectId),
      _folderQuery(folder)));
  }

  // Where one file on one message is fetched from. Under the message's own
  // path, because that is what the route resolves: the folder is matched
  // against this account's folders and the identifier against that
  // folder's members, so a part is reachable exactly where the message
  // carrying it is.
  function _partPath(folder, objectId, partId) {
    return _path(_withQuery(MAIL_PATH + "/" + encodeURIComponent(objectId) +
      "/parts/" + encodeURIComponent(partId), _folderQuery(folder)));
  }

  function _composePath(folder, objectId, mode) {
    return _path("/compose?source=" + encodeURIComponent(objectId) +
      "&" + _folderQuery(folder) +
      "&mode=" + encodeURIComponent(mode));
  }

  function _inboxPathFrom(folders) {
    var inbox = _findRole(folders, INBOX_ROLE);
    if (inbox) return _folderPath(inbox);
    if (folders.length > 0) return _folderPath(folders[0]);
    return _path(_withQuery(MAIL_PATH, "folder=" + encodeURIComponent(DEFAULT_FOLDER)));
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
  //
  // The cursor is `{ modseq, objectid }`, the last row of the page above,
  // or null for the newest page. Several rows can share one mod-sequence,
  // since one STORE over many messages gives them all the same number, so
  // rows are ordered by mod-sequence and then object id, and a page
  // starts below the cursor row in that order. A cursor with no object id
  // starts below every row at its mod-sequence.
  async function _pageBefore(account, folder, before, filter) {
    var actor = _actorFor(account);
    // A cursor above everything the folder holds is not a cursor into
    // it, so it reads as the newest page. Left as sent it would also be
    // a way to ask for the walk below on a folder that does not need
    // one, which is a handful of reads a request should not be able to
    // order up.
    var top = folder.modseqMax + 1;
    var inside = before !== null && typeof before === "object" &&
      before.modseq > 0 && before.modseq < top;
    var ceiling = inside ? before.modseq : top;
    var ceilingId = inside && typeof before.objectid === "string" ? before.objectid : null;

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
    // A row read twice, which the upward walk below does at a window
    // boundary, is kept once.
    function _keep(rows) {
      var ordered = rows.slice().sort(_rowOrder);
      var out = [];
      var taken = Object.create(null);
      for (var i = ordered.length - 1; i >= 0 && out.length < PAGE_SIZE + 1; i -= 1) {
        var row = ordered[i];
        if (row.modseq > ceiling) continue;
        if (row.modseq === ceiling && (ceilingId === null || row.objectid >= ceilingId)) continue;
        if (taken[row.objectid] === true) continue;
        taken[row.objectid] = true;
        out.push(row);
      }
      return out;
    }

    // Downward from the cursor, in segments read whole. `floor` is the
    // bottom of what has been read: every row with a mod-sequence above
    // it and at or below the cursor is in `collected`. A folder whose
    // numbers run without a gap fills a page on the first read.
    //
    // A read is capped and runs upward from its floor, so one that comes
    // back full without reaching the bottom of what has been read has
    // left rows out of the middle of its range. That happens where many
    // rows share a mod-sequence, as one STORE over many messages leaves
    // them. The read is taken again over a narrower span rather than
    // used, because a page built from it would skip the rows it left out.
    var kept = [];
    var collected = [];
    var floor = ceiling;
    var span = FIRST_PAGE_SPAN;
    var narrowings = 0;
    for (var probe = 0; probe < MAX_PAGE_PROBES + MAX_SPAN_NARROWINGS; probe += 1) {
      var from = floor - span > 0 ? floor - span : 0;
      var rows = await _window(from);
      var highest = 0;
      for (var h = 0; h < rows.length; h += 1) {
        if (rows[h].modseq > highest) highest = rows[h].modseq;
      }
      if (rows.length >= WINDOW_CAP && highest <= floor) {
        if (span === 1 || narrowings >= MAX_SPAN_NARROWINGS) break;
        span = Math.max(1, Math.floor(span / 4));
        narrowings += 1;
        continue;
      }
      for (var c = 0; c < rows.length; c += 1) {
        if (rows[c].modseq > from && rows[c].modseq <= floor) collected.push(rows[c]);
      }
      floor = from;
      kept = _keep(collected);
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
        // The next read starts below the last mod-sequence this one
        // reached, so rows sharing it that the read's cap cut off are
        // read rather than skipped. `_keep` drops the ones read twice.
        var last = window[window.length - 1].modseq;
        floor = window[0].modseq < last ? last - 1 : last;
      }
    }

    var hasOlder = kept.length > PAGE_SIZE;
    if (hasOlder) kept = kept.slice(0, PAGE_SIZE);
    return {
      rows:      kept,
      hasOlder:  hasOlder || floor > 0,
      olderThan: kept.length > 0
        ? { modseq: kept[kept.length - 1].modseq, objectid: kept[kept.length - 1].objectid }
        : null,
    };
  }

  // Rows in mod-sequence order, and object id order among rows sharing
  // a mod-sequence, so a page boundary inside such a run has one place.
  function _rowOrder(a, c) {
    if (a.modseq !== c.modseq) return a.modseq - c.modseq;
    if (a.objectid === c.objectid) return 0;
    return a.objectid < c.objectid ? -1 : 1;
  }

  // The `before` query value of a folder page: `<modseq>` or
  // `<modseq>.<objectid>`. Garbage reads as no cursor, which is the
  // newest page.
  function _cursorFrom(value) {
    var text = typeof value === "string" ? value : "";
    var dot = text.indexOf(".");
    var modseq = _int(dot === -1 ? text : text.slice(0, dot), 0, 0, Number.MAX_SAFE_INTEGER);
    if (modseq === 0) return null;
    var objectid = dot === -1 ? "" : text.slice(dot + 1);
    return { modseq: modseq, objectid: objectid.length > 0 ? objectid : null };
  }

  function _cursorText(cursor) {
    return cursor.objectid === null ? String(cursor.modseq)
      : cursor.modseq + "." + cursor.objectid;
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
      var files = attachmentMark(flags);
      out.push({
        objectId:  message.objectid,
        subject:   _headerText(_str(message.subject, "(no subject)")),
        from:      _displayName(message.from),
        fromAddr:  _shownAddress(message.from),
        initial:   _initial(message.from),
        // The preview is a column, not the message. Every other value on
        // this row is screened and this one is read on the same line by
        // the same person, so an override in the opening words reorders
        // the row rather than a paragraph somebody chose to open. The
        // body itself is rendered unscreened on the conversation page,
        // which is where the zero-width joiner in an emoji sequence and
        // the separator in a Devanagari conjunct have to survive.
        preview:   _headerText(_preview(message.bodyText, 140)),
        received:  _when(message.internalDate || message.receivedAt,
          { dateStyle: "medium", timeStyle: "short" }),
        sizeLabel: _byteSize(message.sizeBytes),
        unread:    flags.indexOf("\\Seen") === -1,
        flagged:   flags.indexOf("\\Flagged") !== -1,
        answered:  flags.indexOf("\\Answered") !== -1,
        deleted:   flags.indexOf("\\Deleted") !== -1,
        legalHold: message.legalHold === true,
        // Two marks rather than one, because there are three answers.
        // The row says the message carries files, or says the answer is
        // unknown, or says neither. A page with one mark would show a
        // message this server never opened exactly as it shows a message
        // that is genuinely bare, which is the reading that hides a file.
        carriesFiles: files === "present",
        filesUnknown: files === "unknown",
        href:      _href(_messagePath(folder, message.objectid)),
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
    // `referrerPolicy` is named rather than left at the framework's
    // default of `no-referrer`, which erases the origin the cross-check
    // further down this same chain reads. REFERRER_POLICY carries the
    // reason.
    // `protocolResolver` on both of the middleware that read the
    // transport, so the HSTS decision and the cookie and origin
    // decisions come from the reading built above rather than from this
    // process's own socket. See `transport`.
    router.use(b.middleware.securityHeaders({
      referrerPolicy:   REFERRER_POLICY,
      protocolResolver: transport.resolve,
    }));
    router.use(b.middleware.botGuard());
    router.use(b.middleware.cookies());
    router.use(b.middleware.cspNonce({ directives: ["script-src", "style-src"] }));
    router.use(b.middleware.fetchMetadata());
    router.use(b.middleware.bodyParser({ json: { limit: JSON_BODY_MAX_BYTES } }));
    router.use(b.middleware.csrfProtect({
      cookie:           true,
      checkOrigin:      true,
      skipStateless:    true,
      protocolResolver: transport.resolve,
    }));
    router.use(b.middleware.attachUser({
      cookieName: SESSION_COOKIE,
      tokenFrom:  "both",
      userLoader: _loadAccount,
    }));
    // A token presented over a connection that cannot carry one.
    //
    // Minting a session and presenting one are the two credential paths,
    // and a gate on the first alone leaves a token copied from anywhere
    // else authenticating over the cleartext port, whether it arrives in
    // the cookie or in the `Authorization` header the reader above also
    // accepts. The request is answered as though it carried no session,
    // and the gate that turns it away sends the reader to `/sign-in`,
    // which says what the transport was.
    //
    // The session row is not destroyed. This refuses a request; it does
    // not end a session, so a stranger sending a copied token to the
    // wrong port cannot sign the account out by trying.
    router.use(function (req, res, next) {
      if (!_transportCarriesCredentials(req)) req.user = null;
      next();
    });
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
    // The public documents that are the same for every reader are the
    // only paths added beside the asset mount: the crawler documents, the
    // MTA-STS policy and the badge. Each states its own public directive,
    // and `b.render` would keep a `no-store` set here over it. The front
    // page is NOT one
    // of them, and leaving it here is the decision rather than an
    // oversight: it answers a signed-in reader with a redirect into their
    // own mailbox and a stranger with the public page, so it varies by
    // cookie. The `Vary: Cookie, Authorization` this sets is what keeps a
    // shared cache from handing one reader's redirect to another, and the
    // branch that renders the public page overrides the directive on its
    // own response rather than here.
    router.use(b.middleware.noCache({
      cacheControl: PAGE_CACHE_CONTROL,
      when: function (req) {
        if (req.pathname.indexOf("/static/") === 0) return false;
        if (req.pathname === "/robots.txt" || req.pathname === "/sitemap.xml") return false;
        if (req.pathname === "/.well-known/mta-sts.txt" || req.pathname === "/badge.svg") {
          return false;
        }
        return true;
      },
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
      return { ok: false, read: false, error: _faultForDisplay(err) };
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
      return { ok: false, read: false, error: _faultForDisplay(err) };
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

  // Registered per probe rather than across both, because the verdict is
  // the same on each and only what should be done about it differs.
  health.registerCheck("listeners", _listenersBound,
    { tier: "readiness", critical: true });
  health.registerCheck("listeners", _listenersBound,
    { tier: "liveness", critical: false });
  health.registerCheck("listeners-withheld", _listenersWithheld,
    { tier: ["liveness", "readiness"], critical: false });
  health.registerCheck("certificate", _certificate,
    { tier: ["liveness", "readiness"], critical: false });
  // Never critical, on either probe, and each probe says no for its own
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
  //
  // The namespace revision is added to the total. A mailbox created,
  // renamed or deleted changes what Mailbox/get answers without moving
  // any folder counter, and a deleted mailbox takes its counter out of
  // the sum; the revision rises by that counter plus one when it does.
  function _accountState(folders) {
    var total = typeof folders.namespaceRevision === "number" ? folders.namespaceRevision : 0;
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
  // The account a push subscription watches comes off the authenticated
  // actor and never off the frame the client sent. `dataTypes` is the
  // only thing a client chooses here, and all it can do is narrow what
  // it is told about its own mailbox.
  //
  // The state a push subscription reports is `_accountState`, the same
  // string every JMAP answer carries, because a push carrying a value
  // the API does not agree with is a notification a client cannot act
  // on: it refetches, reads a different state, and concludes nothing
  // changed.
  // -------------------------------------------------------------------

  var pushWatchers = new Map();
  var pushSweeper  = null;

  // The account's current state, or null when it cannot be read. The
  // adapter refuses a folder list for an account that no longer exists,
  // and a push subscription outliving its account is a channel with nothing
  // left to say rather than an error to raise at a client that has
  // already lost its session.
  function _pushStateOf(accountId) {
    try { return _accountState(_foldersFor({ id: accountId })); }
    catch (_e) { return null; }
  }

  // The event a push subscription is sent, or null when the types it asked
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
            _faultForDisplay(err));
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
        log.error("the JMAP push sweep threw: " + _faultForDisplay(err));
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
      // Seeded with the state as it stands, so a push subscription reports
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

  // The level above one mailbox name, or null when the name is at the top
  // of the hierarchy.
  function _parentOf(wireName) {
    var above = superiorLevels(wireName);
    return above.length === 0 ? null : above[above.length - 1];
  }

  // The last level of a name, which is what RFC 8621 section 2 calls the
  // mailbox's name: that section says it MUST NOT contain the name of the
  // parent, and a client renders it under the parent it resolved from
  // `parentId`. The id keeps the whole path, because that is what every
  // other verb here addresses a folder by.
  function _leafOf(wireName, parent) {
    if (parent === null) return wireName;
    return wireName.slice(parent.length + HIERARCHY_DELIMITER.length);
  }

  function _jmapMailbox(folder) {
    var parent = _parentOf(folder.name);
    return {
      id:        folder.name,
      name:      parent === null ? folder.label : _leafOf(folder.name, parent),
      role:      folder.role || null,
      parentId:  parent,
      sortOrder: folder.rank,
      myRights: {
        mayReadItems: true, mayAddItems: true, mayRemoveItems: true,
        maySetSeen: true, maySetKeywords: true, mayCreateChild: false,
        mayRename: false, mayDelete: false, maySubmit: true,
      },
    };
  }

  // A level a name carries that no folder of this account answers to.
  //
  // RFC 9051 section 6.3.5 removes only the name DELETE was given, so an
  // account can hold `Clients/Acme/2026` with nothing named
  // `Clients/Acme`, and the IMAP listing keeps that level reachable as
  // `\NonExistent \HasChildren`. RFC 8621 has no such attribute, and a
  // `parentId` the answer does not carry is a reference the client cannot
  // resolve: it drops the mailbox under it, and mail the owner still has
  // leaves the tree they are shown.
  //
  // So the level is answered, and every right on it is false. It holds no
  // message, nothing may be filed into it, and `Email/query` naming it
  // matches nothing, which is what the rights say out of the answer
  // itself rather than leaving a client to try.
  function _jmapDerivedMailbox(wireName) {
    var parent = _parentOf(wireName);
    return {
      id:        wireName,
      name:      _leafOf(wireName, parent),
      role:      null,
      parentId:  parent,
      sortOrder: _folderRank(""),
      myRights: {
        mayReadItems: false, mayAddItems: false, mayRemoveItems: false,
        maySetSeen: false, maySetKeywords: false, mayCreateChild: false,
        mayRename: false, mayDelete: false, maySubmit: false,
      },
    };
  }

  // One account's mailboxes as a JMAP client reads them: the folders it
  // holds, and the levels above those that no folder answers to. Every
  // `parentId` in the answer names something else in the answer, which is
  // what a client needs to draw the tree at all.
  function _jmapMailboxes(folders) {
    var out = [];
    var placed = Object.create(null);
    for (var i = 0; i < folders.length; i += 1) {
      out.push(_jmapMailbox(folders[i]));
      placed[folders[i].name] = true;
    }
    for (var f = 0; f < folders.length; f += 1) {
      var above = superiorLevels(folders[f].name);
      for (var a = 0; a < above.length; a += 1) {
        if (placed[above[a]] === true) continue;
        placed[above[a]] = true;
        out.push(_jmapDerivedMailbox(above[a]));
      }
    }
    return out;
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
    // The two marks recording whether the message carries files. This
    // server reads those off the message when it files it and nothing
    // recomputes them afterwards, so a client that could write one could
    // make `hasAttachment` say whatever it liked about mail it did not
    // send. RFC 8621 section 4.1.4 makes that property the server's to
    // set, and this is the write that would take it away.
    if (isAttachmentKeyword(keyword)) return null;
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
      // The marks recording whether the message carries files stay out of
      // the map. JMAP has its own property for that question, and a
      // client reading the answer in two places is a client that can
      // write one of them back: the whole-keyword-set form replaces what
      // it is given, so a keyword served here and refused on the way in
      // is a set no client can send back unchanged.
      if (isAttachmentKeyword(flag)) continue;
      if (flag.charAt(0) === "\\") continue;
      keywords[flag] = true;
    }
    return keywords;
  }

  function _jmapEmail(folderName, message, attachments) {
    var flags = Array.isArray(message.flags) ? message.flags : [];
    var keywords = _keywordsOf(flags);
    var mailboxIds = Object.create(null);
    mailboxIds[folderName] = true;
    var email = {
      id:         message.objectid,
      blobId:     message.objectid,
      threadId:   message.threadRootId,
      mailboxIds: mailboxIds,
      keywords:   keywords,
      size:       message.sizeBytes,
      receivedAt: new Date(message.receivedAt || message.internalDate || 0).toISOString(),
      messageId:  message.messageId ? [message.messageId] : null,
      inReplyTo:  message.inReplyTo ? [message.inReplyTo] : null,
      // RFC 8621 section 4.1.4 reports the References header as the
      // message carried it. The list is read rather than rebuilt and
      // then cut back: a message with no Message-ID of its own has
      // nothing appended to cut off again, so cutting one dropped a
      // real ancestor and reported the chain one id short.
      references: _referenceList(message),
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
      // RFC 8621 section 4.1.4 makes this true when the message has parts
      // a client should offer as downloadable. It is read off the mark
      // the mail layer wrote when the message was filed, rather than
      // derived here: this method takes a set of identifiers the client
      // chose, so a derivation per identifier would let one request order
      // a stored-body read and a structure parse per message it named,
      // and the octets have to be read whatever the parse costs.
      //
      // A message this server did not open holds neither mark, and the
      // answer for it is true. The same section lets a server decide this
      // by its own reading, and of the two answers available to a boolean
      // that is the one that does not hide a file: a message is unopened
      // here because it is above the octet read bound, which is where the
      // mail carrying files lives.
      hasAttachment: attachmentMark(flags) !== ATTACHMENT_ABSENT,
    };
    // The list of parts under that boolean, when the caller derived one.
    // It is attached rather than declared above, because a property this
    // server will not answer for a message is left out of the object
    // rather than answered null: RFC 8621 section 4.1.4 types it as a
    // list, and a client reading `.length` off a null is a client this
    // server broke to say nothing.
    if (attachments !== null) email.attachments = attachments;
    return email;
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

  // One message's octets, read under this account's own scope, or null.
  //
  // `readMessageSource` resolves the folder against the acting account
  // first and decides membership inside it, so an identifier another
  // account holds answers `null` here exactly as one nothing holds does.
  // It is also the read this surface already derives a reply and a
  // forward from, so the files listed on a page, the octets a forward
  // carries and the parts a JMAP client is told about come from one
  // reader rather than several that could disagree about which message is
  // which.
  function _octetsOf(actor, folder, objectId) {
    var source;
    try {
      source = mailbox.readMessageSource(actor, folder.name, objectId);
    } catch (_unreadable) {
      // Drop-silent by design: the adapter refuses a message whose
      // header block does not parse, and the caller's answer for a
      // message it cannot open is the same either way.
      return null;
    }
    if (!source) return null;
    if (source.withheld !== null || source.bytes === null) {
      return { bytes: null, withheld: source.withheld || "message-too-large" };
    }
    return { bytes: source.bytes, withheld: null };
  }

  // Every part of one message this server counts as a file, with the
  // reason there are none when there are none.
  //
  // ONE READING OF WHAT A FILE IS. `leafParts` walks the structure and
  // `isFile` decides, and that pair is what the mark written when a
  // message is filed counts, what the conversation page lists, what the
  // browser part route serves, what a blob id can reach and what
  // `Email/get` names in `attachments`. A second reading anywhere in that
  // set would show a reader a file on the page and tell their client the
  // message is bare.
  //
  // THE THREE EMPTY ANSWERS. `absent` is an identifier this account does
  // not hold, `unopened` is a message above the octet read bound and
  // `unparsed` is a structure that did not parse. None of the three is a
  // message that carries no file, and a caller that collapsed them would
  // report an empty list for a message whose files it did not look at.
  function _fileLeaves(actor, folder, objectId) {
    var octets = _octetsOf(actor, folder, objectId);
    if (octets === null) return { leaves: [], reason: "absent" };
    if (octets.bytes === null) return { leaves: [], reason: "unopened" };
    var leaves;
    try {
      leaves = leafParts(octets.bytes);
    } catch (_unparsed) {
      // Drop-silent by design: the parse refusal names a cap or a
      // malformed boundary, and every caller's answer for a message it
      // could not read is the reason rather than the refusal's words.
      return { leaves: [], reason: "unparsed" };
    }
    var files = [];
    for (var i = 0; i < leaves.length; i += 1) {
      if (leaves[i].isFile) files.push(leaves[i]);
    }
    return { leaves: files, reason: "" };
  }

  // The `attachments` of RFC 8621 section 4.1.4 for one message, or null
  // when this server will not answer for it.
  //
  // THE MARK DECIDES WHETHER ANYTHING IS READ. `hasAttachment` on the
  // same object is read off the mark the mail layer wrote when the
  // message was filed, and that mark records the same `isFile` count this
  // list would produce. So a message marked as carrying none answers the
  // empty list without opening anything, and a message this server never
  // opened answers null without opening anything now. Deriving the list
  // independently would cost a stored-body read and a structure parse per
  // identifier whatever the mark said, and it would let the two
  // properties disagree: a non-empty list beside `hasAttachment: false`
  // is one answer contradicting the other on the same object.
  //
  // NULL IS NOT THE EMPTY LIST. A message above the octet read bound
  // carries `hasAttachment: true`, because a boolean that hid a file is
  // the worse of the two answers available. An empty list beside that is
  // a client told there are files and handed none. The property is left
  // out instead, which a client that asked for it can see.
  function _attachmentsOf(actor, folder, message) {
    var mark = attachmentMark(Array.isArray(message.flags) ? message.flags : []);
    if (mark === ATTACHMENT_ABSENT) return [];
    if (mark !== ATTACHMENT_PRESENT) return null;
    var files = _fileLeaves(actor, folder, message.objectid);
    if (files.reason !== "") return null;
    return files.leaves.map(function (leaf) {
      return _bodyPart(message.objectid, leaf);
    });
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
        // A mark recording whether the message carries files is not one
        // of the client's keywords: it is absent from the map this
        // answers with, and a patch naming one is refused. So a
        // replacement cannot have asked for it and must not take it off.
        // Removing it would turn `hasAttachment` false on a message
        // nobody touched, and nothing recomputes it afterwards.
        if (isAttachmentKeyword(heldFlag)) continue;
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

  // A method-level error, in the shape the framework dispatcher emits as
  // `["error", { type, description }, callId]`.
  function _jmapError(type, description) {
    return { type: JMAP_ERROR_PREFIX + type, description: description };
  }

  // The refusal for a call with no `accountId`, or null. The dispatcher
  // refuses an `accountId` the actor does not hold before a handler runs,
  // and lets a call that names none through.
  function _jmapAccountArgRefusal(args) {
    if (typeof args.accountId === "string" && args.accountId.length > 0) return null;
    return _jmapError("invalidArguments", "accountId is required.");
  }

  // The refusal for a `/get` call's `ids` and `properties`, or null.
  // `ids` is null, absent, or a list of at most JMAP_MAX_OBJECTS_IN_GET
  // strings; `properties` is null, absent, or a list of property names
  // (RFC 8620 section 5.1).
  //
  // The shape is refused rather than repaired, because a client that sent
  // `properties` as a string asked for something, and reading past it
  // answers a question it did not ask with an object it did not want.
  // Which names are in the list is a separate question each method
  // answers for itself: a name this server does not answer for costs the
  // client that property and nothing else, and refusing the whole call
  // over one would refuse a conforming client asking for a property RFC
  // 8621 defines and this server has not built.
  function _jmapGetRefusal(args) {
    var noAccount = _jmapAccountArgRefusal(args);
    if (noAccount !== null) return noAccount;
    if (args.properties !== undefined && args.properties !== null) {
      if (!Array.isArray(args.properties)) {
        return _jmapError("invalidArguments",
          "properties must be null or a list of property names.");
      }
      for (var p = 0; p < args.properties.length; p += 1) {
        if (typeof args.properties[p] !== "string") {
          return _jmapError("invalidArguments",
            "properties[" + p + "] is not a property name.");
        }
      }
    }
    if (args.ids === undefined || args.ids === null) return null;
    if (!Array.isArray(args.ids)) {
      return _jmapError("invalidArguments", "ids must be null or a list of ids.");
    }
    if (args.ids.length > JMAP_MAX_OBJECTS_IN_GET) {
      return _jmapError("requestTooLarge", "ids names " + args.ids.length +
        " objects and maxObjectsInGet is " + JMAP_MAX_OBJECTS_IN_GET + ".");
    }
    for (var i = 0; i < args.ids.length; i += 1) {
      if (typeof args.ids[i] !== "string") {
        return _jmapError("invalidArguments", "ids[" + i + "] is not an id.");
      }
    }
    return null;
  }

  // The refusal for a `/set` call's `create`, `update` and `destroy`, or
  // null. `create` and `update` are null, absent or an object;
  // `destroy` is null, absent or a list of strings; together they name at
  // most JMAP_MAX_OBJECTS_IN_SET objects (RFC 8620 section 5.3).
  function _jmapSetRefusal(args) {
    var noAccount = _jmapAccountArgRefusal(args);
    if (noAccount !== null) return noAccount;
    var total = 0;
    var maps = ["create", "update"];
    for (var m = 0; m < maps.length; m += 1) {
      var map = args[maps[m]];
      if (map === undefined || map === null) continue;
      if (typeof map !== "object" || Array.isArray(map)) {
        return _jmapError("invalidArguments", maps[m] + " must be null or an object.");
      }
      total += Object.keys(map).length;
    }
    if (args.destroy !== undefined && args.destroy !== null) {
      if (!Array.isArray(args.destroy)) {
        return _jmapError("invalidArguments", "destroy must be null or a list of ids.");
      }
      total += args.destroy.length;
    }
    if (total > JMAP_MAX_OBJECTS_IN_SET) {
      return _jmapError("requestTooLarge", "create, update and destroy name " + total +
        " objects and maxObjectsInSet is " + JMAP_MAX_OBJECTS_IN_SET + ".");
    }
    var destroyed = Array.isArray(args.destroy) ? args.destroy : [];
    for (var d = 0; d < destroyed.length; d += 1) {
      if (typeof destroyed[d] !== "string") {
        return _jmapError("invalidArguments", "destroy[" + d + "] is not an id.");
      }
    }
    return null;
  }

  // The refusal for an `Email/query` call's arguments, or null.
  //
  // RFC 8620 section 5.5 gives a query four arguments this server has to
  // answer for and names the refusal for each: `sort` is answered
  // `unsupportedSort`, a `filter` this server cannot process is answered
  // `unsupportedFilter`, and an `anchor` it cannot place is answered
  // `anchorNotFound`. All three are refusals rather than omissions
  // because each of them changes which messages match: a client asking
  // for flagged mail and given every message has been answered with mail
  // it did not ask for, and nothing in the answer says the condition
  // went unread.
  function _jmapQueryRefusal(args) {
    var noAccount = _jmapAccountArgRefusal(args);
    if (noAccount !== null) return noAccount;

    if (args.position !== undefined && args.position !== null &&
        !Number.isInteger(args.position)) {
      return _jmapError("invalidArguments", "position must be null or a whole number.");
    }
    if (args.limit !== undefined && args.limit !== null &&
        (!Number.isInteger(args.limit) || args.limit < 0)) {
      return _jmapError("invalidArguments", "limit must be null or a whole number of zero or more.");
    }
    if (args.calculateTotal !== undefined && args.calculateTotal !== null &&
        typeof args.calculateTotal !== "boolean") {
      return _jmapError("invalidArguments", "calculateTotal must be null or a boolean.");
    }
    if (args.sort !== undefined && args.sort !== null) {
      if (!Array.isArray(args.sort)) {
        return _jmapError("invalidArguments", "sort must be null or a list of Comparators.");
      }
      if (args.sort.length > 0) {
        return _jmapError("unsupportedSort", "This server answers a query newest first and " +
          "sorts on nothing else, which is what the account's empty emailQuerySortOptions says.");
      }
    }
    if (args.anchor !== undefined && args.anchor !== null) {
      return _jmapError("anchorNotFound", "This server answers a query from a position rather " +
        "than from an anchor, so no anchor is ever found in its results.");
    }
    // `collapseThreads` false is what this server does, so it is answered
    // rather than refused. True asks for one row per thread, which is a
    // different set of ids from the one it would return.
    if (args.collapseThreads !== undefined && args.collapseThreads !== null) {
      if (typeof args.collapseThreads !== "boolean") {
        return _jmapError("invalidArguments", "collapseThreads must be null or a boolean.");
      }
      if (args.collapseThreads === true) {
        return _jmapError("invalidArguments", "This server answers a query with one row per " +
          "message. Ask for collapseThreads false, or read the thread through Thread/get.");
      }
    }
    if (args.filter !== undefined && args.filter !== null) {
      if (typeof args.filter !== "object" || Array.isArray(args.filter)) {
        return _jmapError("invalidArguments", "filter must be null or a FilterCondition object.");
      }
      var named = Object.keys(args.filter);
      for (var i = 0; i < named.length; i += 1) {
        if (JMAP_QUERY_CONDITIONS.indexOf(named[i]) === -1) {
          return _jmapError("unsupportedFilter", "This server reads the filter conditions " +
            JMAP_QUERY_CONDITIONS.join(", ") + " and cannot process " +
            _echoAuthor(named[i]) + ".");
        }
        if (typeof args.filter[named[i]] !== "string") {
          return _jmapError("invalidArguments", named[i] + " must be a string.");
        }
      }
    }
    return null;
  }

  // The limit one query answers under, from what the client asked for.
  // Absent is the server's own page; a larger request is capped, which
  // RFC 8620 section 5.5 has the answer report back.
  function _jmapQueryLimit(wanted) {
    if (wanted === undefined || wanted === null) return JMAP_QUERY_MAX_LIMIT;
    return wanted < JMAP_QUERY_MAX_LIMIT ? wanted : JMAP_QUERY_MAX_LIMIT;
  }

  // The ids a query walks up, newest first, through the same pager the
  // folder page is drawn with. `complete` says the walk reached the end
  // of the folder, which is what a total and a negative position both
  // need and what a walk stopped at the page ceiling cannot claim.
  //
  // `needed` is how many ids are enough to answer, or null to walk to
  // the end. The pager returns a page and a cursor onto the row below
  // it, so a walk costs one read per page and never repeats a row.
  async function _jmapQueryIds(account, folder, extra, needed) {
    var ids = [];
    var cursor = null;
    var complete = false;
    for (var page = 0; page < JMAP_QUERY_MAX_PAGES; page += 1) {
      var got = await _pageBefore(account, folder, cursor, extra);
      for (var i = 0; i < got.rows.length; i += 1) ids.push(got.rows[i].objectid);
      if (got.rows.length === 0 || !got.hasOlder) { complete = true; break; }
      cursor = got.olderThan;
      if (needed !== null && ids.length >= needed) break;
    }
    return { ids: ids, complete: complete };
  }

  // Whether an RFC 8621 Address carries SMTP parameters. An empty object
  // carries none.
  function _hasSmtpParameters(entry) {
    var parameters = entry.parameters;
    if (parameters === undefined || parameters === null) return false;
    return typeof parameters !== "object" || Array.isArray(parameters) ||
      Object.keys(parameters).length > 0;
  }

  // The addresses of one header field, each in the form the identity
  // layer derives, with the entries it cannot read collected apart.
  function _submissionAddresses(field, into, invalid) {
    var written = _addresses(field).map(_bareAddress);
    for (var i = 0; i < written.length; i += 1) {
      var parsed = address.parse(written[i]);
      if (!parsed.ok) { invalid.push(_echoAuthor(written[i])); continue; }
      if (into.indexOf(parsed.address) === -1) into.push(parsed.address);
    }
    return into;
  }

  // The SetError refusing a submission that asked to be sent later, or
  // null.
  //
  // RFC 8621 section 7 has a client read `maxDelayedSend` off the
  // account's submission capability before it offers to schedule
  // anything, and this server advertises zero: `composer.send` hands the
  // message to the outbound path as this method runs and there is
  // nothing that would hold it. A `sendAt` read and dropped is the one
  // failure a client cannot see, because the answer carries a `sendAt`
  // of its own and a client comparing the two would need to know the
  // server rewrote it. A time already past is nothing to wait for and is
  // accepted.
  function _sendAtRefusal(submission) {
    var sendAt = submission.sendAt;
    if (sendAt === undefined || sendAt === null) return null;
    var refusal = {
      type:       "invalidProperties",
      properties: ["sendAt"],
      description: "This server releases a submission as it accepts it, which is what the " +
        "account's maxDelayedSend of " + JMAP_MAX_DELAYED_SEND_SECONDS + " says. Send the " +
        "message when it should go out, or leave sendAt unset.",
    };
    if (typeof sendAt !== "string") return refusal;
    var when = Date.parse(sendAt);
    if (!isFinite(when)) return refusal;
    return when > Date.now() ? refusal : null;
  }

  // The return path and recipients `composer.send` takes for one JMAP
  // submission, or `{ error }` carrying the SetError that refuses it.
  //
  // With no envelope, the return path is the account's own address and
  // the recipients are the draft's To, Cc and Bcc addresses (RFC 8621
  // section 7).
  //
  // An envelope's `mailFrom` must be one of the addresses
  // `permittedAuthors` returns for the account, which is the set the
  // submission listener checks MAIL FROM against. Any other value is
  // refused `forbiddenMailFrom`, and `refusedSender` and `allowed` are
  // returned for the audit row.
  //
  // An envelope's `rcptTo` is the complete recipient list. It must name
  // every To and Cc address of the draft, and each address it adds is
  // sent as a blind copy. SMTP parameters on `mailFrom` or on a recipient
  // are refused `invalidProperties`.
  function _submissionRoute(account, message, envelope) {
    var invalid = [];
    var to  = _submissionAddresses(message.to, [], invalid);
    var cc  = _submissionAddresses(message.cc, [], invalid);
    var bcc = _submissionAddresses(message.bcc, [], invalid);
    var noRecipients = { error: { type: "noRecipients", description: "The submission names no recipient." } };
    var tooMany = { error: { type: "tooManyRecipients", description: "A message may name at most " +
      SEND_MAX_RECIPIENTS + " recipients." } };

    if (envelope === undefined || envelope === null) {
      if (invalid.length > 0) {
        return { error: { type: "invalidRecipients", invalidRecipients: invalid,
          description: "The draft names an address this server will not send to." } };
      }
      var total = to.length + cc.length + bcc.length;
      if (total === 0) return noRecipients;
      if (total > SEND_MAX_RECIPIENTS) return tooMany;
      return { envelopeFrom: account.address, to: to, cc: cc, bcc: bcc };
    }

    if (typeof envelope !== "object" || Array.isArray(envelope)) {
      return { error: { type: "invalidProperties", properties: ["envelope"],
        description: "envelope must be null or an Envelope object." } };
    }
    var mailFrom = envelope.mailFrom;
    if (!mailFrom || typeof mailFrom !== "object" || Array.isArray(mailFrom) ||
        typeof mailFrom.email !== "string") {
      return { error: { type: "invalidProperties", properties: ["envelope/mailFrom"],
        description: "envelope.mailFrom must be an Address with an email." } };
    }
    if (_hasSmtpParameters(mailFrom)) {
      return { error: { type: "invalidProperties", properties: ["envelope/mailFrom/parameters"],
        description: "This server does not apply SMTP parameters." } };
    }
    var allowed = permittedAuthors(store, { id: account.id, address: account.address });
    var sender = address.parse(mailFrom.email);
    if (!sender.ok || allowed.indexOf(sender.address) === -1) {
      return {
        refusedSender: mailFrom.email,
        allowed:       allowed,
        error: { type: "forbiddenMailFrom", description: _echoAuthor(mailFrom.email) +
          " is not an address this account may send as." },
      };
    }

    if (!Array.isArray(envelope.rcptTo)) {
      return { error: { type: "invalidProperties", properties: ["envelope/rcptTo"],
        description: "envelope.rcptTo must be a list of Address objects." } };
    }
    if (envelope.rcptTo.length === 0) return noRecipients;
    if (envelope.rcptTo.length > SEND_MAX_RECIPIENTS) return tooMany;
    var recipients = [];
    var unreadable = [];
    for (var r = 0; r < envelope.rcptTo.length; r += 1) {
      var entry = envelope.rcptTo[r];
      if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.email !== "string") {
        unreadable.push(String(r));
        continue;
      }
      if (_hasSmtpParameters(entry)) {
        return { error: { type: "invalidProperties", properties: ["envelope/rcptTo/parameters"],
          description: "This server does not apply SMTP parameters." } };
      }
      var parsed = address.parse(entry.email);
      if (!parsed.ok) { unreadable.push(_echoAuthor(entry.email)); continue; }
      if (recipients.indexOf(parsed.address) === -1) recipients.push(parsed.address);
    }
    if (unreadable.length > 0) {
      return { error: { type: "invalidRecipients", invalidRecipients: unreadable,
        description: "envelope.rcptTo names an address this server will not send to." } };
    }
    var named = to.concat(cc);
    var missing = named.filter(function (entryAddress) { return recipients.indexOf(entryAddress) === -1; });
    if (missing.length > 0) {
      return { error: { type: "invalidProperties", properties: ["envelope/rcptTo"],
        description: "envelope.rcptTo leaves out " + missing.join(", ") + ", which the draft's " +
          "To or Cc field names. Every address in those fields receives the message." } };
    }
    return {
      envelopeFrom: sender.address,
      to:           to,
      cc:           cc,
      bcc:          recipients.filter(function (entryAddress) { return named.indexOf(entryAddress) === -1; }),
    };
  }

  var jmapMethods = {
    "Mailbox/get": async function (actor, args) {
      var refused = _jmapGetRefusal(args);
      if (refused !== null) return refused;
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var mailboxes = _jmapMailboxes(folders);
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
      var refused = _jmapAccountArgRefusal(args);
      if (refused !== null) return refused;
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var mailboxes = _jmapMailboxes(folders);
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
      var refused = _jmapQueryRefusal(args);
      if (refused !== null) return refused;
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var filter = args.filter || {};
      var folderName = typeof filter.inMailbox === "string" ? filter.inMailbox : DEFAULT_FOLDER;
      var folder = _findFolder(folders, folderName);
      var limit = _jmapQueryLimit(args.limit);
      var wantTotal = args.calculateTotal === true;
      var asked = Number.isInteger(args.position) ? args.position : 0;
      // The namespace revision and the folder's counter are separate parts
      // of the state rather than a sum, so a mailbox deleted and created
      // again, or renamed into the name a query asks for, answers a new
      // state even when the two numbers add up to an earlier total.
      var revision = typeof folders.namespaceRevision === "number"
        ? folders.namespaceRevision : 0;
      var answer = {
        accountId:  args.accountId,
        queryState: revision + "." + (folder ? folder.modseqMax : 0),
        canCalculateChanges: false,
        position:   0,
        limit:      limit,
        ids:        [],
      };
      if (!folder) {
        // A filter naming a mailbox this account does not hold matches
        // nothing, which is a count of zero rather than an unknown one.
        if (wantTotal) answer.total = 0;
        return answer;
      }

      var extra = {};
      if (typeof filter.text === "string" && filter.text.length > 0) extra.text = filter.text;
      if (typeof filter.from === "string" && filter.from.length > 0) extra.from = filter.from;
      if (typeof filter.to === "string" && filter.to.length > 0)     extra.to = filter.to;
      if (typeof filter.body === "string" && filter.body.length > 0) extra.body = filter.body;
      var narrowed = Object.keys(extra).length > 0 ? extra : null;

      // A position counted from the end, and a total, are both answers
      // about the whole result set, so neither can be given from a walk
      // that stopped partway. A position counted from the start needs
      // only the rows up to it.
      var fromTheEnd = asked < 0;
      var needed = fromTheEnd || wantTotal ? null : asked + limit;
      var walked = await _jmapQueryIds(account, folder, narrowed, needed);
      if (!walked.complete && walked.ids.length < (needed === null ? Infinity : needed)) {
        return _jmapError("requestTooLarge", "This server answers a query over the newest " +
          JMAP_QUERY_MAX_ROWS + " messages of a mailbox. Narrow the filter, or read the " +
          "mailbox over IMAP, which pages without a ceiling.");
      }

      var start = fromTheEnd ? walked.ids.length + asked : asked;
      if (start < 0) start = 0;
      answer.position = start;
      answer.ids = walked.ids.slice(start, start + limit);
      if (wantTotal) answer.total = walked.ids.length;
      return answer;
    },

    "Email/get": async function (actor, args) {
      var refused = _jmapGetRefusal(args);
      if (refused !== null) return refused;
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      // The list of parts is answered only to a client that named it.
      // RFC 8621 section 4.2 carries `attachments` in the default
      // property set, and this server departs from that: deriving the
      // list opens the message and walks its structure, and one call may
      // name fifty identifiers against an eight mebibyte read bound, so
      // every client would pay that for every message whether or not it
      // had any use for the answer. The same section gates the body
      // values the same way, and the departure is one a client sees:
      // the property is absent rather than empty.
      var wantsParts = Array.isArray(args.properties) &&
        args.properties.indexOf("attachments") !== -1;
      // Narrowed to the folders this account holds, which is the actor
      // the blob download route reads octets under. It is the same set
      // the loop below walks, so it takes nothing away from the fetch.
      var readActor = _actorFor(account, folders);
      var ids = Array.isArray(args.ids) ? args.ids : [];
      var list = [];
      var notFound = [];
      for (var i = 0; i < ids.length; i += 1) {
        var hit = null;
        for (var f = 0; f < folders.length && hit === null; f += 1) {
          var message = await agent.fetch({
            actor: _actorFor(account), folder: folders[f].storeName, objectId: ids[i],
          });
          if (message) {
            hit = _jmapEmail(folders[f].name, message,
              wantsParts ? _attachmentsOf(readActor, folders[f], message) : null);
          }
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
      var refused = _jmapSetRefusal(args);
      if (refused !== null) return refused;
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
          notUpdated[id] = {
            type:        "invalidProperties",
            // The client's own bytes come back in this sentence: the
            // keyword and the property name a patch names are quoted by
            // the refusal that would not take them.
            description: _faultForDisplay(patchErr),
          };
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
      var refused = _jmapGetRefusal(args);
      if (refused !== null) return refused;
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
      var refused = _jmapGetRefusal(args);
      if (refused !== null) return refused;
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
      var refused = _jmapSetRefusal(args);
      if (refused !== null) return refused;
      var account = await _jmapAccount(actor);
      var folders = _foldersFor(account);
      var identities = _identitiesFor(account);
      var oldState = _accountState(folders);
      var created = {};
      var notCreated = {};
      var requests = args.create ? Object.keys(args.create) : [];
      for (var i = 0; i < requests.length; i += 1) {
        var key = requests[i];
        var submission = args.create[key] || {};
        // Read before the draft is, so a submission this server will not
        // hold is refused without a store read and without the client
        // being told which of its drafts exists.
        var delayed = _sendAtRefusal(submission);
        if (delayed !== null) { notCreated[key] = delayed; continue; }
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
        var source = mailbox.readMessageSource(_actorFor(account), folder.name, emailId);
        if (source === null) {
          notCreated[key] = { type: "invalidProperties", properties: ["emailId"] };
          continue;
        }
        if (source.withheld !== null) {
          notCreated[key] = {
            type:        "tooLarge",
            description: "The draft is larger than this server reads to send it.",
          };
          continue;
        }
        var route = _submissionRoute(account, source.message, submission.envelope);
        if (route.error) {
          if (route.refusedSender !== undefined) {
            _recordAuthorRefusal("jmap-submission-envelope", route.refusedSender, route.allowed);
          }
          notCreated[key] = route.error;
          continue;
        }
        try {
          var sent = await composer.send({
            from:         identity.address,
            // With no envelope, the same split the compose form makes,
            // for the same reason. The author is the identity the client
            // chose and the return path is the account's own address, so
            // a bounce lands in the mailbox of whoever sent the message.
            // Both surfaces sign through `compose.send`, so the signature
            // names the identity's domain and the SPF half is the one
            // that does not align. Written out on the compose route.
            envelopeFrom: route.envelopeFrom,
            to:           route.to,
            cc:           route.cc,
            bcc:          route.bcc,
            subject:      _str(message.subject, ""),
            text:         _str(message.bodyText, ""),
            inReplyTo:    message.inReplyTo || undefined,
            // The chain the draft carried, sent on unchanged. A
            // submission is the client's own message going out, so the
            // threading it wrote is the threading that leaves.
            references:   _referenceList(message),
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
          // The far side's own words, which is what a delivery refusal
          // carries back.
          notCreated[key] = {
            type:        "forbiddenToSend",
            description: _faultForDisplay(sendErr),
          };
        }
      }

      // This server keeps no EmailSubmission records once a message is
      // handed to the outbound path, so every id an update or a destroy
      // names is reported not found.
      var notUpdated = {};
      var updateIds = args.update ? Object.keys(args.update) : [];
      for (var u = 0; u < updateIds.length; u += 1) notUpdated[updateIds[u]] = { type: "notFound" };
      var notDestroyed = {};
      var destroyIds = Array.isArray(args.destroy) ? args.destroy : [];
      for (var d = 0; d < destroyIds.length; d += 1) notDestroyed[destroyIds[d]] = { type: "notFound" };

      return {
        accountId:    args.accountId,
        oldState:     oldState,
        // A submission files a copy in Sent, so the state a client
        // caches after one has to be read after the send rather than
        // before it.
        newState:     _accountState(_foldersFor(account)),
        created:      created,
        notCreated:   notCreated,
        updated:      {},
        notUpdated:   notUpdated,
        destroyed:    [],
        notDestroyed: notDestroyed,
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

  // Read once at construction. The upgrade mount below checks the same
  // list before it hands the socket to the framework.
  var jmapWebSocketOrigins = _jmapWebSocketOrigins();

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
    // The options behind the core limits this file advertises, so the
    // framework enforces the values the session document names.
    maxBlobBytes:             JMAP_MAX_SIZE_UPLOAD,
    maxConcurrentUpload:      JMAP_MAX_CONCURRENT_UPLOAD,
    maxConcurrentRequests:    JMAP_MAX_CONCURRENT_REQUESTS,
    webSocketOrigins:        jmapWebSocketOrigins,
    // permessage-deflate stays off, which is the framework's default
    // and the same reasoning that keeps IMAP COMPRESS=DEFLATE off: a
    // channel carrying attacker chosen text beside confidential text
    // through one compressor is a compression oracle.
    webSocketPermessageDeflate: false,
    serverCapabilities: {
      "urn:ietf:params:jmap:core": {
        maxSizeUpload:         JMAP_MAX_SIZE_UPLOAD,
        maxConcurrentUpload:   JMAP_MAX_CONCURRENT_UPLOAD,
        maxSizeRequest:        JMAP_MAX_SIZE_REQUEST,
        maxConcurrentRequests: JMAP_MAX_CONCURRENT_REQUESTS,
        maxCallsInRequest:     JMAP_MAX_CALLS_IN_REQUEST,
        maxObjectsInGet:       JMAP_MAX_OBJECTS_IN_GET,
        maxObjectsInSet:       JMAP_MAX_OBJECTS_IN_SET,
        // `collationAlgorithms` is the framework's default set. The
        // framework refuses an empty one, and no query here sorts:
        // `Email/query` answers newest first and refuses any `sort`.
      },
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
        // RFC 8621 section 1.6.2 and section 7. The session capabilities
        // object above carries an empty object for each of these two,
        // which is what those sections ask for; the numbers belong here,
        // per account. A client reads them once and draws its window
        // from what it found, so a property left out is one it fills in
        // from its own default and then acts on: a New Mailbox button
        // over a server serving no `Mailbox/set`, a sort control over a
        // query that sorts on nothing, a Send Later field over a server
        // that sends now.
        accountCapabilities: {
          "urn:ietf:params:jmap:mail": {
            maxMailboxesPerEmail:       JMAP_MAX_MAILBOXES_PER_EMAIL,
            maxMailboxDepth:            JMAP_MAX_MAILBOX_DEPTH,
            maxSizeMailboxName:         MAX_FOLDER_NAME_CHARS,
            maxSizeAttachmentsPerEmail: JMAP_MAX_ATTACHMENT_BYTES,
            emailQuerySortOptions:      [],
            mayCreateTopLevelMailbox:   JMAP_MAY_CREATE_TOP_LEVEL_MAILBOX,
          },
          "urn:ietf:params:jmap:submission": {
            maxDelayedSend:       JMAP_MAX_DELAYED_SEND_SECONDS,
            submissionExtensions: {},
          },
        },
      };
      var primary = {};
      primary["urn:ietf:params:jmap:mail"] = account.id;
      primary["urn:ietf:params:jmap:submission"] = account.id;
      return { primaryAccounts: primary, accounts: accounts };
    },
  });

  // -------------------------------------------------------------------
  // The JMAP API route, `POST /jmap/api`.
  //
  // It calls `jmap.dispatch` and writes the answer. A request the
  // dispatcher refuses as a whole is answered with an RFC 8620 section
  // 3.6.1 problem document, `application/problem+json` and status 400:
  //
  //   notJSON            the Content-Type is not application/json, the
  //                      body is empty, or the body does not parse
  //   notRequest         the body is JSON and not a Request object
  //   limit              maxCallsInRequest, maxBackRefDepth or
  //                      maxConcurrentRequests was crossed; the document
  //                      carries the limit's name in `limit`
  //   unknownCapability  `using` names a capability this server does not
  //                      advertise
  //
  // A body that is not JSON, that nests past the JSON parser's depth
  // limit, or that is larger than maxSizeRequest is refused by
  // `b.middleware.bodyParser` before this route runs, with a 400 or 413
  // in that middleware's own JSON shape.
  //
  // `maxConcurrentRequests` counts the requests this route has open for
  // one account. The WebSocket transport dispatches its frames outside
  // this route and is not counted.
  // -------------------------------------------------------------------

  var jmapOpenRequests = new Map();

  function _jmapProblem(res, type, detail, extensions) {
    b.problemDetails.send(res, {
      type:       type,
      status:     400,
      detail:     detail,
      extensions: extensions || {},
    });
  }

  // The core limit a refusal's text names, or null. Used when a refusal
  // in the RFC form arrives without its `limit` property.
  var JMAP_LIMIT_NAMES = ["maxSizeRequest", "maxCallsInRequest", "maxConcurrentRequests",
    "maxObjectsInGet", "maxObjectsInSet"];
  function _limitNamedIn(detail) {
    for (var i = 0; i < JMAP_LIMIT_NAMES.length; i += 1) {
      if (detail.indexOf(JMAP_LIMIT_NAMES[i]) !== -1) return JMAP_LIMIT_NAMES[i];
    }
    if (/methodCalls exceeds cap/.test(detail)) return "maxCallsInRequest";
    return null;
  }

  // The problem document for a request the dispatcher refused as a
  // whole, from the refusal's `type` and `description`.
  function _jmapRefusalProblem(res, refusal) {
    var type = String(refusal.type || "");
    var detail = String(refusal.description || "");
    var limitPrefix = JMAP_ERROR_PREFIX + "limit/";
    if (type.indexOf(limitPrefix) === 0) {
      _jmapProblem(res, JMAP_PROBLEM.limit, detail, { limit: type.slice(limitPrefix.length) });
      return;
    }
    // The RFC 8620 section 3.6.1 form, which names the limit in its own
    // property rather than in the type.
    if (type === JMAP_PROBLEM.limit) {
      var named = typeof refusal.limit === "string" && refusal.limit.length > 0
        ? refusal.limit : _limitNamedIn(detail);
      _jmapProblem(res, JMAP_PROBLEM.limit, detail, named === null ? {} : { limit: named });
      return;
    }
    if (type === JMAP_ERROR_PREFIX + "requestTooLarge") {
      _jmapProblem(res, JMAP_PROBLEM.limit, detail, { limit: "maxSizeRequest" });
      return;
    }
    if (type === JMAP_PROBLEM.unknownCapability) {
      _jmapProblem(res, JMAP_PROBLEM.unknownCapability, detail);
      return;
    }
    if (type === "guard-jmap/bad-json" || type === "guard-jmap/bad-input") {
      _jmapProblem(res, JMAP_PROBLEM.notJSON, detail);
      return;
    }
    if (type === JMAP_ERROR_PREFIX + "forbidden") {
      b.problemDetails.send(res, { type: type, status: 401, detail: detail });
      return;
    }
    if (type === JMAP_ERROR_PREFIX + "serverFail") {
      b.problemDetails.send(res, { type: type, status: 500, detail: detail });
      return;
    }
    _jmapProblem(res, JMAP_PROBLEM.notRequest, detail);
  }

  async function _jmapApi(req, res) {
    var account = req.user;
    var mediaType = String((req.headers && req.headers["content-type"]) || "")
      .split(";")[0].trim().toLowerCase();
    if (mediaType !== "application/json") {
      _jmapProblem(res, JMAP_PROBLEM.notJSON,
        "A JMAP request is sent with Content-Type application/json.");
      return;
    }
    if (req.body === undefined || req.body === null) {
      _jmapProblem(res, JMAP_PROBLEM.notJSON, "The request body is empty.");
      return;
    }
    if (typeof req.body !== "object" || Array.isArray(req.body)) {
      _jmapProblem(res, JMAP_PROBLEM.notRequest, "The request body is not a JSON object.");
      return;
    }

    var open = jmapOpenRequests.get(account.id) || 0;
    if (open >= JMAP_MAX_CONCURRENT_REQUESTS) {
      _jmapProblem(res, JMAP_PROBLEM.limit, "This account already has " + open +
        " JMAP requests open and maxConcurrentRequests is " + JMAP_MAX_CONCURRENT_REQUESTS + ".",
        { limit: "maxConcurrentRequests" });
      return;
    }
    jmapOpenRequests.set(account.id, open + 1);
    try {
      var answer = await jmap.dispatch(account, req.body);
      if (answer && typeof answer.type === "string") {
        _jmapRefusalProblem(res, answer);
        return;
      }
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(answer));
    } finally {
      var remaining = (jmapOpenRequests.get(account.id) || 1) - 1;
      if (remaining > 0) jmapOpenRequests.set(account.id, remaining);
      else jmapOpenRequests.delete(account.id);
    }
  }

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
  //   Origin. `b.websocket.isOriginAllowed` compares the `Origin` header
  //   against `jmapWebSocketOrigins`, the list `_jmapWebSocketOrigins`
  //   builds from the configured hostname and TLS port, and the same
  //   list is passed to the framework handler. An upgrade whose `Origin`
  //   is not on the list is refused with 403 and an audit row. The list
  //   holds only `https://` origins, so a page served over cleartext at
  //   this hostname is refused. An upgrade with no `Origin` header is
  //   accepted; browsers always send one on a WebSocket handshake.
  //
  //   The framework's default with no list compares the `Origin` host
  //   with the `Host` header and ignores the scheme, which accepts
  //   `http://<hostname>` against a TLS deployment.
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
    // allow:swallow-unverified destroying an already destroyed socket does
    // not throw, so there is no input that drives this; it is the guard for
    // a socket the peer closed between the write above and this line, and
    // the connection is being ended either way.
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
      // allow:swallow-unverified pausing a socket the peer already closed
      // does not throw, so there is no input that drives this; holding the
      // socket still is what it is for, and a socket that is gone needs no
      // holding.
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
      if (!b.websocket.isOriginAllowed(req, jmapWebSocketOrigins)) {
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
      // An upgrade never reaches the router, so the gate the request
      // lifecycle holds over a credential arriving on a connection that
      // cannot carry one is held again here. The reader below takes the
      // session token off the same cookie, so without this line the
      // cleartext port would refuse that token on every page and accept
      // it on this socket, which is the whole mailbox.
      if (!_transportCarriesCredentials(req)) {
        b.audit.safeEmit({
          action:   "blamepost.jmap.websocket.refused",
          outcome:  "denied",
          actor:    auditActor.forRequest(req),
          metadata: { reason: "transport-cannot-carry-a-credential" },
        });
        _refuseUpgrade(socket, 403, "This connection is not encrypted, so this server " +
          "will not read a session from it. Connect over TLS.");
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
        // allow:swallow-unverified resuming a socket the peer already closed
        // does not throw, so there is no input that drives this; the reader
        // it releases the socket to is already attached.
        try { socket.resume(); } catch (_e) { /* drop-silent by design: already gone */ }
      }).catch(function (err) {
        log.error("a JMAP WebSocket upgrade threw: " + _faultForDisplay(err));
        if (handedOff) {
          // allow:swallow-unverified this is the cleanup on the path where
          // the upgrade itself threw after the socket was handed off, so
          // reaching it needs the framework handler to throw and the socket
          // to be gone in the same request. The connection ends either way.
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
        href:    _href(_folderPath(folder)),
        current: folder.name === currentName,
      };
    });
  }

  function _adminNav(active) {
    return [
      { href: _href("/admin"),          label: "Overview",  current: active === "overview" },
      { href: _href("/admin/domains"),  label: "Domains",   current: active === "domains" },
      { href: _href("/admin/accounts"), label: "Accounts",  current: active === "accounts" },
      { href: _href("/admin/lockouts"), label: "Lockouts",  current: active === "lockouts" },
      { href: _href("/admin/aliases"),  label: "Aliases",   current: active === "aliases" },
      { href: _href("/admin/credentials"), label: "Credentials",
        current: active === "credentials" },
      { href: _href("/admin/dkim"),     label: "Selectors", current: active === "dkim" },
      { href: _href("/admin/dmarc"),    label: "DMARC",     current: active === "dmarc" },
      { href: _href("/admin/queue"),    label: "Queue",     current: active === "queue" },
      { href: _href("/admin/audit"),    label: "Audit",     current: active === "audit" },
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
    // What the mailbox holds, beside the cap the operator set on it. A
    // cap on its own says what the operator chose and not whether it is
    // about to bind, and the second is the part of the row that moves
    // between one day and the next.
    var held = mailbox.accountQuota({ id: account.id });
    var percent = _percent(held.usedBytes, account.quotaBytes);
    return {
      id:          account.id,
      address:     account.address,
      // The one value on this row the account holder wrote. The reading
      // that stores it refuses the C0 range and the delete codepoint, so
      // what is left to take off here is everything above them.
      displayName: _headerText(account.displayName || ""),
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
      usedLabel:   _byteSize(held.usedBytes),
      usedCount:   held.usedCount,
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

  // The DMARC counting, grouped for the page. The store answers one row
  // per hosted domain and reporting window, because that is the range
  // the receivers themselves declared; the question an operator asks is
  // per domain, so the windows are gathered here and the totals summed
  // once.
  //
  // Every hosted domain gets a card whether or not anything was counted
  // for it. A domain dropped from the listing for having no rows reads
  // as a domain with nothing wrong, and those are the two states that
  // most need telling apart: a receiver that has stopped reporting and a
  // domain whose mail all aligns produce the same empty page.
  //
  // Rows naming a domain this server no longer hosts are kept and
  // marked. Withdrawing a domain does not destroy the reports about it,
  // and dropping them here would take evidence off the page while it is
  // still on the volume.
  //
  // The counting and the volume left out of it are gathered into two
  // separate lists rather than two columns of one table. The store
  // leaves a report out of the counting when this server did not
  // authenticate the message that carried it, and an operator whose
  // numbers look low is asking a different question from the one the
  // counting answers, so the two readings do not share a row: a window
  // appears among the counting when it counted something, among the
  // excluded when something was left out, and in both when both.
  function _dmarcCards(domains, rows, now, days) {
    var byDomain = Object.create(null);
    var cards = [];

    function _card(name, hosted) {
      if (byDomain[name]) return byDomain[name];
      byDomain[name] = {
        domain:          name,
        hosted:          hosted,
        counted:         0,
        aligned:         0,
        unauthenticated: 0,
        peakSources:     0,
        newestEnd:       0,
        windows:         [],
        excluded:        [],
      };
      cards.push(byDomain[name]);
      return byDomain[name];
    }

    for (var d = 0; d < domains.length; d += 1) _card(domains[d].domain, true);

    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      var card = _card(row.domain, false);
      var began = _when(row.windowBegin, { dateStyle: "medium", timeStyle: "short" });
      var ended = _when(row.windowEnd, { dateStyle: "medium", timeStyle: "short" });
      card.counted         += row.counted;
      card.aligned         += row.aligned;
      card.unauthenticated += row.unauthenticated;

      if (row.counted > 0) {
        // The largest reading any one window gave, not a sum. One relay
        // is one source in every window it sent from, so adding the
        // counts would report a fleet where there is one machine.
        if (row.failingSources > card.peakSources) card.peakSources = row.failingSources;
        // How current the EVIDENCE is, so a domain whose only recent
        // reports were left out does not read as freshly reported on.
        if (row.windowEnd > card.newestEnd) card.newestEnd = row.windowEnd;
        var windowRate = _percent(row.aligned, row.counted);
        card.windows.push({
          began:     began,
          ended:     ended,
          endedAt:   row.windowEnd,
          counted:   row.counted,
          aligned:   row.aligned,
          unaligned: row.unaligned,
          rateLabel: windowRate === null ? "" : windowRate + "%",
          sources:   row.failingSources,
        });
      }

      if (row.unauthenticated > 0) {
        card.excluded.push({
          began:           began,
          ended:           ended,
          endedAt:         row.windowEnd,
          unauthenticated: row.unauthenticated,
        });
      }
    }

    function _newestFirst(left, right) { return right.endedAt - left.endedAt; }

    for (var c = 0; c < cards.length; c += 1) {
      var finished = cards[c];
      var rate = _percent(finished.aligned, finished.counted);
      finished.hasEvidence = finished.counted > 0;
      finished.unaligned   = finished.counted - finished.aligned;
      finished.rate        = rate;
      finished.rateLabel   = rate === null ? "" : rate + "%";
      finished.rateBucket  = rate === null ? 0 : _bucket(rate);
      finished.through     = _when(finished.newestEnd, { dateStyle: "medium" });
      finished.behindDays  = finished.newestEnd > 0
        ? Math.floor((now - finished.newestEnd) / b.constants.TIME.days(1))
        : 0;
      finished.isStale     = finished.hasEvidence && finished.behindDays >= DMARC_STALE_DAYS;
      finished.hasExcluded = finished.unauthenticated > 0;
      finished.withdrawn   = finished.hosted === false;
      // Reports arrived and none of them counted. It is not the same
      // reading as silence and it is the louder of the two: either this
      // server is not authenticating the reports it receives, or
      // somebody is writing reports at a published address.
      finished.allExcluded = !finished.hasEvidence && finished.hasExcluded;

      finished.windowCount = finished.windows.length;
      finished.windows.sort(_newestFirst);
      finished.excluded.sort(_newestFirst);
      if (finished.windows.length > DMARC_WINDOW_ROWS) {
        finished.windows = finished.windows.slice(0, DMARC_WINDOW_ROWS);
      }
      if (finished.excluded.length > DMARC_WINDOW_ROWS) {
        finished.excluded = finished.excluded.slice(0, DMARC_WINDOW_ROWS);
      }
      // How many are listed and how many there are, kept as two numbers.
      // One of them read as both is a line telling an operator that the
      // newest four hundred of four hundred windows are shown.
      finished.shownCount = finished.windows.length;
      finished.truncated  = finished.windowCount > finished.shownCount;
      finished.href = _href("/admin/dmarc?domain=" +
        encodeURIComponent(finished.domain) + "&days=" + days);
    }

    // Worst first, in the order the work is done. A domain whose reports
    // all went uncounted leads, because that is a reading that is wrong
    // rather than bad. Then a domain nothing reported on at all, which
    // an empty page would hide. Then the rest by alignment rate. A tie
    // sorts by name, so two readings of one server list the same domains
    // in the same order.
    function _attention(card) {
      if (card.allExcluded) return 0;
      if (!card.hasEvidence) return 1;
      return 2;
    }
    cards.sort(function (left, right) {
      var byState = _attention(left) - _attention(right);
      if (byState !== 0) return byState;
      if (left.hasEvidence && left.rate !== right.rate) return left.rate - right.rate;
      if (left.domain < right.domain) return -1;
      return left.domain > right.domain ? 1 : 0;
    });
    return cards;
  }

  // -------------------------------------------------------------------
  // The zone writer, as this console drives it.
  // -------------------------------------------------------------------

  // One gate per hosted domain, built when a domain is first published
  // for and kept afterwards.
  //
  // A gate builds a provider client, and that client installs an outbound
  // scanner that refuses a request carrying the credential's own bytes.
  // Building one per request would install a scanner per request and
  // release none of them: the zone handle owns every gate it hands out
  // and closes them all when the server stops, so a gate this file drops
  // on the floor is a gate that stays open until then.
  //
  // The keys are domains this server hosts. Nothing reaches here without
  // being resolved against the hosted rows first, so the set is bounded
  // by the operator's own domain table.
  var zoneGates = Object.create(null);

  function _gateFor(domain) {
    if (zoneGates[domain] === undefined) zoneGates[domain] = zone.forDomain(domain);
    return zoneGates[domain];
  }

  // What this process is holding between the page that RENDERED a change
  // set and the post that performs it.
  //
  // The gate's `apply` takes the object `preview` computed, and it has to
  // be that object rather than a freshly computed one. A route that
  // recomputed the set at submit time would perform whatever the zone
  // needs at THAT moment, which is not what the operator read and agreed
  // to, and the zone can move between the two.
  //
  // Each entry is bound to the account that computed it and carries a
  // digest of the change set as it was rendered. The form posts the
  // opaque name and the digest back, and both have to match. That is what
  // a swapped name cannot survive: two sets prepared in two tabs are two
  // entries, and a form whose hidden name was moved from one to the other
  // still carries the digest of the set the operator actually read.
  //
  // The reason lives here too rather than in a hidden field. It is the
  // one operator-written string in this flow, and holding it means no
  // part of it is ever reflected back into a rendered form.
  //
  // In this process and nowhere else. A change set is computed against a
  // zone as it stood a moment ago, and a restart is exactly the event
  // after which it should be computed again.
  var heldChangeSets = [];

  // What the operator read, reduced to one value. The rendered diff is in
  // it, because the diff is the thing on the page: two sets that differ
  // in any line an operator could have read produce different digests.
  function _changeSetDigest(preview) {
    return b.crypto.sha3Hash(JSON.stringify({
      domain:      preview.domain,
      zone:        preview.zone,
      fingerprint: preview.fingerprint,
      diff:        preview.diff,
    }));
  }

  function _dropStaleChangeSets(now) {
    var kept = [];
    for (var i = 0; i < heldChangeSets.length; i += 1) {
      if (now - heldChangeSets[i].at < ZONE_HELD_TTL_MS) kept.push(heldChangeSets[i]);
    }
    while (kept.length > ZONE_HELD_MAX) kept.shift();
    heldChangeSets = kept;
  }

  function _holdChangeSet(accountId, level, reason, preview) {
    var now = Date.now();
    var entry = {
      id:        b.crypto.generateToken(),
      accountId: accountId,
      domain:    preview.domain,
      level:     level,
      reason:    reason,
      preview:   preview,
      digest:    _changeSetDigest(preview),
      at:        now,
    };
    heldChangeSets.push(entry);
    _dropStaleChangeSets(now);
    return entry;
  }

  // Which account a request is acting as. The console gate has already
  // resolved it, so this reads the account off the request rather than
  // deciding anything, and a request carrying none holds nothing and
  // finds nothing.
  function _actingAccountId(req) {
    return req.user && typeof req.user.id === "string" && req.user.id.length > 0
      ? req.user.id
      : "";
  }

  // The set one account is holding under one name. The account is part of
  // the lookup rather than a check after it, so a name belonging to
  // somebody else's session is not held at all rather than held and
  // refused.
  function _heldChangeSet(accountId, id) {
    if (typeof id !== "string" || id.length === 0) return null;
    if (typeof accountId !== "string" || accountId.length === 0) return null;
    _dropStaleChangeSets(Date.now());
    for (var i = 0; i < heldChangeSets.length; i += 1) {
      if (heldChangeSets[i].id === id && heldChangeSets[i].accountId === accountId) {
        return heldChangeSets[i];
      }
    }
    return null;
  }

  function _releaseChangeSet(entry) {
    heldChangeSets = heldChangeSets.filter(function (held) { return held !== entry; });
  }

  // One line of a change set, in the words the confirmation page shows.
  // The gate renders its own diff for a terminal; this is the same set
  // read as a table, where each row names an address and what is about to
  // happen at it.
  //
  // Both values are screened before they are displayed, the way a header
  // this surface renders is. The value being written was composed here,
  // but the value an address is HOLDING came out of the provider's
  // response, and the operator is about to read a line and type a domain
  // back on the strength of it. A right-to-left override in that string
  // reorders what they read without changing what is removed. Escaping
  // stops it executing and does not stop it misleading.
  //
  // The screened copy is what is rendered and nothing else. What the gate
  // performs is the change set it computed, which this never touches.
  function _changeRow(change) {
    var value = change.after && typeof change.after.content === "string"
      ? _headerText(change.after.content) : "";
    var held = change.before && typeof change.before.content === "string"
      ? _headerText(change.before.content) : "";
    if (change.action === "create") {
      return { name: change.type + " " + change.name, detail: "add " + value };
    }
    if (change.action === "delete") {
      return { name: change.type + " " + change.name, detail: "remove " + held };
    }
    return { name: change.type + " " + change.name,
      detail: "replace " + held + " with " + value };
  }

  // A domain named in a request, resolved against the hosted rows before
  // anything reads it. A name this server does not host resolves to null
  // and reaches neither the stepper nor the zone.
  async function _hostedZoneDomain(written) {
    var asked = address.parseDomain(_str(written, ""));
    if (!asked.ok) return null;
    var domains = _asArray(await store.domains.list({}));
    for (var i = 0; i < domains.length; i += 1) {
      if (domains[i].domain === asked.domain) return domains[i].domain;
    }
    return null;
  }

  // Which policy levels an operator may publish for a domain, and why the
  // rest are not offered.
  //
  // Stepping DOWN is not gated, and that is the stepper's own statement
  // rather than a decision taken here: an operator whose mail is being
  // discarded publishes the weaker record first and looks afterwards.
  // Stepping UP is the step the evidence rules exist for, so the only
  // stronger level offered is the one the stepper says the evidence
  // carries. A domain publishing no readable record at all can publish
  // the weakest level and nothing else, because there is no reading to
  // step from.
  function _offeredLevels(verdict, levels) {
    var weakest = levels[0];
    var at = verdict.level === null ? -1 : levels.indexOf(verdict.level);
    return levels.map(function (level, index) {
      var offered = at === -1
        ? level === weakest
        : (index <= at || (verdict.ok === true && level === verdict.next));
      return {
        level:   level,
        record:  typeof verdict.records[level] === "string" ? verdict.records[level] : "",
        offered: offered,
        weaker:  at !== -1 && index < at,
        current: at !== -1 && index === at,
      };
    });
  }

  // The publishing half of the DMARC page, for one domain. Null whenever
  // this server edits no zone, which is what keeps the read-only
  // deployment exactly as it was: no stepper is run, no resolver is asked
  // and no provider is reached.
  async function _policyCard(domain) {
    var levels = policyStepper.describe().levels;
    var verdict;
    try {
      verdict = await policyStepper.evaluate({ domain: domain });
    } catch (err) {
      log.error("the DMARC policy stepper could not read " + domain + ": " +
        _faultForDisplay(err));
      return {
        domain:     domain,
        unreadable: true,
        levels:     [],
        published:  "",
        hasPublished: false,
        next:       "",
        hasNext:    false,
        carries:    false,
        hasChecks:  false,
        detail:     "This server could not read where this domain's DMARC policy stands, " +
          "so it is not offering to change it. The server log says what failed.",
        checks:     [],
      };
    }
    return {
      domain:     domain,
      unreadable: false,
      levels:     _offeredLevels(verdict, levels),
      published:  verdict.level === null ? "" : verdict.level,
      hasPublished: verdict.level !== null,
      next:       verdict.next === null ? "" : verdict.next,
      hasNext:    verdict.next !== null,
      carries:    verdict.ok === true,
      detail:     verdict.detail,
      hasChecks:  verdict.checks.length > 0,
      checks:     verdict.checks.map(function (one) {
        return {
          name:     one.name,
          ok:       one.ok === true,
          found:    one.found === null || one.found === undefined ? "" : String(one.found),
          required: one.required === null || one.required === undefined
            ? "" : String(one.required),
        };
      }),
    };
  }

  // A refusal from the zone gate or its provider client, written as the
  // problem document this route answers with.
  //
  // The code decides the type and the status; the message is the gate's
  // own, which is written for the operator now reading it. A code from
  // either of those layers that this table does not name is still such a
  // refusal, so it answers under the provider type.
  //
  // Anything else reaching here is a fault in this process. Its message
  // names paths, options and internals, so it is logged and answered with
  // a sentence that says what is actually known, which is nothing about
  // where the zone now stands.
  function _zoneRefusal(res, err) {
    var code = err && typeof err.code === "string" ? err.code : "";
    if (DNS_REFUSAL_CODES.indexOf(code) === -1) {
      log.error("a zone change failed under no refusal this server publishes (" +
        (code || "no code") + "): " + _faultForDisplay(err));
      b.audit.safeEmit({
        action:   "blamepost.web.zone_change_refused",
        outcome:  "denied",
        actor:    auditActor.current(),
        metadata: { code: code || null, status: 500 },
      });
      _sendProblem(res, {
        status: 500,
        type:   ZONE_PROBLEM.refused,
        title:  "This server could not make that change",
        detail: "Nothing here says where the zone now stands, so read it before repeating " +
          "anything: prepare the record again to see what the provider holds, or run " +
          "`blamepost zone verify`. The server log says what failed.",
      });
      return;
    }
    // The provider's own words in the refusals it publishes, so they are
    // screened here rather than at the document that carries them.
    var detail = err && typeof err.message === "string" && err.message.length > 0
      ? _faultForDisplay(err)
      : "The zone writer refused this change and said nothing further.";
    var table = {};
    table[dnsCodes.recordDrift]     = { status: 409, type: ZONE_PROBLEM.drift,
      title: "The zone moved under this change set" };
    table[dnsCodes.tooManyChanges]  = { status: 422, type: ZONE_PROBLEM.tooMany,
      title: "That change set is larger than this gate performs" };
    table[dnsCodes.writeNotAllowed] = { status: 403, type: ZONE_PROBLEM.notAllowed,
      title: "This server does not write that record" };
    table[dnsCodes.mxWriteDisabled] = { status: 403, type: ZONE_PROBLEM.notAllowed,
      title: "This server does not write that record" };
    table[dnsCodes.badRecord]       = { status: 422, type: ZONE_PROBLEM.level,
      title: "That record is not one this gate writes" };
    table[dnsCodes.writeIncomplete] = { status: 500, type: ZONE_PROBLEM.incomplete,
      title: "The change set stopped partway" };
    var matched = Object.prototype.hasOwnProperty.call(table, code)
      ? table[code]
      : { status: 502, type: ZONE_PROBLEM.provider,
        title: "The DNS provider refused this change" };
    // Recorded here as well as in the gate. The gate's own row says a
    // zone change was refused; this one says which console request drew
    // it, which is what an operator reconstructing an afternoon reads.
    b.audit.safeEmit({
      action:   "blamepost.web.zone_change_refused",
      outcome:  "denied",
      actor:    auditActor.current(),
      metadata: { code: code || null, status: matched.status },
    });
    _sendProblem(res, {
      status: matched.status,
      type:   matched.type,
      title:  matched.title,
      detail: detail,
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
      // Screened like every other displayed value that somebody else
      // wrote. What a row records is often the thing that was refused,
      // so the detail on this page carries an address or a header a
      // stranger chose, quoted back as it was typed.
      detail:  _headerText(row.reason || row.metadata || ""),
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
  function _lockoutFillPath(address, source) {
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
      fillHref:  account ? _href(_lockoutFillPath(account.address, parts.source)) : "",
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
      postHref:    _href(opts.path),
      backHref:    _href(opts.path),
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

  // Turning one alias off, or back on. Neither direction asks for a
  // typed confirmation: both are undone by the button beside them, and
  // a page that asked twice for everything would teach an operator to
  // type through the question.
  //
  // A catch-all has no address of its own, so the domain it claims is
  // what names it on the page. Both values come from the row the
  // identity layer answered with.
  function _aliasStatusAsk(action, alias) {
    var disabling = action === "disable";
    var named = alias.isCatchAll ? "everything at " + alias.domain : alias.address;
    return _pending({
      path:    "/admin/aliases",
      action:  action,
      carry:   [{ name: "id", value: alias.id }],
      title:   disabling
        ? "Stop delivering " + named + "?"
        : "Start delivering " + named + " again?",
      summary: disabling
        ? "This keeps the row and stops the delivery."
        : "This puts the row back in service.",
      consequence: disabling
        ? "Mail to " + named + " will be refused at the wire instead of reaching " +
          alias.destination + ", from the moment this is saved. It does not fall through " +
          "to the domain's catch-all: routing stops at the disabled alias, so an address " +
          "you turn off here stays off. The row stays with the reason you give beside it, " +
          "and the button on this page starts it delivering again."
        : "Mail to " + named + " reaches " + alias.destination + " again, from the " +
          "moment this is saved. A sending server that held a message while the alias " +
          "was off delivers it on its next retry.",
      subjects: [{ name: named, detail: "delivers to " + alias.destination }],
      needsReason: true,
      verb:       disabling ? "Stop this alias" : "Start this alias",
      fineprint:  "One leg of a fan-out at a time: an address forwarding to several " +
        "people has a row each, and this changes the one named above. The reason is " +
        "recorded in the audit trail. Leaving this page changes nothing.",
    });
  }

  // -------------------------------------------------------------------
  // Routes.
  // -------------------------------------------------------------------

  // -------------------------------------------------------------------
  // The public pages.
  // -------------------------------------------------------------------

  // Whether this server publishes its front page.
  //
  // Two values decide it and the order is the point. The environment
  // states the posture this deployment boots with, and the store holds
  // what an operator has since decided in the console. A stored value
  // wins because it is the later statement, and `null` from the store
  // means nobody has made one, which is why the store answers `null`
  // rather than a default: a stored `false` and an unset setting are
  // different facts, and folding them together would make the console
  // unable to turn off a page the environment turned on.
  function _publicSiteEnabled() {
    var stored = store.settings.get(PUBLIC_SITE_SETTING);
    if (stored === null) return config.publicSiteEnabled === true;
    return stored === true;
  }

  // The origin this server calls itself in a canonical link, a preview
  // card and a sitemap. Those are absolute URLs by definition rather than
  // link targets on this server, so they are not built through `_path`,
  // which refuses everything that is not a path here. Nothing a request
  // carries reaches this: the name is the configured hostname and the
  // port is the configured TLS port, both settled at boot.
  function _siteOrigin() {
    var port = _int(config.httpsPort, 8443, 1, 65535);
    return _siteHostOrigin() + (port === 443 ? "" : ":" + port);
  }

  // `https://` and the configured hostname, with no port.
  function _siteHostOrigin() {
    var host = String(config.hostname);
    // The hostname is a validated setting rather than anything a request
    // carries, and this refuses it anyway. A name holding a slash, an
    // at sign, a colon or a backslash would compose an absolute URL
    // pointing at a different origin than this server, and a canonical
    // link is the one place a browser and a crawler are both told to
    // believe the address over what they typed.
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
      throw new TypeError("blamepost.web: the configured hostname '" +
        host.slice(0, 64) + "' is not a name this server can build its own " +
        "absolute URLs from.");
    }
    return "https://" + host;
  }

  // The `Origin` values a browser may open the JMAP WebSocket from.
  //
  // `https://<hostname>` is always on the list: it is the origin a
  // browser sends behind a TLS terminator on port 443, and the origin of
  // a deployment that publishes port 443 onto the TLS port. When this
  // process terminates TLS, `_siteOrigin()` is added, which carries
  // BLAMEPOST_HTTPS_PORT unless that port is 443. No `http://` origin is
  // on the list, so a page served over cleartext at this name is refused
  // the socket.
  function _jmapWebSocketOrigins() {
    var origins = [_siteHostOrigin()];
    if (tlsTerminatesHere && origins.indexOf(_siteOrigin()) === -1) {
      origins.push(_siteOrigin());
    }
    return origins;
  }

  // One absolute URL on this server, for the three places a page has to
  // name itself to something outside it: the canonical link, the preview
  // card and the sitemap. The path half goes through the same refusal
  // every link target on this surface goes through, and the origin half
  // is built above, so a value returned here was screened in both halves
  // rather than concatenated in place.
  function _siteUrl(path) {
    return _siteOrigin() + _path(path);
  }

  // The router `mount` registered this surface's routes on. It stays null
  // until `mount` runs, and while it is null no public page is listed.
  var mountedRouter = null;

  // Whether a route pattern matches a request path under the router's
  // segment rules: the same number of `/`-separated segments, each literal
  // segment equal, and each `:name` segment non-empty.
  function _routePatternMatches(pattern, path) {
    var want = pattern.split("/");
    var have = path.split("/");
    if (want.length !== have.length) return false;
    for (var i = 0; i < want.length; i += 1) {
      if (want[i].charAt(0) === ":") {
        if (have[i].length === 0) return false;
      } else if (want[i] !== have[i]) {
        return false;
      }
    }
    return true;
  }

  // Whether GET on the page's path is dispatched to a route registered
  // for that path. The router tries GET routes in registration order and
  // runs the first whose pattern matches, so the page counts only when
  // that first match is a pattern equal to the path. A parameter pattern
  // such as `/:name` registered earlier matches the path too, and the
  // request goes to it instead. The route table is read from the router
  // on every call, so a route registered after `mount` returned counts
  // as soon as it is registered.
  function _pageIsServed(page) {
    if (mountedRouter === null) return false;
    var routes = mountedRouter.inspectRoutes();
    for (var i = 0; i < routes.length; i += 1) {
      if (routes[i].method !== "GET") continue;
      if (!_routePatternMatches(routes[i].pattern, page.path)) continue;
      return routes[i].pattern === page.path;
    }
    return false;
  }

  function _mountedPages() {
    return PUBLIC_PAGES.filter(_pageIsServed);
  }

  function _siteNav() {
    return _mountedPages()
      .filter(function (page) { return page.inNav === true; })
      .map(function (page) { return { href: _href(page.path), label: page.label }; });
  }

  // robots.txt. The public pages are allowed by not being named, and
  // every surface behind a credential is named. The sitemap is announced
  // here because that is the one place a crawler looks for it without
  // being told.
  function _robotsBody() {
    var lines = ["User-agent: *"];
    for (var i = 0; i < CRAWLER_DISALLOWED.length; i += 1) {
      lines.push("Disallow: " + CRAWLER_DISALLOWED[i]);
    }
    lines.push("Allow: /static/");
    lines.push("");
    lines.push("Sitemap: " + _siteUrl("/sitemap.xml"));
    return lines.join("\n") + "\n";
  }

  function _sitemapBody() {
    var pages = _mountedPages();
    var out = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"];
    for (var i = 0; i < pages.length; i += 1) {
      out.push("  <url>");
      out.push("    <loc>" + _siteUrl(pages[i].path) + "</loc>");
      out.push("    <changefreq>" + pages[i].changefreq + "</changefreq>");
      out.push("    <priority>" + pages[i].priority + "</priority>");
      out.push("  </url>");
    }
    out.push("</urlset>");
    return out.join("\n") + "\n";
  }

  // The badge another operator puts on their own site to say they run
  // this software.
  //
  // It is a route rather than a file under the asset mount for two
  // reasons that both come back to the headers. The mount answers every
  // asset with `Cross-Origin-Resource-Policy: same-origin`, which is the
  // right answer for a stylesheet and the wrong one for the single image
  // whose whole purpose is to be loaded by a page on somebody else's
  // site: a browser drops it before it renders. Declaring this one
  // resource embeddable is what the header is for, and it is a statement
  // about one public image rather than a relaxation of the policy the
  // rest of the surface is served under. Nothing else moves, and a
  // request for this path carries no session and reads nothing.
  //
  // The version is the only value interpolated and it comes from the
  // package manifest, so nothing a request carries reaches the document.
  function _badgeSvg() {
    var label = "runs blamepost";
    var value = pkg.version;
    var labelWidth = 104;
    var valueWidth = 8 * value.length + 22;
    var total = labelWidth + valueWidth;
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + total + '" height="20" ' +
      'role="img" aria-label="' + label + " " + value + '">' +
      "<title>" + label + " " + value + "</title>" +
      '<rect width="' + total + '" height="20" rx="3" fill="#14161c"/>' +
      '<rect x="' + labelWidth + '" width="' + valueWidth + '" height="20" rx="3" fill="#4338ca"/>' +
      '<rect x="' + labelWidth + '" width="4" height="20" fill="#4338ca"/>' +
      '<g fill="#ffffff" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,' +
      'Helvetica Neue,Arial,sans-serif" font-size="11">' +
      '<text x="10" y="14">' + label + "</text>" +
      '<text x="' + (labelWidth + 11) + '" y="14">' + value + "</text>" +
      "</g></svg>\n";
  }

  function _siteDescription() {
    return "A self-hosted mail server that runs inbound MX, authenticated " +
      "submission, IMAP, JMAP, POP3, ManageSieve, webmail and an operator " +
      "console from one process, with no npm runtime dependencies.";
  }

  // The lowest Node.js version the manifest's `engines.node` range admits,
  // with the comparison operator removed: `>=24.22.1` reads `24.22.1`.
  function _nodeFloor() {
    return String((pkg.engines && pkg.engines.node) || "").replace(/^[^\d]*/, "");
  }

  // The front page's whole JSON-LD element: the start tag
  // `<script type="application/ld+json">`, the record serialized by
  // `b.safeJson.stringifyForScript`, and the end tag. The site layout
  // writes this string unescaped into the document head, and no template
  // writes a value into the body of a script element.
  //
  // `b.safeJson.stringifyForScript` writes every `<`, `>` and `&`, and the
  // code points U+2028 and U+2029, as JSON string escapes rather than as
  // the characters themselves. A value holding `</script>` therefore
  // reaches the document with no angle bracket in it, which does not
  // close the element, and parses back to the original string. Nothing a
  // request carries reaches any value in it.
  //
  // The record carries no `offers` and no rating. The package name has its
  // npm scope removed, and the license is the SPDX page for the manifest's
  // license identifier.
  function _jsonLdElement() {
    var record = {
      "@context":           STRUCTURED_DATA_CONTEXT,
      "@type":              STRUCTURED_DATA_TYPE,
      name:                 String(pkg.name).replace(/^@[^/]+\//, ""),
      description:          _siteDescription(),
      softwareVersion:      pkg.version,
      applicationCategory:  STRUCTURED_DATA_CATEGORY,
      softwareRequirements: "Node.js " + _nodeFloor() + " or newer",
      license:              SPDX_LICENSE_PAGE_BASE + pkg.license + ".html",
      url:                  pkg.homepage,
    };
    return '<script type="application/ld+json">' +
      b.safeJson.stringifyForScript(record) + "</script>";
  }

  function _sitePage(req, res) {
    var badgeUrl = _siteUrl("/badge.svg");
    _publicPage(req, res, "site", {
      siteNav:          _siteNav(),
      version:          pkg.version,
      nodeFloor:        _nodeFloor(),
      jsonLdElement:    _jsonLdElement(),
      pageTitle:        "blamepost: a self-hosted mail server in one process",
      pageDescription:  _siteDescription(),
      // The canonical link is root-relative, which the HTML specification
      // allows and every crawler resolves against the page it is on. It
      // is a link target on this server, so it is built the way every
      // other link target here is built. The absolute form beside it
      // feeds the preview card, where a reader of the card is not on this
      // page and has nothing to resolve a relative address against.
      canonicalHref:    _href("/"),
      canonicalUrl:     _siteUrl("/"),
      previewImageUrl:  _siteUrl("/static/assets/site/shot-mailbox-light.png"),
      previewImageAlt:  "The blamepost mailbox, listing messages in an inbox " +
                        "beside a folder rail and a quota meter.",
      badgeUrl:         badgeUrl,
      // Rendered as text inside a code block for an operator to copy, not
      // as an attribute this page resolves.
      badgeSnippet:     '<a href="' + _siteUrl("/") + '"><img src="' + badgeUrl +
                        '" alt="Runs blamepost" width="180" height="20"></a>',
    });
  }

  // The gate in front of every wiki path, whether the wiki was built or
  // not. A signed-in reader passes whether or not the public site is
  // published. A reader with no session passes only while the site is
  // published, and otherwise meets the same gate every private route is
  // mounted with, which redirects a browser to the sign-in page and
  // answers a caller asking for JSON with a 401. Returns true when the
  // gate answered the request.
  function _referenceGate(req, res) {
    if (req.user || _publicSiteEnabled()) return false;
    requireAccount(req, res, function () { res.redirect(_path("/sign-in")); });
    return true;
  }

  // One page of the reference wiki. A path the wiki has no page at answers
  // 404.
  function _referencePage(req, res) {
    if (_referenceGate(req, res)) return;
    var page = reference.page(req.pathname);
    if (page === null) {
      _fail(req, res, 404, "No such page", "The reference has no page at this address.");
      return;
    }
    _publicPage(req, res, page.view, {
      siteNav:         _siteNav(),
      pageTitle:       page.documentTitle,
      pageDescription: page.description,
      canonicalHref:   _href(page.path),
      canonicalUrl:    _siteUrl(page.path),
      previewImageUrl: _siteUrl("/static/assets/site/shot-mailbox-light.png"),
      previewImageAlt: "The blamepost mailbox, listing messages in an inbox " +
                       "beside a folder rail and a quota meter.",
      wiki:            page,
    });
  }

  // Every GET at or below `/wiki` while the wiki could not be built. The
  // reader passes the same gate first, and the page names no part of the
  // builder's message: the error log and the audit row carry that.
  // Requests with any other method go on down the chain.
  function _referenceUnavailable(req, res, next) {
    if (req.method !== "GET") { next(); return; }
    if (_referenceGate(req, res)) return;
    _fail(req, res, 503, "Reference unavailable",
      "The reference pages could not be generated when this server started. The server's " +
      "error log names the documentation block that stopped them.");
  }

  function mount(router) {
    mountedRouter = router;
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

    // What a crawler is told, and it follows the front page rather than
    // standing on its own. With the page off there is no public surface
    // here at all, so the answer is that nothing may be indexed and there
    // is no sitemap to read: a server whose only pages are behind a
    // credential should not be inviting a crawler to walk them.
    router.get("/robots.txt", function (req, res) {
      var on = _publicSiteEnabled();
      b.render.text(res, on ? _robotsBody() : "User-agent: *\nDisallow: /\n", {
        headers: { "Cache-Control": "public, max-age=3600" },
      });
    });

    router.get("/sitemap.xml", function (req, res) {
      if (!_publicSiteEnabled()) {
        _fail(req, res, 404, "Nothing here", "This server publishes no public pages.");
        return;
      }
      b.render.text(res, _sitemapBody(), {
        headers: {
          "Content-Type":  "application/xml; charset=utf-8",
          "Cache-Control": "public, max-age=3600",
        },
      });
    });

    router.get("/badge.svg", function (req, res) {
      if (!_publicSiteEnabled()) {
        _fail(req, res, 404, "Nothing here", "This server publishes no public pages.");
        return;
      }
      b.render.text(res, _badgeSvg(), {
        headers: {
          "Content-Type":  "image/svg+xml; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
          // The one resource on this surface that is meant to be loaded
          // by a page on another site. Everything else keeps same-origin.
          "Cross-Origin-Resource-Policy": "cross-origin",
        },
      });
    });

    router.get("/.well-known/jmap", jmap.discoveryHandler);
    router.get("/jmap/session", requireAccount, jmap.sessionHandler);
    router.post("/jmap/api", requireAccount, _jmapApi);
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
    //
    // The options pass through `_renderOpts`, which names
    // `PAGE_CACHE_CONTROL` on the response, so the answer carries
    // `private, no-store` rather than the `b.render` default.
    router.get(JMAP_WEBSOCKET_PATH, function (req, res) {
      b.render.text(res,
        "This path is the JMAP WebSocket transport of RFC 8887. Connect with " +
        "Upgrade: websocket and Sec-WebSocket-Protocol: jmap.\n", _renderOpts(req, {
          status:  426,
          headers: {
            "Upgrade":               "websocket",
            "Connection":            "Upgrade",
            "Sec-WebSocket-Version": "13",
          },
        }, false));
    });
    router.post("/jmap/upload/:accountId", requireAccount, jmap.uploadHandler);

    // One blob, as the octets it names, per RFC 8620 section 6.2.
    //
    // The session document names this route and `Email/get` answers
    // whether a message carries a file, so a client holding both has
    // been told a file is there and handed the way to fetch it. The URL
    // template's four variables are all filled by the client, and this
    // route reads two of them: the accountId decides nothing but whether
    // to answer at all, and the blobId decides what is answered. The
    // `name` segment and the `accept` query are read by nothing here,
    // for the reasons the two comments below give.
    //
    // WHAT THE RESPONSE SAYS IT IS. Every blob is served under one media
    // type, and it is not the one the sender declared nor the one the
    // client asked for. RFC 8620 section 6.2 lets a client name a type
    // and lets a server answer a different one, and a response repeating
    // either claim would let a message decide what a browser does with
    // it: a part claiming `text/html` and served as one is a document
    // rendering on the origin this reader's session cookie is scoped to.
    // RFC 2046 section 4.5.1 has a receiver treat bytes it cannot
    // identify as `application/octet-stream`, and `nosniff` stops a
    // browser reading the content and deciding otherwise. That header is
    // also written by the security middleware on every response this
    // application sends, and it is stated here as well, on a response
    // carrying octets a stranger chose, so the guarantee does not depend
    // on a chain configured elsewhere.
    //
    // WHAT IT IS CALLED. The name in the `Content-Disposition` is the
    // one the MESSAGE carries, put through the same two screens the
    // browser route puts it through: the filename guard decides what a
    // receiver may save it as, and both RFC 6266 section 4.1 forms are
    // written so a receiver reading only the ASCII one still gets a
    // name. The name segment of the URL is the client's own suggestion
    // and is not served, because a response built from it would let the
    // caller decide what a receiver writes to disk.
    router.get("/jmap/download/:accountId/:blobId/:name", requireAccount,
      async function (req, res) {
        var account = req.user;
        // The accountId the URL carries is the one this actor is
        // enumerated for, or the request is refused. RFC 8620 section
        // 3.6.1 answers an accountId the actor does not hold rather than
        // looking a blob up under it, so the id in the URL cannot select
        // a scope; the resolution below is bound to the actor either
        // way, and this is the refusal that says so at the door.
        if (_str(req.params.accountId, "") !== String(account.id)) {
          _failBlob(res);
          return;
        }
        var ref = _blobRef(req.params.blobId);
        if (ref === null) {
          _failBlob(res);
          return;
        }
        var found = await _blobOctets(account, ref);
        if (found === null) {
          _failBlob(res);
          return;
        }
        await b.render.stream(res, [found.bytes], _renderOpts(req, {
          headers: {
            "Content-Type":           "application/octet-stream",
            "Content-Disposition":    _dispositionFor(found.name),
            "Content-Length":         String(found.bytes.length),
            "X-Content-Type-Options": "nosniff",
          },
        }, false));
      });

    // ---- The sending route ----

    // The second transport a domain-scoped sending credential reaches
    // this server on. It is mounted here, beside JMAP, because it is the
    // other route on this surface a program rather than a browser drives,
    // and it takes no account session at all.
    //
    // It is NOT wrapped in `requireAccount`. That gate resolves the
    // session `attachUser` left on the request, and `attachUser` is
    // mounted `tokenFrom: "both"`, which means the framework reads an
    // `Authorization: Bearer` value as a SESSION token. A route that
    // asked `req.user` here would be asking the wrong question of the
    // right header: what answers it is a session this server minted, and
    // what arrived is a sending credential. So the header is read here,
    // the credential is verified against the registry, and `req.user` is
    // never consulted.
    //
    // The same collision is why a request carrying ANY Cookie header is
    // refused below rather than merely ignored. A credential path
    // reachable while a browser's ambient credential is also present is
    // one a page on another site can spend, and it is also the only thing
    // holding up the CSRF waiver this chain runs under: `skipStateless`
    // waives the token check for a request that carries no cookie, on the
    // grounds that such a request has no ambient credential to abuse. A
    // route that accepted a cookie-bearing request would be relying on
    // that reasoning while breaking its premise.
    router.post(API_SEND_PATH, async function (req, res) {
      // This route hands back no cookie, and taking off the one the chain
      // above appended is what makes that true.
      //
      // `b.middleware.csrfProtect` issues its double-submit cookie on
      // every request that arrives without one, state-changing or not, so
      // a program driving this route is handed a cookie it has no use
      // for. An application whose HTTP client keeps cookies sends it back
      // on the next call, and that call is refused twice over: the token
      // gate stops waiving its check the moment a Cookie header is
      // present, and this route refuses a cookie-bearing request outright
      // for the reason above it. The application never sent a cookie of
      // its own and has nothing to act on in either refusal. So the
      // header comes off here, on the one route where no cookie is ever
      // wanted, rather than leaving a client to discover that its second
      // request is the one that fails.
      if (typeof res.removeHeader === "function") res.removeHeader("Set-Cookie");

      // Before anything is verified and before the body is read. The
      // secret has already crossed the wire by the time this runs, and
      // what is left to protect is everything after it: no verification,
      // so a credential's failure budget is not spent by a request that
      // was never going to be honored, and no message, so nothing leaves
      // under a credential presented where it could be read off the wire.
      if (!_transportCarriesCredentials(req)) {
        b.audit.safeEmit({
          action:   "blamepost.web.api_send_transport_refused",
          outcome:  "denied",
          actor:    auditActor.current(),
          metadata: { path: req.pathname },
        });
        _sendProblem(res, {
          status: 403,
          type:   SEND_PROBLEM.transport,
          title:  "This connection cannot carry a credential",
          detail: TRANSPORT_REFUSAL,
        });
        return;
      }

      if (typeof req.headers.cookie === "string" && req.headers.cookie.length > 0) {
        b.audit.safeEmit({
          action:   "blamepost.web.api_send_ambient_credential_refused",
          outcome:  "denied",
          actor:    auditActor.current(),
          metadata: { path: req.pathname },
        });
        _sendProblem(res, {
          status: 400,
          type:   SEND_PROBLEM.ambient,
          title:  "This route takes a credential and no session",
          detail: "The request carried a Cookie header. This route reads a sending " +
            "credential from the Authorization header and authenticates nothing else, so a " +
            "request that also carries a browser session is refused rather than resolved " +
            "one way or the other. Send the credential with no cookies.",
        });
        return;
      }

      var presented = b.requestHelpers.extractBearer(req);
      if (presented === null) {
        res.setHeader("WWW-Authenticate", "Bearer");
        _sendProblem(res, {
          status: 401,
          type:   SEND_PROBLEM.credential,
          title:  "No sending credential was presented",
          detail: "Send the credential issued for the domain this message is written as, " +
            "in an Authorization header: Authorization: Bearer <credential>.",
        });
        return;
      }

      // Through the mail layer's credential entry point rather than
      // through the registry underneath it. That function is where the
      // failure budget for this identity space is read and spent, and it
      // is the whole reason this route cannot ask the registry directly:
      // a surface that verifies a secret and counts nothing is a bound an
      // attacker walks around by choosing that surface, and the budget
      // guessing spends here is the same one guessing spends on port 587.
      //
      // No domain is named. SASL carries an authentication identity and
      // the listener cross-checks it against the row, so a token pasted
      // into another domain's application fails at the sign-in. A Bearer
      // header names nothing to cross-check, so the scope is read off the
      // row alone, which is what every decision below reads anyway.
      //
      // Every refusal is the same refusal. The registry files its own row
      // naming which of not-found, revoked, expired, a broken binding or
      // a withdrawn domain it was, so an operator reads the distinction
      // off the trail while an application gets one answer to act on. A
      // spent budget is not told apart from a wrong secret here either,
      // because a lockout a caller can recognize is a lockout it can
      // measure.
      var checked = await verifySendingCredential(store.credentials, {
        secret: presented,
        // Read from the socket rather than from a forwarded header, for
        // the reason the sign-in form reads it that way: a header a
        // client writes is a header a client uses to choose which trail
        // its attempt lands on.
        source: b.requestHelpers.clientIp(req),
      });
      if (checked.ok !== true) {
        res.setHeader("WWW-Authenticate", "Bearer");
        _sendProblem(res, {
          status: 401,
          type:   SEND_PROBLEM.credential,
          title:  "That credential was refused",
          detail: "This server did not accept the credential presented. The audit trail " +
            "records which of an unknown secret, a revoked credential, an expired one, a " +
            "domain no longer hosted here or too many failed attempts it was.",
        });
        return;
      }
      var actor = checked.actor;
      var scope = actor.sendingCredential;

      // The replay key. Required rather than optional, because what an
      // absent one costs is a duplicate mail to a real person every time
      // a client's request times out after this server accepted it and
      // before the answer arrived. A route that made the record optional
      // would be one where the common client bug has no defense.
      //
      // Validated through the guard rather than used as it arrived: the
      // key is rendered into audit metadata and into log lines, and one
      // carrying a control byte chooses where those lines end.
      var suppliedKey = req.headers["idempotency-key"];
      if (typeof suppliedKey !== "string" || suppliedKey.length === 0) {
        _sendProblem(res, {
          status: 400,
          type:   SEND_PROBLEM.key,
          title:  "This route needs an Idempotency-Key",
          detail: "Send an Idempotency-Key header naming this message. It is what lets a " +
            "retry after a timeout answer with the first result rather than sending the " +
            "message a second time.",
        });
        return;
      }
      var replayKey;
      try {
        replayKey = b.guardIdempotencyKey.validate(suppliedKey);
      } catch (_keyErr) {
        _sendProblem(res, {
          status: 400,
          type:   SEND_PROBLEM.key,
          title:  "That Idempotency-Key was refused",
          detail: "The key must be at most 256 bytes of printable US-ASCII, with no " +
            "control characters, no slash or backslash, and no '..' sequence.",
        });
        return;
      }

      // The body as it arrived, fingerprinted before anything reads a
      // field off it. Canonical JSON so the same message written with its
      // keys in another order is the same message, and a digest rather
      // than the body so a record holds no message text.
      var recordKey = _replayRecordKey(scope.id, replayKey);
      var fingerprint = b.crypto.sha3Hash(
        b.canonicalJson.stringify(_bodyOf(req)));
      var reservation = _reserveReplay(recordKey, fingerprint);
      if (reservation.state === "settled") {
        res.setHeader("Idempotency-Replayed", "true");
        _writeSendAnswer(res, reservation.answer);
        return;
      }
      if (reservation.state === "full") {
        res.setHeader("Retry-After", String(SEND_REPLAY_FULL_RETRY_SECONDS));
        _sendProblem(res, {
          status: 503,
          type:   SEND_PROBLEM.keysFull,
          title:  "Too many sends are still running",
          detail: "This server holds a record for every Idempotency-Key it has answered or " +
            "is answering, and every record it may hold belongs to a send that has not " +
            "finished. Nothing was sent. Retry after the time in Retry-After.",
        });
        return;
      }
      if (reservation.state === "in-flight") {
        _sendProblem(res, {
          status: 409,
          type:   SEND_PROBLEM.keyConflict,
          title:  "A request under this key is still running",
          detail: "Another request carrying this Idempotency-Key has not finished. Wait " +
            "for its answer rather than sending the message again.",
        });
        return;
      }
      if (reservation.state === "mismatch") {
        _sendProblem(res, {
          status: 422,
          type:   SEND_PROBLEM.keyMismatch,
          title:  "That Idempotency-Key belongs to a different message",
          detail: "This key was used for a message with different contents. Answering with " +
            "the first result would report a send of this message that never happened, so " +
            "the request is refused. Use a new key for a new message.",
        });
        return;
      }

      // From here the record is reserved, and the `finally` below is what
      // guarantees it is never left that way. A refusal decided before
      // anything can have gone out gives the key back, because nothing
      // was sent and a client correcting or retrying its request should
      // keep it. An answer taken from the signer onwards settles, because
      // by then a message may have left and a second attempt under the
      // same key must never send it again.
      //
      // The release sits in a `finally` rather than on each refusal
      // branch for the case that has no branch: a throw between here and
      // the answer. Left to a per-branch release, such a throw would
      // leave a reservation nothing ever settles, and the client's own
      // key would then answer 409 for a day over a message that never
      // left. The composer's credential gate is what can do it: a
      // credential whose keyed binding breaks between the verify and the
      // count raises rather than answering that the window is clear.
      var settled = false;
      try {
        settled = await _sendUnderReservation(req, res, actor, scope, recordKey);
      } finally {
        if (!settled) _releaseReplay(recordKey);
      }
    });

    // The part of the sending route that runs with a replay record
    // reserved. Returns whether it settled that record.
    //
    // It settles when a message may have left the building, and gives the
    // key back when nothing did. Entering the composer is not the line:
    // the credential gate inside it refuses a crossed ceiling, an
    // unreadable one and a credential that has stopped standing, and all
    // three are decided before the signer and before the outbound path, so
    // nothing has gone anywhere. Each is also an answer a client is meant
    // to retry under the same key, and a stored one replayed on that retry
    // would report a send that never happened.
    async function _sendUnderReservation(req, res, actor, scope, recordKey) {
      var read = _readSendBody(_bodyOf(req));
      if (!read.ok) {
        _sendProblem(res, {
          status: 400,
          type:   SEND_PROBLEM.body,
          title:  "That message was not one this route can send",
          detail: read.detail,
        });
        return false;
      }

      // The envelope sender, measured through the reader the submission
      // listener's own sender policy asks. A credential that names none
      // gets the return path the registry minted for it, which is where
      // this server already routes its bounces.
      var envelopeFrom = read.envelopeFrom === null
        ? (scope.returnPath || read.from)
        : read.envelopeFrom;
      if (!permittedAuthor(store, actor, envelopeFrom)) {
        _refuseSendEnvelope(scope, envelopeFrom);
        _sendProblem(res, {
          status: 403,
          type:   SEND_PROBLEM.envelope,
          title:  "That envelope sender is not one this credential may write",
          detail: "The credential for " + scope.domain + " may write any address at " +
            scope.domain +
            (scope.refusedLocalParts.length === 0
              ? ""
              : ", other than " + scope.refusedLocalParts.map(function (part) {
                return part + "@" + scope.domain;
              }).join(", ")) +
            ". An address at any other domain needs a credential issued for that domain.",
        });
        return false;
      }

      // The credential's standing and its two send ceilings are NOT
      // asked here. They run inside the composer below, on the built
      // message, immediately after the author binding, because that is
      // the order the submission listener runs them in and the ordering
      // is the point: a message the credential may not write must cost
      // it no part of its window on either transport. Counting here
      // would let a caller burn a ceiling down with messages this server
      // never sends, at a rate the wire does not match over identical
      // traffic. The refusals come back through the catch below.

      var answer;
      try {
        // The composer, which is the same handle the browser compose form
        // and JMAP EmailSubmission/set send through, built over the
        // listeners' own relay. Composing it here is what puts this route
        // on the one outbound chain: the author binding runs over the
        // finished bytes, the message is signed for the domain in its
        // From, a recipient this server hosts is filed rather than sent
        // out to DNS, and everything else goes through the MX lookup,
        // MTA-STS, DANE, REQUIRETLS, retry and DSN chain.
        //
        // `file: false`, because a sending credential is not a mailbox
        // owner. There is no Sent folder belonging to it, and the copy
        // would be filed under an account id that names no account.
        var sent = await composer.send({
          from:         read.from,
          envelopeFrom: envelopeFrom,
          to:           read.recipients.to,
          cc:           read.recipients.cc,
          bcc:          read.recipients.bcc,
          subject:      read.subject,
          text:         read.text,
          html:         read.html,
          inReplyTo:    read.inReplyTo,
          references:   read.references,
          // RFC 5322 section 3.6.2 makes Sender the agent that
          // transmitted a message, which is the on-behalf-of shape a
          // sending application emits for an author at a domain this
          // server holds no key for. It is passed as a header because the
          // composer writes no Sender of its own, and the author binding
          // reads it off the finished block either way.
          headers:      read.sender === null ? undefined : { Sender: read.sender },
        }, { actor: actor, file: false });

        answer = {
          status: 202,
          json:   {
            messageId: sent.messageId,
            signed:    sent.signed === true,
            local:     sent.delivery.localCount,
            remote:    sent.delivery.remoteCount,
            refused:   sent.delivery.refusedCount,
          },
        };
      } catch (sendErr) {
        var refusalCode = (sendErr && sendErr.code) || null;
        log.error("the sending route refused a message for the credential on " +
          scope.domain + ": " + _faultForDisplay(sendErr));

        // The two classes the composer's credential gate raises, each
        // decided before anything was signed or handed to the outbound
        // path, so nothing left the building and the replay record is
        // given back rather than settled. A stored answer replayed on
        // the retry either of these asks for would report a send that
        // never happened.
        if (refusalCode === LISTENER_CODES.sendingCredentialCeiling) {
          var reading = sendErr.reading || {};
          b.audit.safeEmit({
            action:   "blamepost.web.api_send_ceiling_reached",
            outcome:  "denied",
            actor:    { userId: scope.id },
            metadata: {
              credentialId:       scope.id,
              scopeDomain:        scope.domain,
              messages:           reading.messages,
              recipients:         reading.recipients,
              maxMessages:        reading.maxMessages,
              maxRecipients:      reading.maxRecipients,
              windowMs:           reading.windowMs,
              messagesExceeded:   reading.messagesExceeded === true,
              recipientsExceeded: reading.recipientsExceeded === true,
            },
          });
          // RFC 6585 section 4 pairs 429 with the wait, and RFC 9110
          // section 10.2.3 takes the wait in seconds. The window is what
          // a client has to sit out, rounded up so a value of zero is
          // never sent for a wait that has not finished. It comes off the
          // reading the gate already took: a second reading here would
          // count the message twice.
          res.setHeader("Retry-After",
            String(Math.ceil((reading.windowMs || 0) / b.constants.TIME.seconds(1))));
          _sendProblem(res, {
            status: 429,
            type:   SEND_PROBLEM.ceiling,
            title:  "This credential has reached its ceiling for the current window",
            detail: _faultForDisplay(sendErr),
          });
          return false;
        }
        if (refusalCode === LISTENER_CODES.sendingCredentialCeilingUnreadable) {
          // A ceiling this server cannot measure has not been shown to be
          // clear, so the message is refused rather than relayed on the
          // reading that could not be taken. The credential verified a
          // moment ago, so what reaches here is a row that stopped being
          // readable in between, which is the operator's to repair and
          // not the sender's to work around. `503` and a retry say
          // exactly that, and the reservation is given back so the same
          // key works once it is repaired.
          _sendProblem(res, {
            status: 503,
            type:   SEND_PROBLEM.ceilingUnreadable,
            title:  "This credential's ceiling could not be read",
            detail: "The message was not sent. This server could not read the send ceiling " +
              "for the credential on " + scope.domain + ", and a ceiling it cannot measure " +
              "has not been shown to be clear. The operator's audit trail names what is " +
              "wrong with the record.",
          });
          return false;
        }
        if (refusalCode === LISTENER_CODES.sendingCredentialStopped) {
          // Revoked, expired, or issued for a domain this server no
          // longer hosts, decided between the request that verified it
          // and the message it was about to send. Permanent rather than
          // temporary: each of the three is a decision somebody made,
          // and an application retrying will not undo it.
          res.setHeader("WWW-Authenticate", "Bearer");
          _sendProblem(res, {
            status: 401,
            type:   SEND_PROBLEM.credential,
            title:  "That credential is no longer one this server sends for",
            detail: "The message was not sent. The credential stopped standing between the " +
              "moment it was checked and the moment this message was composed. The audit " +
              "trail records which of a revocation, an expiry or a withdrawn domain it was.",
          });
          return false;
        }

        // The author binding refuses here, and it is the same call the
        // submission listener applies to every message it accepts. What
        // it throws carries the SMTP reply it asked for, so the class is
        // read off that rather than off the message text: 5.7.1 is an
        // address the identity does not hold and 5.6.0 is a header block
        // naming no single readable author. Both are the caller's to fix
        // and neither is a server fault.
        var refusedAuthor = sendErr && sendErr.smtpCode === "550";
        answer = {
          problem: {
            status: refusedAuthor ? 403 : 502,
            type:   refusedAuthor ? SEND_PROBLEM.author : SEND_PROBLEM.undeliverable,
            title:  refusedAuthor
              ? "That author is not one this credential may write"
              : "That message was not handed to the outbound path",
            // The far side chose these words, and the answer they land
            // in is stored for a client that retries under the same
            // idempotency key, so the screen runs where the value is
            // built rather than where it is written out.
            detail: _faultForDisplay(sendErr),
          },
        };
      }
      // Settled whichever way it went, because the composer was entered
      // and a message may have left. A client retrying under this key
      // reads the answer this request produced rather than sending again.
      _settleReplay(recordKey, answer);
      _writeSendAnswer(res, answer);
      return true;
    }

    // ---- Sign in ----

    // The page a reader gets instead of the form, and instead of the
    // answer to a post, when the connection cannot carry a password. It
    // renders no password field, so the credential the refusal is about
    // never reaches the wire in the first place.
    function _refuseTheTransport(req, res, address) {
      _page(req, res, "sign-in", {
        address:          address,
        problem:          TRANSPORT_REFUSAL,
        transportRefused: true,
      }, { status: 403 });
    }

    router.get("/sign-in", function (req, res) {
      if (!_transportCarriesCredentials(req)) { _refuseTheTransport(req, res, ""); return; }
      if (req.user) { res.redirect(_inboxPath(req.user)); return; }
      _page(req, res, "sign-in", { address: "", problem: null });
    });

    router.post("/sign-in", signInLimit, async function (req, res) {
      // Before the body is read and before anything is verified. The
      // password is already spent by the time it arrives here, and what
      // is left to protect is everything after it: no verification, so
      // the account's failure budget is not spent by a request that was
      // never going to be honored, and no session, so the trail does not
      // record a sign-in the browser will discard the cookie for.
      if (!_transportCarriesCredentials(req)) { _refuseTheTransport(req, res, ""); return; }
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

    // The root, which is three answers rather than one.
    //
    // A signed-in reader is sent to their own mailbox. Publishing the
    // front page does not take that shortcut away, so an operator who
    // types the bare hostname lands in their mail rather than on a page
    // about the software they are already running.
    //
    // A stranger gets the front page when it is published. When it is
    // not, the gate that answers them is the same middleware every other
    // private route is mounted with, rather than a second reading of the
    // same rule written out here: it answers a browser with a redirect to
    // the sign-in page and a caller asking for JSON with a 401. It is
    // never reached with a session in hand, so the callback below is a
    // way back to the sign-in page rather than a second policy.
    router.get("/", function (req, res) {
      if (req.user) { res.redirect(_inboxPath(req.user)); return; }
      if (!_publicSiteEnabled()) {
        requireAccount(req, res, function () { res.redirect(_path("/sign-in")); });
        return;
      }
      _sitePage(req, res);
    });

    // The reference wiki. Every page sits at most two segments below
    // `/wiki`, so these three patterns reach all of them. Each is a GET
    // route, and the public navigation and the sitemap list `/wiki` only
    // while a GET route is registered for exactly that path.
    //
    // When the wiki could not be built, no route is registered. The
    // answer is prefix middleware, which the route table does not carry,
    // so the navigation and the sitemap leave `/wiki` out while every GET
    // at or below it answers 503.
    if (reference !== null) {
      router.get("/wiki", _referencePage);
      router.get("/wiki/:section", _referencePage);
      router.get("/wiki/:section/:name", _referencePage);
    } else {
      router.use(wiki.BASE_PATH, _referenceUnavailable);
    }

    // The mailbox. Which folder is being read comes off the query string,
    // because a mailbox name carries the hierarchy delimiter and may carry
    // a backslash, and neither survives a path segment (see `_folderQuery`).
    //
    // A request naming no folder is the mailbox itself, and the mailbox
    // opens at the inbox. A request naming a folder that matches nothing
    // is a refusal: answering with the inbox instead would show mail the
    // reader did not ask for under a heading saying they did.
    router.get(MAIL_PATH, requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var query = _queryOf(req);
      var name = _folderName(query.folder);
      if (name.length === 0) { res.redirect(_inboxPathFrom(folders)); return; }
      var folder = _findFolder(folders, name);
      if (!folder) {
        _fail(req, res, 404, "No such folder", "This account has no folder named " + name + ".");
        return;
      }
      var before = _cursorFrom(query.before);
      var page = await _pageBefore(account, folder, before, null);
      var messages = await _summarize(account, folder, page.rows);
      // The mailbox this account owns, against the cap set on the
      // account. `agent.quota` is not an alternative: it takes a wire
      // folder name, which belongs to every account that has one, so it
      // answers for a folder and names no cap. The append path measures
      // every folder against the account's cap, so a figure shown beside
      // that cap has to be the same total.
      var quota = mailbox.accountQuota(_actorFor(account));
      var percent = _percent(quota.usedBytes, quota.capBytes);
      var base = _folderPath(folder);
      _page(req, res, "mailbox", {
        folders:      _decorateFolders(folders, folder.name),
        folder:       folder,
        messages:     messages,
        empty:        messages.length === 0,
        olderHref:    page.hasOlder && page.olderThan !== null
          ? _href(_withQuery(base,
            "before=" + encodeURIComponent(_cursorText(page.olderThan)))) : "",
        newestHref:   before !== null ? _href(base) : "",
        actionHref:   _href(_actionPath(folder)),
        quotaUsed:    _byteSize(quota.usedBytes),
        quotaCount:   quota.usedCount,
        quotaCap:     quota.capBytes ? _byteSize(quota.capBytes) : "",
        quotaPercent: percent,
        quotaBucket:  _bucket(percent),
        searchQuery:  "",
      });
    });

    router.post(MAIL_PATH + "/actions", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var actor = _actorFor(account, folders);
      var name = _folderName(_queryOf(req).folder);
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
        var destination = _findFolder(folders, _folderName(body.destination));
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

    // The octets one blob id names, read under this account's own scope,
    // with the name they are served under, or null.
    //
    // Both readings are the ones this surface already has. `_locateFolder`
    // asks the agent for the identifier in each folder the account holds,
    // so an identifier another account holds resolves to no folder here
    // exactly as one nothing holds does, and the readers below then open
    // the message under the same actor. A part comes from `_fileLeaves`,
    // which is the single reading of what counts as a file on this
    // server: the conversation page lists exactly these parts, the
    // `attachments` of an `Email/get` name exactly these parts, and the
    // mark written when the message was filed counts exactly these
    // parts, so a blob id cannot reach something none of them admits.
    //
    // The name is the one the message carries rather than the one the
    // URL carries. RFC 8620 section 6.2 lets a client put a name in the
    // download URL, and a response built from it would let a client
    // decide what a receiver saves the octets as, which is a decision
    // that belongs to the message.
    async function _blobOctets(account, ref) {
      var folders = _foldersFor(account);
      var folder = await _locateFolder(account, folders, ref.objectId);
      if (!folder) return null;
      var actor = _actorFor(account, folders);
      if (ref.partNumber === null) {
        var octets = _octetsOf(actor, folder, ref.objectId);
        if (octets === null || octets.bytes === null) return null;
        return { bytes: octets.bytes, name: MESSAGE_BLOB_FILENAME };
      }
      var files = _fileLeaves(actor, folder, ref.objectId);
      for (var i = 0; i < files.leaves.length; i += 1) {
        if (files.leaves[i].number === ref.partNumber) {
          return { bytes: files.leaves[i].part.leaf.body, name: files.leaves[i].name };
        }
      }
      return null;
    }

    // The only refusal the route that serves a blob answers with.
    //
    // It takes no argument for the reason the browser route's refusal
    // takes none. Every way a blob id can fail to name octets this
    // account may read produces this call, so an accountId the actor is
    // not enumerated for, an identifier another account holds, an
    // identifier nothing holds, a part number nothing holds, a part that
    // is the message's own text, a message above the octet read bound
    // and an id outside the RFC 8620 section 1.2 grammar are one
    // response, byte for byte. Two refusals a caller can tell apart
    // answer the question "does this name something on this server",
    // which is a different question from "does it name something of
    // mine", and a signed-in account walking identifiers would learn
    // which ones name other people's mail.
    //
    // RFC 8620 section 6.2 names no problem type for this endpoint, so
    // the document carries the RFC 9457 default rather than a urn
    // invented here for a client to match on.
    function _failBlob(res) {
      b.problemDetails.send(res, {
        status: 404,
        title:  "No such blob",
        detail: "No blob of that id is readable by this account.",
      });
    }

    // What one message carries, as the conversation page shows it.
    //
    // It returns three answers rather than one, because the reader's next
    // move differs across all three. A message with files gets the rows.
    // A message this server did not open gets a sentence naming the
    // bound, because a reader looking at a blank list would read it as a
    // message that carries nothing. A message whose structure does not
    // parse gets its own sentence, because that is a fault in the stored
    // message rather than a rule this server is applying.
    //
    // The route below serves exactly what this function lists. A part
    // absent from these rows is a part that route answers 404 for, so the
    // two empty answers bound what a request can reach.
    function _filesOn(actor, folder, objectId) {
      var files = _fileLeaves(actor, folder, objectId);
      if (files.reason === "unopened") {
        return { rows: [], note: "This message is larger than " + SOURCE_READ_BOUND_TEXT +
          ", so it is not opened here and the files on it are not listed." };
      }
      if (files.reason === "unparsed") {
        // The parse refusal names a cap or a malformed boundary, and
        // neither is something the reader can act on. What they can act
        // on is knowing the list is empty because the message could not
        // be read rather than because it is bare.
        return { rows: [], note: "The structure of this message could not be read, so the " +
          "files on it are not listed. Its text is shown above." };
      }
      var rows = [];
      for (var i = 0; i < files.leaves.length; i += 1) {
        rows.push({
          // The screen runs here because a stranger chose this name and a
          // person is about to read it. `_dispositionFor` builds the name
          // the response serves the same part under, separately.
          name: files.leaves[i].name.length > 0
            ? _headerText(files.leaves[i].name)
            : "a file the sender did not name",
          type: _shownMediaType(files.leaves[i].part.leaf.contentType),
          size: _byteSize(files.leaves[i].part.leaf.body.length),
          href: _href(_partPath(folder, objectId, files.leaves[i].number)),
        });
      }
      return { rows: rows, note: "" };
    }

    router.get(MAIL_PATH + "/:objectId", requireAccount, async function (req, res) {
      var account = req.user;
      var actor = _actorFor(account);
      var folders = _foldersFor(account);
      var name = _folderName(_queryOf(req).folder);
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
        // Per message as well, and for the same reason the body is: a
        // conversation is several messages and a file can be on any of
        // them, so a list built for the opened one alone would leave the
        // reader unable to see, let alone reach, a file on the message
        // above it. It costs one octet read per message in the thread,
        // bounded by the read bound each of those reads carries.
        var files = _filesOn(actor, folder, message.objectid);
        conversation.push({
          blockedCount: rendered.blockedCount,
          imagesHref:   rendered.blockedCount > 0
            ? _href(_withQuery(_messagePath(folder, message.objectid), "images=on")) : "",
          parts:      files.rows,
          partCount:  files.rows.length,
          partsLabel: _counted(files.rows.length, "file on this message",
            "files on this message"),
          partsNote:  files.note,
          objectId:  message.objectid,
          subject:   _headerText(_str(message.subject, "(no subject)")),
          from:      _displayName(message.from),
          fromAddr:  _shownAddress(message.from),
          initial:   _initial(message.from),
          // The recipient list is a header a stranger wrote, like the
          // subject above it and the display name beside it, and it is
          // the line a reader checks to see whether a message was
          // addressed to them or to a list they are on.
          to:        _headerText(_str(message.to, "")),
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
        backHref:     _href(base),
        actionHref:   _href(_actionPath(folder)),
        objectId:     objectId,
        replyHref:    _href(_composePath(folder, objectId, "reply")),
        replyAllHref: _href(_composePath(folder, objectId, "reply-all")),
        forwardHref:  _href(_composePath(folder, objectId, "forward")),
        moveTargets:  folders.filter(function (f) { return f.name !== folder.name; }),
      }, showImages ? { headers: { "Content-Security-Policy": CSP_WITH_IMAGES } } : undefined);
    });

    // One file off one message, as the octets the sender encoded.
    //
    // ONE REFUSAL. A folder this account does not hold, an identifier it
    // does not hold, a part number no message holds, a number that is not
    // one, a message this server does not open and a part that is the
    // message's own text all answer with the same page. A refusal that
    // told them apart would answer the question "does this name something
    // on this server", which is a different question from "does it name
    // something of mine", and a signed-in account walking identifiers
    // would learn which ones name other people's mail.
    //
    // WHAT THE RESPONSE SAYS IT IS. Every part is served under one media
    // type, and it is not the one the sender declared. The page shows the
    // sender's claim beside the name, and no response header carries it,
    // because a header carrying it would let the sender decide what a
    // browser does with the response: a part claiming `text/html` and
    // served as one is a document rendering on the origin this reader's
    // session cookie is scoped to. RFC 2046 section 4.5.1 has a receiver
    // treat bytes it cannot identify as `application/octet-stream`, and
    // `nosniff` stops a browser reading the content and deciding
    // otherwise.
    //
    // The `nosniff` header is also written by the security middleware on
    // every response this application sends. It is stated here as well,
    // on the one response that carries octets a stranger chose, so the
    // guarantee does not depend on a chain that is configured elsewhere.
    router.get(MAIL_PATH + "/:objectId/parts/:partId", requireAccount,
      async function (req, res) {
        var account = req.user;
        var actor = _actorFor(account);
        var folder = _findFolder(_foldersFor(account),
          _folderName(_queryOf(req).folder));
        var objectId = _str(req.params.objectId, "");
        var partId = _str(req.params.partId, "");
        // The grammar first, before anything opens a message. A value
        // outside it names a part no message this server reads can hold,
        // so there is nothing to look up and nothing to spend a read on.
        if (!folder || objectId.length === 0 || !PART_ID_RE.test(partId)) {
          _failPart(req, res);
          return;
        }

        // A message this server did not open and a structure that did not
        // parse both offer no part, which is the same answer as a part
        // number nothing holds, and the page this was reached from
        // already says which of the two it was.
        var files = _fileLeaves(actor, folder, objectId);
        var wanted = null;
        for (var i = 0; i < files.leaves.length; i += 1) {
          if (files.leaves[i].number === partId) wanted = files.leaves[i];
        }
        if (wanted === null) {
          _failPart(req, res);
          return;
        }

        var body = wanted.part.leaf.body;
        await b.render.stream(res, [body], _renderOpts(req, {
          headers: {
            "Content-Type":           "application/octet-stream",
            "Content-Disposition":    _dispositionFor(wanted.name),
            "Content-Length":         String(body.length),
            "X-Content-Type-Options": "nosniff",
          },
        }, false));
      });

    // ---- Search ----

    router.get("/search", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var query = _queryOf(req);
      var term = _str(query.q, "");
      var scope = _folderName(query.folder);
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
        var page = await _pageBefore(account, folder, null, { text: term });
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
        actionHref:  folder ? _href(_actionPath(folder)) : "",
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
    function _composeScope(account, folders, draft, chosen, problem, sourceNote) {
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
        sourceNote:      sourceNote || null,
        fromAddr:        showing,
        authors:         authors,
        mayChooseAuthor: authors.length > 1,
      };
    }

    // What a draft of a message above MAX_SOURCE_READ_BYTES is missing,
    // shown above the form. The mailbox does not open such a message, so
    // a reply is addressed from its From and To alone and a forward
    // quotes its stored text instead of attaching it.
    function _unopenedSourceNote(forwarding) {
      return forwarding
        ? "This message is larger than " + SOURCE_READ_BOUND_TEXT + ", so it is quoted " +
          "below instead of being attached. Its own attachments are not included."
        : "This message is larger than " + SOURCE_READ_BOUND_TEXT + ", so its Reply-To and " +
          "Cc fields were " +
          "not read. The recipients below come from its From and To fields; check them " +
          "before you send.";
    }

    // The message a forward attaches, read again for the account posting
    // the form. `forwardOf` and `forwardFolder` arrive as form fields, so
    // they name nothing until the mailbox answers for this account: a
    // folder it does not own, an identifier it does not hold and a
    // message too large to open are each refused with a sentence for the
    // form, and nothing is attached or sent.
    //
    // Answers `{ attachments }` on success and `{ problem }` on a refusal.
    // The attachment is the composer's own forward derivation over the
    // octets, so the part the post sends is the part `compose.forward`
    // builds.
    async function _forwardAttachment(account, folders, draft) {
      if (draft.forwardOf.length === 0) return { attachments: undefined, problem: null };
      var folder = _findFolder(folders, _folderName(draft.forwardFolder));
      var read = folder
        ? mailbox.readMessageSource(_actorFor(account), folder.name, draft.forwardOf)
        : null;
      if (!read) {
        return { attachments: undefined, problem: "The message you are forwarding is no " +
          "longer in that folder, so there is nothing to attach. Open it again and forward " +
          "it from there." };
      }
      if (read.bytes === null) {
        return { attachments: undefined, problem: "The message you are forwarding is larger " +
          "than " + SOURCE_READ_BOUND_TEXT + ", so it cannot be attached." };
      }
      var carried = await composer.forward({ original: read.bytes, draft: true });
      return { attachments: carried.attachments, problem: null };
    }

    router.get("/compose", requireAccount, async function (req, res) {
      var account = req.user;
      var folders = _foldersFor(account);
      var query = _queryOf(req);
      var draft = {
        to: "", cc: "", bcc: "", subject: "", text: "", inReplyTo: "", references: "",
        forwardOf: "", forwardFolder: "",
      };
      var sourceNote = null;
      var source = _str(query.source, "");
      var mode = _str(query.mode, "");
      if (source.length > 0) {
        var folder = _findFolder(folders, _folderName(query.folder));
        // The message as the mailbox holds it: its own octets, and the
        // stored row with `Reply-To` and `Cc` read back off those octets.
        // The read sets no flag and moves no modification sequence. A
        // message above MAX_SOURCE_READ_BYTES is not opened, and the
        // composer then derives from the row alone.
        var read = folder
          ? mailbox.readMessageSource(_actorFor(account), folder.name, source)
          : null;
        if (read) {
          var message = read.message;
          // The derivation is the composer's. A reply written on this
          // form and a reply the composer sends outright answer the
          // same people, carry the same subject and hang off the same
          // point in the conversation, because one function decides all
          // three. Deriving them here as well would be a second answer
          // to which conversation a reply belongs to, and the two would
          // disagree on the day one of them was corrected.
          //
          // The author comes off her own copy list by mailbox rather
          // than by spelling, which is the composer's rule: the sender
          // chose how to write the address, and `Alice@Example.com` and
          // `alice+list@example.com` are the same mailbox the routing
          // layer delivered to.
          //
          // Every address she holds goes over, not just the one the
          // reply is written under. A message to a departmental alias
          // reached her at the alias, so a copy list measured against
          // her own address alone would copy her back to herself under
          // the alias she was addressed at. The set is the same one the
          // author picker offers and the same one submission binds the
          // `From` header against.
          //
          // The composer takes `original` when it is there and `message`
          // otherwise, so an unopened message is answered from the row.
          var derived = mode === "forward"
            ? await composer.forward({ original: read.bytes, message: message, draft: true })
            : await composer.reply({
              original: read.bytes,
              message:  message,
              from:     account.address,
              identities: _identitiesFor(account).map(function (held) {
                return held.address;
              }),
              replyAll: mode === "reply-all",
              draft:    true,
            });
          draft.inReplyTo  = derived.inReplyTo || "";
          draft.references = derived.references.join(" ");
          draft.subject    = _headerText(derived.subject);
          // The form's recipient fields carry addresses and no display
          // names. A display name is text the sender chose, and the
          // field is where the account holder reads back who they are
          // about to write to.
          draft.to = (derived.to || []).map(_bareAddress)
            .filter(function (addr) { return addr.length > 0; }).join(", ");
          draft.cc = (derived.cc || []).map(_bareAddress)
            .filter(function (addr) { return addr.length > 0; }).join(", ");
          // Two blank lines above the quotation, so the reply starts
          // where the cursor lands.
          draft.text = "\n\n" + _screenedDraftText(derived.text) + "\n";
          // A forward of an opened message attaches it as a
          // message/rfc822 part and quotes none of it. The form carries
          // which message that is, and the post reads it again for this
          // account before attaching anything.
          if (mode === "forward" && read.bytes !== null) {
            draft.forwardOf     = read.objectid;
            draft.forwardFolder = folder.name;
          }
          if (read.withheld !== null) sourceNote = _unopenedSourceNote(mode === "forward");
        }
      }
      _page(req, res, "compose",
        _composeScope(account, folders, draft, account.address, null, sourceNote));
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
        forwardOf:     _str(body.forwardOf, ""),
        forwardFolder: _str(body.forwardFolder, ""),
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

      var forwarded = await _forwardAttachment(account, folders, draft);
      if (forwarded.problem !== null) {
        _page(req, res, "compose",
          _composeScope(account, folders, draft, author.address, forwarded.problem),
          { status: 400 });
        return;
      }

      try {
        await composer.send({
          from:         author.address,
          // The return path stays the account's own address whatever the
          // author is. Bounces belong in the mailbox of whoever pressed
          // send rather than in a shared one nobody reads. The submission
          // listener would take the alias here too, since one set answers
          // the envelope and the author alike, so this is a choice about
          // where a bounce lands rather than a limit.
          //
          // It costs SPF alignment and not DKIM alignment. `compose.send`
          // signs for the domain in the From it builds, so a message
          // written under an alias in a SECOND hosted domain leaves signed
          // for the domain it displays and aligns under DKIM. SPF
          // authenticates the envelope domain, which is the account's, so
          // that half does not align. DMARC passes on either.
          envelopeFrom: account.address,
          to:           recipients,
          cc:           copies,
          bcc:          blind,
          subject:      draft.subject,
          text:         draft.text,
          attachments:  forwarded.attachments,
          inReplyTo:    draft.inReplyTo.length > 0 ? draft.inReplyTo : undefined,
          references:   draft.references.length > 0 ? draft.references.split(/\s+/) : undefined,
        }, { actor: _actorFor(account) });
      } catch (sendErr) {
        // The far side's own reply text, on its way to a person and to
        // the log in one step, so it is screened once here.
        var refusedBy = _faultForDisplay(sendErr);
        log.error("outbound refused for " + account.address + ": " + refusedBy);
        _page(req, res, "compose",
          _composeScope(account, folders, draft, author.address, refusedBy),
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
      // `dkim.list()` answers with one row per selector, carrying the
      // domain it belongs to. It has no nested `selectors` array, so a
      // count that summed one read undefined on every row and published a
      // zero on every server: an operator with four live selectors was
      // told there were none, which reads as a server that cannot sign.
      // The other three tiles count their own rows the same way.
      var selectorCount = keyed.length;
      _page(req, res, "admin/overview", {
        nav:            _adminNav("overview"),
        domainCount:    domains.length,
        accountCount:   accounts.length,
        queueDepth:     waiting.length,
        selectorCount:  selectorCount,
        pendingDomains: pending.map(function (d) { return { domain: d.domain }; }),
        hasPending:     pending.length > 0,
        publicSiteOn:   _publicSiteEnabled(),
      });
    });

    // The front page switch. One press either way and reversible by the
    // button that replaces it, so it asks for nothing first: the console
    // asks before an act that destroys something or takes a surface away
    // from people who are using it, and this is neither.
    router.post("/admin/site", requireAccount, requireAdmin, async function (req, res) {
      var action = _str(_bodyOf(req).action, "");
      if (action !== "publish" && action !== "hide") {
        res.redirect(_path("/admin"));
        return;
      }
      await store.settings.set({
        name:      PUBLIC_SITE_SETTING,
        value:     action === "publish",
        changedBy: req.user.address,
        reason:    action === "publish"
          ? "front page published from the console"
          : "front page withdrawn from the console",
      });
      _back(res, "/admin", action === "publish" ? "site-published" : "site-hidden");
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
          ? _href("/admin/accounts?offset=" + (offset + limit) + "&limit=" + limit) : "",
        prevHref: offset > 0
          ? _href("/admin/accounts?offset=" + Math.max(0, offset - limit) + "&limit=" + limit) : "",
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
          // The three verbs that take this console away from somebody are
          // measured against what would be left, and the same measurement
          // answers for an account that administers nothing: excluding one
          // changes no count, so the caller's own row keeps the answer
          // above zero.
          //
          // The measurement excludes the row resolved above rather than
          // the field as it arrived. The field may carry an address, which
          // `accounts.get` resolves and which matches no account id, so a
          // measurement keyed on it would count the account it is about.
          //
          // Revoking the role joins the other two here rather than growing
          // a guard of its own, because it is the same question asked about
          // the same set. It names no command line verb, and the absence is
          // the point: this console is the only place the role is granted,
          // so the way past this refusal is to give it to somebody else.
          if (action === "suspend" || action === "archive" || action === "revoke-role") {
            var stranding = _strandingRefusal({
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
            if (stranding !== null) {
              await _renderAccounts(req, res, stranding, 400, ADMIN_PAGE_SIZE, 0);
              return;
            }
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
        // The role is not granted here. A grant from this console goes
        // through `grant-role` on an account that already exists, which
        // asks for a reason and files `account.role_granted`. Creating an
        // account holding the role would do neither, so a post naming the
        // role in any form is refused rather than creating an ordinary
        // account the operator did not ask for.
        if (body.isAdmin !== undefined) {
          await _renderAccounts(req, res,
            "Nothing has been created. An account is created without the operator role, and " +
            "the role is given afterwards with Give it the console on its row, which asks for " +
            "the reason the audit trail records against the grant.",
            400, ADMIN_PAGE_SIZE, 0);
          return;
        }
        await store.accounts.create({
          address:     _str(body.address, "").toLowerCase(),
          displayName: _str(body.displayName, ""),
          password:    typeof body.password === "string" ? body.password : "",
          quotaBytes:  _int(body.quotaBytes, 0, 0, Number.MAX_SAFE_INTEGER),
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

    // The alias one request names, read back off the identity layer. A
    // row removed or changed from another window since this list was
    // drawn is a request that refuses rather than one that acts on a
    // page which has gone stale, and every value the pages below name
    // comes from this read rather than from the request.
    async function _heldAlias(id) {
      return _asArray(await store.aliases.list({ includeDisabled: true }))
        .filter(function (row) { return row.id === id; })[0] || null;
    }

    router.post("/admin/aliases", requireAccount, requireAdmin, async function (req, res) {
      var body = _bodyOf(req);
      var action = _str(body.action, "");
      if (action !== "add" && action !== "remove" &&
          action !== "disable" && action !== "enable") {
        await _renderAliases(req, res, null, 0);
        return;
      }
      try {
        // Turning an alias off and back on again. Disabling is the
        // reversible answer when an address is being abused or a role
        // has moved: the row and its history stay, resolution stops
        // offering the destination at once, and the button beside it
        // puts it back. Removing deletes the row, so reaching for it to
        // silence an address for a fortnight loses the address.
        //
        // Neither direction asks for a typed confirmation, which is the
        // shape every verb undone by the button next to it takes on
        // these pages. Both ask for the reason, because the identity
        // layer records one on the row either way and a sentence
        // supplied here would answer that with words nobody chose.
        if (action === "disable" || action === "enable") {
          var target = await _heldAlias(_str(body.id, ""));
          if (target === null) {
            await _renderAliases(req, res,
              "This server holds no such alias. Nothing has been changed. Open the list " +
              "again: it may have been removed from another window.", 400);
            return;
          }
          var statusAsk = _aliasStatusAsk(action, target);
          if (_stillAsking(req, res, body, statusAsk)) return;
          await store.aliases.setStatus({
            id:     target.id,
            status: action === "disable" ? "disabled" : "active",
            reason: _str(body.reason, ""),
          });
          _back(res, "/admin/aliases",
            action === "disable" ? "alias-disabled" : "alias-enabled");
          return;
        }
        if (action === "remove") {
          // The row is resolved before anything is asked, because the
          // page has to name what it is about to remove and because an
          // alias removed from another window since this list was drawn
          // is a request that should refuse rather than one that should
          // be confirmed.
          var id = _str(body.id, "");
          var rows = _asArray(await store.aliases.list({ includeDisabled: true }));
          var held = rows.filter(function (row) { return row.id === id; })[0] || null;
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
          // The value typed back has to name this row and no other. The
          // legs of a fan-out share their address, and the legs of a
          // catch-all delivering to several destinations share their
          // domain, so while another row shares the name the destination
          // is what is typed. The count is taken on every post rather than
          // carried from the page, so a sibling removed in the meantime
          // changes what is asked for and the post is asked again.
          var legs = rows.filter(function (row) { return row.address === held.address; });
          var shared = legs.length > 1;
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
            phrase:     shared ? held.destination : named,
            noun:       shared ? "destination" : (held.isCatchAll ? "domain" : "address"),
            prompt:     shared
              ? "Type the destination this leg delivers to, to confirm"
              : (held.isCatchAll ? "Type the domain to confirm" : "Type the address to confirm"),
            promptHint: shared
              ? named + " delivers to " + legs.length + " destinations, one row each, so the " +
                "destination is what names this row. Nothing else confirms this."
              : "Exactly as it is written above. Nothing else confirms this.",
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

    // -----------------------------------------------------------------
    // Sending credentials: what each one has spent, and the two acts on
    // its ceilings.
    // -----------------------------------------------------------------

    // The window one credential has spent, taken once through the
    // registry's own reader.
    //
    // A credential whose row no longer parses refuses the reading rather
    // than answering about ceilings taken off a row somebody edited, and
    // that refusal is kept to the row: one unreadable credential in a
    // domain is not a reason to answer the operator with a failed page,
    // and the credential that cannot be read is the one they most need
    // in front of them.
    async function _credentialCeilingRow(record) {
      var row = {
        id:             record.id,
        bounceMailbox:  record.bounceMailbox === null ? "" : record.bounceMailbox,
        hasReading:     false,
        readingProblem: "",
        messages:       0,
        recipients:     0,
        maxMessages:    0,
        maxRecipients:  0,
        windowMinutes:  0,
        atCeiling:      false,
        crossed:        "",
        summary:        record.id + ": this server cannot read its ceilings",
      };
      var reading;
      try {
        reading = await store.credentials.counters.read(record.id);
      } catch (readErr) {
        row.readingProblem = _refusalText(readErr,
          "This credential's window could not be read on this server.");
        return row;
      }
      row.hasReading    = true;
      row.messages      = reading.messages;
      row.recipients    = reading.recipients;
      row.maxMessages   = reading.maxMessages;
      row.maxRecipients = reading.maxRecipients;
      row.windowMinutes = reading.windowMs / b.constants.TIME.minutes(1);
      row.atCeiling     = reading.exceeded === true;
      // One line naming the credential and where it stands, for the
      // places a form has to offer it as a single value to pick.
      row.summary = record.id + ": " + _ceilingLine(reading);
      // Which of the two, because they are set for different reasons and
      // an operator raising the wrong one changes nothing.
      row.crossed = reading.messagesExceeded === true
        ? (reading.recipientsExceeded === true ? "both ceilings" : "the message ceiling")
        : (reading.recipientsExceeded === true ? "the recipient ceiling" : "");
      return row;
    }

    // Which domain the page is reading. A credential speaks for one
    // domain and the registry refuses a listing that names none, so the
    // page always reads one: what the query names when it names a hosted
    // domain, and otherwise the first this server holds.
    //
    // A query naming a domain this server does not host is answered
    // about rather than folded into the default. An operator who
    // mistyped one would otherwise read another domain's credentials
    // under the name they typed.
    function _pickCredentialDomain(hosted, asked) {
      if (asked.length === 0) {
        return { domain: hosted.length > 0 ? hosted[0] : "", problem: null };
      }
      var read = address.parseDomain(asked);
      var wanted = read.ok ? read.domain : "";
      if (wanted.length > 0 && hosted.indexOf(wanted) !== -1) {
        return { domain: wanted, problem: null };
      }
      return {
        domain:  "",
        problem: "This server does not host that domain, so it has no sending credentials " +
          "to read. Pick one of the domains below.",
      };
    }

    async function _renderCredentials(req, res, problem, status, asked) {
      var hosted = _asArray(await store.domains.list({ status: "active" }))
        .map(function (d) { return d.domain; });
      var picked = _pickCredentialDomain(hosted, _str(asked, ""));
      var rows = [];
      if (picked.domain.length > 0) {
        var listed = _asArray(await store.credentials.list({ domain: picked.domain }));
        for (var i = 0; i < listed.length; i += 1) {
          rows.push(await _credentialCeilingRow(listed[i]));
        }
      }
      _page(req, res, "admin/credentials", {
        nav:     _adminNav("credentials"),
        domains: hosted.map(function (name) {
          return { domain: name, current: name === picked.domain };
        }),
        hasDomains:     hosted.length > 0,
        domain:         picked.domain,
        hasDomain:      picked.domain.length > 0,
        credentials:    rows,
        hasCredentials: rows.length > 0,
        // The bounds a ceiling and a window may be set between, rendered
        // from the registry's own constants. A form naming a bound this
        // server does not hold sends an operator to type a number that
        // is refused after they have pressed the button.
        maxCeiling:       credentialsModule.MAX_CEILING,
        minWindowMinutes: credentialsModule.MIN_WINDOW_MS / b.constants.TIME.minutes(1),
        maxWindowMinutes: credentialsModule.MAX_WINDOW_MS / b.constants.TIME.minutes(1),
        problem:          problem || picked.problem || null,
      }, status ? { status: status } : undefined);
    }

    router.get("/admin/credentials", requireAccount, requireAdmin,
      async function (req, res) {
        var query = _queryOf(req);
        try {
          await _renderCredentials(req, res, null, 0, _str(query.domain, ""));
        } catch (err) {
          await _renderCredentials(req, res,
            _refusalText(err, "The sending credentials could not be read."), 400, "");
        }
      });

    // One number off the ceilings form.
    //
    // Absent and empty both mean "leave this one alone", because a form
    // is submitted whole and an operator moving one ceiling should not
    // have to retype the other two. Anything written that does not read
    // as a whole number is refused here, naming the field. The BOUND it
    // has to fall inside is the registry's and is refused there, so one
    // layer decides what a ceiling may be and this one only decides
    // whether a number was written at all.
    function _ceilingField(body, name) {
      var written = _str(body[name], "");
      if (written.length === 0) return { named: false, ok: true, value: undefined };
      if (!/^-?[0-9]+$/.test(written)) return { named: true, ok: false, value: undefined };
      return { named: true, ok: true, value: Number(written) };
    }

    // What the registry refused, as a problem document. The registry
    // writes every one of these for a person, so the message is carried
    // across as itself and what is added here is the status and the type
    // a reader branches on.
    function _credentialRefusal(res, refusal, title) {
      var code = (refusal && typeof refusal.code === "string") ? refusal.code : "";
      var status = 400;
      var type   = CREDENTIAL_PROBLEM.ceiling;
      if (code === "store/sending-credential-window-in-use") {
        status = 409;
        type   = CREDENTIAL_PROBLEM.windowInUse;
      } else if (code === "store/no-such-sending-credential") {
        status = 404;
        type   = CREDENTIAL_PROBLEM.notFound;
      } else if (code === "store/no-such-domain" || code === "store/bad-domain") {
        type = CREDENTIAL_PROBLEM.domain;
      } else if (code.indexOf("store/") !== 0) {
        status = 500;
        type   = CREDENTIAL_PROBLEM.refused;
      }
      _sendProblem(res, {
        status: status,
        type:   type,
        title:  title,
        detail: _refusalText(refusal, "This server could not make that change, and the " +
          "server log says what it refused. Nothing was changed."),
      });
    }

    // How a window reads, written as one line for the page that asks
    // before it acts. It is built from the reading the route already
    // took rather than from a second one, so the numbers an operator
    // confirms are the numbers that were measured.
    function _ceilingLine(reading) {
      return reading.messages + " message(s) to " + reading.recipients +
        " recipient(s), against ceilings of " + reading.maxMessages + " and " +
        reading.maxRecipients + " every " +
        (reading.windowMs / b.constants.TIME.minutes(1)) + " minute(s)";
    }

    // The two acts on a credential's ceilings, and what each of them
    // costs.
    //
    // Both name the credential back, for the reason archiving an account
    // types the address. This is one button on a list of rows that all
    // look alike, the rows are named by hexadecimal strings that read
    // like every other hexadecimal string on the page, and neither act
    // can be taken back from here: a window given back cannot be
    // un-given, and mail that left under a raised ceiling has left. The
    // reversible verbs elsewhere in this console are undone by the
    // button beside them, and neither of these is.
    function _credentialAsk(action, record, reading, wanted) {
      if (action === "release-window") {
        return _pending({
          path:   "/admin/credentials",
          action: action,
          carry:  [{ name: "id", value: record.id }],
          title:  "Give the window on " + record.id + " back?",
          summary: "This puts what that credential has sent in the current window back to " +
            "zero.",
          consequence: "The credential for " + record.domain + " sends its full allowance " +
            "again from the moment this is saved, without waiting for the window to roll. " +
            "The mail it already sent is not recalled and the ceilings themselves do not " +
            "move: what changes is only what has been counted against them. A credential " +
            "reaching a ceiling it never used to reach is the shape a stolen one makes, so " +
            "look at what it sent before giving the window back, and replace its secret " +
            "with `blamepost credential rotate " + record.id + " --reason <text>` if the " +
            "traffic is not " +
            "the application's.",
          subjects: [{ name: record.id, detail: "has sent " + _ceilingLine(reading) }],
          phrase:      record.id,
          noun:        "identifier",
          prompt:      "Type the credential's identifier to confirm",
          promptHint:  "Exactly as it is written above. Nothing else confirms this.",
          needsReason: true,
          verb:        "Give the window back",
          fineprint:   "The reason is recorded against " + record.domain + " in the audit " +
            "trail, beside what the window held when it was given back. Leaving this page " +
            "changes nothing.",
        });
      }
      var carry = [{ name: "id", value: record.id }];
      var moves = [];
      if (wanted.maxMessages !== undefined) {
        carry.push({ name: "maxMessages", value: String(wanted.maxMessages) });
        moves.push("the message ceiling from " + record.maxMessages + " to " +
          wanted.maxMessages);
      }
      if (wanted.maxRecipients !== undefined) {
        carry.push({ name: "maxRecipients", value: String(wanted.maxRecipients) });
        moves.push("the recipient ceiling from " + record.maxRecipients + " to " +
          wanted.maxRecipients);
      }
      if (wanted.windowMinutes !== undefined) {
        carry.push({ name: "windowMinutes", value: String(wanted.windowMinutes) });
        moves.push("the window from " +
          (record.windowMs / b.constants.TIME.minutes(1)) + " to " + wanted.windowMinutes +
          " minute(s)");
      }
      return _pending({
        path:   "/admin/credentials",
        action: action,
        // Every value carried is one this server parsed out of the first
        // post and rendered from what it read, and the registry measures
        // each of them against its own bounds again when the act is
        // performed. Nothing the operator typed as prose goes back into
        // the form.
        carry:  carry,
        title:  "Change the ceilings on " + record.id + "?",
        summary: "This changes what that credential may send in one window.",
        consequence: "The credential for " + record.domain + " is measured against the new " +
          "numbers from its next message: " + moves.join(", ") + ". A ceiling is what " +
          "bounds the mail a credential in somebody else's hands sends before anything " +
          "stops it, so raising one widens that and lowering one below what the window " +
          "already holds refuses the credential's next message. What has already been " +
          "counted against the old numbers is not given back by this; the button beside it " +
          "on the list does that.",
        subjects: [{ name: record.id, detail: "has sent " + _ceilingLine(reading) }],
        phrase:      record.id,
        noun:        "identifier",
        prompt:      "Type the credential's identifier to confirm",
        promptHint:  "Exactly as it is written above. Nothing else confirms this.",
        needsReason: true,
        verb:        "Change these ceilings",
        fineprint:   "The reason is recorded against " + record.domain + " in the audit " +
          "trail, beside both readings of every number this moves. Leaving this page " +
          "changes nothing.",
      });
    }

    router.post("/admin/credentials", requireAccount, requireAdmin,
      async function (req, res) {
        var body   = _bodyOf(req);
        var action = _str(body.action, "");
        if (action !== "release-window" && action !== "set-ceilings") {
          _sendProblem(res, {
            status: 400,
            type:   CREDENTIAL_PROBLEM.action,
            title:  "That is not an act this page performs",
            detail: "This page gives a sending credential's window back and changes its " +
              "ceilings. Nothing else posts to it.",
          });
          return;
        }

        // The credential the act names, read back off the registry before
        // anything is asked, so the page names the row this will actually
        // reach rather than a value off the request. A credential whose
        // row no longer parses is refused here: its ceilings are not
        // readable, so there is nothing to move and nothing to measure a
        // release against.
        var id = _str(body.id, "");
        var record;
        try {
          record = await store.credentials.show(id);
        } catch (showErr) {
          _credentialRefusal(res, showErr, "That credential could not be read");
          return;
        }
        if (record === null || record.bindingHolds !== true) {
          _sendProblem(res, {
            status: 404,
            type:   CREDENTIAL_PROBLEM.notFound,
            title:  "No credential on this server answers to that identifier",
            detail: record === null
              ? "Nothing on this volume carries that identifier. Open the credentials page " +
                "again: it may have been withdrawn from another window."
              : "That row is on this volume and this server cannot read it, so its " +
                "ceilings are not ceilings this server can state or move. It refuses every " +
                "message either way. Withdraw it and issue a replacement.",
          });
          return;
        }

        var wanted = { maxMessages: undefined, maxRecipients: undefined,
          windowMinutes: undefined };
        if (action === "set-ceilings") {
          var messages   = _ceilingField(body, "maxMessages");
          var recipients = _ceilingField(body, "maxRecipients");
          var window     = _ceilingField(body, "windowMinutes");
          var unreadable = [
            messages.ok   ? "" : "the message ceiling",
            recipients.ok ? "" : "the recipient ceiling",
            window.ok     ? "" : "the window",
          ].filter(function (name) { return name.length > 0; });
          if (unreadable.length > 0) {
            _sendProblem(res, {
              status: 400,
              type:   CREDENTIAL_PROBLEM.ceiling,
              title:  "That is not a number this page can read",
              detail: "Write " + unreadable.join(" and ") + " as a whole number, or leave " +
                "the box empty to leave that one alone. Nothing has been changed.",
            });
            return;
          }
          if (!messages.named && !recipients.named && !window.named) {
            _sendProblem(res, {
              status: 400,
              type:   CREDENTIAL_PROBLEM.ceiling,
              title:  "Nothing was named to change",
              detail: "Fill in at least one of the message ceiling, the recipient ceiling " +
                "or the window. A change naming none of them would record an operator " +
                "action in the audit trail that never happened.",
            });
            return;
          }
          wanted.maxMessages   = messages.value;
          wanted.maxRecipients = recipients.value;
          wanted.windowMinutes = window.value;
        }

        // The reading the page about to be drawn is built from, taken
        // through the registry's own reader and taken once. Counting the
        // message would be the other call, and a page that asked it
        // would spend a credential's ceiling for having been looked at.
        var reading;
        try {
          reading = await store.credentials.counters.read(record.id);
        } catch (readErr) {
          _credentialRefusal(res, readErr, "That credential's window could not be read");
          return;
        }

        var ask = _credentialAsk(action, record, reading, wanted);
        if (_stillAsking(req, res, body, ask)) return;

        var back = "/admin/credentials?domain=" + encodeURIComponent(record.domain);
        try {
          if (action === "release-window") {
            // No default on the reason. The registry refuses an empty
            // one, and a sentence supplied here would answer that
            // refusal with words nobody chose.
            await store.credentials.counters.release({
              id: record.id, reason: _str(body.reason, ""),
            });
            _back(res, back, "credential-window-released");
            return;
          }
          await store.credentials.setCeilings({
            id:            record.id,
            reason:        _str(body.reason, ""),
            maxMessages:   wanted.maxMessages,
            maxRecipients: wanted.maxRecipients,
            windowMs:      wanted.windowMinutes === undefined
              ? undefined
              : wanted.windowMinutes * b.constants.TIME.minutes(1),
          });
          _back(res, back, "credential-ceilings-set");
        } catch (changeErr) {
          _credentialRefusal(res, changeErr, action === "release-window"
            ? "That window was not given back"
            : "Those ceilings were not changed");
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
          // act on this page that erases key material.
          //
          // The pair is looked up in the selector inventory before
          // anything is asked, and the page names the row found there
          // rather than the two fields as they arrived. A domain and a
          // selector this server holds no active pair under are refused
          // here, before an operator is asked to type anything.
          //
          // The value typed back is the name the pair's record is
          // published at, `<selector>._domainkey.<domain>`. The selector
          // alone is not enough: the default selector is `bp<YYYYMM>`, so
          // every domain keyed in the same month carries the same one, and
          // a press on the next card down would be confirmed by the name
          // the operator meant to type.
          //
          // No reason is asked for. The signer writes its own account of
          // the run into the row it files, and a sentence collected here
          // would either be thrown away or would overwrite the one an
          // incident review actually needs.
          var selector = _str(body.selector, "").toLowerCase();
          var pair = null;
          if (domain.length > 0 && selector.length > 0) {
            pair = _asArray(await dkim.list(domain)).filter(function (row) {
              return row.state === "active" && row.algorithm === "ed25519" &&
                row.selector === selector;
            })[0] || null;
          }
          if (pair === null) {
            await _renderDkim(req, res,
              "This server holds no active signing pair under that selector for that domain. " +
              "Nothing has been retired. Open the list again: the pair may have been retired " +
              "from another window.", 400);
            return;
          }
          var retireAsk = _pending({
            path:    "/admin/dkim",
            action:  action,
            carry:   [
              { name: "domain",   value: pair.domain },
              { name: "selector", value: pair.selector },
            ],
            title:   "Retire the pair signing for " + pair.domain + "?",
            summary: "Both halves of the pair leave signing together.",
            consequence: "The sealed private keys for this pair are erased and nothing " +
              "signs with them again. Their records stay published through the overlap so " +
              "mail already in flight still verifies, and " + pair.domain + " signs with " +
              "whatever pair is left. Retiring the pair a domain is still relying on " +
              "leaves it signing nothing, and there is no way back from this page.",
            subjects: [{ name: pair.dnsName, detail: "the Ed25519 selector " + pair.selector +
              ", and its RSA half" }],
            phrase:     pair.dnsName,
            noun:       "record name",
            prompt:     "Type the record name to confirm",
            promptHint: "Exactly as it is written above. Nothing else confirms this.",
            verb:       "Retire this pair",
            fineprint:  "Withdraw the records themselves only after the overlap has run " +
              "out, which is the last step of a rotation rather than the first. Leaving " +
              "this page changes nothing.",
          });
          if (_stillAsking(req, res, body, retireAsk)) return;
          await dkim.retire({ domain: pair.domain, selector: pair.selector });
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

    // What receivers reported back about mail claiming each hosted
    // domain, and, where this server holds a credential for the zone,
    // what publishing each policy level would change in it.
    //
    // The reading changes nothing. The publishing half is two posts, and
    // both of them are below.
    //
    // The request decides two things and neither of them reaches the
    // store as it was written. The window arrives as a whole number of
    // days already bounded by how long the rows survive, and the domain
    // is resolved against the hosted rows here, so what the store is
    // asked is composed from values this server owns.
    router.get("/admin/dmarc", requireAccount, requireAdmin, async function (req, res) {
      var query = _queryOf(req);

      // The longest window that can answer, read off the handle rather
      // than named in this file. Aggregate rows are destroyed on the
      // retention window the operator configured, so a request for more
      // days than that reads exactly the same rows and would report a
      // wider window than the evidence covers.
      var kept = await store.reports.describe();
      var keptDays = Math.max(DMARC_MIN_DAYS,
        Math.floor(kept.aggregateRetentionMs / b.constants.TIME.days(1)));
      var days = _int(query.days, Math.min(DMARC_DEFAULT_DAYS, keptDays),
        DMARC_MIN_DAYS, keptDays);

      var domains = _asArray(await store.domains.list({}));

      // The domain a request names, resolved against the hosted rows
      // before anything reads it. The derivation used here answers with
      // a verdict rather than throwing, which is what a query string
      // needs: a name this server cannot parse leaves the page reading
      // every domain instead of refusing the request. A name that parses
      // and is not hosted narrows to nothing, so neither the store nor
      // the rendered page ever holds what was asked for.
      var asked = address.parseDomain(_str(query.domain, ""));
      var selected = "";
      for (var d = 0; d < domains.length && selected === ""; d += 1) {
        if (asked.ok && domains[d].domain === asked.domain) selected = domains[d].domain;
      }

      var now = Date.now();
      var rows = _asArray(await store.reports.rollup({
        since: now - b.constants.TIME.days(days),
        until: now,
      }));

      var shownDomains = selected === "" ? domains : domains.filter(function (row) {
        return row.domain === selected;
      });
      var shownRows = selected === "" ? rows : rows.filter(function (row) {
        return row.domain === selected;
      });
      var cards = _dmarcCards(shownDomains, shownRows, now, days);

      // The two listings the counting cannot give, read only once the
      // page has been narrowed to one domain. Both answer about a single
      // domain, and the overview renders a card per hosted domain, so
      // asking there would be one read per card for a list nobody can act
      // on before they have picked a domain. The range handed to them is
      // the one the counting above was read over, so the window control
      // cannot move one reading and leave the other where it was.
      //
      // `selected` is a domain resolved against the hosted rows earlier
      // in this handler, so what reaches the store is a name this server
      // owns rather than the one the request carried.
      var since = now - b.constants.TIME.days(days);
      var failing = null;
      var heard   = null;
      if (selected !== "") {
        failing = await store.reports.failingSources({
          domain: selected, since: since, until: now, limit: DMARC_SOURCE_ROWS,
        });
        heard = await store.reports.reporters({
          domain: selected, since: since, until: now, limit: DMARC_REPORTER_ROWS,
        });
      }

      // Where this domain's policy stands and what publishing each level
      // would be. Read only once the page has been narrowed to one
      // domain, and only where this server holds a credential for the
      // zone: the overview renders a card per hosted domain, and the
      // stepper resolves records and reads the report rows for the one it
      // is asked about.
      //
      // An operator who holds their own DNS gets the page exactly as it
      // was. No stepper runs, no resolver is asked, and no provider is
      // reached, which is the whole of what naming no zone provider
      // means.
      var policy = null;
      if (zone !== null && selected !== "") policy = await _policyCard(selected);

      // One failing sender, as the page shows it. `someAligned` is the
      // reading that separates a relay of the operator's that is
      // misconfigured, which also gets mail through, from a machine that
      // has never aligned anything and is claiming the domain.
      var sourceRows = failing === null ? [] : failing.sources.map(function (one) {
        return {
          sourceIp:    one.sourceIp || "",
          readable:    one.readable === true,
          messages:    one.messages,
          aligned:     one.aligned,
          someAligned: one.aligned > 0,
          windows:     one.windows,
          lastSeen:    _when(one.lastSeen, { dateStyle: "medium" }),
        };
      });

      // One reporting organization, with how long it has been since
      // anything arrived from it. A receiver that stopped reporting and a
      // domain whose mail all aligns read the same on the counting above,
      // and this column is what tells them apart.
      //
      // `organization` is the registered domain the reports passed DMARC
      // for, which is what the row counts as. `orgName` is the name the
      // reports gave themselves, and `otherNames` is how many more names
      // the same domain used.
      var reporterRows = heard === null ? [] : heard.reporters.map(function (one) {
        var silentDays = one.newestAt > 0
          ? Math.floor((now - one.newestAt) / b.constants.TIME.days(1))
          : 0;
        var otherNames = one.names > 1 ? one.names - 1 : 0;
        return {
          organization: one.organization || "",
          orgName:    one.orgName,
          otherNames: otherNames,
          hasOtherNames: otherNames > 0,
          otherNamesLabel: _counted(otherNames, "other name", "other names"),
          reports:    one.reports,
          records:    one.records,
          newest:     _when(one.newestAt, { dateStyle: "medium", timeStyle: "short" }),
          silentDays: silentDays,
          silent:     silentDays >= DMARC_STALE_DAYS,
        };
      });

      var counted = 0;
      var aligned = 0;
      var unauthenticated = 0;
      var quiet = 0;
      var uncounted = 0;
      for (var c = 0; c < cards.length; c += 1) {
        counted += cards[c].counted;
        aligned += cards[c].aligned;
        unauthenticated += cards[c].unauthenticated;
        if (cards[c].allExcluded) uncounted += 1;
        else if (!cards[c].hasEvidence) quiet += 1;
      }
      var rate = _percent(aligned, counted);

      // The windows offered. A choice longer than the rows go is dropped
      // rather than shown and clamped, because an operator picking it
      // would be told they were reading a year while the volume holds a
      // month. The window actually read is always among them, so the
      // control cannot show one window while the page reports another.
      var choices = DMARC_DAY_CHOICES.filter(function (n) { return n <= keptDays; });
      if (choices.indexOf(keptDays) === -1) choices = choices.concat([keptDays]);
      if (choices.indexOf(days) === -1) choices = choices.concat([days]);
      choices.sort(function (left, right) { return left - right; });

      _page(req, res, "admin/dmarc", {
        nav:           _adminNav("dmarc"),
        cards:         cards,
        empty:         cards.length === 0,
        days:          days,
        keptDays:      keptDays,
        dayChoices:    choices.map(function (n) {
          return { days: n, current: n === days };
        }),
        domainChoices: domains.map(function (row) {
          return { domain: row.domain, current: row.domain === selected };
        }),
        selected:      selected,
        narrowed:      selected !== "",
        // Whether a card offers the link that narrows to its own domain.
        // A page already narrowed to one domain offers a link to where
        // the reader is standing.
        showLinks:     selected === "",
        counted:       counted,
        aligned:       aligned,
        unaligned:     counted - aligned,
        rateLabel:     rate === null ? "" : rate + "%",
        rateBucket:    rate === null ? 0 : _bucket(rate),
        unauthenticated: unauthenticated,
        hasExcluded:     unauthenticated > 0,
        quietCount:    quiet,
        hasQuiet:      quiet > 0,
        uncountedCount: uncounted,
        hasUncounted:   uncounted > 0,
        // The two listings. `sourcesListed` and `sourcesTotal` are kept
        // apart so a page showing the loudest twenty five of ninety says
        // so, rather than reading as the whole of what is failing.
        sources:            sourceRows,
        hasSources:         sourceRows.length > 0,
        sourcesListed:      failing === null ? 0 : failing.listed,
        sourcesTotal:       failing === null ? 0 : failing.total,
        sourcesTruncated:   failing === null ? false : failing.truncated,
        // The failing volume this list leaves out, which is not the
        // page-wide excluded total above: that one covers every message
        // reported on, and this one covers the messages that failed.
        sourcesExcluded:    failing === null
          ? "" : _counted(failing.unauthenticated, "message", "messages"),
        hasSourcesExcluded: failing !== null && failing.unauthenticated > 0,
        reporters:          reporterRows,
        hasReporters:       reporterRows.length > 0,
        reportersListed:    heard === null ? 0 : heard.listed,
        reportersTotal:     heard === null ? 0 : heard.total,
        reportersTruncated: heard === null ? false : heard.truncated,
        reportsExcluded:    heard === null
          ? "" : _counted(heard.unauthenticatedReports, "report", "reports"),
        hasReportsExcluded: heard !== null && heard.unauthenticatedReports > 0,
        // Verified reports stored before the authenticated domain was
        // recorded. Their volume is in the counting and they name no
        // organization.
        reportsUnattributed: heard === null
          ? "" : _counted(heard.unattributedReports, "report", "reports"),
        hasReportsUnattributed: heard !== null && heard.unattributedReports > 0,
        // The publishing half. Null on every page this server cannot
        // publish from, which is the whole of the read-only shape.
        policy:        policy,
        canPublish:    policy !== null,
        zoneOff:       zone === null,
      });
    });

    // Computing what publishing a policy level would change, and
    // performing the set that was computed.
    //
    // Two posts, and the first writes nothing. `zone-prepare` reads the
    // zone through the gate and answers with the confirmation page,
    // holding the computed set in this process; `zone-apply` hands that
    // held object back to the gate. Nothing between them recomputes it,
    // so what is performed is the set that was displayed.
    //
    // Every refusal is an RFC 9457 problem document under a
    // `urn:blamepost:problem:` type, the way the sending route answers.
    // A zone edit is the one act on this console with an effect outside
    // this server, and a refusal that redrew a page would leave an
    // operator reading a form to work out whether anything was written.
    router.post("/admin/dmarc", requireAccount, requireAdmin, async function (req, res) {
      var body   = _bodyOf(req);
      var action = _str(body.action, "");
      if (action !== "zone-prepare" && action !== "zone-apply") {
        _sendProblem(res, {
          status: 400,
          type:   ZONE_PROBLEM.action,
          title:  "That is not an act this page performs",
          detail: "This page prepares the DMARC record for one policy level and publishes " +
            "a record it prepared. Nothing else posts to it.",
        });
        return;
      }
      if (zone === null) {
        _sendProblem(res, {
          status: 503,
          type:   ZONE_PROBLEM.writerOff,
          title:  "This server edits no zone",
          detail: "BLAMEPOST_ZONE_PROVIDER names no provider, so this server holds no " +
            "credential for any zone and publishes nothing. The DMARC page prints the " +
            "record for each policy level either way; publish it at your provider, then " +
            "run `blamepost doctor` to see what is resolving.",
        });
        return;
      }
      if (action === "zone-prepare") {
        await _zonePrepare(req, res, body);
        return;
      }
      await _zoneApply(req, res, body);
    });

    // The first post. It reads the zone and renders what would change,
    // and it is the only place a change set is computed.
    //
    // The reason is collected here rather than on the confirmation page.
    // It is recorded against the read as well as the write, so the audit
    // trail answers why a zone was looked at and not only why it was
    // edited, and holding it in this process rather than in a hidden
    // field means no part of what the operator typed is reflected back
    // into a rendered form.
    async function _zonePrepare(req, res, body) {
      var domain = await _hostedZoneDomain(body.domain);
      if (domain === null) {
        _sendProblem(res, {
          status: 400,
          type:   ZONE_PROBLEM.domain,
          title:  "This server does not host that domain",
          detail: "A DMARC record is published for a domain this server hosts. Add the " +
            "domain on the Domains page first.",
        });
        return;
      }

      var reason = _str(body.reason, "").trim();
      if (reason.length === 0 || reason.length > ZONE_MAX_REASON_CHARS) {
        _sendProblem(res, {
          status: 400,
          type:   ZONE_PROBLEM.reason,
          title:  "A zone change is recorded with a reason",
          detail: "Say why this record is being published, in at most " +
            ZONE_MAX_REASON_CHARS + " characters. It is written into the audit row beside " +
            "the change, and a row with no reason answers nothing later about why the " +
            "zone was edited.",
        });
        return;
      }

      var level  = _str(body.level, "");
      var levels = policyStepper.describe().levels;
      if (levels.indexOf(level) === -1) {
        _sendProblem(res, {
          status: 400,
          type:   ZONE_PROBLEM.level,
          title:  "That is not a DMARC policy level",
          detail: "The levels this server publishes are " + levels.join(", ") + ".",
        });
        return;
      }

      var card = await _policyCard(domain);
      if (card.unreadable) {
        _sendProblem(res, {
          status: 409,
          type:   ZONE_PROBLEM.stepNotCarried,
          title:  "Where this policy stands could not be read",
          detail: card.detail,
        });
        return;
      }
      var wanted = card.levels.filter(function (row) { return row.level === level; })[0];
      if (!wanted || wanted.offered !== true || wanted.record.length === 0) {
        _sendProblem(res, {
          status: 409,
          type:   ZONE_PROBLEM.stepNotCarried,
          title:  "The evidence does not carry that step",
          detail: (card.detail || "This server is not offering that policy level for " +
            domain + ".") + " Publishing a weaker policy than the one in force needs no " +
            "evidence and is offered whenever a record is readable.",
        });
        return;
      }

      // Pruning, and only at the address the record goes to. Two DMARC
      // records at one name is a permanent error to every receiver that
      // reads it, so publishing a policy means leaving one record there
      // rather than adding a second. The gate reaches no address the
      // change set is silent about, so nothing else in the zone is read
      // or touched.
      var computed;
      try {
        computed = await _gateFor(domain).preview({
          desired: [{ type: "TXT", name: "_dmarc." + domain, content: wanted.record }],
          reason:  reason,
          prune:   true,
        });
      } catch (err) {
        _zoneRefusal(res, err);
        return;
      }

      if (computed.changes.length === 0) {
        _sendProblem(res, {
          status: 409,
          type:   ZONE_PROBLEM.stepNotCarried,
          title:  "The zone already holds that record",
          detail: "Nothing would change at _dmarc." + domain + ": the provider already " +
            "holds exactly the record this level publishes, and it is the only record " +
            "there. Nothing was written.",
        });
        return;
      }

      var entry = _holdChangeSet(_actingAccountId(req), level, reason, computed);
      var removals = computed.changes.filter(function (one) {
        return one.action === "delete";
      }).length;

      _confirmPage(req, res, _pending({
        path:   "/admin/dmarc",
        action: "zone-apply",
        // Everything carried is a value this server produced: an opaque
        // name for the held set and a digest of what was rendered.
        // Nothing the operator typed goes back into the form.
        carry: [
          { name: "changeset", value: entry.id },
          { name: "diff",      value: entry.digest },
        ],
        title:   "Publish p=" + level + " for " + domain + "?",
        summary: "This edits the zone at your DNS provider. " +
          _counted(computed.changes.length, "change", "changes") +
          (removals > 0
            ? ", " + _counted(removals, "of them a removal", "of them removals")
            : "") + ".",
        consequence: "Every receiver judges mail claiming " + domain + " by the record " +
          "below once it resolves. A removal here takes a record at _dmarc." + domain +
          " that this change set names and nothing else: an address this set is silent " +
          "about is not read and not touched. The zone is read again at the moment this " +
          "is performed, and a record that moved under the change set stops the write " +
          "rather than being overwritten by it.",
        subjects:   computed.changes.map(_changeRow),
        phrase:     domain,
        noun:       "domain",
        prompt:     "Type the domain to confirm",
        promptHint: "Exactly as it is written above. Nothing else confirms this.",
        verb:       "Publish this record",
        fineprint:  "The change set above is the one that will be performed. Preparing it " +
          "again computes a new one against whatever the zone holds then. Leaving this " +
          "page changes nothing, and this one expires after fifteen minutes.",
      }));
    }

    // The second post. It performs the set that the page above rendered
    // and nothing else.
    //
    // The set is looked up by the name the form carries, under the
    // account that computed it, and the digest of what was rendered has
    // to match. A form whose hidden name was moved to another held set
    // fails that comparison, which is the case a page that simply
    // performed "whatever is pending" cannot see: the operator would be
    // publishing a change set they never read.
    async function _zoneApply(req, res, body) {
      var entry = _heldChangeSet(_actingAccountId(req), _str(body.changeset, ""));
      if (entry === null) {
        _sendProblem(res, {
          status: 409,
          type:   ZONE_PROBLEM.notHeld,
          title:  "That change set is no longer held",
          detail: "This server holds a computed change set for fifteen minutes, in the " +
            "process that computed it, for the account that asked for it. This one has " +
            "expired, has already been performed, or was computed before a restart. " +
            "Nothing was written. Prepare the record again and read the new diff: the " +
            "zone may have moved since.",
        });
        return;
      }
      if (_str(body.diff, "") !== entry.digest) {
        _sendProblem(res, {
          status: 409,
          type:   ZONE_PROBLEM.moved,
          title:  "That is not the change set this form showed",
          detail: "The change set named by this form is not the one whose diff the form " +
            "was rendered from. Nothing was written. Prepare the record again and confirm " +
            "against the diff that comes back.",
        });
        return;
      }

      // The confirmation, against the change set that was displayed. It
      // is asked for every zone write rather than only for a removal or
      // a bulk set: this is the one act on this console whose effect is
      // outside this server, and it is undone only by another edit to
      // the same zone.
      var ask = _pending({
        path:   "/admin/dmarc",
        action: "zone-apply",
        carry: [
          { name: "changeset", value: entry.id },
          { name: "diff",      value: entry.digest },
        ],
        title:   "Publish p=" + entry.level + " for " + entry.domain + "?",
        summary: "This edits the zone at your DNS provider.",
        consequence: "Every receiver judges mail claiming " + entry.domain + " by the " +
          "record below once it resolves. The zone is read again at the moment this is " +
          "performed, and a record that moved under the change set stops the write rather " +
          "than being overwritten by it.",
        subjects:   entry.preview.changes.map(_changeRow),
        phrase:     entry.domain,
        noun:       "domain",
        prompt:     "Type the domain to confirm",
        promptHint: "Exactly as it is written above. Nothing else confirms this.",
        verb:       "Publish this record",
        fineprint:  "Leaving this page changes nothing, and this change set expires " +
          "fifteen minutes after it was prepared.",
      });
      if (_stillAsking(req, res, body, ask)) return;

      // Held once, performed once. The set goes out of the register
      // before the write rather than after it, so a second post that
      // arrives while this one is in flight finds nothing to perform
      // instead of writing the same change twice.
      _releaseChangeSet(entry);

      var applied;
      try {
        applied = await _gateFor(entry.domain).apply(entry.preview, {
          reason:  entry.reason,
          confirm: true,
        });
      } catch (err) {
        _zoneRefusal(res, err);
        return;
      }

      // The two reads afterwards. They are asked through the gate, which
      // reports rather than throws, because the provider holding a record
      // a resolver has not answered with yet is ordinary while a previous
      // answer is still cached. Which of the four states this landed in
      // decides the notice, and the operator's next move differs between
      // all of them.
      var seen = null;
      try {
        seen = await _gateFor(entry.domain).verify(applied, { reason: entry.reason });
      } catch (err) {
        log.error("the zone write for " + entry.domain + " was performed and could not be " +
          "read back: " + _faultForDisplay(err));
      }
      // A read that did not happen is its own answer and never the clean
      // one. The write is on the zone either way, and what is missing is
      // any statement about where the record is, so an operator told the
      // publish is complete would stop looking on the strength of two
      // reads that never returned.
      var notice = "zone-published-unread";
      if (seen !== null) {
        notice = seen.ok === true
          ? "zone-published"
          : (seen.conflicts > 0 ? "zone-published-conflict" : "zone-published-pending");
      }
      _back(res, "/admin/dmarc?domain=" + encodeURIComponent(entry.domain), notice);
    }

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
          ? _href("/admin/audit?limit=" + limit + "&offset=" + (offset + limit)) : "",
        newerHref: offset > 0
          ? _href("/admin/audit?limit=" + limit + "&offset=" + Math.max(0, offset - limit)) : "",
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
    // The reading of the transport this surface was built with, so the
    // framework's own request lifecycle is composed against the same one
    // the routes are rather than constructing a second from the same
    // setting.
    resolveProtocol:       transport.resolve,
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
 *   zone:      object,   // the hosted-DNS write gate, or null when no provider is named
 *   dmarcPolicy: object, // the DMARC policy stepper; supplied with zone or not at all
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
  configModule.assertAbsoluteDataDir("blamepost.web.serve: dataDir", dataDir);

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

  // Take the port on a socket this function owns, then give it back.
  //
  // The framework's `app.listen` resolves from the listening callback and
  // catches only a synchronous throw, so a bind that fails asynchronously
  // reaches the server it built as an `error` event with no handler on
  // it, and an unhandled `error` event ends the process. EADDRINUSE and
  // EACCES both arrive that way: another process on the HTTP port, or a
  // port under 1024 without the capability to bind it. The mail
  // listeners do not have this shape, because the lifecycle they share
  // arms a one-shot `error` handler that rejects the listen instead. The
  // browser surface cannot arm one, because the server does not exist
  // outside the promise that has already resolved.
  //
  // So the bind is attempted here first, where the error is catchable,
  // and reported as the rejection the caller's unwind is written
  // against: a failed TLS bind closes the cleartext port, and a failed
  // start releases every mail port before the process ends. Port 0 is
  // skipped because the kernel chooses it and the choice cannot be in
  // use.
  //
  // The port is free for the moment between this socket closing and the
  // application taking it. Losing that race produces the same unhandled
  // event as before, so this narrows the failure rather than adding one.
  function _refusePortAlreadyHeld(port) {
    if (port === 0) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      var probe = nodeNet.createServer();
      probe.once("error", function (err) { reject(err); });
      probe.listen({ port: port, host: address, exclusive: true }, function () {
        probe.close(function () { resolve(); });
      });
    });
  }

  async function _bind(name, port, tlsOptions) {
    await _refusePortAlreadyHeld(port);
    var listening = await app.listen({ port: port, host: address, tls: tlsOptions });
    // Before anything else reads a header off this server. Both ports get
    // it: the cleartext one negotiates HTTP/1.1 today and the reader is a
    // no-op there, and a listener that only held on the TLS port would
    // stop holding the day the other one carried h2c.
    _interposeAuthority(listening.server);
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
          _faultForDisplay(err));
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
      // The framework mounts its own request lifecycle before the one the
      // routes mount, and its CSRF gate checks the origin by default, so a
      // request refused for its origin is answered here and never reaches
      // the chain below. Naming the referrer policy in both places is what
      // makes the surface answer one policy rather than one per chain, and
      // the transport reading is passed for the same reason: the earlier
      // mount decides the first refusal and the later one writes the last
      // header, so a request measures one of each pair and a mount left on
      // the framework default would read this process's socket while its
      // twin read the proxy.
      //
      // The error handler is named for a third reason. Left at the
      // framework default it reads `NODE_ENV`, and an unset variable is
      // read as a developer's machine: the answer to a fault then
      // carries the exception's stack, which names the absolute path of
      // the directory this server was installed into and the framework
      // file the fault came from. The container image sets the variable;
      // `blamepost serve` under a service manager, which is the other
      // documented way to run this, sets nothing.
      //
      // The first fault a passer-by can reach needs no session and no
      // account: the request-line bound is refused where the router
      // parses the target, before the session is read and before any
      // route matches. So the posture is stated here rather than left
      // to the environment. The structured log still carries the whole
      // stack, which is where an operator reads it.
      app = await b.createApp({
        dataDir:    dataDir,
        routes:     handle.routes,
        middleware: {
          securityHeaders: {
            referrerPolicy:   REFERRER_POLICY,
            protocolResolver: handle.resolveProtocol,
          },
          csrf:         { protocolResolver: handle.resolveProtocol },
          bodyParser:   { json: { limit: JSON_BODY_MAX_BYTES } },
          errorHandler: { mode: "prod" },
        },
      });
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
