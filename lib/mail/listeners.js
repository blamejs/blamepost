// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.mail.listeners
 * @nav      Mail protocols
 * @title    Protocol listeners
 * @order    10
 * @featured true
 *
 * @intro
 *   Every wire protocol this server speaks, built from configuration
 *   and wired to the two stores: the identity and routing store that
 *   answers "whose mailbox is this address", and the message store the
 *   protocols read and write.
 *
 *   ## What binds where
 *
 *   Port 25 is inbound mail from the internet (`b.mail.server.mx`).
 *   Port 587 is authenticated submission with STARTTLS and port 465 is
 *   the same listener in implicit-TLS mode (`b.mail.server.submission`,
 *   RFC 8314). Port 143 is IMAP4rev2 (`b.mail.server.imap`, RFC 9051),
 *   port 110 is POP3 (`b.mail.server.pop3`, RFC 1939, off unless the
 *   operator turns it on), and port 4190 is ManageSieve
 *   (`b.mail.server.managesieve`, RFC 5804). JMAP is absent here: it
 *   mounts inside the web application at `/jmap` rather than taking a
 *   port of its own.
 *
 *   ## The mailbox listeners negotiate TLS in band, and only in band
 *
 *   IMAP upgrades through STARTTLS, POP3 through STLS, ManageSieve
 *   through STARTTLS. Nothing here binds 993 or 995, and a client that
 *   wants implicit TLS to a mailbox on this server does not have it.
 *
 *   A TLS terminator in front of 143 or 110 does not supply it, and the
 *   reason is worth writing down because the arrangement looks like it
 *   should work. Behind a terminator the listener is handed a plaintext
 *   connection, so its own view of the session is unencrypted, and each
 *   of these listeners refuses credentials on an unencrypted session:
 *   IMAP answers `BAD AUTHENTICATE requires TLS (use STARTTLS first)`,
 *   POP3 refuses USER and PASS over cleartext, ManageSieve refuses the
 *   mechanism. Measured against a terminator on 993 forwarding to 143,
 *   that is what a client gets for every credential it offers. The
 *   refusals are correct. A listener cannot see TLS it is not part of,
 *   and the alternative is to believe a hop about the confidentiality
 *   of a connection it terminated, which turns an address check into
 *   the thing standing between a password and the wire.
 *
 *   So the answer is not a terminator and not a trusted hop. It is an
 *   implicit-TLS mode on these listeners, wrapping the socket at accept
 *   the way the submission listener already does for port 465, which is
 *   what RFC 8314 section 3 asks for on 993 in the first place.
 *
 *   The framework now offers it: `b.mail.server.imap.create`,
 *   `b.mail.server.pop3.create` and `b.mail.server.managesieve.create`
 *   each accept `implicitTls: true`, off by default. This file does not
 *   compose it yet, so 993 and 995 stay unbound and a client that can
 *   only do implicit TLS to a mailbox still has no route here. What that
 *   now needs is a port, a listener section and a certificate path per
 *   mode, in the configuration schema, the container's exposed ports and
 *   the firewall table, which is a listener an operator turns on rather
 *   than a flag threaded through an existing one. ROADMAP.md carries it.
 *
 *   ## The MX listener will not bind on an unprepared domain
 *
 *   Inbound mail that arrives before SPF, DKIM, DMARC and MTA-STS
 *   exist is mail nobody can authenticate, sent to a domain that
 *   cannot prove anything about itself. So the MX listener sits behind
 *   a boot gate: it refuses to bind until the operator has confirmed
 *   the records in `docs/operator-guide.md` are live. Acknowledgement
 *   is a claim, not a proof, which is why `blamepost doctor` exists to
 *   resolve the records and say which one is actually wrong.
 *
 *   The confirmation is taken twice, and the second is the one that
 *   keeps working. `BLAMEPOST_DNS_ACKNOWLEDGED` covers the server, and
 *   every active hosted domain carries its own acknowledgement written
 *   by `blamepost domain acknowledge`. Without the per domain half, a
 *   domain added an hour after the variable was set would inherit a
 *   confirmation nobody made about it.
 *
 *   ## The MX listener will not bind on a server hosting nothing
 *
 *   A hosted domain is what a recipient is measured against, and the
 *   measurement is the refusal a peer gets when it names somebody
 *   else's address. The framework can now express an empty hosted set:
 *   it applies the check whatever the set holds, so a listener built
 *   over nothing refuses every recipient permanently rather than
 *   accepting them. So this is a choice rather than the only thing
 *   available, and the choice is still to keep port 25 shut.
 *
 *   The two answers differ in what a sender does next, and that is the
 *   whole of it. A bound listener refusing every recipient with a
 *   permanent code tells a peer the address does not exist here, and a
 *   peer told that gives up and reports back to its own sender. During
 *   the minutes or hours between an MX record being published and the
 *   first domain being added, that turns ordinary arriving mail into
 *   bounces the sender cannot retry. A port that is not listening is a
 *   connection refused, which every sending server treats as temporary
 *   and retries against, so the same mail arrives once the domain
 *   exists.
 *
 *   Nothing is lost by staying shut: with no hosted domain there is no
 *   address that resolves to a mailbox here, so the listener could not
 *   have delivered anything to anybody either way. The refusal is
 *   scoped to that one listener rather than to the boot, because a
 *   server with no domain yet is an ordinary first boot. An operator
 *   reaches the first domain through `blamepost init`, which opens the
 *   data directory directly and needs nothing listening, and taking the
 *   browser surface down for the duration would make the step that
 *   fixes the condition look like the thing that broke. The refusal is
 *   written to the boot log and to an audit row, because the operator
 *   who asks about it is usually asking months later, about mail that
 *   never arrived.
 *
 *   ## Withdrawing a domain takes effect on the running server
 *
 *   The framework's MX listener reads the hosted domains per recipient at
 *   RCPT, from an array given at construction. This file hands it an
 *   array, so the set it builds in `start()` is the set that listener
 *   keeps for as long as it holds the port. An operator who disables or
 *   removes a hosted domain would otherwise change every management
 *   surface and not change port 25.
 *
 *   The option also takes a FUNCTION now, answered per recipient, which
 *   is the shape that would make the set itself current. Nothing here
 *   passes one, and the reason is the resolver's contract: it is
 *   synchronous, and the hosted set on this server is a store read. A
 *   function form would need an in-memory mirror of the domain table kept
 *   correct by every path that writes one, which is a larger thing than a
 *   composition change and buys what the per address question below
 *   already delivers.
 *
 *   So the per address question the listener asks on every RCPT decides
 *   the domain as well as the local part. A recipient at a domain the
 *   store no longer hosts, whether it was switched off or removed, is
 *   refused there and then with a permanent code, before the peer is
 *   invited to send anything, and the reason is written to an audit row
 *   naming which of the two states the domain is in. Switching a domain
 *   back on is live in the same way, but only for a domain that was
 *   ACTIVE when the listener bound: that one is in the hosted set the
 *   whole time, the per address question is the only thing refusing it,
 *   and the next RCPT is accepted as soon as the row changes back.
 *
 *   The reverse direction is not answerable from the per address question
 *   at all. A domain ADDED since the listener bound is refused by the
 *   framework's own hosted-set check, which runs before that question and
 *   returns, so nothing this file composes is ever asked about it. A
 *   newly added domain therefore needs the server restarted before port
 *   25 will accept mail for it, which is what `docs/operator-guide.md`
 *   tells the operator to do.
 *
 *   A domain that was already DISABLED when the listener bound sits on
 *   that same side of the line, which is the case easiest to get wrong
 *   from the paragraph above. `start()` builds the hosted set from the
 *   rows whose status is active, so a disabled domain is not in it, and
 *   re-enabling the row later leaves the hosted-set check refusing every
 *   recipient before the per address question is reached. It needs the
 *   restart an added domain needs, for the same reason and at the same
 *   point. Only a domain switched off and back on WITHIN one run of the
 *   server is live, because that one never left the set. Closing it means making the hosted set
 *   itself current, which is the function form above rather than anything
 *   reachable from the hook below.
 *
 *   ## This server does not relay for a source address
 *
 *   The framework's MX listener can be told to accept a recipient
 *   outside the hosted domains when the peer's address falls inside an
 *   operator-named range. That option is not composed here, and a
 *   configuration carrying a range stops the boot rather than being
 *   quietly dropped.
 *
 *   The reason is that the case it exists for is already served better
 *   through the front door. Every listener here requires STARTTLS
 *   before it will accept an envelope, so a device that can reach
 *   `RCPT TO` on port 25 can also sign in on 587 or 465, where its mail
 *   is bound to an account, signed for the domain it claims, and
 *   reported to a mailbox when it fails. A range buys none of those: an
 *   address names a network segment rather than a sender, relayed mail
 *   cannot be signed without letting anything inside the segment forge
 *   a hosted domain, and a failure is owed to a reverse path nobody
 *   verified. The argument is written out in full above
 *   `_refuseRelayGrant`, which is also where the refusal lives.
 *
 *   ## The ceilings are the operator's, not the framework's
 *
 *   Every listener bounds what one source address may ask of it: how
 *   many connections it may hold at once and open per minute, how many
 *   sign-ins it may fail, and how large a message it may send. The
 *   framework supplies all four when a caller supplies none, so a
 *   composition that passes nothing still holds a ceiling. It just
 *   holds one nobody here chose, and an operator has no way to see it
 *   or move it.
 *
 *   They are read from `config.limits` and handed to every listener for
 *   that reason. The connection ceiling is the one that matters most,
 *   and the reason is who shares a source address: ten at once is a
 *   fair bound on a stranger delivering mail to port 25 and a low one
 *   for the people reading their mail, because a single client holds
 *   several IMAP connections open and a household or an office arrives
 *   as one address. Each listener builds its own limiter from the same
 *   numbers rather than sharing one between them, so a client that
 *   holds a mailbox open does not spend the allowance it needs to send.
 *
 *   ## Submission is bound to the authenticated identity
 *
 *   `identityBinding: "strict"` means the `MAIL FROM` address has to be
 *   one the authenticated account owns. The refusal is the framework's:
 *   `553 5.7.1 Sender address rejected: not owned by authenticated
 *   identity`, and separately `553 5.7.1 Sender address rejected:
 *   authenticated identity has no assigned mailboxes` when the account
 *   owns none at all. That second case matters: an empty address set
 *   means unfinished provisioning, and reading it as "allow anything"
 *   is how an authenticated relay turns into an open one.
 *
 *   The envelope is only half of an identity. `MAIL FROM` is the
 *   address a receiver bounces to and never shows anybody; `From` is
 *   the address a person reads, and the framework binds the first and
 *   never reads the second. So the author is bound here, in the relay
 *   handoff, where the finished message first exists: every address
 *   this server hosts that appears in `From` or `Sender` has to be one
 *   the account may write, and at least one address across the two has
 *   to be, so the message is attributable to somebody who signed in for
 *   it. The set is the account's own address plus every alias that
 *   lands in its mailbox, tags folded the way routing folds them, and
 *   never a catch-all.
 *
 *   The refusal names its own reply through `smtpCode`,
 *   `enhancedStatus` and `replyText`, so it reaches the client
 *   permanently and says which rule it broke: `550 5.7.1` for an author
 *   this account may not write, and `550 5.6.0` for a `From` and
 *   `Sender` pair that names no single readable author. Without those a
 *   rejection inherits the framework's `451 4.3.0`, which would tell a
 *   conforming MTA to retry a message refused identically every time.
 *   The reply text is short and names no address; the address that was
 *   rejected and the ones that would have been accepted go to the audit
 *   trail and the log.
 *
 *   The listener's own outbound signature gate is turned off here, and
 *   the reason is ordering rather than posture. That gate refuses a
 *   submission whose client did not already attach a
 *   `DKIM-Signature`, which no ordinary mail client does. This server
 *   signs during relay, after the gate, so leaving it armed would
 *   refuse every real client while changing nothing about what leaves
 *   the building signed.
 *
 *   ## SASL
 *
 *   PLAIN, over the TLS the listeners already require before they
 *   will accept credentials. A client may carry its credentials on
 *   the AUTHENTICATE line itself, and a client may leave them off and
 *   wait to be asked for them. Both spellings are the base protocol
 *   rather than an extension: RFC 9051 section 6.2.2 makes the
 *   initial response an optional argument of IMAP4rev2's
 *   AUTHENTICATE, and RFC 4954 section 4 says the same for SMTP
 *   submission. These listeners advertise IMAP4rev2 and no earlier
 *   revision, so the inline form needs no SASL-IR capability beside
 *   it. SASL-IR (RFC 4959) is the IMAP4rev1 spelling of an argument
 *   IMAP4rev2 already carries, and the mechanism list is the only
 *   part of the framework's capability line this composition supplies,
 *   so there is no atom to add there in any case.
 *
 *   A client that leaves the credentials off is answered with an
 *   empty challenge, and the line it sends next arrives at the same
 *   verifier. Each listener writes that challenge in its own syntax:
 *   the IMAP `+` continuation, the SMTP `334` reply, the POP3 `+`
 *   line, and on ManageSieve a zero-length literal, which RFC 5804
 *   §2.1 is what makes an empty ask expressible there at all. Only
 *   the opening step may ask. A client that answers a challenge with
 *   nothing is refused rather than challenged again, because a second
 *   challenge is the start of an exchange with no end.
 *
 *   All four listeners carry the exchange the same way, so the
 *   verifier is one function rather than four variants of one. A
 *   client that opens the exchange the long way is not penalised for
 *   it: the round trip is a normal one and costs no part of the
 *   account's authentication-failure budget, and a client that
 *   withdraws with a single `*` is answered as having withdrawn
 *   rather than as having guessed wrong.
 *
 *   The framework hands IMAP `LOGIN` and POP3 `USER` and `PASS` to
 *   the same verifier in an already split form. A PLAIN response
 *   whose authorization identity differs from its authentication
 *   identity is refused: acting as another account is not something
 *   this server grants.
 *
 * @card
 *   Builds the SMTP, submission, IMAP, POP3 and ManageSieve listeners from
 *   configuration and binds their ports. Submission accepts only a sender
 *   address the signed-in account owns, and port 25 stays unbound until the
 *   operator has acknowledged the DNS records.
 */

var nodeBuffer = require("node:buffer");

var b = require("../vendor/blamejs");

var posture = require("./posture");

var mailbox = require("./mailbox");

// The screen between text somebody else wrote and somebody reading it,
// and the table of what a stored field is refused for. A Sieve script
// name and the folder a script files into are both written by an account
// holder and both end up in an operator's log and in an audit row, so
// both go through here on the way out.
var displayText = require("../text");

// The defaults table, for the shipped value of every ceiling under
// `limits`. The schema that decides whether an operator's number is
// acceptable and the table of what runs when they write none are one
// module, so a ceiling cannot be settable here and unset there.
var configModule = require("../config");

// Two spellings of one mailbox are one mailbox, and `lib/store/address`
// is the single place that decides so: it folds the case of both halves
// and strips the RFC 5233 plus tag down to the mailbox that owns it.
// The header binding below compares one address against another and has
// to reach the same verdict the routing layer reaches, or this server
// refuses an account the address it delivers to that same account.
var storeAddress = require("../store/address");

// The shape the audit chain fills its actor columns from. Every row this
// file writes goes through it rather than naming the columns in a
// literal, so one reading of a field decides what reaches an operator's
// terminal: each one is trimmed, bounded and stripped of the codepoints
// a terminal acts on rather than prints. Two of the four arrive off the
// wire, so an unbounded field would be a peer choosing how large this
// server's audit rows are.
var auditActor = require("../store/actor");

// The one reader that answers how many addresses an RFC 5322 address
// header names. Composed rather than repeated: an address hidden inside
// a display name is exactly the input two readers would disagree about,
// and one of the two here decides whose name goes on a signed message.
var splitAddressHeader = require("./compose").splitAddressHeader;

// Which part of one of those entries is the address. `"Alice Smith"
// <alice@example.com>` names one address and carries another string
// beside it, and a reader that took the whole entry would measure the
// display name as though somebody had claimed it.
var normalizeAddress = require("./compose").normalizeAddress;

// How many angle addresses one of those entries carries. The reader
// above answers with one address whatever the entry holds, and an entry
// holding two is one it chose between: RFC 5322 §3.4 gives a mailbox one
// angle address and says nothing about which of two a reader takes. The
// binding below needs the count to know it was handed a choice, because
// the address it never saw is the one a forged header is built on.
var angleAddressCount = require("./compose").angleAddressCount;

if (typeof splitAddressHeader !== "function" || typeof normalizeAddress !== "function" ||
    typeof angleAddressCount !== "function") {
  throw new TypeError("blamepost.mail.listeners: the compose module must export " +
    "splitAddressHeader, normalizeAddress and angleAddressCount, which are the three " +
    "readers the submission header binding measures an author against");
}

// The one forward scan that answers where a message's header block
// ends. Composed rather than repeated: a second scan here is how the
// IMAP surface and the report surface came to disagree about the same
// stored message.
var headerBreak = mailbox.headerBreak;

// The bounded RFC 3462 §3 quote of a message's own headers, for the
// reports the inbound path composes. Composed rather than written again:
// the caps on it and the choice of which empty line ends the block
// decide what a peer can put into a report this server addresses to a
// third party, and the outbound spool's own report paths answer that
// question the same way because they ask the same reader.
var reportedHeaderBlock = mailbox.reportedHeaderBlock;

// The sequence set reader FETCH and STORE already go through, composed
// here so the SEARCH keys that take one read the same grammar. A second
// reader would be a second answer to what `2:*,7` addresses.
var sequenceSet = mailbox.sequenceSet;

// What this server accepts as a keyword flag, read from the module that
// decides it. KEYWORD and UNKEYWORD screen an atom against the rule
// STORE screens one against, so there is no keyword a client can set
// and then cannot search for.
var KEYWORD_FLAG_RE = mailbox.KEYWORD_FLAG_RE;

if (typeof sequenceSet !== "function" || !(KEYWORD_FLAG_RE instanceof RegExp)) {
  throw new TypeError("blamepost.mail.listeners: the mailbox module must export " +
    "sequenceSet and KEYWORD_FLAG_RE, which are the two grammars the IMAP SEARCH " +
    "composition reads off the wire");
}

// The signing refusal code this listener branches on when it records a
// message it had to relay unsigned. Read from the module that throws it,
// so the two cannot drift apart. The handle in `opts.dkim` carries the
// behavior; the contract lives here.
var DKIM_CODES = require("./dkim").CODES;

// Read once, at load, so a missing export is a boot failure rather than
// a throw from inside the catch that records an unsigned relay. That
// catch runs per message and must not raise: a throw there would kill
// the delivery whose signing refusal it was only trying to record, which
// turns a message that would have gone out unsigned into one that does
// not go out at all.
if (!DKIM_CODES || typeof DKIM_CODES.noActiveSelector !== "string") {
  throw new TypeError("blamepost.mail.listeners: the dkim module must export CODES with " +
    "noActiveSelector, which is the code this listener files a relayed-unsigned message " +
    "under when the domain has no key");
}

// Nothing in this file reads the code the outbound queue refuses a full
// spool with, and that is the point rather than an omission. A handoff
// takes the room it needs before it writes anything and holds it until
// it is done, so a queue that fills mid-message is somebody else being
// refused and never this message. The refusal it does meet, at the one
// moment refusing is free, unwinds a handoff that has committed nothing,
// which both listeners already turn into a temporary answer on the wire
// without looking at what the cause was. Telling causes apart after a
// mailbox already holds the message is the shape that put a second copy
// in it, so no cause is told apart there any more: every one is recorded
// against the recipient it belongs to and reported to the sender.

var TIME  = b.constants.TIME;
var BYTES = b.constants.BYTES;

// The namespace every audit action in this file is written under, and
// the first segment `b.audit` reads to decide whether a row may land.
// An action under a namespace nobody registered is refused by
// `b.audit.record`, and `safeEmit` drops that refusal silently, because
// an audit write must never be allowed to end a delivery. So an
// unregistered namespace does not announce itself: it means none of
// these rows exist. The refusal still happens on the wire and nothing
// records that it did, which is the half of it an operator reads
// afterwards.
//
// Registered here rather than assumed, because a caller composing this
// module may have registered nothing and the cost of guessing wrong is
// invisible. Registration is idempotent, so a caller that already did
// it loses nothing.
var AUDIT_NAMESPACE = "blamepost";

// RFC 4616 separates the three SASL PLAIN fields with NUL. Written as
// its code point so this source file carries no control byte of its own.
var SASL_PLAIN_SEPARATOR = String.fromCharCode(0);

// The two authentication surfaces this server has, and the whole of what
// separates them: what an identity presented on one is allowed to be.
//
// SUBMISSION accepts an account or a sending credential. MAILBOX accepts
// an account and nothing else, so a credential offered to IMAP, POP3 or
// ManageSieve names no identity there and is refused the way a wrong
// password is.
//
// The split is by LISTENER rather than by check, and that is the point
// of naming it here. A sending credential speaks for a whole hosted
// domain, so one verifier shared across the four listeners would hand a
// secret issued to send mail the ability to open every mailbox in that
// domain, read it over IMAP, delete it over POP3 and rewrite the filters
// over ManageSieve. Nothing in the credential's own scope bounds any of
// that, because its scope is a sending scope: the refusal list names
// addresses it may not write as and says nothing about what it may read.
//
// Frozen and exported so the builders and the gate that checks which
// builder got which form read one spelling rather than two.
var AUTH_SURFACES = Object.freeze({
  SUBMISSION: "submission",
  MAILBOX:    "mailbox",
});

// The failure budget a presented sending credential spends, kept apart
// from the account budgets in `lib/store/accounts.js` in three ways that
// each matter.
//
// It is keyed on the CREDENTIAL identifier paired with the peer that
// presented the token, and never on a mailbox, so guessing at a
// credential cannot lock an account holder out of their own mail and
// guessing at a mailbox cannot stop an application sending.
//
// The pair is what the refusal is keyed on, and the pairing is the whole
// of the arrangement. The identifier is readable from the token before
// the secret is checked, which is what lets a wrong secret be counted
// against the credential it was offered for rather than against nothing.
// A value readable before the secret is a value the peer wrote, so a
// counter keyed on the identifier alone is a counter any peer can spend
// against a credential it does not hold: five wrong secrets hold the
// credential for a minute, and a run of them every six hours holds a
// domain's outbound mail down for as long as the sender cares to keep
// sending. Pairing the identifier with the peer leaves a guesser holding
// nothing but their own lockout, and leaves the application sending from
// its own address throughout.
//
// Both transports still spend ONE counter for one peer. The submission
// listener reads the peer off the socket it is holding and the sending
// route reads it off the request's own connection, and both are keyed
// through `b.requestHelpers.ipKey`, so a guess made on port 587 and a
// guess made on the browser port from the same address land on the same
// key. A surface that verifies a secret and counts nothing is a bound an
// attacker walks around by choosing that surface, and that is still not
// on offer.
//
// There is no familiar-source exemption. The account budgets carry one
// because a person signing in from the device they use daily must not be
// locked out by somebody else's guessing. A sending application is not a
// person: it holds a secret this server generated, it does not forget
// it, and an exemption would be a way for a source that once verified to
// keep guessing after the budget was spent. The pairing answers the
// question the exemption answers there, and answers it without a window
// in which an address that once verified is trusted.
//
// The per-peer ceiling on the listener is untouched. Every listener
// already counts a failed AUTH against the connecting address through
// `authFailuresPerIpPer15Min`, and it counts a credential failure
// exactly as it counts an account failure, so nothing here has to
// restate it.
var CREDENTIAL_BUDGET_NAMESPACE = "blamepost.auth.sending-credential.peer";
var CREDENTIAL_BUDGET_CACHE     = "blamepost.auth.sending-credential.peer.cache";

// The counter that watches one credential across every peer at once.
//
// It counts and it never refuses. Refusing on it would put back exactly
// what the pairing above removes: a bound one party can spend on behalf
// of everybody, reachable by whoever can name the credential. Any
// threshold low enough to matter is one an attacker holding a handful of
// addresses crosses on purpose, so crossing it files an audit row for
// the operator and changes no answer given on the wire.
//
// What it is for is the one thing the paired counter cannot show. A
// paired counter reads five failures from four hundred addresses as four
// hundred separate peers each within their bound, and the operator sees
// nothing. This reads it as one credential under two thousand failed
// attempts, which is a campaign against a named credential and is the
// operator's to act on by rotating or revoking it.
//
// There is nothing to protect by refusing. The secret is thirty-two
// bytes this server generated, so online guessing is not a search that
// finishes; the bound exists to stop the work and the noise, and the
// paired counter together with the listener's own per-address ceiling
// already stop both.
var CREDENTIAL_SPREAD_NAMESPACE = "blamepost.auth.sending-credential.spread";
var CREDENTIAL_SPREAD_CACHE     = "blamepost.auth.sending-credential.spread.cache";

// How many failures against one credential, from all peers together,
// file that row. A credential holds a secret a machine was configured
// with, so its ordinary failure rate is zero and a deployment rolling
// out a stale token from a few hosts is the only benign run of any
// length. Fifty inside the counter's window is past that and well below
// what a campaign produces.
var CREDENTIAL_SPREAD_ATTEMPTS = 50;

// How many counters are held at once, per cache. Each evicts the least
// recently used beyond this, and an evicted counter is a counter back at
// zero, so it is set far above the number of sending credentials a
// server plausibly holds.
//
// The two caches are separate rather than one. Paired counters are as
// many as (credentials x peers) and a spray from many addresses is what
// fills them, so a shared cache would let that spray push the per
// credential counters out and take the operator's only view of the
// campaign with them.
//
// Eviction buys a guesser nothing. Pushing their own paired counter out
// costs a source address, and a second source address already carries
// its own five attempts without any of the work.
var CREDENTIAL_BUDGET_ENTRIES = 10000;

// The two readings the clock below is built out of, taken together at
// load so the pair describes one instant.
var WALL_ORIGIN_MS    = Date.now();
var ELAPSED_ORIGIN_MS = b.time.monotonicMs();

// The clock the credential budget is measured on: where the wall clock
// stood when this module loaded, advanced from there by a source the
// host cannot move. It is the construction `lib/store/accounts.js` uses
// for the account budgets, for the reason written beside it there: a
// budget is a duration, `Date.now()` answers what time it is, and it
// moves when an operator corrects a wrong time, when NTP steps a drifted
// host, and when a container starts before it has synchronized. A step
// forward lifts a lockout nobody served; a step backwards holds one past
// its end. Neither surfaces as an error anywhere.
//
// Anchored on the wall clock rather than a bare elapsed count, because
// the instant a lockout lifts is written into the audit row and read
// back as a date. The cache underneath takes the SAME clock: an entry
// expired against the wall clock is handed back by a step forward even
// when the arithmetic over it was steady.
function _steadyNow() {
  return WALL_ORIGIN_MS + (b.time.monotonicMs() - ELAPSED_ORIGIN_MS);
}

// Built on first use rather than when this file is required, so a
// process that merely reads this module does not arm a sweep timer. One
// per process rather than one per composed server, so rebuilding the
// listeners does not hand whoever is guessing a fresh budget.
var credentialBudgets = null;

function _credentialBudgets() {
  if (credentialBudgets !== null) return credentialBudgets;
  credentialBudgets = {
    peer: b.auth.lockout.create({
      namespace: CREDENTIAL_BUDGET_NAMESPACE,
      clock:     _steadyNow,
      cache:     b.cache.create({
        namespace:  CREDENTIAL_BUDGET_CACHE,
        backend:    "memory",
        clock:      _steadyNow,
        maxEntries: CREDENTIAL_BUDGET_ENTRIES,
      }),
      audit: b.audit,
    }),
    // The watch. Its verdict is deliberately not read anywhere: the row
    // it files when it crosses is the whole of its output, and the
    // comment above the threshold says why refusing on it would put the
    // reachable lockout back. Its own failure rows are off, because the
    // paired counter beside it files one for every attempt already and a
    // second copy of the same event under a different namespace is a
    // trail an operator has to de-duplicate by hand.
    spread: b.auth.lockout.create({
      namespace:     CREDENTIAL_SPREAD_NAMESPACE,
      clock:         _steadyNow,
      maxAttempts:   CREDENTIAL_SPREAD_ATTEMPTS,
      cache:         b.cache.create({
        namespace:  CREDENTIAL_SPREAD_CACHE,
        backend:    "memory",
        clock:      _steadyNow,
        maxEntries: CREDENTIAL_BUDGET_ENTRIES,
      }),
      audit:         b.audit,
      auditFailures: false,
    }),
  };
  return credentialBudgets;
}

// Which identity space an authentication name belongs to, decided from
// the name alone.
//
// An RFC 5321 mailbox always carries an `@` and a domain never does, so
// the two spaces are disjoint by construction and the split is made
// before any secret is read. That ordering is the whole of why the name
// decides rather than the secret: routing on the SHAPE OF THE SECRET
// would let one identity be reached under another's name, so a guess
// aimed at a mailbox could be answered by the credential registry and
// spend neither budget, and an account whose password happened to look
// like a token would be verified against the wrong store.
//
// The name is read through `lib/store/address`, which is the one
// derivation every hosted domain on this server is written and looked up
// through. A second reading here would be a second answer to what
// `EXAMPLE.COM.` names, and the answer decides which row a credential is
// checked against.
//
// A name that is neither a readable address nor a readable domain falls
// through to the account path and is refused there, so an operator who
// configured a client with a bare username is answered about the
// mailbox they meant rather than counted against a credential.
function _scopeDomainOf(authcid) {
  if (typeof authcid !== "string" || authcid.length === 0) return null;
  if (authcid.indexOf("@") !== -1) return null;
  var verdict = storeAddress.parseDomain(authcid);
  return verdict.ok ? verdict.domain : null;
}

// The identifier inside a presented token, which is what a failure is
// counted against.
//
// It names a row and is not a secret, so it can be read before the
// secret is checked, and that is what lets a wrong secret be charged to
// the credential it was offered for. A token that does not parse at all
// is charged to nothing, because there is no credential it names.
//
// Bounded and screened rather than taken as it arrives: the counter key
// comes off the wire, and an unbounded one is a way for a peer to write
// arbitrary keys into a cache this server keeps. The shape is the one
// `lib/store/credentials` issues identifiers in.
var CREDENTIAL_ID_RE = /^[0-9a-f]{2,64}$/;

function _credentialIdOf(token) {
  var parts = b.apiKey.parseFormat(token);
  if (!parts || typeof parts.idHex !== "string") return null;
  var id = parts.idHex.toLowerCase();
  return CREDENTIAL_ID_RE.test(id) ? id : null;
}

// The key one credential's failures are counted against on one peer.
//
// The peer goes through `b.requestHelpers.ipKey`, which is what
// `lib/store/accounts.js` keys its own pair budget through. It keeps an
// IPv4 address exact, collapses an IPv6 one to the prefix its site is
// allocated so a client rotating the low bits of its own address does
// not mint a fresh budget every attempt, and reads an IPv4-mapped IPv6
// address back as the dotted form, so one peer keys the same way whether
// a listener reported `127.0.0.1` or `::ffff:127.0.0.1`. That last part
// is what keeps the two transports on one counter: they bind separately
// and an operator may give one an IPv6 address and the other an IPv4
// one.
//
// The peer is written FIRST. A peer key is a dotted address or a masked
// prefix and carries no vertical bar, and a credential identifier is
// hexadecimal, so read from the left the split is unambiguous and two
// different pairs cannot fold into one key.
//
// A peer this server could not read leaves the left half empty, which is
// a key of its own rather than a fall-back to the identifier alone.
// Every transport composed here hands over an address it read off its
// own socket, so the empty half is reached by a caller that named no
// peer at all; it bounds that caller and it is not a key any peer
// carrying an address can land on, so it cannot become the shared bucket
// the pairing exists to remove.
function _credentialBudgetKey(id, source) {
  return b.requestHelpers.ipKey(typeof source === "string" ? source : "") + "|" + id;
}

// The name a sending credential's scope goes by where the framework
// expects an address set. It is prose in angle brackets, and both halves
// are load-bearing.
//
// The prose is what an operator reads in the refusal's own audit row,
// where the framework reports the set the envelope was measured against.
// `any address at example.com` is what the credential may write, said in
// the one place the framework offers to say anything at all.
//
// The angle brackets are what keep it out of the comparison. RFC 5321
// section 4.1.2 writes the reverse path inside them, so the framework
// reads `MAIL FROM` with a capture that ends at the first `>`, and a
// string carrying one can never come off that line. The scope name
// therefore cannot be matched by anything a client sends, which is the
// property the whole arrangement rests on: matching it would hand a
// credential an envelope sender the refusal list never saw.
//
// `test/layer-2-integration/sending-credential-scope.test.js` spells it
// on the wire and measures the refusal, because the grammar it relies on
// lives in the vendored tree and a refresh can move it.
function _scopeName(domain) {
  return "<any address at " + domain + ">";
}

// The port map from the operator guide. A configuration that names no
// ports gets exactly this.
// `maxLineBytes` is the longest command line each listener reads before
// refusing one. Passing it is the point: a listener handed no number
// applies the vendored framework's own, which nothing here chose and
// nothing here prints, so a refresh that moved one would change what
// this server accepts with no configuration and no log line saying so.
// Each value is the framework's current default, so these move no
// behavior. `test/layer-1-state/config-listeners.test.js` holds this
// table and the loader's to the same numbers, and
// `test/layer-2-integration/listener-line-ceiling.test.js` measures on a
// socket that the number reaches the listener.
var DEFAULTS = Object.freeze({
  mx:          Object.freeze({ enabled: true,  port: 25,   address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(1) }),
  submission:  Object.freeze({ enabled: true,  port: 587,  address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(1) }),
  submissions: Object.freeze({ enabled: true,  port: 465,  address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(1) }),
  imap:        Object.freeze({ enabled: true,  port: 143,  address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(8) }),
  pop3:        Object.freeze({ enabled: false, port: 110,  address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(1) }),
  managesieve: Object.freeze({ enabled: true,  port: 4190, address: "0.0.0.0",
                               maxLineBytes: b.constants.BYTES.kib(8) }),
});

// The range an operator's own line ceiling has to sit in. The floor is
// the 512 octets RFC 5321 section 4.5.3.1.4 requires an SMTP server to
// accept, so no setting can put a listener below what its standard
// obliges it to read. The ceiling bounds what one connection can hold
// unterminated in memory, once per connection.
//
// The loader checks the same range, and this is not a duplicate of that
// check. `create` is reached with a configuration object built by hand
// as well as with one the loader produced, and a number that never went
// through the loader has been checked by nothing until here.
var MIN_LINE_BYTES = 512;
var MAX_LINE_BYTES = b.constants.BYTES.kib(64);

// What the MX listener does with the SPF, DKIM and DMARC verdict it
// computes at the end of DATA, when the configuration says nothing.
//
// `enforce` applies the sending domain's published policy, and `defer`
// answers a DNS failure with a temporary refusal rather than accepting
// a message whose authentication could not be evaluated. Both are the
// safe direction: a receiver that records a verdict without acting on
// it delivers spoofed mail from its own operators' domains, and one
// that reads a broken resolver as "no policy published" does the same
// for every domain on the internet for as long as its DNS is down.
//
// Frozen and exported for the same reason the port map above is. The
// operator guide prints this pair as the default an operator gets by
// changing nothing, and a default that lives only where it is applied
// is one a document can promise and the server can stop keeping,
// with nothing between the two to say so.
var DEFAULT_INBOUND = Object.freeze({
  mode:        "enforce",
  onTemperror: "defer",
});

// What a listener can be, as one word, for the inventory the health
// probes report and anything else that has to say where a listener got
// to. Four states rather than a pair, and the distinction the pair
// cannot make is the one that matters: BOUND took its port, WITHHELD is
// a port this server decided to leave shut and can say why, UNBOUND is a
// port that was meant to be open and is not, and DISABLED is a listener
// this configuration never asked for.
//
// Only UNBOUND is a fault. A reader that has WITHHELD and UNBOUND as one
// value reports the ordinary first boot, where no domain is hosted yet
// and port 25 has nothing to receive for, as a server that failed to
// start. That is how a readiness gate, a load balancer and a dependent
// service all decide a working mail server is down.
//
// Frozen and exported so the module that builds the inventory and the
// module that reads it share these words rather than each spelling them
// out. Two copies of a vocabulary drift, and a state word that drifts
// silently reclassifies whatever carries it.
var LISTENER_STATES = Object.freeze({
  BOUND:    "bound",
  WITHHELD: "withheld",
  UNBOUND:  "unbound",
  DISABLED: "disabled",
});

// The listeners a renewed certificate does not reach while this process
// is running, and the reason it does not.
//
// Empty, and the emptiness is the statement. Every listener composed here
// takes its certificate as an accessor, so the option is read at the
// moment a connection needs a context and a rotation reaches whatever
// reads it that way. All five now do: MX, submission, IMAP and POP3
// always did, and ManageSieve read its option once at construction and
// served the certificate this process started with for the life of the
// process, whatever was written to disk afterwards. It reads the option
// per connection now, so a renewal reaches every mail port with nothing
// to restart.
//
// The list stays rather than being deleted with its entry. It is a
// statement about the framework, which can regress or grow a sixth
// listener, and the rotation path reads it to tell an operator which
// port still needs a restart instead of leaving them to find out from a
// client that stopped connecting.
//
// It is a constant, maintained by hand, and nothing here measures it. A
// listener that stopped rotating would leave this empty and the reload
// line would keep saying every port took the renewal. What would catch
// that is `test/layer-2-integration/tls-certificate-renewal.test.js`,
// which writes a second certificate over the first and then reads the
// chain back off all seven ports, so the claim is checked against the
// ports rather than against this list. The browser half is derived and
// this half is not, which is why the two are concatenated rather than
// kept as one value.
//
// Every member is a listener a rotation does NOT reach, so growth is what
// takes something away and the emptying of it is a defect fixed. Read as a
// list of offerings, the last entry leaving reported as surface lost.
//
// @membership blamepost.mail.listeners.STALE_AFTER_ROTATION constraint
var STALE_AFTER_ROTATION = Object.freeze([]);

/**
 * @primitive blamepost.mail.listeners.keyAgreementGroups
 * @signature blamepost.mail.listeners.keyAgreementGroups()
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 8446 §4.2.7 (supported groups), §9.1 (mandatory to implement)
 * @related   blamepost.tlsContext, blamepost.web.serve
 *
 * The key-agreement preference every listener presents, as the string
 * node reads under `ecdhCurve`, with one check on it this server will
 * not start without.
 *
 * The string itself comes from `b.network.tls.serverKeyAgreementGroups`.
 * That is the SERVER form, and the distinction is the whole point of
 * asking for it by name: a flat colon-separated list is an offer order
 * to a client and an accept SET to a server, so the client form applied
 * to a listener refuses every group it does not name, `secp256r1`
 * among them, which RFC 8446 §9.1 makes mandatory to implement. On port
 * 25 that is not a downgrade to cleartext. This server accepts an
 * envelope only on an encrypted session, so a peer whose handshake is
 * refused has no second route: it meets `530 5.7.0 Must issue a STARTTLS
 * command first` on any retry and its mail sits in a queue until it
 * bounces. The server form is slash-separated tuples, which accepts
 * every registered curve while still spending a HelloRetryRequest to
 * climb to a hybrid.
 *
 * The framework's listener path composes that string, and this file
 * does not compose a second one. Two spellings of one policy are two
 * halves of a server disagreeing about it, so what is left here is the
 * part the framework does not answer for.
 *
 * That part is the refusal below. Hybrid key agreement is not a
 * preference this server expresses, it is a property it claims, and a
 * vendored tree that stopped publishing one would compose a
 * classical-only posture that parses, binds every port and says
 * nothing. The check reads the composed string rather than the constant
 * behind it, because the constant is no longer what reaches the wire:
 * asking the value that is actually handed to `ecdhCurve` is the only
 * question whose answer cannot go stale.
 *
 * It is not a setting. The same string reaches the mail listeners and
 * the browser port, and no configuration this server reads widens or
 * narrows it.
 *
 * @example
 *   var groups = blamepost.mail.listeners.keyAgreementGroups();
 *   // "X25519MLKEM768/SecP256r1MLKEM768/SecP384r1MLKEM1024/X25519/X448:..."
 */
function keyAgreementGroups() {
  var composed = b.network.tls.serverKeyAgreementGroups(
    undefined, "blamepost.mail.listeners.keyAgreementGroups");

  // The leading tuple is what a peer offering everything negotiates, so
  // it is the one that has to name a hybrid. Reading the first tuple
  // rather than searching the whole string is deliberate: a hybrid
  // sitting behind a classical group is a string that mentions
  // post-quantum key agreement and does not run it.
  var leading = typeof composed === "string" ? composed.split("/")[0].split(":") : [];
  var leads = leading.some(function (name) {
    return Object.prototype.hasOwnProperty.call(b.constants.PQC_GROUPS, name);
  });
  if (!leads) {
    throw new TypeError("blamepost.mail.listeners.keyAgreementGroups: the composed " +
      "key agreement leads with " + JSON.stringify(composed) + ", which names no " +
      "post-quantum hybrid this framework publishes a codepoint for. Refusing to " +
      "compose a classical-only posture for the listeners. Either the vendored tree " +
      "stopped publishing a hybrid, in which case check lib/vendor/MANIFEST.json " +
      "against it, or a caller narrowed the key shares to classical groups through " +
      "b.network.tls.pqc.setKeyShares before the listeners were built.");
  }
  return composed;
}

// SASL mechanisms advertised. PLAIN only, and only after TLS, which is
// what the listeners enforce on their own.
var SASL_MECHANISMS = Object.freeze(["PLAIN"]);

var DEFAULT_DRAIN_MS = TIME.seconds(20);

// How long the connection path will wait on the DNS handle it was given.
//
// Every lookup the inbound path makes happens with a peer on the other
// end of an open socket waiting for a reply. The HELO gate resolves the
// connecting address's reverse name during EHLO and confirms it forward
// again; SPF, DKIM verification and DMARC resolve the sender's published
// policy at the end of DATA. The handle those lookups go to is not this
// server's: an operator pins one, and what it does when a question
// cannot be answered is its own business.
//
// A handle that REJECTS is harmless, because every gate above already
// has a verdict for a lookup that failed. A handle that ACCEPTS the
// question and never answers it is the one shape with no verdict at
// all, and it is ordinary rather than exotic: a nameserver that takes
// the query and drops the response, a firewall that blackholes the
// reply, and a handle written around an internal service that has
// stopped answering all present exactly that way. Measured against one,
// an EHLO sat unanswered with the connection held and nothing written on
// it, until the listener's own five minute idle timeout cut the socket.
// The per source connection ceiling then means a peer needs only a
// handful of those at once to occupy this server without sending a byte
// of mail.
//
// So the composition holds a budget over the handle it was given. The
// number is deliberately generous rather than tight: the resolver this
// server builds already bounds every upstream fetch at ten seconds, and
// the reverse check spends one of those on the reverse name and one on
// each name that comes back, so this never fires against it. It exists
// for the handle that carries no bound of its own, where the alternative
// is a session held open with nothing said.
//
// A lookup that runs out of budget is a lookup that FAILED, and it is
// never folded into "this name publishes nothing". `async/timeout` is
// not in `_isAbsentName` and must not be added to it: a policy that
// disappears when its query stalls is a policy an attacker removes by
// stalling the query.
//
// The number and the bound that applies it both come from
// `./posture` rather than being written again here. The posture report
// asks the same handle the same kind of question, so a second copy would
// be a second answer to when this server stops waiting: one of the two
// gets tuned, the other does not, and nothing says which path got which.
var DNS_ANSWER_BUDGET_MS = posture.DNS_ANSWER_BUDGET_MS;

// A body that some receiver will read as two messages, refused where
// every accepted body passes on its way to being stored or relayed.
//
// RFC 5321 §2.3.8 makes CRLF the only line ending, and §4.1.1.4 ends
// the mail data at `<CRLF>.<CRLF>` and nothing else. A dot line whose
// boundary is written any other way is a sequence this server reads as
// body and a lenient receiver reads as the end of the message.
// Everything after it is then a fresh transaction, on a connection this
// server opened and this server authenticated, which is what carries
// the forged sender inside it past SPF, DKIM alignment and DMARC.
// CVE-2023-51764 and its Sendmail and Exim siblings are all that shape.
//
// The framework refuses it at the point of parse, on `DATA` and on the
// chunked path alike, so this is not the only screen the body meets. It
// is a different measurement of the same property rather than a second
// copy of one. The parse-time screen reads the body as it arrives, one
// chunk at a time with a few bytes of overlap and a note of what
// preceded the buffer, because a scan that waited for the whole message
// would make acceptance cost time out of proportion to size. Deciding
// whether an `\n` is bare means reading the byte before it, and that is
// the judgement a chunk boundary makes delicate. This runs at the one
// place every accepted body passes, whichever listener and whichever
// verb it arrived through, and it runs on the assembled message with no
// boundary in it at all, so it asks the question in the form that has no
// edge case, and a body that slipped past the incremental reading is
// caught before anything is stored or relayed.
//
// Composed rather than written out. The guard already knows the four
// boundary spellings and which combinations of them a receiver honors,
// and a second hand-rolled list is a second answer to one question.
//
// The wire code the client sees is `554 5.7.0`, on both listeners,
// set on the rejection below. A body a receiver would read as two
// messages is never going to be taken, so the verdict is permanent and
// the sender is told to stop rather than to retry. The audit row carries
// the envelope and the size, which the reply does not.
//
// The refusal carries a code because the handoffs throw for more than
// one reason: this, and a message no recipient on it resolves for. Both
// reach the listener as the same reply, so a caller that needs to tell
// them apart has only the code to do it with.
var BODY_READ_AS_TWO_MESSAGES = "listeners/body-read-as-two-messages";

// ---- the receiver's own name on a message ---------------------------------
//
// RFC 8601 §5 has a receiver remove every `Authentication-Results` header
// carrying its own authserv-id before it adds the one it computed.
// Everything downstream that reads such a header is reading it because
// this server's name is on it: the recipient's Sieve script, the browser
// interface, and the report reader that decides whether a DMARC
// aggregate report counts as evidence. A header a sender wrote under
// that name is a verdict a stranger chose for all three.
//
// The framework removes them before it prepends its own, and it matches
// the field name as a literal line prefix followed by a colon. Every
// reader on the other side is an RFC 5322 parser instead, and the two do
// not agree about what an `Authentication-Results` header is. Measured
// against `b.safeMime.parse`, which is the reader this file hands the
// Sieve interpreter: a header folded onto a second line, one naming the
// receiver in a quoted string, and one with a space or a tab before its
// colon all read as this server's verdict and all three come through a
// prefix match untouched.
//
// So the removal is done again here, against the same reading the
// consumers use. Doing it again rather than instead: the framework's
// pass is what keeps the canonical spelling out, and a screen that
// depends on being the only one would be a screen that stops working the
// day the composition changes.
//
// Two rules, and the second is what makes the first safe:
//
//   - A header naming a DIFFERENT authserv-id is a prior hop's record
//     and stays. It is what a forwarder found before this server saw the
//     message, and RFC 8601 §5 keeps it for that reason. Removing every
//     such header would destroy the evidence the header exists to carry.
//   - This server's name belongs on a message only when this server put
//     it there. `wroteOne` says whether it did, so a message this server
//     authenticated keeps the topmost claim and loses the rest, and a
//     message it authenticated nothing about loses all of them.
//
// Byte-preserving. The header block is decoded as latin1 and the body is
// never decoded at all, so 8-bit content is untouched, and a header that
// is kept is written back with the folding it arrived with rather than
// with a rendering of it.

// The field name, its optional obsolete whitespace, and its colon. RFC
// 5322 §3.6.8 writes the field name against the colon and §4.5.8 carries
// the form with whitespace between them as syntax a parser still
// accepts. `b.safeMime.parse` accepts both, so this matches both: a
// screen narrower than the reader in front of it is the whole defect.
var RECEIVER_VERDICT_FIELD_RE = /^Authentication-Results[ \t]*:/i;

// The name a message's `Authentication-Results` header claims was
// written by. RFC 8601 §2.2 puts the authserv-id first, as a bare token
// or as a quoted string, optionally followed by a version number.
function _verdictIdentity(value) {
  var head = b.structuredFields.splitUnquoted(
    b.structuredFields.unfoldHeaderContinuations(value), ";")[0];
  if (head === undefined || head === null) return "";
  head = String(head).trim();
  var space = head.search(/[ \t]/);
  return b.structuredFields.stripDoubleQuotes(space === -1 ? head : head.slice(0, space)).trim();
}

/**
 * @primitive blamepost.mail.listeners.screenReceiverVerdicts
 * @signature blamepost.mail.listeners.screenReceiverVerdicts(body, authservId, wroteOne)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 8601 §5, RFC 8601 §2.2, RFC 5322 §3.6.8, RFC 5322 §4.5.8
 * @related   blamepost.mail.listeners.create, blamepost.mail.reports.create
 *
 * One message with every `Authentication-Results` header claiming this
 * server's authserv-id removed, except the one this server wrote.
 * Returns the body unchanged when there is nothing to remove, so a
 * message that carries no such header pays a scan of its header block
 * and nothing else.
 *
 * `wroteOne` is whether this server computed a verdict for this message.
 * When it did, the topmost claim is the one it prepended and is kept.
 * When it did not, every claim under its name is a sender's and none is
 * kept.
 *
 * Headers naming any other authserv-id are a prior hop's record and are
 * never touched. The body is never decoded.
 *
 * @example
 *   var screened = blamepost.mail.listeners.screenReceiverVerdicts(
 *     body, "mx.example.com", true);
 */
function screenReceiverVerdicts(body, authservId, wroteOne) {
  var bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
  if (typeof authservId !== "string" || authservId.length === 0) return bytes;
  // Where the header block ends is asked of the one derivation that
  // answers it, which reads a bare LF as an end of line as well as a
  // CRLF. A scan for the CRLF spelling alone reads a message written
  // with bare LF as headers all the way down, and the sender then
  // chooses which of its own body lines this screen treats as a header.
  var brk = headerBreak(bytes);
  var headerEnd = brk === null ? bytes.length : brk.at + brk.terminator;
  var head = bytes.slice(0, headerEnd).toString("latin1");
  if (head.toLowerCase().indexOf("authentication-results") === -1) return bytes;

  // Lines with their own terminators kept beside them, so a header that
  // stays is written back as the octets it arrived as rather than as a
  // rendering of them.
  var pieces = head.split(/(\r\n|\n)/);
  var lines = [];
  for (var p = 0; p < pieces.length; p += 2) {
    if (pieces[p].length === 0 && p + 1 >= pieces.length) continue;
    lines.push({ text: pieces[p], term: pieces[p + 1] === undefined ? "" : pieces[p + 1] });
  }

  // Header by header rather than line by line, because the identity that
  // decides this can be on a continuation line. A header is its first
  // line plus every following line that begins with whitespace (RFC 5322
  // §2.2.3).
  var kept = "";
  var removed = 0;
  var keptOwn = false;
  for (var i = 0; i < lines.length; i += 1) {
    var block = [lines[i]];
    while (i + 1 < lines.length &&
           (lines[i + 1].text.charAt(0) === " " || lines[i + 1].text.charAt(0) === "\t")) {
      i += 1;
      block.push(lines[i]);
    }
    if (RECEIVER_VERDICT_FIELD_RE.test(block[0].text)) {
      var value = block.map(function (line) { return line.text; }).join("\r\n")
        .replace(RECEIVER_VERDICT_FIELD_RE, "");
      if (_verdictIdentity(value) === authservId) {
        if (wroteOne === true && !keptOwn) keptOwn = true;
        else { removed += 1; continue; }
      }
    }
    for (var k = 0; k < block.length; k += 1) kept += block[k].text + block[k].term;
  }
  if (removed === 0) return bytes;
  return Buffer.concat([Buffer.from(kept, "latin1"), bytes.slice(headerEnd)]);
}

// Who acted, for a row this file writes about something that happened on
// a socket.
//
// A listener serves two kinds of principal on one port and the choice
// between them is made per row rather than per listener. A session that
// authenticated has both halves: the account or credential the exchange
// named, and the address it arrived from. A connection that presented
// nothing has the second alone, and that is what the row records: a name
// a refused attempt claimed is a name whoever is guessing chose, and
// writing it into the column that answers who acted hands an auditor a
// value the peer picked. So the identity is passed only where one was
// proved, and its absence is the answer rather than a gap.
//
// The peer is the column rather than a field inside the metadata blob
// because `b.audit.query` filters on action, outcome and the actor
// columns and takes no metadata criteria. What else came from one
// address is the question an operator asks after a break-in, and it is
// answerable only from a column.
//
// The connection is carried where the handler holds one, so two sessions
// the same account opened at once are told apart on the trail.
//
// Built by the module that owns the shape, which is where each field is
// trimmed, bounded and stripped of the codepoints a terminal acts on
// rather than prints.
function _wireActor(principal, peer, connectionId) {
  return auditActor.build({
    userId:    (principal && principal.id) || null,
    ip:        peer || (principal && principal.remoteAddress) || null,
    sessionId: connectionId || null,
  });
}

// The peer a listener handed over on a message, whichever of the two
// shapes it arrived in. The MX and submission listeners put it on the
// handoff as a nested pair, and the policy hooks put it beside the
// envelope; a row written from either has the same address to record.
function _peerOn(carrier) {
  if (!carrier || typeof carrier !== "object") return null;
  if (typeof carrier.remoteAddress === "string") return carrier.remoteAddress;
  var remote = carrier.remote;
  return (remote && typeof remote.address === "string") ? remote.address : null;
}

function _refuseIfReadAsTwoMessages(direction, envelope, body) {
  var bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
  if (!b.guardSmtpCommand.detectBodySmuggling(bytes)) return;
  b.audit.safeEmit({
    action:   "blamepost.mail.listeners.body_read_as_two_messages",
    outcome:  "denied",
    // One expression, two right answers. An inbound message is a
    // stranger's and names a peer alone; an outbound one was submitted
    // by an account that authenticated and names both.
    actor:    _wireActor(envelope.actor, _peerOn(envelope), envelope.connectionId),
    metadata: {
      direction:      direction,
      mailFrom:       envelope.mailFrom || "",
      recipientCount: (envelope.rcpts || []).length,
      sizeBytes:      bytes.length,
    },
  });
  var err = new Error("this message body carries an end-of-data sequence that is not the one " +
    "RFC 5321 section 4.1.1.4 defines, so a receiver that honors it would read one message as " +
    "two and take the second as sent from here. It is refused rather than stored or relayed.");
  err.code = BODY_READ_AS_TWO_MESSAGES;
  // The same reply the listener's own bare-LF refusal writes, because a
  // peer cannot act on the difference between the two and should not
  // have to. 554 is the transaction failure RFC 5321 section 4.2.2
  // defines for a message refused after it was accepted for transfer,
  // which is where this check runs. Without a code the framework
  // answers 451 and the sender retries a body that will never be taken.
  err.smtpCode       = "554";
  err.enhancedStatus = "5.7.0";
  err.replyText      = "Message refused: body carries an end-of-data sequence " +
    "RFC 5321 section 4.1.1.4 does not define";
  throw err;
}

// ---- the author an authenticated account may write ------------------------
//
// The listener binds the envelope sender and stops there: it compares
// `MAIL FROM` against the authenticated account's mailbox set and never
// reads the message. `From` is the address a person actually reads, and
// it arrives unbound, so an account that passes the envelope binding can
// still put any address it likes on the letter. The relay signs on the
// way out, so the forged header leaves under the hosting domain's own
// key, arrives aligned and passes DMARC on this server's authority
// rather than in spite of it. Between two accounts on one server that is
// impersonation with a valid password in front of it, which is the same
// thing hard rule 5 refuses at the envelope and a worse version of it.
//
// ## What the account may write
//
// The set is computed from the store rather than taken from a list,
// because the store is already the thing that decides who an address
// belongs to. It holds the account's own address and every alias that
// lands in that account's mailbox, and every comparison folds an RFC
// 5233 tag the way routing folds one, so `alice+receipts@example.com`
// is her address here exactly as it is her address to the MX listener.
//
// A catch-all is excluded, and that exclusion is the load-bearing one. A
// catch-all claims every name at a domain, so counting it as an identity
// would hand the account holding it every address the domain could ever
// have, which is the defect restated rather than fixed.
//
// ## The rule
//
// Every address this server hosts that appears in `From` or `Sender`
// must be one this account may write, and at least one address across
// the two must be, so the message is attributable to somebody who
// authenticated for it.
//
// The two halves answer different failures. The first is alignment: an
// author at a hosted domain gets this server's signature, so writing a
// colleague's address there is forgery this server performs on the
// client's behalf. The second is attribution: an author at a domain
// nobody here hosts gets no alignment from this server's key and is
// answered by that domain's own DMARC policy, but a message naming only
// such an author is one this server relays for nobody it can name.
//
// RFC 5322 §3.6.2 makes `Sender` the agent that actually transmitted a
// message, which is the on-behalf-of shape real clients emit, and the
// rule keeps it working for an outside author while refusing to let it
// license a local one. A `Sender` header is written by the same client
// as the `From` header, so treating it as permission to write any local
// address would put the binding one header away from being bypassed by
// exactly the account it was meant to stop.
var FROM_HEADER_NOT_OWNED = "listeners/from-header-not-owned";

// The send-volume ceiling a sending credential crossed. The window is
// rolling, so the refusal is TEMPORARY: the sender is told to come back
// rather than to stop, and RFC 5321 section 4.2.1 makes that a 4yz.
var SENDING_CREDENTIAL_CEILING = "listeners/sending-credential-ceiling";

// A send-volume ceiling this server could not read at all, which is a
// different thing from one that was crossed and wants a different answer.
// A crossed ceiling is the sender's to wait out; an unreadable one is the
// operator's to repair, and the message is refused either way because a
// ceiling that cannot be measured has not been shown to be clear.
var SENDING_CREDENTIAL_CEILING_UNREADABLE = "listeners/sending-credential-ceiling-unreadable";

// A sending credential that has stopped standing since the session
// authenticated. The refusal is PERMANENT: an expiry an operator wrote,
// a domain they withdrew and a credential they revoked are all decisions
// rather than conditions, so RFC 5321 section 4.2.1 makes this a 5yz and
// the sending application is told to stop rather than to come back.
var SENDING_CREDENTIAL_STOPPED = "listeners/sending-credential-stopped";

// An account that has left service since its session authenticated. The
// refusal is PERMANENT for the same reason the credential one above is:
// a suspension, an archive, an erasure and a withdrawn domain are all
// decisions an operator made rather than conditions that clear on their
// own, so RFC 5321 section 4.2.1 makes this a 5yz on the submission port
// and the mailbox protocols answer their own negative verdict.
var SESSION_ACCOUNT_STOPPED = "listeners/session-account-stopped";

// How many identities a refusal and its audit row name. The client
// chooses the header and may write a hundred addresses into it, so an
// unbounded join hands it the size of the row this server writes about
// it. The counts are reported whole even when the names are not.
var MAX_REPORTED_IDENTITIES = 16;

function _identityList(addresses) {
  var named = addresses.slice(0, MAX_REPORTED_IDENTITIES);
  var rest  = addresses.length - named.length;
  return rest > 0 ? named.join(", ") + ", and " + rest + " more" : named.join(", ");
}

// The header block of a message, as octets, in the form a MIME reader
// wants: the headers as they arrived, then the empty line that ends
// them, and no body.
//
// The message never becomes text. Decoding it would substitute a
// replacement character for every octet the decoder does not recognize,
// which is three octets where there was one, and this is a message this
// server is about to sign and relay: the copy that leaves has to be the
// copy that arrived. Where the block ends is `headerBreak`'s answer
// rather than a scan taken here, so this reads the same octets every
// other surface reads.
//
// Trimming the body off is what keeps the reader's own ceilings from
// deciding whether a message is deliverable. A full parse is bounded on
// part count, nesting depth, body size and the charsets it will accept,
// and a large or unusual body that trips one of those would refuse a
// message whose header block is perfectly ordinary. Only the headers
// decide anything here, so only the headers are handed over.
var HEADER_BLOCK_END = Buffer.from("\r\n\r\n", "ascii");

function _headerBlockOnly(bytes) {
  var brk = headerBreak(bytes);
  var end = brk === null ? bytes.length : brk.at;
  return Buffer.concat([bytes.subarray(0, end), HEADER_BLOCK_END]);
}

// Every value a message carries under one header name, in the order it
// wrote them. Read off the parsed block rather than counted here,
// because how many times a field appears is the question a forged
// header is asked to produce two answers to.
function _headerValues(parsed, name) {
  var raw = (parsed && parsed.headers && parsed.headers.raw) || {};
  var values = raw[name];
  return Array.isArray(values) ? values : [];
}

/**
 * @primitive blamepost.mail.listeners.permittedAuthors
 * @signature blamepost.mail.listeners.permittedAuthors(store, actor)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5233 (subaddressing), RFC 5322 §3.6.2 (From and Sender)
 * @related   blamepost.mail.listeners.create, blamepost.store.address.parse
 *
 * Every address an authenticated account may write as the author of a
 * message. Returns an array of canonical addresses, tags folded away,
 * with the account's own address first.
 *
 * Computed from the store on every message rather than cached on the
 * session, because an alias the operator withdraws should stop being a
 * sending identity at the next message rather than at the next sign-in.
 *
 * A catch-all alias is not an identity and is left out. It claims every
 * name at a domain, so counting one would hand the account that holds
 * it every address the domain could ever carry, which is the thing this
 * binding exists to refuse.
 *
 * @example
 *   var authors = blamepost.mail.listeners.permittedAuthors(store, {
 *     id:      account.id,
 *     address: "Alice+News@Example.com",
 *   });
 *   authors[0];
 *   // "alice@example.com"
 */
function permittedAuthors(store, actor) {
  var own = storeAddress.parse((actor && actor.address) || "");
  var out = [];
  if (own.ok) out.push(own.address);
  if (!own.ok || !store.aliases || typeof store.aliases.list !== "function") return out;

  var rows;
  try {
    rows = store.aliases.list({ destination: own.address });
  } catch (_e) {
    // The account's own address came from a sign-in this store just
    // accepted, so a refusal here is the store answering about aliases
    // rather than about her. The account keeps its own address, which
    // is the set it started with, and the message is measured against
    // that: a lookup that failed must not widen what anybody may write.
    return out;
  }

  for (var i = 0; i < (rows || []).length; i += 1) {
    var row = rows[i];
    if (!row || row.isCatchAll === true) continue;
    var alias = storeAddress.parse(row.address || "");
    if (!alias.ok || out.indexOf(alias.address) !== -1) continue;
    out.push(alias.address);
  }
  return out;
}

// The sending scope an actor carries, or null when it carries none.
//
// One reader for the question "is this identity a sending credential",
// so nothing branches on the shape of the field itself. It is total and
// fails towards the account path: an actor whose scope is present but
// malformed answers null, and an account with no addresses may write
// nothing, so a damaged scope refuses rather than widening.
//
// The fields are re-checked here rather than trusted from the verifier
// that built them, because this is what every permission decision below
// reads and it is one function call from the wire.
function _sendingCredentialOf(actor) {
  var scope = actor && actor.sendingCredential;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return null;
  if (typeof scope.id !== "string" || scope.id.length === 0) return null;
  if (typeof scope.domain !== "string" || scope.domain.length === 0) return null;
  if (!Array.isArray(scope.refusedLocalParts)) return null;
  return scope;
}

// Why one canonical address falls outside a sending scope, or null when
// it falls inside. The scope is a whole hosted domain minus two sets of
// local parts, which no array can enumerate, so the question is asked
// about one address rather than answered as a list.
//
// The two sets are read at different moments.
//
// The credential's own refusal list is operator configuration. It is
// stored on the credential, bound into the credential's keyed digest,
// and changed only by `blamepost credential refusals`, so it is read off
// the scope the credential verified under.
//
// A mailbox carrying the operator role is refused on top of that list,
// and the role is read from the account table on every call. The list a
// credential starts with names the operator mailboxes that existed when
// it was issued, and nothing rewrites that list when an operator creates
// an account with the role or grants the role to an existing one. Read
// from the stored list alone, a credential issued in January writes as
// an operator mailbox added in June. `accounts.get` returns the account
// as it stands at this call, so a role granted a moment ago is refused
// at the next message on both transports, including on an SMTP session
// that authenticated before the grant.
//
// The operator-role refusal is a floor rather than a default: clearing
// or shortening a credential's refusal list does not lift it. Emptying
// the list is how an operator lets an application answer as postmaster
// or abuse. The stored result is an empty array, and an empty array
// cannot record whether the operator meant it to cover operator
// mailboxes that did not exist yet. Writing as an account that holds the
// admin console is a different permission from writing as a role
// address, and this server signs that mail into DMARC alignment for the
// domain.
//
// Compared at the mailbox the address is DELIVERED to. `parse` folds the
// RFC 5233 tag away, so `orders+august@example.com` is measured as
// `orders`, which is the same reading the routing layer, the refusal
// list and the account lookup are all written against. A comparison on
// the written spelling would let a tag walk straight past both sets.
//
// It fails closed. A store with no account handle, or an account lookup
// that raises, answers `operator-role-unreadable`, because an address
// that could not be checked against the operator role has not been
// shown to be outside it.
function _sendingScopeRefusal(store, scope, parsed) {
  if (parsed.domain !== scope.domain) return "domain-outside-scope";
  if (scope.refusedLocalParts.indexOf(parsed.localPart) !== -1) return "local-part-refused";
  var accounts = store && store.accounts;
  if (!accounts || typeof accounts.get !== "function") return "operator-role-unreadable";
  var account;
  try {
    account = accounts.get(parsed.address);
  } catch (_e) {
    return "operator-role-unreadable";
  }
  if (account && account.isAdmin === true) return "operator-mailbox";
  return null;
}

/**
 * @primitive blamepost.mail.listeners.permittedAuthor
 * @signature blamepost.mail.listeners.permittedAuthor(store, actor, candidate)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5233 (subaddressing), RFC 5322 §3.6.2 (From and Sender)
 * @related   blamepost.mail.listeners.permittedAuthors, blamepost.mail.listeners.authorBinding
 *
 * Whether one address is one this identity may write. Returns a boolean
 * and never throws, so a wire handler can hand it whatever arrived.
 *
 * This is the decision, and `permittedAuthors` beside it is the display.
 * The two are kept apart because they answer different questions and
 * only one of them can be answered as a list. An account may write a
 * finite set of addresses, which a browser can offer as a menu. A
 * sending credential may write every local part at one hosted domain
 * except the ones on its own refusal list and any mailbox there that
 * carries the operator role, and an array cannot say that: rendered as a
 * list it is empty, and an empty list read as a decision refuses the
 * credential everything.
 *
 * The operator role is read from the account table on every call rather
 * than from the credential, so a mailbox created with the role or granted
 * it after the credential was issued is refused at the next message. The
 * refusal holds whatever the credential's own refusal list says,
 * including a list the operator has emptied.
 *
 * Every enforcement reader goes through here. Moving one of them and
 * leaving the other is worse than moving neither, because it produces a
 * server that permits an address as an author and refuses the same
 * address as an envelope sender.
 *
 * The candidate is parsed here rather than taken as canonical, so an
 * address this server cannot read is false rather than a comparison
 * against a spelling.
 *
 * @example
 *   if (!permittedAuthor(store, session.actor, "orders@example.com")) refuse();
 */
function permittedAuthor(store, actor, candidate) {
  var parsed = storeAddress.parse(candidate || "");
  if (!parsed.ok) return false;
  var scope = _sendingCredentialOf(actor);
  if (scope !== null) return _sendingScopeRefusal(store, scope, parsed) === null;
  return permittedAuthors(store, actor).indexOf(parsed.address) !== -1;
}

// The actor a verified sending credential carries for the rest of the
// session.
//
// `mailboxes` holds ONE entry and it is not an address. The framework
// compares `MAIL FROM` against this array before it asks the sender
// policy, so a real address here would be one the credential may write
// without the refusal list ever being consulted, and a refusal list an
// operator changes between two messages would not reach the session
// that is sending them. There is no address a domain scope covers
// unconditionally, so there is nothing honest to put here, and every
// envelope has to reach the policy that reads the live scope.
//
// An EMPTY array would do that and is the wrong answer for a different
// reason. The framework reads an empty set as "this identity has no
// send-as identity assigned" and refuses with
// `authenticated identity has no assigned mailboxes`, which is true of
// an account whose provisioning is unfinished and false of a
// credential: it has a scope, and the scope simply does not cover the
// address that was offered. An operator who reads that sentence goes
// and assigns a mailbox that has nothing to do with the refusal.
//
// So the entry is a name for the scope rather than a member of it. It
// is written in angle brackets, and that is what makes it unspellable
// rather than merely unlikely: RFC 5321 section 4.1.2 puts the reverse
// path inside angle brackets, the framework reads it with a capture
// that stops at the first `>`, and a string carrying one can therefore
// never be produced from a `MAIL FROM` line. The comparison against it
// cannot match, every envelope goes to the policy, and the refusal a
// peer reads is the one that is true of a credential.
//
// `roles` is ABSENT rather than empty, and the two are not the same
// thing to write. `b.permissions` reads an actor's scopes when it has
// an array of them and its roles otherwise, and an actor carrying
// neither resolves to no scope and is refused every verb. An empty
// array resolves to the same nothing and reads as a field somebody
// meant to fill, so the absent spelling is the one that says a
// credential holds no mailbox permission on purpose.
//
// `address` is empty because a credential has none. The scope beside
// it is what every permission decision reads, and it is frozen so a
// handler holding the session cannot widen the domain or shorten the
// refusal list it was verified under.
//
// One construction, module level, reached by every transport. Two
// assemblies of this shape drift a field at a time, and the field that
// drifts decides what the credential may write.
// `remoteAddress` is the peer that presented the credential, carried on
// the identity because that is the object the whole session holds. The
// rows a credential's session writes are refusals an operator reads
// during an incident, and the address an application is sending from is
// what they can act on; a row that named the credential and not the
// address cannot say whether the application moved or somebody else has
// the token.
function _credentialActorFor(verdict, peer) {
  return {
    id:        verdict.credentialId,
    username:  verdict.domain,
    address:   "",
    domain:    verdict.domain,
    isAdmin:   false,
    mailboxes: [_scopeName(verdict.domain)],
    remoteAddress: typeof peer === "string" && peer.length > 0 ? peer : null,
    sendingCredential: Object.freeze({
      id:                verdict.credentialId,
      domain:            verdict.domain,
      bounceMailbox:     verdict.bounceMailbox,
      returnPath:        verdict.returnPath || null,
      refusedLocalParts: Object.freeze((verdict.refusedLocalParts || []).slice()),
    }),
  };
}

/**
 * @primitive blamepost.mail.listeners.verifySendingCredential
 * @signature blamepost.mail.listeners.verifySendingCredential(registry, opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 4954 §4 (SASL over submission), RFC 9110 §11.6.2 (Bearer)
 * @related   blamepost.mail.listeners.permittedAuthor, blamepost.store.credentials.verify
 *
 * One presented sending credential, checked and turned into the actor
 * every permission decision reads. Returns `{ ok: true, actor }` or
 * `{ ok: false, reason }` and never throws, so a wire handler and a
 * route handler can both hand it whatever arrived.
 *
 * This is the entry point for the credential identity space, and it is
 * the only place the failure budget for that space is read and spent.
 * The budget is keyed on the identifier inside the token PAIRED with the
 * peer that presented it. The identifier names a row and is not a
 * secret, so a wrong secret is charged to the credential it was offered
 * for; it is also a value this server hands out, so a run of guesses
 * locks the credential for the address that made them and for no other
 * address. A transport that reached the registry directly would answer
 * the same question with no budget at all, and the bound the other
 * transports enforce would be one an attacker walks around by choosing
 * that transport.
 *
 * `opts.source` is therefore part of what is enforced rather than only
 * something the audit row carries. A caller that names no peer is
 * counted against a key of its own; both transports composed here read
 * one off their own socket.
 *
 * `opts.presentedAs` is the domain the client NAMED, when the transport
 * carries one. SASL does, in the authentication identity, and the row's
 * own domain has to match it: without that check a token pasted into
 * the configuration of an application for another domain would sign in
 * and send as the domain it really belongs to, under a name the
 * operator never wrote and this server would sign into alignment. A
 * Bearer header names no domain, so there is nothing to cross-check and
 * the scope is read off the row alone.
 *
 * Every refusal is the same refusal. The registry files its own row
 * naming which of not-found, revoked, expired, a broken binding or a
 * withdrawn domain it was, so an operator reads the distinction off the
 * trail while a client gets one answer to act on. A spent budget is not
 * told apart from a wrong secret on the wire either, because a
 * distinguishable lockout is a lockout an attacker can measure.
 *
 * @opts
 *   secret:      string,  // required; the token exactly as it was presented
 *   presentedAs: string,  // optional; the domain the client named, when it named one
 *   source:      string,  // optional; the peer. Half of the failure budget key, and
 *                         //   recorded on the audit row
 *
 * @example
 *   var checked = await verifySendingCredential(store.credentials, {
 *     secret: presented, source: peer,
 *   });
 */
async function verifySendingCredential(registry, opts) {
  opts = opts || {};
  if (!registry || typeof registry.verify !== "function") {
    // No registry was composed, so this server issues no sending
    // credentials and a token names nobody. The answer is a refusal
    // rather than a fall-through, which on the submission listener
    // would let a domain be measured as an address.
    return { ok: false, reason: "sending-credentials-not-configured" };
  }
  var secret = opts.secret;
  if (typeof secret !== "string" || secret.length === 0) {
    return { ok: false, reason: "credentials-rejected" };
  }
  var id = _credentialIdOf(secret);
  // A token that does not parse at all is charged to nothing, because
  // there is no credential it names.
  if (id === null) return { ok: false, reason: "credentials-rejected" };

  var budgets = _credentialBudgets();
  var budgetKey = _credentialBudgetKey(id, opts.source);

  // One failure, counted twice: once against this peer, which is what
  // refuses, and once against the credential across every peer, which
  // only files a row. The second call's verdict is not read, and the
  // comment above `CREDENTIAL_SPREAD_ATTEMPTS` says why acting on it
  // would put back the lockout any peer can reach.
  async function spend() {
    await budgets.peer.recordFailure(budgetKey);
    await budgets.spread.recordFailure(id);
  }

  var standing = await budgets.peer.check(budgetKey);
  if (standing.locked === true) return { ok: false, reason: "too-many-attempts" };

  var verdict = await registry.verify(secret);
  if (!verdict || verdict.ok !== true) {
    await spend();
    return { ok: false, reason: "credentials-rejected" };
  }
  var presentedAs = typeof opts.presentedAs === "string" && opts.presentedAs.length > 0
    ? opts.presentedAs
    : null;
  if (presentedAs !== null && verdict.domain !== presentedAs) {
    await spend();
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_domain_mismatch",
      outcome:  "denied",
      // The peer and nobody. A credential that named the wrong domain
      // has not been accepted as an identity, and the row that records
      // the refusal must not read as though it had: the id the token
      // carries goes in the metadata, where it is evidence about what
      // was presented rather than an answer to who acted.
      actor:    _wireActor(null, opts.source),
      metadata: {
        credentialId: verdict.credentialId,
        presentedAs:  presentedAs,
        scopeDomain:  verdict.domain,
      },
    });
    return { ok: false, reason: "credentials-rejected" };
  }
  // A secret that verified is not a guess. The counter kept against this
  // credential on THIS peer goes back to zero, and nothing else does.
  // The counters other peers have spent stand, because a correct secret
  // presented from the application's own address says nothing about the
  // address that was guessing; clearing theirs would hand a guesser a
  // fresh five attempts at the rate the application happens to send. And
  // there is no source exemption to grant, because a sending application
  // is not a person who can be locked out of their own mail.
  await budgets.peer.recordSuccess(budgetKey);
  return { ok: true, actor: _credentialActorFor(verdict, opts.source) };
}

// One refusal of an author, said out loud and written down.
//
// The message names the identity that was rejected and the ones that
// would have been accepted, because a shared or delegated mailbox is
// the first thing an operator trips over here and a bare refusal sends
// them to look at their mail client. The row carries the same pair, so
// the answer survives the session that produced it.
// The two classes of author refusal, as RFC 3463 enhanced statuses.
//
// `5.6.0` is a content fault: the header block is malformed, so there is
// no author to check against anything. `5.7.1` is an authorization
// fault: the header is well formed and names an address this account
// does not hold. A peer branches on these, and the difference is the one
// worth telling it about, because the first is the sending client's bug
// and the second is the operator's provisioning.
var AUTHOR_HEADER_STATUS = "5.6.0";
var AUTHOR_POLICY_STATUS = "5.7.1";

// The reply the peer reads. Kept short and fixed per class: the full
// explanation names addresses and runs to several lines, which belongs
// in the log and the audit row rather than in an SMTP reply.
var AUTHOR_REPLY_TEXT = {
  "5.6.0": "Message rejected: From or Sender header cannot be read as a single author",
  "5.7.1": "Message rejected: author address not owned by authenticated identity",
};

// What an identity may write, in the sentence an operator reads, and the
// advice that follows from it.
//
// Two forms, because the two identities are shaped differently and a
// sentence written for one is false about the other. An account holds a
// list of addresses, so naming the list is the answer and adding an
// alias is the fix. A sending credential holds a domain, so there is no
// list to name and no alias to add: the answer is the domain it speaks
// for and the addresses inside it that are held back, and the fix for an
// address anywhere else is a credential for that domain.
//
// The account form's empty case says the identity has no mailbox
// assigned to it yet, which is true of an account whose provisioning is
// unfinished. It is reached only by an account, because a credential
// takes the branch above it.
function _permittedAuthorSentence(actor, allowed, permitted) {
  var scope = _sendingCredentialOf(actor);
  if (scope !== null) {
    return "The sending credential for " + scope.domain + " may write any address at " +
      scope.domain + " other than " +
      (scope.refusedLocalParts.length === 0
        ? ""
        : _identityList(scope.refusedLocalParts.map(function (part) {
          return part + "@" + scope.domain;
        })) + " and ") +
      "any mailbox there that carries the operator role. An address at any other domain " +
      "needs a credential issued for that domain.";
  }
  return "The account " + ((actor && actor.address) || "that signed in") + " may write " +
    (allowed.length === 0
      ? "no author address at all, which means it has no mailbox assigned to it yet"
      : "these author addresses: " + permitted) +
    ". Add the address as an alias for this account if it should be one it can write.";
}

// `carrier` is the handoff the refusal was reached through. The peer and
// the connection live on it rather than on the actor, and a row written
// without them names who authenticated and not where the session came
// from, which is the half an operator reads a wire row for.
function _refuseAuthor(actor, allowed, rejected, why, status, carrier) {
  // No default. A site that forgets to say which class it is would
  // otherwise inherit whichever one was written here, and the two carry
  // opposite advice to the peer.
  if (status !== AUTHOR_HEADER_STATUS && status !== AUTHOR_POLICY_STATUS) {
    throw new TypeError("_refuseAuthor: status must be " + AUTHOR_HEADER_STATUS +
      " or " + AUTHOR_POLICY_STATUS + ", got " + JSON.stringify(status));
  }
  var permitted = _identityList(allowed);
  var scope = _sendingCredentialOf(actor);
  b.audit.safeEmit({
    action:   "blamepost.mail.listeners.submission_from_not_owned",
    outcome:  "denied",
    actor:    _wireActor(actor, _peerOn(carrier), carrier && carrier.connectionId),
    metadata: {
      // What the client authenticated as, which for a credential is the
      // domain it named on the AUTHENTICATE line rather than an address.
      // `identityKind` is beside it because the two are different kinds
      // of string and a query that reads one without the other would
      // take a bare domain for a malformed address.
      authenticatedAs: scope !== null ? scope.domain : ((actor && actor.address) || ""),
      identityKind:    scope !== null ? "sending-credential" : "account",
      credentialId:    scope !== null ? scope.id : null,
      scopeDomain:     scope !== null ? scope.domain : null,
      rejected:        rejected,
      reason:          why,
      // A credential's permitted set is a domain rather than a list, and
      // the count is null rather than zero because zero is a number an
      // operator reads as a provisioning fault.
      permitted:       scope !== null ? "any address at " + scope.domain : permitted,
      permittedCount:  scope !== null ? null : allowed.length,
      refusedLocalParts: scope !== null ? scope.refusedLocalParts.slice() : null,
    },
  });
  var err = new Error("this message was not relayed because " + why + ". " +
    _permittedAuthorSentence(actor, allowed, permitted));
  err.code = FROM_HEADER_NOT_OWNED;
  // The reply this refusal asks the listener for. Without these the
  // framework answers 451, which tells a conforming MTA the refusal is
  // temporary (RFC 5321 section 4.2.1), so it retries a message that
  // will be refused identically until its queue lifetime runs out and
  // the sender never learns why.
  err.smtpCode       = "550";
  err.enhancedStatus = status;
  err.replyText      = AUTHOR_REPLY_TEXT[status];
  throw err;
}

// The author binding, applied to one accepted message before anything
// signs or relays it.
//
// Refusing here rather than later is the whole point: the message has
// not been signed, has not reached a mailbox and has not left the
// building, so a refusal costs the forged letter everything and costs a
// legitimate one a retry.
async function _refuseUnownedAuthor(store, outbound) {
  var actor = outbound.actor || null;
  var allowed = permittedAuthors(store, actor);
  var bytes = Buffer.isBuffer(outbound.body)
    ? outbound.body
    : Buffer.from(String(outbound.body || ""), "utf8");

  var parsed;
  try {
    parsed = b.safeMime.parse(_headerBlockOnly(bytes), mailbox.MESSAGE_PARSE_CAPS);
  } catch (err) {
    // The parser's own answer, screened. It quotes the header line the
    // peer sent, so the codepoints in it are the peer's to choose, and
    // this sentence is written into an audit row an operator reads back.
    _refuseAuthor(actor, allowed, "",
      "its header block could not be read, so there is no author to check it against " +
      "and this server will not sign a message whose sender it cannot identify (" +
      displayText.forDisplay((err && err.message) || String(err)) + ")",
      AUTHOR_HEADER_STATUS, outbound);
  }

  var fromValues   = _headerValues(parsed, "from");
  var senderValues = _headerValues(parsed, "sender");

  // RFC 5322 section 3.6 allows one From and at most one Sender. Two of
  // either leaves the author for the receiver to choose, and different
  // receivers choose differently, which is the choice a forged header
  // is written to exploit.
  if (fromValues.length === 0) {
    _refuseAuthor(actor, allowed, "",
      "it carries no From header, and RFC 5322 section 3.6 requires one. A message with " +
      "no author is one this server would sign without knowing whose it is",
      AUTHOR_HEADER_STATUS, outbound);
  }
  if (fromValues.length > 1) {
    _refuseAuthor(actor, allowed, "",
      "it carries " + fromValues.length + " From headers and RFC 5322 section 3.6 allows " +
      "one, so which address a recipient is shown depends on which mail program opens it",
      AUTHOR_HEADER_STATUS, outbound);
  }
  if (senderValues.length > 1) {
    _refuseAuthor(actor, allowed, "",
      "it carries " + senderValues.length + " Sender headers and RFC 5322 section 3.6 " +
      "allows one, so the agent that transmitted it is left for the receiver to guess at",
      AUTHOR_HEADER_STATUS, outbound);
  }

  // Every mailbox a receiver MIGHT display, rather than the ones the
  // sender certainly named. The two readings differ on a comma-separated
  // piece that parses as an address by itself, and this is the side of
  // that difference the binding has to take: a mailbox left out of this
  // list is one this server signs for and relays without measuring, and
  // a receiver is shown it all the same. The display surfaces ask the
  // same reader the other question, which its options describe.
  var AUTHOR_READING = { bareAddressIsAMailbox: true };

  var candidates = splitAddressHeader(fromValues[0], AUTHOR_READING).map(function (entry) {
    return { field: "From", written: entry };
  });
  if (candidates.length === 0) {
    _refuseAuthor(actor, allowed, _identityList([_echoHeader(fromValues[0])]),
      "its From header names nobody, so the message identifies no author and displays none",
      AUTHOR_HEADER_STATUS, outbound);
  }
  if (senderValues.length === 1) {
    var senders = splitAddressHeader(senderValues[0], AUTHOR_READING);
    // RFC 5322 section 3.6.2 gives Sender a single mailbox. More than
    // one is not a delegation, it is an ambiguity.
    if (senders.length !== 1) {
      _refuseAuthor(actor, allowed, _identityList([_echoHeader(senderValues[0])]),
        "its Sender header names " + (senders.length === 0 ? "nobody" : senders.length +
        " addresses") + " and RFC 5322 section 3.6.2 gives it exactly one, which is the " +
        "single agent that transmitted the message", AUTHOR_HEADER_STATUS, outbound);
    }
    candidates.push({ field: "Sender", written: senders[0] });
  }

  // Every candidate settled for ambiguity before any of them is
  // measured, and both headers, because one list carries both.
  //
  // RFC 5322 section 3.4 writes a mailbox as an optional display name
  // followed by ONE angle address. Two of them with no comma between is
  // one entry under that grammar and two mailboxes under no grammar at
  // all, and nothing says which a reader takes: some stop at the first
  // and some take the last. This server takes the last, so the first
  // reaches neither the refusal list nor the addresses this identity
  // holds, and a receiver that stops at it is shown an address nothing
  // here read, under this server's own signature and aligned for DMARC.
  //
  // Refusing is the answer rather than reading the other one, because
  // the other end forges just as well: a display name may carry angle
  // brackets of its own, so a reader that took the first would take
  // `"<victim@example.com>" <shop@example.com>` apart at a bracket
  // inside somebody's name. There is no end of the entry that is safe to
  // prefer; what is unsafe is an entry with two ends.
  for (var c = 0; c < candidates.length; c += 1) {
    var written = candidates[c].written;
    var angles  = angleAddressCount(written);
    if (angles > 1) {
      // What to do about it differs by header, because the two carry
      // different numbers of mailboxes. RFC 5322 section 3.6 gives From
      // a list, so a message with two authors is written with a comma;
      // section 3.6.2 gives Sender one agent, so there is nothing to
      // separate and the second address is the part to remove.
      var remedy = candidates[c].field === "From"
        ? " Separate them with a comma if the message really has two authors"
        : " Sender names the one agent that transmitted the message, so remove all but it";
      _refuseAuthor(actor, allowed, _echoHeader(written),
        "its " + candidates[c].field + " header writes " + angles + " addresses into one " +
        "mailbox and RFC 5322 section 3.4 gives it one, so which address a recipient is " +
        "shown depends on which mail program opens it." + remedy, AUTHOR_HEADER_STATUS, outbound);
    }
  }

  var attributable = false;
  for (var i = 0; i < candidates.length; i += 1) {
    var candidate = candidates[i];
    var address = storeAddress.parse(
      normalizeAddress(candidate.written, "listeners: " + candidate.field).address);
    if (!address.ok) {
      _refuseAuthor(actor, allowed, _echoHeader(candidate.written),
        "its " + candidate.field + " header names an address this server cannot read (" +
        address.reason + "), and an address that cannot be read cannot be checked",
        AUTHOR_HEADER_STATUS, outbound);
    }
    // Through the one decision reader rather than against the display
    // list. An account's answer is unchanged, and a sending credential
    // gets the domain scope an array cannot express: `allowed` is empty
    // for one, so a membership test against it would refuse a credential
    // every address in the domain it exists to write.
    var permitted = permittedAuthor(store, actor, address.address);
    if (permitted) attributable = true;
    // A domain this server hosts is a domain this server signs for, so
    // an author there leaves aligned and passes DMARC on this server's
    // say-so. That is the one this account has to be entitled to. An
    // author anywhere else gets no alignment from this server's key and
    // is answered by that domain's own policy.
    var routed = await store.resolve(address.address);
    var hostedHere = routed !== null && routed !== undefined && routed.local === true;
    if (hostedHere && !permitted) {
      _refuseAuthor(actor, allowed, address.address,
        "its " + candidate.field + " header names " + address.address + ", an address at a " +
        "domain this server signs for that this account does not hold. Mail written that " +
        "way arrives carrying this domain's own signature over somebody else's name",
        AUTHOR_POLICY_STATUS, outbound);
    }
  }

  if (!attributable) {
    _refuseAuthor(actor, allowed,
      _identityList(candidates.map(function (c) { return _echoHeader(c.written); })),
      "no address in its From or Sender header is one this account may write, so the " +
      "message is attributable to nobody who signed in to send it",
      AUTHOR_POLICY_STATUS, outbound);
  }
}

// How much of a client's own header a refusal quotes back. The value
// has already been through the wire guard and the MIME reader, so this
// bounds the length of what is repeated rather than its content.
var MAX_REPORTED_HEADER_ECHO = 120;

function _echoHeader(value) {
  var text = String(value === undefined || value === null ? "" : value);
  return text.length > MAX_REPORTED_HEADER_ECHO
    ? text.slice(0, MAX_REPORTED_HEADER_ECHO) + "..."
    : text;
}

// How many refused recipients an audit row and a refusal message name.
// A peer chooses the recipient list and may send a hundred addresses of
// its own devising, so an unbounded join hands it the size of the row
// this server writes about it. The count is reported whole even when
// the names are not.
var MAX_REPORTED_RECIPIENTS = 32;

function _reportedRecipients(refused) {
  var named = refused.slice(0, MAX_REPORTED_RECIPIENTS).map(function (r) { return r.rcpt; });
  var rest  = refused.length - named.length;
  return rest > 0 ? named.join(", ") + ", and " + rest + " more" : named.join(", ");
}

// The order listeners come up in, and the reverse of the order they go
// down in. Mailbox access first so a client reconnecting during a
// restart finds its mailbox before mail starts arriving again.
var START_ORDER = ["imap", "pop3", "managesieve", "submission", "submissions", "mx"];

function _assertPort(value, label) {
  if (typeof value !== "number" || !isFinite(value) ||
      Math.floor(value) !== value || value < 1 || value > 65535) {
    throw new TypeError(label + " must be an integer port between 1 and 65535");
  }
  return value;
}

// Read one listener section. An absent section takes the defaults; a
// present one with a value of the wrong type throws, because a port
// written as a string is a typo the operator should learn about at
// boot rather than through a listener that quietly did not bind.
function _listenerConfig(section, defaults, label) {
  if (section === undefined || section === null) {
    return { enabled: defaults.enabled, port: defaults.port, address: defaults.address,
      maxLineBytes: defaults.maxLineBytes };
  }
  if (typeof section !== "object" || Array.isArray(section)) {
    throw new TypeError("blamepost.mail.listeners.create: config.listeners." + label +
      " must be an object of { enabled, port, address, maxLineBytes }");
  }
  var out = { enabled: defaults.enabled, port: defaults.port, address: defaults.address,
    maxLineBytes: defaults.maxLineBytes };
  if (section.enabled !== undefined) {
    if (typeof section.enabled !== "boolean") {
      throw new TypeError("blamepost.mail.listeners.create: config.listeners." + label +
        ".enabled must be true or false");
    }
    out.enabled = section.enabled;
  }
  if (section.port !== undefined) {
    out.port = _assertPort(section.port, "config.listeners." + label + ".port");
  }
  if (section.address !== undefined) {
    if (typeof section.address !== "string" || section.address.length === 0) {
      throw new TypeError("blamepost.mail.listeners.create: config.listeners." + label +
        ".address must be an interface address such as 0.0.0.0 or ::");
    }
    out.address = section.address;
  }
  if (section.maxLineBytes !== undefined) {
    if (typeof section.maxLineBytes !== "number" || !isFinite(section.maxLineBytes) ||
        Math.floor(section.maxLineBytes) !== section.maxLineBytes ||
        section.maxLineBytes < MIN_LINE_BYTES || section.maxLineBytes > MAX_LINE_BYTES) {
      throw new TypeError("blamepost.mail.listeners.create: config.listeners." + label +
        ".maxLineBytes must be a whole number of octets between " + MIN_LINE_BYTES +
        " and " + MAX_LINE_BYTES);
    }
    out.maxLineBytes = section.maxLineBytes;
  }
  return out;
}

// The per-source ceilings, read from the operator's configuration.
//
// Every listener the framework ships resolves a limiter of its own when
// the caller hands it none, so a composition that passes nothing still
// gets one. It just gets the framework's numbers rather than the
// operator's, and nothing on the wire or in the log says which. The
// numbers matter because they are not all sized for the same peer. Ten
// concurrent connections from one address is a sensible bound on a
// stranger delivering mail to port 25 and a low one for a mailbox
// client: a single mail client holds several IMAP connections open at
// once, and everyone behind one home or office address shares it, so
// the eleventh connection is refused and the person it belongs to reads
// that as the server being down.
//
// The recipient-failure ceiling is the one on this list that bounds an
// attack rather than a workload. RFC 5321 section 3.5 has RCPT TO answer
// differently for a mailbox that exists and one that does not, and the
// MX listener answers a name it does not hold with a permanent refusal
// at RCPT, which is the right answer for a sender and an oracle for a
// stranger: a word list walked against it reads back the account map.
// The ceiling is how many guesses a minute one source gets, so it is
// sized for a list expanding to this server rather than for a scanner.
// Only a refused recipient is charged, so a message to fifty live
// addresses spends none of it.
//
// So the ceilings are read here and handed to every listener. A
// configuration that names none produces an empty specification, which
// is the framework's own default: the same server as before, with the
// numbers now in one place an operator can change.
//
// This list is written by hand against a framework that grows, so it is
// reconciled rather than reviewed. Every name the framework's rate-limit
// defaults publish appears here or on the withheld list below, and
// nothing may be on neither: a ceiling the framework gained and nobody
// here answered for is a real bound, applied on every connection, that
// the operator cannot see in their configuration and cannot move.
// `test/layer-0-primitives/rate-limit-key-parity.test.js` is what makes
// the next one a decision instead of an omission.
//
// Every member is a ceiling an operator can set, so this is a list of what
// the server OFFERS: a name leaving it is a setting a configuration can no
// longer name, and a name arriving is a new lever. It runs the opposite way
// to the withheld list beside it, which is why neither can be classified
// from the direction its count moved.
//
// @membership blamepost.mail.listeners.RATE_LIMIT_KEYS capability
var RATE_LIMIT_KEYS = Object.freeze([
  "maxConcurrentConnectionsPerIp",
  "connectionsPerIpPerMinute",
  "authFailuresPerIpPer15Min",
  "rcptFailuresPerIpPerMinute",
]);

// What each of those is when the operator sets none, read from the
// module that holds the defaults table rather than restated. The four
// above are the keys the specification copies; these are the values it
// starts from, and the message ceiling beside them is what the two SMTP
// listeners advertise as the SIZE keyword of RFC 1870.
//
// The list above says which ceilings this server OFFERS and says nothing
// about what they are, which is the half an operator never sets and
// therefore never sees. Left unseeded, all five come from the framework
// while docs/operator-guide.md publishes them as this server's.
var LIMIT_DEFAULTS = configModule.LIMIT_DEFAULTS;

// The four of them that ride the rate-limit specification, split out so
// the seed below carries the rate-limit keys and nothing else: the
// message ceiling is not one of the limiter's fields and passing it
// there would be a key the framework does not read.
var LIMIT_DEFAULTS_RATE = Object.freeze(RATE_LIMIT_KEYS.reduce(function (acc, key) {
  acc[key] = LIMIT_DEFAULTS[key];
  return acc;
}, {}));

// How many sockets one listener accepts at once, whoever they belong to.
// Passed by all five `create()` calls, so the number is this server's
// rather than whatever the framework currently defaults to: a listener
// running on an inherited value is a listener whose published bound moves
// on a vendored refresh with nothing to say so, while SECURITY.md goes on
// naming the old one.
//
// The per-address ceiling bounds ONE peer and says nothing about how many
// peers there are, so without this the process-wide total is that ceiling
// multiplied by however many source addresses a sender can speak from,
// which a botnet, a NAT pool or a single v6 /64 makes large. This is the
// bound that does not multiply. The runtime applies it before the
// connection handler runs, so a refused socket costs no descriptor and no
// state machine, and the peer is told nothing at all; the listener
// records the refusal against this number, because a listener sitting at
// capacity and turning real senders away otherwise looks exactly like an
// idle one.
//
// It is not offered as a setting, and that is a decision rather than an
// oversight. The number bounds the listener, so the operator lever that
// matters at the volumes where it binds is the process's descriptor
// budget, which belongs to the container and not to this configuration; a
// ceiling raised past what the process can hold turns a refusal a peer can
// read into an accept error it cannot. The interaction that does need
// saying is with maxConcurrentConnectionsPerIp, whose own schema reaches
// this same number: set the two equal and one source address can take the
// whole listener, at which point the listener ceiling stops separating one
// peer from everybody else. The operator guide says so under the ceilings
// table.
var MAX_CONNECTIONS = 1024;

// The slowest a peer may send a transfer, in bytes a second, before the
// listener cuts it. Passed to every listener through the rate-limit
// specification below, for the same reason the socket ceiling is passed:
// SECURITY.md publishes the number, so this server holds it.
//
// It is the bound an idle timeout cannot give. A peer that sends one
// octet, waits, and sends another is never idle and is never making
// progress either, because every arriving octet pushes the idle deadline
// out again, and meanwhile it holds a socket, a slot in the per-address
// ceiling and an assembled body for as long as it likes. The floor is
// judged over bounded windows, so an opening burst buys no credit against
// a slow tail. It covers the DATA and BDAT body on the two SMTP
// listeners, an IMAP literal, and a ManageSieve PUTSCRIPT or AUTHENTICATE
// literal; a peer below it is answered `421 4.7.0` and cut.
var BODY_RATE_FLOOR_BYTES_PER_SECOND = 100;

// The ceilings the framework accepts and this server does not offer as a
// setting, each with the reason it does not.
//
// The list exists so that declining is a decision somebody wrote down.
// Without it the only way past a new framework key would be to wire it,
// so the pressure would be to add a ceiling nobody had thought about,
// which is the same silence in the other direction.
//
// Withheld here means withheld from the OPERATOR, and the two entries
// reach different ends of that. `minBytesPerSecond` is passed on every
// listener at the number above, so what an operator cannot do is move it;
// `disabled` is not passed at all, so what an operator cannot do is exist.
// Reading either entry as "the framework decides this" would be wrong in
// the first case and right in the second, which is why each says which it
// is.
//
// The list reaches only as far as the rate limiter's own table, and that
// is a bound on the check rather than on the problem. `maxConnections` is
// the worked example: a per-listener ceiling on accepted sockets that
// belongs to no rate-limit table, so the parity gate this list feeds
// cannot see it, and naming it here would report it as a ceiling the
// framework no longer accepts. It is held as MAX_CONNECTIONS above
// instead. A ceiling the framework grows in that second category is
// exactly as invisible as the ones the gate was built for, and what stands
// in front of it is a value this repository sets rather than a release
// note somebody reads.
var WITHHELD_RATE_LIMIT_KEYS = Object.freeze({
  minBytesPerSecond:
    "A byte-rate floor on a transfer, held by this server at a hundred bytes a second " +
    "and passed to every listener that reads one, judged over bounded windows " +
    "so an opening burst buys no credit against a slow tail. It covers the DATA and BDAT " +
    "body on the two SMTP listeners, an IMAP literal, and a ManageSieve PUTSCRIPT or " +
    "AUTHENTICATE literal. A peer below that rate is cut, which is the protection " +
    "idleTimeoutMs cannot give, because " +
    "each arriving byte pushes an idle deadline out again. What is withheld is the " +
    "operator's lever rather than the defense, and rather than the number: the value is " +
    "BODY_RATE_FLOOR_BYTES_PER_SECOND above, SECURITY.md publishes it, and a wire vector " +
    "measures it on both SMTP listeners in both framings. It stays withheld because both " +
    "directions off it are worse " +
    "than it. Lower changes nothing an attacker could not already have from " +
    "the connection ceilings. Higher starts cutting real mail: a hundred bytes a second " +
    "is four orders of magnitude below what a working sender achieves, so the first " +
    "setting that shortens a hold meaningfully is also the first one that refuses a " +
    "congested mobile or satellite link, and it refuses it with a temporary code the " +
    "sender retries against for days. What the floor does not do is bound how long a " +
    "conforming-but-slow peer holds a connection, since a peer sending exactly at the " +
    "floor is inside it for maxMessageBytes over the floor; the levers for that are " +
    "maxMessageBytes and the two connection ceilings, and both are already reachable. " +
    "It moves to RATE_LIMIT_KEYS on a measured case for a different number, alongside " +
    "a vector at the setting that case asks for.",
  disabled:
    "An off switch for the whole limiter. It is not a ceiling and there is no value an " +
    "operator could set it to that this server wants: every listener holds its per-source " +
    "bounds as part of what it is, and a configuration key that turns them off would make " +
    "the connection ceiling, the sign-in budget and the recipient enumeration bound opt-out " +
    "together, from one line. An operator who needs more headroom raises the numbers, which " +
    "is what the four wired ceilings are for.",
});

function _assertCount(value, label) {
  if (typeof value !== "number" || !isFinite(value) ||
      Math.floor(value) !== value || value < 1) {
    throw new TypeError(label + " must be a whole number of at least 1");
  }
  return value;
}

// Read `config.limits` into the two shapes the listeners want: the
// specification each one builds its own limiter from, and the message
// ceiling the two SMTP listeners carry.
//
// A limiter EACH rather than one between them. The framework's own
// arrangement is per listener, and collapsing it to one shared budget
// would mean an ordinary mail client, which holds IMAP connections
// open and opens a submission connection to send, spent one allowance
// across both, so sending a message could cost the account its mailbox.
// Sharing a budget is a thing this framework offers and not a thing
// this server wants.
//
// The body-rate floor is written into every specification this builds,
// including the one a configuration naming no ceilings at all produces.
// It is not read from `section`, so it is not a value an operator can
// reach: RATE_LIMIT_KEYS is what the loop below copies, the floor is not
// on it, and the loader has no field for it either. That is what keeps
// the number this server publishes the number every listener runs.
//
// The five settable ceilings are written in for the same reason and by a
// different route. Each one IS a field an operator may set, so the half
// that has to be written here is the value governing when they set
// nothing. A specification built only from `section` leaves every field
// they left alone to the framework's own table, which is five numbers
// docs/operator-guide.md publishes beside the fields that move them and
// this repository does not choose. `LIMIT_DEFAULTS` is where they are
// chosen; this seeds from it and then lets the operator overwrite.
function _limitsConfig(section) {
  var rateLimit = Object.assign(
    { minBytesPerSecond: BODY_RATE_FLOOR_BYTES_PER_SECOND },
    LIMIT_DEFAULTS_RATE);
  var maxMessageBytes = LIMIT_DEFAULTS.maxMessageBytes;
  if (section === undefined || section === null) {
    return { rateLimit: rateLimit, maxMessageBytes: maxMessageBytes };
  }
  if (typeof section !== "object" || Array.isArray(section)) {
    throw new TypeError("blamepost.mail.listeners.create: config.limits must be an object of " +
      "{ maxMessageBytes, " + RATE_LIMIT_KEYS.join(", ") + " }");
  }
  for (var i = 0; i < RATE_LIMIT_KEYS.length; i += 1) {
    var key = RATE_LIMIT_KEYS[i];
    if (section[key] === undefined) continue;
    rateLimit[key] = _assertCount(section[key], "config.limits." + key);
  }
  if (section.maxMessageBytes !== undefined) {
    maxMessageBytes = _assertCount(section.maxMessageBytes, "config.limits.maxMessageBytes");
  }
  return { rateLimit: rateLimit, maxMessageBytes: maxMessageBytes };
}

// ---- relay for a source address, and why this server does not --------------
//
// The framework's MX listener can be told to accept a recipient outside
// the hosted domains when the connecting peer's address falls inside an
// operator-named range. That option is not passed from here, and a
// configuration carrying one stops the boot rather than being ignored.
//
// ## What it does today, measured rather than assumed
//
// A peer inside the range gets `250` to a stranger's sender and `250` to
// a stranger's recipient, then `354`, and then `451` once it has sent
// the whole message. The first two are the answer an open relay gives
// and the answer a scanner records. The last is a temporary code for a
// condition that never clears, so a well behaved peer retries the same
// message until it gives up, and the operator who wrote the range
// believes the device can send.
//
// ## Why the answer is to refuse rather than to finish it
//
// The case the setting exists for is a printer or an application server
// on the operator's own network, and this server already serves that
// case better through the front door. Every listener here requires
// STARTTLS before it will accept an envelope, on the MX listener as much
// as on submission, and the profile that would relax it is not one this
// server offers. So a device that can reach `RCPT TO` on port 25 has
// already completed a TLS handshake, which means it can also sign in on
// 587 or 465. The one device an address range could serve that an
// account cannot is a device that speaks no TLS, and no such device gets
// past the greeting here in any case.
//
// What the account buys, and the range cannot:
//
//   - An identity. An address says which network a message came from and
//     never which sender. Everything else that leaves this server is
//     bound to an account, at the envelope and again at the author
//     headers, and a range names a segment rather than a party. When one
//     host inside it is taken over, the only lever is to withdraw the
//     whole range, which takes the printer down with it. An account is
//     withdrawn on its own.
//   - A signature. Relayed mail cannot be signed here, and that is not a
//     gap to close: signing it would let anything inside the range emit
//     mail aligned under a hosted domain's key, which is the forgery the
//     author binding exists to refuse, performed by this server on
//     behalf of a peer that authenticated to nobody. So relayed mail
//     leaves unsigned, under this server's address and name. Claiming a
//     hosted domain, it is refused by the operator's own DMARC policy at
//     the receiver; claiming anything else, it is unattributable mail
//     spending this server's reputation.
//   - A delivery report with somewhere to go. A relayed message that
//     fails permanently owes a report to its reverse path, and nothing
//     verified that path: the device wrote it. The server either sends
//     the report to an address a stranger's device chose or drops it and
//     the device never learns. An account has a mailbox.
//
// A device that genuinely cannot hold an account is not left without an
// answer: the operator runs a submission relay of their own in front of
// it, which is where the credential for that device then lives. That is
// a smaller and more revocable trust boundary than a range this server
// applies to every host on a segment.
//
// ## The empty case is not the same as the absent one
//
// This refuses a range and says nothing about a list with no entries in
// it, and the asymmetry is deliberate. The framework's relay check reads
// an empty allowlist as granting nobody, so empty and absent both fail
// closed there and neither is a hazard. The hosted-domain set is the
// input where they differ, and `_buildMx` refuses an empty one rather
// than passing the absent form for exactly that reason. Not passing the
// relay option at all is the strongest of the three positions: there is
// no value, so there is no spelling of it to read the wrong way.
var RELAY_GRANT_REFUSED = "listeners/relay-grant-refused";

function _refuseRelayGrant(relayAllowedFor) {
  if (relayAllowedFor === undefined || relayAllowedFor === null) return;
  if (!Array.isArray(relayAllowedFor)) {
    throw new TypeError("blamepost.mail.listeners.create: config.relayAllowedFor must be an " +
      "array of { cidr, scope } entries when it is present at all, and this server refuses a " +
      "non-empty one. Leave it unset.");
  }
  if (relayAllowedFor.length === 0) return;
  var err = new TypeError("blamepost.mail.listeners.create: config.relayAllowedFor names " +
    relayAllowedFor.length + " address range(s), and this server does not relay for a source " +
    "address. Every listener it runs requires STARTTLS before it will accept an envelope, so " +
    "any device able to reach this server is also able to authenticate to it: create an " +
    "account for the device and point it at the submission listener on port 587 or 465. Mail " +
    "sent that way is bound to the account that sent it, is signed for the domain it claims, " +
    "and produces a delivery report that account can read. A range grants none of those. " +
    "Remove the setting.");
  err.code = RELAY_GRANT_REFUSED;
  throw err;
}

function _requireMethods(handle, names, label) {
  if (!handle || typeof handle !== "object") {
    throw new TypeError(label + " is required");
  }
  for (var i = 0; i < names.length; i += 1) {
    if (typeof handle[names[i]] !== "function") {
      throw new TypeError(label + " must expose " + names[i] + "(). " +
        "The listeners need " + names.join(", ") + " from it.");
    }
  }
  return handle;
}

// ---- the recipient lookup has to answer without suspending -----------------

// The local part every construction probe wears. It says what it is, so
// a reader finding it in a query log knows a boot put it there. Nothing
// is written under it: the lookup only reads.
var RESOLVE_PROBE_LOCAL = "blamepost-composition-probe";

// The domain the probe falls back on when this server hosts none of its
// own yet. It is reserved for documentation by RFC 2606 section 3, and
// it is here for one property: it PARSES.
//
// The reserved names that read as more obviously synthetic are the wrong
// choice, and quietly so. `.invalid`, `.test` and `localhost` are all
// refused by the domain guard, so a probe wearing one never gets past
// the lookup's guard clause, and it reports a synchronous answer from
// the one branch this probe exists to stop measuring.
var RESOLVE_PROBE_DOMAIN = "example.com";

// One active hosted domain, or null when this server hosts none and null
// when the handle cannot say so in this run.
//
// This SELECTS AN INPUT rather than judging the handle. A domain list
// that answers late or refuses is a fault, and it is refused where it is
// one: `start()` reads the same list and throws on a handle that does
// not answer it with an array. Raising it here as well would turn a
// probe settling for less reach into a second and earlier verdict about
// something this function never asked about.
function _aHostedDomain(store) {
  var domains = store.domains;
  if (!domains || typeof domains.list !== "function") return null;
  var rows;
  try { rows = domains.list(); }
  catch (_e) { return null; /* the list is unreadable here, so the probe settles for the reach it has; start() is where an unreadable list is the fault */ }
  if (!Array.isArray(rows)) return null;
  for (var i = 0; i < rows.length; i += 1) {
    var row = rows[i];
    if (!row || row.status !== "active") continue;
    if (typeof row.domain === "string" && row.domain.length > 0) return row.domain;
  }
  return null;
}

// The recipients the lookup is asked about at construction, cheapest
// first, chosen so that between them they reach every branch of the
// lookup that reads a row.
//
// One recipient establishes nothing. A recipient that does not parse is
// answered from a guard clause sitting above every read, and that guard
// clause stays above them however the storage underneath changes, so a
// probe made only of that one measures the single branch that touches no
// storage. Every branch the re-read at the write actually takes is on
// the far side of a domain row, an alias row and an account row. A
// handle synchronous at the guard and suspended at the rows is both the
// shape this refusal exists to catch and the shape a single cheap probe
// is least able to see.
//
// So the probe walks the ladder as far as the volume allows:
//
//   1. A recipient that does not parse, which is the guard clause. Kept
//      because other paths in this file do hand the lookup one, and it
//      costs a parse.
//   2. A recipient that parses, at a domain this server does not host.
//      It cannot be answered above the reads, so it forces the hosted
//      domain row that every parseable recipient reads first.
//   3. A recipient at a domain this server does host, when it hosts one.
//      That one falls past the domain row into the alias rows, the
//      account row and the domain's catch-all, which is every reader the
//      lookup has.
//
// On a volume hosting no domain yet, the third is unreachable for every
// recipient, so the first two cover everything the lookup can currently
// do. The third is added only when it parses, because one that does not
// is answered by the guard clause the first already covers and would
// read as reach this probe does not have.
function _resolveProbeRecipients(store) {
  var out = ["", RESOLVE_PROBE_LOCAL + "@" + RESOLVE_PROBE_DOMAIN];
  var hosted = _aHostedDomain(store);
  if (hosted === null) return out;
  var deep = RESOLVE_PROBE_LOCAL + "@" + hosted;
  if (storeAddress.parse(deep).ok) out.push(deep);
  return out;
}

// Whether a recipient still has somewhere to land is decided at the
// instant the copy is filed, with nothing able to run between the
// reading and the write. A reading that suspends is one an operator's
// suspension can land inside: the mailbox they closed while the message
// was arriving would receive it anyway, and nothing would report that it
// had. So the property is probed at construction rather than asserted in
// prose, and a handle that answers late is found here rather than at the
// first message that crossed the window.
function _refuseAsyncResolve(store) {
  var recipients = _resolveProbeRecipients(store);
  for (var i = 0; i < recipients.length; i += 1) {
    var answer = store.resolve(recipients[i]);
    if (answer !== null && answer !== undefined && typeof answer.then === "function") {
      throw new TypeError("blamepost.mail.listeners.create: opts.store.resolve must answer " +
        "synchronously. The delivery path asks it again at the moment it files a copy, so that " +
        "the answer and the write are one run nothing can be interleaved with, and a handle " +
        "that answers with a promise reopens exactly the window that check exists to close. " +
        "This was asked of a recipient that does not parse, one at a domain this server does " +
        "not host, and one at a domain it does, so a lookup answering from a cached verdict " +
        "and suspending where it reads a row is refused here rather than accepted.");
    }
  }
}

// Which domain an address belongs to, read through the one derivation
// that decides it, so the name handed to the signer is the name the
// selector rows are keyed on. The envelope this reads is written by
// whoever connected, and the absolute form of a domain is a spelling
// they may legitimately send; splitting the address by hand would carry
// that spelling into the signing path rather than the domain.
//
// An empty string for a name that cannot be one, which is what both
// callers already treat as "there is no domain to act on".
function _domainOf(value) {
  var parsed = storeAddress.parse(value);
  return parsed.ok ? parsed.domain : "";
}

// A name that does not exist, told apart from a lookup that could not
// complete.
//
// The mail-authentication primitives read `ENOTFOUND` and `ENODATA` as
// "this name publishes nothing" and every other failure as a lookup to
// try again later. The resolver signals the same distinction in its own
// vocabulary, and the two codes are separate: `resolver/nxdomain` is
// RFC 1035 §4.1.1 RCODE 3, the name error, which is the answer an
// underscore-prefixed policy name gives on a domain that published
// nothing and so the commonest answer in DNS. A server that reads one
// as a lookup problem calls every such domain a broken resolver.
//
// `resolver/query-failed` and `resolver/upstream-failed` are the other
// side and stay lookup problems. A server failure, a refusal and a query
// nobody answered are not a record nobody published, and a receiver that
// read them as one would accept spoofed mail for every domain on the
// internet for as long as its own resolver stayed unwell. That is a
// downgrade an attacker arranges by breaking the lookup, so the codes
// are matched by name here rather than sniffed out of a message: an
// RCODE in the text of a failure that was not a name error is exactly
// the thing that must not be read as absence.
//
// `blamepost.mail.posture.txtLookup` applies this same rule to the TXT
// questions, and this file composes it below for exactly that. The
// question types SPF resolves for its `a`, `mx` and `exists` mechanisms
// are not TXT and have no such reader, which is why the rule is also
// stated here. Both statements cite RFC 1035 §4.1.1 and both must say
// the same thing.
function _isAbsentName(err) {
  if (!err) return false;
  return err.code === "ENOTFOUND" || err.code === "ENODATA" ||
    err.code === "resolver/nxdomain";
}

// The signal the gate reads as "nothing is published at this name",
// which SPF, DMARC and DKIM each have a defined verdict for.
function _absentRecords(qname, qtype) {
  var err = new Error("no " + qtype + " records for " + qname);
  err.code = "ENODATA";
  return err;
}

// The message authentication gate resolves through a callback rather
// than through a resolver handle, and the two want different shapes.
// `b.mail.inbound.verify` documents `dnsLookup(qname, type)` as
// returning the records themselves: TXT as an array of string arrays,
// A and AAAA and PTR as flat string arrays, MX as `{ exchange,
// preference }`. `resolver.query` returns the envelope those records
// arrive in instead. Handing the query straight to the callback gives
// SPF an object where it expects an array, and every verdict comes back
// a temporary error, so the reshape is one half of what this does.
//
// The other half is absence. Every question here can be answered "that
// name does not exist", and the gate has a verdict for that which is
// not the verdict for a lookup that failed.
function _dnsLookupOver(resolver, budgetMs) {
  if (!resolver) return undefined;
  // TXT carries every policy record the gate reads: the SPF record, the
  // DMARC record, and the DKIM and ARC public keys. One reader already
  // answers TXT over a pinned resolver and already tells an unpublished
  // name from an unreachable one, so it is composed rather than
  // restated here.
  var readTxt = posture.txtLookup(resolver);

  // Each question carries its own budget rather than the whole
  // evaluation carrying one. SPF alone may resolve ten names under RFC
  // 7208 section 4.6.4, and a single budget across the set would make
  // the tenth lookup's allowance depend on how slow the first nine
  // were, so a message would be refused for the shape of the sender's
  // record rather than for anything about the answer.
  return function _dnsLookup(qname, type) {
    return posture.withinDnsBudget(_answer(qname, type), budgetMs,
      "inbound dns " + String(type).toUpperCase() + " " + qname);
  };

  async function _answer(qname, type) {
    var qtype = String(type).toUpperCase();
    if (qtype === "TXT") return readTxt(qname, "TXT");
    var answer;
    try {
      answer = await resolver.query(qname, qtype);
    } catch (lookupErr) {
      if (!_isAbsentName(lookupErr)) throw lookupErr;
      throw _absentRecords(qname, qtype);
    }
    var wanted = b.network.dns.resolver.QTYPE_BY_NAME[qtype];
    var rrs = (answer && answer.rrs) || [];
    var out = [];
    for (var i = 0; i < rrs.length; i += 1) {
      var rr = rrs[i];
      if (!rr || rr.type !== wanted) continue;
      if (qtype === "MX") {
        var mx = rr.decoded || {};
        if (mx.exchange) {
          out.push({
            exchange:   String(mx.exchange),
            preference: typeof mx.preference === "number" ? mx.preference : 0,
          });
        }
        continue;
      }
      var value = rr.decoded === undefined || rr.decoded === null ? "" : String(rr.decoded);
      if (value.length > 0) out.push(value);
    }
    // An empty answer is the name existing and publishing no record of
    // this type, which is the same verdict as the name not existing at
    // all and a different one from a lookup that failed.
    if (out.length === 0) throw _absentRecords(qname, qtype);
    return out;
  }
}


// ---- IMAP SEARCH (RFC 9051 §6.4.4) -----------------------------------------
//
// The framework's IMAP listener dispatches SEARCH through its method
// registry and ships a default that answers `NO SEARCH not configured`,
// because a search expression is a question about the message bodies an
// application stores rather than about the protocol. This is that
// application's answer, and it is composed as a registry override so the
// wire guard, the per handler budget and the audit trail in front of
// every other verb stay in front of this one.
//
// ## Why the evaluation is a scan and not an index read
//
// The message store carries a full text index, and it is the wrong
// substrate for this verb. It holds keyed hashes of whole tokens, so it
// matches a complete word and nothing else, while RFC 9051 section
// 6.4.4 makes every string key a SUBSTRING match: `SUBJECT "round"`
// against a subject reading "Roundtrip" is a match the specification
// requires and the index cannot produce. It folds the From and To
// addresses into one column, so it answers a sender question with a
// recipient. It drops stopwords and anything outside two to sixty-four
// codepoints, and it caps a result set. Every one of those differences
// arrives at the client as a message missing from a result set carrying
// a tagged OK, which is indistinguishable from a mailbox that does not
// hold it.
//
// So `mailStore.searchScan` hands over the rows and the keys below
// decide. The index keeps serving the surfaces whose specifications
// leave matching semantics to the server.
//
// ## Why a key this server cannot answer refuses the whole expression
//
// The keys are refused at the point of PARSE, before any message is
// read, and a refusal ends the command. That is not a convenience: an
// expression has no partial evaluation. `OR SUBJECT round CC bravo`
// asks one question, and answering it from the half this server can run
// reports the messages matching a query the client did not send. The
// client has no way to see the difference, and the result it renders is
// the answer to something else.
//
// Refusing at the parse also means the shape of the code carries the
// rule. There is no branch that evaluates one key and skips another,
// because a key that cannot be answered never becomes a predicate.

// The charsets a search term may be written in. RFC 9051 section 6.4.4
// makes UTF-8 the default and deprecates the argument; US-ASCII is a
// subset of it and every client that names one names one of these two.
var SEARCH_CHARSETS = Object.freeze({ "US-ASCII": true, "UTF-8": true });
var SEARCH_CHARSET_CODE = "[BADCHARSET (US-ASCII UTF-8)]";

// How deep a search expression may nest. The same number the wire
// guard's strict profile names for this, restated here because the
// guard does not apply it: it parses the command line into a tag, a
// verb and an argument string and leaves the expression to whoever
// reads it.
var MAX_SEARCH_DEPTH = 32;

// How much of a client's own text a refusal quotes back. The command
// line is already capped and carries no control byte, so this bounds
// the length of the reply rather than its content.
var MAX_SEARCH_ECHO = 120;

// The per handler ceilings the registry requires. A search reads every
// message in the folder, which is the same order of work as a FETCH
// over the whole of it, so it carries the same kind of budget.
var SEARCH_HANDLER_BYTES = BYTES.mib(1);
var SEARCH_HANDLER_MS    = TIME.minutes(2);

// RFC 9051 section 9 date-text, which is what BEFORE, ON and SINCE take.
var SEARCH_DATE_RE = /^([0-9]{1,2})-([A-Za-z]{3})-([0-9]{4})$/;
var SEARCH_MONTHS = Object.freeze({
  JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4,  JUN: 5,
  JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11,
});

// LARGER and SMALLER take a number of octets. Bounded so a client
// cannot hand over a digit string long enough to be worth parsing.
var SEARCH_NUMBER_RE = /^[0-9]{1,15}$/;

// An atom in a key position that is a sequence set rather than a key
// name. No search key name begins with a digit or an asterisk, so the
// two are never ambiguous.
var SEARCH_SEQ_SET_RE = /^[0-9*][0-9,:*]*$/;

// The system flags a search key asks about, and whether the key is the
// positive or the negative form. RFC 9051 section 2.3.2 lists them.
var SEARCH_FLAG_KEYS = Object.freeze({
  ANSWERED:   { flag: "\\answered", want: true  },
  UNANSWERED: { flag: "\\answered", want: false },
  DELETED:    { flag: "\\deleted",  want: true  },
  UNDELETED:  { flag: "\\deleted",  want: false },
  DRAFT:      { flag: "\\draft",    want: true  },
  UNDRAFT:    { flag: "\\draft",    want: false },
  FLAGGED:    { flag: "\\flagged",  want: true  },
  UNFLAGGED:  { flag: "\\flagged",  want: false },
  SEEN:       { flag: "\\seen",     want: true  },
  UNSEEN:     { flag: "\\seen",     want: false },
});

// The keys this server recognizes, can name a reason for, and cannot
// answer exactly. Each reason says what is missing rather than that
// something is, because the operator reading it in an audit row is
// deciding whether their client is broken or their server is.
var SEARCH_UNANSWERABLE = Object.freeze({
  CC: "CC asks about a header this server does not keep. The message store parses a " +
      "message on the way in and keeps the subject, the sender and the To addresses; " +
      "the Cc header is not among them, so there is nothing to match against and an " +
      "empty result would read as a message that is not there.",
  BCC: "BCC asks about a header this server does not keep, and one that a delivered " +
       "message usually does not carry in any case.",
  SENTBEFORE: "SENTBEFORE asks about the Date header, which this server reads and does " +
    "not parse. Only the date the message arrived is kept, and answering a question " +
    "about when it was sent with when it arrived is a different answer. BEFORE asks " +
    "about the arrival date and is answered.",
  SENTON: "SENTON asks about the Date header, which this server reads and does not " +
    "parse. ON asks about the arrival date and is answered.",
  SENTSINCE: "SENTSINCE asks about the Date header, which this server reads and does " +
    "not parse. SINCE asks about the arrival date and is answered.",
  BODY: "BODY asks about the body of the message, and this server cannot read the whole " +
    "of one. The message store keeps the first text part and the first HTML part, so an " +
    "ordinary message carrying a second text part, which is what a text attachment or a " +
    "calendar invite beside the body is, keeps only the first of them, and the text inside " +
    "a forwarded message part is never read at all. RFC 9051 section 6.4.4 lets a server " +
    "skip body parts that are neither text nor a message and does not let it skip those, " +
    "so a match in one of them would come back as no match, which reads as a mailbox that " +
    "does not hold the message. SUBJECT, FROM, TO and HEADER read fields that are kept " +
    "whole and are answered.",
  TEXT: "TEXT asks about the headers and the body together, and this server can read " +
    "neither whole. It keeps the subject, the sender and the To addresses and no other " +
    "header, and it keeps one text part of the body. A message matching anywhere outside " +
    "that would come back as no match at all. SUBJECT, FROM, TO and HEADER over the kept " +
    "fields are answered.",
});

// The headers a HEADER key can be evaluated against, which are the ones
// the message store keeps as the sender wrote them. References is
// absent on purpose: it is stored as its message ids re-joined with
// commas rather than as the text of the header, so a substring of the
// header as sent is not a substring of what is kept.
var SEARCH_HEADER_FIELDS = Object.freeze({
  "SUBJECT":     function (m) { return m.subject; },
  "FROM":        function (m) { return m.from; },
  "TO":          function (m) { return m.to; },
  "MESSAGE-ID":  function (m) { return m.messageId; },
  "IN-REPLY-TO": function (m) { return m.inReplyTo; },
});

// The fields each string key is matched against. Every one of them is a
// header the message store keeps whole, so a substring question about
// it has a complete answer. BODY is absent for the opposite reason and
// refuses: see SEARCH_UNANSWERABLE above.
var SEARCH_STRING_KEYS = Object.freeze({
  SUBJECT: function (m) { return [m.subject]; },
  FROM:    function (m) { return [m.from]; },
  TO:      function (m) { return [m.to]; },
});

// One refusal, carrying the IMAP condition it is answered with. BAD is
// a command this server could not parse and NO is one it parsed and
// will not run, which RFC 9051 section 7.1 separates and clients act on
// differently: a BAD tells the client to fix its own dialog.
function _searchRefusal(condition, responseCode, text) {
  var refusal = new Error("SEARCH " + text);
  refusal.code = "listeners/imap-search-refused";
  refusal.searchCondition = condition;
  refusal.searchResponseCode = responseCode;
  refusal.searchText = text;
  return refusal;
}

function _searchBad(text) { return _searchRefusal("BAD", null, text); }
function _searchNo(text)  { return _searchRefusal("NO", null, text); }

// A client's own token, bounded, for a refusal that names what it
// refused.
//
// The wire guard refuses every control byte on the COMMAND LINE, which
// covers each argument that arrives on it. It does not cover a literal:
// RFC 9051 section 4.3 sends one as a counted payload after the command,
// and it reaches here having only been checked as UTF-8. `_imapSearchLiteral`
// refuses a line break in that payload at the point of parse, and
// `_imapTagged` folds one out of the line it writes, so a term quoted
// back cannot end the response line early.
function _searchEcho(value) {
  var text = String(value === undefined || value === null ? "" : value);
  return text.length > MAX_SEARCH_ECHO ? text.slice(0, MAX_SEARCH_ECHO) + "..." : text;
}

// The form both sides of a substring comparison are put in. RFC 9051
// section 6.4.4 matches without regard to case, and a header carries
// whichever normalization form the sender's software produced, so a
// term typed as one sequence of codepoints has to find a subject
// written as an equivalent one. Composed the same way and in the same
// order the message store's own tokenizer composes it, so one server
// has one idea of when two pieces of text are the same text.
function _searchFold(value) {
  return String(value === undefined || value === null ? "" : value)
    .normalize("NFC").toLowerCase();
}

function _searchContains(haystack, needle) {
  return _searchFold(haystack).indexOf(_searchFold(needle)) !== -1;
}

function _searchHasFlag(message, folded) {
  var flags = message.flags || [];
  for (var i = 0; i < flags.length; i += 1) {
    if (String(flags[i]).toLowerCase() === folded) return true;
  }
  return false;
}

// The start of a day in UTC, which is the zone this server records an
// internal date in and reports one back in. RFC 9051 section 6.4.4
// compares dates rather than instants, so both sides are reduced to the
// day they fall on and compared as numbers. A date that does not exist,
// such as the thirty-first of February, comes back null rather than
// rolling forward into March.
function _searchDay(text) {
  var found = SEARCH_DATE_RE.exec(String(text));
  if (!found) return null;
  var month = SEARCH_MONTHS[found[2].toUpperCase()];
  if (month === undefined) return null;
  var day  = parseInt(found[1], 10);
  var year = parseInt(found[3], 10);
  var at = Date.UTC(year, month, day);
  var back = new Date(at);
  if (back.getUTCFullYear() !== year || back.getUTCMonth() !== month ||
      back.getUTCDate() !== day) {
    return null;
  }
  return at;
}

function _messageDay(ms) {
  var when = new Date(ms);
  return Date.UTC(when.getUTCFullYear(), when.getUTCMonth(), when.getUTCDate());
}

// The search expression split into the pieces RFC 9051 section 9 draws
// it from: atoms, quoted strings and the parentheses that group them. A
// term carried as a literal has already been read off the wire by the
// listener and arrives here as `literalTerm`, so it is appended as the
// last string in the expression, which is where the command line put it.
function _searchTokens(args, literalTerm) {
  var text = String(args === undefined || args === null ? "" : args);
  var out = [];
  var i = 0;
  while (i < text.length) {
    var ch = text.charAt(i);
    if (ch === " " || ch === "\t") { i += 1; continue; }
    if (ch === "(") { out.push({ kind: "open" }); i += 1; continue; }
    if (ch === ")") { out.push({ kind: "close" }); i += 1; continue; }
    if (ch === "\"") {
      var value  = "";
      var closed = false;
      i += 1;
      while (i < text.length) {
        var c = text.charAt(i);
        if (c === "\\") {
          if (i + 1 >= text.length) break;
          value += text.charAt(i + 1);
          i += 2;
          continue;
        }
        if (c === "\"") { closed = true; i += 1; break; }
        value += c;
        i += 1;
      }
      if (!closed) {
        throw _searchBad("carries a quoted string that never closes.");
      }
      out.push({ kind: "string", value: value });
      continue;
    }
    var start = i;
    while (i < text.length && " \t()\"".indexOf(text.charAt(i)) === -1) i += 1;
    out.push({ kind: "atom", value: text.slice(start, i) });
  }
  if (literalTerm !== null) out.push({ kind: "string", value: literalTerm });
  return out;
}

function _searchNext(tokens, at, wanted) {
  if (at.i >= tokens.length) {
    throw _searchBad("ends where " + wanted + " should be.");
  }
  var token = tokens[at.i];
  at.i += 1;
  return token;
}

// One astring argument: a quoted string or a bare atom, which is what
// RFC 9051 section 9 allows wherever it allows an astring.
function _searchString(tokens, at, keyName) {
  var token = _searchNext(tokens, at, "the string " + keyName + " takes");
  if (token.kind === "string" || token.kind === "atom") return token.value;
  throw _searchBad(keyName + " takes a string and was given a parenthesis.");
}

function _searchAtom(tokens, at, keyName, wanted) {
  var token = _searchNext(tokens, at, wanted + " for " + keyName);
  if (token.kind !== "atom") {
    throw _searchBad(keyName + " takes " + wanted + " and was given something else.");
  }
  return token.value;
}

// A sequence set key, over message numbers or over UIDs. The spec is
// checked here, at the point of parse, by compiling it once against a
// stand-in highest number: a set nobody can read is a refusal rather
// than a folder scan that ends in one. It is compiled again at
// evaluation, when the mailbox has said what `*` stands for.
function _searchSeqSetKey(spec, useUid) {
  try { sequenceSet(spec, 1); }
  catch (e) {
    throw _searchBad("'" + _searchEcho(spec) + "' is not a sequence set (" +
      ((e && e.message) || "unreadable") + ")");
  }
  var compiled   = null;
  var compiledAt = null;
  return function (message, ctx) {
    var highest = useUid ? ctx.highestUid : ctx.highestSeq;
    if (compiled === null || compiledAt !== highest) {
      compiled   = sequenceSet(spec, highest);
      compiledAt = highest;
    }
    return compiled(useUid ? message.uid : message.seq);
  };
}

function _searchAnd(keys) {
  if (keys.length === 1) return keys[0];
  return function (message, ctx) {
    for (var i = 0; i < keys.length; i += 1) {
      if (!keys[i](message, ctx)) return false;
    }
    return true;
  };
}

// Keys until the group they are in ends, combined with AND, which RFC
// 9051 section 6.4.4 makes the meaning of writing two keys side by side.
function _searchKeyList(tokens, at, insideParens) {
  var keys = [];
  while (at.i < tokens.length) {
    if (tokens[at.i].kind === "close") break;
    keys.push(_searchKey(tokens, at));
  }
  if (keys.length === 0) {
    throw _searchBad(insideParens
      ? "carries an empty group, and a group holds at least one key."
      : "needs at least one search key.");
  }
  return _searchAnd(keys);
}

function _searchKey(tokens, at) {
  at.depth += 1;
  if (at.depth > MAX_SEARCH_DEPTH) {
    throw _searchBad("nests past " + MAX_SEARCH_DEPTH + " levels, which is deeper than " +
      "this server reads.");
  }
  try { return _searchKeyBody(tokens, at); }
  finally { at.depth -= 1; }
}

function _searchKeyBody(tokens, at) {
  var token = _searchNext(tokens, at, "a search key");
  if (token.kind === "open") {
    var group = _searchKeyList(tokens, at, true);
    var closer = at.i < tokens.length ? tokens[at.i] : null;
    if (!closer || closer.kind !== "close") {
      throw _searchBad("opens a group it never closes.");
    }
    at.i += 1;
    return group;
  }
  if (token.kind === "close") {
    throw _searchBad("closes a group that was never opened.");
  }
  if (token.kind === "string") {
    throw _searchBad("puts a quoted string where a search key belongs.");
  }

  var name = token.value.toUpperCase();

  if (name === "ALL") return function () { return true; };

  if (Object.prototype.hasOwnProperty.call(SEARCH_FLAG_KEYS, name)) {
    var rule = SEARCH_FLAG_KEYS[name];
    return function (message) {
      return _searchHasFlag(message, rule.flag) === rule.want;
    };
  }

  // IMAP4rev2 removed the \Recent flag and this server never sets one,
  // so these three have an exact answer rather than an approximated
  // one: nothing is recent, NEW is recent and unseen so nothing is new,
  // and OLD is everything that is not recent, which is everything. A
  // client old enough to send one gets the right answer instead of a
  // refusal, and no message is ever left out of one.
  if (name === "RECENT" || name === "NEW") return function () { return false; };
  if (name === "OLD") return function () { return true; };

  if (name === "KEYWORD" || name === "UNKEYWORD") {
    var keyword = _searchAtom(tokens, at, name, "a keyword flag");
    if (keyword.charAt(0) === "\\") {
      throw _searchBad(name + " takes a keyword, and '" + _searchEcho(keyword) +
        "' is a system flag. Ask for a system flag by its own key.");
    }
    if (!KEYWORD_FLAG_RE.test(keyword)) {
      throw _searchBad("'" + _searchEcho(keyword) + "' is not a keyword this server keeps.");
    }
    var folded = keyword.toLowerCase();
    var wantKeyword = name === "KEYWORD";
    return function (message) {
      return _searchHasFlag(message, folded) === wantKeyword;
    };
  }

  if (name === "LARGER" || name === "SMALLER") {
    var sizeText = _searchAtom(tokens, at, name, "a number of octets");
    if (!SEARCH_NUMBER_RE.test(sizeText)) {
      throw _searchBad(name + " takes a number of octets and was given '" +
        _searchEcho(sizeText) + "'.");
    }
    var bound = parseInt(sizeText, 10);
    var wantLarger = name === "LARGER";
    return function (message) {
      return wantLarger ? message.sizeBytes > bound : message.sizeBytes < bound;
    };
  }

  if (name === "BEFORE" || name === "ON" || name === "SINCE") {
    var dateText = _searchString(tokens, at, name);
    var day = _searchDay(dateText);
    if (day === null) {
      throw _searchBad(name + " takes a date written as 1-Feb-2026 and was given '" +
        _searchEcho(dateText) + "'.");
    }
    return function (message) {
      var on = _messageDay(message.internalDate);
      if (name === "BEFORE") return on < day;
      if (name === "ON") return on === day;
      return on >= day;
    };
  }

  if (Object.prototype.hasOwnProperty.call(SEARCH_STRING_KEYS, name)) {
    var fieldsOf = SEARCH_STRING_KEYS[name];
    var term = _searchString(tokens, at, name);
    return function (message) {
      var fields = fieldsOf(message);
      for (var i = 0; i < fields.length; i += 1) {
        if (_searchContains(fields[i], term)) return true;
      }
      return false;
    };
  }

  if (name === "HEADER") {
    var fieldName = _searchString(tokens, at, "HEADER").toUpperCase();
    var headerTerm = _searchString(tokens, at, "HEADER " + _searchEcho(fieldName));
    if (!Object.prototype.hasOwnProperty.call(SEARCH_HEADER_FIELDS, fieldName)) {
      throw _searchNo("HEADER '" + _searchEcho(fieldName) + "' asks about a header this " +
        "server does not keep. The message store parses a message on the way in and " +
        "keeps Subject, From, To, Message-ID and In-Reply-To; a search over any other " +
        "field would match nothing whatever the message says, which reads as a mailbox " +
        "that does not hold it.");
    }
    var readHeader = SEARCH_HEADER_FIELDS[fieldName];
    return function (message) {
      var value = readHeader(message);
      // RFC 9051 section 6.4.4: an empty string asks whether the header
      // is there at all, whatever it says.
      if (headerTerm.length === 0) return String(value || "").length > 0;
      return _searchContains(value, headerTerm);
    };
  }

  if (name === "UID") {
    return _searchSeqSetKey(_searchAtom(tokens, at, "UID", "a UID set"), true);
  }

  if (name === "NOT") {
    var negated = _searchKey(tokens, at);
    return function (message, ctx) { return !negated(message, ctx); };
  }

  if (name === "OR") {
    var left  = _searchKey(tokens, at);
    var right = _searchKey(tokens, at);
    return function (message, ctx) {
      return left(message, ctx) || right(message, ctx);
    };
  }

  if (Object.prototype.hasOwnProperty.call(SEARCH_UNANSWERABLE, name)) {
    throw _searchNo(SEARCH_UNANSWERABLE[name]);
  }

  if (name === "RETURN") {
    throw _searchNo("RETURN asks for the ESEARCH result form, which this listener does " +
      "not serve on either spelling of the command. SEARCH and UID SEARCH both answer " +
      "with the untagged SEARCH line RFC 9051 section 7.3.4 defines, the second in " +
      "unique identifiers. Send the command without RETURN.");
  }

  if (SEARCH_SEQ_SET_RE.test(token.value)) {
    return _searchSeqSetKey(token.value, false);
  }

  throw _searchBad("'" + _searchEcho(token.value) + "' is not a search key RFC 9051 " +
    "section 6.4.4 defines.");
}

/**
 * @primitive blamepost.mail.listeners.compileSearch
 * @signature blamepost.mail.listeners.compileSearch(args, literalTerm)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9051 §6.4.4 (SEARCH), RFC 9051 §9 (search-key grammar)
 * @related   blamepost.mail.mailbox.searchScan, blamepost.mail.mailbox.sequenceSet
 *
 * One IMAP SEARCH argument string compiled into a predicate over the
 * rows `blamepost.mail.mailbox.searchScan` returns. `literalTerm` is
 * the text of a term the client sent as a literal, or null when the
 * command carried none.
 *
 * The predicate takes a row and a context carrying the highest message
 * number and the highest UID in the mailbox, which is what a sequence
 * set's `*` stands for.
 *
 * Everything this server cannot answer exactly refuses HERE, before a
 * message has been read, and the refusal carries the IMAP condition it
 * is answered with. That is the whole design: an expression has no
 * partial evaluation, so a key that cannot be answered never becomes a
 * predicate and there is no branch that could report the half of a
 * question this server can run as though it were the answer to the
 * whole of it.
 *
 * @example
 *   var match = blamepost.mail.listeners.compileSearch("UNSEEN SUBJECT \"round\"", null);
 *   match(row, { highestSeq: 3, highestUid: 3 });
 *   // true
 */
function compileSearch(args, literalTerm) {
  var tokens = _searchTokens(args, literalTerm === undefined ? null : literalTerm);
  var at = { i: 0, depth: 0 };

  // RFC 9051 section 6.4.4 puts an optional CHARSET before the keys.
  // The argument is deprecated in IMAP4rev2 and UTF-8 is what a term
  // arrives in, so the two spellings that mean UTF-8 are accepted and
  // anything else refuses with the response code section 7.1 defines
  // for it, which is how a client learns what to send instead.
  if (tokens.length > 0 && tokens[0].kind === "atom" &&
      tokens[0].value.toUpperCase() === "CHARSET") {
    at.i = 1;
    var charset = _searchString(tokens, at, "CHARSET").toUpperCase();
    if (!Object.prototype.hasOwnProperty.call(SEARCH_CHARSETS, charset)) {
      throw _searchRefusal("NO", SEARCH_CHARSET_CODE,
        "cannot read a term written in '" + _searchEcho(charset) + "'. Send the term as " +
        "UTF-8, which RFC 9051 section 6.4.4 makes the default.");
    }
  }

  var expression = _searchKeyList(tokens, at, false);
  if (at.i !== tokens.length) {
    throw _searchBad("carries a close parenthesis that closes nothing.");
  }
  return expression;
}

// ---- IMAP session state (RFC 9051 section 6.3, RFC 7162, RFC 2177) ---------
//
// SELECT, EXAMINE, CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE,
// LIST, CLOSE, ENABLE and IDLE are composed as registry overrides, the
// same way SEARCH is. The framework's defaults for them differ from the
// specifications in these ways:
//
//   - CREATE, DELETE, RENAME, SUBSCRIBE and UNSUBSCRIBE each answer
//     `NO <verb> not configured`, so an account holder can make a
//     mailbox and never remove, rename or subscribe to one, and every
//     client's folder control fails. RFC 9051 sections 6.3.4 to 6.3.8
//     make all five part of IMAP4rev2, which this server advertises.
//   - LIST reads neither its reference nor its pattern and serves
//     neither the selection nor the return options, so every narrowed
//     question is answered with the whole namespace. RFC 9051 section
//     6.3.9 matches both arguments and defines the options a client
//     reads its subscribed set back with.
//   - SELECT and EXAMINE send no PERMANENTFLAGS response. RFC 9051
//     section 6.3.2 makes it a required OK untagged response, and a
//     client that is not sent one assumes every flag it sends is kept.
//   - A SELECT or EXAMINE that fails leaves the previous mailbox
//     selected, so the next EXPUNGE removes the flagged messages of a
//     mailbox the client no longer has open. RFC 9051 section 6.3.2
//     leaves no mailbox selected after a failed SELECT.
//   - EXPUNGE from a session that opened the mailbox with EXAMINE
//     removes messages, and a non-peeking FETCH from one sets `\Seen`.
//     RFC 9051 section 6.3.3 permits neither.
//   - CLOSE removes nothing. RFC 9051 section 6.4.1 has it remove every
//     message flagged `\Deleted` from a mailbox opened read-write.
//   - SELECT reads the CONDSTORE select parameter of RFC 7162 section
//     3.1.8 as part of the mailbox name, and ENABLE turns on QRESYNC,
//     whose VANISHED responses this server does not send.
//   - IDLE leaves its thirty-minute ceiling scheduled after the client
//     disconnects.

// The extensions the framework's capability line names that this server
// does not serve, each with what it would take to serve it. They are
// removed from the greeting, the CAPABILITY answer and the AUTHENTICATE
// completion, and ENABLE does not turn one on.
var IMAP_UNSERVED_EXTENSIONS = Object.freeze({
  QRESYNC:  "RFC 7162 section 3.2 needs a VANISHED response for every expunged UID, on " +
            "SELECT, on EXPUNGE and on FETCH, which needs a record of expunged UIDs and " +
            "a FETCH composition this server does not have.",
  NOTIFY:   "RFC 5465 needs a push channel from the mailbox layer to a live connection.",
  CATENATE: "RFC 4469 needs IMAP URL resolution across mailboxes.",
});

var IMAP_SELECT_HANDLER_BYTES = BYTES.mib(1);
var IMAP_SELECT_HANDLER_MS    = TIME.seconds(30);
// A CREATE carries one mailbox name and RFC 9051 section 5.1 caps a name
// well under this, so the ceiling is the room a literal announcing one
// needs rather than the room a message needs. The deadline is the
// select handler's, because the work behind it is the same kind: a few
// small writes against the volume, which a volume under load can make
// wait.
var IMAP_CREATE_HANDLER_BYTES = BYTES.kib(8);
var IMAP_CREATE_HANDLER_MS    = TIME.seconds(30);
// DELETE and RENAME answer on one line, so the response ceiling is the
// create handler's. The deadline is not: a DELETE destroys every message
// the mailbox holds and a RENAME of INBOX files every message it holds
// into another mailbox, which is the same work an APPEND does per
// message rather than the few small writes a CREATE does, so both take
// the budget the framework gives its long commands.
var IMAP_WRITE_HANDLER_BYTES  = BYTES.kib(8);
var IMAP_WRITE_HANDLER_MS     = TIME.minutes(2);
var IMAP_CLOSE_HANDLER_BYTES  = BYTES.mib(1);
var IMAP_CLOSE_HANDLER_MS     = TIME.seconds(30);
var IMAP_SHORT_HANDLER_BYTES  = BYTES.kib(8);
var IMAP_SHORT_HANDLER_MS     = TIME.seconds(5);
var IMAP_IDLE_HANDLER_MS      = TIME.minutes(2);

// RFC 2177 section 3 lets a server end an IDLE after thirty minutes.
// The ceiling is one minute under that, which is the framework's number.
var IMAP_IDLE_CEILING_MS = TIME.minutes(29);

function _imapSelectBad(verb, text) {
  var refusal = new Error(verb + " " + text);
  refusal.code = "listeners/imap-select-refused";
  return refusal;
}

// The mailbox name one command names, and where reading it stopped.
// RFC 9051 section 5.1 writes a mailbox name as an astring, so it
// arrives as a bare atom, as a quoted string, or as a literal. A name
// sent as a literal arrives as `literalBody` with nothing left on the
// line, because the listener takes the literal out of the command.
//
// One reader for every verb that takes a name, because two would be two
// answers to what a name is: the screen below refuses a control
// character, and a verb reading its own argument some other way is the
// verb that admits one.
//
// Throws with the text of a BAD for anything that cannot be read.
function _imapMailboxArgument(verb, args, literalBody) {
  var tokens;
  try { tokens = _searchTokens(args, null); }
  catch (e) {
    throw _imapSelectBad(verb, (e && e.searchText) || "carries arguments this server cannot read.");
  }

  if (literalBody !== undefined && literalBody !== null) {
    return { mailbox: _imapLiteralText(verb, literalBody), tokens: tokens, at: 0 };
  }
  if (tokens.length === 0 || (tokens[0].kind !== "atom" && tokens[0].kind !== "string")) {
    throw _imapSelectBad(verb, "needs a mailbox name.");
  }
  return { mailbox: tokens[0].value, tokens: tokens, at: 1 };
}

// The text of a literal, screened as the last argument of a command.
//
// One reader for every verb that can receive one, because two would be
// two answers to what a literal may carry. The command guard refuses a
// literal opener anywhere but the end of a line, so a command carries at
// most one and it is always the last argument.
//
// The control character table is this server's own, which covers the C1
// range at U+0080 to U+009F as well as the C0 block and the delete code
// point. U+009B is the control sequence introducer, and the refusal this
// server writes for an unknown mailbox quotes the name back to the
// client, so a name admitted here is an escape sequence the server
// itself sends to the terminal that asked for it.
function _imapLiteralText(verb, literalBody) {
  var bytes = Buffer.isBuffer(literalBody) ? literalBody : Buffer.from(String(literalBody));
  if (!nodeBuffer.isUtf8(bytes)) {
    throw _imapSelectBad(verb, "names a mailbox that is not UTF-8, which RFC 9051 section " +
      "5.1 makes the encoding of a mailbox name.");
  }
  var text = bytes.toString("utf8");
  if (displayText.hasControlChar(text)) {
    throw _imapSelectBad(verb, "names a mailbox carrying a control character.");
  }
  return text;
}

// A command whose whole argument is one mailbox name: CREATE, DELETE,
// SUBSCRIBE and UNSUBSCRIBE all take exactly that and nothing else.
//
// An argument that cannot be read is refused rather than folded into the
// name, which is the failure shape for every unread argument: the
// command completes and the wrong thing exists.
function _imapSoleMailboxRequest(verb, args, literalBody, note) {
  var read = _imapMailboxArgument(verb, args, literalBody);
  if (read.at !== read.tokens.length) {
    throw _imapSelectBad(verb, "carries arguments besides the mailbox name. " + note);
  }
  return { mailbox: read.mailbox };
}

// The mailbox name of one CREATE, and nothing else. RFC 9051 section
// 6.3.4 gives the command a mailbox and no other argument, and RFC 6154
// section 3 adds a USE parameter under a capability this server does not
// advertise.
//
// An argument that cannot be read is refused rather than folded into the
// name, which is the failure shape for every unread argument: the
// command completes and the wrong thing exists. A client that sent the
// USE parameter would have made a mailbox called after the parameter
// text and been told the special use was recorded.
function _imapCreateRequest(args, literalBody) {
  return _imapSoleMailboxRequest("CREATE", args, literalBody,
    "RFC 9051 section 6.3.4 takes a mailbox name alone, and this server does not advertise " +
    "the CREATE-SPECIAL-USE capability that RFC 6154 section 3 puts a USE parameter under.");
}

// The mailbox name of one DELETE, SUBSCRIBE or UNSUBSCRIBE. RFC 9051
// sections 6.3.5, 6.3.7 and 6.3.8 each give the command a mailbox name
// and no other argument.
function _imapNamedMailboxRequest(verb, args, literalBody) {
  return _imapSoleMailboxRequest(verb, args, literalBody,
    "RFC 9051 gives " + verb + " a mailbox name and nothing else.");
}

// The two names of one RENAME (RFC 9051 section 6.3.6): the mailbox that
// exists and the name it is to have.
//
// The command guard refuses a literal opener anywhere but the end of a
// line, so a RENAME sending one sends the NEW name that way and the
// existing name on the command line. A client that put the existing name
// in a literal is told what this server reads rather than having the
// command half-read, because a rename that took one name from the wrong
// place would move a mailbox the client did not name.
function _imapRenameRequest(args, literalBody) {
  var tokens;
  try { tokens = _searchTokens(args, null); }
  catch (e) {
    throw _imapSelectBad("RENAME",
      (e && e.searchText) || "carries arguments this server cannot read.");
  }
  var wanted = "takes the name of an existing mailbox and the name it is to have " +
    "(RFC 9051 section 6.3.6).";

  function nameAt(index) {
    var token = tokens[index];
    if (token === undefined || (token.kind !== "atom" && token.kind !== "string")) return null;
    return token.value;
  }

  if (literalBody !== undefined && literalBody !== null) {
    var newName = _imapLiteralText("RENAME", literalBody);
    if (tokens.length !== 1 || nameAt(0) === null) {
      throw _imapSelectBad("RENAME", "reads a literal as the last argument of a command, so a " +
        "RENAME sending one puts the existing mailbox name on the command line and the new " +
        "name in the literal. " + wanted);
    }
    return { from: nameAt(0), to: newName };
  }
  if (tokens.length !== 2 || nameAt(0) === null || nameAt(1) === null) {
    throw _imapSelectBad("RENAME", wanted);
  }
  return { from: nameAt(0), to: nameAt(1) };
}

// The hierarchy separator, taken from the layer that owns the namespace
// rather than written again here. A LIST response carries it, a pattern
// is matched against it, and a second spelling would be a listing whose
// separator disagrees with the names in it.
var IMAP_DELIMITER = mailbox.HIERARCHY_DELIMITER;

// RFC 9051 section 6.3.9 selection options this server serves. REMOTE is
// a request to show mailboxes on other servers, and this one has none,
// so it narrows nothing and is accepted as asked.
var IMAP_LIST_SELECTION = Object.freeze({ SUBSCRIBED: true, REMOTE: true });
// And the return options. STATUS is answered from the same reader the
// STATUS command uses, so a client asking for counts in a listing is
// told what it would have been told one command at a time.
var IMAP_LIST_RETURN = Object.freeze({ SUBSCRIBED: true, CHILDREN: true, STATUS: true });

// What one pattern may be once the reference is joined to it. A mailbox
// name stops at 255 bytes, so a pattern this long already covers a whole
// name and a wildcard beside it, and the two ceilings are what bound the
// walk below against a pattern a stranger wrote.
//
// Both are measured on the joined and collapsed pattern rather than on
// what the client typed. The reference is prefixed to the pattern, so a
// ceiling read off the pattern alone is one a long reference walks past.
//
// The wildcard ceiling is the one that matters. The walk pays a pass over
// the name for each wildcard, against each of the mailboxes an account
// may hold, so the cost of a pattern that matches nothing rises with the
// count: measured against a thousand mailboxes named with the longest
// name this server stores, one wildcard costs 11 ms, two cost 348 ms, and
// sixteen cost 5 seconds. A pattern a mail client sends carries one or
// two.
var MAX_LIST_PATTERN_BYTES     = 256;
var MAX_LIST_PATTERN_WILDCARDS = 16;

// RFC 9051 section 6.3.9: `%` matches zero or more characters within one
// level of the hierarchy and `*` matches across levels.
//
// Every pair of offsets the walk passes through is recorded when it
// fails, rather than only the pair it failed at. A pattern is
// stranger-controlled text and a client may send several, so a matcher
// that backtracked freely would answer `a*a*a*a*b` against a long name by
// re-walking the same suffix once per path through it, which is
// exponential work for a command that fits on one line. Recording every
// visited pair bounds it at one walk per pair; recording only the last
// leaves every pair before it to be reached again and walked forward to
// the same refusal.
function _imapNameMatches(pattern, name) {
  var refused = new Set();
  var width = name.length + 1;
  // RFC 9051 section 5.1 makes INBOX case-insensitive, so the five
  // characters of an INBOX level at the start of a name match a pattern
  // in any case. Every other level compares exactly.
  var inboxEnd = (name === "INBOX" || name.indexOf("INBOX" + IMAP_DELIMITER) === 0) ? 5 : 0;

  function same(ch, ni) {
    var held = name.charAt(ni);
    return ni < inboxEnd ? held === ch.toUpperCase() : held === ch;
  }

  function refuse(seen) {
    for (var s = 0; s < seen.length; s += 1) refused.add(seen[s]);
    return false;
  }

  function walk(pi, ni) {
    var seen = [];
    while (pi < pattern.length) {
      var key = pi * width + ni;
      if (refused.has(key)) return refuse(seen);
      seen.push(key);
      var ch = pattern.charAt(pi);
      if (ch === "*" || ch === "%") {
        // Where this wildcard may stop: the end of the name for `*`, and
        // the next separator at or after here for `%`.
        var last = name.length;
        if (ch === "%") {
          var stop = name.indexOf(IMAP_DELIMITER, ni);
          if (stop !== -1) last = stop;
        }
        for (var j = ni; j <= last; j += 1) {
          if (walk(pi + 1, j)) return true;
        }
        return refuse(seen);
      }
      if (ni >= name.length || !same(ch, ni)) return refuse(seen);
      pi += 1;
      ni += 1;
    }
    if (ni === name.length) return true;
    return refuse(seen);
  }

  return walk(0, 0);
}

// The reference and the pattern joined into the one name a listing is
// matched against. RFC 9051 section 6.3.9 reads the pair as a single
// left-to-right hierarchy; a pattern that opens with the separator is
// rooted and the reference is not prefixed to it.
//
// Runs of wildcards are collapsed. `**`, `%%`, `*%` and `%*` each select
// exactly what the wider of the two selects, and leaving them apart
// gives the matcher a second wildcard that can only repeat the first
// one's work.
function _imapListPattern(reference, pattern) {
  var joined = pattern.charAt(0) === IMAP_DELIMITER ? pattern : String(reference) + pattern;
  var out = "";
  for (var i = 0; i < joined.length; i += 1) {
    var ch = joined.charAt(i);
    var previous = out.charAt(out.length - 1);
    if ((ch === "*" || ch === "%") && (previous === "*" || previous === "%")) {
      if (ch === "*" && previous === "%") out = out.slice(0, out.length - 1) + "*";
      continue;
    }
    out += ch;
  }
  return out;
}

// What one LIST asks for (RFC 9051 section 6.3.9): the selection options,
// the reference, one or more patterns, and the return options.
//
// Every option this server does not serve is refused by name rather than
// ignored. A client that asked for a narrowed listing and was handed the
// whole namespace reads it as the answer to the question it asked.
function _imapListRequest(args, literalBody) {
  var trailing = literalBody === undefined || literalBody === null
    ? null
    : _imapLiteralText("LIST", literalBody);
  var tokens;
  try { tokens = _searchTokens(args, trailing); }
  catch (e) {
    throw _imapSelectBad("LIST", (e && e.searchText) || "carries arguments this server cannot read.");
  }

  var at = { i: 0 };
  var wanted = "takes a reference name and a mailbox pattern (RFC 9051 section 6.3.9).";

  function atKind(kind) {
    return at.i < tokens.length && tokens[at.i].kind === kind;
  }
  function takeName(what) {
    if (at.i >= tokens.length ||
        (tokens[at.i].kind !== "atom" && tokens[at.i].kind !== "string")) {
      throw _imapSelectBad("LIST", what);
    }
    var value = tokens[at.i].value;
    at.i += 1;
    return value;
  }
  function takeAtoms(what) {
    var out = [];
    at.i += 1;
    while (at.i < tokens.length && tokens[at.i].kind !== "close") {
      if (tokens[at.i].kind !== "atom") throw _imapSelectBad("LIST", what);
      out.push(tokens[at.i].value.toUpperCase());
      at.i += 1;
    }
    if (at.i >= tokens.length) {
      throw _imapSelectBad("LIST", "carries a parenthesized list that never closes.");
    }
    at.i += 1;
    return out;
  }

  var selection = atKind("open")
    ? takeAtoms("writes each selection option as a name (RFC 9051 section 6.3.9).")
    : [];
  for (var s = 0; s < selection.length; s += 1) {
    if (IMAP_LIST_SELECTION[selection[s]] === true) continue;
    throw _imapSelectBad("LIST", "was asked for the " + selection[s] + " selection option, " +
      "which this server does not serve. It serves SUBSCRIBED and REMOTE.");
  }

  var reference = takeName(wanted);
  var patterns = [];
  if (atKind("open")) {
    at.i += 1;
    while (at.i < tokens.length && tokens[at.i].kind !== "close") {
      patterns.push(takeName(wanted));
    }
    if (at.i >= tokens.length) {
      throw _imapSelectBad("LIST", "carries a pattern list that never closes.");
    }
    at.i += 1;
  } else {
    patterns.push(takeName(wanted));
  }
  if (patterns.length === 0) throw _imapSelectBad("LIST", wanted);

  var returns = [];
  var statusItems = [];
  if (at.i < tokens.length) {
    if (tokens[at.i].kind !== "atom" || tokens[at.i].value.toUpperCase() !== "RETURN") {
      throw _imapSelectBad("LIST", "carries an argument after the pattern that is not the " +
        "RETURN list of RFC 9051 section 6.3.9.");
    }
    at.i += 1;
    if (!atKind("open")) {
      throw _imapSelectBad("LIST", "writes the return options as a parenthesized list " +
        "(RFC 9051 section 6.3.9).");
    }
    at.i += 1;
    while (at.i < tokens.length && tokens[at.i].kind !== "close") {
      if (tokens[at.i].kind !== "atom") {
        throw _imapSelectBad("LIST", "writes each return option as a name (RFC 9051 section 6.3.9).");
      }
      var option = tokens[at.i].value.toUpperCase();
      at.i += 1;
      if (IMAP_LIST_RETURN[option] !== true) {
        throw _imapSelectBad("LIST", "was asked for the " + option + " return option, which " +
          "this server does not serve. It serves SUBSCRIBED, CHILDREN and STATUS.");
      }
      if (option === "STATUS") {
        if (!atKind("open")) {
          throw _imapSelectBad("LIST", "writes the STATUS return option with the parenthesized " +
            "list of items it asks for (RFC 9051 section 6.3.9).");
        }
        statusItems = takeAtoms("writes each STATUS item as a name (RFC 9051 section 6.3.9).");
      }
      returns.push(option);
    }
    if (at.i >= tokens.length) {
      throw _imapSelectBad("LIST", "carries a return option list that never closes.");
    }
    at.i += 1;
  }
  if (at.i !== tokens.length) {
    throw _imapSelectBad("LIST", "carries arguments after the return options.");
  }

  var compiled = [];
  for (var p = 0; p < patterns.length; p += 1) {
    var one = _imapListPattern(reference, patterns[p]);
    if (Buffer.byteLength(one, "utf8") > MAX_LIST_PATTERN_BYTES) {
      throw _imapSelectBad("LIST", "carries a reference and a pattern that come to more than " +
        "the " + MAX_LIST_PATTERN_BYTES + " bytes this server matches against a mailbox name, " +
        "which stops at 255.");
    }
    if ((one.match(/[*%]/g) || []).length > MAX_LIST_PATTERN_WILDCARDS) {
      throw _imapSelectBad("LIST", "carries more than the " + MAX_LIST_PATTERN_WILDCARDS +
        " wildcards this server matches in one pattern.");
    }
    compiled.push(one);
  }

  return {
    reference:      String(reference),
    patterns:       compiled,
    // The empty pattern is a request for the hierarchy separator and the
    // root of the reference rather than for a listing, which section
    // 6.3.9 answers with one \Noselect response.
    rootOnly:       patterns.length === 1 && patterns[0] === "",
    subscribedOnly: selection.indexOf("SUBSCRIBED") !== -1,
    wantSubscribed: returns.indexOf("SUBSCRIBED") !== -1,
    wantStatus:     returns.indexOf("STATUS") !== -1,
    statusItems:    statusItems,
  };
}

// The mailbox name and the select parameters of one SELECT or EXAMINE.
// RFC 9051 section 6.3.2 takes a mailbox, and RFC 7162 section 3.1.8 adds
// an optional parenthesized list of select parameters after it.
//
// Throws with the text of a BAD for anything that cannot be read. A
// QRESYNC parameter is one of those: RFC 7162 section 3.2.5 answers it
// with BAD from a session that has not enabled QRESYNC, and no session
// here can enable it.
function _imapSelectRequest(verb, args, literalBody) {
  var read = _imapMailboxArgument(verb, args, literalBody);
  var mailboxName = read.mailbox;
  var tokens = read.tokens;
  var at = read.at;
  if (literalBody !== undefined && literalBody !== null && tokens.length > 0) {
    throw _imapSelectBad(verb, "carries arguments besides the mailbox name it sent as a literal.");
  }

  var condstore = false;
  if (at === tokens.length) return { mailbox: mailboxName, condstore: condstore };

  if (tokens[at].kind !== "open") {
    throw _imapSelectBad(verb, "carries '" + _searchEcho(tokens[at].value || ")") + "' after " +
      "the mailbox name, where only a parenthesized list of select parameters may follow.");
  }
  at += 1;
  var named = 0;
  while (at < tokens.length && tokens[at].kind !== "close") {
    var param = tokens[at];
    if (param.kind !== "atom") {
      throw _imapSelectBad(verb, "carries a select parameter that is not an atom.");
    }
    var paramName = param.value.toUpperCase();
    if (paramName === "QRESYNC") {
      throw _imapSelectBad(verb, "carries the QRESYNC parameter, and QRESYNC is not enabled " +
        "on this session (RFC 7162 section 3.2.5). This server does not offer QRESYNC.");
    }
    if (paramName !== "CONDSTORE") {
      throw _imapSelectBad(verb, "carries the select parameter '" + _searchEcho(param.value) +
        "', which this server does not know.");
    }
    condstore = true;
    named += 1;
    at += 1;
  }
  if (at >= tokens.length) {
    throw _imapSelectBad(verb, "opens a parameter list it never closes.");
  }
  if (named === 0) {
    throw _imapSelectBad(verb, "carries an empty parameter list, and RFC 7162 section 3.1.8 " +
      "puts at least one parameter in it.");
  }
  if (at + 1 !== tokens.length) {
    throw _imapSelectBad(verb, "carries arguments after its parameter list.");
  }
  return { mailbox: mailboxName, condstore: condstore };
}

/**
 * @primitive blamepost.mail.listeners.create
 * @signature blamepost.mail.listeners.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5321 (SMTP), RFC 6409 (submission), RFC 8314 (implicit TLS), RFC 9051 (IMAP), RFC 1939 (POP3), RFC 5804 (ManageSieve)
 *
 * Build every listener this server runs. Returns
 * `{ start, stop, bound, describe, relay }`.
 *
 * `relay` is the outbound handle with this server's own recipients
 * routed to mailboxes here, described under
 * `blamepost.mail.listeners.relay`. It is built whatever binds, so a
 * server with the submission port shut still hands the browser and JMAP
 * surfaces the same answer about where a recipient goes.
 *
 * Nothing binds at create time. `start` runs an ordered boot sequence
 * through `b.bootGates`: the DNS posture gate first, then one gate per
 * listener. A gate that fails stops the sequence, closes whatever
 * already bound, and throws, so a half started server never sits there
 * accepting mail it cannot route. `stop` drains in the reverse order
 * inside a bounded deadline, which is what lets a supervisor stop this
 * process with a signal instead of killing it.
 *
 * The store contract is checked here rather than at the first
 * connection: `resolve` plus `accounts.authenticate`, `domains.list`
 * and `aliases.list` on the identity store, and `appendMessage` on the
 * message store.
 *
 * @opts
 *   config:     object,   // required; hostname, dns posture, listener sections, resource ceilings
 *   store:      object,   // required; resolve, accounts.authenticate, domains.list, aliases.list
 *   mailStore:  object,   // required; the protocol facing message store
 *   certificate: object,  // required; the loader handle, whose secureContext is read per connection
 *   delivery:   object,   // required; the blamepost.mail.delivery handle
 *   sendingCredentials: object,  // optional; blamepost.store.credentials, needing verify and
 *                                //   counters.record. Submission is the only LISTENER that reads
 *                                //   it, and a credential offered to IMAP, POP3 or ManageSieve
 *                                //   names no identity; the browser port's sending route reaches
 *                                //   the same registry through the two calls this handle exposes
 *   dkim:       object,   // optional; signs relayed submissions
 *   resolver:   object,   // optional; b.network.dns.resolver for HELO, SPF, DKIM verify and DMARC
 *   dnsAnswerBudgetMs: number,   // optional; how long a session waits on that handle, default 45s
 *   greylist:   object,   // optional; b.mail.greylist handle
 *   rbl:        object,   // optional; b.mail.rbl handle
 *
 * @example
 *   var listeners = blamepost.mail.listeners.create({
 *     config:      config,
 *     store:       store,
 *     mailStore:   store.mailbox,
 *     certificate: blamepost.tlsContext({ certFile: cert, keyFile: key }),
 *     delivery:    delivery,
 *     dkim:        dkim,
 *   });
 *   await listeners.start();
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.listeners.create: opts object is required");
  }
  var config = opts.config;
  if (!config || typeof config !== "object") {
    throw new TypeError("blamepost.mail.listeners.create: opts.config is required");
  }
  if (typeof config.hostname !== "string" || config.hostname.length === 0) {
    throw new TypeError("blamepost.mail.listeners.create: config.hostname is required. " +
      "It is the name this server announces in its SMTP banner and the name the MX " +
      "record has to point at.");
  }
  // Before anything else this function checks, because everything else
  // it checks is a thing the caller can fix and this is a thing the
  // caller has to give up. A composition that refused the relay grant
  // only after the store and the certificate satisfied it would hand an
  // operator two rounds of failure for one configuration.
  _refuseRelayGrant(config.relayAllowedFor);
  var certificate = opts.certificate;
  if (!certificate || typeof certificate !== "object" ||
      certificate.secureContext === undefined || certificate.secureContext === null) {
    throw new TypeError("blamepost.mail.listeners.create: opts.certificate is required, and " +
      "it is the loader handle rather than a context. None of these listeners has a " +
      "plaintext mode, and the certificate an operator's client rewrites every renewal has " +
      "to be readable at the moment a connection arrives rather than at the moment this " +
      "server started. Build it with blamepost.tlsContext({ certFile, keyFile }) over the " +
      "certificate BLAMEPOST_TLS_CERT and BLAMEPOST_TLS_KEY name.");
  }
  var store = _requireMethods(opts.store, ["resolve"],
    "blamepost.mail.listeners.create: opts.store");
  // And it answers synchronously, which is probed rather than asserted
  // in prose. See `_refuseAsyncResolve` for what is asked and why one
  // question is not enough to ask it.
  _refuseAsyncResolve(store);
  // The two readers the account re-read needs are NOT asked for here.
  // They are asked for by the listeners that perform it, which is what
  // `_requireAccountLivenessReaders` does. A server that binds port 25
  // and nothing else opens no session and never reaches the re-read, so
  // asking every composition for readers most of them never call would
  // refuse a working one.
  _requireMethods(store.accounts, ["authenticate"],
    "blamepost.mail.listeners.create: opts.store.accounts");
  _requireMethods(store.domains, ["list"],
    "blamepost.mail.listeners.create: opts.store.domains");
  // The submission listener measures a message's author against the
  // addresses that reach the authenticated account, and an alias is
  // half of that set. A store that cannot answer would leave every
  // account able to write only its own address, which is a refusal
  // nobody configured, so the gap is found at boot instead.
  _requireMethods(store.aliases, ["list"],
    "blamepost.mail.listeners.create: opts.store.aliases");
  var mailStore = _requireMethods(opts.mailStore,
    ["appendMessage"],
    "blamepost.mail.listeners.create: opts.mailStore");
  var delivery = _requireMethods(opts.delivery,
    ["send", "bounce"],
    "blamepost.mail.listeners.create: opts.delivery");
  // The queue's own admission, which both handoffs take before
  // committing a message anywhere and hold until they are done with it.
  // A handle without it would compose listeners that accept mail into a
  // queue with no bottom, so it is refused at construction rather than
  // discovered at the message that would have crossed the ceiling.
  _requireMethods(opts.delivery.queue,
    ["reserve", "capacity"],
    "blamepost.mail.listeners.create: opts.delivery.queue");
  if (opts.dkim !== undefined && opts.dkim !== null && typeof opts.dkim.sign !== "function") {
    throw new TypeError("blamepost.mail.listeners.create: opts.dkim must expose sign(domain, bytes)");
  }
  // The sending-credential registry, when the store carries one. Absent,
  // this server has no such identity and a name shaped like a domain is
  // measured as an address and refused, which is what it did before the
  // registry existed.
  //
  // Both halves are required together rather than one at a time. The
  // registry answers what a credential may write and how much it may
  // send, and a handle offering only the first would authenticate
  // credentials whose two ceilings are written on every row and read
  // nowhere. A ceiling that is declared and never enforced is worse than
  // one that was never offered, because an operator sets it and believes
  // it is holding.
  var sendingCredentials = null;
  if (opts.sendingCredentials !== undefined && opts.sendingCredentials !== null) {
    // `stillSending` beside `verify` for the same reason `counters.record`
    // is beside it. The scope a session carries is settled at AUTH, and
    // the connection can outlive the credential: the clock reaches an
    // expiry on its own, and the admin console withdraws a domain through
    // the running server. A handle offering only `verify` would answer
    // those changes at the next sign-in and never on the session that is
    // sending.
    sendingCredentials = _requireMethods(opts.sendingCredentials,
      ["verify", "stillSending"],
      "blamepost.mail.listeners.create: opts.sendingCredentials");
    _requireMethods(opts.sendingCredentials.counters, ["record"],
      "blamepost.mail.listeners.create: opts.sendingCredentials.counters");
  }

  // Every listener composition goes through here, and the reason it is a
  // function rather than a value is the renewal.
  //
  // The certificate this server presents changes while the process runs.
  // An operator's certificate client rewrites the two files every sixty
  // to ninety days and signals nothing, and the loader watching them
  // rebuilds the context in place when it notices. A listener composed
  // against whatever that handle held at boot goes on presenting the
  // certificate that has since expired, and the failure is silent from
  // every angle an operator can see: the reload succeeded, the files on
  // disk are right, the listeners are still bound, and every handshake a
  // sending peer offers fails. So the option the listener holds is an
  // ACCESSOR, read at the moment a connection needs a context rather
  // than at the moment this function ran.
  //
  // Which listeners that actually reaches is a property of the framework
  // rather than of this file, and it is uniform now: all five read the
  // option per connection, so a renewal reaches every mail port while the
  // process runs. It was not always, which is why the answer is still
  // asked for rather than assumed. `staleAfterRotation` names whatever
  // set does not rotate, so a caller can tell an operator which ports a
  // renewal did not reach instead of leaving them to discover it from a
  // client. The mail half of that answer is the constant above and is
  // empty; the browser half is computed. So a mail listener that stopped
  // rotating would need the constant edited before it was named, and the
  // renewal test is what would report it in the meantime.
  function _tlsOption(o) {
    Object.defineProperty(o, "tlsContext", {
      enumerable: true,
      get: function () { return certificate.secureContext; },
    });
    return o;
  }

  var hostname = config.hostname;
  var dkim = opts.dkim || null;
  var resolver = opts.resolver || null;
  // The budget the connection path holds over that handle. A composition
  // may shorten it; nothing may turn it off, because the value that
  // would turn it off is the behavior it exists to end. Read at
  // construction and refused there, so a number written as a string is
  // a boot failure rather than a bound that quietly reverted to the
  // default on the first connection.
  var dnsAnswerBudgetMs = DNS_ANSWER_BUDGET_MS;
  if (opts.dnsAnswerBudgetMs !== undefined) {
    if (typeof opts.dnsAnswerBudgetMs !== "number" || !isFinite(opts.dnsAnswerBudgetMs) ||
        opts.dnsAnswerBudgetMs <= 0) {
      throw new TypeError("blamepost.mail.listeners.create: opts.dnsAnswerBudgetMs must be a " +
        "positive finite number of milliseconds. It is how long a session will wait on the " +
        "DNS handle this server was given before answering the peer a temporary failure, and " +
        "there is no value for it that means no limit.");
    }
    dnsAnswerBudgetMs = opts.dnsAnswerBudgetMs;
  }
  var profile = config.profile || "strict";
  // Delivery decisions an operator has to be able to see: a filter that
  // failed, a folder a script named and this account does not have, an
  // action this build cannot perform. Each of those keeps the message
  // and says so, and a line nobody can read would make the keeping
  // indistinguishable from the filtering.
  var log = b.log.boot("mail.listeners");
  b.audit.registerNamespace(AUDIT_NAMESPACE);
  var sections = config.listeners || {};
  // POP3 is the one listener the configuration has its own switch for,
  // because it is the one an operator opts into rather than out of. A
  // per listener section still overrides it, which is what an operator
  // moving POP3 to a different port needs.
  var pop3Default = Object.assign({}, DEFAULTS.pop3, { enabled: config.pop3Enabled === true });
  var wanted = {
    mx:          _listenerConfig(sections.mx,          DEFAULTS.mx,          "mx"),
    submission:  _listenerConfig(sections.submission,  DEFAULTS.submission,  "submission"),
    submissions: _listenerConfig(sections.submissions, DEFAULTS.submissions, "submissions"),
    imap:        _listenerConfig(sections.imap,        DEFAULTS.imap,        "imap"),
    pop3:        _listenerConfig(sections.pop3,        pop3Default,          "pop3"),
    managesieve: _listenerConfig(sections.managesieve, DEFAULTS.managesieve, "managesieve"),
  };

  var limits = _limitsConfig(config.limits);

  var handles = {};
  var boundPorts = {};

  // Why a listener that is enabled took no port, for the ones this
  // server decided against rather than failed at. Read beside
  // `boundPorts` and never instead of it: a listener is bound, or it is
  // held shut for a reason written here, or it is neither, and the third
  // case is the only one that is a fault. A reader with only the first
  // two of those cannot tell a deliberate refusal from a bind that did
  // not happen, and reports a server doing its job as a server that
  // failed to come up.
  var withheld = {};

  // ---- Authentication -----------------------------------------------------

  // Decode one SASL PLAIN response (RFC 4616): authorization identity,
  // NUL, authentication identity, NUL, password. Returns null on
  // anything that is not a well formed response, which the caller turns
  // into an authentication failure rather than an exception, because
  // the listener already owns the reply code for that.
  // The encoding is checked as the client wrote it, and it has to be
  // the canonical spelling: whole groups of four, and the bits a padded
  // group cannot use set to zero (RFC 4648 §3.5). The decoder underneath
  // drops what it cannot use rather than refusing, so a permissive check
  // accepts several distinct lines for one credential: a trailing
  // character, an extra padding character, a space after the response.
  // Every one of them signs in. Nothing an account holder does
  // changes: their client emits the canonical form. What changes is that
  // a log correlation, an intrusion signature or a replay window keyed on
  // the response stops being defeatable by appending a character.
  //
  // What the encoding carries is checked for the same reason. RFC 4616
  // §2 puts all three fields in UTF-8, and the decoder underneath does
  // not refuse a payload that is not: it substitutes a replacement
  // character for every sequence it cannot read, so responses carrying
  // different octets arrive as one credential and the many-to-one the
  // encoding rule above closes is open again a step later. Worse, a line
  // no conforming client could send would reach the identity layer as a
  // credential, and every guess that gets that far spends the mailbox's
  // failure budget, which is how an attacker locks an account holder out
  // of their own mail without ever sending a password. Refused here
  // instead, where the response is parsed.
  function _decodePlain(clientResponse) {
    if (typeof clientResponse !== "string" || clientResponse.length === 0) return null;
    if (!b.safeBuffer.isCanonicalBase64(clientResponse)) return null;
    var raw = Buffer.from(clientResponse, "base64");
    if (!nodeBuffer.isUtf8(raw)) return null;
    var parts = raw.toString("utf8").split(SASL_PLAIN_SEPARATOR);
    if (parts.length !== 3) return null;
    return { authzid: parts[0], authcid: parts[1], password: parts[2] };
  }

  // The actor the listeners carry for the rest of the session, built
  // from the store's authentication verdict.
  //
  // `mailboxes` is the address set the submission listener compares
  // MAIL FROM against, and it holds the account's own address alone.
  // An alias is a delivery route rather than an identity: mail arriving
  // for it reaches this account, which says nothing about the account
  // being entitled to sign mail as it. Widening this to include aliases
  // would let one account send as every address routed to it.
  //
  // `roles` is what the mailbox role gate resolves against, and it is
  // the only permission statement this actor makes. A `scopes` key is
  // deliberately absent: `b.permissions` reads that array in preference
  // to the roles whenever it is present, so an empty one is not a
  // request to decide from the role, it is an explicit grant of nothing,
  // and an actor carrying both is refused every verb its role allows.
  // The two roles match the ones the browser surface issues, so one
  // account holds the same permissions whichever way it signs in.
  //
  // `remoteAddress` is the peer the credential arrived from. It is on
  // the identity rather than passed down because the identity is the one
  // object that travels from the exchange that established it to every
  // command the session sends, including the verbs the framework
  // dispatches itself and the rows the mailbox layer writes underneath
  // them. A session names an account and an address, and every row it
  // writes can then name both: an operator asking what else came from
  // one address is asking a question about the address rather than about
  // the account, and only the rows that carry it can answer.
  function _actorFor(verdict, peer) {
    return {
      id:        verdict.accountId,
      username:  verdict.address,
      address:   verdict.address,
      domain:    verdict.domain,
      isAdmin:   verdict.isAdmin === true,
      mailboxes: [String(verdict.address).toLowerCase()],
      roles:     verdict.isAdmin === true ? ["admin", "account"] : ["account"],
      remoteAddress: typeof peer === "string" && peer.length > 0 ? peer : null,
    };
  }

  // One verifier per SURFACE rather than one for the whole server, and
  // the surface decides what an identity is allowed to be.
  //
  // Every listener drives the same step runner, so the SASL exchange,
  // the challenge, the withdrawal and the malformed response are
  // answered identically whichever port a client arrived on. What
  // differs is the identity space: submission reads an account or a
  // sending credential, and the mailbox protocols read an account and
  // nothing else. A credential offered to IMAP, POP3 or ManageSieve
  // reaches `store.accounts.authenticate` as an address this server
  // cannot read, is refused under `bad-credentials`, and draws the reply
  // a wrong password draws, so nothing on the wire tells the two apart.
  //
  // The surface is required and has no default. A builder that forgot to
  // say which one it is would otherwise inherit whichever was written
  // here, and one of the two answers hands a sending secret every
  // mailbox in its domain.
  function _verifier(surface) {
    if (surface !== AUTH_SURFACES.SUBMISSION && surface !== AUTH_SURFACES.MAILBOX) {
      throw new TypeError("blamepost.mail.listeners: _verifier needs the surface it is " +
        "built for, " + JSON.stringify(AUTH_SURFACES.SUBMISSION) + " or " +
        JSON.stringify(AUTH_SURFACES.MAILBOX) + ", got " + JSON.stringify(surface) + ". " +
        "It decides whether a sending credential is an identity on this listener, and a " +
        "credential accepted by a mailbox protocol would read every mailbox in its domain.");
    }
    return async function _verify(mechanism, credentials) {
      credentials = credentials || {};
      var username;
      var password;
      if (typeof credentials.username === "string") {
        // IMAP LOGIN and POP3 USER plus PASS arrive already split.
        username = credentials.username;
        password = credentials.password;
      } else if (String(mechanism).toUpperCase() === "PLAIN") {
        var response = credentials.clientResponse;
        // The step counter belongs to the listener, and it is what
        // separates the opening call from the answer to a challenge.
        var step = typeof credentials.step === "number" ? credentials.step : 0;
        if (response === null || response === undefined) {
          // AUTHENTICATE with no initial response, which RFC 9051
          // section 6.2.2, RFC 4954 section 4, RFC 5034 section 4 and
          // RFC 5804 section 2.1 all answer by asking for one. The
          // empty challenge is the whole of the ask: PLAIN is client
          // first, so the server has nothing to say beyond go ahead.
          //
          // Only the opening step asks. A client that answers a
          // challenge with nothing has already been asked, and asking
          // again is an exchange with no end.
          if (step === 0) return { pending: true, challenge: "" };
          return { ok: false, reason: "sasl-initial-response-absent" };
        }
        if (response === "*" && step > 0) {
          // A line holding one asterisk, answering a challenge, is the
          // client withdrawing its own exchange: RFC 9051 section 6.2.2
          // and RFC 4954 section 4. It is not a bad credential and the
          // audit trail should not read like one. On the opening step
          // there is no exchange to withdraw, so an asterisk there is
          // just a response that is not base64, and it falls through to
          // the decoder that says so.
          return { ok: false, reason: "sasl-exchange-cancelled" };
        }
        var decoded = _decodePlain(response);
        if (!decoded) return { ok: false, reason: "malformed-sasl-response" };
        if (decoded.authzid && decoded.authzid !== decoded.authcid) {
          // Acting as a second identity is what the authorization field
          // asks for. This server grants nobody that.
          return { ok: false, reason: "proxy-authorization-refused" };
        }
        username = decoded.authcid;
        password = decoded.password;
      } else {
        // APOP and the challenge response mechanisms need a shared secret
        // the server can reproduce. Passwords here are stored as
        // verifiers, so the honest answer is a refusal.
        return { ok: false, reason: "mechanism-" + String(mechanism).toLowerCase() + "-refused" };
      }
      if (typeof username !== "string" || username.length === 0 ||
          typeof password !== "string" || password.length === 0) {
        return { ok: false, reason: "empty-credentials" };
      }
      var source = typeof credentials.remoteAddress === "string"
        ? credentials.remoteAddress
        : null;
      // The one branch that separates the two surfaces. A name that
      // reads as a hosted domain is a sending credential, and only the
      // submission listener has that identity space at all: on a mailbox
      // protocol the same name falls through to the account path below,
      // where an address this server cannot read names nobody.
      var scopeDomain = surface === AUTH_SURFACES.SUBMISSION
        ? _scopeDomainOf(username)
        : null;
      if (scopeDomain !== null) {
        // Through the exposed entry point rather than past it. It is
        // where the credential failure budget is read and spent, and the
        // sending route on the browser port reaches the same function,
        // so guesses made on either transport are counted against one
        // credential rather than against one surface each.
        return await verifySendingCredential(sendingCredentials, {
          secret:      password,
          presentedAs: scopeDomain,
          source:      source,
        });
      }
      // The peer travels with the credential because the failure budget
      // the identity layer keeps is keyed on the mailbox, and a budget
      // keyed on the mailbox alone is a way to lock an account holder out
      // of their own mail. The peer is what lets a source this mailbox
      // has already signed in from through while the budget is spent.
      // Every listener hands it over; a verdict is refused on the wire
      // either way, so nothing here reads it.
      var verdict = await store.accounts.authenticate({
        address:  username,
        password: password,
        source:   source,
      });
      if (!verdict || verdict.ok !== true) {
        return { ok: false, reason: (verdict && verdict.reason) || "credentials-rejected" };
      }
      return { ok: true, actor: _actorFor(verdict, source) };
    };
  }

  function _authConfig(surface) {
    return { mechanisms: SASL_MECHANISMS.slice(), verify: _verifier(surface) };
  }

  // ---- Inbound routing ----------------------------------------------------

  // The message as the Sieve interpreter wants to see it: a flat header
  // list, the envelope the peer declared, and a size. The interpreter is
  // pure and reads nothing else, so this is the whole of what a script
  // can decide on.
  //
  // Envelope and headers are different things and a script may test
  // either. `envelope :from` is what the peer said in MAIL FROM, and the
  // From header is what the message claims; the two disagree on every
  // forwarded message and on every forgery, which is most of why Sieve
  // offers both.
  //
  // `envelope :to` is the recipient the peer wrote in RCPT TO, which RFC
  // 5228 section 5.4 defines as the address that caused this delivery.
  // That is the address rather than the mailbox behind it, and an alias
  // is where the two stop being the same string: mail to a departmental
  // address lands in somebody's own mailbox, and filing by the address
  // it arrived at is the reason a person reaches for this test at all,
  // since the messages carry the same To header either way. Handing over
  // the mailbox instead answered every such rule false, which is a rule
  // that files nothing and says nothing.
  // The size is taken from the message rather than from the text parsed
  // out of it. RFC 5228 §5.9 gives `size` the number of octets in the
  // message, and a decode is not a count-preserving view of one: every
  // octet sequence it does not recognize becomes a replacement
  // character three octets wide, so a body in a legacy charset would
  // test larger than it is and a script written around `:over` would
  // file mail on a number the message does not have.
  // The parser takes the octets as well, so the message is never
  // decoded on the way in. A decode here would be a second copy of every
  // message this server accepts, and it would hand the parser a rendering
  // of the message rather than the message.
  function _sieveEnv(inbound, rcpt) {
    var bytes = Buffer.isBuffer(inbound.body)
      ? inbound.body
      : Buffer.from(String(inbound.body || ""), "utf8");
    var parsed = b.safeMime.parse(bytes, mailbox.MESSAGE_PARSE_CAPS);
    var raw = (parsed && parsed.headers && parsed.headers.raw) || {};
    var headers = [];
    Object.keys(raw).forEach(function (name) {
      var values = raw[name] || [];
      for (var i = 0; i < values.length; i += 1) {
        headers.push({ name: name, value: values[i] });
      }
    });
    return {
      headers:   headers,
      envelope:  { from: inbound.mailFrom || "", to: String(rcpt || "") },
      sizeBytes: bytes.length,
    };
  }

  // Where a message should land, according to the recipient's own
  // filter. Returns a folder name, or null when the script discarded it.
  //
  // Every failure here answers INBOX. A script is written by an account
  // holder, stored, and then run against every message that arrives for
  // them, so a parse error, a runaway loop that exhausts its gas budget,
  // or a folder that no longer exists must cost the message nothing. A
  // filter that eats mail when it breaks is worse than no filter, and
  // the account holder is the last person who would find out.
  function _sieveFolderFor(target, inbound, rcpt) {
    var actor = { id: target.accountId, address: target.mailbox };
    var script;
    try {
      script = mailStore.sieveScripts.active(actor);
    } catch (err) {
      // The value goes into the screen unconverted. A catch block
      // receives whatever a throw or a rejection carried, and reading a
      // shape nobody chose as text can fail on its own: an object with
      // no prototype has no `toString` to call, and one carrying a
      // `toString` that throws raises its own error. Converting here
      // would do that reading outside the screen, where the screen's
      // promise never to throw cannot cover it, and the throw would take
      // the delivery with it.
      log.error("could not read the active Sieve script for " + target.mailbox +
        ", delivering to INBOX: " + displayText.forDisplay((err && err.message) || err));
      return "INBOX";
    }
    if (!script) return "INBOX";

    var verdict;
    try {
      verdict = b.mail.sieve.runScript(script.body, _sieveEnv(inbound, rcpt), {
        profile: profile,
      });
    } catch (err) {
      // The name and the reason are both screened on the way out. The
      // name is the account holder's, and the reason is the interpreter
      // quoting the script it could not run, so both are text somebody
      // else wrote arriving in an operator's terminal.
      var failedName = displayText.forDisplay(script.name);
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.failed",
        outcome:  "failure",
        metadata: { mailbox: target.mailbox, script: failedName,
                    reason: displayText.forDisplay((err && err.message) || err) },
      });
      log.error("Sieve script " + JSON.stringify(failedName) + " for " + target.mailbox +
        " failed, delivering to INBOX: " +
        displayText.forDisplay((err && err.message) || err));
      return "INBOX";
    }

    // A message is filed once here, so the actions are read for one
    // destination and everything the script asked for beyond it is
    // reported. RFC 5228 section 2.10.3 lets an implementation limit how
    // many actions it takes and requires it to say when it did, and the
    // limit is the reason the report exists: an account holder who
    // writes two destinations and is told nothing reads the one message
    // they find as the whole of what happened.
    //
    // The destination follows from WHAT the author wrote rather than
    // from the order they wrote it in. A `fileinto` names a folder and a
    // `keep` names the default, so the named folder is the one taken
    // whichever line came first. Reading them in order instead let a
    // `keep` written above a `fileinto` take INBOX and leave the folder
    // the script named holding nothing, with no line anywhere saying so.
    var actions = (verdict && verdict.actions) || [];
    var folder = null;
    var kept = false;
    var discarded = false;
    var unapplied = [];
    for (var i = 0; i < actions.length; i += 1) {
      var action = actions[i];
      if (action.kind === "fileinto") {
        if (folder === null) folder = action.folder;
        else unapplied.push(action.kind);
        continue;
      }
      // Discard cancels the implicit keep and nothing else, so beside a
      // `fileinto` it asks for nothing this server did not do.
      if (action.kind === "discard") { discarded = true; continue; }
      if (action.kind === "keep") { kept = true; continue; }
      // Anything else the interpreter emitted and this path does not
      // apply. `redirect` is the one this build emits: it puts a message
      // on the wire, and the only thing that does that here is the
      // outbound composer. Read by KIND rather than by a list of names,
      // so an action a later interpreter starts emitting is reported
      // rather than dropped in a branch that never learned about it.
      unapplied.push(action.kind);
    }
    // An explicit `keep` beside a folder is a second copy this server
    // does not make. It only reaches here when the author wrote it: a
    // `fileinto` cancels the implicit keep, so the two are never in the
    // list together unless both were typed.
    if (folder === null && kept) folder = "INBOX";
    else if (kept) unapplied.push("keep");
    for (var u = 0; u < unapplied.length; u += 1) {
      var askedBy = displayText.forDisplay(script.name);
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.action_unavailable",
        outcome:  "failure",
        metadata: { mailbox: target.mailbox, script: askedBy, sieveAction: unapplied[u] },
      });
      log.error("Sieve script " + JSON.stringify(askedBy) + " for " + target.mailbox +
        " asked for " + unapplied[u] + ", which this server did not perform. The message " +
        "is kept rather than dropped.");
      if (folder === null) folder = "INBOX";
    }
    // RFC 5228 section 2.10.2: something files the message or the
    // implicit keep does. A discard with nothing else beside it is the
    // one case that ends with no folder at all.
    if (folder === null && !discarded) return "INBOX";
    if (folder === null) return null;
    return folder;
  }

  // Deliver one inbound message to one target the store resolved.
  //
  // A local target lands in the folder the recipient's own Sieve script
  // chooses, which is their INBOX when they have no script, when the
  // script keeps the message, and whenever anything about the script
  // goes wrong. A target on another domain, which an alias forwarding
  // off this server produces, leaves through the one outbound path, so a
  // forwarded message gets the same MTA-STS, DANE and REQUIRETLS
  // treatment as anything else this server sends.
  //
  // `origin` says which share of the outbound queue a forward may take.
  // A message being forwarded off this server arrived from a stranger,
  // and how many of them arrive is decided by whoever writes to the
  // alias, so it stops short of the ceiling and the remainder stays
  // available to accounts that have authenticated.
  //
  // `rcpt` is the recipient the envelope named, which this target was
  // resolved from, and it is what the reachability question below is
  // asked about again. `hold` is the queue room the handoff already took
  // for the whole message, so a forward spends that rather than asking
  // for more and being refused with mailboxes here already holding a
  // copy.
  async function _deliverToTarget(target, inbound, origin, rcpt, hold) {
    // This server's name comes off the message unless this server put it
    // there. Done here rather than at either caller because this is the
    // one funnel both of them reach, and it covers the three things that
    // happen to a body: the folder the recipient's script picks, the
    // octets stored, and the copy a forward puts back on the wire. A
    // forged verdict that left again would be this server asserting to
    // the next receiver something it never measured.
    //
    // `inbound.auth` is the verdict the MX listener computed, which the
    // framework prepends as a header of its own. It is absent on a
    // message an account submitted, and absent on one whose
    // authentication could not be completed and was accepted anyway, and
    // in both cases nothing under this server's name on that message was
    // written by this server.
    inbound = Object.assign({}, inbound, {
      body: screenReceiverVerdicts(inbound.body, hostname, !!inbound.auth),
    });
    if (target.local !== true) {
      await delivery.send({
        from:   inbound.mailFrom,
        to:     [target.mailbox],
        rfc822: inbound.body,
        origin: origin,
        hold:   hold || undefined,
      });
      return { kind: "forward", address: target.mailbox };
    }
    _refuseIfTargetHasMoved(rcpt, target);
    var actor = { id: target.accountId, address: target.mailbox };
    var folder = _sieveFolderFor(target, inbound, rcpt);
    if (folder === null) {
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.discarded",
        outcome:  "success",
        metadata: { mailbox: target.mailbox },
      });
      return { kind: "discarded", mailbox: target.mailbox };
    }
    var stored;
    try {
      stored = await mailStore.appendMessage(folder, inbound.body,
        { actor: actor, flags: [], recipient: rcpt });
    } catch (err) {
      // The script named a folder this account does not have. RFC 5228
      // section 4.1 lets an implementation deliver to INBOX instead of
      // creating it, and creating it is not available here: folder names
      // live in one place and nothing can add one, so inventing a folder
      // at delivery time would be a second naming scheme.
      if (folder === "INBOX") throw err;
      // The folder is a string literal inside the account holder's own
      // script, so it never passed a name gate: it reaches here exactly
      // because the mailbox gate refused it or the account holds no
      // folder by that name. Screened on the way into the log line and
      // the audit row, which is where it is read.
      var missing = displayText.forDisplay(folder);
      log.error("Sieve for " + target.mailbox + " files into " + JSON.stringify(missing) +
        ", which is not a folder on this account. Delivering to INBOX instead: " +
        displayText.forDisplay((err && err.message) || err));
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.folder_missing",
        outcome:  "failure",
        metadata: { mailbox: target.mailbox, folder: missing },
      });
      stored = await mailStore.appendMessage("INBOX", inbound.body,
        { actor: actor, flags: [], recipient: rcpt });
      folder = "INBOX";
    }
    return {
      kind:     "mailbox",
      mailbox:  target.mailbox,
      folder:   folder,
      objectid: stored && stored.objectid,
    };
  }

  // Targets worth attempting. The store marks a suspended mailbox and a
  // disabled domain undeliverable, and delivering to one anyway would
  // put mail into a mailbox nobody is meant to be reading.
  function _deliverableTargets(verdict) {
    return (verdict.targets || []).filter(function (t) { return t.deliverable === true; });
  }

  // Whether a resolved recipient has anywhere to land. One predicate,
  // because three places ask it: the RCPT check that refuses on the wire,
  // the handoff that resolves the envelope, and the delivery verb that
  // asks it again at the instant it writes. A second spelling of it would
  // let the listener accept an address the handoff then refuses, which is
  // the `250` followed by a report that this whole path exists to stop.
  function _mailboxIsReachable(routed) {
    return !!routed && routed.deliverable === true &&
      _deliverableTargets(routed).length > 0;
  }

  // Refuse a target that has stopped accepting mail since the envelope
  // was resolved.
  //
  // The handoff resolves every recipient before it delivers any of them,
  // because that is what lets it refuse the whole message while refusing
  // is still free. What it holds afterwards is a description of the
  // moment the recipient was accepted, and the peer has been transmitting
  // ever since: an operator suspending a mailbox does it while mail is
  // arriving, which is the whole point of doing it, and a domain switched
  // off is the same shape. Delivering on the earlier answer puts the
  // message in a mailbox nobody is meant to be reading, which is the
  // failure the suspension was performed to prevent.
  //
  // So the question is asked AGAIN here, through the same predicate the
  // handoff asked it with, and the answer and the write it authorizes are
  // one run: `resolve`, `_sieveFolderFor` and `appendMessage` are all
  // synchronous, so nothing can interleave between them. Asking it any
  // earlier would leave the same window open, one suspension narrower.
  //
  // It is asked about the recipient the envelope named rather than about
  // the mailbox behind it, because that is the address the whole path
  // decides on and a second question would be a second answer.
  //
  // The refusal is raised rather than returned, and its code is the
  // store's own reason, so it reaches the caller's per-recipient handler
  // as any other undeliverable target does: the message goes to whoever
  // could still receive it and the sender is told about the one who could
  // not. Unwinding the message here would answer the sender a temporary
  // failure for a mailbox that will never take it, and the retry would
  // deliver a second copy to every other recipient.
  function _refuseIfTargetHasMoved(rcpt, target) {
    var routed = store.resolve(rcpt);
    var live = _deliverableTargets(routed || {});
    for (var i = 0; i < live.length; i += 1) {
      if (live[i].mailbox === target.mailbox && _mailboxIsReachable(routed)) return;
    }
    var reason = _movedReason(routed, target);
    var moved = new Error("the mailbox " + target.mailbox + " stopped accepting mail while " +
      "this message was being transmitted (" + reason + "), so it was not delivered there.");
    moved.code = reason;
    throw moved;
  }

  // Why a target that was reachable no longer is, in the store's own
  // vocabulary so the sentence the sender reads is the one the refusal
  // table already writes for it. The target's own reason is preferred
  // over the recipient's, because on an address with several
  // destinations the recipient may still be reachable through another
  // one and only this mailbox has stopped.
  function _movedReason(routed, target) {
    var targets = (routed && routed.targets) || [];
    for (var i = 0; i < targets.length; i += 1) {
      if (targets[i].mailbox !== target.mailbox) continue;
      if (targets[i].reason) return targets[i].reason;
    }
    return (routed && routed.reason) || "no-deliverable-target";
  }

  // What the sender is told. The store's reasons are internal words, and
  // a report quoting one verbatim tells a stranger nothing. Each maps to
  // a sentence and to the RFC 3463 status the sender's own server will
  // act on: a suspended mailbox is a temporary condition worth retrying,
  // an address that does not exist is permanent.
  //
  // A reason with no entry falls through to the `account-` family answer
  // below, which is temporary, and that is right for two of the three
  // states a mailbox is held in. It is wrong for the third, which is why
  // that one has entries of its own here: a table entry is read before
  // the fallback, so naming one member moves that member and leaves the
  // others exactly where they were.
  // One sentence per family for the ways a message is refused for what
  // it is rather than for who it was addressed to. The sender cannot act
  // on which counter was crossed and the reason code is what an operator
  // reads, so the sentence names the condition and stops there.
  var MESSAGE_STRUCTURE_TEXT =
    "This message declares more structure than this server reads.";
  var MESSAGE_FORMAT_TEXT =
    "This message is not in a form this server can read.";
  var MESSAGE_MEDIA_TEXT =
    "This message uses a content encoding or character set this server does not read.";
  var MESSAGE_TOO_BIG_TEXT =
    "This message is larger than this server stores.";

  var REFUSAL_TEXT = Object.freeze({
    "no-such-mailbox":       "No mailbox by that name at this server.",
    "unknown-domain":        "This server does not handle mail for that domain.",
    "invalid-address":       "That recipient address is not a valid mailbox address.",
    "domain-disabled":       "Mail for that domain is not being accepted at the moment.",
    "no-deliverable-target": "The address exists but every mailbox it points at is unavailable.",
    "alias-loop":            "The address forwards in a loop and never reaches a mailbox.",
    "mailbox/over-quota":    "That mailbox is full.",
    // The same sentence an address with no mailbox gets, because that is
    // what this address becomes. The mail this account held is already
    // destroyed and the row is kept only to answer for what a
    // preservation order or the retention floor held back, so the only
    // way out of the state is the row going, after which the sender is
    // told exactly this by the entry above. Telling them to try again
    // would be describing a mailbox that is coming back.
    "account-erasing":       "No mailbox by that name at this server.",
    // The message itself. Every reason below is decided by the bytes the
    // sender transmitted, so the same message meets the same answer on
    // every attempt and the sentence tells them to change the message
    // rather than to wait.
    "safe-mime/oversize-nesting":         MESSAGE_STRUCTURE_TEXT,
    "safe-mime/oversize-part-count":      MESSAGE_STRUCTURE_TEXT,
    "safe-mime/oversize-headers":         MESSAGE_STRUCTURE_TEXT,
    "safe-mime/too-many-headers":         MESSAGE_STRUCTURE_TEXT,
    "safe-mime/oversize-header-line":     MESSAGE_STRUCTURE_TEXT,
    "safe-mime/oversize-boundary":        MESSAGE_STRUCTURE_TEXT,
    "safe-mime/malformed-boundary":       MESSAGE_FORMAT_TEXT,
    "safe-mime/malformed-headers":        MESSAGE_FORMAT_TEXT,
    "safe-mime/control-char-in-header":   MESSAGE_FORMAT_TEXT,
    "safe-mime/rfc2047-header-injection": MESSAGE_FORMAT_TEXT,
    "safe-mime/unknown-transfer-encoding": MESSAGE_MEDIA_TEXT,
    "safe-mime/unknown-charset":          MESSAGE_MEDIA_TEXT,
    "safe-mime/oversize-message":         MESSAGE_TOO_BIG_TEXT,
    "safe-mime/oversize-body":            MESSAGE_TOO_BIG_TEXT,
    "mail-store/oversize-message":        MESSAGE_TOO_BIG_TEXT,
    "mail-store/oversize-body":           MESSAGE_TOO_BIG_TEXT,
    "mail-store/bad-message-id":          MESSAGE_FORMAT_TEXT,
    "mail-store/bad-in-reply-to":         MESSAGE_FORMAT_TEXT,
    "mail-store/bad-references":          MESSAGE_FORMAT_TEXT,
    "mailbox/empty-message":              MESSAGE_FORMAT_TEXT,
    // The outbound queue rather than the message or the address, so the
    // sender is told to keep it. Without an entry this reaches the
    // fallback below and a sender is told permanently that an address
    // they can reach does not exist.
    "delivery/spool-full":
      "This server could not take the message for delivery elsewhere at the moment.",
  });
  var REFUSAL_STATUS = Object.freeze({
    "no-such-mailbox":       "5.1.1",
    "unknown-domain":        "5.1.2",
    "invalid-address":       "5.1.3",
    "domain-disabled":       "4.2.1",
    "no-deliverable-target": "4.2.1",
    "alias-loop":            "5.4.6",
    // Temporary, because the mailbox owner can empty it. RFC 3463 gives
    // mailbox-full its own code, and answering it as one tells the
    // sender's server to keep trying at its end rather than returning
    // the message to the person who sent it.
    "mailbox/over-quota":    "4.2.2",
    // Permanent, and the one member of the `account-` family that is.
    // The other two states a mailbox is held in are lifted by the
    // operator, so the fallback below is right for them: the sender
    // keeps the message, retries, and delivers it when the hold comes
    // off. This state is not lifted. Reinstatement refuses it
    // categorically, the mail it held is already destroyed, and the row
    // leaves only when the erasure finishes, after which the address is
    // answered 5.1.1 anyway. A temporary answer here spends the whole of
    // the sending server's retry window against an address that can
    // never accept the message and then returns it to the person who
    // sent it days later, describing a condition that was never
    // transient. Answering permanently at RCPT costs one command instead
    // of a message body and tells them now.
    "account-erasing":       "5.1.1",
    // RFC 3463 section 3.7 defines X.6.0 as a content problem none of
    // the other detail codes expresses, which is what a message
    // declaring more structure than the parser walks is: the registry
    // has no subcode for a nesting depth or a part count. X.6.1 is media
    // the receiver does not support, which is what an unread transfer
    // encoding or character set is. X.3.4 is RFC 3463's size status and
    // the one the two SMTP listeners already answer a message over the
    // byte ceiling with.
    "safe-mime/oversize-nesting":         "5.6.0",
    "safe-mime/oversize-part-count":      "5.6.0",
    "safe-mime/oversize-headers":         "5.6.0",
    "safe-mime/too-many-headers":         "5.6.0",
    "safe-mime/oversize-header-line":     "5.6.0",
    "safe-mime/oversize-boundary":        "5.6.0",
    "safe-mime/malformed-boundary":       "5.6.0",
    "safe-mime/malformed-headers":        "5.6.0",
    "safe-mime/control-char-in-header":   "5.6.0",
    "safe-mime/rfc2047-header-injection": "5.6.0",
    "safe-mime/unknown-transfer-encoding": "5.6.1",
    "safe-mime/unknown-charset":          "5.6.1",
    "safe-mime/oversize-message":         "5.3.4",
    "safe-mime/oversize-body":            "5.3.4",
    "mail-store/oversize-message":        "5.3.4",
    "mail-store/oversize-body":           "5.3.4",
    "mail-store/bad-message-id":          "5.6.0",
    "mail-store/bad-in-reply-to":         "5.6.0",
    "mail-store/bad-references":          "5.6.0",
    "mailbox/empty-message":              "5.6.0",
    // RFC 3463 X.3.1, the mail system being full. Temporary: the sweep
    // that drains the queue clears it, and the sender keeps the message
    // until it does.
    "delivery/spool-full":   "4.3.1",
  });

  function _refusalText(reason) {
    if (REFUSAL_TEXT[reason]) return REFUSAL_TEXT[reason];
    if (String(reason).indexOf("account-") === 0) {
      return "That mailbox is not accepting mail at the moment.";
    }
    return "The message could not be delivered to that address.";
  }

  function _refusalStatus(reason) {
    if (REFUSAL_STATUS[reason]) return REFUSAL_STATUS[reason];
    if (String(reason).indexOf("account-") === 0) return "4.2.1";
    return "5.1.1";
  }

  // The reasons a peer is told to stop rather than to send the message
  // again, and the SMTP code that says so.
  //
  // SMTP answers a whole transaction once, and RFC 5321 section 4.2.1
  // reads the first digit of that answer: 4yz asks the peer for the same
  // message again, 5yz tells it to stop. The handoff below knows which
  // of the two a refusal is, because the reason it collected is the same
  // reason the report is composed from, and a reason named here carries
  // that knowledge onto the wire.
  //
  // A reason absent from this table is answered temporarily, and the
  // default falls that way deliberately. A temporary answer to a
  // permanent condition costs a peer its retry window; a permanent
  // answer to a temporary one destroys the message. An entry here is a
  // condition the same message cannot pass on a later attempt, and a
  // condition an operator or a mailbox owner can clear is not one.
  //
  // 550 is RFC 5321's permanent refusal for a recipient this server does
  // not take mail for. 554 is the transaction failure section 4.2.2
  // defines for a message refused after DATA was accepted, which is
  // where a refusal about the message itself is reached, and it is the
  // code the end-of-data smuggling refusal above already answers with.
  // 552 is that section's storage-allocation refusal, which is what the
  // two SMTP listeners already answer a message over the byte ceiling
  // with.
  var WIRE_PERMANENT_CODE = Object.freeze({
    "no-such-mailbox":                    "550",
    "unknown-domain":                     "550",
    "invalid-address":                    "550",
    "alias-loop":                         "550",
    "account-erasing":                    "550",
    "safe-mime/oversize-nesting":         "554",
    "safe-mime/oversize-part-count":      "554",
    "safe-mime/oversize-headers":         "554",
    "safe-mime/too-many-headers":         "554",
    "safe-mime/oversize-header-line":     "554",
    "safe-mime/oversize-boundary":        "554",
    "safe-mime/malformed-boundary":       "554",
    "safe-mime/malformed-headers":        "554",
    "safe-mime/control-char-in-header":   "554",
    "safe-mime/rfc2047-header-injection": "554",
    "safe-mime/unknown-transfer-encoding": "554",
    "safe-mime/unknown-charset":          "554",
    "safe-mime/oversize-message":         "552",
    "safe-mime/oversize-body":            "552",
    "mail-store/oversize-message":        "552",
    "mail-store/oversize-body":           "552",
    "mail-store/bad-message-id":          "554",
    "mail-store/bad-in-reply-to":         "554",
    "mail-store/bad-references":          "554",
    "mailbox/empty-message":              "554",
  });

  // The reply for a message no recipient could take, or null to leave
  // the listener its own temporary answer.
  //
  // Three things have to hold before a permanent code is written, and
  // each of them fails toward the temporary answer:
  //
  //   - Every refused recipient names the SAME reason. One reply covers
  //     the whole transaction, and a set of conditions that are not one
  //     condition has no single verdict to report. A message refused for
  //     one address and deferred for another is one the peer should
  //     bring back.
  //   - The reason is named in the table above. Anything else is a
  //     condition this file has not classified, and an unclassified
  //     condition is not evidence of a permanent one.
  //   - `REFUSAL_STATUS` holds an entry for it whose class matches the
  //     code's first digit. The status and the code are read by
  //     different peers off the same reply, and the framework silently
  //     replaces a status that contradicts its code, so a disagreement
  //     between the two tables would leave the reply carrying a detail
  //     nobody wrote. The fallback in `_refusalStatus` is not consulted:
  //     it answers `5.1.1` for a reason it does not know, which is the
  //     permanent verdict this whole path exists to stop being reached
  //     by default.
  function _wireRefusal(refused) {
    if (!Array.isArray(refused) || refused.length === 0) return null;
    var reason = refused[0].reason;
    for (var i = 1; i < refused.length; i += 1) {
      if (refused[i].reason !== reason) return null;
    }
    var code = WIRE_PERMANENT_CODE[reason];
    if (!code) return null;
    var status = REFUSAL_STATUS[reason];
    if (!status || status.charAt(0) !== code.charAt(0)) return null;
    return { code: code, status: status, text: _refusalText(reason) };
  }

  // Take the outbound queue room this message will need, or refuse it
  // before any of it has been committed anywhere.
  //
  // Both handoffs do this at the one point where refusing is free: the
  // recipients are resolved, so the number that will need the queue is
  // known, and nothing has reached a mailbox or the spool yet. Asking
  // later means an envelope that spooled some of its recipients and was
  // refused for the rest, and the sender's retry then delivers a second
  // copy to everybody whose entry was already waiting.
  //
  // The room is TAKEN rather than measured, and held until the handoff
  // is done with the message. Between this point and the last spool
  // write are every mailbox copy this server files, an MX lookup and a
  // conversation with each receiver, and the queue is one directory
  // shared with every other connection and with the retry sweep. A
  // reading would be spent by somebody else inside that window: two
  // senders crossing the last slot together would both be admitted here,
  // both file their local copies, and the one refused at its own spool
  // write would be told to send the whole message again. Every mailbox
  // that already had it would then have it twice.
  //
  // It throws when there is no room, and the throw is how the answer
  // reaches the wire: both listeners turn a handoff that raises into a
  // temporary refusal, which leaves the message with whoever still has
  // it. An account holder sees it stay in their outbox; a peer retries on
  // its own schedule and reports to its own sender if it eventually gives
  // up. Either way the party who can still act on the message is the
  // party holding it.
  //
  // The wire text is the listener's, and it is coarser than the
  // condition deserves. What an operator needs is the depth, the ceiling
  // and which share was exhausted, so that goes to the audit trail and
  // the log where a person can read it rather than into a reply nobody
  // keeps.
  function _reserveRoomToForward(routes, body, origin) {
    var leaving = 0;
    for (var i = 0; i < routes.length; i += 1) {
      var targets = routes[i].targets;
      for (var t = 0; t < targets.length; t += 1) {
        if (targets[t].local !== true) leaving += 1;
      }
    }
    return _reserveQueueRoom(leaving, body, origin);
  }

  // The same reservation taken with a count the caller already has.
  //
  // The arithmetic belongs to the module that owns the spool and is not
  // restated here. Two copies of a ceiling are two ceilings, and the
  // moment they disagree the listener admits a message the spool then
  // refuses, which is the partial write this exists to prevent.
  //
  // Null when nothing on this message leaves the server. Two accounts
  // here writing to each other need no outbound queue at all, and a full
  // queue must not stop them: mail between mailboxes on this server
  // should no more depend on the queue than it depends on this server's
  // own MX record resolving.
  function _reserveQueueRoom(leaving, body, origin) {
    if (leaving <= 0) return null;
    var size = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(String(body || ""), "utf8");
    var held = delivery.queue.reserve({
      entries: leaving,
      bytes:   leaving * size,
      origin:  origin,
    });
    if (held.taken === true) return held;
    log.error("a message for " + leaving + " recipient(s) elsewhere was refused: " +
      held.refusal.message + " The sender was told to try again, so the message is not lost.");
    throw held.refusal;
  }

  // The MX listener's delivery handoff. It runs after the listener has
  // already refused everything it can refuse on the wire, so what
  // arrives here is a message for a domain this server hosts, addressed
  // to mailboxes that resolved at RCPT.
  //
  // What still reaches here is a recipient whose condition changed
  // between the two moments, or one that was never permanent to begin
  // with: a mailbox that filled while the peer was transmitting, an
  // account suspended mid-message, a domain switched off. `550` is the
  // wrong answer to all of those, because the owner can clear them, so
  // they are met here rather than on the wire.
  //
  // When NOTHING could be delivered, this throws, and the reply the
  // listener writes is decided by `WIRE_PERMANENT_CODE` from the reason
  // every refused recipient carries. A condition somebody can clear is
  // answered `451 4.3.0`, which is the answer those cases want and the
  // answer every unrecognized reason gets:
  //
  //   - Answering 250 and composing a report accepts responsibility for
  //     a message that reached nobody, and then addresses the report to
  //     the envelope sender. On a run of mail to addresses that do not
  //     exist here, that sender is whoever forged the envelope, so the
  //     report is backscatter this server emits at a third party in a
  //     volume the party running the sequence chooses. The report path
  //     bounds that per sender for the reports it does owe; owing more
  //     of them for messages nobody could receive is the wrong side of
  //     that bound to be adding to.
  //   - Answering 451 hands the problem back to a peer that still has
  //     the message. It retries against a condition that may clear,
  //     gives up on its own schedule, and generates a report from its
  //     side, where the reverse path is one that peer accepted from its
  //     own sender rather than one this server was handed.
  //
  // The empty reverse path RFC 5321 section 4.5.5 requires of a report
  // is not what decides this. `delivery` names that path once and every
  // report it composes travels with it, so the choice above is about
  // who should be holding the message, not about what this server can
  // put in a MAIL FROM.
  //
  // A condition nobody can clear is answered permanently instead, and
  // that is the same argument rather than an exception to it. Handing a
  // message back to a peer that still holds it is only worth anything
  // while another attempt could land: a message whose structure this
  // parser will not walk, or addressed to a name this server does not
  // hold, meets the identical refusal on every attempt, so a temporary
  // answer spends the peer's whole retry window and then reports days
  // late about a condition that was never transient. The peer is told
  // now, and it composes the report from its own side exactly as it
  // would have later.
  //
  // Only the all-refused case throws. A message that reached one
  // mailbox and missed another is already stored, so a retry would
  // deliver the stored copy twice, and duplicating delivered mail to
  // improve a report is a worse trade than the report being late.
  function _mxAgent() {
    return {
      handoff: async function (inbound) {
        // What the listener hands over is the whole mail data, the CRLF
        // that ends its last line included: RFC 5321 §4.1.1.4 makes the
        // first CRLF of `<CRLF>.<CRLF>` the terminator of that line, and
        // the framework's `DATA` reader ends the body after it.
        _refuseIfReadAsTwoMessages("inbound", inbound, inbound.body);
        var delivered = [];
        var refused = [];

        // Every recipient is resolved before any of them is delivered,
        // so the question below can be asked while nothing has been
        // committed yet. Resolving and delivering in one pass would mean
        // the first recipient is already in a mailbox by the time the
        // outbound queue turns out to have no room for the second, and a
        // peer that retries after a temporary refusal delivers that
        // first copy again.
        var routes = [];
        for (var i = 0; i < inbound.rcpts.length; i += 1) {
          var rcpt = inbound.rcpts[i];
          var routed = await store.resolve(rcpt);
          if (!_mailboxIsReachable(routed)) {
            refused.push({ rcpt: rcpt, reason: (routed && routed.reason) || "no-such-mailbox" });
            continue;
          }
          routes.push({ rcpt: rcpt, targets: _deliverableTargets(routed) });
        }

        // Anything on this message that leaves the server again needs
        // room in the outbound queue, and there is one moment at which
        // finding there is none costs nothing. The room is taken here and
        // held to the end of the handoff, so a queue that fills while
        // this message is being delivered cannot refuse it after a
        // mailbox already has it. `451` hands the message back to a peer
        // that still holds it and retries on its own schedule, which is
        // the sender keeping their own mail.
        var hold = _reserveRoomToForward(routes, inbound.body, "inbound");
        try {
          for (var k = 0; k < routes.length; k += 1) {
            var routeTargets = routes[k].targets;
            for (var t = 0; t < routeTargets.length; t += 1) {
              try {
                delivered.push(await _deliverToTarget(routeTargets[t], inbound, "inbound",
                  routes[k].rcpt, hold));
              } catch (err) {
                // A recipient that could not be delivered is a refusal,
                // not a reason to unwind the whole handoff. SMTP gives
                // DATA one reply covering every recipient on the message,
                // so letting this throw after an earlier recipient was
                // already stored answers the peer a temporary failure,
                // and the retry that follows delivers the stored copy a
                // second time. That holds for every cause, the queue
                // included: the room this message needs was taken above
                // and is held, so a queue that filled meanwhile is
                // somebody else being refused rather than this message,
                // and a fault that reaches here anyway must not turn one
                // delivered copy into two. The all-refused rule below
                // still throws when nothing landed, which is the one case
                // where a retry costs nothing.
                refused.push({
                  rcpt:   routeTargets[t].mailbox || routes[k].rcpt,
                  reason: (err && err.code) || "no-deliverable-target",
                });
              }
            }
          }
          if (delivered.length === 0 && refused.length > 0) {
            b.audit.safeEmit({
              action:   "blamepost.mail.inbound.refused",
              outcome:  "failure",
              // The peer and nobody. A message from the internet was
              // sent by somebody this server has never met, so the
              // address it arrived from is the whole of what the row can
              // stand behind, and it is what an operator asks about when
              // one source is refused all day.
              actor:    _wireActor(null, _peerOn(inbound), inbound.connectionId),
              metadata: {
                mailFrom:   inbound.mailFrom,
                recipients: _reportedRecipients(refused),
                recipientCount: refused.length,
                reason:     refused[0].reason,
              },
            });
            var undeliverableHere = new Error(
              "no recipient on this message resolves to a mailbox here: " +
              _reportedRecipients(refused));
            // The listener reads these three off the rejection and
            // writes the reply from them. Without them it answers 451,
            // which asks the peer for a message this server has already
            // decided it will never take, so the peer sends it again on
            // its own schedule until its queue lifetime runs out and the
            // reason computed here reaches nobody. `_wireRefusal`
            // answers null for every condition that can clear, and the
            // properties are then left unset so the listener keeps that
            // temporary answer.
            var wire = _wireRefusal(refused);
            if (wire !== null) {
              undeliverableHere.smtpCode       = wire.code;
              undeliverableHere.enhancedStatus = wire.status;
              undeliverableHere.replyText      = wire.text;
            }
            throw undeliverableHere;
          }
          // Read once for the whole message rather than once per refused
          // recipient. It is the same answer every time, and finding it
          // costs a scan of the message when the peer sent no header
          // separator at all, which is a scan the peer would otherwise be
          // buying one of per address it named.
          var reportedHeaders = refused.length > 0 ? reportedHeaderBlock(inbound.body) : "";
          for (var r = 0; r < refused.length; r += 1) {
            await delivery.bounce({
              to:              inbound.mailFrom,
              recipient:       refused[r].rcpt,
              reason:          _refusalText(refused[r].reason),
              statusCode:      _refusalStatus(refused[r].reason),
              originalHeaders: reportedHeaders,
            });
          }
          return {
            messageId: delivered.length > 0 && delivered[0].objectid ? delivered[0].objectid : null,
            delivered: delivered.length,
            refused:   refused.length,
          };
        } finally {
          if (hold !== null) hold.release();
        }
      },
    };
  }

  /**
   * @primitive blamepost.mail.listeners.relay
   * @signature listeners.relay.send(envelope)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 5321 §3.3, RFC 5228 §2.10.2 (Sieve), RFC 3464 (DSN)
   * @related   blamepost.mail.delivery.send, blamepost.store.resolve
   *
   * The delivery handle with this server's own recipients routed to
   * mailboxes here. It carries every verb
   * `blamepost.mail.delivery.create` builds and replaces one of them:
   * `send` resolves each recipient first, files the ones this server
   * hosts, and hands only the rest to the outbound chain.
   *
   * Mail between two accounts on this server does not depend on that
   * server's own MX record resolving, on the host being able to reach
   * itself, or on its own MTA-STS and DANE policy applied against
   * itself. It does not depend on the outbound queue either: only the
   * recipients that leave are counted against it, and "leave" is a
   * property of the TARGET rather than of the address the sender wrote,
   * because an alias on a hosted domain that forwards elsewhere resolves
   * as local and still needs an entry.
   *
   * Every surface an account holder sends from composes this handle:
   * the submission listener, the browser compose form and JMAP
   * `EmailSubmission/set`. A surface given the raw outbound handle
   * instead sends a message addressed to a mailbox on this disk out to
   * DNS and waits for it to arrive back on port 25, and the two surfaces
   * then disagree about where one address goes.
   *
   * A local recipient gets the same delivery the MX listener gives one:
   * the reachability question asked again at the instant of the write,
   * the recipient's own Sieve script, the quota and the retention floor
   * the message store holds. The message is the one the caller handed
   * over, signature included, so the copy in the mailbox is the copy
   * that would have gone on the wire.
   *
   * The outcome is the outbound chain's, with the local deliveries
   * folded into `delivered` and the local refusals into `failed`, so one
   * caller reads one verdict for a message that went both ways. The
   * counts travel beside the lists for a caller that needs them apart,
   * and `outbound` is what the outbound chain answered, null when
   * nothing on the message left. A recipient here that refuses is
   * reported to the sender rather than sent onward, because handing a
   * message addressed to this server to somebody else is worse than
   * telling the sender it did not arrive.
   *
   * `rfc822` is a Buffer, a Uint8Array, or the text of one, and an
   * envelope carrying anything else is refused before a recipient is
   * resolved. This server sends what it is given, so a caller that
   * omitted the message or handed over a value that is not bytes has
   * nothing to send: the message that would leave is that value's own
   * text, or nothing at all, and it leaves signed under a hosted
   * domain's key and arrives as mail this server vouched for. The three
   * surfaces that compose this handle each build the bytes their own
   * way, which makes this argument the seam between them and the last
   * place a message can be refused for nothing.
   *
   * There is no byte ceiling here. The two SMTP listeners hold
   * `config.limits.maxMessageBytes` at the point of parse and answer a
   * message over it `552 5.3.4`, which is the protocol's own code for
   * it, and the outbound queue holds its own ceiling on what may be
   * spooled. A third ceiling on this argument would be a third answer to
   * one question, and the first setting where two of them disagree is
   * the one where a surface accepts a message the queue then refuses.
   *
   * @opts
   *   from:       string,    // the reverse path
   *   to:         array,     // the recipients, hosted here or not
   *   rfc822:     Buffer,    // the finished message, already signed; Uint8Array or text also read
   *   origin:     string,    // which share of the outbound queue; default "submission"
   *   requireTls: boolean,   // carried to the outbound chain unchanged
   *
   * @example
   *   // example.com is hosted here and holds a mailbox for bob. example.net is not hosted.
   *   var listeners = blamepost.mail.listeners.create(listenerOpts);
   *   var outcome = await listeners.relay.send({
   *     from:   "alice@example.com",
   *     to:     ["bob@example.com", "carol@example.net"],
   *     rfc822: signedMessage,
   *   });
   *   outcome.localCount;
   *   // 1
   *   outcome.remoteCount;
   *   // 1
   */
  async function _relaySend(envelope) {
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
      throw new TypeError("blamepost.mail.listeners.relay.send: envelope object is required");
    }
    var body = b.safeBuffer.toBuffer(envelope.rfc822, {
      errorFactory: function (_code, message) {
        return new TypeError("blamepost.mail.listeners.relay.send: rfc822 is the finished " +
          "message and " + message + ". A caller with no message has none to send, and " +
          "what would leave is the text of the value it handed over, signed under a " +
          "hosted domain's key.");
      },
    });
    var mailFrom = envelope.from === undefined || envelope.from === null ? "" : envelope.from;
    // An authenticated account's own mail unless the caller says
    // otherwise. Which share of the outbound queue a message may take is
    // decided by where it came from, and every surface that composes
    // this handle is one an account signed in to.
    var origin = envelope.origin === undefined ? "submission" : envelope.origin;
    var rcpts = Array.isArray(envelope.to)
      ? envelope.to
      : (envelope.to === undefined || envelope.to === null ? [] : [envelope.to]);

    // Each hosted recipient is kept beside the address it was resolved
    // from rather than flattened into a list of targets. The recipient is
    // what the reachability question is asked about again at the write,
    // and it is what the sender is told about if the answer has changed
    // by then.
    var localRoutes = [];
    var remote = [];
    var undeliverable = [];
    for (var i = 0; i < rcpts.length; i += 1) {
      var rcpt = rcpts[i];
      var routed = await store.resolve(rcpt);
      if (!routed || routed.local !== true) {
        // Somewhere else entirely, which is the ordinary case.
        remote.push(rcpt);
        continue;
      }
      if (routed.deliverable !== true) {
        // Local and refusing. Sending it out to the internet would hand a
        // message addressed to this server to somebody else.
        undeliverable.push({ rcpt: rcpt, reason: routed.reason || "no-such-mailbox" });
        continue;
      }
      var hosted = _deliverableTargets(routed);
      for (var h = 0; h < hosted.length; h += 1) {
        localRoutes.push({ rcpt: rcpt, target: hosted[h] });
      }
    }

    // Between resolving the recipients and delivering to any of them,
    // which is the last moment refusing this message costs nothing.
    // Everything below either files a copy in a mailbox on this server or
    // writes one to the outbound queue, and a client that retries after a
    // temporary refusal repeats whichever of those already happened. The
    // room is held from here to the end of the call, so a queue that
    // fills while this message is being delivered refuses the next
    // message rather than this one.
    //
    // Only the recipients that leave the server are counted, and "leave"
    // is a property of the TARGET rather than of the address the sender
    // wrote. An alias on a hosted domain that forwards elsewhere resolves
    // as local and still needs an outbound entry, so counting the
    // addresses this server does not host would reserve less room than
    // the message goes on to write and the reservation would stop meaning
    // anything. Two accounts on this server writing to each other need no
    // outbound queue at all, and a full queue must not stop them.
    var leaving = remote.length;
    for (var q = 0; q < localRoutes.length; q += 1) {
      if (localRoutes[q].target.local !== true) leaving += 1;
    }
    var hold = _reserveQueueRoom(leaving, body, origin);
    try {
      var delivered = [];
      for (var t = 0; t < localRoutes.length; t += 1) {
        try {
          var landed = await _deliverToTarget(localRoutes[t].target, {
            mailFrom: mailFrom,
            body:     body,
          }, origin, localRoutes[t].rcpt, hold);
          delivered.push({
            recipient: localRoutes[t].rcpt,
            local:     landed.kind !== "forward",
            mailbox:   landed.mailbox || landed.address || null,
            folder:    landed.folder === undefined ? null : landed.folder,
          });
        } catch (err) {
          // One recipient failing is not a reason to unwind a message
          // other recipients already have. Submission gets one reply for
          // the whole message, so raising here would tell the client to
          // send it again and every mailbox that already had it would
          // have it twice. The account holder is told about the address
          // that failed instead, which is the same answer they get for
          // one that was already refusing when the message arrived.
          undeliverable.push({
            rcpt:   localRoutes[t].rcpt,
            reason: (err && err.code) || "no-deliverable-target",
          });
        }
      }
      var outbound = null;
      if (remote.length > 0) {
        outbound = await delivery.send({
          from:       mailFrom,
          to:         remote,
          rfc822:     body,
          origin:     origin,
          hold:       hold || undefined,
          requireTls: envelope.requireTls,
        });
      }
      // Read once, for the reason the inbound handoff reads it once.
      var reportedHeaders = undeliverable.length > 0 ? reportedHeaderBlock(body) : "";
      var failed = [];
      for (var u = 0; u < undeliverable.length; u += 1) {
        var text   = _refusalText(undeliverable[u].reason);
        var status = _refusalStatus(undeliverable[u].reason);
        await delivery.bounce({
          to:              mailFrom,
          recipient:       undeliverable[u].rcpt,
          reason:          text,
          statusCode:      status,
          originalHeaders: reportedHeaders,
        });
        failed.push({
          recipient:  undeliverable[u].rcpt,
          local:      true,
          reason:     text,
          reasonCode: status,
        });
      }
      return {
        delivered: delivered.concat((outbound && outbound.delivered) || []),
        deferred:  ((outbound && outbound.deferred) || []).slice(),
        failed:    failed.concat((outbound && outbound.failed) || []),
        // What was actually filed, not what was resolved. A caller
        // reading this to say a message was delivered would be reading
        // the routing decision rather than the outcome.
        localCount:   delivered.length,
        remoteCount:  remote.length,
        refusedCount: undeliverable.length,
        outbound:     outbound,
      };
    } finally {
      if (hold !== null) hold.release();
    }
  }

  // The handle above, built by delegation rather than by copying, so a
  // caller that starts reading another verb off it finds the one the
  // outbound module built. Only `send` is this file's.
  var relayHandle = Object.create(delivery);
  relayHandle.send = _relaySend;

  // The account an actor names, in the shape the author binding measures
  // against.
  //
  // An actor is assembled by the surface that presents it, and the
  // surfaces need different things from one. The submission listener
  // builds one from the credential it has just verified, so it carries
  // the address that credential belongs to. The browser and JMAP build
  // one for the message store, where an account is a set of folders and
  // its address is no part of the question, so theirs carries an id and
  // no address at all. Reading the address off whichever shape arrived
  // would measure a browser's message against an empty set of permitted
  // authors and refuse the account's own mail.
  //
  // The account id is the field every surface carries, so the address is
  // read from the store under it when the actor has none. The two answer
  // the same, because both are that one account row.
  function _sendingIdentity(actor) {
    // A sending credential is carried through whole. It holds no address
    // and never will, so the store read below would look up an account
    // under a credential identifier, find nothing, and hand the binding
    // an identity with an empty scope: refused everywhere, including the
    // domain the credential exists to write.
    var scope = _sendingCredentialOf(actor);
    if (scope !== null) return { id: scope.id, address: "", sendingCredential: scope };
    var id = (actor && actor.id) || null;
    var written = (actor && actor.address) || "";
    if (written.length > 0 || id === null) return { id: id, address: written };
    try {
      var account = store.accounts.get(id);
      return { id: id, address: (account && account.address) || "" };
    } catch (_e) {
      // The set stays empty and the message is refused. A lookup that
      // failed must not widen what anybody may write, which is the same
      // answer `permittedAuthors` gives when it cannot read the aliases.
      return { id: id, address: "" };
    }
  }

  /**
   * @primitive blamepost.mail.listeners.authorBinding
   * @signature listeners.authorBinding(actor, rfc822, carrier?)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5322 §3.6, RFC 5321 §4.2.1, RFC 3463 (enhanced status)
   * @related   blamepost.mail.listeners.permittedAuthors, blamepost.mail.compose.send
   *
   * This is the author binding as one call. It reads the `From` and
   * `Sender` headers out of a finished message and measures them
   * against the addresses
   * `blamepost.mail.listeners.permittedAuthors` answers for the account
   * that signed in. It returns nothing on success and throws on a
   * refusal.
   *
   * The refusal carries `550` and an RFC 3463 enhanced status naming
   * its class: `5.6.0` when the header block names no single readable
   * author, and `5.7.1` when it names an address at a domain this
   * server signs for that the account does not hold. It also carries
   * the audit row, so the trail an operator queries holds every
   * surface's refusals rather than only the ones that arrived over
   * SMTP.
   *
   * An author at a domain this server does not host is accepted when
   * `Sender` names an address the account holds, because this server's
   * key creates no alignment for a domain it does not sign for and that
   * domain's own policy answers for it.
   *
   * `actor` is whatever the calling surface carries. Only the account id
   * on it has to be there: an actor built for the message store, which
   * names folders rather than an address, is read against the store to
   * find the address it belongs to.
   *
   * The submission listener applies this to every message it accepts.
   * `blamepost.mail.compose.send` composes it so the browser compose
   * form, JMAP `EmailSubmission/set` and anything else built on the
   * composer are measured against the same set by the same code, rather
   * than each proving it separately.
   *
   * `carrier` is the handoff the message arrived on, when the caller has
   * one. A refusal written from it names the peer and the connection
   * beside the account, which is what an operator reads a wire row for. A
   * caller with no wire peer passes none.
   *
   * @example
   *   await listeners.authorBinding(session.actor, built.rfc822, handoff);
   */
  async function authorBinding(actor, rfc822, carrier) {
    await _refuseUnownedAuthor(store, {
      actor:         _sendingIdentity(actor),
      body:          rfc822,
      // Carried so a refusal names where the session came from as well as
      // who authenticated. A caller with no wire peer, which is every
      // caller reaching this through the composer, passes none and the
      // row names the account alone.
      remoteAddress: _peerOn(carrier),
      connectionId:  (carrier && carrier.connectionId) || null,
    });
  }

  // The submission listener's relay handoff. Signing happens here
  // because the listener hands over the finished message, which is the
  // only moment the header set is complete and still unsent.
  //
  // Where each recipient goes is the relay's question rather than this
  // function's. The browser compose form and JMAP `EmailSubmission/set`
  // ask the same handle, so the three surfaces an account holder sends
  // from cannot answer it differently.
  // The two ceilings a sending credential carries, counted against the
  // message about to go out and refused when either is crossed.
  //
  // Counted here rather than at the envelope because a recipient count
  // is what one of the two measures, and RCPT is still arriving while
  // the envelope is being built. This is the first moment the whole
  // message exists and the last before anything is signed or relayed.
  //
  // Two counts rather than one, and the registry keeps both: a hundred
  // messages carrying one recipient each and one message carrying a
  // hundred thousand are different events, and a leaked credential
  // produces the second, which a single counter cannot see.
  //
  // The refusal is TEMPORARY. The window is rolling, so the volume that
  // crossed the ceiling falls out of it and the same message succeeds
  // later; telling the sender to stop would turn a rate ceiling into a
  // permanent bounce for mail an operator wants delivered. RFC 5321
  // section 4.2.1 makes 4yz the class a sender retries, and 4.5.3.1 puts
  // a resource ceiling at 452.
  //
  // A registry that cannot read the credential RAISES rather than
  // answering, and the raise is left to travel: a ceiling this server
  // cannot measure has not been shown to be clear, and relaying on that
  // is the one reading that turns a broken row into no ceiling at all.
  // Whether the credential this session authenticated under is still one
  // this server sends for, asked once per message.
  //
  // The scope is frozen onto the actor at AUTH and nothing on the
  // connection can widen it, which answers what the credential MAY write.
  // It does not answer whether the credential still exists, and those come
  // apart on a session that stays open: an expiry the operator recorded is
  // reached by the clock with nothing written, and the admin console
  // withdraws a hosted domain through the running server's own handle. A
  // session that authenticated a minute before either would go on sending
  // until the client closed it.
  //
  // Asked of the store rather than computed from a deadline carried on the
  // actor. A frozen deadline answers the clock and nothing else, so it
  // would hold today and quietly stop holding the day any credential state
  // becomes writable while the server runs.
  //
  // Before the ceiling, so a message from a credential that has stopped
  // does not spend a window it is no longer entitled to, and before the
  // signer and the relay, so nothing has been signed or handed anywhere.
  //
  // A registry that cannot answer RAISES rather than returning, and the
  // raise is left to travel. A credential this server cannot read has not
  // been shown to be standing, and relaying on that reading is what turns
  // a broken row into a credential nothing stops.
  async function _refuseIfCredentialStopped(actor) {
    var scope = _sendingCredentialOf(actor);
    if (scope === null || sendingCredentials === null) return;
    var standing = await sendingCredentials.stillSending(scope.id);
    if (standing && standing.ok === true) return;
    var reason = (standing && standing.reason) || "not-found";
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_stopped",
      outcome:  "denied",
      actor:    _wireActor(actor),
      metadata: {
        credentialId: scope.id,
        scopeDomain:  scope.domain,
        // Which of the reasons it was. An operator reading this row is
        // asking why an application that was sending an hour ago is not,
        // and the answer separates a withdrawn domain from an expiry.
        reason:       reason,
      },
    });
    var err = new Error("this message was not relayed because the sending credential for " +
      scope.domain + " is no longer one this server sends for (" + reason + "). The scope " +
      "was settled when this connection authenticated and the credential has stopped " +
      "standing since. Issue a credential and sign in again.");
    err.code           = SENDING_CREDENTIAL_STOPPED;
    err.smtpCode       = "550";
    err.enhancedStatus = "5.7.1";
    err.replyText      = "Message refused: the sending credential this session " +
      "authenticated with is no longer valid";
    throw err;
  }

  async function _spendSendingCredentialCeiling(actor, outbound) {
    var scope = _sendingCredentialOf(actor);
    if (scope === null || sendingCredentials === null) return;
    var reading;
    try {
      reading = await sendingCredentials.counters.record({
        id:         scope.id,
        recipients: ((outbound && outbound.rcpts) || []).length,
      });
    } catch (readErr) {
      // A ceiling this server cannot measure has not been shown to be
      // clear, so the raise travels rather than being read as a window
      // with room in it. The credential verified a moment ago, so what
      // reaches here is a row that stopped being readable in between,
      // which is the operator's to repair.
      //
      // The message is carried across screened, and the same screened
      // text reaches the row and the error, because it is what a peer is
      // told and what the trail records and those two disagreeing is a
      // trail that does not answer for the session it is about. What is
      // added is a code, so a caller that has to turn this into an
      // answer of its own can tell an unreadable ceiling from a crossed
      // one instead of reporting both as the same fault.
      var whyUnreadable = displayText.forDisplay(
        (readErr && readErr.message) || String(readErr));
      b.audit.safeEmit({
        action:   "blamepost.mail.listeners.sending_credential_ceiling_unreadable",
        outcome:  "failure",
        actor:    _wireActor(actor),
        metadata: {
          credentialId: scope.id,
          scopeDomain:  scope.domain,
          reason:       whyUnreadable,
        },
      });
      var unreadable = new Error(whyUnreadable);
      unreadable.code  = SENDING_CREDENTIAL_CEILING_UNREADABLE;
      unreadable.cause = readErr;
      throw unreadable;
    }
    if (!reading || reading.exceeded !== true) return;
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_ceiling_reached",
      outcome:  "denied",
      actor:    _wireActor(actor),
      metadata: {
        credentialId:       scope.id,
        scopeDomain:        scope.domain,
        messages:           reading.messages,
        recipients:         reading.recipients,
        maxMessages:        reading.maxMessages,
        maxRecipients:      reading.maxRecipients,
        windowMs:           reading.windowMs,
        // Which of the two was crossed, because they are set for
        // different reasons and an operator raising the wrong one
        // changes nothing.
        messagesExceeded:   reading.messagesExceeded === true,
        recipientsExceeded: reading.recipientsExceeded === true,
      },
    });
    var err = new Error("this message was not relayed because the sending credential for " +
      scope.domain + " has reached its " +
      (reading.recipientsExceeded === true ? "recipient" : "message") +
      " ceiling for the current window. It sent " + reading.messages + " message(s) to " +
      reading.recipients + " recipient(s) against ceilings of " + reading.maxMessages +
      " and " + reading.maxRecipients + ". The window is rolling, so the send succeeds " +
      "once the volume ahead of it falls out; an operator can raise the ceiling or give " +
      "the window back.");
    err.code           = SENDING_CREDENTIAL_CEILING;
    err.smtpCode       = "452";
    err.enhancedStatus = "4.5.3";
    err.replyText      = "Message deferred: sending credential has reached its ceiling " +
      "for the current window";
    // The reading itself, so a caller answering in another protocol
    // builds its own refusal out of the numbers this one already took
    // rather than taking a second reading. A second reading would count
    // the message twice, and the two answers would name different
    // volumes for one message.
    err.reading        = reading;
    throw err;
  }

  /**
   * @primitive blamepost.mail.listeners.sendingCredentialGate
   * @signature listeners.sendingCredentialGate(actor, envelope)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5321 §4.2.1 (4yz is retried), RFC 3463 (enhanced status)
   * @related   blamepost.mail.listeners.authorBinding, blamepost.mail.compose.send
   *
   * Everything the submission listener asks of a sending credential
   * between the author binding and the signer, as one call. It returns
   * nothing when the message may go and throws when it may not, and it
   * is a no-op for an account: an actor carrying no credential scope
   * has neither a standing to re-read nor a window to spend.
   *
   * Two questions, in the order the wire asks them. Whether the
   * credential is still one this server sends for, which a session that
   * stays open cannot answer from the scope it authenticated under,
   * because an expiry is reached by the clock and a domain is withdrawn
   * through the admin console with nothing written to the connection.
   * Then the two send ceilings, counted against this message: a hundred
   * messages carrying one recipient each and one message carrying a
   * hundred thousand are different events, and a leaked credential
   * produces the second.
   *
   * A crossed ceiling throws `452 4.5.3` and carries the reading it
   * took, so a caller answering in another protocol builds its own
   * refusal out of those numbers rather than counting the message a
   * second time. The refusal is temporary: the window is rolling, so
   * the same message succeeds once the volume ahead of it falls out.
   *
   * The ceiling is spent AFTER the binding, which is the ordering rather
   * than an implementation detail. A message the credential was never
   * entitled to write must not spend the window it was refused under,
   * and a surface that counted first would let a caller burn a ceiling
   * down with messages the server never sends.
   *
   * `blamepost.mail.compose.send` runs this on the same message it runs
   * the author binding on, so the browser port's sending route and the
   * submission listener spend ONE window in one order rather than
   * keeping one each.
   *
   * @example
   *   await listeners.sendingCredentialGate(session.actor, { rcpts: recipients });
   */
  async function sendingCredentialGate(actor, envelope) {
    await _refuseIfCredentialStopped(actor);
    await _spendSendingCredentialCeiling(actor, envelope);
  }

  // ---- an account that left service while its session was open -------------
  //
  // The check above covers a sending credential, and an account has the
  // same window with none of the same cover. A password is verified once,
  // at AUTH, and the actor built from that verdict is the session's
  // identity for as long as the socket is up. An IMAP client holds one
  // connection open for hours under IDLE, a submission session stays open
  // for as long as its client has mail, and a POP3 session holds its
  // maildrop for the length of a download, so the verdict that admitted
  // any of them is minutes or hours old by the time a command arrives.
  //
  // The operator's side of that window is an incident. They suspend a
  // mailbox whose password they believe somebody else is holding, or they
  // withdraw the domain it belongs to, and neither writes anything to a
  // connection. Without a re-read the browser tab stops at its next
  // request and the IMAP connection goes on serving mail.
  //
  // So every command a signed-in session sends re-reads the same two rows
  // `blamepost.web` reads on every request: the account, and the domain
  // it belongs to. The two surfaces then serve or refuse one account
  // identically whichever way it signed in.
  //
  // The two reads together cost about 0.14 ms against a sealed store
  // holding two hundred accounts, and a session under IDLE sends no
  // commands while it idles, so the cost falls on each command a client
  // actually issues. Nothing is cached: a cache would be a third answer
  // to whether an account is in service, carrying a staleness window of
  // its own, which is this defect in a smaller size.

  // Whether the account an actor names is still one this server serves.
  //
  // Returns null when there is nothing to ask. A sending credential holds
  // no account row, and `_refuseIfCredentialStopped` is the check that
  // belongs to it; an actor carrying no id names nobody to read.
  //
  // The reason and the sentence are DERIVED from the status the row
  // carries rather than chosen from a list of the states this file knows
  // about. A status the store grows later then arrives here named,
  // refused and written down, instead of falling through a table into the
  // branch that serves the mail.
  function _accountStanding(actor) {
    if (!actor || _sendingCredentialOf(actor) !== null) return null;
    var id = actor.id;
    if (typeof id !== "string" || id.length === 0) return null;
    var account = store.accounts.get(id);
    if (!account) {
      return {
        ok:       false,
        reason:   "account-missing",
        address:  (actor.address && String(actor.address)) || "",
        domain:   (actor.domain && String(actor.domain)) || "",
        sentence: "the account no longer exists",
      };
    }
    // The state, taken once. `blamepost.store.accounts.get` answers it
    // through the one derivation that reads BOTH of the columns an
    // account row records its state in, so a row whose erasure wrote its
    // marker and could not write the status column reads as erasing here
    // rather than as a mailbox in service. Taken into a local rather than
    // read at each of the three places below, so the comparison, the
    // reason and the sentence cannot end up naming different states.
    var state = account.status;
    if (state !== "active") {
      return {
        ok:       false,
        reason:   "account-" + state,
        address:  account.address,
        domain:   account.domain,
        sentence: "the account is " + state,
      };
    }
    var hosted = store.domains.get(account.domain);
    if (!hosted) {
      return {
        ok:       false,
        reason:   "domain-not-hosted",
        address:  account.address,
        domain:   account.domain,
        sentence: "this server no longer hosts " + account.domain,
      };
    }
    if (hosted.status !== "active") {
      return {
        ok:       false,
        reason:   "domain-" + hosted.status,
        address:  account.address,
        domain:   account.domain,
        sentence: "the domain " + account.domain + " is " + hosted.status,
      };
    }
    return { ok: true };
  }

  // The refusal, said once and thrown, for every listener to answer in
  // its own protocol.
  //
  // It is synchronous because both reads are. A listener calls it from
  // inside the promise chain it already wraps every store call in, so the
  // throw arrives as the rejection that chain's catch turns into `NO`,
  // `-ERR` or a 5yz reply.
  //
  // A store that cannot answer is refused rather than served. An account
  // this server cannot read has not been shown to be in service, and
  // reading a failed lookup as permission is what turns one broken row
  // into a session nothing stops.
  // The two rows the re-read reads, required of the store by every
  // listener that performs it: the three mailbox protocols through the
  // adapter they are handed, and submission at the message it hands over.
  //
  // Asked here rather than at create() because an MX listener opens no
  // session. Inbound mail arrives from peers this server has never met
  // and a held mailbox is answered at RCPT, so a composition that binds
  // port 25 and nothing else never reaches this check, and requiring it
  // of that composition would refuse a store that answers everything
  // asked of it. The listeners that DO reach it ask before they bind, so
  // a gap is still a boot failure rather than a command nobody covered.
  function _requireAccountLivenessReaders(listener) {
    var label = "blamepost.mail.listeners: the " + listener + " listener re-reads the " +
      "account behind a signed-in session for every command it serves, so a session cannot " +
      "outlive a suspension, an archive, an erasure or a withdrawn domain. opts.store";
    _requireMethods(store.accounts, ["get"], label + ".accounts");
    _requireMethods(store.domains, ["get"], label + ".domains");
  }

  function _refuseIfAccountStopped(actor, verb) {
    var standing;
    try {
      standing = _accountStanding(actor);
    } catch (readErr) {
      standing = {
        ok:       false,
        reason:   "account-unreadable",
        address:  (actor && actor.address && String(actor.address)) || "",
        domain:   (actor && actor.domain && String(actor.domain)) || "",
        sentence: "this server could not read whether the account is still in service (" +
          displayText.forDisplay((readErr && readErr.message) || String(readErr)) + ")",
      };
    }
    if (standing === null || standing.ok === true) return;
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.session_account_stopped",
      outcome:  "denied",
      actor:    _wireActor(actor),
      metadata: {
        accountId: (actor && actor.id) || null,
        address:   standing.address,
        domain:    standing.domain,
        // Which of the readings it was, because a suspension, an archive,
        // an erasure, a withdrawn domain and a row this server could not
        // read send an operator to five different places.
        reason:    standing.reason,
        // What the session was asking for when it was refused. An
        // operator reading the trail wants to know whether a client was
        // fetching mail or sending it.
        verb:      String(verb),
      },
    });
    var err = new Error("this mailbox is no longer one this server serves: " +
      standing.sentence + ". The session authenticated while it was in service and the " +
      "state has changed since.");
    err.code           = SESSION_ACCOUNT_STOPPED;
    err.smtpCode       = "550";
    err.enhancedStatus = "5.7.1";
    err.replyText      = "Message refused: the mailbox this session authenticated as is no " +
      "longer in service";
    throw err;
  }

  // The adapter verbs a signed-in session reaches, each of which takes
  // the actor first. Wiring the check onto the ADAPTER rather than onto
  // each handler is what makes it one decision: the framework dispatches
  // most of these itself and this file overrides the rest, and a check
  // written per handler would be absent from whichever half nobody
  // remembered.
  var SESSION_ACTOR_FIRST_VERBS = Object.freeze([
    "selectFolder", "statusFolder", "listFolders", "fetchRange", "searchScan",
    "storeFlags", "expungeFolder", "getMetadata", "setMetadata",
    "createFolder", "deleteFolder", "renameFolder", "subscribeFolder", "unsubscribeFolder",
    "openPop3Drop", "listMessages", "getMessage", "markDelete", "resetPop3Drop",
    "commitPop3Drop",
  ]);

  // The filter scripts, which ManageSieve reaches through a nested
  // handle. `active` is absent on purpose: it is read during inbound
  // delivery under an actor this server built for the recipient rather
  // than under a session, and mail arriving for a held mailbox is decided
  // at RCPT rather than here.
  var SESSION_SIEVE_VERBS = Object.freeze([
    "put", "list", "get", "setActive", "delete", "rename", "haveSpace",
  ]);

  // The one verb that names a mailbox before it names anybody. IMAP
  // APPEND is `appendMessage(name, bytes, opts)`, and the actor travels
  // on the options.
  var SESSION_OPTS_ACTOR_VERBS = Object.freeze({ appendMessage: 2 });

  function _gateVerb(adapter, owner, name, readActor) {
    var underlying = adapter[name];
    if (typeof underlying !== "function") {
      throw new TypeError("blamepost.mail.listeners.create: opts.mailStore" + owner +
        " must expose " + name + "(). Every command a signed-in session sends is refused " +
        "once the account has left service, and the refusal is wired onto the adapter verbs " +
        "the listeners call, so a verb missing here is a command the check cannot cover.");
    }
    return function () {
      _refuseIfAccountStopped(readActor(arguments), name);
      return underlying.apply(adapter, arguments);
    };
  }

  function _firstArgument(args) { return args[0]; }

  function _actorOnOptionsAt(at) {
    return function (args) {
      var options = args[at];
      return options && typeof options === "object" ? options.actor : null;
    };
  }

  /**
   * The mailbox adapter as a SIGNED-IN SESSION sees it: every verb a
   * wire command reaches, with the account re-read in front of it.
   *
   * The inbound path keeps the adapter untouched. A message arriving for
   * a mailbox that is out of service is a question RCPT already answers,
   * and routing delivery through a check built for sessions would refuse
   * mail on a rule written about clients.
   */
  function _buildSessionMailStore() {
    _requireAccountLivenessReaders("mailbox");
    var gated = {};
    SESSION_ACTOR_FIRST_VERBS.forEach(function (name) {
      gated[name] = _gateVerb(mailStore, "", name, _firstArgument);
    });
    Object.keys(SESSION_OPTS_ACTOR_VERBS).forEach(function (name) {
      gated[name] = _gateVerb(mailStore, "", name,
        _actorOnOptionsAt(SESSION_OPTS_ACTOR_VERBS[name]));
    });
    var scripts = mailStore.sieveScripts;
    if (!scripts || typeof scripts !== "object") {
      throw new TypeError("blamepost.mail.listeners.create: opts.mailStore.sieveScripts must " +
        "be the handle ManageSieve reads and writes filter scripts through.");
    }
    gated.sieveScripts = Object.assign({}, scripts);
    SESSION_SIEVE_VERBS.forEach(function (name) {
      gated.sieveScripts[name] = _gateVerb(scripts, ".sieveScripts", name, _firstArgument);
    });
    return Object.assign({}, mailStore, gated);
  }

  // Built at the moment a mailbox listener is composed, and built once.
  //
  // Once, because IMAP, POP3 and ManageSieve all hand the framework the
  // same adapter and this file's own overrides read the same one. Two
  // copies would be two answers to which verbs the account is re-read in
  // front of.
  //
  // At composition rather than at create(), because the full adapter is
  // what a mailbox listener needs and not what every composition has. An
  // MX-only server delivers arriving mail and opens no session, so it
  // carries an adapter that appends a message and nothing else. Asking
  // that composition for twenty session verbs would refuse a server whose
  // sessions do not exist. The three builders below reach this, so a
  // composition that DOES open sessions still finds a gap at boot rather
  // than at the command it could not cover.
  var sessionStoreHandle = null;
  function _sessionStore() {
    if (sessionStoreHandle === null) sessionStoreHandle = _buildSessionMailStore();
    return sessionStoreHandle;
  }

  function _submissionAgent() {
    return {
      handoff: async function (outbound) {
        _refuseIfReadAsTwoMessages("outbound", outbound, outbound.body);
        // Before anything else this handoff does, because a mailbox the
        // operator has taken out of service is not one whose mail this
        // server relays, and the whole of the work below is relaying it.
        // The mailbox protocols reach the same check through the adapter
        // they read; this listener writes no mailbox, so it asks here.
        _refuseIfAccountStopped(outbound.actor, "submission relay");
        // Before the signer, because a signature is this server putting
        // its name to whatever the header says, and before delivery,
        // because a refused message must not have reached a mailbox.
        //
        // Through the exposed binding rather than past it, so the wire
        // and the composer reach the check by the same call and a change
        // to one of them cannot leave the other measuring something else.
        await authorBinding(outbound.actor, outbound.body, outbound);
        // After the binding, so a message this identity was never
        // entitled to write does not spend the ceiling it was refused
        // under, and before the signer and the relay, so a message the
        // ceiling stops has not been signed or handed anywhere.
        //
        // Through the exposed gate rather than past it, for the reason
        // the binding above goes through the exposed binding: the
        // composer runs this same call on the same message, so the wire
        // and the browser port's sending route cannot end up asking a
        // different pair of questions in a different order.
        await sendingCredentialGate(outbound.actor, outbound);
        var body = outbound.body;
        var senderDomain = _domainOf(outbound.mailFrom);
        if (dkim && senderDomain) {
          try {
            body = await dkim.sign(senderDomain, body);
          } catch (err) {
            // The message still goes, because refusing to relay an
            // account's own mail over a key problem is a worse outage
            // than sending it unsigned. But it leaves as mail receivers
            // cannot attribute to this domain, and the row that says so
            // is the only place an operator can find that out, so the
            // row records a failure. Filed as a success it would be
            // invisible to `b.audit.query` on outcome, which is the one
            // question an operator asks of an audit trail.
            //
            // The cause goes in the action rather than the metadata.
            // `b.audit.query` filters on action, outcome and actor and
            // takes no metadata criteria, so a cause recorded in the
            // metadata blob is one an operator cannot filter on, and the
            // two causes want different answers. A domain with no
            // selector is a setup state that ends when setup ends, and
            // the fix is one command. Anything else keeps the original
            // name: a key that will not unseal is not that, and filing
            // it as one would send an operator to fix the wrong thing.
            var cause = err && err.code;
            var whyUnsigned = displayText.forDisplay((err && err.message) || String(err));
            b.audit.safeEmit({
              action: cause === DKIM_CODES.noActiveSelector
                ? "blamepost.mail.listeners.submission_unsigned_no_key"
                : "blamepost.mail.listeners.submission_unsigned",
              outcome:  "failure",
              // Whose mail left unattributable, and from where. The
              // domain in the metadata says which key was missing; this
              // says which account's clients are sending mail receivers
              // cannot align, which is the half an operator needs to
              // tell one broken application from a whole domain.
              actor:    _wireActor(outbound.actor, _peerOn(outbound), outbound.connectionId),
              metadata: {
                domain: senderDomain,
                cause:  cause || null,
                reason: whyUnsigned,
              },
            });
            log.error("mail from " + senderDomain + " is being relayed without a DKIM " +
              "signature, so receivers cannot attribute it to that domain: " +
              whyUnsigned);
          }
        }
        var routed = await _relaySend({
          from:   outbound.mailFrom,
          to:     outbound.rcpts,
          rfc822: body,
          origin: "submission",
        });
        return {
          messageId: null,
          // What was actually filed, not what was resolved. A caller
          // reading this to say a message was delivered would be reading
          // the routing decision rather than the outcome.
          local:     routed.localCount,
          remote:    routed.remoteCount,
          refused:   routed.refusedCount,
          delivery:  routed.outbound,
        };
      },
    };
  }

  // ---- Listener construction ----------------------------------------------

  // The HELO identity gate, composed so the resolver and the operator's
  // own names travel with every evaluation. The MX listener calls
  // `evaluate(ctx, {})`, so anything this server wants applied has to be
  // folded in here rather than passed at the call site.
  //
  // The operator's resolver goes over as it is. The gate confirms a
  // peer's claimed name by resolving the reverse name and resolving
  // what comes back forward again, and it reads the reverse name
  // through `resolver.queryPtr`, which the framework's resolver
  // provides. It also refuses a resolver that does not, rather than
  // reporting the clean "no reverse name" that a missing reader would
  // produce for every address alive. That refusal is the reason nothing
  // stands in for the reader here: a substitute would fill the gap
  // before the gate could look, so a resolver genuinely unable to
  // answer PTR would reach the check as a working one and the refusal
  // written to say so could never fire.
  //
  // The whole round trip carries the budget rather than each lookup
  // inside it, and that is not a preference. Bounding the lookups would
  // mean handing the gate a resolver this file had wrapped, and the gate
  // REFUSES a resolver that cannot answer a reverse question precisely
  // so a handle that cannot do the check is never read as an address
  // with no reverse name. A wrapper is the shape that fills that gap
  // before the gate can look at it, so the handle goes over untouched
  // and the budget sits outside the call.
  function _heloGate(localDomains) {
    var selfNames = [hostname].concat(localDomains);
    return {
      evaluate: function (ctx, evaluateOpts) {
        return posture.withinDnsBudget(b.mail.helo.evaluate(
          Object.assign({}, ctx, { resolver: resolver }),
          Object.assign({ profile: profile, selfNames: selfNames }, evaluateOpts || {})
        ), dnsAnswerBudgetMs, "helo identity check");
      },
    };
  }

  function _buildMx(localDomains) {
    // The hosted set is what every recipient is measured against, and
    // the measurement is the relay refusal. The framework applies it
    // against whatever this names, an empty set included, so an MX
    // listener over nothing is a listener that refuses every recipient
    // permanently rather than one with the check switched off.
    //
    // This still refuses to build one, and the reason is the sender
    // rather than the check. A permanent refusal at RCPT is a peer being
    // told the address does not exist here, which it reports back to its
    // own sender instead of retrying, so a server that binds port 25
    // before its first domain exists turns the arriving mail of that
    // window into bounces. Not binding is a connection refused, which
    // every sending server retries against.
    //
    // The caller decides whether an MX listener should exist at all, and
    // it decides that on this same emptiness, so by the time this runs
    // the set has something in it. The refusal is restated here because
    // a later caller reading only this function would otherwise find
    // that a listener over an empty set builds cleanly and says nothing
    // about what it will do with the mail.
    if (!Array.isArray(localDomains) || localDomains.length === 0) {
      throw new TypeError("blamepost.mail.listeners: an MX listener is built against the " +
        "domains this server hosts, and there are none. With an empty set every recipient " +
        "is a stranger's and none of them resolves to a mailbox here, so the listener " +
        "would accept a relay probe and refuse the message afterwards. Add a domain with " +
        "`blamepost init` or `blamepost domain add <domain>` before binding port 25.");
    }
    var inbound = config.inbound || {};
    return b.mail.server.mx.create(_tlsOption({
      greeting:        hostname + " ESMTP blamepost",
      profile:         profile,
      localDomains:    localDomains,
      // `relayAllowedFor` is deliberately absent rather than empty. The
      // refusal at the top of create() is what an operator meets; this
      // is the composition matching it, so there is no value written
      // here for anyone to widen. See the note above _refuseRelayGrant.
      rateLimit:       limits.rateLimit,
      maxConnections:  MAX_CONNECTIONS,
      maxMessageBytes: limits.maxMessageBytes,
      maxLineBytes:    wanted.mx.maxLineBytes,
      helo:            _heloGate(localDomains),
      rbl:             opts.rbl || undefined,
      greylist:        opts.greylist || undefined,
      // The per address question, asked at RCPT. `localDomains` above
      // decides the domain and has never been able to decide the local
      // part, so without this every name at a hosted domain is accepted
      // and the mailbox question waits until the message is whole.
      recipientPolicy: _mxRecipientPolicy,
      agent:           _mxAgent(),
      // SPF, DKIM verification, DMARC policy, the ARC chain and the
      // receiver's Authentication-Results header, evaluated at the end
      // of DATA. On by default: a receiver that does not check is a
      // receiver whose users get spoofed mail from their own domain.
      // ARC is verified and reported and deliberately changes nothing:
      // it says a forwarder vouches for an authentication result this
      // server can no longer reproduce, and trusting that is a decision
      // about the forwarder rather than about the message.
      guardEnvelope: {
        mode:        inbound.mode || DEFAULT_INBOUND.mode,
        onTemperror: inbound.onTemperror || DEFAULT_INBOUND.onTemperror,
        authservId:  hostname,
        // Every lookup these four checks make goes to the resolver the
        // operator chose. Left unset, the gate builds one of its own
        // with default options, so the HELO check would read the
        // operator's zone view and SPF, DKIM and DMARC would read the
        // host's, and the answer that decides whether a message is
        // accepted would be the one the operator did not configure.
        dnsLookup:   _dnsLookupOver(resolver, dnsAnswerBudgetMs),
      },
    }));
  }

  // ---- a domain that left the hosted set while port 25 was up ---------------
  //
  // The framework reads the hosted set per recipient with an `indexOf`,
  // from what it was given at construction. Given an array, as it is
  // here, the set a listener was built with is the set it keeps until
  // something builds another one, and `start()` builds it once from the
  // domains the store called active that morning. An operator who
  // withdraws a domain therefore changes every management surface and
  // does not change the listener.
  //
  // The option also takes a function, answered per recipient, and taking
  // it would move this decision into the framework's own relay check. It
  // is not taken: that resolver is synchronous while the hosted set here
  // is a store read, so the function form needs a live in-memory mirror
  // of the domain table rather than a different argument. See the module
  // block above for what that would cost and what it would buy.
  //
  // What the peer met before this check is not delivered mail. The
  // handoff resolves every recipient again and refuses them all, so
  // nothing reaches a mailbox. What it met was `250` to a recipient this
  // server says it no longer serves, an invitation to transmit the whole
  // message, and a `451` at the end, repeated for the peer's entire
  // retry window. That is the open-relay answer a scanner records and
  // the accept-then-refuse shape `_mailboxIsReachable` exists to keep
  // off this listener.
  //
  // Removing a domain is the worse half. An address at a hosted domain
  // holding no mailbox is refused `550` here; the same address once the
  // domain is gone resolves as not local, which a hook reading locality
  // alone would take as somebody else's question, so removing a domain
  // would make this listener MORE accepting of an address than hosting
  // it is.
  //
  // ## Why the answer is permanent
  //
  // A withdrawn domain is answered the way a domain this server never
  // heard of is answered, and it is answered at RCPT. Three things
  // decide that:
  //
  //   - It is what the restarted server says. Rebuild the listener and
  //     the framework's own hosted-set check refuses the same recipient
  //     `550 5.7.1 Relaying denied`, permanently, at RCPT. A running
  //     server that answered transiently would disagree with a restarted
  //     one about the same address, which is the defect restated rather
  //     than fixed.
  //   - A transient answer is not reachable from here in any case. The
  //     framework writes `550` for every refusal this hook returns; the
  //     only other reply it can produce is the `451 4.7.1` it writes
  //     when the hook THROWS, which is reserved for a store that could
  //     not answer. Borrowing it for a decision the operator made would
  //     report a working server as a broken one.
  //   - `450` buys a temporarily disabled domain nothing that survives.
  //     The retry window it would preserve already ends at the next
  //     restart, when the frozen set is rebuilt without the domain and
  //     every peer is answered permanently regardless. An operator cannot
  //     rely on a guarantee that lasts only until the next upgrade.
  //
  // The enhanced code is the framework's `5.1.1` rather than the `5.1.2`
  // RFC 3463 gives a destination system that does not accept mail for a
  // domain, because this hook supplies the prose and not the code. Both
  // are permanent and both are addressing failures, so a sender's queue
  // treats them identically; only the diagnostic precision is lost.
  //
  // ## What still disagrees, and why refusing is still right
  //
  // The frozen set is unchanged by any of this, so the framework goes on
  // classifying the address as local for its own purposes. Two follow
  // from that. The relay refusal never fires, which is what lets the
  // recipient reach this hook at all. And `_heloGate` still carries the
  // withdrawn domain among the names this server answers to, so a peer
  // greeting as it is still measured as claiming one of ours. That
  // leaves two answers about what is hosted, one of them current.
  // Refusing the recipient is the right half to make current: the other
  // reading, that the address is not local and this is therefore a relay
  // attempt, is the answer that ends in mail leaving the building.
  // (`authservId` is the third place the framework defaults to
  // `localDomains[0]`, and this composition sets it to `hostname`
  // explicitly, so it never had the divergence.)
  //
  // The callback form this was asked upstream for has landed, so the
  // divergence is now a choice rather than a constraint: passing a
  // function would make the framework's own relay check current and
  // retire this hook's domain branch. What that costs is the reason it
  // has not been taken. The refusal below writes an audit row naming the
  // domain and which of the two states it is in, and the framework's
  // relay refusal writes neither. Moving the decision up would answer the
  // peer a line earlier and stop answering the operator at all, and the
  // operator's answer is the half that gets read months later.
  //
  // ## The peer is told the same thing either way
  //
  // Both states answer with the text for a domain this server does not
  // handle. Telling a stranger that a domain was once hosted here is a
  // fact about the operator's configuration that they have no reason to
  // publish, and the two mean the same thing to the sender. Which of the
  // two it was goes to the audit row, where the operator reads it.
  var LEFT_THE_HOSTED_SET = Object.freeze({
    "domain-disabled": "disabled",
    "unknown-domain":  "removed",
  });

  // Whether this verdict is about a domain that has left the hosted set,
  // and which way it left.
  //
  // The store already answered, on this recipient, a moment ago. Both
  // states arrive as a reason on the verdict the hook below is holding:
  // a domain switched off resolves local with `domain-disabled`, one
  // removed resolves not local with `unknown-domain`. So this reads the
  // live answer rather than asking a second time, because a second
  // lookup would be a second answer to who hosts this domain and the two
  // would eventually differ.
  //
  // An address the store could not parse is neither. It carries no
  // domain to have an opinion about, so it falls through to the reason
  // table below exactly as before.
  function _domainLeftTheHostedSet(routed) {
    if (!routed || typeof routed.domain !== "string" || routed.domain.length === 0) return null;
    var state = LEFT_THE_HOSTED_SET[routed.reason];
    return state === undefined ? null : { domain: routed.domain, state: state };
  }

  // One recipient refused for its domain, said on the wire and written
  // down.
  //
  // The framework files a `recipient_refused` event of its own for every
  // refusal this hook returns, and that event carries the prose rather
  // than the cause, so it cannot say that the domain was withdrawn or
  // which way. This row is the half an operator needs months later, when
  // the symptom is mail that bounced and the cause is a domain somebody
  // switched off.
  //
  // The peer's own address is on the row because a wire refusal is
  // performed by a peer rather than by a principal, so the party that
  // acted is named in the column that answers who acted while the column
  // beside it stays empty. It is a column rather than a field in the
  // metadata because `b.audit.query` filters on the actor columns and
  // takes no metadata criteria, and one source refused all day is a
  // question about the source.
  //
  // Both addresses are the peer's own text on its way into an operator's
  // terminal, so each goes through the screen the rest of this file
  // writes stranger text with rather than being trusted to have passed
  // one earlier.
  function _refuseWithdrawnDomain(ctx, withdrawn) {
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.mx_recipient_domain_not_hosted",
      outcome:  "denied",
      actor:    _wireActor(null, _peerOn(ctx), ctx.connectionId),
      metadata: {
        domain:   withdrawn.domain,
        state:    withdrawn.state,
        rcptTo:   displayText.forDisplay(ctx.rcptTo || ""),
        mailFrom: displayText.forDisplay(ctx.mailFrom || ""),
      },
    });
    return { ok: false, reason: _refusalText("unknown-domain") };
  }

  // Recipient policy for inbound mail. RFC 5321 §3.3 answers a mailbox
  // this server does not hold with `550 5.1.1`, at RCPT, before the
  // peer transmits anything, and this is where that answer is decided.
  //
  // The framework has already refused what it can by the time this
  // runs: a domain outside the set the listener was BUILT with is a
  // relay refusal, and a malformed or hardened-out domain is refused at
  // the grammar. What that leaves is the section above: a recipient can
  // reach here at a domain the store no longer hosts, because the set
  // the relay check consults is the one from the last boot. This server
  // grants relay to nobody, so that is the only way a recipient the
  // store calls foreign arrives here at all, and it is answered first.
  //
  // ## Only a permanent condition is refused here
  //
  // The hook has one refusal and it is `550`, which tells the sending
  // server to stop retrying and report to its own sender. That is the
  // right answer for an address that does not exist and the wrong one
  // for a mailbox that is full or an account that is suspended, both
  // of which the owner can clear. So the store's reason is put through
  // the same status table the reports use, and only a `5` refuses on
  // the wire. A temporary condition is accepted here and met at the
  // handoff exactly as before, which keeps the sender retrying against
  // a condition that can change.
  //
  // The domain check above sits in front of that table rather than
  // inside it, and the split is what keeps both answers right. The
  // table's `4.2.1` for a disabled domain is still the correct reply to
  // the one case that reaches the handoff now: a domain switched off
  // between a RCPT that passed and the message finishing, which is a
  // real race and a genuinely momentary condition. The steady state is
  // decided here instead, where the peer has not yet sent anything.
  //
  // ## A store that cannot answer is not a verdict about the mailbox
  //
  // Nothing here catches. A rejection from the store travels out of
  // this function, and the framework answers `451 4.7.1` for it, so a
  // database that is unreachable defers the recipient instead of
  // telling a stranger that a mailbox they were writing to does not
  // exist. Swallowing it into a refusal would turn one bad minute into
  // permanently bounced mail for every account on the server.
  //
  // ## The reason is this server's own prose
  //
  // The text goes onto a line-oriented reply and the peer chose the
  // address, so a reason quoting it back would let a CR or LF end the
  // `550` early and have the rest read as a second, forged reply. The
  // text comes from the fixed table the reports use and names no
  // address at all, which is the same reason those reports read the
  // way they do.
  function _mxRecipientPolicy(ctx) {
    return Promise.resolve(store.resolve(ctx.rcptTo)).then(function (routed) {
      var withdrawn = _domainLeftTheHostedSet(routed);
      if (withdrawn !== null) return _refuseWithdrawnDomain(ctx, withdrawn);
      if (!routed || routed.local !== true) return { ok: true };
      if (_mailboxIsReachable(routed)) return { ok: true };
      var reason = routed.reason || "no-such-mailbox";
      if (String(_refusalStatus(reason)).charAt(0) !== "5") return { ok: true };
      return { ok: false, reason: _refusalText(reason) };
    });
  }

  // Recipient policy for authenticated submission. The address has to
  // be one a mail server can route, which is a check the wire grammar
  // does not make: `RCPT TO:<alice@localhost>` is syntactically fine
  // and undeliverable.
  function _submissionRecipientPolicy(ctx) {
    var domain = _domainOf(ctx.rcptTo);
    if (domain.length === 0) {
      return { ok: false, reason: "Recipient address has no domain" };
    }
    var verdict = b.guardDomain.validate(domain, b.guardDomain.buildProfile({ profile: profile }));
    if (!verdict.ok) {
      return {
        ok:     false,
        reason: "Recipient domain refused (" +
          (verdict.issues && verdict.issues[0] && verdict.issues[0].kind) + ")",
      };
    }
    return { ok: true };
  }

  // The envelope sender an authenticated account may write, for the
  // addresses the listener's own mailbox set cannot hold.
  //
  // That set is fixed when the session authenticates and holds the
  // account's own address, so it cannot answer for an alias the operator
  // added a minute ago, and it cannot enumerate a subaddress at all
  // because the tag is chosen by whoever writes the address. Both are
  // resolved here instead, per request and from the store.
  //
  // It is the SAME set the author binding measures the `From` header
  // against, read through the same function rather than derived a second
  // time. Two derivations of one rule is how a server ends up permitting
  // an address as an author and refusing it as a sender, which is the
  // pair this composition closes.
  //
  // Asked only after the listener's set has already declined, so an
  // ordinary send under the account's own address never reaches it.
  //
  // It fails closed in both directions. An address this server cannot
  // read is refused, and a store that cannot answer raises, which the
  // framework turns into the same refusal an unowned address gets. A
  // policy that could not decide has not decided in the sender's favor.
  // A sending credential's envelope refusal, written down before the
  // verdict is returned.
  //
  // The reply itself is the framework's, and returning false is what
  // gets the right one. The framework picks between two sentences on
  // whether the actor's mailbox set is empty: an empty set draws
  // `authenticated identity has no assigned mailboxes`, and a non-empty
  // one draws `not owned by authenticated identity`. Only the second is
  // true of a credential, which is why the actor carries a scope name in
  // that set rather than nothing.
  //
  // Raising instead of returning would draw the same correct sentence
  // and does not work: the framework's policy path writes that reply to
  // the socket its connection closure captured, which on every session
  // that reached AUTH is the one STARTTLS replaced. Measured against
  // this listener, a raising policy left the client with no reply at all
  // until the idle timeout cut the session. So the refusal is returned,
  // and the row below is what carries the detail the reply cannot.
  function _noteCredentialSenderRefused(scope, ctx, parsed) {
    var written = (ctx && ctx.mailFrom) || "";
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.sending_credential_sender_refused",
      outcome:  "denied",
      actor:    _wireActor(ctx && ctx.actor, _peerOn(ctx), ctx && ctx.connectionId),
      metadata: {
        credentialId: scope.id,
        scopeDomain:  scope.domain,
        // The address that was refused, and which reason it was: outside
        // the domain the credential speaks for, held back by the refusal
        // list, a mailbox carrying the operator role, a role lookup that
        // could not be answered, or a string this server could not read
        // as an address at all. They send an operator to different
        // places. The reason is read from the same function the decision
        // was, so the row cannot name a reason the decision did not use.
        // A role changed between the two reads leaves nothing to name,
        // and the row says so.
        rejected:     parsed.ok ? parsed.address : _echoHeader(written),
        reason:       parsed.ok
          ? (_sendingScopeRefusal(store, scope, parsed) || "scope-changed-between-reads")
          : "envelope-sender-unreadable",
        refusedLocalParts: scope.refusedLocalParts.slice(),
      },
    });
    return { ok: false };
  }

  // The envelope sender an authenticated identity may write, for the
  // addresses the listener's own mailbox set cannot hold.
  //
  // Asked through the same decision reader the author binding asks, so
  // one address cannot be permitted as an author and refused as a
  // sender. An account's answer is its address set resolved per request;
  // a credential's is its domain scope minus its refusal list.
  //
  // It fails closed in both directions. An address this server cannot
  // read is refused, and a store that cannot answer raises, which the
  // framework turns into the same refusal an unowned address gets. A
  // policy that could not decide has not decided in the sender's favor.
  function _senderPolicy(ctx) {
    var actor  = ctx && ctx.actor;
    var parsed = storeAddress.parse((ctx && ctx.mailFrom) || "");
    if (parsed.ok && permittedAuthor(store, actor, parsed.address)) return { ok: true };
    var scope = _sendingCredentialOf(actor);
    if (scope === null) return { ok: false };
    return _noteCredentialSenderRefused(scope, ctx, parsed);
  }

  function _buildSubmission(implicitTls) {
    // This listener writes no mailbox, so it reaches the re-read at the
    // message it hands over rather than through the adapter, and it has
    // to ask for the readers on its own account.
    _requireAccountLivenessReaders("submission");
    return b.mail.server.submission.create(_tlsOption({
      implicitTls:     implicitTls === true,
      greeting:        hostname + " Submission blamepost",
      profile:         profile,
      // The one listener whose identity space holds a sending credential.
      auth:            _authConfig(AUTH_SURFACES.SUBMISSION),
      rateLimit:       limits.rateLimit,
      maxConnections:  MAX_CONNECTIONS,
      maxMessageBytes: limits.maxMessageBytes,
      // The implicit-TLS listener on 465 and the STARTTLS one on 587 are
      // separate sections, so each carries its own ceiling.
      maxLineBytes:    (implicitTls ? wanted.submissions : wanted.submission).maxLineBytes,
      identityBinding: "strict",
      senderPolicy:    _senderPolicy,
      agent:           _submissionAgent(),
      // The listener's own gate asks the client to arrive with a
      // signature already attached. This server signs during relay,
      // which happens after the gate, so arming it would refuse every
      // ordinary mail client and change nothing about what leaves
      // signed.
      dkimRequireMode: "off",
      recipientPolicy: _submissionRecipientPolicy,
    }));
  }

  // One response line. The framework's listener writes its own replies
  // through equivalents of these two and does not lend them to an
  // override, so they are restated for the one verb this composition
  // serves. A socket that has already gone is not an error worth
  // raising: the command it was answering ended with it.
  // The CRLF that ends a response line is written here, so this is
  // where the line is made to hold exactly one. A refusal quotes the
  // term it refused, and a term that reached it carrying CR or LF would
  // otherwise choose where this line ends and what the client reads as
  // the next one. Every reader on the way in refuses those bytes, and
  // this is the backstop under all of them: it is the one place every
  // response line passes through, so a quoting refusal added later
  // cannot reopen the hole by forgetting to screen its own argument.
  function _imapLine(line) {
    return b.safeBuffer.foldHeaderText(String(line));
  }

  function _imapTagged(socket, tag, line) {
    try { socket.write(tag + " " + _imapLine(line) + "\r\n"); }
    catch (_e) { /* drop-silent by design: the client is already gone */ }
  }

  function _imapUntagged(socket, line) {
    try { socket.write("* " + _imapLine(line) + "\r\n"); }
    catch (_e) { /* drop-silent by design: the client is already gone */ }
  }

  // A SEARCH this server will not answer, said out loud on the wire and
  // written to the audit trail. Both halves matter and they are read by
  // different people: the client's user sees a command that failed
  // rather than a mailbox that looks empty, and the operator asking why
  // a mail client reports no results has a row naming the key.
  //
  // The reply always names the verb, because a client whose search
  // failed has only the tagged line to say which command it was.
  //
  // BAD is written only when the expression itself is what could not be
  // read, because RFC 9051 section 7.1 makes BAD a protocol error and a
  // client acts on it by looking for a fault in the command it sent.
  // Anything else that ends this command is the server failing to run a
  // command it understood, which is NO, so that is the default and a
  // failure arriving from the folder read lands on it.
  // Who acted on one IMAP row: the account the session authenticated as,
  // the address the connection came from, and the connection itself. The
  // session holds all three and every row this listener writes carries
  // them, refusals and completions alike. A trail naming the peer only
  // where something was refused cannot answer what else the same address
  // did while it held the credential, which is the question asked after
  // a password turns out to be somebody else's.
  function _imapActor(state) {
    return _wireActor(state && state.actor, state && state.remoteAddress, state && state.id);
  }

  function _refuseImapSearch(state, socket, tag, refusal) {
    var condition = refusal && refusal.searchCondition === "BAD" ? "BAD" : "NO";
    var code = (refusal && refusal.searchResponseCode) || null;
    var text = (refusal && (refusal.searchText || refusal.message)) ||
      "was refused and gave no reason.";
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.imap_search_refused",
      outcome:  "denied",
      actor:    _imapActor(state),
      metadata: {
        mailbox:   state.selectedMailbox || "",
        condition: condition,
        reason:    String(text).slice(0, MAX_SEARCH_ECHO),
      },
    });
    _imapTagged(socket, tag, condition + " " + (code === null ? "" : code + " ") +
      "SEARCH " + text);
  }

  // The SEARCH verb, composed over the folder scan. The expression is
  // compiled BEFORE the scan, so an expression this server will not
  // answer costs a refusal rather than a read of every message in the
  // mailbox, and the refusal reaches the client at the point of parse.
  function _imapSearch(state, socket, parsed, literalBody) {
    var tag = parsed.tag;
    if (!state.actor) {
      _imapTagged(socket, tag, "NO SEARCH needs an authenticated session.");
      return undefined;
    }
    if (!state.selectedMailbox) {
      _imapTagged(socket, tag, "BAD SEARCH is a Selected state command (RFC 9051 " +
        "section 6.4.4); SELECT a mailbox first.");
      return undefined;
    }

    var expression;
    try {
      expression = compileSearch(parsed.args, _imapSearchLiteral(literalBody));
    } catch (refusal) {
      _refuseImapSearch(state, socket, tag, refusal);
      return undefined;
    }

    return Promise.resolve()
      .then(function () {
        return _sessionStore().searchScan(state.actor, state.selectedMailbox);
      })
      .then(function (messages) {
        var rows = messages || [];
        var ctx = { highestSeq: 0, highestUid: 0 };
        for (var h = 0; h < rows.length; h += 1) {
          if (rows[h].seq > ctx.highestSeq) ctx.highestSeq = rows[h].seq;
          if (rows[h].uid > ctx.highestUid) ctx.highestUid = rows[h].uid;
        }
        // `UID SEARCH` is this same handler reached through the UID verb,
        // and RFC 9051 section 6.4.9 changes exactly one thing about it:
        // the numbers on the untagged line are unique identifiers rather
        // than message sequence numbers. The search KEYS keep the meaning
        // section 6.4.4 gives them, so a bare sequence set stays a
        // sequence set and a UID key stays uids; only the answer changes.
        //
        // Reading the flag is not optional politeness. Both kinds of
        // number are small integers, so a result set of the wrong kind
        // arrives looking exactly like one of the right kind, and the
        // client acts on it: the FETCH, STORE or COPY that follows names
        // messages the user never chose. A client asks for this form
        // precisely because a sequence number does not survive the
        // session that issued it, so the wrong answer lands on the
        // clients keeping a durable cache.
        var hits = [];
        for (var i = 0; i < rows.length; i += 1) {
          if (expression(rows[i], ctx)) {
            hits.push(parsed.useUid ? rows[i].uid : rows[i].seq);
          }
        }
        // RFC 9051 section 7.3.4 writes the result as one untagged line
        // carrying the message numbers, and as the bare form when the
        // answer is that nothing matched.
        _imapUntagged(socket, "SEARCH" + (hits.length === 0 ? "" : " " + hits.join(" ")));
        b.audit.safeEmit({
          action:   "blamepost.mail.listeners.imap_search",
          outcome:  "success",
          actor:    _imapActor(state),
          metadata: {
            mailbox: state.selectedMailbox,
            scanned: rows.length,
            matched: hits.length,
            uidForm: parsed.useUid === true,
          },
        });
        _imapTagged(socket, tag, "OK SEARCH completed");
      })
      .catch(function (failure) {
        // Anything the scan or the evaluation raises ends the command
        // as a refusal. A result set computed from a folder this server
        // could not read whole is not the answer to the question, and
        // reporting one under a tagged OK is the failure this verb is
        // shaped to avoid.
        _refuseImapSearch(state, socket, tag, failure);
      });
  }

  // The term a client sent as a literal, as text. RFC 9051 section
  // 6.4.4 with the default charset puts a search term in UTF-8, and a
  // payload that is not is refused rather than decoded: a decode
  // substitutes a replacement character for every sequence it cannot
  // read, so several distinct terms would arrive as one and the search
  // that ran would be for something the client never sent.
  function _imapSearchLiteral(literalBody) {
    if (literalBody === undefined || literalBody === null) return null;
    var bytes = Buffer.isBuffer(literalBody) ? literalBody : Buffer.from(String(literalBody));
    if (!nodeBuffer.isUtf8(bytes)) {
      throw _searchBad("carries a term that is not UTF-8. RFC 9051 section 6.4.4 makes " +
        "UTF-8 the charset a term is written in.");
    }
    var text = bytes.toString("utf8");
    // CR, LF and NUL are refused here because this is the one argument
    // the wire guard never saw. Every other search argument arrives on
    // the command line, which is screened before the command is
    // dispatched; RFC 9051 section 4.3 sends a literal as a counted
    // payload after it, so the only screen it had was the UTF-8 check
    // above, and CR and LF both decode. A refusal quotes the term it
    // refused, so a term carrying CRLF that survives to that point ends
    // the response line early and puts the rest at the start of the
    // next one, where a client reads it as an untagged response the
    // server never sent.
    var injected = b.codepointClass.firstLineInjectionCharOffset(text);
    if (injected !== -1) {
      throw _searchBad("carries a term with a line break or a null in it, at offset " +
        injected + ". RFC 9051 section 6.4.4 writes a search term as text on one line.");
    }
    return text;
  }

  // ---- IMAP selected state ------------------------------------------------

  // The mailbox each IMAP session has open and whether it opened it
  // read-only, keyed by the session's actor. The verifier builds a new
  // actor object for every sign-in and the listener passes that object on
  // every call the session makes, so one entry belongs to one session.
  // The SELECT and EXAMINE handlers below are the only writers.
  var imapSelections = new WeakMap();

  // Every IMAP session in the selected state, by account id. A RENAME or
  // DELETE sent by one session changes the names every other session of
  // the same account resolves, so the verb's follow-up runs over all of
  // them. A session is added on a successful SELECT or EXAMINE and
  // removed when it leaves the selected state or its connection closes.
  var imapSelectedByAccount = new Map();

  function _imapTrackSelected(state, socket) {
    var key = state.actor && state.actor.id;
    if (typeof key !== "string" || key.length === 0) return;
    var held = imapSelectedByAccount.get(key);
    if (held === undefined) {
      held = new Set();
      imapSelectedByAccount.set(key, held);
    }
    held.add(state);
    state.selectionAccountKey = key;
    // Kept so a verb another session sends can tell this one that its
    // mailbox went away.
    if (socket) state.selectionSocket = socket;
    if (state.selectionCloseWatched !== true && socket && typeof socket.once === "function") {
      state.selectionCloseWatched = true;
      socket.once("close", function () { _imapUntrackSelected(state); });
    }
  }

  function _imapUntrackSelected(state) {
    var key = state.selectionAccountKey;
    if (typeof key !== "string") return;
    var held = imapSelectedByAccount.get(key);
    if (held === undefined) return;
    held.delete(state);
    if (held.size === 0) imapSelectedByAccount.delete(key);
  }

  // The sessions of the account `state` belongs to that hold a mailbox
  // selected, including `state` itself when it does.
  function _imapSelectedSessionsOf(state) {
    var key = state.actor && state.actor.id;
    var held = typeof key === "string" ? imapSelectedByAccount.get(key) : undefined;
    var out = held === undefined ? [] : Array.from(held);
    if (out.indexOf(state) === -1) out.push(state);
    return out;
  }

  function _imapWritableSelection(actor, mailboxName) {
    var selection = actor ? imapSelections.get(actor) : undefined;
    return selection !== undefined && selection.mailbox === mailboxName &&
      selection.readOnly === false;
  }

  // The identifier each successful SELECT or EXAMINE gives the session.
  // The framework compares the one a command started under with the one
  // the session holds when the command finishes, and refuses the command
  // `NO [CLOSED]` when they differ, so a selection made by the override
  // below carries one as the framework's own SELECT does. A string, so it
  // is never equal to one the framework issues.
  var imapSelectionSeq = 0;

  // Back to the Authenticated state (RFC 9051 section 3).
  function _imapDeselect(state) {
    state.selectedMailbox  = null;
    state.selectedReadOnly = false;
    state.selectionId      = null;
    state.stage            = "authenticated";
    if (state.actor) imapSelections.delete(state.actor);
    _imapUntrackSelected(state);
  }

  // Ends a selection that a DELETE or a RENAME of INBOX has taken away,
  // and says so on the wire. The session that sent the verb is told with
  // `* OK [CLOSED]` ahead of its tagged answer (RFC 9051 section 7.1) and
  // stays connected in the authenticated state. Any other session holding
  // the mailbox has a command of its own in flight or none, and RFC 9051
  // gives it no response that closes a selection, so it is sent an
  // untagged BYE and its connection is closed; the client reconnects and
  // selects again.
  function _imapCloseSelection(session, issuer, why) {
    var socket = session.selectionSocket;
    _imapDeselect(session);
    if (!socket) return;
    if (session === issuer) {
      _imapUntagged(socket, "OK [CLOSED] " + why);
      return;
    }
    _imapUntagged(socket, "BYE " + why);
    try { socket.end(); }
    catch (_e) { /* drop-silent by design: the client is already gone */ }
  }

  // The adapter as the IMAP listener sees it. FETCH carries the session's
  // mode, so a read from a read-only session sets no `\Seen`, and EXPUNGE
  // from a read-only session is refused before anything is read. A
  // session without a selection of its own is treated as read-only.
  function _imapMailStore() {
    return Object.assign({}, _sessionStore(), {
      fetchRange: function (actor, mailboxName, seqSet, partsSpec, fetchOpts) {
        return _sessionStore().fetchRange(actor, mailboxName, seqSet, partsSpec,
          Object.assign({}, fetchOpts, {
            readOnly: !_imapWritableSelection(actor, mailboxName),
          }));
      },
      expungeFolder: function (actor, mailboxName) {
        if (!_imapWritableSelection(actor, mailboxName)) {
          var refusal = new Error("EXPUNGE removes nothing from a mailbox opened with EXAMINE, " +
            "which RFC 9051 section 6.3.3 opens read-only.");
          refusal.code = "listeners/imap-read-only";
          throw refusal;
        }
        return _sessionStore().expungeFolder(actor, mailboxName);
      },
    });
  }

  function _imapReason(failure, fallback) {
    return String((failure && failure.message) || fallback).slice(0, MAX_SEARCH_ECHO * 2);
  }

  // SELECT and EXAMINE. The session leaves the Selected state before the
  // arguments are read, so a command that fails for any reason leaves no
  // mailbox selected (RFC 9051 section 6.3.2). A mailbox the account does
  // not hold is answered with the NONEXISTENT response code of RFC 9051
  // section 7.1.
  function _imapSelectHandler(examine) {
    var verb = examine ? "EXAMINE" : "SELECT";
    return function (state, socket, parsed, literalBody) {
      var tag = parsed.tag;
      if (!state.actor) {
        _imapTagged(socket, tag, "NO " + verb + " needs an authenticated session.");
        return undefined;
      }
      _imapDeselect(state);
      var request;
      try { request = _imapSelectRequest(verb, parsed.args, literalBody); }
      catch (refusal) {
        _imapTagged(socket, tag, "BAD " + _imapReason(refusal, verb + " could not be read."));
        return undefined;
      }
      return Promise.resolve()
        .then(function () {
          return _sessionStore().selectFolder(state.actor, request.mailbox,
            { readOnly: examine });
        })
        .then(function (info) {
          state.selectedMailbox  = request.mailbox;
          state.selectedReadOnly = examine;
          imapSelectionSeq += 1;
          state.selectionId      = "blamepost-" + imapSelectionSeq;
          state.stage            = "selected";
          // RFC 7162 section 3.1.8: MODSEQ on every FETCH response from here on.
          if (request.condstore) state.enabledCondStore = true;
          imapSelections.set(state.actor, { mailbox: request.mailbox, readOnly: examine });
          _imapTrackSelected(state, socket);
          _imapUntagged(socket, info.exists + " EXISTS");
          _imapUntagged(socket, info.recent + " RECENT");
          _imapUntagged(socket, "FLAGS (" + (info.flags || []).join(" ") + ")");
          // RFC 9051 section 6.3.2 makes this one of the required OK
          // untagged responses to SELECT and to EXAMINE, and RFC 9051
          // section 7.1 says what a client does without it: it assumes
          // every flag it sends is kept permanently. It then offers the
          // account holder marks this mailbox will not hold, and offers
          // no way to invent a keyword where the mailbox would have kept
          // one, because the `\*` in this same list is what says new
          // keywords are allowed.
          //
          // The list is empty for a session that opened the mailbox with
          // EXAMINE. Section 6.3.2 permits no change to the permanent
          // state of a mailbox opened read-only, so nothing that session
          // sets is kept, and the store refuses its STORE. The mode is
          // read here rather than in the mailbox layer because the mode
          // belongs to this session: the same account holds other
          // sessions of its own, and a list built where the session is
          // not known would answer for whichever of them asked last.
          _imapUntagged(socket, "OK [PERMANENTFLAGS (" +
            (examine ? [] : (info.permanentFlags || [])).join(" ") + ")] " +
            (examine ? "No flags are kept from a read-only selection" : "Flags kept"));
          _imapUntagged(socket, "OK [UIDVALIDITY " + info.uidvalidity + "] UIDs valid");
          _imapUntagged(socket, "OK [UIDNEXT " + info.uidnext + "] Predicted next UID");
          _imapUntagged(socket, "OK [HIGHESTMODSEQ " + info.modseq + "] Highest");
          b.audit.safeEmit({
            action:   "blamepost.mail.listeners.imap_select",
            outcome:  "success",
            actor:    _imapActor(state),
            metadata: {
              mailbox:   request.mailbox,
              readOnly:  examine,
              exists:    info.exists,
              condstore: request.condstore,
            },
          });
          _imapTagged(socket, tag, "OK [" + (examine ? "READ-ONLY" : "READ-WRITE") + "] " +
            verb + " completed");
        })
        .catch(function (failure) {
          var code = failure && failure.code === "mailbox/no-folder" ? "[NONEXISTENT] " : "";
          _imapTagged(socket, tag, "NO " + code + _imapReason(failure, verb + " failed."));
        });
    };
  }

  // What a CREATE that could not be done is answered with. RFC 9051
  // section 7.1 gives three of the reasons a response code of their own,
  // and each one tells the client something different to do: the name is
  // taken, the name cannot be a mailbox name here, or the account has as
  // many mailboxes as it may have. A client that is told only NO offers
  // the account holder the same failed command again.
  // What a mailbox verb that could not be done is answered with. RFC
  // 9051 section 7.1 gives each of these a response code of its own, and
  // each tells the client something different to do: the name is taken,
  // the name cannot be a mailbox name here, the account has as many
  // mailboxes as it may have, the name is not there, or the server will
  // not do it at all. A client that is told only NO offers the account
  // holder the same failed command again.
  //
  // One table for the five verbs that write the namespace, because they
  // refuse for the same reasons through the same layer, and a second
  // table per verb is where one of them stops carrying a code.
  //
  // CONTACTADMIN is the answer for mail a preservation order or the
  // retention window kept. Neither is something the account holder can
  // lift, and it is the operator who knows when it comes off, so the
  // advice the code carries is the advice that applies.
  var IMAP_MAILBOX_CODES = {
    "mailbox/mailbox-exists":       "ALREADYEXISTS",
    "mailbox/bad-mailbox-name":     "CANNOT",
    "mailbox/bad-rename":           "CANNOT",
    "mailbox/mailbox-protected":    "CANNOT",
    "mailbox/folder-ceiling":       "LIMIT",
    "mailbox/subscribed-ceiling":   "LIMIT",
    "mailbox/no-folder":            "NONEXISTENT",
    "mailbox/mailbox-preserved":    "CONTACTADMIN",
    "mailbox/mailbox-refilled":     "INUSE",
    // RFC 5530 section 3: a temporary failure. The refusal says how many
    // messages moved and where they are, so it is quoted back.
    "mailbox/rename-incomplete":    "UNAVAILABLE",
  };

  // The five verbs that write one account's mailbox namespace: CREATE,
  // DELETE, RENAME, SUBSCRIBE and UNSUBSCRIBE. The framework ships a
  // default for each that answers `NO <verb> not configured`, because
  // what a mailbox name may be and what happens to the mail under one
  // are questions about the namespace an application keeps rather than
  // about the protocol. Left unwired, a client can make a folder and
  // never remove or rename it, against a server advertising IMAP4rev2,
  // where RFC 9051 sections 6.3.4 to 6.3.8 make all five part of the
  // base protocol.
  //
  // A name is stranger-controlled text on its way into a namespace that
  // is read back into listings, refusals, audit rows and an operator's
  // terminal, so the mailbox layer screens every one through the rule
  // every other name on this server passes. Nothing is screened a second
  // time here: a second rule is a second answer, and the names these
  // verbs store are read back by verbs that ask the first one.
  //
  // One shape for all five, because they answer the same way: the verb
  // runs, an audit row says what happened, and the client is told. Five
  // copies of that would be five places a response code goes missing one
  // verb at a time.
  //
  // The audit row is what each verb keeps of its own, because the action
  // name has to be readable where it is written: a name assembled from a
  // variable cannot be checked against the namespaces registered at
  // boot, and the framework refuses an unregistered one while the
  // emitter that the hot paths use drops what it cannot file. The two
  // together are silent, on exactly the paths an operator goes looking
  // for afterwards.
  // `settle` runs after a verb succeeds and before the tagged OK, for the
  // verbs that move or remove a mailbox this session may be holding open.
  // The selected state is named rather than identified, so a verb that
  // changes what a name refers to has to say so here or the session keeps
  // addressing a name that now means something else.
  //
  // `settleFailed` runs after a refusal and before the tagged NO, for a
  // verb that can be refused after it has already changed a mailbox, so
  // the sessions holding it are told as they are after a success.
  function _imapNamespaceHandler(verb, read, run, record, settle, settleFailed) {
    return function (state, socket, parsed, literalBody) {
      var tag = parsed.tag;
      if (!state.actor) {
        _imapTagged(socket, tag, "NO " + verb + " needs an authenticated session.");
        return undefined;
      }
      var request;
      try { request = read(parsed.args, literalBody); }
      catch (refusal) {
        _imapTagged(socket, tag, "BAD " + _imapReason(refusal, verb + " could not be read."));
        return undefined;
      }
      return Promise.resolve()
        .then(function () { return run(state.actor, request); })
        .then(function (outcome) {
          record(state, outcome, null);
          if (settle) settle(state, outcome);
          _imapTagged(socket, tag, "OK " + verb + " completed");
        })
        .catch(function (failure) {
          record(state, null, failure);
          if (settleFailed) settleFailed(state, request, failure);
          // Only a refusal this server wrote is quoted back. Anything
          // else reaching here came from the volume underneath, and its
          // text names the tables and columns this server keeps, which is
          // a description of the schema written to whoever asked for a
          // mailbox. The client is told the command failed; the row the
          // record above wrote tells the operator why.
          var code = IMAP_MAILBOX_CODES[failure && failure.code];
          if (code === undefined) {
            _imapTagged(socket, tag, "NO " + verb + " could not be completed.");
            return;
          }
          _imapTagged(socket, tag, "NO [" + code + "] " + _imapReason(failure, verb + " failed."));
        });
    };
  }

  // What a refused namespace verb puts on its audit row.
  //
  // The message is the text as the layer underneath wrote it, for the
  // operator alone: a failure the handler has no response code for is one
  // it cannot describe on the wire, and the row is then the only record
  // of what it was. The counts are a refused DELETE's: how much it
  // destroyed before it reached the message it could not, and how much it
  // kept. This is the row an operator reads when somebody asks why a
  // mailbox is half empty.
  function _imapVerbRefusal(verb, failure) {
    return {
      reason:    String((failure && failure.code) || "unknown"),
      message:   _imapReason(failure, verb + " failed."),
      destroyed: failure && typeof failure.destroyed === "number" ? failure.destroyed : null,
      kept:      failure && typeof failure.kept === "number" ? failure.kept : null,
    };
  }

  var _imapCreate = _imapNamespaceHandler("CREATE", _imapCreateRequest,
    function (actor, request) { return _sessionStore().createFolder(actor, request.mailbox); },
    function (state, made, failure) {
      b.audit.safeEmit({
        action:   failure ? "blamepost.mail.listeners.imap_create_refused"
                          : "blamepost.mail.listeners.imap_create",
        outcome:  failure ? "denied" : "success",
        actor:    _imapActor(state),
        metadata: failure ? _imapVerbRefusal("CREATE", failure)
                          : { mailbox: made.name, levels: (made.created || []).length },
      });
    });

  // DELETE (RFC 9051 section 6.3.5). The mailbox goes and its mail goes
  // with it, through the one delete path on this server, so a message a
  // preservation order or the retention window keeps stops the removal
  // and the mailbox is still there holding it.
  var _imapDelete = _imapNamespaceHandler("DELETE",
    function (args, literalBody) {
      return _imapNamedMailboxRequest("DELETE", args, literalBody);
    },
    function (actor, request) { return _sessionStore().deleteFolder(actor, request.mailbox); },
    function (state, removed, failure) {
      b.audit.safeEmit({
        action:   failure ? "blamepost.mail.listeners.imap_delete_refused"
                          : "blamepost.mail.listeners.imap_delete",
        outcome:  failure ? "denied" : "success",
        actor:    _imapActor(state),
        metadata: failure ? _imapVerbRefusal("DELETE", failure)
                          : { mailbox: removed.name, destroyed: removed.destroyed },
      });
    },
    _imapFollowDelete,
    function (state, request, failure) {
      // A DELETE refused over a message something keeps has already
      // destroyed the ones before it, so the sequence numbers a session
      // holding the mailbox has are stale.
      if (failure && failure.code === "mailbox/mailbox-preserved" && failure.destroyed > 0) {
        _imapCloseSelectionsOf(state, request.mailbox,
          "messages were removed from the selected mailbox, so select it again");
      }
    });

  // RENAME (RFC 9051 section 6.3.6). The inferior names move with the
  // name above them and the superior levels the new name needs are
  // created, except for INBOX, which the section gives its own rule: the
  // messages move and INBOX itself stays.
  var _imapRename = _imapNamespaceHandler("RENAME", _imapRenameRequest,
    function (actor, request) {
      return _sessionStore().renameFolder(actor, request.from, request.to);
    },
    function (state, moved, failure) {
      b.audit.safeEmit({
        action:   failure ? "blamepost.mail.listeners.imap_rename_refused"
                          : "blamepost.mail.listeners.imap_rename",
        outcome:  failure ? "denied" : "success",
        actor:    _imapActor(state),
        metadata: failure ? _imapVerbRefusal("RENAME", failure)
                          : { from: moved.from, to: moved.to, mailboxes: moved.moved,
                              levels: (moved.created || []).length },
      });
    },
    _imapFollowRename,
    function (state, request, failure) {
      // A RENAME of INBOX that stopped partway has moved some of its
      // messages out, so the sequence numbers a session holding INBOX
      // has are stale.
      if (failure && failure.code === "mailbox/rename-incomplete") {
        _imapCloseSelectionsOf(state, "INBOX",
          "messages were moved out of INBOX, so select it again");
      }
    });

  // A rename moves the mailbox and every inferior name under it, and the
  // identifiers travel with them, so a session holding one open is holding
  // the thing that moved. The selected state names it, so the name is
  // rewritten here: the mailbox itself when it is the one that moved, and
  // a descendant by replacing the moved prefix.
  //
  // Renaming INBOX is the exception RFC 9051 section 6.3.6 carves out. The
  // messages move to the new mailbox and INBOX itself stays where it is,
  // so a session selected on INBOX is still selected on INBOX and its name
  // is not rewritten.
  function _imapRenamedSelection(selected, from, to) {
    if (typeof selected !== "string" || selected.length === 0) return null;
    if (from.toUpperCase() === "INBOX") return null;
    if (selected === from) return to;
    if (selected.indexOf(from + IMAP_DELIMITER) === 0) {
      return to + selected.slice(from.length);
    }
    return null;
  }

  // Every session of the account follows, not only the one that sent
  // the RENAME: another session holding the mailbox open resolves it by
  // the same name.
  //
  // Renaming INBOX moves its messages out and leaves INBOX in place, so a
  // session holding INBOX open holds sequence numbers that name nothing.
  // It leaves the selected state, is told so, and the client selects
  // INBOX again.
  function _imapFollowRename(state, moved) {
    if (!moved || typeof moved.from !== "string" || typeof moved.to !== "string") return;
    var sessions = _imapSelectedSessionsOf(state);
    var inbox = moved.from.toUpperCase() === "INBOX";
    for (var i = 0; i < sessions.length; i += 1) {
      if (inbox) {
        if (typeof sessions[i].selectedMailbox === "string" &&
            sessions[i].selectedMailbox.toUpperCase() === "INBOX") {
          _imapCloseSelection(sessions[i], state,
            "INBOX was renamed and its messages moved, so select it again");
        }
        continue;
      }
      _imapFollowRenameIn(sessions[i], moved.from, moved.to);
    }
  }

  function _imapFollowRenameIn(session, from, to) {
    var next = _imapRenamedSelection(session.selectedMailbox, from, to);
    if (next === null) return;
    session.selectedMailbox = next;
    // The write grant is held beside the name and read back by comparing
    // names, so it moves in the same step. Leaving it on the old name
    // would keep a grant alive against a name anything may create again.
    var selection = session.actor ? imapSelections.get(session.actor) : undefined;
    if (selection !== undefined) {
      imapSelections.set(session.actor, { mailbox: next, readOnly: selection.readOnly });
    }
  }

  // A delete removes the mailbox outright, so there is nothing for the
  // selection to follow and the session leaves the selected state. The
  // inferior names of a deleted mailbox stay where they are, so only the
  // name that went is dropped and a session holding a child keeps it.
  //
  // Leaving the name selected would be worse than leaving it pointing at
  // nothing: the name is free for anything to create again, and the
  // selected state is read back by comparing names, so the session would
  // be handed a mailbox it never opened.
  // Ends every selection of `name` held by the account `state` belongs
  // to. INBOX matches in any case.
  function _imapCloseSelectionsOf(state, name, why) {
    if (typeof name !== "string" || name.length === 0) return;
    var inbox = name.toUpperCase() === "INBOX";
    var sessions = _imapSelectedSessionsOf(state);
    for (var i = 0; i < sessions.length; i += 1) {
      var held = sessions[i].selectedMailbox;
      if (typeof held !== "string") continue;
      if (inbox ? held.toUpperCase() === "INBOX" : held === name) {
        _imapCloseSelection(sessions[i], state, why);
      }
    }
  }

  function _imapFollowDelete(state, removed) {
    if (!removed || typeof removed.name !== "string") return;
    var sessions = _imapSelectedSessionsOf(state);
    for (var i = 0; i < sessions.length; i += 1) {
      if (sessions[i].selectedMailbox === removed.name) {
        _imapCloseSelection(sessions[i], state, "the selected mailbox was deleted");
      }
    }
  }

  var _imapSubscribe = _imapNamespaceHandler("SUBSCRIBE",
    function (args, literalBody) {
      return _imapNamedMailboxRequest("SUBSCRIBE", args, literalBody);
    },
    function (actor, request) { return _sessionStore().subscribeFolder(actor, request.mailbox); },
    function (state, added, failure) {
      b.audit.safeEmit({
        action:   failure ? "blamepost.mail.listeners.imap_subscribe_refused"
                          : "blamepost.mail.listeners.imap_subscribe",
        outcome:  failure ? "denied" : "success",
        actor:    _imapActor(state),
        metadata: failure ? _imapVerbRefusal("SUBSCRIBE", failure)
                          : { mailbox: added.name, added: added.added },
      });
    });

  var _imapUnsubscribe = _imapNamespaceHandler("UNSUBSCRIBE",
    function (args, literalBody) {
      return _imapNamedMailboxRequest("UNSUBSCRIBE", args, literalBody);
    },
    function (actor, request) {
      return _sessionStore().unsubscribeFolder(actor, request.mailbox);
    },
    function (state, dropped, failure) {
      b.audit.safeEmit({
        action:   failure ? "blamepost.mail.listeners.imap_unsubscribe_refused"
                          : "blamepost.mail.listeners.imap_unsubscribe",
        outcome:  failure ? "denied" : "success",
        actor:    _imapActor(state),
        metadata: failure ? _imapVerbRefusal("UNSUBSCRIBE", failure)
                          : { mailbox: dropped.name, removed: dropped.removed },
      });
    });

  // Whether one entry of the namespace belongs in the answer to this
  // LIST. RFC 9051 section 6.3.9 returns a name that does not exist only
  // when it satisfies the selection criteria or something is filed
  // underneath it, so a name whose mailbox has gone reaches a client
  // either as the parent of what is still there or as one it subscribed
  // to and asked for.
  function _imapListSelects(request, entry) {
    if (request.subscribedOnly && entry.attributes.indexOf("Subscribed") === -1) return false;
    if (entry.exists !== true && !request.subscribedOnly &&
        entry.attributes.indexOf("HasChildren") === -1) {
      return false;
    }
    for (var i = 0; i < request.patterns.length; i += 1) {
      if (_imapNameMatches(request.patterns[i], entry.name)) return true;
    }
    return false;
  }

  // The attributes one listed name carries on the wire. `\Subscribed` is
  // sent when the client asked about the subscribed set, either as the
  // selection option or as the return option, which is what RFC 9051
  // section 6.3.9 attaches it to.
  function _imapListAttributes(request, entry) {
    var out = [];
    for (var i = 0; i < entry.attributes.length; i += 1) {
      if (entry.attributes[i] === "Subscribed" &&
          !request.wantSubscribed && !request.subscribedOnly) {
        continue;
      }
      out.push("\\" + entry.attributes[i]);
    }
    return out;
  }

  // LIST (RFC 9051 section 6.3.9). The framework ships a listing that
  // reads neither the reference nor the pattern and answers every
  // narrowed question with the whole namespace, which a client reads as
  // the answer to the question it asked: a folder pane asking for one
  // level is given every level, and a client asking for the subscribed
  // set is given the unsubscribed ones too.
  //
  // The namespace itself is the mailbox layer's, including which names
  // exist and which are subscribed. This reads it once and decides what
  // to send.
  async function _imapList(state, socket, parsed, literalBody) {
    var tag = parsed.tag;
    if (!state.actor) {
      _imapTagged(socket, tag, "NO LIST needs an authenticated session.");
      return undefined;
    }
    var request;
    try { request = _imapListRequest(parsed.args, literalBody); }
    catch (refusal) {
      _imapTagged(socket, tag, "BAD " + _imapReason(refusal, "LIST could not be read."));
      return undefined;
    }

    // RFC 9051 section 6.3.9: an empty mailbox name asks for the
    // hierarchy separator and the root of the reference, answered with
    // one \Noselect response. The root is the empty string, which the
    // section permits for a non-rooted reference, and every name on this
    // server is non-rooted: there is one namespace per account and no
    // prefix in front of it.
    if (request.rootOnly) {
      _imapUntagged(socket, "LIST (\\Noselect) \"" + IMAP_DELIMITER + "\" \"\"");
      _imapTagged(socket, tag, "OK LIST completed");
      return undefined;
    }

    try {
      var folders = await _sessionStore().listFolders(state.actor);
      for (var i = 0; i < folders.length; i += 1) {
        var entry = folders[i];
        if (!_imapListSelects(request, entry)) continue;
        _imapUntagged(socket, "LIST (" + _imapListAttributes(request, entry).join(" ") + ") \"" +
          IMAP_DELIMITER + "\" " + b.safeBuffer.quoteString(entry.name));
        // RFC 9051 section 6.3.9 puts the STATUS return option's answer
        // in an untagged STATUS response of its own, read through the
        // same verb the STATUS command is answered from. A name that
        // does not exist has no counts, and section 6.3.9 asks for none.
        if (!request.wantStatus || entry.exists !== true) continue;
        var info = await _sessionStore().statusFolder(state.actor, entry.name,
          request.statusItems);
        var parts = [];
        for (var k = 0; k < request.statusItems.length; k += 1) {
          if (info[request.statusItems[k]] === undefined) continue;
          parts.push(request.statusItems[k] + " " + info[request.statusItems[k]]);
        }
        _imapUntagged(socket, "STATUS " + b.safeBuffer.quoteString(entry.name) +
          " (" + parts.join(" ") + ")");
      }
      _imapTagged(socket, tag, "OK LIST completed");
    } catch (failure) {
      var code = IMAP_MAILBOX_CODES[failure && failure.code];
      b.audit.safeEmit({
        action:   "blamepost.mail.listeners.imap_list_refused",
        outcome:  "denied",
        actor:    _imapActor(state),
        metadata: {
          reason:  String((failure && failure.code) || "unknown"),
          message: _imapReason(failure, "LIST failed."),
        },
      });
      if (code === undefined) {
        _imapTagged(socket, tag, "NO LIST could not be completed.");
        return undefined;
      }
      _imapTagged(socket, tag, "NO [" + code + "] " + _imapReason(failure, "LIST failed."));
    }
    return undefined;
  }

  // CLOSE (RFC 9051 section 6.4.1). From a read-write session it removes
  // every message flagged `\Deleted` through the same delete path EXPUNGE
  // takes, so a message under legal hold or inside the retention floor
  // stays, and it sends no untagged EXPUNGE. From a read-only session it
  // removes nothing. Either way the session returns to the Authenticated
  // state, including when the removal fails.
  function _imapClose(state, socket, parsed) {
    var tag = parsed.tag;
    if (!state.actor) {
      _imapTagged(socket, tag, "NO CLOSE needs an authenticated session.");
      return undefined;
    }
    if (!state.selectedMailbox) {
      _imapTagged(socket, tag, "BAD CLOSE is a Selected state command (RFC 9051 section " +
        "6.4.1); no mailbox is selected.");
      return undefined;
    }
    var mailboxName = state.selectedMailbox;
    var writable = _imapWritableSelection(state.actor, mailboxName);
    _imapDeselect(state);
    if (!writable) {
      _imapTagged(socket, tag, "OK CLOSE completed");
      return undefined;
    }
    return Promise.resolve()
      .then(function () { return _sessionStore().expungeFolder(state.actor, mailboxName); })
      .then(function (outcome) {
        b.audit.safeEmit({
          action:   "blamepost.mail.listeners.imap_close",
          outcome:  "success",
          actor:    _imapActor(state),
          metadata: {
            mailbox: mailboxName,
            removed: ((outcome && outcome.expunged) || []).length,
            kept:    ((outcome && outcome.refused) || []).length,
          },
        });
        _imapTagged(socket, tag, "OK CLOSE completed");
      })
      .catch(function (failure) {
        b.audit.safeEmit({
          action:   "blamepost.mail.listeners.imap_close",
          outcome:  "failure",
          actor:    _imapActor(state),
          metadata: { mailbox: mailboxName, reason: _imapReason(failure, "CLOSE failed.") },
        });
        _imapTagged(socket, tag, "NO CLOSE " + _imapReason(failure, "failed."));
      });
  }

  // ENABLE (RFC 5161). CONDSTORE is the one extension here a client can
  // enable. Anything else is ignored, as section 3.1 requires, and the
  // ENABLED response lists only what this command turned on.
  function _imapEnable(state, socket, parsed) {
    var tag = parsed.tag;
    if (!state.actor) {
      _imapTagged(socket, tag, "BAD ENABLE is an Authenticated state command (RFC 5161 " +
        "section 3.1); authenticate first.");
      return undefined;
    }
    var requested = String(parsed.args || "").split(/\s+/).filter(Boolean);
    if (requested.length === 0) {
      _imapTagged(socket, tag, "BAD ENABLE names at least one extension (RFC 5161 section 4).");
      return undefined;
    }
    var enabled = [];
    for (var i = 0; i < requested.length; i += 1) {
      if (requested[i].toUpperCase() === "CONDSTORE" && state.enabledCondStore !== true) {
        state.enabledCondStore = true;
        enabled.push("CONDSTORE");
      }
    }
    _imapUntagged(socket, "ENABLED" + (enabled.length > 0 ? " " + enabled.join(" ") : ""));
    _imapTagged(socket, tag, "OK ENABLE completed");
    return undefined;
  }

  // IDLE (RFC 2177). The listener reads DONE and cancels the ceiling
  // itself. The ceiling is also canceled when the connection closes, and
  // it does not hold the process open.
  var imapIdleWatched = new WeakSet();

  function _imapIdle(state, socket, parsed) {
    var tag = parsed.tag;
    if (!state.actor) {
      _imapTagged(socket, tag, "NO IDLE needs an authenticated session.");
      return undefined;
    }
    try { socket.write("+ idling\r\n"); }
    catch (_e) { /* drop-silent by design: the client is already gone */ }
    var ceiling = setTimeout(function () {
      if (!state.idle || state.idle.timer !== ceiling) return;
      state.idle = null;
      _imapUntagged(socket, "BYE IDLE ran for " + (IMAP_IDLE_CEILING_MS / TIME.minutes(1)) +
        " minutes without DONE");
      try { socket.destroy(); }
      catch (_e) { /* drop-silent by design: the client is already gone */ }
    }, IMAP_IDLE_CEILING_MS);
    if (typeof ceiling.unref === "function") ceiling.unref();
    state.idle = { tag: tag, timer: ceiling };
    if (!imapIdleWatched.has(socket)) {
      imapIdleWatched.add(socket);
      socket.once("close", function () {
        if (state.idle && state.idle.timer) clearTimeout(state.idle.timer);
        state.idle = null;
      });
    }
    return undefined;
  }

  // The framework's capability list without the extensions this server
  // does not serve.
  function _imapCapabilities(caps) {
    return caps.filter(function (name) {
      return !Object.prototype.hasOwnProperty.call(IMAP_UNSERVED_EXTENSIONS,
        String(name).toUpperCase());
    });
  }

  function _buildImap() {
    return b.mail.server.imap.create(_tlsOption({
      greeting:       hostname + " IMAP4rev2 blamepost",
      profile:        profile,
      // Accounts only. A sending credential speaks for a whole hosted
      // domain, so one accepted here would SELECT and FETCH every
      // mailbox in that domain.
      auth:           _authConfig(AUTH_SURFACES.MAILBOX),
      rateLimit:      limits.rateLimit,
      maxConnections: MAX_CONNECTIONS,
      maxLineBytes:   wanted.imap.maxLineBytes,
      // A literal larger than the message ceiling is refused on its
      // announcement, before any of its octets are read. An APPEND is the
      // largest thing a literal carries, and the message store refuses a
      // message over this ceiling at the append in any case.
      maxLiteralBytes: limits.maxMessageBytes,
      mailStore:      _imapMailStore(),
      capabilities:   _imapCapabilities,
      // SEARCH. The framework ships a default that answers `NO SEARCH
      // not configured`, because a search expression is a question
      // about the messages an application stores rather than about the
      // protocol. Left unwired, every IMAP client's search is dead
      // while the same account's search works over JMAP and in the
      // browser. The override rides the framework's own dispatch
      // registry, so the wire guard, the per handler ceiling and the
      // audit row in front of every other verb stay in front of this
      // one. The six after it are described above `_imapMailboxArgument`.
      overrides: {
        SEARCH: {
          fn:              _imapSearch,
          maxHandlerBytes: SEARCH_HANDLER_BYTES,
          maxHandlerMs:    SEARCH_HANDLER_MS,
        },
        SELECT: {
          fn:              _imapSelectHandler(false),
          maxHandlerBytes: IMAP_SELECT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SELECT_HANDLER_MS,
        },
        EXAMINE: {
          fn:              _imapSelectHandler(true),
          maxHandlerBytes: IMAP_SELECT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SELECT_HANDLER_MS,
        },
        CREATE: {
          fn:              _imapCreate,
          maxHandlerBytes: IMAP_CREATE_HANDLER_BYTES,
          maxHandlerMs:    IMAP_CREATE_HANDLER_MS,
        },
        DELETE: {
          fn:              _imapDelete,
          maxHandlerBytes: IMAP_WRITE_HANDLER_BYTES,
          maxHandlerMs:    IMAP_WRITE_HANDLER_MS,
        },
        RENAME: {
          fn:              _imapRename,
          maxHandlerBytes: IMAP_WRITE_HANDLER_BYTES,
          maxHandlerMs:    IMAP_WRITE_HANDLER_MS,
        },
        SUBSCRIBE: {
          fn:              _imapSubscribe,
          maxHandlerBytes: IMAP_SHORT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SHORT_HANDLER_MS,
        },
        UNSUBSCRIBE: {
          fn:              _imapUnsubscribe,
          maxHandlerBytes: IMAP_SHORT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SHORT_HANDLER_MS,
        },
        LIST: {
          fn:              _imapList,
          maxHandlerBytes: IMAP_SELECT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SELECT_HANDLER_MS,
        },
        CLOSE: {
          fn:              _imapClose,
          maxHandlerBytes: IMAP_CLOSE_HANDLER_BYTES,
          maxHandlerMs:    IMAP_CLOSE_HANDLER_MS,
        },
        ENABLE: {
          fn:              _imapEnable,
          maxHandlerBytes: IMAP_SHORT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_SHORT_HANDLER_MS,
        },
        IDLE: {
          fn:              _imapIdle,
          maxHandlerBytes: IMAP_SHORT_HANDLER_BYTES,
          maxHandlerMs:    IMAP_IDLE_HANDLER_MS,
        },
      },
    }));
  }

  // RFC 1939 section 3 leases a maildrop to one session, and the two
  // reports below are how the store hears about that session's life.
  //
  // The activity report arrives for every command, NOOP included. The
  // listener answers NOOP by itself, so the store never sees the
  // keepalive the protocol gives a client, and a lease aged on the
  // store's own reading would reclaim a maildrop under a connection that
  // is still using it.
  //
  // The ending arrives once, however the session ended: a QUIT, the
  // listener's autologout, or a link that dropped without either. It is
  // the release. Without it the only release is the store's idle window,
  // which cannot tell a finished session from a slow one and leaves an
  // account holder locked out of their own mailbox for as long as it
  // runs after a network blip.
  //
  // The listener reports the ending after the session's store work has
  // settled, so a QUIT has already applied its marks through
  // `commitPop3Drop` by the time the release runs and there is nothing
  // left for it to find. A session that ended any other way leaves its
  // marks unapplied, which is what RFC 1939 section 6 says happens to
  // them.
  //
  // Both run as consumer hooks, so a throw here is recorded by the
  // listener as a failed hook and dropped rather than reaching the
  // teardown that called it. A store that cannot carry them stops the
  // boot where the POP3 listener is built instead, because a listener
  // composed over one would run on the idle window alone and nothing
  // would say so.
  function _pop3SessionActivity(actor) {
    mailStore.touchPop3Drop(actor);
  }

  function _pop3SessionEnd(actor) {
    mailStore.releasePop3Drop(actor);
  }

  function _buildPop3() {
    // Both names are in the sentence and the absent ones are named again,
    // because a caller who mistyped one hook and a caller who wired
    // neither are different mistakes with different fixes, and a refusal
    // that reads the same for both leaves the first one rereading their
    // own adapter to work out which half it means.
    var missingLeaseHooks = [];
    if (typeof mailStore.touchPop3Drop !== "function") missingLeaseHooks.push("touchPop3Drop");
    if (typeof mailStore.releasePop3Drop !== "function") missingLeaseHooks.push("releasePop3Drop");
    if (missingLeaseHooks.length > 0) {
      throw new TypeError("blamepost.mail.listeners: the POP3 listener needs a mailStore " +
        "exposing touchPop3Drop(actor) and releasePop3Drop(actor), and this one does not " +
        "expose " + missingLeaseHooks.join(" or ") + ". RFC 1939 section 3 leases " +
        "a maildrop to one session, and those are what report the session's activity and its " +
        "ending to whatever holds the lease. Pass the adapter blamepost.mail.mailbox.create " +
        "returns, or turn the POP3 listener off.");
    }
    return b.mail.server.pop3.create(_tlsOption({
      greeting:       hostname + " POP3 blamepost",
      profile:        profile,
      // Accounts only, and this is the listener where accepting a
      // credential would cost the most: RFC 1939 section 6 has a session
      // download the maildrop and mark it deleted on QUIT.
      auth:           _authConfig(AUTH_SURFACES.MAILBOX),
      rateLimit:      limits.rateLimit,
      maxConnections: MAX_CONNECTIONS,
      maxLineBytes:   wanted.pop3.maxLineBytes,
      mailStore:      _sessionStore(),
      // The two lease reports go to the adapter itself rather than to the
      // gated copy, and they are the only calls that do. Neither is a
      // client asking for anything: the activity report keeps a maildrop
      // from being reclaimed under a live connection and the ending is
      // the release, so refusing them once the account leaves service
      // would hold the lease open on a mailbox nobody may reach.
      onSessionActivity: _pop3SessionActivity,
      onSessionEnd:      _pop3SessionEnd,
    }));
  }

  function _buildManageSieve() {
    return b.mail.server.managesieve.create(_tlsOption({
      greeting:       hostname + " ManageSieve blamepost",
      profile:        profile,
      // Accounts only. A credential accepted here would rewrite the
      // filters that decide where every account in the domain files its
      // mail, including a filter that discards it.
      auth:           _authConfig(AUTH_SURFACES.MAILBOX),
      rateLimit:      limits.rateLimit,
      maxConnections: MAX_CONNECTIONS,
      maxLineBytes:   wanted.managesieve.maxLineBytes,
      mailStore:      _sessionStore(),
    }));
  }

  var BUILDERS = {
    imap:        function () { return _buildImap(); },
    pop3:        function () { return _buildPop3(); },
    managesieve: function () { return _buildManageSieve(); },
    submission:  function () { return _buildSubmission(false); },
    submissions: function () { return _buildSubmission(true); },
  };

  // ---- Lifecycle ----------------------------------------------------------

  function _dnsAcknowledged() {
    return config.dnsAcknowledged === true;
  }

  // The domains this server accepts mail for, each with the posture the
  // operator has confirmed for it. Only the active ones: a domain the
  // operator disabled should have its mail refused at RCPT with a relay
  // denial rather than accepted and then bounced.
  //
  // A row carrying no acknowledgement reads as unacknowledged. The gate
  // below is a refusal to collect mail nobody downstream can
  // authenticate, so the absence of an answer is not a yes.
  //
  // Each name is DERIVED rather than folded here, through the one
  // derivation every other surface reads a domain through. The framework
  // takes this set once at construction and matches every recipient
  // against it with an `indexOf`, so whatever spelling reaches it is the
  // spelling port 25 requires a peer to have written. A case fold alone
  // agrees with the derivation on three of the four spellings of every
  // name and drops the DNS root's trailing dot on the floor. A row
  // carrying that dot, whether from a restore, from a caller that
  // reached the store directly, or from a write path added later, would
  // leave this listener refusing mail for a domain the console, the
  // command line and the signer all call hosted. The refusal is
  // `550 5.7.1 Relaying denied`, which says the domain is somebody
  // else's, and nothing upstream of the wire can see it happen.
  //
  // A row that cannot be read as a name at all stops the boot instead of
  // being folded into something. It got there by a route that skipped
  // every guard, this set is what every recipient is measured against,
  // and a listener that quietly dropped it would refuse that domain's
  // mail for as long as nobody looked.
  async function _activeDomains() {
    var rows = await store.domains.list();
    if (!Array.isArray(rows)) {
      throw new TypeError("blamepost.mail.listeners.start: store.domains.list() must resolve " +
        "to an array of the domains this server hosts");
    }
    return rows
      .filter(function (row) {
        return typeof row === "string" || row.status === undefined || row.status === "active";
      })
      .map(function (row) {
        var written = typeof row === "string" ? row : row.domain;
        var name = storeAddress.parseDomain(written);
        if (!name.ok) {
          throw new TypeError("blamepost.mail.listeners.start: the store lists " +
            JSON.stringify(String(written)) + " among the domains this server hosts, and it " +
            "is not a usable domain name (" + name.reason + "). Every recipient port 25 sees " +
            "is measured against this set, so a name that cannot be read leaves that domain's " +
            "mail refused as somebody else's. Take the row out with `blamepost domain remove` " +
            "and add the domain again.");
        }
        return {
          domain:          name.domain,
          dnsAcknowledged: row.dnsAcknowledged === true,
        };
      });
  }

  /**
   * @primitive blamepost.mail.listeners.start
   * @signature listeners.start()
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: ordered boot with a DNS posture gate)
   * @related   blamepost.mail.listeners.create, blamepost.mail.listeners.stop
   *
   * Bring the listeners up in order behind `b.bootGates`. The DNS
   * posture gate runs first and refuses the whole sequence when the MX
   * listener is enabled and either the server or one of its active
   * domains has an unacknowledged posture; the refusal names the
   * domains it is waiting on. Each bind is its own gate, so a port
   * already in use names the listener that could not take it rather
   * than a bare operating system error.
   *
   * A failure anywhere closes whatever already bound before the error
   * reaches the caller. There is no partially started state to reason
   * about afterwards.
   *
   * @example
   *   await listeners.start();
   */
  async function start() {
    var activeDomains = await _activeDomains();
    var localDomains = activeDomains.map(function (row) { return row.domain; });
    var gates = [];
    gates.push({
      name: "dns.posture",
      fn: function () {
        if (!wanted.mx.enabled) return;
        if (!_dnsAcknowledged()) {
          throw new Error("The MX listener will not bind until the DNS records in " +
            "docs/operator-guide.md exist for every hosted domain: MX, SPF ending in -all, " +
            "DMARC at p=quarantine or stronger, the DKIM selector records this server " +
            "prints, MTA-STS, and TLS-RPT. Set BLAMEPOST_DNS_ACKNOWLEDGED=1 once they " +
            "are live, then run `blamepost doctor` to check them against what this " +
            "server expects.");
        }
        // The process wide setting is a statement about the server the
        // day it was made. It says nothing about a domain added
        // afterwards, and a domain whose records are not published yet
        // is exactly the one whose mail nobody can authenticate, so
        // each hosted domain carries its own acknowledgement.
        var pending = activeDomains
          .filter(function (row) { return row.dnsAcknowledged !== true; })
          .map(function (row) { return row.domain; });
        if (pending.length > 0) {
          throw new Error("The MX listener will not bind while a hosted domain has no " +
            "acknowledged DNS posture. Waiting on: " + pending.join(", ") + ". Publish the " +
            "records in docs/operator-guide.md for each of them, then record it with " +
            "`blamepost domain acknowledge <domain> --by <who>`. " +
            "BLAMEPOST_DNS_ACKNOWLEDGED covers the server, not a domain added after it " +
            "was set.");
        }
      },
    });

    START_ORDER.forEach(function (name) {
      if (!wanted[name].enabled) return;
      // Port 25 stays shut while this server hosts nothing.
      //
      // An MX listener exists to put mail into mailboxes here, and with
      // no hosted domain there is no address that resolves to one. Every
      // recipient a peer could name is a stranger's, so the listener a
      // build over an empty set produces is one that refuses every
      // recipient at RCPT with a permanent code. It is a correct
      // listener; the trouble is what it does to mail rather than what
      // it does to a relay probe. A peer refused permanently stops
      // trying and reports back to its own sender, so mail arriving in
      // the window between the MX record going live and the first domain
      // being added is bounced rather than held. A port that is not
      // listening is a connection refused, which senders treat as
      // temporary and retry against until the domain exists.
      //
      // Refused here rather than by failing the boot, because a server
      // with no domain yet is an ordinary first boot rather than a
      // misconfiguration. An operator starts the server and then runs
      // `blamepost init`, which opens the data directory directly and
      // needs nothing listening, so failing the boot would leave the
      // browser surface down during the one step that creates the first
      // domain. The mailbox listeners and the browser surface come up;
      // the one listener that cannot do its job does not.
      //
      // It is said three times, because the three readers are different.
      // The log line is what an operator watching the first boot sees,
      // the audit row is what answers the question afterwards when the
      // symptom is mail that never arrived, and the record kept here is
      // what the health probes report while it lasts. All three read one
      // sentence rather than three copies of it, because a reason that
      // is worded differently in the place an operator looks is a reason
      // they have to work out is the same reason.
      //
      // Not at error level. This is the ordinary first boot the quick
      // start puts every operator through, and a start that logs a
      // failure for the state it was designed to reach teaches the
      // operator that this server's failures are not worth reading.
      if (name === "mx" && localDomains.length === 0) {
        var why = "this server hosts no domain, so every recipient a peer could name " +
          "would be a stranger's and none of them resolves to a mailbox here. Add a " +
          "domain with `blamepost init` or `blamepost domain add <domain>`, acknowledge " +
          "its DNS posture with `blamepost domain acknowledge <domain> --by <who>`, and " +
          "start the server again.";
        withheld[name] = why;
        log.warn("port " + wanted.mx.port + " is not bound: " + why);
        b.audit.safeEmit({
          action:   "blamepost.mail.listeners.mx_unbound_no_hosted_domain",
          outcome:  "denied",
          metadata: { port: wanted.mx.port, address: wanted.mx.address },
        });
        return;
      }
      gates.push({
        name: "listener." + name,
        fn: async function () {
          var handle = name === "mx" ? _buildMx(localDomains) : BUILDERS[name]();
          var listening = await handle.listen({
            port:    wanted[name].port,
            address: wanted[name].address,
          });
          handles[name] = handle;
          boundPorts[name] = listening && listening.port ? listening.port : wanted[name].port;
        },
      });
    });

    // The gate runner reports a failure by calling its exit hook. A
    // library must not end the process, so the hook is a no operation
    // and the failure is rethrown here instead, carrying the gate's own
    // error rather than a generic one. Without this the caller would
    // see a message about a missing exit handler and learn nothing
    // about which gate refused or why.
    var failure = null;
    gates.forEach(function (gate) {
      gate.onFail = function (err) { failure = err; };
    });
    var outcome;
    try {
      outcome = await b.bootGates.run(gates, {
        exit: function () { /* the failure is rethrown below */ },
        log:  function (line) {
          try {
            b.audit.safeEmit({
              action:   "blamepost.mail.listeners.boot_failed",
              outcome:  "failure",
              metadata: { line: line },
            });
          } catch (_e) { /* drop-silent by design */ }
        },
      });
    } catch (err) {
      await stop({ timeoutMs: TIME.seconds(5) });
      throw err;
    }
    if (outcome && outcome.failed) {
      await stop({ timeoutMs: TIME.seconds(5) });
      throw failure || new Error("blamepost.mail.listeners.start: the '" + outcome.failed +
        "' gate refused and gave no reason");
    }
    return outcome;
  }

  /**
   * @primitive blamepost.mail.listeners.stop
   * @signature listeners.stop(opts?)
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: bounded drain on shutdown)
   * @related   blamepost.mail.listeners.start
   *
   * Close every bound listener in the reverse of the start order, with
   * a deadline. Inbound mail stops first so nothing new arrives while
   * mailbox sessions finish. A listener that will not close inside the
   * deadline is reported and the drain continues, because one wedged
   * connection must not prevent the rest of the shutdown.
   *
   * @opts
   *   timeoutMs: number,   // per listener deadline; default twenty seconds
   *
   * @example
   *   await listeners.stop({ timeoutMs: 15000 });
   */
  async function stop(stopOpts) {
    stopOpts = stopOpts || {};
    var timeoutMs = stopOpts.timeoutMs === undefined ? DEFAULT_DRAIN_MS : stopOpts.timeoutMs;
    var order = START_ORDER.slice().reverse();
    var closed = [];
    for (var i = 0; i < order.length; i += 1) {
      var name = order[i];
      if (!handles[name]) continue;
      try {
        // The third argument is an options object, not an error. Passing
        // an Error puts its `name` property into the timeout message,
        // and every Error is named "Error", so a wedged listener would
        // be reported without saying which one it was.
        await b.safeAsync.withTimeout(
          Promise.resolve(handles[name].close({ timeoutMs: timeoutMs })),
          timeoutMs,
          { name: "listener " + name }
        );
        closed.push(name);
      } catch (err) {
        // Shutdown observability. Reporting and continuing is the whole
        // point: the alternative leaves the remaining listeners bound
        // and the supervisor with no option but a hard kill.
        try {
          b.audit.safeEmit({
            action:   "blamepost.mail.listeners.drain_incomplete",
            outcome:  "failure",
            metadata: {
              listener: name,
              error:    displayText.forDisplay((err && err.message) || String(err)),
            },
          });
        } catch (_e) {
          // allow:swallow-unverified the audit sink is the reporting path
          // itself and swallows inside safeEmit, and this runs during the
          // drain, where a throw would leave the remaining listeners bound.
        }
      }
      delete handles[name];
      delete boundPorts[name];
    }
    return { closed: closed };
  }

  /**
   * @primitive blamepost.mail.listeners.bound
   * @signature listeners.bound()
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: runtime listener inventory)
   * @related   blamepost.mail.listeners.describe
   *
   * The listeners that are actually bound right now and the ports they
   * took. An ephemeral bind reports the port the operating system
   * chose, which is what a test needs in order to connect.
   *
   * @example
   *   listeners.bound();   // { mx: 25, submission: 587, imap: 143 }
   */
  function bound() {
    return Object.assign({}, boundPorts);
  }

  /**
   * @primitive blamepost.mail.listeners.describe
   * @signature listeners.describe()
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: configured posture for doctor and the admin UI)
   * @related   blamepost.mail.listeners.bound
   *
   * What this server is configured to run, whether or not it is
   * running. `blamepost doctor` compares this against live DNS, and the
   * admin UI renders it, so the answer describes intent rather than
   * current state.
   *
   * @example
   *   listeners.describe().hostname;   // "mx.example.com"
   */
  function describe() {
    return {
      hostname:        hostname,
      profile:         profile,
      dnsAcknowledged: _dnsAcknowledged(),
      mechanisms:      SASL_MECHANISMS.slice(),
      listeners:       JSON.parse(JSON.stringify(wanted)),
      // Every ceiling the listeners are running, whether the operator
      // named it or left it alone. A field they left alone is reported
      // at the value governing it, which is this server's own and is
      // written down in lib/config rather than being whatever the
      // framework currently defaults to, so reporting it states a fact
      // about this server. An operator asking `doctor` which ceilings
      // they are running gets all of them.
      limits:          Object.assign({}, limits.rateLimit,
        { maxMessageBytes: limits.maxMessageBytes }),
      // No relay posture is reported, because there is none to report.
      // A key here holding an empty list would read as a capability
      // switched off rather than as one the server does not have, and
      // `doctor` and the admin surface would both render it as a knob.
      bound:           bound(),
      // The listeners this server decided against binding, each against
      // the reason it decided. Reported beside `bound` rather than
      // folded into it, because a reader holding both can tell a port
      // that is deliberately shut from one that should be open and is
      // not, and a reader holding only `bound` cannot tell them apart at
      // all.
      withheld:        Object.assign({}, withheld),
    };
  }

  return {
    start:    start,
    stop:     stop,
    bound:    bound,
    describe: describe,
    // The outbound handle with this server's own recipients routed to
    // mailboxes here. Handed to every surface that sends on an account's
    // behalf, so the browser and JMAP answer "where does this recipient
    // go" the way the submission listener answers it.
    relay:    relayHandle,
    // The author binding this listener applies to every message it
    // accepts. Handed to the composer for the same reason the relay is:
    // a surface that answers "may this account write this From" for
    // itself is a second answer, and the first configuration where the
    // two disagree is the one where a message leaves signed under a
    // hosted domain over a name its sender does not hold.
    authorBinding: authorBinding,
    // The rest of what this listener asks of a sending credential once
    // the binding has passed: whether it still stands, and its two send
    // ceilings. Handed to the composer beside the binding, in the order
    // the wire runs them, so the browser port's sending route spends the
    // same window at the same step rather than counting a message the
    // binding is about to refuse.
    sendingCredentialGate: sendingCredentialGate,
  };
}

module.exports = {
  create:        create,
  compileSearch: compileSearch,
  // The addresses an account may write as an author, exposed so a
  // surface that offers the account a choice of identity offers the
  // same set the wire will accept. A second computation of it would be
  // an interface offering an address the listener then refuses.
  permittedAuthors: permittedAuthors,
  // Whether ONE address is one an identity may write, which is the
  // decision every enforcement reader asks and the only form of the
  // question a domain-scoped sending credential can answer. Exported
  // beside the list above rather than instead of it: the list is what a
  // surface offering a choice of identity renders, and it is empty for a
  // credential, so a surface that made its decision from the list would
  // refuse a credential every address in the domain it exists to write.
  permittedAuthor: permittedAuthor,
  // RFC 8601 §5, applied against the same reading of a header that every
  // consumer of one uses. Exported so a surface that files a message
  // without reaching the delivery funnel can compose the one screen
  // rather than write a second reading of which headers claim this
  // server's name, and so the removal can be driven directly for the
  // spellings a wire test cannot reach.
  screenReceiverVerdicts: screenReceiverVerdicts,
  // The entry point for the sending-credential identity space, and the
  // one place its failure budget is read and spent. Exported rather than
  // held inside the listener because the browser port carries the same
  // identity on a second transport, and a transport that reached the
  // registry itself would verify the same secret with no budget behind
  // it. The bound the other transport enforces would then be one an
  // attacker walks around by choosing the transport that lacks it.
  verifySendingCredential: verifySendingCredential,
  // Every refusal this listener throws by name, so a surface that has to
  // turn one into an answer of its own reads the code rather than the
  // message text. A message is prose an operator can rewrite; a code is
  // the contract, and a surface matching on prose starts answering the
  // wrong status the first time the sentence is edited.
  //
  // Read by the sending route on the browser port, which composes through
  // the same gate the wire runs and has to render each of these classes
  // as its own HTTP status.
  CODES: Object.freeze({
    fromHeaderNotOwned:         FROM_HEADER_NOT_OWNED,
    sendingCredentialCeiling:   SENDING_CREDENTIAL_CEILING,
    sendingCredentialCeilingUnreadable: SENDING_CREDENTIAL_CEILING_UNREADABLE,
    sendingCredentialStopped:   SENDING_CREDENTIAL_STOPPED,
  }),
  // The two identity spaces this server authenticates, and which
  // listener holds each. Exported so a gate can read which builder was
  // handed which surface rather than restating the split.
  AUTH_SURFACES: AUTH_SURFACES,
  // The key agreement every listener presents, mail ports and browser
  // port alike. Exported because two modules build TLS contexts by
  // different routes, and a second spelling of this list is two halves
  // of one server accepting different sets.
  keyAgreementGroups: keyAgreementGroups,
  DEFAULTS:      DEFAULTS,
  MIN_LINE_BYTES: MIN_LINE_BYTES,
  MAX_LINE_BYTES: MAX_LINE_BYTES,
  // The inbound authentication posture a configuration that says
  // nothing runs at. Exported so the settings reference is compared
  // against the value the MX listener applies rather than against a
  // second spelling of it written beside the row.
  DEFAULT_INBOUND: DEFAULT_INBOUND,
  // The words a listener's state is reported in, shared with whatever
  // builds the inventory and whatever reads it so neither has a private
  // spelling of them.
  LISTENER_STATES: LISTENER_STATES,
  // The two halves of this server's answer to the framework's
  // rate-limit table: the ceilings it passes, and the ones it does not
  // together with why. Exported so the parity gate can read them rather
  // than restate them, which is the one thing a copy of a list must
  // never be checked against.
  RATE_LIMIT_KEYS:          RATE_LIMIT_KEYS,
  WITHHELD_RATE_LIMIT_KEYS: WITHHELD_RATE_LIMIT_KEYS,
  // The two bounds this server holds rather than inherits, and that the
  // parity gate above structurally cannot reach: the socket ceiling sits
  // in no rate-limit table, and the body-rate floor is deliberately kept
  // off the settable list. Exported so a gate can hold each against the
  // number SECURITY.md publishes, because a bound that is only checked
  // where it is applied is a bound whose document is checked nowhere.
  MAX_CONNECTIONS:                  MAX_CONNECTIONS,
  BODY_RATE_FLOOR_BYTES_PER_SECOND: BODY_RATE_FLOOR_BYTES_PER_SECOND,
  // Which ports a certificate renewal does not reach in process, so the
  // rotation path can name them to an operator rather than leaving the
  // gap to be discovered from a client that stopped connecting.
  STALE_AFTER_ROTATION:     STALE_AFTER_ROTATION,
};
