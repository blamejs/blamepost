// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.mail.listeners
 * @title  Protocol listeners
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
 *   what RFC 8314 section 3 asks for on 993 in the first place. That is
 *   the framework's to add: `b.mail.server.imap.create` takes no such
 *   option and the socket is wrapped inside its connection handler,
 *   so there is nothing here to compose it out of. Until it exists, 993
 *   and 995 are not served, and an operator is better told that than
 *   handed an arrangement that binds a port and refuses every sign-in.
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
 *   The refusal reaches the client as the framework's `451 4.3.0`,
 *   which is the only reply a refused handoff can produce and is a
 *   transient code for a permanent condition. It is the same tradeoff
 *   the body screen above makes and it is made the same way: the reason
 *   goes to the audit trail and the log, where it names the address
 *   that was rejected and the ones that would have been accepted, and
 *   the message stays off the wire meanwhile. Answering a permanent
 *   `553` needs the listener to carry a code out of the handoff, which
 *   is upstream of this repository.
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
 */

var nodeBuffer = require("node:buffer");

var b = require("../vendor/blamejs");

var posture = require("./posture");

var mailbox = require("./mailbox");

// Two spellings of one mailbox are one mailbox, and `lib/store/address`
// is the single place that decides so: it folds the case of both halves
// and strips the RFC 5233 plus tag down to the mailbox that owns it.
// The header binding below compares one address against another and has
// to reach the same verdict the routing layer reaches, or this server
// refuses an account the address it delivers to that same account.
var storeAddress = require("../store/address");

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

if (typeof splitAddressHeader !== "function" || typeof normalizeAddress !== "function") {
  throw new TypeError("blamepost.mail.listeners: the compose module must export " +
    "splitAddressHeader and normalizeAddress, which are the two readers the submission " +
    "header binding measures an author against");
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

// The port map from the operator guide. A configuration that names no
// ports gets exactly this.
var DEFAULTS = Object.freeze({
  mx:          Object.freeze({ enabled: true,  port: 25,   address: "0.0.0.0" }),
  submission:  Object.freeze({ enabled: true,  port: 587,  address: "0.0.0.0" }),
  submissions: Object.freeze({ enabled: true,  port: 465,  address: "0.0.0.0" }),
  imap:        Object.freeze({ enabled: true,  port: 143,  address: "0.0.0.0" }),
  pop3:        Object.freeze({ enabled: false, port: 110,  address: "0.0.0.0" }),
  managesieve: Object.freeze({ enabled: true,  port: 4190, address: "0.0.0.0" }),
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
// The wire code the client sees is the framework's: a refused handoff
// is answered `451 4.3.0` whatever the reason, on both listeners. A
// malformed body deserves a permanent verdict and that can only be
// written where the body is parsed, which is upstream of this
// repository. Refusing transiently keeps the message out of the store
// and off the wire meanwhile, and the audit row carries the reason the
// wire code cannot.
//
// The refusal carries a code because the handoffs throw for more than
// one reason: this, and a message no recipient on it resolves for. Both
// reach the listener as the same reply, so a caller that needs to tell
// them apart has only the code to do it with.
var BODY_READ_AS_TWO_MESSAGES = "listeners/body-read-as-two-messages";

function _refuseIfReadAsTwoMessages(direction, envelope, body) {
  var bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
  if (!b.guardSmtpCommand.detectBodySmuggling(bytes)) return;
  b.audit.safeEmit({
    action:   "blamepost.mail.listeners.body_read_as_two_messages",
    outcome:  "denied",
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

// One refusal of an author, said out loud and written down.
//
// The message names the identity that was rejected and the ones that
// would have been accepted, because a shared or delegated mailbox is
// the first thing an operator trips over here and a bare refusal sends
// them to look at their mail client. The row carries the same pair, so
// the answer survives the session that produced it.
function _refuseAuthor(actor, allowed, rejected, why) {
  var permitted = _identityList(allowed);
  b.audit.safeEmit({
    action:   "blamepost.mail.listeners.submission_from_not_owned",
    outcome:  "denied",
    actor:    { userId: (actor && actor.id) || null },
    metadata: {
      authenticatedAs: (actor && actor.address) || "",
      rejected:        rejected,
      reason:          why,
      permitted:       permitted,
      permittedCount:  allowed.length,
    },
  });
  var err = new Error("this message was not relayed because " + why + ". The account " +
    ((actor && actor.address) || "that signed in") + " may write " +
    (allowed.length === 0
      ? "no author address at all, which means it has no mailbox assigned to it yet"
      : "these author addresses: " + permitted) +
    ". Add the address as an alias for this account if it should be one it can write.");
  err.code = FROM_HEADER_NOT_OWNED;
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
    parsed = b.safeMime.parse(_headerBlockOnly(bytes));
  } catch (err) {
    _refuseAuthor(actor, allowed, "",
      "its header block could not be read, so there is no author to check it against " +
      "and this server will not sign a message whose sender it cannot identify (" +
      ((err && err.message) || String(err)) + ")");
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
      "no author is one this server would sign without knowing whose it is");
  }
  if (fromValues.length > 1) {
    _refuseAuthor(actor, allowed, "",
      "it carries " + fromValues.length + " From headers and RFC 5322 section 3.6 allows " +
      "one, so which address a recipient is shown depends on which mail program opens it");
  }
  if (senderValues.length > 1) {
    _refuseAuthor(actor, allowed, "",
      "it carries " + senderValues.length + " Sender headers and RFC 5322 section 3.6 " +
      "allows one, so the agent that transmitted it is left for the receiver to guess at");
  }

  var candidates = splitAddressHeader(fromValues[0]).map(function (entry) {
    return { field: "From", written: entry };
  });
  if (candidates.length === 0) {
    _refuseAuthor(actor, allowed, _identityList([_echoHeader(fromValues[0])]),
      "its From header names nobody, so the message identifies no author and displays none");
  }
  if (senderValues.length === 1) {
    var senders = splitAddressHeader(senderValues[0]);
    // RFC 5322 section 3.6.2 gives Sender a single mailbox. More than
    // one is not a delegation, it is an ambiguity.
    if (senders.length !== 1) {
      _refuseAuthor(actor, allowed, _identityList([_echoHeader(senderValues[0])]),
        "its Sender header names " + (senders.length === 0 ? "nobody" : senders.length +
        " addresses") + " and RFC 5322 section 3.6.2 gives it exactly one, which is the " +
        "single agent that transmitted the message");
    }
    candidates.push({ field: "Sender", written: senders[0] });
  }

  var attributable = false;
  for (var i = 0; i < candidates.length; i += 1) {
    var candidate = candidates[i];
    var address = storeAddress.parse(
      normalizeAddress(candidate.written, "listeners: " + candidate.field).address);
    if (!address.ok) {
      _refuseAuthor(actor, allowed, _echoHeader(candidate.written),
        "its " + candidate.field + " header names an address this server cannot read (" +
        address.reason + "), and an address that cannot be read cannot be checked");
    }
    var permitted = allowed.indexOf(address.address) !== -1;
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
        "way arrives carrying this domain's own signature over somebody else's name");
    }
  }

  if (!attributable) {
    _refuseAuthor(actor, allowed,
      _identityList(candidates.map(function (c) { return _echoHeader(c.written); })),
      "no address in its From or Sender header is one this account may write, so the " +
      "message is attributable to nobody who signed in to send it");
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
    return { enabled: defaults.enabled, port: defaults.port, address: defaults.address };
  }
  if (typeof section !== "object" || Array.isArray(section)) {
    throw new TypeError("blamepost.mail.listeners.create: config.listeners." + label +
      " must be an object of { enabled, port, address }");
  }
  var out = { enabled: defaults.enabled, port: defaults.port, address: defaults.address };
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

// The ceilings the framework accepts and this server does not pass, each
// with the reason it does not.
//
// The list exists so that declining is a decision somebody wrote down.
// Without it the only way past a new framework key would be to wire it,
// so the pressure would be to add a ceiling nobody had thought about,
// which is the same silence in the other direction.
//
// It reaches only as far as the rate limiter's own table, and that is a
// bound on the check rather than on the problem. `maxConnections` is the
// worked example: a per-listener ceiling on accepted sockets, default
// 1024, taken by all five `create()` calls and belonging to no
// rate-limit table, so the parity gate this list feeds cannot see it and
// naming it here would report it as a ceiling the framework no longer
// accepts. A ceiling the framework grows in this second category is
// exactly as invisible as the ones the gate was built for, and the only
// thing standing in front of it is somebody reading a release note.
//
// It is not offered as a setting either, and that is a decision rather
// than an oversight. The number bounds the listener, so the operator
// lever that matters at the volumes where 1024 binds is the process's
// descriptor budget, which belongs to the container and not to this
// configuration; a ceiling raised past what the process can hold turns
// a refusal a peer can read into an accept error it cannot. The
// interaction that does need saying is with
// maxConcurrentConnectionsPerIp, whose own schema reaches 1024: set the
// two equal and one source address can take the whole listener, at which
// point the listener ceiling stops separating one peer from everybody
// else. The operator guide says so under the ceilings table.
var WITHHELD_RATE_LIMIT_KEYS = Object.freeze({
  minBytesPerSecond:
    "A byte-rate floor on the message body, applied by the two SMTP listeners at the " +
    "framework's own default of a hundred bytes a second, judged over bounded windows " +
    "so an opening burst buys no credit against a slow tail. A peer below that rate is " +
    "answered 421 and cut, which is the protection idleTimeoutMs cannot give, because " +
    "each arriving byte pushes an idle deadline out again. The floor holds on this " +
    "server today and the operator guide says so; what is withheld is the number, not " +
    "the defense. It stays withheld because both directions off the default are worse " +
    "than the default. Lower changes nothing an attacker could not already have from " +
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
function _limitsConfig(section) {
  if (section === undefined || section === null) return { rateLimit: {}, maxMessageBytes: undefined };
  if (typeof section !== "object" || Array.isArray(section)) {
    throw new TypeError("blamepost.mail.listeners.create: config.limits must be an object of " +
      "{ maxMessageBytes, " + RATE_LIMIT_KEYS.join(", ") + " }");
  }
  var rateLimit = {};
  for (var i = 0; i < RATE_LIMIT_KEYS.length; i += 1) {
    var key = RATE_LIMIT_KEYS[i];
    if (section[key] === undefined) continue;
    rateLimit[key] = _assertCount(section[key], "config.limits." + key);
  }
  var maxMessageBytes;
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
// refused. The wire guard has already refused every control byte on the
// line, so nothing here can forge a response line.
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
  function _actorFor(verdict) {
    return {
      id:        verdict.accountId,
      username:  verdict.address,
      address:   verdict.address,
      domain:    verdict.domain,
      isAdmin:   verdict.isAdmin === true,
      mailboxes: [String(verdict.address).toLowerCase()],
      roles:     verdict.isAdmin === true ? ["admin", "account"] : ["account"],
    };
  }

  // One verifier, and one for every listener rather than a variant per
  // protocol. All four drive the same step runner, so a client is
  // answered the same way whichever port it arrived on, and a rule
  // about credentials cannot hold on one listener and not its
  // neighbor.
  function _verifier() {
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
        source:   typeof credentials.remoteAddress === "string"
          ? credentials.remoteAddress
          : null,
      });
      if (!verdict || verdict.ok !== true) {
        return { ok: false, reason: (verdict && verdict.reason) || "credentials-rejected" };
      }
      return { ok: true, actor: _actorFor(verdict) };
    };
  }

  function _authConfig() {
    return { mechanisms: SASL_MECHANISMS.slice(), verify: _verifier() };
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
  function _sieveEnv(inbound, target) {
    var bytes = Buffer.isBuffer(inbound.body)
      ? inbound.body
      : Buffer.from(String(inbound.body || ""), "utf8");
    var parsed = b.safeMime.parse(bytes);
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
      envelope:  { from: inbound.mailFrom || "", to: target.mailbox },
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
  function _sieveFolderFor(target, inbound) {
    var actor = { id: target.accountId, address: target.mailbox };
    var script;
    try {
      script = mailStore.sieveScripts.active(actor);
    } catch (err) {
      log.error("could not read the active Sieve script for " + target.mailbox +
        ", delivering to INBOX: " + ((err && err.message) || String(err)));
      return "INBOX";
    }
    if (!script) return "INBOX";

    var verdict;
    try {
      verdict = b.mail.sieve.runScript(script.body, _sieveEnv(inbound, target), {
        profile: profile,
      });
    } catch (err) {
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.failed",
        outcome:  "failure",
        metadata: { mailbox: target.mailbox, script: script.name,
                    reason: (err && err.message) || String(err) },
      });
      log.error("Sieve script " + JSON.stringify(script.name) + " for " + target.mailbox +
        " failed, delivering to INBOX: " + ((err && err.message) || String(err)));
      return "INBOX";
    }

    var actions = (verdict && verdict.actions) || [];
    var folder = null;
    var discarded = false;
    for (var i = 0; i < actions.length; i += 1) {
      var action = actions[i];
      if (action.kind === "fileinto" && folder === null) { folder = action.folder; continue; }
      if (action.kind === "discard") { discarded = true; continue; }
      if (action.kind === "keep") { folder = folder || "INBOX"; continue; }
      // redirect and vacation both put a message on the wire, which this
      // build cannot do, and vacation additionally needs the suppression
      // state a responder keeps. Refusing loudly and keeping the message
      // is the honest answer: the account holder still gets their mail,
      // and the operator can see the action was asked for and not taken.
      if (action.kind === "redirect" || action.kind === "vacation") {
        b.audit.safeEmit({
          action:   "blamepost.mail.sieve.action_unavailable",
          outcome:  "failure",
          metadata: { mailbox: target.mailbox, script: script.name, sieveAction: action.kind },
        });
        log.error("Sieve script " + JSON.stringify(script.name) + " for " + target.mailbox +
          " asked for " + action.kind + ", which this build cannot perform. The message is " +
          "kept rather than dropped.");
        folder = folder || "INBOX";
      }
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
    var folder = _sieveFolderFor(target, inbound);
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
      stored = await mailStore.appendMessage(folder, inbound.body, { actor: actor, flags: [] });
    } catch (err) {
      // The script named a folder this account does not have. RFC 5228
      // section 4.1 lets an implementation deliver to INBOX instead of
      // creating it, and creating it is not available here: folder names
      // live in one place and nothing can add one, so inventing a folder
      // at delivery time would be a second naming scheme.
      if (folder === "INBOX") throw err;
      log.error("Sieve for " + target.mailbox + " files into " + JSON.stringify(folder) +
        ", which is not a folder on this account. Delivering to INBOX instead: " +
        ((err && err.message) || String(err)));
      b.audit.safeEmit({
        action:   "blamepost.mail.sieve.folder_missing",
        outcome:  "failure",
        metadata: { mailbox: target.mailbox, folder: folder },
      });
      stored = await mailStore.appendMessage("INBOX", inbound.body, { actor: actor, flags: [] });
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
  // When NOTHING could be delivered, this throws, and the listener
  // answers the peer `451 4.3.0`. That is a temporary code for what is
  // now a temporary condition, which is the answer those cases want:
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
  // Only the all-refused case throws. A message that reached one
  // mailbox and missed another is already stored, so a retry would
  // deliver the stored copy twice, and duplicating delivered mail to
  // improve a report is a worse trade than the report being late.
  function _mxAgent() {
    return {
      handoff: async function (inbound) {
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
              metadata: {
                mailFrom:   inbound.mailFrom,
                recipients: _reportedRecipients(refused),
                recipientCount: refused.length,
                reason:     refused[0].reason,
              },
            });
            throw new Error("no recipient on this message resolves to a mailbox here: " +
              _reportedRecipients(refused));
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
   * @opts
   *   from:       string,    // the reverse path
   *   to:         array,     // the recipients, hosted here or not
   *   rfc822:     Buffer,    // the finished message, already signed
   *   origin:     string,    // which share of the outbound queue; default "submission"
   *   requireTls: boolean,   // carried to the outbound chain unchanged
   */
  async function _relaySend(envelope) {
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
      throw new TypeError("blamepost.mail.listeners.relay.send: envelope object is required");
    }
    var body = Buffer.isBuffer(envelope.rfc822)
      ? envelope.rfc822
      : Buffer.from(String(envelope.rfc822 || ""), "utf8");
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
        // the plan rather than the outcome.
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

  // The submission listener's relay handoff. Signing happens here
  // because the listener hands over the finished message, which is the
  // only moment the header set is complete and still unsent.
  //
  // Where each recipient goes is the relay's question rather than this
  // function's. The browser compose form and JMAP `EmailSubmission/set`
  // ask the same handle, so the three surfaces an account holder sends
  // from cannot answer it differently.
  function _submissionAgent() {
    return {
      handoff: async function (outbound) {
        _refuseIfReadAsTwoMessages("outbound", outbound, outbound.body);
        // Before the signer, because a signature is this server putting
        // its name to whatever the header says, and before delivery,
        // because a refused message must not have reached a mailbox.
        await _refuseUnownedAuthor(store, outbound);
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
            b.audit.safeEmit({
              action: cause === DKIM_CODES.noActiveSelector
                ? "blamepost.mail.listeners.submission_unsigned_no_key"
                : "blamepost.mail.listeners.submission_unsigned",
              outcome:  "failure",
              metadata: {
                domain: senderDomain,
                cause:  cause || null,
                reason: (err && err.message) || String(err),
              },
            });
            log.error("mail from " + senderDomain + " is being relayed without a DKIM " +
              "signature, so receivers cannot attribute it to that domain: " +
              ((err && err.message) || String(err)));
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
          // the plan rather than the outcome.
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
      maxMessageBytes: limits.maxMessageBytes,
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
        mode:        inbound.mode || "enforce",
        onTemperror: inbound.onTemperror || "defer",
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
  //     every peer is answered permanently regardless. A guarantee that
  //     lasts until the next upgrade is not one an operator can plan on.
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
  // acted is named in a field of its own.
  function _refuseWithdrawnDomain(ctx, withdrawn) {
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.mx_recipient_domain_not_hosted",
      outcome:  "denied",
      metadata: {
        domain:        withdrawn.domain,
        state:         withdrawn.state,
        rcptTo:        ctx.rcptTo || "",
        mailFrom:      ctx.mailFrom || "",
        remoteAddress: ctx.remoteAddress || "",
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

  function _buildSubmission(implicitTls) {
    return b.mail.server.submission.create(_tlsOption({
      implicitTls:     implicitTls === true,
      greeting:        hostname + " Submission blamepost",
      profile:         profile,
      auth:            _authConfig(),
      rateLimit:       limits.rateLimit,
      maxMessageBytes: limits.maxMessageBytes,
      identityBinding: "strict",
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
  function _imapTagged(socket, tag, line) {
    try { socket.write(tag + " " + line + "\r\n"); }
    catch (_e) { /* drop-silent by design: the client is already gone */ }
  }

  function _imapUntagged(socket, line) {
    try { socket.write("* " + line + "\r\n"); }
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
  function _refuseImapSearch(state, socket, tag, refusal) {
    var condition = refusal && refusal.searchCondition === "BAD" ? "BAD" : "NO";
    var code = (refusal && refusal.searchResponseCode) || null;
    var text = (refusal && (refusal.searchText || refusal.message)) ||
      "was refused and gave no reason.";
    b.audit.safeEmit({
      action:   "blamepost.mail.listeners.imap_search_refused",
      outcome:  "denied",
      actor:    { userId: (state.actor && state.actor.id) || null },
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
        return mailStore.searchScan(state.actor, state.selectedMailbox);
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
          actor:    { userId: state.actor.id || null },
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
    return bytes.toString("utf8");
  }

  function _buildImap() {
    return b.mail.server.imap.create(_tlsOption({
      greeting:   hostname + " IMAP4rev2 blamepost",
      profile:    profile,
      auth:       _authConfig(),
      rateLimit:  limits.rateLimit,
      mailStore:  mailStore,
      // SEARCH. The framework ships a default that answers `NO SEARCH
      // not configured`, because a search expression is a question
      // about the messages an application stores rather than about the
      // protocol. Left unwired, every IMAP client's search is dead
      // while the same account's search works over JMAP and in the
      // browser. The override rides the framework's own dispatch
      // registry, so the wire guard, the per handler ceiling and the
      // audit row in front of every other verb stay in front of this
      // one.
      overrides: {
        SEARCH: {
          fn:              _imapSearch,
          maxHandlerBytes: SEARCH_HANDLER_BYTES,
          maxHandlerMs:    SEARCH_HANDLER_MS,
        },
      },
    }));
  }

  function _buildPop3() {
    return b.mail.server.pop3.create(_tlsOption({
      greeting:   hostname + " POP3 blamepost",
      profile:    profile,
      auth:       _authConfig(),
      rateLimit:  limits.rateLimit,
      mailStore:  mailStore,
    }));
  }

  function _buildManageSieve() {
    return b.mail.server.managesieve.create(_tlsOption({
      greeting:   hostname + " ManageSieve blamepost",
      profile:    profile,
      auth:       _authConfig(),
      rateLimit:  limits.rateLimit,
      mailStore:  mailStore,
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
            metadata: { listener: name, error: (err && err.message) || String(err) },
          });
        } catch (_e) { /* drop-silent by design */ }
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
      // What the operator set, not what the listeners resolved. A field
      // left unset is absent here rather than filled in with the
      // framework's number, so this answers "what did I ask for" and
      // never invents an answer nobody wrote.
      limits:          Object.assign({}, limits.rateLimit,
        limits.maxMessageBytes === undefined
          ? {}
          : { maxMessageBytes: limits.maxMessageBytes }),
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
  // The key agreement every listener presents, mail ports and browser
  // port alike. Exported because two modules build TLS contexts by
  // different routes, and a second spelling of this list is two halves
  // of one server accepting different sets.
  keyAgreementGroups: keyAgreementGroups,
  DEFAULTS:      DEFAULTS,
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
  // Which ports a certificate renewal does not reach in process, so the
  // rotation path can name them to an operator rather than leaving the
  // gap to be discovered from a client that stopped connecting.
  STALE_AFTER_ROTATION:     STALE_AFTER_ROTATION,
};
