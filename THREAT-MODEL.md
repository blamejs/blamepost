# Threat model

A mail server is one of the few things left that accepts unauthenticated,
attacker-controlled bytes from anyone on the internet, parses them with a
decades-deep stack of standards, and then stores the result somewhere people
read it. blamepost is designed around that fact.

This document states what a deployment protects, where the trust boundaries sit,
which threat classes the design answers, and what it does not cover. It is
written for an operator deciding whether to put it in front of a domain.
[SECURITY.md](SECURITY.md) describes the same defenses organized by surface, and
carries the reporting process.

## Assets

- **Mail content.** Message bodies, attachments, subjects, envelope addresses,
  and the folder structure around them. Confidential to the accounts that hold
  them, and the reason everything else on this list matters.
- **Account credentials.** Password verifiers, session material, and the
  authentication state that binds a connection to an account. A single working
  credential turns an outsider into an insider on every protocol at once.
- **DKIM private keys.** The signing keys for every hosted domain. Losing one
  lets an attacker sign mail as that domain, which is a reputational and
  fraud-shaped problem long after the key is rotated.
- **The vault passphrase.** The single secret that unlocks the sealed material in
  the data directory. It is not stored in the volume it protects.
- **Audit integrity.** The record of who did what. It is only useful if an
  attacker who reaches the database cannot rewrite it, and the reach that
  matters is the passphrase rather than the file: every row hash is computed
  from columns anyone can read, so a rewritten sequence agrees with itself, and
  what a rewrite has to get past is a signature made with a key the vault
  passphrase unseals. Against somebody holding that passphrase this asset is
  not protected, which is why it is listed beside the passphrase rather than
  instead of it.

  One route into this asset costs neither the passphrase nor the volume, and it
  is the reason a purged range is reported the way it is. The table recording
  where an archive and purge stopped is unsigned, unchained, uncovered by any
  checkpoint and unguarded by any trigger, and one row written into it discards
  every audit row at or below the counter it names. Write access to the
  database is the whole price. Nothing this server reads can tell that row
  apart from the one an honest retention run leaves, so the boundary is drawn
  at what is said rather than at what is refused: the range is reported as
  unread and trusted on an unsigned counter, never as a range nothing was
  removed from, and the reading is recorded so a second run cannot answer more
  softly than the first. What closes it is the archive bundle, which lives off
  this volume and is the operator's to hold against the counter.
- **Deliverability.** The standing of the sending domain and IP with receivers.
  It is slow to build, fast to lose, and an attacker who gets a server to emit
  spam destroys it without ever reading a message.
- **Availability.** Mail that is refused with a temporary code is delayed; mail
  refused with a permanent one is gone. A parser that hangs on a crafted input
  takes the whole listener with it.

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Inbound SMTP on port 25, from anyone | **Untrusted** | Strict RFC 5321 state machine, per-peer connection budgets, HELO discipline, envelope screening, SPF / DKIM / DMARC evaluated before the message is accepted, and the ARC chain evaluated alongside them and reported without entering that decision. RBL and greylisting are gates the listener accepts and this release wires nothing into, so neither is a defense a deployment has today |
| Message bytes and MIME structure, inbound or outbound | **Untrusted, always** | Bounded parsing under size and depth caps; a structure that violates the standard is refused rather than repaired |
| A submission client after SASL AUTH | **Authenticated, not trusted** | The envelope sender must be the account's own address, and a SASL response whose authorization identity names a second account is refused. The finished message is measured too: every address in `From` or `Sender` at a domain this server hosts has to be one the account may write, and at least one across the two has to be. Rate limits and storage quotas still apply. An author at a domain hosted elsewhere is not screened; the first threat class has the boundaries |
| An IMAP, POP3, JMAP or ManageSieve client after AUTH | **Authenticated, scoped** | Every verb dispatches through one adapter that resolves the authenticated account before it reads a row, so a session reaches its own folders, messages and filter scripts and nothing else. Destruction and moves go on through the agent that holds the retention floor and writes the audit row |
| A webmail browser session | **Authenticated, scoped** | Same scoping, plus the full HTTP middleware chain: CSRF, origin and fetch-metadata checks, cookie prefixes, strict CSP |
| An admin session | **Operator** | The administrator flag is held by an account and covers the whole server rather than one domain, so an account that has it administers every hosted domain. Changes are audited; the pages it reads are not, so the record answers what an administrator altered and not what they looked at. An admin session claims no mail scope, so it reaches no mailbox but its own through this interface |
| DNS answers | **Untrusted, and unauthenticated** | MTA-STS is the one policy anchored outside DNS: the record says only that a policy exists, and the policy itself is fetched over HTTPS from a name the certificate has to match. Everything else is taken on the resolver's word. No lookup this server makes asks its upstream for a DNSSEC verdict, and no TLSA record is checked against a peer's certificate, so a signed zone buys nothing on this side today. The resolver is built by the server rather than named in the configuration, which is what an operator running their own validating recursive needs to know |
| A remote MX during delivery | **Untrusted** | The TLS requirement comes from the sending side's policy, never from what the far side offers. MTA-STS is in force. DANE authenticates a peer only once the operator has stated that the resolver this server uses validates DNSSEC, and REQUIRETLS is composed and reaches no wire; the transport threat class has the detail |
| Operator configuration and environment | **Trusted** | Validated at boot; a bad value throws where the operator is watching |
| The vendored framework | **Trusted after verification at vendoring time** | Pinned to a published version, with the publisher's integrity digest verified before the tarball is extracted and recorded in the manifest. The running process does not re-verify the tree at boot, so a host that can rewrite files under `lib/vendor/` is already inside the trust boundary below |
| The host kernel and filesystem | **Trusted runtime** | Assumed intact; see the last section |

The rule underneath all of it: **the message never chooses its own policy.** A
sender does not get to say whether its mail is authenticated. A receiving MX does
not get to say whether TLS is required. A client does not get to say which
mechanisms it may authenticate with. Every one of those decisions comes from the
operator's configuration and the standards, and arrives at the decision point
before the attacker-controlled input does.

## Adversaries

**The spammer looking for a relay.** Scans the address space for a server that
will accept mail for a destination it does not host, or that will send for an
account it has not authenticated. This is the single most common attack on a new
mail server and it starts within hours of the MX record appearing.

**The credential-stuffer.** Replays breach corpora against submission, IMAP,
POP3 and the webmail login, at whatever rate goes unnoticed. Success here is
worse than a relay: a stuffed credential sends authenticated, DKIM-signed mail
from a domain with real standing, and reads the mailbox on the way past.

**The hostile sender.** Crafts the message itself: MIME nested to exhaustion,
headers that parse differently in the server than in the client, encodings
chosen to smuggle one thing past the scanner and show another to the reader,
line endings that mean one message to the server and two to the next hop.

**The misbehaving or malicious client.** Sends protocol input no compliant client
would: a literal whose declared length disagrees with its bytes, a bare CR inside
a command, a verb in the wrong state, a command line long enough to matter. Some
of this is a buggy MUA. Some of it is not, and the server cannot tell them apart
by intent.

**The local-network attacker.** Sits between a client and the server, or between
the server and a remote MX. Strips STARTTLS from the negotiation, answers DNS
with an MX of their choosing, or waits for a listener that will fall back to
plaintext rather than fail.

**The opportunist with the disk.** Obtains the data volume without the
passphrase: a stolen backup, a decommissioned drive, a snapshot copied out of a
hypervisor.

## Threat classes and the design response

1. **Unauthorized relay.** The MX listener accepts mail only for domains it
   hosts, and refuses a recipient in any other domain at `RCPT` with `550
   5.7.1`. A recipient in a hosted domain that resolves to no mailbox is
   refused at `RCPT` as well, with `550 5.1.1`, while the peer is still on the
   socket and before it has transmitted anything.

   Only a permanent condition is answered that way, and the difference is
   deliberate. A mailbox that is full or an account that is suspended is
   accepted at `RCPT` and met at the delivery handoff instead, which answers
   `451 4.3.0` when nothing on the message could be delivered. The owner can
   clear both of those, and telling a sender to stop retrying a condition that
   will lift is worse than making it wait. A peer holding a `451` keeps the
   message and reports back to its sender on its own schedule, so the message
   is never accepted and then discarded.

   Refusing a name on the wire is also an answer about which names exist, so
   the listener bounds how many recipients one source address may have refused
   in a minute. Past that ceiling it answers `421` and closes the connection
   rather than going on answering, which turns an enumeration sweep into a
   series of disconnects. `limits.rcptFailuresPerIpPerMinute` sets it.

   Nothing widens that recipient rule. `relayAllowedFor` names source ranges
   the MX listener would relay for whatever the recipient domain is, and this
   server refuses to start when one is set, naming the setting and the
   submission listener to use instead. The row stays in the schema rather than
   being deleted, so the variable is documented as refused rather than
   silently unread.

   The reason it is refused rather than honored is that a range has nothing
   left to serve. Every listener here requires STARTTLS before it will accept
   an envelope, on the MX port as much as on submission, and the profile that
   would relax that is not one this server offers: `MAIL FROM` before the
   upgrade is answered `530 5.7.0 Must issue a STARTTLS command first` under
   both. So a device that can reach `RCPT TO` on port 25 has already completed
   a TLS handshake, and a device that can do TLS can authenticate on 587 or
   465. The one device an address range could serve that an account cannot is
   a device that speaks no TLS at all, and no such device gets past the
   greeting here in any case.

   What the range would have cost reads best against what an account buys. An
   address says which network a message came from and never which sender, so a
   range names a segment rather than a party: when one host inside it is taken
   over, the only lever is withdrawing the whole range, which takes the
   legitimate device down with it, where an account is withdrawn on its own.
   That is the identity binding below with the authentication removed. And
   relayed mail could only ever have left unsigned, which is not a gap somebody
   could close later: signing it would let anything inside the range emit mail
   aligned under a hosted domain's key, which is exactly the forgery the author
   binding refuses, performed by this server on behalf of a peer that
   authenticated to nobody.

   The submission listener refuses `MAIL FROM` until AUTH succeeds, and then
   refuses any envelope sender other than the authenticated account's own
   address, with
   `553 5.7.1 Sender address rejected: not owned by authenticated identity`,
   before any recipient is accepted. That is the string to filter for when
   watching logs for credential misuse. Nothing turns that one off: the
   binding is composed strict and takes no configuration.

   The binding compares two lowercase ASCII strings, and what makes that
   enough is everything that happens before it. Every command line meets a
   guard first, and under the profile these listeners run the guard refuses
   any byte above `0x7e` outright, so a composed or decomposed spelling, a raw
   international domain, a homograph and anything else outside ASCII is
   answered `500 5.5.2` at the point of parse and never becomes an address to
   compare. SMTPUTF8 is not advertised, so a client has no way to ask for that
   to change. A punycode label does survive the guard, because it is ASCII,
   and then simply is not the account's address, which ends in a refusal
   rather than a match. What is left is case, and both sides are folded on an
   alphabet where folding has one answer.

   The header a person reads is bound separately, and the two bindings are
   easy enough to confuse that it is worth saying which covers
   what. `MAIL FROM` is the envelope, checked at the wire before a recipient
   is accepted. `From` and `Sender` are checked on the finished message,
   after it has been accepted and before anything signs, stores or relays it:
   every address in either header that sits at a domain this server hosts has
   to be one the account may write, and at least one address across the two
   has to be, so the message is attributable to somebody who signed in for it.
   A message that fails is refused before it reaches a mailbox here or a
   socket to anywhere else, so mail between two accounts on this server is
   measured on the same terms as mail leaving it. A message carrying no
   `From`, a second `From` or `Sender`, a group naming nobody, or a header
   block that cannot be read is refused whatever it names.

   What an account may write is its own address plus the active aliases
   pointing at it, read from the store on every message so an alias the
   operator withdraws stops being a sending identity at the next message
   rather than at the next sign-in. Every comparison is made in the canonical
   form routing uses, so a plus tag folds away. A catch-all is excluded: it
   claims every name at a domain, so counting it would hand its holder every
   address the domain could ever carry, which is the forgery this binding
   exists to refuse rather than a set of identities.

   The refusal reaches the client as `451 4.3.0`, a transient code for a
   permanent condition, because that is the only reply a refused relay handoff
   can produce; tracked upstream as blamejs#668. It fails closed, so the
   mismatched class here is the reporting rather than the decision: a sender
   reads the 4 and retries something that will be refused identically every
   time. The reason it cannot carry goes to the log and to an audit row
   under `blamepost.mail.listeners.submission_from_not_owned`, naming the
   address that was rejected and the ones that would have been accepted. That
   row is what to watch, and it separates the two cases that produce it: an
   account probing the boundary, and an account holder whose shared address
   was never made an alias.

   Three things bound the guarantee. An author at a domain this server hosts
   nothing for is not screened at all, so `From: alice@example.com,
   partner@example.net` with no `Sender` is accepted: alice's address makes
   the message attributable, and nothing here signs for `example.net` or
   aligns anything to it, so that domain's own DMARC record is what answers
   for its name. The set follows one alias row while routing follows a chain
   to ten, so `team@example.com` pointing at `sales@example.com` pointing at a
   mailbox is delivered to that mailbox and is still not an address it may
   write; the asymmetry errs toward refusing, which costs a legitimate message
   rather than admitting a forged one, and the fix is an alias pointing
   directly at the account. And the envelope half cannot fold a plus tag while
   the author half can, so `alice+receipts@example.com` is an address alice
   may write in `From` and may not write in `MAIL FROM`, on the same server
   that accepts it as a recipient and delivers it to her. That comparison is a
   lookup in a fixed list built inside the vendored framework with no callback
   an application could answer from, so it is not something this repository can
   close. It fails closed, so it is a false refusal rather than a way in.
   [ROADMAP.md](ROADMAP.md) tracks both open halves.

   The residual an operator decides about is that an alias is a sending
   identity. Pointing a shared address at an account grants that account the
   ability to write as it, and a distribution address is one row per
   destination, so an address fanned out to three people is an address all
   three may write. A direct alias grants both at once: there is no form of it
   that delivers to an account without also letting that account write as it.
   The two addresses that reach a mailbox without becoming writable are the
   catch-all and the second hop above, and neither is a control an operator
   sets deliberately. So an operator who wants a shared address nobody may
   send under wants an account rather than an alias, and an operator whose
   accounts do not trust each other should read every alias they hand out as a
   name those accounts may sign mail with.

   How much that residual costs depends on alignment, and alignment follows
   the envelope rather than the author. DKIM signs with the envelope domain,
   and the envelope is always the account's own address, so an alias in the
   same domain as the account leaves signed and aligned, while an alias an
   operator put in a second hosted domain leaves signed for the account's
   domain and displaying the other. That one does not align, so the displayed
   domain's own DMARC record decides what a receiver does with it.

   The browser interface and JMAP offer the same set the wire binds against
   rather than a wider one. Both read it from the derivation the submission
   port uses, so a compose form cannot offer an author the wire would refuse,
   and an alias the operator withdraws stops being offered at the next
   message rather than at the next sign in. The envelope stays the account's
   own address in both, so what choosing an alias changes is the displayed
   author and not the return path.

2. **Credential attack.** Passwords are stored as Argon2id verifiers, and a
   miss spends the same Argon2id work a hit does, so an address that has no
   account is indistinguishable from one whose password was wrong. Each
   listener carries an authentication-failure budget in a rolling window, keyed
   on the peer address, and refuses further attempts from that address once it
   is spent. Every failure is audited, which is what makes a slow attempt
   visible at all.

   Read the key carefully, because it decides what each budget covers. The one
   above is per peer address and per listener, so it answers one host hammering
   one protocol and nothing else.

   A second budget answers the shape that one cannot see. It is kept against the
   mailbox, shared by the browser sign-in form and all five mail listeners, and
   spent by wrong credentials wherever they arrive from. Five wrong passwords
   inside a quarter of an hour close the mailbox to further attempts, and each
   subsequent lockout lasts longer than the one before it, up to six hours.
   Moving between source addresses does not refill it, and neither does moving
   between protocols: guesses spent on IMAP are gone on POP3 and in the browser.
   An address with no account here spends the budget exactly as a real mailbox
   does, so the refusal answers no question about which addresses exist. The
   mailbox is keyed by its canonical address, so a plus tag on the local part
   routes to the same budget rather than to a fresh one.

   The reason a budget keyed on the mailbox is not simply a way to lock somebody
   out of their own mail is the peer. A source address the mailbox has already
   signed in from is still admitted while the budget is spent, so an attacker
   failing on an account holder's behalf from addresses of their own does not
   shut that account holder out. Each such address carries a budget of its own,
   the same five attempts counted separately, so the exemption bounds anyone
   sharing a connection with the account holder rather than exempting them.
   That is the budget a familiar source cannot step around: it is read first
   and refuses on its own terms. Both budgets are held in memory for the life
   of the process.

   A successful sign in clears the budget for the address it came from and not
   the one kept against the mailbox, which is a deliberate difference from how
   this is usually done. A mail client authenticates on every poll and every
   send, so releasing the mailbox budget on a correct credential would refill it
   for whoever is guessing at that mailbox, at whatever rate its owner's client
   happens to run at. It decays instead, a quarter of an hour after the last
   failure.

   Two limits are worth naming. Anyone sharing a source address with an account
   holder, behind one office connection or one carrier, inherits the exemption
   that address earned and is bounded by that address's budget rather than by
   the mailbox's; the same is true for an IPv6 client in the account holder's
   own allocation. And the counters are held per process, so restarting the
   server releases every budget it was holding.

   Every failure and every lockout transition is audited under `auth.lockout.*`
   with the mailbox named on the row, which is what tells an attack apart from a
   mail client that has been left holding a password its owner has since
   changed. The operator interface reads that trail back and releases a mailbox
   from it against a reason, which is required and goes on the record beside
   the release; naming the machine the account holder is on releases the
   smaller budget kept against that peer as well, and leaving it out does not.

   The command line cannot do the same, and the reason is structural rather
   than an omission worth waiting for. The budgets are counters in the running
   process, and every command-line verb that touches an account opens the data
   volume, which one process holds at a time. A release issued there would run
   against a stopped server that had already discarded every counter, build an
   empty set, and report that nothing was locked, every time. An account holder
   with nobody to ask waits out the current lockout, which starts at one
   minute.

3. **Hostile message content.** MIME is parsed under explicit size, depth and
   part-count caps applied before the structure is walked, so a nesting bomb
   costs bounded work. Header and encoding handling follows the standard rather
   than guessing at intent, which is what closes the class where the server and
   the client disagree about what a message says. Being memory-safe JavaScript
   removes the overflow and use-after-free surface that most historical mail-parser
   CVEs occupied; what remains is exhaustion and ambiguity, and both are answered
   by caps and by strictness.

   A message is stored and relayed as the octets it arrived as. That closes the
   version of this class where the server rewrites a message and then reasons
   about the rewrite, and it is what lets a signature survive the hop.
   Retrieval is where it stops being complete. POP3 returns the stored octets.
   IMAP renders a fetched section as text before it writes it, so a message
   carrying anything that is not valid UTF-8, which is what an unencoded 8-bit
   body in a legacy charset looks like, reaches an IMAP client with every
   unreadable octet replaced, and a partial fetch whose range splits a
   character has the same limit at its edges. The announced literal always
   matches the bytes that reach the socket, so the session stays framed and the
   client never reads one response as part of another; what the client cannot
   do is verify a signature over what it received. It is a limit in the
   vendored framework, filed upstream, and the stored message is untouched, so
   the same message read over POP3 comes back whole.

   The other way a retrieval answer can be wrong is to be incomplete and say
   nothing about it, and IMAP `SEARCH` is where that would happen. This server
   keeps some of a message parsed and the rest only as octets, so a search key
   over what it does not keep has no exact answer: `BODY` and `TEXT` read
   parts that were never indexed whole, `CC` and `BCC` read headers that are
   not kept, and `SENTBEFORE`, `SENTON` and `SENTSINCE` ask about the `Date`
   header when only the arrival time is stored. Each of those is refused with
   `NO` at the point the expression is parsed, before any message is read, and
   the refusal names what is missing. Answering them from what is kept would
   return a result set that is short by however many messages matched in the
   part that was not read, and a client cannot tell that from a mailbox that
   does not hold them. A refusal ends the whole expression rather than one key
   of it, because an expression has no partial evaluation: half of
   `OR SUBJECT round CC bravo` is the answer to a question the client did not
   ask. `HEADER` splits on the same line: it answers over the five fields the
   store keeps whole and refuses over any other, naming them. The keys that
   are answered, among them `SUBJECT`, `FROM`, `TO`, the flags, the sizes and
   the arrival dates, are answered by scanning the messages rather than by
   consulting the full-text index, whose token matching, folded address column
   and result cap would produce the same short answer under a tagged `OK`.

4. **Wire-protocol smuggling.** SMTP dot-stuffing and line-ending ambiguity are
   handled in the wire layer rather than left to the parser above it. That is
   the class where two implementations disagree about where a message ends. IMAP
   literal framing is validated against its declared length, bare CR and LF are
   refused, and each verb is checked for shape and for state. A malformed command
   gets the protocol's own error code, immediately. Nothing is accepted "for
   compatibility"; that tolerance is the origin of nearly every parser CVE in
   this product category.

   The end-of-data screen is taken a second time over the whole accepted body,
   in the one place every message passes on its way to being stored or
   relayed. The reason is that the two ways a message can arrive are framed
   differently. A `DATA` body is framed by the terminating dot, so the reader
   that finds the dot is also the reader that can refuse a counterfeit one; a
   chunked body under RFC 3030 is framed by a declared byte count and its
   content is opaque to the framing, which is the correct answer about framing
   and leaves the octets unexamined. Screening after reassembly covers both,
   and it sees the whole message rather than one chunk, so a boundary dropped
   into the middle of the sequence has nothing to hide behind. What it refuses
   is a dot line whose boundary is written any way other than `CRLF` on both
   sides: bare LF either side, bare CR either side, and the two mixed
   spellings. A lenient receiver reads one of those as the end of the message
   and everything after it as a fresh transaction, carried on a connection
   this server opened and authenticated, which is what walks a forged sender
   inside it past SPF, DKIM alignment and DMARC. Both the port a stranger
   delivers to and both submission paths refuse it rather than repairing it.

5. **Transport downgrade and interception.** Mail listeners refuse to boot
   without a TLS context, so there is no accidental plaintext mode, and none of
   them accepts a credential before the session is encrypted. Submission
   answers `538 5.7.11` and withholds its mechanism list until the upgrade;
   IMAP, POP3 and ManageSieve refuse their authentication verbs and advertise
   the mechanism either way.

   That refusal protects the account and not the connection, and the difference
   is the one an operator has to act on. A stripped STARTTLS on a mailbox port
   means the client has already put the password on the wire in the clear by
   the time the server says no. Nothing the server does can call that back. Two
   things close it and neither is set here: a mail client configured to require
   encryption, and a terminator offering implicit TLS on 993 and 995 in front
   of the in-band ports. Both are the operator's to put in place.

   Outbound is where the sending side's policy decides, and it decides before
   the socket opens. The delivery composer resolves the recipient domain's
   mail exchangers, settles transport policy against them, and only then hands
   the message to the transport, so a peer never negotiates its own protection
   down: what it offers is measured against what this server already required,
   and a recipient the policy will not deliver to is deferred and eventually
   reported on rather than delivered to in the clear.

   MTA-STS is what runs by default. The record question is asked before a
   message is handed over, and under an enforcing posture a domain whose record
   could not be settled is held rather than delivered to in the clear, because
   a suppressed answer and an honest "no record" look identical and reading
   them the same way is how mail goes out unprotected to a domain that asked
   for TLS. A domain that publishes no policy is unaffected, which is what
   keeps mail moving to most of the internet. The policy document itself is
   fetched over HTTPS, and a mail exchanger the policy does not list is
   refused.

   DANE runs on a statement this server cannot make for itself. RFC 7672
   §2.1.1 and §2.2 forbid using a TLSA record that was not DNSSEC-validated,
   and nothing in this process can see whether the resolver it was handed
   validates, so the assertion belongs to the operator and is written as
   `outboundPolicy.dnssecValidated`. Without it no TLSA lookup is made at all,
   under either posture, and delivery goes on with no DANE authentication.
   With it, records are fetched over the operator's own resolver rather than
   the host's, and the transport matches the peer's certificate chain against
   them and refuses the send on a mismatch.

   `outboundPolicy.dane` at `enforce` without that assertion is refused at
   start rather than accepted, because accepting it would refuse every peer
   that publishes TLSA while delivering to every peer that publishes none.
   Asserting it falsely is the worse of the two failures: it authenticates
   peers against records anybody on the path could have rewritten, under a
   banner saying they were verified. Set it only if the resolver really does
   validate. Publishing TLSA records for a hosted domain protects senders that
   validate them either way, and `blamepost doctor --dane` checks that they
   resolve.

   REQUIRETLS is composed and cannot be turned on. Nothing puts the keyword on
   the wire: the flag reaches the transport and the transport has no reader for
   it, so no receiver is ever asked. The setting that requests it therefore
   stops the boot rather than being accepted and dropped, which is the
   difference that matters for a threat model. A protection that is accepted
   and silently not applied produces the same evidence as one that works, so an
   operator who believed confidential mail was being withheld from peers that
   cannot encrypt would have no way to discover otherwise. Refusing removes
   that belief rather than the protection, because there was no protection to
   remove.

6. **Disk theft.** Message content, credentials and DKIM private keys are sealed
   under the vault before they reach disk. The volume alone is opaque without the
   passphrase, which is not stored in it. Seals are bound to the identity of what
   they protect, so a sealed value relocated to another row fails to open rather
   than disclosing itself somewhere it does not belong.

7. **Cross-account access.** One layer owns the record of which folders belong
   to which account, and every surface resolves a name through it before it
   reads a row. That layer is where isolation has to happen: the message store
   underneath keeps a single flat namespace of folders with no owner column, so
   nothing below it could tell one account's INBOX from another's. A verb that
   cannot identify its account refuses rather than falling back to a shared
   folder. That is the check to test, and it is in one place.

   The surfaces are not otherwise one call, and where they differ is the audit
   trail rather than the scoping. The browser interface and JMAP drive a
   mailbox agent that records each read and each change against the acting
   account. IMAP and POP3 read through the adapter directly and record nothing
   per verb. Destruction and moves are the exception and go through the agent
   from every protocol, so those carry the retention floor, the legal-hold
   refusal and the row wherever they arrive from. An operator reconstructing
   who read what will find the browser and JMAP answered and IMAP silent.

8. **Bypassing retention.** Hard deletion has exactly one path, and the retention
   floor and legal-hold substrate are enforced inside it. The floor is zero
   unless the operator has set a compliance posture, and unset is the shipped
   default, so on a server nobody has configured for a regulator a legal hold
   is the only thing that keeps a message somebody asked to destroy. Setting a
   posture is a promise worth meaning: below the floor a hard delete is refused
   for the mailbox owner as readily as for an administrator. IMAP `EXPUNGE`, the
   POP3 `DELE` set as it commits at `QUIT`, JMAP `Email/set` with `destroyed`
   and the webmail purge all arrive there, so a deletion cannot escape a hold by
   arriving over a different protocol. What each client is told afterwards
   differs, because the specifications differ: RFC 9051 §6.4.3 gives `EXPUNGE`
   no refusal form, so a message that stayed simply draws no untagged line,
   while RFC 1939 §6 does, so a POP3 commit that could not remove everything
   answers `-ERR` rather than a success the client would act on.

9. **Resource exhaustion.** Every listener bounds one source address: how many
   connections it may hold at once, how many it may open in a minute, how many
   sign-ins it may fail in a rolling quarter of an hour, and how large a message
   it may send. All four are settable, and the connection ceiling is the one
   worth moving, because ten at once is a fair bound on a stranger delivering
   mail to port 25 and a low one for an office or a household whose mail clients
   all reach the server as a single address. Each listener holds its own
   allowance, so a client that keeps a mailbox open does not spend what it needs
   to send. A connection that stops talking is closed on a per protocol idle
   timeout, and a peer that has slowed rather than stopped is closed too: both
   SMTP listeners hold a floor of a hundred bytes a second on the message body,
   answering `421 4.7.0` below it, over `DATA` and over chunked transfer alike.
   The rate is judged over short windows rather than across the whole message,
   so an opening burst buys no credit against a slow tail. That closes the case
   the idle timeout structurally cannot reach, because each arriving byte pushes
   an idle deadline out again.

   Every one of those budgets is keyed on the source address, so an attacker
   spread across many addresses buys the per-address ceiling once per address.
   What bounds the total is a second ceiling each listener holds on its own: at
   most 1024 accepted sockets, whoever they belong to, with the excess closed by
   the runtime before it costs a parser or a state machine. Beyond that, capacity
   in front of the server is the answer, which is why volumetric denial of
   service is listed as outside this model. Neither the byte-rate floor nor the
   per-listener ceiling is settable; the four per-address budgets are.

   Accepting a message costs time in proportion to its size. The SMTP reader
   scans each arriving chunk once for the terminator and for the smuggling
   shape, carrying a few bytes of overlap so a pattern spanning a boundary is
   still found, and assembles the whole body once at the end. So the message
   ceiling bounds the memory one inbound message holds rather than a
   disproportionate share of processor time, and it is that resident cost,
   multiplied by the connections a listener will accept, that raising it should
   be weighed against.

   Sieve scripts run under a gas counter so a runaway rule cannot stall
   delivery, and a script that exhausts it delivers to INBOX rather than costing
   the message.

10. **Reputation abuse.** Every outbound path goes through one delivery
    composer, so there is no second sender that skips policy.

    Inbound mail is evaluated against the sending domain's own DMARC record at
    the end of DATA, which is the same check external receivers run, and a
    domain publishing `p=reject` has its forgeries refused on the wire with
    `550 5.7.26`. A domain publishing `p=quarantine` does not: this server has
    nowhere to quarantine to, so the message is accepted, an
    `Authentication-Results` header recording the failure is prepended, and it
    lands in the recipient's INBOX unless their own Sieve script files it
    elsewhere. An operator who wants a failing message kept out of an inbox
    publishes `p=reject`, or writes that rule into Sieve and tests it.

    The ARC chain is evaluated in the same pass and reported as an `arc=`
    result in that header, and it is deliberately kept out of the accept
    decision. Reporting a verdict this server then ignores looks like an
    oversight, so the reason is worth stating: an ARC result is worth exactly
    what its sealer is worth, and there is no setting here that names the
    sealers an operator trusts. Anyone who can register a domain and publish a
    selector can seal a flawless chain over their own forgery, asserting that a
    victim's domain authenticated before the message was forwarded. A chain
    allowed to lift a DMARC failure would therefore be a general way past DMARC
    for any domain at all, available to whoever wanted it, so a chain that
    validates lifts nothing and a chain that does not verify refuses nothing.
    Any header the sender attached claiming this server's own name is removed
    before this server writes its own, so a filter reads the receiver's finding
    rather than one the sender chose. What the header cannot carry is why a
    chain failed: RFC 8617 §5.2 gives it three tokens, so a seal that was
    checked and rejected and a sealer's key that could not be looked up both
    read `arc=fail`. The verdict behind it separates them and the audit row
    records the difference, which matters because only one of the two says
    anything about the sender. The trust that can be expressed today is
    the narrower one: a recipient's Sieve script reads the `arc=` result and
    files on it, and the account holder who subscribed to a mailing list is the
    person who knows they trust it, which no server-wide list of sealers could
    say for them.

    Signing is not unconditional either, which matters because a receiver's
    view of this domain is built out of what arrives signed. The signer reads a
    message as text, so a message carrying octets that are not valid UTF-8
    cannot be signed without altering it, and a signature over an altered copy
    would attribute to the domain a message its sender never wrote. Those relay
    unaltered and unsigned, under an audit action of their own. A domain with
    no active selector produces the same outcome under a different action.
    Either way the mail goes and the row is the only place it is recorded, so
    an operator who needs every message attributable watches for
    `blamepost.mail.listeners.submission_unsigned_unrepresentable` and its two
    siblings.

    Suspending an account stops it authenticating at once, which is the control
    an operator has for a compromised credential. What is not here is a
    per-account sending budget: nothing caps how much one authenticated account
    may send, so the bound on a stuffed credential is how quickly its outbound
    volume is noticed. Watch it, and treat a spike as an incident. What such a
    credential reaches is the whole of it: mail signed for the account's own
    domain and delivered to peers, the mailbox it belongs to, and every other
    mailbox on this server. The standing the domain has with receivers is
    spent from the moment the first run goes out, which is why the outbound
    volume is the number to have an alarm on rather than a report to read
    afterwards.

11. **Supply chain.** Zero npm runtime dependencies. One vendored framework,
    pinned to a published version, integrity-verified against the publisher's
    digest before it is extracted, and changed only through a single script that
    fails closed when the digest mismatches or when the registry publishes no
    digest at all. Releases carry four trust roots, each verifiable without
    the others: signed tags, SLSA L3 provenance, Sigstore-signed SBOMs, and a
    post-quantum signature over the release digests. The fourth is built and
    wired into the publish workflow, and until the `RELEASE_PQC_SIGNING_KEY`
    secret is set in the publish environment the step announces that it
    skipped and the release ships with the other three.
    [SECURITY.md](SECURITY.md) carries the verification recipe for each root.

12. **Future decryption of today's ciphertext.** Sealed data uses post-quantum
    key agreement and symmetric encryption with no classical-only fallback, so
    there is nothing worth capturing now to decrypt later. This covers data at
    rest and does not extend to DKIM: the `DKIM-Signature` `a=` tag draws from an
    IANA registry with no ML-DSA value, so the outbound mail this server does
    sign carries Ed25519 and RSA-SHA256, and a signature on archived mail is
    only as strong as those against a future capability. That limit belongs to
    the wire format, and
    ROADMAP.md tracks it as blocked on standardization rather than claiming
    otherwise.

    Mail in transit sits in the same threat class and carries a weaker
    guarantee than data at rest, because the peer decides half of it. Every
    listener presents one key-agreement preference, written as the ML-KEM
    hybrids followed by the elliptic curves. The order is enforced rather than
    advertised: a peer that names a hybrid anywhere in its offer is asked to
    retry on the hybrid even when it put a classical curve first, so a session
    lands on a classical exchange only when the sender implements no hybrid at
    all. That is as far as a receiver can push. Such a session is
    indistinguishable afterwards from a hybrid one, because a server socket
    cannot report the group it negotiated, so an operator cannot measure how
    much of their inbound mail is exposed to this.

    Refusing the classical exchange outright would not close the gap, and the
    reason is the shape of this server rather than a preference. No listener
    accepts an envelope on an unencrypted session, so a sender whose handshake
    is refused on port 25 has no second route: it retries in the clear, is
    answered `530 5.7.0 Must issue a STARTTLS command first`, and the message
    stays in its queue until it bounces. Narrowing the accepted set trades whole
    messages for an exposure the narrowing does not remove, since the sender
    that would have been forced onto a hybrid is exactly the sender that has
    none. The preference therefore accepts every curve RFC 8446 §4.2.7
    registers, including the `secp256r1` §9.1 makes mandatory where X25519 is
    only a SHOULD, and leaves off only finite-field Diffie-Hellman. The browser
    interface carries the same preference, so the two halves of the server
    accept one set. An operator whose threat model includes captured transit
    traffic should confirm the exchange at the sending end as well, and
    understand that the classical fallback below it is silent.

13. **A correct configuration deployed under weakened guarantees.** Every class
    above assumes the process is actually running with the protections it
    describes, and that assumption is the one nothing else checks. A vault left
    in its unprotected mode, a database opened without at-rest encryption, an
    audit signing key sitting unsealed, clock checking switched off so audit
    timestamps stop being evidence, a transport floor lowered back below TLS
    1.3, a data directory the rest of the host can read, a runtime older than
    this build supports, or the process started in a development or test
    runtime: each of those is silent. Mail flows, clients connect, and the
    guarantees are not the ones this document describes.

    So they are asserted at boot rather than assumed, before any listener binds,
    and a deployment that fails one refuses to start and names every predicate
    that failed rather than the first. The data directory check reads the mode
    on disk, which is what a mounted volume decides rather than what created it,
    and it applies where file modes do: `chmod 750` is the fix and the refusal
    prints it. This gate stands alongside the one that keeps the MX listener
    shut until the DNS records for every hosted domain have been acknowledged.

14. **Mail that is lost with nothing reporting it.** The classes above are
    about a message somebody should not have, or should not have been able to
    send. This one is about a message that was accepted correctly and is then
    gone, while the server carries on answering normally. No attacker is
    needed. It belongs here because the mail is as lost either way, and
    because nothing else on the server says so.

    The version that loses everything at once needs only a second process
    writing the same data directory. The database is encrypted at rest, so
    opening it for writing means decrypting the whole file into a working copy
    of its own, serving every query from that copy, and writing it back on a
    timer and at shutdown. Two writers cannot see each other's copy, so both
    write the whole volume back and whichever writes last replaces the other's
    entirely. Every message the loser accepted since it started is gone, the
    window is bounded by neither process's lifetime, and what is on disk is
    internally consistent and simply missing that mail, so nothing downstream
    reports it either. The verbs that reach this are the ones nobody thinks to
    guard: `audit read` and `account sieve` report rather than change, and what
    sends them here is that each is recorded as it runs and leaving that row is
    a write. So the rule is about writing the volume rather than about which
    verbs are safe. One process writes it, recorded in a lock file naming that
    process and the process table it belongs to, and a second is refused before
    anything decrypts. The holder is confirmed by asking the kernel whether it
    is still running, never by taking an assurance that the server is stopped,
    because a gate that reads an assurance fails open on the one occasion the
    assurance is wrong. A lock recorded in a different process namespace, which
    is what a server inside a container looks like from the host, is refused
    without being reaped: deciding a process is dead from a lookup in the wrong
    table is the decision that loses the mail. A reader is not a second writer
    and takes no lock: `account list`, `domain list`, `dkim list`, `blobs
    report`, `audit verify-chain` and `doctor` open the same volume read-only,
    write nothing back, and answer while the server runs. Verbs that open
    neither the database nor the vault, such as reading the outbound spool,
    never arrive here at all.

    The other version loses one message rather than all of them. A delivered
    message is two writes that cannot be made one: the sealed octets go under
    `blobs/` named by the digest of their own content, and a row naming that
    digest goes in the database. A filesystem write is not part of a database
    transaction and never can be, so a process that stops between the two
    leaves one half alone and neither half complains. Four states follow, and
    no protocol reports any of them. Octets nothing references sit on the
    volume, never served and never reclaimed. A row whose octets are missing
    lists in IMAP, JMAP and POP3 and then fails to return a body, which is an
    outage for one message that is invisible until somebody opens it. Octets
    that no longer hash to the digest naming them are the same outage with a
    reason to look at the volume rather than at the mailbox. And a quota
    charged for a message no protocol can list fills a mailbox up against
    nothing. `blamepost blobs report` names all four and `blamepost doctor`
    runs the same check; both count the bodies rather than opening them, so
    the one that has been altered in place is only visible under `blobs report
    --verify`, which unseals each referenced body and hashes it back.

    Reporting is deliberately separate from deleting, and the two answer
    differently while the server runs. The report opens the volume read-only,
    which freezes the rows at the server's last write to disk while the blob
    directory keeps moving, so it carries that moment and holds a body written
    after it apart from a body nothing references. Without that bound every
    message delivered since would be counted as unreferenced, which is a wrong
    answer rather than an old one. The digest check is unaffected either way: a
    referenced body that no longer hashes to its own name is altered whenever
    it is read.

    The reclaim refuses on that same open, and refuses rather than narrowing
    its window, because unlinking a file is not a database write and nothing
    below the store could stop one. Against the volume itself it removes only
    unreferenced octets, only once they have been on disk for longer than a
    day, and only after re-reading the rows immediately before each unlink. On
    a running server a body with no row and a body whose row is still being
    written are the same thing to look at, and waiting is what tells them
    apart, so the window has no setting: a knob there would exist to be set to
    zero on the day somebody is in a hurry. A file under `blobs/` that is not a
    body at its own content-addressed path is reported and never removed,
    because a reclaim that deletes what it does not recognize is one that
    deletes an operator's partial restore.

## Outside this model

These are real risks that blamepost does not answer. They are listed so an
operator can decide how to cover them, not to dismiss them.

- **A compromised host.** Once an attacker has root, the unsealed vault key is in
  memory, the DKIM keys are in memory, and every mailbox is readable. Host
  hardening is the operator's, and it is worth doing: full-disk encryption,
  secure boot, a mandatory-access-control policy, a minimal attack surface on
  the box.
- **A malicious or coerced operator.** An administrator can read mail and can
  destroy an account. Not through the operator interface, which claims no mail
  scope and reaches no mailbox but its own, but from the host: whoever holds the
  vault passphrase and a shell can reset an account's password with
  `blamepost account passwd` and then sign in as it. The audit chain records
  that, and it does not survive this adversary: the key signing its checkpoints
  is sealed under the same passphrase, so somebody holding it can rewrite every
  row, sign the result, and rewrite the plaintext record beside the volume that
  would otherwise disagree. A system whose administrator is the adversary is not
  a system this design can defend. What answers this is a copy of the trail
  somewhere the server cannot reach, meaning a log sink on another host fed as
  the rows are written, plus end-to-end encryption between correspondents for
  the mail itself, which the server neither provides nor interferes with.
- **Loss of the vault passphrase.** There is no recovery path, deliberately. That
  is what makes disk theft survivable; it also means the passphrase must survive
  independently of the volume.
- **A compromised account device.** A credential typed into a phone with malware
  on it is a working credential. Session binding and lockout slow an attacker
  down; they do not undo an endpoint compromise.
- **Network-layer denial of service.** Per-connection and per-address budgets cap
  what one source can consume. Volumetric attacks need capacity in front of the
  server, from whoever provides its connectivity.
- **Traffic analysis.** Who corresponds with whom, when, and how much is visible
  to anyone positioned on the network, and to the receiving side, regardless of
  transport encryption. Mail's metadata is not confidential and never has been.
- **Spam classification and reputation blocking.** This release runs no
  classifier, no blocklist lookup and no greylisting. The MX listener accepts
  the gates for all three and nothing is passed to them, and no setting turns
  them on, so an operator who wants that layer today puts it in front of port 25
  or filters after delivery with Sieve. What the listener does enforce is
  authentication and shape: SPF, DKIM, DMARC, ARC, HELO discipline and envelope
  screening, with the ARC result reported rather than acted on. [ROADMAP.md](ROADMAP.md) tracks wiring the rest under Anti-abuse
  and content scanning.
- **What the far side does.** Once a message is delivered, its confidentiality,
  retention and disclosure belong to the receiving system. Transport policy
  protects it in flight and nothing after.
- **Legal compulsion.** Warrants, orders and their handling are the operator's
  jurisdiction and the operator's problem. The audit chain records access; it
  does not prevent lawful access.
- **Physical and fault attacks** against the host.

## Reporting

Security issues are reported privately. [SECURITY.md](SECURITY.md) has the
process, the response targets, and the recipes for verifying that a release is
the one that was published.
