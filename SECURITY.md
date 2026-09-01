# Security policy

blamepost accepts bytes from anyone who can reach port 25. Its security posture
is not a feature list. It is the reason the project exists in the shape it does.
This document covers how to report a vulnerability, what the response targets
are, the obligations that come with running a mail server, and how to verify
that the release you are about to deploy is the one that was published.

[THREAT-MODEL.md](THREAT-MODEL.md) states what the server defends against, where
the trust boundaries sit, and what is outside them.

## Supported versions

Pre-1.0, only the latest tagged release is supported. Older patch lines receive
no backports. Operators upgrade across breaking changes; deprecation warnings
ship at least one minor before a removal.

| Version | Security patches |
|---|---|
| Latest `v0.x` tag | yes |
| Any earlier tag | no |

Once 1.0 ships, the windows in [LTS-CALENDAR.md](LTS-CALENDAR.md) take effect.

## Reporting a vulnerability

**Do not open a public issue.** A mail-server vulnerability is exploitable the
moment it is described, against every deployment that has not yet upgraded.

Report privately through GitHub Security Advisories:

**<https://github.com/blamejs/blamepost/security/advisories/new>**

If the advisory form is not available to you, mail `security@blamejs.com`, the
maintainer-operated mailbox for this organization.

Include:

- The version: a `v0.X.Y` tag, or the `main` `<sha>` you tested.
- What you observed and what the impact is.
- A reproducer. For a wire-protocol issue, the exact bytes: the SMTP, IMAP,
  POP3 or ManageSieve transcript, or the raw message that triggers it, attached
  as base64 rather than described in prose.
- Whether anyone else knows, and any disclosure timeline you are already
  committed to.

Reports are acknowledged on receipt and triaged before the clock below starts.

### Response targets

| Severity | What it covers | Fixed release |
|---|---|---|
| Critical | Remote code execution, authentication bypass, unauthenticated relay, vault compromise, cross-account mail disclosure, audit-chain tampering | 24 h |
| High | Submission-identity bypass, session or CSRF bypass, sealed-data leak path, TLS-policy downgrade, a parser crash reachable pre-auth | 7 d |
| Medium | Information disclosure without an authentication bypass, denial of service against a single connection or account, a policy check that fails open | 30 d |
| Low | Defense-in-depth gaps, log-redaction misses, hardening that should be tighter | 90 d |

Disclosure is coordinated with the reporter. The advisory publishes when the
fixed release ships, with a typical embargo of 14 days afterwards so operators
have time to upgrade. Reporter credit goes in the release notes unless anonymity
is requested.

## Running a mail server responsibly

Some obligations cannot be enforced by the software. They are yours.

- **Publish the DNS posture before the first message.** SPF ending in `-all`,
  DMARC at `p=quarantine` or stricter, per-domain DKIM selectors, an MTA-STS
  policy in `enforce` mode, a TLS-RPT endpoint, and forward-confirmed reverse
  DNS on the sending IP. The record-by-record recipe is in
  [docs/operator-guide.md](docs/operator-guide.md), and the MX listener refuses
  to bind until you confirm it is done. A server that sends unauthenticated mail
  damages its own domain's reputation faster than any spam filter can be tuned.
  Verify it with `blamepost doctor` rather than by eye, and read its answers in
  three kinds rather than two. Every lookup the check makes is bounded, so a
  resolver that accepts a question and never answers cannot hold the run open,
  and a lookup that could not be completed is recorded as unanswered rather than
  folded into a missing record. That distinction decides where you go next: a
  missing record is yours to publish, while an unanswered one is a question
  about the resolver this server reads and says nothing about your zone.
  Nothing here treats a lookup that ran out of time as a record that is not
  published, which matters because the opposite would let somebody retire a
  policy by stalling its query rather than by having to break it.
- **Know where this server's DNS questions go.** One resolver serves every mail
  path, and nothing names its upstream: no configuration key and no
  `BLAMEPOST_` variable reaches it, so it queries the vendored framework's
  default DNS-over-HTTPS endpoint. Every SPF, DKIM, DMARC, MTA-STS, TLSA and
  reverse-name lookup therefore leaves this machine to a third party, which then
  sees every name a peer causes this server to ask about. It is also the
  resolver you are vouching for when you set `outboundPolicy.dnssecValidated:
  true` so `dane: "enforce"` will run, so satisfy yourself that it validates
  before you make that statement. Substituting a resolver means passing
  `blamepost.create` one of your own, which is a lever for embedding this server
  rather than for running the image. Hold the default against whatever egress
  and confidentiality policy the host is under, and treat it as a choice you
  made rather than one that was made for you.
- **Set an abuse posture and watch it.** A working mail server is a target for
  spam and phishing operators the day it appears in DNS. What blamepost enforces
  on its own is authentication and shape: HELO discipline, envelope screening,
  SPF, DKIM and DMARC at DATA with the ARC chain (RFC 8617) evaluated beside
  them and reported in `Authentication-Results` without changing the
  disposition, per-peer connection and authentication-failure
  budgets, a refusal of any body a lenient receiver would read as two messages
  (the CVE-2023-51764 SMTP-smuggling class, refused on the MX port and on both
  submission ports, and on the chunked transfer the submission ports advertise
  as well as the line-by-line one every port accepts), and a refusal
  to relay for an unauthenticated sender, for an envelope the authenticated
  account does not own, or for an author it may not write. There is no
  source-address exception to any of that. This server does not relay for a
  network, and a range configured for one stops the start rather than being
  honored, because every listener it runs requires STARTTLS before it will
  accept an envelope: a device that can reach `RCPT TO` on port 25 has already
  completed a handshake it could have signed in over, so give it an account on
  the submission listener instead of a place on an allowlist. A range would also
  be the wrong shape for the job, since an address names a segment rather than a
  party, and withdrawing one compromised host means withdrawing every device
  behind it. What it does not yet run is the reputation layer: no blocklist
  lookup, no greylisting, no content scoring, and no per-account sending budget.
  The ARC result is reported and
  never acted on, because acting on a chain means trusting whoever sealed it and
  there is no setting that names the sealers you trust. The per-peer budgets
  count connections, connection rate, authentication failures and refused
  recipients, and beside them both SMTP listeners hold a floor on how slowly a
  peer may send: a body arriving below a hundred bytes a second is answered
  `421 4.7.0` and cut, over `DATA` and over chunked transfer alike, judged over
  short windows so an opening burst buys no credit against a slow tail. That is
  the bound the idle timeout cannot give, since a peer sending one byte at a
  time is never idle. Each listener also accepts at most 1024 sockets at once
  whoever they belong to, so the process-wide total is not the per-address
  ceiling multiplied by however many addresses a sender can speak from. Neither
  number is settable; size what one hostile address can hold open against the
  per-address ceilings that are.
  Put a reputation layer in front of port 25 or after delivery if you need
  one, review the audit log for authentication failures and submission spikes
  with `blamepost audit read --outcome denied`, and treat a sudden outbound
  volume change as an incident rather than as growth.
- **An alias is a sending identity, not only a forward.** Submission binds the
  `From` header as well as the envelope, and the set it measures an author
  against is the account's own address plus every active alias that lands in
  that account's mailbox. So pointing `ceo@example.com` at an assistant's
  account, to get holiday mail somewhere it will be read, also lets that account
  write `ceo@example.com` as the author of outgoing mail. Where the alias and
  the account sit in the same domain, that mail leaves signed with the domain's
  key and DMARC-aligned, and nothing a recipient can see distinguishes it from
  mail the named person sent. For a shared departmental address this is what the
  binding is for. For a convenience forward it is a grant nobody meant to make,
  and there is no forward-only alias to reach for instead: an address that must
  receive mail without anyone being able to send as it needs an account of its
  own rather than an alias onto somebody else's mailbox. Two things bound the
  grant. A catch-all is never an identity, because it claims every name in the
  domain. And only a direct alias counts, so an address that reaches the mailbox
  through a second alias delivers there without becoming an author that mailbox
  may write. The set is read from the store on every message, so removing or
  disabling an alias withdraws the identity at the next message rather than at
  the next sign-in. Where the grant is actually exercised is the webmail
  interface and JMAP, both of which compose their own envelope from the account's
  own address and put the chosen alias in `From` alone. Review the alias list on
  the same schedule you review who holds administrator rights.
- **Watch the queue, because it is the first place trouble shows.** A message a
  peer defers keeps its place and its budget; one that fails permanently ends
  with a delivery report to the account that sent it. `blamepost queue list`
  shows what is waiting and against which receiver, and `blamepost queue held`
  shows what has stopped and what would release it. The queue is bounded, and
  reaching the bound refuses new mail with a temporary code rather than dropping
  it, so a stalled outbound path costs deliverability rather than messages.
  Watch the depth as well as the contents: at the ceiling your own account
  holders are the ones being told to try again. An account that ignores its
  reports keeps mailing addresses that no longer exist, which is one of the
  strongest spam signals a receiver has.
- **Report generation is bounded, and the bound is a spam control rather than a
  performance one.** A delivery report goes to whoever the failed message
  claimed to be from, which on a forged run is somebody who never wrote to you,
  so an unbounded reporter is a way to make this server send mail on an
  attacker's behalf. Reports are capped per sender and in total across a rolling
  window, and they draw on a reserved share of the queue that authenticated
  submission is never charged for. A report refused by that bound is recorded
  rather than silently dropped, so the count stays meaningful. If you see it
  climbing, somebody is using your server's name. Canceling queued mail is the
  same reporting path reached by hand, and it reports only what it actually
  erased: a message that leaves the queue while a cancellation is running is
  recorded as not canceled and its sender is not written to, so pressing that
  button during an incident cannot turn into mail addressed to a reverse path
  somebody else chose.
- **Do not host what you will not police.** If you host domains for other
  people, one account's blocklist entry becomes every account's deliverability
  problem, because receivers score the sending IP. Suspend submission for an
  abusive account rather than letting a shared reputation absorb it. Note also
  that administrator rights are held server-wide rather than per domain: an
  account with them administers every hosted domain, not the one it belongs to.
  Grant them to people you would trust with all of the mail on the machine.
- **A domain name is folded to one form, and a lookalike is refused rather than
  folded.** The spellings that mean the same domain are treated as the same
  domain wherever one is read: the absolute form ending in the DNS root's dot,
  and any difference of case. So the same domain typed into the administration
  pages, passed on the command line and written in a client's envelope reaches
  one hosted-domain row, one set of signing selectors and one sealed key file,
  and you cannot end up with two of any of them by typing the name a second way.
  An address carries a domain, so the same holds inside one. An account signs in
  over submission, IMAP, POP3 and ManageSieve whichever way its domain was
  written in the client, and no second spelling opens a second mailbox. A
  message that arrived naming the absolute form in a header can be answered:
  the reply, the forward and a send from a JMAP client all reach the mailbox
  that header names, addressed in the form the receiving server reads.
  What is refused outright is a name that only renders like one you host: a
  label containing non-ASCII characters, a label already encoded as `xn--`, and
  a label mixing scripts. That refusal is not selective, so an internationalized
  domain cannot be hosted here at all today. If you need one, host its ASCII
  form and be aware that mail addressed to the Unicode spelling will not reach
  it.
- **Keep a second administrator, so containment does not cost an outage.** The
  console refuses the three changes that would leave nobody able to sign in to
  it, and decides that refusal in the moment the change is saved, so neither one
  mistyped form nor two windows working at once can shut it. That refusal is not
  a substitute for having somebody else with the role. An administrator whose
  password has been taken is suspended from the console in seconds while another
  administrator remains. When there is only one, the way to close that account
  runs through the host, and every verb that changes an account needs the data
  volume the running server holds, so it means stopping the server: correct
  containment, and a full mail outage for as long as it takes. Grant the role to
  a second account you control before you need it. `blamepost init`, run again
  against the same data directory with an address that does not exist yet,
  creates one from the command line without touching the hosted domain or its
  keys.
- **Console sessions are held to the device they were opened on, and mailbox
  sessions are not.** A console request whose client address, browser or accepted
  language differs from the sign-in is refused, and the operator signs in again.
  The session row is kept, so the account's mail stays open and a stranger
  replaying a copied cookie cannot sign the operator out by trying. Mailbox
  sessions are recorded rather than ended when the device changes, because
  binding a mailbox to an address logs a phone out every time it moves between
  wifi and a cell network. Read `auth.session.fingerprint_drift` to see where a
  mailbox session has been used from, and
  `blamepost.web.console_device_refused` for a console session that was turned
  away. If you administer from several machines, expect a password on each.
- **Know which sign-in budgets a clock correction can clear.** Guessing at one
  mailbox is bounded per mailbox, and the counters this server keeps are measured
  on a clock the host cannot step, so an NTP correction or a virtual machine
  resuming from a snapshot does not release a lockout early or hand back a
  counter that has not decayed. Two budgets are not on that clock, because they
  are measured inside the framework and it offers no seam for one: the
  per-source authentication-failure ceiling the mail listeners apply before a
  password is checked, and the five-minute window on browser sign-in posts. A
  step forward past either window ends it. Both fail in the permissive
  direction, so a host whose time source somebody else can influence has a way
  to retire those two counts on demand. Keep the clock disciplined, and prefer a
  time source you control.
- **The browser sign-in bound is per source address, and a terminator makes it
  one bound for everybody.** Fifty posts to the sign-in form in any five-minute
  slot from one address are accepted; past that the form answers `429` until the
  slot ends. This server reads the peer off the socket and ignores
  `X-Forwarded-For` everywhere, so behind the TLS terminator in `compose.yml`
  every browser arrives from the terminator's address and those fifty are shared
  across everyone signing in. The bound is there to cap cost rather than
  guessing: each post buys one password verification, which runs even for an
  address with no mailbox here so that the answer does not say which addresses
  exist. Size any front door you put in front of this with that sharing in mind.
- **Check that no signing key has outlived the record that named it.**
  `blamepost doctor` holds the sealed private keys in the data directory's
  `keys` folder against the DKIM selector records, and its `signing keys` line
  fails on either direction. A key no record names is signing material this
  server will never use or remove, and it rides into every backup bundle taken
  from then on, so whoever reaches one of those copies signs mail as the domain
  for as long as they last, including after the name is hosted somewhere else.
  Delete the files it names by hand. An active selector whose key is not on the
  volume is the opposite failure and it is already running: that domain's mail
  is leaving unsigned. Withdrawing a domain or a selector moves the key out of
  its place before the record goes and destroys it afterwards, so material this
  line finds was left by a restore, a hand edit, or a withdrawal the volume
  would not let finish. That last one leaves the file under its usual name with
  `.erasing` on the end and the command that ran prints it, so one reaching this
  line means the message went unread.
- **Protect the vault passphrase.** `BLAMEPOST_VAULT_PASSPHRASE` unlocks the
  sealed DKIM keys and account secrets in the data volume, and it unlocks the
  audit-signing key with them. That last one is worth saying plainly, because
  it sets the boundary the audit trail's guarantee stands on: whoever holds
  this passphrase can both read the mail and sign a rewritten trail, so the
  trail is evidence against everyone except the holder of this secret. Argon2id
  makes brute-force expensive; a short memorable passphrase is still memorable
  to somebody else. Keep it out of the shell history, out of the image, and out
  of the repository, and keep an offline copy. Losing it loses the volume.
- **Keep the backup passphrase separate from the vault passphrase.** A backup
  bundle is encrypted with its own passphrase, read from a file so it never
  reaches the shell history or the process list. The server refuses a file
  holding the vault passphrase, because a bundle travels off the machine and the
  vault passphrase does not: one secret opening both means a bundle that leaks
  takes the live volume with it. Both are needed to restore, and neither is in
  the bundle.
- **Take backups and prove they restore.** `blamepost backup run` writes an
  encrypted, signed bundle of the whole data volume. `blamepost backup verify`
  decrypts every file in one and checks it without touching the live volume, and
  neither it nor `blamepost backup inspect` opens the database, so both still
  answer on a server whose volume will not open. A bundle nobody has restored is
  a hypothesis, so rehearse `blamepost restore apply` on a scratch machine on a
  schedule. Record the signing key fingerprint that `inspect` prints and pass it
  back as `--fingerprint`: without it a signature proves the bundle is
  unmodified but not who wrote it.
- **Check the message bodies against the rows after any hard stop.**
  `blamepost blobs report --verify` unseals every stored body and hashes it back
  against the digest naming its file, so a body that has been altered or
  truncated under a file nobody rewrites is found by you rather than by the
  account holder who opens the message. The same walk in its counted form runs
  inside `blamepost doctor`, and both answer while the server is running. On
  that path the rows stop at the server's last write to disk while the blob
  directory is live, so the report carries that moment and names a body written
  after it as one the rows had not reached rather than as a body nothing
  references; without that bound every message delivered since would be counted
  as unreferenced, which would read as a volume diverging on a server where
  nothing is wrong. The digest check itself is unaffected by how old the rows
  are. Bodies that no row references are reported and never removed without
  `blobs reclaim --confirm --reason`, and never until they have been
  unreferenced longer than a delivery can take, because inside that window one
  that was stranded and one that is arriving look alike. `blobs reclaim` is the
  one verb here that still needs the server stopped, and it refuses on a
  read-only open rather than narrowing its window: unlinking a body is not a
  database write, so nothing below the store could stop one issued against rows
  that stopped minutes ago.
- **Watch for bodies a delivery had to rewrite.** A message delivered to several
  accounts is stored once, so a delivery that finds the file already there and
  shorter than the message can be writes the message again rather than leaving
  every later account holding an unreadable copy. Each rewrite is recorded as
  `blamepost.mail.mailbox.body_repaired` with the digest of the body, and a run
  of those rows is among the earliest signals a volume gives that it is failing:
  `blamepost audit read --action blamepost.mail.mailbox.body_repaired`. Do not
  read their absence as a clean volume. That check is a length, so it sees a body
  cut short and not one that changed in place, which is what the verifying walk
  above is for.
- **Alert on a message whose two records have come apart.** A message is the
  message store's row and this server's row beside it, and a mailbox holds the
  intersection of the two, so a row on either side without its partner is left
  out of every listing rather than served half. Four actions name the ways a
  pair separates, and none of them is ordinary:
  `blamepost.mail.mailbox.filing_not_rolled_back` and
  `blamepost.mail.mailbox.move_unbound` are a message the store holds that no
  mailbox names, which no delete verb reaches and an account erasure walks past,
  so each one is a body still on the volume that you have to clear by hand;
  `blamepost.mail.mailbox.stranded_preserved` and
  `blamepost.mail.mailbox.stranded_destroyed` are the reverse, a row here whose
  store partner has gone, finished on the layer that can still see it with the
  preservation order and the retention floor read again first. A run of any of
  them is a volume refusing writes rather than four separate incidents.
- **The retention floor is measured from arrival, so an uploaded date cannot
  move it.** RFC 9051 lets a client set a message's internal date when it
  uploads one, and this server stores that value, answers `INTERNALDATE` from
  it, and measures no window against it. The floor is measured against the clock
  this server stamped when the message was filed, and a row that cannot say when
  it arrived is kept rather than destroyed, because reading an absent arrival as
  the epoch would clear every window you can set. An uploaded date that is not a
  moment at all, whether not finite, before the epoch, or too large to hold
  exactly, is refused as `mailbox/bad-internaldate` where it arrives.
- **Prove an erasure landed instead of assuming it.** `blamepost account remove
  <address> --destroy --reason <text>` erases the account row, the aliases
  pointing at it, and everything the account holds: its mailboxes, its messages,
  its filter scripts, its annotations and the sealed message bodies. It runs
  through the same delete path IMAP `EXPUNGE` takes, so a message under a
  preservation order or inside the retention floor stays; the command names each
  one with the mailbox it is in and the reason, and exits non-zero only when
  something could not be erased for any other reason. The mail goes first and
  the account row last, only once nothing still names it: no mailbox row, no
  filter script, no annotation and no alias. A record you are required to
  produce is reachable only through the identity that owns it, so anything the
  erasure kept keeps that identity with it. An erasure that kept anything back
  opens with `Partly erased`, says the account was kept, and leaves it out of
  service and listed as `erasing`; run the same command again once the order is
  lifted or the window has passed. Two records mark that state and the status
  column is only one of them, because a records-retention posture can put a
  trigger on that column and refuse the transition itself: the row also carries
  `erasureHeldAt`, and the erasure files a chain entry as it closes.
  `blamepost account resume` and an archive both read them, so an account whose
  status write did not land cannot be archived and then reinstated back into
  ordinary use. A run that could write none of them prints `FAIL` for the write
  it could not make, and that is the case needing you rather than a rerun:
  suspend the mailbox, because its mail is destroyed and it would otherwise keep
  authenticating. Inbound mail stops either way: a peer naming an erasing
  address at `RCPT TO` is answered `550 5.1.1` before the body is transmitted,
  permanently rather than temporarily, because the state is not one you lift.
  `blamepost blobs report` is the check afterwards: it lists mail no
  account holds, which is mail on the volume that nothing can reach, and a
  volume reporting nothing under that heading is holding no mail belonging to an
  account that is gone. Mail an order or the floor is keeping does not appear
  there, because its account is still holding it. What this does not reach is a
  backup or a snapshot taken before it ran, since a message body is sealed under
  the volume's vault key rather than under anything the erasure destroys, so set
  the expiry of your backups against the erasure requests you expect to answer.
- **Answer a preservation order before you need to.** Listing an account's mail
  names the id each message is addressed by and marks anything already
  preserved; it prints no bodies, and it is recorded. Placing an order makes
  every hard delete refuse those messages afterwards, on every protocol and in
  an account erasure. Reading the orders back is how you establish that one is
  in force rather than trusting the command that placed it. Lifting one is
  confirmed and takes an approver, because the next hard delete on those
  messages destroys them. Orders carry no expiry, so a duty ends when you end
  it.

  **Hold an order against its boundary before you rely on it.** The register is
  keyed on the exact record the order names, and what you can name is a message.
  An order over an account's mail therefore preserves those messages and does
  not extend to the account's filter scripts, its annotations or its aliases: an
  erasure run while the order stands keeps every message it covers and destroys
  all three. The account row survives with them, because a kept message is
  addressable only through it, and the erasure reports itself as the partial one
  it is. Where a matter requires the fact that an address
  existed, or the rules its owner filtered on, an order over its mail preserves
  neither, and the answer is to hold the erasure until the matter closes rather
  than to place a wider order this server has no way to record.

  ```sh
  blamepost account messages alice@example.com --reason "identifying the records the order covers"
  blamepost account hold alice@example.com --mailbox INBOX --message obj_f313c8391a521b3b8c12af988195a7b4 --reason "preservation order 24-cv-01933" --citation FRCP-26
  blamepost account holds alice@example.com
  blamepost account release alice@example.com --mailbox INBOX --message obj_f313c8391a521b3b8c12af988195a7b4 --reason "matter closed" --approver records@example.com --confirm
  ```
- **Verify the audit chain on a schedule, and you can do it while mail flows.**
  `blamepost audit verify-chain` walks every row and every signed checkpoint and
  names the row and the two hashes if it stops. Run it after any restore, after
  any unexplained restart, and routinely enough that a break is found by you
  rather than by the person asking for the evidence. It answers while the server
  holds the data volume, from a read-only open that anchors no checkpoint of its
  own and verifies every signature already there, so the verdict is the one a
  stopped volume gives: the row hashes link, the signatures are the chain this
  server signed, and the record beside the volume agrees with the rows. That
  combination is what a rewrite with the checkpoints deleted cannot pass, and
  reaching it costs no interruption to mail. What the running answer covers is the
  chain up to the server's last write to disk, which the line above the answer
  names; the chain only ever grows, so that is a verified prefix. Stop the
  server when you need the verdict to reach the most recent rows as well.
- **Know what a killed server leaves unanchored, which is the last hour.** The
  record beside the volume, the one a wholesale rewrite of the chain has to get
  past, advances when the volume is opened, once an hour while the server runs,
  and once more when a stop closes the store in order. A process that ends
  without a stop, which is what an out of memory kill, a host reboot, a container
  killed rather than signaled and a power loss all are, therefore leaves the rows
  written since its last hourly anchor covered by the chain and the checkpoints
  alone. That is the half somebody who can write to a stopped volume can rewrite
  and leave agreeing with itself. Two things follow. Stop this server rather than
  killing it, which means giving the supervisor a stop timeout longer than the
  shutdown takes, so the window is closed rather than merely bounded. And treat
  the hour before an unexplained halt as the part of the trail that a copy of the
  volume is worth more than a reading of it.
- **Alert on `degraded`, because that is where an expiring certificate appears.**
  Nothing here issues or renews a certificate, so a renewal client that dies is
  invisible from every angle until the day every peer stops talking to this
  server at once. Both probes read the pair on disk on every poll and reduce
  their verdict from `ok` to `degraded` once the certificate is inside a
  fortnight of expiring, the chain is incomplete, the name this server announces
  is not covered, or the two files no longer agree. Over the loopback interface
  the answer also carries the days remaining and whether the pair is one this
  server could present at all. Neither probe refuses, including for a certificate
  that has already run out: refusing would take a server that is still carrying
  mail out of rotation, withdraw the interface you would read the reason from,
  and invite a restart this server would not complete, since it does not start on
  a certificate it cannot present. So `degraded` is the only signal, and a
  monitoring policy that alerts on failure alone will not see it.
- **Alert on `degraded` for the outbound queue too.** A queue that is filling
  and not draining is a server answering every probe perfectly while mail stops
  leaving, and nothing else on either probe can see it: the ports are still
  held, the store is still open and the certificate is still fresh. Both probes
  carry a `queue` check that reduces its verdict when the queue has filled past
  the point where it stops accepting mail for forwarding, when mail is waiting
  and nothing is draining it, or when this build cannot reach a peer at all.
  Neither probe refuses, for the reason the certificate does not: a restart
  re-reads the same queue off the same volume and changes nothing about it, and
  withdrawing the interface takes away the console you would cancel the stuck
  mail from without moving any of the traffic that fills the queue, which
  arrives on the mail ports rather than this one.
- **The health endpoint answers a stranger less than it answers itself.** The
  per-check breakdown, which names every listener and why one is held back, is
  returned only to a peer on the loopback interface, which is what the
  container's own probe is. Asked through a published port, the endpoint answers
  the status word alone. That split exists because the endpoint shares a port
  with webmail, so it is reachable by anyone who can reach the browser
  interface, and a per-check inventory of a mail server tells them which parts
  are up and which are held back. The peer is read from the connection rather
  than from a forwarded-for header, so a proxy cannot be talked into presenting
  someone as local.
- **A trail that cannot be written loses the row, not the change.** An
  administrative row is written after the change it describes has already
  reached disk, so a trail that is unavailable cannot make that change
  un-happen and does not pretend to: the verb reports its own outcome and the
  row is dropped. Plan for the consequence rather than the mechanism. If the
  trail is pointed at storage that can fail independently of the data volume, a
  gap in the trail is possible while every change it should have recorded
  stands, so alert on the gap rather than reading an uninterrupted chain as
  proof of completeness. Nothing is buffered to achieve this: a row still
  reaches durable storage before the verb returns, so an available trail loses
  nothing. A hard deletion is recorded by a separate path this does not touch,
  which is what keeps a crypto-erasure provable.
- **The chain proves that over the rows it read, and a purged range is not one
  of them.** An archive and purge deletes audit rows on purpose and records
  where the deletion stopped, and that record is the weakest thing on this
  volume: it sits in a table with no signature over it, no link into the chain,
  no checkpoint covering it and no append-only trigger guarding it, so one row
  written there discards every audit row at or below the counter it names from
  the walk. Writing it costs write access to the database, which is less than
  the vault passphrase every other reading here costs. So a volume carrying one
  is never reported as a trail nothing was removed from. `blamepost audit
  verify-chain` names the counter, says the gap is trusted on an unsigned
  record rather than on an archive it verified, and tells you to read the
  archive bundle for the range back with `blamepost audit verify-bundle`. The
  bundle is off the volume by design and this server resolves nothing to it;
  holding it against the counter is the operator's step and there is no
  substitute for it. Alert on that note the way you would alert on a break: a
  range nobody can produce a bundle for is a deletion wearing a retention run's
  clothes. The finding is recorded in `audit.disputed` and repeated on every
  later run, because opening the volume re-anchors the chain and destroys the
  comparison that found it. The volume goes on delivering mail either way.
- **Know which rows answer "who", and which do not.** The chain proves that no
  row was inserted, altered or removed by anyone who did not hold the vault
  passphrase, and every row records what happened, when, and the reason where
  the command took one. Administrative rows also
  record who: a console action names the signed-in account with the peer address
  and agent string beside it, and a command-line invocation names the
  operating-system account and the host the process ran as, written as
  `cli:<user>@<host>` so a filter on that column can tell a shell user from an
  account. A command-line row carries no peer address and none is invented,
  because a command run at a terminal arrived from nowhere and a value read out
  of the shell's environment would be a value that shell chose. That is a
  decision rather than a gap.
- **Delivery and the wire rows deliberately name no principal.** A message
  arriving from a stranger has a peer, not an identity anybody proved, and a
  refused sign-in names only the peer for the same reason: writing the address a
  refused attempt claimed into the column that answers who acted would let
  whoever is guessing choose the name an auditor reads back. So read the peer on
  those rows and the actor on the administrative ones, and do not expect either
  column to answer for the other.
- **The DKIM key lifecycle is on the trail too.** Minting, rotation, retirement
  and the sweep of a selector whose overlap has elapsed each write a row, under
  `blamepost.mail.dkim.keys_generated`, `blamepost.mail.dkim.keys_rotated`,
  `blamepost.mail.dkim.keys_retired` and
  `blamepost.mail.dkim.selectors_swept`. A rotation row names the outgoing and
  the incoming selector together, which is the only moment the pair exists at
  once. Refused attempts are recorded alongside the ones that succeeded, so a
  rotation somebody tried and could not finish is visible rather than absent. No
  key material of either half reaches a row: what is recorded is the selector
  name, its algorithm and its domain.

## Verifying a release

Every release carries four independent trust roots, and each is verifiable
without trusting the other three. The post-quantum sidecar described under the
fourth appears from the first release after the release-signing key is set up;
everything else here, including that root's byte digests, ships on every
release. Where the sidecar is present the roots also chain: the signed tag
covers the commit that carries the release-signing public key, that key verifies
the sidecar signature, and the sidecar covers the artifact bytes.

### 1. Signed commit and signed tag

Tags are annotated and SSH-signed. Verify against the maintainer's published
key rather than against the web UI's checkmark:

```sh
TAG=vX.Y.Z
git fetch --tags origin

git -c gpg.ssh.allowedSignersFile=keys/allowed_signers tag -v "$TAG"
```

Expected: `Good "git" signature for security@blamejs.com`.

`keys/allowed_signers` ships in the repository, so this works offline and does
not depend on a network service answering. It also means the file arrived with
the tag it is being used to check, so anchor it against something outside the
repository before you rely on it. Either anchor is enough:

```sh
# The fingerprint recorded in the table at the foot of this document.
# Each line in an allowed_signers file begins with a principal and a
# namespace, so the key itself is fed to ssh-keygen rather than the file.
awk '!/^#/ && NF {print $3, $4}' keys/allowed_signers | ssh-keygen -lf -

# The maintainer's signing keys as GitHub holds them. Every key in
# keys/allowed_signers appears here, and this list is a superset: it
# carries keys used for other projects, so it confirms a key rather
# than deciding which keys this project accepts.
gh api users/dotCooCoo/ssh_signing_keys --jq '.[].key'
```

Note that `https://github.com/dotCooCoo.keys` is a different list. It returns
authentication keys, and a key registered for signing alone does not appear
there, so it is the wrong place to look for a signing key.

Then confirm the tag points where it should. The commit it names is on `main`'s
first-parent history and arrived through a merged pull request, not a direct
push or a rewritten tag:

```sh
SHA=$(git rev-list -n 1 "$TAG")
git merge-base --is-ancestor "$SHA" origin/main && echo "on-main: OK"

PR=$(gh api "repos/blamejs/blamepost/commits/${SHA}/pulls" --jq '.[0].number')
test -n "$PR" && echo "merged via PR #${PR}: OK"
```

This is the defense against retroactive tag rewriting, a class that has been
exploited at scale. `tj-actions/changed-files` (CVE-2025-30066) reached more
than 23,000 repositories through a rewritten tag in March 2025.

### 2. SLSA L3 provenance

Each release ships an in-toto attestation binding the artifact to the workflow
run, commit and tag that built it. `gh attestation verify` walks the chain
through the GitHub API; `slsa-verifier` does it offline:

```sh
TAG=vX.Y.Z

gh release download "$TAG" --repo blamejs/blamepost --pattern '*.intoto.jsonl'
gh release download "$TAG" --repo blamejs/blamepost --pattern '*.tgz'

slsa-verifier verify-artifact <tarball>          \
  --provenance-path <tarball>.intoto.jsonl       \
  --source-uri      github.com/blamejs/blamepost \
  --source-tag      "$TAG"
```

For an air-gapped check, point `slsa-verifier` at a locally snapshotted Sigstore
TUF root with `--trusted-root /path/to/trusted_root.json`, captured once from a
trusted channel.

**What this proves and what it does not.** Provenance binds the bytes to that
exact build. It says nothing about whether the source was clean. The TanStack
compromise in May 2025 shipped 84 malicious versions carrying valid SLSA L3
provenance, because the attack was on the source side. Pair it with the signed
commit and signed tag checks.

### 3. Sigstore-keyless SBOM signatures

The project's own SBOM and the vendored tree's are both signed through the
publishing workflow's OIDC identity, with no long-lived key. Pin the workflow
path and the transparency-log URL, so a redirected lookup cannot substitute a
forged log:

```sh
cosign verify-blob sbom.cdx.json                                                                         \
  --bundle                      sbom.cdx.json.sigstore                                                   \
  --certificate-identity-regexp '^https://github.com/blamejs/blamepost/\.github/workflows/npm-publish\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com'                            \
  --rekor-url                   'https://rekor.sigstore.dev'
```

Repeat for `sbom.vendored.cdx.json` with its own `.sigstore` bundle.

The container image is signed the same way, by the release workflow that builds
it:

The image tag carries no `v`. The git tag is `vX.Y.Z` and the image published
from it is `X.Y.Z`, alongside the `X.Y` line and `latest`, which is the form
`compose.yml` and the quick start both use.

```sh
cosign verify ghcr.io/blamejs/blamepost:X.Y.Z                                                                    \
  --certificate-identity-regexp '^https://github.com/blamejs/blamepost/\.github/workflows/release-container\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com'
```

A successful verification proves the image came out of the release workflow on a
tag push, rather than from anyone holding a registry write token.

Verify by digest rather than by tag when it matters. A tag is a mutable pointer
and `latest` and the `X.Y` line both move; the digest the verification printed is
what a deployment should pin:

```sh
cosign verify ghcr.io/blamejs/blamepost@sha256:<digest> ...
```

### 4. Byte digests and the ML-DSA-65 sidecar

Classical digests first:

```sh
sha256sum -c <tarball>.sha256
openssl dgst -sha3-512 <tarball>    # compare against <tarball>.sha3-512
```

Then the post-quantum sidecar, which the framework's own ML-DSA-65 primitive
verifies with no Sigstore client and no external verifier binary.

A release cut before the release-signing key was set up carries no
`<tarball>.mldsa.sig`, and `keys/release-pqc-pub.json` is absent from the source
at that tag, so the fetch below returns 404. That is expected rather than a sign
of tampering: the digests above and the three roots before them are unaffected,
and the sidecar appears from the first release after setup. Check the tag you
are verifying before concluding a signature is missing.

Fetch the public key from the git source at the tag, not from the release page,
so it is covered by the signed tag you already verified:

```sh
TAG=vX.Y.Z

curl -fsSL -o release-pqc-pub.json \
  "https://raw.githubusercontent.com/blamejs/blamepost/${TAG}/keys/release-pqc-pub.json"

node -e '
  var b   = require("./lib/vendor/blamejs");
  var fs  = require("node:fs");
  var pub = JSON.parse(fs.readFileSync("release-pqc-pub.json", "utf8"));
  var sig = fs.readFileSync(process.argv[1]);
  var msg = fs.readFileSync(process.argv[2]);
  var ok  = b.pqcSoftware.ml_dsa_65.verify(
    sig, msg, Buffer.from(pub.publicKey, "base64url")
  );
  if (!ok) { process.stderr.write("ML-DSA verify FAILED\n"); process.exit(1); }
  process.stderr.write("ML-DSA verify OK (fingerprint "
    + pub.fingerprint_sha3_512.slice(0, 16) + ")\n");
' <tarball>.mldsa.sig <tarball>
```

Compare the printed fingerprint against the value recorded under Keys and
fingerprints. An attacker swapping the public key would also have to forge the
signed tag covering the commit that carries it.

## Keys and fingerprints

| Purpose | Algorithm | Value |
|---|---|---|
| Commit and tag signing | SSH Ed25519 | `SHA256:4jGhPWssp3tslI+eN2KMWenuog+8h58xOhHDY9xIfxA`, the principal `security@blamejs.com` in `keys/allowed_signers`. Registered as a signing key and not as an authentication key, so it appears under `users/dotCooCoo/ssh_signing_keys` and deliberately not at `https://github.com/dotCooCoo.keys`. |
| Release signing | ML-DSA-65 (FIPS 204) | `8c59e7029d7afc8cda650d9a870c657945c58f2cb7b6f270f00b5d13669eaf35b3b1f0ad0bbb4a0c2ea7b440965e109a753b2ae22d107cad1510362d96a3865a`, the SHA3-512 of the raw public key in `keys/release-pqc-pub.json`. Reproduce it with `node -e 'var f=require("node:fs"),c=require("node:crypto");var p=JSON.parse(f.readFileSync("keys/release-pqc-pub.json","utf8"));console.log(c.createHash("sha3-512").update(Buffer.from(p.publicKey,"base64url")).digest("hex"))'`. This file is commit-signed, so the value here is the out-of-band check on the key file beside it. |

The release-signing key is generated per repository by
`node scripts/generate-release-signing-key.js`, which writes
`keys/release-pqc-pub.json` for committing and prints the private half for the
`RELEASE_PQC_SIGNING_KEY` secret. Rotating it updates the committed public key,
requires the secret to be reset to match, and ships the new fingerprint in this
table in the same commit. Earlier fingerprints stay recoverable with
`git log -- keys/release-pqc-pub.json`.

Until the `RELEASE_PQC_SIGNING_KEY` secret is set in the publish environment,
the release workflow's sidecar step skips with a warning. The byte digests in
that section still ship, as do the three trust roots before it, so such a
release carries every root above, the fourth in its digest form alone.

## Cryptographic posture

Where the choice belongs to this project, it is post-quantum:

| Layer | Algorithm | Standard |
|---|---|---|
| Key agreement, sealed data | ML-KEM-1024, in a hybrid with P-384 | FIPS 203 |
| Release signatures | ML-DSA-65 | FIPS 204 |
| Audit-chain signatures | SLH-DSA-SHAKE-256f | FIPS 205 |
| Symmetric | XChaCha20-Poly1305 | RFC 8439, extended nonce |
| Digest | SHA3-512 | FIPS 202 |
| Key derivation | HKDF-SHA3-512, SHAKE256 | RFC 5869, FIPS 202 |
| Passwords | Argon2id | RFC 9106 |

Where an interoperable wire format sets the algorithm, it does not, and saying
otherwise would be a claim an operator could not verify:

| Layer | Algorithm | Standard | Why not post-quantum |
|---|---|---|---|
| DKIM, first selector | Ed25519 over SHA-256 | RFC 8463 | No ML-DSA value is registered for the DKIM `a=` tag |
| DKIM, second selector | RSA-SHA256 | RFC 6376 | Fallback for receivers without Ed25519 support |
| Transport, every listener | TLS 1.3 floor; ML-KEM hybrids first, every registered elliptic curve behind them | RFC 8446 | A peer with no post-quantum support still has to be able to deliver, so a classical exchange stays reachable |

Both signatures ship together, which is the dual signing RFC 8463 §3 describes,
and a receiver that cannot verify one evaluates the other.

**What leaves a message unsigned has nothing to do with its character set.** An
8-bit body in a legacy single-byte charset is signed like any other: the octets
the signer returns are the octets that went in, and the signature covers those
same octets. That pair is the whole guarantee and either half alone is worthless,
since a signer returning the message intact while hashing a decoded copy emits a
signature that fails at every receiver, and one that hashes and returns the
decoded copy attests to content the sender never wrote.

Two things do stop the signer, and they are separate audit actions so an alert on
one does not send you to fix the other. A domain holding no active selector
cannot be signed for, which is a setup state rather than a steady one because
`blamepost domain add` mints a pair as it hosts the domain. And anything that
stops the signer afterwards, a key that will not unseal being the usual one. Both
are named with their actions under Mail that is not valid UTF-8 in
[docs/operator-guide.md](docs/operator-guide.md). A domain publishing `p=reject` should expect a receiver to reject
unsigned mail when SPF does not also align.

Post-quantum DKIM is not offered because the `a=` tag draws from an IANA
registry with no ML-DSA entry, so such a signature would be unverifiable by
every receiver rather than merely unsupported by some. It is tracked in
[ROADMAP.md](ROADMAP.md) as blocked on standardization.

The transport row is the one most easily misread from the table above it. Every
listener refuses anything below TLS 1.3, and that floor is set for the whole
process rather than per listener, so it holds for the sockets this server opens
outbound as well. Which key exchange runs inside that handshake is a separate
question, and the answer is the same on every port this server binds.

Every listener presents a context carrying one key-agreement preference, written
as slash-separated positions. Each group this server prefers holds a position of
its own: `X25519MLKEM768`, then `SecP256r1MLKEM768`, then `SecP384r1MLKEM1024`,
then `X25519`. The slash is what makes those an order rather than a list. A
peer that names a hybrid anywhere in what it offers is asked to retry on the
hybrid, even when it put a classical curve first; a peer that supports no hybrid
completes on whichever curve it brought.

Ordering exists only between positions, so groups sharing one are a set the
server takes in whatever order the handshake reaches them. That is why every
preferred group holds a position of its own rather than sharing one: a hybrid
sharing a position with `X25519` loses to it whenever a peer offers both, and the
preference would then say something other than what the list reads as.

The final position is the exception and holds the remaining curves RFC 8446
§4.2.7 registers (`X448`, `secp256r1`, `secp384r1` and `secp521r1`) as one
unranked set, which is what lets a conforming peer reach this server whatever it
implements. §9.1 makes `secp256r1` mandatory and X25519 only a SHOULD, so a peer
offering the first and not the second is entitled to arrive and does. What the
preference leaves off is finite-field Diffie-Hellman, and that is the whole of
what it refuses.

The line is drawn there because of what a refusal costs on this server rather
than because finite-field groups are the only weak thing a peer could name.
No listener here accepts an envelope on an unencrypted session, so a sender
whose handshake is refused on port 25 has no second route: it retries in the
clear, is answered `530 5.7.0 Must issue a STARTTLS command first`, and the
message stays in its queue until it bounces. A group left off the list costs
whole messages, not confidentiality, which is why only a group no conforming
TLS 1.3 peer offers alone is left off.

The browser interface carries the same preference. It builds its TLS port from
the certificate bytes rather than sharing the mail listeners' context, so it
reaches that port by a different route, but the set is one set and a measurement
of either half answers for both.

Two properties remain worth knowing before you plan around any of it. A peer
that supports no hybrid completes over a classical curve, by design, and nothing
records that the session ran without a post-quantum exchange: a server socket
cannot report the group it negotiated, so an operator asking how much of their
inbound mail arrives that way has no way to find out from this server or from
any other on the same runtime. And the ordering can only reach a hybrid a peer
already implements. If a hybrid on the wire is a requirement you have to
satisfy, confirm it at the sending end as well as here.

Data this server holds is a different matter, and there the guarantee is real.
Sealed data carries an algorithm identifier in its envelope header, so a
substitution fails the authentication check rather than downgrading quietly, and
old data keeps opening after the active algorithm moves forward.

The vendored post-quantum implementations implement the FIPS-published
algorithms but have not themselves been through CMVP validation. Deployments
under a FIPS mandate should read the framework's own security policy on the
cryptographic boundary before assuming coverage.

## What ships with the release

Alongside the artifact and its signatures, each release publishes an SBOM for
the project and a second one for the vendored tree, so a scanner can match the
exact pinned framework version against vulnerability databases. Because the
framework is vendored rather than installed, ordinary dependency scanners never
see it. The SBOM is how it becomes visible, and a match against a known advisory
fails the build before the release ships.
