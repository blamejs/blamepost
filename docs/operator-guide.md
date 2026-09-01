# Operator guide

Everything an operator does after `docker run`: publishing the DNS records that
make mail deliverable, and running the server once it is up.

Examples use `example.com` and `mx.example.com` throughout. Those names are
reserved for documentation (RFC 2606), so nothing here can accidentally send mail
to a stranger. Substitute your own.

Commands are written as `blamepost <verb>`, the form on a host install. In the
container, reach the same CLI through the running process:

```bash
docker exec blamepost node bin/blamepost.js doctor
```

Every `blamepost <verb>` command below takes that prefix. Under compose, it is
`docker compose exec blamepost node bin/blamepost.js <verb>`.

## Before the first start: the certificate

Every mail listener here requires TLS and none has a plaintext mode, so
`blamepost serve` refuses to start until `BLAMEPOST_TLS_CERT` and
`BLAMEPOST_TLS_KEY` point at a certificate and key on disk. The browser port on
8080 is the one that stays cleartext, because a container health check and a
proxy in front are what poll it, and a session is not reachable over it: the
session cookie is only ever sent back over TLS. The data directory keeps `tls/`
for the pair:

```text
BLAMEPOST_TLS_CERT=/var/lib/blamepost/tls/fullchain.pem
BLAMEPOST_TLS_KEY=/var/lib/blamepost/tls/privkey.pem
```

blamepost does not order or renew the certificate. Use whatever issues your
certificates now, an ACME client such as certbot or lego, an internal authority,
or the pair a terminator in front already holds, and have it write into those
paths.

Point `BLAMEPOST_TLS_CERT` at the **full chain**, not at the leaf on its own.
Certificate clients write both: certbot leaves `cert.pem` holding only your
certificate and `fullchain.pem` holding it followed by the issuer that vouches
for it. A browser handed the leaf alone fetches the missing issuer itself and
shows no error, and a sending mail server does not fetch anything and fails the
handshake, so this is a mistake that survives testing in a browser and stops
mail. `blamepost doctor` reports it.

The certificate needs to cover the hostname in `BLAMEPOST_HOSTNAME`, and
`mta-sts.example.com` as well if this server is the one publishing the MTA-STS
policy file described below.

The private key may be sealed with the vault passphrase, in which case it is
unsealed in memory at load and never written back in the clear.

### What happens at renewal

Your certificate client rewrites both files every sixty to ninety days. What a
running server does about that depends on the port:

- **The mail listeners pick the renewal up in place.** SMTP on 25, submission on
  465 and 587, IMAP on 143, POP3 on 110 and ManageSieve on 4190 read the
  certificate when a connection arrives, so the next connection after the reload
  gets the new one. Sessions already open keep the certificate they started
  under, which is how TLS works and needs no action.
- **Webmail, the admin console and JMAP on 8443 pick it up too.** That port
  builds its own TLS context out of the two files, so instead of re-reading them
  per connection it is handed the renewed pair when the reload happens. The next
  browser to connect gets the new certificate; the port is not rebound and open
  connections are not dropped.

The server checks both files every 30 seconds and rebuilds from them when their
modification time changes. Each reload writes a line naming the certificate path
it rebuilt from, whichever of the two files changed, and any ports still holding
the old certificate, and records a
`mail.server.tls.context_reloaded` audit event. If you ship logs, that line is
how you confirm a renewal landed, and the absence of it after a renewal window
is how you find out one did not.

So: **a renewal needs no restart.** Every port this server binds takes the new
certificate while the process runs. The reload line still names any port that
did not take it, so if one ever appears there, that port needs a restart and the
line tells you which; a restart is a drain and a rebind, and the mail ports are
not harmed by taking it. The server's own description carries the same list, so
it stays correct without being remembered.

A renewal written half-way, with the certificate replaced and the key not yet,
is read, found not to agree, and discarded, and the server keeps serving the
pair it already had until the next poll finds a complete one. Nothing needs to
be done about that window.

### When a renewal stops running

Nothing here renews anything, so a renewal client that has stopped is invisible
until mail stops. Three places report it before that:

- `blamepost doctor` prints the expiry date and how many days are left, and says
  so as a note once a certificate is inside 14 days of expiring. A certificate
  client replaces a certificate with about a third of its life left, so a
  certificate that has reached that point has already missed several attempts.
- **The readiness probe reads the pair on every poll**, so a monitoring system
  finds this without anyone running a command. `/readyz` and `/healthz` carry a
  `certificate` check, and its verdict drops from `ok` to `degraded` as soon as
  the certificate is inside those 14 days, the chain is incomplete, the name is
  not covered, or the two files no longer agree. Over the loopback interface,
  which is where the container's own health check runs, the response also
  carries `expiresInDays` and a `usable` flag, and names which reading failed.
  Alert on `degraded`.
- `blamepost serve` refuses to start on a certificate whose validity has
  closed, naming the date, rather than binding ports that would refuse every
  connection offered to them.

The probe **reduces its verdict and does not refuse**, even for a certificate
that has already run out. Refusing would take a server out of rotation while it
is still carrying mail for every peer, and it would withdraw the web interface
you would have read the reason from. It would also invite a restart, and this
server will not start on a certificate it cannot present, so a restart at that
moment ends it rather than repairing it. Renew the certificate; the running
server picks it up.

A certificate that is wrong but still usable, such as a leaf with no issuer or
one that does not cover this server's hostname, is reported by `doctor` as a
failure and logged at boot, and does not stop the server. Both faults serve
every peer that does not check the thing they got wrong, and taking a working
mail server down over either would cost more than it saved.

## After the first start: the administrator

`serve` creates no accounts. A server that has just come up has a working web
interface and nobody who can sign in to it, so this is the step that finishes
the install:

```bash
blamepost init --admin-email admin@example.com
```

`init` prepares the data directory, hosts the address's domain, creates the
account with administrator rights, mints that domain's DKIM keys and prints the
records to publish. It generates a password and prints it once unless
`--admin-password` or `BLAMEPOST_ADMIN_PASSWORD` supplies one. Read it out of
the output at the time; nothing prints it again.

It is also the only command that creates an account carrying administrator
rights. `blamepost account add` creates an ordinary mailbox. Run `init` again
later, against the same data directory and a different address, and it creates a
second administrator: the domain is already hosted so it is left alone, and the
DKIM pair it already holds is printed rather than replaced.

The admin interface is where the role is given to an existing account and where
it is taken back. Both are buttons on the account list, both ask for a reason
before anything changes, and both are recorded:

```bash
blamepost audit read --action account.role_granted
blamepost audit read --action account.role_revoked
```

The two buttons appear under different conditions, and the difference matters
when you are taking a role away in a hurry. **Take back the console** is offered
on every row that holds the role, including an account that is suspended,
archived or part way through an erasure. This console is the only place the role
can be taken, and an account part way through an erasure can never be returned
to service, so a row that did not offer the button would hold the role for good.
**Give it the console** is offered only on an account that is in service, because
a grant on one that authenticates nowhere confers nothing and leaves a role
somebody has to remember to take back.

Taking the role back is the answer to an administrator whose credential has been
taken, and to one who no longer needs it. It reaches a session that account
already has open rather than waiting for it to expire, and it leaves the mailbox
signing in, sending and receiving, which is what separates it from suspending an
account whose owner did nothing wrong. The console is where the role is given to
an existing account and taken back, and the command line has no verb for either
direction. The one command-line route to the role is `blamepost init` run again
against the same data directory with an address that does not exist, which
creates a further administrator rather than promoting somebody already here.

Because the role comes from those places and nowhere else, four of the console's
own forms could shut the console to everybody: suspending the last administrator,
archiving them, taking the role from them, and disabling the domain that
administrator's address belongs to, since an account is only usable while its
domain is. Each of the four measures who would still be able to sign in
afterwards and refuses when the answer is nobody, naming the way forward. The
refusal is recorded either way:

```bash
blamepost audit read --action blamepost.web.last_administrator_removal_not_permitted
```

It refuses on that reading and never on the verb, so an administrator is still
suspended, archived or stripped of the role from the console while another one
remains, and a domain holding no administrator is still disabled from the
console. Nothing in the identity layer changed, so the command line refuses
nothing it refused before. "Nobody can sign in to the console" under incident
response covers the way back if you arrive there by some other route.

### The console asks before it acts

Five acts on these pages cannot be taken back from these pages, and each of them
takes two steps rather than one. The first press answers with a page naming
exactly what is about to happen; that page asks you to type something it shows
you, and only then does anything change:

| Act | What you type |
|-----|---------------|
| Archive an account | the account's address |
| Stop accepting mail for a domain | the domain name |
| Remove an alias | the alias address, or the domain for a catch-all |
| Retire a signing pair | the selector |
| Cancel queued messages | how many of them are still waiting |

The count is measured again when you send the second step, so a message that
reaches its recipient while you are reading stops the whole cancellation instead
of being quietly left out of it. Each message is checked once more in the moment
it is canceled. One that leaves the queue during the run is reported as not
canceled, its sender is not written to, and the audit trail records it that way,
so nothing tells a sender an operator stopped mail that in fact arrived.

The check that stops you locking yourself out is taken twice as well: once when
you press the button, so you are not asked to type a name for a change that was
going to be refused, and once in the moment the change is saved. That second
check is the one that decides, and it is what makes two console windows safe: if
somebody else takes the operator role from the only other administrator, or
withdraws the domain their address is on, while your confirmation page is open,
your change is refused when you send it rather than going through on a reading
that has gone stale. Both of you would otherwise see one administrator left and
both would be right about a server neither of you was going to leave behind.

The reversible acts never ask you to type a value back. Some of them still take
a second step, because everything that records a reason asks you for one:
suspending an account, putting a domain back in service, and giving or taking
back the console role each ask for the reason and nothing more. Reinstating an
account, adding a domain or an alias, minting and rotating a pair, withdrawing
selectors whose overlap has already run out, and forcing the queue change on one
press. If you expect a one-click archive and meet a typed prompt, nothing is
broken.

`init` runs before a certificate exists, deliberately, so the order above works
on a host where the certificate has not been issued yet.

---

# Part 1: DNS posture

Self-hosted mail fails at DNS more than anywhere else, and it fails quietly:
messages leave, receivers file them as junk or drop them, and nothing in the logs
says why. Publish all of the following before the first real message.

blamepost enforces one part of this rather than trusting it: the MX listener does
not bind until the operator confirms the posture. Everything else the server
checks and reports, but cannot fix from the inside.

## Check as you go

At any point, ask the server what it can see:

```bash
blamepost doctor
blamepost doctor --domain example.com
```

`doctor` resolves each record, compares it with what the server is configured to
do, and names what is missing, stale, or contradicted by something else. Run it
after every change. DNS caches, so a record can be right in your registrar's
panel and wrong on the internet for another hour.

It answers in three kinds, not two, and the third is the one worth recognizing.
A record can come back **unchecked**, printed with a `?` rather than a pass or a
failure mark: this server asked, waited, and gave up before an answer arrived.
Such a row names neither what was expected nor what was found, because neither
was seen, and the record may well be published and perfectly correct. The
closing summary counts unchecked records apart from checks that disagreed, so if
you have both you can see how many of each rather than reading one total and
guessing. That is a question about the resolver this server reads
rather than about your zone, so the place to look is the resolver, not the
registrar. Every lookup is bounded, so a name server that has gone quiet cannot
leave the command hanging with nothing on screen, and a run that could not
settle every question does not report itself as passing. Running out of time is
never read as a record that is not published: if it were, anyone able to stall a
query could retire a policy without having to break it.

## MX

Point the domain at the listener's hostname, and point that hostname at the IP.

```text
example.com.        IN  MX   10 mx.example.com.
mx.example.com.     IN  A    198.51.100.10
mx.example.com.     IN  AAAA 2001:db8::10
```

`mx.example.com` is `BLAMEPOST_HOSTNAME`. Use a name that is only ever this
server, not a shared web host name. It is what the server announces in `EHLO`,
what receivers look up in reverse, and what MTA-STS and DANE bind to.

Publish an `AAAA` record only if the server actually sends over IPv6 and that
address has working reverse DNS. An IPv6 address without reverse DNS is worse
than no IPv6 at all, because several large receivers refuse it outright.

This record carries mail arriving from other servers. Mail between two accounts
on this server does not go through it; see "Mail between two mailboxes on this
server" in Part 2.

## Reverse DNS and forward confirmation

Set the `PTR` record for every address that sends mail to `mx.example.com`. That
is done at whoever owns the IP, which is your hosting provider or your ISP rather
than your domain's registrar.

```text
10.100.51.198.in-addr.arpa.  IN  PTR  mx.example.com.
```

The result must be *forward-confirmed*: the `PTR` resolves to `mx.example.com`,
and `mx.example.com` resolves back to the same address. Receivers check both
directions. A mismatch, or a generic provider-assigned name like
`ip-198-51-100-10.example.net`, costs delivery on its own.

If your provider will not set a `PTR`, that provider is not somewhere to run a
mail server.

## SPF

One `TXT` record at the domain apex, listing who may send for it, ending in a
hard fail.

```text
example.com.        IN  TXT  "v=spf1 mx -all"
```

`mx` authorizes the hosts in the domain's own MX records, which is exactly the
server that also receives its mail. `-all` means anything else is a forgery.

**Use `-all`, not `~all`.** A soft fail asks the receiver to think about it, and
receivers differ about what they conclude. The strict form is the one that
actually protects the domain, and if it breaks a sending path, that path was
unauthorized and you have just found it.

Mail may also leave from an address that is not an MX host: a separate egress
address, or an application server that sends its own notifications. Authorize
each one explicitly:

```text
example.com.        IN  TXT  "v=spf1 mx ip4:198.51.100.20 ip6:2001:db8::20 -all"
```

Keep the record inside the ten-lookup limit that SPF evaluation imposes. Every
`include:` and every `mx` costs lookups. Exceeding the limit makes the record
fail permanently, which is a different and worse outcome than failing to
authorize one host.

## DMARC

One `TXT` record at `_dmarc`, telling receivers what to do when authentication
fails and where to send the reports.

```text
_dmarc.example.com. IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; pct=100; fo=1; adkim=s; aspf=s"
```

- **`p=quarantine` is the floor.** `p=reject` is better and is where a stable
  domain should end up. `p=none` publishes a policy that asks receivers to do
  nothing, which protects nobody.
- **`adkim=s` and `aspf=s`** require strict alignment, so a signature from a
  subdomain does not bless the parent. Relaxed alignment is a gift to anyone who
  can get a subdomain.
- **`fo=1`** asks for a failure report on any authentication failure, not only on
  a total one. That is what makes a misconfigured sending path visible.
- **`rua` and `ruf`** must be addresses that someone reads. Reports arrive as XML
  attachments daily; they are how you learn that a forgotten application server
  has been sending unauthenticated mail as your domain for a year.

**Migrating an existing domain?** A short window at `p=none` with `rua` reporting
is a legitimate first step: it finds sending paths you had forgotten without
disrupting them. It is a survey, not a destination. Days, not quarters. It is
only useful if you actually read the reports it produces.

## DKIM

Each sending domain gets two selectors, and blamepost signs every outbound
message with both. `blamepost domain add` mints them and prints the records as it
hosts the domain, so by the time you are reading this the keys already exist and
are sealed in the data volume. To see the records again:

```bash
blamepost dkim records example.com
```

They look like this:

```text
bp202608._domainkey.example.com.      IN  TXT  "v=DKIM1; k=ed25519; p=<base64>"
bp202608-rsa._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<base64>"
```

The selector name defaults to `bp` followed by the year and month the key was
minted, and the RSA selector takes that name with an `-rsa` suffix, so a glance
at DNS says when a key was issued. `blamepost dkim rotate --selector <name>`
chooses your own from the next rotation onwards.

`blamepost dkim generate --domain example.com` exists for the case this server
holds no active selector for a domain at all. `blamepost domain add` mints one as
it hosts the domain, so the case you meet in practice is a domain added from the
administration interface, which hosts it without minting: its mail leaves
unsigned until you generate a pair, on that page or with this verb. Run against a
domain that already has keys it refuses and
points at `rotate`, which is the right verb: minting a second pair while the
first keeps signing is what keeps mail verifying through the change.

- **The Ed25519 selector** (RFC 8463) is the one a modern verifier prefers.
- **The RSA-SHA256 selector** (RFC 6376) is the fallback for receivers that do
  not implement Ed25519. A verifier evaluates whichever it understands and
  ignores the other, which RFC 6376 §6.1 already requires of it.

Publish both. Dropping the RSA record silently loses authentication at every
receiver that has not implemented RFC 8463.

The selector names are a convention, not a requirement. Pass your own if you
prefer. What matters is that the published `p=` matches the key the server holds.
`blamepost doctor` compares them and complains if they have drifted, which
happens most often after a restore from a backup taken before a rotation.

**If a receiver mishandles the second signature.** There is nothing to set here.
Both selectors sign every message this server sends, no configuration turns one
algorithm off, and no `dkim` verb withdraws half a pair: `blamepost dkim retire`
names a pair and takes both halves with it, so reaching for it to drop the
Ed25519 record takes the RSA record with it. On a domain holding the single pair
it was set up with, that stops the domain signing altogether rather than leaving
it signing with RSA. Your choices are to publish both records or to send that
domain's mail from somewhere else. RFC 6376 section 6.1 puts the fault on the receiver, which
is required to evaluate the signatures it understands and to keep going past the
ones it does not, and a receiver that cannot do that will also mishandle mail
from every sender that is part way through a key rotation.

A domain that does end up holding one algorithm, which is what a `generate` or
`rotate` interrupted part way can leave behind, signs nothing at all until it
holds both again. `blamepost dkim generate` refuses while a selector is still
active and `blamepost dkim rotate` has no pair to rotate away from, so the way
back is to retire what is left and generate a fresh pair, publishing the two new
records. Mail sent between those two steps leaves unsigned and fails DMARC
wherever the domain's policy sends failures. `blamepost dkim list` shows which
selectors a domain still holds and what state each is in.

## Mail that is not valid UTF-8

RFC 6152 permits a message body to carry 8-bit content, and senders using a
legacy character set still produce it. blamepost stores, signs and serves such a
message exactly as it arrived, and the two places that could quietly alter it
both work in octets.

**It signs over the bytes that were sent.** The signature covers the message the
sender wrote rather than a decoded copy of it, so what a receiver verifies is
what left. Signing a decoded copy would produce a signature that either fails at
every receiver or attests to content nobody wrote, depending on which half was
decoded, and both are worse than the message arriving unsigned.

**It reads back byte for byte on every protocol.** POP3 `RETR` and `TOP`, IMAP
`FETCH BODY[]`, and a partial fetch all return the stored octets, and the window
a partial fetch takes is measured on octets, which is what RFC 9051 section
6.4.5 counts in. An account holder reporting that accented text is intact in one
client and shows replacement characters in another is looking at that client
rather than at a corrupted stored message.

What does leave a message unsigned has nothing to do with its character set. A
domain this server holds no active selector for cannot be signed for, and since
`blamepost domain add` mints a pair as it hosts the domain, that is a setup
state rather than a steady one:

```
blamepost audit read --action blamepost.mail.listeners.submission_unsigned_no_key
blamepost audit read --action blamepost.mail.compose.unsigned_no_key
```

Anything else that stops the signer, a key that will not unseal being the usual
one, is a different action, so an alert on one will not send you to fix the
other:

```
blamepost audit read --action blamepost.mail.listeners.submission_unsigned
blamepost audit read --action blamepost.mail.compose.unsigned
```

Each pair names the same condition on the two paths a message can be sent from,
the desktop client on the submission port and the browser, so query both. A
domain waiting for its first pair looks identical from either surface and
alerting on one alone would find only half the mail it affects.

Either way the message still goes out, because refusing to relay an account's
own mail over a key problem is a worse outage than sending it unsigned. A domain
publishing `p=reject` should expect unsigned mail to be rejected by receivers
when SPF does not also align, which is why both actions are worth an alert
rather than a quarterly look.

## MTA-STS

MTA-STS tells sending servers that mail to this domain must go over TLS to a
named set of MX hosts, and it is anchored in HTTPS rather than in DNS, so it does
not need a signed zone.

**Two things must exist.** A policy file served over HTTPS:

```text
https://mta-sts.example.com/.well-known/mta-sts.txt
```

```text
version: STSv1
mode: enforce
mx: mx.example.com
max_age: 86400
```

And a `TXT` record whose `id` changes whenever the policy file changes:

```text
mta-sts.example.com.    IN  A    198.51.100.10
_mta-sts.example.com.   IN  TXT  "v=STSv1; id=20260822T120000"
```

`mode: enforce`, not `testing`. Testing mode publishes a policy that senders
report on and then ignore, which means an attacker stripping TLS still succeeds.

Senders cache the policy by `id`, not by the file's contents. Change the file
without changing the `id` and the change is invisible for up to `max_age`.

`max_age: 86400` is a good starting value: if you get the MX list wrong, the
mistake ages out in a day rather than a fortnight. Raise it once the posture has
been stable for a while.

**Serving the file.** Point `mta-sts.example.com` at the server and make sure the
certificate you gave it covers that name too; the web listener serves the policy
generated from your configured MX hosts, so the file and the server cannot
disagree. Senders refuse a policy fetched over a certificate that does not
validate, so a certificate without that name means no sender ever reads the
policy. If you
already run a web server for the domain, serve the same three lines from there
instead. It is a static file, and nothing about it needs to live on the mail
host.

**What generates it.** Three settings, checked at start:

```
BLAMEPOST_MTA_STS_MODE=enforce
BLAMEPOST_MTA_STS_MX='["mx.example.com"]'
BLAMEPOST_MTA_STS_MAX_AGE=86400
```

`BLAMEPOST_MTA_STS_MX` defaults to this server's own hostname, which is the
right answer for exactly as long as there is one MX. Publish every host that
appears in the `MX` records, or senders will refuse delivery to the ones the
policy omits. An entry may carry a wildcard in its leftmost label, so
`*.mx.example.com` covers a set of hosts under one name (RFC 8461 §3.1).
Change any of the three and the `id` in the `_mta-sts` TXT record has to change
with it, or senders keep serving themselves the cached copy.

## TLS-RPT

One `TXT` record naming where senders should send aggregate reports about the
TLS connections they made to you. This is how you find out that some fraction of
senders are failing to negotiate TLS with your server, which is otherwise
entirely invisible from your side.

```text
_smtp._tls.example.com. IN  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
```

An HTTPS destination works as well as a mailbox and has less abuse surface:

```text
_smtp._tls.example.com. IN  TXT  "v=TLSRPTv1; rua=https://reports.example.com/tlsrpt"
```

Reports arrive daily, gzipped, in JSON. Publish this even if you do not read them
at first. The record costs nothing, and the reports start accumulating from the
day it exists, which is the day you wish you had published it.

**Where you can point it.** This server does not serve a TLS-RPT intake endpoint,
so an `https://` destination has to name something you run or a service you have
signed up to. A `mailto:` destination on a domain hosted here works with no extra
infrastructure: the reports land in that mailbox as ordinary messages carrying a
gzipped JSON attachment. Nothing in this server parses or summarizes them yet, so
what you get is the raw report until you open it or feed it to a tool. Reading
them in the admin interface is on the roadmap and is not in this release.

**The shape senders actually read.** The record has to begin with `v=TLSRPTv1`
and it has to carry `rua=`, or every sender skips it and the record collects
nothing. `blamepost doctor` reads it through the same code the sending half uses,
so a record it accepts is one senders will act on, and a record it complains
about is one they would ignore.

**This server sends them too.** When it delivers to a domain that publishes
`_smtp._tls`, it keeps a count of how its own transport security went with that
domain and sends that domain a report once a day. What goes in one is what
RFC 8460 defines: per policy and mail exchanger, how many sessions succeeded, how
many failed, and which failure it was. The only address in one is your own
postmaster, as the contact a receiver replies to. No account address, no
recipient address, no subject and no message content ever appears, and a domain
that publishes no record is sent nothing at all.

An `https://` destination is posted to directly. A `mailto:` destination is
composed as mail and goes out over the same outbound path as everything else,
with the same MX lookup, transport policy, retry budget and queue. Either way
the outcome is recorded: `blamepost.mail.delivery.tls_rpt_sent` on the audit
trail for a report that went, and `blamepost.mail.delivery.tls_rpt_unsent` plus
an error line for a destination that refused it. A destination that refused
keeps the counts, so the next day's report covers the whole period rather than
losing it.

## DANE / TLSA: only with DNSSEC

DANE pins the certificate a sender must see when it connects, which closes the
gap MTA-STS leaves open on the first contact with a domain.

```text
_25._tcp.mx.example.com.  IN  TLSA  3 1 1 <sha256-of-the-spki>
```

```bash
blamepost doctor --dane    # confirms a TLSA record exists for port 25 on this host
```

`--dane` answers presence and nothing more: it resolves `_25._tcp.<hostname>`
and reports how many records came back. It does not read the certificate this
server presents, and it does not hash it and compare, so a TLSA record that no
longer matches the key in use passes this check while every DANE-aware sender
refuses delivery. That is the failure the rollover advice below is about, and it
is one you have to prevent by procedure rather than catch with a check.

**A TLSA record without DNSSEC is decoration.** DANE's security comes entirely
from the sender being able to validate the DNS answer. On an unsigned zone, an
attacker who can answer DNS can also remove the TLSA record, and a sender that
never saw it will not miss it. If the zone is not signed, stop at MTA-STS.

If the zone *is* signed, publish it. Then remember that certificate renewal now
touches DNS. A renewed key with a stale TLSA record makes every DANE-aware
sender refuse delivery. Use a `3 1 1` record over the key, keep the key across
renewals, or publish both records during a rollover.

**The sending half is a separate setting, and it is gated on a statement about
your resolver.** Everything above is about the records you publish so that
senders can authenticate this server. What this server demands when it is the
sender is `BLAMEPOST_OUTBOUND_POLICY`:

```
BLAMEPOST_OUTBOUND_POLICY='{"mtaSts":"enforce","dane":"opportunistic","dnssecValidated":true}'
```

`dnssecValidated` is you telling the server that the resolver you pointed it at
validates DNSSEC. Nothing here can check that, and the refusal to guess is
deliberate: it is a fact about your resolver, which may validate, may forward to
something that strips the authenticated-data bit, or may be a public endpoint
reached over DoH, and no answer coming back says which of the three you have.

**Set it only if it is true.** RFC 7672 §2.1.1 and §2.2 forbid using a TLSA
record that was not validated, and the reason is the whole of DANE: a record
nothing checked is a record anyone on the path could have rewritten. Asserting
validation falsely authenticates peers against exactly those records, under a
banner saying they were verified, which leaves you worse off than not running
DANE at all.

Left unset, no TLSA lookup is made and none is needed. Mail reaches every
receiver it would have reached, over whatever TLS that receiver offers, with no
DANE authentication claimed for any of them and no per-delivery lookup spent on
records that could not have been used anyway.

With it set, the `dane` value starts deciding something:

- **`"dane":"opportunistic"`**, the shipped value, pins the certificate for
  every receiver that publishes TLSA records and leaves the rest alone. A
  receiver whose chain does not match its records is not delivered to, and the
  message waits for its next attempt.
- **`"dane":"enforce"`** additionally treats a TLSA lookup that fails as a
  reason not to deliver over that mail exchanger, which matters when a receiver
  publishes records and your resolver cannot fetch them. It refuses to start
  without `dnssecValidated` beside it, and the refusal names both the value to
  add and `opportunistic` as the alternative.

A receiver that publishes no TLSA record is unaffected by either. Under both,
the failures are temporary rather than permanent, so a receiver whose records
you cannot reconcile defers rather than bounces, and `blamepost queue list`
shows their answer against the waiting recipients.

## Firewall

Inbound, at the host and at any network in front of it:

| Port | Listener | Why |
|---|---|---|
| 25 | `mx` | Inbound mail from other servers |
| 587 | `submission` | Submission from your own clients, STARTTLS |
| 465 | `submissions` | The same, implicit TLS (RFC 8314) |
| 143 | `imap` | IMAP4rev2, STARTTLS |
| 110 | `pop3` | Only if POP3 is enabled, STLS |
| 4190 | `managesieve` | ManageSieve |
| 8080, 8443 | web app | Webmail, admin and JMAP, if reached directly rather than through a proxy |
| 80, 443 | not bound here | The MTA-STS policy file if the server serves it, and whatever your certificate client needs for its challenge |

IMAP and POP3 negotiate TLS in band, so this server binds 143 and 110 and does
not bind 993 or 995. **A TLS terminator in front of 143 or 110 does not supply
them**, and it is worth saying plainly because the arrangement looks like it
should work. Behind one, the listener is handed a plaintext connection, so it
refuses every credential:

```text
a2 AUTHENTICATE PLAIN <a correct credential>
a2 BAD AUTHENTICATE requires TLS (use STARTTLS first)
```

That refusal is right rather than a bug. The listener cannot see TLS it was not
part of, and the alternative, telling it to treat a plaintext connection from a
named source as encrypted, puts an address check between a password and the
wire and hands the exemption to anything else that can reach that address. So a
client that can only do implicit TLS has no route here today. It is tracked
upstream as blamejs#665, which asks for the implicit-TLS mode the submission
listener already has on 465. The `tls` profile in `compose.yml` is unrelated:
it publishes 80 and 443 and proxies HTTP to the web port, so it reaches no mail
listener at all.

**One client worth knowing about before you reach for it.** Python's
standard-library `imaplib` cannot connect to this server, on any port. It
accepts only servers advertising `IMAP4rev1` or `IMAP4`, and this server
advertises `IMAP4rev2`, which RFC 9051 permits; `imaplib` refuses in its
constructor before sending a command, with `server not IMAP4 compliant`. That
matters because `imaplib` is what a lot of monitoring and migration scripts are
built on. The answer is a client that speaks RFC 9051, not a change here:
advertising `IMAP4rev1` would claim a specification this server deliberately
declines parts of, and a script admitted past that check would then have its
`LOGIN` refused and read it as a bad password.

Those are the defaults. Each listener has a variable that moves its port alone,
which is the form that fits a `docker run` line:

| Variable | Listener | Default |
|---|---|---|
| `BLAMEPOST_MX_PORT` | `mx` | `25` |
| `BLAMEPOST_SUBMISSION_PORT` | `submission` | `587` |
| `BLAMEPOST_SMTPS_PORT` | `submissions` | `465` |
| `BLAMEPOST_IMAP_PORT` | `imap` | `143` |
| `BLAMEPOST_POP3_PORT` | `pop3` | `110` |
| `BLAMEPOST_MANAGESIEVE_PORT` | `managesieve` | `4190` |

Use them when the process cannot bind a privileged port, and publish the
standard port on the host instead:

```
docker run -e BLAMEPOST_MX_PORT=2525 -p 25:2525 ...
```

### When the process cannot take a port below 1024

The container runs as UID 65532 with every Linux capability dropped, and in the
usual deployment that is enough. A container gets its own network namespace, and
current Docker and Kubernetes start the unprivileged-port floor at zero inside
one, so 25, 465, 587 and 143 bind with no capability granted and no flag set.
An image cannot set a sysctl, so this is set where the container is started:
`compose.yml` carries `net.ipv4.ip_unprivileged_port_start: "0"` and the
`docker run` line in the README passes
`--sysctl net.ipv4.ip_unprivileged_port_start=0`. Either states the requirement
rather than creating it, and both are worth keeping for a runtime that has not
adopted the default or a host where the floor has been raised. The setting is
namespaced, so it changes nothing outside the container.

Two deployments do not get that namespace, and both are where the table above
earns its keep:

- **Host networking.** `--network host` puts the process in the host's own
  network namespace, where the floor is the host's `net.ipv4.ip_unprivileged_port_start`,
  usually `1024`. The sysctl is refused outright there rather than applied:
  Docker answers `sysctl "net.ipv4.ip_unprivileged_port_start" not allowed in
  host network namespace` and the container never starts. Move the listeners to
  high ports and put the standard ones in front of them, or lower the floor on
  the host itself with `sysctl -w net.ipv4.ip_unprivileged_port_start=0`, which
  affects every process on that machine and is a decision about the machine
  rather than about this server.
- **A host install with no container at all.** Same floor, same three ways past
  it: run as root, grant `CAP_NET_BIND_SERVICE` to the Node binary, or lower the
  floor. The port variables above avoid all three.

Publishing a mapped port rewrites the peer address the listener sees, so every
per-peer budget the listeners keep, on concurrent connections, connection rate,
authentication failures and recipient failures, counts the runtime's own address
instead of the sender's. Host networking keeps the real one. That is the trade,
and it is why the sysctl on a container's own namespace is the documented
default rather than the port variables.

`BLAMEPOST_LISTENERS` is the wider form. It moves any port, switches a listener
off, and moves the interface one binds, so open what you configured rather than
what these tables say:

```
BLAMEPOST_LISTENERS='{"imap":{"port":1143},"managesieve":{"enabled":false}}'
```

A listener you do not name keeps its default port and still binds it. A listener
name or a field the server does not read is refused at start rather than
ignored, so a typo costs a failed start instead of a port that silently never
moved.

Three refusals to expect, all at start and all naming what to change:

- Two listeners on one port, including the case where one of them took its
  default and you never wrote it down. Moving IMAP to 25 collides with the MX
  listener whether or not the configuration mentions it.
- A listener on `BLAMEPOST_HTTP_PORT` or `BLAMEPOST_HTTPS_PORT`. The browser and
  JMAP surface holds those two, and no listener section mentions them.
- One listener's port set by both its own variable and `BLAMEPOST_LISTENERS`.
  One of the two would be doing nothing, so the next edit to it would change
  nothing on the server. Keep whichever form you prefer and drop the other.

Outbound:

| Port | Why |
|---|---|
| 25 | Delivering mail. **Must be unfiltered.** |
| 53 | DNS |
| 123 | UDP. The clock check the store runs at boot |
| 443 | Any HTTPS reporting endpoint you use, and your certificate client's calls to its authority |

Outbound 25 is the one that catches people. Many providers block it by default
and some will not unblock it at all. Confirm it works before planning a
migration, not after:

```bash
nc -vz gmail-smtp-in.l.google.com 25
```

### The clock check at boot

Opening the store sends one SNTP query over UDP/123 to a public time server and
compares the answer against this machine's clock. It is there because the audit
trail's timestamps are what an auditor reads, and a host whose clock has drifted
writes a trail that is wrong without ever looking wrong.

What it does with the answer:

- **Under five minutes of drift.** A log line, and the boot continues.
- **Five minutes to an hour.** A warning, and the boot continues.
- **An hour or more.** The boot is refused, and the message names the drift.
  Fix the host's time synchronization. `BLAMEJS_NTP_STRICT=0` continues anyway,
  which is worth reaching for only to get a server up long enough to read its
  own audit trail.
- **No answer at all.** A warning, and the boot continues. A blocked UDP/123 is
  not treated as a reason to refuse service, so this is easy to leave broken
  without noticing. Open the port, and check the boot log says it got an answer
  rather than assuming silence means agreement.

`BLAMEJS_NTP_SERVERS` takes a comma-separated list if you run your own time
source, and `BLAMEJS_SKIP_NTP_CHECK=1` turns the whole check off. Neither is a
substitute for the host synchronizing its clock: this is one query at boot, not
a replacement for `chronyd` or `systemd-timesyncd`.

## Acknowledging the posture

The MX listener stays closed until you confirm the records in Part 1 exist. The
confirmation comes in two halves and the listener wants both.

The first covers this server:

```text
BLAMEPOST_DNS_ACKNOWLEDGED=1
```

The second covers each hosted domain, one at a time:

```bash
blamepost domain acknowledge example.com --by you@example.com
```

Without either, the server still starts but nothing binds port 25. You can add
domains and accounts, and the web and mailbox listeners come up.

Two halves rather than one because they answer different questions and go stale
at different times. The variable is set once, when the server is first stood up.
A domain you add six months later has its own MX, SPF, DMARC, DKIM, MTA-STS and
TLS-RPT records, none of which existed when you set the variable, so letting it
inherit that confirmation would open port 25 for a domain nobody had checked.
The per domain acknowledgment is recorded with the address you pass in `--by`
and shows up in `blamepost domain list` and in the audit trail. Take one back
with `--withdraw` when a domain's records come down.

The gate is a hand on the shoulder, not a validator. Acknowledging asserts that
you have published the records and read `blamepost doctor`'s output; the server
has no way to tell an honest acknowledgment from a hopeful one. The reason it
exists is that the alternative failure is much worse than a listener that refuses
to start. That failure is a server accepting mail it cannot authenticate or
deliver, from senders who then think it worked.

The listener reads both halves at boot, so acknowledging a new domain takes
effect at the next restart rather than immediately.

---

# Part 2: Running it

## The data directory and its mode

Everything this server keeps is under `BLAMEPOST_DATA_DIR`, which is
`/var/lib/blamepost` in the image: the encrypted database, the sealed key files,
the message blobs, the outbound spool and the certificate pair.

**It has to be mode `0750` or tighter.** Before any listener binds, `serve`
asserts the posture the deployment claims to have, and a data directory the rest
of the host can read fails that assertion. The process names the mode and exits:

```text
dataDir '/var/lib/blamepost' has mode 0755; production policy requires <= 0750 (chmod 750 /var/lib/blamepost)
```

The check reads the mode on disk, which is what the mount decides rather than
what created the directory, and it applies wherever POSIX file modes do.

A named volume takes its mode from the image, which ships `0750`, so the quick
start and `compose.yml` need nothing. A **bind mount** is where this bites, and
it usually bites on ownership before it ever reaches the mode.

A directory made with `mkdir` at the usual umask arrives at `0755` and owned by
whoever ran the command, which is normally root rather than the unprivileged UID
the image runs as. The container cannot write into it at all, so it stops while
creating the directories it keeps its data in, and what `docker logs` holds is a
permission error naming the path:

```text
blamepost serve: EACCES: permission denied, mkdir '/var/lib/blamepost/blobs'
```

The mode assertion quoted above is real, but it runs later, once the process has
been able to create those directories. You see it when the ownership is right
and the mode is not: a bind mount owned by the container's UID at `0755` reaches
the assertion and gets the mode line. Both failures happen before any listener
binds; they simply name different things, and the one you are most likely to
meet first is the permission error.

```bash
mkdir -p /srv/blamepost/data
chmod 750 /srv/blamepost/data
chown 65532:65532 /srv/blamepost/data     # the UID the image runs as
docker run -v /srv/blamepost/data:/var/lib/blamepost ...
```

The ownership line matters as much as the mode. At `0750` only the owner may
write, so the directory has to belong to the UID the container runs as. Getting
the mode right and the owner wrong produces a different failure with a different
message, further into the boot.

Two things later put the mode back where it started, so check it at both. A
restore that recreates the directory takes the umask of whoever ran it rather
than the mode of the volume it replaced. And a volume held on or exported over a
filesystem that does not carry POSIX modes presents whatever that layer decides;
move the data directory onto local storage rather than relaxing the requirement,
because the mode is what keeps the sealed key files off the rest of the host.

## One writer at a time

**One process may have the data directory open for writing, and the second is
refused.** The database is encrypted at rest, which means opening it for writing
is not a read: the whole file is decrypted into a working copy of its own on a
memory-backed directory, every query is served from that copy, and the copy is
written back over the encrypted file periodically and again at shutdown.

For the running server that is the design. A second writer destroys mail. The
two cannot see each other's working copy, so both write the whole volume back
and whichever writes last replaces the other's entirely. Every message the loser
accepted since it started is gone, and the window is bounded by neither
process's lifetime. What is left on disk is a valid database that is simply
missing that mail, so nothing afterwards reports the loss.

So the refusal is not a rule about which commands are risky. It is a rule about
writing the volume, and every command that needs to write meets the same wall:

```text
blamepost audit: the data directory at /var/lib/blamepost is already open for
writing in process 1. blamepost decrypts the whole database into a working copy
of its own while it is open and writes that copy back, so two writers cannot see
each other's work and whichever writes last overwrites the other, losing every
message delivered in between. Stop the server and run this again. Nine verbs
answer without stopping it, from a read-only open: doctor, account list, account
show, domain list, domain show, dkim list, dkim records, blobs report and audit
verify-chain. A verb that reports and also records that it read is not among
them, because recording the read is a write.
```

`init`, `restore`, `backup`, `queue remove` and every verb that changes an
account, a domain or a DKIM selector need it, as do `audit read`, `audit
archive`, `audit export`, `audit purge`, `account sieve` and `blobs reclaim`.
`queue list`, `queue held` and `queue flush` read the outbound spool off disk
instead, so they keep working while the server runs.

The lock is a file, `blamepost.lock`, in the data directory. It records the
process holding the volume, and the refusal checks that process against the
kernel rather than against anyone's assurance that the server is stopped. A lock
left behind by a server that was killed names a process that is gone, and the
next command reaps it and proceeds, so a crash does not lock you out of your own
data.

A reader takes no lock and waits for none. It is not a second writer: it never
writes the encrypted file, so it has nothing to lose the race with.

### Nine reporting verbs answer while the server runs

`account list`, `account show`, `domain list`, `domain show`, `dkim list`,
`dkim records`, `blobs report`, `audit verify-chain` and `doctor` do not refuse.
Each tries a writable open first, so an operator who has already stopped the
server gets a current answer, and only the refusal above sends the command down
the other path: a read-only open of the same volume.

A read-only open decrypts a working copy of its own and then writes nothing.
`db.enc` is never written back, the sealed database key is never re-sealed, no
audit checkpoint is anchored, `audit.tip` is never advanced, and the database
handle is opened read-only so a write that reached it would fail where it was
issued rather than succeeding into a copy nobody persists. Everything decrypted
is removed when the command returns.

`doctor` is the verb this exists for. You reach for it exactly when the server is
up and behaving oddly, and being told to stop the mail server first was the wrong
instruction at the worst moment.

**The answer says how old it is, and that number is measured rather than
estimated.** It is the modification time of the encrypted database, read before
the open, so it names the moment the server last wrote the volume to disk. The
rows do not move underneath a long report either: they are decrypted once, at
the open, so a delivery landing halfway through cannot leave one half of a
report describing a different moment from the other. The caveat prints above the
answer rather than under it, because a long answer in a terminal is read from
the top:

```text
Snapshot of 2026-08-22T14:07:31.482Z, 43 second(s) ago.
  another process holds the data directory, so the volume was opened read-only and these rows are as
  they stood when the server last wrote them to disk. Whatever it has stored since is
  not here. Stop the server and run this again for an answer that is current.
```

**`--json` changes shape on that path, and the change is the point.** Where the
answer came off the volume itself, the JSON is the document itself. Where it
came off a copy, the same answer arrives inside an envelope, with the document
itself under `result`:

```json
{
  "snapshot": {
    "takenAt":    1787407651482,
    "takenAtIso": "2026-08-22T14:07:31.482Z",
    "source":     "/var/lib/blamepost/db.enc",
    "reason":     "another process holds the data directory"
  },
  "result": []
}
```

A script written against the bare shape stops parsing at exactly the moment it
would otherwise have believed a stale answer. That is a breaking change and it is
the safety mechanism: quietly handing back the usual shape is the failure the
envelope exists to prevent. Either handle both shapes, or stop the server before
the script runs.

### Which verbs still refuse, and why

The test is not whether a verb changes anything an operator asked to change. It
is whether the verb has to WRITE on the way to its answer, and two kinds of read
do.

**A read whose own record has to outlive the command.** `audit read` is recorded
as it runs, and `account sieve` records that an administrator opened somebody's
filter scripts. That row is a write, so a read-only open cannot make it, and a
read that claims to be recorded and is not is worse than a read that refuses.

**A verb that writes before it copies.** `backup run` anchors the audit chain so
the bundle carries a signature over its own last row, and requires the volume
flushed so the bundle is not older than the database it claims to be. `audit
archive`, `audit export` and `audit purge` write for the same reasons. None of
that is available to a handle that will not write.

Every verb that changes something refuses as it always did.

### Reading two things that move at different speeds

`blobs report` holds the sealed message bodies on the live disk against the rows
that name them, and while the server runs those two come from different moments:
the rows stop at the last write to disk and the blob directory does not. A
message delivered in between has its body on the volume with its row still in
the server's own copy.

So the report carries the moment the rows stop, and separates the two findings.
A body written before it and referenced by nothing is an unreferenced body, which
is what the verb is for. A body written after it is reported as one the rows had
not reached, is not counted against the verdict, and is not reclaimable by
anything:

```text
  note  3 bodies, 41216 bytes, written after 2026-08-22T14:07:31.482Z, which is
        where these rows stop. That is mail the server has taken and not yet
        written to disk, so it is not counted either way.
```

The rest of the report is unaffected by how old the rows are. A row naming a body
that is not on disk is missing whenever it is read; a referenced body that no
longer hashes to its own name is altered whenever it is read, which is what
`--verify` unseals each one to find; and the quota and ownership comparisons are
rows against rows. `doctor` runs the same check through the same reader, so the
two cannot describe one volume differently.

`blobs reclaim` is a different matter and refuses outright on a read-only open,
under `store/snapshot-is-read-only`. Unlinking a body is not a database write, so
nothing below could stop it: the bodies would go from the live volume on the
strength of rows that stopped minutes ago, and the audit row that is the only
record they existed could not be written at all.

### What the read-only open needs, and what becomes of it

A read-only open still decrypts a working copy of somebody's mail, so where it
lives and how long it lives are both deliberate.

It goes on the same memory-backed mount the server already decrypts into, which
is `/dev/shm` in the shipped container, so it never lands on persistent storage a
backup or a disk image would pick up. A host with no such mount, and no
`BLAMEJS_TMPDIR` naming one, is told so and the command stops rather than writing
mail to a disk. That mount also has to be writable by the user running the
command.

With nothing named, `/dev/shm` is accepted only when the kernel reports it as a
`tmpfs` or `ramfs` mount, so a plain directory somebody created at that path does
not pass. Off Linux there is no mount table to read and no path is inferred, so
the command stops until you name one.

**What `BLAMEJS_TMPDIR` is checked against is a name, not a mount.** On Linux the
path it resolves to has to begin with `/dev/shm`, `/run/shm`, `/run/user/` or
`/tmp`, and a path that does not is refused at boot under `db/tmpdir-not-tmpfs`.
That test reads the resolved name rather than the mount table, so it accepts two
things you may not want. A `/tmp` that is ordinary disk passes it, and passes
without a warning, which is the common case on a host where `/tmp` was never
mounted as tmpfs. And three of those four names are matched as prefixes rather
than as directories, so `/tmpdata` and `/dev/shmx` pass as well.

Off Linux nothing can be classified, so the path you name is used and the server
logs a warning saying the residency could not be established.

Either way, the decrypted database is written where you point this, and a backup,
a snapshot, a replica or a disk image reaches it for as long as the command runs.
Confirm the mount yourself with `findmnt -no FSTYPE <path>`, and treat whatever
you name as carrying the same secrets the volume does.

The copy is named for the process that made it and claimed with an ownership
record before any bytes go into it, and it is removed when the command returns.
One left behind by a command that died is reclaimed by the next open, which asks
the operating system whether the recorded owner is still running rather than
inferring it from a filename. A copy whose owner is still running is left where
it is. A host that lost power is covered by the mount itself, which is memory and
does not survive the reboot.

Four refusals belong to this path. None of them writes to the volume, because
nothing on this path ever does:

| Code | What it means |
|---|---|
| `store/no-working-copy-mount` | There is no memory-backed directory to decrypt into. |
| `store/snapshot-no-source` | There is no database at that path to read. A directory that has never been through `blamepost init` looks like this. |
| `store/snapshot-out-of-step` | The rows on disk are older than the volume's own record of where its audit trail had reached, which is what a server starting up while this was being read looks like. Run the command again. |
| `store/snapshot-unreadable` | The database would not decrypt or open. Either the passphrase does not unseal the database key, or the database is damaged where it lies. |

**The checkpoint signatures are verified on this path.** A read-only open anchors
no checkpoint of its own, which matters: anchoring one would advance the record
beside the volume to a point the volume never reached, and a server killed before
its next write-back would then come back to a database the rollback check refuses
to open. It still verifies every signature already there, which is the half a
rewritten chain cannot recompute, so `blamepost audit verify-chain` reaches the
same verdict it reaches against a stopped volume. What it walks is the chain up
to the server's last write to disk; the chain only ever grows, so that is a
verified prefix rather than a partial reading, and the snapshot line above the
answer says where it stops.

### Reaching the command line in the container

The lock is checked against the process table it was written in, and a container
and its host do not share one. Run the command inside the same container as the
server:

```bash
docker exec blamepost blamepost audit read --limit 100
```

Running it on the host against a bind-mounted data directory is refused with a
different message, because from out there the recorded process cannot be looked
up at all:

```text
blamepost audit: the data directory at /srv/blamepost/data is held by process 1
in a different process namespace, so this process cannot tell whether it is still
running.
```

That refusal is deliberate. Guessing that the process is gone, and being wrong,
is the case that loses mail. If the server really is gone for good, delete
`blamepost.lock` from the data directory and run the command again.

The nine reporting verbs above treat this the same way they treat a lock they
can check: they fall back to a read-only open rather than refusing, and label the
answer as one. So a host-side `blamepost domain list` answers, with the caveat
attached, and it needs the passphrase and a memory-backed mount on the host to do
it. Every other verb is refused with the message above.

## Where settings come from

Two origins, checked by the same code and read in this order:

1. The JSON file at `BLAMEPOST_CONFIG`, which is optional. Absent, the
   environment and the defaults carry everything.
2. The environment, which wins over the file, setting by setting. Overriding one
   value leaves the rest of the file in place.

A variable that is empty or holds only spaces counts as unset, because that is
how a container runtime spells an absent value, and it falls through to the file
or the default. The same value written as `""` in the file is refused instead:
the file is this server's own document, so an empty value there is a typo worth
failing on rather than a way to mean nothing.

Anything the server cannot honor stops the start with a message naming the
setting, where the value came from, and what was expected. A setting that carries
structure is checked all the way down, so a bad port inside a listener section
says which listener and a bad relay entry says which entry. A key the file
carries that this server does not read is refused rather than ignored, because a
setting that reads as applied and is not is the failure this check exists to
prevent.

Two things a structured setting does not do. The environment form replaces the
whole setting rather than merging into the file's copy of it, so
`BLAMEPOST_LISTENERS` in the environment supersedes every listener the file
named, not just the ones it mentions. And a listener's own port variable is the
exception, because it names one field: it overrides that port and leaves the rest
of the section, including the interface, as the file wrote it.

## Every setting

This is the whole list. A variable that is not here is not one this server
reads, and setting it changes nothing. The JSON key is the name to use in the
configuration file; the variable is the name to use in the environment.

| Variable | Key | Default | What it does |
|---|---|---|---|
| `BLAMEPOST_CONFIG` | | `/etc/blamepost/blamepost.config.json` | The configuration file to read. Named in the environment only, because it is the thing that names the file. |
| `BLAMEPOST_HOSTNAME` | `hostname` | *required* | The public MX hostname this server answers for. Announced in `EHLO`, looked up in reverse by receivers, and bound to by MTA-STS and DANE. |
| `BLAMEPOST_VAULT_PASSPHRASE` | `vaultPassphrase` | *required* | Seals the DKIM private keys and every sealed database column. At least 16 characters, and no recovery path if it is lost. |
| `BLAMEPOST_DATA_DIR` | `dataDir` | `/var/lib/blamepost` | The single data directory: database, message blobs, outbound spool, sealed keys and certificates. Mode `0750` or tighter, or `serve` exits before binding anything. See The data directory and its mode. |
| `BLAMEPOST_TLS_CERT` | `tlsCert` | unset | The certificate chain every listener presents. `serve` refuses to start without it and its key. |
| `BLAMEPOST_TLS_KEY` | `tlsKey` | unset | The matching private key, which may itself be sealed with the vault passphrase. |
| `BLAMEPOST_DNS_ACKNOWLEDGED` | `dnsAcknowledged` | `false` | The server-wide half of the MX boot gate. Set it to `1` once the records in Part 1 are live. |
| `BLAMEPOST_ADMIN_EMAIL` | `adminEmail` | unset | The address `blamepost init` creates as the administrator. Read by `init` and by nothing else. |
| `BLAMEPOST_ADMIN_PASSWORD` | `adminPassword` | unset | That account's password, also read by `init` alone. Set both of these or neither; one without the other is refused at start. |
| `BLAMEPOST_HTTP_PORT` | `httpPort` | `8080` | Webmail, admin and JMAP over HTTP. |
| `BLAMEPOST_HTTPS_PORT` | `httpsPort` | `8443` | The same surface over HTTPS, when TLS terminates in this process. |
| `BLAMEPOST_POP3_ENABLED` | `pop3Enabled` | `false` | Whether the POP3 listener binds. The one listener that is off by default. |
| `BLAMEPOST_LOG_LEVEL` | `logLevel` | `info` | The lowest severity written to the log: `debug`, `info`, `warn`, `error` or `fatal`. |
| `BLAMEPOST_PROFILE` | `profile` | `strict` | How strictly the wire protocols judge a domain, a HELO name and a command line. `balanced` widens `strict` to accept punycode and non-latin scripts, which a server receiving mail from internationalized domains needs. |
| `BLAMEPOST_LISTENERS` | `listeners` | *per-listener defaults* | Which listeners bind, and on which port and interface. Covered under Firewall above. |
| `BLAMEPOST_RELAY_ALLOWED_FOR` | `relayAllowedFor` | *nobody* | The address ranges the MX listener would relay for. This server does not relay for a source address, so setting this to anything with an entry in it stops the boot rather than being honored. Covered under Devices that have to send through this server. |
| `BLAMEPOST_INBOUND` | `inbound` | `{"mode":"enforce","onTemperror":"defer"}` | What the MX listener does with the SPF, DKIM and DMARC verdict it computes at the end of `DATA`. `enforce` applies the sending domain's published policy; `monitor` records the verdict and delivers anyway. `onTemperror` decides whether a DNS failure defers the message or accepts it. The ARC chain (RFC 8617) is evaluated at the same point and reported as an `arc=` result in `Authentication-Results`: `none` when the message carries no chain, `pass` when it validates, `fail` otherwise. No value moves the message. A chain is worth what its sealer is worth, and there is no setting here that names the sealers you vouch for, so a chain that validates cannot lift a DMARC failure and a broken one cannot cause a refusal. A recipient's Sieve script can read the `arc=` result and file on it. Do not read `arc=fail` as evidence of forgery on its own: RFC 8617 §5.2 gives the chain only three tokens, so a seal that did not verify and a sealer's key that could not be looked up both land on `fail`. The `mail.server.mx.envelope_verdict` audit row separates them, carrying `arcReason` and `arcTransient` beside the status, and a run of `key-lookup-unavailable` is a resolver problem rather than a sender one. |
| `BLAMEPOST_LIMITS` | `limits` | *the shipped ceilings* | `{ maxMessageBytes, maxConcurrentConnectionsPerIp, connectionsPerIpPerMinute, authFailuresPerIpPer15Min, rcptFailuresPerIpPerMinute }`: the resource ceilings every listener holds against one source address. The last of them bounds address enumeration rather than load. Covered under Connection and message ceilings below. |
| `BLAMEPOST_POSTMASTER` | `postmaster` | `mailer-daemon@<hostname>` | The envelope sender on every delivery status notification this server composes, and the address whose arriving mail is read for reports about this server's own sending. **Point it at a real mailbox on a domain you host.** The default is built from the MX hostname, which is usually not itself a hosted domain, so a report addressed there is refused at RCPT and never arrives: the reports that tell you a DMARC endpoint or an operator address has broken are exactly the ones you would never see. Covered under Reports about your own mail. |
| `BLAMEPOST_OUTBOUND_POLICY` | `outboundPolicy` | `{"mtaSts":"enforce","dane":"opportunistic","dnssecValidated":false}` | The transport security this server demands of the peers it delivers to: the MTA-STS posture of RFC 8461 and the DANE posture of RFC 7672. `dnssecValidated` is your statement that the resolver this server uses validates DNSSEC, which nothing here can check and which RFC 7672 §2.1.1 and §2.2 make a precondition for using a TLSA record at all. Set it only if it is true. Without it no TLSA lookup is made, and `"dane":"enforce"` refuses to start. See DANE / TLSA. |
| `BLAMEPOST_OUTBOUND_RETRY` | `outboundRetry` | `{"maxAttempts":35,"backoffMs":[60000,300000,900000,3600000,14400000]}` | How long a message a peer deferred stays in the spool before its sender is told it failed. One wait per attempt, climbed in order, and the last wait repeats for every attempt past the end of the list, so the shipped schedule waits a minute, five minutes, fifteen minutes, an hour, and then four hours between every attempt after that. Thirty five attempts spend five days and eighty one minutes, which is the give-up time RFC 5321 §4.5.4.1 asks for. The waits have to rise, because the delivery path indexes them by attempt number. `maxAttempts` is what to change to give up sooner or later, and past the fifth attempt each one adds four hours: `5` gives up after eighty one minutes and `11` after a day and eighty one minutes. |
| `BLAMEPOST_OUTBOUND_SPOOL` | `outboundSpool` | `{"maxMessages":10000,"maxBytes":2147483648}` | How much undelivered outbound mail this server holds before it starts refusing new mail with a temporary code. Both ceilings apply and whichever is reached first binds, because depth is what each sweep pays and bytes are what the volume pays. Covered under The outbound queue below. |
| `BLAMEPOST_OUTBOUND_TIMEOUTS` | `outboundTimeouts` | *the delivery composer's own* | `{ mxLookupMs, perHostMs }`: how long an outbound attempt waits for the recipient domain's MX answer and for the peer itself. The floors stop a value written in seconds from failing every delivery, and the ceilings stop one wedged peer from holding the spool. |
| `BLAMEPOST_REQUIRE_TLS` | `requireTls` | `false` | Whether every outbound envelope asks for REQUIRETLS (RFC 8689), so a receiver holds a message back rather than delivering it over a connection it could not encrypt. This server does not put that parameter on the wire, so turning it on stops the boot rather than being honored quietly. The refusal is deliberate: a receiver that would hold the message is never asked, mail the setting says would bounce is delivered instead, and nothing reports the difference, so an operator trusting the flag has no way to find out it did nothing. MTA-STS is the transport protection that does apply to every outbound message; DANE applies as well once you have declared your resolver DNSSEC-validating, which it does not do on a default install. See DANE / TLSA. |
| `BLAMEPOST_COMPLIANCE_POSTURE` | `compliancePosture` | `none` | The regulatory posture the mailbox agent enforces on a hard delete. See Retention below, because this is the one setting that changes what delete means. |
| `BLAMEPOST_MTA_STS_MODE` | `mtaStsMode` | `enforce` | The mode published in the MTA-STS policy this server serves. Covered under MTA-STS. |
| `BLAMEPOST_MTA_STS_MX` | `mtaStsMx` | this server's hostname | The MX hosts listed in that policy. Covered under MTA-STS. |
| `BLAMEPOST_MTA_STS_MAX_AGE` | `mtaStsMaxAge` | `604800` | How long in seconds a sender caches that policy. Between `86400` and `31557600`. |
| `BLAMEPOST_SECURITY_CONTACT` | `securityContact` | `["mailto:postmaster@<hostname>"]` | The contact URIs published at `/.well-known/security.txt` (RFC 9116). Each has to carry a scheme, so a bare address is refused. |
| `BLAMEPOST_SECURITY_POLICY_URL` | `securityPolicyUrl` | unset | The disclosure policy page named in that same file. |
| `BLAMEPOST_SECURITY_TXT_EXPIRES` | `securityTxtExpires` | one year from start | An RFC 3339 timestamp after which the published `security.txt` stops being authoritative. One that has already passed is refused at start. |

The six per-listener port variables are in the Firewall table above, next to the
ports they move.

## Retention: what delete means

By default a hard delete is a hard delete. An account holder who expunges a
message, and an administrator who purges one, both get what they asked for, and
the only thing that keeps a message against their wishes is a legal hold.

```
BLAMEPOST_COMPLIANCE_POSTURE=soc2
```

`soc2` puts a one year floor under that. A hard delete of anything younger is
refused, for the account owner exactly as much as for an administrator, so a
message deleted today stays on disk and stays readable until it is old enough
to go. The refusal reaches every protocol, because deletion has one path: IMAP
`EXPUNGE`, the POP3 `DELE` set as it commits at `QUIT`, JMAP `Email/set` with
`destroyed`, and the purge in the browser interface all arrive at the same gate.

**Set it only if that is the promise you mean to make.** The person pressing
delete is not told that a regulator outranks them; the message simply stays. On
a mailbox where people expect delete to mean delete, that is a surprise worth
choosing deliberately rather than switching on because the value looks
reassuring.

The framework also models `hipaa`, `pci-dss` and `gdpr`, and this server refuses
all three at start rather than accepting them. Under each of those the mailbox
agent refuses every operation whose actor does not carry a field naming why that
particular access is lawful, and blamepost has no model that could supply one.
The guard checks only that the field is a non-empty string, so a constant would
satisfy it, and writing a constant would manufacture an attestation nobody made
while reading as a control that passed. `none` and `soc2` are the two values
this server can honestly offer.

Erasing an account is a different operation and is described under Deleting an
account. The retention floor governs deleting a message, and it governs an
erasure too: an erasure runs through the same delete path, so a message inside
the window the posture names stays until it is old enough to go, and the command
says which ones stayed.

## Message bodies on disk

A delivered message is two writes to two different places. The body is sealed
and written under `blobs/` on the data volume, named by the SHA3-512 of its
content, so one message delivered to several accounts is stored once. A row is
then written naming that digest. Nothing spans the pair, because a file write is
not part of a database transaction, so a process killed between the two leaves
one half without the other, and neither half complains.

Hold the two against each other:

```bash
blamepost blobs report
blamepost blobs report --verify
```

Without `--verify` a body counts as present when its file is there, which is a
walk of the directory and a comparison of two sets. With it, every referenced
body is unsealed and hashed back against the digest naming its file, which is
the only way to see one that has been altered or truncated in place. That costs
a read and a hash per message, so the plain form suits a schedule and the
verifying form suits a reason: a disk that reported errors, a volume moved
between hosts, a restore you want to trust.

`blamepost doctor` runs the counted form as one of its own checks, so a diverged
volume shows up in the routine health check without being asked for. That check
is the one thing `doctor` will not answer against a running server: it needs the
files and the rows read at the same moment, and against a copy of the rows every
message that arrived since would count as a body nothing references. So it
reports that check as not done, names the moment its rows were copied, and sends
you here. Run `blobs report` with the server stopped when you want the answer.

Either verb exits non-zero when the two disagree, and names each disagreement:

- **A message whose body is not on disk.** IMAP, JMAP and POP3 all list the
  message and then fail to return it, and nobody finds out until somebody opens
  it. This cannot be repaired from here, because the bytes are the only copy.
  Restore the volume from a bundle taken before the loss, or destroy the message
  so clients stop offering one they cannot open.
- **A body that no longer matches its digest.** The same outage, and a reason to
  look at the volume rather than at the mailbox: the seal opened, so this is not
  a wrong key, it is bytes that changed under a file nobody rewrites. Check the
  disk before restoring onto it.
- **A body that no longer opens at all.** A file cut short does not decrypt,
  because the seal authenticates what it carries end to end. A client asking for
  that message is told the body was altered or cut short and is not asked to try
  again, since trying again cannot help.
- **Bodies nothing references.** Storage that is never served and never
  reclaimed, because the reference count that removes a body only ever runs
  while deleting a message that still has a row. Harmless to leave, and it
  grows. `blobs reclaim` is what frees it.
- **A mailbox whose quota disagrees with the messages in it.** The message store
  raises its own byte and message counters when it accepts a message; the row
  binding that message to a mailbox is written afterwards. An interrupted
  delivery can leave the counter raised for a message the owner can neither read
  nor delete, and their mailbox fills against nothing. Reclaiming bodies does
  not change this, because the count lives in the database rather than on the
  volume. The report names the account, the mailbox and the size of the gap.
- **Something under `blobs/` that is not a message body.** Reported and never
  removed. Nothing here knows what it is.

### A delivery rewrites a body it finds cut short

One place repairs a body without being asked, and it is worth knowing about
because it is where a failing disk becomes visible.

A message delivered to several accounts is stored once, so the second account to
receive it files a row and reads the file that is already there. If that file has
gone short, every account after the first inherits it and never holds a readable
copy of its own. The delivery is holding the message at that moment, so it
compares the length of the file against the message and writes the message when
the file is shorter than the sealed form of it can be. That is the write that was
about to happen anyway, it lands atomically, and it touches no row: what is
repaired is the octets, and the count of messages naming them does not move.

Each repair writes an audit row carrying the digest of the body:

```bash
blamepost audit read --action blamepost.mail.mailbox.body_repaired
```

One row is a bad sector. A run of them is a volume to replace, and this is the
only place that says so, because nothing else on the server sees the file both
before and after.

The check is a length, which is nearly free and is why it can run on every
delivery. Read what it does not cover as carefully as what it does. The length it
compares against is the room the message itself has to occupy inside the seal,
not the length of the whole sealed file, so there is space above it: on a large
message it catches a file cut below roughly three quarters of its length, and on
a small one, where the envelope around the message is most of the file, only a
file cut to a small fraction of it. A body that changed without changing length
at all, which is what a single flipped bit leaves, is outside it entirely.

Nothing is served for any of those. The read hashes the stored octets back before
returning them, so the message is refused rather than answered with somebody
else's mail, and `blobs report --verify` is what names the file. Run it after
restoring onto a disk you have any doubt about, and treat the repair as a
saving on the deliveries it happens to catch rather than as the thing that keeps
the volume honest.

### A delete the volume would not finish

Destroying a message is two acts on this layer once the gates have let it
through: the row binding it to a mailbox goes, and the sealed octets that row
names go with it when no other row still points at them. The volume can refuse
either one. A mount that has gone read-only, a permission that changed, another
process holding a file open, or write-once triggers under a records-retention
posture all refuse below the server entirely.

A delete of several messages is a set of separate outcomes and each one is
answered for. **A message the volume would not finish removing is reported as one
that did not go, and every message behind it in the same delete still goes.** It
has left the mailbox either way, so no client is offered a message it can no
longer read; what stayed is the storage, and reporting that message as destroyed
would say the octets are gone while they are still on the volume and still
readable.

What you are told depends on which protocol asked, because each specification
gives the server a different vocabulary:

- **POP3** has a word for it, so the commit at `QUIT` answers `-ERR Commit
  failed: some deleted messages not removed`, with a count per reason and the
  count that did go.
- **JMAP `Email/set` and the browser interface** report the message as one that
  was not destroyed, under the reason `row-not-removed` or `body-not-removed`.
- **IMAP** has none: RFC 9051 gives `EXPUNGE` no refusal form, so the command
  completes and the client is told to renumber around the message, which is
  true of the mailbox. The trail is the only place this reaches an IMAP client's
  operator.
- **An account erasure** prints it as a `FAIL` line rather than a `kept` line,
  because nothing chose to keep it, and exits 1.

Every one of them writes an audit row carrying the digest of the body that
stayed:

```bash
blamepost audit read --action blamepost.mail.mailbox.destruction_incomplete
```

Fix the volume, then account for what is on it. The two halves end differently.
A body left behind with its row already gone is octets nothing references:
`blobs report --verify` lists it, and `blobs reclaim` frees it once the volume
gives the file up. A row left behind still names its body, so the pair stays
whole and `blobs report` shows it as a quota disagreement rather than as a
stranded body; the message is already out of every mailbox listing, and running
the delete again once the volume or the posture that refused it is fixed is what
finishes it.

**A rerun reaches the row even though no mailbox listing does.** What a reader
is served is this layer's rows intersected with the message store's, and a row
whose store partner has already gone is outside that intersection, so it appears
in no folder, no search and no `FETCH`. The delete path asks a second question of
every identifier the listing does not answer, so the identifier the refusal gave
you is still the identifier to run the delete with. Take it from the audit row
above.

That rerun ends one of two ways. If the volume has been fixed, the row goes and
the octets go with it, and the delete is finished. If the thing refusing is a
records-retention posture rather than a fault, the row will not go on any run,
and the second run destroys the message anyway and keeps the row: what a
write-once table preserves is the row, and that row carries the folder, the
identifier, the UID, the digest, the size and the dates rather than any message
content. Whether the mail itself may be destroyed is decided by the retention
floor and any preservation order, and both are consulted again on that rerun,
from this layer, before anything is touched. So an erasure request can be
answered in full even under a posture that keeps the record: the mail is gone,
the record of it stays, and `blobs report` shows the mailbox still counted
against a message no protocol lists.

### Reclaiming bodies nothing references

```bash
# Stop first. Reclaiming opens the volume, and so does the running server; the
# second one to open it is refused rather than allowed to overwrite the first.
docker stop blamepost

blamepost blobs reclaim \
  --confirm \
  --reason "bodies stranded by the crash on 2026-08-22"

docker start blamepost
```

Stopping first is enforced rather than advised, and it buys a second thing
besides the volume. Reclaiming re-reads the message rows immediately before it
removes each body, so a body that gained a row since the walk is left alone. That
check holds against anything happening inside the same process, and it cannot
hold against a delivery arriving in a server that is still running: content
addressing means a message with a body already on disk reuses that file rather
than writing it again, so a delivery landing at the wrong moment would leave a
row naming a body that had just been removed. That is a message that exists and
cannot be read, and the single-opener refusal is what prevents it.

Both flags are required, and the reason goes into the audit chain. That row is
the only record afterwards that these bodies were ever here, so a reclaim with
nothing recorded answers nothing later.

**A body is only removed once it has been unreferenced for a day.** This is the
part worth understanding before you reach for the verb. A body whose row was
lost and a body whose row is still being written look exactly alike from
outside: both are a file that nothing references yet. Waiting is what tells them
apart, because delivery writes the body and its row inside one call, so a body
still unreferenced a day later was not mid-delivery. Anything newer is reported
as held back, with the moment it becomes reclaimable, and left where it is.

There is no flag that shortens the window. What it guards against is bounded by
how long one delivery takes rather than by anything you decide, so the answer to
"not yet" is to come back, and the report tells you when.

**A body the volume will not give up is named, and the rest still go.** A
removal can be refused: a mount that has gone read-only, a permission that
changed, a file another process is holding open. Each refusal is printed on its
own `FAIL` line with what the volume said, the remaining bodies are still
removed, and the command exits non-zero so a scheduled reclaim that has stopped
freeing anything is noticed before the volume fills. Nothing removed the rows,
so running it again once the volume gives the file up reaches what was left.

Nothing else is ever removed. A row whose body is missing is not repaired, a
body that fails `--verify` is not deleted, and a file under `blobs/` that is not
a message body is left exactly where it is. Each of those is a decision, and a
reclaim that made them quietly would be the second thing to have gone wrong.

## Domains

```bash
blamepost domain add example.com
blamepost domain list
blamepost domain show example.com
blamepost domain disable example.com --reason "moving to another host 2026-08-22"
blamepost domain enable  example.com --reason "move canceled"
```

Adding a domain does not make it deliverable. `add` mints its DKIM keys and
prints the records; publish those and the rest from Part 1, run
`blamepost doctor --domain example.com` until it is clean, then
`blamepost domain acknowledge example.com --by you@example.com` and restart. The
MX listener refuses to bind at all while any active domain is unacknowledged, so
adding a domain and stopping there takes inbound mail down for every domain at
the next restart, not just for the new one.

**The restart in that sequence is what makes port 25 accept mail for the new
domain**, and it is not optional. The hosted set the listener answers RCPT
against is read once when it binds, so until you restart, mail for a domain you
added is refused with a permanent code and the sender's queue discards it rather
than retrying. That is worth knowing for the order you do things in: publish the
MX record **after** the restart, not before, or the gap between the two is
mail that bounces instead of waiting.

**Disable is how you take a domain out of service without losing it.** A
disabled domain stops being one this server accepts mail for, so inbound mail
addressed to it is refused at RCPT, and everything it holds stays exactly where
it was: its accounts, their mail, and its DKIM selectors. `enable` puts it back.
Both record a reason in the audit trail. A disabled domain is also skipped by the
MX listener's acknowledgment gate, so switching one off does not hold up a
restart.

**Disabling takes effect at the next RCPT, with no restart**, and so does
enabling. The direction that needs a restart is adding, above; taking a domain
out of service is live. Peers are refused permanently rather than temporarily,
so a sender reports the failure to whoever wrote the message instead of retrying
for days against a decision you meant to make. Removing a domain answers the
same way as disabling it, and a stranger is told only that this server does not
handle mail for that domain: which of the two happened, and that the domain was
ever hosted here, is a fact about your configuration with no reason to publish
it. That distinction is kept where it belongs, in the audit trail, under
`blamepost.mail.listeners.mx_recipient_domain_not_hosted`, whose `state` field
reads `disabled` or `removed`. That row is what answers "why did mail for this
domain start bouncing" a year from now.

What disable is not is a quiet pause. The refusal is a refusal, not a hold, so
senders find out rather than queueing until you turn it back on. Reach for it
when a domain is moving elsewhere or is under investigation, not to buy an hour.

Removing a domain is a different operation and it cannot be undone:

```bash
blamepost domain remove example.com --destroy --reason "moved to another host"
```

There is no archived copy. The row and every DKIM selector under it are erased,
which is why the flag is explicit. Removal also refuses while the domain still
holds any account or alias, and while any alias in another domain points into
it. Repoint or delete those first. That refusal is deliberate: mail an alias
aims at a name in a hosted domain is refused at RCPT today, and once the domain
is gone the same alias becomes a forward, so the message starts being accepted
and sent off the machine. Deleting the mail itself is an account operation,
described under Deleting an account.

**The sealed private keys go with the selector records, and they go first.** The
command prints how many of each it destroyed. A selector record's key file name
is the only thing on this server that can find that file: nothing walks the data
directory's `keys` folder while the server runs, and a backup copies the whole
volume, so a key left behind would sign mail as the domain for as long as the
volume and its backups last, including after somebody else takes the name on.
When the volume will not give a key up before the records are erased, the whole
removal refuses with the records intact and names the file, so running the
command again reaches it. A key that moved out of its place and could not then
be destroyed is the other case and there is no second run for it: the removal
has already committed, the record that named the file is gone, and the file is
named on its own line for you to delete by hand. A key left in the keys folder
below covers what that looks like.

The records themselves are still published. This server never edits DNS, so
delete the `_domainkey` TXT records for the domain from its zone yourself once
the removal has run.

## Accounts

```bash
blamepost account add     alice@example.com --quota 5368709120
blamepost account list    --domain example.com
blamepost account list    --include-archived
blamepost account show    alice@example.com
blamepost account passwd  alice@example.com
blamepost account suspend alice@example.com --reason "credential stuffed 2026-08-22"
blamepost account resume  alice@example.com
```

`add` generates a password and prints it once when `--password` is omitted, which
is the safer default: a password typed on a command line is in the shell history
of whoever ran it. `--quota` is in bytes and the mailbox is unlimited without it.
It is set when the account is created, and `show` prints it back.

`list` leaves archived accounts out, because the common question is which
mailboxes are live. `--include-archived` puts them back in, and that is where to
look for the address `resume` takes back. An account part way through an erasure
is listed either way: it authenticates no better than an archived one, but it is
the one state you have an outstanding job against, since mail this server was
asked to destroy is still on the volume until the erasure finishes.

**Suspension stops both sending and receiving.** A suspended account cannot
authenticate, so it cannot send, and it stops being a deliverable target, so
mail addressed to it is refused rather than filed. A sender writing to a
suspended mailbox gets a report back; nothing is accepted and then dropped.

**It takes effect at the message, not at the connection.** A message already
being transmitted when you run the command does not reach the mailbox: whether
the address still has somewhere to land is decided at the moment the copy would
be filed, so a suspension that lands mid-transfer refuses that message like any
other. This matters when you are suspending an account because of what is
arriving in it, which is when mail is in flight by definition.

Everything the account already holds is kept, and `resume` puts it back exactly
as it was. So suspension is the right first move on a compromised credential:
the damage stops immediately and it is reversible. What it is not is a quiet
hold on incoming mail. If the mailbox needs to keep receiving while you
investigate, change the password instead and leave the account active.

Each of these that changes something writes an audit row carrying what changed,
when, the reason where the verb takes one, and who ran it, which for a command
line invocation is the operating-system account and the host the process ran as.
`list` and `show` change nothing and write nothing. Actions taken on someone
else's mailbox require an explicit reason, because an unexplained administrative
access is what an audit log exists to surface.

`list` and `show` are also the two that answer while the server runs. Everything
else here needs the volume, so it needs the server stopped; see "Seven reporting
verbs answer while the server runs" for what the two hand back instead and how to
read the age on it.

Two account actions are deliberately not here. Giving a mailbox back the sign-in
attempts that wrong passwords spent is done in the admin interface, under
Lockouts, and it cannot be done from the command line at all. The counters live
in the running server's memory, and every verb that could release one needs that
server stopped, so a command line release would report that nothing was locked no
matter what was happening. See "A mailbox is refused everywhere and the password
is right".

Giving an existing account the administrator role, and taking it back, are the
other one. Both are buttons on the account list in the admin interface. Taking
it back is offered on any account that holds the role, whatever state that
account is in, while giving it is offered only on an account that is in service.
See "After the first start: the administrator" for why the two differ. `init`
is the only command-line verb that grants the role, and it does so while
creating the account rather than on one that already exists.

## Aliases

An alias points one address at one destination, and a chain of them is followed
to its end. They are added and removed in the admin interface under Aliases;
there is no command line verb for them. A destination outside this server is
accepted, and a message forwarded to one leaves through the same outbound path
and the same transport policy as everything else this server sends. It takes a
smaller share of the queue than an account's own mail does, because how much of
it arrives is decided by whoever writes to the alias rather than by anyone here;
see The outbound queue.

**Forwarding off this server costs the message its authentication, and that is
inherent to forwarding rather than a setting here.** A forwarded message keeps
the envelope sender it arrived with and is not signed on the way out, because
signing somebody else's message with your domain's key would attest to content
your domain did not write. So the receiving side sees mail from the original
sender's domain arriving from your address: SPF fails for that domain, and any
DKIM signature the original carried survives only if nothing on the hop altered
the message. Forwarding to a large receiver is where this shows up, as mail
that reaches the destination's junk folder or is refused outright. An alias
that lands in a mailbox here has none of that problem, which is the argument
for hosting the mailbox rather than forwarding it.

**Creating an alias also hands out a sending identity.** Submission binds the
`From` header of every message an account sends, and the authors it accepts are
the account's own address plus every active alias landing in that account's
mailbox. So an alias on `ceo@example.com` aimed at `alice@example.com` does two
things: mail addressed to `ceo@example.com` arrives in alice's mailbox, and
alice can write `ceo@example.com` as the author of her own outgoing mail. Where
the alias and the account sit in the same domain, that mail leaves signed with
the domain's key and DMARC-aligned, and a recipient has nothing to tell it apart
from mail sent by whoever actually holds the address. For a departmental address
that several people answer, this is the point of the binding. Where sending was
never intended, the address needs an account of its own: there is no alias that
forwards without granting.

Two limits bound the grant. A catch-all is never a sending identity, so claiming
a domain's unmatched mail does not let the account holding that claim write
every name in the domain. And only a direct alias counts, so an address that
reaches a mailbox through a second alias is delivered there and is still not an
address that mailbox may write. Disabling an alias withdraws the delivery and
the identity together, at the next message rather than at the next sign-in,
because the set is read from the store per message.

Where the identity is actually usable is the webmail interface and JMAP, which
compose their own envelope; a mail client on the submission port cannot send
under an alias. "Sending as an alias" below has the detail, and it is worth
reading before you tell somebody a departmental address is set up for them.

## Mail between two mailboxes on this server

A message addressed to an account this server hosts is written into that
account's mailbox directly. It never leaves the host, so it does not depend on
the MX record resolving, on this machine being able to reach its own public
address, or on the MTA-STS and DANE policy the domain publishes about itself.
It takes no room in the outbound queue, so a full queue does not stop it.

All three sending surfaces route the same way: a mail client on 587 or 465, the
compose form in the browser, and JMAP `EmailSubmission/set`.

The delivery is the one an arriving message gets. The recipient's Sieve script
runs, the quota applies, and the retention floor applies. The copy filed in the
recipient's mailbox carries the DKIM signatures the message left with, and the
sender keeps a copy in `Sent`.

An envelope naming recipients here and elsewhere is split. The addresses here
are filed, the rest go out over the outbound path with the transport policy and
the retry budget, and only the ones that leave count against the queue. Aliases
are resolved first, so an address that forwards to a mailbox here is filed
there and one that forwards off this server leaves over the outbound path. An
address this server hosts and cannot deliver to, such as a suspended mailbox or
a name nobody holds, is reported to the sender rather than sent onward.

## What a sending server is told about a recipient

An address this server does not hold is refused while the sending server is
still on the socket, at `RCPT TO`, before it transmits a byte of the message:

```text
550 5.1.1 No mailbox by that name at this server.
```

That is what RFC 5321 §3.3 asks for, and it is the answer that costs a sender
least: their server stops, and the person who mistyped the address hears about
it in seconds rather than after somebody else's retry schedule runs out. A
recipient at a domain this server does not host is refused a step earlier, with
`550 5.7.1 Relaying denied`. An alias you have disabled is refused there too,
permanently, so senders find out rather than queueing against it.

**A condition the owner can clear is deliberately not refused there.** A
suspended account and a full mailbox are both accepted at `RCPT TO` and met at
delivery instead, because `550` tells a sending server to stop trying and report
a permanent failure, and neither of those is permanent. Telling somebody's
correspondents that their address does not exist, while the thing that would fix
it is you resuming the account or the owner emptying their Trash folder, is
worse than a message that arrives late. Those two carry `4.2.1` and `4.2.2`
instead, which ask the sender's own server to keep trying at its end.

**A mailbox part way through an erasure is refused there, and permanently.** It
is answered one command into the session, before the sender transmits the
message, with the same line an address holding no mailbox gets:

```text
550 5.1.1 No mailbox by that name at this server.
```

It is the one state in that family you do not lift. The mail the account held is
already destroyed, `blamepost account resume` refuses the account, and the row
leaves when the erasure finishes, after which the address is answered `550 5.1.1`
anyway. A temporary answer would spend the sending server's entire retry window
against an address that can never accept the message, then return it to the
person who sent it days later, describing a condition that was never temporary.
Telling them at `RCPT TO` costs one command instead of a whole message body.
Suspended and archived mailboxes are not affected by this and still answer
temporarily.

What that looks like from here depends on the rest of the message. Where other
recipients on the same message were delivered, the peer is told the message
arrived and this server composes a delivery report to the envelope sender
naming the recipient that did not. Where nothing on the message could be
delivered, the peer is answered:

```text
451 4.3.0 Local delivery error
```

and keeps the message, so it retries on its own schedule and reports to its own
sender if it gives up. This server writes no report of its own in that case, and
that is deliberate: a report goes to whoever the envelope claimed to be from,
which on a run of mail to addresses that do not exist here is a third party who
never wrote to you. The peer's return path is one it accepted from a sender it
knows. That case is on the trail, one row per message, naming the recipients:

```bash
blamepost audit read --action blamepost.mail.inbound.refused
```

## What an account may put in `From`

The envelope sender and the `From` header are bound separately, and a client can
satisfy one and fail the other.

`MAIL FROM` has to be the account's own address as the account is spelled. An
alias is refused there, and so is the account's own plus-tagged address:
`alice+receipts@example.com` is accepted as a recipient on port 25 and refused
as an envelope sender on 587. That is a false refusal rather than a way in, and
[ROADMAP.md](../ROADMAP.md) tracks it under Sending under an alias and Sending
from your own subaddress. It is also the reason the section below ends where it
does: the browser and JMAP can send under an alias and an ordinary desktop
client cannot.

`From` is measured against the wider set, with plus tags folded away the same
way routing folds them. The rules a client can trip over:

- Every address in `From` or `Sender` at a domain this server hosts has to be
  one the account may write. An address at a hosted domain that belongs to
  nobody is refused too, because the domain's key would sign it into alignment.
- At least one address across `From` and `Sender` has to be one the account may
  write, so the message is attributable to somebody who signed in to send it.
- An author at a domain this server does not host is left alone.
  `From: partner@example.net` with `Sender: alice@example.com` is accepted:
  this server's key creates no alignment for a domain it does not host, so that
  domain's own DMARC policy is what answers for the message.
- A message with no `From`, with two `From` fields, with two `Sender` fields,
  with a `From` naming an empty group, or with a header block that cannot be
  read is refused whatever it names.

**The refusal reaches the client as `451 4.3.0 Local delivery error`.** That is
a transient code for a permanent condition and it names no cause, because it is
the one reply the listener writes for every refused message. Expect a client to
handle it badly: curl reports it as a malformed reply rather than a temporary
failure, so a script cannot branch on it, and a sending MTA reads the 4 and
retries a message that will be refused identically every time. Tracked upstream
as blamejs#668, which asks that a refusal be able to choose its own reply. The
reason is in the log and in an audit row:

```bash
blamepost audit read --action blamepost.mail.listeners.submission_from_not_owned
```

Each row names the address that was rejected and the addresses that would have
been accepted, which is usually enough to tell a misconfigured client from an
account someone else is using.

### Sending as an alias

The set an account may write is its own address plus every active alias that
lands directly in its mailbox, in canonical form so a subaddress folds into the
mailbox it belongs to. A catch-all is never in the set: it claims every name in
the domain, and counting one would hand the account holding it every address the
domain could ever carry.

**In the browser**, an account holding more than one of those addresses gets a
picker on the compose form; an account holding one gets none, because a control
with a single option in it is clutter on the form people use most. What the
browser shows decides nothing. The server reads the set from the store again on
every send and writes the address out of that set rather than the one the request
carried, so an account that was offered no picker is measured against the same
set as one that was, and an author typed into the request by hand meets the same
refusal. The return path stays the account's own address, so a bounce lands in
the mailbox of whoever actually sent the message.

**Over JMAP**, `Identity/get` answers with one identity per permitted address,
and `EmailSubmission/set` now requires an `identityId` naming one of them. A
create with the field missing is refused as an invalid property and one naming an
identity this account does not hold is refused as `identityNotFound`; neither is
quietly sent as the account instead, which is the failure a mailbox owner would
otherwise discover in the recipient's reply.

**An ordinary desktop client on the submission port cannot use this.** Such a
client derives the envelope from whichever identity it is configured with, so it
puts the alias in `MAIL FROM` as well as in `From`, and the envelope binding
refuses that with `553 5.7.1 Sender address rejected: not owned by authenticated
identity`. The browser and JMAP compose their own envelope and never have the
problem. If someone needs to send as a departmental address from a mail client,
the answer today is a second account for that address rather than an alias onto
theirs.

Point a client at 587 or 465 for sending and 143 for reading, and set it to
require TLS. On the authentication method, the answer is narrow and worth
knowing before a client refuses to connect.

Over SASL, this server offers `PLAIN` and nothing else. IMAP `LOGIN` and POP3
`USER` with `PASS` also work, since both hand over the same two values. A client
configured for `CRAM-MD5`, `DIGEST-MD5`, `SCRAM-SHA-256`, `NTLM` or OAuth is
refused, and the refusal is deliberate rather than a gap in the listener:
passwords here are stored as Argon2id verifiers, and every one of those
mechanisms needs a secret the server can reproduce. Storing something reversible
to satisfy a client would trade the property that makes a stolen database
worthless.

`PLAIN` sends the password inside the TLS session, which is why no listener has
a plaintext mode and why the authentication state machine refuses credentials
before TLS. In most clients the setting to choose is spelled "normal password"
or "plain", together with "SSL/TLS" or "STARTTLS". Anything offering to send the
password "encrypted" means a challenge-response mechanism and will fail.

Both spellings of the exchange work, on all four listeners that authenticate. A
client may carry its credentials on the `AUTHENTICATE` line itself, and a client
may leave them off and wait to be asked. The ask is empty, because PLAIN is a
mechanism where the client speaks first, and each listener writes it in its own
syntax: the IMAP `+` continuation, the SMTP `334` reply, the POP3 `+` line, and
on ManageSieve a zero-length literal, which is the only way RFC 5804 §2.1 can
express an empty ask. A client that opens the exchange the long way is not
charged for it: the round trip is a normal one and spends no part of the
account's authentication-failure budget, and a client that withdraws with a
single `*` is read as having withdrawn rather than as having guessed wrong.

## Devices that have to send through this server

The MX listener relays for nobody, and there is no setting that widens it.
A message arriving on port 25 is accepted only when it is addressed to a domain
this server hosts, and anything else is refused with `550 5.7.1 Relaying
denied`. That is what stops this server from being the one a spam campaign
borrows.

`BLAMEPOST_RELAY_ALLOWED_FOR` is an address-range grant this server refuses.
**Setting it stops the boot**:

```
BLAMEPOST_RELAY_ALLOWED_FOR='[{"cidr":"192.0.2.0/24","scope":"branch office"}]'
```

The refusal names the setting, says which origin supplied the value so you know
whether to edit the environment or the configuration file, gives the reason set
out below, and tells you to remove it. An empty list asks for nothing and starts
normally. The setting is refused rather than deleted outright so that an
operator who had one reads a sentence, instead of finding that the variable had
quietly stopped meaning anything.

**The device you have gets an account, and that is better rather than merely
equivalent.** The case a range existed for is a printer, a scanner or an
application server on a network you control, and this server already serves it
through the front door. Every listener here requires STARTTLS before it will
accept an envelope, on port 25 exactly as much as on submission, and neither
profile this server offers relaxes that: a peer that has not upgraded is
answered `530 5.7.0 Must issue a STARTTLS command first` at `MAIL FROM`. So a
device that could ever have reached `RCPT TO` had already completed a TLS
handshake, which means it can sign in on 587 or 465. The only device a range
could serve that an account cannot is one that speaks no TLS at all, and that
device never gets past the greeting here either way.

So the range carried the whole risk of relaying for everything else on that
segment and bought nothing. What the account buys instead:

- **A party rather than a segment.** An address says which network a message
  came from and never which sender. When one host inside a range is taken over,
  the only lever is withdrawing the range, which takes the printer down with
  it. `blamepost account suspend` withdraws one device.
- **A signature.** Relayed mail could only ever leave unsigned, because the
  inbound path does not sign and must not: signing it would let anything on that
  segment emit mail aligned under a hosted domain's key, which is the forgery
  the author binding exists to refuse. Unsigned mail claiming a hosted domain is
  refused by your own DMARC policy at the receiver, and claiming anything else
  it is unattributable mail spending this server's reputation. An account's mail
  is signed for the domain it claims.
- **Somewhere for the bad news to go.** A relayed message that fails
  permanently owes a delivery report to a return path the device wrote and
  nobody verified. An account has a mailbox, so the report reaches something
  that can be read.

Set the device up the way you would set up a person: give it an account, as
under Accounts above, point it at 587 with STARTTLS or 465 with implicit TLS,
and hand it the password. Its `MAIL FROM` has to be that account's own address,
which is the binding described under What an account may put in `From`. A device
that genuinely cannot hold a credential needs a submission relay of your own in
front of it, which keeps the credential in one place you control rather than
extending trust to a whole segment.

## Connection and message ceilings

Every listener holds a ceiling on what one source address may ask of it, so a
single hostile peer cannot take the server away from everyone else. The first
four below are those; the fifth bounds one message rather than one address, and
only the two SMTP listeners read it. The shipped numbers are these:

| Ceiling | Shipped value | What it bounds |
|---|---|---|
| `maxConcurrentConnectionsPerIp` | `10` | Connections one address may hold open at once, counted per listener. |
| `connectionsPerIpPerMinute` | `60` | New connections one address may open in a rolling minute. |
| `authFailuresPerIpPer15Min` | `10` | Failed sign-ins from one address in a rolling fifteen minutes. |
| `rcptFailuresPerIpPerMinute` | `50` | Refused recipients from one address in a rolling minute. |
| `maxMessageBytes` | `52428800` (50 MiB) | The largest message `MAIL FROM` may declare and `DATA` may carry. |

A peer over a ceiling is refused in the protocol it is speaking: `421 4.7.0` on
SMTP, `* BAD` on IMAP, `-ERR` on POP3, `NO` on ManageSieve. The refusal is
recorded. Nothing is dropped silently.

**Two further bounds hold at fixed values, and neither is a field above.** Every
mail listener accepts at most 1024 sockets at once, whoever they belong to, which
is five listeners on the shipped configuration and six once POP3 is turned on;
the browser interface is an HTTP surface and is not one of them. The
ceilings in the table bound one address; this one bounds the listener, so the
total is no longer the per-address number multiplied by however many addresses
a sender can speak from, which a botnet, a NAT pool or a single IPv6 /64 makes
large. A socket over the ceiling is closed before it costs a parser.

Two things follow from that number and neither is obvious from it. The first is
that six listeners at 1024 each is more open descriptors than a container's
default soft limit usually allows, and a process that runs out answers a new
connection with an accept error rather than with a protocol refusal a peer can
read. If you expect real load, raise the descriptor limit with `ulimit -n`, or
`LimitNOFILE` under systemd, or `ulimits.nofile` in the compose file, rather
than discovering the ceiling is unreachable. The second is that
`maxConcurrentConnectionsPerIp` and the listener ceiling interact: raise the
per-address number toward 1024 and one source address can take the whole
listener, at which point the listener ceiling stops separating one peer from
everybody else. Keep the per-address ceiling well below it. Fifty, the example
below, leaves room for twenty distinct addresses at full stretch.

And a peer sending a message body slower than a hundred bytes a second is
answered `421 4.7.0` and cut, on both SMTP listeners and whether the body
arrives through `DATA` or `BDAT`. This is the bound the idle timeout cannot
give: a peer sending one byte at a time is never idle, so it holds a connection
and its share of the per-address ceiling for as long as it likes. The rate is
judged over short windows rather than across the whole message, so an opening
burst buys no credit against a slow tail. A hundred bytes a second is far below
what any working sender achieves, so ordinary mail on a bad link is not near
it.

**The connection ceiling is the one to look at first, and the reason is who
shares an address.** Ten concurrent connections is a fair bound on a stranger
delivering mail to port 25. It is a low one for the people reading their mail:
a single mail client keeps several IMAP connections open at once, and everyone
behind one home or office address arrives as that address. Two clients can
reach ten between them, and the person whose connection is refused sees only
that their mail stopped working.

Raise it if your users share an address:

```
BLAMEPOST_LIMITS='{"maxConcurrentConnectionsPerIp":50}'
```

A field you leave out keeps its shipped value, so the line above changes that
one ceiling and nothing else.

**`rcptFailuresPerIpPerMinute` is the one on the list that bounds an attack
rather than a workload.** RFC 5321 §3.5 has the MX listener answer a recipient
it holds differently from one it does not, which is the right answer to give a
sender and is also an oracle: a stranger can walk a word list against port 25
and read back which addresses exist here. This is how many guesses a minute one
source address gets before it is answered `421 4.7.0` and the connection is
closed, so the reason to lower it is a directory harvest rather than a busy
server.

Only a refused recipient is charged. A message to fifty live addresses on one
connection spends none of it, which is why the number can sit well above what
ordinary mail needs and still make enumeration worthless.

The floor is `5` rather than `1`, and going near it costs you delivery. A
legitimate sender puts several recipients on one connection, and a mailing list
expanding to this server carries addresses that have since been closed, so a
ceiling set that low answers ordinary mail with temporary failures and delays
it. The sender retries and the mail arrives late rather than not at all, which
is exactly the kind of fault nobody reports and nobody can see from here.

Lower `maxMessageBytes` if you do not want to accept large attachments. Reading
a message costs time in proportion to its size, so what the ceiling really
bounds is memory: the body is assembled once when the transfer ends and stays
resident for the rest of the transaction, one copy per message in flight. Size
it against that number multiplied by the transfers you expect at once, not
against the disk the mail will land on:

```
BLAMEPOST_LIMITS='{"maxMessageBytes":26214400,"maxConcurrentConnectionsPerIp":50}'
```

The number is advertised to senders on the `EHLO` response as `SIZE`, so a
sending server knows before it starts. A message declaring more is refused with
`552` at `MAIL FROM`, before any of it crosses the wire.

Per-command line lengths and idle timeouts are deliberately not settable. Both
have floors the mail RFCs require a server to meet, and a value below one of
them refuses correct clients while doing nothing about a hostile one.

These are in-process ceilings and they see only what reaches the process. A
packet filter or a load balancer in front of the server still earns its keep:
it refuses a connection flood before the flood costs this process anything.

## Rotating DKIM keys

Rotate on a schedule, and rotate immediately if a key might have been exposed.
The procedure keeps both selectors valid during a seven-day overlap. Signatures
on mail already in flight still verify while the change propagates, and so do
signatures on the bounces that mail generates.

```bash
# 1. Mint the replacement pair. Both pairs sign while the overlap runs.
#    The default selector name carries the month, so rotating a second
#    time inside the same month needs --selector to avoid the name that
#    is already published.
blamepost dkim rotate --domain example.com

# 2. Print every record that must be in the zone right now, old and new
#    together, and publish the ones you do not already have.
blamepost dkim records example.com

# 3. Wait for propagation, then confirm old and new both resolve.
blamepost doctor

# 4. Seven days later, stop signing with the outgoing pair. Name the
#    Ed25519 selector; its RSA partner carries the same name with an
#    -rsa suffix and retires with it.
blamepost dkim retire --domain example.com --selector bp202608

# 5. Report which retired selectors have finished their overlap and can
#    now be deleted from the zone.
blamepost dkim sweep --domain example.com
```

**Do not compress this.** The gap between step 4 and step 5 is what covers mail
sitting in a remote queue, a DSN generated three days after a send, and a
mailing list that re-sends with the original signature. Deleting the old record
early turns all of that into authentication failures against your own domain,
which is a DMARC report you get to explain.

Step 4 destroys the outgoing pair's private keys, because nothing will sign with
them again and keeping them only widens what a stolen volume yields. Step 5
removes the records that named them, and destroys any private key still sitting
behind one: that is the case a selector reaches when it was moved out of signing
without step 4 having run. `blamepost dkim sweep --immediate` withdraws a record
before its overlap has elapsed, which is what to reach for when you believe a key
is exposed, and it destroys the key along with the record.

```bash
blamepost dkim list example.com    # which selectors exist, which is signing
```

`dkim list` and `dkim records` answer while the server runs, carrying the moment
the volume was last written; the three verbs that change a selector need it
stopped.

Every step above is on the audit trail, which is the record an auditor asks for
when they want to know when a key was replaced and by whom:

```bash
blamepost audit read --action blamepost.mail.dkim.keys_generated
blamepost audit read --action blamepost.mail.dkim.keys_rotated
blamepost audit read --action blamepost.mail.dkim.keys_retired
blamepost audit read --action blamepost.mail.dkim.selectors_swept
```

A rotation row names the outgoing selector and the incoming one together, because
that is the only moment the pair exists at once. Attempts that were refused are
recorded alongside the ones that finished, so a rotation somebody started and
could not complete is visible rather than absent. No key material of either half
reaches a row: what is written down is the selector name, its algorithm and its
domain.

### A key left in the keys folder

Anything that destroys a selector record moves its sealed private key out of the
way first and destroys it once the record has gone. That ordering is what keeps
a key from being left behind under a name nothing points at: the record is the
only thing on this server that finds the file, so the file is only destroyed
after the record it belonged to is on its way out, and a key the volume will not
move refuses the whole withdrawal with the record intact.

There is one case that ordering cannot cover. If the volume refuses to destroy a
key after its record has already gone, the file is left in the `keys` folder
under its usual name with `.erasing` on the end. Nothing signs with it, because
no record points at that name, and nothing here will report it a second time.
`blamepost domain remove` and `blamepost dkim sweep` each print the names when it
happens, and the administration interface says so on the page you swept from,
with the names in the server log:

```bash
ls /var/lib/blamepost/keys/*.erasing
rm  /var/lib/blamepost/keys/<name>.erasing
```

Delete them. Whoever holds one signs mail as the domain it belonged to, and that
stays true if somebody else hosts the name later. Until you do, a later
withdrawal that would have to write over one of them refuses and names it,
because what is sitting there is signing material and writing over it destroys
the only copy.

**Check whether the record is still published before you delete one.** A
`.erasing` file left by a removal that committed belongs to a record that is
gone, and deleting it is the whole of the fix. The other way into the same
filename is a withdrawal that was refused after it had already moved the key
aside and could not move it back, and that one leaves the record standing: the
selector is still published, the domain is still meant to sign with it, and the
`.erasing` file is the only copy of the key. Deleting it there costs the domain
that selector for good. `blamepost dkim list example.com` answers which case you
are in. Where the record is still there, running the withdrawal again is enough:
the key is not in its place, nothing else can be, and the withdrawal puts it back
before it stages it a second time. Renaming it back by hand first also works and
reaches the same state. What still refuses is a `.erasing` file sitting beside a
key that IS in its place, because two files under one selector leave nothing on
this server able to say which one the record means, and writing over either
destroys signing material.

If you missed the message when it was printed, `blamepost doctor` finds them
anyway: its `signing keys` line holds every file in the folder against the
selector records, and one of these is named by no record.

A mint can leave one the other way round. Minting writes the sealed private key
first and publishes the record naming it afterwards, because a record for a key
that is not there is a domain whose mail leaves unsigned. A run stopped between
those two writes leaves a key file under its ordinary name with no record
pointing at it, and `blamepost doctor` reports that one under `signing keys` too.

Minting again for the same selector then refuses rather than writing over it:

```text
blamepost dkim: example.com.bp202608.ed25519.sealed is already in the keys folder
on this volume, and what is in it is a sealed private key. Nothing was minted.
```

Two things reach that line and the refusal cannot tell them apart, because the
record that would say which is the record that has not been written. One is
another mint working on that pair right now, on a second command line or through
the admin interface, in which case the answer is to wait and run `blamepost dkim
list` to see what it published. The other is the leftover above, in which case
delete the named file from the `keys` folder and run the mint again. Either way,
`--selector` with a name of your own mints without touching the file at all.

Nothing was written when you see that line, so a refused mint changes nothing and
the domain keeps signing with whatever it was signing with.

## The outbound queue

```bash
blamepost queue list
blamepost queue list --account alice@example.com
blamepost queue list --destination example.net
blamepost queue show <id>
blamepost queue held
blamepost queue flush
blamepost queue flush --force
blamepost queue remove <id> --reason "undeliverable, sender notified by hand"
```

`list` prints one line per waiting recipient, soonest first: the id, the
recipient, the attempt count, when the next attempt is due, the mail exchanger
the last attempt reached, and the reason it did not land.

```text
56a84c2f074774f28a26cf71  bob@example.net  attempt 2  due Mon, 24 Aug 2026 09:41:00 GMT  via mx1.example.net  451 4.2.1 mailbox busy, try later
```

The reason is the diagnosis most of the time, because a receiver's own refusal
text says what it wants. The `via` clause is what tells you whose refusal it is
when a domain publishes several mail exchangers: one host refusing while the
others accept is that host, or this server's transport security against it,
while every host refusing is the domain. It is absent where the attempt never
reached a host at all, which is what an MX lookup that failed looks like, and
saying nothing there is deliberate: naming a peer that was never contacted sends
you to ask the wrong party.

The two filters answer the two questions a backlog raises. `--account` narrows
to one sender, which is what to reach for when the queue grew suddenly and you
want to know whether it came from one mailbox. `--destination` narrows to one
receiving domain, which is the shape a single receiver deferring you takes. An
address or domain that cannot be read is refused rather than answered with an
empty list, because an empty list is what a correct answer looks like too.

Below the listing, `list` prints how full the queue is and, when there are any,
the message bodies in it that no descriptor names. A waiting recipient is two
files and the message is written before the descriptor, so a process that stops
between the two writes leaves a message that nothing lists and nothing sends,
while the ceiling still weighs it. That is the shape of a queue that reads as
empty and refuses mail anyway. Each is named by id, and `blamepost queue remove
<id> --reason ...` clears it: the verb takes either kind of id. `blamepost
doctor` reports the same thing under `outbound spool`.

`show` takes one id and prints what a row cannot hold: every attempt made on
that message, oldest first, with what the receiver said each time, and how the
message ends if nothing changes.

```text
id         56a84c2f074774f28a26cf71
recipient  bob@example.net
sender     alice@example.com
queued     Mon, 24 Aug 2026 07:15:00 GMT
size       2314 byte(s)

2 attempts, oldest first:
  Mon, 24 Aug 2026 07:41:00 GMT  attempt 1  deferred  via mx1.example.net  4.7.1  451 4.7.1 greylisted, try again in 300 seconds
  Mon, 24 Aug 2026 08:41:00 GMT  attempt 2  deferred  via mx2.example.net  4.3.2  451 4.3.2 the receiving system is not accepting messages

Attempt 2 of 35 spent, 33 left. Next attempt Mon, 24 Aug 2026 09:41:00 GMT.
After 33 more attempt(s) this message is given up on and a delivery report is sent to alice@example.com.
```

Two attempts refused for different reasons is a fault that moved; the same
refusal repeated is one that persists. `list` carries the last reason only, so
that difference is only visible here. The closing line is the answer to how many
attempts are left and to who hears about it: a message whose sender is the empty
reverse path is itself a delivery report, and there is nobody to tell. Convert
the count to a date against the schedule in `BLAMEPOST_OUTBOUND_RETRY`, where
every attempt past the fifth is four hours after the one before it.

Take the id from `list`. An id that this server did not mint is refused rather
than turned into a path, and a well formed id with nothing behind it reports
that the message is no longer waiting, which covers delivery, a message given up
on, and a cancellation alike. `blamepost audit read --action
blamepost.mail.queue.message_removed` says whether an operator removed it.

`held` is the different question: what has stopped rather than what is waiting.
A held entry has no next attempt to sort by and no budget left to report, so it
reads in `list` as a row with nothing in the columns that matter. `held` counts
by cause instead of listing per recipient, and names the oldest, because one
fault holds every message bound for the same place and a per-recipient list
buries that. Unless this server was upgraded across a build that held mail, the
answer is:

```text
Nothing is held. Every message in the queue still has attempts left.
```

Held mail is mail set aside outside the retry budget by a hold flag this build
does not set. It keeps its place and spends no attempts, and
`blamepost queue flush` puts it back on the ordinary budget, after which it ends
like any other message.

`flush` retries everything already due. `--force` retries everything, including
entries whose next attempt is still in the future, which is what to reach for
after fixing the fault that caused the backlog rather than waiting out the
backoff.

An entry that spends every attempt in `BLAMEPOST_OUTBOUND_RETRY` is given up on,
and its sender is told. Three shapes of that end up in the same place, and the
enhanced status on the report says which one it was.

A receiver that keeps deferring runs out its budget and the report carries that
receiver's own status and the last thing it said.

An attempt that never reached a receiver at all carries RFC 3463 status `4.4.4`,
which is what an MX lookup that never completes looks like: no host answered, so
there is no reply to take a code from and the delivery path writes that one
itself.

A verdict this server made rather than a receiver carries status `4.4.7`, and an
MTA-STS record the pinned resolver could not settle is the shipped example. The
message was held here as long as this server would hold it, rather than an
address refusing it.

The last two are worth reading as a pair against the first, because neither says
anything is wrong with the recipient. The message is worth sending again once
the fault is fixed, and a `5.x.x` from a receiver would have said the opposite.

Two entries end without anybody being written to, and both are correct. A
delivery report is itself a message, and RFC 5321 §6.1 gives it an empty return
path, so one that runs out of attempts has nobody to tell. And an entry whose
message has already left the volume was settled by whoever took it, which the
paragraph on a cancellation destroyed in part covers. Both are recorded:

```bash
blamepost audit read --action blamepost.mail.delivery.spool_abandoned
```

Every row carries whether the sender was written to and, where they were not,
which of the two silences it was.

### How many delivery reports this server will generate

There is a third silence, and it is the one to know about because nothing in the
queue shows it. This server bounds how many delivery reports it generates, and a
report the bound refuses is recorded rather than sent.

A report is addressed to the sender of the message it is about. On a run of mail
to addresses that do not exist here, that sender is whoever forged it, so
emitting one report per arriving message turns this server into a backscatter
amplifier pointed at whoever the run names, in a quantity chosen by whoever is
running it. Three ceilings hold that, all of them per process and all reset by a
restart:

- **25 reports per original sender per hour.** Somebody who mistypes an address
  a few times still hears about every one of them.
- **500 reports in total per hour.** Roughly what a small server's whole
  legitimate bounce volume looks like in an hour, so reaching it means something
  other than ordinary mail is happening.
- **4096 distinct senders tracked at once.** The per-sender counters are keyed
  by an address somebody else chose, so the table holding them has a bottom.
  Past it, a sender that is not already being tracked is refused a report rather
  than admitted untracked.

The hour is measured against how long this server has been running rather than
against the clock, so correcting a wrong time or letting NTP step a drifted host
does not hand out a fresh budget.

**The third ceiling is the one that behaves in a way you would not guess.** The
first two are spent by a single abusive run and refuse further reports about
that run. The third is spent by variety rather than by volume: 4096 distinct
senders in one hour, which a backscatter flood reaches easily and a server
hosting many domains can reach on ordinary mail, and after that a legitimate
sender whose message genuinely failed gets no bounce at all. To that sender,
silence is indistinguishable from delivery, which is the worst shape a mail
failure can take.

Nothing in `queue list` or `queue show` shows this, because the report was never
queued. What records it is the audit trail and the error log, both of which name
the address that was owed a report and what it was owed one about:

```bash
blamepost audit read --action blamepost.mail.delivery.report_unsent
```

A row here means a sender was not told their mail failed. A run of them on a
server that is not under a flood means the tracking ceiling is being reached on
ordinary traffic, and a restart clears the counters.

`remove` abandons one message: the body is erased and the sender is never told,
so use it for mail you know is undeliverable. It takes a reason, which is
recorded in the audit trail, and it refuses an id that is not in the queue rather
than reporting a removal. Take the ids from `queue list`. An id that came from
somewhere else names nothing, and a run that answered "removed" for one would
leave the message on disk waiting for its next attempt.

It also refuses when the message leaves between the moment you run it and the
moment it would be erased, and this is the answer to read carefully:

```text
blamepost queue: <id> is no longer in the queue, so nothing was removed and no
row says otherwise.
```

A queued message can leave on its own at any point. A receiver takes it, or its
attempts run out and a delivery report goes to whoever it claimed to be from,
and neither tells this command. The message is past cancelling when you see
that line: it is with the receiver, and nothing here brings it back. The
attempt is still recorded, under `blamepost.mail.queue.message_removed` with a
`failure` verdict and the reason you gave, so an incident has the moment you
asked as well as what happened.

The third answer is the one to act on. When the data volume will not release
the files, nothing is canceled and the message is still queued:

```text
blamepost queue: <id> is still in the queue. This server could not take its body
off the data volume: EBUSY: resource busy or locked.
```

Nothing was destroyed and the message is intact, so the running server will
attempt it again on its own schedule and you should treat it as still going out.
Find what is holding the file open under `/var/lib/blamepost/queue/`, which is
usually a backup walking the volume, a virus scanner, or a stale bind mount.
Clear it and run the same command again: the message is still there to cancel.
This answer also carries a `failure` row, with the part that could not be
removed named in it.

The fourth answer is rarer and reads differently, because the message is already
gone:

```text
blamepost queue: <id> was destroyed in part. This server took its body off the
data volume and could not take its descriptor: EBUSY: resource busy or locked.
```

A cancellation removes three files: the message body, the descriptor that lists
it, and the small claim file an attempt writes while it is holding the entry.
The body goes first, and this server puts it back if the descriptor will not go,
so the third answer above really does leave the message intact. This one is the
case where the volume would not take the message back either. The message can
never be sent, its sender was not written to, and the entry is still listed
because the descriptor is still there. Clear whatever is holding that file open
and cancel it again to take the rest. If you do nothing, the running server
reads the entry, finds no message to send and gives up on it on its own. That
does not close the gap: an entry with no message beside it is what a
cancellation and a completed delivery both leave, so the server writes to
nobody about it rather than guessing. Telling this sender, if they need
telling, is yours to do.

A cancellation that succeeded can also report that the claim file stayed. That
one is bookkeeping rather than mail: the message is canceled, nothing reads
the file, and nothing here will clear it, so delete it by hand once the volume
lets go.

**A cancellation that reports success stops the queue, not the wire.** This
server attempts a queued message on its sweep, and an attempt reads the message
into memory before it opens a conversation with the receiver. A cancellation
landing inside that window destroys the spooled copy and reports the message
removed, which is true of the data volume: nothing here will attempt it again.
The receiver may still have been handed that copy by the attempt that was
already running, and nothing recalls a message a receiver has accepted. So treat
a cancellation on a message whose attempt was in flight as possibly delivered.

The verb does not wait for that attempt to finish, and it should not. It is what
you reach for when a credential has been taken and the mail it is sending is
going out now, and waiting behind a connection that has yet to time out would
let the rest of that mail leave while you watched. Canceling at once stops
every attempt that has not started, which on a backlog is nearly all of them.

One record tells you the race went your way:

```bash
blamepost audit read --action blamepost.mail.delivery.spool_removed_mid_attempt
```

A row there is an attempt that found its entry canceled underneath it and had
not delivered, so that message did not leave on that attempt. There is no row
for the other outcome, and there is no way to add one: an attempt the receiver
has already accepted clears the entry itself, so a canceled message and a
delivered one leave the same empty queue behind. When you need to know whether
one particular message reached somebody, ask the receiving side.

The administration queue page reports the same answers. A cancellation it could
not make is not shown as canceled, no delivery report goes to the sender, and
the server log names what the volume refused. Reload the page: anything still
listed was not canceled, except after the fourth answer, which is the one case
where a listed entry is a message that has already been destroyed. The page says
so rather than sending you to the listing.

Things worth knowing:

- **A message in the queue is a message with a verdict behind it.** Every
  recipient here was attempted, and the reason beside it is what the last
  attempt got. A message a peer deferred keeps its place and spends one of its
  attempts; a message that runs out of them ends as a permanent failure with a
  delivery report to whoever sent it. Nothing sits outside the budget, so a
  queue that is not draining is a receiver or a network rather than a hold.
  `blamepost doctor` answers the prior question under `outbound delivery`, which
  is whether a message can leave this server at all.
- **Delivery reports are rate bounded, and the bound is a spam control.** A
  report is addressed to whoever the failed message claimed to be from, so on a
  run of mail forging a third party's address, an unbounded reporter is a way to
  make this server send that third party mail on the attacker's behalf. This
  server generates at most 25 reports for any one claimed sender in an hour and
  at most 500 in total, and reports may occupy no more than a tenth of the
  queue, so a run of undeliverable mail cannot spend the room your own account
  holders need to send. A report the bound refuses is recorded rather than
  dropped: `blamepost.mail.delivery.report_unsent` names who was owed one and
  about what, and an error line says the same. The row's `origin` says which
  act left the sender uninformed, so the four are separable without reading
  the addresses: `local-refusal` is a recipient that resolves to no mailbox
  here, `gave-up` is an entry whose retry budget ran out, and `cancelled` is a
  message an operator stopped. Reaching either number means something other
  than ordinary mail is happening, and the addresses in those rows are where to
  start looking.
- **The queue has a bottom, and reaching it refuses new mail rather than losing
  it.** It shares one volume with the mailboxes, the message bodies and the audit
  trail, so it cannot grow without a bound. Past either ceiling a submission is
  answered with a temporary code and the message stays in the sender's outbox,
  and an arriving message is answered the same way and stays with the peer that
  sent it. Mail arriving for forwarding stops short of the ceiling, so a flood
  through an alias cannot spend the room your own accounts need to send: on the
  shipped ceilings that is eight thousand of the ten thousand entries.
  `blamepost queue list` prints how full it is, `blamepost doctor` reports it
  under `outbound queue`, and `blamepost queue held` says what is waiting and
  what would release it. Raise it with `BLAMEPOST_OUTBOUND_SPOOL` if the volume
  has room; clear what is never going to leave with `blamepost queue remove`.
  How deep the queue runs for a given failure rate is set by the give-up time,
  because an entry holds its slot until it is delivered or given up on: at the
  shipped five days, a sustained eighty or so recipients an hour that never
  become deliverable is what fills ten thousand slots. Shortening
  `BLAMEPOST_OUTBOUND_RETRY` shortens the queue in the same proportion, and it
  does so by telling senders their mail failed sooner.
- **That refusal lands before any of the message is delivered.** Room for
  everything a message will need is taken when its recipients are known and
  before the first copy is filed, so a temporary code on a full queue means
  nothing arrived anywhere: not in a mailbox on this server, not in the queue.
  The sender still holds the whole message and resending it delivers one copy
  rather than a second one to whoever already had it. The room is held until the
  message is finished with, so a message being delivered right now counts
  against the ceiling even though its entries are not on disk yet. That is why a
  server near its ceiling can refuse while `blamepost queue list` still shows a
  slot free: the slot is spoken for. It comes back within the second either way,
  when the message that took it finishes.
- **A queue growing against one destination** is that receiver deferring you,
  not a local fault. Read their response. Most large receivers put a
  documentation URL in the text. Do not retry it by hand in a loop; that makes it
  worse.
- **A queue growing across all destinations** is local: DNS resolution, outbound
  25 blocked, or a certificate the server cannot load.
- **An MTA-STS failure is a refusal to downgrade, and it is correct.** If a
  destination's policy says enforce and its certificate does not match, the
  delivery fails rather than falling back to plaintext. The fix belongs to them.
- **A sudden outbound spike from one account** is an incident, not growth. See
  Incident response.

### When the queue stops moving

A queue that is filling and not draining reads from outside exactly like a
healthy server. The listeners are bound, the store is open, the certificate is
fresh, and mail is not leaving. Both probes carry a `queue` check so a
monitoring system finds that without anyone running a command.

The check reduces the verdict from `ok` to `degraded` on three readings, and
each one is a way for mail to stop rather than a way for it to be slow. The
answer names which one fired:

- `queue depth`, or `queue bytes` for the byte ceiling, means the queue has
  filled past the point where it stops accepting mail for forwarding. That is
  not a warning level chosen for the probe. It is the reservation the queue
  already applies, so reaching it means this server has begun refusing mail
  through an alias, and your own account holders are the next to be refused.
- `queue drain` means mail is waiting and the sweep that retries it is not
  running.
- `outbound transport` means this build cannot put a message on the wire at all,
  so nothing that reaches the queue will ever leave it.

Over the loopback interface, which is where the container's own probe runs, the
answer also carries how much is waiting, the depth at which forwarding stops,
and how many messages the queue has refused since the server started.

**Alert on `degraded`.** Neither probe refuses on any of the three, so a policy
that alerts on failure alone will never see this. Refusing would not help
either. A liveness failure asks a runtime to restart the process, and a restart
does not drain a queue: the queue is files on the data volume, every entry is
read back on the next boot exactly as it was written, and the attempts that were
in flight are lost and repeated. A readiness failure moves traffic away from the
HTTP port, which is not the port that fills the queue, since mail keeps arriving
on 25, 587 and 465 whatever a proxy decides about 8080. What withdrawing that
port does reach is the administration console, which is where you would read the
queue and cancel what is never going to leave.

**What the check does not catch.** A queue that is stuck but small stays `ok`.
Three messages to one dead receiver, on a server whose ceiling is ten thousand,
is below every reading above, and it is indistinguishable from three messages
being retried normally, which is far more common and is not a fault. So the
check answers whether the queue as a whole has stopped, not whether one
destination has. Use `blamepost queue list` for that question: it prints what
the far side actually said, and the difference between one destination deferring
you and every destination doing so is the first two entries in the list above.
For one stuck message rather than one stuck destination, `blamepost queue show
<id>` is the better answer: it prints every attempt made on that message with
what the receiver said each time, so a fault that moved between attempts reads
differently from one that has persisted, and it says how many attempts are left
before the sender is told.

The check says nothing about how long anything has been waiting either, and that
is deliberate. A message legitimately retries for days before it is given up on,
so age on its own is not a fault, and a probe that treated it as one would be a
probe you learned to ignore.

## Reports about your own mail

This server composes delivery status notifications for mail it could not hand
over, and it reads the ones that arrive about mail it sent. That second half
matters for a specific reason. Mail addressed to an account bounces back to the
account holder, who reads it. Mail this server sends on its own behalf has
nowhere to bounce to that a person checks: the TLS-RPT reports it owes the
domains it delivers to carry a return path of `BLAMEPOST_POSTMASTER`, and a
report saying one of them failed is the only signal that a reporting endpoint or
that address has broken.

**Point `BLAMEPOST_POSTMASTER` at a real mailbox on a domain you host.** The
shipped default is built from the MX hostname, and the MX hostname is usually
not itself a hosted domain, so mail addressed there is refused at RCPT like any
other stranger's recipient. The reports never arrive to be read. One line of
configuration fixes it and nothing else will tell you it is wrong.

**Nothing acts on a report, and that is deliberate rather than unfinished.**
Anyone can compose a well-formed delivery status notification and send it to
your postmaster address claiming any message failed. Acting on one means
trusting a document a stranger wrote about mail you sent, and this server keeps
nothing that could prove the link: it issues no envelope identifier on the way
out, and a message a peer accepted and bounced afterwards left the outbound
queue at the moment it was accepted, so exactly the messages a report is about
are the ones with no record left to match. So a report is read, recorded and
counted, and no message, queue entry or delivery state moves because of it.
Read the counts as a signal to go and look, not as a verdict.

A report that is not readable is recorded as unreadable rather than guessed at:
one that is not a delivery status notification at all, one whose structure the
parser refuses, one missing the fields the standard makes mandatory, and one
whose recipients carry an action token the standard does not define. Each is
counted under its own reason, and mail addressed to the postmaster that is
simply ordinary mail is not treated as a failed report.

## Deleting an account

Deletion archives by default. The mailbox, its audit history and its keys are
sealed in place, reachable only through an audited administrative path.

```bash
blamepost account remove alice@example.com --reason "left the company 2026-08-22"
```

This is what an operator almost always wants: it satisfies "the account is gone"
while surviving the discovery, two weeks later, that something in it was needed.

**Erasure is separate, explicit, and irreversible.** For a right-to-erasure
request under GDPR Article 17, or an equivalent obligation, `--destroy` erases
the account row and everything the account holds on this volume: the aliases
pointing at it, its mailboxes, its messages, its filter scripts, its
annotations, and the sealed message bodies under `blobs/`. Sealed columns are
nulled and the index pages that held them are rebuilt as each row goes, so the
ciphertext is not left in the database file for a later read to recover.

```bash
blamepost account remove alice@example.com \
  --destroy \
  --reason "Art. 17 erasure request received 2026-08-22, ref FOO-1234"
```

Both flags are required. The reason is recorded in the audit chain, which is what
lets you demonstrate later that the erasure happened, when, and on whose
instruction. The record of the destruction survives the data it destroyed.

**Read what the command prints, because an erasure is often partial.** It runs
through the same delete path IMAP `EXPUNGE` takes, so two things still keep mail
back, one message at a time:

- A **preservation order**, placed with `blamepost account hold` and described
  under "Preservation orders" below. A court's order to keep a record outranks a
  request to destroy it, which GDPR Article 17(3)(e) says in as many words.
- The **retention floor**, when `BLAMEPOST_COMPLIANCE_POSTURE` is set to `soc2`.
  A message younger than the window that posture names stays until it is old
  enough to go.

Mail is not the only thing that can stay. The account's mailbox rows, its filter
scripts and its annotations are erased row by row, and a governance gate wanting
a second approver can hold any one of them back the same way. Every one of those
refusals is printed and none of them stops the run: the mail is already destroyed
by the time they are reached, so a refusal that ended the command would leave you
with no record of what had gone. Lines beginning `kept` are held back on purpose
and lines beginning `FAIL` are not.

The audit row counts the two kinds apart. `mailPreserved` and `mailFailed` count
messages; `recordsPreserved` and `recordsFailed` count the mailbox rows, filter
scripts and annotations that stayed. An answer to an Article 17 request or a
preservation order is built on the first pair, so a filter script a gate is
holding does not inflate the number of the subject's messages that survived.

The account row is the last thing the erasure writes, and it is answered for on
the same terms. A gate can refuse the erase of the account row itself, which
leaves the account exactly where a kept filter script leaves it: out of service,
listed as `erasing`, and reachable by the same command later. A volume that
refuses the write that puts it out of service is the sharper case and prints
`FAIL`: the mail is gone and the mailbox is still authenticating and still
taking delivery, so suspend it with `blamepost account suspend` and run the
erasure again.

Each record that stayed is printed by name, with the mailbox it is in where it
has one, and the reason it stayed. A mailbox holding a record that stayed keeps
its row, whether that record is a message the delete path would not destroy or
an annotation the erase would not take, and so does the account: a record you are
required to produce is reachable only through the identity that owns it, so an
erasure that kept anything back keeps the account too. That is also why the
report can still name the mailbox an annotation was set on when you run the
command again. Release the order, or wait out the window, then run the same
command again to erase what was held back:

```
Partly erased alice@example.com, and its account was kept.
  1 message destroyed across 5 mailboxes, 0 aliases erased.
  kept  message obj_f313c8391a521b3b8c12af988195a7b4 in INBOX: legal-hold. It is preserved on purpose and still resolves to this account.
  Release the order or obtain the grant, then run the same command again to erase what was held back.
1 mailbox still holds a record this erasure could not destroy, so its row was kept and that record stays addressable.
The account row was kept too, because it is what the mail above is addressable through. It cannot sign in, takes no delivery and cannot be resumed; `blamepost account list` shows it as erasing until this finishes.
```

The kept account is out of service from the moment the erasure runs. It refuses
every credential, takes no delivery, and `blamepost account resume` refuses it,
because the mail it held is already destroyed and nothing brings that back. It
shows in `blamepost account list` as `erasing` so an unfinished erasure is
visible without being looked for, and the row goes on the run that finally
reaches the last of its mail. The first line names which of the two happened:
`Erased` when the account went, `Partly erased` when it did not.

The exit status stays 0 for anything kept on purpose, because that is the system
working. It is 1 when something could not be erased for any other reason, so a
script driving a bulk erasure stops on the account that needs a person rather
than recording every one of them as done.

A `FAIL` line for a message is not always mail still sitting on the volume, and
the report says which it is rather than leaving you to read it off the reason.
When the volume would not remove the row binding a message to a mailbox, a rerun
destroys the message and keeps the row, as described under "A delete the volume
would not finish". After that the erasure still reports the row it could not
remove, and it says the rest is destroyed and its rows were kept. The mail is
gone; what stays is a record with no message content in it, and `blobs report
--verify` names the mailbox those rows are still counted against.

Both of those sentences are printed only for messages. A filter script or an
annotation that could not be erased prints its own `FAIL` line and nothing about
the volume, because neither is mail and neither leaves message content behind.

**Verify an erasure rather than assuming it.** `blamepost blobs report --verify`
unseals every referenced message body and hashes it back against the digest
naming it, and it lists mail no account holds, which is mail on the volume that
nothing can reach. A volume reporting nothing under that heading is holding no
mail belonging to an account that is gone. Mail an order or the floor is keeping
does not appear there and should not: its account is still on the table holding
it, which is the whole reason the account was kept.

## Preservation orders

A preservation order stops a message being destroyed, on every protocol, until
you lift it. It outranks the retention floor and it outranks a right-to-erasure
request; GDPR Article 17(3)(e) is the exception you answer such a request with.

An order is placed on named messages rather than on a mailbox, so mail arriving
after the order is not silently swept into it, and it carries no expiry date:
nothing here sweeps one, so a date recorded against an order would read as an end
this server never acts on. It ends when you lift it.

**An order covers the messages it names and nothing else the account holds.**
The register is keyed on the exact record an order was placed against, and
`blamepost account hold` places one against a message, so an order over an
account's mail does not extend to that account's filter scripts, its annotations
or its aliases. An erasure of the account will destroy all three while the order
over its messages is still in force, and each of those messages will still be
kept. The account row is kept too, because a message the order covers is
addressable only through it, so the erasure reports itself as partial and leaves
the account out of service. This is the boundary to hold an order against before
you rely on it: if what a matter requires you to preserve is the fact that an
address existed or the rules it filtered on, an order over its mail does not
preserve either, and the answer is to not run the erasure until the matter
closes. `blamepost account holds <address>` lists what is actually covered, one
line per message, which is also how you find out that an order you believe is in
place is not.

**Find the records first.** An order arrives naming a matter and a date range,
not object ids, so `blamepost account messages` lists what an account holds: one
line per message with its id, two dates, the sender, the subject, and `HELD`
against anything already under an order. It never prints a body. Reading
somebody's mail list is recorded, so it takes a `--reason` the way
`blamepost account sieve` does, and `--mailbox` narrows it to one mailbox.

**The two dates are not interchangeable.** `arrived` is the clock reading this
server took when it filed the message. `client` is `INTERNALDATE`, which RFC 9051
section 6.3.12 lets an IMAP client set when it uploads a message, so it is a value
the account holder's software chose and a message can be made to show any date.
Match a court's date range against `arrived`: it is the date this server can stand
behind, and it is the one the retention floor is measured against. `client` is
what the account holder sees in their own client, so it is the column to reach for
when matching a record to a message somebody has described.

```bash
blamepost account messages alice@example.com \
  --reason "identifying the records preservation order 24-cv-01933 covers"
```

```bash
blamepost account hold alice@example.com --mailbox INBOX \
  --message obj_f313c8391a521b3b8c12af988195a7b4 \
  --reason "preservation order 24-cv-01933" \
  --citation FRCP-26 --custodian records@example.com
```

`--message` takes one id, a comma-separated list, or the flag repeated.
`--citation` and `--custodian` are optional and are what a regulator asks for
later: the matter the order is under, and who is answerable for the records.

**Read the order back rather than trusting the command that placed it.**
`blamepost account holds <address>` lists every message currently under an order
with the reason, citation, custodian and who placed it, across every mailbox or
one named with `--mailbox`. It is also how you find out that an order you believe
is in place is not.

Placing an order on a message the account does not hold is refused by name and
exits 1, rather than reporting a duty that was never taken on.

```bash
blamepost account release alice@example.com --mailbox INBOX \
  --message obj_f313c8391a521b3b8c12af988195a7b4 \
  --reason "matter closed" --approver records@example.com --confirm
```

Lifting is the half that ends a duty, so it takes `--confirm` and an
`--approver`: the next expunge, POP3 commit, JMAP destroy or account erasure on
those messages will destroy them, and the name of whoever decided the duty had
ended is what the audit row carries. Placing and lifting both write hash-chained
rows, `legalhold.placed` and `legalhold.released`, which `blamepost audit read`
returns.

**What erasure does not reach: copies made before it ran.** Message bodies are
sealed under this volume's vault key rather than under anything the erasure
destroys, so a backup or a snapshot taken earlier still opens with the same key
and still holds the mail. Erasure is a property of this volume from the moment
it runs. Carrying it into your backup history is a retention policy on the
backups themselves, and that policy is yours rather than this server's: plan the
expiry of your backups against the erasure requests you expect to answer. On
this volume recovery is not possible, not from a snapshot taken afterwards and
not from support, and that is the property the mechanism exists to provide.

**What erasure does not reach: mail the account already sent that is still
waiting to go out.** The outbound spool holds a message by its envelope and its
own identifier rather than by the account that submitted it, so a message
queued for a retry survives the erasure and is still delivered or still bounced.
That is usually what you want, since the message has left the mailbox and is in
transit. When it is not, `blamepost queue list` shows what is waiting and
`blamepost queue remove` takes an entry out, and both are worth running before
the erasure rather than after.

## The audit trail

Every administrative action that changes something writes a row: what changed,
when, the outcome, and the reason where the verb takes one. The rows are hash
chained, so each one carries the hash of the one before it, and signed
checkpoints anchor the chain: one when the volume is opened, one an hour while
the server runs, and one on the way out when it is stopped.

**An administrative row names who ran the command.** A command run at a terminal
records the operating-system account the process ran as and the host it ran on,
written as `cli:<user>@<host>`, with the binary and its version beside it and the
process id as the session. A shell user is not an account here, so the identity
carries that `cli:` mark and a filter on the column can tell the two apart. An
action taken in the admin interface records the account that was signed in, with
the address it came from and the agent string it sent.

**A command-line row carries no source address, and that is a decision.** A
command run at a terminal arrived from nowhere, and a value read out of the
environment of the shell that ran it would be a value that shell chose, so the
column is left empty rather than filled with something that reads like a fact.
Read the host in the identity instead.

**A trail that cannot be written loses the row, not the change.** The row is
written after the change it describes has already landed, so a trail that is
unavailable cannot undo that change and does not try. The verb reports its own
outcome and the row is dropped. This matters if you point the trail at storage
that can fail on its own, separately from the data volume: a gap is then
possible while every change it should have recorded stands, so alert on the gap
rather than reading an unbroken chain as proof that nothing is missing. Nothing
is buffered to make this work, so a trail that is available loses nothing: the
row reaches durable storage before the verb returns. Hard deletion is recorded
by a path of its own that this does not affect, which is what keeps an erasure
provable to somebody asking for the evidence.

**Delivery and the wire rows are different, and correctly so.** A message
arriving from a stranger has a peer rather than a principal, and a refused
sign-in names only the peer: at that moment the address it claimed is a claim,
and writing it into the column that answers who acted would let whoever is
guessing choose the name you read back. Two rows deliberately name somebody other
than an operator for the same reason. An account proving its own credential names
that account, and a refused attempt names the peer alone. So read the actor on
administrative rows and the peer on the others, and do not expect either column
to answer for the other.

The `--reason` every destructive verb requires still carries what the identity
cannot, which is why it is worth writing as though somebody will read it.

**An account turned away from the administration surface leaves a row.** A
signed-in mailbox owner that asks for an administration page or posts an
administration form is refused, and the refusal is recorded as
`blamepost.web.console_not_permitted` with the account in the actor column and
the method and path it asked for in the metadata. A caller carrying no session
at all is a different row, `auth.required.denied`, so an account that signed in
and then went looking reads differently from a stranger that never got that far.

**Canceling a queued message is recorded whichever surface canceled it.** The
administration queue page and `blamepost queue remove` both file
`blamepost.mail.queue.message_removed`, naming the message, the recipient it was
for and the reason given. There is no cancellation without a reason on either
surface, and no default stands in for one: the cancellation itself refuses
without it, so the page keeps asking until you type one and the command line
refuses without `--reason`.

Who is told differs by surface, and every row says which happened in the same
two fields: `reported` is whether the sender was written to, and `withheld`
names why not. `blamepost queue remove` writes to nobody and records
`operator-withheld-notice`: it is the verb the incident runbook reaches for on
mail a stolen credential sent, where the sender is whoever sent it, and if that
sender does need to hear from you, send them a message yourself. The console
writes to the sender when the return path is in a domain this server hosts, and
records `sender-not-hosted` when it is not, because a message arriving through
a forwarding alias carries a return path a stranger chose and reporting to it
turns a button in your console into mail aimed at somebody who never wrote to
you. Either way the reason you typed is never sent: it is recorded here and
nowhere else.

A report that does go carries the canceled message's own headers, which is how
its sender tells it from the other messages they sent to that address. It
carries nothing else of the message.

A message that leaves the queue while a cancellation is working through your
selection files a row under the same action with outcome `failure`, saying the
message was not erased and its sender was not written to. Read the outcome
column before you conclude a message was stopped:
`blamepost audit read --action blamepost.mail.queue.message_removed --outcome failure`.

Read the trail:

```bash
blamepost audit read --limit 100
blamepost audit read --action account.suspended
blamepost audit read --action blamepost.web.console_not_permitted
blamepost audit read --action blamepost.mail.queue.message_removed
blamepost audit read --outcome denied --from 2026-08-01T00:00:00Z
```

`--outcome` takes `success`, `failure` or `denied`, and a word it does not
recognize is refused rather than answered with an empty list. An empty list is
what a quiet week looks like, so the two must not be confusable. Reading the
trail is itself recorded, which is the point: an unexplained administrative read
is exactly what an audit log exists to surface.

That is also why `audit read` is one of the verbs that needs the server stopped
rather than answering from a copy of the volume. The row saying you read the
trail would be written into the copy and thrown away with it, and a read that
claims to be recorded and is not is worse than one that refuses. The admin
console shows the same rows without stopping anything, and records the read the
same way.

Prove it has not been edited:

```bash
blamepost audit verify-chain
```

This answers three questions and reports them on their own lines. The chain math
confirms that no row has been inserted, altered or removed. The signed
checkpoints confirm that the chain itself is the one this server wrote, which the
chain math alone cannot: every row hash is computed from readable columns, so
somebody holding the database file can rewrite the whole sequence and leave it
agreeing with itself. The third is a record this server keeps beside the database
rather than in it, naming the counter and the hash of the row the chain last
ended at, and it is what catches the move the other two do not: rewrite every row
so the sequence agrees with itself, then delete the checkpoints instead of trying
to forge one, and the next command to open the volume signs a fresh one over the
rewritten tip. Nothing left inside the database disagrees with anything else in
it. The record outside it still does.

**Where that stops, and it is not a detail.** The key signing the checkpoints is
sealed under `BLAMEPOST_VAULT_PASSPHRASE`, the same secret that decrypts the
database and the mail, and the record beside the volume is a plain file on that
volume. So the guarantee is "no row was inserted, altered or removed by anyone
who did not hold the vault passphrase", and the command says it in those words.
Somebody who holds it can rewrite the rows, sign the result and rewrite the
record, and no reading this server can make will disagree. If you need a trail
that answers for the passphrase-holder too, ship the rows as they are written to
a sink on another host; nothing this volume carries can substitute for a copy
kept where this server cannot reach it.

**A reading that could not be made is not a reading that passed.** A volume whose
record beside the database is missing, which is either a first-ever run or a file
somebody removed, reports `note not held against anything outside the database`
and does not print the line about nothing having been altered. On a volume that has been
opened before, that note is itself the finding: the record is written again every
time the volume is anchored, so its absence means something removed it.

**A gap where the record points is reported as a gap, not as a retention run.**
The record beside the database can name a counter that has no row behind it, and
there is one legitimate reason for that: an archive and purge deleted the range.
Where the deletion stopped is written into a table inside the database. That
table is worth less than every other reading here. It carries no signature, is
linked into no chain, is covered by no checkpoint and has no append-only trigger
over it, so writing one row into it costs write access to the database and
nothing else, while rewriting the rows or forging a checkpoint costs the vault
passphrase. One row there discards every audit row at or below the counter it
names from the walk.

So the command reports the gap as `note a gap this run did not read, trusted on
an unsigned counter`, names the counter, and does not print the line about
nothing having been inserted, altered or removed. It cannot: those rows were
never read. It also does not tell you an archive was verified, because nothing
here verifies one. The identifier the record carries names the signed checkpoint
the archive was made against rather than a location, and the archive bundle is a
directory you were told to keep where this server cannot reach it. What the
command can say is whether that checkpoint is still on the volume at or above the
purged range, and it says which. That is worth something narrow: a rewrite that
deleted rows and relinked the survivors changes every surviving row hash and has
to delete the checkpoints over them, so one still standing means the rows that
remain were not relinked. It means nothing about the rows that are gone.

**What to do about that note.** Find the archive bundle covering the range and
read it back:

```bash
blamepost audit verify-bundle --in <bundle-dir> --passphrase-file <path>
```

Hold the counters it reports against the counter in the note. If they cover the
range, the gap is an ordinary retention run and you are done. If no bundle covers
it, those rows were removed rather than archived, and you are reading the result
of a deletion that was dressed as a purge. Take a copy of the data directory
before anything else.

The note survives being read, which is the part that matters during an incident.
Any command that opens the volume anchors the chain again over a row that is
still there, so the comparison that found the gap cannot make itself a second
time. The finding is therefore written to `audit.disputed` on the volume and
every later run reports it from that file. The volume keeps running either way:
this is a range nothing established in either direction, and refusing to deliver
mail over it would be the wrong trade. Remove the file once you have accounted
for the range.

Opening the volume anchors the current tip, so any command that takes the volume
leaves the chain signed up to the moment it ran. A running server anchors it
again once an hour, and the stop anchors it a last time: `blamepost serve`
flushes and anchors the trail before it closes the store, so a cleanly stopped
volume is anchored at its newest row.

**What a server that is killed leaves behind is the last hour, and no more.** An
out of memory kill, a host reboot, a container killed rather than signaled and a
power loss all end the process without running a stop, so the rows written since
the most recent hourly anchor are covered by the chain and the checkpoints alone,
which is the half a rewrite of every row can be made to agree with. Everything
before that anchor is held against the record beside the volume as well. The
hourly cadence is not settable: a shorter one signs more often, and every
signature it leaves is about fifty kilobytes on the volume for good and another
few milliseconds on every later `verify-chain`, so a year of a short interval
costs tens of gigabytes and a verification measured in hours. An hour keeps that
year inside half a gigabyte. An hour in which nothing was written costs nothing
at all, because there is no new tip to sign.

**This is the verb that has to have the volume, and the reason is the second
question.** The reporting verbs that answer while the server runs read a private
copy, opened deliberately without signing a fresh checkpoint over it, because
anchoring from a copy would advance the record beside the volume past a point the
volume never reached. So nothing on that path verifies the signatures over the
checkpoints already on disk. The chain math still runs there and a break still
refuses; what only a stopped volume can establish is that the chain is the one
this server signed.

A verdict of `FAIL` names the row it stopped at and the two hashes that
disagree. Do not restart the server in a loop. Take a copy of the data directory
first: the state at the moment of the failure is the evidence.

**A finding against the record beside the volume is written down, and the volume
stays shut until you clear it.** That refusal is the one that cannot repeat
itself on its own: opening the volume anchors the chain again, which replaces the
record that disagreed, so the comparison that found it cannot be made a second
time. Running the command again to be sure would have reported the volume intact.
So the finding is recorded in `audit.disputed` in the data directory, and every
later open reads it and refuses under the same code rather than appending to a
trail nobody can stand behind. Take your copy, restore from a backup written
before the rewrite, and remove that file only when you are finished with it.
Removing it on its own leaves the rewritten trail in place and stops anything
reporting it.

Hand a range to an auditor:

```bash
blamepost audit export \
  --from 2026-01-01T00:00:00Z \
  --to   2026-03-31T23:59:59Z \
  --out  /srv/evidence/2026-q1 \
  --passphrase-file /etc/blamepost/bundle.pass
```

The bundle is a directory holding an encrypted copy of the rows and a manifest.
The chain math in it stands on its own, so an auditor can check the range links
together without this server. An exported range carries no anchor, so that is as
far as it goes on its own: proving it is the range this server signed needs the
covering checkpoint, which an archive bundle carries and an export does not.
`verify-bundle` says which of the two it read and whether the signature was
checked.

```bash
blamepost audit verify-bundle \
  --in /srv/evidence/2026-q1 \
  --passphrase-file /etc/blamepost/bundle.pass
```

Filtering an export by `--action` is refused when the filter would skip rows in
the middle of the range. A slice with a hole in it cannot be proven, and a
bundle that cannot be proven is worth nothing to the person it was made for.

Shorten the live table only after the archive is verified:

```bash
blamepost audit archive \
  --before 2026-01-01T00:00:00Z \
  --out    /srv/archive/pre-2026 \
  --passphrase-file /etc/blamepost/bundle.pass

blamepost audit verify-bundle --in /srv/archive/pre-2026 \
  --passphrase-file /etc/blamepost/bundle.pass

blamepost audit purge --archive /srv/archive/pre-2026 \
  --confirm --reason "quarterly retention run" \
  --passphrase-file /etc/blamepost/bundle.pass
```

An archive holds the rows without deleting anything. The purge is the delete, it
takes an explicit confirmation and a recorded reason, and it refuses any bundle
that does not verify.

**A purge always leaves a row behind, and a purge that would not is refused.**
The next event attaches to the last row, and the check this server runs at start
compares its recorded counter against the highest one in the table. Take the
last row and there is nothing to attach to and nothing to compare against, and
the server never starts again. So `--before` has to name a cut with activity
after it. Archiving with a cut in the future produces a valid evidence bundle
and says plainly that it cannot be purged.

## Backup and restore

Backups are encrypted bundles rather than copies of the directory. Each file is
sealed separately, the manifest is signed, and the whole thing can be checked
without being restored.

```bash
# Stop first. A copy taken while the database is being written is not a backup.
docker stop blamepost

blamepost backup run \
  --storage /srv/backups \
  --passphrase-file /etc/blamepost/bundle.pass \
  --keep 14

docker start blamepost
```

The passphrase comes from a file rather than a flag, because a secret on a
command line is in the shell history and in the process list. Make one that is
long, keep it at mode `0600`, and keep a copy somewhere the machine's loss does
not reach:

```bash
head -c 32 /dev/urandom | base64 > /etc/blamepost/bundle.pass
chmod 600 /etc/blamepost/bundle.pass
```

**It cannot be the vault passphrase, and the server refuses to use it if it is.**
A bundle travels off this machine and the vault passphrase does not. One secret
opening both means a bundle that leaks takes the live volume with it.

What is in a bundle: the encrypted database and its sealed key, the vault key,
the audit signing key, the sealed message bodies, the DKIM private keys, the
outbound spool, the certificates, and every other file on the data volume. The
list is the volume itself rather than a set of names somebody remembered, because
a file left out of a backup is data that does not come back and the way that
shows up is not an error.

See what is there and check one without restoring it:

```bash
blamepost backup list --storage /srv/backups
blamepost backup inspect --storage /srv/backups --bundle 2026-08-24T09-00-00-000Z-a8f30b21
blamepost backup verify  --storage /srv/backups --bundle 2026-08-24T09-00-00-000Z-a8f30b21 \
  --passphrase-file /etc/blamepost/bundle.pass
```

`inspect` needs no passphrase, so choosing which bundle to restore does not mean
unlocking every candidate. `verify` decrypts every file and checks it against the
manifest, writing nothing to the data volume. Neither opens the database, so both
still answer on a server whose data volume will not open. That is the day they
matter.

`inspect` and `verify` both report the key that signed the manifest. The
signature proves the bundle has not been modified since it was written. It does
not on its own prove who wrote it, because the key travels with the bundle. Pass
`--fingerprint` with the value you recorded when the bundle was made and any
other key is refused.

### Restoring

```bash
docker stop blamepost

blamepost restore apply \
  --storage /srv/backups \
  --bundle  2026-08-24T09-00-00-000Z-a8f30b21 \
  --passphrase-file /etc/blamepost/bundle.pass \
  --confirm --reason "recovering from the disk failure on 2026-08-24"

blamepost blobs report --verify
blamepost doctor

docker start blamepost
```

**Run both checks with the server still stopped, before you start it.** That
order is not a preference. `blobs report --verify` opens every message body and
re-hashes it, which is the check that would find a body the bundle carried
damaged. Both verbs will answer against a started server too, but off a
read-only open whose rows stop at the server's last write to disk, so a message
delivered since reads as one the rows had not reached and is not counted either
way. On a volume nothing is writing to there is no such gap, which is the whole
reason to ask before the start rather than after it. Start the server once both
have answered.

The restore puts the data directory that was there aside as a rollback point,
moves the bundle in, then opens the result and verifies its audit chain before it
reports success. If the restored directory does not open, the rollback point goes
back automatically and the command says why. That is what a rollback path is
for: a bundle that turns out to be unusable must not cost you the volume you
still had.

**A trail that cannot be written does not undo the restore.** Whether the
restored volume opened and whether the row describing the restore could be
written are two questions, and only the first decides whether the restore
stands. If the act succeeded and the row could not be filed, both `restore
apply` and `restore rollback` print one line on standard error saying so and
still exit `0`. That line matters more here than anywhere else on the command
line: the volume you just replaced is the one that would have held the row, so
nothing else on the machine records the fact. If you script these verbs on the
exit code, know that the line exists and read it. An operator restoring after an
outage is exactly the person whose audit sink is most likely to be unavailable,
and losing the restore to that would be the worst possible moment for it.

```bash
blamepost restore list-rollbacks
blamepost restore rollback --confirm --reason "the restored volume was the wrong day"
```

Five things to get right:

1. **Restore into the same data directory path.** The database key is sealed to
   the absolute path of the directory it belongs to, so a bundle taken from
   `/var/lib/blamepost` produces a volume that will not open anywhere else. The
   restore reads the path out of the bundle and refuses a mismatch before it
   moves anything, so this costs a clear message rather than a broken volume. To
   rehearse a restore, use a scratch machine or container with the same path.
2. **The vault passphrase is not in the bundle, and the bundle is useless without
   both it and the bundle passphrase.** Store them separately, offline, somewhere
   that survives the loss of the machine and the loss of you. This is the single
   most common way a correctly backed up mail server becomes unrecoverable.
3. **Rehearse the restore on a schedule.** A bundle nobody has restored is a
   hypothesis. `blamepost backup verify` proves the bytes come back; a rehearsal
   proves the server does. Leave `BLAMEPOST_DNS_ACKNOWLEDGED` unset on the
   rehearsal so the MX listener stays closed and it cannot start taking real
   mail.
4. **A restore rewinds DKIM state.** If the bundle predates a rotation, the
   server signs with the old selectors while DNS advertises the new ones. Run
   `blamepost doctor` immediately after any restore, with the server still
   stopped; it catches exactly this. Run `blamepost blobs report --verify`
   beside it, for the reason under the recipe above: it is the check that opens
   the bodies, and it cannot run once the server holds the volume.
5. **Prune deliberately.** `--keep` on `run` sweeps after a successful bundle.
   Dropping older bundles without taking a new one is its own verb, and it takes
   the same confirmation and recorded reason every destructive verb here does:

   ```bash
   blamepost backup purge --storage /srv/backups --keep 7 \
     --confirm --reason "quarterly storage review" \
     --passphrase-file /etc/blamepost/bundle.pass
   ```

**Upgrading** follows the same order: back up, pull the new image by digest, start
it, run `blamepost doctor`. Schema migrations run at boot and are one-way, which
is why the backup comes first rather than after.

## Incident response

### A credential has been stuffed

Signs: outbound volume from one account jumping, authentication failures
clustering, complaints, or a receiver suddenly deferring everything.

```bash
blamepost queue list --account alice@example.com   # works while the server runs
blamepost account show alice@example.com           # answers too, off a copy

docker stop blamepost                              # this is the containment step
blamepost account suspend alice@example.com --reason "outbound spike 2026-08-22"
blamepost queue remove    <id> --reason "outbound spike 2026-08-22"
blamepost account passwd  alice@example.com
docker start blamepost

blamepost account resume  alice@example.com        # later, with the server stopped again
```

**Stop the server first, and treat that as the containment rather than as an
interruption.** Every verb that changes an account needs the data directory, and
one process holds it at a time, so these refuse against a running server (see
"One process at a time"). That ordering is the right one anyway: stopping the
process closes the submission listener immediately, which is what actually stops
the credential sending, whereas a suspension written while the server runs would
not reach the process that is authenticating it.

`queue list` reads the outbound spool rather than the database, so run it before
you stop anything and keep the ids. `account show` answers before you stop
anything too, off a copy of the volume, and labels itself with the moment that
copy was taken. During an incident read the label: a quota or a status from a
minute ago is fine for orientation and is not the thing to confirm a containment
against.

`queue remove` abandons one message and tells the sender nothing, which is what
you want for mail a compromised account sent. Take the ids from the `queue list`
above rather than guessing: there is no verb that clears an account's queue in
one step, and an id that names nothing is refused rather than reported removed.
The reason lands in the audit trail, which is the record of what was canceled.

Suspend before you investigate. Suspension stops both directions: the account
cannot authenticate, so it cannot send, and it stops being a deliverable target,
so nothing new is filed into the mailbox. That is the trade: none of it is
destructive, but the mailbox is unreachable until you resume it. If it has to
keep receiving while you investigate, change the password instead and leave the
account active.

That is an alternative to suspending, not to stopping the server. `blamepost
account passwd` needs the data volume, and one process holds that at a time, so
it wants the server stopped exactly as suspension does. What it buys you is that
the mailbox is still a deliverable target when you start it again, so mail
arriving during the investigation lands rather than bouncing. Either way the
stolen password stops working the moment the change lands, including against a
sign in that was already under way when you made it.

Then cancel what is still queued before it lands. A message delivered is a
message you cannot recall, and every one of them carries your domain's signature.
The queue page tells you which of your selection it actually erased and which had
already gone, so treat anything it reports as gone as delivered and work from
there rather than from the list you selected.

Check what the credential could write as, not only which mailbox it reached.
Every active alias landing in that mailbox is an author the account may put in
`From`, so a credential on one ordinary mailbox may have been sending under a
departmental address as well as its own. The alias list is in the admin
interface, and removing an alias withdraws that author at the next message.

Afterwards, check the account's Sieve script. Adding a rule is standard practice
for whoever took the credential, and it survives a password change.

A Sieve rule cannot forward mail off this server. `redirect` and `vacation` are
refused wherever they appear, the message is kept rather than dropped, and the
refusal is recorded under
`blamepost.mail.sieve.action_unavailable`. What a rule can do is hide things: one
filing security notices into a folder nobody reads, or discarding them, keeps
the account holder from noticing the intrusion. Read the whole script rather
than looking only for a forwarding address.

```bash
docker stop blamepost
blamepost account sieve alice@example.com --reason "incident 4471"
blamepost account sieve alice@example.com --reason "incident 4471" --script file-invoices
docker start blamepost
```

The first lists the account's scripts and marks the one that is active, which
is the only one that runs. The second prints a script's body.

The reason is required and lands in the audit trail. Reading somebody's filter
rules is administrative access to their private configuration, and the row is
the record that it happened and why. Reaching for the account's password
instead would work and is worse: resetting it to get in tips off whoever is
watching the mailbox.

Expect the calls afterwards. A run at your accounts leaves every mailbox it
named unable to sign in, whether or not the guessing got anywhere: five wrong
passwords inside a quarter of an hour spend that mailbox's budget, and the
budget cannot tell a wrong guess from a wrong guess. So the people whose
addresses happened to be on somebody's list are locked out having done nothing,
and there will be more of them than there are compromised accounts. The next
section is how you give them their attempts back.

### A mailbox is refused everywhere and the password is right

Signs, in the order they usually reach you:

- One mailbox refused on every protocol at once, while every other mailbox on
  the same server is fine. Nothing server wide picks one account.
- The account holder's desk client still works and their phone does not, or the
  other way round. A source address a mailbox has already signed in from is
  still let in while the budget is spent, so the machine that was working keeps
  working and the one that was retrying is the one that stops.
- The refusal talks about attempts rather than about the credential. In the
  browser it says to try again later; on the mail listeners it is a plain
  authentication failure, which is deliberate, since telling a caller which of
  the two walls they hit is telling them how to plan around it.

There are three budgets, and knowing which one you are looking at is most of the
work.

The first is kept against the mailbox, from anywhere. Five wrong passwords
inside a quarter of an hour spend it. The wait that follows starts at one
minute and lengthens with each further run at the same mailbox: one minute,
five, fifteen, an hour, then six hours for every one after that. The count
decays a quarter of an hour after the last failure, so a client that stops
retrying serves out the current wait and starts clean.

The second is kept against one machine and one mailbox together, on the same
five in a quarter of an hour. It is read first, so a machine that has spent it
is refused even when the mailbox itself would be let through. This is the one
that leaves a single phone refused after you have already given the mailbox
back.

The third is not a mailbox budget at all: each listener counts authentication
failures per source address, ten in a quarter of an hour, and refuses that
address on that listener. It is held inside the listener, and nothing in this
server either releases it or reads it, so it appears nowhere in what follows.
That stays true now that the console shows live numbers beside the recorded
rows: those numbers are the two mailbox budgets and never this one. It clears
itself a quarter of an hour after the last failure from that address. A mailbox
you have released can therefore still be refused on one protocol, from one
machine, until that window passes.

Read the trail before you decide which it is:

```bash
docker stop blamepost
blamepost audit read --action auth.lockout.engaged
blamepost audit read --action account.authentication_refused
docker start blamepost
```

Both of those need the data directory, and one process holds it at a time, so
they refuse against a running server (see "One process at a time"). `audit read`
is deliberately not one of the verbs that answers off a copy, because the row
recording your read would go into the copy and be thrown away with it. That is
worth knowing before you reach for it mid call. The admin console shows the same
rows without stopping anything and records the read the same way: the Lockouts
page carries the lockouts and the releases, and the Audit page carries
everything, `account.authentication_refused` included.

`auth.lockout.engaged` is one row per budget that ran out, and it carries when
that lockout was recorded to lift. `account.authentication_refused` is one row
per refused attempt, and carries the peer it came from alongside the address it
named. Read the peer rather than the address: an attempt that was refused
proved no identity, so the address on it is a claim and the peer is a fact.

That distinction is what separates the two cases. Failures from one source
address, evenly spaced, are a client on a timer holding a password its owner has
already changed. Failures from many source addresses, one or two each, are
somebody working through a list, and the mailbox is locked out as a side effect
of that rather than as the point of it.

Then open Lockouts in the admin console. It reads two things and keeps them
apart, and telling them apart is the rest of the work.

**The table is the record.** It lists what has run out, for which mailbox, from
which machine where a machine is what it was counted against, when each ran out,
when each is recorded to lift, and how many times that budget has run out before.
Each row also carries the counter behind it, which is what is refusing a password
right now.

**The lookup below it asks the counters directly, for one mailbox.** A mailbox
reaches the table only once a budget has already run out, so the table carries
neither a mailbox partway through its attempts nor one nobody has ever touched.
Both are what somebody taking a support call is asking about. Type the address
in, add a machine to read that machine's own budget beside it, and you have an
answer for a caller who is on no list at all.

**Read the counts carefully, because this is the number most likely to mislead
you.** A count of wrong passwords is an early warning and nothing more, and it
means something only below the threshold: the failure that spends a budget resets
the count. So a budget that is holding somebody out reads zero, and so does a
mailbox nobody has ever guessed at. That is why no count is shown beside a held
budget. What is worth reading for one of those is the Times column, how many
times that budget has run out, which is also what sets how long each wait is.

**Recorded and live can disagree, and the disagreement is information rather than
a defect.** The rows are on disk and survive a restart; the counters are in the
running process and do not. So a lockout recorded before a restart is standing
over a budget that is already free, and the row says so where that has happened.
The opposite is marked too: a row whose window has passed, sitting beside a
budget held under a more recent lockout than the one that row describes.

**A caller who cannot reach the form at all has hit a different bound.** Fifty
posts to the sign-in form in any five-minute slot from one source address are
accepted, and past that the form answers `429 Too Many Requests` until the slot
ends. Nothing on the Lockouts page releases it, because it is not a lockout: it
counts posts rather than wrong passwords, and it exists to cap cost, since every
post buys one password verification whether or not the address has a mailbox
here. Waiting out the slot is the whole remedy.

That count is per source address, and this server reads the peer off the socket
and ignores `X-Forwarded-For` everywhere. Behind a TLS terminator, every browser
therefore arrives from the terminator's address, so the fifty are shared across
everyone signing in. On a server with a busy morning behind one terminator, that
is the bound to raise first, and it is the reason a caller can be refused the
form having typed nothing wrong.

**A clock correction clears this one, and does not clear the budgets above.** The
per-mailbox and per-machine counters are measured on a clock the host cannot
step, so fixing a wrong clock does not release a lockout early. The five-minute
window here is measured on the wall clock, so a step forward past it ends the
slot. Read that in the direction it matters: correcting a clock can hand back
sign-in attempts, never take a lockout away.

Then release it. Fill in the mailbox, the machine if the account holder can name
it, and why.

Four things about that form are worth saying plainly:

- The reason is required, and it lands in the audit trail naming you. Releasing
  a budget is the one action in the console that takes a defense away from
  somebody else's mailbox.
- Leaving the machine empty releases the mailbox and leaves that machine's own
  budget alone. The notice names which budgets it released and which it left
  untouched, so this is something you read rather than something you infer. If
  the account holder is still refused from exactly one device afterwards, that
  is why, and releasing again with the machine filled in is the fix.
- **Copy the machine out of the table rather than retyping it.** A row that is
  still inside its window carries a link that fills the form in from it. What a
  counter is kept under is a key this server wrote rather than the address a
  client dialled from: an IPv6 client is recorded as the prefix its site is
  allocated, not as the address it connected from. Both spellings resolve, so
  either the recorded key or the address the caller reads off their own machine
  will work. What does not work is anything this server cannot read as an
  address at all, and naming one refuses the whole release: nothing is released,
  the mailbox included, and the console says so rather than reporting a release
  you did not get. That refusal is deliberate. The machine budget is the one
  read first when a sign-in is judged, so it is usually the one you are trying
  to clear, and releasing the mailbox alone under a notice saying it worked
  would leave the caller refused by the exact budget they phoned about. Clear
  the field to release the mailbox on its own, or copy the key out of the table.
- The console reports **which** budget was holding rather than merely whether one
  was, and the two mixed answers are the ones to act on, because they point in
  opposite directions. *The machine you named was already clear* rules that
  device out: it had spent no allowance, so whatever is refusing the account is
  not the thing you were told about, and the next place to look is elsewhere.
  *The mailbox budget was already clear* is the reverse: the machine was the only
  one of the two refusing them, which is exactly why releasing the mailbox on its
  own had not helped and why they called back.
- If neither budget was holding anything, the console says so rather than
  reporting a release. Take that answer seriously: whatever is refusing that
  account is somewhere else, and a suspended account, a disabled domain and a
  genuinely wrong password all look the same from the client's side.

This lives in the browser rather than on the command line because the counters
live in the running server's memory. A release has to reach the process that is
refusing the password, and every command-line verb that could carry one needs
that server stopped, which leaves no counters to release. A command line release
would report that nothing was locked, every time.

Finally, fix the client. A mail client still holding the old password spends the
budget again within minutes of the release, and the second wait is longer than
the first.

### Nobody can sign in to the console

Signs: an administrator's password is accepted and the administration pages
answer 403, or the sign in is refused outright for an account you know is right
and other mailboxes are unaffected.

The administrator role is granted by `blamepost init` and by the console, and by
nothing else, so an administrator who has been archived, suspended, or stranded
on a withdrawn domain cannot be put back from the browser. The console refuses
the four changes that would cause it (see "After the first start: the
administrator"), and it decides that refusal in the moment the change is saved
rather than when the page was drawn, so two windows or two operators working at
once cannot combine into it either. The usual ways to arrive here are a restore
from a backup taken before the role was granted, an `account remove --destroy`
run from the host, or a domain disabled from the command line.

Every verb that fixes it needs the data directory, and the running server holds
it, so stop the server first. That is the same ordering the credential case
above uses and for the same reason:

```bash
docker stop blamepost

blamepost account list                             # the administrators are labeled
blamepost account resume admin@example.com         # suspended or archived: this is the way back
blamepost domain enable  example.com --reason "administrator could not sign in"

docker start blamepost
```

`blamepost account add` creates an ordinary mailbox and has no flag that grants
the role, so adding an account is not a way out. When there is no administrator
left to resume, run `init` against the same data directory with an address that
does not exist yet:

```bash
blamepost init --admin-email rescue@example.com
```

It creates that account with the role, leaves an already-hosted domain alone,
prints the DKIM records the domain already holds rather than minting new ones,
and prints a generated password once unless you pass `--admin-password`. Sign in
with it and promote whoever should have the role from the console.

### A POP3 client says the mailbox is in use

RFC 1939 gives a maildrop to one session at a time, so this server hands it to
whoever opens it first and refuses everybody else until that session is done.
The refusal is correct, and the account holder is usually the one being refused,
because the session holding the maildrop is almost always their own from a
minute ago.

A session ends the maildrop cleanly by sending `QUIT`. A client that loses its
connection instead never sends one, and this server is not told the connection
went away, so the maildrop stays held. It is released after thirty minutes with
no activity on it. The socket itself closes earlier, after ten minutes idle, but
that closes the connection rather than the hold. So the worst case for somebody
whose phone dropped off the network mid-download is a wait of up to half an
hour before they can collect mail again.

What to tell them, in order:

- **Wait.** Nothing is lost and nothing needs repairing. The hold expires on its
  own and their mail is where they left it.
- **Nothing was deleted by the interrupted session.** POP3 applies deletions
  only at `QUIT`, so a session that died having marked twenty messages for
  deletion deleted none of them. They will be offered again on the next
  collection, which is the correct outcome and not a duplicate delivery.
- **A restart clears every hold immediately.** Holds live in the running
  server's memory and nothing is written to the data volume, so there is no lock
  file to find and no state to clean up by hand. If the account holder cannot
  wait, restarting the server is the release. It costs every other connection in
  flight, so it is the answer for a stuck morning rather than a routine one.
- **If it recurs on the same account, look at the client.** A client set to leave
  mail on the server re-downloads the whole maildrop every time, so its sessions
  are the longest ones and the most likely to be interrupted. Either let it
  delete on collection, or move that account to IMAP, which has no exclusivity
  rule and is the better fit for a mailbox read from more than one device.

The wait exists because the POP3 listener gives this server no signal when a
connection ends, so a timer is the only release available and it cannot tell a
finished session from a slow one. Tracked upstream as blamejs#669.

### The domain's mail is being rejected

```bash
blamepost doctor --domain example.com
blamepost queue list --destination example.net   # the receiver's own words, per message
```

Almost always DNS. `doctor` resolves the MX, SPF, DMARC, DKIM, MTA-STS and
TLS-RPT records, and the TLSA record under `--dane`, and compares each with what
this server is configured to do. The DKIM check is the one that earns its keep
after a restore: it compares the published `p=` against the private key the
server actually signs with, which is the failure a backup taken before a
rotation produces and the one nothing else can see from the sending side.

Three causes it does not catch, so check them by hand when `doctor` comes back
clean and mail is still being refused:

- **An SPF record past the ten-lookup limit.** `doctor` reads the record, its
  redirect chain and its `all` qualifier, and does not count the DNS lookups an
  evaluation would spend. Every `include:`, `mx` and `a` costs one, and going
  over turns the record into a permanent error at the receiver.
- **Reverse DNS.** No check resolves the `PTR` for this server's sending
  address, so a provider re-imaging the host and changing the name is invisible
  here. `dig +short -x <your.sending.ip>` is the check, and the answer has to be
  `BLAMEPOST_HOSTNAME` and resolve back to the same address.
- **An MTA-STS `id` that was not bumped.** `doctor` confirms the TXT record
  carries an `id` and that the fetched policy names this server and says
  `enforce`. It has no memory of the previous `id`, so it cannot tell you the
  policy changed underneath a value senders are still caching. Change the `id`
  whenever you change the file, and treat that as procedure rather than
  something a check will catch.

If DNS is clean, check whether the sending IP is on a blocklist. Most publish a
removal process. Work through it rather than around it, and find what got you
listed first, because a delisting without a fix lasts days.

### One sender's TLS handshake is refused and the others are fine

The symptom belongs to the sender rather than to you: their log says the TLS
handshake failed against your MX, no message ever reaches `DATA`, and everyone
else delivers normally. Nothing appears in this server's own log, because the
connection ends before any protocol runs on it.

Every listener names the key agreements it accepts: the ML-KEM hybrids first,
then every elliptic curve RFC 8446 §4.2.7 registers, which is `secp256r1`,
`secp384r1`, `secp521r1`, X25519 and X448. A conforming TLS 1.3 sender offers at
least one of those, so the usual cause is a sender offering only finite-field
Diffie-Hellman, which is the one class left off.

Check it from a machine that can reach the port. Each of these completes:

```bash
openssl s_client -connect mail.example.com:25 -starttls smtp -groups X25519 </dev/null
openssl s_client -connect mail.example.com:25 -starttls smtp -groups P-256 </dev/null
openssl s_client -connect mail.example.com:25 -starttls smtp -groups P-384 </dev/null
```

and this one does not:

```bash
openssl s_client -connect mail.example.com:25 -starttls smtp -groups ffdhe2048 </dev/null
```

A refusal on the first three is not the key agreement and you should look at the
certificate and the sender's trust store instead. A refusal on the last is the
shipped behavior and there is no setting here that widens the set. Where a
partner is affected, the fix is at their end: enabling any registered curve
covers it, and a TLS 1.3 implementation is required to support `secp256r1`
already.

There is no plaintext route around it. A sender refused at the handshake retries
in the clear and is answered `530 5.7.0 Must issue a STARTTLS command first` at
`MAIL FROM`, so the message stays in their queue rather than arriving
unencrypted.

The browser interface carries the same preference, so testing the admin URL and
testing port 25 give the same answer about the key agreement. They still differ
in everything else a handshake involves, so a certificate or name mismatch has to
be checked on the port that reported it.

### A DKIM key may have been exposed

Rotate immediately, using the procedure under Rotating DKIM keys, and do not
compress the overlap.
The exposure window is already open; a botched rotation adds an authentication
failure on top of it. Then work out how the key got out, because it was sealed in
the volume, which means either the passphrase or the host.

Start that from the trail, which is where the key's own history is:

```bash
blamepost audit read --action blamepost.mail.dkim.keys_generated
blamepost audit read --action blamepost.mail.dkim.keys_rotated
```

Between them those rows date every selector this domain has ever signed with, so
they bound the window a stolen key could have been useful in, and they name who
minted it. Refused attempts are recorded too, which is worth reading here: a
rotation somebody tried and could not finish is a row that would otherwise leave
no trace. The rows carry no key material of either half, only the selector name,
its algorithm and its domain, so the trail is safe to hand to whoever is
investigating.

### The audit chain refuses to verify

The server refuses further appends and says so at boot. Do not restart it in a
loop. Take a copy of the volume before doing anything else, then work from that
copy. The state at the moment of the failure is the evidence, and a restart
overwrites some of it. A chain that does not verify means either storage
corruption or that something reached the database directly; both need answering
before the server goes back into service.

```bash
blamepost audit verify-chain --json      # the finding, in a form you can keep
```

`verify-chain` still answers on a volume that will not open, because reporting
the refusal is its job: it catches the refusal the boot raised and prints it as a
verdict rather than as a command that crashed. Run it with `--json` and keep the
output. The refusal names which of the three readings failed, and that is what
tells the two causes apart.

**Read the finding before you restore, because the two causes need opposite
responses.** A single row failing its own hash with everything around it intact
is what storage damage looks like: the volume is unreliable and the answer is
hardware. A sequence that agrees with itself while a checkpoint signature or the
record beside the volume disagrees is what a rewrite looks like: the volume is
fine and somebody reached the database, so restoring without answering how puts
the same server back where it was.

**The copy of the data directory is the only preservation you get here, which is
why it is the first step rather than a precaution.** `audit export` and `audit
archive` both have to open the volume to read the rows, so neither answers on one
that is refusing, and there is no way to lift the disputed range out into a
bundle after the fact. Take the copy, keep it somewhere the running server cannot
write to, and work from it.

Then find the ground to go back to. The backup verbs answer whatever the volume
is doing:

```bash
blamepost backup list --storage /srv/backups
blamepost backup verify --storage /srv/backups --bundle <id> \
  --passphrase-file /etc/blamepost/bundle.pass
```

Find the newest bundle that verifies and whose chain was intact when it was
written, then restore it. What is between that bundle and now is lost, which is
why the schedule matters more than the mechanism.

`restore apply` replaces the data directory and keeps the old one as a rollback
point, so a finding recorded in `audit.disputed` goes with it and the restored
volume opens. If you resolve the incident some other way and keep the volume you
have, remove that file yourself once you are finished with it. Nothing clears it
for you, because a finding that clears itself on the next restart is a finding
nobody reads.

### The container started and then reported unhealthy

The image's health check is an HTTP request to `/healthz` on the HTTP port. It
answers in three verdicts, not two, and the middle one is the one most first
boots produce.

**A listener has four states, and only one of them is a fault.** `bound` took
its port. `disabled` was not turned on by this configuration, which is where
POP3 sits by default. `withheld` is enabled and deliberately not bound, and the
server carries its own sentence saying why: port 25 withholds itself while no
domain is hosted and acknowledged, because a server that accepted mail for
recipients it knows nothing about would be collecting a stranger's mail.
`unbound` is the fault: enabled, expected to bind, did not.

So `/healthz` answers `degraded` with a 200 while something is withheld. The
process is worth keeping and is serving everything else; a fresh container
between `docker compose up -d` and `blamepost init` is in exactly that state,
and it is expected rather than a problem. `/readyz` is the one that refuses,
because that is the lever that fits: stop routing, leave the process alone.
Nothing about a listener fails liveness, since a restart fixes none of it, and a
runtime that killed the process would take down the browser surface you were
about to run `init` against.

`503` from `/healthz` means the store is not open. That is the condition a
restart can genuinely address, and it is the only one that answers so.

The probe writes its verdict rather than exiting silently, so `docker inspect`
carries the reason alongside the failing streak. Ask from inside the container
to get the full per-check breakdown; asked through the published port, the
endpoint answers the status word alone, because it shares a port with webmail
and the breakdown describes a mail server.

```bash
curl -sA operator http://127.0.0.1:8080/readyz   # the same verdict, readiness tier
docker logs <container> | tail -40               # the gate that refused names itself
```

**The `-A` is not decoration, and this catches people.** The browser surface
refuses the default user agent of every common automation client on every path,
the probes included: `curl`, `wget`, `python-requests`, `axios` and
`Go-http-client` are all turned away with `403 Forbidden`. So an operator
reaching for `curl http://127.0.0.1:8080/healthz` to see what is wrong gets a
refusal that looks like the server being broken, and it is the guard working.
Send any user agent that is not one of those and you get the real answer. The
container's own health check is unaffected: it does not use curl.

Three endpoints, three questions:

| Path | Question | Who asks |
|---|---|---|
| `/healthz` | Is this process worth keeping? | The container runtime, deciding whether to restart it |
| `/readyz` | Should traffic go to it right now? | A load balancer or proxy, deciding whether to route |
| `/startupz` | Has the slow part of the boot finished? | An orchestrator waiting out a first boot |

During a shutdown `/readyz` answers 503 straight away so a proxy stops routing,
while `/healthz` keeps answering until the drain finishes. That split is
deliberate: a runtime that read a draining process as a dead one would kill it
halfway through.

### Something is wrong and you need to look

```bash
blamepost doctor                          # the whole posture, server up or down

BLAMEPOST_LOG_LEVEL=debug blamepost serve # full protocol detail
```

`doctor` reads the hosted domains and their selectors out of the encrypted
database before it resolves a single record, so it needs that database. Against a
running server it takes a private copy of it rather than refusing, and labels the
answer with the moment the server last wrote the volume to disk. For DNS posture
that label costs you nothing: a domain added in the last minute is the only thing
a copy could be missing, and DNS has not propagated for it yet either.

Two checks change. Message bodies and signing keys each need the files on disk
and the rows read at the same moment, so against a copy both report as not done.
Stop the server and run `blamepost doctor` again, or `blobs report` for the
bodies on their own. Everything else is the same verdict either way. See "Seven
reporting verbs answer while the server runs".

The `signing keys` line holds the data directory's `keys` folder against the DKIM
selector records. It fails on either of two states, and they need opposite
responses. A sealed key that no record names is signing material nothing here
will use or remove, and every backup taken from now on carries it: delete the
files it names from the `keys` folder by hand. An active selector whose key is
not on the volume is a domain whose mail is leaving unsigned right now: restore
the volume from a backup taken before the key went, or replace the pair with
`blamepost dkim retire` followed by `blamepost dkim generate`. A retiring
selector with no key is neither, and is not counted, because retirement destroys
the private half and leaves the record published through its overlap.

The `outbound spool` line holds the message bodies in the queue directory against
the descriptors that name them. A waiting recipient is two files, and the message
is written first so that a process stopping between the two writes leaves a
message nobody has to send yet rather than a descriptor with nothing behind it.
The cost is a message with no descriptor: every listing reads descriptors, so
that body is in no listing and has no identifier you could type, while the
queue's ceiling is measured off the volume and weighs it. Enough of them and the
server refuses mail with `blamepost queue list` showing nothing. This line names
each one, and `blamepost queue remove <id> --reason ...` clears it. A body
written in the last five minutes is left out, because the pair is legitimately
half on disk for that instant and a message arriving normally must not be
reported as one to delete. `blamepost queue list` says the same thing at the
bottom of its output, which is where you are looking when the queue reads as
empty and mail is being refused anyway.

Debug logging includes wire-level protocol exchanges. It is what you want while
diagnosing, and it is not what you want running permanently against a mailbox
somebody trusts you with. Turn it off afterwards.
