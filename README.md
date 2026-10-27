<div align="center">

# blamepost

**Self-hosted mail server that owns its stack: SMTP, IMAP, JMAP, POP3, ManageSieve and webmail in one container. PQC-first, zero runtime deps.**

<a href="https://github.com/blamejs/blamepost/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/blamejs/blamepost/ci.yml?branch=main&label=CI" alt="CI status"></a>
<a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
<a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D24.22.1-2ea043" alt="Node.js 24.22.1 or newer"></a>
<a href="https://slsa.dev"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
<a href="#vendoring"><img src="https://img.shields.io/badge/runtime%20deps-0-2ea043" alt="Zero runtime dependencies"></a>
<a href="#security"><img src="https://img.shields.io/badge/crypto-PQC--first-d946ef" alt="PQC-first cryptography"></a>

</div>

---

Running your own mail usually means assembling one: Postfix in front, Dovecot
behind, an LDAP or SQL directory beside them, OpenDKIM bolted on, a Sieve daemon,
a webmail app on its own stack, and a spam engine gluing the seams. Six upgrade
cadences, six config languages, and six places to look when a message goes
missing.

blamepost is the whole path in one process. Inbound MX, authenticated
submission, IMAP, JMAP, POP3, ManageSieve, outbound delivery, DKIM signing,
Sieve filtering, webmail and an admin UI all run in a single Node process
backed by a single data directory. Nothing installs beside it, and nothing sits
on npm underneath it.

**Status:** pre-1.0. The surface is still moving. Before upgrading across more
than a few patches, read the notes for the versions you are skipping in
[CHANGELOG.md](CHANGELOG.md). [ROADMAP.md](ROADMAP.md) marks every capability as
shipped, targeted, accepted or under design, so what is present today and what is
still coming are both legible.

## Quick start

The container is the documented default. It carries the runtime, the vendored
framework, and every listener.

```bash
docker run -d --name blamepost \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -p 25:25 -p 465:465 -p 587:587 \
  -p 143:143 \
  -p 4190:4190 \
  -p 8080:8080 -p 8443:8443 \
  -v blamepost-data:/var/lib/blamepost \
  --env-file ./.env \
  ghcr.io/blamejs/blamepost:0.1.0
```

The image runs as UID 65532 with every Linux capability dropped, and it binds
25, 465, 587 and 143 that way. A container gets its own network namespace, and
current Docker and Kubernetes already start the unprivileged-port floor at zero
inside one, so nothing has to grant a capability or set a flag for those ports
to be reachable.
`--sysctl net.ipv4.ip_unprivileged_port_start=0` states that requirement rather
than creating it, which is worth keeping for a runtime that has not adopted the
default or a host where the floor has been moved. It is namespaced, so it
changes nothing outside the container. `compose.yml` sets the same sysctl.

The floor is real under `--network host`, where the namespace is the host's own
and the sysctl is refused rather than applied. That is the deployment where the
per-listener port variables in [docs/operator-guide.md](docs/operator-guide.md)
are the answer: move each listener to a high port and publish the standard one
in front of it.

The data directory must be mode `0750` or tighter and must belong to the UID the
image runs as. Both are checked before any listener binds, so a bind-mounted
host directory created at the usual umask stops the container on every start:
owned by root it fails while creating the directories it keeps data in, and
owned correctly but left at `0755` it fails naming the mode. A named volume, as
above, inherits the image's own `0750` and ownership and needs nothing. The
operator guide has the two-line fix.

`.env` holds the settings, so no secret lands in the process table or in
`docker inspect`:

```sh
BLAMEPOST_HOSTNAME=mx.example.com
BLAMEPOST_VAULT_PASSPHRASE=<a long random string you keep offline>
BLAMEPOST_DNS_ACKNOWLEDGED=1
BLAMEPOST_TLS_CERT=/var/lib/blamepost/tls/fullchain.pem
BLAMEPOST_TLS_KEY=/var/lib/blamepost/tls/privkey.pem
```

Give it `chmod 600` and keep it out of version control.

Three of those need explaining before the first boot:

- `BLAMEPOST_VAULT_PASSPHRASE` seals the DKIM private keys and account secrets
  in the data volume. Lose it and the volume is unreadable. No recovery path
  exists, by design.
- `BLAMEPOST_DNS_ACKNOWLEDGED=1` is the operator's assertion that the DNS
  records in [docs/operator-guide.md](docs/operator-guide.md) are published.
  Without it the MX listener refuses to bind, so a half-configured server never
  starts accepting mail it cannot authenticate or deliver. It covers this
  server. Each hosted domain is acknowledged on its own, below.
- `BLAMEPOST_TLS_CERT` and `BLAMEPOST_TLS_KEY` name a certificate and key that
  have to exist before the first boot. Put the pair in the data volume's `tls/`
  folder, from certbot, lego, your own authority, or wherever your certificates
  come from now. Every mail listener requires TLS and none has a plaintext mode,
  so a server with no certificate has nothing to start. The browser surface
  answers on 8443 from that same pair and on 8080 in the clear, and 8080 is there
  for the container health check and for a proxy in front. This server accepts a
  password when the connection is TLS, when a proxy named in
  `BLAMEPOST_TRUSTED_PROXIES` states that the browser's connection was, or when
  the peer is on the loopback interface, and it refuses one otherwise. A request
  published out of a container reaches the server from the bridge gateway rather
  than over loopback, so 8443 is the port to sign in on. A renewal written to
  those two paths is picked up in place: the mail listeners and the browser
  interface both present the new certificate without a restart, and the health
  probes report a certificate that is running out so a renewal that stopped is
  found before mail is.

The container comes up with no accounts in it, and it reports itself **degraded
until you add one**. That is expected rather than a fault: port 25 withholds
itself while no domain is hosted, because a server accepting mail for recipients
it knows nothing about would be collecting a stranger's mail. Everything else is
bound and serving, and both probes answer 200 with a verdict of `degraded` that
names the withheld listener and the reason, so nothing restarts the container or
stops routing to it while you finish setting it up.

`blamepost init` is the command that creates the administrator, and it is the one
step between a running server and a server you can sign in to. It is also the only command that creates an
account carrying administrator rights, since `blamepost account add` creates an
ordinary mailbox. Run it against the data volume to finish the install, and run
it again later with a different address whenever you want a second
administrator:

```bash
docker exec blamepost node bin/blamepost.js init --admin-email admin@example.com
```

`init` hosts that address's domain, mints its DKIM keys, prints the records to
publish, and prints a generated password once unless `--admin-password` supplies
one. It reads `BLAMEPOST_ADMIN_EMAIL` and `BLAMEPOST_ADMIN_PASSWORD` when the
flags are absent. Set those two together or not at all: an email with no
password would leave the server choosing a credential and writing it to a log,
and a log is not where a password belongs. Setting one without the other is
refused at start rather than half-honored.

Once `init` has run, webmail and admin are on port 8443 over HTTPS, at the name
the certificate covers: `https://mx.example.com:8443` for the settings above.
Sign in as the address you passed it, then add further domains and accounts from
the admin UI or the CLI:

```bash
docker exec blamepost node bin/blamepost.js domain add example.com
docker exec blamepost node bin/blamepost.js account add alice@example.com
docker exec blamepost node bin/blamepost.js dkim records example.com
docker exec blamepost node bin/blamepost.js doctor
docker exec blamepost node bin/blamepost.js domain acknowledge example.com --by admin@example.com
```

`domain add` mints that domain's DKIM keys and prints the records to publish as
it goes, so there is no separate key-generation step. `dkim records` prints them
again whenever you need them back. `blamepost doctor` resolves them and tells you
which ones are missing, stale, or contradicted by what is actually in DNS, and
it holds the sealed private keys on the volume against the records that name
them: a key no record claims is signing material nothing here will use, and an
active selector with no key is a domain whose mail is leaving unsigned.
Withdrawing a domain or a selector destroys the key before the record, so
neither half outlives the other.

`blamepost domain acknowledge` is the last step, and it is per domain rather
than per server: the MX listener refuses to bind while any active domain is
unacknowledged, so a domain added months later gets the same gate the first one
did instead of inheriting an old confirmation. Restart the server after
acknowledging a new domain so the MX listener picks it up.

### Compose

If you want optional services beside it, start from `compose.yml`:

```bash
git clone https://github.com/blamejs/blamepost.git
cd blamepost
# write the same settings into .env, then:
docker compose up -d
```

With no profile, that is the same image against the same volume. On its own it
is a complete mail server. Two profiles add the optional pieces:

```bash
docker compose --profile scan up -d   # heavier content scanning beside it
docker compose --profile tls  up -d   # a reverse proxy in front of the web UI
```

Neither is needed for mail to flow. Each attaches through an operator-supplied
endpoint rather than being bundled into the server.

The `tls` profile terminates TLS and reaches the web port in cleartext, so set
`BLAMEPOST_TRUSTED_PROXIES` to the range it reaches the server from before
anyone signs in through it. Without that, the browser is on HTTPS while this
server reads its own socket as cleartext, and the sign-in post is refused.

### Without a container

The server is a plain Node process and runs directly on a host with Node.js
24.22.1 or newer:

```bash
git clone https://github.com/blamejs/blamepost.git
cd blamepost
bash scripts/vendor-update.sh blamejs latest

export BLAMEPOST_HOSTNAME=mx.example.com
export BLAMEPOST_VAULT_PASSPHRASE='a long random string you keep offline'

node bin/blamepost.js init  --data-dir ./data --admin-email admin@example.com
node bin/blamepost.js serve --data-dir ./data
```

The vendor step is required on a fresh clone. `lib/vendor/blamejs/` is not
committed, and nothing boots until it is populated.

A browser on that same host reaches this process over loopback, so
`http://localhost:8080` takes a password there. Port 8443 takes one from any
address, and a browser that reaches it by a name the certificate does not cover
warns before it loads the page.

Every command needs `BLAMEPOST_HOSTNAME` and `BLAMEPOST_VAULT_PASSPHRASE`, and
refuses to run without them rather than picking a value for you. `serve`
additionally needs `BLAMEPOST_TLS_CERT` and `BLAMEPOST_TLS_KEY`; `init` and
`doctor` deliberately run before a certificate exists, which is when `doctor`
saying so is worth the most. On a host, binding a port below the machine's
`net.ipv4.ip_unprivileged_port_start` needs root, `CAP_NET_BIND_SERVICE`, or
that floor lowered; the per-listener port variables in
[docs/operator-guide.md](docs/operator-guide.md) are the alternative to all
three. The data directory needs mode `0750` or tighter, because `serve` asserts
its production posture before it binds anything.

## What ships

Every listener is one blamejs primitive composed into the boot sequence. All are
on by default except POP3.

| Port | Protocol | Standard |
|---|---|---|
| 25 | Inbound MX over SMTP | RFC 5321, with SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 9989) and ARC (RFC 8617) evaluated at DATA |
| 587 | Submission + STARTTLS | RFC 6409, SASL AUTH per RFC 4954 |
| 465 | Submission over implicit TLS | RFC 8314 |
| 143 | IMAP + STARTTLS | RFC 9051 (IMAP4rev2), CONDSTORE per RFC 7162, METADATA per RFC 5464 |
| 110 | POP3 + STLS, off by default | RFC 1939, RFC 2595 |
| 4190 | ManageSieve | RFC 5804 |
| 8080 | HTTP for webmail, admin and JMAP | RFC 8620 and RFC 8621 on the JMAP path |
| 8443 | HTTPS for that same surface, when TLS terminates locally | RFC 8620 and RFC 8621 on the JMAP path |

IMAP and POP3 negotiate TLS in band, so this server binds 143 and 110 and binds
nothing on 993 or 995. A client that can only do implicit TLS on those two ports
has no route here today, and a TCP terminator accepting TLS on 993 or 995 and
forwarding the plaintext stream to 143 or 110 is not one: the listener is handed
an unencrypted connection and refuses every credential offered over it, which is
the correct answer to a hop asking to be believed about confidentiality it
terminated. The reverse proxy behind `compose.yml`'s `tls` profile is unrelated;
that one fronts the web interface.

JMAP (RFC 8620 Core, RFC 8621 Mail) is mounted inside the web app at `/jmap`
rather than on a port of its own, so it inherits the same authentication,
session and security middleware as the rest of the HTTP surface. That includes
the transport rule above: a session is read only from a connection this server
can establish is encrypted, so point a JMAP client at 8443 rather than at the
cleartext port.

Binary data (RFC 8620 section 6) is served in one direction. A client fills in
the `downloadUrl` the session document names,
`/jmap/download/{accountId}/{blobId}/{name}?accept={type}`, and fetches a
message's raw bytes or one file off it. A blob id is a message identifier,
which is the value `Email.blobId` carries, or that identifier followed by `-p`
and the body part number of RFC 9051 section 6.4.5 with each dot written as a
dash, so the file at part `1.2` downloads under `<message>-p1-2`. Every blob is
served as `application/octet-stream` with `nosniff` whatever the sender declared
and whatever `accept` asked for, disposed as an attachment under the name the
message carries. Upload is not served: `uploadUrl` answers `503` with the type
`urn:ietf:params:jmap:error:serverUnavailable`, the session document advertises
`maxSizeUpload` as 0, and a client that uploads an attachment before sending
fails at that step. IMAP `FETCH` returns the same bytes. ROADMAP.md tracks blob
upload.

**Whether a message carries files** is recorded on the message when it is filed,
as the IMAP keyword `$HasAttachment` or `$HasNoAttachment`. `hasAttachment` on
JMAP `Email/get` is read from that mark rather than derived per request, an IMAP
client sees the keyword in `FETCH FLAGS`, and the folder listing marks the rows
that have one. A message above the 8 MiB read bound is not opened, so it records
neither keyword: the listing says the answer is not known for it and
`hasAttachment` answers true, which RFC 8621 §4.1.4 leaves to the server and
which hides no file. Both keywords are server-set, so `Email/set` and IMAP
`STORE` refuse to write either. `blamepost attachments backfill` records the mark
for mail that was already on the volume.

**Which files a message carries** is answered by `Email/get` in the `attachments`
list of RFC 8621 §4.1.4, to a call that names `attachments` in `properties`. Each
part carries `partId`, `blobId`, `size`, `name`, `type`, `charset`, `disposition`,
`cid`, `language` and `location`, so a client takes a blob id out of the answer
rather than building one from the grammar above. A call that does not name the
property carries no list: building one opens each message and walks its
structure, and one call may name 50 identifiers against the 8 MiB read bound. A
message with no file answers an empty list; a message above that bound carries no
`attachments` property at all. `headers`, `subParts` and `bodyProperties` are not
served, and ROADMAP.md tracks `bodyStructure`, `textBody`, `htmlBody` and
`bodyValues`.

**The mailbox tree** is the same one over JMAP as over IMAP. `Mailbox/get` gives
each mailbox a `parentId` naming the level above it and a `name` carrying the
last level alone, as RFC 8621 §2 requires, and every `parentId` in an answer
names another mailbox in that answer. A level that no mailbox answers to, which
is what IMAP `DELETE` leaves listed as `\NonExistent \HasChildren`, is answered
with every right false. The session document advertises `maxMailboxDepth` as
`null`, which RFC 8621 §1.6.2 defines as no limit. What is capped is the length
of a name, which `maxSizeMailboxName` reports, and the 1000 mailboxes one account
may hold. A mailbox id is the full path, which is the value `Email/query` takes
in `inMailbox`.

**IMAP `CREATE`** makes a mailbox for the account that sent it, so a client's new
folder control works. A trailing `/` is the declaration RFC 9051 §6.3.4 describes
and is not part of the name created; a `/` inside the name creates the superior
levels it needs, and each of them is selectable. A name that is already there is
refused with `[ALREADYEXISTS]`, a name this server will not keep with `[CANNOT]`,
and an account holding the 1000 mailboxes one account may have with `[LIMIT]`. A
mailbox name is screened before it is stored, so the screen a client's `SELECT`
passes is the screen the stored name passed: the characters that make one name
render as another are refused, and so is a level spelled `.` or `..`, which in a
path names somewhere other than where it reads.

**IMAP `DELETE`, `RENAME`, `SUBSCRIBE` and `UNSUBSCRIBE`** finish the folder
controls. `DELETE` destroys the mail the mailbox holds through the same delete
path as `EXPUNGE`, so a message a legal hold or the retention floor keeps stops
the removal: the client is answered `NO [CONTACTADMIN]` with the count that was
kept, and the mailbox is still there holding it. `INBOX` and the five mailboxes
carrying an RFC 6154 role are refused, because this server files into those by
name. Removing a name that has names underneath it leaves them where they are
and leaves the level listed as `\NonExistent \HasChildren`. `RENAME` moves the
inferior names with it, creates the superior levels the new name needs, and
keeps the mailbox's `UIDVALIDITY`, so a client's cache survives; renaming
`INBOX` moves the messages and leaves `INBOX` in place, empty, which RFC 9051
§6.3.6 requires. A subscribed name outlives the mailbox it names, per §6.3.8, and
`LIST` now matches its reference and patterns and serves the `SUBSCRIBED`,
`CHILDREN` and `STATUS` options a client reads that set back with.

**IMAP `SELECT` and `EXAMINE`** send the `PERMANENTFLAGS` response RFC 9051
§6.3.2 requires, so a client knows which flags survive the session instead of
assuming all of them do. A read-write selection names the five system flags plus
`\*`, which says a client may invent keywords of its own and this server keeps
them. A selection opened with `EXAMINE` names none, because §6.3.2 permits no
permanent change from one and `STORE` from it is refused. The `$HasAttachment`
and `$HasNoAttachment` keywords are in the `FLAGS` list and not in
`PERMANENTFLAGS`: a message carries them, and a client may not set them.

**IMAP `SEARCH`** answers flags and keywords, arrival dates, sizes, sequence and
UID sets, `SUBJECT`, `FROM`, `TO`, the header fields the server stores, and any
boolean combination of them, matching on substrings as RFC 9051 §6.4.4
requires. A key whose data is not stored is refused by name rather than
answered with an empty set, so a client is never told a mailbox has no matches
when the question was not asked. Each refusal names the key it refused and the
reason on the wire, so a client sees which part of the expression could not be
answered. `UID SEARCH` is served from the same handler and answers in unique
identifiers, as RFC 9051 §6.4.9 requires, so a client keeping a cache between
sessions gets numbers that still mean something in the next one.

**Webmail** is server-rendered: read, search, compose, reply, forward, move,
flag, mark read, trash and purge, with client JavaScript as opt-in islands
rather than the foundation. A conversation lists the files each message carries,
with the name, the declared media type and the size, and serves each one as a
download: `application/octet-stream`, `Content-Disposition: attachment` and
`nosniff` on every part whatever the sender declared it to be, so a part
claiming `text/html` does not render as a page on this server's origin. A
message above 8 MiB is not opened, so its files are neither listed nor served.
An account that holds more than one sending address
picks between them when it composes, and JMAP offers the same set as one
identity per address. Sieve rules (RFC 5228) are not editable here: scripts are
uploaded, listed, activated and deleted over ManageSieve on 4190, so an account
holder who wants filtering needs a ManageSieve client, and `blamepost account
sieve` reads back what an account holds. Creating, renaming and deleting a
folder is not offered in the browser; an IMAP client does all three. An account
holder can open a folder at any depth, including one whose name carries the
hierarchy delimiter or a backslash. The folder is named in the query string, so a
mailbox page is `/mail?folder=<name>` and a message page is
`/mail/<message>?folder=<name>`.

**Admin** covers domains, accounts, aliases, quotas, DKIM selectors and their
rotation, sign-in lockouts and the release of one, the outbound queue, and the
audit log. Every administrative action writes a hash-chained audit row carrying
what changed, when, how it came out, and who did it: a command-line invocation
records the operating-system account and host it ran as, and a console action
records the signed-in account. Delivery and the wire rows are deliberately
different, because a message arriving from a stranger has a peer rather than a
principal. DMARC aggregate reports are parsed and shown per domain on the
DMARC page. Parsing TLS-RPT reports into that surface is on the roadmap and
is not in this release.

**Reference** pages at `/wiki` cover every module and primitive in the running
build: signature, status, options, examples, source location and the
specifications each one cites, with an index of every cited RFC and standard.
The server generates them from the documentation comments in `lib/`. A signed-in
account can read them, and a visitor with no session can read them while the
public site is published. [docs/operator-guide.md](docs/operator-guide.md)
lists the paths and the cache header each page carries.

**Sending credentials** are the shape an application takes when it sends under
many local parts of one domain and holds no mailbox. `blamepost credential add`
issues one scoped to a hosted domain, prints its token once and never again, and
gives it a return path of `bounces+<id>@<domain>` so the bounces reach a mailbox
you named rather than an address in the domain that holds none. Each carries two
ceilings over a rolling window, one on messages and one on recipients, and a list
of local parts it refuses that starts with `postmaster`, `abuse` and every
mailbox in the domain holding the operator role. `blamepost credential list`,
`blamepost credential show` and `blamepost credential bounces` resolve where each
credential's bounces are actually landing, and answer while the server runs,
which is what finds a bounce mailbox archived after the credential was issued.
An application presents one on 587 or 465, signing in over SASL with the hosted
domain as the user name, or posts JSON to `POST /api/send` on the browser port,
which takes the token in an `Authorization: Bearer` header, requires an
`Idempotency-Key` and binds no port of its own.

**Outbound delivery** runs one path: MX lookup, MTA-STS policy enforcement
(RFC 8461), DANE once you declare your resolver DNSSEC-validating (RFC 7672),
REQUIRETLS when you ask for it (RFC 8689), retry with backoff, and DSN generation
(RFC 3464). Mail the server sends
on its own behalf takes that same path, delivery status notifications included,
and the reports that come back about it are read. A repository gate refuses a raw
transport call anywhere in `lib/`, so no second, less careful sender exists.
DANE (RFC 7672) needs one thing from you before it is in that list. A server
cannot discover whether its own resolver validates DNSSEC, and RFC 7672 says a
TLSA record may only be used when it was validated, so `outboundPolicy.dane` at
`enforce` is refused at start until you set `outboundPolicy.dnssecValidated`
and tell it that yours does. Only set that if it is true: asserting it falsely
is worse than not running DANE, because it authenticates peers on the strength
of answers nothing checked. The `opportunistic` default needs nothing and
authenticates nobody. Nothing here configures which resolver is being vouched
for. One resolver serves every mail path and no setting names its upstream, so
it queries the vendored framework's default DNS-over-HTTPS endpoint unless you
embed this server and pass `blamepost.create` one of your own.
[SECURITY.md](SECURITY.md) sets out what that means for the rest of your DNS
posture.

What happens to a message that cannot be delivered is decided by the outcome
the chain returns, never by the words the far side used, so a receiver cannot
talk this server into abandoning mail by phrasing a refusal to look like
something else. A message a peer defers keeps its place and its retry budget. A
message that fails permanently ends with a delivery report to the account that
sent it, and one that instead runs out of attempts against a fault no receiver
ever owned ends with a report under `4.4.7`, transient rather than permanent,
because no peer was ever reached and nothing has been established about the
address, so the sender knows the message is worth sending again. Those reports
are rate limited per sender and in total, because a
report is addressed to whoever the failed message claimed to be from and on a
forged run that is somebody who never wrote to you. `blamepost queue list`
shows what is waiting and `blamepost queue held` shows what has stopped and
what would release it. The health probes answer the same question without
anybody running a command: they report `degraded` once the queue has filled past
the point where it stops accepting mail for forwarding, once mail is waiting
with nothing draining it, or once this build cannot reach a peer at all, so a
server that answers every other check perfectly while mail stops leaving is
found by your monitoring rather than by the person whose message never arrived.

## Requirements

- **Node.js 24.22.1 or newer**, or Docker. Nothing is transpiled; the source in
  the repository is the code the runtime executes.
- **A domain you control, with DNS access.** MX, SPF, DMARC, DKIM, MTA-STS and
  TLS-RPT records are operator-side prerequisites, not something the server can
  publish for you. The full recipe is in
  [docs/operator-guide.md](docs/operator-guide.md).
- **Unfiltered outbound TCP/25.** Many hosting providers block it by default.
  Confirm yours does not before you schedule a migration.
- **A public IP with matching forward and reverse DNS.** Receivers weigh this
  heavily, and some refuse mail without it.
- **Inbound TCP/25, 587, 465, 143 and 4190** open at the firewall, plus 110 when
  POP3 is switched on.
- **A TLS certificate and key for that hostname.** Every mail listener requires
  TLS and none has a plaintext mode, so `blamepost serve` refuses to start until
  `BLAMEPOST_TLS_CERT` and `BLAMEPOST_TLS_KEY` point at a pair on disk. Issue it
  the way you already issue certificates: an ACME client such as certbot or lego
  renewing into the data directory's `tls/` folder, a certificate from your own
  authority, or the pair your TLS terminator already holds. blamepost does not
  order or renew certificates itself. That is on the roadmap and is not in this
  release.

## Configuration

Environment variables take precedence over the config file. `blamepost serve`
needs `BLAMEPOST_HOSTNAME`, `BLAMEPOST_VAULT_PASSPHRASE`, `BLAMEPOST_TLS_CERT`
and `BLAMEPOST_TLS_KEY`. The other settings carry defaults, and `blamepost init`
and `blamepost doctor` run before a certificate exists so that `doctor` can tell
you it is missing.

| Variable | Default | What it does |
|---|---|---|
| `BLAMEPOST_HOSTNAME` | *required* | Public hostname the MX listener announces, for example `mx.example.com`. Must match the MX record and the reverse DNS of the sending IP. |
| `BLAMEPOST_VAULT_PASSPHRASE` | *required* | Seals DKIM private keys and account secrets in the data directory. No recovery if lost. |
| `BLAMEPOST_DNS_ACKNOWLEDGED` | `false` | Must be `1` before the MX listener binds. The operator's confirmation that this server's DNS posture is published. Each hosted domain is confirmed separately with `blamepost domain acknowledge`, so a domain added later does not inherit this one. |
| `BLAMEPOST_DATA_DIR` | `/var/lib/blamepost` | The single data volume: database, message blobs, outbound queue, sealed keys, certificates. |
| `BLAMEPOST_CONFIG` | `/etc/blamepost/blamepost.config.json` | Optional config file. Anything set in the environment wins over it. |
| `BLAMEPOST_HTTP_PORT` | `8080` | Webmail, admin and JMAP over HTTP. |
| `BLAMEPOST_HTTPS_PORT` | `8443` | The same surface over HTTPS, when TLS terminates in-process. |
| `BLAMEPOST_TRUSTED_PROXIES` | *nobody* | Address ranges of the reverse proxies whose `X-Forwarded-Proto` decides whether the browser reached this server over TLS. From any other peer the header is ignored. Set it when a proxy terminates TLS in front of `BLAMEPOST_HTTP_PORT`, as the `tls` compose profile does; without it, signing in through that proxy is refused. Entries need a mask, as in `["192.0.2.0/24"]`. |
| `BLAMEPOST_ADMIN_EMAIL` | unset | Address of the administrator account. Read by `blamepost init`, which is the command that creates it, and by nothing else. |
| `BLAMEPOST_ADMIN_PASSWORD` | unset | Password for that account, read by `blamepost init`. Omit it and `init` generates one and prints it once. Change it from the UI afterwards. |
| `BLAMEPOST_TLS_CERT` | *required by `serve`* | Path to the certificate chain every listener presents. |
| `BLAMEPOST_TLS_KEY` | *required by `serve`* | Path to the matching private key. It may be sealed with the vault passphrase; the loader unseals it in memory. |
| `BLAMEPOST_PUBLIC_SITE_ENABLED` | `false` | Answer `/` with a public page describing blamepost, and `/wiki` with the reference wiki, rather than sending a visitor with no session to the sign-in page. It sets the posture this server boots with; the switch on the console overview page changes it while the server runs, and the console wins. With it off, `/robots.txt` asks crawlers to index nothing and there is no sitemap. |
| `BLAMEPOST_POP3_ENABLED` | `false` | Bind the POP3 listener on 110, which negotiates TLS in band with STLS. Nothing binds 995 on any setting. Off unless you have clients that need it. |
| `BLAMEPOST_LOG_LEVEL` | `info` | `debug` adds the entries this server writes about what it recovered from, and prints the stack behind a command that failed. `warn`, `error` and `fatal` are accepted and remove nothing: the info, warning and error entries are written at every level. |
| `BLAMEPOST_PROFILE` | `strict` | How strictly the wire protocols judge a domain, a HELO name and a command line. `balanced` widens `strict` to accept punycode and non-latin scripts, which you need in order to receive mail from internationalized domains. |
| `BLAMEPOST_POSTMASTER` | `mailer-daemon@<hostname>` | Envelope sender on every delivery status notification this server composes, and the address whose arriving mail is read for reports about this server's own sending. Point it at a real mailbox on a domain you host: the default is built from the MX hostname, which is usually not one, so those reports are refused at the recipient and never arrive. |
| `BLAMEPOST_REQUIRE_TLS` | `false` | Whether every outbound envelope asks for REQUIRETLS (RFC 8689). With it on, the keyword goes on `MAIL FROM` for a peer that advertises the extension, and a peer that does not advertise it is not delivered to at all, which RFC 8689 §4.1 requires. Most receivers do not implement it, so leave it off unless your correspondents do. MTA-STS applies to every outbound message either way, and DANE once you declare your resolver DNSSEC-validating. |
| `BLAMEPOST_MTA_STS_MODE` | `enforce` | Mode in the MTA-STS policy this server publishes. `testing` collects reports without asking senders to refuse delivery; `none` withdraws the policy. |
| `BLAMEPOST_COMPLIANCE_POSTURE` | `none` | `soc2` sets a one year retention floor: a hard delete of anything younger is refused, for the account owner as much as for an administrator. Leave it at `none` unless that is the promise you mean to make. |
| `BLAMEPOST_DMARC_FORENSIC_ENABLED` | `false` | Whether the per-message DMARC failure reports of RFC 6591, sent to the address your `ruf=` tag names, are stored. Turning it on stores personal data belonging to people who are not your users: the sending address, the envelope sender and the recipients of somebody else's message. The failing message itself is never stored whatever this is set to. |
| `BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS` | `30` | Days the counting from aggregate DMARC reports is kept. Between `1` and `400`. |
| `BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS` | `7` | Days a stored forensic report is kept. Between `1` and `30`, and never longer than `BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS`; a pair written the other way round stops the start. |
| `BLAMEPOST_MTA_STS_MAX_AGE` | `604800` | Seconds a sender caches that policy. Between `86400` and `31557600`. |
| `BLAMEPOST_SECURITY_TXT_EXPIRES` | one year from start | RFC 3339 timestamp after which the published `security.txt` stops being authoritative. A timestamp that has already passed is refused at start. |
| `BLAMEPOST_ZONE_PROVIDER` | `none` | Which hosted DNS provider this server may edit records at. `none` and `cloudflare` are the two values. At `none` no credential is opened and nothing is sent to a DNS provider. |
| `BLAMEPOST_ZONE_API_TOKEN` | unset | The provider API token, as this server's vault sealed it. An unsealed value is refused at start. Leave it unset to use the sealed token `blamepost zone token set` writes to the data volume; supplying both stops the start. |
| `BLAMEPOST_ZONE_ALLOW_MX_WRITES` | `false` | Whether the zone writer may edit the `MX` record at a hosted domain's apex. Repointing `MX` moves delivery away from this server, which is the one change it cannot report on afterwards. |
| `BLAMEPOST_ZONE_ENDPOINT` | unset | The provider API address the zone writer sends to, for a deployment whose outbound traffic goes through a proxy of its own. |
| `BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT` | `false` | Whether that address may resolve inside a private, loopback or link-local range. Setting it without an endpoint stops the start. |
| `BLAMEPOST_LISTENERS` | *see below* | Which protocol listeners bind, and on which port and interface. |
| `BLAMEPOST_LIMITS` | *see below* | The ceilings every listener holds against one source address: connections, connection rate, sign-in failures, refused recipients. The largest message accepted sits in the same setting and bounds one message on the two SMTP listeners. |
| `BLAMEPOST_RELAY_ALLOWED_FOR` | *unset* | Declared and refused. This server does not relay for a source address, so a range written here stops the start rather than being ignored. Explained below. |
| `BLAMEPOST_INBOUND` | *see below* | What the MX listener does with the SPF, DKIM and DMARC verdict it computes at the end of `DATA`. The ARC chain is evaluated at the same point and reported in `Authentication-Results`; it does not change what happens to the message. |
| `BLAMEPOST_OUTBOUND_POLICY` | *see below* | MTA-STS and DANE posture this server demands of the peers it delivers to. |
| `BLAMEPOST_OUTBOUND_RETRY` | *see below* | How long a deferred message stays in the spool before its sender is told it failed. |
| `BLAMEPOST_OUTBOUND_SPOOL` | *see below* | How much undelivered outbound mail the spool holds before new mail is refused with a temporary code. A message count and a byte total, whichever is reached first. |
| `BLAMEPOST_OUTBOUND_TIMEOUTS` | *see below* | How long an outbound attempt waits for an MX answer and for the peer itself. |
| `BLAMEPOST_SECURITY_CONTACT` | `mailto:postmaster@<hostname>` | Contact URIs published at `/.well-known/security.txt`. |
| `BLAMEPOST_SECURITY_POLICY_URL` | unset | Disclosure policy page named in that same file. |
| `BLAMEPOST_MTA_STS_MX` | this server's hostname | MX hosts listed in the published MTA-STS policy. Set it as soon as a second MX exists. |

Each mail listener also has a variable that moves its own port and touches
nothing else, which is the form that fits a `docker run` line when the process
cannot bind a privileged port: `BLAMEPOST_MX_PORT`,
`BLAMEPOST_SUBMISSION_PORT`, `BLAMEPOST_SMTPS_PORT`, `BLAMEPOST_IMAP_PORT`,
`BLAMEPOST_POP3_PORT` and `BLAMEPOST_MANAGESIEVE_PORT`.
[docs/operator-guide.md](docs/operator-guide.md) carries the full settings
reference, every variable in one table with its default and its effect.

### Settings that hold more than one value

Eleven of those carry structure. In the config file they are written as JSON,
because the file already is JSON. In the environment they are the same JSON on
one line. Both go through the same checks, so the two forms cannot disagree
about what is valid. Ten of the eleven are below; the eleventh,
`relayAllowedFor`, is refused rather than honored and is covered after them.

```json
{
  "listeners":        { "imap": { "port": 1143, "address": "127.0.0.1" },
                        "pop3": { "enabled": true } },
  "limits":           { "maxMessageBytes": 52428800, "maxConcurrentConnectionsPerIp": 64,
                        "connectionsPerIpPerMinute": 240, "authFailuresPerIpPer15Min": 10,
                        "rcptFailuresPerIpPerMinute": 50 },
  "inbound":          { "mode": "enforce", "onTemperror": "defer" },
  "outboundPolicy":   { "mtaSts": "enforce", "dane": "opportunistic" },
  "outboundRetry":    { "maxAttempts": 35,
                        "backoffMs": [60000, 300000, 900000, 3600000, 14400000] },
  "outboundSpool":    { "maxMessages": 10000, "maxBytes": 2147483648 },
  "outboundTimeouts": { "mxLookupMs": 10000, "perHostMs": 60000 },
  "securityContact":  [ "mailto:security@example.com" ],
  "securityPolicyUrl": [ "https://example.com/security" ],
  "mtaStsMx":         [ "mx1.example.com", "mx2.example.com" ]
}
```

The same two settings from the environment:

```
BLAMEPOST_LISTENERS='{"imap":{"port":1143},"pop3":{"enabled":true}}'
BLAMEPOST_LIMITS='{"maxConcurrentConnectionsPerIp":64}'
```

A listener you do not name keeps its documented port. `listeners` accepts
`mx`, `submission`, `submissions`, `imap`, `pop3` and `managesieve`, each with
`enabled`, `port`, `address` and `maxLineBytes`. A name or a field outside
those is a typo, and it is refused rather than ignored.

`relayAllowedFor` names source ranges the MX listener would accept a recipient
outside the hosted domains for, and setting it stops the start with a message
naming the setting and the submission listener to use instead. The shape is
still checked first, so a range written as `192.0.2.7` or as `the office` is
answered as the typo it is rather than with an argument about relaying; an
empty list asks for nothing and is accepted. The row stays in the schema on
purpose. Deleting it would turn the file key into an unknown key and the
variable into a name nothing reads, and the environment is a namespace shared
with every other tool on the host, so an operator who had already set it would
get a server that relays for nobody and never mentions it.

What makes the refusal safe to live with is that there is nothing left for a
range to serve. A device that can reach `RCPT TO` on port 25 has already
completed a TLS handshake, because the MX listener answers `MAIL FROM` with
`530 5.7.0 Must issue a STARTTLS command first` under both profiles this server
offers, and a device that can do TLS can sign in on 587 or 465. The one device
a range could serve that an account cannot is a device that speaks no TLS at
all, and that device never gets past the greeting here. So give the printer or
the application server an account: mail sent that way is bound to the account
that sent it, is signed for the domain it claims, and produces a delivery
report that account can read. A range grants none of the three, because an
address names a segment rather than a party. When one host inside it is taken
over, the only lever is withdrawing the whole range, which takes the legitimate
device down with it, where an account is revoked on its own.

`limits` holds five ceilings, each applied per source address, per listener. The
shipped values are sized for a peer delivering mail rather than for a person
reading it, which is why `maxConcurrentConnectionsPerIp` is usually the one to
raise: it ships at 10, a single mail client keeps several IMAP connections open
at once, and everyone behind one home or office address arrives as that address,
so the eleventh connection is refused and the person it belongs to reads that as
the server being down. It accepts `1` to `1024`. `connectionsPerIpPerMinute`
ships at 60 and accepts `1` to `10000`. `authFailuresPerIpPer15Min` ships at 10
and accepts `1` to `1000`; it bounds one source address and is not the
per-account budget, which is kept separately so that failing against somebody's
mailbox cannot lock them out of it. `rcptFailuresPerIpPerMinute` ships at 50 and
accepts `5` to `10000`; it bounds address enumeration rather than load, because
a recipient refused at `RCPT` tells the peer whether a mailbox exists, and past
the ceiling the listener answers `421` and closes rather than going on
answering. `maxMessageBytes` ships at 50 MiB and accepts `65536` to
`52428800`, so it lowers and does not raise: the sealed file holding one stored
message is sixteen ninths of it, and the read path serving `BODY[]` opens at
most 96 MiB. A field you leave out keeps its shipped value.
Idle timeouts are not settable: they have floors the mail RFCs require a server
to meet, and a value under one of them refuses correct clients. The longest
command line a listener reads is set per listener as `maxLineBytes`.

Anything the server cannot honor stops the start with a message naming the
setting, where the value came from, and what was expected, down to the position
inside the value:

```
BLAMEPOST_LISTENERS at listeners.imap.port: expected a TCP port number
between 1 and 65535, got "1143x".
```

## DNS prerequisites

A mail server is only as deliverable as its DNS. Before the first message,
publish: an `MX` record; an `SPF` policy ending in `-all`; a `DMARC` policy at
`p=quarantine` or stricter; a DKIM selector record per sending domain; an
MTA-STS policy in `enforce` mode with its `_mta-sts` TXT id; a TLS-RPT
aggregate-report endpoint; and forward-confirmed reverse DNS on the sending IP.
Publish DANE/TLSA as well, but only when the zone is signed.

Left alone, this server publishes none of it. It prints the records and you put
them in the zone. Naming a hosted DNS provider in `BLAMEPOST_ZONE_PROVIDER` and
sealing a token with `blamepost zone token set` adds four read-only commands
over that: `blamepost zone preview` holds a zone up against the DKIM selector
records this server expects to find in it, `blamepost zone verify` reads each one
twice, from the provider and through a resolver, so a record that has not
propagated yet is told apart from one that resolves to something else,
`blamepost zone verify-token` asks the provider whether the sealed token is
live, and `blamepost zone allowlist` prints the names and types a write may
touch. It also lets the DMARC page in the administration console publish the
`_dmarc` record for one hosted domain through that same credential. The
setting names no provider by default, and at that default no credential is
opened and nothing is sent to a DNS provider.

The reports receivers send back to the `rua=` address in your DMARC record are
read and kept. `blamepost reports list` gives the reading a policy is moved on,
per domain: the volume counted, how much of it aligned, the sending addresses
failing both alignments largest first, and which organizations reported and when.
A hosted domain nothing has reported on says so rather than printing zeroes, and
reports whose carrier this server could not authenticate are left out of the
counting with the volume they held printed beside it. `blamepost reports show`
opens one report, and `blamepost reports forget` answers an erasure request from
somebody who has no account here.

That counting is what decides a policy step. `blamepost dmarc status` says whether
a domain's evidence carries the move from `p=none` to `p=quarantine`, and from
there to `p=reject`, with every rule printed beside what the domain has and the
`_dmarc` record text for all three levels either way. A sending address failing
both alignments holds the step until `blamepost dmarc mark` records what it is,
and the reporters contradict a claim that an address was fixed if it keeps
failing. Stepping down is not gated: `blamepost dmarc preview` prints the weaker
record without opening the data volume, so the way back is available on a server
that is down.

The DMARC page in the administration console is where that reading becomes a
record. With a hosted DNS provider named, it shows the change set publishing a
level would make at `_dmarc.<domain>`, and publishes it once the operator
confirms against that diff. The zone is read again at the moment of the write, so
a record that moved underneath stops it; afterwards the record is read back at
the provider and through a resolver, and the two disagreeing is reported rather
than read as a clean publish. Without a provider named, the page reads reports
and you put the record in the zone yourself.

[docs/operator-guide.md](docs/operator-guide.md) has the record-by-record
recipe with the exact values, followed by day-2 operations: account and domain
management, DKIM rotation, reading a zone at a hosted DNS provider, reading what
peers report about your domains, queue inspection, deletion and erasure,
preservation orders, backup and restore, and incident response.

## Vendoring

blamepost has zero npm runtime dependencies. The framework it composes is
[blamejs](https://github.com/blamejs/blamejs), published as `@blamejs/core` and
vendored under `lib/vendor/blamejs/` from the registry's own tarball. The
version, that tarball's URL, the publisher integrity digest and a hash of the
extracted tree are all recorded in `lib/vendor/MANIFEST.json`.

```bash
bash scripts/vendor-update.sh blamejs <version>  # pin a specific version
bash scripts/vendor-update.sh blamejs latest     # move to the newest release
bash scripts/vendor-update.sh --check            # fails on drift; CI runs this
bash scripts/vendor-update.sh --diff             # what changed since the pin
```

That script is the only way the vendored tree changes, and a `require` reaching
past `lib/vendor/blamejs/index.js` into the tree's internals is refused by a
repository gate. If blamepost needs something the framework does not do, the
change belongs upstream in blamejs or in this repository as a composition over
the existing surface. It never lands as a patch applied in place to the vendored
copy, because the next refresh replaces the tree wholesale and takes the patch
with it.

The trade is deliberate. One pinned tarball, verified against the digest its
publisher recorded, is auditable in a way a resolved dependency tree is not, and
a mail server that accepts bytes from anyone on the internet is the wrong place
to inherit an unreviewed transitive upgrade. Vendoring the published artifact
rather than a source checkout also means the tree here is the one operators
consume, carrying only the package's file allowlist. The refresh verifies the
digest before it extracts anything, so an archive that fails the check is never
unpacked.

## Security

Cryptographic choices are post-quantum first wherever the choice is this
project's to make: ML-KEM-1024 for key agreement, ML-DSA-65 for release
signatures, XChaCha20-Poly1305 for sealing, SHAKE256 and SHA3-512 for digests,
HKDF-SHA3-512 for derivation, and Argon2id for passwords. Stored mail,
credentials and signing keys are sealed with those primitives, so a stolen
database is not worth harvesting now to decrypt later. Each DKIM private key is
sealed to the domain, selector and algorithm it belongs to, and each stored
message body to the content digest it is filed under, so a value sealed as
anything else does not open as that key or as that message.

Mail on the wire is a different question, and the honest answer is that the
formats set the ceiling. Outbound mail carries two DKIM signatures by default,
Ed25519 and RSA-SHA256, which is the dual signing RFC 8463 §3 describes. A
receiver that cannot verify Ed25519 falls back to the RSA signature and ignores
the other, which RFC 6376 §6.1 already requires of it.

There is no post-quantum DKIM option, here or anywhere. The `a=` tag draws from
an IANA registry that has no ML-DSA value, so a post-quantum signature would be
unverifiable by every receiver on the internet rather than merely unsupported.
[ROADMAP.md](ROADMAP.md) tracks it as blocked on standardization instead of
claiming it.

TLS on the SMTP path has a ceiling of the same kind, since no receiver can make
a sender implement ML-KEM, but there is more to ask for than a default. Every
listener presents a key-agreement preference in which each preferred group holds
a ranked position of its own, first the ML-KEM hybrids and then X25519, with the
remaining curves RFC 8446 §4.2.7 registers behind them in one unranked position,
so a conforming peer is never refused. It is an order rather than a set: a peer
that supports a hybrid is asked to use it even when it offered a classical curve
first. What the preference refuses is
finite-field Diffie-Hellman, and nothing else, because no listener here accepts
an envelope on an unencrypted session and a group left off costs whole messages
rather than confidentiality. [SECURITY.md](SECURITY.md) has the detail.

Security middleware is wired into the request lifecycle rather than exposed as
config: CSRF protection, origin and fetch-metadata checks, the bot guard, sealed
storage, encrypted sessions, cookie prefixes and Trusted Types are on because
they are part of the boot sequence. No flag turns them off, and a misbehaving
mail client is a reason to fix the client rather than to relax the
authentication state machine.

[SECURITY.md](SECURITY.md) covers vulnerability reporting, the response
timeline, the responsible-use posture that comes with operating a mail server,
and the four independent trust roots on every release with copy-pasteable
verification recipes. [THREAT-MODEL.md](THREAT-MODEL.md) states what the server
defends and what it does not.

## Documentation

| | |
|---|---|
| [docs/operator-guide.md](docs/operator-guide.md) | DNS posture and day-2 operations |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the single process is put together |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Assets, adversaries, trust boundaries |
| [SECURITY.md](SECURITY.md) | Reporting, response targets, release verification |
| [ROADMAP.md](ROADMAP.md) | Capability milestones through 1.0 |
| [LTS-CALENDAR.md](LTS-CALENDAR.md) | Support windows and the pre-1.0 policy |
| [MIGRATING.md](MIGRATING.md) | One upgrade recipe per breaking change |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Local setup, house rules, the PR loop |
| [GOVERNANCE.md](GOVERNANCE.md) | Who decides what, and what happens if they stop |
| [SUPPORT.md](SUPPORT.md) | Where to ask which question |

## License

blamepost is licensed under Apache-2.0. The full text is in
[LICENSE](LICENSE), and vendored-component attribution is in [NOTICE](NOTICE).
