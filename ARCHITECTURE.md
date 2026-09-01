# Architecture

blamepost is one Node process, one data directory, one container image. This
document is the orientation map: what runs where, which primitive backs each
listener, how a message moves through, and why the shape is what it is.

## One process, all of it

Every protocol blamepost speaks is a listener inside a single process, sharing
one message store, one authentication path, one audit chain and one vault.

```text
                            ┌─────────────────────────────────────────┐
   inbound mail    :25 ───► │ mx           b.mail.server.mx           │
                            ├─────────────────────────────────────────┤
   MUA submission  :587 ──► │ submission   b.mail.server.submission   │
                   :465 ──► │                                         │
                            ├─────────────────────────────────────────┤
   MUA mailbox     :143 ──► │ imap         b.mail.server.imap         │
                   :110 ──► │ pop3         b.mail.server.pop3         │
                            │              (off by default)           │
                            ├─────────────────────────────────────────┤
   filter mgmt    :4190 ──► │ managesieve  b.mail.server.managesieve  │
                            ├─────────────────────────────────────────┤
   browser + JMAP :8080 ──► │ web app      webmail · admin · /jmap    │
                  :8443 ──► │              b.mail.server.jmap         │
                            └───────────────────┬─────────────────────┘
                                                │
                       ┌────────────────────────┴────────────────────────┐
                       │  b.mail.agent   dispatch · scopes · audit       │
                       │  b.mailStore    messages · folders · flags      │
                       │  b.db + blobs   sealed SQLite · content store   │
                       │  b.vault        sealed keys · sealed columns    │
                       └────────────────────────┬────────────────────────┘
                                                │
   outbound  egress :25 ◄───────────────────────┘  b.mail.send.deliver
```

**Nothing outside the box is required.** No queue broker, no object store, no
separate database server, no key-management service, no external identity
provider, no hosted anything. The process reads and writes one directory on one
filesystem; wipe the container and re-attach the volume and it comes back
identical. Mail flows correctly with no adjacent service at all. A spam scorer,
a virus scanner, or a TLS terminator you already run attaches through an
operator-supplied endpoint when you want one.

## Which primitive backs which listener

| Listener | Primitive | What the primitive owns |
|---|---|---|
| Inbound MX, `:25` | `b.mail.server.mx` | The RFC 5321 state machine, SMTP-smuggling defense at the wire layer, and the gate cascade. blamepost arms HELO discipline, envelope screening, and SPF / DKIM / DMARC / ARC evaluation at DATA, after which the primitive writes the `Authentication-Results` header (RFC 8601) on the way in. Only the first three reach the disposition; the ARC result is written down and nothing else. The RBL and greylisting gates are wiring points the primitive accepts and this release passes nothing to |
| Submission, `:587` / `:465` | `b.mail.server.submission` | RFC 6409 submission and RFC 8314 implicit TLS, SASL AUTH (RFC 4954) offering PLAIN, and the binding of the authenticated account to `MAIL FROM` |
| IMAP, `:143` | `b.mail.server.imap` | IMAP4rev2 (RFC 9051), CONDSTORE and QRESYNC modseq synchronization (RFC 7162), literal-framing and command-shape refusal |
| POP3, `:110` | `b.mail.server.pop3` | RFC 1939 with STLS (RFC 2595). Off by default; a fallback for clients that cannot speak IMAP |
| ManageSieve, `:4190` | `b.mail.server.managesieve` | RFC 5804 script upload, activation and listing, with validation before storage |
| JMAP, `/jmap` on the web app | `b.mail.server.jmap` | JMAP Core (RFC 8620) and JMAP Mail (RFC 8621) as an HTTP-mounted handler |
| Webmail and admin, `:8080` / `:8443` | the blamejs web app | Routing, session handling, the security middleware chain, and server-rendered HTML |
| Outbound delivery | `b.mail.send.deliver` | MX resolution, MTA-STS enforcement (RFC 8461), DANE (RFC 7672), retry scheduling, and DSN generation (RFC 3464). REQUIRETLS (RFC 8689) is carried as far as the transport and no further, so it is refused rather than advertised |
| Filtering | `b.mail.sieve` | The RFC 5228 interpreter that produces the action list the delivery step applies |

Every protocol's mailbox verb arrives at one adapter,
`blamepost.mail.mailbox`, which resolves the authenticated account before it
touches a row, so a session reaches its own folders and nothing else.
Destruction goes one step further and routes through `b.mail.agent.expunge`,
which is where the retention floor and the legal-hold substrate are enforced
and where the audit row is written. IMAP `EXPUNGE`, the POP3 `DELE` set as it
commits at `QUIT`, JMAP `Email/set` with `destroyed` and the webmail purge all
arrive there. No wire handler reaches the store's destructive path directly, so
a deletion cannot escape a retention rule by arriving over a different protocol.

## Storage

One directory holds everything.

```text
/var/lib/blamepost/
├── db.enc                   the encrypted SQLite database: accounts, domains,
│                            aliases, folders, the message index, flags, quotas,
│                            Sieve scripts, the audit chain
├── db.key.enc               that database's key, sealed by the vault
├── vault.key.sealed         the vault keypair, sealed under the passphrase
├── audit-sign.key.sealed    the audit-chain signing keypair, sealed likewise
├── blobs/                   message bodies and attachments, content-addressed
├── queue/                   the outbound spool
├── keys/                    DKIM private keys, sealed by the vault
└── tls/                     the certificate and key the operator supplies
```

The three sealed key files at the root are the reason the passphrase has to
survive independently of the volume. Every one of them opens only under it, and
nothing in the directory can be read without them.

**Three more files come and go beside those, and none is drawn above because
none is always there.** `blamepost.lock` names the process holding the volume
and exists only while one does. `audit.tip` records where the audit chain stood
when it was last anchored, as a counter and a row hash in plaintext, and is
written each time a checkpoint is. `audit.disputed` is written only when that
record disagrees with the rows, and while it exists the volume refuses to open
at all, so a rewritten trail is not appended to while somebody works out what
happened.

**One passphrase opens the mail and signs the audit trail, and that sets the
boundary the trail's guarantee stands on.** `audit-sign.key.sealed` is the key
whose signature makes a checkpoint unforgeable, and it opens under the same
passphrase as `db.key.enc`. So the trail is evidence against anyone who reaches
the volume without that secret, and it is not evidence against anyone who holds
it: they can rewrite every row, sign the result, and rewrite `audit.tip`, which
is a plain unsigned file on the same volume. Splitting the two secrets would not
change that, because the process needs both to run. What answers it is a copy of
the rows shipped as they are written to somewhere this server cannot reach.

**The database holds the index, not the bytes.** The message store is the
framework's `b.mailStore`, created once over `b.db` and shared by every
listener, so message storage has one implementation and blamepost is not it. The
store opens a transaction through that handle for every append and every hard
delete, and settles which calling convention the handle offers by whether the
body ran, so the database goes in with nothing in between; a handle it can get
no transaction out of at all is refused rather than written to outside one. The
store keeps per-message metadata queryable in plaintext: the stable object id,
the modseq counter, internal date, flags, size, thread root and legal-hold
marker. Beside those sit the sealed fields that would be PII in a database dump:
subject, sender, recipients, and the extracted text and HTML parts. Message
bodies live in `blobs/`, addressed by the digest of their content, so an
identical attachment delivered to twenty accounts is stored once and each
mailbox references it.

**A mailbox holds the intersection of the two rows, not either one alone.** The
store's row and the row beside it carrying the IMAP unique identifier and the
folder are written by different calls and can come apart, so membership is
decided in a single place as the messages both records answer for, and every
projection over it (`EXISTS`, `FETCH`, `SEARCH`, the POP3 listing, the delete
path) reads that one list rather than querying for itself. A row on either side
without its partner is left out rather than served half. The read that decides it
raises its own bound and asks again until the store's answer comes back short of
the bound it was given, because a bounded read that returns exactly as many rows
as it was allowed cannot say whether it was truncated, and a truncation would
drop a paired message rather than the unpaired one that caused it. Each way the
pair can separate carries an audit action of its own, so a message the store
holds that no mailbox names, and a row here whose store partner has gone, are
both named where they happen.

**Sealed by default.** Columns carrying mail content are sealed through the
vault's AEAD envelope before they reach disk, with the authentication tag bound
to the column's identity, so a sealed value copied between rows fails to open
rather than disclosing itself somewhere it does not belong. Forensically useful
columns stay queryable in plaintext: object ids, timestamps, flags, sizes,
hold markers, and the hash columns that make sealed-field lookups possible
without unsealing.

**DKIM private keys never sit in plaintext.** They are sealed under the vault
passphrase in `keys/`, unsealed into memory at boot, and used in-process. There
is no signer container to reach over a socket and no secret to hand to a
sidecar.

## Boot order

Ordering is load-bearing; each step depends on the one above it.

1. **Config.** The file at `BLAMEPOST_CONFIG` is read if present, then the
   environment is merged over it. A bad value throws here, at the entry point,
   rather than surfacing as a strange failure on the wire an hour later.
2. **Vault.** The keypair is loaded, or generated on first run, from
   `BLAMEPOST_VAULT_PASSPHRASE`. Sealed columns, sealed DKIM keys and the signed
   audit chain all depend on the key being present.
3. **Schema and store.** SQLite opens, the schema is created if absent, and the
   audit chain is verified. A chain that does not verify refuses further appends
   rather than quietly continuing. Opening the database also samples the clock
   against public NTP servers over UDP port 123, because the audit chain's
   timestamps stop meaning anything once the clock has moved: a reading more
   than an hour out refuses the boot. It is the one outbound connection the boot
   makes to a party the operator did not name, and an egress filter that blocks
   it costs the query's timeout and a logged warning rather than the boot. Set
   `BLAMEJS_NTP_SERVERS` to sample a time source you run instead, or
   `BLAMEJS_SKIP_NTP_CHECK=1` to drop the sample and the drift warning with it.
4. **DNS posture gate.** The gate takes two confirmations: the server's,
   supplied as `BLAMEPOST_DNS_ACKNOWLEDGED=1`, and each active domain's, written
   by `blamepost domain acknowledge`. Without both the MX listener does not
   bind, so a domain added after the variable was set is gated on its own
   records rather than on an older confirmation. The other listeners still
   start, so an operator can configure domains and accounts before accepting
   mail.
5. **TLS.** The certificate and key come from `BLAMEPOST_TLS_CERT` and
   `BLAMEPOST_TLS_KEY`. The pair is read before anything binds, so a certificate
   whose validity has closed stops the boot instead of producing listeners that
   refuse every connection. Both files are then watched, and a renewal written
   in place reaches the running server two ways: the mail listeners read the
   certificate per connection, and the web listener, which builds its own TLS
   context out of the bytes and cannot read one per connection, is handed the
   renewed pair on the reload and installs it on the bound server. Every port
   takes the renewal, so no restart is part of it. The list of ports a reload
   does not reach is asked of each layer rather than written down, so a port
   that stops rotating is named without an edit, and the reload prints that list
   when it is not empty. Every mail listener requires a TLS context to boot,
   so no implicit plaintext mode exists, and a server with no certificate
   refuses to start rather than binding something it cannot encrypt. The health
   probes read the pair on every poll, so a renewal that stopped running reduces
   the verdict to `degraded` while there is still time to act.

   The two routes to a context also have to agree on what they accept, so the
   key-agreement preference is composed once, by
   `blamepost.mail.listeners.keyAgreementGroups`, and read by both. The mail
   listeners hand it to the certificate loader; the web listener puts it beside
   the certificate bytes it passes to the framework's HTTP listener. A second
   spelling of it in either place is two halves of one server accepting
   different sets, which is a divergence nothing on the wire announces.
6. **Web app.** The router and the middleware chain come up, JMAP mounts at
   `/jmap`, and the webmail and admin routes mount on top.
7. **Mail listeners.** Each enabled listener binds its port.

Shutdown reverses it: listeners stop accepting, in-flight sessions drain, the
queue checkpoints, and the store closes last.

## The request path

A browser request crosses the same middleware chain every time, composed from
blamejs and not exposed as configuration, in this order: request id, security
headers, bot guard, cookies, CSP nonce, fetch-metadata checks, body parsing,
CSRF, session attach, and the cache posture. A rate limit sits on the sign-in
path specifically, because that is the one an attacker replays. Webmail and
admin routes run after that chain, never beside it. There is no cross-origin
sharing layer, because nothing here is meant to be called from another origin.

The JMAP handler mounts inside the same chain. A JMAP client authenticates the
way a browser does and is rate-limited the way a browser is; it does not get a
side entrance.

Validation happens once, on the server. The webmail UI renders what the server
decided; it does not carry a second copy of the rules for the browser to
re-check, because two copies of a rule is one copy that will drift.

## Inbound: a message arriving

1. **Connection.** `b.mail.server.mx` accepts and applies the connection-level
   budget, then runs HELO discipline against the one resolver this server
   shares across every mail path. That resolver is not configurable: no setting
   names its upstream, so it asks the vendored framework's default DNS-over-HTTPS
   endpoint unless an embedder passes `blamepost.create` a resolver of its own.
   The
   budget is keyed on the peer address and covers concurrent connections,
   connection rate and recipient failures. Two further bounds are not keyed on
   the address: a floor of a hundred bytes a second on the message body, which
   answers `421 4.7.0` and cuts a peer that has slowed rather than stopped, and
   a ceiling of 1024 accepted sockets on the listener as a whole. The idle
   timeout still covers the peer that stops sending altogether.
   [ROADMAP.md](ROADMAP.md) carries the detail under Rate limiting.
2. **Envelope.** `MAIL FROM` and each `RCPT TO` are screened, and recipients are
   resolved against the hosted domains and aliases. A recipient in a domain this
   server does not host is refused at `RCPT`; a recipient in a hosted domain with
   no mailbox behind it is refused after `DATA`, for the reason under threat
   class 1 in [THREAT-MODEL.md](THREAT-MODEL.md).
3. **DATA.** The body is read under a size cap, MIME structure is screened, and
   the authentication pass runs: SPF against the connecting IP, DKIM over the
   signed headers, DMARC over the aligned result, and the ARC chain (RFC 8617)
   a forwarder or a mailing list left behind. The verdict lands in an
   `Authentication-Results` header, and any header a sender attached claiming
   this server's name is removed before that one is written, so a filter reads
   the receiver's finding and not the sender's.
4. **Policy.** The DMARC policy of the sending domain decides accept, quarantine
   or reject. The ARC result is not part of that decision: a chain is worth what
   its sealer is worth, and there is no setting naming the sealers an operator
   vouches for, so a chain that validates cannot lift a DMARC failure and a
   broken one cannot cause a refusal. What acts on it is the recipient's own
   Sieve script, which reads the `arc=` result out of the header at step 5.
5. **Filtering.** The recipient's active Sieve script runs on the interpreter,
   under a gas counter so a runaway rule cannot stall delivery. `fileinto`,
   `keep` and `discard` are dispatched. `redirect` and `vacation` both need to
   put a message on the wire, so each is refused with an audit row and the
   message is kept rather than dropped.
6. **Store.** The body is written to the blob store, the index row is appended
   through `b.mailStore`, the folder's modseq advances, and threading is
   resolved from `Message-Id`, `In-Reply-To` and `References` at append time so
   thread reads are a single index lookup.
7. **Notify.** IMAP sessions with the folder selected see the new message
   through their existing connection; JMAP clients see the state string change.

A malformed command, a bad literal, or a body that violates the framing rules is
refused loudly with the protocol's own error code. Nothing is tolerated "for
compatibility". Every parser CVE in this product category started as a
tolerance.

## Outbound: a message leaving

1. **Submission.** `b.mail.server.submission` requires AUTH before `MAIL FROM`
   and then checks that the authenticated account actually owns the envelope
   sender. A mismatch is refused at the wire with `553 5.7.1 Sender address
   rejected: not owned by authenticated identity`, before any recipient is
   accepted, which stops a compromised credential from being used to forge
   another account's identity. The `From` header is bound separately, against a
   wider set: the account's own address plus every active alias landing in its
   mailbox, canonical so a subaddress folds, and never a catch-all. The webmail
   and JMAP surfaces compose their own envelope and read that same set, so an
   account can write an alias as the author there; a client on the submission
   port puts the alias in both places and is stopped by the envelope binding.
2. **Signing.** The message is signed in-process, as the DKIM section below
   describes.
3. **Spool.** The envelope enters `queue/`, durable across restarts.
4. **Delivery.** `b.mail.send.deliver` resolves the recipient's MX, applies the
   MTA-STS policy for that domain, checks TLSA records when the zone is signed,
   and delivers over TLS. REQUIRETLS (RFC 8689) is not requested: the parameter
   does not reach the wire, so the setting that asks for it is refused at boot
   rather than reporting a protection no receiver is ever asked to apply.
5. **Retry and DSN.** Temporary failures back off and retry; permanent failures
   and expired retries generate a DSN back to the sender.

Every outbound path goes through step 4: submission relay, an alias forwarding
off this server, and the delivery status notifications the server composes on
its own behalf. A repository gate refuses a raw transport call anywhere in
`lib/`, because a second sender that skips MTA-STS is a downgrade attack
waiting for a maintainer in a hurry.

Step 4 reaches the socket. The composer calls the framework's SMTP transport,
the transport opens the connection, and the bytes written after `DATA` are the
bytes the message arrived with rather than a copy rebuilt from parsed fields, a
body that is not valid UTF-8 included. Whether a build can send at all is
measured rather than remembered: `blamepost doctor` asks the framework surface
for the transport the composer reaches for at the first send and reports the
answer under `outbound delivery`, and both health probes carry the same reading,
so a build that cannot send says so at boot rather than leaving an operator to
infer it from a queue that stopped draining.

## DKIM: two signatures, one message

Each sending domain carries two selectors, and every outbound message gets both
signatures:

- **An Ed25519 selector** (RFC 8463), publishing `k=ed25519`. Shorter key,
  shorter record, and what a modern verifier prefers.
- **An RSA-SHA256 selector** (RFC 6376), publishing `k=rsa` and named after the
  first with an `-rsa` suffix. It exists for receivers that still do not
  implement Ed25519, which remains a meaningful share of them.

These are the two algorithms the `DKIM-Signature` `a=` tag admits, so the pair
is set by the wire format rather than chosen. There is deliberately no
post-quantum selector: the `a=` registry has no ML-DSA value, so publishing an
invented one would produce signatures no receiver could verify while advertising
a guarantee the domain does not have. ROADMAP.md tracks post-quantum DKIM as
blocked on standardization.

A receiver evaluates whichever signature it understands and skips the other.
RFC 6376 §6.1 already requires a verifier to handle multiple signatures and to
keep going past ones it cannot check, so carrying both costs a little DNS and
buys authentication at receivers on either side of the RFC 8463 line.

Signing runs inside the process that holds the sealed key. That leaves no signer
service to reach, no socket to secure, and no window where an unsealed key
crosses a process boundary. The pair is not separable: both selectors sign every
message, no setting turns one algorithm off, and retiring names a pair and takes
both halves, so a receiver that mishandles the second header has no per-domain
answer here. Rotation keeps the retiring selector published for seven days so
signatures on in-flight mail and their bounces still verify.

## Why the framework is vendored

blamejs lives under `lib/vendor/blamejs/` as the published npm tarball for one
pinned version, recorded in `lib/vendor/MANIFEST.json` and changed only by
`scripts/vendor-update.sh`.

1. **One chokepoint, auditable.** A pinned version and a manifest entry are a
   thing a person can read. A resolved dependency tree is not. Upgrading is a
   reviewed, single-commit event rather than a lockfile diff nobody opens.
2. **The transitive tree is visible.** The framework's own vendored bundles come
   along inside the tree, with their manifest, so the full set of third-party
   code is enumerable from the repository rather than from a package manager's
   cache.
3. **Integrity is checked where the bytes arrive.**
   `scripts/vendor-update.sh` refuses to extract anything until the publisher's
   `dist.integrity` digest verifies, fails closed when the registry publishes no
   integrity value at all, and records the version, that digest, the resolved
   tarball URL and a hash of the extracted tree in `lib/vendor/MANIFEST.json`.
   `vendor-update.sh --check` then measures the pinned version against the
   registry on every run, so a pin that stopped moving blocks a release. The
   running process does not re-verify the tree at boot. The recorded tree hash
   is re-measured by `scripts/check-vendor-integrity.js`, which runs in the
   `npm run gates` chain, so a tree that drifted from the manifest fails a
   static gate rather than reaching a boot that would load it unchecked.
4. **The alternative is worse here than elsewhere.** A mail server parses
   attacker-supplied bytes from anyone who can reach port 25. Inheriting an
   unreviewed upgrade into that surface is not a risk worth the convenience.

The tree is read-only. Anything blamepost needs that the framework does not do
goes upstream to blamejs, or gets composed here from the surface that already
exists.

## The release pipeline

Every release carries four trust roots, each verifiable without trusting the
other three. [SECURITY.md](SECURITY.md) has the operator-side recipes.

1. **A signed commit and a signed tag.** SSH-signed, with the tag's commit
   confirmed to be on `main`'s first-parent history and to have arrived through
   a merged pull request rather than a direct push or a rewritten tag.
2. **SLSA L3 provenance.** An in-toto attestation binding the artifact bytes to
   the exact workflow run, commit and tag that produced them.
3. **Sigstore-keyless SBOM signatures.** The project's own SBOM and the vendored
   tree's are both signed through the workflow's OIDC identity, with the
   issuance recorded in the public transparency log.
4. **Byte digests and a post-quantum sidecar.** SHA-256 and SHA3-512 over the
   artifact, plus an ML-DSA-65 signature verifiable with the framework's own
   primitive and the public key committed in-tree at `keys/release-pqc-pub.json`.
   Until that key is generated the sidecar step skips with a warning and the
   other three roots still ship; [SECURITY.md](SECURITY.md) records the state it
   is in.

They chain: the signed tag covers the commit that carries the public key file,
the public key verifies the sidecar, and the sidecar covers the artifact bytes.
Tampering with any one root is detectable from the others.

## Tests

```text
test/layer-0-primitives/   pure functions, parsers, config, static gates
test/layer-1-state/        anything touching the database, vault or store
test/layer-2-integration/  real listeners on ephemeral ports, wire-level
test/smoke.js              the single entry point, walks the layers in order
```

Layer 0 covers primitives with no database, no network and no vault. Layer 1
spins an isolated data directory per test and exercises the store, the vault,
sessions and the queue. Layer 2 binds real listeners and drives them the way a
client does, through an SMTP conversation, an IMAP session or a JMAP request. It
includes the adversarial shapes: a bare CR in a literal, a smuggled dot
sequence, a `MAIL FROM` the authenticated account does not own.

`node test/smoke.js` is the single entry point and walks every layer in
dependency order, layer 2 included. Almost all of that layer builds its
listeners inside the test process on ephemeral loopback ports, so it needs
nothing installed. The few files that drive the shipped container image declare
that themselves by calling the integration harness's engine gate; the engine is
probed once through that same harness before anything runs, and a file that
needed one is named and counted as skipped rather than folded into the pass
count. `SMOKE_REQUIRE_CONTAINER=1` makes an absent engine refuse the whole run
instead, which is what a release or a CI runner wants: the tool being missing is
the finding rather than something to route around.

New behavior lands with a test that fails on the current tree and passes on the
fix, driving the real path a client would take rather than a hand-built internal
call. Where a bug is structural rather than local, a detector in
`codebase-patterns.test.js` refuses the shape that caused it, so the class
cannot come back somewhere else.

## Repository layout

```text
bin/blamepost.js       CLI: serve, init, account, domain, dkim, queue, doctor,
                       blobs, audit, backup, restore
lib/index.js           the composition facade over the vendored framework
lib/config/            config loading, schema validation, environment merge
lib/mail/              listener composition, delivery, DKIM, Sieve, auth
lib/store/             accounts, domains, aliases, address routing
lib/web/               server-rendered webmail and admin
lib/web/views/         HTML templates
lib/web/public/        static assets and opt-in JavaScript islands
lib/vendor/blamejs/    the vendored framework
docker/                configuration for the optional services compose.yml offers
docs/operator-guide.md DNS posture and day-2 operations
scripts/               release, currency, pinning and changelog tooling
test/                  the layered suites and smoke.js
keys/                  the ML-DSA-65 release-signing public key, once generated
release-notes/         structured release source, one file per minor line
Dockerfile             the all-in-one image
compose.yml            the same image plus optional adjacent services
```

## Where to read first

1. `bin/blamepost.js`: how the process starts and what the CLI dispatches.
2. `lib/config/`: every setting, its default, and where it is validated.
3. `lib/index.js`: the composition facade, and which framework primitive backs
   what.
4. `lib/mail/`: listener wiring and the delivery path.
5. `lib/store/`: the account, domain, alias and routing tables.
6. `lib/web/`: the route table and the middleware chain.
