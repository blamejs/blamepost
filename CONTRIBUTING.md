# Contributing to blamepost

Thanks for considering a contribution. blamepost is a mail server with firm
architectural defaults, and this document is the guide to getting a patch
through them cleanly.

## Quick links

- **Found a bug?** Open an issue with the bug-report template. For a security
  bug, do not open a public issue. Report it privately, following
  [SECURITY.md](SECURITY.md).
- **Have a feature idea?** Open a feature-request issue first so the design gets
  discussed before code is written. See "Ship complete" below for why, and check
  [ROADMAP.md](ROADMAP.md) for what is already targeted or accepted.
- **Ready to write a fix?** Read [Development setup](#development-setup),
  [House rules](#house-rules) and [The PR loop](#the-pr-loop).
- **Just want a working server?** [README.md](README.md) for the container,
  [docs/operator-guide.md](docs/operator-guide.md) for DNS and day-2 operations.

## Development setup

```bash
# 1. Clone. There are no npm runtime dependencies; the install only fetches
#    dev tooling, and on many days you do not need it at all.
git clone https://github.com/blamejs/blamepost.git
cd blamepost

# 2. Optional. The vendored framework is committed under lib/vendor/blamejs/
#    and comes with the clone, so run this only to change the pinned version.
bash scripts/vendor-update.sh blamejs latest

# 3. Run the suite. This is the single entry point and walks every layer.
node test/smoke.js

# 4. Boot a real server against a scratch data directory. Every command needs
#    these two and refuses to run without them; `serve` also needs
#    BLAMEPOST_TLS_CERT and BLAMEPOST_TLS_KEY, while `init` and `doctor`
#    deliberately run before a certificate exists.
export BLAMEPOST_HOSTNAME=mx.example.com
export BLAMEPOST_VAULT_PASSPHRASE='a long enough local development passphrase'

node bin/blamepost.js init  --data-dir ./data --admin-email admin@example.com
node bin/blamepost.js serve --data-dir ./data

# 5. Static gates. `npm run gates` is the chain package.json declares and
#    the chain CI runs on your pull request, so run that rather than a
#    list of its members: the list lives in one place and is the same
#    thing CI executes.
npm run gates
npx eslint@latest --max-warnings 0 .
shellcheck $(git ls-files '*.sh')
node scripts/generate-changelog-entry.js --check
node scripts/consolidate-release-notes.js --check
bash scripts/vendor-update.sh --check

#    One gate is yours alone. `node scripts/check-operator-prose.js` needs
#    a checker installed on your machine, which no hosted runner carries,
#    so CI declares it off and says so in its log. Nothing downstream will
#    catch what it catches; run it before you open the pull request.
node scripts/check-operator-prose.js

# 6. Step 3 already ran the wire-level tests. Almost all of them bind real
#    listeners on ephemeral loopback ports inside the test process, so they
#    need nothing installed. The few files that drive the shipped container
#    image are named and counted as skipped when no container engine answers.
#    This makes an absent engine refuse the run instead, which is what CI and
#    a release want:
SMOKE_REQUIRE_CONTAINER=1 node test/smoke.js
```

**Requirements:** Node.js 24.22.1 or newer, which is the version `engines.node`,
`.nvmrc` and every workflow pin state. Nothing is transpiled, so the source
in the repository is the code the runtime executes. Binding ports below 1024
locally needs root or `CAP_NET_BIND_SERVICE`; the test suite uses ephemeral
ports and does not.

Use `example.com`, `example.org` and `example.net` in every test fixture,
example and doc snippet. They are reserved for exactly this (RFC 2606), and a
real domain in a fixture eventually sends real mail to a stranger.

**Adding a gate to the chain?** It has to publish what it examined. Print
`EXAMINED <n> <unit>` as the last lines of standard output, one line per
unit, on a passing run and a failing one alike. The release flow reads
those and refuses a gate that exited clean having examined nothing,
because a clean verdict over an empty set answers for no part of the
tree, and a gate whose file discovery quietly stopped matching is
otherwise indistinguishable from one with nothing to report.

Pick the unit that would have to move for the gate to be doing its job,
and publish two when two can fail on their own. Counting source files
alone is not enough for a gate that then extracts something from them:
twenty-two files yielding zero blocks proves exactly as little as zero
files. Count what you walked and count what you actually applied the
rules to.

A self-test is welcome and is not a substitute. Proving the checker
still fires on a planted example says nothing about whether it reached
your files, and a checker can pass its own self-test while reading none
of the tree.

**Writing a gate over the `@primitive` blocks?** Take the list from
`scripts/source-primitives.js`. It binds the documentation block reader
in `lib/web/wiki/blocks.js` to this repository and carries every tag any
gate needs. The wiki at `/wiki` is built by the same reader. Do not add a
second pattern that finds the blocks again. A gate governs exactly the
set it found, so two lists built by two walks agree only until one of
them cannot see a block, and that disagreement is silent in the direction
that costs: a primitive your pattern misses is one your gate reports
nothing about, and it still exits clean. The api snapshot, the lifecycle
schedule, the block validator and the wiki all read that one reader, and
a pattern matching a documentation tag anywhere else fails the detector
suite.

## What lands where

| The change is… | It belongs in… |
|---|---|
| Listener wiring, delivery, DKIM, Sieve, authentication composition | `lib/mail/` |
| Schema, message index, blob handling, quota accounting | `lib/store/` |
| A setting, its default, or its validation | `lib/config/` |
| A webmail or admin route, template or asset | `lib/web/`, `lib/web/views/`, `lib/web/public/` |
| A CLI subcommand or flag | `bin/blamepost.js` |
| Container entrypoint, healthcheck, optional-service wiring | `docker/`, `Dockerfile`, `compose.yml` |
| Release, currency, pinning or changelog tooling | `scripts/` |
| DNS posture or a day-2 operator procedure | `docs/operator-guide.md` |
| Anything an operator will notice after upgrading | `release-notes/v<X>.<Y>.<Z>.json`, which is folded into `release-notes/v<X>.<Y>.x.json` and regenerates `CHANGELOG.md` |
| A framework primitive, a protocol parser, a crypto envelope | upstream in [blamejs](https://github.com/blamejs/blamejs) |

That last row is the one people get wrong. blamepost composes the framework. It
does not extend it in place. `lib/vendor/blamejs/` is read-only, and a
repository gate refuses any `require` that reaches past its entry point into the
tree's internals. If the framework is missing something, file it there and
compose around it here in the meantime. A patch applied to the vendored tree is
discarded by the next refresh without telling anyone, which is the reason the
rule is absolute rather than a preference.

Add to the file that already owns the domain. A new module needs a genuinely new
domain to justify itself, not a new function.

## House rules

These are hard. A patch that violates one gets bounced regardless of how clean
it reads.

### Zero npm runtime dependencies

The server ships with none, and vendors exactly one thing: the framework, as a
published registry tarball extracted under `lib/vendor/blamejs/` and pinned in
`lib/vendor/MANIFEST.json`. `scripts/vendor-update.sh` is the only way that tree
changes.

If you think a new library is needed: it almost certainly is not. The framework
already covers the wire protocols, the crypto, the storage, the HTTP surface and
the guards. If it genuinely does not, the answer is upstream, not a second entry
in `package.json`. Expect substantial pushback on any proposal that adds one.

### Post-quantum first

Every signature, key agreement, digest, derivation and password hash goes through
the framework's primitives: ML-KEM-1024, ML-DSA-65, XChaCha20-Poly1305,
SHAKE256, SHA3-512, HKDF-SHA3-512, Argon2id. Do not introduce AES-GCM, SHA-256
or a classical-only key exchange as an application default. Classical algorithms
appear where a wire format requires them, such as the Ed25519 DKIM selector and
TLS negotiation with a receiver. They appear beside a post-quantum choice, not
instead of one.

DKIM signs with both selectors, Ed25519 and RSA-SHA256, and the pair is not
separable: no setting turns one algorithm off, and retiring names a pair and
takes both halves. A proposal to make the choice per-domain owes an answer to
what the domain signs with while the half it still holds is being withdrawn,
which is the part that makes this a feature rather than a flag.

### Wire-protocol readers refuse loudly

Malformed SMTP, IMAP, POP3, ManageSieve or JMAP input is refused with the error
code that protocol defines, at the point it is read. Never tolerate a malformed
shape "for compatibility" and never repair one silently. Every parser CVE in this
product category began as a tolerance that seemed harmless, and the Dovecot,
Exim and Stalwart catalogues all have them.

That is one of four validation postures, and you pick consciously:

- **Config-time and entry-point:** throw. A bad setting fails at boot, where the
  operator is watching.
- **Wire-protocol readers:** refuse loudly with the protocol's own code.
- **Hot-path observability sinks:** drop silently inside a `try` / `catch`. A
  metrics write must never take down a delivery.
- **Defensive request-shape readers:** return a documented default for a
  missing or garbage field.

### Security defaults are not configuration

CSRF, origin and fetch-metadata checks, the bot guard, sealed storage, encrypted
sessions, cookie prefixes and Trusted Types are wired into the request lifecycle
by composing framework middleware. They are not behind flags, and a patch that
adds a flag to switch one off will not land.

A misbehaving mail client is a reason to fix the client. It is not a reason to
relax the submission authentication state machine.

Tests exercise the production code path. No `NODE_ENV=test` branch skips
encryption or authentication. A test that passes because it took a different
path has tested nothing.

### One path for the dangerous operations

- **Submission is identity-bound.** SASL AUTH binds the authenticated account to
  `MAIL FROM`. An envelope sender the account does not own is refused at the wire
  with `553 5.7.1 Sender address rejected: not owned by authenticated identity`,
  before any recipient is accepted.
- **Deletion routes through `agent.expunge`.** IMAP `EXPUNGE`, POP3 `DELE` and
  JMAP `Email/set` with `destroyed` all arrive there, because that is where the
  legal-hold substrate is enforced, and the retention floor with it when the
  operator has set a compliance posture. Never call the store
  directly from a wire handler.
- **Outbound goes through `b.mail.send.deliver`.** MX resolution, MTA-STS, DANE,
  REQUIRETLS, retry and DSN live in that one composer, and a detector refuses a
  raw transport call anywhere in `lib/`. A second sender that skips MTA-STS is a
  downgrade attack with a maintainer's name on it.
- **Account deletion archives by default.** Destroying requires an explicit
  `destroy: true` and a recorded reason, because an erasure is irreversible and
  the archive path is what an operator actually wants nine times in ten. An
  erasure reaches the account's mail as well as its row, through the mailbox
  adapter's own verb, so the retention floor and the preservation-order gate run
  exactly as they run for a wire delete. Erasing the row alone leaves the
  mailboxes, the message rows and the sealed bodies on the volume with nothing
  left to release them, and a detector refuses that shape.

### Code style

- **CommonJS only.** `require()` and `module.exports`. No ES module syntax in
  `lib/`. The ESLint config and the workflow files are the documented
  exceptions.
- **`var` declarations**, not `let` or `const`, for consistency with the rest of
  the tree and with the framework.
- **No TypeScript, no transpilation.** What ships is what runs, and every build
  step is one more hop in the supply chain.
- **Every `.js` file starts** with the SPDX line, the copyright line, and
  `"use strict";`, in that order.
- **Top-of-file `require()`s.** An inline require needs a comment on the line
  explaining the circular dependency that forced it.
- **Backend validates, frontend displays.** No duplicate validation shipped to
  the browser. Server-rendered first; client JavaScript is an opt-in island.
- **Reach for a framework primitive before writing a helper.** If you find
  yourself parsing a header, screening a filename or comparing a secret by hand,
  the framework already has it.

### Ship complete

Every primitive is designed for a defensible first release rather than a minimum
version with the interesting parts left for another day. Before a feature PR,
list the full surface in the issue, re-derived from the governing RFC: every
verb the RFC defines, every response code, every documented failure mode. Say
what is in, what is not, and why each exclusion is a decision rather than an
unfinished edge.

A recorded decision not to build a slice, with the condition that would reopen
it, is complete. A bullet promising an unnamed release is not, and a pre-commit
grep refuses the vocabulary that usually carries one.

## Mail-stack rules

Mail has failure modes that ordinary web work does not, and these follow from
them.

- **A DNS-affecting change updates `docs/operator-guide.md` in the same PR.** The
  recipe moves with the patch whenever what an operator must publish changes: a
  new selector convention, a changed policy field, a different record. An
  operator following a stale record set has a silently undeliverable domain and
  no error to search for.
- **Anything touching a wire protocol runs the wire-level suite.** `node
  test/smoke.js` is the whole command, and the PR says so. Read the run's own
  skip list rather than the check count: a file that drives the shipped
  container image is named and counted as skipped when no engine answers, and a
  skipped file is not a passing one. A self-round-trip through our own parser
  proves that the parser agrees with itself.
- **Test against a real client where one exists.** A change to the IMAP surface
  is worth a session from an actual MUA; a change to submission is worth a real
  send. Clients disagree with the RFC in specific, known ways, and finding out
  which way after a release is expensive.
- **Never widen an authentication state machine to accommodate a client.** Fix
  the client, or refuse the client. The state machine is the only thing standing
  between an open relay and a working server.
- **A new sending path is not a new sender.** Route it through the existing
  delivery composer.
- **Retention and legal hold are not optional on a delete path.** If you are
  adding a way to remove a message, it goes through the expunge path or it does
  not go.
- **Mind deliverability in defaults.** A permissive SPF suggestion, a lax DMARC
  example or an unsigned notification path makes a domain look like a spammer.
  Each is a bug even when every test passes.

## Developer Certificate of Origin

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/). Adding a
`Signed-off-by` line to each commit certifies that you wrote the patch, or
otherwise have the right to submit it, under the project's Apache-2.0 license.
Sign off with `git commit -s`; the sign-off must match the commit author.

## The PR loop

1. **Open an issue first** for anything non-trivial. Design discussion catches a
   scope problem before the code exists. Typos, doc corrections and single-line
   fixes can skip it.
2. **Branch off `main`.** The branch name does not matter; merges are squashed.
3. **One concern per PR.** A listener change with its tests and its operator-doc
   update is one PR. That change plus an unrelated lint cleanup is two.
4. **Verify before pushing.**
   - `node test/smoke.js` finishes with a check count no lower than the last
     release.
   - That same run skips no file when the diff touches a wire protocol,
     delivery, or the store. Start a container engine if it does, or run
     `SMOKE_REQUIRE_CONTAINER=1 node test/smoke.js` so an absent one refuses
     rather than skips.
   - `npx eslint@latest --max-warnings 0 .` exits 0.
   - `node test/layer-0-primitives/codebase-patterns.test.js` exits 0, so the
     structural detectors are clean.
   - `node scripts/check-operator-prose.js` exits 0, so nothing operator-facing
     carries internal narrative.
   - `node scripts/check-forbidden-vocabulary.js` exits 0, so no file uses the
     commercial product terms listed in that script.
   - `bash scripts/vendor-update.sh --check` exits 0, so the vendored tree
     matches its pin.
   - `shellcheck $(git ls-files '*.sh')` exits 0.
5. **Read the log, do not re-run the script.** `.test-output/smoke.log` holds
   every line of the last run through synchronous writes. When something fails,
   that file already has the answer.
6. **Commit message style:** lowercase imperative, one-sentence first line. The
   body says why and what the tradeoff was, and cites the governing RFC or CVE.
   It carries no internal narrative: no phase or batch vocabulary, no "modeled on
   X", no claim that the tests pass. Operators read these when they upgrade.
7. **Open the PR** and wait for CI with `gh pr checks --watch`.
8. **Review focuses on:** does this match the patterns already here; is
   malformed input a loud refusal rather than a quiet repair; did you sweep the
   tree for the one-off code this change replaces; does a delete or a send route
   through the single path; does the operator doc still describe reality.

## Releasing

Maintainers cut releases; contributors do not need this, but the shape explains
why some review comments ask for a release-notes file.

Patch is the default. Pre-1.0 that covers bug fixes, vendor refreshes, internal
work and additive surface. A minor is an explicit decision recorded in the
release notes rather than something inferred from a feature landing. A major
carries breaking changes and ships deprecation warnings in a prior minor.

Every release rides with its documentation: the structured source in
`release-notes/v<X>.<Y>.<Z>.json`, the `CHANGELOG.md` regenerated from it, and
whatever operator-facing doc the change invalidated. Then the branch, the signed
commit, the pull request, the squash merge, the signed tag, and the publish
workflow that attaches the four trust roots described in
[SECURITY.md](SECURITY.md).

That structured source is written by hand, one file for the release being cut.
`node scripts/release.js regen` then folds it into the minor series file
`release-notes/v<X>.<Y>.x.json`, which holds every released version of that
line, newest first, and removes the file it folded. A minor line therefore
carries one JSON however many patches it accumulates, and `CHANGELOG.md` groups
by that line so somebody upgrading across several patches reads them together.
Two gates hold the arrangement together: `consolidate-release-notes.js --check`
refuses a hand-written file that says something different from the copy already
folded, and `generate-changelog-entry.js --check` refuses a `CHANGELOG.md` that
no longer matches the notes it was rendered from. Never hand-edit `CHANGELOG.md`
itself; edit the JSON and rebuild.

## What to contribute

**New here?** Issues labeled `good first issue` are scoped deliberately small: a
doc correction, a test for an uncovered branch, an error message that could
better say what to do next. Comment that you are taking one, then open a PR.

Areas where help is most useful, roughly in order:

1. **Adversarial protocol fixtures.** Malformed SMTP transcripts, hostile MIME,
   IMAP literal-framing abuse, oversized and deeply nested structures, Sieve
   scripts written to run forever. The parsers are the highest-value surface to
   harden.
2. **Client interoperability.** A real MUA that disagrees with the server, with
   the transcript attached. Thunderbird, Apple Mail, mutt, K-9, FairEmail and
   Outlook profiles each have their own idea of the specification.
3. **Operator documentation.** DNS is where self-hosted mail actually fails.
   Provider-specific notes, a clearer diagnostic, a `doctor` check that catches a
   misconfiguration earlier.
4. **Accessibility and clarity in webmail.** It is server-rendered HTML, which
   makes it possible to get right; that is not the same as it being right.

What the project does not want:

- New npm runtime dependencies.
- A TypeScript port or a build step.
- Classical-only cryptographic fallbacks "for compatibility".
- A tolerance in a parser for input the standard forbids.
- A configuration flag that turns a security default off.
- Any of the vocabulary of a hosted service. This is a server an operator runs.
  It has no accounts to sell, no usage to meter, and no upstream to phone.

## Maintainer responsibilities

If you are being added as a maintainer, the additional commitments are:

- Triage incoming issues within 7 days.
- Respond to security reports on the targets in [SECURITY.md](SECURITY.md).
- Review PRs in your area within 14 days.
- Sign off and tag releases.

## Getting help

- **Usage questions and design proposals:**
  [GitHub Discussions](https://github.com/blamejs/blamepost/discussions).
- **Reproducible bugs:**
  [GitHub Issues](https://github.com/blamejs/blamepost/issues).
- **Security:** privately, per [SECURITY.md](SECURITY.md). Never in an issue.
- **Real-time:** the project runs no chat server. Collaboration is asynchronous.

The [Code of Conduct](CODE_OF_CONDUCT.md) governs this document.
