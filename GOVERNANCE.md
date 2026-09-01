# Governance

blamepost is a mail server. Operators who put it in front of a domain are
betting their mail on it. Three questions matter before they commit:

1. Who decides what changes?
2. What happens to the project if that person stops?
3. How does a change that affects a running deployment get communicated?

This document answers them.

## Current model

Solo maintainer, pre-1.0.

- **Maintainer:** dotCooCoo (Robert Lee), GitHub [dotCooCoo](https://github.com/dotCooCoo).
- **Organization:** [github.com/blamejs](https://github.com/blamejs).
- **Repository:** [github.com/blamejs/blamepost](https://github.com/blamejs/blamepost).
- **Package:** `@blamejs/blamepost`. **Image:** `ghcr.io/blamejs/blamepost`.
- **Contact:** `security@blamejs.com`, the mailbox named in
  [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

The project moves to a multi-maintainer model when an aligned co-maintainer with
a sustained commit cadence in a core area joins. Until then the maintainer is
final on technical direction.

A bus factor of one is the largest non-technical risk this project carries. It
is stated here rather than left for an operator to discover.

## Roles

**Contributor.** Anyone who opens an issue or a pull request. No commitment
expected beyond the [Code of Conduct](CODE_OF_CONDUCT.md) and the sign-off in
[CONTRIBUTING.md](CONTRIBUTING.md).

**Reviewer.** A contributor with sustained history in one area whose review the
maintainer actively seeks on changes there. No repository permissions; the
standing is social and is recorded by being requested on PRs.

**Maintainer.** Commit access, release authority in their area, and the
responsibilities listed in CONTRIBUTING.md: issue triage within 7 days, security
response on the SECURITY.md targets, PR review within 14 days.

**Lead maintainer.** Final call on technical direction, the security process,
and what ships in a release. Currently the sole maintainer.

## How someone becomes a maintainer

Nothing here runs on an application form or a vote. The path is observable work.

1. **Sustained contribution in a core area** over several releases: the listener
   composition, the store, the delivery path, the web surface, or the release
   tooling. A handful of good patches is contribution; carrying an area through
   its bugs and its upgrades is maintainership.
2. **Demonstrated alignment with the project's hard rules**: zero runtime
   dependencies, post-quantum-first crypto, wire-protocol readers that refuse
   loudly, security defaults that are not configuration, one path for delivery
   and one for deletion. Alignment shows in review comments as much as in code.
3. **Review that catches things.** Reviewing other people's patches for a while
   is how the maintainer learns whether you would catch what they would.
4. **An invitation, then a public record.** The maintainer extends the
   invitation; the addition lands in this file and in `CODEOWNERS` in the same
   commit, so the change is visible rather than assumed.

Maintainers who go inactive for six months move back to reviewer standing, with
no ceremony and no prejudice. The point is that the file describes who is
actually available, not who once was. Coming back is an ask.

## How decisions get made

- **Technical direction.** Maintainer-final. Operator input arrives through
  Issues and Discussions, and the maintainer weighs it. No formal vote decides
  the outcome. The capability plan is public in [ROADMAP.md](ROADMAP.md).
- **Security triage.** Per [SECURITY.md](SECURITY.md): coordinated disclosure
  through GitHub Security Advisories, fix targets by severity, and a public
  advisory when the fix ships.
- **Operator-impacting changes.** Pre-1.0 the project reserves the right to break
  operator-facing surface in a minor. Deprecation warnings ship at least one
  minor before a removal. Post-1.0 the same contract applies across majors, with
  the support window in [LTS-CALENDAR.md](LTS-CALENDAR.md).
- **Release scope.** Patch is the default. A minor is an explicit decision the
  maintainer records in the release notes. A major requires a prior deprecation
  cycle.

## Change process

Most changes need nothing more than an issue and a PR. Three classes need more,
because reversing them after operators have deployed is expensive or impossible.

**A change proposal** goes in a GitHub Discussion and stays open for comment
before a decision. One is required for:

- **Anything that changes what an operator must publish in DNS.** A new selector
  convention, a changed policy field, a different record shape. An operator who
  misses this has a domain that silently stops being deliverable.
- **Anything that changes data at rest in a way that a downgrade cannot undo.**
  That covers the schema, the blob layout, the seal envelope and the queue
  format.
- **Anything that changes a wire-visible default**, including the DKIM signing
  posture, the TLS floor, and the authentication mechanisms a listener offers.

The shape of a proposal:

| Section | What it answers |
|---|---|
| Problem | What breaks today, for whom, with a concrete case |
| Governing standard | The RFC or specification that constrains the answer |
| Proposal | The change, in enough detail to implement |
| Operator impact | What an operator must do, and what happens if they do nothing |
| Migration | How an existing deployment gets from here to there |
| Alternatives | What else was considered and why it lost |

Comment stays open at least **14 days**, or **30 days** for a change to this
file. The maintainer closes each proposal with a decision and the reasoning, in
the thread, so the record survives the discussion. A rejected proposal states
the condition that would reopen it.

Security fixes are exempt. They ship on the SECURITY.md timeline and are
documented after the fact.

## Release authority

Only a maintainer cuts a release. The mechanics are not delegable, because each
one is a trust root:

- **Signed commits and tags.** Every release commit and tag is SSH-signed by the
  maintainer's key. The repository's tag ruleset refuses an unsigned or
  lightweight tag, so the invariant is enforced server-side rather than by
  discipline.
- **Provenance and signatures.** SLSA L3 attestation, Sigstore-keyless SBOM
  signatures and the container image signature come from the release workflows
  through OIDC. No long-lived key exists, and nobody signs by hand.
- **The post-quantum sidecar** is produced with the `RELEASE_PQC_SIGNING_KEY`
  secret in the `npm-publish` environment, whose public half is committed at
  `keys/release-pqc-pub.json` and whose fingerprint is published in SECURITY.md.
- **Merge before tag.** A release tag points at a commit that reached `main`
  through a merged pull request. The publish flow refuses a tag that does not
  satisfy that chain.

An operator can verify all four independently, and the recipes are in
SECURITY.md. That is the point of the arrangement. Release authority is not "the
maintainer says so"; it is a chain an outsider can walk.

## Succession

**Designated successor: not yet named**, with a stated reopen condition.

Naming one requires:

- A contributor with sustained commit cadence in a core area.
- Familiarity with the decisions recorded in [ARCHITECTURE.md](ARCHITECTURE.md),
  [THREAT-MODEL.md](THREAT-MODEL.md) and the release notes. Maintainer-local
  notes are not durable; the public artifacts plus the source are what a
  successor actually inherits.
- A stated commitment to the hard rules above.

Candidacy is reviewed whenever a contributor crosses that threshold.

**Repository ownership.** The organization is currently single-owner. The
maintainer commits to adding a second organization owner within 30 days of
naming a successor. Until then, recovery from maintainer incapacity runs through
GitHub Support's account-recovery flow, keyed on DNS control and 2FA recovery
codes.

**Publish credentials.** Release publishing is an OIDC trusted-publisher binding
scoped to the `npm-publish` environment, with a 2FA-protected backup token held
offline as the fallback.

**Signing keys.** The commit and tag signing key rotates like this: generate the
new key; sign a rotation announcement with the old one during an overlap window;
update SECURITY.md's fingerprint table; record the rotation in
[LTS-CALENDAR.md](LTS-CALENDAR.md) so anyone verifying tags automatically can
update their pin; retire the old key 30 days after the announcement. The
Sigstore identity needs no rotation of its own. It follows organization
ownership.

**Critical knowledge** lives in the repository, in public: ARCHITECTURE.md for
the system shape, THREAT-MODEL.md for what it defends, ROADMAP.md for direction,
docs/operator-guide.md for how it is actually run, and CHANGELOG.md derived from
`release-notes/*.json` for how the surface got here.

## Recovery paths

| Asset | Path |
|---|---|
| Package publishing | Registry account-recovery flow (registered domain plus 2FA recovery codes); offline backup token |
| Container registry | Follows GitHub organization ownership |
| GitHub organization | GitHub Support account-recovery flow with 2FA recovery codes |
| Commit and tag signing key | Rotation procedure above, with a 30-day notification window |
| Release-signing key (ML-DSA-65) | Regenerate, commit the new public key, reset the environment secret, publish the new fingerprint in SECURITY.md |
| Sigstore identity | Identity-based; rotates with organization ownership |
| `blamejs.com` (the contact domain) | Registrar account-recovery flow; DNS held with 2FA and a recovery address |

## If the maintainer goes quiet

- **Escalation trigger:** 30 days with no maintainer activity and no hiatus
  announced in advance in LTS-CALENDAR.md.
- **If a successor is named**, the succession process activates.
- **If not**, the project enters maintenance hibernation with a public
  announcement: a banner on the README, a pinned issue, and a CHANGELOG entry
  recording the status change. Published releases stay available and keep
  running; anyone about to upgrade sees the banner first.

For a mail server this matters more than for a library. An operator running an
unmaintained mail server needs to know it is unmaintained, because the parsers
face the open internet every day.

## Known gaps

Stated plainly so an operator can weigh them against their own risk tolerance.

1. **No named successor.** Reopens when a contributor crosses the threshold
   above.
2. **Single organization owner.** Addressed within 30 days of naming a successor;
   it tracks succession rather than having its own trigger.
3. **No second reviewer.** The person most likely to share the author's blind
   spots reviews every patch. The automated gates compensate until a second
   maintainer exists: the detector suite, the static analysis, the fuzzing, the
   wire-level tests. They do not fully replace it, and this is the single
   strongest argument for contributing.
4. **OpenSSF Best Practices, silver level.** Structurally reachable once the
   multi-maintainer model is live.
