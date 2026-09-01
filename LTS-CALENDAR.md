# LTS calendar

blamepost ships on a published major cadence. Each major receives **24 months of
security-only patches**, starting the day the next major is published. Feature
backports are not promised.

| Version | First release | Security patches through | Minimum runtime | Signature posture |
|---|---|---|---|---|
| `v0.x` (pre-1.0) | not yet released | until v1.0 ships | Node >= 24.19.0 | Ed25519 + RSA-SHA256 dual DKIM selectors; ML-DSA-65 release signing |
| `v1.x` | not yet scheduled | first release + 24 months | the Node active LTS at that release | Ed25519 + RSA-SHA256 dual DKIM selectors; ML-DSA-65 release signing |

## Pre-1.0: only the latest tag is supported

Until 1.0 ships, exactly one version is supported: the newest tag. Not the newest
patch on your minor, but the newest tag, full stop. Older tags get no backports,
including for security fixes, because the fix ships as a new tag and upgrading to
it is the remediation.

This is a real constraint on how you run it. Pin the image by digest so a pull
cannot surprise you, watch the releases, and upgrade deliberately. A mail server
running an unpatched parser is exposed to anyone who can open a connection to
port 25, which is everyone.

Every release may change something an operator depends on. Read
[CHANGELOG.md](CHANGELOG.md) before upgrading across more than a few patches, and
back up the data volume first. The procedure is in
[docs/operator-guide.md](docs/operator-guide.md).

## What a security patch covers

- Critical and high-severity vulnerabilities in blamepost's own code: a parser
  denial of service, an authentication or relay bypass, a policy check that fails
  open, cross-account disclosure, audit-chain tampering.
- Vulnerabilities in the vendored framework, remediated by refreshing the pin.
  The response targets in [SECURITY.md](SECURITY.md) apply to the vendored tree
  exactly as they apply to first-party code.
- Changes forced by a standards body deprecating an algorithm or a mechanism the
  server relies on: a DKIM key type, a TLS floor, a DNS record shape.

Not covered: feature backports, performance work, or non-security bug fixes.
Those land on the current line.

## What an upgrade can change, pre-1.0

- **The on-disk format.** Schema migrations run at boot and are one-way. This is
  why the backup comes first.
- **DNS records you publish.** A change to the selector convention or a policy
  field means republishing. Any release that requires it says so in the first
  line of its notes, and `blamepost doctor` reports the mismatch.
- **Defaults on the wire.** The TLS floor, the offered authentication
  mechanisms, and the signing posture can move. Each move is stated in the
  release notes with what it means for receivers.
- **The CLI and the config schema.** Both stabilize at 1.0.

Post-1.0, the deprecation contract covers all four: a warning ships at least one
minor before a removal, and a break waits for a major.

## Algorithm posture

The signature column in the version table is the posture for **new** material on
that line. Sealed data carries its algorithm identifier in the envelope header,
so material written under an earlier posture keeps opening after the active
choice moves forward. A rotation does not strand a mailbox.

Outbound mail is signed with two selectors by default, Ed25519 and RSA-SHA256,
which are the algorithms the DKIM `a=` tag admits. If a post-quantum key type is
ever registered for DKIM, adopting it adds a third selector rather than
replacing either. That is a wire-visible change, so it goes through the proposal
process in [GOVERNANCE.md](GOVERNANCE.md) with a migration window in which the
existing records keep answering.

When an algorithm is added or retired, the change ships as a minor on the
current major and the row above is updated in the same commit.

## Node minimum policy

The minimum runtime is the lowest full Node version supported on that line. It
tracks Node's own active-LTS schedule: a new blamepost major adopts whichever
Node major is active LTS at the time, pins the patch release it was tested
against, and then freezes that floor for the major's security-patch window, so
nobody is forced onto a newer runtime mid-window.

The floor is declared once, as `engines.node` in `package.json`, and every other
statement of it is a copy held to that value: `.nvmrc`, the `node-version` pin
in each workflow, the runtime recorded beside each container base image, the
README badge, and the prose in this file and the contributor guide.
`npm run gates` fails when any of them disagrees.

Nothing is transpiled, so the supported Node version is exactly the version the
source runs on. Operators using the container do not need to track this at all,
because the image carries its own runtime.

## Signing-key rotations

Rotations of the commit and tag signing key are announced here, so anyone
verifying tags automatically has one file to watch. Each entry records the date,
the retiring fingerprint, the incoming fingerprint, and the overlap window during
which both are valid. The current fingerprints live in
[SECURITY.md](SECURITY.md).

No rotation has occurred.

## The calendar takes effect at 1.0

`v0.x` carries no LTS commitment. The version table describes what the windows
will be, not a promise that applies today. Until 1.0 the policy is the one this
page opens with: upgrade to the newest tag.
