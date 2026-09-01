<!--
Thanks for the pull request. Fill in the sections below. CI (smoke +
static gates + container build) is required to pass before merge.
Local pre-flight:

  npm ci
  node test/smoke.js
  npx --no-install eslint --max-warnings 0 .
  node test/layer-0-primitives/codebase-patterns.test.js
  node scripts/check-api-snapshot.js
  node scripts/check-operator-prose.js

Security-sensitive patches: don't open here. See SECURITY.md.
-->

## Summary

<!-- One or two sentences. What does this change, and why. -->

## Type of change

<!-- Check all that apply -->

- [ ] Bug fix (no API change)
- [ ] New capability in the mail stack (SMTP / IMAP / JMAP / POP3 / ManageSieve / Sieve)
- [ ] Webmail or admin UI change
- [ ] New CLI subcommand (`bin/blamepost.js`)
- [ ] Storage / schema change
- [ ] Vendored blamejs refresh
- [ ] Docs / operator-guide update
- [ ] Test coverage or CI change
- [ ] Refactor (no behavior change)
- [ ] Other:

## Linked issue

Closes #

## House rules checklist

- [ ] No new npm runtime dependencies. blamejs stays vendored under `lib/vendor/` and is only ever changed through `scripts/vendor-update.sh`
- [ ] PQC-first: signature / KEM / digest / KDF / password-hash choices go through the vendored primitives (ML-KEM-1024, ML-DSA-65, XChaCha20-Poly1305, SHAKE256, SHA3-512, HKDF-SHA3-512, Argon2id)
- [ ] Security middleware is composed into the request lifecycle, not put behind a config flag
- [ ] CommonJS / `var` / no TypeScript / no transpilation
- [ ] Used vendored primitives instead of hand-rolled helpers or raw literals
- [ ] No "future patch" deferrals. If this introduces a shared helper, every existing call site moves to it in the same pull request

## Wire-protocol and mail-path checks

<!-- Delete the ones that don't apply, but delete them consciously. -->

- [ ] Wire-protocol readers refuse malformed input LOUDLY with the protocol's defined error code, never tolerated "for compatibility"
- [ ] Submission stays identity-bound: a `MAIL FROM` the authenticated account does not own is refused at the wire
- [ ] Every delete path routes through `b.mail.agent.expunge` (retention floor + legal hold), never `b.mailStore.delete()` from a wire handler
- [ ] Every outbound path goes through `b.mail.send.deliver(envelope)`, covering MX lookup, MTA-STS, DANE, retry and DSN
- [ ] DKIM / ARC signing still defaults to the Ed25519 + RSA-SHA256 dual signer (RFC 8463 §3). The `a=` registry admits no post-quantum value, so do not add one
- [ ] No operator-side DNS requirement changed without a matching `docs/operator-guide.md` update

## Tests

- [ ] `node test/smoke.js` passes. Check count: `____`
- [ ] `npx --no-install eslint --max-warnings 0 .` exits 0
- [ ] `node test/layer-0-primitives/codebase-patterns.test.js` is clean
- [ ] New tests cover the new behavior (RED before the fix, GREEN after):
  - [ ] Layer 0 (primitive)
  - [ ] Layer 1 (state-touching)
  - [ ] Layer 2 (integration: listeners, containers, delivery)

## Documentation

- [ ] `@module` / `@primitive` comment blocks added or updated in the same diff
- [ ] `release-notes/v<X>.<Y>.<Z>.json` entry authored, folded into `release-notes/v<X>.<Y>.x.json`, and `CHANGELOG.md` rebuilt
- [ ] `docs/operator-guide.md` updated when operator-side wiring changed (DNS records, env vars, ports, volumes)
- [ ] SECURITY.md updated for a new threat-model entry or a change to the supported versions
- [ ] README.md updated when the capability appears in the high-level description
- [ ] Commit message explains *why* and *what tradeoff*, not just *what*

## Behavior changes

<!-- If this changes existing behavior in any way that reaches an operator,
such as a wire response, an exit code, a default value, an accepted-input
set or a stored shape, call it out so
the release notes can flag it and operators know what to expect. -->

## Upgrade impact

<!-- What does an operator running the previous version have to do?
Nothing, restart, re-run a migration, publish a new DNS record, rotate a
key? "Nothing" is a fine answer when it's true. -->

## Open questions / reviewer focus
