---
name: Feature request
about: Propose a capability for the mail stack, the webmail or admin UI, or the CLI
title: ''
labels: enhancement
assignees: ''
---

<!--
Every capability lands with its full operator-facing scope, not a first
cut with the interesting half left out. File the issue first to settle
scope before opening a pull request; it saves a round of rework.
-->

## Problem

<!-- What does an operator or an account holder need that they cannot do
today? A concrete scenario beats an abstract one. If the surface is
spec-defined, cite the RFC and the section that pins the wire behavior. -->

## Which surface

- [ ] Inbound MX (SMTP)
- [ ] Submission (SMTP AUTH)
- [ ] IMAP
- [ ] POP3
- [ ] JMAP
- [ ] ManageSieve / Sieve evaluation
- [ ] Outbound delivery, queue or DSN
- [ ] DKIM / ARC / DMARC / SPF / MTA-STS / TLS-RPT
- [ ] Webmail or admin UI
- [ ] CLI (`blamepost <subcommand>`)
- [ ] Storage or configuration

## Proposed shape

<!-- What does it look like from outside? For a wire capability, the
transcript. For an API, the call site. For the CLI, the invocation. -->

```bash
blamepost <subcommand> --flag value
```

## Standards reference

<!-- Which RFC or registry defines the format or the extension keyword?
Link the section that pins the wire encoding, the capability string, or
the response code. Leave this blank rather than guessing at a number. -->

## Initial-release scope

What is IN the first shipped version:
-

What is explicitly OUT, and why each "out" is a complete decision rather
than an open question:
-

## Configuration surface

<!-- Which config keys or BLAMEPOST_* environment variables does this
add? Which are required, and what does each default to? -->

## Interoperability

<!-- Which clients or receiving servers did you check this against?
A capability that only one implementation understands needs a fallback
path, and that path is part of the scope. -->

## Failure modes

<!-- Pick the input-validation policy consciously per call site:

  - Config-time / entry-point inputs: THROW with a stable reason so an
    operator sees the typo at boot.
  - Hot-path observability sinks: drop silently inside try/catch.
  - Defensive request-shape readers: return defaults.
  - Wire-protocol readers (SMTP / IMAP / JMAP / POP3 / ManageSieve):
    REFUSE LOUD with the protocol's defined error code. Never tolerate
    malformed wire input for compatibility.
-->

- Bad configuration at boot →
- Malformed or hostile wire input →
- Remote peer unavailable or refusing →

## Security and privacy impact

<!-- Does this widen what an unauthenticated peer can reach? Does it
store or log anything new about a message or an account? Does it add a
signature, key or certificate the operator has to rotate? -->

## Crypto posture

- [ ] No crypto involved
- [ ] Verifies or parses existing material using a classical algorithm (verify-only)
- [ ] Produces new key material. Which algorithm, and is it PQC-first?

## Alternatives considered

<!-- What you ruled out and why. Saves the reviewer asking. -->

## Additional context
