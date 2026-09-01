---
name: Bug report
about: Report a defect in a listener, delivery, storage, the webmail or admin interface, or the CLI
title: ''
labels: bug
assignees: ''
---

<!--
Security bug? Don't file it here. See SECURITY.md for the private
disclosure process. Public issues are for non-security defects.

Before filing: search existing issues to avoid duplicates.

Redact before pasting. A protocol transcript can carry credentials, an
AUTH line, a session token, real recipient addresses and message
content. Replace domains with example.com, replace addresses with
someone@example.com, and cut the base64 after AUTH.
-->

## What happened

<!-- One or two sentences. What did the server do that you didn't expect. -->

## What you expected

## Which surface

- [ ] Inbound MX (SMTP, port 25)
- [ ] Submission (SMTP, ports 465 / 587)
- [ ] IMAP (ports 143 / 993)
- [ ] POP3 (ports 110 / 995)
- [ ] JMAP (`/jmap` on the web app)
- [ ] ManageSieve (port 4190) or Sieve evaluation
- [ ] Outbound delivery, queue or DSN
- [ ] DKIM / ARC signing, or DMARC / SPF evaluation
- [ ] Webmail or admin UI
- [ ] CLI (`blamepost <subcommand>`)
- [ ] Storage, migration or startup

## How to reproduce

<!-- Minimal repro. Exact steps beat prose. -->

1.
2.
3.

## Protocol transcript

<!-- The single most useful thing you can attach. Paste the client/server
dialogue with the direction marked, e.g. `C:` for what the client sent
and `S:` for what the server answered. Include the greeting, EHLO/CAPABILITY
and every line through the failure. Redact credentials and real addresses. -->

<details><summary>Transcript</summary>

```
C: EHLO client.example.com
S: 250-mx.example.com
...
```

</details>

## Client (mail user agent)

<!-- Which client, which version, which platform. A defect that only
reproduces on one MUA is usually a protocol-detail difference. Include
the account settings that matter: port, TLS mode (implicit / STARTTLS),
auth mechanism. -->

- Client and version:
- Platform:
- Port and TLS mode:
- Auth mechanism:

## DNS posture

<!-- Paste the output of the doctor subcommand, which reports the
records the server needs (MX, SPF, DMARC, DKIM selector, MTA-STS,
TLS-RPT). Many delivery reports resolve to a missing or contradictory
record. -->

<details><summary><code>blamepost doctor</code> output</summary>

```
paste here
```

</details>

## Environment

- blamepost version: `v0.X.Y` (or main `<sha>`)
- How it runs: container image / `node bin/blamepost.js serve`
- Node.js version (when not using the image): `node --version`
- Host OS and architecture:
- Reverse proxy or TLS terminator in front of it, if any:

## Server logs

<!-- Set BLAMEPOST_LOG_LEVEL=debug and reproduce, then paste the lines
around the failure. -->

<details><summary>Logs</summary>

```
paste relevant log lines, error codes or stack traces here
```

</details>

## What you've already tried

<!-- Helpful for ruling out duplicates and known interactions. -->

## Additional context
