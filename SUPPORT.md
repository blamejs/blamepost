# Support

Thanks for running blamepost. This page points you at the right channel.

## Where to go

| I want to… | Go here |
|---|---|
| Stand a server up | [README.md](README.md) for the container, [docs/operator-guide.md](docs/operator-guide.md) for DNS |
| Fix a delivery problem | [docs/operator-guide.md](docs/operator-guide.md), then `blamepost doctor` |
| Understand how it is built | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See what changed between versions | [CHANGELOG.md](CHANGELOG.md) |
| See what is targeted or accepted | [ROADMAP.md](ROADMAP.md) |
| Ask a usage question or propose a feature | [GitHub Discussions](https://github.com/blamejs/blamepost/discussions) |
| Report a reproducible bug | [GitHub Issues](https://github.com/blamejs/blamepost/issues) |
| Report a security vulnerability | **Privately.** See [SECURITY.md](SECURITY.md). Never in an issue or a discussion. |
| Report conduct | `security@blamejs.com`, per [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |

Discussions is for "how do I", "should this work like this", and "here is an
idea". Issues is for "this is broken, here is how to see it". If you are unsure,
start in Discussions; moving a confirmed bug to an issue is easy, and answering a
question in an issue tracker is noisy for everyone else.

## Before you open an issue

Mail bugs are context-heavy. A report that carries the context gets a real answer
instead of three rounds of questions.

**Always include:**

- **Version:** the `v0.X.Y` tag, the image digest, or the `main` `<sha>` you are
  running. `blamepost doctor` prints it.
- **How it is deployed:** the container, compose, or a bare Node process. Node
  version if the last one.
- **What you expected and what happened.** For mail, "what happened" usually
  means: was the message accepted, rejected outright, refused with a temporary
  4xx code, or silently filed somewhere unexpected.

**For a protocol problem, include the transcript.** The actual conversation, with
the server's responses rather than a summary of it, is the single most useful
thing in a mail bug report:

```text
S: 220 mx.example.com ESMTP
C: EHLO client.example.org
S: 250-mx.example.com
S: 250 STARTTLS
C: MAIL FROM:<alice@example.org>
S: 530 5.7.0 ...
```

**Redact the credentials, not the codes.** Replace the argument to `AUTH` and any
password with `[redacted]`. Keep every response code and every response line
exactly as the server sent them. The code is the diagnosis, and a paraphrase
loses it.

**For a client problem, name the client.** "IMAP is broken" and "Thunderbird
128.4 on Linux shows an empty folder after a move, mutt on the same account does
not" are different reports. Include the client, its version, and its platform,
and say whether a second client behaves the same way. Clients disagree with the
specification in specific, known ways, and knowing which one you are hitting is
half the fix.

**For a delivery or authentication problem, include the DNS posture.** Run this
and paste the output, with your domain in place of `example.com`:

```sh
dig +short MX  example.com
dig +short TXT example.com                        # SPF
dig +short TXT _dmarc.example.com                 # DMARC
dig +short TXT selector._domainkey.example.com    # DKIM, per selector
dig +short TXT _mta-sts.example.com               # MTA-STS id
dig +short TXT _smtp._tls.example.com             # TLS-RPT
dig +short -x <your.sending.ip>                   # reverse DNS
```

Also paste the `Authentication-Results` header from a message that shows the
problem, and the receiving side's bounce or DSN if you have one. Most reported
"blamepost will not deliver" problems turn out to be a record that is missing,
stale, or contradicted by another one, which is why `blamepost doctor` checks
all of it and why the output is worth attaching.

**For a message that parses wrongly, attach the message.** Base64 the raw bytes
rather than pasting them. A mail client will rewrite line endings, re-wrap
headers, and change the thing you are reporting. Strip anything you would not
want public; if you cannot strip it and still reproduce, that is a private
report, not an issue.

**Attach the log.** `.test-output/smoke.log` for a test failure;
`BLAMEPOST_LOG_LEVEL=debug` output around the moment for a runtime one.

A loud refusal on malformed input is usually the server working as designed.
Wire-protocol readers refuse rather than repair, on purpose. If you believe
something should be accepted and is not, or is accepted and should not be, that
is exactly the report worth filing. Include the bytes and the RFC section you are
reading it against.

## Versions and upgrades

Pre-1.0, the supported version is the latest tag. Older tags get no backports.
Read [CHANGELOG.md](CHANGELOG.md) before jumping more than a few patches, and
back up the data volume first. The procedure is in
[docs/operator-guide.md](docs/operator-guide.md).

Patch is the default release size. A minor is an explicit decision recorded in
the release notes. A major carries breaking changes with deprecation warnings in
a prior minor. [GOVERNANCE.md](GOVERNANCE.md) records how those calls get made,
and [LTS-CALENDAR.md](LTS-CALENDAR.md) records the support window that takes
effect at 1.0.

## Security

Security reports do not go through Issues or Discussions. Report privately with
GitHub's [advisory form](https://github.com/blamejs/blamepost/security/advisories/new).
Response targets and release-verification recipes are in
[SECURITY.md](SECURITY.md).

## License

blamepost is [Apache-2.0](LICENSE) licensed. Vendored-component attribution is in
[NOTICE](NOTICE).
