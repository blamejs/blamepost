# Interop suite

Files here drive a **running** blamepost from the outside, with clients
that are not this codebase: another MTA delivering to the MX listener, a
mail client speaking IMAP or ManageSieve, a receiving server that
enforces MTA-STS. That is the layer where a listener's own idea of what
it emitted stops being evidence and something else's parser becomes the
judge.

## What the suite needs to run

A **running blamepost**, which `scripts/check-services.js` gates on, and
these in the environment:

| Variable | What it is |
|---|---|
| `BLAMEPOST_INTEROP_HOST` | Where the server answers. |
| `BLAMEPOST_INTEROP_IMAP_PORT` | The IMAP port to drive. |
| `BLAMEPOST_INTEROP_ADDRESS` | An account that already exists on it. |
| `BLAMEPOST_INTEROP_PASSWORD` | That account's password. |
| `BLAMEPOST_INTEROP_CA` | The certificate authority to verify the chain against. |
| `BLAMEPOST_INTEROP_TLS_INSECURE` | Skip chain verification. A written act, spelled exactly, and it must never be set in a run whose result anybody relies on. |

**Absent credentials are a failure, not a skip.** A file that cannot sign
in has not proved anything, and the difference between that and a
passing run is the whole value of this layer. The refusal names the two
commands that create what is missing, so it is actionable rather than
merely loud.

## Finding a client

A client is LOCATED at run time, never installed and never made a
dependency: hard rule 1 is why, and the prose gate follows the same
pattern for the same reason. `test/helpers/foreign-client.js` does it.

Two properties of that helper are load-bearing. **Presence is decided by
whether the program could be started**, so `ENOENT` is absence and every
other spawn outcome is presence: a client that runs and exits non-zero is
present and answering, and reading its exit code as absence would let a
broken client read as a missing one. And the probe reads the protocol
list out of the client's own banner, so a build of that client compiled
without IMAP is rejected as unusable rather than accepted as present.

A client that is genuinely absent produces `helpers.skip` and lands in
the skip counter, which the runner reports separately and never folds
into the pass count.

## What the runner expects

`node scripts/test-integration.js` runs every `*.test.js` here, each in a
fresh Node process, after `node scripts/check-services.js` confirms that
every listener the suite talks to is bound and answering its protocol's
greeting.

A file:

- is named `<thing>.test.js`,
- exports `run()`, sync or async,
- prints `CHECKS <n>` on success, and
- prints `SKIPS <n>` when an optional endpoint could not answer, so a
  check that did not run is never folded into the pass count.

Exit codes: `0` every file passed, `1` a required endpoint is
unreachable, `2` at least one file failed, `3` a runner-level error, `4`
the suite is empty so nothing was proven.

Run one file by name, or assume the stack is ready:

```
node scripts/test-integration.js smtp-submission
node scripts/test-integration.js --skip-service-check
```

## What does not belong here

The layered suites under `test/layer-0-primitives/`,
`test/layer-1-state/` and `test/layer-2-integration/` build the server
inside the test process and bind ephemeral loopback ports. They need no
external stack, they are run by `node test/smoke.js`, and pointing this
runner at them would prove nothing about interoperability while
reporting a green gate.
