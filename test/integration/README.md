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
pattern for the same reason. `test/helpers/foreign-client.js` does it,
against the capability table in `clients.js`.

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

## The client table

`clients.js` holds one entry per CAPABILITY, not per program: the
submission cases need an interpreter whose standard library has
`smtplib` and the mailbox cases need one with `imaplib`, and a build
carrying one and not the other is present for one and absent for the
other. A file claims an entry with `clients.spec("<id>")`.

The runner reads the same table. It takes every id in the table that
appears as a quoted string in a selected file's source as a client that
file needs, probes each one before it spawns anything, and reports how
many it located. That is why the table is the only place a specification
lives: a runner holding its own copy would report on a different set of
programs than the one the files went on to drive.

`node test/layer-0-primitives/interop-gate-contract.test.js` reconciles
the two directions, so a capability nothing claims fails there rather
than becoming a client the gate insists on for cases that do not exist.

## What the runner expects

`node scripts/test-integration.js` locates the foreign clients the
selected files claim, confirms every listener the suite talks to is bound
and answering as this server (`node scripts/check-services.js`), then
runs every `*.test.js` here, each in a fresh Node process.

A file:

- is named `<thing>.test.js`,
- exports `run()`, sync or async,
- claims what it needs with `clients.spec("<id>")`,
- prints `CHECKS <n>` on success, and
- prints `SKIPS <n>` when an optional endpoint could not answer, so a
  check that did not run is never folded into the pass count.

**A run that located no client is not a pass.** The clients are located
and never installed, so a machine with none of them runs every case that
needs no foreign parser, records a skip for the rest, and reaches the end
with nothing proved about interoperability. The runner publishes what it
reached as `EXAMINED <n> <unit>` on the last lines of stdout, on a
passing run and a failing one alike, and a unit that came back zero
refuses the run by name:

| Unit | Empties when |
|---|---|
| `interop-files` | Discovery found no file to run. |
| `located-clients` | No foreign parser was found on the machine. |
| `driven-checks` | The files ran and asserted nothing. |

Every client that could not be located is named. Set
`INTEGRATION_REQUIRE_CLIENTS=1` and an absent client refuses the whole
run before anything is spawned, which is what a pipeline wants.

Exit codes: `0` every file passed, `1` a required endpoint is
unreachable, `2` at least one file failed, `3` a runner-level error, `4`
the suite is empty so nothing was proven, `5` a client the selected files
need is absent under `INTEGRATION_REQUIRE_CLIENTS=1`, `6` a published
unit came back empty, `7` the service pre-flight was skipped without a
written reason.

Skipping the pre-flight skips the answer to whether the server is
running, so it takes a reason and prints it as a banner. The flag on its
own is refused.

Run one file by name, skip the pre-flight, or refuse a machine that is
missing a client:

```
node scripts/test-integration.js smtp-submission
node scripts/test-integration.js --skip-service-check --service-check-skip-reason="the stack is up under a different runner"
INTEGRATION_REQUIRE_CLIENTS=1 node scripts/test-integration.js
```

`BLAMEPOST_INTEGRATION_DIR` moves the directory the runner discovers
files in. It exists so the runner's own behavior can be driven over
fixture files; it moves the files only, and the client table stays this
one.

## What does not belong here

The layered suites under `test/layer-0-primitives/`,
`test/layer-1-state/` and `test/layer-2-integration/` build the server
inside the test process and bind ephemeral loopback ports. They need no
external stack, they are run by `node test/smoke.js`, and pointing this
runner at them would prove nothing about interoperability while
reporting a green gate.
