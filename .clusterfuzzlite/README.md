# ClusterFuzzLite integration

The build definition for coverage-guided fuzzing of the wire-protocol
readers. The harnesses themselves live in `fuzz/`.

## What is here

| File | What it is |
|------|------------|
| `project.yaml` | Language and contact metadata. OpenSSF Scorecard's Fuzzing check reads this directory. |
| `Dockerfile` | The OSS-Fuzz JavaScript build image, plus the tree and `build.sh`. |
| `Dockerfile.dockerignore` | What that build uploads. BuildKit reads it instead of the context root's `.dockerignore`. |
| `build.sh` | Builds every `fuzz/*.fuzz.js` harness and ships its seed corpus and dictionary to `$OUT`. |

## The build context

`Dockerfile` copies the whole tree and then `build.sh`, with the repository
root as the context. The context root's `.dockerignore` excludes `fuzz/` and
this directory, because the shipped image reads neither and a seed corpus
grows without bound during a local run. `Dockerfile.dockerignore` is what
puts both back for this build alone.

Two properties of that file decide how it is edited. It REPLACES the context
root's file rather than adding to it, so every exclusion that file carries is
restated in it, and the two directories named above are the only difference
between them.
And only BuildKit reads it: under the legacy builder the context root's
exclusions apply, and the build then stops on `Cannot locate specified
Dockerfile`, because those exclusions cover the directory the Dockerfile sits
in. BuildKit is the default from Docker 23 on.

`test/layer-2-integration/fuzz-build-context.test.js` renders both contexts
with docker and reads back what arrived: every `COPY` source the Dockerfile
names, every harness with its corpus and dictionary, and one planted probe
per exclusion the context root's file carries, at the root and one directory
in.

## What runs today

`.github/workflows/cflite_pr.yml` and `.github/workflows/cflite_batch.yml`
invoke jazzer.js directly rather than through
`google/clusterfuzzlite/actions/build_fuzzers`. The v1 action refuses a
JavaScript project: it rejects a named sanitizer and an empty sanitizer
list alike, so the build step fails before a harness is compiled. This
directory is the definition an OSS-Fuzz submission mirrors and the one
that re-engages when a JavaScript fix ships upstream.

Both paths read the same harness set from the same glob, and both ask
`node fuzz/run-once.js --mode <name>` for each one. A harness that
returns a value is compiled with `--sync` and one that returns a promise
is compiled without it, so the mode a harness declares is the mode both
paths give it.

## Adding a harness

Name it `fuzz/<name>.fuzz.js` and export two things: `fuzz(data)` taking
a `Buffer`, and `targets()` returning one entry per reader the harness
drives, as `{ name, of, call }` where `of` is the object holding the
reader and `call` is its property name. The workflows and `build.sh`
discover the file from the commit that adds it; there is no list to
update.

`targets()` is what lets the seed-corpus gate measure that each seed
ARRIVES at the reader the harness names, rather than only that the
harness ran without a finding. A harness that exports none is refused,
and so is one that names a reader no seed reaches.

Two optional files travel with it, both matched by name:

- `fuzz/<name>_seed_corpus/` holds curated inputs. Give every one an
  extension: `.gitignore` tracks the curated seeds by that extension and
  drops the extensionless entries libFuzzer writes back during a run.
- `fuzz/<name>.dict` is a libFuzzer dictionary. The line-oriented
  readers need one, because a curated seed is a text file and CR is the
  byte an editor rewrites on the way to disk. Each seed therefore holds
  one command with no terminator, and the framing bytes reach the fuzzer
  from the dictionary. The bare-CR and bare-LF refusals and the
  DATA-body smuggling detector (CVE-2023-51764, CVE-2023-51765,
  CVE-2023-51766) are defined on exactly those sequences.

## Running locally

Install the toolchain once, then fuzz one target:

```
npm ci --prefix fuzz
npx --prefix fuzz jazzer --sync fuzz/smtp-command.fuzz.js fuzz/smtp-command_seed_corpus -- \
  -dict=fuzz/smtp-command.dict -max_total_time=60 -error_exitcode=1 -timeout=30
```

A finding prints the reproducer inline and writes it to `crash-<hash>`
in the working directory. Replay it under plain Node for a stack trace:

```
node fuzz/run-once.js smtp-command @crash-<hash>
```

`node fuzz/run-once.js <target> --corpus` reads the whole seed corpus and
reports one line per input, which is the check that a harness still loads
and still treats a well-formed transcript as a pass.

## What counts as a finding

Every reader here is specified to refuse malformed input with the
protocol's own error code, so refusals are the normal result and are not
reported. `fuzz/harness.js` draws the line: an error of the reader's own
class carrying a code is a refusal, and anything else leaves the harness
as a throw. A hang or an out-of-memory is a finding through libFuzzer's
own `-timeout` and `-rss_limit_mb`.
