#!/bin/bash -eu
# Build every harness under fuzz/ for ClusterFuzzLite or OSS-Fuzz.
#
# The harness set is read from the tree rather than listed here, matching
# .github/workflows/cflite_pr.yml: a new fuzz/<name>.fuzz.js is built from
# the commit that adds it, and there is no second list to keep in
# agreement. Each harness ships its seed corpus as <name>_seed_corpus.zip
# and its dictionary as <name>.dict, which are the names libFuzzer picks
# up beside a target of the same name.
#
# $SRC and $OUT come from the base image.

cd "$SRC/blamepost/fuzz"
npm ci

cd "$SRC/blamepost"

built=0
for harness in fuzz/*.fuzz.js; do
  name="$(basename "$harness" .fuzz.js)"

  # A harness that returns a promise carries the line
  # `module.exports.async = true;`, and `run-once.js --mode` reads it
  # without loading the harness. Every other harness is built with
  # --sync. Under --sync jazzer does not wait for a returned promise, so
  # a rejection from an asynchronous harness would never be reported.
  mode="$(node fuzz/run-once.js --mode "$name")"
  case "$mode" in
    sync)  compile_javascript_fuzzer blamepost "$harness" --sync ;;
    async) compile_javascript_fuzzer blamepost "$harness" ;;
    *)
      echo "build.sh: run-once.js --mode $name printed '$mode', not sync or async." >&2
      exit 1
      ;;
  esac

  corpus="fuzz/${name}_seed_corpus"
  if [ -d "$corpus" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "$corpus"/*
  fi

  dict="fuzz/${name}.dict"
  if [ -f "$dict" ]; then
    cp "$dict" "$OUT/${name}.dict"
  fi

  built=$((built + 1))
done

# A build that produced nothing is a failure rather than a quiet success.
# The workflows discover the same set from the same glob, so a run that
# found no harness here would have found none there either, and both
# would have reported a pass over an empty set.
if [ "$built" -eq 0 ]; then
  echo "build.sh: no fuzz/*.fuzz.js harness was found, so nothing was built." >&2
  exit 1
fi

echo "EXAMINED $built harnesses"
