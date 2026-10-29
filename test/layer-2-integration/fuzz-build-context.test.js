// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the fuzzing build definition would actually receive, measured with
 * docker rather than read off an ignore file.
 *
 * `.clusterfuzzlite/Dockerfile` copies the whole tree and then the build
 * script beside it, with the repository root as the context. The root
 * `.dockerignore` excludes `**\/fuzz` and `**\/.clusterfuzzlite`, so both
 * COPY sources are withheld from that context: the harnesses never arrive
 * and the build script cannot be resolved. Measured before the ignore file
 * beside the Dockerfile existed, the context transferred 2 B and the build
 * stopped at `"/.clusterfuzzlite/build.sh": not found`.
 *
 * Nothing reported it. `.github/workflows/cflite_pr.yml` and
 * `cflite_batch.yml` invoke jazzer directly, so no run in this repository
 * builds that Dockerfile, and a definition nobody builds is a definition
 * that fails on the day somebody does. `.clusterfuzzlite/README.md` names
 * two such days: an OSS-Fuzz submission mirroring this directory, and the
 * ClusterFuzzLite build action re-engaging when it accepts a JavaScript
 * project.
 *
 * WHY THE ROOT IGNORE FILE IS NOT WIDENED. Re-including either directory
 * there would put fuzz corpora and this build definition into the shipped
 * image's context, and `build-context.test.js` holds the rule that no
 * dotted directory reaches it at all. The two exclusions are correct for
 * the image and wrong for the fuzzing build, which is what a per-Dockerfile
 * ignore file is for: BuildKit reads `<dockerfile>.dockerignore` beside the
 * Dockerfile when one exists.
 *
 * AND IT REPLACES THE ROOT FILE RATHER THAN ADDING TO IT. Measured here:
 * with an adjacent file present, every pattern in the context root's
 * `.dockerignore` stops applying. So the fuzzing build's ignore file has to
 * restate the credential, runtime-state and dependency exclusions itself,
 * or a fuzzing build uploads the environment file holding the vault
 * passphrase, the sealed keys and the live database that the root file
 * withholds from every other build. That is the half of this change most
 * likely to be got wrong, so it is derived from the root file rather than
 * compared against a list: every exclusion the root file carries, except
 * the two the fuzzing build needs back, is probed at the context root and
 * one directory in.
 *
 * The measurement is the real one. Docker renders the context to a local
 * directory, so what is counted is the set a build would upload rather than
 * this file's opinion about pattern syntax. The probe instruction file sits
 * outside the context, which is also how its adjacent ignore file is
 * pointed at the repository's own: a Dockerfile written into
 * `.clusterfuzzlite/` would appear in its own measurement and would have to
 * be written into the tree to be measured at all.
 *
 * Run standalone: node test/layer-2-integration/fuzz-build-context.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var harness = require("./container-harness");

var count = helpers.count;

var FUZZ_DIR       = "fuzz";
var CFLITE_DIR     = ".clusterfuzzlite";
var CFLITE_FILE    = CFLITE_DIR + "/Dockerfile";
var CFLITE_IGNORE  = CFLITE_FILE + ".dockerignore";
var ROOT_IGNORE    = ".dockerignore";

// Two lines that are right for the shipped image and wrong for this build.
// Everything else the root ignore file says has to keep holding here, and
// the case at the bottom is what measures that.
var FUZZ_BUILD_NEEDS = ["**/fuzz", "**/.clusterfuzzlite"];

// The instruction file that makes the whole context observable. The real
// Dockerfile copies named paths and pulls a multi-gigabyte toolchain base,
// so building it would report on its COPY list and on the network rather
// than on the context.
var CONTEXT_DOCKERFILE = "FROM scratch\nCOPY . /\n";

// The dependency directory a local `npm ci --prefix fuzz` leaves behind.
// `build.sh` installs inside the image, so uploading a developer's copy
// would send the jazzer toolchain through the context on every build.
var FUZZ_DEPENDENCIES = FUZZ_DIR + "/node_modules";

// The four files `build.sh` reads by name, as opposed to by glob: the two
// manifests `npm ci` needs, the mode reader it calls per harness, and the
// module every harness requires.
var FUZZ_NAMED_FILES = [
  FUZZ_DIR + "/package.json",
  FUZZ_DIR + "/package-lock.json",
  FUZZ_DIR + "/run-once.js",
  FUZZ_DIR + "/harness.js",
];

// The vendored trust anchor, which the root ignore file's last line puts
// back and which the harnesses reach through `lib/vendor/blamejs`.
var VENDOR_ANCHOR = "lib/vendor/blamejs/lib/vendor/bimi-trust-anchors.pem";

var PROBE_DEPTH = "deep/nested";

// A planted file no pattern names, so an empty answer cannot be read as
// everything having been excluded.
var PROBE_KEPT_UNMATCHED = "probe-keeper.txt";

// ---------------------------------------------------------------------------
// Reading the repository
// ---------------------------------------------------------------------------

function repoPath(rel) {
  return nodePath.join(helpers.REPO_ROOT, rel.split("/").join(nodePath.sep));
}

// Every path the fuzzing Dockerfile names as a COPY source, read from the
// Dockerfile itself. A COPY added there next year is probed on the run
// after it lands rather than when somebody remembers to extend a list.
function copySources(dockerfileText) {
  var found = [];
  dockerfileText.split(/\r?\n/).forEach(function (line) {
    var at = /^\s*COPY\s+(?!--)(\S+)\s+\S+\s*$/i.exec(line);
    if (at) found.push(at[1]);
  });
  return found;
}

// The exclusion patterns an ignore file carries, in file order. A comment
// is not a pattern and a negation is not an exclusion: it puts a path back,
// so probing one for absence would assert the opposite of what it does.
function exclusionPatterns(ignoreText) {
  return ignoreText.split(/\r?\n/)
    .map(function (line) { return line.trim(); })
    .filter(function (line) {
      return line !== "" && line.charAt(0) !== "#" && line.charAt(0) !== "!";
    });
}

// One relative path a pattern is meant to catch, synthesized from the
// pattern. The depth prefix comes off because depth is what is being
// measured, and each wildcard becomes an ordinary segment so what is left
// is a name a file can have.
function probePathFor(pattern) {
  return pattern
    .replace(/^\*\*\//, "")
    .replace(/\*+/g, "probe")
    .replace(/\?/g, "p");
}

// Every harness in the tree with the corpus and dictionary that travel with
// it, matched by name the way `build.sh` matches them. Seed entries without
// an extension are the ones libFuzzer writes back during a local run;
// `.gitignore` drops those and so does this.
function harnessFiles() {
  var entries = nodeFs.readdirSync(repoPath(FUZZ_DIR));
  var wanted  = [];
  entries.forEach(function (entry) {
    var name = /^(.+)\.fuzz\.js$/.exec(entry);
    if (!name) return;
    wanted.push(FUZZ_DIR + "/" + entry);
    var dict = FUZZ_DIR + "/" + name[1] + ".dict";
    if (nodeFs.existsSync(repoPath(dict))) wanted.push(dict);
    var corpus = FUZZ_DIR + "/" + name[1] + "_seed_corpus";
    if (!nodeFs.existsSync(repoPath(corpus))) return;
    nodeFs.readdirSync(repoPath(corpus)).forEach(function (seed) {
      if (nodePath.extname(seed) !== "") wanted.push(corpus + "/" + seed);
    });
  });
  return wanted;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// Renders a context and returns every path in it, relative and
// separator-normalized.
//
// `ignoreText` is written beside the instruction file as
// `<name>.Dockerfile.dockerignore`, which is where BuildKit looks for a
// per-Dockerfile ignore file. Passing null writes none, so the render falls
// back to the context root's own file, and that is the state this whole
// file is about.
async function renderContext(scratchRoot, contextRoot, outName, ignoreText) {
  var dockerfile = nodePath.join(scratchRoot, outName + ".Dockerfile");
  var outDir     = nodePath.join(scratchRoot, outName);
  nodeFs.writeFileSync(dockerfile, CONTEXT_DOCKERFILE, { mode: 0o600 });
  if (ignoreText !== null) {
    nodeFs.writeFileSync(dockerfile + ".dockerignore", ignoreText, { mode: 0o600 });
  }
  nodeFs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

  await harness.dockerOrThrow(
    ["build", "--file", dockerfile, "--output", "type=local,dest=" + outDir,
      contextRoot],
    "rendering the fuzzing build context to measure what it would upload",
    { timeoutMs: harness.BUILD_TIMEOUT_MS });

  var found = [];
  (function walk(dir, prefix) {
    nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      var rel = prefix ? prefix + "/" + entry.name : entry.name;
      if (entry.isDirectory()) walk(nodePath.join(dir, entry.name), rel);
      else found.push(rel);
    });
  })(outDir, "");
  return found;
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

// The fix has to exist before anything below it can measure what it does.
// Stated as its own verdict rather than folded into the arrivals, because
// an absent file and a wrong one send a reader to different places.
function theBuildDefinitionCarriesAnIgnoreFileOfItsOwn() {
  count("the fuzzing build definition carries an ignore file beside its Dockerfile, so the " +
    "context root's exclusions are not what decides what it receives",
  nodeFs.existsSync(repoPath(CFLITE_IGNORE)), CFLITE_IGNORE);
}

// Every path the Dockerfile names, resolved against what a build would
// actually be handed. This is the failure as it presents itself: the build
// stops at a COPY whose source is not in the context.
function everyCopySourceReachesTheContext(arrived, sources) {
  count("the fuzzing Dockerfile still names COPY sources to resolve, so what follows " +
    "answers for it rather than for an empty list",
  sources.length > 0, sources.join(" "));

  var unresolved = sources.filter(function (src) {
    if (src === ".") return arrived.length === 0;
    if (arrived.indexOf(src) !== -1) return false;
    return !arrived.some(function (p) { return p.indexOf(src + "/") === 0; });
  });
  count("every path the fuzzing Dockerfile copies is in the context it is built against, " +
    "so no COPY in it can stop the build on a source the client never uploaded",
  unresolved.length === 0, unresolved.join(" "));
}

// What the build script reads. A context carrying the Dockerfile and none
// of the harnesses would pass the case above and then build nothing.
function everyHarnessAndItsFixturesArrive(arrived) {
  var harnesses = harnessFiles();
  count("the tree still carries fuzz harnesses to ship, so what follows answers for them",
    harnesses.filter(function (h) { return /\.fuzz\.js$/.test(h); }).length > 0,
    harnesses.length + " file(s)");

  var missing = harnesses.concat(FUZZ_NAMED_FILES).filter(function (rel) {
    return arrived.indexOf(rel) === -1;
  });
  count("every harness reaches the context with the seed corpus and dictionary that " +
    "travel with it, and with the manifests the build installs from",
  missing.length === 0, missing.slice(0, 8).join(" "));

  count("the framework the harnesses require reaches it too",
    arrived.indexOf(VENDOR_ANCHOR) !== -1 &&
    arrived.some(function (p) { return p.indexOf("lib/vendor/blamejs/") === 0; }),
    VENDOR_ANCHOR);
}

// The dependency directory a local run leaves in the tree. `build.sh` runs
// `npm ci` inside the image, so a developer's install is dead weight on
// every build and is the largest thing in that directory.
function theLocalDependencyInstallStaysBehind(arrived) {
  var carried = arrived.filter(function (p) {
    return p.indexOf(FUZZ_DEPENDENCIES + "/") === 0;
  });
  count("a local dependency install under the harness directory is left behind, because " +
    "the build installs inside the image",
  carried.length === 0, carried.length + " file(s), first: " + carried.slice(0, 3).join(" "));
}

// The half a fix gets wrong. An adjacent ignore file replaces the context
// root's rather than adding to it, so every exclusion the root file carries
// has to be restated here or a fuzzing build uploads what every other build
// withholds.
//
// Derived from the root file rather than listed, so a pattern added there
// next year is probed on the run after it lands. The planted context is the
// one this repository cannot supply on its own: it holds no environment
// file, no private key outside the vendored tree and no database, which is
// exactly the material the root file names.
async function everyOtherExclusionStillHolds(scratchRoot, fuzzIgnoreText) {
  var rootPatterns = exclusionPatterns(
    nodeFs.readFileSync(repoPath(ROOT_IGNORE), "utf8"));
  var mustStillHold = rootPatterns.filter(function (p) {
    return FUZZ_BUILD_NEEDS.indexOf(p) === -1;
  });

  count("the context root's ignore file carries exclusions to carry over, so what follows " +
    "answers for the file rather than for an empty list",
  mustStillHold.length > 0, mustStillHold.length + " pattern(s)");
  count("the two the fuzzing build needs back are the only ones held out of that reading",
    rootPatterns.length - mustStillHold.length === FUZZ_BUILD_NEEDS.length,
    FUZZ_BUILD_NEEDS.join(" "));

  var probeRoot = nodePath.join(scratchRoot, "probe-context");
  var planted   = [];
  function plant(rel) {
    var abs = nodePath.join(probeRoot, rel.split("/").join(nodePath.sep));
    nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true, mode: 0o700 });
    nodeFs.writeFileSync(abs, rel + "\n", { mode: 0o600 });
    planted.push(rel);
  }
  nodeFs.mkdirSync(probeRoot, { recursive: true, mode: 0o700 });
  nodeFs.copyFileSync(repoPath(ROOT_IGNORE), nodePath.join(probeRoot, ".dockerignore"));
  mustStillHold.forEach(function (pattern) {
    var rel = probePathFor(pattern);
    plant(rel);
    plant(PROBE_DEPTH + "/" + rel);
  });
  plant(PROBE_KEPT_UNMATCHED);
  // One probe per line the context root's file excludes and this build
  // needs back. They are what separates the two ignore files: under the
  // root file neither arrives, and the render below is meaningless unless
  // both do.
  var needed = FUZZ_BUILD_NEEDS.map(function (pattern) {
    var rel = probePathFor(pattern) + "/probe-needed.txt";
    plant(rel);
    return rel;
  });

  var arrived = await renderContext(scratchRoot, probeRoot, "fuzz-probe", fuzzIgnoreText);

  count("the planted context rendered and carries the file no pattern names, so an empty " +
    "answer cannot be read as everything having been excluded",
  arrived.indexOf(PROBE_KEPT_UNMATCHED) !== -1, arrived.length + " path(s)");

  var absentNeeded = needed.filter(function (rel) { return arrived.indexOf(rel) === -1; });
  count("the planted render answered under the adjacent ignore file rather than the " +
    "context root's, measured by the two directories the root file withholds arriving",
  absentNeeded.length === 0, absentNeeded.join(" ") || needed.join(" "));

  var leaked = planted.filter(function (rel) {
    return rel !== PROBE_KEPT_UNMATCHED && needed.indexOf(rel) === -1 &&
      arrived.indexOf(rel) !== -1;
  });
  count("every exclusion the context root's file carries, except the two this build needs " +
    "back, still holds under the fuzzing build's own ignore file, at the context root and " +
    "one directory in, so the vault passphrase, the sealed keys and the live database are " +
    "left behind here as well",
  leaked.length === 0,
  leaked.length + " reached the daemon, first: " + (leaked.slice(0, 6).join(" ") || "none"));
}

// ---------------------------------------------------------------------------

async function run() {
  await harness.requireStack("fuzz-build-context.test.js");

  theBuildDefinitionCarriesAnIgnoreFileOfItsOwn();

  var fuzzIgnoreText = nodeFs.existsSync(repoPath(CFLITE_IGNORE))
    ? nodeFs.readFileSync(repoPath(CFLITE_IGNORE), "utf8")
    : null;
  var sources = copySources(nodeFs.readFileSync(repoPath(CFLITE_FILE), "utf8"));

  var scratchRoot = helpers.tempDir("fuzz-build-context");
  try {
    var arrived = await renderContext(
      scratchRoot, helpers.REPO_ROOT, "fuzz-rendered", fuzzIgnoreText);

    everyCopySourceReachesTheContext(arrived, sources);
    everyHarnessAndItsFixturesArrive(arrived);
    theLocalDependencyInstallStaysBehind(arrived);
    await everyOtherExclusionStillHolds(scratchRoot, fuzzIgnoreText);
  } finally {
    helpers.removeTempDir(scratchRoot);
  }

  return helpers.getChecks();
}

module.exports = { name: "fuzz-build-context", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
