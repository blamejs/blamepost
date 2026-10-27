// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a build actually sends, measured rather than read off the ignore
 * file.
 *
 * `.dockerignore` decides the build context: the set of bytes the client
 * hands the daemon before a single instruction runs. Nothing else in this
 * repository looks at it, and it is the one file here whose syntax LOOKS
 * like a file everybody already knows and is not.
 *
 * A `.gitignore` pattern with no slash in it matches at every depth, so
 * `*.log` there reaches a log twelve directories down. A `.dockerignore`
 * pattern is matched against the whole relative path with Go's
 * `filepath.Match`, whose `*` does not cross a separator, so `*.log`
 * there reaches exactly the logs sitting in the context root and nothing
 * below them. The two files are read side by side, they share an author
 * and a vocabulary, and the second one silently covers a fraction of what
 * it appears to.
 *
 * That is not a style point. The patterns written this way are the ones
 * guarding credential material and developer scratch, so the half that
 * silently does nothing is the half that matters: gate logs holding
 * captured source and failure transcripts, agent and editor state, and
 * anything a private key extension names once it is one directory in.
 *
 * The exclusion has to stop in one specific place. The vendored framework
 * carries a trust anchor whose extension is on that list, and an image
 * built without it ships a vendored tree that no longer matches the one
 * the integrity gate verifies. So the depth rule is asserted in both
 * directions here: excluded everywhere, kept under the vendored tree. A
 * fix that reached one directory too far would pass an absence check and
 * break the artifact.
 *
 * The measurement is the real one. Docker renders the context itself, to
 * a local directory, so what is counted is the same set an operator's own
 * `docker build .` uploads rather than this file's opinion about pattern
 * syntax.
 *
 * Two contexts are rendered, because this tree cannot answer the question
 * on its own. It carries no environment file, no private key outside the
 * vendored tree and no gate log outside a directory already excluded, so
 * measuring it says only that the files which happen to exist today were
 * left behind. An operator's tree has all three, which is why the ignore
 * file names them. The second context is planted for the purpose: the
 * repository's own ignore file, and one file per exclusion pattern
 * written both at the context root and one directory in. Docker decides,
 * and a pattern that reaches only the top of the tree shows up as the
 * copy at depth arriving while the copy at the root did not.
 *
 * The planted set is derived from the ignore file rather than listed
 * here. A list is the half that goes stale: it was a list of two names
 * matched against the file's own text, which asserted that the file said
 * what it said and would have gone on passing while sixteen patterns
 * reached nothing below the context root.
 *
 * Run standalone: node test/layer-2-integration/build-context.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var harness = require("./container-harness");

var count = helpers.count;

// Rendering the context needs an instruction file, and it must not be the
// shipped one: that Dockerfile copies a named list of paths, so a build of
// it would report on the COPY list rather than on the context. Two lines
// that take everything are what makes the whole context observable.
var CONTEXT_DOCKERFILE = "FROM scratch\nCOPY . /\n";

// Extensions that name key, certificate or archive material. Each is a
// pattern in `.dockerignore`, and each has to hold at every depth: a
// private key one directory below the context root is the same disclosure
// as one sitting in it.
var CREDENTIAL_EXTENSIONS = [".pem", ".key", ".crt", ".cert", ".p12", ".pfx"];

// The one path under that rule which has to survive it. The vendored
// framework ships a trust anchor, the image is built from the vendored
// tree, and a context that drops it produces an image whose vendored tree
// differs from the one the manifest pins.
var VENDOR_PREFIX = "lib/vendor/";

// Nothing in the build reads a dotted directory. Every one of them in
// this tree holds version control, CI definitions, editor state or the
// diagnostics a gate persists, and the only one tracked at all is the
// workflow directory, which the image does not contain.
//
// Asserted as the shape rather than as a list of names, because the list
// is the part that goes stale: a directory nobody has invented yet is
// caught by "it starts with a dot and a build does not read it", and is
// missed by any inventory somebody has to remember to extend.
var DOT_DIRECTORY = /(?:^|\/)\.[^/]+\//;

// Where the planted context puts its second copy of every probe file.
// One directory in is enough to separate a pattern that reaches the whole
// tree from one that reaches the context root: the file that vanishes
// from the top and arrives from here is the whole defect.
var PROBE_DEPTH = "deep/nested";

// The two planted files that must SURVIVE the render. One sits under the
// vendored prefix and carries a credential extension, so an exclusion
// widened one directory too far reports here as a keeper gone missing
// rather than passing every absence check on its way to a broken image.
// The other has no pattern behind it at all, so an empty answer cannot
// read as everything having been excluded.
var PROBE_KEPT_UNDER_VENDOR = VENDOR_PREFIX + "blamejs/probe-anchor.pem";
var PROBE_KEPT_UNMATCHED    = "probe-keeper.txt";

// The third place every probe is planted, and the one the depth rule
// cannot answer for on its own.
//
// The re-include at the end of the ignore file is the only line that puts
// a path back, and the file is last-match-wins, so it decides what every
// exclusion above it means inside the tree it names. Planting at the
// context root and one directory in measures how FAR an exclusion
// reaches; it cannot measure where the re-include stops, because no probe
// lands where the re-include applies. A negation written one shape too
// wide therefore passes both depth readings and hands the daemon the
// credential material the exclusions above it were written to withhold.
//
// This is not a context-only exposure. The shipped Dockerfile copies
// `lib` whole into the runtime stage, so a path the re-include restores
// is not merely uploaded to the daemon, it ships inside the published
// image.
var PROBE_DEPTH_UNDER_VENDOR = VENDOR_PREFIX + "blamejs/probe";

// The one shape the vendored tree genuinely needs back, and the reason.
// The framework ships a trust anchor whose extension is on the credential
// list, and an image built without it carries a vendored tree that no
// longer matches the one `lib/vendor/MANIFEST.json` pins, which breaks the
// integrity check for every operator who did not vendor it themselves.
// That anchor is the whole debt: measured against the real vendored tree,
// one file and no other is restored by the re-include.
//
// Every other exclusion keeps its meaning inside the vendored tree, which
// is what the case below reads. An environment file, a private key, a
// registry configuration or a database under the vendored prefix is the
// same disclosure it is anywhere else, and the vendored tree is not a
// reason to make an exception for it.
var VENDOR_RESTORED_SUFFIX = ".pem";

// The exclusion patterns the ignore file carries, in file order. Comments
// and blank lines are not patterns, and a negation is not an exclusion: it
// puts a path BACK, so probing one for absence would assert the opposite
// of what it is written to do.
function exclusionPatterns(ignoreText) {
  return ignoreText.split(/\r?\n/)
    .map(function (line) { return line.trim(); })
    .filter(function (line) {
      return line !== "" && line.charAt(0) !== "#" && line.charAt(0) !== "!";
    });
}

// One relative path a pattern is meant to catch, synthesized from the
// pattern itself. The depth prefix comes off, because depth is the thing
// being measured rather than assumed, and each wildcard becomes an
// ordinary segment so what is left is a name a file can have.
//
// Derived rather than listed, so a pattern added to the ignore file next
// year is probed on the run after it lands and nobody has to remember to
// extend anything here.
function probePathFor(pattern) {
  return pattern
    .replace(/^\*\*\//, "")
    .replace(/\*+/g, "probe")
    .replace(/\?/g, "p");
}

// Builds the context this repository does not contain: its own ignore
// file, one probe file per exclusion pattern at the context root and
// again at depth, and the two files that have to come back.
function plantProbeContext(scratchRoot, patterns) {
  var probeRoot = nodePath.join(scratchRoot, "probe-context");
  var planted   = [];

  function plant(rel) {
    var abs = nodePath.join(probeRoot, rel);
    nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true, mode: 0o700 });
    nodeFs.writeFileSync(abs, rel + "\n", { mode: 0o600 });
    planted.push(rel);
  }

  nodeFs.mkdirSync(probeRoot, { recursive: true, mode: 0o700 });
  nodeFs.copyFileSync(
    nodePath.join(helpers.REPO_ROOT, ".dockerignore"),
    nodePath.join(probeRoot, ".dockerignore"));

  var underVendor = [];
  patterns.forEach(function (pattern) {
    var rel = probePathFor(pattern);
    plant(rel);
    plant(PROBE_DEPTH + "/" + rel);
    // The same probe a third time, inside the tree the re-include names,
    // so what that line puts back is measured rather than assumed.
    var vendored = PROBE_DEPTH_UNDER_VENDOR + "/" + rel;
    plant(vendored);
    underVendor.push({ pattern: pattern, path: vendored });
  });
  plant(PROBE_KEPT_UNDER_VENDOR);
  plant(PROBE_KEPT_UNMATCHED);
  return { root: probeRoot, planted: planted, underVendor: underVendor };
}

// Renders a build context to a directory and returns every path in it,
// relative and separator-normalized.
//
// The instruction file is written outside the context on purpose. A
// Dockerfile placed inside it would appear in its own measurement.
async function renderContext(scratchRoot, contextRoot, outName) {
  var dockerfile = nodePath.join(scratchRoot, outName + ".Dockerfile");
  var outDir     = nodePath.join(scratchRoot, outName);
  nodeFs.writeFileSync(dockerfile, CONTEXT_DOCKERFILE, { mode: 0o600 });
  nodeFs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

  await harness.dockerOrThrow(
    ["build", "--file", dockerfile, "--output", "type=local,dest=" + outDir,
      contextRoot],
    "rendering a build context to measure what it would upload",
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

// The finding this file exists for. Every dotted directory in this tree
// is version control, CI definitions, editor state or the diagnostics a
// gate persists, and the context carried two of them whole, because the
// patterns meant to catch their contents reach only the context root.
function noDottedDirectoryIsUploaded(paths) {
  var carried = paths.filter(function (p) { return DOT_DIRECTORY.test(p); });
  count("no dotted directory reaches the build context at any depth, because nothing " +
    "in the build reads one and they hold this repository's own scratch",
    carried.length === 0,
    carried.length + " file(s), first: " + carried.slice(0, 3).join(" "));
}

// The same rule reached by a second route, so a pattern that stops
// working on a file sitting outside a dotted directory is still caught.
function noGateLogIsUploaded(paths) {
  var logs = paths.filter(function (p) { return /\.log$/.test(p); });
  count("no log file reaches the build context at any depth, so the pattern that " +
    "names them is doing what its position in the file implies",
    logs.length === 0, logs.length + " file(s), first: " + logs.slice(0, 3).join(" "));
}

// Both directions of the depth rule, which is the half a fix gets wrong.
// Excluded everywhere; kept under the vendored tree, whose trust anchor
// carries one of the same extensions and has to ship.
function credentialMaterialIsExcludedEverywhereButTheVendoredTree(paths) {
  var matching = paths.filter(function (p) {
    return CREDENTIAL_EXTENSIONS.some(function (ext) {
      return p.slice(-ext.length) === ext;
    });
  });
  // The exemption is the certificate shape inside the vendored tree, not
  // the tree itself. A prefix that exempts whatever happens to sit under
  // it reads every future private key there as expected, which is the
  // shape of a check that blesses the hole it was written to find.
  var outside = matching.filter(function (p) {
    if (p.indexOf(VENDOR_PREFIX) !== 0) return true;
    return p.slice(-VENDOR_RESTORED_SUFFIX.length) !== VENDOR_RESTORED_SUFFIX;
  });
  count("no key or certificate material reaches the build context outside the certificate " +
    "shape the vendored trust anchor needs, at any depth rather than only in the context root",
    outside.length === 0, outside.slice(0, 5).join(" ") || "nothing");

  // The guard on the fix. An exclusion written one directory too broad
  // passes every absence check above and produces an image whose vendored
  // tree no longer matches the one the manifest pins.
  var anchor = VENDOR_PREFIX + "blamejs/lib/vendor/bimi-trust-anchors.pem";
  count("the vendored trust anchor still reaches the build context, so the exclusion " +
    "above stops at the tree the image is built from",
    paths.indexOf(anchor) !== -1, anchor);
}

// The tree the repository is built from is not the tree an operator
// builds from. Ours has no environment file in it; theirs does, because
// the compose stack reads the vault passphrase from the environment and
// documents a local build from this same directory in the same file. So
// the question is put to docker against a context that has one, at the
// root and one directory in, and the answer is which copies came back.
//
// What is asserted is the depth, not the text. An assertion that the
// ignore file contains a given line reports on the line and on nothing
// the line does, which is how the file came to hold sixteen patterns
// that stopped at the context root while a check on two of them passed.
async function everyExclusionReachesEveryDepth(scratchRoot) {
  var ignoreText = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, ".dockerignore"), "utf8");
  var patterns = exclusionPatterns(ignoreText);
  count("the ignore file carries exclusion patterns to probe, so what follows answers for " +
    "the file rather than for an empty list",
    patterns.length > 0, patterns.length + " pattern(s)");

  var probe   = plantProbeContext(scratchRoot, patterns);
  var arrived = await renderContext(scratchRoot, probe.root, "probe-rendered");

  count("the planted context rendered and carries the file no pattern names, so an empty " +
    "answer cannot be read as everything having been excluded",
    arrived.indexOf(PROBE_KEPT_UNMATCHED) !== -1, arrived.length + " path(s)");

  var keepers = [PROBE_KEPT_UNDER_VENDOR, PROBE_KEPT_UNMATCHED];
  // The vendored copies are held out of this reading and answered by the
  // case below. This one asks how far an exclusion reaches; that one asks
  // where the re-include stops, and folding them together would report
  // one number for two questions with different remedies.
  var leaked  = probe.planted.filter(function (rel) {
    return keepers.indexOf(rel) === -1 && rel.indexOf(VENDOR_PREFIX) !== 0 &&
      arrived.indexOf(rel) !== -1;
  });
  count("every exclusion holds one directory in as well as at the context root, so the " +
    "environment file holding the vault passphrase and every private key beside it are " +
    "left behind wherever in the tree an operator keeps them",
    leaked.length === 0,
    leaked.length + " reached the daemon, first: " + (leaked.slice(0, 5).join(" ") || "none"));

  count("the re-include still stops the exclusions at the vendored tree, so a pattern " +
    "widened to reach every depth did not take the trust anchor with it",
    arrived.indexOf(PROBE_KEPT_UNDER_VENDOR) !== -1, PROBE_KEPT_UNDER_VENDOR);

  theReIncludeRestoresOneShapeAndNotTheRest(probe, arrived);
}

// Where the re-include stops, which the depth readings above cannot see.
//
// The ignore file is last-match-wins and the re-include is its last line,
// so that line decides what every exclusion above it means inside the tree
// it names. The exclusions are written to hold at every depth; a
// re-include written as a whole subtree cancels all of them inside it, and
// the environment file, the private key, the registry configuration and
// the database that the lines above withhold everywhere else are handed to
// the daemon from there, and, because the shipped Dockerfile copies `lib`
// whole, into the published image.
//
// The debt the re-include exists to pay is one file: the vendored trust
// anchor, whose extension is on the credential list. So what is asserted
// is that the line pays that debt and no more. Every exclusion probe
// planted inside the vendored tree has to be absent, except the shape the
// anchor needs, and the exception is named rather than a prefix that
// exempts whatever happens to sit under it.
function theReIncludeRestoresOneShapeAndNotTheRest(probe, arrived) {
  var restored = probe.underVendor.filter(function (entry) {
    return arrived.indexOf(entry.path) !== -1;
  });
  var unwanted = restored.filter(function (entry) {
    return entry.path.slice(-VENDOR_RESTORED_SUFFIX.length) !== VENDOR_RESTORED_SUFFIX;
  });

  count("the vendored probes were planted, so what follows answers for the re-include " +
    "rather than for an empty list",
    probe.underVendor.length > 0, probe.underVendor.length + " probe(s)");

  count("the re-include puts back the certificate shape the vendored trust anchor needs " +
    "and nothing else, so an exclusion written to hold at every depth still holds inside " +
    "the tree the image is built from",
    unwanted.length === 0,
    unwanted.length + " restored by the re-include, first: " +
      (unwanted.slice(0, 6).map(function (e) {
        return e.path + " (" + e.pattern + ")";
      }).join(" ") || "none"));
}

// A context is uploaded on every build. Size is the cheapest signal that
// something large is being carried by accident, and the bound is set far
// above the tree so it reports a directory nobody meant to send rather
// than ordinary growth.
function theContextIsTheSizeOfTheSourceTree(paths, scratchRoot) {
  var outDir = nodePath.join(scratchRoot, "rendered");
  var bytes = paths.reduce(function (sum, rel) {
    return sum + nodeFs.statSync(nodePath.join(outDir, rel)).size;
  }, 0);
  var ceilingBytes = 48 * 1024 * 1024;
  count("the build context stays within a bound set well above the source tree, so a " +
    "directory that starts being carried by accident is reported rather than copied into " +
    "every build",
    bytes <= ceilingBytes,
    Math.round(bytes / 1048576) + " MiB against a " +
      Math.round(ceilingBytes / 1048576) + " MiB ceiling");
}

// ---------------------------------------------------------------------------

async function run() {
  await harness.requireStack("build-context.test.js");

  var scratchRoot = helpers.tempDir("build-context");
  try {
    var paths = await renderContext(scratchRoot, helpers.REPO_ROOT, "rendered");
    count("the build context rendered and carries the application source, so an empty " +
      "answer cannot be read as everything having been excluded",
      paths.indexOf("package.json") !== -1 && paths.some(function (p) {
        return p.indexOf("lib/") === 0;
      }), paths.length + " path(s)");

    noDottedDirectoryIsUploaded(paths);
    noGateLogIsUploaded(paths);
    credentialMaterialIsExcludedEverywhereButTheVendoredTree(paths);
    await everyExclusionReachesEveryDepth(scratchRoot);
    theContextIsTheSizeOfTheSourceTree(paths, scratchRoot);
  } finally {
    helpers.removeTempDir(scratchRoot);
  }

  return helpers.getChecks();
}

module.exports = { name: "build-context", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
