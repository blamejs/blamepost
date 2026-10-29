#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check-node-floor: one declared Node version, and every other statement of it
 * held to that value.
 *
 * `engines.node` in package.json is the source of truth. Everything else that
 * names a Node version is a copy: `.nvmrc`, the `node-version` pin in each
 * workflow, the runtime inside the container base images, the README badge,
 * and the prose in the documents an operator reads before installing anything.
 *
 * Copies drift silently, and that is the whole reason this gate exists. Each
 * of those references is read by a different tool, so a tree can hold four
 * different answers at once and every tool is satisfied with the one it reads.
 * npm honors `engines`; nvm reads `.nvmrc`; the workflow runner reads
 * `node-version`; the operator reads the README. Nothing compares them. The
 * first sign is a bug report from someone who installed the version the README
 * told them to, on a runtime the release pipeline never ran a test on.
 *
 * What is checked:
 *
 *   engines.node   Must declare exactly one floor, written `>=X.Y.Z`. A range
 *                  with several branches has no single floor to compare
 *                  against, so it is refused rather than guessed at.
 *   .nvmrc         Must be that floor, in full. A bare major means a developer
 *                  and CI can be two minors apart while both look pinned.
 *   workflows      Every `node-version` in .github/workflows must be the
 *                  floor, every step that sets Node up must declare one of
 *                  its own, and at least one workflow must set Node up at
 *                  all. A step name that states a version is held to it too.
 *                  The workflow is READ AS A DOCUMENT, so a pin counts
 *                  wherever YAML lets it be written and a line that only
 *                  looks like one does not: a flow mapping, a quoted key and
 *                  a build-matrix list are pins, and a `node-version:` in a
 *                  `run:` script body is a shell line. A workflow that is
 *                  not a YAML document at all is a finding of its own.
 *   Dockerfile     Each digest-pinned base image carries a record of the Node
 *                  version measured inside it, one line per published
 *                  platform. A record names the digest it was measured
 *                  against, so bumping the digest without re-measuring fails
 *                  here instead of shipping an unknown runtime. The image may
 *                  run a NEWER Node than the floor, and usually does; what is
 *                  refused is a base image that has fallen below it.
 *   README badge   The version in the shields.io badge, which is the first
 *                  Node version most readers ever see.
 *   floor prose    Every sentence anywhere in the tree that states a Node
 *                  floor, recognized by its shape rather than by which file it
 *                  is in, so a new document cannot introduce a stale one.
 *
 * ABSENCE FAILS. Every rule above has a second half that fires when the
 * reference is gone rather than wrong: a missing .nvmrc, a workflow that sets
 * Node up without pinning it, an ARG with no record above it, a README with no
 * badge, a document that has lost its floor statement, a workflow this gate
 * could not read. A gate that shrugs at a reference it cannot find stops
 * gating at exactly the moment nobody is told, and a deleted reference is what
 * a careless edit produces most often.
 *
 * What is deliberately NOT a finding: prose about some other Node version.
 * "Node 26 deprecates X" and "Node 22 changed Y" are statements about the
 * runtime's history, not claims about this project's floor, and a gate that
 * flattened them would teach people to stop writing them. Only the floor
 * shapes count: `node >= V`, `node-%3E%3DV`, and `Node.js V or newer`.
 *
 * Pure static gate. It reads files, and it asks git which paths the repository
 * ignores. No network, no container runtime, no listeners bound.
 *
 * Run:
 *   node scripts/check-node-floor.js
 *   node scripts/check-node-floor.js --json
 *   node scripts/check-node-floor.js --root <dir>
 *
 * Exit codes:
 *   0  every reference states the declared floor
 *   1  a reference drifted, or a required reference is absent
 *   2  the run could not be performed (unreadable root, unreadable package.json)
 */

var fs   = require("node:fs");
var path = require("node:path");
var { spawnSync } = require("node:child_process");

// The hardened JSON reader, composed rather than hand-rolled. It matters here
// for one property in particular: a duplicate key is refused instead of
// last-wins. A package.json carrying two `engines` blocks has no single source
// of truth, which is precisely the condition this gate exists to detect, so
// reading it with a parser that silently picks one would defeat the check at
// its first step.
var b = require("../lib/vendor/blamejs");

// The one reader and writer of the published-count contract. Composed rather
// than written by hand here, so the definition of a refusable zero is the same
// one every caller of this gate applies to what it publishes.
var examinedCounts = require("./examined-counts.js");

var ROOT_DEFAULT = path.resolve(__dirname, "..");

var LABEL = "[node-floor] ";

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

// engines.node must be one floor, in full. `>=24.19` and `^24 || ^26` are both
// refused: the first cannot be compared against a three-part version without
// inventing a patch number, the second has no single floor.
var ENGINES_FLOOR_RE = /^>=\s*(\d+\.\d+\.\d+)$/;
var FULL_VERSION_RE  = /^(\d+)\.(\d+)\.(\d+)$/;

var WORKFLOW_DIR  = ".github/workflows";
var WORKFLOW_EXT  = /\.ya?ml$/;

// The profile the workflow read runs under.
//
// What refuses at EVERY profile was measured rather than assumed, and it is
// everything that would make trusting a document a mistake: a
// deserialization tag, an alias explosion, an anchor or alias of any size,
// a null byte, a tab in indentation, a genuine duplicate mapping key, and a
// document that does not parse. Choosing a profile below strict gives none
// of that up.
//
// What strict adds is a set of screens about how some OTHER parser might
// coerce a scalar, and ordinary Actions syntax trips them as a matter of
// course: `on:` reads as an implicit YAML 1.1 boolean, and so does a bare
// `No` in a step value. Neither says anything about which Node version a
// job runs on. Strict also carries a duplicate-key screen of its own that
// reads into block scalars, so a `script: |` body holding the same
// JavaScript property name in two object literals is reported as a
// duplicate mapping key; the parser underneath still refuses a real one.
var YAML_READ = Object.freeze({ profile: "balanced" });

// Tested against the VALUE of a step's `uses:` rather than against the text
// of the file. A workflow that names the action in a comment is naming it,
// not running it, and the pin a commented-out step does not carry is not a
// missing pin.
var SETUP_NODE_RE = /^actions\/setup-node(?:@|$)/;

// The two keys that state which runtime a job gets. Collected wherever the
// document writes them, because each is a statement of the same fact: a
// step's `with:`, a build matrix and a reusable-workflow input default all
// decide the version something runs on.
var PIN_KEY         = "node-version";
var PIN_FILE_KEY    = "node-version-file";
var PIN_KEYS        = [PIN_KEY, PIN_FILE_KEY];

// The depth the document walk stops at. The parser caps nesting well below
// this, so reaching it means the shape changed rather than that a workflow
// got deep.
var WALK_MAX_DEPTH = 64;

// A version stated next to the word Node in a workflow, which is how step
// names and comments carry one. This stays a scan over the file's text, and
// deliberately: a parse discards every comment, and a comment stating a
// Node version is exactly the copy that drifts unread. So the structure
// question is answered by the parsed document and the prose question by the
// bytes, and neither is asked of the other.
var WORKFLOW_NODE_MENTION_RE = /\bnode\s+v?(\d+(?:\.\d+){0,2})\b/gi;

// The base image records. They sit immediately above the ARG they describe,
// one line per platform, each naming the Node version measured inside that
// image and the digest it was measured against.
var BASE_ARG_RE    = /^ARG\s+(BASE_SRC|BASE_RUNTIME)\s*=\s*(\S+)\s*$/;
var BASE_RECORD_RE = /^#\s*node:\s*(\d+\.\d+\.\d+)\s+on\s+([a-z0-9]+\/[a-z0-9]+)\s+in\s+(sha256:[0-9a-f]{64})\s*$/;
var RECORD_LEAD_RE = /^#\s*node:/;
var DIGEST_RE      = /@(sha256:[0-9a-f]{64})\b/;
var REQUIRED_BASE_ARGS = ["BASE_SRC", "BASE_RUNTIME"];

// The platforms the container release publishes. A base image measured on only
// one of them leaves the other half of the published manifest unverified, and
// the two children of a multi-platform index are separately built images that
// can carry different package versions.
var REQUIRED_PLATFORMS = ["linux/amd64", "linux/arm64"];

var BADGE_FILE = "README.md";
var BADGE_RE   = /img\.shields\.io\/badge\/node-%3e%3d(\d+(?:\.\d+){0,2})/gi;

// The floor-statement shapes. `%3e%3d` is the URL-encoded `>=` a badge carries.
var FLOOR_STATEMENT_RES = [
  /\bnode(?:\.js|js)?\b[\s-]{0,4}(?:%3e%3d|>=)\s*v?(\d+(?:\.\d+){0,2})\b/gi,
  /\bnode(?:\.js|js)?\s+v?(\d+(?:\.\d+){0,2})\s+or\s+newer\b/gi,
];

// Documents that must carry at least one floor statement. Losing the sentence
// is as much a defect as getting it wrong: a contributor guide that no longer
// says which runtime to install sends someone to whatever their machine had.
var FLOOR_DOCUMENTS = ["README.md", "CONTRIBUTING.md", "LTS-CALENDAR.md"];

// Where the floor-statement sweep looks. The repository root is included as
// files only; these are the directories walked below it.
var SWEEP_DIRS = [".clusterfuzzlite", ".github", "bin", "docker", "docs", "fuzz",
  "lib", "release-notes", "scripts", "test"];
var SWEEP_EXT_RE   = /\.(?:js|mjs|cjs|md|ya?ml|json|toml|sh|html|css|txt)$/;
var SWEEP_NAME_RE  = /^(?:Dockerfile|NOTICE|LICENSE|\.nvmrc)$/;

// Paths the sweep does not read, each with the reason it does not. A skip that
// is not named is a blind spot nobody can review, so these are printed in the
// summary of every run rather than left to be inferred from the code.
var SWEEP_EXCLUSIONS = [
  {
    match:  /^lib\/vendor\//,
    reason: "the vendored framework declares its own engine floor and is replaced wholesale by the vendor refresh",
  },
  {
    match:  /(?:^|\/)package-lock\.json$/,
    reason: "generated, and it records the engine ranges of development packages rather than this project's floor. Matched at every depth, because the fuzz harness toolchain has a lockfile of its own and it records jazzer.js's floor rather than this repository's",
  },
  {
    match:  /^fuzz\/[^/]+_seed_corpus\//,
    reason: "fuzz seeds are wire bytes rather than prose, and libFuzzer writes its own entries into these directories during a run, so what is under them is not a fixed set anyone authored",
  },
  {
    match:  /(?:^|\/)node_modules\//,
    reason: "third-party packages state their own engine floors, and this gate answers for the floor this repository declares. Matched at every depth, because the fuzz harness installs its toolchain under a directory of its own. Only the filesystem fallback ever reaches this: the tracked-file discovery asks git, which never lists an ignored path, and without the exclusion the fallback reported a dozen findings out of third-party readme files that the tracked walk cannot see. The two discoveries still do not answer about the same tree, because the fallback walks every ignored directory as well and this removes only the largest of them, so treat a fallback verdict as advisory. The tracked walk is the gate",
  },
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function cmpVersion(a, bv) {
  var pa = FULL_VERSION_RE.exec(a);
  var pb = FULL_VERSION_RE.exec(bv);
  if (!pa || !pb) return NaN;
  for (var i = 1; i <= 3; i += 1) {
    var d = Number(pa[i]) - Number(pb[i]);
    if (d !== 0) return d;
  }
  return 0;
}

function toPosix(p) { return p.split(path.sep).join("/"); }

function readTextIfPresent(abs) {
  try { return fs.readFileSync(abs, "utf8"); }
  catch (_e) { return null; }
}

function splitLines(text) { return text.split(/\r?\n/); }

function lineOfIndex(text, index) {
  var n = 1;
  for (var i = 0; i < index && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) n += 1;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Reading a workflow
// ---------------------------------------------------------------------------

// The line a parse failure names, so a finding points at the byte that
// stopped the read rather than at the top of the file.
var PARSE_LINE_RE = /\bat line (\d+)/;

/**
 * readWorkflowDocument(text) parses one workflow, or says why it could not.
 *
 * A workflow this gate cannot read is a workflow whose Node pin nobody
 * checked, and the line matcher this replaces had no way to notice: it
 * walked whatever bytes were there, matched nothing, and the file joined
 * the count of files that were read. That is the absence case the rest of
 * this gate is built around, one level up from a missing `.nvmrc`.
 */
function readWorkflowDocument(text) {
  var doc;
  try {
    doc = b.guardYaml.parse(String(text), YAML_READ);
  } catch (e) {
    var why = (e && e.message) || String(e);
    var at  = PARSE_LINE_RE.exec(why);
    return { problem: why, line: at ? Number(at[1]) : 0 };
  }
  return { doc: doc };
}

// How a pin reads in a finding. A version is written as YAML wrote it; a
// value that is not a scalar is quoted whole, so a `node-version:` holding
// a mapping is reported as the thing it is instead of as [object Object].
function pinText(value) {
  if (typeof value === "string") return value;
  if (value === null || typeof value !== "object") return String(value);
  return JSON.stringify(value);
}

/**
 * collectWorkflow(doc) walks a parsed workflow and returns every Node pin
 * in it, every step that sets Node up, and the one shape the parser gets
 * wrong without saying so.
 *
 * The walk is over the whole document rather than down `jobs.*.steps`,
 * which keeps the breadth the line matcher had: a pin is a pin wherever
 * YAML lets it be written, including a flow mapping, a quoted key and a
 * build-matrix list, and none of those three were visible to a matcher
 * anchored on a line opening with the key.
 *
 * The setup-node steps come back separately because the file-level answer
 * is not enough. A workflow that pins a version in one job and sets Node up
 * unpinned in another satisfies "this file carries a pin" while the job
 * that runs takes whatever the runner image shipped.
 */
function collectWorkflow(doc) {
  var pins       = [];
  var setupSteps = [];
  var misparsed  = null;

  function walk(node, prefix, depth) {
    if (depth > WALK_MAX_DEPTH || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (var i = 0; i < node.length; i += 1) walk(node[i], prefix + "[" + i + "]", depth + 1);
      return;
    }

    var uses = node.uses;
    if (typeof uses === "string" && SETUP_NODE_RE.test(uses.trim())) {
      var w = node.with;
      var carriesPin = w !== null && typeof w === "object" && !Array.isArray(w) &&
        PIN_KEYS.some(function (k) { return Object.prototype.hasOwnProperty.call(w, k); });
      setupSteps.push({ path: prefix || "the document root", pinned: carriesPin });
    }

    Object.keys(node).forEach(function (k) {
      if (misparsed === null && k.charAt(0) === "{") misparsed = k;
      var here = prefix ? prefix + "." + k : k;
      var v    = node[k];
      if (PIN_KEYS.indexOf(k) !== -1) {
        if (Array.isArray(v)) {
          v.forEach(function (entry, i) {
            pins.push({ key: k, value: entry, path: here + "[" + i + "]" });
          });
        } else {
          pins.push({ key: k, value: v, path: here });
        }
      }
      walk(v, here, depth + 1);
    });
  }

  walk(doc, "", 0);
  return { pins: pins, setupSteps: setupSteps, misparsed: misparsed };
}

/**
 * lineForPin(lines, key, valueText) is where a pin was written, for the
 * report alone.
 *
 * The verdict comes from the parsed document; this only says where to look.
 * It answers only when exactly one line in the file carries both the key
 * and the value, so it is never a guess: a pin the source lookup cannot
 * place is reported with its document path and no line, rather than with a
 * line belonging to something else.
 */
function lineForPin(lines, key, valueText) {
  var found = 0;
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].indexOf(key) === -1) continue;
    if (valueText !== "" && lines[i].indexOf(valueText) === -1) continue;
    if (found !== 0) return 0;
    found = i + 1;
  }
  return found;
}

// ---------------------------------------------------------------------------
// Which paths the repository ignores
// ---------------------------------------------------------------------------

// Working notes and local scratch are not repository content, and on another
// clone they simply are not there. Asking git is the only answer that stays
// correct as the ignore rules change, and it covers a contributor's machine
// rules as well as the ones checked in.
//
// When git cannot answer, every candidate is read. That direction is
// deliberate: reading one file too many produces a finding somebody can look
// at, while skipping files on a guess produces silence.
// Paths are handed over in bounded batches. spawnSync writes the whole input
// before it reads a byte of output, so a payload large enough to fill the pipe
// buffer while the child is blocked writing its answer would hang, and a hung
// gate looks like a slow machine rather than a bug. A batch small enough to sit
// inside one pipe buffer cannot reach that state.
var IGNORE_BATCH_PATHS = 200;

function ignoredPaths(root, relPaths) {
  var ignored = Object.create(null);
  for (var start = 0; start < relPaths.length; start += IGNORE_BATCH_PATHS) {
    var batch = relPaths.slice(start, start + IGNORE_BATCH_PATHS);
    var res = spawnSync("git", ["check-ignore", "--stdin"], {
      cwd:      root,
      input:    batch.join("\n") + "\n",
      encoding: "utf8",
    });
    // status 0: some paths in the batch are ignored. status 1: none are.
    // Anything else means git could not answer, and the caller reads
    // everything rather than guessing.
    if (res.error || (res.status !== 0 && res.status !== 1)) return Object.create(null);
    String(res.stdout || "").split(/\r?\n/).forEach(function (line) {
      var t = line.trim();
      if (t) ignored[t] = true;
    });
  }
  return ignored;
}

// ---------------------------------------------------------------------------
// Candidate files for the floor-statement sweep
// ---------------------------------------------------------------------------

function sweepCandidates(root) {
  var out = [];

  function excluded(rel) {
    for (var i = 0; i < SWEEP_EXCLUSIONS.length; i += 1) {
      if (SWEEP_EXCLUSIONS[i].match.test(rel)) return true;
    }
    return false;
  }

  function consider(abs, rel) {
    var base = path.basename(rel);
    if (!SWEEP_EXT_RE.test(base) && !SWEEP_NAME_RE.test(base)) return;
    if (excluded(rel)) return;
    out.push({ abs: abs, rel: rel });
  }

  function walk(absDir, relDir) {
    var entries;
    try { entries = fs.readdirSync(absDir, { withFileTypes: true }); }
    catch (_e) { return; }
    entries.forEach(function (e) {
      var abs = path.join(absDir, e.name);
      var rel = relDir ? relDir + "/" + e.name : e.name;
      // An excluded directory is pruned rather than walked and discarded file
      // by file. The vendored tree alone is thousands of entries, and reading
      // them to throw them away is the difference between a gate that runs on
      // every edit and one that does not.
      if (e.isDirectory()) { if (!excluded(rel + "/")) walk(abs, rel); }
      else if (e.isFile()) consider(abs, rel);
    });
  }

  var rootEntries;
  try { rootEntries = fs.readdirSync(root, { withFileTypes: true }); }
  catch (_e) { rootEntries = []; }
  rootEntries.forEach(function (e) {
    if (e.isFile()) consider(path.join(root, e.name), e.name);
  });

  SWEEP_DIRS.forEach(function (d) {
    var abs = path.join(root, d.split("/").join(path.sep));
    if (fs.existsSync(abs)) walk(abs, d);
  });

  var ignored = ignoredPaths(root, out.map(function (f) { return f.rel; }));
  return out.filter(function (f) { return !ignored[f.rel]; });
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

function readFloor(root, findings) {
  var abs = path.join(root, "package.json");
  var raw = readTextIfPresent(abs);
  if (raw === null) {
    return { error: "package.json is unreadable at " + toPosix(abs) };
  }
  var pkg;
  try { pkg = b.guardJson.parse(raw); }
  catch (e) {
    return { error: "package.json could not be read: " + ((e && e.message) || String(e)) };
  }
  var declared = pkg && pkg.engines ? pkg.engines.node : undefined;
  if (typeof declared !== "string" || declared.length === 0) {
    findings.push({
      file: "package.json",
      message: "engines.node is absent. It is the source of truth for every other Node version in this repository, so there is nothing to hold the rest to.",
    });
    return { floor: null };
  }
  var m = ENGINES_FLOOR_RE.exec(declared.trim());
  if (!m) {
    findings.push({
      file: "package.json",
      message: "engines.node is \"" + declared + "\", which does not state one floor. Write it as >=X.Y.Z so every other reference has a single value to match.",
    });
    return { floor: null };
  }
  return { floor: m[1], declared: declared.trim() };
}

function checkNvmrc(root, floor, findings, counts) {
  var rel = ".nvmrc";
  var raw = readTextIfPresent(path.join(root, rel));
  if (raw === null) {
    findings.push({
      file: rel,
      message: "absent. nvm and the contributor setup read this file, so without it a developer runs whichever Node their shell last selected.",
    });
    return;
  }
  var value = raw.trim();
  counts.nvmrc = 1;
  if (value !== floor) {
    findings.push({
      file: rel,
      message: "states \"" + value + "\", and engines.node declares " + floor +
        ". A bare major here lets a developer and the release runner sit minors apart while both look pinned.",
    });
  }
}

function checkWorkflows(root, floor, findings, counts) {
  var dirAbs = path.join(root, WORKFLOW_DIR.split("/").join(path.sep));
  var names;
  try {
    names = fs.readdirSync(dirAbs).filter(function (n) { return WORKFLOW_EXT.test(n); });
  } catch (_e) {
    findings.push({
      file: WORKFLOW_DIR,
      message: "absent or unreadable, so no workflow node-version pin can be checked.",
    });
    return;
  }
  if (!names.length) {
    findings.push({
      file: WORKFLOW_DIR,
      message: "holds no workflow files, so nothing pins the Node version continuous integration runs on.",
    });
    return;
  }

  var setupNodeFiles = 0;
  names.sort().forEach(function (name) {
    var rel = WORKFLOW_DIR + "/" + name;
    var text = readTextIfPresent(path.join(dirAbs, name));
    if (text === null) {
      findings.push({ file: rel, message: "unreadable." });
      return;
    }

    var read = readWorkflowDocument(text);
    if (read.problem) {
      findings.push({
        file: rel,
        line: read.line,
        message: "does not parse as YAML, so nothing in it was checked and every pin it " +
          "carries went unread: " + read.problem,
      });
      return;
    }

    var lines = splitLines(text);
    var found = collectWorkflow(read.doc);

    // The one wrong answer the parser gives without saying so. A flow
    // mapping written as the item of a block sequence, `- { uses: x }`,
    // comes back as a mapping whose single key is `"{ uses"` and whose
    // value is the rest of the line as text, so the step is not refused, it
    // is simply not in the document. A mapping key opening with a brace is
    // that misparse and nothing else produces one, so this check disappears
    // on its own when the parser learns the shape.
    if (found.misparsed !== null) {
      findings.push({
        file: rel,
        message: "a flow mapping in block-sequence position was read as the plain scalar key " +
          JSON.stringify(found.misparsed) + ", so the step it belongs to is not in the parsed " +
          "document and any Node pin on it went unchecked. Write the item as a block mapping.",
      });
    }

    found.pins.forEach(function (p) {
      counts.workflowPins += 1;
      var value = pinText(p.value);
      if (p.key === PIN_FILE_KEY) {
        if (value !== ".nvmrc") {
          findings.push({
            file: rel,
            line: lineForPin(lines, p.key, value),
            message: p.path + " points at \"" + value + "\", which this gate does not hold to " +
              "the floor. Point it at .nvmrc, or pin " + PIN_KEY + " directly.",
          });
        }
        return;
      }
      if (value !== floor) {
        findings.push({
          file: rel,
          line: lineForPin(lines, p.key, value),
          message: p.path + " is \"" + value + "\", and engines.node declares " + floor + ".",
        });
      }
    });

    if (found.setupSteps.length > 0) {
      setupNodeFiles += 1;
      if (found.pins.length === 0) {
        findings.push({
          file: rel,
          message: "sets Node up with actions/setup-node and declares no " + PIN_KEY +
            ", so the job runs whichever Node the runner image happens to carry.",
        });
      }
      // Bound to the step rather than to the file. A pin somewhere else in
      // the document does not reach the job that is about to run unpinned.
      found.setupSteps.forEach(function (s) {
        if (s.pinned) return;
        findings.push({
          file: rel,
          message: "the actions/setup-node step at " + s.path + " declares no " + PIN_KEY +
            " of its own, so that job runs whichever Node the runner image happens to carry " +
            "however the rest of the file is pinned.",
        });
      });
    }

    // A version written beside the word Node, which is how step names and
    // comments carry one. Read off the bytes, because a parse discards the
    // comments this is here for.
    WORKFLOW_NODE_MENTION_RE.lastIndex = 0;
    var hit;
    while ((hit = WORKFLOW_NODE_MENTION_RE.exec(text)) !== null) {
      counts.workflowMentions += 1;
      if (hit[1] !== floor) {
        findings.push({
          file: rel,
          line: lineOfIndex(text, hit.index),
          message: "names Node " + hit[1] + ", and engines.node declares " + floor + ".",
        });
      }
    }
  });

  if (setupNodeFiles === 0) {
    findings.push({
      file: WORKFLOW_DIR,
      message: "no workflow uses actions/setup-node, so nothing in continuous integration pins the Node version the gates run on.",
    });
  }
  counts.workflowFiles = names.length;
  counts.setupNodeFiles = setupNodeFiles;
}

function checkDockerfile(root, floor, findings, counts) {
  var rel = "Dockerfile";
  var text = readTextIfPresent(path.join(root, rel));
  if (text === null) {
    findings.push({
      file: rel,
      message: "absent, so nothing records which Node version the published image carries.",
    });
    return;
  }
  var lines = splitLines(text);
  var seen = Object.create(null);

  lines.forEach(function (line, i) {
    var m = BASE_ARG_RE.exec(line);
    if (!m) return;
    var argName = m[1];
    var value   = m[2];
    seen[argName] = true;
    counts.baseArgs += 1;

    var d = DIGEST_RE.exec(value);
    if (!d) {
      findings.push({
        file: rel,
        line: i + 1,
        message: argName + " is not digest-pinned, so the Node version inside it cannot be recorded or held to the floor.",
      });
      return;
    }
    var digest = d[1];

    // The records are the run of comment lines directly above the ARG. Every
    // line in that run that opens `# node:` must parse as a record, so a
    // mistyped one reads as malformed rather than as absent.
    var covered = Object.create(null);
    var recordLines = 0;
    for (var j = i - 1; j >= 0 && lines[j].trim().charAt(0) === "#"; j -= 1) {
      if (!RECORD_LEAD_RE.test(lines[j])) continue;
      recordLines += 1;
      var record = BASE_RECORD_RE.exec(lines[j].trim());
      if (!record) {
        findings.push({
          file: rel,
          line: j + 1,
          message: argName + " has a malformed Node version record. Write it as `# node: <version> on <platform> in <digest>`.",
        });
        continue;
      }
      counts.baseRecords += 1;
      covered[record[2]] = true;

      if (record[3] !== digest) {
        findings.push({
          file: rel,
          line: j + 1,
          message: argName + " was measured against " + record[3].slice(0, 19) +
            " and now pins " + digest.slice(0, 19) +
            ". Measure the new image and update the record, so the version this file claims is one somebody read off the image.",
        });
      }
      var cmp = cmpVersion(record[1], floor);
      if (cmp < 0) {
        findings.push({
          file: rel,
          line: j + 1,
          message: argName + " carries Node " + record[1] + " on " + record[2] +
            ", below the engines.node floor of " + floor + ". The image cannot run this project.",
        });
      }
    }

    if (recordLines === 0) {
      findings.push({
        file: rel,
        line: i + 1,
        message: argName + " carries no Node version record above it. Measure the image and write `# node: <version> on <platform> in <digest>` on the lines above, so a digest bump that drops below the floor is visible in the diff.",
      });
      return;
    }

    REQUIRED_PLATFORMS.forEach(function (p) {
      if (!covered[p]) {
        findings.push({
          file: rel,
          line: i + 1,
          message: argName + " has no Node version record for " + p +
            ", which the container release publishes. Half the published manifest would go unmeasured.",
        });
      }
    });
  });

  REQUIRED_BASE_ARGS.forEach(function (argName) {
    if (!seen[argName]) {
      findings.push({
        file: rel,
        message: "declares no " + argName + " base image argument, so one of the two build stages has no recorded runtime.",
      });
    }
  });
}

function checkBadge(root, floor, findings, counts) {
  var text = readTextIfPresent(path.join(root, BADGE_FILE));
  if (text === null) {
    findings.push({ file: BADGE_FILE, message: "absent." });
    return;
  }
  BADGE_RE.lastIndex = 0;
  var hit;
  var found = 0;
  while ((hit = BADGE_RE.exec(text)) !== null) {
    found += 1;
    counts.badges += 1;
    if (hit[1] !== floor) {
      findings.push({
        file: BADGE_FILE,
        line: lineOfIndex(text, hit.index),
        message: "the Node badge reads " + hit[1] + ", and engines.node declares " + floor +
          ". It is the first Node version most readers see.",
      });
    }
  }
  if (found === 0) {
    findings.push({
      file: BADGE_FILE,
      message: "carries no Node version badge. It is the reference a reader takes at a glance, and losing it is how the stated floor stops being checked at all.",
    });
  }
}

function checkFloorStatements(root, floor, findings, counts) {
  var carriers = Object.create(null);
  sweepCandidates(root).forEach(function (f) {
    var text = readTextIfPresent(f.abs);
    if (text === null) return;
    FLOOR_STATEMENT_RES.forEach(function (re) {
      re.lastIndex = 0;
      var hit;
      while ((hit = re.exec(text)) !== null) {
        counts.statements += 1;
        carriers[f.rel] = (carriers[f.rel] || 0) + 1;
        if (hit[1] !== floor) {
          findings.push({
            file: f.rel,
            line: lineOfIndex(text, hit.index),
            message: "states a Node floor of " + hit[1] + ", and engines.node declares " + floor + ".",
          });
        }
      }
    });
  });

  FLOOR_DOCUMENTS.forEach(function (doc) {
    if (!carriers[doc]) {
      findings.push({
        file: doc,
        message: "carries no statement of the Node floor. Say which runtime the project needs, so this gate has something to hold to " + floor + ".",
      });
    }
  });
  counts.floorDocuments = FLOOR_DOCUMENTS.filter(function (d) { return carriers[d]; }).length;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

function evaluate(root) {
  var findings = [];
  var counts = {
    nvmrc: 0, workflowFiles: 0, setupNodeFiles: 0, workflowPins: 0,
    workflowMentions: 0, baseArgs: 0, baseRecords: 0, badges: 0,
    statements: 0, floorDocuments: 0,
  };

  var floorRead = readFloor(root, findings);
  if (floorRead.error) return { fatal: floorRead.error, findings: findings, counts: counts, floor: null };
  var floor = floorRead.floor;
  if (!floor) return { findings: findings, counts: counts, floor: null };

  checkNvmrc(root, floor, findings, counts);
  checkWorkflows(root, floor, findings, counts);
  checkDockerfile(root, floor, findings, counts);
  checkBadge(root, floor, findings, counts);
  checkFloorStatements(root, floor, findings, counts);

  findings.sort(function (x, y) {
    if (x.file !== y.file) return x.file < y.file ? -1 : 1;
    return (x.line || 0) - (y.line || 0);
  });
  return { findings: findings, counts: counts, floor: floor, declared: floorRead.declared };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// Entry point, so bad input throws rather than degrading to a default: an
// operator running this by hand finds the mistake in the invocation, not in a
// report about a directory that was never read.
function parseArgs(argv) {
  var opts = { root: ROOT_DEFAULT, json: false };
  for (var i = 0; i < argv.length; i += 1) {
    var a = argv[i];
    if (a === "--json") { opts.json = true; continue; }
    if (a === "--root") {
      i += 1;
      if (i >= argv.length) throw new TypeError("--root requires a directory path");
      opts.root = path.resolve(argv[i]);
      continue;
    }
    throw new TypeError("unrecognized argument: " + a);
  }
  var stat;
  try { stat = fs.statSync(opts.root); }
  catch (_e) { throw new TypeError("--root is not a readable directory: " + toPosix(opts.root)); }
  if (!stat.isDirectory()) throw new TypeError("--root is not a directory: " + toPosix(opts.root));
  return opts;
}

function formatFinding(f) {
  return LABEL + f.file + (f.line ? ":" + f.line : "") + ": " + f.message;
}

// WHAT THE RUN EXAMINED, published as the last lines of stdout on every path
// that reaches a verdict:
//
//   EXAMINED <n> workflow-floor-references
//   EXAMINED <n> container-floor-references
//   EXAMINED <n> document-floor-references
//   EXAMINED <n> floor-documents
//
// FOUR, one per discovery, because a discovery is what stops matching and a
// sum hides the one that did. These numbers used to be added together into a
// single `floor-references`, and that unit could not refuse the fault it
// existed to catch: the workflow sweep going to zero, which is a moved
// `.github/workflows` or a `node-version:` matcher that stopped matching, left
// the total at twenty-five out of thirty-eight and the gate printed OK. A unit
// that can be carried by the ones beside it answers for none of them.
//
// The split follows the three parts of the tree the sweep reads, since those
// are the three ways a walk can be pointed somewhere the references no longer
// are. `workflow-floor-references` is the workflow directory: version pins and
// named versions. `container-floor-references` is the container surface: the
// platform records the base images carry. `document-floor-references` is the
// prose: badges and floor statements. `floor-documents` is the required
// documents the floor was found stated in, and it moves on its own again: the
// three sweeps above can all read correctly while the document set the gate is
// pointed at has gone.
//
// Badges and statements share a unit rather than splitting further, because a
// repository can legitimately carry no badge and the number that would then go
// to zero is not a fault. Every other unit here is a set this repository cannot
// empty without that being the finding, so no unit below can be carried by
// another one.
//
// In --json mode the same numbers already ride inside the document as
// `counts`, so the lines are not appended there: that stdout carries the
// document alone for a caller that parses it.
function _examinedUnits(counts) {
  var c = counts || {};
  return [
    { unit: "workflow-floor-references",
      n: (c.workflowPins || 0) + (c.workflowMentions || 0) },
    { unit: "container-floor-references", n: c.baseRecords || 0 },
    { unit: "document-floor-references",
      n: (c.badges || 0) + (c.statements || 0) },
    { unit: "floor-documents", n: c.floorDocuments || 0 },
  ];
}

// Published through the shared publisher rather than written by hand, so an
// empty unit is refused by the one definition of a refusable zero instead of
// being emitted as a line every caller is right to reject. The return is the
// publisher's verdict, which a caller folds into its own: a run that found
// findings keeps its exit 1, and a run that found none but examined nothing
// takes one.
function _publishExamined(counts) {
  return examinedCounts.publish(_examinedUnits(counts), { tag: LABEL.trim() });
}

function main(argv) {
  var opts;
  try { opts = parseArgs(argv); }
  catch (e) {
    process.stderr.write(LABEL + ((e && e.message) || String(e)) + "\n");
    return 2;
  }

  var res = evaluate(opts.root);

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      floor:      res.floor,
      declared:   res.declared || null,
      fatal:      res.fatal || null,
      counts:     res.counts,
      exclusions: SWEEP_EXCLUSIONS.map(function (x) { return { pattern: String(x.match), reason: x.reason }; }),
      findings:   res.findings,
    }) + "\n");
    if (res.fatal) return 2;
    return res.findings.length ? 1 : 0;
  }

  if (res.fatal) {
    process.stderr.write(LABEL + res.fatal + "\n");
    return 2;
  }

  SWEEP_EXCLUSIONS.forEach(function (x) {
    process.stdout.write(LABEL + "not swept: " + String(x.match) + ", because " + x.reason + ".\n");
  });

  if (res.findings.length) {
    res.findings.forEach(function (f) { process.stderr.write(formatFinding(f) + "\n"); });
    process.stderr.write(LABEL + res.findings.length + " reference(s) disagree with the declared Node floor" +
      (res.floor ? " of " + res.floor : "") + ".\n");
    // Published on the failing path too, so the number is in the log beside
    // the findings rather than only beside a pass.
    _publishExamined(res.counts);
    return 1;
  }

  var c = res.counts;
  process.stdout.write(LABEL + "OK, every reference states the engines.node floor " + res.floor + ".\n");
  process.stdout.write(LABEL + "checked: .nvmrc, " + c.workflowPins + " node-version pin(s) and " +
    c.workflowMentions + " named version(s) across " + c.setupNodeFiles + " of " + c.workflowFiles +
    " workflow(s), " + c.baseArgs + " base image(s) carrying " + c.baseRecords + " platform record(s), " +
    c.badges + " badge(s), " + c.statements + " floor statement(s) including " +
    c.floorDocuments + " of " + FLOOR_DOCUMENTS.length + " required document(s).\n");
  // The publisher's verdict IS the verdict when nothing else objected: a sweep
  // that compared no reference has a clean answer covering no part of the tree,
  // and that is the fault this gate is most likely to develop quietly.
  return _publishExamined(c);
}

module.exports = {
  evaluate:            evaluate,
  cmpVersion:          cmpVersion,
  FLOOR_DOCUMENTS:     FLOOR_DOCUMENTS,
  SWEEP_EXCLUSIONS:    SWEEP_EXCLUSIONS,
  // Exported so the split can be asserted directly. Which references land in
  // which unit is the whole of what the change to this gate was, and reading
  // it back off a run's stdout would only ever confirm the numbers this tree
  // happens to hold today rather than the rule that put them there.
  _examinedUnits:      _examinedUnits,
};

if (require.main === module) process.exit(main(process.argv.slice(2)));
