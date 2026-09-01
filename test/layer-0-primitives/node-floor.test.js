// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * node-floor: the gate that keeps every stated Node version equal to the
 * one `engines.node` declares.
 *
 * The failure this covers is quiet and expensive. `package.json` says one
 * thing, `.nvmrc` says another, a workflow pins a bare major, and the
 * container image carries whatever runtime its base digest happened to
 * ship that week. Nothing disagrees loudly: every one of those files is
 * read by a different tool, so the tree can hold four answers at once and
 * every tool is satisfied with the one it reads. An operator following the
 * README installs a runtime the release pipeline never tested on.
 *
 * `scripts/check-node-floor.js` reads `engines.node` as the single source
 * of truth and refuses any other statement that disagrees with it. This
 * file drives that script the way the gate chain drives it, as a child
 * process whose exit code is the verdict, over synthetic trees built to
 * carry one defect each.
 *
 * ABSENCE IS A VECTOR HERE, not an afterthought. A gate that silently
 * skips a reference it cannot find stops gating at the moment the
 * reference is deleted, and a deleted reference is exactly what a careless
 * edit produces. So half the cases below remove something rather than
 * changing it, and each one asserts the gate still fails.
 *
 * The live tree is a case in its own right: the script runs against this
 * repository and must exit zero. That is the check that makes the rest of
 * the file worth having.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/node-floor.test.js`.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var { spawn } = require("node:child_process");
var helpers = require("../helpers");
var check   = helpers.check;

var REPO_ROOT  = helpers.REPO_ROOT;
var GATE       = path.join(REPO_ROOT, "scripts", "check-node-floor.js");
var PKG        = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));

// The floor the fixtures are written against. Read from the repository so
// this file never becomes a second place the floor is declared.
var FLOOR = String((PKG.engines || {}).node || "").replace(/^>=/, "");

// The drift cases need a well-formed version that is NOT the floor. It is
// derived rather than written, because the gate reads the bytes of every file
// in the tree including this one: a literal wrong floor here would be a real
// finding, and silencing it would mean excluding the test corpus from the
// sweep, which is the one place a fabricated version is most likely to hide.
function otherVersion(v) {
  var p = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!p) return "0.0.0";
  var minor = Number(p[2]);
  if (minor > 0) return p[1] + "." + (minor - 1) + ".0";
  return String(Number(p[1]) - 1) + ".0.0";
}

var OTHER       = otherVersion(FLOOR);
var OTHER_SHORT = OTHER.split(".").slice(0, 2).join(".");
var FLOOR_SHORT = FLOOR.split(".").slice(0, 2).join(".");

// The fragment a drift finding carries when it has read the pin itself.
// The absence findings name the key without ever quoting a version, so a
// case that asserts only "node-version" is satisfied by the gate failing
// because the pin went missing, which is not what these cases are about.
var DRIFTED = "is \"" + OTHER + "\"";

var SRC_DIGEST     = "sha256:" + "a1b2c3d4".repeat(8);
var RUNTIME_DIGEST = "sha256:" + "e5f60718".repeat(8);

// Concurrency for the fixture runs. Each case is an isolated child over
// its own directory, so they have nothing to contend for beyond CPU.
var LANES = 4;

// ---------------------------------------------------------------------------
// Running the gate
// ---------------------------------------------------------------------------

function runGate(args) {
  return new Promise(function (resolve) {
    var child = spawn(process.execPath, [GATE].concat(args || []), {
      cwd:   REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    var out = "";
    child.stdout.on("data", function (d) { out += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("error", function (e) { resolve({ code: -1, out: "spawn failed: " + e.message }); });
    child.on("close", function (code) { resolve({ code: code, out: out }); });
  });
}

// ---------------------------------------------------------------------------
// Fixture trees
// ---------------------------------------------------------------------------

// The base image records for one digest, one line per published platform.
var PLATFORMS = ["linux/amd64", "linux/arm64"];

function record(version, platform, digest) {
  return "# node: " + version + " on " + platform + " in " + digest + "\n";
}

function records(digest) {
  return PLATFORMS.map(function (p) { return record(FLOOR, p, digest); }).join("");
}

// A coherent tree: every reference the gate knows about, all agreeing with
// the floor. Each case below takes this and breaks exactly one thing, so a
// failure names the defect the case introduced rather than a fixture bug.
function coherentTree() {
  return {
    "package.json": JSON.stringify({
      name:    "fixture",
      version: "0.0.0",
      engines: { node: ">=" + FLOOR },
      scripts: { gates: "node scripts/check-node-floor.js" },
    }, null, 2) + "\n",

    ".nvmrc": FLOOR + "\n",

    "Dockerfile":
      "# syntax=docker/dockerfile:1.7\n" +
      records(SRC_DIGEST) +
      "ARG BASE_SRC=cgr.dev/chainguard/node:latest-dev@" + SRC_DIGEST + "\n" +
      records(RUNTIME_DIGEST) +
      "ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@" + RUNTIME_DIGEST + "\n" +
      "FROM ${BASE_RUNTIME} AS runtime\n",

    "README.md":
      "# fixture\n\n" +
      "<a href=\"https://nodejs.org\"><img src=\"https://img.shields.io/badge/node-%3E%3D" +
      FLOOR + "-2ea043\" alt=\"Node.js " + FLOOR + " or newer\"></a>\n\n" +
      "- **Node.js " + FLOOR + " or newer**, or Docker.\n",

    "CONTRIBUTING.md":
      "**Requirements:** Node.js " + FLOOR + " or newer. Nothing is transpiled.\n",

    "LTS-CALENDAR.md":
      "| Version | Minimum runtime |\n|---|---|\n| `v0.x` | Node >= " + FLOOR + " |\n",

    "docs/operator-guide.md":
      "Run `blamepost doctor` once the container is up.\n",

    ".github/workflows/ci.yml":
      "name: CI\njobs:\n  smoke:\n    steps:\n" +
      "      - name: Set up Node " + FLOOR + " LTS\n" +
      "        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020  # v7.0.0\n" +
      "        with:\n" +
      "          node-version: '" + FLOOR + "'\n",
  };
}

function materialize(root, tree) {
  Object.keys(tree).forEach(function (rel) {
    var abs = path.join(root, rel.split("/").join(path.sep));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, tree[rel], "utf8");
  });
}

// A case is { label, expect, mutate, names }. `expect` is "pass" or
// "fail"; `names` is a fragment the output must carry, so a case cannot be
// satisfied by the gate failing for an unrelated reason.
var CASES = [
  {
    label:  "a tree whose references all agree passes",
    expect: "pass",
    mutate: function () { /* the coherent tree, unmodified */ },
  },
  {
    label:  "a bare major in .nvmrc is refused",
    expect: "fail",
    names:  ".nvmrc",
    mutate: function (t) { t[".nvmrc"] = "24\n"; },
  },
  {
    label:  "a missing .nvmrc is refused rather than skipped",
    expect: "fail",
    names:  ".nvmrc",
    mutate: function (t) { delete t[".nvmrc"]; },
  },
  {
    label:  "a bare major in a workflow node-version is refused",
    expect: "fail",
    names:  "node-version",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("node-version: '" + FLOOR + "'", "node-version: '" + FLOOR.split(".")[0] + "'");
    },
  },
  {
    label:  "a setup-node step with no node-version is refused",
    expect: "fail",
    names:  "node-version",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace(/\s+with:\n\s+node-version: '[^']*'\n/, "\n");
    },
  },
  {
    label:  "a workflow directory with no setup-node step at all is refused",
    expect: "fail",
    names:  "setup-node",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = "name: CI\njobs:\n  lint:\n    steps:\n      - run: true\n";
    },
  },
  {
    label:  "no workflow directory at all is refused rather than skipped",
    expect: "fail",
    names:  ".github/workflows",
    mutate: function (t) { delete t[".github/workflows/ci.yml"]; },
  },
  {
    label:  "a workflow step name stating a different Node version is refused",
    expect: "fail",
    names:  "ci.yml",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("Set up Node " + FLOOR + " LTS", "Set up Node " + OTHER + " LTS");
    },
  },
  // ---- Shapes a line-oriented reader cannot see ----
  //
  // The workflow reader parses the document rather than matching lines, so
  // a pin is a pin wherever YAML lets it be written, and a line that only
  // looks like one is not. Each case below is one of those two directions,
  // and every one of them was answered wrongly by the line matcher this
  // replaced.
  {
    label:  "a node-version written as a flow mapping is read",
    expect: "fail",
    names:  DRIFTED,
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("        with:\n          node-version: '" + FLOOR + "'\n",
          "        with: { node-version: '" + OTHER + "' }\n");
    },
  },
  {
    label:  "a quoted node-version key is read",
    expect: "fail",
    names:  DRIFTED,
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("          node-version: '" + FLOOR + "'\n",
          "          \"node-version\": '" + OTHER + "'\n");
    },
  },
  {
    label:  "a matrix node-version list stating the floor passes",
    expect: "pass",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("  smoke:\n    steps:\n",
          "  smoke:\n    strategy:\n      matrix:\n        node-version: ['" + FLOOR + "']\n" +
          "    steps:\n");
    },
  },
  {
    label:  "a matrix node-version list is read entry by entry",
    expect: "fail",
    names:  DRIFTED,
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("  smoke:\n    steps:\n",
          "  smoke:\n    strategy:\n      matrix:\n        node-version: ['" + FLOOR + "', '" +
          OTHER + "']\n    steps:\n");
    },
  },
  {
    label:  "a node-version written inside a run body is a shell line, not a pin",
    expect: "pass",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] += "      - name: write a snippet\n" +
        "        run: |\n" +
        "          cat > snippet.yml <<'EOF'\n" +
        "          node-version: " + OTHER + "\n" +
        "          EOF\n";
    },
  },
  {
    label:  "shell punctuation in a run body does not stop the workflow being read",
    expect: "fail",
    names:  DRIFTED,
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = t[".github/workflows/ci.yml"]
        .replace("          node-version: '" + FLOOR + "'\n",
          "          node-version: '" + OTHER + "'\n") +
        "      - name: a shell step\n" +
        "        run: |\n" +
        "          test -f x && rm -f ./* # not a tag !bang\n";
    },
  },
  // A whole step written as one flow mapping. The vendored parser reads the
  // item as a plain scalar rather than as a mapping, so the step is not in
  // the parsed document at all, and a reader that trusted the result would
  // pass a drifted pin without ever seeing it. The case asserts the outcome
  // rather than the reason, so it keeps holding once the parser learns the
  // shape and the drift is caught by reading the pin instead.
  {
    label:  "a drifted pin in a step written as one flow mapping does not pass",
    expect: "fail",
    names:  "ci.yml",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = "name: CI\njobs:\n  smoke:\n    steps:\n" +
        "      - { name: setup, uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020, " +
        "with: { node-version: '" + OTHER + "' } }\n";
    },
  },
  {
    label:  "a workflow that does not parse as YAML is refused rather than read as pinning nothing",
    expect: "fail",
    names:  "does not parse",
    mutate: function (t) {
      t[".github/workflows/broken.yml"] = "name: broken\njobs:\n\tbuild:\n    steps: []\n";
    },
  },
  {
    label:  "a setup-node step with no pin of its own is refused where the file pins elsewhere",
    expect: "fail",
    names:  "setup-node",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = "name: CI\njobs:\n  smoke:\n" +
        "    strategy:\n      matrix:\n        node-version: ['" + FLOOR + "']\n" +
        "    steps:\n" +
        "      - name: Set up Node " + FLOOR + " LTS\n" +
        "        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020  # v7.0.0\n" +
        "        with:\n          cache: npm\n";
    },
  },
  {
    label:  "actions/setup-node named only in a comment does not count as setting Node up",
    expect: "fail",
    names:  "setup-node",
    mutate: function (t) {
      t[".github/workflows/ci.yml"] = "name: CI\njobs:\n  smoke:\n    steps:\n" +
        "      # uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020\n" +
        "      - run: true\n";
    },
  },
  {
    label:  "a base image recorded below the floor is refused",
    expect: "fail",
    names:  "Dockerfile",
    mutate: function (t) {
      t.Dockerfile = t.Dockerfile.replace(record(FLOOR, "linux/amd64", RUNTIME_DIGEST),
        record(OTHER, "linux/amd64", RUNTIME_DIGEST));
    },
  },
  {
    label:  "a record whose digest no longer matches its ARG is refused",
    expect: "fail",
    names:  "Dockerfile",
    mutate: function (t) {
      t.Dockerfile = t.Dockerfile.replace(
        "ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@" + RUNTIME_DIGEST,
        "ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@sha256:" + "0f1e2d3c".repeat(8));
    },
  },
  {
    label:  "an ARG with no record above it is refused rather than skipped",
    expect: "fail",
    names:  "Dockerfile",
    mutate: function (t) { t.Dockerfile = t.Dockerfile.replace(records(SRC_DIGEST), ""); },
  },
  {
    label:  "an ARG measured on only one published platform is refused",
    expect: "fail",
    names:  "linux/arm64",
    mutate: function (t) {
      t.Dockerfile = t.Dockerfile.replace(record(FLOOR, "linux/arm64", RUNTIME_DIGEST), "");
    },
  },
  {
    label:  "a malformed record is refused rather than read as absent",
    expect: "fail",
    names:  "malformed",
    mutate: function (t) {
      t.Dockerfile = t.Dockerfile.replace(record(FLOOR, "linux/arm64", RUNTIME_DIGEST),
        "# node: " + FLOOR + " in " + RUNTIME_DIGEST + "\n");
    },
  },
  {
    label:  "a Dockerfile missing one of the two base ARGs is refused",
    expect: "fail",
    names:  "BASE_SRC",
    mutate: function (t) {
      t.Dockerfile = t.Dockerfile
        .replace(records(SRC_DIGEST), "")
        .replace("ARG BASE_SRC=cgr.dev/chainguard/node:latest-dev@" + SRC_DIGEST + "\n", "");
    },
  },
  {
    label:  "a README badge stating a different version is refused",
    expect: "fail",
    names:  "README.md",
    mutate: function (t) {
      t["README.md"] = t["README.md"].replace("badge/node-%3E%3D" + FLOOR, "badge/node-%3E%3D" + OTHER);
    },
  },
  {
    label:  "a README with no badge is refused rather than skipped",
    expect: "fail",
    names:  "README.md",
    mutate: function (t) {
      t["README.md"] = "# fixture\n\n- **Node.js " + FLOOR + " or newer**, or Docker.\n";
    },
  },
  {
    label:  "prose stating a different floor is refused",
    expect: "fail",
    names:  "README.md",
    mutate: function (t) {
      t["README.md"] = t["README.md"]
        .replace("- **Node.js " + FLOOR + " or newer**", "- **Node.js " + OTHER + " or newer**");
    },
  },
  {
    label:  "a contributor guide with no floor statement is refused",
    expect: "fail",
    names:  "CONTRIBUTING.md",
    mutate: function (t) { t["CONTRIBUTING.md"] = "Open a pull request against main.\n"; },
  },
  {
    label:  "a support calendar stating a different floor is refused",
    expect: "fail",
    names:  "LTS-CALENDAR.md",
    mutate: function (t) {
      t["LTS-CALENDAR.md"] = t["LTS-CALENDAR.md"].replace("Node >= " + FLOOR, "Node >= " + OTHER);
    },
  },
  {
    label:  "a floor statement in an operator document is refused when it drifts",
    expect: "fail",
    names:  "operator-guide.md",
    mutate: function (t) {
      t["docs/operator-guide.md"] += "\nThe container needs Node.js " + OTHER + " or newer on the host.\n";
    },
  },
  {
    label:  "a floor statement in a file outside the document set is refused when it drifts",
    expect: "fail",
    names:  "helper.js",
    mutate: function (t) {
      t["scripts/helper.js"] = "// The release signature needs the engine floor (Node >=" +
        OTHER_SHORT + ", OpenSSL 3.5).\n";
    },
  },
  {
    label:  "a package.json with no engines.node is refused",
    expect: "fail",
    names:  "engines.node",
    mutate: function (t) {
      var pkg = JSON.parse(t["package.json"]);
      delete pkg.engines;
      t["package.json"] = JSON.stringify(pkg, null, 2) + "\n";
    },
  },
  {
    label:  "an engines.node range with no single floor is refused",
    expect: "fail",
    names:  "engines.node",
    mutate: function (t) {
      var pkg = JSON.parse(t["package.json"]);
      pkg.engines.node = "^24 || ^26";
      t["package.json"] = JSON.stringify(pkg, null, 2) + "\n";
    },
  },
  {
    label:  "an engines.node floor that is not a full three-part version is refused",
    expect: "fail",
    names:  "engines.node",
    mutate: function (t) {
      var pkg = JSON.parse(t["package.json"]);
      pkg.engines.node = ">=" + FLOOR_SHORT;
      t["package.json"] = JSON.stringify(pkg, null, 2) + "\n";
    },
  },
];

// ---------------------------------------------------------------------------

async function run() {
  check("the gate script exists at scripts/check-node-floor.js", fs.existsSync(GATE));

  check("engines.node declares a plain floor to test against", /^\d+\.\d+\.\d+$/.test(FLOOR));

  // The gate is only a gate if the chain runs it.
  check("the gates script runs check-node-floor",
    typeof PKG.scripts.gates === "string" &&
    PKG.scripts.gates.indexOf("check-node-floor.js") !== -1);

  // ---- The live tree ----

  var live = await runGate([]);
  check("the gate passes on this repository (exit 0), output: " +
    live.out.replace(/\s+/g, " ").trim().slice(0, 400),
  live.code === 0);

  check("a passing run names the floor it enforced", live.out.indexOf(FLOOR) !== -1);

  // ---- The invocation itself. Bad input is refused, never absorbed ----
  //
  // The failure this guards is a run that reports nothing because it read
  // nothing. A gate that answers "clean" for a directory it could not open is
  // worse than one that is not run at all, because somebody believes it.

  var scratch = helpers.tempDir("nodefloor");

  var badRoot = await runGate(["--root", path.join(scratch, "absent")]);
  check("a --root that does not exist fails rather than reporting a clean tree",
    badRoot.code === 2);

  var noValue = await runGate(["--root"]);
  check("--root with no value is refused", noValue.code === 2);

  var unknown = await runGate(["--sweep-everything"]);
  check("an unrecognized argument is refused", unknown.code === 2);

  // ---- The machine-readable report ----

  var jsonRoot = path.join(scratch, "json-case");
  materialize(jsonRoot, coherentTree());
  var jsonRun = await runGate(["--root", jsonRoot, "--json"]);
  check("a coherent tree reports zero findings over --json (exit 0), output: " +
    jsonRun.out.replace(/\s+/g, " ").trim().slice(0, 300),
  jsonRun.code === 0);

  var report = null;
  try { report = JSON.parse(jsonRun.out); }
  catch (_e) { /* a report that does not parse is what the next check reports */ }
  check("--json emits one parseable report", report !== null);
  check("--json names the floor it enforced", report && report.floor === FLOOR);
  check("--json carries an empty finding list on a coherent tree",
    report && Array.isArray(report.findings) && report.findings.length === 0);
  check("--json names every path the sweep does not read, with its reason",
    report && Array.isArray(report.exclusions) && report.exclusions.length > 0 &&
    report.exclusions.every(function (x) {
      return typeof x.pattern === "string" && typeof x.reason === "string" && x.reason.length > 0;
    }));

  // ---- The fixture cases ----

  var dir = helpers.tempDir("nodefloor");
  var results = [];
  var next = 0;

  async function lane() {
    for (;;) {
      var i = next;
      next += 1;
      if (i >= CASES.length) return;
      var c = CASES[i];
      var root = path.join(dir, "case-" + i);
      var tree = coherentTree();
      c.mutate(tree);
      materialize(root, tree);
      results[i] = await runGate(["--root", root]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(LANES, CASES.length) }, lane));

  CASES.forEach(function (c, i) {
    var r = results[i];
    var flat = r.out.replace(/\s+/g, " ").trim();
    if (c.expect === "pass") {
      check(c.label + " (exit 0), output: " + flat.slice(0, 300), r.code === 0);
      return;
    }
    check(c.label + " (non-zero exit), output: " + flat.slice(0, 300), r.code === 1);
    check(c.label + ": the finding names " + c.names + ", output: " + flat.slice(0, 300),
      flat.indexOf(c.names) !== -1);
  });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
