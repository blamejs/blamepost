// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * static-gate-invocation: a gate nothing runs is not a gate, and a gate
 * that first runs after the merge is a defect discovered in the most
 * expensive place there is.
 *
 * This repository carries a dozen static gates under `scripts/`. Each one
 * reads the committed tree and answers a question about it: does the
 * CHANGELOG still derive from the structured release notes, does every
 * vendored file still hash to what the manifest recorded, does every
 * reference still state the same engine floor. Writing one is half the
 * work. The other half is arranging for somebody to be told when it
 * fails, and that half has no visible symptom when it is missing: the
 * gate sits in `scripts/`, passes on the maintainer's machine, and is
 * invoked by nothing.
 *
 * Two shapes of that failure have already happened here, and neither one
 * is visible from either file on its own:
 *
 *   - A gate that runs NOWHERE. It exists, it is documented as required,
 *     and no workflow names it. The only way to notice is to read the
 *     script directory and the workflow directory side by side and
 *     compare them by eye.
 *   - A gate that runs only on a TAG PUSH. It is wired into the publish
 *     workflow and nothing else, so a pull request goes green without it
 *     and the gate first executes after the merge, at the moment its
 *     verdict costs the most to act on. This reads as covered from the
 *     workflow file, because the gate is right there in it.
 *
 * The durable fix is not a hand-checked list. It is one place that names
 * the static gates, executed by the workflow rather than described to it,
 * so a gate added to the list starts running pre-merge with no second
 * edit anywhere. That place is `scripts.gates` in package.json.
 *
 * Why that anchor and not another:
 *
 *   - It is COMMITTED and it SHIPS. Every clone and the published tarball
 *     both carry package.json, so this test reads the same list in a
 *     clean checkout and on a CI runner that it reads locally. An anchor
 *     that is absent in a clean checkout produces a test that passes
 *     having read nothing, which is the worst outcome available.
 *   - It is EXECUTABLE. A workflow runs `npm run gates`, so the list is
 *     not a description of what CI does, it is the thing CI does. A
 *     description drifts; a chain that is actually invoked cannot.
 *   - It is ALREADY the authority. `node-floor.test.js` and
 *     `supply-chain-vendor-integrity.test.js` each assert their own gate
 *     is named in this chain, on the same reasoning. A second list beside
 *     it would be a second thing to keep in step.
 *
 * So the cases below are three questions. Is the chain well formed and
 * does every link exist. Is the chain actually invoked by a workflow that
 * runs BEFORE a merge, which is what makes membership mean anything. And
 * is every gate-shaped script in `scripts/` reachable from a pull request,
 * either through the chain, through a direct step in a pull-request
 * workflow, or through a written exemption that says why it cannot answer
 * there at all.
 *
 * The exemptions are the part that has to stay honest, so they are held
 * to both edges. An exemption naming a script that no longer exists is
 * removed, and an exemption on a script that IS covered is removed too,
 * because a stale exemption is a note in the tree asserting something
 * untrue about it.
 *
 * No sockets, no database, no network. It reads package.json, the script
 * directory and the workflow files.
 *
 * Run standalone:
 * node test/layer-0-primitives/static-gate-invocation.test.js
 */

var fs   = require("node:fs");
var path = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

var REPO_ROOT     = helpers.REPO_ROOT;
var SCRIPTS_DIR   = path.join(REPO_ROOT, "scripts");
var WORKFLOWS_DIR = path.join(REPO_ROOT, ".github", "workflows");
var PACKAGE_JSON  = path.join(REPO_ROOT, "package.json");

// The npm script that carries the declared chain, and the command a
// workflow runs to execute it. Both are frozen contracts rather than
// renameable symbols: the key is what package.json publishes and the
// command is what a runner types.
var CHAIN_KEY     = "gates";
var CHAIN_COMMAND = "npm run " + CHAIN_KEY;

// ---------------------------------------------------------------------------
// Gates that cannot answer from a checkout, and why
// ---------------------------------------------------------------------------

/**
 * DECLARED_EXEMPT names each gate-shaped script that is deliberately not
 * reachable from a pull request, with the reason it cannot be.
 *
 * The bar is not "this gate is slow" or "nobody got to it". It is that
 * the gate has nothing true to say about a checkout: its verdict depends
 * on a tool the repository does not provision, on a running stack, or on
 * an artifact some earlier run has to produce first. Anything that CAN
 * answer from the committed tree belongs in the chain instead, because
 * the cheapest moment to learn it fails is before the merge.
 */
var DECLARED_EXEMPT = {
  "check-operator-prose.js":
    "Drives the technical-writing skill's offline checker, which is a " +
    "machine-local tool this repository never installs or vendors, because " +
    "zero runtime dependencies means a gate may not pull one in. A hosted " +
    "runner has no checker, and the gate refuses on absence by design rather " +
    "than skipping quietly, so on a runner it can only report the tool is " +
    "missing. Its earliest true verdict is the maintainer's machine before " +
    "the commit. It joins the chain when the repository itself provisions " +
    "the checker.",

  "check-services.js":
    "Probes the running listeners over the wire before the integration " +
    "suite starts, so a partial-up stack fails once here instead of as a " +
    "dozen connection errors. A checkout has nothing bound to probe: its " +
    "verdict is about a running server, not about the committed tree.",

  "check-swallow-coverage.js":
    "Reads an lcov report to prove every swallowing catch body is entered " +
    "by a test, so it needs a coverage run to have happened first. It is " +
    "invoked through the coverage script that produces that report rather " +
    "than read straight from the source tree.",

  "release.js":
    "The release orchestrator. It invokes gates rather than being one, and " +
    "its subcommands drive git, gh and the signed release commit, none of " +
    "which a pull-request run may do.",
};

// ---------------------------------------------------------------------------
// Reading the anchor
// ---------------------------------------------------------------------------

function _packageJson() {
  return JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8"));
}

/**
 * _chainSegments(chain) splits the declared chain into its links.
 *
 * The chain names a runner and then one QUOTED command per gate, so the
 * quoted spans are the links. A link is kept whole, flags and all,
 * because a gate invoked without its check flag is a different command.
 *
 * The links used to be joined with `&&` and were split on it. That shape
 * stopped at its first failing link and ran none of the rest, reporting
 * nothing about them at all, so one red gate turned every gate behind it
 * into a silence that reads like a red. The list is still declared in
 * exactly one place and still executed rather than described; what
 * changed is that a failing link no longer ends the run, which is why the
 * case below asks about the runner instead of about the join.
 */
function _chainSegments(chain) {
  var quoted = String(chain || "").match(/"[^"]+"/g) || [];
  return quoted
    .map(function (s) { return s.slice(1, -1).trim(); })
    .filter(function (s) { return s.length > 0; });
}

/**
 * _scriptPathsIn(text) pulls every `scripts/<name>.js` and
 * `test/**\/<name>.test.js` path out of a command line, so a link can be
 * checked against the file it claims to run.
 */
function _scriptPathsIn(text) {
  var found = String(text).match(/(?:scripts|test)\/[A-Za-z0-9_./-]+\.js/g);
  return found ? found : [];
}

// ---------------------------------------------------------------------------
// Reading the workflows, and when each of them fires
// ---------------------------------------------------------------------------

/**
 * _firesOnPullRequest(text) answers whether a workflow runs before a
 * merge.
 *
 * The distinction this whole file is about is pre-merge against
 * post-merge, and a workflow keyed on `push: tags:` is the post-merge
 * half. So the trigger block is read rather than assumed: the top-level
 * `on:` key, in either its block form or its inline list form, and
 * `pull_request` named inside it.
 *
 * A `pull_request` written deeper in the file, inside a job condition or
 * a script body, is not a trigger, which is why the block boundary is
 * read rather than the whole file searched.
 */
function _firesOnPullRequest(text) {
  var lines = String(text).split(/\r?\n/);
  var i;
  for (i = 0; i < lines.length; i++) {
    var line = lines[i];

    // The inline list form: `on: [push, pull_request]`.
    var inline = line.match(/^on:\s*\[(.*)\]\s*$/);
    if (inline) {
      return inline[1].split(",").some(function (t) {
        return t.trim() === "pull_request";
      });
    }

    // The inline scalar form: `on: pull_request`.
    var scalar = line.match(/^on:\s*([A-Za-z_]+)\s*$/);
    if (scalar) return scalar[1] === "pull_request";

    if (!/^on:\s*$/.test(line)) continue;

    // The block form. Everything indented under `on:` belongs to it, and
    // the block ends at the first line that starts in column zero.
    for (i = i + 1; i < lines.length; i++) {
      var body = lines[i];
      if (/^\S/.test(body)) return false;
      if (/^\s+pull_request:\s*$/.test(body)) return true;
      if (/^\s+pull_request:\s*\{/.test(body)) return true;
    }
    return false;
  }
  return false;
}

function _workflows() {
  return fs.readdirSync(WORKFLOWS_DIR)
    .filter(function (f) { return /\.ya?ml$/.test(f); })
    .sort()
    .map(function (f) {
      var text = fs.readFileSync(path.join(WORKFLOWS_DIR, f), "utf8");
      return {
        name:        f,
        text:        text,
        pullRequest: _firesOnPullRequest(text),
      };
    });
}

/**
 * _runLines(text) returns every shell line a workflow executes.
 *
 * A gate named in a comment is not a gate that runs, and this repository
 * writes long explanatory comments above nearly every step, so comment
 * lines are dropped before anything is matched. The same goes for a `name:`
 * that quotes the command it is about.
 */
function _runLines(text) {
  var lines  = String(text).split(/\r?\n/);
  var out    = [];
  var inRun  = false;
  var indent = 0;

  lines.forEach(function (line) {
    var trimmed = line.trim();

    if (inRun) {
      if (trimmed === "") { out.push(""); return; }
      var thisIndent = line.length - line.replace(/^\s*/, "").length;
      if (thisIndent > indent) {
        if (trimmed.charAt(0) !== "#") out.push(trimmed);
        return;
      }
      inRun = false;
    }

    if (trimmed.charAt(0) === "#") return;

    var block = line.match(/^(\s*)-?\s*run:\s*[|>][-+]?\s*$/);
    if (block) {
      inRun  = true;
      indent = block[1].length;
      return;
    }

    var single = line.match(/^\s*-?\s*run:\s+(.*)$/);
    if (single) out.push(single[1].trim());
  });

  return out;
}

// ---------------------------------------------------------------------------
// The gate-shaped scripts
// ---------------------------------------------------------------------------

/**
 * _gateScripts() returns every script in `scripts/` that answers a
 * question about the tree.
 *
 * Two shapes count, and both are structural rather than a hand-kept list.
 * A `check-` or `validate-` prefix is the naming convention this
 * repository uses for a gate. A script offering a `--check` flag is
 * asserting something about the tree whatever it is called, which is how
 * the changelog and release-notes gates are found: neither carries the
 * prefix and both are gates.
 *
 * It is EXPORTED because a second file asks a second question of the same
 * population: this one asks whether every gate is reachable before a
 * merge, and published-count-floor.test.js asks whether every gate says
 * what it examined. Two questions, one definition of what a gate is. A
 * copy of this function beside the other question would be a second
 * hand-maintained answer to "what counts as a gate", and the two would
 * come apart in the direction where one of them stops covering a new
 * script and reports a clean sweep of a smaller tree.
 */
function _gateScripts() {
  return fs.readdirSync(SCRIPTS_DIR)
    .filter(function (f) { return /\.js$/.test(f); })
    .filter(function (f) {
      if (/^(check|validate)-/.test(f)) return true;
      return fs.readFileSync(path.join(SCRIPTS_DIR, f), "utf8").indexOf('"--check"') !== -1;
    })
    .sort();
}

// ---------------------------------------------------------------------------
// Cases: the chain is well formed
// ---------------------------------------------------------------------------

function _chainCases(pkg) {
  var chain = pkg.scripts && pkg.scripts[CHAIN_KEY];

  count("the declared static-gate chain exists in package.json",
    typeof chain === "string" && chain.trim().length > 0,
    "scripts." + CHAIN_KEY + " = " + JSON.stringify(chain));

  if (typeof chain !== "string") return [];

  var segments = _chainSegments(chain);

  // Canary. A chain that read as empty would satisfy every claim below
  // about its links.
  count("the chain still reads as a set of links", segments.length > 1,
    segments.length + " link(s)");

  // Every link has to RUN, and every failure has to reach the exit code.
  // Those are two requirements and a shell join satisfies at most one of
  // them: `&&` carries the verdict and skips the rest of the list, while
  // `;` and `||` run the rest and report only the last link. Neither is
  // a way to get both, which is why the list is handed to a runner that
  // keeps its own tally. What is asserted here is that the chain reaches
  // that runner and that no link smuggles a shell operator back in;
  // gate-chain-completeness.test.js drives the runner itself and pins the
  // behavior.
  count("the chain hands its links to the runner that keeps a tally",
    chain.indexOf("scripts/run-gates.js") !== -1, "chain: " + chain);

  var joined = segments.filter(function (s) {
    return s.indexOf("&&") !== -1 || s.indexOf(";") !== -1 || s.indexOf("||") !== -1;
  });
  count("no link joins two gates behind one command, where the second would " +
    "be skipped or its verdict dropped", joined.length === 0, joined.join(" | "));

  var missing = [];
  segments.forEach(function (segment) {
    _scriptPathsIn(segment).forEach(function (rel) {
      if (!fs.existsSync(path.join(REPO_ROOT, rel))) missing.push(rel);
    });
  });
  count("every link in the chain names a file that exists", missing.length === 0,
    missing.join(", "));

  var pathless = segments.filter(function (s) { return _scriptPathsIn(s).length === 0; });
  count("every link in the chain names the file it runs", pathless.length === 0,
    pathless.join(" | "));

  return segments;
}

// ---------------------------------------------------------------------------
// Cases: something runs the chain, before the merge
// ---------------------------------------------------------------------------

function _invocationCases(workflows) {
  // Canary. A scan that found no workflow, or no pull-request workflow,
  // would agree with anything said about them.
  count("the workflow scan still finds workflow files", workflows.length > 0,
    workflows.length + " file(s)");

  var onPullRequest = workflows.filter(function (w) { return w.pullRequest; });
  count("the trigger reader still finds pull-request workflows",
    onPullRequest.length > 0,
    onPullRequest.map(function (w) { return w.name; }).join(", "));

  var runners = onPullRequest.filter(function (w) {
    return _runLines(w.text).some(function (l) { return l.indexOf(CHAIN_COMMAND) !== -1; });
  });

  count("a pull-request workflow runs the declared static-gate chain, so a gate " +
    "added to it is measured before the merge rather than after it",
  runners.length > 0,
  "looked for `" + CHAIN_COMMAND + "` in: " +
      onPullRequest.map(function (w) { return w.name; }).join(", "));

  return runners.length > 0;
}

// ---------------------------------------------------------------------------
// Cases: no gate is left unreachable from a pull request
// ---------------------------------------------------------------------------

function _coverageCases(workflows, segments, chainRuns) {
  var gates = _gateScripts();

  // Canary. An empty scan would report perfect coverage of nothing.
  count("the gate scan still finds the gate scripts", gates.length > 1,
    gates.length + " script(s): " + gates.join(", "));

  // Every shell line any pull-request workflow executes, in one list.
  var preMergeCommands = [];
  workflows.filter(function (w) { return w.pullRequest; }).forEach(function (w) {
    _runLines(w.text).forEach(function (l) { preMergeCommands.push(l); });
  });

  var chainText = chainRuns ? segments.join(" && ") : "";

  function _coverage(name) {
    if (chainText.indexOf("scripts/" + name) !== -1) return "chain";
    var direct = preMergeCommands.some(function (l) {
      return l.indexOf("scripts/" + name) !== -1;
    });
    return direct ? "workflow" : null;
  }

  var orphans = [];
  var staleExemptions = [];

  gates.forEach(function (name) {
    var how    = _coverage(name);
    var reason = DECLARED_EXEMPT[name];

    if (how && reason) {
      // A written exemption on a gate that IS reachable is a note in the
      // tree asserting something untrue about it. Delete the note.
      staleExemptions.push(name + " (reachable via the " + how + ")");
      return;
    }
    if (how) return;
    if (reason) return;

    orphans.push(name);
  });

  count("every gate-shaped script is reachable from a pull request, through the " +
    "chain, through a step in a pull-request workflow, or through a written " +
    "exemption saying why it cannot answer there",
  orphans.length === 0,
  orphans.length === 0 ? "" : "unreachable: " + orphans.join(", "));

  count("no exemption is written for a gate that is reachable anyway",
    staleExemptions.length === 0, staleExemptions.join(", "));

  // The exemption table itself. An entry naming a script that no longer
  // exists outlives the thing it was about and starts excusing nothing.
  var vanished = Object.keys(DECLARED_EXEMPT).filter(function (name) {
    return !fs.existsSync(path.join(SCRIPTS_DIR, name));
  });
  count("every exemption names a script that still exists", vanished.length === 0,
    vanished.join(", "));

  var unexplained = Object.keys(DECLARED_EXEMPT).filter(function (name) {
    return String(DECLARED_EXEMPT[name]).trim().length < 40;
  });
  count("every exemption carries a reason rather than a bare entry",
    unexplained.length === 0, unexplained.join(", "));
}

// ---------------------------------------------------------------------------
// Cases: the trigger reader itself
// ---------------------------------------------------------------------------

// The reader decides which half of the problem a workflow is in, so it is
// asserted directly rather than trusted. A reader that answered true for
// everything would report the tag-only gates as covered.
function _triggerReaderCases() {
  count("a block trigger naming pull_request reads as pre-merge",
    _firesOnPullRequest("name: x\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n") === true);

  count("a tag-push trigger does not read as pre-merge",
    _firesOnPullRequest('name: x\non:\n  push:\n    tags: ["v*"]\n  workflow_dispatch:\njobs:\n') === false);

  count("an inline list naming pull_request reads as pre-merge",
    _firesOnPullRequest("name: x\non: [push, pull_request]\njobs:\n") === true);

  count("an inline list without it does not",
    _firesOnPullRequest("name: x\non: [push]\njobs:\n") === false);

  count("a bare scalar trigger is read",
    _firesOnPullRequest("name: x\non: pull_request\njobs:\n") === true);

  count("the word appearing below the trigger block is not a trigger",
    _firesOnPullRequest('name: x\non:\n  push:\n    tags: ["v*"]\njobs:\n' +
      "  a:\n    if: github.event_name == 'pull_request'\n") === false);
}

// The run-line reader decides whether a gate is invoked or merely
// mentioned, and this repository writes a paragraph of comment above
// almost every step. A reader that counted comments would report the
// gaps as closed.
function _runLineReaderCases() {
  var single = _runLines("jobs:\n  a:\n    steps:\n      - name: a step\n" +
    "        run: node scripts/check-thing.js\n");
  count("a single-line run is read",
    single.length === 1 && single[0] === "node scripts/check-thing.js",
    JSON.stringify(single));

  var block = _runLines("jobs:\n  a:\n    steps:\n      - name: a step\n" +
    "        run: |\n          set -euo pipefail\n          node scripts/check-thing.js\n");
  count("a block run is read line by line",
    block.indexOf("node scripts/check-thing.js") !== -1, JSON.stringify(block));

  var commented = _runLines("jobs:\n  a:\n    steps:\n" +
    "      # run: node scripts/check-thing.js\n" +
    "      - name: a step\n        run: echo hello\n");
  count("a commented-out step is not a step that runs",
    commented.indexOf("node scripts/check-thing.js") === -1, JSON.stringify(commented));

  var inBody = _runLines("jobs:\n  a:\n    steps:\n      - name: a step\n" +
    "        run: |\n          # node scripts/check-thing.js\n          echo hello\n");
  count("a comment inside a block body is not a command either",
    inBody.indexOf("node scripts/check-thing.js") === -1, JSON.stringify(inBody));

  var named = _runLines("jobs:\n  a:\n    steps:\n" +
    "      - name: node scripts/check-thing.js\n        run: echo hello\n");
  count("a step name quoting the command is not the command",
    named.indexOf("node scripts/check-thing.js") === -1, JSON.stringify(named));
}

// ---------------------------------------------------------------------------

function run() {
  var pkg       = _packageJson();
  var workflows = _workflows();

  _triggerReaderCases();
  _runLineReaderCases();

  var segments  = _chainCases(pkg);
  var chainRuns = _invocationCases(workflows);
  _coverageCases(workflows, segments, chainRuns);

  return helpers.getChecks();
}

module.exports = {
  name:        "static-gate-invocation",
  run:         run,
  getChecks:   helpers.getChecks,
  gateScripts: _gateScripts,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
