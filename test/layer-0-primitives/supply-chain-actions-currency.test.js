// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * supply-chain-actions-currency: a reference the gate did not measure is
 * UNKNOWN, and UNKNOWN is not current.
 *
 * `scripts/check-actions-currency.js` reads every `uses:` reference out of
 * the workflow files and asks GitHub whether the pinned version is still
 * the latest release. A gate that reports a stale pin is useful. A gate
 * that prints "every pinned action matches the latest upstream release"
 * because the API refused the connection has stopped measuring anything and
 * says the opposite in the line CI reads.
 *
 * That is the same failure its sibling `scripts/check-vendor-currency.js`
 * carries a written policy against, and it is the one answer a currency
 * gate must never give. Three things count as unmeasured and they are the
 * same hole from three directions: an upstream that did not answer, an
 * answer that could not be compared against the pin, and a reference the
 * reader could not classify well enough to ask about.
 *
 * The third one is the quiet one, so it gets the most cases here. A reader
 * that matches the shape it expects and drops everything else counts what
 * it recognized while a reference nobody vouched for rides through, and the
 * summary line reads clean. The one reference in this repository that must
 * stay pinned to a tag was invisible to every run that way, and a tag is
 * exactly the pin that can least look after itself: a commit id is
 * immutable, so a stale one shows up the moment upstream cuts a release,
 * while a tag can be repointed at new code with no local diff at all.
 *
 * Every case is offline. `GITHUB_API_BASE` points the gate at a stand-in
 * standing on loopback that can be made to answer correctly, answer with a
 * newer release, answer with something that is not a version at all, or not
 * answer. `ACTIONS_CURRENCY_WORKFLOWS_DIR` points it at a temporary
 * directory, so a hostile reference shape can be driven through the real
 * command without writing one into `.github/workflows`.
 *
 * The cases that run against this repository's own workflow set build their
 * routes from the gate's own reader, so the fixture describes whatever is
 * actually pinned today rather than a list that goes stale the first time a
 * pin moves. Nothing there writes: the `--fix` path is exercised only
 * against the temporary directory, and the workflow bytes are digested
 * before and after to prove it.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/supply-chain-actions-currency.test.js`.
 */

var crypto = require("node:crypto");
var fs     = require("node:fs");
var path   = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

// The loopback stand-in, the closed-port finder and the spawn wrapper are
// shared with the vendor cases. Two mocks of one API are two sets of
// assumptions about what it answers, and they drift.
var shared = require("./vendor-refresh-atomicity.test.js");

// Requiring the gate must run nothing. A module whose main() fires on load
// cannot be unit tested at all, and every failure path below would have to
// be inferred from reading it.
var currency = require("../../scripts/check-actions-currency.js");

var REPO_ROOT   = helpers.REPO_ROOT;
var GATE_SCRIPT = path.join(REPO_ROOT, "scripts", "check-actions-currency.js");

// Stand-in commit ids. Forty hex characters, because that is what a pinned
// reference carries and what the gate would write back.
var STAND_IN_SHA = "1".repeat(40);
var OLD_SHA      = "a".repeat(40);
var NEW_SHA      = "b".repeat(40);

var PASSING_LINE = "every pinned action matches the latest upstream release";

var WORKFLOWS_DIR = path.join(REPO_ROOT, ".github", "workflows");

// ---------------------------------------------------------------------------
// Routes, built from what the workflows actually pin today
// ---------------------------------------------------------------------------

function _pins() {
  return currency._groupPins(currency._readWorkflows().references);
}

/**
 * _routes(tagFor) builds the API document set for every pinned action.
 * `tagFor(ownerRepo, pinnedVersion)` returns the tag the stand-in should
 * report as the latest release, or null to answer with nothing usable.
 */
function _routes(tagFor) {
  var routes = {};
  _pins().forEach(function (entry) {
    var tag  = tagFor(entry.action, entry.version);
    var base = "/repos/" + entry.action;
    if (tag === null) {
      routes[base + "/releases/latest"]   = { body: { tag_name: "nightly" } };
      routes[base + "/tags?per_page=100"] = { body: [{ name: "nightly" }] };
      return;
    }
    routes[base + "/releases/latest"] = { body: { tag_name: tag } };
    routes[base + "/tags?per_page=100"] = { body: [{ name: tag }] };
    routes[base + "/commits/" + encodeURIComponent(tag)] = { body: { sha: STAND_IN_SHA } };
  });
  return routes;
}

function _vTag(version) {
  return /^v/.test(String(version)) ? String(version) : "v" + version;
}

function _sameTag(ownerRepo, pinnedVersion) {
  return _vTag(pinnedVersion);
}

function _newerTag(ownerRepo, pinnedVersion) {
  var parts = String(pinnedVersion).replace(/^v/, "").split(".");
  while (parts.length < 3) parts.push("0");
  parts[0] = String(parseInt(parts[0], 10) + 1);
  return "v" + parts.join(".");
}

// Below every version this repository pins, so each measured action reads
// as pinned ahead of what the stand-in publishes.
function _olderTag() {
  return "v0.0.0";
}

function _noVersionAtAll() {
  return null;
}

// ---------------------------------------------------------------------------
// Driving the gate
// ---------------------------------------------------------------------------

function _runGate(apiBase, args, extraEnv) {
  var env = Object.assign({ GITHUB_API_BASE: apiBase }, extraEnv || {});
  return shared.runCommand(process.execPath, [GATE_SCRIPT].concat(args || []), {
    cwd: REPO_ROOT,
    env: env,
  });
}

function _runGateIn(dir, apiBase, args) {
  return _runGate(apiBase, args, { ACTIONS_CURRENCY_WORKFLOWS_DIR: dir });
}

async function _withApi(routes, fn) {
  var server = await shared.startRegistry({ routes: routes });
  try { return await fn(server.base); }
  finally { await server.close(); }
}

function _transcript(result) {
  return "exit=" + String(result.status) +
    " stdout: " + String(result.stdout || "").replace(/\s+/g, " ").slice(-900) +
    " stderr: " + String(result.stderr || "").replace(/\s+/g, " ").slice(-400);
}

/**
 * _workflowBytes() digests every workflow file, so a case that must not
 * write can prove it did not. The `--fix` path rewrites these files in
 * place, and a test that only reads an exit code cannot tell a repair run
 * that changed nothing from one that changed the repository.
 */
function _workflowBytes() {
  var h = crypto.createHash("sha256");
  fs.readdirSync(WORKFLOWS_DIR).sort().forEach(function (name) {
    h.update(name);
    h.update(fs.readFileSync(path.join(WORKFLOWS_DIR, name)));
  });
  return h.digest("hex");
}

// ---------------------------------------------------------------------------
// Reading a `uses:` scalar, then classifying what was read
// ---------------------------------------------------------------------------

function _refs(text) {
  return currency._readWorkflowText(text, "fixture.yml", path.join(WORKFLOWS_DIR, "fixture.yml"));
}

// One step, with whatever `uses:` line the case is about.
function _step(usesLine) {
  return _steps([usesLine]);
}

/**
 * _steps(usesLines) is one workflow document carrying several steps.
 *
 * Concatenating two `_step()` documents is what this replaces, and it built
 * a file with `name`, `on` and `jobs` declared twice. GitHub refuses that
 * file, and so does any parser holding YAML to unique mapping keys, so a
 * case written that way was describing a workflow nobody could run.
 */
function _steps(usesLines) {
  return "name: fixture\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
    usesLines.map(function (line) {
      return "      - name: a step\n" + line + "\n";
    }).join("");
}

function _only(usesLine) {
  var refs = _refs(_step(usesLine));
  return refs.length === 1 ? refs[0] : { kind: "test-fixture-read-" + refs.length + "-references" };
}

function _classifierCases() {
  var sha = _only("        uses: acme/widget@" + OLD_SHA + "  # v1.2.3");
  check("a commit-id pin is read as a pin", sha.kind === "pin" && sha.pinType === "sha");
  check("a commit-id pin takes its version from the trailing comment", sha.version === "v1.2.3");
  check("a commit-id pin records the action", sha.action === "acme/widget");
  check("a commit-id pin records the commit id", sha.sha === OLD_SHA);

  var sub = _only("        uses: acme/widget/.github/workflows/build.yml@" + OLD_SHA + "  # v1.2.3");
  check("a subpath reference keeps owner/repo as the action", sub.action === "acme/widget");
  check("a subpath reference keeps the subpath",
    sub.subpath === "/.github/workflows/build.yml");

  var dq = _only('        uses: "acme/widget@' + OLD_SHA + '"  # v1.2.3');
  check("a double-quoted reference is read", dq.kind === "pin" && dq.action === "acme/widget");
  check("a double-quoted reference still finds its version comment", dq.version === "v1.2.3");

  var sq = _only("        uses: 'acme/widget@v1.2.3'");
  check("a single-quoted tag reference is read as a tag pin",
    sq.kind === "pin" && sq.pinType === "tag" && sq.version === "v1.2.3");

  var unterminated = _only('        uses: "acme/widget@' + OLD_SHA);
  check("a quoted reference that is never closed is unreadable",
    unterminated.kind === "unreadable");

  var tag = _only("        uses: acme/reusable/.github/workflows/x.yml@v2.1.0  # a note");
  check("a tag pin is read as a pin", tag.kind === "pin" && tag.pinType === "tag");
  check("a tag pin takes its version from the ref, not the comment", tag.version === "v2.1.0");
  check("a tag pin has no commit id", tag.sha === null);

  var pre = _only("        uses: acme/widget@v2.1.0-rc.3");
  check("a prerelease tag is a tag pin", pre.kind === "pin" && pre.pinType === "tag");
  check("a prerelease tag keeps its suffix", pre.version === "v2.1.0-rc.3");

  var build = _only("        uses: acme/widget@v2.1.0+20260101");
  check("a tag carrying build metadata is a tag pin",
    build.kind === "pin" && build.pinType === "tag" && build.version === "v2.1.0+20260101");

  var noComment = _only("        uses: acme/widget@" + OLD_SHA);
  check("a commit-id pin with no version comment is unreadable",
    noComment.kind === "unreadable");
  check("the missing version comment is named in the reason",
    /version comment/.test(String(noComment.problem)));

  var dateComment = _only("        uses: acme/widget@" + OLD_SHA + "  # pinned 2026-01-02");
  check("a comment that is a date rather than a version does not read as one",
    dateComment.kind === "unreadable");

  var branch = _only("        uses: acme/widget@main");
  check("a branch pin is unreadable", branch.kind === "unreadable");
  check("the branch reason says a moving ref can be repointed with no local diff",
    /repointed at new code with no\s+local diff/.test(String(branch.problem)));

  var alias = _only("        uses: acme/widget@v4");
  check("a major tag alias is unreadable", alias.kind === "unreadable");
  check("the alias reason says it names no fixed version",
    /no fixed version/.test(String(alias.problem)));

  var shortSha = _only("        uses: acme/widget@06be81b  # v3.5.0");
  check("an abbreviated commit id is unreadable", shortSha.kind === "unreadable");

  var local = _only("        uses: ./.github/actions/build");
  check("a local action is skipped deliberately", local.kind === "local");

  var container = _only("        uses: docker://alpine:3.20");
  check("a container image is skipped deliberately", container.kind === "docker");

  var listForm = _refs(_step("      - uses: acme/widget@" + OLD_SHA + "  # v1.2.3"));
  check("the list-item form of the key is read",
    listForm.length === 1 && listForm[0].kind === "pin");

  // Everything below must NOT be read as a reference at all.
  var inRun = _refs(
    "jobs:\n  build:\n    steps:\n      - name: a step\n        run: |\n" +
    "          echo \"uses: acme/widget@" + OLD_SHA + "  # v1.2.3\"\n" +
    "          grep -n 'uses:' .github/workflows/ci.yml\n" +
    "      - uses: acme/real@" + OLD_SHA + "  # v9.9.9\n");
  check("a reference written inside a run: body is script, not a pin",
    inRun.length === 1 && inRun[0].action === "acme/real");

  var inScript = _refs(
    "jobs:\n  build:\n    steps:\n      - uses: acme/script@" + OLD_SHA + "  # v1.0.0\n" +
    "        with:\n          script: |\n" +
    "            // uses: acme/widget@" + OLD_SHA + "  # v1.2.3\n");
  check("a reference inside any other block scalar is not a pin either",
    inScript.length === 1 && inScript[0].action === "acme/script");

  var commented = _refs(
    "jobs:\n  build:\n    steps:\n" +
    "      # uses: acme/widget@" + OLD_SHA + "  # v1.2.3\n" +
    "      - uses: acme/real@" + OLD_SHA + "  # v9.9.9\n");
  check("a commented-out reference is a comment, not a pin",
    commented.length === 1 && commented[0].action === "acme/real");

  var nameValue = _refs(
    "jobs:\n  build:\n    steps:\n" +
    "      - name: pinact run --check (refuses any tag-shaped `uses:` reference)\n" +
    "        run: pinact run --check\n");
  check("a step name that quotes the key is not a reference", nameValue.length === 0);

  // Two pin types for one action need two answers, so the grouping keys on
  // the pin type as well as the name.
  var mixed = currency._groupPins(_refs(
    "jobs:\n  build:\n    steps:\n" +
    "      - uses: acme/widget@" + OLD_SHA + "  # v1.2.3\n" +
    "      - uses: acme/widget@v1.2.3\n"));
  check("one action pinned two ways is two entries", mixed.length === 2);
  check("one action pinned two ways keeps both pin types",
    mixed.map(function (e) { return e.pinType; }).sort().join(",") === "sha,tag");

  // The lowest version across the workflow set is the one measured, so the
  // report names the pin that is furthest behind.
  var twoVersions = currency._groupPins(_refs(
    "jobs:\n  build:\n    steps:\n" +
    "      - uses: acme/widget@" + OLD_SHA + "  # v2.0.0\n" +
    "      - uses: acme/widget@" + NEW_SHA + "  # v1.0.0\n"));
  check("an action pinned at two versions is measured at the lower one",
    twoVersions.length === 1 && twoVersions[0].version === "v1.0.0");
  check("the higher pin is still listed against the same entry",
    twoVersions[0].refs.length === 2);
}

// ---------------------------------------------------------------------------
// The repository's own workflow set
// ---------------------------------------------------------------------------

function _realWorkflowCases() {
  var scan   = currency._readWorkflows();
  var counts = currency._scanCounts(scan.references);

  check("the reader finds the workflow files", scan.files.length > 0);
  check("the reader finds references in them", scan.references.length > 0);

  // Every reference this repository writes has to be classified. A shipped
  // workflow the gate cannot read is a pin nobody is measuring.
  var unreadable = scan.references.filter(function (r) { return r.kind === "unreadable"; });
  check("every uses: reference in this repository is classified. Unreadable: " +
    JSON.stringify(unreadable.map(function (r) { return r.file + ":" + r.line + " " + r.problem; })),
    unreadable.length === 0);
  check("the reference counts add up to what was read",
    counts.sha + counts.tag + counts.local + counts.docker + counts.unreadable ===
      scan.references.length);

  var pins = currency._groupPins(scan.references);
  check("the reader finds the commit-id pins in this repository", counts.sha > 0);

  // The one reference that must stay tag-pinned. It is listed under
  // `ignore_actions` in .pinact.yaml so pinact leaves the tag alone, and
  // that exemption is about rewriting the pin rather than about measuring
  // it, so the currency question still has to be asked.
  var tagPins = pins.filter(function (p) { return p.pinType === "tag"; });
  check("the tag-pinned reference is collected as a pin. Found: " +
    JSON.stringify(pins.map(function (p) { return p.action + "@" + p.pinType; })),
    tagPins.length > 0);

  var ignores = currency._loadPinactIgnores();
  check("the pinact ignore list is readable", ignores.length > 0);
  tagPins.forEach(function (p) {
    check("a tag pin is measured even when .pinact.yaml names it (" + p.action + ")",
      currency._isPinactIgnored(ignores, p) === null);
  });

  // The exemption rule itself, against a constructed list, so it stays
  // covered whatever this repository happens to name today. The commit-id
  // half still holds: that exemption is there for an API that refuses the
  // runner rather than for a pin shape.
  var named = [{ nameRe: /^acme\/widget$/, name: "acme/widget" }];
  check("a commit-id pin named by the ignore list is exempt",
    currency._isPinactIgnored(named,
      { action: "acme/widget", pinType: "sha", refs: [] }) !== null);
  check("a tag pin named by the same entry is not exempt",
    currency._isPinactIgnored(named,
      { action: "acme/widget", pinType: "tag", refs: [] }) === null);
  check("a pin nobody named is not exempt",
    currency._isPinactIgnored(named,
      { action: "acme/other", pinType: "sha", refs: [] }) === null);
  // pinact matches the full reference name, so an entry written against the
  // subpath form has to match a pin recorded under owner/repo.
  check("an entry naming the subpath form matches the pin it belongs to",
    currency._isPinactIgnored(
      [{ nameRe: /^acme\/widget\/\.github\/workflows\/x\.yml$/, name: "subpath entry" }],
      { action: "acme/widget", pinType: "sha",
        refs: [{ subpath: "/.github/workflows/x.yml" }] }) !== null);

  _pinactReaderCases();
}

// ---------------------------------------------------------------------------
// Cases: reading .pinact.yaml
// ---------------------------------------------------------------------------

// The exemption list decides which commit-id pins this gate stops asking
// about, so an entry it fails to read is an action that gets measured when
// its organization refuses the runner, and the run fails on something
// nobody can fix. YAML lets one mapping be written several ways, and the
// entries below are the same two exemptions in each of them.
function _names(text) {
  return currency._parsePinactIgnores(text).map(function (e) { return e.name; }).sort();
}

function _pinactReaderCases() {
  var shipped = _names(fs.readFileSync(path.join(REPO_ROOT, ".pinact.yaml"), "utf8"));
  check("the shipped exemption list still reads as two entries. Read: " +
    JSON.stringify(shipped), shipped.length === 2);
  check("the shipped exemption list still names the reusable workflow. Read: " +
    JSON.stringify(shipped),
  shipped.some(function (n) { return /slsa-github-generator/.test(n); }));
  check("the shipped exemption list still names the scanner action. Read: " +
    JSON.stringify(shipped),
  shipped.some(function (n) { return /trivy-action/.test(n); }));

  var refFirst = _names(
    "version: 3\nignore_actions:\n  - ref: .*\n    name: acme/widget\n");
  check("an entry whose ref is written before its name is read. Read: " +
    JSON.stringify(refFirst),
  refFirst.length === 1 && refFirst[0] === "acme/widget");

  var flow = _names(
    "version: 3\nignore_actions: [{ name: acme/widget, ref: '.*' }]\n");
  check("an entry written in flow style is read. Read: " + JSON.stringify(flow),
    flow.length === 1 && flow[0] === "acme/widget");

  var quoted = _names(
    "version: 3\nignore_actions:\n  - name: \"acme/widget\"\n    ref: \".*\"\n");
  check("a double-quoted name keeps its value. Read: " + JSON.stringify(quoted),
    quoted.length === 1 && quoted[0] === "acme/widget");

  var elsewhere = _names(
    "version: 3\nignore_actions:\n  - name: acme/widget\n    ref: .*\n" +
    "checkout:\n  - name: acme/other\n");
  check("a name under a different key is not an exemption. Read: " +
    JSON.stringify(elsewhere),
  elsewhere.length === 1 && elsewhere[0] === "acme/widget");

  var none = _names("version: 3\n");
  check("a configuration with no ignore list exempts nothing", none.length === 0);

  // A configuration file that cannot be read is not the same as one that
  // exempts nothing. Answering with an empty list would measure an action
  // whose organization refuses the runner and fail the run on something no
  // pin bump can fix, and it would do it without saying why.
  function _refuses(label, text) {
    var threw = false;
    try { currency._parsePinactIgnores(text); }
    catch (_e) { threw = true; }
    check(label, threw);
  }

  _refuses("a configuration that does not parse is refused rather than read as empty",
    "version: 3\nignore_actions:\n\t- name: acme/widget\n");
  _refuses("a list item carrying no name is refused rather than skipped",
    "version: 3\nignore_actions:\n  - ref: .*\n");
  _refuses("a list item that is a bare scalar is refused rather than skipped",
    "version: 3\nignore_actions:\n  - acme/widget\n");

  // One good entry beside one this reader cannot take a name from is the
  // configuration where a skip hides: the list is non-empty, the gate looks
  // like it honored the file, and one exemption silently went missing.
  _refuses("one unreadable item refuses the whole list rather than honoring the rest",
    "version: 3\nignore_actions:\n  - name: acme/widget\n    ref: .*\n  - ref: .*\n");
}

// ---------------------------------------------------------------------------
// Cases: the upstream answered
// ---------------------------------------------------------------------------

async function _measuredCases() {
  await _withApi(_routes(_sameTag), async function (base) {
    var r = await _runGate(base, []);
    check("every pin matching the stand-in's latest release exits 0. " + _transcript(r),
      r.status === 0);
    check("a fully measured run prints the passing line. " + _transcript(r),
      String(r.stdout).indexOf(PASSING_LINE) !== -1);
    check("a measured run says how many references it read. " + _transcript(r),
      /read \d+ uses: reference\(s\) across \d+ workflow file\(s\)/.test(String(r.stdout)));
    check("a measured run marks the tag pin as a tag pin. " + _transcript(r),
      /\(tag pin\)/.test(String(r.stdout)));
  });

  await _withApi(_routes(_newerTag), async function (base) {
    var r = await _runGate(base, []);
    check("a newer upstream release fails the gate. " + _transcript(r), r.status === 1);
    check("a newer upstream release reads as STALE. " + _transcript(r),
      /STALE/.test(String(r.stdout)));
    check("a stale run never prints the passing line. " + _transcript(r),
      String(r.stdout).indexOf(PASSING_LINE) === -1);
  });

  // A pin higher than anything the upstream published. It is measured, so
  // it passes, and it is reported as itself rather than as a match.
  await _withApi(_routes(_olderTag), async function (base) {
    var r = await _runGate(base, []);
    check("a pin ahead of the latest published release passes. " + _transcript(r),
      r.status === 0);
    check("a pin ahead of the latest published release is labeled. " + _transcript(r),
      /AHEAD/.test(String(r.stdout)));
  });
}

// ---------------------------------------------------------------------------
// Cases: the upstream did not answer, or answered something uncomparable
// ---------------------------------------------------------------------------

async function _unmeasuredCases() {
  var deadPort = await shared.closedPort();
  var dead     = "http://127.0.0.1:" + deadPort;

  var r1 = await _runGate(dead, []);
  check("an upstream that refuses the connection fails the gate. " + _transcript(r1),
    r1.status === 1);
  check("an unreachable upstream reads as UNKNOWN. " + _transcript(r1),
    /UNKNOWN/.test(String(r1.stdout)));
  check("an unreachable upstream never prints the passing line. " + _transcript(r1),
    String(r1.stdout).indexOf(PASSING_LINE) === -1);
  check("the unknown summary says currency is unknown rather than current. " + _transcript(r1),
    /not current/i.test(String(r1.stdout)));

  // Reached the API, and nothing it said can be compared against the pin.
  // The gate has to land this in the same bucket as an upstream that never
  // answered: both leave the pin unmeasured.
  await _withApi(_routes(_noVersionAtAll), async function (base) {
    var r2 = await _runGate(base, []);
    check("an upstream publishing no comparable version fails the gate. " + _transcript(r2),
      r2.status === 1);
    check("an uncomparable version reads as UNKNOWN. " + _transcript(r2),
      /UNKNOWN/.test(String(r2.stdout)));
    check("an uncomparable version never prints the passing line. " + _transcript(r2),
      String(r2.stdout).indexOf(PASSING_LINE) === -1);
  });

  // The repair run reads the same measurement. `scripts/pin-all.js --fix`
  // spawns it and turns a zero exit into "GitHub Action SHAs pinned and
  // updated", so a repair run that reached no upstream at all must not
  // answer zero. Nothing is stale against an API that never answered, so
  // this case rewrites nothing and the workflow bytes prove it.
  var before = _workflowBytes();
  var r4 = await _runGate(dead, ["--fix"]);
  check("--fix against an unreachable upstream does not report success. " + _transcript(r4),
    r4.status === 1);
  check("--fix against an unreachable upstream says the pins are unmeasured. " + _transcript(r4),
    /unknown, not current/i.test(String(r4.stdout)));
  check("--fix against an unreachable upstream rewrites no workflow file",
    _workflowBytes() === before);

  // The advisory local run. The exit code changes and the claim does not.
  var r3 = await _runGate(dead, ["--warn"]);
  check("--warn exits 0 against an unreachable upstream. " + _transcript(r3), r3.status === 0);
  check("--warn still reports the pins as unmeasured. " + _transcript(r3),
    /UNKNOWN/.test(String(r3.stdout)));
  check("--warn never prints the passing line either. " + _transcript(r3),
    String(r3.stdout).indexOf(PASSING_LINE) === -1);
}

// ---------------------------------------------------------------------------
// Cases: a reference the reader cannot classify, driven through the command
// ---------------------------------------------------------------------------

function _writeWorkflows(dir, files) {
  Object.keys(files).forEach(function (name) {
    fs.writeFileSync(path.join(dir, name), files[name]);
  });
}

async function _unclassifiedReferenceCases() {
  var deadPort = await shared.closedPort();
  var dead     = "http://127.0.0.1:" + deadPort;

  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "branch.yml": _step("        uses: acme/widget@main"),
    });
    var r = await _runGateIn(dir, dead, []);
    check("a branch-pinned reference fails the run. " + _transcript(r), r.status === 1);
    check("a branch-pinned reference reads as UNKNOWN. " + _transcript(r),
      /UNKNOWN/.test(String(r.stdout)));
    check("a branch-pinned reference is listed with its file and line. " + _transcript(r),
      /branch\.yml:\d+/.test(String(r.stdout)));
    check("the report counts it as unreadable rather than dropping it. " + _transcript(r),
      /1 unreadable/.test(String(r.stdout)));
    check("a run carrying an unreadable reference never prints the passing line. " +
      _transcript(r), String(r.stdout).indexOf(PASSING_LINE) === -1);
    check("the summary says the reference itself could not be read. " + _transcript(r),
      /reference itself could not be read/.test(String(r.stdout)));
  });

  // The configuration where the hole actually hides: a workflow set where
  // everything else measured clean. With one reference nobody could read
  // beside a pin that matches upstream, the run has the material for a
  // passing line, and printing it would vouch for a reference the gate
  // never looked into.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "mixed.yml": _steps([
        "        uses: acme/byid@" + OLD_SHA + "  # v1.0.0",
        "        uses: acme/widget@main",
      ]),
    });
    var routes = {
      "/repos/acme/byid/releases/latest":   { body: { tag_name: "v1.0.0" } },
      "/repos/acme/byid/tags?per_page=100": { body: [{ name: "v1.0.0" }] },
      "/repos/acme/byid/commits/v1.0.0":    { body: { sha: NEW_SHA } },
    };
    await _withApi(routes, async function (base) {
      var r = await _runGateIn(dir, base, []);
      check("one unreadable reference fails a run where every pin measured clean. " +
        _transcript(r), r.status === 1);
      check("a measured pin does not buy the passing line for an unreadable reference. " +
        _transcript(r), String(r.stdout).indexOf(PASSING_LINE) === -1);
      check("the measured pin is still reported as current. " + _transcript(r),
        /\[OK\] acme\/byid/.test(String(r.stdout)));
      check("the unreadable reference is still listed beside it. " + _transcript(r),
        /mixed\.yml:\d+/.test(String(r.stdout)));
    });
  });

  // A commit-id pin whose version comment went missing. The commit id is
  // still immutable, and there is still nothing to compare it against, so
  // it is measured by nobody.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "nocomment.yml": _step("        uses: acme/widget@" + OLD_SHA),
    });
    var r = await _runGateIn(dir, dead, []);
    check("a commit-id pin with no version comment fails the run. " + _transcript(r),
      r.status === 1);
    check("a commit-id pin with no version comment is listed. " + _transcript(r),
      /nocomment\.yml:\d+/.test(String(r.stdout)));
  });

  // Nothing measurable at all. A run that inspected no pin has not
  // established that the pins are current, because there were none to look
  // at, and the passing line would be true of it.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "onlylocal.yml": _steps([
        "        uses: ./.github/actions/build",
        "        uses: docker://alpine:3.20",
      ]),
    });
    var r = await _runGateIn(dir, dead, []);
    check("a workflow set with nothing to measure fails the run. " + _transcript(r),
      r.status === 1);
    check("a workflow set with nothing to measure says no pin was found. " + _transcript(r),
      /no action pin was found to measure/.test(String(r.stdout)));
    check("local and container references are counted as skipped deliberately. " +
      _transcript(r), /1 local, 1 container image/.test(String(r.stdout)));
  });

  // A workflow the reader cannot read at all. The line reader walks it
  // regardless and finds no `uses:` in it, so the file contributes nothing
  // and the run reports on the files it could read as though that were all
  // of them. It is the unreadable-reference hole one level up: the summary
  // counts what it looked at, the passing line goes out, and a whole file
  // of pins was never inspected.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "good.yml":   _step("        uses: acme/byid@" + OLD_SHA + "  # v1.0.0"),
      "broken.yml": "name: broken\njobs:\n\tbuild:\n    steps:\n      - uses: acme/hidden@v1.0.0\n",
    });
    var routes = {
      "/repos/acme/byid/releases/latest":   { body: { tag_name: "v1.0.0" } },
      "/repos/acme/byid/tags?per_page=100": { body: [{ name: "v1.0.0" }] },
      "/repos/acme/byid/commits/v1.0.0":    { body: { sha: NEW_SHA } },
    };
    await _withApi(routes, async function (base) {
      var r = await _runGateIn(dir, base, []);
      check("a workflow that does not parse fails the run. " + _transcript(r),
        r.status === 1);
      check("a workflow that does not parse is named. " + _transcript(r),
        /broken\.yml/.test(String(r.stdout)));
      check("a workflow that does not parse never buys the passing line. " +
        _transcript(r), String(r.stdout).indexOf(PASSING_LINE) === -1);
      check("the workflow that did parse is still measured beside it. " + _transcript(r),
        /\[OK\] acme\/byid/.test(String(r.stdout)));
    });
  });

  // A step written as one flow mapping. The line reader cannot match a
  // `uses:` that does not open its own line, so the reference is silence
  // rather than a finding, which is the hole this whole gate is written
  // against. The case asserts the outcome rather than the reason, because
  // the two guards behind it fail on opposite sides of an upstream fix: the
  // vendored parser currently reads the item as a plain scalar, and once it
  // reads it as a mapping the document will carry a reference the line
  // reader still cannot produce.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "good.yml":    _step("        uses: acme/byid@" + OLD_SHA + "  # v1.0.0"),
      "compact.yml": "name: fixture\non: [push]\njobs:\n  build:\n    steps:\n" +
        "      - { name: a step, uses: acme/hidden@v1.0.0 }\n",
    });
    var routes = {
      "/repos/acme/byid/releases/latest":   { body: { tag_name: "v1.0.0" } },
      "/repos/acme/byid/tags?per_page=100": { body: [{ name: "v1.0.0" }] },
      "/repos/acme/byid/commits/v1.0.0":    { body: { sha: NEW_SHA } },
    };
    await _withApi(routes, async function (base) {
      var r = await _runGateIn(dir, base, []);
      check("a reference no reader can produce fails the run. " + _transcript(r),
        r.status === 1);
      check("the workflow carrying it is named. " + _transcript(r),
        /compact\.yml/.test(String(r.stdout)));
      check("a reference no reader can produce never buys the passing line. " +
        _transcript(r), String(r.stdout).indexOf(PASSING_LINE) === -1);
    });
  });

  // The directory override is an entry point, so a bad value is a refusal
  // rather than a repository that appears to pin nothing.
  var missing = path.join(REPO_ROOT, "no-such-workflows-directory");
  var rMissing = await _runGateIn(missing, dead, []);
  check("a workflows directory that does not exist is refused. " + _transcript(rMissing),
    rMissing.status === 2);
  check("the refusal names the override. " + _transcript(rMissing),
    /ACTIONS_CURRENCY_WORKFLOWS_DIR/.test(String(rMissing.stderr) + String(rMissing.stdout)));

  var notADir = await _runGateIn(GATE_SCRIPT, dead, []);
  check("a workflows override pointing at a file is refused. " + _transcript(notADir),
    notADir.status === 2);
}

// ---------------------------------------------------------------------------
// Cases: a tag pin is measured, and --fix leaves it alone
// ---------------------------------------------------------------------------

function _fixtureBoth() {
  return "name: fixture\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
    "      - name: a commit-id pin\n" +
    "        uses: acme/byid@" + OLD_SHA + "  # v1.0.0\n" +
    "      - name: a tag pin\n" +
    "        uses: acme/bytag/.github/workflows/build.yml@v1.0.0  # a note\n";
}

function _bumpRoutes() {
  var routes = {};
  ["acme/byid", "acme/bytag"].forEach(function (repo) {
    routes["/repos/" + repo + "/releases/latest"]     = { body: { tag_name: "v2.0.0" } };
    routes["/repos/" + repo + "/tags?per_page=100"]   = { body: [{ name: "v2.0.0" }] };
    routes["/repos/" + repo + "/commits/v2.0.0"]      = { body: { sha: NEW_SHA } };
    routes["/repos/" + repo + "/releases/tags/v2.0.0"] = { body: { body: "the release notes" } };
  });
  routes["/repos/acme/byid/compare/" + OLD_SHA + "..." + NEW_SHA] = {
    body: {
      html_url: "https://example.invalid/compare",
      commits: [{ sha: NEW_SHA, commit: { message: "bump\n\nbody", author: { name: "someone" } } }],
      files: [{ filename: "action.yml", status: "modified", additions: 2, deletions: 1, patch: "@@\n+two\n-one\n" }],
    },
  };
  return routes;
}

async function _tagPinCases() {
  // Measured and current, end to end, with the tag pin marked as one.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, { "tag.yml": _step("        uses: acme/bytag@v1.0.0") });
    var routes = {
      "/repos/acme/bytag/releases/latest":   { body: { tag_name: "v1.0.0" } },
      "/repos/acme/bytag/tags?per_page=100": { body: [{ name: "v1.0.0" }] },
      "/repos/acme/bytag/commits/v1.0.0":    { body: { sha: NEW_SHA } },
    };
    await _withApi(routes, async function (base) {
      var r = await _runGateIn(dir, base, []);
      check("a tag pin matching the latest release passes. " + _transcript(r), r.status === 0);
      check("a tag pin is marked as a tag pin in the report. " + _transcript(r),
        /acme\/bytag.*\(tag pin\)/.test(String(r.stdout)));
      check("a measured tag pin counts as a version-tag reference. " + _transcript(r),
        /1 by version tag/.test(String(r.stdout)));
    });
  });

  // Behind upstream, so it fails, and the report says the move is a manual
  // one because there is no old commit id to diff against.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, { "tag.yml": _step("        uses: acme/bytag@v1.0.0") });
    await _withApi(_bumpRoutes(), async function (base) {
      var r = await _runGateIn(dir, base, []);
      check("a tag pin behind upstream fails the run. " + _transcript(r), r.status === 1);
      check("a tag pin behind upstream reads as STALE. " + _transcript(r),
        /STALE.*acme\/bytag/.test(String(r.stdout)));
      check("a stale tag pin says --fix rewrites commit-id pins only. " + _transcript(r),
        /rewrites commit-id pins only/.test(String(r.stdout)));
    });
  });

  // The repair run. The commit-id pin moves, the tag pin does not, and the
  // exit code says the workflow set is still not current.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, { "both.yml": _fixtureBoth() });
    var target = path.join(dir, "both.yml");
    await _withApi(_bumpRoutes(), async function (base) {
      var r = await _runGateIn(dir, base, ["--fix"]);
      var after = fs.readFileSync(target, "utf8");
      check("--fix rewrites the commit-id pin. " + _transcript(r),
        after.indexOf("acme/byid@" + NEW_SHA + "  # v2.0.0") !== -1);
      check("--fix leaves the tag pin exactly as it was. " + _transcript(r),
        after.indexOf("acme/bytag/.github/workflows/build.yml@v1.0.0  # a note") !== -1);
      check("--fix says it left the tag pin alone. " + _transcript(r),
        /left acme\/bytag v1\.0\.0 alone/.test(String(r.stdout)));
      check("--fix does not report success while a pin it cannot repair is stale. " +
        _transcript(r), r.status === 1);
      check("--fix printed the review material for the bump it did make. " + _transcript(r),
        /the release notes/.test(String(r.stdout)) && /action\.yml/.test(String(r.stdout)));
    });
  });

  // A repair that left nothing behind. `scripts/pin-all.js --fix` spawns
  // this command and records a non-zero exit as a failed segment, so a run
  // that measured every pin and rewrote every stale one has to answer zero.
  // Being stale before the rewrite is what the run was asked to fix, and
  // reporting it afterwards would make a working repair read as a broken
  // one.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "byid.yml": _step("        uses: acme/byid@" + OLD_SHA + "  # v1.0.0"),
    });
    var target = path.join(dir, "byid.yml");
    await _withApi(_bumpRoutes(), async function (base) {
      var r = await _runGateIn(dir, base, ["--fix"]);
      check("a repair that left nothing behind exits 0. " + _transcript(r), r.status === 0);
      check("a repair that left nothing behind moved the pin. " + _transcript(r),
        fs.readFileSync(target, "utf8").indexOf("acme/byid@" + NEW_SHA + "  # v2.0.0") !== -1);
    });
  });

  // A repair on a file with carriage returns in it. Rewriting one pin must
  // not rewrite every line ending in the file: a whole-file ending change
  // buried under a one-line bump is a diff nobody reads, and on a mixed
  // tree it is the kind of edit that shows up as every line changed.
  await helpers.withTempDir("actionsdir", async function (dir) {
    var target = path.join(dir, "crlf.yml");
    var text   = _step("        uses: acme/byid@" + OLD_SHA + "  # v1.0.0")
      .replace(/\n/g, "\r\n");
    fs.writeFileSync(target, text);
    var beforeCrlf = (text.match(/\r\n/g) || []).length;
    var beforeLf   = (text.match(/\n/g) || []).length;
    await _withApi(_bumpRoutes(), async function (base) {
      var r = await _runGateIn(dir, base, ["--fix"]);
      var after = fs.readFileSync(target, "utf8");
      check("--fix moves the pin in a file with carriage returns. " + _transcript(r),
        after.indexOf("acme/byid@" + NEW_SHA + "  # v2.0.0") !== -1);
      check("--fix leaves every line ending as it found it",
        (after.match(/\r\n/g) || []).length === beforeCrlf &&
        (after.match(/\n/g) || []).length === beforeLf);
    });
  });

  // A bump the compare API would not describe. The pin is still rewritten,
  // and the run has to say the review material it told the operator to read
  // was never fetched.
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "byid.yml": _step("        uses: acme/byid@" + OLD_SHA + "  # v1.0.0"),
    });
    var routes = _bumpRoutes();
    delete routes["/repos/acme/byid/compare/" + OLD_SHA + "..." + NEW_SHA];
    await _withApi(routes, async function (base) {
      var r = await _runGateIn(dir, base, ["--fix"]);
      check("--fix names a bump it rewrote with no review material. " + _transcript(r),
        /REVIEW MATERIAL MISSING/.test(String(r.stdout)));
      check("--fix does not report success for an unreviewable bump. " + _transcript(r),
        r.status === 1);
    });
  });
}

// ---------------------------------------------------------------------------
// Cases: --json is one document a parser can read
// ---------------------------------------------------------------------------

async function _structuredOutputCases() {
  await helpers.withTempDir("actionsdir", async function (dir) {
    _writeWorkflows(dir, {
      "mixed.yml": _steps([
        "        uses: acme/byid@" + OLD_SHA + "  # v1.0.0",
        "        uses: acme/bytag@v1.0.0",
        "        uses: acme/widget@main",
      ]),
    });
    await _withApi(_bumpRoutes(), async function (base) {
      var r = await _runGateIn(dir, base, ["--json"]);
      var doc = null;
      var parseError = null;
      try { doc = JSON.parse(String(r.stdout)); }
      catch (e) { parseError = (e && e.message) || String(e); }
      check("--json emits a document a parser can read. " +
        (parseError || "") + " " + _transcript(r), doc !== null);
      if (doc === null) return;
      check("--json carries the reference scan",
        doc.scan && doc.scan.references.length === 3);
      check("--json carries the per-reference counts",
        doc.scan.counts.sha === 1 && doc.scan.counts.tag === 1 &&
        doc.scan.counts.unreadable === 1);
      check("--json carries the verdict rather than printing it after the document",
        doc.verdict && doc.verdict.code === 1 && /UNKNOWN|FAIL/.test(doc.verdict.summary));
      check("--json marks the pin type on each result",
        doc.results.filter(function (x) { return x.pinType === "tag"; }).length === 1);
      check("--json exit code still matches the verdict. " + _transcript(r),
        r.status === doc.verdict.code);
    });
  });

  // The two output modes promise different things to different readers, so
  // asking for both is refused rather than answered with a stream that is
  // neither.
  // Refused before either override is resolved and before any request, so
  // the endpoint named here is never addressed.
  var deadPort = await shared.closedPort();
  var both = await _runGate("http://127.0.0.1:" + deadPort, ["--json", "--fix"]);
  check("--json and --fix together are refused. " + _transcript(both), both.status === 2);
  check("the refusal names both flags. " + _transcript(both),
    /--fix and --json/.test(String(both.stderr) + String(both.stdout)));
}

// ---------------------------------------------------------------------------
// Cases: the API override cannot be used to downgrade the transport
// ---------------------------------------------------------------------------

async function _overrideCases() {
  var r1 = await _runGate("http://api.example.invalid", []);
  check("a plaintext override addressing a public host is refused. " + _transcript(r1),
    r1.status === 2);
  check("the refusal names the override. " + _transcript(r1),
    /GITHUB_API_BASE/.test(String(r1.stderr) + String(r1.stdout)));

  var r2 = await _runGate("not a url at all", []);
  check("an override that is not a URL is refused. " + _transcript(r2), r2.status === 2);

  var r3 = await _runGate("ftp://127.0.0.1:9/", []);
  check("an override on a transport the gate does not speak is refused. " + _transcript(r3),
    r3.status === 2);
}

// ---------------------------------------------------------------------------
// The comparison and the verdict, exercised without a network
// ---------------------------------------------------------------------------

function _pureCases() {
  check("the gate exports its workflow reader", typeof currency._readWorkflows === "function");
  check("the gate exports its reference reader", typeof currency._readWorkflowText === "function");
  check("the gate exports its grouping", typeof currency._groupPins === "function");
  check("the gate exports its verdict function", typeof currency._verdict === "function");
  check("the gate exports its comparison", typeof currency._semverCompare === "function");

  // A comparison that could not be made has established nothing. Returning
  // zero for it means "the pin matches the published release", which is the
  // fail-open one layer below the summary line.
  check("comparing against an unparseable version answers 'cannot tell'",
    currency._semverCompare(currency._semverParse("1.2.3"),
      currency._semverParse("nightly")) === null);
  check("comparing an unparseable pin answers 'cannot tell'",
    currency._semverCompare(currency._semverParse("nightly"),
      currency._semverParse("1.2.3")) === null);
  check("comparing two unparseable versions answers 'cannot tell'",
    currency._semverCompare(null, null) === null);
  check("equal versions still compare equal",
    currency._semverCompare(currency._semverParse("v4.2.1"),
      currency._semverParse("4.2.1")) === 0);
  check("an older pin still compares low",
    currency._semverCompare(currency._semverParse("4.2.0"),
      currency._semverParse("4.2.1")) === -1);
  check("a newer pin still compares high",
    currency._semverCompare(currency._semverParse("5.0.0"),
      currency._semverParse("4.2.1")) === 1);

  // Trailing text that is not a version must not read as one. A prefix
  // match turns "2.1.0-nightly-build" into 2.1.0 and reports a pin as
  // current against something nobody compared.
  check("a version with trailing text that is not a version does not parse",
    currency._semverParse("1.2.3nonsense") === null);

  // Prerelease ordering. A release outranks a prerelease of the same
  // version, which is what makes the tag scan pick v2.1.0 over v2.1.0-rc.3.
  check("a release outranks a prerelease of the same version",
    currency._semverCompare(currency._semverParse("v2.1.0"),
      currency._semverParse("v2.1.0-rc.3")) === 1);
  check("a prerelease is behind the release of the same version",
    currency._semverCompare(currency._semverParse("v2.1.0-rc.3"),
      currency._semverParse("v2.1.0")) === -1);
  check("the same prerelease compares equal",
    currency._semverCompare(currency._semverParse("v2.1.0-rc.3"),
      currency._semverParse("v2.1.0-rc.3")) === 0);
  // Ordering rc.1 against rc.2 needs identifier rules this gate does not
  // implement, so it answers "cannot tell" rather than guessing they match.
  check("two different prereleases of one version cannot be ordered",
    currency._semverCompare(currency._semverParse("v2.1.0-rc.1"),
      currency._semverParse("v2.1.0-rc.2")) === null);
  check("build metadata does not change precedence",
    currency._semverCompare(currency._semverParse("v2.1.0+a"),
      currency._semverParse("v2.1.0+b")) === 0);

  check("a three-part version is a full version",
    currency._isFullVersion("v1.2.3") === true);
  check("a major tag alias is not a full version",
    currency._isFullVersion("v4") === false);
  check("a major and minor tag alias is not a full version",
    currency._isFullVersion("v4.2") === false);

  var current = currency._verdict([{ status: "current" }, { status: "skipped" }]);
  check("everything measured and current is exit 0", current.code === 0);

  // Measuring nothing is not finding nothing wrong. A repository that stops
  // writing pinned references, or a pinning tool that changes the comment
  // it emits, empties this gate, and the passing line would then describe a
  // run that inspected no pin at all.
  var nothing = currency._verdict([]);
  check("finding no pinned action at all is exit 1", nothing.code === 1);
  check("finding no pinned action reads as UNKNOWN", /UNKNOWN/.test(nothing.summary));
  check("finding no pinned action never claims the pins match",
    nothing.summary.indexOf(PASSING_LINE) === -1);

  // Every pin skipped is the same hole: nothing was measured, so nothing is
  // known, and the skip list must not be able to empty the gate quietly.
  var allSkipped = currency._verdict([{ status: "skipped" }, { status: "skipped" }]);
  check("a run where every pin was skipped is exit 1", allSkipped.code === 1);
  check("a run where every pin was skipped never claims the pins match",
    allSkipped.summary.indexOf(PASSING_LINE) === -1);

  // A pin ahead of the latest published release is measured, so it passes,
  // and it is reported as itself rather than folded into a match.
  var ahead = currency._verdict([{ status: "ahead" }, { status: "current" }]);
  check("a pin ahead of the latest release still passes", ahead.code === 0);
  check("a pin ahead of the latest release is named in the summary",
    /ahead/i.test(ahead.summary));
  check("a pin ahead of the latest release is not unmeasured",
    currency._isUnmeasured({ status: "ahead" }) === false);

  // A deliberate hold inside a major is measured and passes, and it is
  // never folded into "current": the pin does not match the latest release,
  // and saying it does is a claim nothing established.
  var held = currency._verdict([{ status: "held" }, { status: "current" }]);
  check("a pin held inside its major passes", held.code === 0);
  check("a held pin is named in the summary rather than read as a match",
    /held/i.test(held.summary));
  check("a held pin counts as measured", currency._isMeasured({ status: "held" }) === true);

  var stale = currency._verdict([{ status: "current" }, { status: "stale" }]);
  check("a stale pin is exit 1", stale.code === 1);
  check("a stale pin summary names the staleness", /stale|behind/i.test(stale.summary));

  currency.UNMEASURED_STATUSES.forEach(function (status) {
    var v = currency._verdict([{ status: status }]);
    check("status '" + status + "' is exit 1", v.code === 1);
    check("status '" + status + "' reads as UNKNOWN", /UNKNOWN/.test(v.summary));
    check("status '" + status + "' counts as unmeasured",
      currency._isUnmeasured({ status: status }) === true);
    check("status '" + status + "' never counts as measured",
      currency._isMeasured({ status: status }) === false);
  });

  check("an upstream that did not answer is unmeasured",
    currency.UNMEASURED_STATUSES.indexOf("api-error") !== -1);
  check("an answer that could not be compared is unmeasured",
    currency.UNMEASURED_STATUSES.indexOf("unreadable-version") !== -1);
  check("a reference that could not be classified is unmeasured",
    currency.UNMEASURED_STATUSES.indexOf("unreadable-reference") !== -1);
  check("a current pin is not unmeasured",
    currency._isUnmeasured({ status: "current" }) === false);
  check("a stale pin is not unmeasured",
    currency._isUnmeasured({ status: "stale" }) === false);
  check("a pin skipped by the pinact ignore list is not unmeasured",
    currency._isUnmeasured({ status: "skipped" }) === false);
  check("a pin skipped by the pinact ignore list is not measured either",
    currency._isMeasured({ status: "skipped" }) === false);

  // Both counts reported together, so a run that is stale AND partly
  // unmeasured does not hide the half it could not see behind the half it
  // could.
  var both = currency._verdict([{ status: "stale" }, { status: "api-error" }]);
  check("a mixed run reports the stale count and the unmeasured count",
    /stale|behind/i.test(both.summary) && /could not be checked|not be measured/i.test(both.summary));
  check("a mixed run is exit 1", both.code === 1);

  // The rewrite is line-scoped and keeps everything it did not measure.
  var line = "        uses: acme/widget@" + OLD_SHA + "  # v1.0.0  keep this note";
  var rewritten = currency._rewritePinLine(line, OLD_SHA, "v1.0.0", NEW_SHA, "v2.0.0");
  check("the rewrite moves the commit id",
    rewritten.indexOf("acme/widget@" + NEW_SHA) !== -1);
  check("the rewrite moves the version comment", rewritten.indexOf("# v2.0.0") !== -1);
  check("the rewrite keeps the rest of the comment",
    rewritten.indexOf("keep this note") !== -1);
  check("the rewrite keeps the indentation", /^ {8}uses:/.test(rewritten));

  // The scalar reader, on its own.
  check("a plain scalar ends at a whitespace-preceded hash",
    currency._splitScalar("acme/widget@v1  # a note").value.trim() === "acme/widget@v1");
  check("a hash with no whitespace in front of it stays in the value",
    currency._splitScalar("acme/widget@v1#frag").value.trim() === "acme/widget@v1#frag");
  check("a quoted scalar keeps a hash inside the quotes",
    currency._splitScalar('"acme/widget@v1#frag"  # a note').value === "acme/widget@v1#frag");
  check("a quoted scalar still finds the comment after the quote",
    currency._splitScalar('"acme/widget@v1"  # a note').comment.trim() === "a note");
}

// ---------------------------------------------------------------------------

async function run() {
  _pureCases();
  _classifierCases();
  _realWorkflowCases();
  await _measuredCases();
  await _unmeasuredCases();
  await _unclassifiedReferenceCases();
  await _tagPinCases();
  await _structuredOutputCases();
  await _overrideCases();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
