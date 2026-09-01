// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * GitHub-Actions-currency gate, the CI/CD-supply-chain sibling of
 * `scripts/check-vendor-currency.js`.
 *
 * Walks every `.github/workflows/*.yml`, reads every `uses:` reference in
 * it, and asserts the pinned version still matches the latest upstream
 * release. A stale action becomes a release blocker in the pre-merge gate
 * suite, instead of being surfaced after-the-fact by a Dependabot PR.
 *
 * Two pin shapes are measured, and they are tracked per reference rather
 * than per action, because the same action can be pinned one way in one
 * workflow and the other way in another:
 *
 *   - A commit-id pin, `uses: owner/repo@<40-hex>  # vX.Y.Z`, whose version
 *     is the trailing comment the pinning discipline requires. The commit
 *     id is immutable, so a pin that has fallen behind becomes visible the
 *     moment upstream cuts a release.
 *   - A version-tag pin, `uses: owner/repo@vX.Y.Z`. A tag is NOT immutable:
 *     upstream can repoint it at new code and nothing changes in this
 *     repository, so no local diff will ever show it moving. The version
 *     behind the tag is the only thing left to check, which makes the
 *     tag-pinned reference the one that can least look after itself.
 *
 * `--fix` rewrites commit-id pins only. The review material it prints is a
 * diff between the old and the new commit id, and a tag pin has no old
 * commit id to diff against, so a stale tag pin is reported and left in
 * place for a human to move after reading the upstream release.
 *
 * Actions listed under `ignore_actions` in `.pinact.yaml` are honored for
 * commit-id pins: that list exempts an action from pinact's tag-to-SHA
 * rewriting, and aquasecurity/trivy-action is there because its org blocks
 * the commits API from runner IPs so online re-resolution cannot complete.
 * It does NOT exempt a version-tag pin from currency. For the tag-pinned
 * SLSA reusable workflow the ignore entry says only "leave this one
 * tag-pinned", and a pin left tag-shaped on purpose still has to be
 * measured.
 *
 * Two kinds of `uses:` reference are skipped deliberately, because neither
 * has an upstream release to compare against: a local action (`./path`) and
 * a container image (`docker://...`). Everything else is read first and
 * classified afterwards, so a reference this gate cannot classify is
 * listed with its file and line and FAILS the run. A shape that drops out
 * of the report while the summary counts what it looked at and reads clean
 * is the same hole as an unreachable API, one step earlier.
 *
 * The reference reader stays line-oriented, and that is a decision rather
 * than a leftover. A commit-id pin's version is the trailing `# vX.Y.Z`
 * comment, which any parse discards by definition, and `--fix` rewrites one
 * line in place; neither survives a round trip through a parsed document.
 * What a parse answers instead is the question the line reader cannot ask
 * at all: was this file a YAML document. A workflow that is not one is the
 * hole above one level up, because the line reader walks it regardless,
 * recognizes nothing, and the file joins the count of files that were read
 * while every pin in it goes unmeasured.
 *
 * Run locally:
 *   node scripts/check-actions-currency.js
 *   node scripts/check-actions-currency.js --json     // one parseable
 *                                                       // document carrying
 *                                                       // the scan, the
 *                                                       // per-pin results
 *                                                       // and the verdict
 *   node scripts/check-actions-currency.js --warn     // exit 0, print only
 *   node scripts/check-actions-currency.js --fix       // rewrite stale
 *                                                       // commit-id pins to
 *                                                       // the latest id +
 *                                                       // version comment
 *
 * `--fix` and `--json` are refused together: one prints review material for
 * a human, the other emits a document for a parser.
 *
 * Run in CI: the workflow passes GITHUB_TOKEN so the GitHub API gives the
 * authenticated 5000/hour budget instead of the 60/hour unauthenticated
 * per-IP limit.
 *
 * GITHUB_API_BASE overrides the API endpoint, for a GitHub Enterprise
 * installation or for an offline test. A non-https override is refused
 * unless it addresses loopback, so an endpoint on the network cannot be
 * reached in the clear: whoever answers it decides which action version
 * this repository treats as current.
 *
 * ACTIONS_CURRENCY_WORKFLOWS_DIR overrides the directory that is walked,
 * so the reader can be driven over hostile reference shapes without
 * writing them into `.github/workflows`. Both overrides are entry points
 * rather than requests, so a bad value throws.
 *
 * Failure policy, in one sentence: an action this gate could not measure is
 * reported as UNKNOWN and never as current. A stale pin fails. So does an
 * unmeasured one, under its own summary line, because a check that did not
 * happen reading as up to date is the one answer a currency gate must never
 * give: the pin stops being measured and nothing says so. Three things
 * count as unmeasured, and they are the same hole from three directions: an
 * API that did not answer, an answer that could not be compared against the
 * pin, and a reference that could not be classified well enough to ask.
 * `--warn` is the advisory local run, and it still prints the UNKNOWN
 * verdict before exiting 0.
 */

var fs    = require("node:fs");
var http  = require("node:http");
var path  = require("node:path");
var https = require("node:https");

// The YAML guard, composed rather than hand-rolled. It decides two things
// here: whether a workflow file is a document at all, and what the pinact
// exemption list says.
var b = require("../lib/vendor/blamejs");

var examinedCounts = require("./examined-counts.js");

var ROOT                  = path.join(__dirname, "..");
var DEFAULT_WORKFLOWS_DIR = path.join(ROOT, ".github", "workflows");
var PINACT_PATH           = path.join(ROOT, ".pinact.yaml");

// The profile every YAML read in this file runs under.
//
// What refuses at EVERY profile was measured rather than assumed, and it is
// everything that would make trusting a document a mistake: a
// deserialization tag, an alias explosion, an anchor or alias of any size,
// a null byte, a tab in indentation, a genuine duplicate mapping key, and a
// document that does not parse. Choosing a profile below strict gives none
// of that up.
//
// What strict adds on top is a set of screens about how some OTHER parser
// might coerce a scalar, and ordinary Actions syntax trips them as a matter
// of course: `on:` reads as an implicit YAML 1.1 boolean, and so does a
// bare `No` in a step value. Neither says anything about whether a pin is
// current.
//
// Strict also carries its own duplicate-key screen, separate from the
// parser's, and that one reads into block scalars instead of treating them
// as the opaque text they are: a `script: |` body holding the same
// JavaScript property name in two object literals is reported as a
// duplicate mapping key. That is what `.github/workflows/ci.yml` in this
// repository does, so strict cannot read the workflow set this gate exists
// to read, while the parser underneath still refuses a real duplicate.
var YAML_READ = Object.freeze({ profile: "balanced" });

var DEFAULT_API_BASE = "https://api.github.com";

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var DO_FIX     = process.argv.indexOf("--fix") !== -1;
var TIMEOUT_MS = 10000;

// Loopback literals, the only hosts a plaintext API override may address.
var LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1"];

function _isLoopback(hostname) {
  if (LOOPBACK_HOSTS.indexOf(hostname) !== -1) return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

/**
 * _resolveApiBase() resolves the API endpoint this run measures against.
 * This is an entry point rather than a request, so bad input throws: an
 * operator who mistyped an endpoint finds out here, instead of watching
 * every action report as unreachable and reading it as a network problem.
 */
function _resolveApiBase() {
  var raw = process.env.GITHUB_API_BASE;
  if (typeof raw !== "string" || raw.length === 0) return DEFAULT_API_BASE;
  var parsed;
  try { parsed = new URL(raw); }
  catch (_e) { throw new TypeError("GITHUB_API_BASE is not a URL: " + raw); }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new TypeError("GITHUB_API_BASE must be http or https, got " + parsed.protocol);
  }
  if (parsed.protocol === "http:" && !_isLoopback(parsed.hostname)) {
    throw new TypeError("GITHUB_API_BASE may only use http for a loopback address, got " + raw);
  }
  return parsed.href.replace(/\/+$/, "");
}

/**
 * _resolveWorkflowsDir() resolves the directory this run reads. Same entry
 * point discipline as the API endpoint: a path that is not a directory
 * throws here, rather than reading as a repository that pins no action at
 * all.
 */
function _resolveWorkflowsDir() {
  var raw = process.env.ACTIONS_CURRENCY_WORKFLOWS_DIR;
  if (typeof raw !== "string" || raw.length === 0) return DEFAULT_WORKFLOWS_DIR;
  var stat;
  try { stat = fs.statSync(raw); }
  catch (_e) {
    throw new TypeError("ACTIONS_CURRENCY_WORKFLOWS_DIR cannot be read: " + raw);
  }
  if (!stat.isDirectory()) {
    throw new TypeError("ACTIONS_CURRENCY_WORKFLOWS_DIR is not a directory: " + raw);
  }
  return path.resolve(raw);
}

// Resolved on first use rather than on load, so requiring this file for its
// pure helpers cannot throw on an environment variable it will never read.
var _apiBaseMemo = null;
function apiBase() {
  if (_apiBaseMemo === null) _apiBaseMemo = _resolveApiBase();
  return _apiBaseMemo;
}

var _workflowsDirMemo = null;
function workflowsDir() {
  if (_workflowsDirMemo === null) _workflowsDirMemo = _resolveWorkflowsDir();
  return _workflowsDirMemo;
}

// Per-action overrides. Keyed by "owner/repo".
//   { type: "hold-major", major: N, reason: "..." } flags stale only
//        WITHIN the pinned major; a newer major reports as HELD, which
//        passes and is never folded into "current": the pin does not match
//        the latest release and saying it does would be a claim nothing
//        measured.
//   { type: "skip", reason: "..." } never flags.
var SPECIAL_MAP = {
  // Empty, because every pinned action tracks upstream latest. The
  // tag-pinned exception is measured as a tag pin rather than skipped.
};

// ---- .pinact.yaml ignore parsing -----------------------------------------
//
// The `ignore_actions:` list, read with the framework's YAML guard. pinact
// v3 treats both `name` and `ref` as regular expressions; a matching action
// is exempted from the tag-to-SHA rewriting pinact performs, and this gate
// honors that for commit-id pins only.
//
// Only `name` is read. pinact's `ref` pattern scopes its rewrite decision
// to one pinned id, and the reason this gate honors an entry at all is an
// upstream API that refuses the runner, which is a property of the
// organization rather than of the id currently pinned.
//
// What the line scanner this replaces could not do is the point. It keyed a
// new entry on the `- name:` shape, so an entry that wrote `ref` first was
// dropped entirely, and one written as a flow mapping was never seen at
// all. Both are ordinary YAML for the same document, and a dropped entry is
// an action measured against an API that refuses the runner, which fails a
// run for a reason no pin bump can address.
function _safeRegExp(src) {
  try { return new RegExp(src); }
  catch (_e) {
    // Fall back to a literal match if the pattern isn't valid regex.
    try { return new RegExp(src.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")); }
    catch (_e2) { return null; }
  }
}

function _parsePinactIgnores(text) {
  var doc  = b.guardYaml.parse(String(text), YAML_READ);
  var list = doc && typeof doc === "object" ? doc.ignore_actions : null;
  if (!Array.isArray(list)) return [];
  return list.map(function (entry, i) {
    // An item this reader cannot take a name from is refused, never
    // skipped. Skipping it measures an action the operator wrote the entry
    // to stop measuring, and the run then fails on an upstream that refuses
    // the runner, which reads as a stale pin and is not one.
    var name = entry && typeof entry === "object" && !Array.isArray(entry)
      ? entry.name
      : undefined;
    if (typeof name !== "string" || name.length === 0) {
      throw new TypeError("ignore_actions[" + i + "] carries no name, so there is no action " +
        "to exempt. Write it as `- name: owner/repo` with a `ref:` beside it.");
    }
    var re = _safeRegExp(name);
    if (!re) {
      throw new TypeError("ignore_actions[" + i + "] name " + JSON.stringify(name) +
        " could not be read as a pattern or as a literal.");
    }
    return { nameRe: re, name: name };
  });
}

function _loadPinactIgnores() {
  var text;
  try { text = fs.readFileSync(PINACT_PATH, "utf8"); }
  catch (_e) { return []; }
  return _parsePinactIgnores(text);
}

// Does any pinact ignore entry match this pin? Test the bare owner/repo AND
// every full owner/repo[/subpath] form (pinact matches the full `uses:`
// action name, which may include a workflow subpath).
//
// A version-tag pin is never exempted. The ignore list answers "should
// pinact rewrite this reference to a commit id", and for the one entry that
// is there because it MUST stay tag-shaped, the answer is no and the
// currency question is untouched by it.
function _isPinactIgnored(ignores, entry) {
  if (!entry || entry.pinType !== "sha") return null;
  var candidates = [entry.action];
  (entry.refs || []).forEach(function (r) {
    if (r.subpath) candidates.push(entry.action + r.subpath);
  });
  for (var i = 0; i < ignores.length; i++) {
    for (var c = 0; c < candidates.length; c++) {
      if (ignores[i].nameRe.test(candidates[c])) return ignores[i];
    }
  }
  return null;
}

// ---- GitHub API ----------------------------------------------------------

function _githubGet(apiPath) {
  return new Promise(function (resolve, reject) {
    var headers = {
      "User-Agent": "blamepost-actions-currency/1",
      "Accept":     "application/vnd.github+json",
    };
    var token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = "Bearer " + token;
    var url = apiBase() + apiPath;
    // node:http is reachable only for the loopback endpoint
    // _resolveApiBase already validated.
    var transport = url.indexOf("http://") === 0 ? http : https;
    var req = transport.get(url, { timeout: TIMEOUT_MS, headers: headers }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        if (res.statusCode !== 200) {
          return reject(new Error("github " + apiPath + " status " + res.statusCode));
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("github " + apiPath + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

async function _resolveSha(ownerRepo, ref) {
  var c = await _githubGet("/repos/" + ownerRepo + "/commits/" + encodeURIComponent(ref));
  if (!c || typeof c.sha !== "string") throw new Error("could not resolve sha for " + ownerRepo + "@" + ref);
  return c.sha;
}

// Fetch the supply-chain review material for a bump: the commit range
// between the pinned commit id and the new one, plus the release notes for
// the new tag. A human reviews this before trusting the pin.
async function _releaseChangelog(ownerRepo, oldSha, newTag, newSha) {
  var out = {
    compareUrl: "https://github.com/" + ownerRepo + "/compare/" + oldSha + "..." + newSha,
    commits: [], files: [], body: "", compareError: null,
  };
  try {
    var cmp = await _githubGet("/repos/" + ownerRepo + "/compare/" + oldSha + "..." + newSha);
    if (cmp && cmp.html_url) out.compareUrl = cmp.html_url;
    if (cmp && Array.isArray(cmp.commits)) {
      out.commits = cmp.commits.map(function (c) {
        var msg = ((c.commit && c.commit.message) || "").split("\n")[0];
        var who = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.name) || "?";
        return (c.sha || "").slice(0, 10) + "  " + who + "  " + msg;
      });
    }
    if (cmp && Array.isArray(cmp.files)) {
      out.files = cmp.files.map(function (f) {
        return {
          name: f.filename, status: f.status,
          add: f.additions, del: f.deletions,
          patch: typeof f.patch === "string" ? f.patch : null,
        };
      });
    }
  } catch (e) { out.compareError = (e && e.message) || String(e); }
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/tags/" + encodeURIComponent(newTag));
    if (rel && typeof rel.body === "string") out.body = rel.body;
  } catch (_e) { /* action ships tags without a GitHub Release body */ }
  return out;
}

async function _latestVersion(ownerRepo) {
  var tag = null;
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/latest");
    if (rel && typeof rel.tag_name === "string" && _semverParse(rel.tag_name)) tag = rel.tag_name;
  } catch (_e) { /* fall through to tags */ }
  if (!tag) {
    var tags = await _githubGet("/repos/" + ownerRepo + "/tags?per_page=100");
    if (!Array.isArray(tags) || tags.length === 0) {
      throw new Error("no releases or tags for " + ownerRepo);
    }
    var best = null;
    for (var i = 0; i < tags.length; i++) {
      var p = _semverParse(tags[i].name);
      if (p && (!best || _semverCompare(p, best.parsed) > 0)) {
        best = { name: tags[i].name, parsed: p };
      }
    }
    if (!best) throw new Error("no semver-shaped tag for " + ownerRepo);
    tag = best.name;
  }
  return { tag: tag, sha: await _resolveSha(ownerRepo, tag) };
}

// A whole version token, anchored, so trailing text that is not a version
// does not read as one. Build metadata is dropped, because semantic
// versioning excludes it from precedence.
var VERSION_TOKEN_RE =
  /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$/;

// Returns [major, minor, patch, prerelease-or-null], or null when the
// string is not a version at all.
function _semverParse(v) {
  var m = String(v).match(VERSION_TOKEN_RE);
  if (!m) return null;
  return [
    parseInt(m[1], 10),
    parseInt(m[2] || "0", 10),
    parseInt(m[3] || "0", 10),
    m[4] || null,
  ];
}

// A version with all three numeric components present. A `v4` or `v4.2` tag
// is an alias upstream repoints as it releases, so it names no fixed
// version to compare.
function _isFullVersion(v) {
  return /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/.test(String(v));
}

// Returns null when either side did not parse, and never 0.
//
// Returning 0 for an unreadable version is the same defect as reporting an
// unreachable API as current, one layer down: 0 means "the pin matches the
// published release", and a comparison that could not be made has not
// established that. Every caller has to see the difference, so the answer
// for "cannot tell" is its own value rather than the value that means
// agreement.
//
// Two different prereleases of one version get the same answer, for the
// same reason. Ordering `rc.1` against `rc.2` needs the identifier rules
// this gate does not implement, and guessing they are equal would report a
// pin as current against a prerelease it is behind.
function _semverCompare(a, b) {
  if (!a || !b) return null;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  var preA = a[3] || null;
  var preB = b[3] || null;
  if (preA === null && preB === null) return 0;
  if (preA === null) return  1;
  if (preB === null) return -1;
  if (preA === preB) return 0;
  return null;
}

// ---- Reading the workflow files ------------------------------------------
//
// The reader takes the `uses:` scalar first, quoting and all, and decides
// what it is afterwards. Recognizing a shape and dropping everything else
// is what made the one tag-pinned reference in this repository invisible to
// every run, so nothing is matched by the shape it is expected to have.

var SHA_RE     = /^[0-9a-f]{40}$/;
var SHORT_SHA_RE = /^[0-9a-f]{7,39}$/;
var ACTION_RE  = /^([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)((?:\/[^@\s]+)?)@(\S+)$/;

// The version a commit-id pin's trailing comment claims. The token needs a
// `v` prefix or an internal dot, so a bare year or a date in a comment is
// not read as a version.
var COMMENT_VERSION_RE =
  /(?:^|\s)(v\d+(?:\.\d+){0,2}|\d+\.\d+(?:\.\d+)?)((?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?)(?=\s|$)/;

// A `uses:` key, in both the bare and the list-item form.
var USES_RE = /^(\s*(?:-\s+)?)uses\s*:\s*(.*)$/;

// A mapping key whose value is a block scalar. Everything indented under it
// is script or free text rather than YAML structure, so a `uses:` written
// inside a `run:` body is a shell line and not a reference. The same is
// true of any other block scalar, so the whole class is skipped rather than
// `run:` alone.
var BLOCK_SCALAR_RE = /^(\s*(?:-\s+)?)([^#\s][^:]*):\s*([|>][-+0-9]*)\s*$/;

function _indentOf(line) {
  return line.length - line.replace(/^\s*/, "").length;
}

/**
 * _splitScalar(rest) separates a YAML scalar from the inline comment that
 * follows it. A quoted scalar can contain anything, including a `#`, so the
 * quote is closed first and the comment looked for after it; a plain scalar
 * ends at the first `#` that has whitespace in front of it, which is what
 * makes a `#` an inline comment in YAML.
 */
function _splitScalar(rest) {
  rest = String(rest);
  var quote = rest.charAt(0);
  if (quote === '"' || quote === "'") {
    var end = -1;
    for (var i = 1; i < rest.length; i++) {
      var ch = rest.charAt(i);
      if (quote === '"' && ch === "\\") { i++; continue; }
      if (ch === quote) {
        if (quote === "'" && rest.charAt(i + 1) === "'") { i++; continue; }
        end = i;
        break;
      }
    }
    if (end === -1) return { value: rest, comment: "", unterminated: true };
    var inner = rest.slice(1, end);
    inner = quote === '"' ? inner.replace(/\\(.)/g, "$1") : inner.replace(/''/g, "'");
    var after = rest.slice(end + 1).match(/^\s*#(.*)$/);
    return { value: inner, comment: after ? after[1] : "", unterminated: false };
  }
  var cut = -1;
  for (var j = 0; j < rest.length; j++) {
    if (rest.charAt(j) === "#" && (j === 0 || /\s/.test(rest.charAt(j - 1)))) { cut = j; break; }
  }
  if (cut === -1) return { value: rest, comment: "", unterminated: false };
  return { value: rest.slice(0, cut), comment: rest.slice(cut + 1), unterminated: false };
}

function _versionInComment(comment) {
  var m = String(comment).match(COMMENT_VERSION_RE);
  return m ? m[1] + (m[2] || "") : null;
}

function _unreadable(ref, problem) {
  ref.kind    = "unreadable";
  ref.problem = problem;
  return ref;
}

/**
 * _classifyUses(scalar, ref) decides what one `uses:` reference is. Every
 * outcome is named: a commit-id pin, a version-tag pin, a local action, a
 * container image, or a reference this gate cannot read. There is no sixth
 * outcome where the reference is quietly dropped.
 */
function _classifyUses(scalar, ref) {
  var split = _splitScalar(scalar);
  ref.value   = split.value.trim();
  ref.comment = split.comment.trim();

  if (split.unterminated) {
    return _unreadable(ref, "the quoted value is never closed");
  }
  if (ref.value === "") {
    return _unreadable(ref, "the uses: value is empty");
  }
  if (/^[|>]/.test(ref.value)) {
    return _unreadable(ref, "the uses: value is a block scalar, which is not a reference");
  }
  if (/^\.{1,2}\//.test(ref.value)) {
    ref.kind = "local";
    return ref;
  }
  if (/^docker:\/\//i.test(ref.value)) {
    ref.kind = "docker";
    return ref;
  }

  var m = ref.value.match(ACTION_RE);
  if (!m) {
    return _unreadable(ref, "could not be read as owner/repo[/path]@ref");
  }
  ref.action  = m[1];
  ref.subpath = m[2] || "";
  ref.ref     = m[3];

  if (SHA_RE.test(ref.ref)) {
    var claimed = _versionInComment(ref.comment);
    if (!claimed) {
      return _unreadable(ref,
        "pinned to a commit id with no trailing version comment, so there is no version " +
        "to compare against the published release");
    }
    ref.kind    = "pin";
    ref.pinType = "sha";
    ref.version = claimed;
    ref.sha     = ref.ref;
    return ref;
  }
  if (SHORT_SHA_RE.test(ref.ref) && !_semverParse(ref.ref)) {
    return _unreadable(ref,
      "pinned to an abbreviated commit id; the pinning discipline writes the full " +
      "40-character id");
  }
  if (!_semverParse(ref.ref)) {
    return _unreadable(ref,
      "pinned to " + JSON.stringify(ref.ref) + ", which is neither a commit id nor a " +
      "version tag. A branch or other moving ref can be repointed at new code with no " +
      "local diff");
  }
  if (!_isFullVersion(ref.ref)) {
    return _unreadable(ref,
      "pinned to " + JSON.stringify(ref.ref) + ", a major or minor tag alias that upstream " +
      "repoints as it releases, so it names no fixed version to compare");
  }
  ref.kind    = "pin";
  ref.pinType = "tag";
  ref.version = ref.ref;
  ref.sha     = null;
  return ref;
}

/**
 * _readWorkflowText(text, file, abs) reads one workflow file and returns
 * every `uses:` reference in it, classified. `file` is the display path and
 * `abs` is what `--fix` would write to.
 */
function _readWorkflowText(text, file, abs) {
  var out      = [];
  var lines    = String(text).split(/\r?\n/);
  var blockCol = -1;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (blockCol >= 0) {
      if (line.trim() === "") continue;
      if (_indentOf(line) > blockCol) continue;
      blockCol = -1;
    }
    // A commented-out reference is a comment, not a pin.
    if (/^\s*#/.test(line)) continue;
    var mUses = line.match(USES_RE);
    if (mUses) {
      var ref = _classifyUses(mUses[2], {
        file: file, abs: abs, line: i + 1, raw: line.trim(),
      });
      out.push(ref);
      // A `uses:` written as a block scalar is already reported as
      // unreadable; its body still has to be stepped over.
      if (/^[|>]/.test(String(mUses[2]).trim())) blockCol = mUses[1].length;
      continue;
    }
    var mBlock = line.match(BLOCK_SCALAR_RE);
    if (mBlock) { blockCol = mBlock[1].length; continue; }
  }
  return out;
}

function _displayPath(abs) {
  var rel = path.relative(ROOT, abs).replace(/\\/g, "/");
  if (rel === "" || rel.indexOf("..") === 0) return abs.replace(/\\/g, "/");
  return rel;
}

// The line number a parse failure names, so the report points at the byte
// that stopped the read rather than at the top of the file.
var PARSE_LINE_RE = /\bat line (\d+)/;

/**
 * _readWorkflowDocument(text) parses one workflow, or says why it could not
 * be read faithfully.
 *
 * This is the guard sitting UNDER the line reader rather than replacing it,
 * and the division is decided by where the material lives. A commit-id
 * pin's version is the trailing `# vX.Y.Z` comment, which a parse discards
 * by definition, and `--fix` rewrites one line in place; neither survives a
 * round trip through a parsed document. So the reference reader stays
 * line-oriented, and the parse answers the two questions it alone can
 * answer: was this file a YAML document, and did it read faithfully.
 *
 * A file that is not a document is the unreadable-reference hole one level
 * up. The line reader walks it regardless, finds nothing it recognizes, and
 * the file contributes zero references while the summary counts it among
 * the ones it read. Every pin in it goes unmeasured and the passing line
 * still goes out.
 */
function _readWorkflowDocument(text) {
  var doc;
  try {
    doc = b.guardYaml.parse(String(text), YAML_READ);
  } catch (e) {
    return { problem: (e && e.message) || String(e) };
  }
  var bad = _misparsedFlowKey(doc, 0);
  if (bad !== null) {
    return {
      problem: "an item is written as a flow mapping in block-sequence position and read as " +
        "the plain scalar key " + JSON.stringify(bad) + ", so no uses: reference can be taken " +
        "from it by either reader. Write the item as a block mapping.",
    };
  }
  return { doc: doc };
}

// The one wrong answer the parser gives without saying so. A flow mapping
// written as the item of a block sequence, `- { uses: acme/widget@v1 }`,
// comes back as a mapping whose single key is `"{ uses"` and whose value is
// the rest of the line as text. A flow sequence in the same position parses
// correctly, and a flow mapping in every other position does too, so this is
// the block-sequence-item case alone.
//
// It matters here because it is silent. The step is not refused, it is
// simply not in the document, and a reader that trusts the result counts a
// file it read short among the files it read. A mapping key that opens with
// a brace is that misparse and nothing else produces one, so the check
// disappears on its own when the parser learns the shape.
function _misparsedFlowKey(node, depth) {
  if (depth > 64 || node === null || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (var i = 0; i < node.length; i++) {
      var inSeq = _misparsedFlowKey(node[i], depth + 1);
      if (inSeq !== null) return inSeq;
    }
    return null;
  }
  var keys = Object.keys(node);
  for (var k = 0; k < keys.length; k++) {
    if (keys[k].charAt(0) === "{") return keys[k];
    var inMap = _misparsedFlowKey(node[keys[k]], depth + 1);
    if (inMap !== null) return inMap;
  }
  return null;
}

/**
 * _parsedUses(doc) is every `uses:` value the parsed document carries.
 *
 * It exists to hold the two readers to the same count. The line reader
 * matches a shape, and a shape it does not match produces silence rather
 * than a finding, which is the failure this whole gate is written against.
 * The parse has no shape to miss, so a reference the document has and the
 * line reader did not produce is a reference nobody classified, and it is
 * reported as one.
 *
 * It also covers the flow-mapping misparse from the far side. Today that
 * shape is invisible to the parse as well, so the brace check above is what
 * catches it; once the parser learns the shape, the parse will carry a
 * reference the line reader still cannot match, and this is what catches it
 * then. Neither check makes the other redundant, because they fail on
 * opposite sides of the same upstream fix.
 */
function _parsedUses(node, depth, out) {
  if (depth > 64 || node === null || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (var i = 0; i < node.length; i++) _parsedUses(node[i], depth + 1, out);
    return out;
  }
  Object.keys(node).forEach(function (k) {
    var v = node[k];
    if (k === "uses" && typeof v === "string") out.push(v.trim());
    _parsedUses(v, depth + 1, out);
  });
  return out;
}

// Where a value sits in the source, for the report alone. The line reader
// did not match this line, by definition, so the value's own text is all
// there is to go on.
function _lineContaining(text, value) {
  var lines = String(text).split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].indexOf(value) !== -1) return i + 1;
  }
  return 1;
}

/**
 * _readWorkflows() walks the workflow directory and returns every `uses:`
 * reference across it, plus the file list, so the report can say how much
 * it actually read rather than how much it recognized.
 */
function _readWorkflows() {
  var dir   = workflowsDir();
  var files = fs.readdirSync(dir, { withFileTypes: true }).filter(function (e) {
    return e.isFile() && (e.name.endsWith(".yml") || e.name.endsWith(".yaml"));
  }).map(function (e) { return e.name; }).sort();
  var references = [];
  files.forEach(function (name) {
    var abs  = path.join(dir, name);
    var file = _displayPath(abs);
    var text = fs.readFileSync(abs, "utf8");
    var read = _readWorkflowDocument(text);
    if (read.problem) {
      var at = PARSE_LINE_RE.exec(read.problem);
      references.push({
        file:    file,
        abs:     abs,
        line:    at ? Number(at[1]) : 1,
        raw:     name,
        value:   file,
        kind:    "unreadable",
        problem: "the file could not be read as a workflow, so every reference in it went " +
                 "unread: " + read.problem,
      });
      return;
    }

    var fromLines = _readWorkflowText(text, file, abs);
    references = references.concat(fromLines);

    var seen = Object.create(null);
    fromLines.forEach(function (r) {
      if (typeof r.value === "string") seen[r.value.trim()] = true;
    });
    _parsedUses(read.doc, 0, []).forEach(function (value) {
      if (seen[value]) return;
      references.push({
        file:    file,
        abs:     abs,
        line:    _lineContaining(text, value),
        raw:     value,
        value:   value,
        kind:    "unreadable",
        problem: "the workflow document carries this uses: reference and the line reader did " +
                 "not produce it, so nothing classified or measured it. The two readers have " +
                 "to agree on how many references a workflow has.",
      });
    });
  });
  return { dir: dir, files: files, references: references };
}

/**
 * _groupPins(references) folds the pinned references into one entry per
 * (action, pin type). The pin type is part of the key on purpose: an action
 * pinned by commit id in one workflow and by tag in another needs a
 * different answer in each place, and `--fix` can rewrite only one of them.
 */
function _groupPins(references) {
  var byKey = {};
  var order = [];
  (references || []).forEach(function (r) {
    if (r.kind !== "pin") return;
    var key = r.action + "@" + r.pinType;
    if (!byKey[key]) {
      byKey[key] = {
        key: key, action: r.action, pinType: r.pinType,
        version: r.version, sha: r.sha, refs: [],
      };
      order.push(key);
    }
    var entry = byKey[key];
    entry.refs.push({
      file: r.file, abs: r.abs, line: r.line,
      subpath: r.subpath, version: r.version, sha: r.sha,
    });
    // An action pinned at two versions across the workflow set is measured
    // at the LOWEST of them, so the gate reports the pin that is furthest
    // behind rather than the one that happens to be read first. A
    // comparison that cannot be made keeps whichever version is already
    // recorded and leaves the other visible in the refs list; silently
    // promoting an uncomparable value would decide the verdict from a
    // string nothing could read.
    var cmp = _semverCompare(_semverParse(r.version), _semverParse(entry.version));
    if (cmp !== null && cmp < 0) {
      entry.version = r.version;
      entry.sha     = r.sha;
    }
  });
  return order.sort().map(function (k) { return byKey[k]; });
}

// ---- Measuring one pin ---------------------------------------------------

async function _checkOne(entry) {
  var special = SPECIAL_MAP[entry.action];
  if (special && special.type === "skip") {
    return {
      action: entry.action, pinType: entry.pinType, status: "skipped",
      reason: special.reason, pinned: entry.version, refs: entry.refs,
    };
  }
  var pinned = _semverParse(entry.version);
  try {
    var info = await _latestVersion(entry.action);
    var latest = _semverParse(info.tag);
    var cmp = _semverCompare(pinned, latest);
    if (cmp === null) {
      // Reached the API, could not compare what it said. That is still a
      // pin nobody measured, so it lands in the same bucket as an API that
      // never answered, and the message names the values to look at.
      return {
        action:  entry.action,
        pinType: entry.pinType,
        pinned:  entry.version,
        oldSha:  entry.sha,
        latest:  info.tag,
        status:  "unreadable-version",
        error:   "cannot compare " + JSON.stringify(entry.version) + " against " +
                 JSON.stringify(info.tag) + ": they cannot be ordered as versions",
        refs:    entry.refs,
      };
    }
    // A pin AHEAD of the latest published release is its own answer, not a
    // match. It happens when an action's newest tag has no release behind
    // it, and folding it into "current" hides a pin pointing at something
    // upstream never published.
    var status = cmp === 0 ? "current" : (cmp > 0 ? "ahead" : "stale");
    if (special && special.type === "hold-major" && latest && latest[0] > special.major) {
      status = "held";
    }
    return {
      action:    entry.action,
      pinType:   entry.pinType,
      pinned:    entry.version,
      oldSha:    entry.sha,
      latest:    info.tag,
      latestSha: info.sha,
      status:    status,
      reason:    status === "held" ? (special && special.reason) : undefined,
      refs:      entry.refs,
    };
  } catch (e) {
    return {
      action:  entry.action,
      pinType: entry.pinType,
      pinned:  entry.version,
      oldSha:  entry.sha,
      status:  "api-error",
      error:   (e && e.message) || String(e),
      refs:    entry.refs,
    };
  }
}

/**
 * _verdict(results) turns the per-action results into the one line this
 * gate answers with, and the exit code that goes with it.
 *
 * The rule it encodes: a pin that could not be measured is UNKNOWN, and
 * UNKNOWN is not a pass. The shape this replaces printed "every pinned
 * action matches the latest upstream release" whenever nothing was stale,
 * which was true of a run where the API answered nothing at all. A CI job
 * reading that line, or its exit code, learns that the pins are current at
 * the exact moment the check stopped happening.
 *
 * Pure, and exported, so the failure paths are provable without a network.
 */
// Every status that means "this pin was not measured". They belong in one
// bucket: an API that did not answer, an answer that could not be read, and
// a reference that could not be classified leave the same hole, and the
// gate must treat them the same way.
var UNMEASURED_STATUSES = ["api-error", "unreadable-version", "unreadable-reference"];

// Every status that means "this pin WAS measured against upstream".
var MEASURED_STATUSES = ["current", "stale", "ahead", "held"];

function _isUnmeasured(result) {
  return UNMEASURED_STATUSES.indexOf(result && result.status) !== -1;
}

function _isMeasured(result) {
  return MEASURED_STATUSES.indexOf(result && result.status) !== -1;
}

function _verdict(results) {
  results = results || [];
  var stale      = results.filter(function (r) { return r.status === "stale"; });
  var unknown    = results.filter(_isUnmeasured);
  var measured   = results.filter(_isMeasured);
  var ahead      = results.filter(function (r) { return r.status === "ahead"; });
  var held       = results.filter(function (r) { return r.status === "held"; });
  var unreadable = results.filter(function (r) { return r.status === "unreadable-reference"; });

  if (stale.length > 0) {
    return {
      code: 1,
      summary: "FAIL: " + stale.length + " pinned action(s) behind the latest upstream release" +
        (unknown.length > 0 ? ", and " + unknown.length + " that could not be checked" : ""),
      advice: "Bump the pinned commit id and version comment with: " +
        "node scripts/check-actions-currency.js --fix",
    };
  }
  if (unknown.length > 0) {
    return {
      code: 1,
      summary: "UNKNOWN: " + unknown.length + " reference(s) could not be measured against " +
        "upstream" +
        (unreadable.length > 0
          ? ", " + unreadable.length + " of them because the reference itself could not be read"
          : "") +
        ". Currency is unknown, not current.",
      advice: unreadable.length > 0
        ? "Pin each reference named above to a commit id with a trailing version comment, " +
          "or to a full version tag. Re-run once the API named beside each action answers; " +
          "pass GITHUB_TOKEN for the authenticated rate budget."
        : "Re-run once the API named beside each action answers. Pass GITHUB_TOKEN for the " +
          "authenticated rate budget.",
    };
  }

  // Nothing measured at all. Measuring nothing is not the same as finding
  // nothing wrong: a repository that stops writing pinned references, or a
  // pinning tool that changes the comment it emits, silently empties this
  // gate. The passing line would then be true of a run that inspected no
  // pin at all.
  if (measured.length === 0) {
    return {
      code: 1,
      summary: "UNKNOWN: no action pin was found to measure. Currency is unknown, not current.",
      advice: "Check that the workflow files carry `uses: owner/repo@<40-hex id>  # vX.Y.Z` " +
        "references, which is the shape .pinact.yaml pins them into, or a full version tag " +
        "where a reference has to stay tag-shaped.",
    };
  }

  return {
    code: 0,
    summary: "OK, every pinned action matches the latest upstream release (or is ignored by .pinact.yaml)" +
      (ahead.length > 0
        ? ", with " + ahead.length + " pinned ahead of the latest published release"
        : "") +
      (held.length > 0
        ? ", with " + held.length + " held inside the pinned major"
        : ""),
    advice: "",
  };
}

// ---- Report --------------------------------------------------------------

function _label(status) {
  return status === "current"             ? "OK"
       : status === "stale"               ? "STALE"
       : status === "ahead"               ? "AHEAD"
       : status === "held"                ? "HELD"
       : status === "api-error"           ? "UNKNOWN"
       : status === "unreadable-version"  ? "UNKNOWN"
       : status === "unreadable-reference"? "UNKNOWN"
       : status === "skipped"             ? "skip"
       :                                    status;
}

function _scanCounts(references) {
  var counts = { sha: 0, tag: 0, local: 0, docker: 0, unreadable: 0 };
  references.forEach(function (r) {
    if (r.kind === "pin") counts[r.pinType] += 1;
    else if (r.kind === "local") counts.local += 1;
    else if (r.kind === "docker") counts.docker += 1;
    else counts.unreadable += 1;
  });
  return counts;
}

function _printReport(scan, results) {
  var counts = _scanCounts(scan.references);
  process.stdout.write(
    "[actions-currency] read " + scan.references.length + " uses: reference(s) across " +
    scan.files.length + " workflow file(s): " +
    counts.sha + " by commit id, " + counts.tag + " by version tag, " +
    counts.local + " local, " + counts.docker + " container image, " +
    counts.unreadable + " unreadable\n");
  process.stdout.write("[actions-currency] " + results.length + " action pin(s) inspected:\n");
  for (var j = 0; j < results.length; j++) {
    var r = results[j];
    var line = "  [" + _label(r.status) + "] " + r.action + "  " + r.pinned;
    if (r.latest) line += " -> " + r.latest;
    if (r.pinType === "tag") line += "  (tag pin)";
    if (r.reason) line += "  (" + r.reason + ")";
    if (r.error)  line += "  (" + r.error + ")";
    process.stdout.write(line + "\n");
    var showRefs = r.status === "unreadable-reference" ||
                   (r.status === "stale" && r.latestSha);
    if (r.status === "stale" && r.latestSha && r.pinType === "sha") {
      process.stdout.write("        pin:  " + r.action + "@" + r.latestSha + "  # " + r.latest + "\n");
    }
    if (r.status === "stale" && r.pinType === "tag") {
      process.stdout.write("        move the tag by hand after reading the upstream release; " +
        "--fix rewrites commit-id pins only\n");
    }
    if (showRefs) {
      for (var rf = 0; rf < (r.refs || []).length; rf++) {
        process.stdout.write("        used: " + r.refs[rf].file + ":" + r.refs[rf].line + "\n");
      }
    }
  }
}

/**
 * _publishExamined(scan, results) publishes what this run read and returns
 * 0 or 1.
 *
 * Two units, and they empty for different reasons. `uses-references` is
 * every `uses:` line the workflow reader recognized: a reader that stopped
 * matching, or a workflow directory that moved, takes it to zero while
 * every verdict rule below still holds over the nothing it read.
 * `measured-pins` is how many of those were actually compared against
 * upstream, which comes apart from the first number the moment the API
 * stops answering. That is the shape where a full scan reports currency it
 * never measured.
 *
 * The lines go to stderr under `--json`, because stdout there is one
 * document for a parser and a count line inside it would make the flag
 * unusable for the thing it exists for. The refusal still reaches the exit
 * code in both modes.
 */
function _publishExamined(scan, results) {
  return examinedCounts.publish([
    { unit: "uses-references", n: scan.references.length },
    { unit: "measured-pins",   n: results.filter(_isMeasured).length },
  ], {
    stream: JSON_OUT ? process.stderr : process.stdout,
    tag:    "[actions-currency]",
  });
}

// ---- --fix ---------------------------------------------------------------

function _escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * _rewritePinLine(line, oldSha, oldVersion, newSha, newTag) replaces the
 * commit id and the version comment on ONE line, leaving the quoting, the
 * spacing and the rest of the comment as they were. Line-scoped on purpose:
 * a file-wide substitution would also rewrite a reference this run
 * classified differently, and there is no diff review between deciding and
 * writing.
 */
function _rewritePinLine(line, oldSha, oldVersion, newSha, newTag) {
  var next = line.replace(oldSha, newSha);
  var re = new RegExp("(#\\s*)v?" + _escapeRe(String(oldVersion).replace(/^v/, "")) +
                      "(?![0-9A-Za-z.-])");
  next = next.replace(re, "$1" + newTag);
  return next;
}

// ---- main ----------------------------------------------------------------

async function main() {
  // Resolve both entry points before any work, so a mistyped override reads
  // as a configuration refusal rather than as every action being
  // unreachable or as a repository that pins nothing.
  try {
    // --fix prints the commit range and the release notes a human reads
    // before trusting a bump, and --json promises one parseable document.
    // Together they produce a stream that is neither, so the combination is
    // refused here rather than emitted and left to the caller to notice.
    if (DO_FIX && JSON_OUT) {
      throw new TypeError("--fix and --json cannot be combined: --fix prints review material " +
        "for a human to read, and --json emits one document for a parser");
    }
    apiBase();
    workflowsDir();
  } catch (e) {
    process.stderr.write("[actions-currency] " + ((e && e.message) || String(e)) + "\n");
    process.exit(2);
    return;
  }

  var scan    = _readWorkflows();
  var pins    = _groupPins(scan.references);
  var ignores;
  // The exemption list decides which pins this gate stops asking about, so
  // a file that is present and unreadable is refused rather than read as
  // exempting nothing. Answering with an empty list would measure an action
  // whose organization refuses the runner, and fail the run for a reason no
  // pin bump can address, without saying why.
  try { ignores = _loadPinactIgnores(); }
  catch (e) {
    process.stderr.write("[actions-currency] .pinact.yaml could not be read: " +
      ((e && e.message) || String(e)) + "\n");
    process.exit(2);
    return;
  }
  var results = [];

  // Every reference the reader could not classify is a result of its own,
  // so it is in the report AND in the verdict. Dropping it would leave the
  // summary counting what it looked at while a reference nobody can vouch
  // for rides through.
  scan.references.filter(function (r) { return r.kind === "unreadable"; }).forEach(function (r) {
    results.push({
      action:  r.value || r.raw,
      pinType: null,
      pinned:  "(unreadable)",
      status:  "unreadable-reference",
      error:   r.problem,
      refs:    [{ file: r.file, abs: r.abs, line: r.line }],
    });
  });

  for (var i = 0; i < pins.length; i++) {
    var entry = pins[i];
    var ig = _isPinactIgnored(ignores, entry);
    if (ig) {
      results.push({
        action:  entry.action,
        pinType: entry.pinType,
        status:  "skipped",
        reason:  ".pinact.yaml ignore (" + ig.name + ")",
        pinned:  entry.version,
        refs:    entry.refs,
      });
      continue;
    }
    results.push(await _checkOne(entry));
  }

  var verdict = _verdict(results);
  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var unknown = results.filter(_isUnmeasured);

  // The structured document carries the verdict inside it, and nothing is
  // printed around it. A caller that pipes this into a parser gets one
  // document; a summary line appended after the closing brace would make
  // the flag unusable for the thing it exists for.
  //
  // Moving the verdict inside the document does NOT cost this gate its
  // empty-set refusal, and the difference is worth naming because it is the
  // trap a `--json` mode invites. The refusal lives in `_verdict` above, so it
  // reaches the exit code in both modes; a caller keying on the exit code alone
  // is answered identically whichever it asked for. A gate that published its
  // count as a printed LINE instead, and then suppressed that line under
  // `--json`, would go silently ungated for every such caller. That is why the
  // refusal here is a verdict rather than a line.
  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({
      scan: {
        files:      scan.files,
        counts:     _scanCounts(scan.references),
        references: scan.references,
      },
      results: results,
      verdict: {
        code:     verdict.code,
        summary:  verdict.summary,
        advice:   verdict.advice,
        warnOnly: WARN_ONLY,
      },
    }, null, 2) + "\n");
  } else {
    _printReport(scan, results);
  }

  if (DO_FIX) {
    var byFile    = {};
    var fixable   = stale.filter(function (r) {
      return r.pinType === "sha" && r.latestSha && r.latest;
    });
    var leftAlone = stale.filter(function (r) { return fixable.indexOf(r) === -1; });
    var unreviewed = [];
    var unwritten  = [];

    for (var fx = 0; fx < fixable.length; fx++) {
      var fr = fixable[fx];
      // The upstream tag verbatim. Prefixing a `v` onto a tag that does not
      // carry one asks the release API for a tag that does not exist, and
      // writes a version comment naming something upstream never published.
      var tag = fr.latest;
      var cl = await _releaseChangelog(fr.action, fr.oldSha, tag, fr.latestSha);
      process.stdout.write("\n=== " + fr.action + "  " + fr.pinned + " -> " + fr.latest + " ===\n");
      process.stdout.write("  old commit id: " + fr.oldSha + "\n  new commit id: " + fr.latestSha + "\n");
      process.stdout.write("  compare: " + cl.compareUrl + "\n");
      if (cl.commits.length) {
        process.stdout.write("  commits between the two ids (" + cl.commits.length + ") [id  author  subject]:\n");
        for (var ci = 0; ci < cl.commits.length; ci++) process.stdout.write("    " + cl.commits[ci] + "\n");
      } else if (cl.compareError) {
        process.stdout.write("  commits: (compare unavailable: " + cl.compareError + ")\n");
      }
      if (cl.files.length) {
        process.stdout.write("  changed files (" + cl.files.length + "):\n");
        for (var sfi = 0; sfi < cl.files.length; sfi++) {
          var sf = cl.files[sfi];
          process.stdout.write("    [" + sf.status + " +" + sf.add + "/-" + sf.del + "] " + sf.name + "\n");
        }
        process.stdout.write("  code diff (per file, capped at 200 lines):\n");
        for (var dfi = 0; dfi < cl.files.length; dfi++) {
          var df = cl.files[dfi];
          process.stdout.write("    ----- " + df.name + " -----\n");
          if (df.patch === null) {
            process.stdout.write("      (patch omitted by GitHub: file too large or binary. Inspect it via the compare URL above)\n");
          } else {
            var dl = df.patch.split("\n");
            for (var dk = 0; dk < Math.min(dl.length, 200); dk++) process.stdout.write("      " + dl[dk] + "\n");
            if (dl.length > 200) process.stdout.write("      ... (" + (dl.length - 200) + " more diff line(s), shown in full at the compare URL)\n");
          }
        }
      }
      if (cl.body) {
        process.stdout.write("  release notes for " + tag + ":\n");
        var bl = cl.body.split("\n");
        for (var bi = 0; bi < Math.min(bl.length, 40); bi++) process.stdout.write("    " + bl[bi] + "\n");
        if (bl.length > 40) process.stdout.write("    ... (" + (bl.length - 40) + " more line(s))\n");
      }
      // A bump whose compare never answered was rewritten with nothing to
      // review. The closing line tells the operator to read the changelogs
      // above, so a bump that has none has to be named rather than counted
      // into the same total.
      if (cl.compareError) {
        unreviewed.push(fr.action + " (" + cl.compareError + ")");
        process.stdout.write("  REVIEW MATERIAL MISSING: the compare API did not answer, so this " +
          "bump was rewritten with no diff to read. Inspect it at the compare URL above " +
          "before committing.\n");
      }

      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var refRow = fr.refs[rj];
        var abs = refRow.abs;
        // Split on the newline alone, so a carriage return stays on the end
        // of the line it belongs to and rejoining reproduces the file's own
        // endings. Splitting on `\r?\n` here and rejoining on `\n` would
        // rewrite every line ending in the file as a side effect of moving
        // one pin.
        if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8").split("\n");
        var idx  = refRow.line - 1;
        var was  = byFile[abs][idx];
        var next = _rewritePinLine(was, refRow.sha, refRow.version, fr.latestSha, tag);
        if (next === was) {
          unwritten.push(refRow.file + ":" + refRow.line);
          continue;
        }
        byFile[abs][idx] = next;
      }
    }

    Object.keys(byFile).forEach(function (abs) {
      fs.writeFileSync(abs, byFile[abs].join("\n"));
    });
    process.stdout.write("\n[actions-currency] --fix: rewrote " + fixable.length +
      " stale action(s) across " + Object.keys(byFile).length +
      " workflow file(s). REVIEW the changelogs above for supply-chain integrity before " +
      "committing; re-run without --fix to verify.\n");

    leftAlone.forEach(function (r) {
      process.stdout.write("[actions-currency] --fix: left " + r.action + " " + r.pinned +
        " alone. " + (r.pinType === "tag"
          ? "A tag pin has no old commit id to diff against, so there is no review material " +
            "to print. Move the tag by hand after reading the upstream release."
          : "The new commit id could not be resolved.") + "\n");
    });
    unwritten.forEach(function (where) {
      process.stdout.write("[actions-currency] --fix: could not rewrite " + where +
        "; the line no longer carries the pin that was measured.\n");
    });

    // A repair run that could not measure every pin has not established
    // that the pins it left alone are current, and its caller
    // (scripts/pin-all.js --fix) reads a zero here as "pinned and up to
    // date". Report the unmeasured half, the pins this run cannot repair,
    // and any bump it wrote without review material, rather than letting
    // the repair stand in for a measurement it never made.
    //
    // Being stale BEFORE the rewrite is not one of those: that is the work
    // this run was asked to do, and answering non-zero for it would make a
    // repair that landed everything read as a failed one.
    var measured = results.filter(_isMeasured);
    var reasons  = [];
    if (unknown.length > 0 || measured.length === 0) reasons.push(verdict.summary);
    if (leftAlone.length > 0) {
      reasons.push(leftAlone.length + " stale pin(s) this run cannot rewrite, named above");
    }
    if (unwritten.length > 0) {
      reasons.push(unwritten.length + " reference(s) the rewrite did not land on: " +
        unwritten.join(", "));
    }
    if (unreviewed.length > 0) {
      reasons.push(unreviewed.length + " bump(s) rewritten with no review material: " +
        unreviewed.join(", "));
    }
    var repairCode = 0;
    if (reasons.length > 0) {
      reasons.forEach(function (why) {
        process.stdout.write("[actions-currency] --fix: " + why + "\n");
      });
      repairCode = 1;
    }
    process.exit(_publishExamined(scan, results) || repairCode);
    return;
  }

  if (!JSON_OUT) {
    process.stdout.write("[actions-currency] " + verdict.summary + "\n");
    if (verdict.advice) process.stdout.write("[actions-currency] " + verdict.advice + "\n");
  }

  if (WARN_ONLY) {
    // The advisory local run still reported the verdict above, in the
    // document or in the summary line. What --warn changes is the exit
    // code, never the claim.
    if (verdict.code !== 0 && !JSON_OUT) {
      process.stdout.write("[actions-currency] --warn: " + stale.length + " stale, " +
        unknown.length + " unmeasured, exiting 0 anyway\n");
    }
    // The counts are published here too, so the advisory run says what it
    // read; the exit code stays 0 because that is the whole of what --warn
    // changes. A refusal that flipped the status here would make the mode
    // mean something different from what it says.
    _publishExamined(scan, results);
    process.exit(0);
    return;
  }
  process.exit(_publishExamined(scan, results) || verdict.code);
}

// Exported for hermetic unit tests. The workflow reader, the classifier,
// the semantic version comparison and the verdict are pure, touch no
// network, and are the load-bearing logic. Requiring this file runs
// nothing.
module.exports = {
  MEASURED_STATUSES:   MEASURED_STATUSES,
  UNMEASURED_STATUSES: UNMEASURED_STATUSES,
  _groupPins:          _groupPins,
  _isMeasured:         _isMeasured,
  _isPinactIgnored:    _isPinactIgnored,
  _isUnmeasured:       _isUnmeasured,
  _isFullVersion:      _isFullVersion,
  _isLoopback:         _isLoopback,
  _loadPinactIgnores:  _loadPinactIgnores,
  _parsePinactIgnores: _parsePinactIgnores,
  _readWorkflowText:   _readWorkflowText,
  _readWorkflows:      _readWorkflows,
  _rewritePinLine:     _rewritePinLine,
  _scanCounts:         _scanCounts,
  _semverCompare:      _semverCompare,
  _semverParse:        _semverParse,
  _splitScalar:        _splitScalar,
  _verdict:            _verdict,
  SPECIAL_MAP:         SPECIAL_MAP,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[actions-currency] script crashed: " + ((e && e.stack) || e) + "\n");
    process.exit(2);
  });
}
