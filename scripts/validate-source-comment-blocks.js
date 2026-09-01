#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/validate-source-comment-blocks is a static gate over the
// `@primitive` documentation blocks in lib/.
//
// Why: those blocks are not decoration. scripts/refresh-api-snapshot.js reads
// `@since` and `@originated` out of them to freeze each primitive's
// introduction version, and scripts/check-status-lifecycle.js reads `@status`
// and `@deprecated` to force a graduation or removal decision on schedule. A
// block missing one of those tags does not fail either of those gates. It
// silently drops out of them, which is the same as never having been governed.
// This gate is what makes the tag mandatory rather than customary.
//
// What is checked, per `@primitive` block:
//
//   @since       present, and plain X.Y.Z. The api-snapshot gate treats it as
//                immutable once shipped, so an unparseable one is a freeze that
//                never engages.
//   @status      present, and one of experimental / stable / deprecated. The
//                lifecycle gate skips any other value.
//   @spec        present. Every primitive names the standard it implements, or
//                `internal (design: ...)` for infrastructure with no external
//                one. A mail server's behavior is mostly somebody else's
//                specification, and the reference is what a reader checks it
//                against.
//   @deprecated  paired with `@status deprecated`, in both directions. Either
//                half alone is a removal date nothing enforces.
//   prose        at least one non-tag line of description. A block that is only
//                tags documents nothing.
//   uniqueness   no token declared by two blocks. The snapshot maps tokens to
//                versions, so a duplicate silently overwrites one of them.
//   @related     every referenced token resolves to a declared primitive.
//   tested       every token is referenced from the test corpus, by its full
//                dotted form or by its namespace plus a call to its method.
//                A documented primitive nothing exercises is a claim, not a
//                capability.
//
// Files with no `@primitive` block are not findings: the gate governs the
// blocks that exist rather than mandating where they appear.
//
// WHAT THE RUN EXAMINED is published as the last lines of every run, pass or
// fail, in the form the release battery reads:
//
//   EXAMINED <n> lib-source-files
//   EXAMINED <n> primitive-blocks
//
// Both numbers, because they fail independently. `lib-source-files` is the walk:
// a lib directory that moved, or a source filter that stopped matching, takes it
// to zero and every rule below has nothing to apply to. `primitive-blocks` is
// what the rules are actually applied to, and it is the honest count of the two:
// a run that opened two hundred files and extracted no block proved exactly as
// much as one that opened none, and prints the same "OK, no findings" either
// way. Publishing only the file count would hide that.
//
// The test corpus is deliberately NOT counted. An empty one does not go quiet:
// every primitive then reports `primitive-without-test`, so that failure arrives
// loudly on its own and needs no liveness number to surface it.
//
// Pure script, with no side effects, no network, no listeners bound.
//
// Exit codes:
//   0  no findings
//   1  findings present (each printed with its file, line and primitive)

var fs   = require("node:fs");
var path = require("node:path");

// The shared walk over this project's own lib sources and the one reader of
// the blocks they carry; the vendored tree is upstream's and is excluded
// there. This gate validates exactly the records the api-snapshot and
// lifecycle gates govern, because all three read them from the same place.
var sourcePrimitives = require("./source-primitives.js");
var libSources        = sourcePrimitives.libSources;
var collectPrimitives = sourcePrimitives.collectPrimitives;

var ROOT     = path.resolve(__dirname, "..");
var LIB_DIR  = path.join(ROOT, "lib");
var TEST_DIR = path.join(ROOT, "test");

var KNOWN_STATUSES = { experimental: 1, stable: 1, deprecated: 1 };
var SEMVER_RE = /^\d+\.\d+\.\d+$/;

var _rel = sourcePrimitives.relative;

// The whole test corpus as one { file -> text } map, read once. Every
// tested-ness question is answered from it.
function readTestCorpus() {
  var out = {};
  (function walk(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
      var p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); return; }
      if (e.isFile() && /\.(js|mjs|cjs)$/.test(e.name)) out[_rel(p)] = fs.readFileSync(p, "utf8");
    });
  }(TEST_DIR));
  return out;
}

// A primitive counts as exercised when a test names it outright, or names the
// namespace that owns it AND calls its method. The second form is what an
// idiomatic test looks like once it has bound the namespace to a local:
//
//   var mail = b.mail;  ...  mail.send.deliver(envelope);
//
// Requiring both halves in the SAME file keeps that from matching a namespace
// mentioned in one test and a same-named method called in an unrelated one.
function isExercised(token, corpus) {
  var parts = token.split(".");
  var method = parts[parts.length - 1];
  var namespace = parts.slice(0, -1).join(".");
  var files = Object.keys(corpus);
  for (var i = 0; i < files.length; i += 1) {
    var text = corpus[files[i]];
    if (text.indexOf(token) !== -1) return true;
    if (namespace.length > 0 &&
        text.indexOf(namespace) !== -1 &&
        text.indexOf("." + method + "(") !== -1) {
      return true;
    }
  }
  return false;
}

function validate() {
  var files = libSources(LIB_DIR);
  var primitives = collectPrimitives(files);
  var corpus = readTestCorpus();
  var findings = [];
  var seen = {};

  function finding(kind, p, msg) {
    findings.push({ kind: kind, file: p.file, line: p.line, primitive: p.token, msg: msg });
  }

  var declared = {};
  primitives.forEach(function (p) { declared[p.token] = true; });

  primitives.forEach(function (p) {
    if (seen[p.token]) {
      finding("duplicate-primitive", p,
        "already declared at " + seen[p.token] + ". The api snapshot maps one version per token, " +
        "so the second declaration silently replaces the first.");
    } else {
      seen[p.token] = p.file + ":" + p.line;
    }

    if (!p.since) {
      finding("missing-since", p, "no @since. The api-snapshot gate has no introduction version to freeze.");
    } else if (!SEMVER_RE.test(p.since)) {
      finding("bad-since", p, "@since " + p.since + " is not a plain X.Y.Z version.");
    }

    if (!p.status) {
      finding("missing-status", p, "no @status. Declare experimental, stable or deprecated, because the lifecycle gate skips anything else.");
    } else if (!KNOWN_STATUSES[p.status]) {
      finding("bad-status", p, "@status " + p.status + " is not experimental, stable or deprecated.");
    }

    if (!p.spec) {
      finding("missing-spec", p,
        "no @spec. Name the standard this implements, or `internal (design: ...)` when there is none.");
    }

    if (p.deprecated && p.status !== "deprecated") {
      finding("deprecation-mismatch", p,
        "declares @deprecated " + p.deprecated + " but @status is " + (p.status || "absent") +
        ". The removal gate only reads blocks whose status is deprecated.");
    }
    if (p.status === "deprecated" && !p.deprecated) {
      finding("deprecation-mismatch", p,
        "is @status deprecated but names no `@deprecated <remove-by-version>`, so nothing enforces the removal.");
    }

    if (p.prose < 40) {
      finding("prose-too-short", p,
        "carries " + p.prose + " characters of description. Say what it does and when to reach for it.");
    }

    p.related.forEach(function (target) {
      if (!declared[target]) {
        finding("unresolved-related", p, "@related " + target + " is not a declared @primitive.");
      }
    });

    if (!isExercised(p.token, corpus)) {
      finding("primitive-without-test", p,
        "is not referenced anywhere under test/. Add a test that calls it, or drop the block.");
    }
  });

  return {
    findings: findings,
    examined: { "lib-source-files": files.length, "primitive-blocks": primitives.length },
  };
}

function report(result) {
  var findings = result.findings;
  var code = 0;
  if (findings.length === 0) {
    console.log("[validate-source-comment-blocks] OK, no findings");
  } else {
    console.log("[validate-source-comment-blocks] " + findings.length + " finding(s):");
    findings.forEach(function (f, i) {
      console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + ":" + f.line +
                  (f.primitive ? " :: " + f.primitive : ""));
      console.log("     " + f.msg);
    });
    code = 1;
  }
  // Last, and on both paths. The verdict above says whether the blocks this run
  // read were well-formed; these lines say how many there were to read, which is
  // the half a clean verdict cannot carry on its own.
  Object.keys(result.examined).forEach(function (unit) {
    console.log("EXAMINED " + result.examined[unit] + " " + unit);
  });
  return code;
}

module.exports = { isExercised: isExercised, validate: validate };

if (require.main === module) {
  process.exit(report(validate()));
}
