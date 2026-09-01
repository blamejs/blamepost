#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Pre-push static gate. It exercises the CHANGELOG section extract that
 * the release workflow runs to pull the current version's notes into the
 * published GitHub Release and npm release notes.
 *
 * The `### vX.Y.Z — YYYY-MM-DD` shape quoted below is the header
 * scripts/generate-changelog-entry.js emits for one release, nested
 * under the `## vX.Y.x` heading for its minor line. Its dash is part of
 * that emitted format, not prose punctuation, so it stays exactly as
 * written wherever this file names or matches the shape. Changing it
 * here would make the gate reject every entry the generator has ever
 * produced.
 *
 * A release block ends where the next one begins: at the next `### v`
 * header, or at the `## vX.Y.x` heading that opens the next minor line.
 * Getting that boundary wrong is how an extract quietly publishes two
 * releases' notes under one version's tag.
 *
 * Running it locally before tag-push means CHANGELOG format drift (a new
 * entry that doesn't match the canonical header) fails at the desk
 * instead of mid-workflow.
 *
 * The block this extracts BECOMES the published release body, so the
 * question is not only whether a block was found but whether anything is
 * in it. A header with nothing under it extracts as one line, matches the
 * canonical shape, and publishes a release page that is a title and
 * nothing else. Both numbers are published for that reason: the block, and
 * the body inside it. They fail independently, and the second is the one a
 * reader of the release actually gets.
 *
 * Exit codes:
 *   0  extract produced a header AND a body under it, and the header
 *      matches the canonical `### vX.Y.Z — YYYY-MM-DD` shape
 *   1  no entry found, the header shape is malformed, or the entry has no
 *      body under its header
 *
 * Usage:
 *   node scripts/check-changelog-extract.js          # uses package.json version
 *   node scripts/check-changelog-extract.js 0.1.0    # explicit version
 */

var fs   = require("node:fs");
var path = require("node:path");

var examinedCounts = require("./examined-counts.js");

var ROOT         = path.resolve(__dirname, "..");
var CHANGELOG    = path.join(ROOT, "CHANGELOG.md");
var PACKAGE_JSON = path.join(ROOT, "package.json");

function readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8"));
  return pkg.version;
}

// Pull the block from the `### v<version> — <date>` header up to (but
// not including) the next release header or the next minor-line heading.
function extractSection(text, version) {
  var lines = text.split(/\r?\n/);
  var out = [];
  var capturing = false;
  var releaseRe = /^### v(\d+\.\d+\.\d+)\b/;
  var minorRe   = /^## v\d+\.\d+\.x\b/;
  for (var i = 0; i < lines.length; i += 1) {
    var ln = lines[i];
    var m = ln.match(releaseRe);
    if (m) {
      if (capturing) break;              // the next release header ends the block
      if (m[1] === version) {
        capturing = true;
        out.push(ln);
        continue;
      }
    }
    if (capturing && minorRe.test(ln)) break;   // the next minor line ends it too
    if (capturing) out.push(ln);
  }
  // Trim trailing blank lines so the "section length" reflects real content.
  while (out.length > 0 && out[out.length - 1].trim() === "") out.pop();
  return out;
}

function main() {
  var version = process.argv[2] || readPackageVersion();
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error("[check-changelog-extract] FAIL: bad version arg: " +
      JSON.stringify(version) + " (expected `MAJOR.MINOR.PATCH`)");
    process.exit(1);
  }

  var text;
  try { text = fs.readFileSync(CHANGELOG, "utf8"); }
  catch (e) {
    console.error("[check-changelog-extract] FAIL: cannot read CHANGELOG.md: " +
      ((e && e.message) || e));
    process.exit(1);
  }

  var section = extractSection(text, version);
  if (section.length === 0) {
    console.error("[check-changelog-extract] FAIL: no CHANGELOG entry found for v" + version);
    console.error("[check-changelog-extract] Expected a header matching `### v" + version +
      " — YYYY-MM-DD`, under the `## v" +
      version.replace(/\.\d+$/, "") + ".x` heading for its minor line.");
    console.error("[check-changelog-extract] The release workflow's notes extract will produce 0 lines and refuse to publish.");
    process.exit(1);
  }

  // The header line must match the canonical shape, which is
  // `### vX.Y.Z — YYYY-MM-DD`. The separator there belongs to the
  // generator's output format. The date lets the workflow stamp the release.
  var header = section[0];
  var canonical = new RegExp(
    "^### v" + version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
    " \\u2014 \\d{4}-\\d{2}-\\d{2}\\s*$"
  );
  if (!canonical.test(header)) {
    console.error("[check-changelog-extract] FAIL: v" + version +
      " header does not match the canonical shape:");
    console.error("[check-changelog-extract]   expected: `### v" + version + " — YYYY-MM-DD`");
    console.error("[check-changelog-extract]   got:       " + JSON.stringify(header));
    process.exit(1);
  }

  // Everything under the header, blank lines dropped. This is the part a
  // reader of the published release sees, and it is the number that has to
  // move for this gate to be answering the question it was written for.
  // The block length alone cannot: an entry that lost its body still
  // extracts one line, still matches the canonical header, and still
  // publishes.
  var body = section.slice(1).filter(function (l) { return l.trim().length > 0; });

  // The verdict is decided before the passing sentence is written. A gate
  // that prints "OK" and then refuses underneath it has said both things,
  // and the first one is what a reader skimming the transcript takes away.
  if (body.length === 0) {
    console.error("[check-changelog-extract] FAIL: the v" + version + " entry is a header with " +
      "nothing under it. The release workflow publishes this block verbatim, so it would " +
      "publish a release page carrying a title and no notes.");
  } else {
    console.log("[check-changelog-extract] OK, v" + version + " entry extracts cleanly (" +
      section.length + " line(s), " + body.length + " of them body); header shape canonical.");
  }

  var code = examinedCounts.publish([
    { unit: "changelog-entry-lines", n: section.length },
    { unit: "entry-body-lines",      n: body.length },
  ], { tag: "[check-changelog-extract]" });

  if (code !== 0) process.exit(1);
}

main();
