// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A link a shipped document makes is a promise the file is beside it, and
 * the guard that keeps that promise can only keep it for the links it
 * recognizes as links.
 *
 * `scripts/check-pack-against-gitignore.js` reads every markdown document
 * the tarball carries and resolves each relative target against the file
 * list `npm pack` actually produces. That is the right question asked the
 * right way round, and the whole of its answer rests on one thing nobody
 * measures: whether the reader saw the link at all.
 *
 * A target the reader walks past is not reported as broken. It is
 * reported as nothing, and the run that walked past it prints the same
 * clean sentence and the same count as a run over a document with no
 * broken links in it. So the failure is silent in the direction that
 * matters, and it grows: every form the reader does not know is a form a
 * document may use freely, because using it costs nothing and is never
 * mentioned.
 *
 * What this file pins is the reader, over the forms a document actually
 * reaches for:
 *
 *   - A destination in angle brackets, which is how a path carries a
 *     space. The plain inline form stops at the first one, so the target
 *     it hands back ends mid-name and resolves to a file nobody wrote.
 *   - An HTML attribute quoted the other way, and quoted not at all. The
 *     README already carries raw `<a href="…">`, so the next one written
 *     with single quotes is native to the file rather than exotic.
 *   - The section a cross-document link names. `./FILE.md#nowhere` is a
 *     promise about a heading, and resolving the file half while throwing
 *     the fragment away answers a question nobody asked: the reader who
 *     follows it lands at the top of a document and hunts.
 *   - The same promise inside one document, `#nowhere`, which is the form
 *     a table of contents is built out of.
 *   - A fence that opens and does not close. The reader skips fenced
 *     lines, and a fence counter that cannot tell one fence character
 *     from the other stops reading at the first mismatch and treats the
 *     entire rest of the document as code. That is the worst shape a
 *     checker has: it goes quiet over the largest documents first,
 *     because they hold the most fences.
 *
 * The forms it must NOT read as links are pinned beside them, because a
 * reader widened until it reports findings nobody can fix is a reader
 * people stop running. Code inside a fence and inside a backticked span
 * stays code, and so does ordinary markup: a closing `</a>` begins with a
 * slash and has the shape of a relative path, and a reader that takes the
 * bait answers a badge row with seven missing files named after HTML
 * elements. That failure is louder than the silent one and costs more,
 * because a gate everybody overrides is a gate nobody has.
 *
 * Run standalone: node test/layer-0-primitives/packed-document-links.test.js
 */

var helpers = require("../helpers");
var guard   = require("../../scripts/check-pack-against-gitignore.js");

var count = helpers.count;

// The targets the reader found in one document, as plain strings, so a
// case reads as the list of promises the document made.
function targetsOf(text) {
  return guard._targetsIn(text).map(function (hit) { return hit.target; });
}

function finds(text, target) {
  return targetsOf(text).indexOf(target) !== -1;
}

// ---- the forms a document reaches for -------------------------------------

// A destination in angle brackets, which is how CommonMark section 6.3
// lets a path carry a space. The plain inline form stops at the first
// space, so without this the target ends mid-name and resolves to a file
// nobody meant.
function testABracketedDestinationMayCarryASpace() {
  var doc = "See [the guide](<./docs/operator guide.md>) for day-2 operations.";
  count("a bracketed destination is read whole, so a path with a space in it is not " +
    "truncated into a file name nobody wrote",
    finds(doc, "./docs/operator guide.md"), JSON.stringify(targetsOf(doc)));

  var def = "[guide]: <./docs/operator guide.md>";
  count("and so is the same shape in a reference definition",
    finds(def, "./docs/operator guide.md"), JSON.stringify(targetsOf(def)));

  count("a bracketed destination with no space is read once rather than twice, so what " +
    "the run says it examined is what it examined",
    targetsOf("[a](<./ROADMAP.md>)").length === 1,
    JSON.stringify(targetsOf("[a](<./ROADMAP.md>)")));
}

// Markup that is not a link, and must not be read as one.
//
// A finding nobody can act on is worse than a missed one: it is confident,
// precise and about nothing, and it teaches people to run the guard with
// their eyes shut. Closing tags are the trap, because `</a>` and `</div>`
// begin with a slash and have the shape of a relative path.
function testOrdinaryMarkupIsNotReadAsALink() {
  var badges = [
    '<p align="center">',
    '  <a href="https://example.com/ci"><img src="https://example.com/b.svg" alt="ci"></a>',
    "  </a>",
    "</div>",
  ].join("\n");
  count("a badge block of closing tags produces no targets, because a closing tag is " +
    "markup rather than a path that happens to start with a slash",
    targetsOf(badges).length === 0, JSON.stringify(targetsOf(badges)));

  count("an absolute URL in angle brackets is left alone, because it names somewhere " +
    "this guard cannot answer for",
    targetsOf("Read <https://example.com/x> please.").length === 0,
    JSON.stringify(targetsOf("Read <https://example.com/x> please.")));

  count("and an ordinary inline tag is not mistaken for a link either",
    targetsOf("Wrap it in <em> to emphasize.").length === 0,
    JSON.stringify(targetsOf("Wrap it in <em> to emphasize.")));
}

// The attribute forms markdown lets through untouched. The README carries
// raw anchor tags already, so the quoting style of the next one is a coin
// flip and both spellings name a file the same way.
function testAnAttributeIsReadWhicheverWayItIsQuoted() {
  count("a single-quoted href is read, because markdown passes the tag through and a " +
    "browser does not care which quote was used",
    finds("<a href='./SECURITY.md'>posture</a>", "./SECURITY.md"),
    JSON.stringify(targetsOf("<a href='./SECURITY.md'>posture</a>")));

  count("and an unquoted one is read as well",
    finds("<a href=./SECURITY.md>posture</a>", "./SECURITY.md"),
    JSON.stringify(targetsOf("<a href=./SECURITY.md>posture</a>")));

  count("a double-quoted href is still read, so widening the reader did not cost the " +
    "form it already handled",
    finds('<img src="./docs/x.png">', "./docs/x.png"),
    JSON.stringify(targetsOf('<img src="./docs/x.png">')));
}

// A fence that opens and does not close. The reader treats fenced lines
// as code, so a counter that cannot tell ``` from ~~~ closes one with the
// other and reads the rest of the document inside out.
function testAFenceOfOneKindDoesNotCloseAFenceOfTheOther() {
  var doc = [
    "~~~",
    "```",
    "~~~",
    "See [the guide](./docs/operator-guide.md).",
  ].join("\n");
  count("a fence written with one character is not closed by the other, so a link below " +
    "a code sample is still read rather than the rest of the document going unchecked",
    finds(doc, "./docs/operator-guide.md"), JSON.stringify(targetsOf(doc)));

  var fenced = [
    "```",
    "See [the guide](./docs/gone.md).",
    "```",
  ].join("\n");
  count("and a link inside a fence is still left alone, because it is a code sample " +
    "rather than a promise",
    targetsOf(fenced).length === 0, JSON.stringify(targetsOf(fenced)));

  count("a backticked span is still left alone for the same reason",
    targetsOf("Write `[a](./gone.md)` to link.").length === 0,
    JSON.stringify(targetsOf("Write `[a](./gone.md)` to link.")));
}

// ---- the section half of a link -------------------------------------------

// A fragment is a promise about a heading, and it is the half a reader
// notices: the file opens and the place they were sent to is not in it.
function testAFragmentNamesASectionThatHasToExist() {
  var doc = "## The PR loop\n\nSee [above](#the-pr-loop) and [nowhere](#not-a-heading).\n";
  var anchors = guard._anchorsIn(doc);

  count("the headings of a document are read into the anchors a link may name",
    anchors.indexOf("the-pr-loop") !== -1, JSON.stringify(anchors));

  count("a fragment is carried out of the reader rather than discarded, so the section " +
    "half of a link is answerable for at all",
    targetsOf(doc).indexOf("#not-a-heading") !== -1, JSON.stringify(targetsOf(doc)));

  count("a heading written with trailing punctuation still yields the anchor a reader " +
    "would follow",
    guard._anchorsIn("### What changed?\n").indexOf("what-changed") !== -1,
    JSON.stringify(guard._anchorsIn("### What changed?\n")));

  count("and a heading carrying inline code and a link yields the anchor those render as",
    guard._anchorsIn("## The `--dry-run` flag\n").indexOf("the---dry-run-flag") !== -1,
    JSON.stringify(guard._anchorsIn("## The `--dry-run` flag\n")));

  count("two headings that slug the same way get the numbered anchor the renderer gives " +
    "the second one, so a link to it is not reported as broken",
    guard._anchorsIn("## Setup\n## Setup\n").indexOf("setup-1") !== -1,
    JSON.stringify(guard._anchorsIn("## Setup\n## Setup\n")));

  count("a heading inside a fence is not an anchor, because it is a code sample",
    guard._anchorsIn("```\n## Not A Heading\n```\n").length === 0,
    JSON.stringify(guard._anchorsIn("```\n## Not A Heading\n```\n")));

  count("an explicit anchor tag in a document is one a link may name, since that is how " +
    "a section without a heading is reached",
    guard._anchorsIn('<a id="vendoring"></a>\n').indexOf("vendoring") !== -1,
    JSON.stringify(guard._anchorsIn('<a id="vendoring"></a>\n')));
}

// ---- the shipped documents ------------------------------------------------

// The reader widened above has to leave this repository's own documents
// passing. A checker that reports findings nobody can fix is one people
// learn to skip, and this is the only case that answers for the real
// tree rather than for a sentence written to probe one rule.
function testTheShippedDocumentsStillPass() {
  var docs = guard._packedMarkdown();
  count("the packed document list resolves, so what follows answers for the tarball " +
    "rather than for an empty set",
    docs.length > 0, docs.length + " document(s)");

  var broken = guard._brokenLinks(docs);
  count("every link and every section this repository's shipped documents name resolves " +
    "inside the tarball, under the widened reader as well as the old one",
    broken.length === 0, broken.slice(0, 6).join(" | ") || "none");
}

// ---- runner ---------------------------------------------------------------

async function run() {
  testABracketedDestinationMayCarryASpace();
  testOrdinaryMarkupIsNotReadAsALink();
  testAnAttributeIsReadWhicheverWayItIsQuoted();
  testAFenceOfOneKindDoesNotCloseAFenceOfTheOther();
  testAFragmentNamesASectionThatHasToExist();
  testTheShippedDocumentsStillPass();
  return helpers.getChecks();
}

module.exports = {
  name:      "packed-document-links",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
