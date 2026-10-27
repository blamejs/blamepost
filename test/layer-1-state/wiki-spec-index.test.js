// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wiki-spec-index: the specification index lists every cited document and
 * section with the primitives citing it.
 *
 * The citation reader is driven with the spellings the blocks in lib/
 * actually use: `section 3.4` beside `§3.4`, a section continuing the
 * document before it, a gloss in parentheses that itself holds a comma,
 * `FRCP 26 / 37(e)`, `GDPR Article 17 and Article 17(3)(e)`, a versioned
 * provider API, and `internal (design: ...)`. Distinct sections of one
 * document stay distinct entries.
 *
 * On the real tree, two known citations are checked against an
 * independent reading of the raw `@spec` text: the index row and the
 * document page list exactly the primitives whose blocks cite them. Every
 * primitive appears either under a citation or in the list of primitives
 * citing no external document, and never in both.
 *
 * Slugs are driven directly: a section sign, a run of punctuation, hyphens
 * at either end, and text with no letters or digits.
 *
 * Primitives driven: `blamepost.web.wiki.specs.parse`,
 * `blamepost.web.wiki.specs.index`, `blamepost.web.wiki.specs.slug` and
 * `blamepost.web.wiki.specs.naturalCompare`.
 *
 * Run standalone: node test/layer-1-state/wiki-spec-index.test.js
 */

var helpers = require("../helpers");
var count   = helpers.count;

var blocks = require("../../lib/web/wiki/blocks.js");
var specs  = require("../../lib/web/wiki/specs.js");
var wiki   = require("../../lib/web/wiki");

function _labels(value) {
  return specs.parse(value).citations.map(function (c) { return c.label; });
}

function _text(spans) {
  return spans.map(function (s) { return s.text; }).join("");
}

function _section(page, heading) {
  for (var i = 0; i < page.sections.length; i += 1) {
    if (page.sections[i].heading === heading) return page.sections[i];
  }
  return null;
}

// ---- citation reading --------------------------------------------------------

function citationsNormalizeWithoutMergingSections() {
  var spellings = ["RFC 5322 section 3.4", "RFC 5322 §3.4", "RFC 5322 § 3.4", "RFC 5322 Section 3.4"];
  var parsed = spellings.map(function (s) { return specs.parse(s).citations[0]; });
  count("every spelling of one section is one citation with one label and one anchor",
    parsed.every(function (c) {
      return c.label === "RFC 5322 §3.4" && c.anchor === "section-3-4" && c.documentSlug === "rfc-5322";
    }), JSON.stringify(parsed));

  count("two sections of one document are two citations",
    JSON.stringify(_labels("RFC 5322 §3.4, RFC 5322 §3.6.2")) ===
    JSON.stringify(["RFC 5322 §3.4", "RFC 5322 §3.6.2"]),
    JSON.stringify(_labels("RFC 5322 §3.4, RFC 5322 §3.6.2")));
  count("a section is not merged into the section it begins with",
    specs.parse("RFC 6376 §3.6").citations[0].anchor !== specs.parse("RFC 6376 §3.6.1").citations[0].anchor,
    "section-3-6 vs section-3-6-1");
  count("a document cited whole is a separate entry from its sections",
    specs.parse("RFC 5322").citations[0].section === null &&
    specs.parse("RFC 5322").citations[0].anchor === "document",
    JSON.stringify(specs.parse("RFC 5322")));

  var continued = specs.parse("RFC 8446 §4.2.7 (supported groups), §9.1 (mandatory to implement)");
  count("a section with no document belongs to the document before it, and each keeps its gloss",
    JSON.stringify(continued.citations.map(function (c) { return [c.label, c.gloss]; })) ===
    JSON.stringify([["RFC 8446 §4.2.7", "supported groups"], ["RFC 8446 §9.1", "mandatory to implement"]]),
    JSON.stringify(continued.citations));

  var glossComma = specs.parse("RFC 8301 §3.2 (RSA key size: 1024 bits required, 2048 recommended)");
  count("a comma inside a gloss does not split the citation",
    glossComma.citations.length === 1 &&
    glossComma.citations[0].gloss === "RSA key size: 1024 bits required, 2048 recommended",
    JSON.stringify(glossComma.citations));

  count("FRCP 26 / 37(e) is two rules of one document",
    JSON.stringify(_labels("FRCP 26 / 37(e)")) === JSON.stringify(["FRCP 26", "FRCP 37(e)"]),
    JSON.stringify(_labels("FRCP 26 / 37(e)")));
  count("an article continuing after `and` belongs to the same regulation",
    JSON.stringify(_labels("GDPR Article 17 and Article 17(3)(e)")) ===
    JSON.stringify(["GDPR Article 17", "GDPR Article 17(3)(e)"]),
    JSON.stringify(_labels("GDPR Article 17 and Article 17(3)(e)")));
  count("attached parentheses stay part of a section rather than becoming a gloss",
    specs.parse("HIPAA 164.530(j)(2)").citations[0].section === "164.530(j)(2)" &&
    specs.parse("HIPAA 164.530(j)(2)").citations[0].gloss === null,
    JSON.stringify(specs.parse("HIPAA 164.530(j)(2)")));
  count("a rule named after its issuer keeps the rule as its section",
    specs.parse("SEC Rule 17a-4").citations[0].label === "SEC Rule 17a-4",
    JSON.stringify(specs.parse("SEC Rule 17a-4")));

  var api = specs.parse("RFC 1035 section 3.2 for the record types, provider API v4 for the paging");
  count("trailing words after a section are a gloss, and a versioned API is one document",
    JSON.stringify(api.citations.map(function (c) { return [c.label, c.gloss]; })) ===
    JSON.stringify([["RFC 1035 §3.2", "for the record types"], ["provider API v4", "for the paging"]]),
    JSON.stringify(api.citations));
  count("an identifier after an API version is a section of it",
    specs.parse("provider API v4 dns_records").citations[0].label === "provider API v4 dns_records",
    JSON.stringify(specs.parse("provider API v4 dns_records")));

  var mixed = specs.parse("RFC 6154 (special use roles), internal (design: one folder namespace, held here)");
  count("an internal design note cites no document and keeps its text whole",
    mixed.citations.length === 1 && mixed.citations[0].label === "RFC 6154" &&
    JSON.stringify(mixed.notes) === JSON.stringify(["one folder namespace, held here"]),
    JSON.stringify(mixed));
  var internal = specs.parse("internal (secrets never reach a log or a support bundle)");
  count("an internal note without `design:` is still a note",
    internal.citations.length === 0 &&
    internal.notes[0] === "secrets never reach a log or a support bundle", JSON.stringify(internal));

  count("sections sort in natural order", specs.naturalCompare("§3.9", "§3.10") < 0,
    String(specs.naturalCompare("§3.9", "§3.10")));
}

function slugsAreLowercaseRunsJoinedBySingleHyphens() {
  count("a section sign reads as the word section in a slug",
    specs.slug("RFC 5322 §3.4") === "rfc-5322-section-3-4", specs.slug("RFC 5322 §3.4"));
  count("a run of other characters becomes one hyphen, and hyphens at either end are removed",
    specs.slug("  (GDPR) -- Article 17(3)(e)  ") === "gdpr-article-17-3-e",
    specs.slug("  (GDPR) -- Article 17(3)(e)  "));
  count("text with no letters or digits slugs to the empty string",
    specs.slug(" -- () ") === "", JSON.stringify(specs.slug(" -- () ")));
  var cited = specs.parse("RFC 8461 section 3.2").citations[0];
  count("a citation's document slug and anchor are the slugs of its document and section",
    cited.documentSlug === specs.slug(cited.document) && cited.anchor === specs.slug(cited.section),
    JSON.stringify(cited));
}

function theIndexGroupsEntriesByDocumentAndSection() {
  var index = specs.index([
    { token: "blamepost.t.a", spec: "RFC 5322 §3.10, GDPR Article 17" },
    { token: "blamepost.t.b", spec: "RFC 5322 section 3.9 (first), RFC 5322 §3.9 (second)" },
    { token: "blamepost.t.c", spec: "RFC 5322, RFC 1035 §3.2" },
    { token: "blamepost.t.d", spec: "internal (design: nothing external)" },
  ]);
  count("documents are ordered with RFCs first by number, then by name",
    JSON.stringify(index.documents.map(function (d) { return d.name; })) ===
    JSON.stringify(["RFC 1035", "RFC 5322", "GDPR"]),
    JSON.stringify(index.documents.map(function (d) { return d.name; })));
  var rfc5322 = index.documents[1];
  count("the whole document comes first, then sections in natural order",
    JSON.stringify(rfc5322.sections.map(function (s) { return s.label; })) ===
    JSON.stringify(["RFC 5322", "RFC 5322 §3.9", "RFC 5322 §3.10"]),
    JSON.stringify(rfc5322.sections.map(function (s) { return s.label; })));
  var nine = rfc5322.sections[1];
  count("one primitive citing one section twice is one entry carrying both glosses",
    nine.entries.length === 1 && nine.entries[0].gloss === "first; second", JSON.stringify(nine.entries));
  count("a primitive citing no document is listed with its note",
    index.unspecified.length === 1 && index.unspecified[0].token === "blamepost.t.d" &&
    index.unspecified[0].notes[0] === "nothing external", JSON.stringify(index.unspecified));
  count("the counts are documents and distinct document sections",
    index.documentCount === 3 && index.citationCount === 5,
    index.documentCount + " documents, " + index.citationCount + " citations");
}

// ---- the real tree -----------------------------------------------------------

// Primitives whose raw @spec text names the citation, read with a pattern
// written for this test rather than through the citation reader.
function _citing(records, pattern) {
  return records.filter(function (p) { return typeof p.spec === "string" && pattern.test(p.spec); })
    .map(function (p) { return p.token; }).sort();
}

function _knownCitation(site, records, label, pattern, docSlug, anchor) {
  var expected = _citing(records, pattern);
  count("the real tree carries the citation " + label, expected.length > 0, expected.join(", "));

  var specIndex = site.page("/wiki/specs");
  var rows = _section(specIndex, "Citations").blocks[0].rows;
  var row = rows.filter(function (r) { return _text(r.cells[0]) === label; })[0];
  count("the specification index has a row for " + label, row !== undefined,
    rows.length + " rows");
  if (row === undefined) return;

  var listed = row.cells[1].filter(function (s) { return s.code; })
    .map(function (s) { return s.text; }).sort();
  count("the " + label + " row lists exactly the primitives whose blocks cite it",
    JSON.stringify(listed) === JSON.stringify(expected),
    "listed " + JSON.stringify(listed) + " expected " + JSON.stringify(expected));
  count("the " + label + " row links to its section on the document page",
    row.cells[0][0].wikiHref === "wiki/specs/" + docSlug + "#" + anchor, row.cells[0][0].wikiHref);
  count("each primitive in the " + label + " row links to its page",
    row.cells[1].filter(function (s) { return s.code; }).every(function (s) {
      var target = site.page("/" + s.wikiHref);
      return target !== null && target.subject.token === s.text;
    }), "links");

  var docPage = site.page("/wiki/specs/" + docSlug);
  var sec = docPage === null ? null : docPage.sections.filter(function (s) { return s.id === anchor; })[0];
  count("the document page has a section for " + label, sec !== undefined && sec !== null,
    docPage ? docPage.sections.map(function (s) { return s.id; }).join(", ") : "no page");
  if (!sec) return;
  var onPage = sec.blocks[0].rows.map(function (r) { return _text(r.cells[0]); }).sort();
  count("the document page section lists the same primitives",
    JSON.stringify(onPage) === JSON.stringify(expected), JSON.stringify(onPage));
}

function theRealIndexListsKnownCitations() {
  var records = blocks.collectPrimitives();
  var site = wiki.build();

  _knownCitation(site, records, "RFC 5322 §3.4", /RFC 5322 (?:§ ?|section )3\.4(?![.\d])/,
    "rfc-5322", "section-3-4");
  _knownCitation(site, records, "GDPR Article 17(3)(e)", /GDPR Article 17\(3\)\(e\)|and Article 17\(3\)\(e\)/,
    "gdpr", "article-17-3-e");

  var specIndex = site.page("/wiki/specs");
  var cited = {};
  _section(specIndex, "Citations").blocks[0].rows.forEach(function (r) {
    r.cells[1].forEach(function (s) { if (s.code) cited[s.text] = true; });
  });
  var unspecified = {};
  var noneSection = _section(specIndex, "No external specification");
  if (noneSection !== null) {
    noneSection.blocks[0].rows.forEach(function (r) { unspecified[_text(r.cells[0])] = true; });
  }
  var neither = records.filter(function (p) { return !cited[p.token] && !unspecified[p.token]; })
    .map(function (p) { return p.token; });
  var both = records.filter(function (p) { return cited[p.token] && unspecified[p.token]; })
    .map(function (p) { return p.token; });
  count("every primitive is listed under a citation or under no external specification",
    neither.length === 0, neither.join(", ") || "all listed");
  count("no primitive is listed in both places", both.length === 0, both.join(", ") || "none");
  count("the index answers for a real set of citations",
    site.counts.documents > 0 && site.counts.citations >= site.counts.documents,
    site.counts.documents + " documents, " + site.counts.citations + " cited sections");

  var withSpec = records.filter(function (p) { return specs.parse(p.spec).citations.length > 0; })[0];
  var page = site.paths().map(site.page).filter(function (pg) {
    return pg.kind === "primitive" && pg.subject.token === withSpec.token;
  })[0];
  var row = page.sections[0].blocks[0].rows.filter(function (r) { return r.label.indexOf("Specification") === 0; })[0];
  var links = row.spans.filter(function (s) { return s.wikiHref; });
  count("a primitive page links each of its citations to the document page section",
    links.length === specs.parse(withSpec.spec).citations.length && links.every(function (s) {
      var hash = s.wikiHref.indexOf("#");
      var target = site.page("/" + s.wikiHref.slice(0, hash));
      var anchor = s.wikiHref.slice(hash + 1);
      return target !== null && target.sections.some(function (sec) { return sec.id === anchor; });
    }), JSON.stringify(links));
}

// ---- runner ------------------------------------------------------------------

async function run() {
  citationsNormalizeWithoutMergingSections();
  slugsAreLowercaseRunsJoinedBySingleHyphens();
  theIndexGroupsEntriesByDocumentAndSection();
  theRealIndexListsKnownCitations();
  return helpers.getChecks();
}

module.exports = { name: "wiki-spec-index", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
