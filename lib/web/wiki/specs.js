// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web.wiki.specs
 * @nav    Reference wiki
 * @title  Specification citations
 * @order  30
 *
 * @intro
 *   Reads the `spec` value of a primitive block into citations and design
 *   notes, and builds the specification index the reference wiki renders:
 *   every cited document, each cited section of it, and the primitives
 *   citing each one.
 *
 *   A value is split at commas, semicolons, the word `and` and a slash
 *   with a space on each side. Nothing inside parentheses is split. A
 *   parenthesized phrase at the end of a citation is its gloss, and the
 *   index shows the gloss beside the citation.
 *
 *   `RFC 5322 section 3.4`, `RFC 5322 §3.4` and `RFC 5322 § 3.4` are one
 *   citation, written `RFC 5322 §3.4`. `RFC 5322 §3.4` and
 *   `RFC 5322 §3.6.2` are two sections of one document, and each has its
 *   own entry. A citation that opens with a section (`§9.1`,
 *   `section 9.1`, `Appendix A`, `Article 17(3)(e)`, `Rule 26`) or with a
 *   bare number (`37(e)`) belongs to the document named before it in the
 *   same value.
 *
 *   A document named by a capitalized abbreviation other than RFC (`GDPR`,
 *   `HIPAA`, `FRCP`, `SEC`) takes the rest of the citation as its section.
 *   A named API with a version (`provider API v4`) takes an identifier
 *   after the version as its section, and any other words as a gloss. Any
 *   other citation is a document named by its own text.
 *
 *   A value opening with `internal` cites no external document. Its
 *   parenthesized text, without a leading `design:`, is a design note.
 */

// The four ways a document is named, which decide how a section is read.
var FAMILY_RFC        = "rfc";
var FAMILY_INSTRUMENT = "instrument";
var FAMILY_API        = "api";
var FAMILY_NAMED      = "named";

var RFC_RE          = /^RFC ?(\d{1,5})/;
var SECTION_RE      = /^(?:§ ?|section )(\d{1,4}(?:\.\d{1,4}){0,8})/i;
var APPENDIX_RE     = /^appendix ([A-Z](?:\.\d{1,4}){0,8})/i;
var NUMBERED_RE     = /^(?:Article|Rule|Part|Title) \S/;
var BARE_NUMBER_RE  = /^\d/;
var DOTTED_RE       = /^\d{1,4}(?:\.\d{1,4}){0,8}$/;
var INSTRUMENT_RE   = /^([A-Z][A-Z0-9]{1,15}) (\S.*)$/;
var IDENTIFIER_RE   = /^[A-Za-z0-9_./-]+$/;
var INTERNAL_RE     = /^internal\b/i;
var DESIGN_PREFIX_RE = /^design:\s?/i;
var WHITESPACE_RUN_RE = /\s+/g;
var NOT_SLUG_RE     = /[^a-z0-9]+/g;

var API_MARK = "API v";

function _collapse(text) {
  return String(text).replace(WHITESPACE_RUN_RE, " ").trim();
}

/**
 * @primitive blamepost.web.wiki.specs.slug
 * @signature specs.slug(text)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: page names of lowercase letters and digits joined by single hyphens)
 * @related   blamepost.web.wiki.specs.parse
 *
 * Returns `text` in lowercase with each `§` read as the word section,
 * each run of characters other than lowercase letters and digits replaced
 * by one hyphen, and the hyphens at either end removed. The wiki names a
 * cited document's page and a section's anchor with it.
 *
 * @example
 *   specs.slug("RFC 5322 §3.4");   // "rfc-5322-section-3-4"
 */
function slug(text) {
  var s = String(text).toLowerCase().split("§").join(" section ").replace(NOT_SLUG_RE, "-");
  var start = 0;
  var end = s.length;
  while (start < end && s.charAt(start) === "-") start += 1;
  while (end > start && s.charAt(end - 1) === "-") end -= 1;
  return s.slice(start, end);
}

// The value split at its top level: commas, semicolons, " and " and " / "
// outside parentheses.
function _pieces(value) {
  var out = [];
  var depth = 0;
  var from = 0;
  var i = 0;
  function cut(at, skip) {
    out.push(value.slice(from, at));
    from = at + skip;
    i = from;
  }
  while (i < value.length) {
    var c = value.charAt(i);
    if (c === "(") { depth += 1; i += 1; continue; }
    if (c === ")") { if (depth > 0) depth -= 1; i += 1; continue; }
    if (depth === 0) {
      if (c === "," || c === ";") { cut(i, 1); continue; }
      if (value.startsWith(" and ", i)) { cut(i, 5); continue; }
      if (value.startsWith(" / ", i)) { cut(i, 3); continue; }
    }
    i += 1;
  }
  out.push(value.slice(from));
  return out.map(_collapse).filter(function (p) { return p.length > 0; });
}

// A trailing " (...)" whose parentheses close at the end of the piece,
// separated from what it glosses. Parentheses attached to a section, as in
// `17(3)(e)`, carry no space before them and stay part of the citation.
function _peel(piece) {
  if (piece.charAt(piece.length - 1) !== ")") return { base: piece, gloss: null };
  var depth = 0;
  for (var i = piece.length - 1; i >= 0; i -= 1) {
    var c = piece.charAt(i);
    if (c === ")") depth += 1;
    else if (c === "(") {
      depth -= 1;
      if (depth === 0) {
        if (i > 0 && piece.charAt(i - 1) === " ") {
          return {
            base:  piece.slice(0, i - 1).trim(),
            gloss: _collapse(piece.slice(i + 1, piece.length - 1)),
          };
        }
        return { base: piece, gloss: null };
      }
    }
  }
  return { base: piece, gloss: null };
}

// A section written at the start of `text`, normalized, and what follows it.
function _leadingSection(text) {
  var m = SECTION_RE.exec(text);
  if (m !== null) return { section: "§" + m[1], rest: text.slice(m[0].length).trim() };
  m = APPENDIX_RE.exec(text);
  if (m !== null) return { section: "Appendix " + m[1].toUpperCase(), rest: text.slice(m[0].length).trim() };
  return null;
}

function _glossOf(parts) {
  var kept = parts.filter(function (p) { return typeof p === "string" && p.length > 0; });
  return kept.length === 0 ? null : kept.join("; ");
}

function _citation(document, family, section, gloss) {
  var label = section === null ? document : document + " " + section;
  return {
    document: document,
    documentSlug: slug(document),
    family:   family,
    section:  section,
    anchor:   section === null ? "document" : slug(section),
    label:    label,
    gloss:    gloss,
  };
}

// One piece, read against the citation before it in the same value.
function _cite(piece, previous) {
  var peeled = _peel(piece);
  var base = peeled.base;

  var rfc = RFC_RE.exec(base);
  if (rfc !== null) {
    var document = "RFC " + Number(rfc[1]);
    var after = base.slice(rfc[0].length).trim();
    var lead = _leadingSection(after);
    if (lead !== null) return _citation(document, FAMILY_RFC, lead.section, _glossOf([lead.rest, peeled.gloss]));
    return _citation(document, FAMILY_RFC, null, _glossOf([after, peeled.gloss]));
  }

  if (previous !== null) {
    var continued = _leadingSection(base);
    if (continued !== null) {
      return _citation(previous.document, previous.family, continued.section,
        _glossOf([continued.rest, peeled.gloss]));
    }
    if (NUMBERED_RE.test(base) || BARE_NUMBER_RE.test(base)) {
      var section = previous.family === FAMILY_RFC && DOTTED_RE.test(base) ? "§" + base : base;
      return _citation(previous.document, previous.family, section, peeled.gloss);
    }
  }

  var apiAt = base.indexOf(API_MARK);
  if (apiAt !== -1 && (apiAt === 0 || base.charAt(apiAt - 1) === " ")) {
    var end = apiAt + API_MARK.length;
    while (end < base.length && base.charAt(end) >= "0" && base.charAt(end) <= "9") end += 1;
    if (end > apiAt + API_MARK.length) {
      var api = base.slice(0, end);
      var tail = base.slice(end).trim();
      if (tail.length > 0 && IDENTIFIER_RE.test(tail)) {
        return _citation(api, FAMILY_API, tail, peeled.gloss);
      }
      return _citation(api, FAMILY_API, null, _glossOf([tail, peeled.gloss]));
    }
  }

  var instrument = INSTRUMENT_RE.exec(base);
  if (instrument !== null) {
    var rest = instrument[2];
    var restLead = _leadingSection(rest);
    if (restLead !== null) {
      return _citation(instrument[1], FAMILY_INSTRUMENT, restLead.section,
        _glossOf([restLead.rest, peeled.gloss]));
    }
    return _citation(instrument[1], FAMILY_INSTRUMENT, rest, peeled.gloss);
  }

  return _citation(base, FAMILY_NAMED, null, peeled.gloss);
}

// A design note from an `internal` piece: its parenthesized text without a
// leading `design:`, or what follows the word when there are no
// parentheses.
function _note(piece) {
  var rest = piece.replace(INTERNAL_RE, "").trim();
  var peeled = _peel("x " + rest);
  var text = peeled.gloss !== null ? peeled.gloss : rest;
  return _collapse(text.replace(DESIGN_PREFIX_RE, ""));
}

/**
 * @primitive blamepost.web.wiki.specs.parse
 * @signature specs.parse(value)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: citation reading)
 * @related   blamepost.web.wiki.specs.index, blamepost.web.wiki.specs.slug
 *
 * Reads one `spec` value into `{ written, citations, notes }`. A value
 * that is not a string is read as the empty string, and `written` holds
 * the string that was read. The module description lists how a value is
 * split and how each piece is read.
 *
 * Each citation holds `document`, `documentSlug`, `family`, `section`
 * (null for the document as a whole), `anchor`, `label` and `gloss`.
 * `family` is one of `rfc`, `instrument`, `api` and `named`. `notes` holds
 * the design notes of the `internal` pieces, in order.
 *
 * @example
 *   specs.parse("RFC 5322 section 3.4").citations[0].label;   // "RFC 5322 §3.4"
 */
function parse(value) {
  var written = typeof value === "string" ? value : "";
  var citations = [];
  var notes = [];
  var previous = null;
  _pieces(written).forEach(function (piece) {
    if (INTERNAL_RE.test(piece)) {
      var note = _note(piece);
      if (note.length > 0) notes.push(note);
      previous = null;
      return;
    }
    var citation = _cite(piece, previous);
    citations.push(citation);
    previous = citation;
  });
  return { written: written, citations: citations, notes: notes };
}

// Digit runs compare as numbers and everything else as text, so §3.10
// sorts after §3.9.
function _naturalParts(text) {
  var parts = [];
  var run = "";
  var digits = false;
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charAt(i);
    var isDigit = c >= "0" && c <= "9";
    if (run.length > 0 && isDigit !== digits) {
      parts.push(digits ? Number(run) : run);
      run = "";
    }
    run += c;
    digits = isDigit;
  }
  if (run.length > 0) parts.push(digits ? Number(run) : run);
  return parts;
}

/**
 * @primitive blamepost.web.wiki.specs.naturalCompare
 * @signature specs.naturalCompare(a, b)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: digit runs compared as numbers)
 * @related   blamepost.web.wiki.specs.index
 *
 * Compares two strings run by run, with each run of digits compared as a
 * number and each other run compared as text, so `§3.10` sorts after
 * `§3.9`. Returns a negative number, zero or a positive number, the
 * contract `Array.prototype.sort` reads.
 *
 * @example
 *   ["§3.10", "§3.9"].sort(specs.naturalCompare);   // ["§3.9", "§3.10"]
 */
function naturalCompare(a, b) {
  var left = _naturalParts(a);
  var right = _naturalParts(b);
  var n = Math.min(left.length, right.length);
  for (var i = 0; i < n; i += 1) {
    if (left[i] === right[i]) continue;
    if (typeof left[i] === "number" && typeof right[i] === "number") return left[i] - right[i];
    return String(left[i]) < String(right[i]) ? -1 : 1;
  }
  return left.length - right.length;
}

function _documentOrder(a, b) {
  var aRfc = a.family === FAMILY_RFC;
  var bRfc = b.family === FAMILY_RFC;
  if (aRfc !== bRfc) return aRfc ? -1 : 1;
  return naturalCompare(a.slug, b.slug);
}

/**
 * @primitive blamepost.web.wiki.specs.index
 * @signature specs.index(primitives)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: every cited document and section with the primitives citing it)
 * @related   blamepost.web.wiki.specs.parse, blamepost.web.wiki.specs.naturalCompare
 *
 * Builds the specification index from records holding `token` and
 * `spec`, and returns `{ documents, unspecified, documentCount,
 * citationCount }`.
 *
 * `documents` lists the RFCs first, then every other document, each group
 * in natural order of its slug. Each document holds `name`, `slug`,
 * `family`, `tokens` (every primitive citing any part of it) and
 * `sections`, with the document as a whole first and then its sections in
 * natural order. Each section holds `section`, `label`, `anchor` and
 * `entries` of `{ token, gloss }`. A primitive citing one section twice is
 * one entry, and its glosses are joined with a semicolon.
 *
 * `unspecified` lists the primitives citing no external document, each
 * with its design notes. `citationCount` counts the sections across every
 * document.
 *
 * @example
 *   specs.index(blocks.collectPrimitives()).documentCount;
 */
function index(primitives) {
  var bySlug = new Map();
  var unspecified = [];

  primitives.forEach(function (p) {
    var parsed = parse(p.spec);
    if (parsed.citations.length === 0) {
      unspecified.push({ token: p.token, notes: parsed.notes });
      return;
    }
    parsed.citations.forEach(function (c) {
      var doc = bySlug.get(c.documentSlug);
      if (doc === undefined) {
        doc = {
          name:     c.document,
          slug:     c.documentSlug,
          family:   c.family,
          tokens:   [],
          sections: new Map(),
        };
        bySlug.set(c.documentSlug, doc);
      }
      if (doc.tokens.indexOf(p.token) === -1) doc.tokens.push(p.token);
      var entry = doc.sections.get(c.anchor);
      if (entry === undefined) {
        entry = { section: c.section, label: c.label, anchor: c.anchor, entries: [] };
        doc.sections.set(c.anchor, entry);
      }
      var existing = null;
      entry.entries.forEach(function (e) { if (e.token === p.token) existing = e; });
      if (existing === null) {
        entry.entries.push({ token: p.token, gloss: c.gloss });
      } else if (c.gloss !== null && existing.gloss !== c.gloss) {
        existing.gloss = existing.gloss === null ? c.gloss : existing.gloss + "; " + c.gloss;
      }
    });
  });

  var citationCount = 0;
  var documents = Array.from(bySlug.values()).map(function (doc) {
    var sections = Array.from(doc.sections.values()).sort(function (a, b) {
      if (a.section === null) return b.section === null ? 0 : -1;
      if (b.section === null) return 1;
      return naturalCompare(a.section, b.section);
    });
    citationCount += sections.length;
    return {
      name:     doc.name,
      slug:     doc.slug,
      family:   doc.family,
      tokens:   doc.tokens,
      sections: sections,
    };
  }).sort(_documentOrder);

  return {
    documents:     documents,
    unspecified:   unspecified,
    documentCount: documents.length,
    citationCount: citationCount,
  };
}

module.exports = {
  FAMILIES:       Object.freeze([FAMILY_RFC, FAMILY_INSTRUMENT, FAMILY_API, FAMILY_NAMED]),
  parse:          parse,
  index:          index,
  slug:           slug,
  naturalCompare: naturalCompare,
};
