// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web.wiki
 * @nav    Reference wiki
 * @title  Reference wiki
 * @order  10
 *
 * @intro
 *   Builds the pages of the reference wiki from the documentation blocks in
 *   `lib/`. Every page is generated: an index, a page for each module
 *   block, a page for each primitive block, a specification index, and a
 *   page for each cited document. A block added to `lib/` gets its page the
 *   next time the wiki is built, with no edit here.
 *
 *   `build(opts)` reads the tree once and returns `page(path)`, `paths()`
 *   and `counts`. `page(path)` returns the page at an exact path, or null.
 *   Every page renders with the view named by `VIEW` and carries every
 *   value that view reads.
 *
 *   ## Paths
 *
 *   - `/wiki` is the index.
 *   - `/wiki/<module-slug>` is a module page.
 *   - `/wiki/<module-slug>/<name>` is a primitive page. The name is the
 *     primitive token without its module token and the dot after it, or the
 *     whole token when the module token is not its prefix.
 *   - `/wiki/specs` is the specification index, and `/wiki/specs/<slug>` is
 *     the page for one cited document.
 *
 *   A primitive belongs to the module block in its own source file. When
 *   its file declares no module, it belongs to the module whose token is
 *   the longest prefix of its own, and when no module token is a prefix, to
 *   a module page named for its namespace.
 *
 *   ## Module tag defaults
 *
 *   A module block without `nav` is listed in the group Other. Without
 *   `title`, it is titled by its module token. Without `order`, or with an
 *   order that is not an integer, it sorts at 100 within its group. Without
 *   `slug`, its slug is the module token without the leading `blamepost.`,
 *   with a hyphen before each capital letter, the letters lowered, and each
 *   dot turned into a hyphen. `featured` set to true, yes or 1 lists the
 *   module under Start here on the index, with its `card` text.
 *
 *   ## Refusals
 *
 *   `build` throws a TypeError naming the source file and line when a slug
 *   is not lowercase letters and digits joined by single hyphens, when a
 *   module slug is `specs`, when a primitive name is not a dotted
 *   identifier, when one file declares two module blocks, and when two
 *   pages would share a path. When the refusal is about one block, the
 *   error also carries that block's file as `file` and its line as `line`.
 *
 *   ## Text
 *
 *   A page holds plain text only. Comment prose is split into paragraphs,
 *   headings, lists and preformatted blocks, and each run of inline code is
 *   its own span, so the view escapes every value and interpolates nothing
 *   raw. Examples and options are code blocks. Every link a page carries is
 *   an absolute path under `/wiki`, and one helper refuses any other value
 *   before it becomes a link. A span's `wikiHref` holds that path without
 *   its leading slash, because the view writes the slash itself.
 */

var pkg    = require("../../../package.json");
var blocks = require("./blocks");
var specs  = require("./specs");
// The one reader for a link target, shared with the browser surface that
// serves these pages. It is what this module composes the framework's
// redirect resolver through. See `_wikiPath` and `_wikiHref` below.
var links  = require("../links");

var BASE_PATH     = "/wiki";
var SPECS_SLUG    = "specs";
var VIEW          = "wiki/page";
var DEFAULT_NAV   = "Other";
var DEFAULT_ORDER = 100;
var NAMESPACE_PREFIX = "blamepost.";

var SLUG_RE          = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
var NAME_RE          = /^[A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*$/;
var INTEGER_RE       = /^-?\d{1,6}$/;
var FEATURED_RE      = /^(?:true|yes|1)$/i;
var HEADING_RE       = /^#{1,6} (\S.*)$/;
var BULLET_RE        = /^[-*] (\S.*)$/;
var NUMBERED_ITEM_RE = /^\d{1,3}\. (\S.*)$/;
var CAPITAL_RE       = /[A-Z]/g;

// The stylesheet's pill variants for each lifecycle status.
var STATUS_PILLS = Object.freeze({
  stable:       "ok",
  experimental: "warn",
  deprecated:   "suspended",
});

// ---------------------------------------------------------------------------
// Link targets
// ---------------------------------------------------------------------------

// Every link a page carries goes through here. Two requirements meet: the
// target sits under this wiki's own base path, which is this module's rule
// and is asked here, and it is an absolute path on this server, which is
// every link surface's rule and is asked by `links.path`. A value failing
// either is refused where it is built.
function _wikiPath(value) {
  if (typeof value !== "string" || value.indexOf(BASE_PATH) !== 0) {
    throw new TypeError("blamepost.web.wiki: a link target must be an absolute path under " +
      BASE_PATH + " on this server. '" + String(value).slice(0, 64) + "' is not one.");
  }
  return links.path(value);
}

function _modulePath(slug) {
  return _wikiPath(BASE_PATH + "/" + slug);
}

function _primitivePath(moduleSlug, name) {
  return _wikiPath(BASE_PATH + "/" + moduleSlug + "/" + name);
}

function _specIndexPath() {
  return _wikiPath(BASE_PATH + "/" + SPECS_SLUG);
}

function _specPath(documentSlug) {
  return _wikiPath(BASE_PATH + "/" + SPECS_SLUG + "/" + documentSlug);
}

// The value the view interpolates into a link, which writes the leading
// slash itself as `href="/{{ s.wikiHref }}"`. The base-path requirement is
// asked first, and `links.href` takes the leading slash off and refuses a
// remainder that would turn the view's own slash into the start of a host
// name. The browser surface interpolates its links through the same
// reader, so neither surface holds a rule the other does not.
function _wikiHref(value) {
  return links.href(_wikiPath(value));
}

// ---------------------------------------------------------------------------
// Spans and blocks
// ---------------------------------------------------------------------------

function _text(text) {
  return { text: String(text), code: false };
}

function _code(text) {
  return { text: String(text), code: true };
}

function _link(text, path) {
  return { text: String(text), code: false, wikiHref: _wikiHref(path) };
}

function _codeLink(text, path) {
  return { text: String(text), code: true, wikiHref: _wikiHref(path) };
}

function _pill(status) {
  var known = typeof status === "string" &&
    Object.prototype.hasOwnProperty.call(STATUS_PILLS, status);
  return {
    text: typeof status === "string" ? status : "undeclared",
    code: false,
    pill: known ? STATUS_PILLS[status] : "warn",
  };
}

// Text split at backticks into plain and code spans. A backtick with no
// partner stays in the text.
function _spans(text) {
  var parts = String(text).split("`");
  if (parts.length % 2 === 0) {
    var tail = parts.pop();
    parts[parts.length - 1] += "`" + tail;
  }
  var out = [];
  parts.forEach(function (part, i) {
    if (part.length === 0) return;
    out.push(i % 2 === 1 ? _code(part) : _text(part));
  });
  return out;
}

function _indent(line) {
  return line.length - line.trimStart().length;
}

function _dedent(lines) {
  var indent = Infinity;
  lines.forEach(function (l) {
    if (l.trim() === "") return;
    if (_indent(l) < indent) indent = _indent(l);
  });
  if (indent === Infinity) indent = 0;
  return lines.map(function (l) { return l.slice(Math.min(indent, _indent(l))); }).join("\n");
}

function _isItem(line) {
  var t = line.trim();
  return BULLET_RE.test(t) || NUMBERED_ITEM_RE.test(t);
}

function _list(lines) {
  var ordered = NUMBERED_ITEM_RE.test(lines[0].trim());
  var items = [];
  lines.forEach(function (line) {
    var t = line.trim();
    var m = ordered ? NUMBERED_ITEM_RE.exec(t) : BULLET_RE.exec(t);
    if (m !== null) items.push([m[1]]);
    else items[items.length - 1].push(t);
  });
  return {
    kind:    "list",
    ordered: ordered,
    items:   items.map(function (parts) { return _spans(parts.join(" ")); }),
  };
}

// One run of non-blank lines. Lines from the first list item on are a
// list. A run whose later lines are indented past its first line keeps its
// layout as preformatted text. Anything else is a paragraph.
function _group(lines) {
  var firstItem = -1;
  for (var i = 0; i < lines.length; i += 1) {
    if (_isItem(lines[i])) { firstItem = i; break; }
  }
  if (firstItem > 0) return _group(lines.slice(0, firstItem)).concat(_group(lines.slice(firstItem)));
  if (firstItem === 0) return [_list(lines)];
  var base = _indent(lines[0]);
  var deeper = lines.slice(1).some(function (l) { return _indent(l) > base; });
  if (deeper) return [{ kind: "pre", text: _dedent(lines) }];
  return [{
    kind:  "paragraph",
    spans: _spans(lines.map(function (l) { return l.trim(); }).join(" ")),
  }];
}

// Comment prose as blocks. Blank lines separate runs, and a line opening
// with one to six number signs and a space is a heading.
function _prose(text) {
  var out = [];
  var run = [];
  function flush() {
    if (run.length > 0) _group(run).forEach(function (blk) { out.push(blk); });
    run = [];
  }
  String(text || "").split("\n").forEach(function (line) {
    var trimmed = line.trim();
    if (trimmed === "") { flush(); return; }
    var heading = HEADING_RE.exec(trimmed);
    if (heading !== null) {
      flush();
      out.push({ kind: "heading", spans: _spans(heading[1]) });
      return;
    }
    run.push(line);
  });
  flush();
  return out;
}

// The first sentence of the first paragraph, ending at a period followed by
// a space or the end, outside inline code.
function _summary(text) {
  var joined = "";
  var lines = String(text || "").split("\n");
  for (var i = 0; i < lines.length; i += 1) {
    var t = lines[i].trim();
    if (t === "" || HEADING_RE.test(t)) {
      if (joined.length > 0) break;
      continue;
    }
    joined += (joined.length > 0 ? " " : "") + t;
  }
  var inCode = false;
  for (var j = 0; j < joined.length; j += 1) {
    var c = joined.charAt(j);
    if (c === "`") inCode = !inCode;
    else if (!inCode && c === "." && (j === joined.length - 1 || joined.charAt(j + 1) === " ")) {
      return joined.slice(0, j + 1);
    }
  }
  return joined;
}

function _plain(text) {
  return String(text).split("`").join("");
}

function _joinSpans(lists, separator) {
  var out = [];
  lists.forEach(function (spans, i) {
    if (i > 0) out.push(_text(separator));
    spans.forEach(function (s) { out.push(s); });
  });
  return out;
}

function _section(heading, id, blocksOfSection) {
  return { heading: heading, id: id, blocks: blocksOfSection };
}

function _facts(rows) {
  return { kind: "facts", rows: rows };
}

function _fact(label, spans) {
  return { label: label, spans: spans };
}

function _table(caption, head, rows) {
  return {
    kind:    "table",
    caption: caption,
    head:    head,
    rows:    rows.map(function (cells) { return { cells: cells }; }),
  };
}

function _deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.keys(value).forEach(function (k) { _deepFreeze(value[k]); });
  return Object.freeze(value);
}

// ---------------------------------------------------------------------------
// Modules and primitives
// ---------------------------------------------------------------------------

function _where(file, line) {
  return file + ":" + line;
}

// A refusal about one block. The message opens with the block's file and
// line, and the error carries both as `file` and `line`.
function _blockRefusal(file, line, text) {
  var err = new TypeError("blamepost.web.wiki: " + _where(file, line) + " " + text);
  err.file = file;
  err.line = line;
  return err;
}

function _kebab(token) {
  var namespace = token.indexOf(NAMESPACE_PREFIX) === 0
    ? token.slice(NAMESPACE_PREFIX.length)
    : token;
  return namespace
    .replace(CAPITAL_RE, function (c) { return "-" + c.toLowerCase(); })
    .split(".")
    .join("-");
}

function _module(rec, synthesized) {
  var slug = rec.slug !== null ? rec.slug : _kebab(rec.token);
  if (!SLUG_RE.test(slug)) {
    throw _blockRefusal(rec.file, rec.line, "gives module " + rec.token + " the slug '" + slug +
      "', which is not lowercase letters and digits joined by single hyphens.");
  }
  if (slug === SPECS_SLUG) {
    throw _blockRefusal(rec.file, rec.line, "gives module " + rec.token + " the slug '" +
      SPECS_SLUG + "', which is the specification index.");
  }
  return {
    token:       rec.token,
    file:        rec.file,
    line:        rec.line,
    synthesized: synthesized,
    title:       rec.title !== null ? rec.title : rec.token,
    nav:         rec.nav !== null ? rec.nav : DEFAULT_NAV,
    order:       rec.order !== null && INTEGER_RE.test(rec.order) ? Number(rec.order) : DEFAULT_ORDER,
    slug:        slug,
    path:        _modulePath(slug),
    featured:    rec.featured !== null && FEATURED_RE.test(rec.featured),
    card:        rec.card,
    intro:       rec.intro,
    opts:        rec.opts,
    description: rec.description,
    primitives:  [],
  };
}

function _namespaceOf(token) {
  var at = token.lastIndexOf(".");
  return at === -1 ? token : token.slice(0, at);
}

function _statusCounts(primitives) {
  var out = { stable: 0, experimental: 0, deprecated: 0, undeclared: 0 };
  primitives.forEach(function (p) {
    if (typeof p.status === "string" && Object.prototype.hasOwnProperty.call(STATUS_PILLS, p.status)) {
      out[p.status] += 1;
    } else {
      out.undeclared += 1;
    }
  });
  return out;
}

function _byOrder(a, c) {
  if (a.order !== c.order) return a.order - c.order;
  var byTitle = specs.naturalCompare(a.title.toLowerCase(), c.title.toLowerCase());
  if (byTitle !== 0) return byTitle;
  return specs.naturalCompare(a.token, c.token);
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

// A page. `crumbs` arrives as one span per ancestor and is stored as one
// span list with a separator between ancestors.
function _page(path, kind, fields) {
  var crumbs = fields.crumbs || [];
  return {
    path:          path,
    view:          VIEW,
    kind:          kind,
    title:         fields.title,
    documentTitle: kind === "index" ? fields.title : fields.title + " | blamepost reference",
    description:   fields.description,
    eyebrow:       fields.eyebrow,
    lead:          fields.lead || [],
    crumbs:        _joinSpans(crumbs.map(function (span) { return [span]; }), " / "),
    sections:      fields.sections,
    subject:       fields.subject || null,
  };
}

function _citationSpans(citations) {
  return _joinSpans(citations.map(function (c) {
    var spans = [_link(c.label, _specPath(c.documentSlug) + "#" + c.anchor)];
    if (c.gloss !== null) spans.push(_text(" (" + c.gloss + ")"));
    return spans;
  }), ", ");
}

function _primitivePage(p, mod, pathByToken) {
  var parsed = specs.parse(p.spec);
  var summary = _summary(p.description);

  var facts = [];
  if (p.signature !== null) facts.push(_fact("Signature", [_code(p.signature)]));
  var status = [_pill(p.status)];
  if (p.status === "deprecated" && p.deprecated !== null) {
    status.push(_text(" and removed by " + p.deprecated));
  }
  facts.push(_fact("Status", status));
  if (p.since !== null) facts.push(_fact("Introduced", [_text(p.since)]));
  if (p.originated !== null) facts.push(_fact("Originated", [_text(p.originated)]));
  if (parsed.citations.length > 0) {
    facts.push(_fact(parsed.citations.length === 1 ? "Specification" : "Specifications",
      _citationSpans(parsed.citations)));
  }
  parsed.notes.forEach(function (note) { facts.push(_fact("Design note", _spans(note))); });
  if (p.spec !== null) facts.push(_fact("Cited as", [_code(p.spec)]));
  facts.push(_fact("Module", [_link(mod.title, mod.path)]));
  facts.push(_fact("Source", [_code(p.file), _text(" line " + p.line)]));

  var sections = [_section(null, null, [_facts(facts)])];
  var description = _prose(p.description);
  if (description.length > 0) sections.push(_section("Description", "description", description));
  if (p.opts !== null) {
    sections.push(_section("Options", "options", [{ kind: "code", text: p.opts }]));
  }
  if (p.examples.length > 0) {
    sections.push(_section(p.examples.length === 1 ? "Example" : "Examples", "examples",
      p.examples.map(function (e) { return { kind: "code", text: e }; })));
  }
  if (p.related.length > 0) {
    sections.push(_section("Related", "related", [{
      kind:    "list",
      ordered: false,
      items:   p.related.map(function (token) {
        return pathByToken.has(token) ? [_codeLink(token, pathByToken.get(token))] : [_code(token)];
      }),
    }]));
  }

  return _page(pathByToken.get(p.token), "primitive", {
    title:       p.token,
    description: summary.length > 0 ? _plain(summary) : p.token,
    eyebrow:     "Primitive",
    lead:        _spans(summary),
    crumbs:      [_link("Reference", BASE_PATH), _link(mod.title, mod.path)],
    sections:    sections,
    subject:     { token: p.token, status: p.status, module: mod.token, file: p.file, line: p.line },
  });
}

function _modulePage(mod, pathByToken) {
  var facts = [
    _fact("Name", [_code(mod.token)]),
    _fact("Group", [_text(mod.nav)]),
    _fact("Source", [_code(mod.file), _text(" line " + mod.line)]),
  ];
  var sections = [_section(null, null, [_facts(facts)])];

  var overview = _prose(mod.intro !== null ? mod.intro : mod.description);
  if (overview.length > 0) sections.push(_section("Overview", "overview", overview));
  if (mod.opts !== null) {
    sections.push(_section("Options", "options", [{ kind: "code", text: mod.opts }]));
  }

  if (mod.primitives.length === 0) {
    sections.push(_section("Primitives", "primitives", [{
      kind: "paragraph", spans: [_text("This module documents no primitives.")],
    }]));
  } else {
    sections.push(_section("Primitives", "primitives", [_table(
      "The primitives " + mod.token + " documents, in source order",
      ["Primitive", "Status", "Summary"],
      mod.primitives.map(function (p) {
        return [
          [_codeLink(p.token, pathByToken.get(p.token))],
          [_pill(p.status)],
          _spans(_summary(p.description)),
        ];
      }))]));
  }

  var lead = mod.card !== null ? _spans(mod.card.split("\n").join(" ")) : [];
  return _page(mod.path, "module", {
    title:       mod.title,
    description: mod.card !== null
      ? _plain(mod.card.split("\n").join(" "))
      : "Reference for " + mod.token + ", generated from its documentation blocks.",
    eyebrow:     "Module",
    lead:        lead,
    crumbs:      [_link("Reference", BASE_PATH), _text(mod.nav)],
    sections:    sections,
    subject:     { token: mod.token, nav: mod.nav, slug: mod.slug, order: mod.order },
  });
}

function _indexPage(groups, counts) {
  var sections = [_section(null, null, [_facts([
    _fact("Version", [_text(pkg.version)]),
    _fact("Modules", [_text(counts.modules)]),
    _fact("Primitives", [_text(counts.primitives)]),
    _fact("Stable", [_text(counts.statuses.stable)]),
    _fact("Experimental", [_text(counts.statuses.experimental)]),
    _fact("Deprecated", [_text(counts.statuses.deprecated)]),
    _fact("Specifications", [_link(counts.documents + " documents and " + counts.citations +
      " cited sections", _specIndexPath())]),
  ])])];

  var featured = [];
  groups.forEach(function (group) {
    group.modules.forEach(function (mod) { if (mod.featured) featured.push(mod); });
  });
  if (featured.length > 0) {
    sections.push(_section("Start here", "start-here", [{
      kind:    "list",
      ordered: false,
      items:   featured.map(function (mod) {
        var item = [_link(mod.title, mod.path)];
        if (mod.card === null) return item;
        return item.concat([_text(": ")], _spans(mod.card.split("\n").join(" ")));
      }),
    }]));
  }

  groups.forEach(function (group) {
    sections.push(_section(group.name, "group-" + specs.slug(group.name), [_table(
      "Modules in " + group.name,
      ["Module", "Name", "Primitives", "Stable", "Experimental"],
      group.modules.map(function (mod) {
        var statuses = _statusCounts(mod.primitives);
        return [
          [_link(mod.title, mod.path)],
          [_code(mod.token)],
          [_text(mod.primitives.length)],
          [_text(statuses.stable)],
          [_text(statuses.experimental)],
        ];
      }))]));
  });

  return _page(BASE_PATH, "index", {
    title:       "blamepost reference",
    description: "Reference for every module and primitive in blamepost " + pkg.version +
      ", generated from the documentation blocks in its source.",
    eyebrow:     "Reference",
    lead:        [_text("Every page here is generated from the documentation blocks in the " +
      "source of blamepost " + pkg.version + ".")],
    sections:    sections,
  });
}

function _specIndexPage(index, pathByToken, counts) {
  var sections = [_section(null, null, [_facts([
    _fact("Documents", [_text(index.documentCount)]),
    _fact("Cited sections", [_text(index.citationCount)]),
    _fact("Primitives citing a specification", [_text(counts.primitives - index.unspecified.length)]),
    _fact("Primitives citing none", [_text(index.unspecified.length)]),
  ])])];

  var rows = [];
  index.documents.forEach(function (doc) {
    doc.sections.forEach(function (entry) {
      rows.push([
        [_link(entry.label, _specPath(doc.slug) + "#" + entry.anchor)],
        _joinSpans(entry.entries.map(function (e) {
          return [_codeLink(e.token, pathByToken.get(e.token))];
        }), ", "),
      ]);
    });
  });
  sections.push(_section("Citations", "citations", [_table(
    "Every cited document and section, with the primitives citing it",
    ["Citation", "Cited by"], rows)]));

  if (index.unspecified.length > 0) {
    sections.push(_section("No external specification", "unspecified", [_table(
      "Primitives that cite no external document, with their design notes",
      ["Primitive", "Design note"],
      index.unspecified.map(function (u) {
        return [
          [_codeLink(u.token, pathByToken.get(u.token))],
          u.notes.length > 0 ? _joinSpans(u.notes.map(_spans), "; ") : [_text("None written")],
        ];
      }))]));
  }

  return _page(_specIndexPath(), "specs", {
    title:       "Specification index",
    description: "Every specification the blamepost source cites, with the primitives citing each one.",
    eyebrow:     "Reference",
    lead:        [_text(index.documentCount + " documents and " + index.citationCount +
      " cited sections.")],
    crumbs:      [_link("Reference", BASE_PATH)],
    sections:    sections,
  });
}

function _specPage(doc, primitiveByToken, moduleByToken, pathByToken) {
  var sections = doc.sections.map(function (entry) {
    return _section(entry.label, entry.anchor, [_table(
      "Primitives citing " + entry.label,
      ["Primitive", "Status", "Module", "Note"],
      entry.entries.map(function (e) {
        var p = primitiveByToken.get(e.token);
        var mod = moduleByToken.get(e.token);
        return [
          [_codeLink(e.token, pathByToken.get(e.token))],
          [_pill(p.status)],
          [_link(mod.title, mod.path)],
          e.gloss !== null ? _spans(e.gloss) : [],
        ];
      }))]);
  });

  return _page(_specPath(doc.slug), "spec", {
    title:       doc.name,
    description: "The blamepost primitives citing " + doc.name + ".",
    eyebrow:     "Specification",
    lead:        [_text("Cited by " + doc.tokens.length + (doc.tokens.length === 1 ? " primitive" : " primitives") +
      " in " + doc.sections.length + (doc.sections.length === 1 ? " entry." : " entries."))],
    crumbs:      [_link("Reference", BASE_PATH), _link("Specification index", _specIndexPath())],
    sections:    sections,
    subject:     { document: doc.name, slug: doc.slug },
  });
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/**
 * @primitive blamepost.web.wiki.build
 * @signature wiki.build(opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: reference pages generated from the documentation blocks in lib)
 * @related   blamepost.web.wiki.build.page, blamepost.web.wiki.build.paths, blamepost.web.wiki.blocks.collect
 *
 * Reads the documentation blocks under `lib/` once and returns the
 * reference wiki as a frozen object holding `page(path)`, `paths()` and
 * `counts`. `counts` holds `modules`, `primitives`, `statuses` (the
 * primitives by `stable`, `experimental`, `deprecated` and `undeclared`),
 * `documents`, `citations` and `unspecified`. Every page and the counts
 * are frozen.
 *
 * A block added to the tree appears in the result of the next call, and
 * not in a result already returned.
 *
 * Throws a TypeError when `opts` is not an object, and for each shape
 * listed under Refusals in the module description, naming the source
 * file and line. A refusal about one block carries that block's file as
 * `file` and its line as `line`.
 *
 * @opts
 *   root: string,   // absolute path of a tree whose lib/ holds the
 *                   // sources; default this server's own tree
 *
 * @example
 *   var reference = wiki.build();
 *   reference.page("/wiki").title;   // "blamepost reference"
 */
function build(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.web.wiki.build: opts must be an object");
  }
  var reader = opts.root === undefined ? blocks : blocks.at(opts.root);
  var records = reader.collect();

  var modules = [];
  var moduleByFile = new Map();
  records.modules.forEach(function (rec) {
    if (moduleByFile.has(rec.file)) {
      throw _blockRefusal(rec.file, rec.line, "declares module " + rec.token + ", and the same " +
        "file already declares module " + moduleByFile.get(rec.file).token +
        ". A file declares one module.");
    }
    var mod = _module(rec, false);
    moduleByFile.set(rec.file, mod);
    modules.push(mod);
  });

  var synthesized = new Map();
  var moduleByToken = new Map();
  var pathByToken = new Map();
  var primitiveByToken = new Map();

  records.primitives.forEach(function (p) {
    var mod = moduleByFile.get(p.file) || null;
    if (mod === null) {
      modules.forEach(function (candidate) {
        if (candidate.synthesized) return;
        if (p.token.indexOf(candidate.token + ".") !== 0) return;
        if (mod === null || candidate.token.length > mod.token.length) mod = candidate;
      });
    }
    if (mod === null) {
      var namespace = _namespaceOf(p.token);
      mod = synthesized.get(namespace) || null;
      if (mod === null) {
        mod = _module({
          token: namespace, file: p.file, line: p.line, title: null, nav: null, order: null,
          slug: null, featured: null, intro: null, card: null, opts: null, description: "",
        }, true);
        synthesized.set(namespace, mod);
        modules.push(mod);
      }
    }

    var name = p.token.indexOf(mod.token + ".") === 0 ? p.token.slice(mod.token.length + 1) : p.token;
    if (!NAME_RE.test(name)) {
      throw _blockRefusal(p.file, p.line, "declares the primitive '" + p.token +
        "', which is not a dotted identifier a page can be addressed by.");
    }
    mod.primitives.push(p);
    if (!pathByToken.has(p.token)) {
      pathByToken.set(p.token, _primitivePath(mod.slug, name));
      moduleByToken.set(p.token, mod);
      primitiveByToken.set(p.token, p);
    }
  });

  var index = specs.index(records.primitives);
  index.documents.forEach(function (doc) {
    if (!SLUG_RE.test(doc.slug)) {
      throw new TypeError("blamepost.web.wiki: the specification '" + doc.name + "', cited by " +
        doc.tokens.join(", ") + ", has no name a page can be addressed by.");
    }
  });

  var statuses = _statusCounts(records.primitives);
  var counts = {
    modules:     modules.length,
    primitives:  records.primitives.length,
    statuses:    statuses,
    documents:   index.documentCount,
    citations:   index.citationCount,
    unspecified: index.unspecified.length,
  };

  var groupsByName = new Map();
  modules.forEach(function (mod) {
    if (!groupsByName.has(mod.nav)) groupsByName.set(mod.nav, { name: mod.nav, modules: [] });
    groupsByName.get(mod.nav).modules.push(mod);
  });
  var groups = Array.from(groupsByName.values()).sort(function (a, c) {
    if (a.name === DEFAULT_NAV) return c.name === DEFAULT_NAV ? 0 : 1;
    if (c.name === DEFAULT_NAV) return -1;
    return specs.naturalCompare(a.name.toLowerCase(), c.name.toLowerCase());
  });
  groups.forEach(function (group) { group.modules.sort(_byOrder); });

  var pages = new Map();
  var sources = new Map();
  // `block` is the `{ file, line }` of the block the page is built from, or
  // null for a page no single block produces.
  function add(page, source, block) {
    if (pages.has(page.path)) {
      var err = new TypeError("blamepost.web.wiki: " + source + " and " + sources.get(page.path) +
        " would both be the page at " + page.path + ".");
      if (block !== null) {
        err.file = block.file;
        err.line = block.line;
      }
      throw err;
    }
    pages.set(page.path, _deepFreeze(page));
    sources.set(page.path, source);
  }

  add(_indexPage(groups, counts), "the index", null);
  add(_specIndexPage(index, pathByToken, counts), "the specification index", null);
  modules.forEach(function (mod) {
    add(_modulePage(mod, pathByToken), "module " + mod.token + " at " + _where(mod.file, mod.line),
      { file: mod.file, line: mod.line });
  });
  records.primitives.forEach(function (p) {
    if (primitiveByToken.get(p.token) !== p) {
      throw _blockRefusal(p.file, p.line, "declares the primitive " + p.token + " a second time.");
    }
    add(_primitivePage(p, moduleByToken.get(p.token), pathByToken),
      "primitive " + p.token + " at " + _where(p.file, p.line), { file: p.file, line: p.line });
  });
  index.documents.forEach(function (doc) {
    add(_specPage(doc, primitiveByToken, moduleByToken, pathByToken), "specification " + doc.name,
      null);
  });

  /**
   * @primitive blamepost.web.wiki.build.page
   * @signature reference.page(path)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one page for each exact path)
   * @related   blamepost.web.wiki.build.paths
   *
   * Returns the page at `path`, or null when `path` is not a string or
   * the wiki has no page at exactly that path. The lookup does not decode
   * the path, trim it, or add or remove a trailing slash.
   *
   * A page holds `path`, `view`, `kind`, `title`, `documentTitle`,
   * `description`, `eyebrow`, `lead`, `crumbs`, `sections` and `subject`.
   * `kind` is one of `index`, `specs`, `module`, `primitive` and `spec`,
   * and `view` names the template every page renders with.
   *
   * @example
   *   reference.page("/wiki/specs").kind;   // "specs"
   */
  function page(path) {
    return typeof path === "string" && pages.has(path) ? pages.get(path) : null;
  }

  /**
   * @primitive blamepost.web.wiki.build.paths
   * @signature reference.paths()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: every page path in build order)
   * @related   blamepost.web.wiki.build.page
   *
   * Returns a new array of every path the wiki has a page at: the index,
   * the specification index, each module page, each primitive page in
   * source order, and each cited document's page.
   *
   * @example
   *   reference.paths()[0];   // "/wiki"
   */
  function paths() {
    return Array.from(pages.keys());
  }

  return Object.freeze({
    counts: _deepFreeze(counts),
    page:   page,
    paths:  paths,
  });
}

module.exports = {
  BASE_PATH:     BASE_PATH,
  VIEW:          VIEW,
  DEFAULT_NAV:   DEFAULT_NAV,
  DEFAULT_ORDER: DEFAULT_ORDER,
  build:         build,
};
