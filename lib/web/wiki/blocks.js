// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web.wiki.blocks
 * @nav    Reference wiki
 * @title  Documentation block reader
 * @order  20
 *
 * @intro
 *   Reads the documentation comment blocks in this project's own `lib/`
 *   sources and returns one record for each primitive block and one for
 *   each module block. The reference wiki renders every page from these
 *   records, and the documentation gates under `scripts/` read the same
 *   records through `scripts/source-primitives.js`.
 *
 *   The walk covers every `.js` file under `lib/` at any depth, in name
 *   order, and skips `lib/vendor/` and any `node_modules` directory.
 *
 *   A block opens with a slash and two asterisks and closes at the first
 *   asterisk and slash after the opener. Each line loses its leading
 *   asterisk decoration before it is read. A tag line is a line whose
 *   trimmed text is an at sign, a tag name, and optionally whitespace and
 *   a value. A single line tag takes its value from its own line, and the
 *   first occurrence carrying a value is the one a record reports.
 *
 *   The multi line tags are `intro`, `card`, `opts`, `example` and
 *   `section`. Each one takes every following line up to the next tag
 *   line or the end of the block, with the shared indentation removed.
 *   The lines no multi line tag takes are the description.
 *
 *   Every function here reads the tree under one root. `at(root)` returns
 *   the same functions bound to a different root, which is how a test
 *   reads a fixture tree.
 */

var fs   = require("node:fs");
var path = require("node:path");

// The comment delimiters, each spelled in two halves.
var BLOCK_OPEN  = "/" + "**";
var BLOCK_CLOSE = "*" + "/";

// Tags whose value is every line up to the next tag line.
var MULTI_LINE_TAGS = Object.freeze(["intro", "card", "opts", "example", "section"]);

// One tag line, read from a trimmed line. A line that does not match fails
// in linear time.
var TAG_LINE_RE = /^@([A-Za-z][A-Za-z0-9]*)(?:\s+(\S.*))?$/;

// The decoration in front of each line of a block.
var DECORATION_RE = /^\s*\*\s?/;

// The separators between several values on one tag line, as `related`
// writes them.
var VALUE_SEPARATOR_RE = /[,\s]+/;

// Every block in a source, with the 1-based line its opener sits on and
// the offset just past its closer. The scan stops at the first opener with
// no closer after it.
function _blocks(src) {
  var out = [];
  var from = 0;
  var line = 1;
  var counted = 0;
  for (;;) {
    var open = src.indexOf(BLOCK_OPEN, from);
    if (open === -1) break;
    var close = src.indexOf(BLOCK_CLOSE, open + BLOCK_OPEN.length);
    if (close === -1) break;
    line += _newlines(src, counted, open);
    counted = open;
    from = close + BLOCK_CLOSE.length;
    out.push({ text: src.slice(open, from), line: line, end: from });
  }
  return out;
}

function _newlines(src, from, to) {
  var n = 0;
  for (var i = src.indexOf("\n", from); i !== -1 && i < to; i = src.indexOf("\n", i + 1)) {
    n += 1;
  }
  return n;
}

// The block's lines with the delimiters and the decoration removed.
function _lines(blockText) {
  return blockText
    .slice(BLOCK_OPEN.length, blockText.length - BLOCK_CLOSE.length)
    .split(/\r?\n/)
    .map(function (l) { return l.replace(DECORATION_RE, "").trimEnd(); });
}

// A multi line body: blank lines at either end removed, and the smallest
// indentation shared by the remaining lines taken off every line.
function _body(lines) {
  var start = 0;
  var end = lines.length;
  while (start < end && lines[start].trim() === "") start += 1;
  while (end > start && lines[end - 1].trim() === "") end -= 1;
  var kept = lines.slice(start, end);
  var indent = Infinity;
  kept.forEach(function (l) {
    if (l.trim() === "") return;
    var lead = l.length - l.trimStart().length;
    if (lead < indent) indent = lead;
  });
  if (indent === Infinity) indent = 0;
  return kept.map(function (l) { return l.trim() === "" ? "" : l.slice(indent); }).join("\n");
}

// The length in characters of every line that is neither empty nor opens
// with an at sign, joined by single spaces. The comment block gate measures
// a primitive's description with this number.
function _proseLength(lines) {
  return lines
    .filter(function (l) { return l.trim().length > 0 && l.trim().charAt(0) !== "@"; })
    .join(" ")
    .trim()
    .length;
}

// One pass over a block. `first` holds the first value each tag carried,
// `every` holds all of them in order, `bodies` holds each multi line tag's
// bodies in order, and `description` is the text no multi line tag took.
function _parse(blockText) {
  var lines = _lines(blockText);
  var first = Object.create(null);
  var every = Object.create(null);
  var bodies = Object.create(null);
  var description = [];
  var open = null;

  function _closeBody() {
    if (open === null) return;
    if (bodies[open.tag] === undefined) bodies[open.tag] = [];
    bodies[open.tag].push(_body(open.lines));
    open = null;
  }

  lines.forEach(function (line) {
    var m = TAG_LINE_RE.exec(line.trim());
    if (m === null) {
      if (open === null) description.push(line);
      else open.lines.push(line);
      return;
    }
    _closeBody();
    var name = m[1];
    var value = m[2] === undefined ? null : m[2];
    if (value !== null) {
      if (first[name] === undefined) first[name] = value;
      if (every[name] === undefined) every[name] = [];
      every[name].push(value);
    }
    if (MULTI_LINE_TAGS.indexOf(name) !== -1) {
      open = { tag: name, lines: value === null ? [] : [value] };
    }
  });
  _closeBody();

  return {
    lines:       lines,
    first:       first,
    every:       every,
    bodies:      bodies,
    description: _body(description),
  };
}

function _value(map, name) {
  return map[name] === undefined ? null : map[name];
}

function _joined(bodies, name) {
  return bodies[name] === undefined ? null : bodies[name].join("\n\n");
}

function _separated(values) {
  var out = [];
  (values || []).forEach(function (value) {
    value.split(VALUE_SEPARATOR_RE).forEach(function (tok) {
      if (tok.length > 0) out.push(tok);
    });
  });
  return out;
}

/**
 * @primitive blamepost.web.wiki.blocks.tagMap
 * @signature blocks.tagMap(primitives, tag)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: token to tag value projection)
 * @related   blamepost.web.wiki.blocks.collectPrimitives
 *
 * Returns an object mapping the token of each primitive record to the
 * record's value for `tag`. A record whose value for `tag` is null, an
 * empty string, zero or absent is left out.
 *
 * @example
 *   blocks.tagMap(blocks.collectPrimitives(), "since");
 */
function tagMap(primitives, tag) {
  var out = {};
  primitives.forEach(function (p) {
    if (p[tag]) out[p.token] = p[tag];
  });
  return out;
}

/**
 * @primitive blamepost.web.wiki.blocks.at
 * @signature blocks.at(root)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one reader bound to one tree)
 * @related   blamepost.web.wiki.blocks.collect, blamepost.web.wiki.blocks.libSources
 *
 * Returns the reader bound to the tree under `root`, as a frozen object
 * holding `ROOT`, `LIB_DIR`, `MULTI_LINE_TAGS`, `at`, `libSources`,
 * `relative`, `collect`, `collectPrimitives`, `collectModules` and
 * `tagMap`. `LIB_DIR` is `root` joined with `lib`. The module exports the
 * reader bound to this server's own tree.
 *
 * Throws a TypeError when `root` is not an absolute path.
 *
 * @example
 *   var fixture = blocks.at("/tmp/fixture");
 *   fixture.collect().modules.length;
 */
function at(root) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new TypeError("blamepost.web.wiki.blocks.at: root must be an absolute directory path");
  }
  var ROOT = root;
  var LIB_DIR = path.join(root, "lib");

  /**
   * @primitive blamepost.web.wiki.blocks.libSources
   * @signature blocks.libSources(libDir?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one walk over the sources in name order)
   * @related   blamepost.web.wiki.blocks.collect
   *
   * Returns every `.js` file under `libDir` at any depth, each as
   * `libDir` joined with its path below it. The entries of each directory
   * are read in name order, and directories named `vendor` or
   * `node_modules` are skipped. `libDir` defaults to `LIB_DIR`, and a
   * directory that does not exist yields an empty list.
   *
   * @example
   *   blocks.libSources().length;
   */
  function libSources(libDir) {
    var out = [];
    (function walk(dir) {
      if (!fs.existsSync(dir)) return;
      fs.readdirSync(dir, { withFileTypes: true })
        .sort(function (a, b) { return a.name.localeCompare(b.name); })
        .forEach(function (e) {
          var entry = path.join(dir, e.name);
          if (e.isDirectory()) {
            if (e.name !== "vendor" && e.name !== "node_modules") walk(entry);
          } else if (e.isFile() && /\.js$/.test(e.name)) {
            out.push(entry);
          }
        });
    }(libDir || LIB_DIR));
    return out;
  }

  /**
   * @primitive blamepost.web.wiki.blocks.relative
   * @signature blocks.relative(file)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: repository relative paths with forward slashes)
   * @related   blamepost.web.wiki.blocks.libSources
   *
   * Returns the path of `file` relative to `ROOT`, with every separator
   * written as a forward slash. Every record `collect` returns names its
   * file this way.
   *
   * @example
   *   blocks.relative(blocks.libSources()[0]);   // "lib/..."
   */
  function relative(file) {
    return path.relative(ROOT, file).split(path.sep).join("/");
  }

  /**
   * @primitive blamepost.web.wiki.blocks.collect
   * @signature blocks.collect(files?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: both record lists from one read of each file)
   * @related   blamepost.web.wiki.blocks.collectPrimitives, blamepost.web.wiki.blocks.collectModules
   *
   * Reads each file in `files` once and returns `{ primitives, modules }`:
   * one record for each primitive block and one for each module block, in
   * file order and then block order. `files` defaults to `libSources()`.
   * A block holding both tags yields a record in each list.
   *
   * A primitive record holds `token`, `file`, `line` (the 1-based line of
   * the block opener), `end` (the offset in the file's text just past the
   * block's closing delimiter), `since`, `status`, `spec`, `deprecated`,
   * `originated` and `signature` as written or null, `related` (every
   * related token, flattened across repeated tag lines), `prose` (the
   * description length the comment block gate measures), `description`
   * (dedented), `opts` (dedented, or null) and `examples` (every example
   * body, dedented, in order).
   *
   * A module record holds `token`, `file`, `line`, the `title`, `nav`,
   * `order`, `slug` and `featured` values as written or null, the `intro`,
   * `card` and `opts` bodies or null, and `description`.
   *
   * @example
   *   var records = blocks.collect();
   *   records.primitives.length;
   */
  function collect(files) {
    var primitives = [];
    var modules = [];
    (files || libSources()).forEach(function (file) {
      var src = fs.readFileSync(file, "utf8");
      _blocks(src).forEach(function (block) {
        var parsed = _parse(block.text);
        var f = parsed.first;
        if (f.primitive !== undefined) {
          primitives.push({
            token:       f.primitive,
            file:        relative(file),
            line:        block.line,
            end:         block.end,
            since:       _value(f, "since"),
            status:      _value(f, "status"),
            spec:        _value(f, "spec"),
            deprecated:  _value(f, "deprecated"),
            originated:  _value(f, "originated"),
            related:     _separated(parsed.every.related),
            prose:       _proseLength(parsed.lines),
            signature:   _value(f, "signature"),
            description: parsed.description,
            opts:        _joined(parsed.bodies, "opts"),
            examples:    (parsed.bodies.example || []).slice(),
          });
        }
        if (f.module !== undefined) {
          modules.push({
            token:       f.module,
            file:        relative(file),
            line:        block.line,
            title:       _value(f, "title"),
            nav:         _value(f, "nav"),
            order:       _value(f, "order"),
            slug:        _value(f, "slug"),
            featured:    _value(f, "featured"),
            intro:       _joined(parsed.bodies, "intro"),
            card:        _joined(parsed.bodies, "card"),
            opts:        _joined(parsed.bodies, "opts"),
            description: parsed.description,
          });
        }
      });
    });
    return { primitives: primitives, modules: modules };
  }

  /**
   * @primitive blamepost.web.wiki.blocks.collectPrimitives
   * @signature blocks.collectPrimitives(files?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the primitive half of one collect)
   * @related   blamepost.web.wiki.blocks.collect, blamepost.web.wiki.blocks.tagMap
   *
   * Returns the primitive records `collect(files)` returns, in the same
   * order.
   *
   * @example
   *   blocks.collectPrimitives()[0].token;
   */
  function collectPrimitives(files) {
    return collect(files).primitives;
  }

  /**
   * @primitive blamepost.web.wiki.blocks.collectModules
   * @signature blocks.collectModules(files?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the module half of one collect)
   * @related   blamepost.web.wiki.blocks.collect
   *
   * Returns the module records `collect(files)` returns, in the same
   * order.
   *
   * @example
   *   blocks.collectModules()[0].token;
   */
  function collectModules(files) {
    return collect(files).modules;
  }

  return Object.freeze({
    ROOT:              ROOT,
    LIB_DIR:           LIB_DIR,
    MULTI_LINE_TAGS:   MULTI_LINE_TAGS,
    at:                at,
    libSources:        libSources,
    relative:          relative,
    collect:           collect,
    collectPrimitives: collectPrimitives,
    collectModules:    collectModules,
    tagMap:            tagMap,
  });
}

module.exports = at(path.resolve(__dirname, "..", "..", ".."));
