#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/validate-source-comment-blocks is a static gate over the
// `@primitive` and `@module` documentation blocks in lib/, and over the
// reference wiki the server builds from them.
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
//   @signature   present, parseable, and naming the last segment of the
//                block's token. The declaration it is compared against is the
//                code directly beneath the block, with only whitespace and
//                ordinary comments between; a second documentation block
//                there means nothing is beneath it.
//
//                A signature with a parameter list documents a callable. The
//                function beneath must carry the name the signature's path
//                ends in, or be bound under that name in the same file as an
//                object key (`create: createAccount`, `"delete": remove`) or
//                a member assignment (`handle.send = _relaySend`). Its
//                parameter count must equal the function's, where a default,
//                a destructured and a rest parameter count as one each.
//
//                A signature without a parameter list documents a sub-handle
//                or a constant. It has no arity and is not compared, except
//                that a function beneath it bound under the token's name is a
//                callable written without its parameters, and is reported.
//   `?` marker   a parameter marked `?` is reported when the function body
//                provably fails on an omitted argument, in the shapes listed
//                under OPTIONAL MARKERS below.
//   @example     at least one. The wiki shows every example on the
//                primitive's page. The gate compiles each body as the body of
//                an async function and does not run it, so a top-level
//                `await` or `return` compiles, and a body the compiler
//                refuses is reported with the compiler's message. A body is
//                also reported when it carries one of EXAMPLE_MARKERS, each a
//                mark written where a value or a call still has to be
//                supplied.
//   ordering     no description line inside an `@opts` or `@example` body.
//                The reader gives a multi-line tag every line up to the next
//                tag line, so a sentence written after one appears inside
//                that block on the wiki page. A line that starts with a
//                capital letter and ends with `.`, `!` or `?` is read as such
//                a sentence.
//
// OPTIONAL MARKERS. Whether a body tolerates an absent argument cannot be
// decided in general, so the check reports only these shapes and reports
// nothing when the body reaches the parameter any other way first. Positions
// are compared, so a signature may name a parameter differently from the
// declaration.
//
//   1. The first reference to the parameter reads a member of it (`opts.id`,
//      `opts[key]`).
//   2. The body opens its handling of the parameter with the statement
//      `opts = opts || {};`, and the next reference reads a member of a
//      member (`opts.range.start`) or calls a member.
//   3. The first reference (after that defaulting statement, the first
//      `opts.field`) sits in the header of an `if` whose body begins with
//      `throw`, and one `||` alternative of the condition is true for
//      `undefined`: `x === undefined`, `x == null`, `!x`,
//      `typeof x !== "string"`, `x !== null`, `!Array.isArray(x)` and the
//      like.
//   4. It is passed as a whole argument to a call of a function declared in
//      the same file, where the call is the statement itself or the right
//      side of one declaration, assignment or `return`. That function must be
//      declared once, not be async or a generator, appear in the file only
//      as its declaration and calls, and open with an `if` of the shape in 3
//      on the receiving parameter.
//
// In every shape the reference is in a top-level statement of the body, no
// `return` has been reached before it, and nothing in its statement before
// it is conditional: no `&&`, `||`, `??`, `?`, `?.` or arrow, no loop,
// `else`, `case`, `try`, `catch`, `function` or `class`, and it is not in the
// body of an `if`. A reference inside a nested block or function, any use of
// `arguments`, a parameter with a default value, a destructured or rest
// parameter, and a mention inside a template literal each end the analysis
// with no finding. A parameter documented as required that the body
// tolerates omitting is not checked.
//
// The records come from scripts/source-primitives.js, which is the reader
// lib/web/wiki/blocks.js bound to this repository. A record carries the
// block's `@signature` value and the offset just past the block's closing
// delimiter. The code beneath is read from the file's text at that offset,
// and a record whose offset does not end a block in that text is a finding.
//
// What is checked, per `@module` block:
//
//   @nav         present, and one of NAV_GROUPS. The wiki groups its index by
//                this value and lists a module without one under Other, so a
//                misspelled group appears as a second group in the navigation.
//   @title       present.
//   @featured    when present, a value the wiki reads as featured, which means
//                the built index lists the module under Start here. Every
//                other value is refused, including one meaning no. A module
//                that is not featured carries no `@featured` tag.
//   @card        present on every module the wiki lists under Start here.
//   @order       when present, a value the wiki sorts by as written, which
//                means the built module page carries exactly that value.
//
// WIKI BUILD. The gate calls `build({ root })` from lib/web/wiki, which is the
// function the server calls, over the same tree. A throw from it is a
// finding carrying the thrown message, which names the file and line: a slug
// the wiki cannot address, a module slug of `specs`, a file declaring two
// modules, a primitive token that is not a dotted identifier, and two blocks
// that would share a page. The `@featured` and `@order` checks above read the
// built pages. The build is also a finding when it reports a different number
// of primitives from the records this gate read.
//
// Files with no documentation block are not findings: the gate governs the
// blocks that exist rather than mandating where they appear.
//
// WHAT THE RUN EXAMINED is published as the last lines of every run, pass or
// fail, in the form the release battery reads:
//
//   EXAMINED <n> lib-source-files
//   EXAMINED <n> primitive-blocks
//   EXAMINED <n> signatures-compared
//   EXAMINED <n> optional-markers-checked
//   EXAMINED <n> module-blocks
//   EXAMINED <n> primitives-checked-for-an-example
//   EXAMINED <n> examples-parse-checked
//   EXAMINED <n> example-marker-scans
//   EXAMINED <n> tag-bodies-read-for-prose
//
// Each number can fail on its own. `lib-source-files` is the walk:
// a lib directory that moved, or a source filter that stopped matching, takes it
// to zero and every rule below has nothing to apply to. `primitive-blocks` is
// what the rules are actually applied to, and it is the honest count of the two:
// a run that opened two hundred files and extracted no block proved exactly as
// much as one that opened none, and prints the same "OK, no findings" either
// way. Publishing only the file count would hide that.
//
// `signatures-compared` counts the blocks whose parameter list was compared
// against a function beneath them. A signature reader that stopped matching,
// or a declaration reader that stopped finding functions, takes it to zero
// while `primitive-blocks` stays where it was. `optional-markers-checked`
// counts the `?` markers matched to a declared parameter and analyzed, and a
// signature parser that stopped seeing `?` takes it to zero while every
// signature is still compared. `module-blocks` counts the `@module` blocks
// the module checks read, and a module reader that stopped matching takes it
// to zero while every primitive count stays where it was.
//
// `primitives-checked-for-an-example` counts the records the example check
// was applied to. `examples-parse-checked` counts the example bodies handed to
// the compiler, and a record field that stopped carrying the bodies takes it
// to zero while every block is still checked for one. `example-marker-scans`
// counts one marker tested against one body, so an empty EXAMPLE_MARKERS takes
// it to zero while every body still compiles. `tag-bodies-read-for-prose`
// counts the `@opts` and `@example` bodies the ordering check read.
//
// The test corpus is deliberately NOT counted. An empty one does not go quiet:
// every primitive then reports `primitive-without-test`, so that failure arrives
// loudly on its own and needs no liveness number to surface it.
//
// No side effects, no network, no listeners bound. Building the wiki loads
// the vendored framework and reads the tree; it writes nothing.
//
// Exit codes:
//   0  no findings
//   1  findings present (each printed with its file, line and block token)

var fs   = require("node:fs");
var path = require("node:path");
var vm   = require("node:vm");

// The shared walk over this project's own lib sources and the one reader of
// the blocks they carry; the vendored tree is upstream's and is excluded
// there. This gate validates exactly the records the api-snapshot and
// lifecycle gates govern, because all three read them from the same place.
var sourcePrimitives = require("./source-primitives.js");

// The reference wiki, built here with the call the server makes.
var wiki = require("../lib/web/wiki");

var ROOT = path.resolve(__dirname, "..");

var KNOWN_STATUSES = { experimental: 1, stable: 1, deprecated: 1 };
var SEMVER_RE = /^\d+\.\d+\.\d+$/;

// The groups a `@module` block may name in `@nav`. A group is added here in
// the change that adds its first module.
var NAV_GROUPS = Object.freeze([
  "Server and configuration",
  "Mail protocols",
  "Sending",
  "DNS and domain authentication",
  "Accounts and domains",
  "Storage and audit",
  "Web interface",
  "Reference wiki",
]);

// Every finding kind the module checks report.
var MODULE_FINDING_KINDS = Object.freeze([
  "missing-nav",
  "unknown-nav",
  "missing-title",
  "featured-not-read",
  "featured-without-card",
  "order-not-read",
]);

// Every finding kind the wiki build reports.
var WIKI_FINDING_KINDS = Object.freeze([
  "wiki-build-refused",
  "wiki-read-another-set",
]);

// Every finding kind the example checks report.
var EXAMPLE_FINDING_KINDS = Object.freeze([
  "missing-example",
  "example-does-not-parse",
  "example-marker",
]);

// Every finding kind the ordering check reports.
var ORDERING_FINDING_KINDS = Object.freeze([
  "prose-after-multi-line-tag",
]);

// Marks written into an example where a value or a call still has to be
// supplied. The unfinished-work pattern is built from two string halves,
// because the unfinished-work detector in
// test/layer-0-primitives/codebase-patterns.test.js scans this file.
var EXAMPLE_MARKERS = Object.freeze([
  Object.freeze({
    id:   "ascii-arrow",
    re:   /\/\/\s*>\s+/,
    hint: "A comment that opens with `> ` reads as a shell prompt. Write the expected value as a " +
      "plain comment on the next line, such as `// true`.",
  }),
  Object.freeze({
    id:   "unfinished-work",
    re:   new RegExp("\\/\\/\\s*TO" + "DO\\b", "i"),
    hint: "Write the rest of the call and remove the mark.",
  }),
  Object.freeze({
    id:   "pseudocode",
    re:   /\/\/\s*pseudocode\b/i,
    hint: "Write the calls an operator would make and remove the mark.",
  }),
  Object.freeze({
    id:   "fill-in",
    re:   /\.\.\.\s*(?:fill|replace|your)/i,
    hint: "Write a real value where the ellipsis stands.",
  }),
  Object.freeze({
    id:   "angle-bracket",
    re:   /<[A-Z][A-Z0-9_-]*>/,
    hint: "An upper case name in angle brackets stands where a value belongs. Write a real " +
      "value, such as `\"example.com\"`.",
  }),
  Object.freeze({
    id:   "replace-me",
    re:   /\[\s*REPLACE[-_ ]?ME\s*\]/i,
    hint: "Write a real value where the bracketed name stands.",
  }),
]);

// A description line, as the ordering check reads one: a capital letter first
// and sentence punctuation last.
var SENTENCE_START_RE = /^[A-Z]/;
var SENTENCE_END_RE   = /[.!?]$/;

// The id of the index section listing featured modules, as the wiki builds it.
var START_HERE_ID = "start-here";

var _rel = sourcePrimitives.relative;

// The whole test corpus under `testDir` as one { file -> text } map, read
// once. Every tested-ness question is answered from it.
function readTestCorpus(testDir) {
  var out = {};
  (function walk(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
      var p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); return; }
      if (e.isFile() && /\.(js|mjs|cjs)$/.test(e.name)) out[_rel(p)] = fs.readFileSync(p, "utf8");
    });
  }(testDir));
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

// ---------------------------------------------------------------------------
// Signatures against the functions beneath their blocks
// ---------------------------------------------------------------------------

// Every finding kind the signature check reports, in the order it checks.
var SIGNATURE_FINDING_KINDS = [
  "block-not-located",
  "missing-signature",
  "unparseable-signature",
  "signature-names-another-primitive",
  "namespace-signature-over-function",
  "no-function-beneath",
  "function-name-mismatch",
  "arity-mismatch",
  "optional-parameter-required",
];

var IDENT_SOURCE      = "[A-Za-z_$][A-Za-z0-9_$]*";
var SIGNATURE_PATH_RE = new RegExp("^" + IDENT_SOURCE + "(?:\\." + IDENT_SOURCE + ")*$");
var SIGNATURE_CALL_RE =
  new RegExp("^(" + IDENT_SOURCE + "(?:\\." + IDENT_SOURCE + ")*)\\s*\\(([^()]*)\\)$");
var SIGNATURE_PARAM_RE = new RegExp("^(\\.\\.\\.)?(" + IDENT_SOURCE + ")(\\?)?$");

var WORD_START_RE = /[A-Za-z_$]/;
var DIGIT_RE      = /\d/;
var FLAG_RE       = /[A-Za-z]/;
var WORD_STICKY   = /[A-Za-z_$][A-Za-z0-9_$]*/y;
var NUMBER_STICKY = /(?:\d[\dA-Za-z_]*(?:\.[\dA-Za-z_]*)?|\.\d[\dA-Za-z_]*)/y;

// Longest first, so a longer punctuator is never read as its prefix.
var PUNCTUATORS = [
  ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
  "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
  "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
];

// A `/` after one of these words starts a regular expression literal.
var REGEX_AFTER_WORDS = {
  return: 1, typeof: 1, instanceof: 1, in: 1, of: 1, new: 1, delete: 1, void: 1,
  throw: 1, case: 1, do: 1, else: 1, yield: 1, await: 1,
};

var METHOD_MODIFIERS = { static: 1, async: 1, get: 1, set: 1 };

var NOT_METHOD_NAMES = {
  if: 1, for: 1, while: 1, switch: 1, catch: 1, with: 1, function: 1, return: 1,
  typeof: 1, new: 1, delete: 1, void: 1, throw: 1, await: 1, yield: 1, do: 1,
  else: 1, super: 1, import: 1, var: 1, let: 1, const: 1, class: 1, in: 1, of: 1,
  instanceof: 1,
};

// Words whose parenthesized header is followed by a block, not a function body.
var HEADER_WORDS = { if: 1, for: 1, while: 1, switch: 1, catch: 1, with: 1 };

// Words that begin a statement ending at its closing brace.
var BLOCK_STATEMENT_WORDS = {
  if: 1, else: 1, for: 1, while: 1, do: 1, try: 1, catch: 1, finally: 1,
  switch: 1, class: 1, function: 1, async: 1,
};

// Tokens before a reference, in its own statement, that mean the reference
// may not be evaluated.
var CONDITIONAL_PUNCTUATORS = {
  "&&": 1, "||": 1, "??": 1, "?": 1, "?.": 1, "=>": 1, "&&=": 1, "||=": 1, "??=": 1,
};
var CONDITIONAL_WORDS = {
  else: 1, for: 1, while: 1, do: 1, case: 1, default: 1, catch: 1, finally: 1,
  try: 1, switch: 1, function: 1, class: 1, yield: 1, with: 1,
};

var ASSIGNING_PUNCTUATORS = {
  "=": 1, "+=": 1, "-=": 1, "*=": 1, "/=": 1, "%=": 1, "**=": 1, "<<=": 1, ">>=": 1,
  ">>>=": 1, "&=": 1, "|=": 1, "^=": 1, "&&=": 1, "||=": 1, "??=": 1, "++": 1, "--": 1,
};

// `!Array.isArray(x)` and its siblings, each true when `x` is undefined.
var NEGATED_MEMBER_PREDICATES = {
  "Array.isArray": 1, "Number.isFinite": 1, "Number.isInteger": 1, "Number.isSafeInteger": 1,
};

/**
 * parseSignature(text) reads one `@signature` value.
 *
 *   { kind: "namespace", path }            a dotted path with no parameter list
 *   { kind: "callable", path, params }     a dotted path and one parameter list,
 *                                          each parameter { name, optional, rest }
 *   { kind: "unparseable" }                anything else
 *
 * A leading `await` or `new` is dropped.
 */
function parseSignature(text) {
  var s = String(text).trim().replace(/^await\s+/, "").replace(/^new\s+/, "");
  if (SIGNATURE_PATH_RE.test(s)) return { kind: "namespace", path: s.split(".") };
  var m = SIGNATURE_CALL_RE.exec(s);
  if (m === null) return { kind: "unparseable" };
  var params = [];
  var inner = m[2].trim();
  if (inner.length > 0) {
    var pieces = inner.split(",");
    for (var i = 0; i < pieces.length; i += 1) {
      var pm = SIGNATURE_PARAM_RE.exec(pieces[i].trim());
      if (pm === null) return { kind: "unparseable" };
      params.push({ name: pm[2], optional: pm[3] === "?", rest: pm[1] === "..." });
    }
  }
  return { kind: "callable", path: m[1].split("."), params: params };
}

function _lineOf(source, offset) {
  var line = 1;
  for (var i = source.indexOf("\n"); i !== -1 && i < offset; i = source.indexOf("\n", i + 1)) {
    line += 1;
  }
  return line;
}

function _escapeRegExp(text) {
  return text.replace(/\$/g, "\\$");
}

// The closing delimiter of a documentation block.
var BLOCK_CLOSE = "*" + "/";

// True when `end` is an offset in `source` just past a block's closing
// delimiter.
function _endsBlock(source, end) {
  return typeof end === "number" && end >= BLOCK_CLOSE.length && end <= source.length &&
    source.slice(end - BLOCK_CLOSE.length, end) === BLOCK_CLOSE;
}

// ---- tokens ---------------------------------------------------------------

function _stringEnd(source, i) {
  var quote = source.charAt(i);
  for (var j = i + 1; j < source.length; j += 1) {
    var c = source.charAt(j);
    if (c === "\\") { j += 1; continue; }
    if (c === quote) return j + 1;
    if (c === "\n") return j;
  }
  return source.length;
}

// The end of a `${ ... }` substitution whose expression starts at `pos`.
function _substitutionEnd(source, pos) {
  var inner = _tokenStream(source, pos);
  var depth = 0;
  for (var k = 0; ; k += 1) {
    var t = inner.at(k);
    if (t === null) return source.length;
    if (t.type !== "punct") continue;
    if (t.value === "{") {
      depth += 1;
    } else if (t.value === "}") {
      if (depth === 0) return t.end;
      depth -= 1;
    }
  }
}

function _templateEnd(source, i) {
  var j = i + 1;
  while (j < source.length) {
    var c = source.charAt(j);
    if (c === "\\") {
      j += 2;
    } else if (c === "`") {
      return j + 1;
    } else if (c === "$" && source.charAt(j + 1) === "{") {
      j = _substitutionEnd(source, j + 2);
    } else {
      j += 1;
    }
  }
  return source.length;
}

// The end of a regular expression literal opening at `i`, or -1 when the
// slash cannot open one.
function _regexEnd(source, i) {
  var inClass = false;
  for (var j = i + 1; j < source.length; j += 1) {
    var c = source.charAt(j);
    if (c === "\n" || c === "\r") return -1;
    if (c === "\\") { j += 1; continue; }
    if (inClass) {
      if (c === "]") inClass = false;
      continue;
    }
    if (c === "[") { inClass = true; continue; }
    if (c === "/") {
      var k = j + 1;
      while (k < source.length && FLAG_RE.test(source.charAt(k))) k += 1;
      return k;
    }
  }
  return -1;
}

// A lazily lexed token list over `source` from offset `pos`. Comments are
// skipped; strings, template literals and regular expression literals are
// one token each. `at(k)` returns token k, or null past the end. A token is
// { type, value, start, end, nl }, where `nl` says a line break precedes it.
function _tokenStream(source, pos) {
  var list = [];
  var i = pos;
  var ended = false;

  function regexMayStart() {
    var prev = list.length > 0 ? list[list.length - 1] : null;
    if (prev === null) return true;
    if (prev.type === "punct") return prev.value !== ")" && prev.value !== "]";
    if (prev.type === "ident") return REGEX_AFTER_WORDS[prev.value] === 1;
    return false;
  }

  function lexOne() {
    var nl = false;
    while (i < source.length) {
      var code = source.charCodeAt(i);
      if (code === 10) {
        nl = true;
        i += 1;
      } else if (code === 32 || code === 9 || code === 13 || code === 11 || code === 12 ||
                 code === 0xa0 || code === 0xfeff || code === 0x2028 || code === 0x2029) {
        i += 1;
      } else if (code === 47 && source.charCodeAt(i + 1) === 47) {
        var lineEnd = source.indexOf("\n", i);
        i = lineEnd === -1 ? source.length : lineEnd;
      } else if (code === 47 && source.charCodeAt(i + 1) === 42) {
        var close = source.indexOf("*/", i + 2);
        var stop = close === -1 ? source.length : close + 2;
        if (source.slice(i, stop).indexOf("\n") !== -1) nl = true;
        i = stop;
      } else {
        break;
      }
    }
    if (i >= source.length) return null;

    var start = i;
    var ch = source.charAt(i);
    var type = "punct";
    var end = i + 1;
    var regexEnd = -1;
    if (ch === "/" && regexMayStart()) regexEnd = _regexEnd(source, i);

    if (WORD_START_RE.test(ch)) {
      WORD_STICKY.lastIndex = i;
      WORD_STICKY.exec(source);
      end = WORD_STICKY.lastIndex;
      type = "ident";
    } else if (DIGIT_RE.test(ch) || (ch === "." && DIGIT_RE.test(source.charAt(i + 1)))) {
      NUMBER_STICKY.lastIndex = i;
      NUMBER_STICKY.exec(source);
      end = NUMBER_STICKY.lastIndex;
      type = "number";
    } else if (ch === "\"" || ch === "'") {
      end = _stringEnd(source, i);
      type = "string";
    } else if (ch === "`") {
      end = _templateEnd(source, i);
      type = "template";
    } else if (regexEnd !== -1) {
      end = regexEnd;
      type = "regex";
    } else {
      for (var p = 0; p < PUNCTUATORS.length; p += 1) {
        if (!source.startsWith(PUNCTUATORS[p], i)) continue;
        if (PUNCTUATORS[p] === "?." && DIGIT_RE.test(source.charAt(i + 2))) continue;
        end = i + PUNCTUATORS[p].length;
        break;
      }
    }
    i = end;
    return { type: type, value: source.slice(start, end), start: start, end: end, nl: nl };
  }

  return {
    at: function (k) {
      if (k < 0) return null;
      while (!ended && list.length <= k) {
        var t = lexOne();
        if (t === null) ended = true;
        else list.push(t);
      }
      return k < list.length ? list[k] : null;
    },
  };
}

function _punct(t, value) {
  return t !== null && t !== undefined && t.type === "punct" && t.value === value;
}

function _word(t, value) {
  return t !== null && t !== undefined && t.type === "ident" && (value === undefined || t.value === value);
}

function _matchingClose(ts, open) {
  var depth = 0;
  for (var k = open; ; k += 1) {
    var t = ts.at(k);
    if (t === null) return -1;
    if (_punct(t, "(")) {
      depth += 1;
    } else if (_punct(t, ")")) {
      depth -= 1;
      if (depth === 0) return k;
    }
  }
}

function _matchingOpen(ts, close) {
  var depth = 0;
  for (var k = close; k >= 0; k -= 1) {
    var t = ts.at(k);
    if (_punct(t, ")")) {
      depth += 1;
    } else if (_punct(t, "(")) {
      depth -= 1;
      if (depth === 0) return k;
    }
  }
  return -1;
}

// ---- declarations ---------------------------------------------------------

function _classifyParameter(tokens) {
  if (tokens.length === 1 && tokens[0].type === "ident") return { kind: "plain", name: tokens[0].value };
  if (tokens.length === 2 && _punct(tokens[0], "...") && tokens[1].type === "ident") {
    return { kind: "rest", name: tokens[1].value };
  }
  if (tokens[0].type === "ident" && _punct(tokens[1], "=")) return { kind: "default", name: tokens[0].value };
  if (_punct(tokens[0], "{") || _punct(tokens[0], "[")) return { kind: "pattern", name: null };
  return { kind: "other", name: null };
}

// The parameters between the `(` at stream index `open` and its `)`, split at
// top-level commas, as { params, close }, or null.
function _parameterList(ts, open) {
  var params = [];
  var current = [];
  var depth = 0;
  for (var k = open + 1; ; k += 1) {
    var t = ts.at(k);
    if (t === null) return null;
    if (t.type === "punct") {
      if (t.value === "(" || t.value === "[" || t.value === "{") {
        depth += 1;
      } else if (t.value === ")" || t.value === "]" || t.value === "}") {
        if (depth === 0) {
          if (t.value !== ")") return null;
          if (current.length > 0) params.push(_classifyParameter(current));
          return { params: params, close: k };
        }
        depth -= 1;
      } else if (t.value === "," && depth === 0) {
        if (current.length === 0) return null;
        params.push(_classifyParameter(current));
        current = [];
        continue;
      }
    }
    current.push(t);
  }
}

function _withParameters(ts, open, decl, arrow) {
  var parsed = _parameterList(ts, open);
  if (parsed === null) return null;
  var k = parsed.close + 1;
  if (arrow) {
    if (!_punct(ts.at(k), "=>")) return null;
    decl.bodyIndex = _punct(ts.at(k + 1), "{") ? k + 2 : null;
  } else {
    if (!_punct(ts.at(k), "{")) return null;
    decl.bodyIndex = k + 1;
  }
  decl.params = parsed.params;
  decl.stream = ts;
  return decl;
}

// A function expression or arrow function starting at stream index `k`, the
// value of a declaration, assignment or object key named `name`.
function _functionValue(ts, k, name, start) {
  var isAsync = false;
  if (_word(ts.at(k), "async") &&
      (_word(ts.at(k + 1), "function") || _punct(ts.at(k + 1), "(") ||
       (_word(ts.at(k + 1)) && _punct(ts.at(k + 2), "=>")))) {
    isAsync = true;
    k += 1;
  }
  if (_word(ts.at(k), "function")) {
    k += 1;
    var generator = false;
    if (_punct(ts.at(k), "*")) { generator = true; k += 1; }
    if (_word(ts.at(k))) k += 1;
    if (!_punct(ts.at(k), "(")) return null;
    return _withParameters(ts, k, { name: name, async: isAsync, generator: generator, start: start }, false);
  }
  if (_punct(ts.at(k), "(")) {
    return _withParameters(ts, k, { name: name, async: isAsync, generator: false, start: start }, true);
  }
  if (_word(ts.at(k)) && _punct(ts.at(k + 1), "=>")) {
    return {
      name: name, async: isAsync, generator: false, start: start,
      params: [{ kind: "plain", name: ts.at(k).value }],
      bodyIndex: _punct(ts.at(k + 2), "{") ? k + 3 : null,
      stream: ts,
    };
  }
  return null;
}

// The function declared at offset `pos`, as { name, async, generator, params,
// bodyIndex, stream, start }, or null when the code there is not a function.
// `bodyIndex` is the stream index of the first token inside the function's
// braces, or null for an arrow function with an expression body.
function _declarationAt(source, pos) {
  var ts = _tokenStream(source, pos);
  var first = ts.at(0);
  if (first === null) return null;
  var start = first.start;

  if (first.type === "string" && _punct(ts.at(1), ":")) {
    return _functionValue(ts, 2, first.value.slice(1, -1), start);
  }
  if (first.type !== "ident") return null;

  if ((first.value === "var" || first.value === "let" || first.value === "const") &&
      _word(ts.at(1)) && _punct(ts.at(2), "=")) {
    return _functionValue(ts, 3, ts.at(1).value, start);
  }
  var m = 0;
  while (_punct(ts.at(m + 1), ".") && _word(ts.at(m + 2))) m += 2;
  if (m > 0) {
    return _punct(ts.at(m + 1), "=") ? _functionValue(ts, m + 2, ts.at(m).value, start) : null;
  }
  if (NOT_METHOD_NAMES[first.value] !== 1 && (_punct(ts.at(1), ":") || _punct(ts.at(1), "="))) {
    return _functionValue(ts, 2, first.value, start);
  }

  var k = 0;
  var isAsync = false;
  if (_word(ts.at(0), "async") && _word(ts.at(1), "function")) { isAsync = true; k = 1; }
  if (_word(ts.at(k), "function")) {
    k += 1;
    var generator = false;
    if (_punct(ts.at(k), "*")) { generator = true; k += 1; }
    if (!_word(ts.at(k)) || !_punct(ts.at(k + 1), "(")) return null;
    return _withParameters(ts, k + 1,
      { name: ts.at(k).value, async: isAsync, generator: generator, start: start }, false);
  }

  // Method shorthand, in an object literal or a class body.
  k = 0;
  isAsync = false;
  var gen = false;
  while (_word(ts.at(k)) && METHOD_MODIFIERS[ts.at(k).value] === 1 &&
         (_word(ts.at(k + 1)) || _punct(ts.at(k + 1), "*"))) {
    if (ts.at(k).value === "async") isAsync = true;
    k += 1;
  }
  if (_punct(ts.at(k), "*")) { gen = true; k += 1; }
  if (!_word(ts.at(k)) || NOT_METHOD_NAMES[ts.at(k).value] === 1 || !_punct(ts.at(k + 1), "(")) return null;
  return _withParameters(ts, k + 1, { name: ts.at(k).value, async: isAsync, generator: gen, start: start }, false);
}

// The function directly beneath a block ending at `end`. Whitespace and
// ordinary comments may sit between; another documentation block, or the end
// of the file, means nothing is beneath it.
function _declarationBeneath(source, end) {
  var j = end;
  for (;;) {
    while (j < source.length && /\s/.test(source.charAt(j))) j += 1;
    if (source.startsWith("/**", j)) return null;
    if (source.startsWith("//", j)) {
      var lineEnd = source.indexOf("\n", j);
      j = lineEnd === -1 ? source.length : lineEnd;
    } else if (source.startsWith("/*", j)) {
      var close = source.indexOf("*/", j + 2);
      j = close === -1 ? source.length : close + 2;
    } else {
      break;
    }
  }
  if (j >= source.length) return null;
  return _declarationAt(source, j);
}

// True when the function named `declared` is bound under `documented` in the
// file: the same name, an object key, or a member assignment. A key or member
// holding a CALL of the function holds its result and does not count.
function _boundUnder(source, documented, declared) {
  if (documented === declared) return true;
  var d = _escapeRegExp(documented);
  var n = _escapeRegExp(declared);
  var key = new RegExp("(?:^|[{,\\s])([\"']?)" + d + "\\1\\s*:\\s*" + n + "(?![A-Za-z0-9_$(.])");
  var member = new RegExp("\\." + d + "\\s*=\\s*" + n + "(?![A-Za-z0-9_$(.=])");
  return key.test(source) || member.test(source);
}

// ---- omitted arguments ----------------------------------------------------

function _isReference(ts, k) {
  var prev = ts.at(k - 1);
  if (_punct(prev, ".") || _punct(prev, "?.")) return false;
  if (_punct(ts.at(k + 1), ":") && (_punct(prev, "{") || _punct(prev, ","))) return false;
  return true;
}

// `name = name || {};`
function _isDefaulting(ts, k, name) {
  return _punct(ts.at(k + 1), "=") && _word(ts.at(k + 2), name) && _punct(ts.at(k + 3), "||") &&
    _punct(ts.at(k + 4), "{") && _punct(ts.at(k + 5), "}") && _punct(ts.at(k + 6), ";");
}

// A `{` at stream index `k` that opens a function body: after `=>`, after the
// parameter list of `function`, or after the parameter list of a method in an
// object literal.
function _opensFunction(ts, k) {
  var prev = ts.at(k - 1);
  if (_punct(prev, "=>")) return true;
  if (!_punct(prev, ")")) return false;
  var open = _matchingOpen(ts, k - 1);
  if (open < 1) return false;
  var before = ts.at(open - 1);
  if (_word(before, "function")) return true;
  if (_punct(before, "*")) return _word(ts.at(open - 2), "function");
  if (!_word(before) || HEADER_WORDS[before.value] === 1) return false;
  var ahead = ts.at(open - 2);
  if (_word(ahead, "function")) return true;
  if (_punct(ahead, "*")) return _word(ts.at(open - 3), "function");
  return _punct(ahead, "{") || _punct(ahead, ",") || (_word(ahead) && METHOD_MODIFIERS[ahead.value] === 1);
}

function _startsBlockStatement(ts, stmt) {
  if (stmt.length === 0) return true;
  var first = ts.at(stmt[0]);
  return first.type === "ident" && BLOCK_STATEMENT_WORDS[first.value] === 1;
}

// True when every token of the statement before the reference is evaluated
// on the way to it.
function _reachesReference(ts, stmt) {
  var header = stmt.length > 0 && _word(ts.at(stmt[0]), "if");
  if (header && !_punct(ts.at(stmt[1]), "(")) return false;
  var depth = 0;
  for (var s = 0; s < stmt.length; s += 1) {
    var t = ts.at(stmt[s]);
    if (t.type === "punct" && CONDITIONAL_PUNCTUATORS[t.value] === 1) return false;
    if (t.type === "ident" && (CONDITIONAL_WORDS[t.value] === 1 || (t.value === "if" && s !== 0))) return false;
    if (header && s >= 1) {
      if (_punct(t, "(")) {
        depth += 1;
      } else if (_punct(t, ")")) {
        depth -= 1;
        if (depth === 0) return false;
      }
    }
  }
  return true;
}

function _throwsAt(ts, k) {
  return _word(ts.at(k), "throw") || (_punct(ts.at(k), "{") && _word(ts.at(k + 1), "throw"));
}

function _isStringLiteral(t) {
  return t !== null && t !== undefined && t.type === "string" && t.value.indexOf("\\") === -1;
}

// True for a literal that is never strictly equal to undefined.
function _definedLiteral(tokens) {
  if (tokens.length !== 1) return false;
  var t = tokens[0];
  return t.type === "string" || t.type === "number" ||
    _word(t, "null") || _word(t, "true") || _word(t, "false");
}

function _isUndefinedLiteral(tokens) {
  return (tokens.length === 1 && _word(tokens[0], "undefined")) ||
    (tokens.length === 2 && _word(tokens[0], "void") && tokens[1].type === "number" && tokens[1].value === "0");
}

// One `||` alternative, true when the subject (one name, or `name.field`) is
// undefined.
function _atomTrueWhenUndefined(atom, subject) {
  var s = subject.length === 1 ? 1 : 3;
  function subjectAt(i) {
    if (i < 0 || i + s > atom.length || !_word(atom[i], subject[0])) return false;
    return s === 1 || (_punct(atom[i + 1], ".") && _word(atom[i + 2], subject[1]));
  }
  function compares(op, other) {
    if (op === "===" || op === "==") {
      return _isUndefinedLiteral(other) || (op === "==" && other.length === 1 && _word(other[0], "null"));
    }
    if (op === "!==") return _definedLiteral(other);
    if (op === "!=") return _definedLiteral(other) && !_word(other[0], "null");
    return false;
  }
  var n = atom.length;

  if (n === s + 1 && _punct(atom[0], "!") && subjectAt(1)) return true;

  if (n > s + 1 && subjectAt(0) && atom[s].type === "punct" &&
      compares(atom[s].value, atom.slice(s + 1))) {
    return true;
  }
  for (var lhs = 1; lhs <= 2; lhs += 1) {
    if (n === lhs + 1 + s && subjectAt(lhs + 1) && atom[lhs].type === "punct" &&
        compares(atom[lhs].value, atom.slice(0, lhs))) {
      return true;
    }
  }

  if (n === s + 3 && _word(atom[0], "typeof") && subjectAt(1) && _isStringLiteral(atom[s + 2])) {
    var op = atom[s + 1];
    var type = atom[s + 2].value.slice(1, -1);
    if ((_punct(op, "===") || _punct(op, "==")) && type === "undefined") return true;
    if ((_punct(op, "!==") || _punct(op, "!=")) && type !== "undefined") return true;
  }

  if (n === s + 6 && _punct(atom[0], "!") && _word(atom[1]) && _punct(atom[2], ".") && _word(atom[3]) &&
      NEGATED_MEMBER_PREDICATES[atom[1].value + "." + atom[3].value] === 1 &&
      _punct(atom[4], "(") && subjectAt(5) && _punct(atom[5 + s], ")")) {
    return true;
  }
  if (n === s + 4 && _punct(atom[0], "!") && _word(atom[1], "isFinite") && _punct(atom[2], "(") &&
      subjectAt(3) && _punct(atom[3 + s], ")")) {
    return true;
  }
  return false;
}

// True when a condition is true for an undefined subject: one of its
// top-level `||` alternatives is, and nothing in it assigns.
function _conditionTrueWhenUndefined(tokens, subject) {
  var atoms = [[]];
  var depth = 0;
  for (var i = 0; i < tokens.length; i += 1) {
    var t = tokens[i];
    if (t.type === "punct") {
      if (ASSIGNING_PUNCTUATORS[t.value] === 1) return false;
      if (t.value === "(" || t.value === "[" || t.value === "{") {
        depth += 1;
      } else if (t.value === ")" || t.value === "]" || t.value === "}") {
        depth -= 1;
      } else if (depth === 0 && (t.value === "?" || t.value === "," || t.value === "??")) {
        return false;
      } else if (depth === 0 && t.value === "||") {
        atoms.push([]);
        continue;
      }
    }
    atoms[atoms.length - 1].push(t);
  }
  return atoms.some(function (atom) { return _atomTrueWhenUndefined(atom, subject); });
}

function _refusedByCondition(ts, stmt, k, end, subject, defaulted) {
  if (stmt.length < 2 || !_word(ts.at(stmt[0]), "if") || !_punct(ts.at(stmt[1]), "(")) return null;
  var close = _matchingClose(ts, stmt[1]);
  if (close < end || !_throwsAt(ts, close + 1)) return null;
  var cond = [];
  for (var c = stmt[1] + 1; c < close; c += 1) cond.push(ts.at(c));
  if (!_conditionTrueWhenUndefined(cond, subject.split("."))) return null;
  return { how: "condition", subject: subject, at: k, defaulted: defaulted };
}

// A statement lead that always evaluates the call after it: nothing,
// `return`, `var x =`, `x =`, each optionally followed by `await`.
function _plainLead(tokens) {
  var i = 0;
  if (_word(tokens[0], "return")) {
    i = 1;
  } else if ((_word(tokens[0], "var") || _word(tokens[0], "let") || _word(tokens[0], "const")) &&
             _word(tokens[1]) && _punct(tokens[2], "=")) {
    i = 3;
  } else if (_word(tokens[0]) && NOT_METHOD_NAMES[tokens[0].value] !== 1 && _punct(tokens[1], "=")) {
    i = 2;
  }
  if (_word(tokens[i], "await")) i += 1;
  return i === tokens.length;
}

// The one function declared under `name` in the file, when every mention of
// the name is its declaration or a call, or null.
function _soleFunction(source, name) {
  var mentions = new RegExp("(^|[^A-Za-z0-9_$.])" + _escapeRegExp(name) + "(?![A-Za-z0-9_$])", "g");
  var starts = [];
  var m;
  while ((m = mentions.exec(source)) !== null) {
    var at = m.index + m[1].length;
    if (!/^\s*\(/.test(source.slice(at + name.length, at + name.length + 16))) return null;
    var head = source.slice(Math.max(0, at - 32), at);
    var keyword = /(?:async\s+)?function\s*\*?\s*$/.exec(head);
    if (keyword !== null) starts.push(at - head.length + keyword.index);
  }
  if (starts.length !== 1) return null;
  var decl = _declarationAt(source, starts[0]);
  return decl !== null && decl.name === name ? decl : null;
}

function _refusedByHelper(source, decl, ts, stmt, k, end, subject, defaulted) {
  if (stmt.length === 0) return null;
  var before = ts.at(k - 1);
  var after = ts.at(end);
  if (!(_punct(before, "(") || _punct(before, ",")) || !(_punct(after, ",") || _punct(after, ")"))) return null;

  var argument = 0;
  var depth = 0;
  var open = -1;
  for (var b = k - 1; b >= stmt[0]; b -= 1) {
    var t = ts.at(b);
    if (t.type !== "punct") continue;
    if (t.value === ")" || t.value === "]" || t.value === "}") {
      depth += 1;
    } else if (t.value === "(" || t.value === "[" || t.value === "{") {
      if (depth === 0) { open = b; break; }
      depth -= 1;
    } else if (t.value === "," && depth === 0) {
      argument += 1;
    }
  }
  if (open < 1 || !_punct(ts.at(open), "(") || open - 1 < stmt[0]) return null;
  var callee = ts.at(open - 1);
  if (!_word(callee) || NOT_METHOD_NAMES[callee.value] === 1) return null;
  var lead = [];
  for (var l = stmt[0]; l < open - 1; l += 1) lead.push(ts.at(l));
  if (!_plainLead(lead)) return null;
  if (decl.params.some(function (p) { return p.name === callee.value; })) return null;

  var helper = _soleFunction(source, callee.value);
  if (helper === null || helper.async || helper.generator || helper.bodyIndex === null) return null;
  var receiving = helper.params[argument];
  if (!receiving || receiving.kind !== "plain") return null;
  var hs = helper.stream;
  var hb = helper.bodyIndex;
  if (!_word(hs.at(hb), "if") || !_punct(hs.at(hb + 1), "(")) return null;
  var close = _matchingClose(hs, hb + 1);
  if (close < 0 || !_throwsAt(hs, close + 1)) return null;
  var cond = [];
  for (var c = hb + 2; c < close; c += 1) cond.push(hs.at(c));
  if (!_conditionTrueWhenUndefined(cond, [receiving.name])) return null;
  return {
    how: "helper", subject: subject, at: k, defaulted: defaulted,
    helper: callee.value, receiving: receiving.name, helperIf: hs.at(hb).start,
  };
}

// The first reference to the parameter, reached unconditionally at the top
// level of the body: decide whether it fails for an omitted argument.
function _decide(source, decl, ts, stmt, k, name, defaulted) {
  if (!_reachesReference(ts, stmt)) return null;
  var next = ts.at(k + 1);
  if (_punct(next, "[")) {
    return defaulted ? null : { how: "read", subject: name, at: k, defaulted: false };
  }
  var subject = name;
  var end = k + 1;
  if (_punct(next, ".")) {
    var field = ts.at(k + 2);
    if (!_word(field)) return null;
    subject = name + "." + field.value;
    if (!defaulted) return { how: "read", subject: subject, at: k, defaulted: false };
    if (field.value in Object.prototype) return null;
    var after = ts.at(k + 3);
    if (_punct(after, ".") || _punct(after, "[") || _punct(after, "(")) {
      return { how: "read", subject: subject, at: k, defaulted: true };
    }
    end = k + 3;
  } else if (defaulted) {
    return null;
  }
  return _refusedByCondition(ts, stmt, k, end, subject, defaulted) ||
    _refusedByHelper(source, decl, ts, stmt, k, end, subject, defaulted);
}

// How the body of `decl` fails when parameter `index` is omitted, as
// { how, subject, at, defaulted, ... }, or null when that is not proven.
function _omissionRefusal(source, decl, index) {
  var param = decl.params[index];
  if (!param || param.kind !== "plain" || decl.generator || decl.bodyIndex === null) return null;
  var name = param.name;
  var mention = new RegExp("(?:^|[^A-Za-z0-9_$])" + _escapeRegExp(name) + "(?![A-Za-z0-9_$])");
  var ts = decl.stream;
  var braces = [];
  var parens = 0;
  var stmt = [];
  var defaulted = false;
  var returning = false;

  for (var k = decl.bodyIndex; ; k += 1) {
    var t = ts.at(k);
    if (t === null) return null;
    var top = braces.length === 0;

    if (t.type === "template" && mention.test(t.value)) return null;
    if (t.type === "ident") {
      if (t.value === "arguments" || t.value === "eval" || t.value === "with") return null;
      if (t.value === "return" && braces.indexOf("function") === -1) {
        var following = ts.at(k + 1);
        if (!top || parens !== 0 || following === null || following.nl) return null;
        returning = true;
      }
      if (t.value === name && _isReference(ts, k)) {
        if (!top) return null;
        if (!defaulted && stmt.length === 0 && _isDefaulting(ts, k, name)) {
          defaulted = true;
          k += 6;
          continue;
        }
        return _decide(source, decl, ts, stmt, k, name, defaulted);
      }
    } else if (t.type === "punct") {
      if (t.value === "{") {
        var kind = "expression";
        if (_opensFunction(ts, k)) kind = "function";
        else if (top && parens === 0 && _startsBlockStatement(ts, stmt)) kind = "block";
        braces.push(kind);
      } else if (t.value === "}") {
        if (braces.length === 0) return null;
        var closed = braces.pop();
        if (braces.length === 0 && parens === 0 &&
            (closed === "block" || (closed === "function" && _startsBlockStatement(ts, stmt)))) {
          if (returning) return null;
          stmt = [];
          continue;
        }
      } else if (top && (t.value === "(" || t.value === "[")) {
        parens += 1;
      } else if (top && (t.value === ")" || t.value === "]")) {
        parens -= 1;
      } else if (top && parens === 0 && t.value === ";") {
        if (returning) return null;
        stmt = [];
        continue;
      }
    }
    stmt.push(k);
  }
}

function _refusalMessage(source, sigParam, decl, index, refusal) {
  var declared = decl.params[index].name;
  var marker = "`" + sigParam.name + "?`" +
    (declared !== sigParam.name ? " (declared `" + declared + "`)" : "");
  var line = _lineOf(source, decl.stream.at(refusal.at).start);
  var fails = decl.async ? "rejects" : "throws";
  var defaulting = "`" + declared + " = " + declared + " || {}`";
  var remedy = " Drop the `?`, or make " + decl.name + " accept a call without it.";
  if (refusal.how === "read" && refusal.defaulted) {
    return marker + " marks the argument omissible, but after " + defaulting + " " + decl.name +
      " reads a member of `" + refusal.subject + "` on line " + line + ", which is undefined when " +
      "the argument is omitted, so the call " + fails + "." + remedy;
  }
  if (refusal.how === "read") {
    return marker + " marks the argument omissible, but " + decl.name + " reads `" + refusal.subject +
      "` on line " + line + " before anything tests `" + declared + "`, so a call that omits it " +
      fails + "." + remedy;
  }
  var undefinedWhen = refusal.defaulted
    ? "which it is after " + defaulting + " when the argument is omitted"
    : "which it is when the argument is omitted";
  if (refusal.how === "condition") {
    return marker + " marks the argument omissible, but the `if` on line " + line + " of " + decl.name +
      " throws when `" + refusal.subject + "` is undefined, " + undefinedWhen + ", so the call " +
      fails + "." + remedy;
  }
  return marker + " marks the argument omissible, but " + decl.name + " passes `" + refusal.subject +
    "` to " + refusal.helper + " on line " + line + ", and the first statement of " + refusal.helper +
    " (line " + _lineOf(source, refusal.helperIf) + ") throws when `" + refusal.receiving +
    "` is undefined, " + undefinedWhen + ", so the call " + fails + "." + remedy;
}

/**
 * signatureFindings(record, source) compares one block's `@signature` against
 * the function directly beneath it.
 *
 * `record` is a primitive record as scripts/source-primitives.js reads it,
 * of which this reads `token`, `signature` and `end`, and `source` is the text
 * of the file the block is in. Returns
 *
 *   findings         [{ kind, msg }], each kind one of SIGNATURE_FINDING_KINDS
 *   compared         true when a parameter list was compared against a function
 *   namespace        true when the signature has no parameter list
 *   optionalChecked  the `?` markers matched to a declared parameter and analyzed
 */
function signatureFindings(record, source) {
  var out = { findings: [], compared: false, namespace: false, optionalChecked: 0 };
  function add(kind, msg) { out.findings.push({ kind: kind, msg: msg }); }

  if (!_endsBlock(source, record.end)) {
    add("block-not-located", "the shared reader ends this block at offset " + record.end +
      ", and no documentation block ends there in the file's text, so its signature was not compared.");
    return out;
  }
  var text = typeof record.signature === "string" ? record.signature : null;
  if (text === null) {
    add("missing-signature", "no @signature. Write the call shape, such as `handle.method(arg, opts?)`, " +
      "or the bare dotted path for a sub-handle or a constant.");
    return out;
  }
  var sig = parseSignature(text);
  if (sig.kind === "unparseable") {
    add("unparseable-signature", "@signature `" + text + "` is neither a dotted path nor a dotted path " +
      "followed by one parameter list of names, each name optionally prefixed with `...` or followed by `?`.");
    return out;
  }
  var tokenParts = String(record.token).split(".");
  var tokenName = tokenParts[tokenParts.length - 1];
  if (sig.path.indexOf(tokenName) === -1) {
    add("signature-names-another-primitive", "@signature `" + text + "` does not name `" + tokenName +
      "`, the last segment of the block's token.");
    return out;
  }

  var decl = _declarationBeneath(source, record.end);
  if (sig.kind === "namespace") {
    out.namespace = true;
    if (decl !== null && _boundUnder(source, tokenName, decl.name)) {
      add("namespace-signature-over-function", "@signature `" + text + "` has no parameter list, and " +
        "the function beneath the block, `" + decl.name + "` on line " + _lineOf(source, decl.start) +
        ", is bound under `" + tokenName + "`. Write its parameters in the signature.");
    }
    return out;
  }

  var documented = sig.path[sig.path.length - 1];
  if (decl === null) {
    add("no-function-beneath", "@signature `" + text + "` documents a callable, and no function is " +
      "declared directly beneath the block. Move the block above the function it documents; a " +
      "sub-handle or a constant is written without a parameter list.");
    return out;
  }
  if (!_boundUnder(source, documented, decl.name)) {
    add("function-name-mismatch", "@signature `" + text + "` documents `" + documented + "`, and the " +
      "function beneath the block is `" + decl.name + "` on line " + _lineOf(source, decl.start) +
      ", which this file does not bind under that name as `" + documented + ": " + decl.name +
      "` or `." + documented + " = " + decl.name + "`. Move the block above the function it documents.");
    return out;
  }

  out.compared = true;
  if (sig.params.length !== decl.params.length) {
    add("arity-mismatch", "@signature `" + text + "` names " + sig.params.length + " parameter(s), and " +
      decl.name + " on line " + _lineOf(source, decl.start) + " declares " + decl.params.length +
      ". List the parameters the function takes.");
    return out;
  }
  sig.params.forEach(function (sigParam, i) {
    if (!sigParam.optional) return;
    out.optionalChecked += 1;
    var refusal = _omissionRefusal(source, decl, i);
    if (refusal !== null) {
      add("optional-parameter-required", _refusalMessage(source, sigParam, decl, i, refusal));
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Examples, and the bodies of multi-line tags
// ---------------------------------------------------------------------------

/**
 * compileExample(body) compiles one `@example` body as the body of an async
 * function and does not run it. Returns null when the body compiles, or the
 * compiler's message when it does not.
 */
function compileExample(body) {
  try {
    void new vm.Script("(async function () {\n" + body + "\n});", { filename: "example.js" });
    return null;
  } catch (e) {
    return e && e.message ? e.message : String(e);
  }
}

/**
 * exampleFindings(record) checks the `examples` of one primitive record as
 * scripts/source-primitives.js reads it. Returns
 *
 *   findings   [{ kind, msg }], each kind one of EXAMPLE_FINDING_KINDS
 *   checked    true, once the record has been checked for an example
 *   compiled   the example bodies handed to the compiler
 *   scans      the markers tested, one for each marker against each body
 */
function exampleFindings(record) {
  var out = { findings: [], checked: false, compiled: 0, scans: 0 };
  function add(kind, msg) { out.findings.push({ kind: kind, msg: msg }); }

  var examples = Array.isArray(record.examples) ? record.examples : [];
  out.checked = true;
  if (examples.length === 0) {
    add("missing-example", "has no @example, so its wiki page shows no call. Add an @example after " +
      "the description and any @opts, holding a call written against the @signature that passes " +
      "only the options @opts lists.");
    return out;
  }
  examples.forEach(function (body, i) {
    var label = "@example #" + (i + 1);
    out.compiled += 1;
    var refusal = compileExample(body);
    if (refusal !== null) {
      add("example-does-not-parse", label + " does not compile as the body of an async function: " +
        refusal + ". Correct the code. Every line after the tag up to the next tag line is part of " +
        "the example, so a description line written there belongs above the first multi-line tag.");
    }
    EXAMPLE_MARKERS.forEach(function (marker) {
      out.scans += 1;
      var hit = marker.re.exec(body);
      if (hit !== null) {
        add("example-marker", label + " carries the " + marker.id + " mark `" + hit[0].trim() + "`. " +
          marker.hint);
      }
    });
  });
  return out;
}

/**
 * orderingFindings(record) reads the `opts` body and each `examples` body of
 * one primitive record for a line written as a sentence. Returns
 *
 *   findings   [{ kind, msg }], each kind one of ORDERING_FINDING_KINDS
 *   read       the bodies read
 */
function orderingFindings(record) {
  var out = { findings: [], read: 0 };
  var bodies = [];
  if (typeof record.opts === "string") bodies.push({ label: "@opts", text: record.opts });
  (Array.isArray(record.examples) ? record.examples : []).forEach(function (body, i) {
    bodies.push({ label: "@example #" + (i + 1), text: body });
  });

  bodies.forEach(function (body) {
    out.read += 1;
    var lines = String(body.text).split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i].trim();
      if (!SENTENCE_START_RE.test(line) || !SENTENCE_END_RE.test(line)) continue;
      out.findings.push({
        kind: "prose-after-multi-line-tag",
        msg:  "the " + body.label + " body holds the sentence `" + line + "`. A multi-line tag takes " +
          "every line up to the next tag line, so the wiki page shows this sentence inside that " +
          "block. Move the description above the first multi-line tag.",
      });
      return;
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Module blocks, and the wiki built from the blocks
// ---------------------------------------------------------------------------

function _blank(value) {
  return value === null || value === undefined || String(value).trim().length === 0;
}

/**
 * wikiFindings(root, records) builds the reference wiki over the tree under
 * `root` with the `build` the server calls, and compares it with `records`,
 * the { primitives, modules } this gate read from the same tree. Returns
 *
 *   findings   [{ kind, msg }], each kind one of WIKI_FINDING_KINDS
 *   built      the object `build` returned, or null when it threw
 */
function wikiFindings(root, records) {
  var out = { findings: [], built: null };
  try {
    out.built = wiki.build({ root: root });
  } catch (e) {
    out.findings.push({
      kind: "wiki-build-refused",
      msg:  "the reference wiki's build throws over this tree, and the message names the block: " +
        (e && e.message ? e.message : String(e)),
    });
    return out;
  }
  if (out.built.counts.primitives !== records.primitives.length) {
    out.findings.push({
      kind: "wiki-read-another-set",
      msg:  "the wiki built pages for " + out.built.counts.primitives + " primitive(s) from this tree, " +
        "and this gate read " + records.primitives.length + " primitive block(s) from it.",
    });
  }
  return out;
}

/**
 * moduleFindings(modules, built) checks each `@module` record. `@nav` and
 * `@title` are checked against the record. `@featured`, `@card` and `@order`
 * are checked against `built`, the wiki `build` returned for the same tree,
 * and are not checked when `built` is null. Returns [{ kind, record, msg }],
 * each kind one of MODULE_FINDING_KINDS, or `wiki-read-another-set` for a
 * module block the wiki built no page for.
 */
function moduleFindings(modules, built) {
  var out = [];
  var pageByToken = {};
  var listed = {};
  if (built !== null) {
    built.paths().forEach(function (p) {
      var page = built.page(p);
      if (page.kind === "module") pageByToken[page.subject.token] = page;
    });
    var index = built.page(wiki.BASE_PATH);
    (index === null ? [] : index.sections).forEach(function (section) {
      if (section.id !== START_HERE_ID) return;
      section.blocks.forEach(function (blk) {
        (blk.items || []).forEach(function (item) {
          if (item.length > 0 && typeof item[0].wikiHref === "string") listed["/" + item[0].wikiHref] = true;
        });
      });
    });
  }

  modules.forEach(function (m) {
    function add(kind, msg) { out.push({ kind: kind, record: m, msg: msg }); }

    if (_blank(m.nav)) {
      add("missing-nav", "no @nav, so the wiki lists the module under Other. Name one of these groups: " +
        NAV_GROUPS.join("; ") + ".");
    } else if (NAV_GROUPS.indexOf(m.nav) === -1) {
      add("unknown-nav", "@nav " + m.nav + " is not a declared group, and the wiki lists it as a group " +
        "of its own. Name one of these groups: " + NAV_GROUPS.join("; ") + ". A new group is added to " +
        "NAV_GROUPS in scripts/validate-source-comment-blocks.js in the change that adds its first module.");
    }
    if (_blank(m.title)) {
      add("missing-title", "no @title, so the wiki titles the module by its token. Write the name the " +
        "navigation lists it by.");
    }

    if (built === null) return;
    if (!Object.prototype.hasOwnProperty.call(pageByToken, m.token)) {
      add("wiki-read-another-set", "the wiki built no module page for this block.");
      return;
    }
    var page = pageByToken[m.token];
    var featured = listed[page.path] === true;
    if (m.featured !== null && !featured) {
      add("featured-not-read", "@featured " + m.featured + " is not a value the wiki reads as featured, " +
        "so the module is not listed under Start here. Write `@featured true`, or remove the tag.");
    }
    if (featured && _blank(m.card)) {
      add("featured-without-card", "is listed under Start here and has no @card, so the index lists it " +
        "with no description. Add a @card of one or two sentences.");
    }
    if (m.order !== null && String(page.subject.order) !== m.order) {
      add("order-not-read", "@order " + m.order + " is sorted by the wiki as " + page.subject.order +
        ", which is not the value written. Write a whole number, such as 10.");
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// `opts.root` points the run at another tree, whose lib/ holds the sources
// and whose test/ holds the test corpus unless `opts.testDir` names another
// directory. The layer-0 and layer-1 tests drive this gate over fixtures that
// way. The command line takes no arguments and always reads this repository.
function validate(opts) {
  opts = opts || {};
  var root = opts.root === undefined ? ROOT : opts.root;
  var reader = sourcePrimitives.reader.at(root);
  var files = reader.libSources();
  var records = reader.collect(files);
  var primitives = records.primitives;
  var corpus = readTestCorpus(opts.testDir === undefined ? path.join(root, "test") : opts.testDir);
  var findings = [];
  var seen = {};
  var sources = {};
  var compared = 0;
  var optionalChecked = 0;
  var namespaceBlocks = 0;
  var checkedForExample = 0;
  var examplesCompiled = 0;
  var markerScans = 0;
  var bodiesRead = 0;

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

    var absolute = path.resolve(root, p.file);
    if (!Object.prototype.hasOwnProperty.call(sources, absolute)) {
      sources[absolute] = fs.readFileSync(absolute, "utf8");
    }
    var signature = signatureFindings(p, sources[absolute]);
    signature.findings.forEach(function (f) { finding(f.kind, p, f.msg); });
    if (signature.compared) compared += 1;
    if (signature.namespace) namespaceBlocks += 1;
    optionalChecked += signature.optionalChecked;

    var example = exampleFindings(p);
    example.findings.forEach(function (f) { finding(f.kind, p, f.msg); });
    if (example.checked) checkedForExample += 1;
    examplesCompiled += example.compiled;
    markerScans += example.scans;

    var ordering = orderingFindings(p);
    ordering.findings.forEach(function (f) { finding(f.kind, p, f.msg); });
    bodiesRead += ordering.read;
  });

  var wikiRun = wikiFindings(root, records);
  wikiRun.findings.forEach(function (f) {
    findings.push({ kind: f.kind, file: "lib", line: null, msg: f.msg });
  });
  moduleFindings(records.modules, wikiRun.built).forEach(function (f) {
    findings.push({ kind: f.kind, file: f.record.file, line: f.record.line, module: f.record.token, msg: f.msg });
  });

  return {
    findings: findings,
    examined: {
      "lib-source-files":         files.length,
      "primitive-blocks":         primitives.length,
      "signatures-compared":      compared,
      "optional-markers-checked": optionalChecked,
      "module-blocks":            records.modules.length,

      "primitives-checked-for-an-example": checkedForExample,
      "examples-parse-checked":            examplesCompiled,
      "example-marker-scans":              markerScans,
      "tag-bodies-read-for-prose":         bodiesRead,
    },
    namespaceBlocks: namespaceBlocks,
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
      var token = f.primitive || f.module;
      console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + (f.line ? ":" + f.line : "") +
                  (token ? " :: " + token : ""));
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

module.exports = {
  NAV_GROUPS:              NAV_GROUPS,
  SIGNATURE_FINDING_KINDS: SIGNATURE_FINDING_KINDS,
  MODULE_FINDING_KINDS:    MODULE_FINDING_KINDS,
  WIKI_FINDING_KINDS:      WIKI_FINDING_KINDS,
  EXAMPLE_FINDING_KINDS:   EXAMPLE_FINDING_KINDS,
  ORDERING_FINDING_KINDS:  ORDERING_FINDING_KINDS,
  EXAMPLE_MARKERS:         EXAMPLE_MARKERS,
  compileExample:          compileExample,
  exampleFindings:         exampleFindings,
  orderingFindings:        orderingFindings,
  isExercised:             isExercised,
  parseSignature:          parseSignature,
  signatureFindings:       signatureFindings,
  moduleFindings:          moduleFindings,
  wikiFindings:            wikiFindings,
  validate:                validate,
};

if (require.main === module) {
  process.exit(report(validate()));
}
