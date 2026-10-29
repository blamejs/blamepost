// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * web-link-origin: a link target this application renders is a path on
 * this server, and a message body cannot become a link that runs script.
 *
 * Two different guarantees meet on the same rendered page, and conflating
 * them is how one gets used to argue the other away:
 *
 *   - APPLICATION links: the navigation, paging and action targets the
 *     browser surface builds. Those are same-origin absolute paths, and
 *     nothing else. An off-site target here is either a redirect out of
 *     the reader's session or a scripting URI, and neither has any
 *     legitimate form.
 *   - MESSAGE-BODY links: whatever a sender wrote. Those may point
 *     anywhere, because mail that links to a web page is ordinary mail.
 *     What they may not do is carry a scheme the browser executes.
 *
 * So same-origin is asserted on the first and NOT on the second, and
 * scheme safety is asserted on the second and is not what makes the
 * first safe. Neither check substitutes for the other.
 *
 * ---------------------------------------------------------------------
 * Why this file exists at all
 *
 * The templates interpolate link targets into `href` and `action`
 * attributes. The engine HTML-escapes `{{ expr }}`, which stops an
 * attribute breakout and does NOT stop a `javascript:` URI, because
 * escaping leaves the scheme intact. So escaping is not the guard, and
 * there are two guards instead. Each template writes the leading slash of
 * a link itself, so the value it interpolates cannot choose a scheme. And
 * the value is built through a helper that composes the path refusal,
 * takes the slash off, and refuses a remainder beginning with a slash or a
 * backslash, which the template's slash would otherwise turn into a host.
 *
 * A helper enforces at the sites which CALL it. Nothing enforced that a
 * link-bearing value came from it, so the property was a convention held
 * by every producer remembering to. A convention held by memory is one
 * that a producer added next month does not inherit.
 *
 * What is asserted, in the order the value travels:
 *
 *   1. The templates are the inventory. Every URL-bearing attribute in
 *      `lib/web/views/` carrying an interpolation is discovered by
 *      reading the templates, never from a list kept here, so a NEW
 *      template participates the day it lands rather than the day
 *      somebody remembers to add it. Every one of them writes a slash
 *      and interpolates what follows it.
 *   2. Every value those attributes read is empty, or is built by a view
 *      field builder: a function recognized by its shape, which removes
 *      one leading character, refuses a remainder that begins with a slash
 *      or a backslash, throws, and composes a call that reaches the path
 *      refusal. A concatenation, a literal, a template literal, a value
 *      read off the request, and a path built for a redirect are each
 *      refused. Every producer file is searched for every value:
 *      `lib/web/index.js`, which builds the application's pages, and
 *      `lib/web/wiki/index.js`, which builds the reference wiki's pages
 *      under the key `wikiHref`. A call is followed into the file that
 *      defines it, which is either the producer or a module the producer
 *      requires, because both surfaces compose ONE reader rather than
 *      each holding a copy of the rule. Only a relative require is
 *      followed and the vendored tree is left out. Each producer keeps
 *      its own record of the builders the walk entered, and each has to
 *      yield assignments for the scan of it to count.
 *   3. The path refusal under that builder actually refuses. The browser
 *      surface composes `b.safeRedirect.resolve` and compares the answer
 *      to what it was given, so this drives that composition with the
 *      targets a browser follows off site: an authority behind a second
 *      slash or a backslash, one hidden behind a tab or a control byte, a
 *      scripting scheme, a bare absolute URL.
 *   4. The message-body sanitizer drops a URL attribute whose scheme the
 *      browser would execute, through every encoding that has been used
 *      to smuggle one past a sanitizer that folded less than a browser
 *      does.
 *   5. The sink. Every template is rendered through the shipped engine
 *      with hostile values at every link, and every rendered link is
 *      resolved the way a browser resolves it.
 *   6. The reader that builds a template's value refuses ALL FIVE of the
 *      characters that turn the template's own slash into the first
 *      character of a host name, and there is exactly one such reader
 *      under `lib/web/`. Sections 1 to 5 cannot see this: the path
 *      refusal beneath the builder already refuses every value whose
 *      second character is one of the five, so no input a test can hand
 *      the shipped composition reaches the leading-character check. It
 *      is a second line, and a second line with no reachable input can
 *      lose three of its five cases without a verdict changing.
 *
 * Anchors are shapes and frozen contracts rather than symbol names.
 * Nothing here names the private helper, so renaming it changes no
 * verdict; what would change a verdict is a value reaching an attribute
 * without being built, which is the property rather than the spelling.
 *
 * The scans carry canaries and publish their counts. A source scan that
 * has quietly stopped matching reports a clean tree, and a clean verdict
 * over an empty set answers for no part of it.
 *
 * No sockets, no containers, no disk beyond reading source text.
 *
 * Run standalone: node test/layer-0-primitives/web-link-origin.test.js
 */

var helpers = require("../helpers");

var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var WEB_ROOT   = path.join(helpers.REPO_ROOT, "lib", "web");
var VIEWS_DIR  = path.join(WEB_ROOT, "views");
var WEB_SOURCE = path.join(WEB_ROOT, "index.js");

// The files that build the values the templates interpolate. The browser
// surface builds its own pages, and the reference wiki builds the pages
// the surface serves under /wiki.
var PRODUCERS = [
  WEB_SOURCE,
  path.join(WEB_ROOT, "wiki", "index.js"),
];

// Control bytes, built from their code points so this file carries none
// of its own and a reader is never guessing which byte is on the line.
var TAB = String.fromCharCode(9);
var NL  = String.fromCharCode(10);
var CR  = String.fromCharCode(13);
var NUL = String.fromCharCode(0);
var VT  = String.fromCharCode(11);
var FF  = String.fromCharCode(12);

// The markup attributes whose value a browser resolves as a URL. The
// point is that the inventory is not "href" alone, because the same
// mistake in `src` or `formaction` is the same mistake, and the ones no
// template in this tree carries today are the ones nobody would think to
// look at when the first one lands.
var URL_ATTRS = [
  "href", "src", "srcset", "action", "formaction", "cite", "poster",
  "background", "ping", "manifest", "longdesc", "profile", "usemap",
  "codebase", "xlink:href", "data",
];

// A browser resolves the URL the same way whichever quoting the author
// chose, so the reader covers all three rather than the one this tree
// happens to be written in today. An unquoted value runs to the first
// space, quote, equals sign, angle bracket or backtick; an interpolation
// inside one is taken whole, because its own braces carry spaces that
// would otherwise end the value early. The two branches share no first
// character, so the run has one parse and cannot backtrack.
var UNQUOTED_VALUE = "(?:\\{\\{\\{?[^{}]*\\}?\\}\\}|[^\\s\"'=<>`{}])+";

function _urlAttrPattern(attrs) {
  return new RegExp(
    "\\b(" + attrs.join("|").replace(/:/g, "\\:") + ")\\s*=\\s*" +
    "(?:\"([^\"]*)\"|'([^']*)'|(" + UNQUOTED_VALUE + "))", "gi");
}

// The value one match carries, whichever of the three quotings it used.
function _attrValue(m) {
  if (m[2] !== undefined) return m[2];
  if (m[3] !== undefined) return m[3];
  return m[4];
}

var URL_ATTR_RE = _urlAttrPattern(URL_ATTRS);

// The template engine's delimiters. `{{ }}` escapes on the way out and
// `{{{ }}}` does not, and both are the engine's frozen syntax rather
// than anything this repository names.
var INTERPOLATION_RE = /\{\{\{?\s*([^{}]+?)\s*\}?\}\}/g;
var RAW_INTERPOLATION_RE = /\{\{\{\s*[^{}]+?\s*\}\}\}/;

// ---------------------------------------------------------------------------
// Reading the templates
// ---------------------------------------------------------------------------

function _templateFiles(dir, into) {
  into = into || [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var abs = path.join(dir, entry.name);
    if (entry.isDirectory()) { _templateFiles(abs, into); return; }
    if (/\.html$/.test(entry.name)) into.push(abs);
  });
  return into;
}

// Every URL-bearing attribute in one template whose value interpolates.
// Returns `{ file, line, attr, expr, raw, prefix }` per interpolation,
// where `raw` records the un-escaped `{{{ }}}` form and `prefix` is the
// literal text the template writes ahead of the first tag in the value.
function _linkSites(rel, text) {
  var out = [];
  URL_ATTR_RE.lastIndex = 0;
  var m;
  while ((m = URL_ATTR_RE.exec(text)) !== null) {
    var value = _attrValue(m);
    if (value.indexOf("{{") === -1) continue;
    var line = text.slice(0, m.index).split(/\r?\n/).length;
    var directive = value.indexOf("{%");
    var firstTag = directive === -1 ? value.indexOf("{{") : Math.min(directive, value.indexOf("{{"));
    INTERPOLATION_RE.lastIndex = 0;
    var inner;
    while ((inner = INTERPOLATION_RE.exec(value)) !== null) {
      out.push({
        file:   rel,
        line:   line,
        attr:   m[1].toLowerCase(),
        expr:   inner[1].trim(),
        raw:    RAW_INTERPOLATION_RE.test(inner[0]),
        prefix: value.slice(0, firstTag),
      });
    }
  }
  return out;
}

// Why a template's own text ahead of a link value does not hold the
// value to a path on this server, or null when it does. The prefix has to
// be exactly one slash, which is the form a view field builder produces
// the rest of. Nothing written ahead of the value leaves the scheme to the
// value. A second slash, a backslash or a control byte after the first
// leaves the host to it. A fragment mark, a scheme or a longer path is a
// position no view field builder produces a value for, so it fails here
// until a reader for that position is written beside the template that
// needs one.
function _prefixVerdict(prefix) {
  if (prefix === "/") return null;
  if (prefix.length === 0) {
    return "the value is interpolated with nothing written ahead of it, so whatever reaches " +
      "the attribute chooses the scheme and the host. Write the slash in the template";
  }
  return "the template writes " + JSON.stringify(prefix) + " ahead of the value, which is not " +
    "the single slash a view field builder produces the rest of";
}

// The property an interpolation finally reads. `m.imagesHref` is fed by
// whatever set `imagesHref`, and the object it hangs off is a loop
// variable that names nothing on its own.
function _leafKey(expr) {
  var parts = expr.split(".");
  return parts[parts.length - 1].trim();
}

// ---------------------------------------------------------------------------
// Reading the producer
// ---------------------------------------------------------------------------

// The value expression assigned to `key:` starting at `from`, up to the
// comma or brace that ends it. Depth-aware and string-aware, so a comma
// inside a call's arguments or inside a literal does not end the value.
function _valueAfter(text, from) {
  var depth = 0;
  var quote = "";
  var i = from;
  for (; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break;
      depth -= 1;
      continue;
    }
    if (c === "," && depth === 0) break;
  }
  return text.slice(from, i).trim();
}

// Positions at depth zero and outside any string, for splitting an
// expression on its own operators rather than on a nested one.
function _topLevel(expr) {
  var spots = [];
  var depth = 0;
  var quote = "";
  for (var i = 0; i < expr.length; i += 1) {
    var c = expr.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") {
      spots.push({ at: i, ch: "string", quote: c });
      quote = c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c === ")" || c === "]" || c === "}") { depth -= 1; continue; }
    if (depth === 0) spots.push({ at: i, ch: c });
  }
  return spots;
}

// The value branches of a conditional, discarding the condition. A
// non-conditional is one branch. `?.` and `??` are not conditionals and
// are stepped over rather than split on.
function _branches(expr) {
  var spots = _topLevel(expr);
  var qAt = -1;
  for (var i = 0; i < spots.length; i += 1) {
    if (spots[i].ch !== "?") continue;
    var next = expr.charAt(spots[i].at + 1);
    if (next === "." || next === "?") continue;
    qAt = spots[i].at;
    break;
  }
  if (qAt === -1) return [expr.trim()];
  // The `:` that pairs with this `?`, skipping any nested conditional.
  var pending = 0;
  var cAt = -1;
  for (var j = 0; j < spots.length; j += 1) {
    if (spots[j].at <= qAt) continue;
    if (spots[j].ch === "?") { pending += 1; continue; }
    if (spots[j].ch !== ":") continue;
    if (pending > 0) { pending -= 1; continue; }
    cAt = spots[j].at;
    break;
  }
  if (cAt === -1) return [expr.trim()];
  return _branches(expr.slice(qAt + 1, cAt)).concat(_branches(expr.slice(cAt + 1)));
}

var STRING_LITERAL_RE = /^(["'])((?:[^\\]|\\.)*?)\1$/;
var CALL_RE           = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\(/;
var IDENTIFIER_RE     = /^[A-Za-z_$][\w$]*$/;
// A read off the request, under the names the browser surface binds it
// to. A target chosen by whoever sent the request is the hostile case
// this whole file is about, and it must never reach an attribute without
// being built.
var REQUEST_READ_RE   = /\b(?:req|request)\s*\.|\.\s*(?:query|body|params|headers)\b/;

// Every value an identifier is bound to in the producer.
// `var base = _folderPath(folder);` is a built value under another name,
// and each binding is classified the same way an assignment is, so the
// name buys nothing: the target it stands for is followed to the refusal
// exactly as though it had been written at the attribute.
function _bindingsOf(source, name) {
  var re = new RegExp("\\b(?:var|let|const)\\s+" + name + "\\s*=\\s*([^;\\n]+)", "g");
  var out = [];
  var m;
  while ((m = re.exec(source.text)) !== null) out.push(m[1].trim());
  return out;
}

// ---------------------------------------------------------------------------
// A producer and the modules it requires
//
// A link target is built by a reader both surfaces compose rather than by
// a copy in each of them, so a call written `links.href(x)` has to be
// followed into the file that defines `href`. A walk that stopped at the
// dot would report every shipped link as unbuilt, and the obvious way to
// quiet it is to put the rule back in both files, which is the drift the
// shared reader exists to remove.
//
// Only a RELATIVE require resolves, and the vendored tree is left out. A
// framework call is not a function this repository defines, and a walk
// that entered `lib/vendor/` would be answering for code this repository
// does not write.
// ---------------------------------------------------------------------------

var LOCAL_REQUIRE_RE =
  /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*"(\.[^"]*)"\s*\)/g;

var VENDOR_SEGMENT = ["lib", "vendor"].join("/");

// The file a relative require names, or null when it names none this walk
// follows: a directory with no `index.js`, a JSON document, or anything
// inside the vendored tree.
function _moduleFile(base) {
  var tries = [base, base + ".js", path.join(base, "index.js")];
  for (var i = 0; i < tries.length; i += 1) {
    var rel = path.relative(helpers.REPO_ROOT, tries[i]).replace(/\\/g, "/");
    if (rel.indexOf(VENDOR_SEGMENT) === 0 || !/\.js$/.test(tries[i])) continue;
    try {
      if (fs.statSync(tries[i]).isFile()) return tries[i];
    } catch (_missing) {
      // Drop-silent by design: a path that is not a file is simply not the
      // module, and the next candidate spelling is tried.
      continue;
    }
  }
  return null;
}

// One source file and the local modules it requires, transitively. `seen`
// is keyed by absolute path so a module required from two places is read
// once and a require cycle terminates.
function _bundleFor(abs, seen) {
  var key = abs.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(seen, key)) return seen[key];

  var bundle = {
    rel:     path.relative(helpers.REPO_ROOT, abs).replace(/\\/g, "/"),
    text:    fs.readFileSync(abs, "utf8"),
    modules: {},
  };
  seen[key] = bundle;

  var dir = path.dirname(abs);
  var found = [];
  LOCAL_REQUIRE_RE.lastIndex = 0;
  var m;
  while ((m = LOCAL_REQUIRE_RE.exec(bundle.text)) !== null) {
    found.push([m[1], path.resolve(dir, m[2])]);
  }
  found.forEach(function (entry) {
    var file = _moduleFile(entry[1]);
    if (file !== null) bundle.modules[entry[0]] = _bundleFor(file, seen);
  });
  return bundle;
}

// A source string on its own, for the proofs below, which write one file
// at a time and require nothing.
function _asBundle(source) {
  return typeof source === "string"
    ? { rel: "<proof>", text: source, modules: {} }
    : source;
}

// A callee resolved to the bundle that defines it. `_href` is this file's
// own function; `links.href` is the shared reader's. Null when the head
// names no local module, when the property is deeper than one level, or
// when the module defines no function under that name, each of which is a
// call this walk cannot establish and must refuse rather than assume.
function _calleeIn(source, name) {
  var dot = name.indexOf(".");
  if (dot === -1) {
    return _functionBody(source, name) === null ? null : { bundle: source, name: name };
  }
  var head = name.slice(0, dot);
  var rest = name.slice(dot + 1);
  if (rest.indexOf(".") !== -1) return null;
  var target = source.modules[head];
  if (!target || _functionBody(target, rest) === null) return null;
  return { bundle: target, name: rest };
}

// The key a walked function is recorded under. Qualified by file, because
// two modules may each define a `href` and the verdicts differ.
function _walkKey(prefix, at) {
  return prefix + at.bundle.rel + "#" + at.name;
}

// The function a walk key names, or null when the key records an
// identifier rather than a function.
function _walkedAt(bundles, key) {
  var hash = key.indexOf("#");
  if (hash === -1) return null;
  var bundle = bundles[key.slice(0, hash)];
  return bundle === undefined ? null : { bundle: bundle, name: key.slice(hash + 1) };
}

// ---------------------------------------------------------------------------
// Following a builder to the refusal underneath it
//
// A link target reaching an attribute through a call is not yet a target
// anything screened: the call has to arrive at the refusal. So a call is
// followed to the function this file defines under that name, its returns
// are classified by the same reader, and the walk ends at the refusal
// itself. A builder returning "//evil.example/x" is refused at every link
// target that reads it, however many helpers sit between the two.
//
// The refusal is recognized by its SHAPE: it compares the framework's
// resolved target against the value it was handed, and throws on anything
// else. Renaming it changes no verdict. Taking either half of that
// composition away stops it being recognized, which is the case worth
// failing on.
// ---------------------------------------------------------------------------

var REFUSAL_RESOLVE_RE = /safeRedirect\s*\.\s*resolve\s*\(/;
var REFUSAL_COMPARE_RE = /===\s*[A-Za-z_$][\w$]*\s*\)/;
var REFUSAL_THROW_RE   = /\bthrow\b/;

function _isTheRefusal(body) {
  return REFUSAL_RESOLVE_RE.test(body) &&
         REFUSAL_COMPARE_RE.test(body) &&
         REFUSAL_THROW_RE.test(body);
}

var CALLEE_RE = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/;

// Comment text replaced by spaces. A brace or a `return` inside prose is
// not code, and a reader that counted one would walk to the wrong place
// or classify a sentence.
function _uncommented(text) {
  var out = "";
  var mode = "";
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charAt(i);
    var two = text.substr(i, 2);
    if (mode === "//") {
      if (c === "\n") { mode = ""; out += c; continue; }
      out += " ";
      continue;
    }
    if (mode === "/*") {
      if (two === "*/") { mode = ""; out += "  "; i += 1; continue; }
      out += (c === "\n" ? c : " ");
      continue;
    }
    if (mode) {
      out += c;
      if (c === "\\") { out += text.charAt(i + 1); i += 1; continue; }
      if (c === mode) mode = "";
      continue;
    }
    if (two === "//") { mode = "//"; out += "  "; i += 1; continue; }
    if (two === "/*") { mode = "/*"; out += "  "; i += 1; continue; }
    if (c === "\"" || c === "'" || c === BACKTICK) { mode = c; out += c; continue; }
    out += c;
  }
  return out;
}

// The matching closer for the grouping character at `from`, counted
// rather than measured off the layout. A bound on the indentation of a
// closing brace stops matching the first time a helper moves inside
// another function, and a reader that has stopped matching passes.
function _matchAt(text, from, open, close) {
  var depth = 0;
  var quote = "";
  for (var i = from; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === BACKTICK) { quote = c; continue; }
    if (c === open) { depth += 1; continue; }
    if (c !== close) continue;
    depth -= 1;
    if (depth === 0) return i;
  }
  return -1;
}

// One function's body, comments already gone. The parameter list is
// walked before the body's brace is looked for, so a default value or a
// destructured parameter carrying a brace does not decide where the body
// starts.
function _functionBody(source, name) {
  var re = new RegExp("\\bfunction\\s+" + name + "\\s*\\(");
  var text = _uncommented(source.text);
  var m = re.exec(text);
  if (m === null) return null;
  var paren = text.indexOf("(", m.index);
  if (paren === -1) return null;
  var endParen = _matchAt(text, paren, "(", ")");
  if (endParen === -1) return null;
  var open = text.indexOf("{", endParen);
  if (open === -1) return null;
  var close = _matchAt(text, open, "{", "}");
  if (close === -1) return null;
  return text.slice(open + 1, close);
}

// Every value a body returns.
function _returnsIn(body) {
  var out = [];
  var re = /\breturn\b/g;
  var m;
  while ((m = re.exec(body)) !== null) {
    var from = m.index + m[0].length;
    var depth = 0;
    var quote = "";
    var i = from;
    for (; i < body.length; i += 1) {
      var c = body.charAt(i);
      if (quote) {
        if (c === "\\") { i += 1; continue; }
        if (c === quote) quote = "";
        continue;
      }
      if (c === "\"" || c === "'" || c === BACKTICK) { quote = c; continue; }
      if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
      if (c === ")" || c === "]" || c === "}") {
        if (depth === 0) break;
        depth -= 1;
        continue;
      }
      if (c === ";" && depth === 0) break;
    }
    var value = body.slice(from, i).trim();
    if (value.length > 0) out.push(value);
  }
  return out;
}

// ---------------------------------------------------------------------------

function _isRootRelative(value, b) {
  return typeof value === "string" && value.charAt(0) === "/" &&
         b.safeRedirect.resolve(value, { fallback: "" }) === value;
}

// An expression wrapped whole in one pair of parentheses, unwrapped. A
// nested conditional is ordinarily written that way, and a reader that
// refused it would be firing on the correct shape, which is how a gate
// teaches people to route around it. Unwrapping weakens nothing: a
// concatenation in parentheses is still a concatenation once the
// parentheses come off.
function _unwrap(expr) {
  var s = expr.trim();
  if (s.charAt(0) !== "(") return s;
  var depth = 0;
  var quote = "";
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") { quote = c; continue; }
    if (c === "(") { depth += 1; continue; }
    if (c !== ")") continue;
    depth -= 1;
    if (depth > 0) continue;
    return i === s.length - 1 ? _unwrap(s.slice(1, -1)) : s;
  }
  return s;
}

// One assigned value, classified. Returns null when it is constrained by
// construction, or the reason it is not.
//
// `walked` carries the verdict already reached for each builder this scan
// has followed, so a helper reached from two link targets is walked once
// and the record of what was followed survives the call for the count to
// publish. A builder that reaches itself is marked while it is being
// walked and its own edge contributes nothing, so the recursion ends and
// the other returns decide.
function _classify(branch, source, b, walked) {
  var seen = walked || {};
  var expr = _unwrap(branch);
  if (expr.length === 0) return "the value is empty text, which parses as nothing at all";

  // Unwrapping can expose a conditional that was written in
  // parentheses, so its branches are classified rather than the whole.
  if (expr !== branch.trim()) {
    var inner = _branches(expr);
    if (inner.length > 1 || inner[0] !== expr) {
      var reasons = inner
        .map(function (part) { return _classify(part, source, b, seen); })
        .filter(function (r) { return r !== null; });
      return reasons.length === 0 ? null : reasons[0];
    }
  }

  var literal = STRING_LITERAL_RE.exec(expr);
  if (literal) {
    var body = literal[2];
    if (body.length === 0) return null;                // "" renders no link at all
    if (!_isRootRelative(body, b)) {
      return "the literal " + JSON.stringify(body) + " is not an absolute path on this " +
             "server, so a browser following it would leave this origin";
    }
    return null;
  }

  if (REQUEST_READ_RE.test(expr)) {
    return "the value is read off the request, so whoever sent it chooses where the link " +
           "points. Build the target instead, so the guard sees it";
  }

  var spots = _topLevel(expr);
  for (var i = 0; i < spots.length; i += 1) {
    if (spots[i].ch === "+") {
      return "the value is concatenated in place rather than built, so nothing screens " +
             "what the pieces say. Wrap the concatenation in the helper that returns a " +
             "link target";
    }
    if (spots[i].ch === "string" && spots[i].quote === "`") {
      return "the value is a template literal assembled in place rather than built, so " +
             "nothing screens what it interpolates";
    }
  }

  if (CALL_RE.test(expr)) return _followsToTheRefusal(expr, source, b, seen);

  if (IDENTIFIER_RE.test(expr)) {
    var idKey = "identifier " + expr;
    if (Object.prototype.hasOwnProperty.call(seen, idKey)) {
      return seen[idKey] === "walking" ? null : seen[idKey];
    }
    seen[idKey] = "walking";

    var bindings = _bindingsOf(source, expr);
    if (bindings.length === 0) {
      seen[idKey] = "the value is the identifier '" + expr + "', and nothing in this file " +
        "binds it, so what reaches the attribute cannot be established here";
      return seen[idKey];
    }
    var bindingVerdict = null;
    for (var k = 0; k < bindings.length && bindingVerdict === null; k += 1) {
      var why = _classify(bindings[k], source, b, seen);
      if (why !== null) {
        bindingVerdict = "the value is the identifier '" + expr + "', and one binding of " +
          "it is not a built target: " + why;
      }
    }
    seen[idKey] = bindingVerdict;
    return bindingVerdict;
  }

  return "the value is an expression this gate cannot establish as a built target: " + expr;
}

// A call, followed to what it returns. Null when every path out of the
// builder reaches the refusal, and the reason it does not otherwise.
function _followsToTheRefusal(expr, source, b, walked) {
  var matched = CALLEE_RE.exec(expr.trim());
  var name = matched === null ? "" : matched[1];

  var at = name.length === 0 ? null : _calleeIn(source, name);
  if (at === null) {
    return "the value comes from '" + name + "()', which is not a function this file " +
           "defines and not one a module it requires defines, so what it returns is not " +
           "established. Build the target through the helper that refuses anything off " +
           "this origin";
  }

  var key = _walkKey("", at);
  if (Object.prototype.hasOwnProperty.call(walked, key)) {
    // A builder already walked, or one being walked right now, which is
    // this call reaching itself. Neither adds a verdict.
    return walked[key] === "walking" ? null : walked[key];
  }
  walked[key] = "walking";

  var body = _functionBody(at.bundle, at.name);

  if (_isTheRefusal(body)) {
    walked[key] = null;
    return null;
  }

  var returns = _returnsIn(body);
  if (returns.length === 0) {
    walked[key] = "'" + name + "()' returns no value this reader can find, so the target " +
      "it produces is not established";
    return walked[key];
  }

  var verdict = null;
  for (var i = 0; i < returns.length && verdict === null; i += 1) {
    var reason = _classify(returns[i], at.bundle, b, walked);
    if (reason !== null) {
      verdict = "'" + name + "()' can return a target that never reaches the refusal: " +
        reason;
    }
  }
  walked[key] = verdict;
  return verdict;
}

// ---------------------------------------------------------------------------
// Following a view field to the builder that takes its slash off
//
// A template writes the leading slash of a link and interpolates the rest,
// so a view field holds a path with its first character removed. A path
// handed to a template instead renders as two slashes and a host. So a
// view field is followed to a VIEW FIELD builder, recognized by its shape:
// the body removes one leading character, compares what is left against a
// slash and against a backslash, throws, and makes a call this file
// defines that reaches the path refusal above. Renaming it changes no
// verdict. Taking away the leading-character refusal, or the path refusal
// under it, stops it being recognized.
//
// The walk records view field verdicts under keys of their own, beside the
// path refusal's, because one function can be followed both ways and the
// answers differ: the path refusal is the right builder for a redirect and
// the wrong one for a template.
// ---------------------------------------------------------------------------

var VIEW_FIELD_TRIM_RE      = /\.\s*(?:slice|substring|substr)\s*\(\s*1\s*\)/;
var VIEW_FIELD_SLASH_RE     = /===\s*"\/"|"\/"\s*===/;
var VIEW_FIELD_BACKSLASH_RE = /===\s*"\\\\"|"\\\\"\s*===/;
var VIEW_FIELD_WALK         = "view field ";

function _isTheViewFieldRefusal(body, source, b, walked) {
  if (!VIEW_FIELD_TRIM_RE.test(body) || !VIEW_FIELD_SLASH_RE.test(body) ||
      !VIEW_FIELD_BACKSLASH_RE.test(body) || !REFUSAL_THROW_RE.test(body)) {
    return false;
  }
  // A bare call and a call through a required module both count, because
  // the path half may live beside the view field half or in the shared
  // reader they both compose.
  var calls = /(^|[^\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(/g;
  var m;
  while ((m = calls.exec(body)) !== null) {
    if (_calleeIn(source, m[2]) === null) continue;
    if (_followsToTheRefusal(m[2] + "()", source, b, walked) === null) return true;
  }
  return false;
}

// One view field value, classified. Null when it is empty or is built by a
// view field builder, and the reason otherwise.
function _classifyViewField(branch, source, b, walked) {
  var seen = walked || {};
  var expr = _unwrap(branch);
  if (expr.length === 0) return "the value is empty text, which parses as nothing at all";

  if (expr !== branch.trim()) {
    var inner = _branches(expr);
    if (inner.length > 1 || inner[0] !== expr) {
      var reasons = inner
        .map(function (part) { return _classifyViewField(part, source, b, seen); })
        .filter(function (r) { return r !== null; });
      return reasons.length === 0 ? null : reasons[0];
    }
  }

  var literal = STRING_LITERAL_RE.exec(expr);
  if (literal) {
    var body = literal[2];
    // "" renders no link behind a condition, and the root behind a slash.
    if (body.length === 0) return null;
    if (_isRootRelative(body, b)) {
      return "the literal " + JSON.stringify(body) + " begins with a slash, and the template " +
        "writes one of its own in front of it, so the link renders as two slashes and a host";
    }
    return "the literal " + JSON.stringify(body) + " reaches the template without passing a " +
      "view field builder, so nothing screened what it says";
  }

  if (REQUEST_READ_RE.test(expr)) {
    return "the value is read off the request, so whoever sent it chooses where the link " +
           "points. Build the value instead, so the builder sees it";
  }

  var spots = _topLevel(expr);
  for (var i = 0; i < spots.length; i += 1) {
    if (spots[i].ch === "+") {
      return "the value is concatenated in place rather than built, so nothing screens " +
             "what the pieces say. Hand the whole path to the view field builder";
    }
    if (spots[i].ch === "string" && spots[i].quote === "`") {
      return "the value is a template literal assembled in place rather than built, so " +
             "nothing screens what it interpolates";
    }
  }

  if (CALL_RE.test(expr)) return _followsToTheViewFieldRefusal(expr, source, b, seen);

  if (IDENTIFIER_RE.test(expr)) {
    var idKey = VIEW_FIELD_WALK + "identifier " + expr;
    if (Object.prototype.hasOwnProperty.call(seen, idKey)) {
      return seen[idKey] === "walking" ? null : seen[idKey];
    }
    seen[idKey] = "walking";
    var bindings = _bindingsOf(source, expr);
    if (bindings.length === 0) {
      seen[idKey] = "the value is the identifier '" + expr + "', and nothing in this file " +
        "binds it, so what reaches the attribute cannot be established here";
      return seen[idKey];
    }
    var bindingVerdict = null;
    for (var k = 0; k < bindings.length && bindingVerdict === null; k += 1) {
      var why = _classifyViewField(bindings[k], source, b, seen);
      if (why !== null) {
        bindingVerdict = "the value is the identifier '" + expr + "', and one binding of " +
          "it is not a built view field: " + why;
      }
    }
    seen[idKey] = bindingVerdict;
    return bindingVerdict;
  }

  return "the value is an expression this gate cannot establish as a built view field: " + expr;
}

// A call, followed to a view field builder. Null when every path out of the
// callee reaches one, and the reason it does not otherwise.
function _followsToTheViewFieldRefusal(expr, source, b, walked) {
  var matched = CALLEE_RE.exec(expr.trim());
  var name = matched === null ? "" : matched[1];

  var at = name.length === 0 ? null : _calleeIn(source, name);
  if (at === null) {
    return "the value comes from '" + name + "()', which is not a function this file " +
           "defines and not one a module it requires defines, so what it returns is not " +
           "established. Build the value through the view field builder";
  }

  var key = _walkKey(VIEW_FIELD_WALK, at);
  if (Object.prototype.hasOwnProperty.call(walked, key)) {
    return walked[key] === "walking" ? null : walked[key];
  }
  walked[key] = "walking";

  var body = _functionBody(at.bundle, at.name);

  if (_isTheRefusal(body)) {
    walked[key] = "'" + name + "()' is the path refusal itself. What it returns begins with a " +
      "slash, and the template writes one of its own in front of it, so the link renders as " +
      "two slashes and a host";
    return walked[key];
  }

  if (_isTheViewFieldRefusal(body, at.bundle, b, walked)) {
    walked[key] = null;
    return null;
  }

  var returns = _returnsIn(body);
  if (returns.length === 0) {
    walked[key] = "'" + name + "()' returns no value this reader can find, so the value it " +
      "produces is not established";
    return walked[key];
  }

  var verdict = null;
  for (var i = 0; i < returns.length && verdict === null; i += 1) {
    var reason = _classifyViewField(returns[i], at.bundle, b, walked);
    if (reason !== null) {
      verdict = "'" + name + "()' can return a value that never reaches a view field " +
        "builder: " + reason;
    }
  }
  walked[key] = verdict;
  return verdict;
}

// Every assignment of `key` in `source`, classified as a view field. One
// function so the live scan and the self-proof below run the SAME reader: a
// proof that exercised a second copy would establish that the copy still
// fires.
function _assignmentsOf(source, key, b, walked) {
  var bundle = _asBundle(source);
  var text = bundle.text;
  var seen = walked || {};
  var out = [];
  var re = new RegExp("(?:^|[\\s{,])" + key + "\\s*:", "g");
  var m;
  while ((m = re.exec(text)) !== null) {
    // A colon inside a comment is prose about the property rather than
    // an assignment of it.
    var lineStart = text.lastIndexOf("\n", m.index) + 1;
    var before = text.slice(lineStart, m.index);
    if (/^\s*(?:\/\/|\*|\/\*)/.test(before) || before.indexOf("//") !== -1) continue;

    var value = _valueAfter(text, m.index + m[0].length);
    out.push({
      line:  text.slice(0, m.index).split(/\r?\n/).length,
      value: value,
      reasons: _branches(value)
        .map(function (branch) { return _classifyViewField(branch, bundle, b, seen); })
        .filter(function (r) { return r !== null; }),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// The reader proves itself on this run rather than on the day it was
// written. Each shape below is a way a link target reaches an attribute
// without being built; a reader that has stopped recognizing one of them
// passes the live scan by seeing nothing, which is the failure a green
// verdict cannot be told apart from.
// ---------------------------------------------------------------------------

var BACKTICK = String.fromCharCode(96);

// The refusal, written out for the proofs below. It is the composition
// the browser surface builds a link target with, under a name nothing in
// the tree uses, so what the reader recognizes is the SHAPE and not a
// spelling it was handed.
var REFUSAL_SOURCE =
  "function _p(v) {\n" +
  "  if (typeof v === \"string\" && v.charAt(0) === \"/\" &&\n" +
  "      b.safeRedirect.resolve(v, { fallback: \"\" }) === v) {\n" +
  "    return v;\n" +
  "  }\n" +
  "  throw new TypeError(\"not a path on this server\");\n" +
  "}";

// A view field builder over that refusal, written under a name nothing in
// the tree uses either.
function _viewFieldSource(name, pathBuilder) {
  return "function " + name + "(value) {\n" +
    "  var tail = " + pathBuilder + "(value).slice(1);\n" +
    "  var first = tail.charAt(0);\n" +
    "  if (first === \"/\" || first === \"\\\\\") {\n" +
    "    throw new TypeError(\"not a view field\");\n" +
    "  }\n" +
    "  return tail;\n" +
    "}";
}

var VIEW_FIELD_SOURCE = REFUSAL_SOURCE + "\n" + _viewFieldSource("_v", "_p");

// A producer beside the modules it requires, for the cross-module vectors
// below. The shipped surfaces build their values through a reader in
// another file, so the walk has to follow a call through a required module
// and has to keep refusing everything it refused before it could.
function _proofBundle(text, modules) {
  var bundle = { rel: "<proof>", text: text, modules: {} };
  Object.keys(modules).forEach(function (name) {
    bundle.modules[name] = { rel: "<proof:" + name + ">", text: modules[name], modules: {} };
  });
  return bundle;
}

function theReaderStillRefusesWhatItIsFor(b) {
  var red = [
    ["a value concatenated in place",
      "var view = { probeHref: \"mail/\" + name };"],
    ["a value read straight off the request",
      "var view = { probeHref: req.query.next };"],
    ["a value assembled in a template literal",
      "var view = { probeHref: " + BACKTICK + "mail/${name}" + BACKTICK + " };"],
    ["a literal that leaves this origin behind a second slash",
      "var view = { probeHref: \"//evil.example/x\" };"],
    ["a literal carrying a scripting scheme",
      "var view = { probeHref: \"javascript:alert(1)\" };"],
    ["a literal that is not a path at all",
      "var view = { probeHref: \"https://evil.example/x\" };"],
    ["a root-relative literal, which the template's own slash turns into two",
      "var view = { probeHref: \"/admin/domains\" };"],
    ["a literal written without its slash, which nothing screened",
      "var view = { probeHref: \"admin/domains\" };"],
    ["an identifier nothing in the file binds",
      "var view = { probeHref: mystery };"],
    ["an identifier bound to something that was never built",
      "var target = req.query.next;\nvar view = { probeHref: target };"],
    ["one good branch and one concatenated branch",
      VIEW_FIELD_SOURCE + "\n" +
      "var view = { probeHref: ok ? _v(\"/a\") : \"mail/\" + name };"],
    ["a builder nothing in the file defines",
      "var view = { probeHref: _nowhere(1) };"],
    ["a path built by the refusal and handed straight to a template",
      REFUSAL_SOURCE + "\n" +
      "var view = { probeHref: _p(\"/admin/queue\") };"],
    ["a path builder over the refusal handed to a template",
      REFUSAL_SOURCE + "\n" +
      "function _folderPath(f) { return _p(\"/mail/\" + f); }\n" +
      "var view = { probeHref: _folderPath(folder) };"],
    ["a view field builder's value with more written after it",
      VIEW_FIELD_SOURCE + "\n" +
      "var view = { probeHref: _v(\"/\") + \"/evil.example\" };"],
    ["a builder that returns a literal off this origin",
      "function _made() { return \"//evil.example/x\"; }\n" +
      "var view = { probeHref: _made(1) };"],
    ["a builder that returns what the request asked for",
      "function _made(req) { return req.query.next; }\n" +
      "var view = { probeHref: _made(req) };"],
    ["a builder that concatenates without reaching a view field builder",
      "function _made(n) { return \"mail/\" + n; }\n" +
      "var view = { probeHref: _made(n) };"],
    ["a builder one hop above another that never refuses",
      "function _outer(n) { return _inner(n); }\n" +
      "function _inner(n) { return \"//evil.example/\" + n; }\n" +
      "var view = { probeHref: _outer(1) };"],
    ["a builder with one good return and one that is not",
      VIEW_FIELD_SOURCE + "\n" +
      "function _made(n) { if (n) { return _v(\"/a\"); } return \"//evil.example/x\"; }\n" +
      "var view = { probeHref: _made(1) };"],
    ["a view field builder that refuses a second slash and not a backslash",
      REFUSAL_SOURCE + "\n" +
      "function _v(value) { var tail = _p(value).slice(1); " +
      "if (tail.charAt(0) === \"/\") { throw new TypeError(\"x\"); } return tail; }\n" +
      "var view = { probeHref: _v(\"/a\") };"],
    ["a view field builder whose path half never reaches the refusal",
      "function _made(n) { return \"/mail/\" + n; }\n" + _viewFieldSource("_v", "_made") + "\n" +
      "var view = { probeHref: _v(\"x\") };"],
    ["a view field builder over a refusal that has lost the compare that makes it one",
      "function _p(v) { if (typeof v === \"string\") { return v; } throw new TypeError(\"no\"); }\n" +
      _viewFieldSource("_v", "_p") + "\n" +
      "var view = { probeHref: _v(\"/mail/x\") };"],
    ["a value from a method call, which is not a function this file defines",
      "var view = { probeHref: someObject.buildTarget(1) };"],
  ];
  red.forEach(function (v) {
    var found = _assignmentsOf("// " + v[0] + "\n" + v[1], "probeHref", b);
    count("the reader refuses " + v[0],
      found.length === 1 && found[0].reasons.length > 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  var green = [
    ["a value built by a view field builder",
      VIEW_FIELD_SOURCE + "\n" +
      "var view = { probeHref: _v(\"/admin/queue\") };"],
    ["the same builder under another name",
      REFUSAL_SOURCE + "\n" + _viewFieldSource("_asViewLink", "_p") + "\n" +
      "var view = { probeHref: _asViewLink(\"/admin/queue\") };"],
    ["a view field builder handed a concatenation",
      VIEW_FIELD_SOURCE + "\n" +
      "var base = _p(\"/mail/x\");\n" +
      "var view = { probeHref: _v(base + \"?before=\" + cursor) };"],
    ["an empty value, which renders no link",
      "var view = { probeHref: \"\" };"],
    ["a conditional whose branches are both fine",
      VIEW_FIELD_SOURCE + "\n" +
      "function _inboxPath(a) { return _p(\"/mail/INBOX\"); }\n" +
      "var view = { probeHref: account ? _v(_inboxPath(account)) : \"\" };"],
    ["an identifier bound to a built view field",
      VIEW_FIELD_SOURCE + "\n" +
      "var link = _v(\"/mail/x\");\nvar view = { probeHref: link };"],
    ["a nested conditional of built view fields",
      VIEW_FIELD_SOURCE + "\n" +
      "var view = { probeHref: a ? _v(\"/x\") : (bq ? _v(\"/y\") : \"\") };"],
    ["a builder that hands its path to a view field builder",
      VIEW_FIELD_SOURCE + "\n" +
      "function _made(n) { return _v(\"/mail/\" + n); }\n" +
      "var view = { probeHref: _made(1) };"],
    ["a builder two hops above a view field builder",
      VIEW_FIELD_SOURCE + "\n" +
      "function _mid(n) { return _v(\"/mail/\" + n); }\n" +
      "function _outer(n) { return _mid(n); }\n" +
      "var view = { probeHref: _outer(1) };"],
    ["a view field builder over a path builder two hops above the refusal",
      REFUSAL_SOURCE + "\n" +
      "function _folderPath(f) { return _p(\"/mail/\" + f); }\n" +
      _viewFieldSource("_v", "_folderPath") + "\n" +
      "var view = { probeHref: _v(\"INBOX\") };"],
    ["a builder whose every return is built",
      VIEW_FIELD_SOURCE + "\n" +
      "function _made(n) { if (n) { return _v(\"/a\"); } if (!n) { return _v(\"/b\"); } " +
      "return _v(\"/c\"); }\n" +
      "var view = { probeHref: _made(1) };"],
    ["a builder that reaches itself, which is a walk rather than a hole",
      VIEW_FIELD_SOURCE + "\n" +
      "function _made(n) { if (n > 1) { return _made(n - 1); } return _v(\"/a\"); }\n" +
      "var view = { probeHref: _made(2) };"],
    ["a builder carrying prose about a value it must never return",
      VIEW_FIELD_SOURCE + "\n" +
      "function _made(n) {\n  // Never return \"//evil.example/x\" from here.\n" +
      "  return _v(\"/mail/\" + n);\n}\n" +
      "var view = { probeHref: _made(1) };"],
  ];
  green.forEach(function (v) {
    var found = _assignmentsOf("// " + v[0] + "\n" + v[1], "probeHref", b);
    count("and it stays silent on " + v[0],
      found.length === 1 && found[0].reasons.length === 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  // Across a module boundary. The walk follows a call through a module the
  // producer requires, and every refusal it makes inside one file it makes
  // through one: a shared reader that never refuses is a shared way to
  // render a link to another host.
  var crossRed = [
    ["a required module whose builder concatenates instead of refusing",
      "var view = { probeHref: links.href(n) };",
      { links: "function href(n) { return \"mail/\" + n; }" }],
    ["a required module that hands back what the request asked for",
      "var view = { probeHref: links.href(req) };",
      { links: "function href(req) { return req.query.next; }" }],
    ["a required module whose builder refuses a slash and not a backslash",
      "var view = { probeHref: links.href(\"/a\") };",
      { links: REFUSAL_SOURCE + "\nfunction href(value) { var tail = _p(value).slice(1); " +
        "if (tail.charAt(0) === \"/\") { throw new TypeError(\"x\"); } return tail; }" }],
    ["a required module whose path half never reaches the refusal",
      "var view = { probeHref: links.href(\"x\") };",
      { links: "function _made(n) { return \"/mail/\" + n; }\n" +
        _viewFieldSource("href", "_made") }],
    ["a required module that returns the path itself, which the template's slash doubles",
      "var view = { probeHref: links.path(\"/admin/queue\") };",
      { links: REFUSAL_SOURCE.split("_p").join("path") }],
    ["a call through a module name nothing in the file requires",
      "var view = { probeHref: links.href(\"/a\") };",
      {}],
    ["a call two properties deep, which names no module this walk resolves",
      "var view = { probeHref: links.web.href(\"/a\") };",
      { links: VIEW_FIELD_SOURCE }],
    ["a required module that defines no function under that name",
      "var view = { probeHref: links.href(\"/a\") };",
      { links: REFUSAL_SOURCE }],
  ];
  crossRed.forEach(function (v) {
    var found = _assignmentsOf(_proofBundle("// " + v[0] + "\n" + v[1], v[2]), "probeHref", b);
    count("the reader refuses " + v[0],
      found.length === 1 && found[0].reasons.length > 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  var crossGreen = [
    ["a value built by a view field builder in a required module",
      "var view = { probeHref: links.href(\"/mail/INBOX\") };",
      { links: REFUSAL_SOURCE + "\n" + _viewFieldSource("href", "_p") }],
    ["a local builder that hands its path to a required module's builder",
      "function _made(n) { return links.href(\"/mail/\" + n); }\n" +
      "var view = { probeHref: _made(1) };",
      { links: REFUSAL_SOURCE + "\n" + _viewFieldSource("href", "_p") }],
    ["a local name for the required module's builder",
      "function _href(value) { return links.href(value); }\n" +
      "var view = { probeHref: _href(\"/mail/INBOX\") };",
      { links: REFUSAL_SOURCE + "\n" + _viewFieldSource("href", "_p") }],
  ];
  crossGreen.forEach(function (v) {
    var found = _assignmentsOf(_proofBundle("// " + v[0] + "\n" + v[1], v[2]), "probeHref", b);
    count("and it stays silent on " + v[0],
      found.length === 1 && found[0].reasons.length === 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  // A comment about a property is not an assignment of it, and a reader
  // that counted one would report a value nobody wrote.
  var commented = _assignmentsOf("// probeHref: \"//evil.example\" is what we must never do\n" +
    VIEW_FIELD_SOURCE + "\nvar view = { probeHref: _v(\"/ok\") };", "probeHref", b);
  count("prose about a property is not read as an assignment of it",
    commented.length === 1 && commented[0].reasons.length === 0,
    JSON.stringify(commented.map(function (x) { return x.value; })));

  // The template side of the same question: what a template writes ahead
  // of the value.
  [
    ["nothing at all", ""],
    ["a second slash", "//"],
    ["a backslash after the slash", "/\\"],
    ["a longer path", "/wiki/"],
    ["a fragment mark", "#"],
    ["a scheme", "https://example.com/"],
  ].forEach(function (v) {
    count("the prefix reader refuses " + v[0] + " ahead of a view field",
      _prefixVerdict(v[1]) !== null, JSON.stringify(v[1]));
  });
  count("and it accepts the single slash a view field builder produces the rest of",
    _prefixVerdict("/") === null, "\"/\"");
}

// ---------------------------------------------------------------------------
// 1 + 2. The templates are the inventory, each writes the slash, and every
// value they read is built without one.
// ---------------------------------------------------------------------------

function everyRenderedLinkTargetIsBuilt(b) {
  var files = _templateFiles(VIEWS_DIR);
  count("the template directory was read rather than missed, so this gate answers for " +
    "something", files.length > 0, files.length + " templates");

  var sites = [];
  files.forEach(function (abs) {
    var rel = path.relative(helpers.REPO_ROOT, abs).replace(/\\/g, "/");
    sites = sites.concat(_linkSites(rel, fs.readFileSync(abs, "utf8")));
  });

  // The matcher still matches. A scan that has quietly stopped finding
  // anything reports a clean tree, which is the one failure a clean
  // verdict cannot be told apart from.
  var canary = _linkSites("canary.html",
    "<a href=\"/{{ someTarget }}\">x</a><form action=\"{{ p.postHref }}\">");
  check("the attribute scanner still finds an interpolated link target", canary.length === 2);
  check("and it reads the attribute and the expression off it",
    canary[0].attr === "href" && canary[0].expr === "someTarget" &&
    canary[1].attr === "action" && canary[1].expr === "p.postHref");
  check("and it reads what the template writes ahead of the value",
    canary[0].prefix === "/" && canary[1].prefix === "");
  check("and it marks an un-escaped interpolation as one",
    _linkSites("c.html", "<a href=\"{{{ x }}}\">x</a>")[0].raw === true);

  // Quoting is the author's choice, and a browser resolves the URL the
  // same way in all three forms. A scan that reads only the double-quoted
  // one answers "no interpolated link targets" for a template written
  // with either of the others, and the link it did not read still reaches
  // the browser.
  var quoting = _linkSites("q.html",
    "<a href='/{{ singleQuoted }}'>x</a>\n<a href=/{{ unquoted }}>y</a>");
  check("the attribute scanner reads a single-quoted and an unquoted link target",
    quoting.length === 2);
  check("and it reads the attribute and the expression off both",
    quoting.length === 2 &&
    quoting[0].attr === "href" && quoting[0].expr === "singleQuoted" &&
    quoting[1].attr === "href" && quoting[1].expr === "unquoted");
  check("and it reads what the template writes ahead of each value",
    quoting.length === 2 && quoting[0].prefix === "/" && quoting[1].prefix === "/");

  count("the browser surface renders link targets, and this gate found them",
    sites.length > 0, sites.length + " interpolated URL attributes");

  console.log("\n  rendered link targets, by template:");
  sites.forEach(function (s) {
    console.log("    " + s.file + ":" + s.line + "  " + s.attr + "=\"" + s.prefix +
      "{{ " + s.expr + " }}\"");
  });

  // The template holds the scheme position by writing the slash itself.
  var unanchored = sites
    .map(function (s) {
      var why = _prefixVerdict(s.prefix);
      return why === null ? null : s.file + ":" + s.line + " " + s.attr + ": " + why;
    })
    .filter(function (x) { return x !== null; });
  count("every interpolated URL attribute writes the leading slash itself and interpolates " +
    "only what follows it", unanchored.length === 0, unanchored.join(" | ") || sites.length +
    " attributes");

  // An un-escaped interpolation in a URL attribute is strictly worse
  // than an escaped one: it re-opens the attribute breakout that
  // escaping closes, on top of the scheme that escaping never closed.
  var rawSites = sites.filter(function (s) { return s.raw; });
  count("no link target is interpolated un-escaped, which would re-open the attribute " +
    "breakout on top of the scheme",
    rawSites.length === 0,
    rawSites.map(function (s) { return s.file + ":" + s.line; }).join(", ") || "none");

  var keys = {};
  sites.forEach(function (s) { keys[_leafKey(s.expr)] = 1; });
  var keyNames = Object.keys(keys).sort();
  count("every interpolation resolved to a property the producers can be searched for",
    keyNames.length > 0, keyNames.join(", "));

  // One record of the walk per producer, across every key, so a helper
  // reached from two link targets is followed once and what was followed
  // in each file can be published. A call is followed only to a function
  // the same file defines, which is why the records are not shared.
  var producers = PRODUCERS.map(function (abs) {
    var read = {};
    var bundle = _bundleFor(abs, read);
    var byRel = {};
    Object.keys(read).forEach(function (at) { byRel[read[at].rel] = read[at]; });
    return {
      rel:        bundle.rel,
      bundle:     bundle,
      bundles:    byRel,
      walked:     {},
      classified: 0,
    };
  });

  var findings = [];
  console.log("\n  where each one is built:");
  keyNames.forEach(function (key) {
    var assigned = 0;
    producers.forEach(function (producer) {
      _assignmentsOf(producer.bundle, key, b, producer.walked).forEach(function (a) {
        assigned += 1;
        producer.classified += 1;
        var flat = a.value.replace(/\s+/g, " ");
        console.log("    " + (a.reasons.length ? "REFUSED " : "built   ") +
          producer.rel + ":" + a.line + "  " + key + ": " + flat.slice(0, 90));
        a.reasons.forEach(function (r) {
          findings.push(producer.rel + ":" + a.line + " " + key + ": " + r);
        });
      });
    });
    count("a producer builds '" + key + "' somewhere, so the template is not reading a " +
      "value nothing sets", assigned > 0, assigned + " assignments");
  });

  producers.forEach(function (producer) {
    count("the producer scan reached the assignments in " + producer.rel + " rather than " +
      "reporting a clean file it never read", producer.classified > 0,
      producer.classified + " assignments classified");
  });

  count("every value that reaches a URL attribute is built by a view field builder, or is " +
    "empty", findings.length === 0, findings.join(" | ") || "none");

  // Which builders the walk actually entered in each producer. A scan that
  // classified every assignment while following nothing would report the
  // same clean verdict as one that followed all of them, so the set is
  // published rather than left to be inferred from silence. The view field
  // builders it recognized and the path builders it followed under them
  // are published apart, and each producer has to yield both: a view field
  // builder nobody recognized, or one whose path half was never followed
  // to the refusal, is a walk that trusted a call for looking like one.
  producers.forEach(function (producer) {
    var viewFields = [];
    var paths = [];
    var names = [];
    Object.keys(producer.walked).sort().forEach(function (name) {
      if (name.indexOf(VIEW_FIELD_WALK + "identifier ") === 0 || name.indexOf("identifier ") === 0) {
        names.push(name);
      } else if (name.indexOf(VIEW_FIELD_WALK) === 0) {
        var at = _walkedAt(producer.bundles, name.slice(VIEW_FIELD_WALK.length));
        if (at === null) return;
        var body = _functionBody(at.bundle, at.name);
        if (producer.walked[name] === null && body !== null &&
            _isTheViewFieldRefusal(body, at.bundle, b, producer.walked)) {
          viewFields.push(at.bundle.rel + " " + at.name);
        }
      } else if (producer.walked[name] === null) {
        var pathAt = _walkedAt(producer.bundles, name);
        if (pathAt !== null) paths.push(pathAt.bundle.rel + " " + pathAt.name);
      }
    });
    console.log("\n  view field builders recognized for " + producer.rel + ":");
    viewFields.forEach(function (name) { console.log("    " + name + "()"); });
    console.log("  path builders followed to the refusal under them:");
    paths.forEach(function (name) { console.log("    " + name + "()"); });
    console.log("  names a value travels under on the way: " + (names.join(", ") || "none"));

    count("the walk recognized a view field builder for " + producer.rel + " by its shape " +
      "rather than trusting a call for looking like one", viewFields.length > 0,
      viewFields.join(", ") || "none");
    count("and followed the path half under it to the refusal", paths.length > 0,
      paths.join(", ") || "none");

    producer.viewFields = viewFields;
  });

  // One reader, not one per surface. Both producers build their template
  // values through a builder recognized by shape, and the shapes are in
  // the same FILE: a surface that grew a copy of the rule would still be
  // recognized above and would show up here as a second file, which is the
  // drift that put two character lists in the tree to begin with.
  var builderFiles = {};
  producers.forEach(function (producer) {
    (producer.viewFields || []).forEach(function (name) {
      builderFiles[name.split(" ")[0]] = 1;
    });
  });
  var builderFileNames = Object.keys(builderFiles).sort();
  count("every surface that renders a link builds its values through builders in ONE file, " +
    "so a case added to the rule reaches all of them",
    builderFileNames.length === 1, builderFileNames.join(", ") || "none");
}

// ---------------------------------------------------------------------------
// 3. The refusal underneath actually refuses.
// ---------------------------------------------------------------------------

// The composition the browser surface builds a link target with: an
// absolute path, handed to the framework's redirect resolver, and kept
// only when the resolver hands back what it was given. Written out here
// rather than imported, because the property under test is that this
// SHAPE refuses: a shape a rename does not change and a deletion does.
function _asLinkTarget(b, value) {
  if (typeof value === "string" && value.charAt(0) === "/" &&
      b.safeRedirect.resolve(value, { fallback: "" }) === value) {
    return value;
  }
  return null;
}

function aTargetThatLeavesThisOriginIsRefused(b) {
  var offSite = [
    ["a scripting scheme",                    "javascript:alert(1)"],
    ["the same scheme in mixed case",         "JaVaScRiPt:alert(1)"],
    ["the same scheme split by a tab",        "java" + TAB + "script:alert(1)"],
    ["a scripting scheme for older engines",  "vbscript:msgbox(1)"],
    ["a document inlined as a scheme",        "data:text/html,<script>alert(1)</script>"],
    ["a bare absolute URL",                   "https://evil.example/x"],
    ["an authority behind a second slash",    "//evil.example/x"],
    ["an authority behind a backslash",       "/\\evil.example/x"],
    ["an authority behind two backslashes",   "\\\\evil.example\\x"],
    ["an authority behind three slashes",     "///evil.example/x"],
    ["an authority hidden behind a tab",      "/" + TAB + "/evil.example/x"],
    ["an authority hidden behind a newline",  "/" + NL + "/evil.example/x"],
    ["an authority hidden behind a return",   "/" + CR + "/evil.example/x"],
    ["an authority hidden behind a null",     "/" + NUL + "/evil.example/x"],
    ["a response header spliced onto a path", "/mail" + CR + NL + "Set-Cookie: a=b"],
    ["a path relative to wherever we are",    "mail/INBOX"],
    ["a walk out of the document root",       "../../etc/passwd"],
    ["nothing at all",                        ""],
    ["a number",                              42],
    ["an absence",                            null],
    ["an undefined",                          undefined],
  ];
  offSite.forEach(function (v) {
    count("a link target is refused when it is " + v[0],
      _asLinkTarget(b, v[1]) === null, JSON.stringify(v[1]));
  });

  // The other half of the same question. A guard that refused everything
  // would pass every check above and render an application with no
  // navigation, so what it ACCEPTS is asserted too.
  var onSite = [
    ["the root",                          "/"],
    ["a folder",                          "/mail?folder=INBOX"],
    ["a folder whose name needed escaping", "/mail?folder=" + encodeURIComponent("Sent Items")],
    ["a nested folder",                   "/mail?folder=" + encodeURIComponent("Clients/Acme")],
    ["a page of a listing",               "/admin/accounts?offset=25&limit=25"],
    ["a compose form with its source",    "/compose?source=abc&folder=INBOX&mode=reply"],
    ["a message asking for its images",   "/mail/objid?folder=INBOX&images=on"],
  ];
  onSite.forEach(function (v) {
    count("and it is kept when it is " + v[0],
      _asLinkTarget(b, v[1]) === v[1], JSON.stringify(v[1]));
  });

  // A colon after the first slash is a path segment rather than a
  // scheme, and an at sign after it is a path segment rather than
  // userinfo. Both read as dangerous and neither is, so they are
  // recorded here as accepted ON PURPOSE: the next reader who spots one
  // finds the resolution rather than filing it again, and a change that
  // starts refusing them fails a check that says why they were allowed.
  var readsHostileIsNot = [
    ["a colon in the first segment",  "/javascript:alert(1)"],
    ["an at sign in the first segment", "/@evil.example/x"],
    ["a colon segment",               "/:/evil.example"],
  ];
  readsHostileIsNot.forEach(function (v) {
    var resolved = new URL(v[1], "https://mail.example.test");
    count("a target carrying " + v[0] + " is same origin and is kept",
      _asLinkTarget(b, v[1]) === v[1] && resolved.origin === "https://mail.example.test",
      v[1] + " -> " + resolved.href);
  });
}

// ---------------------------------------------------------------------------
// 4. A hostile sender writes the message body.
// ---------------------------------------------------------------------------

// The body policy the browser surface composes, read OFF the producer
// rather than restated, so a change to the shipped allowlist is seen
// here instead of this file testing a policy nothing serves.
function _bodyPolicy(source) {
  var attrs = /var BODY_ATTRS = Object\.freeze\(\[([\s\S]*?)\]\)/.exec(source);
  var call  = /b\.guardHtml\.sanitize\(\s*html\s*,\s*\{([\s\S]*?)\n\s*\}\s*\)/.exec(source);
  return {
    attrs: attrs === null ? null : attrs[1].match(/"[^"]+"/g).map(function (s) {
      return s.slice(1, -1);
    }),
    opts: call === null ? null : call[1],
  };
}

function theBodyPolicyIsTheOneTheServerServes(source) {
  var policy = _bodyPolicy(source);
  check("the shipped message-body attribute allowlist was found", policy.attrs !== null);
  check("the shipped sanitizer call was found", policy.opts !== null);

  count("the body allowlist really does admit href on a link, which is what makes the " +
    "scheme vectors below the question they are",
    policy.attrs.indexOf("href") !== -1, policy.attrs.join(", "));

  count("the body is screened under a named profile rather than whatever the defaults are",
    /profile:\s*"balanced"/.test(policy.opts), policy.opts.replace(/\s+/g, " ").slice(0, 200));

  // The profile decides which schemes survive. A call that widened the
  // scheme list would keep every check below passing while serving a
  // different policy, so the widening itself is the finding.
  count("and the call does not widen the scheme list the profile settled",
    !/urlSchemes\s*:/.test(policy.opts), policy.opts.replace(/\s+/g, " ").slice(0, 200));

  count("and it does not carry comments through, which is where conditional markup hides",
    /allowComments:\s*false/.test(policy.opts), policy.opts.replace(/\s+/g, " ").slice(0, 200));

  // Neither is allowlisted, and the pair is why the sanitized link needs
  // no `rel`: a body that cannot name a target cannot open a second
  // browsing context to leak an opener into.
  count("a message cannot choose a browsing context for its links",
    policy.attrs.indexOf("target") === -1, policy.attrs.join(", "));
  count("nor the relationship they declare",
    policy.attrs.indexOf("rel") === -1, policy.attrs.join(", "));

  return policy;
}

// The attributes a sanitized message body is read for. `srcdoc` joins the
// list above because a message body is the one surface that could carry
// one, and the question here is what the sanitizer left rather than what
// a template wrote.
var SANITIZED_URL_ATTRS = URL_ATTRS.concat(["srcdoc"]);

// Every URL-bearing attribute the sanitizer left behind, in whichever
// quoting it wrote them.
function _urlAttrsIn(html) {
  var out = [];
  var re = _urlAttrPattern(SANITIZED_URL_ATTRS);
  var m;
  while ((m = re.exec(html)) !== null) out.push(m[1].toLowerCase() + "=" + _attrValue(m));
  return out;
}

function aHostileSenderCannotWriteALinkThatRuns(b, policy) {
  var withImages = b.guardHtml.BALANCED_ALLOWED_TAGS.slice();
  var textOnly   = withImages.filter(function (t) { return t !== "img"; });

  function sanitize(html, images) {
    return b.guardHtml.sanitize(html, {
      profile:        "balanced",
      allowedTags:    images ? withImages.slice() : textOnly.slice(),
      allowedAttrs:   policy.attrs.slice(),
      allowImageData: images,
      allowComments:  false,
    });
  }

  // Every way a scheme has been smuggled past a sanitizer that folded
  // less than a browser does: case, the whitespace the URL parser strips
  // from anywhere in a scheme, a leading control run, and the character
  // references the markup parser decodes before the URL parser ever
  // sees the value.
  var vectors = [
    ["a scripting scheme, plainly",         '<a href="javascript:alert(1)">x</a>'],
    ["the same scheme in mixed case",       '<a href="JaVaScRiPt:alert(1)">x</a>'],
    ["the same scheme in capitals",         '<a href="JAVASCRIPT:alert(1)">x</a>'],
    ["a tab inside the scheme",             '<a href="java' + TAB + 'script:alert(1)">x</a>'],
    ["a newline inside the scheme",         '<a href="java' + NL + 'script:alert(1)">x</a>'],
    ["a return inside the scheme",          '<a href="java' + CR + 'script:alert(1)">x</a>'],
    ["a null inside the scheme",            '<a href="java' + NUL + 'script:alert(1)">x</a>'],
    ["a vertical tab inside the scheme",    '<a href="java' + VT + 'script:alert(1)">x</a>'],
    ["a form feed inside the scheme",       '<a href="java' + FF + 'script:alert(1)">x</a>'],
    ["a leading space",                     '<a href=" javascript:alert(1)">x</a>'],
    ["a leading run of control bytes",      '<a href="' + NUL + CR + NL + 'javascript:alert(1)">x</a>'],
    ["a decimal reference for the space",   '<a href="&#32;javascript:alert(1)">x</a>'],
    ["a decimal reference inside it",       '<a href="java&#115;cript:alert(1)">x</a>'],
    ["a hex reference inside it",           '<a href="java&#x73;cript:alert(1)">x</a>'],
    ["a named reference for the colon",     '<a href="javascript&colon;alert(1)">x</a>'],
    ["a reference for a tab inside it",     '<a href="java&#9;script:alert(1)">x</a>'],
    ["the scheme older engines ran",        '<a href="vbscript:msgbox(1)">x</a>'],
    ["another one they ran",                '<a href="livescript:alert(1)">x</a>'],
    ["and another",                         '<a href="mocha:alert(1)">x</a>'],
    ["and the fourth",                      '<a href="ecmascript:alert(1)">x</a>'],
    ["a document inlined as a scheme",      '<a href="data:text/html,<script>alert(1)</script>">x</a>'],
    ["the same document in base64",         '<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>'],
    ["a local file",                        '<a href="file:///etc/passwd">x</a>'],
    ["the source of a page",                '<a href="view-source:https://x.example">x</a>'],
    ["an archive member",                   '<a href="jar:https://x.example!/">x</a>'],
    ["a platform handoff",                  '<a href="intent://x#Intent;end">x</a>'],
    ["an archived page",                    '<a href="mhtml:https://x.example!x">x</a>'],
    ["a feed wrapping a scripting scheme",  '<a href="feed:javascript:alert(1)">x</a>'],
    ["a scheme the profile never listed",   '<a href="gopher://x.example">x</a>'],
    ["the same on a quotation",             '<blockquote cite="javascript:alert(1)">x</blockquote>'],
    ["the same on an image",                '<img src="javascript:alert(1)">'],
    ["the same on a form override",         '<button formaction="javascript:alert(1)">x</button>'],
    ["a document redirected wholesale",     '<base href="https://evil.example/">'],
    ["a nested document",                   '<iframe srcdoc="<script>alert(1)</script>"></iframe>'],
    ["an animation retargeting the link",   '<svg><a href="/ok"><animate attributeName="href" values="javascript:alert(1)"/></a></svg>'],
  ];

  vectors.forEach(function (v) {
    var out = sanitize(v[1], false);
    var kept = _urlAttrsIn(out);
    count("a message body cannot link out through " + v[0],
      kept.length === 0, out);
  });

  // A handler is not a scheme and is dropped for its own reason, on an
  // element whose href is perfectly fine.
  var handler = sanitize('<a href="/ok" onclick="alert(1)" ONMOUSEOVER="alert(2)">x</a>', false);
  count("an event handler beside a good target is dropped and the target is kept",
    handler.indexOf("onclick") === -1 && handler.indexOf("ONMOUSEOVER") === -1 &&
    handler.indexOf("href=\"/ok\"") !== -1, handler);

  var styled = sanitize('<a href="/ok" style="width:expression(alert(1))">x</a>', false);
  count("and so is a style attribute carrying its own script",
    styled.indexOf("style") === -1, styled);

  // What a sender MAY do. A mail client whose links all stopped working
  // would fail every check above, so the ordinary message is asserted
  // too, and an off-site link in a BODY is ordinary, which is exactly
  // the line this file draws against the application links overhead.
  var ordinary = [
    ["an https page",     '<a href="https://example.com/a">x</a>',        "https://example.com/a"],
    ["an http page",      '<a href="http://example.com/a">x</a>',         "http://example.com/a"],
    ["a mail address",    '<a href="mailto:someone@example.com">x</a>',   "mailto:someone@example.com"],
    ["a link within the message", '<a href="#section">x</a>',             "#section"],
  ];
  ordinary.forEach(function (v) {
    var out = sanitize(v[1], false);
    count("a message body may still link to " + v[0],
      out.indexOf("href=\"" + v[2] + "\"") !== -1, out);
  });

  // The reader asked to see the images. That widens the tag set and the
  // data URLs an image may carry, and it widens nothing else.
  var svgData = sanitize('<img src="data:image/svg+xml,<svg onload=alert(1)>">', true);
  count("asking for images does not admit a document dressed as one",
    _urlAttrsIn(svgData).length === 0, svgData);

  var jsImage = sanitize('<img src="javascript:alert(1)">', true);
  count("nor an image whose source is a scripting scheme",
    _urlAttrsIn(jsImage).length === 0, jsImage);

  var jsLink = sanitize('<a href="javascript:alert(1)">x</a>', true);
  count("nor does it re-admit a scripting scheme on a link",
    _urlAttrsIn(jsLink).length === 0, jsLink);

  var pngData = sanitize('<img src="data:image/png;base64,iVBORw0KGgo=">', true);
  count("and an image the sender inlined is shown, which is what was asked for",
    pngData.indexOf("data:image/png") !== -1, pngData);

  var heldBack = sanitize('<img src="https://tracker.example/x.gif">', false);
  count("while the reading default holds every image back rather than reporting the sender " +
    "that the message was opened", heldBack.indexOf("img") === -1, heldBack);
}

// ---------------------------------------------------------------------------
// 5. The sink: every URL attribute a template renders, handed a value no
// builder screened.
//
// Sections 1 to 3 hold the builders to the refusal. This holds the
// templates. A producer that skips the refusal hands the template whatever
// it was given, and the template's own text around the interpolation is
// then the only thing between that value and the browser.
//
// Two classes of hostile value need two different places to stop them.
//
//   - The scheme class chooses what runs, or which site the reader lands
//     on, by what the value BEGINS with: `javascript:`, `data:`,
//     `https://elsewhere`. A template that writes the leading slash itself
//     stops every one of them, because `/javascript:alert(1)` is a path on
//     this server. These are driven straight into the sink.
//   - The slash class begins with a second slash or a backslash, and a
//     literal slash in the template does not stop it: `/` followed by
//     `/evil.example/x` names another host. The template cannot hold that,
//     so the composition that builds the template's value has to refuse
//     it. These are driven through that composition, and what it accepts
//     is rendered to show the link lands on the path it was built from.
//
// Rendered through the shipped engine and the real view files. Every
// template is rendered on its own, partials and layouts included, with one
// scope that walks every loop a link sits in. An interpolated URL attribute
// the render does not reach fails the run, so a new link site the scope was
// never taught about is reported rather than passing unexamined.
// ---------------------------------------------------------------------------

var SINK_ORIGIN = "https://mail.example.com";
// A page two segments deep. A target written as a relative path resolves
// under it, so a template that emits one is caught rather than landing on
// the right path by coincidence at the root.
var SINK_PAGE = SINK_ORIGIN + "/admin/accounts";

// The five characters the engine escapes, read back the way a browser
// decodes an attribute value before it parses the URL inside it.
var ATTRIBUTE_ENTITIES = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": "\"", "&#x27;": "'" };
var ATTRIBUTE_ENTITY_RE = /&(?:amp|lt|gt|quot|#x27);/g;

function _decodeAttribute(value) {
  return value.replace(ATTRIBUTE_ENTITY_RE, function (e) { return ATTRIBUTE_ENTITIES[e]; });
}

// Every URL a rendered page hands the browser in an attribute, in document
// order, decoded.
function _renderedUrls(html) {
  var out = [];
  URL_ATTR_RE.lastIndex = 0;
  var m;
  while ((m = URL_ATTR_RE.exec(html)) !== null) {
    var attr  = m[1].toLowerCase();
    var value = _decodeAttribute(_attrValue(m));
    if (attr !== "srcset") { out.push({ attr: attr, value: value }); continue; }
    value.split(",").forEach(function (candidate) {
      var url = candidate.trim().split(" ")[0];
      if (url.length > 0) out.push({ attr: attr, value: url });
    });
  }
  return out;
}

// Why following `value` from SINK_PAGE leaves this origin, or null when it
// stays.
function _leavesTheOrigin(value) {
  var url;
  try { url = new URL(value, SINK_PAGE); }
  catch (_e) { return "it does not parse as a URL"; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return "it runs as " + url.protocol;
  if (url.origin !== SINK_ORIGIN) return "it goes to " + url.origin;
  return null;
}

// Every template, with the interpolated URL attributes the inventory of
// section 1 found in it.
function _viewInventory() {
  return _templateFiles(VIEWS_DIR).map(function (abs) {
    var rel = path.relative(VIEWS_DIR, abs).replace(/\\/g, "/");
    return {
      rel:   rel,
      view:  rel.replace(/\.html$/, ""),
      sites: _linkSites(rel, fs.readFileSync(abs, "utf8")),
    };
  });
}

// One scope that reaches every link a template renders. Every loop walks
// the same row, and the row carries every link key the inventory found, so
// a link inside any loop reads the value under test. The flags are the
// conditions a link sits behind: a message with images held back, a
// standing lockout on a hosted mailbox, a list with rows in it, a signed in
// operator.
function _sinkScope(keys, valueFor) {
  var row = {
    text: "x", label: "x", name: "x",
    blockedCount: 1,
    isMailbox: true, standing: true, released: false,
  };
  keys.forEach(function (k) { row[k] = valueFor(k); });
  var blocks = [
    { kind: "paragraph", spans: [row] },
    { kind: "list", ordered: true, items: [[row]] },
    { kind: "list", ordered: false, items: [[row]] },
    { kind: "facts", rows: [{ label: "x", spans: [row] }] },
    { kind: "table", caption: "x", head: ["x"], rows: [{ cells: [[row]] }] },
  ];
  var scope = {
    csrfToken:   "token",
    account:     { address: "reader@example.com" },
    accountName: "reader",
    isAdmin:     true,
    hostname:    "mail.example.com",
    folder:      { label: "Inbox", name: "INBOX" },
    empty:       false,
    hasResults:  true,
    showLinks:   true,
    folders:     [row],
    messages:    [row],
    nav:         [row],
    siteNav:     [row],
    cards:       [row],
    rows:        [row],
    pending:     row,
    wiki: {
      title: "x", eyebrow: "x", crumbs: [row], lead: [row],
      sections: [{ id: "s", heading: "x", blocks: blocks }],
    },
  };
  keys.forEach(function (k) { scope[k] = valueFor(k); });
  return scope;
}

function _markerFor(keys, key) {
  return "k" + keys.indexOf(key) + "z";
}

// The composition that builds a template's link value: an absolute path
// through a path refusal, with its leading slash taken off, refused again
// when what is left begins with anything that makes the template's own
// slash the first of two. Written out rather than imported, for the reason
// `_asLinkTarget` is: the property under test is that this SHAPE refuses,
// and the reader in section 2 holds every shipped view field to a builder
// with the shape.
function _asTemplateTail(pathRefusal, value) {
  var target = pathRefusal(value);
  if (target === null) return null;
  var tail = target.slice(1);
  var first = tail.charAt(0);
  if (first === "/" || first === "\\" || first === TAB || first === NL || first === CR) return null;
  return tail;
}

var SINK_SCHEME_VECTORS = [
  ["a scripting scheme",                    "javascript:alert(1)//"],
  ["the same scheme in mixed case",         "JaVaScRiPt:alert(1)//"],
  ["the same scheme split by a tab",        "java" + TAB + "script:alert(1)//"],
  ["the same scheme behind a space",        " javascript:alert(1)//"],
  ["the same scheme behind a control byte", VT + "javascript:alert(1)//"],
  ["a scripting scheme for older engines",  "vbscript:msgbox(1)//"],
  ["a document inlined as a scheme",        "data:text/html,<script>alert(1)</script>"],
  ["a bare absolute URL",                   "https://evil.example/"],
  ["a mail handoff",                        "mailto:someone@evil.example?body="],
];

var SINK_SLASH_VECTORS = [
  ["an authority behind a second slash",   "//evil.example/x"],
  ["an authority behind a backslash",      "/\\evil.example/x"],
  ["an authority behind two backslashes",  "\\\\evil.example\\x"],
  ["an authority behind three slashes",    "///evil.example/x"],
  ["an authority hidden behind a tab",     "/" + TAB + "/evil.example/x"],
];

function theSinkHoldsTheSchemePosition(b) {
  var engine = b.template.create({ viewsDir: VIEWS_DIR });
  var views = _viewInventory();
  var linked = views.filter(function (v) { return v.sites.length > 0; });

  var keySet = {};
  linked.forEach(function (v) { v.sites.forEach(function (s) { keySet[_leafKey(s.expr)] = 1; }); });
  var keys = Object.keys(keySet).sort();

  count("the sink inventory read every template and found the ones that render links",
    views.length > 0 && linked.length > 0,
    views.length + " templates, " + linked.length + " with an interpolated URL attribute");

  // Reach. A site the scope never renders is a site nothing below examined.
  var missed = [];
  var reached = 0;
  linked.forEach(function (v) {
    var urls = _renderedUrls(engine.render(v.view, _sinkScope(keys, function (k) {
      return "reach/" + _markerFor(keys, k);
    })));
    v.sites.forEach(function (s) {
      var marker = _markerFor(keys, _leafKey(s.expr));
      var hit = urls.some(function (u) { return u.value.indexOf(marker) !== -1; });
      if (hit) reached += 1;
      else missed.push(v.rel + ":" + s.line + " " + s.attr + " " + s.expr);
    });
  });
  count("the render reached every interpolated URL attribute in every template, so the " +
    "verdicts below answer for all of them", missed.length === 0 && reached > 0,
    missed.join(" | ") || reached + " sites reached");

  // The scheme class, straight into the sink.
  SINK_SCHEME_VECTORS.forEach(function (vector) {
    var findings = [];
    var examined = 0;
    linked.forEach(function (v) {
      var urls = _renderedUrls(engine.render(v.view, _sinkScope(keys, function (k) {
        return vector[1] + _markerFor(keys, k);
      })));
      urls.forEach(function (u) {
        if (!keys.some(function (k) { return u.value.indexOf(_markerFor(keys, k)) !== -1; })) return;
        examined += 1;
        var why = _leavesTheOrigin(u.value);
        if (why !== null) findings.push(v.rel + " " + u.attr + "=" + JSON.stringify(u.value) + ": " + why);
      });
    });
    count("a template handed " + vector[0] + " at every link still renders a link on this " +
      "origin", findings.length === 0 && examined > 0,
      findings.slice(0, 4).join(" | ") || examined + " rendered URL attributes");
  });

  // The slash class never reaches a template: the composition refuses it,
  // and so does its own leading-character check with the path refusal
  // under it weakened to accept anything that starts with a slash.
  var strict = function (v) { return _asLinkTarget(b, v); };
  var weakened = function (v) { return typeof v === "string" && v.charAt(0) === "/" ? v : null; };
  SINK_SLASH_VECTORS.concat(SINK_SCHEME_VECTORS).forEach(function (vector) {
    count("the template's value is never built from " + vector[0],
      _asTemplateTail(strict, vector[1]) === null, JSON.stringify(vector[1]));
  });
  [
    ["a second slash",               "//evil.example/x"],
    ["a backslash",                  "/\\evil.example/x"],
    ["a tab ahead of a second slash", "/" + TAB + "/evil.example/x"],
    ["a newline ahead of it",        "/" + NL + "/evil.example/x"],
    ["a return ahead of it",         "/" + CR + "/evil.example/x"],
  ].forEach(function (vector) {
    count("and the leading-character check refuses " + vector[0] + " on its own, with the " +
      "path refusal under it weakened", _asTemplateTail(weakened, vector[1]) === null,
      JSON.stringify(vector[1]));
  });

  // What the composition accepts lands where it was built to. Each link
  // position is found in a render carrying a marker, and the same position
  // in the render carrying the real value has to resolve to exactly the
  // path it was built from.
  var onSite = [
    "/mail/INBOX",
    "/mail/" + encodeURIComponent("Sent Items"),
    "/admin/accounts?offset=25&limit=25",
    "/compose?source=abc&folder=INBOX&mode=reply",
    "/wiki/specs/rfc-5322#section-3-4",
    "/javascript:alert(1)",
    "/@evil.example/x",
  ];
  var marker = "k" + keys.length + "z";
  onSite.forEach(function (target) {
    var tail = _asTemplateTail(strict, target);
    var wrong = [];
    var landed = 0;
    linked.forEach(function (v) {
      var marked = _renderedUrls(engine.render(v.view, _sinkScope(keys, function () { return marker; })));
      var real   = _renderedUrls(engine.render(v.view, _sinkScope(keys, function () { return tail; })));
      if (marked.length !== real.length) { wrong.push(v.rel + " rendered a different set of links"); return; }
      marked.forEach(function (u, i) {
        if (u.value.indexOf(marker) === -1) return;
        var url;
        try { url = new URL(real[i].value, SINK_PAGE); }
        catch (_e) { wrong.push(v.rel + " " + JSON.stringify(real[i].value) + " does not parse"); return; }
        if (url.origin === SINK_ORIGIN && url.pathname + url.search + url.hash === target) landed += 1;
        else wrong.push(v.rel + " " + real[i].attr + "=" + JSON.stringify(real[i].value) + " -> " + url.href);
      });
    });
    count("a link built from " + target + " lands on exactly that path from every template",
      tail !== null && wrong.length === 0 && landed > 0,
      wrong.slice(0, 4).join(" | ") || landed + " links");
  });

  // The root. Its value is empty, and a template that writes the slash
  // renders `href="/"` for it. A link behind a condition on its own value
  // renders nothing when that value is empty, so only positions present in
  // both renders are compared.
  var rootTail = _asTemplateTail(strict, "/");
  var rootChecked = 0;
  var rootWrong = [];
  linked.forEach(function (v) {
    var marked = _renderedUrls(engine.render(v.view, _sinkScope(keys, function () { return marker; })));
    var real   = _renderedUrls(engine.render(v.view, _sinkScope(keys, function () { return rootTail; })));
    if (marked.length !== real.length) return;
    marked.forEach(function (u, i) {
      if (u.value.indexOf(marker) === -1) return;
      rootChecked += 1;
      if (real[i].value !== "/") rootWrong.push(v.rel + " " + real[i].attr + "=" + JSON.stringify(real[i].value));
    });
  });
  count("the root path is built as an empty value and every template renders it as href=\"/\"",
    rootTail === "" && rootWrong.length === 0 && rootChecked > 0,
    rootWrong.slice(0, 4).join(" | ") || rootChecked + " links");
}

// ---------------------------------------------------------------------------
// 6. One reader, and it names all five characters.
//
// Sections 1 to 3 hold every rendered value to a builder, and section 5
// holds the templates. Neither of them can see the difference between a
// builder that refuses all five leading characters and one that refuses
// two of them, and the reason is worth writing down: the path refusal
// UNDER the builder already refuses every value whose second character is
// one of the five, so nothing a test can hand the shipped composition
// reaches the leading-character check at all. It is a second line, and a
// second line with no reachable input is one that can lose three of its
// five cases without a single verdict changing. Removing the tab, line
// feed and carriage return from it left every gate in this repository
// green.
//
// So the rule is pinned by SHAPE over the one reader that holds it, and
// the reader that reads the shape is itself proven on a body with each
// character taken out. The builder is found by shape rather than by name,
// so renaming it changes no verdict, and finding more than one of them is
// the finding: two builders are two places a character can be dropped from
// and the surface that then renders a link to another host is whichever
// one nobody edited.
//
// The behavioral half is driven too, for what is reachable: every one of
// the five shapes is refused end to end, an ordinary path is accepted, and
// a link built from one lands on exactly that path from a mail template
// AND from a wiki page.
// ---------------------------------------------------------------------------

// The shipped reader, driven directly. `blamepost.web.links.path` is the
// redirect half and `blamepost.web.links.href` is the half a template
// interpolates, and both surfaces build every link through the two.
var WEB_LINKS = require("../../lib/web/links");

// The five characters, as the shipped source spells them. An escape for
// the three control bytes and a doubled backslash for the one that is a
// backslash, so a body is searched for the text a reader of the file sees
// rather than for the byte the string holds.
var FIRST_CHARACTER_FORMS = [
  ["a second slash",     "\"/\""],
  ["a backslash",        "\"\\\\\""],
  ["a tab",              "\"\\t\""],
  ["a line feed",        "\"\\n\""],
  ["a carriage return",  "\"\\r\""],
];

// A leading-character refusal naming every one of the five. Written out so
// the reader below is proven on a body this file controls, with each
// character taken out in turn.
var CANARY_REFUSAL =
  "var first = tail.charAt(0);\n" +
  "if (first === \"/\" || first === \"\\\\\" || first === \"\\t\" || " +
  "first === \"\\n\" || first === \"\\r\") { throw new TypeError(\"x\"); }";

// The canary with one character taken out of it, whichever position that
// character is written in. The first comparison in the chain carries the
// `||` after it rather than before it, and a reader proven only on the
// middle of the chain is one that was never proven on the first.
function _canaryWithout(form) {
  var after = " || first === " + form;
  if (CANARY_REFUSAL.indexOf(after) !== -1) return CANARY_REFUSAL.split(after).join("");
  return CANARY_REFUSAL.split("first === " + form + " || ").join("");
}

// Which of the five a body does not name.
function _missingCharacters(body) {
  return FIRST_CHARACTER_FORMS
    .filter(function (form) { return body.indexOf(form[1]) === -1; })
    .map(function (form) { return form[0]; });
}

function _jsFiles(dir, into) {
  into = into || [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "public" && entry.name !== "views") _jsFiles(abs, into);
      return;
    }
    if (/\.js$/.test(entry.name)) into.push(abs);
  });
  return into;
}

// Every function under `lib/web/` whose body IS a view field builder: it
// takes one leading character off a path, refuses what is left when it
// would name a host, throws, and reaches the path refusal underneath.
function _viewFieldBuildersUnderWeb(b) {
  var out = [];
  _jsFiles(WEB_ROOT).forEach(function (abs) {
    var bundle = _bundleFor(abs, {});
    var walked = {};
    var text = _uncommented(bundle.text);
    var re = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
    var m;
    while ((m = re.exec(text)) !== null) {
      var body = _functionBody(bundle, m[1]);
      if (body === null) continue;
      if (!_isTheViewFieldRefusal(body, bundle, b, walked)) continue;
      out.push({ rel: bundle.rel, name: m[1], body: body });
    }
  });
  return out;
}

// Every shape whose second character turns a template's own slash into the
// first character of a host name.
var OPENS_A_HOST = [
  ["a second slash",                  "//evil.example/x"],
  ["a backslash",                     "/\\evil.example/x"],
  ["a tab ahead of a second slash",   "/" + TAB + "/evil.example/x"],
  ["a line feed ahead of one",        "/" + NL + "/evil.example/x"],
  ["a carriage return ahead of one",  "/" + CR + "/evil.example/x"],
  ["a tab ahead of a bare name",      "/" + TAB + "evil.example"],
  ["a line feed ahead of one",        "/" + NL + "evil.example"],
  ["a carriage return ahead of one",  "/" + CR + "evil.example"],
];

function _refuses(fn, value) {
  try { fn(value); return false; }
  catch (_refused) { return true; }
}

// Every link a render put on the page that carries the marker, resolved
// the way a browser resolves it from a page two segments deep.
function _landedFrom(engine, view, keys, tail) {
  var marker = "k" + keys.length + "z";
  var marked = _renderedUrls(engine.render(view, _sinkScope(keys, function () { return marker; })));
  var real   = _renderedUrls(engine.render(view, _sinkScope(keys, function () { return tail; })));
  var out = [];
  if (marked.length !== real.length) return null;
  marked.forEach(function (u, i) {
    if (u.value.indexOf(marker) === -1) return;
    var url;
    try { url = new URL(real[i].value, SINK_PAGE); }
    catch (_e) { out.push({ ok: false, where: real[i].value }); return; }
    out.push({
      ok:    url.origin === SINK_ORIGIN,
      where: url.pathname + url.search + url.hash,
      href:  url.href,
    });
  });
  return out;
}

function theOneReaderRefusesEveryCharacterThatOpensAHost(b) {
  // ---- The reader that reads the shape, proven on a body it controls ----
  count("the character reader finds all five on a refusal that names all five",
    _missingCharacters(CANARY_REFUSAL).length === 0,
    _missingCharacters(CANARY_REFUSAL).join(", ") || "none missing");

  FIRST_CHARACTER_FORMS.forEach(function (form) {
    var missing = _missingCharacters(_canaryWithout(form[1]));
    count("and it reports " + form[0] + " when a refusal stops naming it",
      missing.length === 1 && missing[0] === form[0], missing.join(", ") || "nothing");
  });

  // ---- One builder, found by shape ----
  var builders = _viewFieldBuildersUnderWeb(b);
  console.log("\n  view field builders under lib/web/, found by shape:");
  builders.forEach(function (x) { console.log("    " + x.rel + " " + x.name + "()"); });

  count("the shape scan found a view field builder under lib/web/, so this section " +
    "answers for something", builders.length > 0,
    builders.map(function (x) { return x.rel + " " + x.name; }).join(", ") || "none");

  var files = {};
  builders.forEach(function (x) { files[x.rel] = 1; });
  count("there is exactly ONE of them, so a character cannot be dropped from a copy the " +
    "other surface never reads",
    builders.length === 1 && Object.keys(files).length === 1,
    builders.map(function (x) { return x.rel + " " + x.name; }).join(", ") || "none");

  // ---- It names every one of the five ----
  builders.forEach(function (builder) {
    var missing = _missingCharacters(builder.body);
    FIRST_CHARACTER_FORMS.forEach(function (form) {
      count("the one reader refuses " + form[0] + " after the template's own slash",
        missing.indexOf(form[0]) === -1,
        builder.rel + " " + builder.name + "(): missing " + (missing.join(", ") || "nothing"));
    });
  });

  // ---- Behavioral, end to end through the shipped reader ----
  OPENS_A_HOST.forEach(function (vector) {
    count("the shipped reader refuses a target carrying " + vector[0] + " as a link value",
      _refuses(WEB_LINKS.href, vector[1]), JSON.stringify(vector[1]));
    count("and refuses it as a redirect target",
      _refuses(WEB_LINKS.path, vector[1]), JSON.stringify(vector[1]));
  });

  // ---- A target the framework will not route ----
  //
  // The request lifecycle answers 400 for a path carrying a percent-encoded
  // separator or a null byte, before any route runs. A link built with one
  // in it renders, sits on the page, and fails when a reader follows it, so
  // it is refused where it is BUILT and the fault lands on the code that
  // built it. The same bytes in the query string are routed and are kept.
  [
    ["a percent-encoded slash",            "/mail/Clients%2FAcme"],
    ["a percent-encoded slash in capitals", "/mail/Clients%2fAcme"],
    ["a percent-encoded backslash",        "/mail/Backups%5C2026"],
    ["a percent-encoded backslash in capitals", "/mail/Backups%5c2026"],
    ["a null byte",                        "/mail/Clients%00"],
    ["one past a query string it also carries", "/mail/a%2Fb?folder=x"],
  ].forEach(function (vector) {
    count("the shipped reader refuses a redirect target whose path carries " + vector[0],
      _refuses(WEB_LINKS.path, vector[1]), JSON.stringify(vector[1]));
    count("and refuses it as a link value too",
      _refuses(WEB_LINKS.href, vector[1]), JSON.stringify(vector[1]));
  });

  [
    ["a folder",                "/mail?folder=INBOX",                "mail?folder=INBOX"],
    ["a nested folder",         "/mail?folder=Clients%2FAcme",       "mail?folder=Clients%2FAcme"],
    ["a folder whose name holds a backslash", "/mail?folder=Backups%5C2026",
      "mail?folder=Backups%5C2026"],
    ["a message under one",     "/mail/obj_1?folder=Clients%2FAcme",
      "mail/obj_1?folder=Clients%2FAcme"],
    ["a page of a listing",     "/admin/accounts?offset=25",         "admin/accounts?offset=25"],
    ["a wiki page",             "/wiki/web-links/href",              "wiki/web-links/href"],
    ["a colon in the first segment", "/javascript:alert(1)",         "javascript:alert(1)"],
    ["the root",                "/",                                 ""],
  ].forEach(function (vector) {
    var built;
    try { built = WEB_LINKS.href(vector[1]); }
    catch (_refused) { built = "THREW"; }
    count("and it still builds " + vector[0] + ", which is what a reader clicks",
      built === vector[2], JSON.stringify(built));
  });

  // ---- Both surfaces render what it builds, and land on this origin ----
  //
  // A mail template and a wiki page, because the two surfaces were the two
  // copies: a test that drove one of them is how the second copy survived
  // long enough to drift.
  var engine = b.template.create({ viewsDir: VIEWS_DIR });
  var keySet = {};
  _viewInventory().forEach(function (v) {
    v.sites.forEach(function (s) { keySet[_leafKey(s.expr)] = 1; });
  });
  var keys = Object.keys(keySet).sort();

  [
    ["a mail template", "mailbox",    "/mail?folder=INBOX"],
    ["a wiki page",     "wiki/page",  "/wiki/web-links/href"],
  ].forEach(function (surface) {
    var tail = WEB_LINKS.href(surface[2]);
    var landed = _landedFrom(engine, surface[1], keys, tail);
    var wrong = (landed || []).filter(function (x) {
      return !x.ok || x.where !== surface[2];
    });
    count("a link the one reader built lands on exactly the path it was built from, from " +
      surface[0], landed !== null && landed.length > 0 && wrong.length === 0,
      wrong.map(function (x) { return x.href || x.where; }).join(" | ") ||
        ((landed || []).length + " links on " + surface[1]));
  });
}

// ---------------------------------------------------------------------------

function run() {
  var b = helpers.b;
  var source = fs.readFileSync(WEB_SOURCE, "utf8");

  theReaderStillRefusesWhatItIsFor(b);
  everyRenderedLinkTargetIsBuilt(b);
  console.log("");
  aTargetThatLeavesThisOriginIsRefused(b);
  var policy = theBodyPolicyIsTheOneTheServerServes(source);
  aHostileSenderCannotWriteALinkThatRuns(b, policy);
  console.log("");
  theSinkHoldsTheSchemePosition(b);
  console.log("");
  theOneReaderRefusesEveryCharacterThatOpensAHost(b);

  return helpers.getChecks();
}

module.exports = { name: "web-link-origin", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
