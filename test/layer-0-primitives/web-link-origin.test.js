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
 * The templates interpolate link targets into `href` attributes. The
 * engine HTML-escapes `{{ expr }}`, which stops an attribute breakout
 * and does NOT stop a `javascript:` URI, because escaping leaves the
 * scheme intact. So escaping is not the guard here, and the guard is
 * upstream: every target is built through a helper that refuses anything
 * which is not an absolute path on this server.
 *
 * That helper enforces at the sites which CALL it. Nothing enforced that
 * an href-bearing value came from it, so the property was a convention
 * held by eleven separate string concatenations remembering to. A
 * convention held by memory is one that a twelfth site added next month
 * does not inherit.
 *
 * What is asserted, in the order the value travels:
 *
 *   1. The templates are the inventory. Every URL-bearing attribute in
 *      `lib/web/views/` carrying an interpolation is discovered by
 *      reading the templates, never from a list kept here, so a NEW
 *      template participates the day it lands rather than the day
 *      somebody remembers to add it.
 *   2. Every one of those values is built by a call, or is a
 *      root-relative literal, or is empty. A concatenation that reaches
 *      an attribute without passing through a call is the shape this
 *      exists to refuse, and a value read off the request is the same
 *      shape with a hostile author.
 *   3. Every root-relative literal really is same-origin, evaluated
 *      rather than eyeballed. A literal is constrained by being a
 *      literal only if somebody checked what it says.
 *   4. The refusal underneath actually refuses. The browser surface
 *      composes `b.safeRedirect.resolve` and compares the answer to what
 *      it was given, so this drives that composition with the targets a
 *      browser follows off site: an authority behind a second slash or a
 *      backslash, one hidden behind a tab or a control byte, a scripting
 *      scheme, a bare absolute URL.
 *   5. The message-body sanitizer drops a URL attribute whose scheme the
 *      browser would execute, through every encoding that has been used
 *      to smuggle one past a sanitizer that folded less than a browser
 *      does.
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

// Control bytes, built from their code points so this file carries none
// of its own and a reader is never guessing which byte is on the line.
var TAB = String.fromCharCode(9);
var NL  = String.fromCharCode(10);
var CR  = String.fromCharCode(13);
var NUL = String.fromCharCode(0);
var VT  = String.fromCharCode(11);
var FF  = String.fromCharCode(12);

// The markup attributes whose value a browser resolves as a URL. This is
// the set the framework's own sanitizer screens, narrowed to the ones a
// server-rendered template in this tree can carry; the point is that the
// inventory is not "href" alone, because the same mistake in `src` or
// `formaction` is the same mistake.
var URL_ATTRS = ["href", "src", "action", "formaction", "cite", "poster", "xlink:href"];

var URL_ATTR_RE = new RegExp(
  "\\b(" + URL_ATTRS.join("|").replace(/:/g, "\\:") + ")\\s*=\\s*\"([^\"]*)\"", "gi");

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
// Returns `{ file, line, attr, expr, raw }` per interpolation, where
// `raw` records the un-escaped `{{{ }}}` form.
function _linkSites(rel, text) {
  var out = [];
  URL_ATTR_RE.lastIndex = 0;
  var m;
  while ((m = URL_ATTR_RE.exec(text)) !== null) {
    var value = m[2];
    if (value.indexOf("{{") === -1) continue;
    var line = text.slice(0, m.index).split(/\r?\n/).length;
    INTERPOLATION_RE.lastIndex = 0;
    var inner;
    while ((inner = INTERPOLATION_RE.exec(value)) !== null) {
      out.push({
        file: rel,
        line: line,
        attr: m[1].toLowerCase(),
        expr: inner[1].trim(),
        raw:  RAW_INTERPOLATION_RE.test(inner[0]),
      });
    }
  }
  return out;
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

// Whether an identifier is bound to a call somewhere in the producer.
// `var base = _folderPath(folder);` is a built value under another name,
// and a binding to anything else is not.
function _boundToCall(source, name) {
  var re = new RegExp("\\b(?:var|let|const)\\s+" + name + "\\s*=\\s*([^;\\n]+)", "g");
  var m;
  var seen = 0;
  var allCalls = true;
  while ((m = re.exec(source)) !== null) {
    seen += 1;
    if (!CALL_RE.test(m[1].trim())) allCalls = false;
  }
  return { seen: seen, allCalls: allCalls };
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
function _classify(branch, source, b) {
  var expr = _unwrap(branch);
  if (expr.length === 0) return "the value is empty text, which parses as nothing at all";

  // Unwrapping can expose a conditional that was written in
  // parentheses, so its branches are classified rather than the whole.
  if (expr !== branch.trim()) {
    var inner = _branches(expr);
    if (inner.length > 1 || inner[0] !== expr) {
      var reasons = inner
        .map(function (part) { return _classify(part, source, b); })
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

  if (CALL_RE.test(expr)) return null;                 // built by a helper

  if (IDENTIFIER_RE.test(expr)) {
    var bound = _boundToCall(source, expr);
    if (bound.seen === 0) {
      return "the value is the identifier '" + expr + "', and nothing in this file binds " +
             "it, so what reaches the attribute cannot be established here";
    }
    if (!bound.allCalls) {
      return "the value is the identifier '" + expr + "', and at least one binding of it " +
             "is not a built target";
    }
    return null;
  }

  return "the value is an expression this gate cannot establish as a built target: " + expr;
}

// Every assignment of `key` in `source`, classified. One function so the
// live scan and the self-proof below run the SAME reader: a proof that
// exercised a second copy would establish that the copy still fires.
function _assignmentsOf(source, key, b) {
  var out = [];
  var re = new RegExp("(?:^|[\\s{,])" + key + "\\s*:", "g");
  var m;
  while ((m = re.exec(source)) !== null) {
    // A colon inside a comment is prose about the property rather than
    // an assignment of it.
    var lineStart = source.lastIndexOf("\n", m.index) + 1;
    var before = source.slice(lineStart, m.index);
    if (/^\s*(?:\/\/|\*|\/\*)/.test(before) || before.indexOf("//") !== -1) continue;

    var value = _valueAfter(source, m.index + m[0].length);
    out.push({
      line:  source.slice(0, m.index).split(/\r?\n/).length,
      value: value,
      reasons: _branches(value)
        .map(function (branch) { return _classify(branch, source, b); })
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

function theReaderStillRefusesWhatItIsFor(b) {
  var red = [
    ["a target concatenated in place",
      "var view = { probeHref: \"/mail/\" + name };"],
    ["a target read straight off the request",
      "var view = { probeHref: req.query.next };"],
    ["a target assembled in a template literal",
      "var view = { probeHref: " + BACKTICK + "/mail/${name}" + BACKTICK + " };"],
    ["a literal that leaves this origin behind a second slash",
      "var view = { probeHref: \"//evil.example/x\" };"],
    ["a literal carrying a scripting scheme",
      "var view = { probeHref: \"javascript:alert(1)\" };"],
    ["a literal that is not a path at all",
      "var view = { probeHref: \"https://evil.example/x\" };"],
    ["an identifier nothing in the file binds",
      "var view = { probeHref: mystery };"],
    ["an identifier bound to something that was never built",
      "var target = req.query.next;\nvar view = { probeHref: target };"],
    ["one good branch and one concatenated branch",
      "var view = { probeHref: ok ? _path(\"/a\") : \"/mail/\" + name };"],
  ];
  red.forEach(function (v) {
    var found = _assignmentsOf("// " + v[0] + "\n" + v[1], "probeHref", b);
    count("the reader refuses " + v[0],
      found.length === 1 && found[0].reasons.length > 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  var green = [
    ["a target built by a helper",
      "var view = { probeHref: _path(\"/admin/queue\") };"],
    ["a helper wrapping a concatenation",
      "var view = { probeHref: _path(base + \"?before=\" + cursor) };"],
    ["an empty value, which renders no link",
      "var view = { probeHref: \"\" };"],
    ["a root-relative literal",
      "var view = { probeHref: \"/admin/domains\" };"],
    ["a conditional whose branches are both fine",
      "var view = { probeHref: account ? _inboxPath(account) : \"\" };"],
    ["an identifier bound to a built target",
      "var base = _folderPath(folder);\nvar view = { probeHref: base };"],
    ["a nested conditional of built targets",
      "var view = { probeHref: a ? _p(\"/x\") : (bq ? _p(\"/y\") : \"\") };"],
  ];
  green.forEach(function (v) {
    var found = _assignmentsOf("// " + v[0] + "\n" + v[1], "probeHref", b);
    count("and it stays silent on " + v[0],
      found.length === 1 && found[0].reasons.length === 0,
      found.length === 0 ? "nothing was read at all" : JSON.stringify(found[0].reasons));
  });

  // A comment about a property is not an assignment of it, and a reader
  // that counted one would report a value nobody wrote.
  var commented = _assignmentsOf("// probeHref: \"//evil.example\" is what we must never do\n" +
    "var view = { probeHref: _path(\"/ok\") };", "probeHref", b);
  count("prose about a property is not read as an assignment of it",
    commented.length === 1 && commented[0].reasons.length === 0,
    JSON.stringify(commented.map(function (x) { return x.value; })));
}

// ---------------------------------------------------------------------------
// 1 + 2 + 3. The templates are the inventory, and every value they read
// is built.
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
    "<a href=\"{{ someTarget }}\">x</a><form action=\"{{ p.postTo }}\">");
  check("the attribute scanner still finds an interpolated link target", canary.length === 2);
  check("and it reads the attribute and the expression off it",
    canary[0].attr === "href" && canary[0].expr === "someTarget" &&
    canary[1].attr === "action" && canary[1].expr === "p.postTo");
  check("and it marks an un-escaped interpolation as one",
    _linkSites("c.html", "<a href=\"{{{ x }}}\">x</a>")[0].raw === true);

  count("the browser surface renders link targets, and this gate found them",
    sites.length > 0, sites.length + " interpolated URL attributes");

  console.log("\n  rendered link targets, by template:");
  sites.forEach(function (s) {
    console.log("    " + s.file + ":" + s.line + "  " + s.attr + "=\"{{ " + s.expr + " }}\"");
  });

  // An un-escaped interpolation in a URL attribute is strictly worse
  // than an escaped one: it re-opens the attribute breakout that
  // escaping closes, on top of the scheme that escaping never closed.
  var rawSites = sites.filter(function (s) { return s.raw; });
  count("no link target is interpolated un-escaped, which would re-open the attribute " +
    "breakout on top of the scheme",
    rawSites.length === 0,
    rawSites.map(function (s) { return s.file + ":" + s.line; }).join(", ") || "none");

  var source = fs.readFileSync(WEB_SOURCE, "utf8");
  var keys = {};
  sites.forEach(function (s) { keys[_leafKey(s.expr)] = 1; });
  var keyNames = Object.keys(keys).sort();
  count("every interpolation resolved to a property the producer can be searched for",
    keyNames.length > 0, keyNames.join(", "));

  var findings = [];
  var producers = 0;
  console.log("\n  where each one is built:");
  keyNames.forEach(function (key) {
    var assignments = _assignmentsOf(source, key, b);
    assignments.forEach(function (a) {
      producers += 1;
      var flat = a.value.replace(/\s+/g, " ");
      console.log("    " + (a.reasons.length ? "REFUSED " : "built   ") +
        "lib/web/index.js:" + a.line + "  " + key + ": " + flat.slice(0, 90));
      a.reasons.forEach(function (r) {
        findings.push("lib/web/index.js:" + a.line + " " + key + ": " + r);
      });
    });
    count("the producer builds '" + key + "' somewhere, so the template is not reading a " +
      "value nothing sets", assignments.length > 0, assignments.length + " assignments");
  });

  count("the producer scan reached the assignments rather than reporting a clean file it " +
    "never read", producers > 0, producers + " assignments classified");

  count("every value that reaches a URL attribute is built, a root-relative literal, or " +
    "empty", findings.length === 0, findings.join(" | ") || "none");
}

// ---------------------------------------------------------------------------
// 4. The refusal underneath actually refuses.
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
    ["a folder",                          "/mail/INBOX"],
    ["a folder whose name needed escaping", "/mail/" + encodeURIComponent("Sent Items")],
    ["a page of a listing",               "/admin/accounts?offset=25&limit=25"],
    ["a compose form with its source",    "/compose?source=abc&folder=INBOX&mode=reply"],
    ["a message asking for its images",   "/mail/INBOX/objid?images=on"],
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
// 5. A hostile sender writes the message body.
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

// Every URL-bearing attribute the sanitizer left behind.
function _urlAttrsIn(html) {
  var out = [];
  var re = /\b(href|src|cite|action|formaction|poster|srcdoc)\s*=\s*"([^"]*)"/gi;
  var m;
  while ((m = re.exec(html)) !== null) out.push(m[1].toLowerCase() + "=" + m[2]);
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

function run() {
  var b = helpers.b;
  var source = fs.readFileSync(WEB_SOURCE, "utf8");

  theReaderStillRefusesWhatItIsFor(b);
  everyRenderedLinkTargetIsBuilt(b);
  console.log("");
  aTargetThatLeavesThisOriginIsRefused(b);
  var policy = theBodyPolicyIsTheOneTheServerServes(source);
  aHostileSenderCannotWriteALinkThatRuns(b, policy);

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
