// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wiki-rendering: every wiki page renders through the shipped template and
 * site layout, every link it renders reaches a page, and text taken from a
 * comment block never renders as markup.
 *
 * Every page of the real tree is rendered with the scope the route hands
 * the view. Each `/wiki` link in the output is followed to a page, and each
 * fragment to an element id on that page. Every link inside the content is
 * a path on this server.
 *
 * A fixture tree carries a hostile module block and a hostile primitive
 * block: a closing script tag, quote-breaking attribute values, HTML
 * elements in the title, the navigation group, the card, the intro, the
 * description, a list item, a heading, the signature, the status, the
 * specification text, a related token, the options and the example. The
 * rendered pages carry none of it as markup, carry each of it as escaped
 * text, and render the example and the options inside code blocks. The
 * same assertions are run first against a render that interpolates raw,
 * and they have to fire there.
 *
 * Run standalone: node test/layer-1-state/wiki-rendering.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

var wiki = require("../../lib/web/wiki");

var VIEWS_DIR = nodePath.join(helpers.REPO_ROOT, "lib", "web", "views");
var ORIGIN    = "https://mx.example.com:8443";

// The layout's own script tag, which every page carries once.
var LAYOUT_SCRIPT = "<script src=\"/static/islands/theme.js\" defer></script>";

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
  return abs;
}

function _block(lines) {
  return ["/**"].concat(lines.map(function (l) { return l.length > 0 ? " * " + l : " *"; }), [" */"])
    .join("\n") + "\n";
}

// The scope the route renders a wiki page with: the request lifecycle's
// values for an anonymous reader, the layout's page metadata, and the page.
function _scope(page) {
  return {
    csrfToken:       "test-csrf-token",
    theme:           "",
    notice:          null,
    account:         null,
    accountName:     "",
    isAdmin:         false,
    hostname:        "mx.example.com",
    inboxHref:       "",
    backPath:        page.path,
    siteNav:         [],
    pageTitle:       page.documentTitle,
    pageDescription: page.description,
    canonicalHref:   page.path.slice(1),
    canonicalUrl:    ORIGIN + page.path,
    previewImageUrl: ORIGIN + "/static/assets/site/shot-mailbox-light.png",
    previewImageAlt: "The blamepost mailbox.",
    wiki:            page,
  };
}

function _engine() {
  return helpers.b.template.create({ viewsDir: VIEWS_DIR });
}

function _main(html) {
  var start = html.indexOf("<main");
  var end = html.indexOf("</main>");
  return start === -1 || end === -1 ? "" : html.slice(start, end);
}

function _occurrences(text, needle) {
  var n = 0;
  for (var i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + needle.length)) n += 1;
  return n;
}

// ---- the real tree -----------------------------------------------------------

function everyRealPageRendersAndEveryLinkLands() {
  var engine = _engine();
  var site = wiki.build();
  var paths = site.paths();
  var html = new Map();
  var failures = [];

  paths.forEach(function (p) {
    try {
      html.set(p, engine.render(wiki.VIEW, _scope(site.page(p))));
    } catch (e) {
      failures.push(p + ": " + e.message);
    }
  });
  count("every one of the " + paths.length + " pages renders through the wiki view and the site layout",
    failures.length === 0 && paths.length > 0, failures.slice(0, 3).join(" | ") || paths.length + " rendered");

  var links = 0;
  var fragments = 0;
  var broken = [];
  var offSite = [];
  var linkRe = /href="([^"]*)"/g;
  html.forEach(function (text, p) {
    count("the page at " + p + " names itself in its title and heading",
      text.indexOf("<h1 class=\"band-title\">") !== -1 && text.indexOf("<title>") !== -1, p);
    var main = _main(text);
    var m;
    linkRe.lastIndex = 0;
    while ((m = linkRe.exec(main)) !== null) {
      var target = m[1];
      if (helpers.b.safeRedirect.resolve(target, { fallback: "" }) !== target || target.charAt(0) !== "/") {
        offSite.push(p + " -> " + target);
        continue;
      }
      if (target.indexOf(wiki.BASE_PATH) !== 0) continue;
      links += 1;
      var hash = target.indexOf("#");
      var path = hash === -1 ? target : target.slice(0, hash);
      if (site.page(path) === null) { broken.push(p + " -> " + target); continue; }
      if (hash !== -1) {
        fragments += 1;
        var id = "id=\"" + target.slice(hash + 1) + "\"";
        if (html.get(path).indexOf(id) === -1) broken.push(p + " -> " + target + " (no element " + id + ")");
      }
    }
  });
  count("the rendered pages carry wiki links to follow", links > 0, links + " links, " + fragments + " fragments");
  count("every wiki link reaches a page, and every fragment an element on it",
    broken.length === 0, broken.slice(0, 5).join(" | ") || "none broken");
  count("every link inside the content is a path on this server",
    offSite.length === 0, offSite.slice(0, 5).join(" | ") || "none off site");
}

// ---- hostile content ---------------------------------------------------------

function _hostileTree() {
  var root = helpers.tempDir("wiki-hostile");
  _write(root, "lib/hostile.js", "\"use strict\";\n" +
    _block([
      "@module   blamepost.hostile",
      "@title    Title\" onmouseover=\"alert(1)",
      "@nav      Nav <script>alert(15)</script>",
      "",
      "@intro",
      "  An intro closing a script: </script><script>alert(\"intro\")</script>",
      "  and an element <img src=x onerror=alert(2)> in `code </code><b>x</b>`.",
      "",
      "@card",
      "  Card \"quoted\" <svg onload=alert(3)>",
    ]) +
    _block([
      "@primitive blamepost.hostile.probe",
      "@signature blamepost.hostile.probe(\"</script><script>alert(4)</script>\")",
      "@since     0.1.0",
      "@status    experimental\" onclick=\"alert(5)",
      "@spec      RFC 5322 §3.4 (<img src=x onerror=alert(6)>), <b>Bold spec</b>, " +
        "internal (design: </textarea><script>alert(7)</script>)",
      "@related   blamepost.hostile.missing\"><script>alert(8)</script>",
      "",
      "A description with a quote-breaking attribute value: \" onfocus=\"alert(9)",
      "and an element <iframe src=\"javascript:alert(10)\"></iframe>.",
      "",
      "- a list item <script>alert(11)</script>",
      "",
      "## Heading <em>markup</em>",
      "",
      "@opts",
      "  evil: \"</code></pre><script>alert(12)</script>\",",
      "",
      "@example",
      "  var x = \"</script><script>alert(13)</script>\";",
      "  document.body.innerHTML = \"<img src=x onerror=alert(14)>\";",
    ]) +
    "function probe() {}\n");
  return root;
}

// Hostile markup that must never appear as markup in a rendered page.
var RAW_MARKERS = [
  "<script>alert", "</script><script>", "<img src=x", "<svg onload", "<iframe src=",
  "<b>Bold", "<b>x</b>", "<em>markup", "</textarea>", "</code></pre><script>",
  "onmouseover=\"", "onclick=\"", "onfocus=\"", "href=\"javascript", "src=\"javascript",
];

function _markupFindings(html) {
  var found = RAW_MARKERS.filter(function (marker) { return html.indexOf(marker) !== -1; });
  var scripts = _occurrences(html, "<script");
  var layoutScripts = _occurrences(html, LAYOUT_SCRIPT);
  if (scripts !== layoutScripts) found.push(scripts + " script tags where the layout carries " + layoutScripts);
  return found;
}

function theAssertionsFireOnARawRender(site) {
  var engine = _engine();
  var module = site.page("/wiki/hostile");
  var primitive = site.page("/wiki/hostile/probe");
  var example = primitive.sections.filter(function (s) { return s.id === "examples"; })[0].blocks[0].text;

  var raw = engine.renderString("<h1>{{{ t }}}</h1><pre><code>{{{ e }}}</code></pre>",
    { t: module.title, e: example });
  count("the markup check fires on the same text interpolated raw",
    _markupFindings(raw).length > 0, raw.slice(0, 160));

  var escaped = engine.renderString("<h1>{{ t }}</h1><pre><code>{{ e }}</code></pre>",
    { t: module.title, e: example });
  count("and it stays silent on the same text escaped",
    _markupFindings(escaped).length === 0, JSON.stringify(_markupFindings(escaped)));
}

function hostileBlockTextRendersAsText(site) {
  var engine = _engine();
  var rendered = {};
  site.paths().forEach(function (p) { rendered[p] = engine.render(wiki.VIEW, _scope(site.page(p))); });

  count("the hostile fixture produced its pages",
    ["/wiki", "/wiki/specs", "/wiki/hostile", "/wiki/hostile/probe", "/wiki/specs/rfc-5322",
      "/wiki/specs/b-bold-spec-b"].every(function (p) { return rendered[p] !== undefined; }),
    Object.keys(rendered).join(" "));

  Object.keys(rendered).forEach(function (p) {
    var found = _markupFindings(rendered[p]);
    count("no comment text renders as markup on " + p, found.length === 0, JSON.stringify(found));
  });

  var mod = rendered["/wiki/hostile"];
  var prim = rendered["/wiki/hostile/probe"];
  var expectations = [
    [mod, "<h1 class=\"band-title\">Title&quot; onmouseover=&quot;alert(1)</h1>", "the module title, escaped in its heading"],
    [mod, "<title>Title&quot; onmouseover=&quot;alert(1) | blamepost reference</title>", "the module title, escaped in the document title"],
    [mod, "content=\"Card &quot;quoted&quot; &lt;svg onload=alert(3)&gt;\"", "the card, escaped inside the description attribute"],
    [mod, "&lt;/script&gt;&lt;script&gt;alert(&quot;intro&quot;)&lt;/script&gt;", "the intro's script tags, as text"],
    [mod, "<code>code &lt;/code&gt;&lt;b&gt;x&lt;/b&gt;</code>", "inline code carrying markup, as text inside one code element"],
    [rendered["/wiki"], "Nav &lt;script&gt;alert(15)&lt;/script&gt;", "the navigation group, as text on the index"],
    [prim, "<code>blamepost.hostile.probe(&quot;&lt;/script&gt;&lt;script&gt;alert(4)&lt;/script&gt;&quot;)</code>", "the signature, as code"],
    [prim, "<span class=\"pill pill-warn\">experimental&quot; onclick=&quot;alert(5)</span>", "an unknown status, as text in the default pill"],
    [prim, "(&lt;img src=x onerror=alert(6)&gt;)", "the citation gloss, as text"],
    [prim, "&lt;/textarea&gt;&lt;script&gt;alert(7)&lt;/script&gt;", "the design note, as text"],
    [prim, "<code>blamepost.hostile.missing&quot;&gt;&lt;script&gt;alert(8)&lt;/script&gt;</code>", "an unresolved related token, as code"],
    [prim, "&quot; onfocus=&quot;alert(9)", "a quote-breaking description, as text"],
    [prim, "&lt;iframe src=&quot;javascript:alert(10)&quot;&gt;&lt;/iframe&gt;", "an element in the description, as text"],
    [prim, "<li>a list item &lt;script&gt;alert(11)&lt;/script&gt;</li>", "a list item, as text"],
    [prim, "<h3>Heading &lt;em&gt;markup&lt;/em&gt;</h3>", "a heading, as text"],
    [prim, "<pre class=\"codeblock\"><code>evil: &quot;&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;alert(12)&lt;/script&gt;&quot;,</code></pre>", "the options, inside a code block"],
    [prim, "<pre class=\"codeblock\"><code>var x = &quot;&lt;/script&gt;&lt;script&gt;alert(13)&lt;/script&gt;&quot;;\ndocument.body.innerHTML = &quot;&lt;img src=x onerror=alert(14)&gt;&quot;;</code></pre>", "the example, inside a code block"],
    [rendered["/wiki/specs/b-bold-spec-b"], "<h1 class=\"band-title\">&lt;b&gt;Bold spec&lt;/b&gt;</h1>", "a specification name, as text"],
  ];
  expectations.forEach(function (e) {
    count("the rendered page carries " + e[2], e[0].indexOf(e[1]) !== -1, e[1]);
  });
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root = null;
  try {
    everyRealPageRendersAndEveryLinkLands();
    root = _hostileTree();
    var site = wiki.build({ root: root });
    theAssertionsFireOnARawRender(site);
    hostileBlockTextRendersAsText(site);
  } finally {
    if (root !== null) helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "wiki-rendering", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
