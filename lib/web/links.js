// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.web.links
 * @nav    Web interface
 * @title  Link targets
 * @order  20
 *
 * @intro
 *   The one reader for a link target this server renders.
 *
 *   Two surfaces build links: the browser surface in `lib/web/index.js`,
 *   which renders webmail and the operator interface, and the reference
 *   wiki in `lib/web/wiki/index.js`, which builds the pages served under
 *   `/wiki`. Both ask the same two questions of every target, and both
 *   ask them here. A copy in each surface is a place a case can be added
 *   to one and not the other, and the surface that then renders a link to
 *   another host is whichever copy nobody edited.
 *
 *   ## What a target is
 *
 *   Every link and every redirect is a path on this server. A leading
 *   slash does not make one: a browser reading `//host/x` takes what
 *   follows as an authority and leaves the origin, and it folds the
 *   backslash in `/\host/x` into a second slash and does the same. A tab
 *   inside the target is stripped before the parse, so a control byte can
 *   hide the shape from a naive reading of it.
 *
 *   `b.safeRedirect.resolve` already knows all of that, so `path` is its
 *   reading rather than a second one: a target it hands back unchanged is
 *   one it recognized as same origin.
 *
 *   ## What a template interpolates
 *
 *   Every template writes the leading slash of a link itself, as
 *   `href="/{{ inboxHref }}"`, so the value it interpolates cannot choose
 *   a scheme. `href` returns the path without that slash, and refuses a
 *   remainder beginning with a slash, a backslash, a tab, a line feed or
 *   a carriage return. After the template's own slash, a browser reads a
 *   second slash or a backslash as the start of a host name, and it
 *   removes the other three before it reads the URL at all, which leaves
 *   the slash that follows them in the first position.
 *
 *   ## Where the refusal lands
 *
 *   Both throw where the path is BUILT rather than where it becomes a
 *   link, because the alternative is an invariant that every separate
 *   string concatenation has to remember on its own.
 *
 *   A surface with a rule of its own keeps that rule at home and composes
 *   these: the wiki requires a target to sit under its own base path, and
 *   that requirement is the wiki's, so it is asked in the wiki and this
 *   pair is asked here.
 *
 *   ## What the framework will not route
 *
 *   A request path carrying a percent-encoded separator or a null byte is
 *   answered 400 before any route runs, because a gate matching the path
 *   and a consumer decoding it would disagree about where the request
 *   points. That refusal is correct and is not relaxed here.
 *
 *   It is asked here as well, on the path this server BUILDS. A target
 *   that carries one of those escapes is a link that renders, sits on the
 *   page, and answers 400 when a reader follows it, which is a defect
 *   that shows up as a browser failure rather than as a fault in the code
 *   that built the link. A value that needs the byte carries it in the
 *   query string, which the framework routes on and a path reader never
 *   splits.
 */

var b = require("../vendor/blamejs");

// The escapes the framework refuses in a request path: a percent-encoded
// slash, a percent-encoded backslash and a null byte. Matched against the
// path alone, which is the same portion the framework tests, so a query
// value carrying one of them is left alone.
var UNROUTABLE_IN_PATH = /%2[fF]|%5[cC]|%00/;

/**
 * @primitive blamepost.web.links.path
 * @signature blamepost.web.links.path(value)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one reader for every link target and redirect)
 * @related   blamepost.web.links.href
 *
 * One absolute path on this server, or a refusal.
 *
 * The value is handed to the framework's redirect resolver and kept only
 * when the resolver hands back what it was given, so a second slash, a
 * backslash, an authority hidden behind a control byte, a scripting
 * scheme and a bare absolute URL are each refused. A redirect takes its
 * target from here. A template takes the value `href` builds from it.
 *
 * It throws a TypeError naming the value, because a target is BUILT by
 * this server rather than read off a request: a refusal here is a fault
 * in the code that built it and not input to route around.
 *
 * It throws again when the portion before the query string carries a
 * percent-encoded separator or a null byte, which the framework answers
 * 400 for. Such a target renders as a link and fails when a reader
 * follows it; a value needing one of those bytes goes in the query
 * string.
 *
 * @example
 *   var links = require("./lib/web/links");
 *   links.path("/mail?folder=INBOX");
 *   // "/mail?folder=INBOX"
 */
function path(value) {
  if (typeof value === "string" && value.charAt(0) === "/" &&
      b.safeRedirect.resolve(value, { fallback: "" }) === value) {
    var cut = value.search(/[?#]/);
    var pathname = cut === -1 ? value : value.slice(0, cut);
    if (UNROUTABLE_IN_PATH.test(pathname)) {
      throw new TypeError(
        "blamepost.web.links: a link target's path carries a percent-encoded separator or " +
        "a null byte, which this server answers 400 for before any route runs. '" +
        String(value).slice(0, 64) + "' would render as a link and fail when it is " +
        "followed. Carry the value in the query string instead.");
    }
    return value;
  }
  throw new TypeError(
    "blamepost.web.links: a link target must be an absolute path on this server. " +
    "'" + String(value).slice(0, 64) + "' is not one, and a browser following it " +
    "would leave this origin.");
}

/**
 * @primitive blamepost.web.links.href
 * @signature blamepost.web.links.href(value)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one reader for every link target and redirect)
 * @related   blamepost.web.links.path
 *
 * The value a template interpolates into a link: an absolute path on
 * this server, checked by `path`, with its leading slash removed.
 *
 * The root path returns the empty string, which renders as `href="/"`. A
 * template that shows a link only when its value is non-empty shows no
 * link for the root.
 *
 * It throws a TypeError when the remainder begins with a slash, a
 * backslash, a tab, a line feed or a carriage return, each of which turns
 * the template's own slash into the first character of a host name.
 *
 * A value from here is a relative target when handed to a redirect, and a
 * path from `path` renders with two leading slashes when handed to a
 * template, so the two are not interchangeable.
 *
 * @example
 *   var links = require("./lib/web/links");
 *   links.href("/mail?folder=INBOX");
 *   // "mail?folder=INBOX"
 */
function href(value) {
  var tail = path(value).slice(1);
  // The first two name a host in the position the template's slash
  // opened. A browser removes the other three before it parses the URL,
  // which puts whatever follows them in that same position.
  var first = tail.charAt(0);
  if (first === "/" || first === "\\" || first === "\t" || first === "\n" || first === "\r") {
    throw new TypeError(
      "blamepost.web.links: a link written after a template's own slash must not begin " +
      "with a slash, a backslash or a control character. '" + String(value).slice(0, 64) +
      "' would render as a link to another host.");
  }
  return tail;
}

module.exports = {
  path: path,
  // allow:web-url-handed-to-the-browser-not-built an export table names this
  // module's own function rather than a value a template reads as a link
  href: href,
};
