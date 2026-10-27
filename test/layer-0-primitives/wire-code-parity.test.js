// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wire-code-parity: the reply a peer is written is the reply the documents
 * describe, and the tables that decide it agree with each other.
 *
 * A reply code is the one operator-visible value that a document can only
 * restate. It is not a setting, so no configuration carries it and no
 * `describe()` returns it; it is decided by a frozen table inside
 * `lib/mail/listeners.js` and read off a socket by somebody else's mail
 * server. Three shipped documents describe those codes in sentences, and
 * a sentence is correct on the day it is written and stays where it is
 * afterwards. The table moves underneath it.
 *
 * It has moved three ways already. A refusal was described as one
 * listener's when both listeners write it. The 554 family was summarized
 * in a form that left out two of its reasons. The temporary answer was
 * given as the answer whenever nothing could be delivered, at a point
 * where the permanent half had already split that case three ways.
 * Nothing read a table against a document in any of those cases.
 *
 * WHAT THIS FILE CAN HONESTLY ASK. Prose is not a table, so a check that
 * every reason in the table is named somewhere in a document is either
 * unmaintainable or empty. Three questions are answerable instead, and
 * each one fails in the direction that actually happens:
 *
 *   - The tables agree with each other. `_wireRefusal` writes a permanent
 *     code only when the same reason carries an enhanced status of the
 *     same class, so a reason whose two entries disagree is an entry that
 *     never reaches the wire and never says so. That question needs no
 *     document at all.
 *   - The documents that describe the handoff name every code it can
 *     write, and no other. This is read inside an anchored region rather
 *     than over the whole file, because a document names port 465 and RFC
 *     status 503 in other paragraphs and a scan over the file would read
 *     those as reply codes. A code added to the table fails both regions.
 *   - Where a document quotes the refusal SENTENCE, the code and the
 *     status in front of it are the ones the source writes with that
 *     sentence.
 *
 * WHAT IS NOT ASKED, and why a check for it would not fail. A scan that
 * read every `<code> <status>` a document quotes and held each against
 * the tables looks like the natural gate and is not soundly writable.
 * Three separate findings say so, each measured on this tree rather than
 * reasoned about:
 *
 *   - A reply code does not identify what wrote it. 550 is written by the
 *     delivery handoff, by the author binding, and by the framework's
 *     DMARC refusal at `550 5.7.26`, which no table here holds. Filtering
 *     a scan by code therefore calls the framework's replies wrong.
 *   - An enhanced status does not identify it either. 5.7.1 is the
 *     author binding's at 550 and the identity binding's at the
 *     framework's 553, and 5.6.0 is the author binding's at 550 and the
 *     MIME structure family's at 554.
 *   - The framework's own set cannot be enumerated to fill the gap. It
 *     builds a reply from a code constant and a separate status string,
 *     so `500 5.5.2` exists as a reply and as no literal anywhere. The
 *     operator guide also prints example queue output in which the last
 *     column is what a RECEIVING server answered, and no value here can
 *     ever describe somebody else's mail server.
 *
 * So the pairing is compared where the sentence beside it says which
 * refusal it belongs to, and nowhere else. A quoted pair with no sentence
 * is left alone rather than measured against a set that cannot be
 * completed.
 *
 * THE ANCHOR IS THE OPERATOR-FACING SENTENCE. Where a document quotes the
 * text of a refusal, the code and the status in front of that text are
 * compared against the ones the source pairs with it. The text is the
 * frozen half: it survives a variable being renamed, and a document that
 * still carries it while the code beside it moved is exactly the failure
 * this file exists for.
 *
 * Three mechanisms write a reply in that file and all three are read
 * here, because they share the RFC 3463 detail codes and a check that
 * knew only one of them would call the other two's replies wrong. The
 * delivery handoff pairs a reason with a code and a status; the author
 * binding refuses a `From` header at 550 with one of two statuses; and
 * the end-of-data refusal writes one fixed reply.
 *
 * The documents read are the ones the published package carries, taken
 * from the manifest that decides what goes into it. CHANGELOG.md is left
 * out of that set: a changelog entry describes what a released version
 * wrote, so it is correct about a code this server no longer writes, and
 * holding it against today's table would ask for history to be rewritten.
 *
 * The tables are read out of the source text rather than imported,
 * because none of the three is exported. A rename of one of them fails
 * this file loudly rather than passing it, which is the direction a
 * missing anchor has to fail in.
 *
 * No sockets, no database. It reads one source file and the shipped
 * documents.
 *
 * Run standalone: node test/layer-0-primitives/wire-code-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var check = helpers.check;
var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

var LISTENERS_SOURCE = "lib/mail/listeners.js";

// The document a released version is described in. It answers for the
// code that version wrote and is not moved when a later one changes.
var HISTORICAL_DOCUMENT = "CHANGELOG.md";

// The temporary answer a refusal the table does not name inherits from
// the framework. Both documents give it as the fallback, so an entry in
// the permanent table carrying this code would make that sentence false
// in a way neither document could show.
var INHERITED_FALLBACK_CODE   = "451";
var INHERITED_FALLBACK_STATUS = "4.3.0";

// Where each document describes what the delivery handoff answers, as the
// sentence that opens the description and the first thing after it. Both
// are asserted present before the region is read: an anchor that moved
// leaves an empty region, and an empty region satisfies every question
// asked of it.
var HANDOFF_REGIONS = [
  {
    rel:   "docs/operator-guide.md",
    start: "**A condition no later attempt can clear is answered permanently instead**",
    end:   "## What an account may put in",
  },
  {
    rel:   "ROADMAP.md",
    start: "The delivery handoff answers by what refused the message:",
    end:   "RFC 5321 §4.2.1.2",
  },
];

function _read(relative) {
  return nodeFs.readFileSync(nodePath.join(REPO_ROOT, relative), "utf8");
}

// A document's prose with every run of whitespace collapsed to one space.
// A reply quoted in a paragraph wraps at whatever column the paragraph
// reached, so `550 5.6.0 Message rejected: From or Sender header cannot
// be read as a single author` is four lines in the file and one sentence
// to a reader.
function _prose(relative) {
  return _read(relative).replace(/\s+/g, " ");
}

// Every document the published package carries, read out of the manifest
// that decides what goes into it. A hand-kept list here would be a fourth
// copy of that set and would fall behind it; the manifest cannot, because
// a document it does not name is one nobody installing this server ever
// receives. Directories in the manifest are read one level down, which is
// what keeps the vendored framework's own documents out: those are
// somebody else's claims and this file holds no value for them.
function shippedDocuments() {
  var out = [];
  var pkg = JSON.parse(_read("package.json"));
  (pkg.files || []).forEach(function (entry) {
    if (/\.md$/.test(entry)) {
      if (entry !== HISTORICAL_DOCUMENT) out.push(entry);
      return;
    }
    var dir = entry.replace(/\/$/, "");
    var full = nodePath.join(REPO_ROOT, dir);
    if (!nodeFs.existsSync(full) || !nodeFs.statSync(full).isDirectory()) return;
    nodeFs.readdirSync(full, { withFileTypes: true }).forEach(function (child) {
      if (child.isFile() && /\.md$/.test(child.name)) out.push(dir + "/" + child.name);
    });
  });
  return out.sort();
}

// ---- reading the tables out of the source ----------------------------------

// The body of the object literal whose opening brace is at `openIndex`,
// found by balancing braces while skipping strings and comments. A
// comment in these tables runs to several sentences and carries both
// quotes and braces, so a scan that did not skip them would stop in the
// middle of one.
function _objectBodyAt(source, openIndex) {
  var depth   = 0;
  var inStr   = null;
  var inLine  = false;
  var inBlock = false;
  for (var i = openIndex; i < source.length; i += 1) {
    var c = source.charAt(i);
    if (inLine) { if (c === "\n") inLine = false; continue; }
    if (inBlock) {
      if (c === "*" && source.charAt(i + 1) === "/") { inBlock = false; i += 1; }
      continue;
    }
    if (inStr) {
      if (c === "\\") { i += 1; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === "/" && source.charAt(i + 1) === "/") { inLine = true; i += 1; continue; }
    if (c === "/" && source.charAt(i + 1) === "*") { inBlock = true; i += 1; continue; }
    if (c === "\"" || c === "'") { inStr = c; continue; }
    if (c === "{") depth += 1;
    else if (c === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(openIndex + 1, i);
    }
  }
  return null;
}

// The body of `var <name> = Object.freeze({ ... })` or `var <name> = { ...
// }`, or null when the file holds no declaration under that name. Null is
// a failure at the call site rather than an empty table here, because a
// table this file cannot find is a table it is not comparing.
function tableBody(source, name) {
  var declaration = new RegExp("var\\s+" + name + "\\s*=\\s*(?:Object\\.freeze\\()?\\s*\\{");
  var at = source.search(declaration);
  if (at === -1) return null;
  return _objectBodyAt(source, source.indexOf("{", at));
}

// The string a value expression evaluates to when it is written out of
// string literals, or null when it names something instead. Two entries
// in these tables run past the line width and are written as a sum.
var STRING_PIECE = "\"(?:[^\"\\\\]|\\\\.)*\"";
var STRING_EXPR_RE = new RegExp(
  "^" + STRING_PIECE + "(?:\\s*\\+\\s*" + STRING_PIECE + "){0,8}$");

function _asString(expr) {
  var text = String(expr).trim();
  if (!STRING_EXPR_RE.test(text)) return null;
  var out = "";
  var re  = new RegExp(STRING_PIECE, "g");
  var m;
  while ((m = re.exec(text)) !== null) out += JSON.parse(m[0]);
  return out;
}

// Every `var <NAME> = "..."` in the file, so a table entry that names a
// constant instead of writing the sentence out is resolved to the same
// sentence a peer reads.
function constantStrings(source) {
  var out = {};
  var re  = new RegExp(
    "\\bvar\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(" + STRING_PIECE +
    "(?:\\s*\\+\\s*" + STRING_PIECE + "){0,8})\\s*;", "g");
  var m;
  while ((m = re.exec(source)) !== null) out[m[1]] = _asString(m[2]);
  return out;
}

// The entries of one table body, as key to resolved string. A value this
// parser cannot resolve to a string is recorded as null rather than
// dropped, so a table whose shape changed is visible as unresolved
// entries instead of as a shorter table.
var ENTRY_VALUE = "(?:" + STRING_PIECE + "|[A-Za-z_$][\\w$]*)";
var ENTRY_RE = new RegExp(
  "\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*(" + ENTRY_VALUE +
  "(?:\\s*\\+\\s*" + ENTRY_VALUE + "){0,8})", "g");

function tableEntries(body, constants) {
  var out = {};
  var text = String(body).split("\n").filter(function (line) {
    return !/^\s*\/\//.test(line);
  }).join("\n");
  var m;
  ENTRY_RE.lastIndex = 0;
  while ((m = ENTRY_RE.exec(text)) !== null) {
    var literal = _asString(m[2]);
    if (literal === null && Object.prototype.hasOwnProperty.call(constants, m[2].trim())) {
      literal = constants[m[2].trim()];
    }
    out[m[1]] = literal;
  }
  return out;
}

// ---- the three mechanisms that name a reply --------------------------------

// The refusals that ask the listener for a specific reply rather than
// inheriting the framework's temporary one. Anchored on the assignment
// SHAPE rather than on the name of the function around it, so a rename
// leaves this reading the same sites.
//
// Each site gives one code and one or more statuses. A site whose status
// is written out is one pairing; a site whose status is a value passed in
// is every key of the table its reply text is looked up in, which is the
// set the site itself refuses anything outside of.
var REPLY_SITE_RE = new RegExp(
  "err\\.smtpCode\\s*=\\s*\"(\\d{3})\"\\s*;" +
  "(?:\\s*//[^\\n]*)*" +
  "\\s*err\\.enhancedStatus\\s*=\\s*([^;]+);" +
  "(?:\\s*//[^\\n]*)*" +
  "\\s*err\\.replyText\\s*=\\s*([^;]+);", "g");

function namedReplySites(source, constants) {
  var sites = [];
  var m;
  REPLY_SITE_RE.lastIndex = 0;
  while ((m = REPLY_SITE_RE.exec(source)) !== null) {
    var code       = m[1];
    var statusExpr = m[2].trim();
    var textExpr   = m[3].trim();

    var status = _asString(statusExpr);
    if (status !== null) {
      sites.push({ code: code, status: status, text: _asString(textExpr) });
      continue;
    }
    // The status is chosen by the caller, so the pairings are whatever the
    // reply-text table this site reads is keyed by.
    var lookup = new RegExp("^([A-Za-z_$][\\w$]*)\\[" + statusExpr + "\\]$").exec(textExpr);
    if (lookup === null) { sites.push({ code: code, status: null, text: null }); continue; }
    var replies = tableEntries(tableBody(source, lookup[1]) || "", constants);
    Object.keys(replies).forEach(function (key) {
      sites.push({ code: code, status: key, text: replies[key] });
    });
  }
  return sites;
}

// ---- the tables are readable, and they agree with each other ---------------

var SOURCE     = _read(LISTENERS_SOURCE);
var CONSTANTS  = constantStrings(SOURCE);
var WIRE_CODE  = tableEntries(tableBody(SOURCE, "WIRE_PERMANENT_CODE") || "", CONSTANTS);
var STATUS     = tableEntries(tableBody(SOURCE, "REFUSAL_STATUS") || "", CONSTANTS);
var TEXT       = tableEntries(tableBody(SOURCE, "REFUSAL_TEXT") || "", CONSTANTS);
var SITES      = namedReplySites(SOURCE, CONSTANTS);

function _values(table) {
  var out = [];
  Object.keys(table).forEach(function (key) {
    if (table[key] !== null && out.indexOf(table[key]) === -1) out.push(table[key]);
  });
  return out.sort();
}

function theTablesAreReadable() {
  check("the module that decides the wire reply is readable and not empty",
    SOURCE.length > 10000);

  count("the permanent-code table is found under the name this file reads it by, and holds " +
    "entries",
    Object.keys(WIRE_CODE).length >= 20,
    Object.keys(WIRE_CODE).length + " reason(s)");

  count("the enhanced-status table is found and holds entries",
    Object.keys(STATUS).length >= 20,
    Object.keys(STATUS).length + " reason(s)");

  count("the refusal-text table is found and holds entries",
    Object.keys(TEXT).length >= 20,
    Object.keys(TEXT).length + " reason(s)");

  // A value this parser could not resolve is a table entry whose sentence
  // is unknown to the checks below, so it is named rather than skipped.
  var unresolved = Object.keys(TEXT).filter(function (key) { return TEXT[key] === null; });
  count("and every sentence in it resolves to the text a peer reads, so none of them is " +
    "carried past the comparisons below unread",
    unresolved.length === 0, unresolved.join(", ") || "none unresolved");

  count("the refusals that name their own reply are found by shape rather than by the name " +
    "of the function holding them",
    SITES.length >= 3, SITES.length + " pairing(s) over the named-reply sites");

  var unnamed = SITES.filter(function (site) { return site.status === null; });
  count("and each of them resolves to a status, because a site this parser reads as having " +
    "none is a reply it is not comparing",
    unnamed.length === 0,
    unnamed.map(function (s) { return s.code; }).join(", ") || "none unresolved");

  count("the permanent table writes more than one code, so the classes below are compared " +
    "against a set rather than against one value",
    _values(WIRE_CODE).length >= 2, _values(WIRE_CODE).join(" "));
}

// ---- a permanent code only reaches the wire with a status to match ---------

// The condition `_wireRefusal` applies before it writes anything. Both
// halves are read off the same reply by different peers, and the
// framework replaces a status whose class contradicts the code, so a
// reason whose two entries disagree writes a reply nobody composed. It
// fails toward the temporary answer instead, silently, which is a
// permanent condition being retried for the length of a queue lifetime.
function everyPermanentReasonCarriesAMatchingStatus() {
  var reasons   = Object.keys(WIRE_CODE);
  var missing   = [];
  var mismatched = [];
  var untexted  = [];

  reasons.forEach(function (reason) {
    var code   = WIRE_CODE[reason];
    var status = STATUS[reason];
    if (status === undefined) { missing.push(reason); return; }
    if (status.charAt(0) !== code.charAt(0)) {
      mismatched.push(reason + " is " + code + " with " + status);
    }
    if (TEXT[reason] === undefined) untexted.push(reason);
  });

  count("every reason the permanent table names is compared against the status table",
    reasons.length >= 20, reasons.length + " reason(s) compared");

  check("and each one has a status entry, because a reason with none is answered temporarily " +
    "however permanent it is" +
    (missing.length ? ", and these do not: " + missing.join(", ") : ""),
    missing.length === 0);

  check("and each status is of the code's own class, because a disagreement between the two " +
    "is a reply the framework rewrites and nobody wrote" +
    (mismatched.length ? ": " + mismatched.join("; ") : ""),
    mismatched.length === 0);

  check("and each one has a sentence of its own, because the fallback sentence tells a sender " +
    "the address could not be delivered to when the message is what was refused" +
    (untexted.length ? ", and these do not: " + untexted.join(", ") : ""),
    untexted.length === 0);

  // The other direction. A reason whose owner or the operator can clear it
  // is answered temporarily on purpose, and an entry in the permanent
  // table for one of them would spend a sender's retry window and then
  // destroy the message.
  var temporary = Object.keys(STATUS).filter(function (reason) {
    return STATUS[reason].charAt(0) === "4";
  });
  count("the reasons carrying a temporary status are compared against the permanent table too",
    temporary.length >= 1, temporary.join(", "));

  var promoted = temporary.filter(function (reason) {
    return Object.prototype.hasOwnProperty.call(WIRE_CODE, reason);
  });
  check("and none of them is in it, so a condition somebody can clear is not answered with a " +
    "code that tells the sender to stop" +
    (promoted.length ? ", and these are: " + promoted.join(", ") : ""),
    promoted.length === 0);
}

// ---- the documents name every code the handoff writes ----------------------

function theDocumentsNameEveryCodeTheHandoffWrites() {
  var wanted = _values(WIRE_CODE);

  HANDOFF_REGIONS.forEach(function (region) {
    var prose = _prose(region.rel);

    var from = prose.indexOf(region.start);
    count(region.rel + " still opens its description of what the delivery handoff answers",
      from !== -1, "the sentence \"" + region.start.slice(0, 60) + "\" is absent");

    var to = prose.indexOf(region.end, from + region.start.length);
    count("and " + region.rel + " still closes it, so the codes below are read out of that " +
      "description rather than out of the whole file",
      to !== -1, "the text \"" + region.end.slice(0, 60) + "\" is absent after it");

    var text  = prose.slice(from, to + region.end.length);
    var found = [];
    var re    = /`([45]\d\d)`/g;
    var m;
    while ((m = re.exec(text)) !== null) {
      if (found.indexOf(m[1]) === -1) found.push(m[1]);
    }
    found.sort();

    // Published, so a region that shrank to nothing cannot report the same
    // green as one that was read and found complete.
    count(region.rel + " gives reply codes inside that description rather than none",
      found.length > 0, found.join(" ") + " over " + text.length + " character(s)");

    var absent = wanted.filter(function (code) { return found.indexOf(code) === -1; });
    check(region.rel + " names every code the delivery handoff can write, so a code added to " +
      "the table is added to the sentence that describes it" +
      (absent.length ? ", and these are missing: " + absent.join(", ") : ""),
      absent.length === 0);

    var stray = found.filter(function (code) { return wanted.indexOf(code) === -1; });
    check("and no code the handoff cannot write, so a code removed from the table is removed " +
      "from " + region.rel + " with it" +
      (stray.length ? ", and these remain: " + stray.join(", ") : ""),
      stray.length === 0);

    count("and it gives the temporary answer everything else falls to, which is the half a " +
      "reader needs in order to read the permanent half as an exception",
      text.indexOf("`" + INHERITED_FALLBACK_CODE + " " + INHERITED_FALLBACK_STATUS + "`") !== -1,
      "the inherited fallback is not named in " + region.rel);
  });

  // The fallback is a fallback. An entry in either table under this code
  // or this status would make both sentences above false, and neither
  // document could show it.
  count("the permanent table writes no code that the documents give as the temporary fallback",
    _values(WIRE_CODE).indexOf(INHERITED_FALLBACK_CODE) === -1,
    _values(WIRE_CODE).join(" "));

  count("and the status table carries no entry under the fallback's own status",
    _values(STATUS).indexOf(INHERITED_FALLBACK_STATUS) === -1,
    _values(STATUS).join(" "));
}

// ---- where a document quotes the sentence, it quotes the reply too ---------

// The strongest half, and the one a rename cannot break. The sentence a
// peer reads is the frozen contract: it survives a table being renamed
// and disappears when the refusal is deleted. So where a document carries
// one, the code and the status in front of it are held against the ones
// the source writes with it.
function everyQuotedRefusalCarriesItsOwnReply() {
  var lines = [];

  Object.keys(WIRE_CODE).forEach(function (reason) {
    if (TEXT[reason] === undefined || TEXT[reason] === null) return;
    if (STATUS[reason] === undefined) return;
    lines.push({
      text:   TEXT[reason],
      prefix: WIRE_CODE[reason] + " " + STATUS[reason] + " ",
      from:   "the delivery handoff's " + reason + " refusal",
    });
  });
  SITES.forEach(function (site) {
    if (site.text === null || site.status === null) return;
    lines.push({
      text:   site.text,
      prefix: site.code + " " + site.status + " ",
      from:   "a refusal that names its own reply",
    });
  });

  count("the refusal sentences a peer reads are formed from the source rather than written " +
    "out here", lines.length >= 5, lines.length + " sentence(s)");

  var docs = shippedDocuments();
  count("the documents read are the ones the published package carries, off its own manifest " +
    "rather than off a list here, so a document added later is inside this comparison",
    docs.length >= 8, docs.length + " document(s): " + docs.join(", "));

  var quoted = 0;
  var wrong  = [];
  docs.forEach(function (rel) {
    var prose = _prose(rel);
    lines.forEach(function (line) {
      var at = 0;
      for (;;) {
        var i = prose.indexOf(line.text, at);
        if (i === -1) break;
        at = i + 1;
        // Only an occurrence presented as a reply is compared. A sentence
        // quoted inside a paragraph without a code in front of it is prose
        // about the refusal rather than a transcript of it.
        // The window is the widest a reply prefix can be, which is three
        // digits, a space, a status of at most nine characters and a
        // space. It bounds the scan rather than deciding what matches:
        // the pattern below is what decides that, and it is anchored to
        // the end of the window so a longer one would find the same hit.
        var written = /([45]\d\d \d\.\d{1,3}\.\d{1,3} )$/.exec(prose.slice(Math.max(0, i - 16), i));
        if (written === null) continue;
        quoted += 1;
        if (written[1] !== line.prefix) {
          wrong.push(rel + " puts \"" + written[1].trim() + "\" in front of " + line.from +
            ", which this server writes as \"" + line.prefix.trim() + "\"");
        }
      }
    });
  });

  count("a shipped document quotes at least one of them as a reply, so this comparison " +
    "reached a transcript rather than passing over an empty set",
    quoted >= 1, quoted + " quoted reply line(s) over " + docs.length + " document(s)");

  check("and every quoted reply carries the code and the status this server writes with that " +
    "sentence" + (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);
}

// ---- runner ----------------------------------------------------------------

function run() {
  theTablesAreReadable();
  everyPermanentReasonCarriesAMatchingStatus();
  theDocumentsNameEveryCodeTheHandoffWrites();
  everyQuotedRefusalCarriesItsOwnReply();
  return helpers.getChecks();
}

module.exports = { name: "wire-code-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
