// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * signature-arity: each `@signature` is compared against the function
 * declared directly beneath its documentation block.
 *
 * `scripts/validate-source-comment-blocks.js` reports, per block:
 *
 *   - a parameter count that differs from the declared function's;
 *   - a parameter marked `?` that the body provably refuses when the
 *     argument is omitted;
 *   - a function beneath the block that is neither named nor bound under
 *     the name the signature documents;
 *   - a signature that names a different primitive from the block's token;
 *   - a callable signature with no function directly beneath it, and a
 *     signature without parentheses over a function bound under its name;
 *   - a block with no `@signature`, or one it cannot parse.
 *
 * A signature without parentheses over anything else documents a
 * sub-handle or a constant. It has no arity, and it is skipped rather than
 * reported.
 *
 * The first vectors carry the shape two listing verbs had while documented
 * as `(opts?)`: the body defaults the argument to `{}` and hands
 * `opts.domain` to a helper whose first statement throws on `undefined`.
 * The parameter counts agreed, so only the optional-marker check can see
 * it.
 *
 * The boundary vectors are the shapes a body uses to tolerate an omitted
 * argument, including every one the optional parameters in lib/ use. Each
 * must stay silent: the check reports only what it can prove throws.
 *
 * Every vector is a source string, read into a record by the shared reader
 * in `scripts/source-primitives.js`, except the last two sections, which run
 * the gate over a fixture tree in a temporary directory and over this
 * repository's own lib/.
 *
 * Run standalone: node test/layer-0-primitives/signature-arity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var gate     = require("../../scripts/validate-source-comment-blocks.js");

var sourcePrimitives = require("../../scripts/source-primitives.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT      = helpers.REPO_ROOT;
var RUN_CEILING_MS = 60000;

// ---- fixtures -------------------------------------------------------------

// One documentation block carrying every tag the other rules require, so a
// vector fails only on the rule it was written for. A null signature leaves
// the tag out.
function _block(indent, token, signature) {
  var lines = ["/**", " * @primitive " + token];
  if (signature !== null) lines.push(" * @signature " + signature);
  lines.push(
    " * @since     0.1.0",
    " * @status    experimental",
    " * @spec      internal (design: fixture)",
    " *",
    " * A fixture primitive, described at enough length to count as prose.",
    " */");
  return lines.map(function (l) { return indent + l; }).join("\n");
}

// A module holding one block. `preamble` is code above the block and
// `code` is everything from the line directly beneath it.
function _module(token, signature, code, preamble) {
  return ["\"use strict\";", preamble || "", _block("", token, signature), code, ""].join("\n");
}

// The temporary tree each vector's source is written into, created on first
// use and removed when the run ends.
var _recordTree = null;

// The record the shared reader builds for the block declaring `token` in
// `source`. The source is written to a file and read back through
// scripts/source-primitives.js, so each vector checks the record the gate
// receives, `signature` and `end` included.
function _record(source, token) {
  if (_recordTree === null) _recordTree = helpers.tempDir("signature-records");
  var file = nodePath.join(_recordTree, "lib", "fixture.js");
  nodeFs.mkdirSync(nodePath.dirname(file), { recursive: true });
  nodeFs.writeFileSync(file, source, "utf8");
  var hits = sourcePrimitives.reader.at(_recordTree).collectPrimitives([file])
    .filter(function (p) { return p.token === token; });
  if (hits.length !== 1) throw new Error("fixture declares " + hits.length + " block(s) for " + token);
  return hits[0];
}

function _check(source, token) {
  return gate.signatureFindings(_record(source, token), source);
}

function _kinds(result) {
  return result.findings.map(function (f) { return f.kind; });
}

function _find(result, kind) {
  var hit = result.findings.filter(function (f) { return f.kind === kind; });
  return hit.length > 0 ? hit[0] : null;
}

// The two listing verbs and their helper, as they were written when the
// signatures still marked the argument optional.
function _listingVerbs(failingSignature, reportersSignature) {
  return [
    "\"use strict\";",
    "function create(opts) {",
    "  function _listedDomain(value, label) {",
    "    if (value === undefined || value === null || value === \"\") {",
    "      throw err(BAD_OPTS,",
    "        label + \" answers about one hosted domain and has to be told which one.\");",
    "    }",
    "    return address.canonicalDomain(value, label + \" domain\");",
    "  }",
    "",
    _block("  ", "fixture.reports.failingSources", failingSignature),
    "  async function failingSources(listOpts) {",
    "    listOpts = listOpts || {};",
    "    var wanted = _listedDomain(listOpts.domain, \"failingSources\");",
    "    var span   = _span(listOpts, \"failingSources\");",
    "    var everything = listOpts.includeUnauthenticated === true;",
    "    return { domain: wanted, span: span, everything: everything };",
    "  }",
    "",
    _block("  ", "fixture.reports.reporters", reportersSignature),
    "  function reporters(listOpts) {",
    "    listOpts = listOpts || {};",
    "    var wanted = _listedDomain(listOpts.domain, \"reporters\");",
    "    return { domain: wanted };",
    "  }",
    "",
    "  return { failingSources: failingSources, reporters: reporters };",
    "}",
    "",
  ].join("\n");
}

// ---- the shape that shipped -----------------------------------------------

function theShippedShapeIsRefused() {
  var marked = _listingVerbs("reports.failingSources(opts?)", "reports.reporters(opts?)");
  ["fixture.reports.failingSources", "fixture.reports.reporters"].forEach(function (token) {
    var r = _check(marked, token);
    var f = _find(r, "optional-parameter-required");
    count("shipped shape: " + token + " documented (opts?) is refused",
      f !== null, JSON.stringify(r.findings));
    count("shipped shape: " + token + " refusal names the helper and the field handed to it",
      f !== null && f.msg.indexOf("_listedDomain") !== -1 && f.msg.indexOf("listOpts.domain") !== -1,
      f && f.msg);
    count("shipped shape: " + token + " parameter counts agreed, so arity did not report it",
      r.compared === true && _kinds(r).indexOf("arity-mismatch") === -1, JSON.stringify(r));
    count("shipped shape: " + token + " had its one optional marker examined",
      r.optionalChecked === 1, String(r.optionalChecked));
  });

  var required = _listingVerbs("reports.failingSources(opts)", "reports.reporters(opts)");
  ["fixture.reports.failingSources", "fixture.reports.reporters"].forEach(function (token) {
    var r = _check(required, token);
    count("shipped shape: " + token + " documented (opts) is silent and compared",
      r.findings.length === 0 && r.compared === true && r.optionalChecked === 0,
      JSON.stringify(r));
  });
}

// ---- omissions the body provably refuses ----------------------------------

var REFUSED = [
  { name: "a dereference before anything tests the argument",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var id = opts.id;\n  return id;\n}" },
  { name: "a dereference inside an if header",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (opts.id) return opts.id;\n  return null;\n}" },
  { name: "a dereference in the arguments of a call that is returned",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  return lookup(opts.id, \"fetch\");\n}" },
  { name: "a dereference after other statements that do not name it",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var started = Date.now();\n  if (started < 0) { log(started); }\n" +
          "  var id = opts.id;\n  return id;\n}" },
  { name: "defaulted, then refused by the if that reads it",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  opts = opts || {};\n" +
          "  if (typeof opts.id !== \"string\" || opts.id.length === 0) {\n" +
          "    throw new TypeError(\"fetch: opts.id is required\");\n  }\n  return opts.id;\n}" },
  { name: "defaulted, then a field of a missing field read",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  opts = opts || {};\n  return opts.range.start;\n}" },
  { name: "positional, refused by an if without braces",
    sig:  "widgets.label(name?)",
    code: "function label(name) {\n  if (typeof name !== \"string\") throw new TypeError(\"label: name\");\n" +
          "  return name;\n}" },
  { name: "positional, refused by a negated array test",
    sig:  "widgets.tagAll(ids?)",
    code: "function tagAll(ids) {\n  if (!Array.isArray(ids)) {\n    throw new TypeError(\"tagAll: ids\");\n" +
          "  }\n  return ids.length;\n}" },
  { name: "positional, handed to a helper that refuses undefined",
    sig:  "widgets.label(name?)",
    preamble: "function _required(value, what) {\n  if (value == null) {\n" +
              "    throw new TypeError(what + \" is required\");\n  }\n  return value;\n}",
    code: "function label(name) {\n  var checked = _required(name, \"label\");\n  return checked;\n}" },
  { name: "a second optional argument, refused while the first is tolerated",
    sig:  "widgets.move(from?, to?)",
    code: "function move(from, to) {\n  var origin = from || \"here\";\n" +
          "  if (to === undefined) {\n    throw new TypeError(\"move: to\");\n  }\n  return origin + to;\n}",
    optional: 2 },
];

function everyOmissionTheBodyProvablyRefusesIsReported() {
  REFUSED.forEach(function (v) {
    var token = "fixture." + v.sig.replace(/\(.*$/, "");
    var source = _module(token, v.sig, v.code, v.preamble);
    var r = _check(source, token);
    var f = _find(r, "optional-parameter-required");
    count("refused omission: " + v.name, f !== null && r.findings.length === 1,
      JSON.stringify(r.findings));
    count("refused omission: " + v.name + " (every optional marker examined)",
      r.optionalChecked === (v.optional || 1), String(r.optionalChecked));
  });
}

// ---- bodies that may tolerate an omitted argument -------------------------

var TOLERATED = [
  // The idioms the optional parameters in lib/ use.
  { name: "defaulted, then read with a fallback",
    sig:  "widgets.load(opts?)",
    code: "function load(opts) {\n  opts = opts || {};\n  var env = opts.env || process.env;\n  return env;\n}" },
  { name: "tested inside a ternary",
    sig:  "widgets.level(env?)",
    code: "function level(env) {\n  var source = (env && typeof env === \"object\") ? env : process.env;\n" +
          "  return source.LEVEL;\n}" },
  { name: "replaced by a fallback before any read",
    sig:  "widgets.seal(token, vault?)",
    code: "function seal(token, vault) {\n  var store = vault || fallback;\n" +
          "  if (typeof store.seal !== \"function\") {\n    throw new TypeError(\"seal: vault\");\n  }\n" +
          "  return store.seal(token);\n}" },
  { name: "defaulted inside a call",
    sig:  "widgets.resolver(opts?)",
    code: "function resolver(opts) {\n" +
          "  return make(Object.assign({ profile: \"strict\" }, opts || {}));\n}" },
  { name: "defaulted, then refused only inside a nested block",
    sig:  "widgets.send(message, opts?)",
    code: "async function send(message, sendOpts) {\n  sendOpts = sendOpts || {};\n" +
          "  var built = build(message);\n  if (binding !== null) {\n    if (!sendOpts.actor) {\n" +
          "      throw new TypeError(\"send: actor\");\n    }\n  }\n  return built;\n}" },
  { name: "tested for truth before use",
    sig:  "widgets.list(domain?)",
    code: "function list(domain) {\n  if (domain) return selectors(domain);\n  return all();\n}" },
  { name: "defaulted, then a field compared in an if that does not throw",
    sig:  "widgets.list(opts?)",
    code: "function list(opts) {\n  opts = opts || {};\n" +
          "  if (opts.domain !== undefined && opts.domain !== null) {\n    query = where(opts.domain);\n" +
          "  }\n  return query;\n}" },
  { name: "defaulted, then the object itself handed to a helper that refuses undefined",
    sig:  "widgets.rollup(opts?)",
    preamble: "function _span(o, what) {\n  if (o === undefined) {\n    throw new TypeError(what);\n  }\n" +
              "  return o;\n}",
    code: "function rollup(rollupOpts) {\n  rollupOpts = rollupOpts || {};\n" +
          "  var span = _span(rollupOpts, \"rollup\");\n  return span;\n}" },
  { name: "defaulted, then a field compared inside a ternary",
    sig:  "widgets.stop(opts?)",
    code: "async function stop(stopOpts) {\n  stopOpts = stopOpts || {};\n" +
          "  var timeoutMs = stopOpts.timeoutMs === undefined ? 5000 : stopOpts.timeoutMs;\n" +
          "  return timeoutMs;\n}" },
  { name: "defaulted to a new name",
    sig:  "widgets.sweep(opts?)",
    code: "async function sweep(runOpts) {\n  var settings = runOpts || {};\n" +
          "  return settings.dryRun === true;\n}" },
  { name: "defaulted, then a field read and compared",
    sig:  "widgets.ingest(raw, opts?)",
    code: "function ingest(raw, ingestOpts) {\n  ingestOpts = ingestOpts || {};\n" +
          "  var now = typeof ingestOpts.now === \"number\" ? ingestOpts.now : Date.now();\n" +
          "  return raw + now;\n}" },

  // The boundary the check must not cross.
  { name: "defaulted by an if",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (!opts) opts = {};\n  var id = opts.id;\n  return id;\n}" },
  { name: "read behind a short circuit",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var id = opts && opts.id;\n  return id;\n}" },
  { name: "read in one arm of a ternary",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var id = ready ? opts.id : null;\n  return id;\n}" },
  { name: "read through optional chaining",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  return opts?.id;\n}" },
  { name: "given a default value in the parameter list",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts = {}) {\n  return opts.id;\n}" },
  { name: "guarded by the arguments object",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (arguments.length === 0) return all();\n  return byId(opts.id);\n}" },
  { name: "read after a return without braces",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (!enabled) return null;\n  return opts.id;\n}" },
  { name: "read after a return inside a block",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (!enabled) {\n    return null;\n  }\n  return opts.id;\n}" },
  { name: "read after a return that ends its line",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  return\n  opts.id;\n}" },
  { name: "read inside a function expression",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var read = function () { return opts.id; };\n  return read;\n}" },
  { name: "read inside a callback",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  items.forEach(function (item) { item.owner = opts.owner; });\n" +
          "  return items;\n}" },
  { name: "read inside an arrow without braces",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var read = () => opts.id;\n  return read;\n}" },
  { name: "read in the body of an if without braces",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (ready) opts.id = 1;\n  return null;\n}" },
  { name: "read in an else-if header",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  if (ready) {\n    go();\n  } else if (opts.id) {\n    stay();\n  }\n" +
          "  return null;\n}" },
  { name: "read inside a try",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  try {\n    return opts.id;\n  } catch (e) {\n    return null;\n  }\n}" },
  { name: "read inside a switch case",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  switch (mode) {\n    case \"a\": return opts.id;\n" +
          "    default: return null;\n  }\n}" },
  { name: "shadowed by a nested function's parameter",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  function inner(opts) { return opts.id; }\n  return inner({ id: 1 });\n}" },
  { name: "named only in a comment, a string and a regular expression before a guarded read",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  // opts.id is read below only when present\n" +
          "  var label = \"opts.id\";\n  var shape = /opts.id/;\n  if (opts) return opts.id;\n" +
          "  return label + shape;\n}" },
  { name: "assigned inside a template literal",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  var note = `${opts = opts || {}}`;\n  return opts.id + note;\n}" },
  { name: "defaulted, then an inherited member tested",
    sig:  "widgets.fetch(opts?)",
    code: "function fetch(opts) {\n  opts = opts || {};\n" +
          "  if (!opts.hasOwnProperty) {\n    throw new TypeError(\"fetch\");\n  }\n  return opts;\n}" },
  { name: "defaulted, then handed to a helper that returns rather than throws",
    sig:  "widgets.fetch(opts?)",
    preamble: "function _optional(value) {\n  if (value === undefined) return null;\n  return value;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = _optional(opts.id);\n  return id;\n}" },
  { name: "defaulted, then handed to a helper whose refusal needs a second condition",
    sig:  "widgets.fetch(opts?)",
    preamble: "function _typed(value) {\n  if (value !== undefined && typeof value !== \"string\") {\n" +
              "    throw new TypeError(\"typed\");\n  }\n  return value;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = _typed(opts.id);\n  return id;\n}" },
  { name: "defaulted, then handed to a helper reached through a member",
    sig:  "widgets.fetch(opts?)",
    preamble: "function required(value) {\n  if (value === undefined) {\n    throw new TypeError(\"x\");\n" +
              "  }\n  return value;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = check.required(opts.id);\n  return id;\n}" },
  { name: "defaulted, then handed to a helper declared twice",
    sig:  "widgets.fetch(opts?)",
    preamble: "function one() {\n  function _need(value) { if (value === undefined) { throw new TypeError(\"a\"); } }\n" +
              "  return _need;\n}\nfunction two() {\n  function _need(value) { return value; }\n  return _need;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = _need(opts.id);\n  return id;\n}" },
  { name: "defaulted, then handed to an async helper",
    sig:  "widgets.fetch(opts?)",
    preamble: "async function _need(value) {\n  if (value === undefined) {\n    throw new TypeError(\"x\");\n" +
              "  }\n  return value;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = _need(opts.id);\n  return id;\n}" },
  { name: "defaulted, then handed to a helper nested in another call",
    sig:  "widgets.fetch(opts?)",
    preamble: "function _need(value) {\n  if (value === undefined) {\n    throw new TypeError(\"x\");\n" +
              "  }\n  return value;\n}",
    code: "function fetch(opts) {\n  opts = opts || {};\n  var id = wrap(ready && _need(opts.id));\n  return id;\n}" },
];

function aBodyThatMayTolerateOmissionIsLeftAlone() {
  TOLERATED.forEach(function (v) {
    var token = "fixture." + v.sig.replace(/\(.*$/, "");
    var source = _module(token, v.sig, v.code, v.preamble);
    var r = _check(source, token);
    count("tolerated omission: " + v.name + " is silent", r.findings.length === 0,
      JSON.stringify(r.findings));
    count("tolerated omission: " + v.name + " was compared, not skipped",
      r.compared === true && r.optionalChecked === 1, JSON.stringify(r));
  });
}

// ---- parameter counts -----------------------------------------------------

function parameterCountsAreComparedAgainstTheDeclarationBeneath() {
  var fewer = _module("fixture.widgets.move", "widgets.move(from, to)",
    "function move(from, to, opts) {\n  return [from, to, opts];\n}");
  var r = _check(fewer, "fixture.widgets.move");
  var f = _find(r, "arity-mismatch");
  count("arity: a signature naming two parameters over a function taking three is refused",
    f !== null && /2/.test(f.msg) && /3/.test(f.msg) && f.msg.indexOf("move") !== -1,
    JSON.stringify(r.findings));

  var more = _module("fixture.widgets.move", "widgets.move(from, to, opts?)",
    "function move(from, to) {\n  return [from, to];\n}");
  r = _check(more, "fixture.widgets.move");
  count("arity: a signature naming an optional parameter the function does not declare is refused",
    _find(r, "arity-mismatch") !== null && r.optionalChecked === 0, JSON.stringify(r));

  var FORMS = [
    { name: "a parameter named differently",
      sig:  "widgets.send(message, opts?)",
      code: "async function send(message, sendOpts) {\n  sendOpts = sendOpts || {};\n  return message;\n}" },
    { name: "a destructured parameter with a default, and a rest parameter",
      sig:  "widgets.merge(base, patch?, ...rest)",
      code: "function merge(base, { a, b } = {}, ...rest) {\n  return [base, a, b, rest];\n}" },
    { name: "defaults that contain commas and parentheses",
      sig:  "widgets.pad(text, width?, fill?)",
      code: "function pad(text, width = Math.max(1, 2), fill = \",\") {\n  return text + width + fill;\n}" },
    { name: "no parameters",
      sig:  "widgets.state()",
      code: "function state() {\n  return 1;\n}" },
    { name: "an awaited signature",
      sig:  "await client.verifyToken()",
      code: "async function verifyToken() {\n  return true;\n}" },
    { name: "a function expression assigned to a variable",
      sig:  "widgets.run(job)",
      code: "var run = async function (job) {\n  return job;\n};" },
    { name: "an arrow function assigned to a constant",
      sig:  "widgets.stop(opts)",
      code: "const stop = (opts) => {\n  return opts;\n};" },
    { name: "an arrow function with one bare parameter",
      sig:  "widgets.twice(n)",
      code: "var twice = n => n * 2;" },
    { name: "a function assigned to an export",
      sig:  "widgets.close(handle)",
      code: "module.exports.close = function (handle) {\n  return handle;\n};" },
  ];
  FORMS.forEach(function (v) {
    var token = "fixture." + v.sig.replace(/^await\s+/, "").replace(/\(.*$/, "");
    var source = _module(token, v.sig, v.code);
    var result = _check(source, token);
    count("arity: " + v.name + " is compared and agrees",
      result.compared === true && result.findings.length === 0, JSON.stringify(result));
  });

  var methods = [
    "\"use strict\";",
    "var api = {",
    _block("  ", "fixture.api.describe", "api.describe(verbose)"),
    "  describe(verbose) {",
    "    return verbose;",
    "  },",
    _block("  ", "fixture.api.close", "api.close(handle, opts?)"),
    "  close: function (handle, opts) {",
    "    return [handle, opts];",
    "  },",
    "};",
    "",
  ].join("\n");
  ["fixture.api.describe", "fixture.api.close"].forEach(function (token) {
    var result = _check(methods, token);
    count("arity: an object member " + token + " is compared and agrees",
      result.compared === true && result.findings.length === 0, JSON.stringify(result));
  });
}

// ---- a block over the wrong function --------------------------------------

function aBlockOverTheWrongFunctionIsRefused() {
  var misplaced = _module("fixture.reports.failingSources", "reports.failingSources(opts)",
    "function reporters(listOpts) {\n  return listOpts;\n}\n" +
    "module.exports = { reporters: reporters };");
  var r = _check(misplaced, "fixture.reports.failingSources");
  var f = _find(r, "function-name-mismatch");
  count("placement: a block documenting failingSources over reporters is refused",
    f !== null && f.msg.indexOf("failingSources") !== -1 && f.msg.indexOf("reporters") !== -1,
    JSON.stringify(r.findings));
  count("placement: a block over the wrong function is not compared against it",
    r.compared === false && _kinds(r).indexOf("arity-mismatch") === -1, JSON.stringify(r));

  var called = _module("fixture.accounts.create", "accounts.create(opts)",
    "async function createAccount(opts) {\n  return opts;\n}\n" +
    "module.exports = { create: createAccount() };");
  r = _check(called, "fixture.accounts.create");
  count("placement: a member holding the function's RESULT is not a binding of the function",
    _find(r, "function-name-mismatch") !== null, JSON.stringify(r.findings));

  var BOUND = [
    { name: "an object key",
      token: "fixture.accounts.create", sig: "accounts.create(opts)",
      code: "async function createAccount(opts) {\n  return opts;\n}\n" +
            "module.exports = { create: createAccount };" },
    { name: "a quoted object key",
      token: "fixture.accounts.delete", sig: "accounts.delete(opts)",
      code: "async function remove(opts) {\n  return opts;\n}\n" +
            "module.exports = {\n  \"delete\":     remove,\n};" },
    { name: "a member assignment, with the signature naming a method of the token",
      token: "fixture.listeners.relay", sig: "listeners.relay.send(envelope)",
      code: "async function _relaySend(envelope) {\n  return envelope;\n}\n" +
            "relayHandle.send = _relaySend;" },
  ];
  BOUND.forEach(function (v) {
    var source = _module(v.token, v.sig, v.code);
    var result = _check(source, v.token);
    count("placement: a function bound under the documented name through " + v.name + " agrees",
      result.compared === true && result.findings.length === 0, JSON.stringify(result));
  });

  var another = _module("fixture.reports.failingSources", "reports.reporters(opts)",
    "function reporters(listOpts) {\n  return listOpts;\n}");
  r = _check(another, "fixture.reports.failingSources");
  count("placement: a signature naming another primitive than the block's token is refused",
    _find(r, "signature-names-another-primitive") !== null, JSON.stringify(r.findings));
}

// ---- namespace blocks -----------------------------------------------------

function namespaceBlocksAreSkippedRatherThanReported() {
  var SKIPPED = [
    { name: "a sub-handle above the first function of its namespace",
      token: "fixture.delivery.reports", sig: "delivery.reports",
      code: "function receiveReport(rfc822, receiveOpts) {\n  return [rfc822, receiveOpts];\n}" },
    { name: "a constant",
      token: "fixture.mailbox.TABLES", sig: "fixture.mailbox.TABLES",
      code: "var TABLES = [\n  \"a\",\n];" },
    { name: "a sub-handle above a comment",
      token: "fixture.delivery.queue", sig: "delivery.queue",
      code: "// A filter an operator typed.\nfunction _filter(x) {\n  return x;\n}" },
    { name: "an error class taken from another module",
      token: "fixture.store.StoreError", sig: "fixture.store.StoreError",
      code: "var StoreError = errors.StoreError;" },
  ];
  SKIPPED.forEach(function (v) {
    var source = _module(v.token, v.sig, v.code);
    var result = _check(source, v.token);
    count("namespace: " + v.name + " is skipped, not reported",
      result.findings.length === 0 && result.compared === false && result.namespace === true,
      JSON.stringify(result));
  });

  var named = _module("fixture.delivery.start", "delivery.start",
    "function start() {\n  return true;\n}");
  var r = _check(named, "fixture.delivery.start");
  count("namespace: a signature without parentheses over the function of that name is refused",
    _find(r, "namespace-signature-over-function") !== null, JSON.stringify(r.findings));

  var bound = _module("fixture.delivery.stop", "delivery.stop",
    "function halt() {\n  return true;\n}\nmodule.exports = { stop: halt };");
  r = _check(bound, "fixture.delivery.stop");
  count("namespace: a signature without parentheses over a function bound under that name is refused",
    _find(r, "namespace-signature-over-function") !== null, JSON.stringify(r.findings));
}

// ---- the signature itself ------------------------------------------------

function aSignatureThatCannotBeComparedIsRefused() {
  var r = _check(_module("fixture.widgets.fetch", null, "function fetch(opts) {\n  return opts;\n}"),
    "fixture.widgets.fetch");
  count("shape: a block with no @signature is refused",
    _find(r, "missing-signature") !== null && r.compared === false, JSON.stringify(r));

  ["widgets.fetch(opts?", "widgets.fetch(opts, [extra])", "widgets.fetch(a b)",
    "widgets.fetch(opts,)", "widgets.fetch(opts) -> Promise"].forEach(function (sig) {
    var result = _check(_module("fixture.widgets.fetch", sig, "function fetch(opts) {\n  return opts;\n}"),
      "fixture.widgets.fetch");
    count("shape: an unparseable signature `" + sig + "` is refused",
      _find(result, "unparseable-signature") !== null && result.compared === false,
      JSON.stringify(result));
  });

  var NOTHING = [
    { name: "a constant", code: "var TABLES = [];" },
    { name: "another documentation block",
      code: _block("", "fixture.widgets.other", "widgets.other()") + "\nfunction other() {\n  return 1;\n}" },
    { name: "the end of the file", code: "" },
    { name: "a call statement", code: "register(fetch);\nfunction fetch(opts) {\n  return opts;\n}" },
  ];
  NOTHING.forEach(function (v) {
    var result = _check(_module("fixture.widgets.fetch", "widgets.fetch(opts)", v.code),
      "fixture.widgets.fetch");
    count("shape: a callable signature over " + v.name + " is refused",
      _find(result, "no-function-beneath") !== null && result.compared === false,
      JSON.stringify(result));
  });

  var noBlock = "\"use strict\";\nfunction fetch(opts) {\n  return opts;\n}\n";
  [14, undefined, noBlock.length + 2].forEach(function (end) {
    var lost = gate.signatureFindings(
      { token: "fixture.widgets.fetch", signature: "widgets.fetch(opts)", end: end }, noBlock);
    count("shape: a record whose end offset (" + end + ") ends no block in the file is refused rather than skipped",
      _find(lost, "block-not-located") !== null && lost.compared === false, JSON.stringify(lost));
  });

  var located = _module("fixture.widgets.fetch", "widgets.fetch(opts)", "function fetch(opts) {\n  return opts;\n}");
  var record = _record(located, "fixture.widgets.fetch");
  count("shape: the reader's record ends at the block's closing delimiter, and the signature is compared",
    located.slice(record.end - 2, record.end) === "*" + "/" && _check(located, "fixture.widgets.fetch").compared === true,
    JSON.stringify(record));
}

// ---- the gate, over a fixture tree ----------------------------------------

function theGateNamesTheFileAndThePrimitive() {
  var root = helpers.tempDir("signature-arity");
  var libDir = nodePath.join(root, "lib");
  var testDir = nodePath.join(root, "test");
  nodeFs.mkdirSync(nodePath.join(libDir, "widgets"), { recursive: true });
  nodeFs.mkdirSync(testDir);

  nodeFs.writeFileSync(nodePath.join(libDir, "widgets", "move.js"),
    _module("fixture.widgets.move", "widgets.move(from, to)",
      "function move(from, to, opts) {\n  return [from, to, opts];\n}"));
  nodeFs.writeFileSync(nodePath.join(libDir, "widgets", "reports.js"),
    _listingVerbs("reports.failingSources(opts?)", "reports.reporters(opts)"));
  nodeFs.writeFileSync(nodePath.join(libDir, "handles.js"),
    _module("fixture.delivery.reports", "delivery.reports",
      "function receiveReport(rfc822, receiveOpts) {\n  return [rfc822, receiveOpts];\n}"));

  var result = gate.validate({ root: root });
  var kinds = gate.SIGNATURE_FINDING_KINDS;
  count("fixture tree: the gate names the finding kinds its signature check reports",
    Array.isArray(kinds) && kinds.length > 0, JSON.stringify(kinds));
  kinds = Array.isArray(kinds) ? kinds : [];
  var found = result.findings.filter(function (f) { return kinds.indexOf(f.kind) !== -1; });

  function named(kind, token, fileTail) {
    return found.filter(function (f) {
      return f.kind === kind && f.primitive === token &&
        typeof f.file === "string" && f.file.slice(-fileTail.length) === fileTail && f.line > 0;
    }).length === 1;
  }

  count("fixture tree: the arity mismatch is reported naming its file and primitive",
    named("arity-mismatch", "fixture.widgets.move", "lib/widgets/move.js"),
    JSON.stringify(result.findings.map(function (f) { return f.kind + " " + f.primitive; })));
  count("fixture tree: the refused optional marker is reported naming its file and primitive",
    named("optional-parameter-required", "fixture.reports.failingSources", "lib/widgets/reports.js"),
    JSON.stringify(found));
  count("fixture tree: nothing else about the signatures is reported",
    found.length === 2, JSON.stringify(found));
  count("fixture tree: four blocks were read",
    result.examined["primitive-blocks"] === 4, JSON.stringify(result.examined));
  count("fixture tree: three signatures were compared, the namespace block was not",
    result.examined["signatures-compared"] === 3 && result.namespaceBlocks === 1,
    JSON.stringify(result.examined) + " namespaces " + result.namespaceBlocks);
  count("fixture tree: the one optional marker was examined",
    result.examined["optional-markers-checked"] === 1, JSON.stringify(result.examined));

  helpers.removeTempDir(root);
}

// ---- the gate, over this repository ---------------------------------------

function _examined(stdout) {
  var out = {};
  String(stdout).split(/\r?\n/).forEach(function (line) {
    var m = /^EXAMINED\s+(\d+)\s+([a-z0-9-]+)$/.exec(line.trim());
    if (m) out[m[2]] = Number(m[1]);
  });
  return out;
}

async function theLiveTreeIsSilentAndSaysWhatItCompared() {
  var result = gate.validate();
  var kinds = gate.SIGNATURE_FINDING_KINDS;
  var found = result.findings.filter(function (f) { return kinds.indexOf(f.kind) !== -1; });
  count("live tree: no block's signature disagrees with the function beneath it",
    found.length === 0, found.map(function (f) {
      return f.kind + " " + f.file + ":" + f.line + " " + f.primitive;
    }).join("; "));

  var blocks = result.examined["primitive-blocks"];
  var compared = result.examined["signatures-compared"];
  count("live tree: blocks were read", blocks > 0, String(blocks));
  count("live tree: every block was either compared or recognized as a namespace",
    compared > 0 && compared + result.namespaceBlocks === blocks,
    compared + " compared + " + result.namespaceBlocks + " namespaces, of " + blocks + " blocks");
  count("live tree: optional markers were examined",
    result.examined["optional-markers-checked"] > 0, String(result.examined["optional-markers-checked"]));

  var run = await spawnRun.runNodeScript(
    [nodePath.join(REPO_ROOT, "scripts", "validate-source-comment-blocks.js")],
    { cwd: REPO_ROOT, ceilingMs: RUN_CEILING_MS });
  var published = _examined(run.out);
  count("live tree: the gate publishes the signatures it compared",
    published["signatures-compared"] === compared, JSON.stringify(published));
  count("live tree: the gate publishes the optional markers it examined",
    published["optional-markers-checked"] === result.examined["optional-markers-checked"],
    JSON.stringify(published));
  var units = Object.keys(result.examined).length;
  var lines = String(run.out).trim().split(/\r?\n/).slice(-units);
  count("live tree: every count the gate publishes is among the last lines of stdout",
    units >= 5 && lines.length === units &&
    lines.every(function (l) { return /^EXAMINED\s+\d+\s+[a-z0-9-]+$/.test(l.trim()); }),
    tail(run.out, units + 1));
}

// ---- runner ---------------------------------------------------------------

async function run() {
  theGateNamesTheFileAndThePrimitive();
  theShippedShapeIsRefused();
  everyOmissionTheBodyProvablyRefusesIsReported();
  aBodyThatMayTolerateOmissionIsLeftAlone();
  parameterCountsAreComparedAgainstTheDeclarationBeneath();
  aBlockOverTheWrongFunctionIsRefused();
  namespaceBlocksAreSkippedRatherThanReported();
  aSignatureThatCannotBeComparedIsRefused();
  await theLiveTreeIsSilentAndSaysWhatItCompared();
  if (_recordTree !== null) helpers.removeTempDir(_recordTree);
  return helpers.getChecks();
}

module.exports = { name: "signature-arity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
