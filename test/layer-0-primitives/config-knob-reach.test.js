// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * config-knob-reach: a setting the loader declares is a setting some other
 * module reads.
 *
 * The settings table states three obligations in its own header, and
 * test/layer-0-primitives/config-schema.test.js mechanizes all three: a
 * row, a default, and a line an operator can find. A setting can satisfy
 * every one of them and still do nothing, because none of them asks
 * whether anything outside the loader ever looks at the value.
 *
 * That shape is the quietest one this repository ships. The variable
 * exists, so the environment accepts it. The row exists, so the file
 * accepts it. The bounds exist, so a wrong value is refused at boot and
 * the operator reads a message proving the setting is real. The document
 * names it, so a reader looking it up finds the sentence. The loader
 * returns it, so a support bundle prints it. Every signal available to
 * an operator says the setting is in force, and the server runs the
 * default they were trying to change. There is no configuration in which
 * the difference is visible, and no other gate here asks the question.
 *
 * `requireTls` is the worked example of what this costs. It was declared
 * while the transport had no reader for the flag, and the handling that
 * kept it honest was a refusal at boot rather than a value accepted and
 * dropped; test/layer-0-primitives/require-tls-posture.test.js now holds
 * that one setting to the handle it produces. This file asks the same
 * question of all of them at once, so the next setting to land is covered
 * the day it lands rather than when somebody remembers to write its
 * parity file.
 *
 * WHAT COUNTS AS A READ. `config.<key>` or `cfg.<key>` on a line of code
 * in `lib/` or `bin/`, outside the loader itself. Those are the two names
 * every consumer binds the loaded object to. A module that bound it to a
 * third name would be reported here rather than passed over, which is the
 * direction a reader should fail in: the finding is read by somebody who
 * can look at the line and widen the reader, and the alternative is a
 * reader that quietly answers for less of the tree each time a module is
 * written.
 *
 * Comment text is not code. A full-line comment is dropped, and a trailing
 * `//` comment is cut off the end of a code line, so a key named in the
 * sentence above a function is not counted as the function reading it.
 * The cut ignores a `//` that follows a colon, because that is the
 * authority marker of a URL rather than the start of a comment.
 *
 * READING IS NECESSARY AND NOT SUFFICIENT. A value read into a binding
 * nothing uses passes here. That is the question `no-unused-vars` answers
 * under the lint gate, and the per-setting parity files answer for the
 * settings whose posture is worth pinning on its own. This file answers
 * the one question neither of those asks across the whole table.
 *
 * A SETTING CARRIED BY A PRIMITIVE. One setting reaches its consumer
 * without any module naming the key: the log level is published to the
 * framework's boot logger by `config.applyLogLevel(cfg)`, which takes the
 * whole object, so the read happens inside the loader. That is a real
 * exemption and it is written down with the call that carries it, and
 * then refuted three ways: the key must still be unread outside the
 * loader, the named call must still be made outside the loader, and the
 * loader must still read the key. An exemption whose setting grew a
 * direct read is reported as rotted rather than left standing, so the
 * table cannot quietly become a list of settings nobody checks.
 *
 * COUNTS. Three, because they fail independently. `declared-settings` is
 * what the loader publishes, `consumer-files-read` is what the directory
 * walk found, and `enforcing-reads-found` is what the reader matched. A
 * reader that stopped matching takes the third to zero while the first
 * two stay healthy; a walk resolved against a wrong directory takes the
 * second to zero while the reader still reports a clean verdict over
 * nothing. Zero in any of the three is refused.
 *
 * No sockets, no database, no network. It reads source text, and the
 * reader's own vectors are source strings rather than files.
 *
 * Run standalone:
 * node test/layer-0-primitives/config-knob-reach.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;
var config  = require("../../lib/config");

var REPO_ROOT = helpers.REPO_ROOT;

// The two trees a consumer of the loaded configuration lives in.
var CONSUMER_ROOTS = ["lib", "bin"];

// The vendored framework is not this repository's code, and the loader
// itself is the module under examination rather than a consumer of it.
var NOT_A_CONSUMER = ["lib/vendor", "lib/config"];

// The names a module binds the loaded object to. A third name is a
// finding rather than an exemption: see the header.
var HOLDER_NAMES = ["config", "cfg"];

// The settings whose value reaches its consumer inside the loader,
// because the consumer hands the whole object to a loader primitive
// instead of naming the key. Each entry is refuted by the checks in
// `anExemptionThatHasRottedIsReported` below.
var CARRIED_BY_A_PRIMITIVE = [
  {
    key:       "logLevel",
    primitive: "applyLogLevel",
    reason:    "the level reaches the framework's boot logger through " +
               "config.applyLogLevel(cfg), which takes the whole object and writes the " +
               "resolved level into the variable that logger consults, so no consumer " +
               "names the key",
  },
];

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

// One line reduced to the code on it. A full-line comment becomes empty;
// a trailing comment is cut off. `://` is left alone, because that is a
// URL's authority marker rather than a comment.
function codeOn(line) {
  var trimmed = line.trim();
  if (trimmed.indexOf("*") === 0)  return "";
  if (trimmed.indexOf("//") === 0) return "";
  if (trimmed.indexOf("/*") === 0) return "";
  var cut = line.search(/(^|[^:])\/\//);
  if (cut === -1) return line;
  // The match may start one character before the slashes when it consumed
  // the character in front of them.
  var slashes = line.indexOf("//", cut);
  return line.slice(0, slashes);
}

function readerFor(key) {
  return new RegExp("\\b(?:" + HOLDER_NAMES.join("|") + ")\\." + key + "\\b");
}

// Every `.js` file under `dir`, as a repository-relative path plus its
// text, skipping the trees that are not consumers.
function sourceFiles(root, dir, rel, out) {
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var full = nodePath.join(dir, entry.name);
    var here = rel === "" ? entry.name : rel + "/" + entry.name;
    if (entry.isDirectory()) {
      for (var i = 0; i < NOT_A_CONSUMER.length; i += 1) {
        if (here === NOT_A_CONSUMER[i]) return;
      }
      sourceFiles(root, full, here, out);
      return;
    }
    if (!/\.js$/.test(entry.name)) return;
    out.push({ path: here, text: nodeFs.readFileSync(full, "utf8") });
  });
  return out;
}

// Where each declared key is read, as `path:line`. Exported so the
// vectors below can drive it over source strings rather than over files.
function readsIn(files, keys) {
  var found = {};
  keys.forEach(function (key) { found[key] = []; });
  files.forEach(function (file) {
    var lines = file.text.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      var code = codeOn(lines[i]);
      if (code === "") continue;
      for (var k = 0; k < keys.length; k += 1) {
        if (readerFor(keys[k]).test(code)) found[keys[k]].push(file.path + ":" + (i + 1));
      }
    }
  });
  return found;
}

function enforcingReads(opts) {
  var root  = opts.root;
  var files = [];
  CONSUMER_ROOTS.forEach(function (name) {
    var dir = nodePath.join(root, name);
    if (!nodeFs.existsSync(dir)) return;
    sourceFiles(root, dir, name, files);
  });
  var keys = config.SETTINGS.map(function (s) { return s.key; });
  var reads = readsIn(files, keys);
  var total = 0;
  keys.forEach(function (key) { total += reads[key].length; });
  return { files: files, keys: keys, reads: reads, total: total };
}

// The loader's own text, for the half of an exemption that has to be
// true inside it.
function loaderText(root) {
  return nodeFs.readFileSync(nodePath.join(root, "lib", "config", "index.js"), "utf8");
}

// ---------------------------------------------------------------------------
// The reader, driven over source strings
// ---------------------------------------------------------------------------

function theReaderReadsCodeAndNotProse() {
  var vectors = [
    { path: "lib/mail/listeners.js",
      text: "var profile = config.profile || \"strict\";\n" },
    { path: "lib/store/index.js",
      text: "  if (!already) process.env[name] = cfg.vaultPassphrase;\n" },
  ];
  var hits = readsIn(vectors, ["profile", "vaultPassphrase"]);
  count("the reader finds a read written as config.<key>",
    hits.profile.length === 1 && hits.profile[0] === "lib/mail/listeners.js:1",
    JSON.stringify(hits.profile));
  count("and one written as cfg.<key>, which is the other name a module binds",
    hits.vaultPassphrase.length === 1,
    JSON.stringify(hits.vaultPassphrase));

  var prose = readsIn([{ path: "lib/x.js", text: [
    " * The operator sets config.requireTls and the handle carries it.",
    "// config.requireTls is described here and read nowhere.",
    "/* config.requireTls again, opening a block. */",
  ].join("\n") }], ["requireTls"]);
  count("a key named in a comment is not counted as a module reading it",
    prose.requireTls.length === 0, JSON.stringify(prose.requireTls));

  var trailing = readsIn([{ path: "lib/y.js", text:
    "var n = other.value;   // config.httpPort is not read on this line\n" }], ["httpPort"]);
  count("and a key named in a trailing comment on a line of code is not counted either",
    trailing.httpPort.length === 0, JSON.stringify(trailing.httpPort));

  var url = readsIn([{ path: "lib/z.js", text:
    "var base = \"https://example.com/\" + config.hostname;\n" }], ["hostname"]);
  count("the trailing-comment cut leaves a URL's slashes alone, so a read beside one " +
    "is still found",
    url.hostname.length === 1, JSON.stringify(url.hostname));

  var prefix = readsIn([{ path: "lib/w.js", text:
    "var x = notconfig.httpPort + config.httpPortOther;\n" }], ["httpPort"]);
  count("a longer key and a longer holder name are not matched as the short one",
    prefix.httpPort.length === 0, JSON.stringify(prefix.httpPort));
}

// The finding itself, proven on a fixture rather than by planting an
// unread setting in the shipped table.
function anUnreadSettingIsNamed() {
  var files = [{ path: "lib/index.js", text: "var port = config.httpPort;\n" }];
  var hits  = readsIn(files, ["httpPort", "mtaStsMaxAge"]);
  count("a setting some module reads is found",
    hits.httpPort.length === 1, JSON.stringify(hits.httpPort));
  count("and a setting no module reads comes back with nothing, which is the finding",
    hits.mtaStsMaxAge.length === 0, JSON.stringify(hits.mtaStsMaxAge));
}

function theWalkSkipsTheTreesThatAreNotConsumers() {
  var report = enforcingReads({ root: REPO_ROOT });
  var vendored = report.files.filter(function (f) {
    return f.path.indexOf("lib/vendor/") === 0;
  });
  count("the vendored framework is not read as a consumer of this server's configuration",
    vendored.length === 0, vendored.slice(0, 3).map(function (f) { return f.path; }).join(", "));

  var loader = report.files.filter(function (f) {
    return f.path.indexOf("lib/config/") === 0;
  });
  count("and neither is the loader, which is the module under examination rather than a " +
    "consumer of it",
    loader.length === 0, loader.map(function (f) { return f.path; }).join(", "));

  count("the walk reached both trees a consumer lives in",
    report.files.some(function (f) { return f.path.indexOf("lib/") === 0; }) &&
    report.files.some(function (f) { return f.path.indexOf("bin/") === 0; }),
    report.files.length + " file(s)");
}

// ---------------------------------------------------------------------------
// The live table
// ---------------------------------------------------------------------------

function aWalkThatReadNothingIsRefused(report) {
  count("the loader still publishes settings, so this is comparing something",
    report.keys.length > 0, report.keys.length);
  count("the walk still found consumer files to read",
    report.files.length > 0, report.files.length);
  count("and the reader still matched reads, rather than answering clean over nothing",
    report.total > 0, report.total);
}

function everySettingIsReadWhereItActs(report) {
  var exempt = {};
  CARRIED_BY_A_PRIMITIVE.forEach(function (e) { exempt[e.key] = e; });

  var unread = [];
  config.SETTINGS.forEach(function (setting) {
    var sites = report.reads[setting.key];
    if (exempt[setting.key] !== undefined) return;
    // A setting the loader declares and refuses is answered by the
    // refusal rather than by a consumer, and the refusal is a property of
    // the row. Its reach is measured by the module that refuses it, which
    // does name the key, so it is not exempted here; it simply has a read
    // like every other row.
    if (sites.length === 0) unread.push(setting.key + " (" + setting.env + ")");
  });

  count("every setting the loader declares is read by a module that acts on it, so a " +
    "value an operator writes reaches something. A setting named here is accepted from " +
    "the environment and the file, refused when it is out of range, printed in a support " +
    "bundle and documented for the operator, and then discarded: read it where it acts, " +
    "or take the row out",
    unread.length === 0, unread.join(", "), { limit: 2000 });

  // The read sites are published per setting on a passing run as well, so
  // a reviewer can see WHERE each one lands rather than only that it does.
  config.SETTINGS.forEach(function (setting) {
    var sites = report.reads[setting.key];
    if (sites.length === 0) return;
    count(setting.key + " is read at " + sites.slice(0, 2).join(", ") +
      (sites.length > 2 ? " and " + (sites.length - 2) + " more" : ""),
      sites.length > 0, sites.length);
  });
}

function anExemptionThatHasRottedIsReported(report) {
  var loader = loaderText(REPO_ROOT);
  count("the exemption table is small enough to read, which is what keeps it a list of " +
    "named cases rather than a way past this gate",
    CARRIED_BY_A_PRIMITIVE.length <= 3, CARRIED_BY_A_PRIMITIVE.length);

  CARRIED_BY_A_PRIMITIVE.forEach(function (entry) {
    var row = config.SETTINGS.filter(function (s) { return s.key === entry.key; })[0];
    count("the exemption for " + entry.key + " names a setting the loader still declares",
      row !== undefined, entry.key);
    if (row === undefined) return;

    count("and " + entry.key + " is still read by no module directly, so the exemption is " +
      "still describing the tree rather than standing over a setting that grew a read",
      report.reads[entry.key].length === 0,
      report.reads[entry.key].join(", "));

    // The call that carries the value, outside the loader. Without it the
    // setting reaches nothing and the exemption is covering a real
    // finding.
    var carried = report.files.filter(function (file) {
      var lines = file.text.split("\n");
      for (var i = 0; i < lines.length; i += 1) {
        if (new RegExp("\\b" + entry.primitive + "\\s*\\(").test(codeOn(lines[i]))) return true;
      }
      return false;
    }).map(function (file) { return file.path; });
    count("the call that carries " + entry.key + " to its consumer, " + entry.primitive +
      "(), is made outside the loader",
      carried.length > 0, carried.join(", "));

    // And the loader really does read the key inside that primitive.
    count("and the loader itself reads " + entry.key + ", which is where the carried value " +
      "is taken from",
      readerFor(entry.key).test(loader), entry.key);

    count("the exemption for " + entry.key + " says why, in a sentence somebody arriving " +
      "at this gate can act on",
      typeof entry.reason === "string" && entry.reason.length > 40, entry.reason);
  });
}

// ---------------------------------------------------------------------------

function run() {
  var report = enforcingReads({ root: REPO_ROOT });

  // Published first, so the run says what it looked at whether the
  // assertions below pass or fail.
  console.log("EXAMINED " + report.keys.length + " declared-settings");
  console.log("EXAMINED " + report.files.length + " consumer-files-read");
  console.log("EXAMINED " + report.total + " enforcing-reads-found");

  theReaderReadsCodeAndNotProse();
  anUnreadSettingIsNamed();
  theWalkSkipsTheTreesThatAreNotConsumers();

  aWalkThatReadNothingIsRefused(report);
  everySettingIsReadWhereItActs(report);
  anExemptionThatHasRottedIsReported(report);

  return helpers.getChecks();
}

module.exports = {
  name:           "config-knob-reach",
  run:            run,
  getChecks:      helpers.getChecks,
  enforcingReads: enforcingReads,
  readsIn:        readsIn,
  // The sibling gate that asks whether a setting is DRIVEN reads source
  // lines the same way, and a second copy of this reader is how two
  // gates come to disagree about what counts as a comment.
  codeOn:         codeOn,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
