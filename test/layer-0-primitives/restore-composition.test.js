// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * restore-composition: two ways of composing the vendored backup and
 * restore primitives that cannot be correct on this server.
 *
 * `directory-rename-restore`. `b.restore.create` stages a decrypted bundle
 * under the operating system temp directory, and `b.restoreRollback.swap`
 * and `.rollback` rename the data directory itself. In the shipped
 * container the data directory is the mount point of a volume: Linux
 * refuses to rename it (EBUSY), refuses to rename into it from the temp
 * directory (EXDEV), and the image's user cannot create a directory beside
 * it (EACCES). A restore composed from those primitives moves nothing in
 * that deployment and leaves a decrypted copy of the volume in `/tmp`.
 * The fix is to stage inside the data directory and move its entries.
 *
 * `retention-inside-backup-engine`. `b.backup.create` given `retention`
 * deletes older bundles inside `run()`, after the new bundle is written
 * and before anything has read it back. It counts every directory whose
 * name looks like a bundle id, so a bundle that does not open, or a
 * directory with a later id and nothing in it, is kept while a bundle that
 * restores is deleted. The fix is to verify first and sweep afterwards,
 * counting only bundles that verified.
 *
 * Both are anchored on the vendored primitive names, which are a frozen
 * contract, rather than on a helper name here. Comments and string
 * literals are masked before matching, so prose that names a primitive in
 * order to explain why it is not used does not fire.
 *
 * Each detector is proven to fire on a fixture written to a temporary
 * file, to stay silent on the corrected shape and on a mention inside a
 * comment or a string, and then run over `bin/` and `lib/` outside the
 * vendored tree, where it must report nothing.
 *
 * Run standalone: node test/layer-0-primitives/restore-composition.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

// ---- masking ----------------------------------------------------------------

// A regular expression literal can start after these characters, and a
// division cannot. Close enough for this tree, and a wrong guess shows up
// as a fixture below failing rather than as a silent miss.
var REGEX_MAY_FOLLOW = "(,=:[!&|?{};";

// The source with the contents of comments, strings, template literals and
// regular expression literals replaced by spaces. Newlines are kept, so an
// index in the mask is an index in the source and line numbers agree.
function mask(text) {
  var out = text.split("");
  var i = 0;
  var n = text.length;
  function blank(from, to) {
    for (var k = from; k < to && k < n; k += 1) {
      if (out[k] !== "\n") out[k] = " ";
    }
  }
  function previousSignificant(at) {
    for (var k = at - 1; k >= 0; k -= 1) {
      if (!/\s/.test(text[k])) return text[k];
    }
    return "";
  }
  while (i < n) {
    var c = text[i];
    var next = text[i + 1];
    if (c === "/" && next === "/") {
      var end = text.indexOf("\n", i);
      if (end === -1) end = n;
      blank(i, end);
      i = end;
    } else if (c === "/" && next === "*") {
      var close = text.indexOf("*/", i + 2);
      close = close === -1 ? n : close + 2;
      blank(i, close);
      i = close;
    } else if (c === "\"" || c === "'" || c === "`") {
      var j = i + 1;
      while (j < n && text[j] !== c) {
        if (text[j] === "\\") j += 1;
        else if (c !== "`" && text[j] === "\n") break;
        j += 1;
      }
      blank(i + 1, j);
      i = j + 1;
    } else if (c === "/" && REGEX_MAY_FOLLOW.indexOf(previousSignificant(i)) !== -1) {
      var r = i + 1;
      var inClass = false;
      while (r < n && text[r] !== "\n") {
        if (text[r] === "\\") r += 1;
        else if (text[r] === "[") inClass = true;
        else if (text[r] === "]") inClass = false;
        else if (text[r] === "/" && !inClass) break;
        r += 1;
      }
      blank(i + 1, r);
      i = r + 1;
    } else {
      i += 1;
    }
  }
  return out.join("");
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

// The index just past the parenthesis matching the one at `open`, read
// over the mask, or -1.
function closingParen(masked, open) {
  var depth = 0;
  for (var k = open; k < masked.length; k += 1) {
    if (masked[k] === "(") depth += 1;
    else if (masked[k] === ")") {
      depth -= 1;
      if (depth === 0) return k + 1;
    }
  }
  return -1;
}

// ---- detectors --------------------------------------------------------------

var DETECTORS = [
  {
    name: "directory-rename-restore",
    scan: function (masked) {
      var found = [];
      var re = /\bb\.restore\.create\s*\(|\bb\.restoreRollback\.(?:swap|rollback)\s*\(/g;
      var m;
      while ((m = re.exec(masked)) !== null) found.push(m.index);
      return found;
    },
  },
  {
    name: "retention-inside-backup-engine",
    scan: function (masked) {
      var found = [];
      var re = /\bb\.backup\.create\s*\(/g;
      var m;
      while ((m = re.exec(masked)) !== null) {
        var open = masked.indexOf("(", m.index);
        var close = closingParen(masked, open);
        var args = close === -1 ? masked.slice(open) : masked.slice(open, close);
        if (/(?:^|[{,\s])retention\s*:/.test(args)) found.push(m.index);
      }
      return found;
    },
  },
];

function run(detector, filePath) {
  var text = nodeFs.readFileSync(filePath, "utf8");
  var masked = mask(text);
  return detector.scan(masked).map(function (index) {
    return nodePath.relative(REPO_ROOT, filePath) + ":" + lineOf(text, index);
  });
}

// ---- fixtures ---------------------------------------------------------------

var FIXTURES = {
  "directory-rename-restore": {
    red: [
      "var handle = b.restore.create({ dataDir: dir, storage: s, passphrase: p });\n",
      "function put(dir, staging) {\n  return b.restoreRollback.swap({ stagingDir: staging, dataDir: dir });\n}\n",
      "async function back(dir, point) {\n  await b.restoreRollback.rollback({ dataDir: dir, rollbackPath: point });\n}\n",
    ],
    green: [
      "var points = b.restoreRollback.list({ dataDir: dir });\n",
      "await b.restoreBundle.extract({ bundleDir: d, stagingDir: inside, passphrase: p });\n",
      "// b.restore.create stages under the temp directory, so it is not used here.\n",
      "var why = \"b.restoreRollback.swap(renames the directory)\";\n",
      "/* b.restoreRollback.rollback({ dataDir }) */\nvar x = 1;\n",
      "var re = /b\\.restore\\.create\\(/;\n",
    ],
  },
  "retention-inside-backup-engine": {
    red: [
      "var engine = b.backup.create({\n  dataDir: d,\n  retention: { keep: 7 },\n});\n",
      "var e = b.backup.create({ dataDir: d, retention: keep === null ? null : { keep: keep } });\n",
    ],
    green: [
      "var engine = b.backup.create({ dataDir: d, storage: s });\nawait sweep({ retention: 3 });\n",
      "var engine = b.backup.create({ dataDir: d, files: list(retentionDays) });\n",
      "var engine = b.backup.create({ dataDir: d });\n// retention: { keep: 7 } is applied after verification\n",
      "var engine = b.backup.create({ note: \"retention: none\" });\n",
    ],
  },
};

// ---- the tree ---------------------------------------------------------------

function sourceFiles() {
  var files = [nodePath.join(REPO_ROOT, "bin", "blamepost.js")];
  var stack = [nodePath.join(REPO_ROOT, "lib")];
  while (stack.length > 0) {
    var dir = stack.pop();
    var entries = nodeFs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i += 1) {
      var full = nodePath.join(dir, entries[i].name);
      if (entries[i].isDirectory()) {
        if (full === nodePath.join(REPO_ROOT, "lib", "vendor")) continue;
        stack.push(full);
      } else if (entries[i].isFile() && /\.js$/.test(entries[i].name)) {
        files.push(full);
      }
    }
  }
  return files.sort();
}

// ---- runner -----------------------------------------------------------------

function provedOnFixtures(tmp) {
  DETECTORS.forEach(function (detector) {
    var fixtures = FIXTURES[detector.name];
    fixtures.red.forEach(function (source, i) {
      var file = nodePath.join(tmp, detector.name + "-red-" + i + ".js");
      nodeFs.writeFileSync(file, source);
      var hits = run(detector, file);
      count(detector.name + " fires on red fixture " + i + " and names the file and line",
        hits.length === 1 && /-red-\d+\.js:\d+$/.test(hits[0]), JSON.stringify(hits));
    });
    fixtures.green.forEach(function (source, i) {
      var file = nodePath.join(tmp, detector.name + "-green-" + i + ".js");
      nodeFs.writeFileSync(file, source);
      var hits = run(detector, file);
      count(detector.name + " stays silent on green fixture " + i, hits.length === 0,
        JSON.stringify(hits));
    });
  });
}

function theTreeIsClean() {
  var files = sourceFiles();
  count("the tree walk reaches bin/blamepost.js and the lib sources", files.length > 20 &&
    files.some(function (f) { return /bin[\\/]blamepost\.js$/.test(f); }), String(files.length));
  DETECTORS.forEach(function (detector) {
    var hits = [];
    files.forEach(function (file) { hits = hits.concat(run(detector, file)); });
    count(detector.name + " finds nothing in bin/ or lib/", hits.length === 0, hits.join(", "));
  });
}

async function main() {
  var tmp = helpers.tempDir("restore-composition");
  try {
    provedOnFixtures(tmp);
    theTreeIsClean();
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(tmp);
  }
}

module.exports = { name: "restore-composition", run: main, getChecks: helpers.getChecks };

if (require.main === module) {
  main().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
