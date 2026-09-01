// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vendor-refresh-atomicity: a refresh either publishes a proven tree or
 * leaves the one that was there.
 *
 * `lib/vendor/blamejs/` is the whole runtime. Nothing in `lib/` loads
 * without it, and on a repository whose first commit has not landed there
 * is no copy to restore it from. So the failure that matters is not a
 * refresh that refuses; it is a refresh that gets halfway and stops.
 * That happened: the script removed the destination before extracting,
 * the removal died partway with the directory locked, and the tree was
 * left at zero files while the manifest still named the version that had
 * just been deleted.
 *
 * Every case here drives `scripts/vendor-update.sh` itself, as an
 * operator runs it, against a temporary repository holding a copy of the
 * script, a fake vendored tree, a manifest, a NOTICE and a README. A
 * loopback HTTP server stands in for the registry. The real
 * `lib/vendor/blamejs/` is never touched: it is the artifact this whole
 * repository composes against, and a test that can damage it is a test
 * nobody can afford to run.
 *
 * The cases are the failure paths, because the success path was never
 * the part that was broken:
 *
 *   - the publisher's digest does not match the bytes
 *   - the archive will not extract
 *   - the archive extracts to something with no package.json
 *   - the archive is a fraction of the size of the tree it replaces
 *   - the entry point cannot be required
 *   - the step that clears the destination fails partway, which is the
 *     one that actually happened and the one most likely to go untested
 *   - the destination is left holding entries after being moved aside
 *   - a previous run's backup is still on disk
 *
 * After each, two things are asserted together: every file of the
 * previous tree is back with its original bytes, and `MANIFEST.json`
 * still records the previous version. Either alone would pass on a tree
 * that lost the other.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/vendor-refresh-atomicity.test.js`.
 */

var crypto  = require("node:crypto");
var fs      = require("node:fs");
var http    = require("node:http");
var path    = require("node:path");
var { spawn, spawnSync } = require("node:child_process");

var helpers = require("../helpers");
var check   = helpers.check;
var skip    = helpers.skip;

var REPO_ROOT      = helpers.REPO_ROOT;
var SHIPPED_SCRIPT = path.join(REPO_ROOT, "scripts", "vendor-update.sh");
var REFRESH_SCRIPT = path.join(REPO_ROOT, "scripts", "refresh-vendor-manifest.js");

// The hash the manifest records comes from this module, so the test
// measures a published tree with the implementation that wrote the value
// rather than with a second copy of the walk.
var manifestTool = require(REFRESH_SCRIPT);

var OLD_VERSION = "0.0.1";
var NEW_VERSION = "1.0.0";
var NPM_NAME    = "@blamejs/core";

// The registry addresses a scoped package as one path segment, so this is
// the path curl actually requests.
var META_PATH = "/@blamejs%2Fcore";

// A top-level entry in the live tree whose name the failure shim watches
// for. It has to be top level: the swap moves top-level entries, so a
// name buried inside a subdirectory never reaches the command being
// made to fail.
var BUSY_ENTRY = "busy-entry.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function _writeFile(p, body) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, body);
}

/**
 * _writePackage(dir, version, opts) lays out a package the shape npm
 * publishes: a package.json, an entry point, and enough module files that
 * a truncated copy is measurably smaller than a whole one.
 *
 * opts.modules      how many files under lib/, default 12
 * opts.brokenEntry  the entry point throws on require
 * opts.noManifest   omit package.json
 * opts.extra        a map of relative path to contents
 */
function _writePackage(dir, version, opts) {
  opts = opts || {};
  var modules = typeof opts.modules === "number" ? opts.modules : 12;
  if (!opts.noManifest) {
    _writeFile(path.join(dir, "package.json"), JSON.stringify({
      name:    NPM_NAME,
      version: version,
      main:    "index.js",
      license: "Apache-2.0",
    }, null, 2) + "\n");
  }
  _writeFile(path.join(dir, "index.js"), opts.brokenEntry
    ? "\"use strict\";\nthrow new Error(\"this build cannot be required\");\n"
    : "\"use strict\";\nmodule.exports = { version: \"" + version + "\" };\n");
  for (var i = 0; i < modules; i += 1) {
    _writeFile(path.join(dir, "lib", "mod-" + i + ".js"),
      "\"use strict\";\nmodule.exports = " + i + "; // " + version + "\n");
  }
  var extra = opts.extra || {};
  Object.keys(extra).forEach(function (rel) {
    _writeFile(path.join(dir, rel), extra[rel]);
  });
}

/**
 * _makeTarball(version, opts) builds the gzipped tar npm would publish,
 * rooted under `package/` the way a registry tarball is, and returns its
 * bytes. Returns null when `tar` is not on the path.
 */
function _makeTarball(version, opts) {
  var scratch = helpers.tempDir("vendorsrc");
  var pkgDir  = path.join(scratch, "package");
  _writePackage(pkgDir, version, opts);
  // Relative names, with the scratch directory as the working directory.
  // An absolute Windows path carries a drive letter, and a colon in an
  // archive name is a remote host spec to tar, so passing one produces a
  // failure that reads as a missing shell rather than as a path.
  var r = spawnSync("tar", ["-czf", "package.tgz", "package"], {
    cwd:      scratch,
    encoding: "utf8",
  });
  if (r.error || r.status !== 0) {
    helpers.removeTempDir(scratch);
    return null;
  }
  var bytes = fs.readFileSync(path.join(scratch, "package.tgz"));
  helpers.removeTempDir(scratch);
  return bytes;
}

function _integrity(bytes) {
  return "sha512-" + crypto.createHash("sha512").update(bytes).digest("base64");
}

var NOTICE_SEPARATOR = new Array(81).join("-");

function _notice(version) {
  return [
    "blamepost",
    "",
    NOTICE_SEPARATOR,
    "Component:   blamejs",
    "Version:     " + version,
    "License:     Apache-2.0",
    NOTICE_SEPARATOR,
    "",
  ].join("\n");
}

function _readme(version) {
  return [
    "# temporary repository",
    "",
    "| Component | Version | License |",
    "| --- | --- | --- |",
    "| [`blamejs`](https://github.com/blamejs/blamejs) | " + version + " | Apache-2.0 |",
    "",
  ].join("\n");
}

/**
 * _makeRepo(scriptPath) builds the temporary repository a refresh runs
 * against and returns its paths. The script under test is copied in,
 * because `vendor-update.sh` resolves the repository from its own
 * location and would otherwise rewrite the real vendored tree.
 */
function _makeRepo(scriptPath) {
  var root = helpers.tempDir("vendorrepo");
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true });
  fs.copyFileSync(scriptPath, path.join(root, "scripts", "vendor-update.sh"));
  fs.copyFileSync(REFRESH_SCRIPT, path.join(root, "scripts", "refresh-vendor-manifest.js"));

  var dest = path.join(root, "lib", "vendor", "blamejs");
  _writePackage(dest, OLD_VERSION, {
    extra: (function () {
      var e = {};
      e[BUSY_ENTRY] = "\"use strict\";\nmodule.exports = \"held open\";\n";
      return e;
    }()),
  });

  var manifestPath = path.join(root, "lib", "vendor", "MANIFEST.json");
  _writeFile(manifestPath, JSON.stringify({
    packages: {
      blamejs: {
        version:   OLD_VERSION,
        npm:       NPM_NAME,
        license:   "Apache-2.0",
        source:    "https://example.invalid/blamejs-" + OLD_VERSION + ".tgz",
        integrity: "sha512-" + "A".repeat(86) + "==",
        bundledAt: "2026-01-01T00:00:00Z",
        bundler:   "npm registry tarball, integrity-verified before extraction",
        files:     { server: "lib/vendor/blamejs/" },
        hashes:    { server: manifestTool.hashTree(dest) },
      },
    },
  }, null, 2) + "\n");

  _writeFile(path.join(root, "NOTICE"), _notice(OLD_VERSION));
  _writeFile(path.join(root, "README.md"), _readme(OLD_VERSION));

  return {
    root:     root,
    script:   path.join(root, "scripts", "vendor-update.sh"),
    dest:     dest,
    manifest: manifestPath,
    notice:   path.join(root, "NOTICE"),
    readme:   path.join(root, "README.md"),
  };
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/**
 * _snapshot(dir) maps every file below `dir` to a digest of its bytes, so
 * "the tree came back exactly as it was" is one comparison rather than a
 * count that a swapped file would satisfy.
 */
function _snapshot(dir) {
  var out = {};
  if (!fs.existsSync(dir)) return out;
  (function walk(current, prefix) {
    fs.readdirSync(current, { withFileTypes: true })
      .sort(function (a, b) { return a.name.localeCompare(b.name); })
      .forEach(function (entry) {
        var full = path.join(current, entry.name);
        var rel  = prefix ? prefix + "/" + entry.name : entry.name;
        if (entry.isDirectory()) walk(full, rel);
        else out[rel] = crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex");
      });
  }(dir, ""));
  return out;
}

function _same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function _fileDigest(p) {
  if (!fs.existsSync(p)) return "ABSENT";
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function _manifestVersion(p) {
  try {
    var m = JSON.parse(fs.readFileSync(p, "utf8"));
    return ((m.packages || {}).blamejs || {}).version || "";
  } catch (_e) {
    return "UNREADABLE";
  }
}

// ---------------------------------------------------------------------------
// The stand-in registry
// ---------------------------------------------------------------------------

/**
 * startRegistry(config) stands a registry up on loopback and resolves with
 * its base URL and a close function.
 *
 * `config.routes` maps an exact request path to a reply, and is read per
 * request rather than captured, so a caller can fill in a route after the
 * server has a port. That matters here: a registry document names its own
 * tarball URL, which nothing can know until the listener is bound.
 *
 * A reply is `{ status, body, contentType }`. A body that is a string or a
 * Buffer is sent as it is, so a document that is deliberately not JSON can
 * be served the same way a valid one is. Anything else is serialized.
 *
 * Exported because the currency cases need the same stand-in. A second
 * copy of a mock is a second set of assumptions about what a registry
 * answers, and the two drift.
 */
function startRegistry(config) {
  return new Promise(function (resolve) {
    var server = http.createServer(function (req, res) {
      var reply = (config.routes || {})[req.url];
      if (!reply) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("no such path");
      }
      var body = reply.body;
      if (typeof body !== "string" && !Buffer.isBuffer(body)) body = JSON.stringify(body);
      res.writeHead(reply.status || 200, {
        "Content-Type": reply.contentType || "application/json",
      });
      return res.end(body);
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({
        base:  "http://127.0.0.1:" + server.address().port,
        close: function () {
          return new Promise(function (done) { server.close(function () { done(); }); });
        },
      });
    });
  });
}

/**
 * closedPort() finds a loopback port with nothing on it, so a case can
 * point a tool at an address that refuses the connection. The listener is
 * opened and closed to get a port the operating system just handed out,
 * which is as close to "certainly free" as a test can get without racing
 * something else on the machine.
 */
function closedPort() {
  return new Promise(function (resolve) {
    var probe = http.createServer(function () {});
    probe.listen(0, "127.0.0.1", function () {
      var port = probe.address().port;
      probe.close(function () { resolve(port); });
    });
  });
}

function _metadata(version, tarballUrl, integrity) {
  var versions = {};
  versions[version] = { dist: { tarball: tarballUrl, integrity: integrity } };
  return { "dist-tags": { latest: version }, versions: versions };
}

// ---------------------------------------------------------------------------
// A destructive step that fails partway
// ---------------------------------------------------------------------------

/**
 * _failureShimDir(marker) builds a directory holding stand-ins for `rm`
 * and `mv` that refuse, exactly once, any invocation naming `marker`, and
 * then hand every later call to the real command.
 *
 * Failing once and only once is what makes this the real failure rather
 * than a wedged filesystem: the destructive step dies partway, and the
 * recovery that follows it has to be able to run. The shim covers both
 * commands because which one a refresh reaches for is an implementation
 * detail; what is being asserted is that the previous tree survives the
 * step failing, however the step is written.
 *
 * Returns null when the real commands cannot be located.
 */
function _failureShimDir(marker) {
  var dir   = helpers.tempDir("vendorshim");
  var state = path.join(dir, "fired");
  var names = ["rm", "mv"];
  for (var i = 0; i < names.length; i += 1) {
    var probe = spawnSync("bash", ["-c", "command -v " + names[i]], { encoding: "utf8" });
    if (probe.error || probe.status !== 0) return null;
    var real = probe.stdout.trim();
    if (!real) return null;
    var body = [
      "#!/bin/sh",
      "for a in \"$@\"; do",
      "  case \"$a\" in",
      "    *" + marker + "*)",
      "      if [ ! -f '" + state + "' ]; then",
      "        : > '" + state + "'",
      "        echo \"" + names[i] + ": cannot act on $a: Device or resource busy\" >&2",
      "        exit 1",
      "      fi",
      "      ;;",
      "  esac",
      "done",
      "exec '" + real + "' \"$@\"",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(dir, names[i]), body);
    fs.chmodSync(path.join(dir, names[i]), 0o755);
  }
  return dir;
}

// ---------------------------------------------------------------------------
// Driving the script
// ---------------------------------------------------------------------------

/**
 * _bashPath(p) hands a path to bash the way bash can read it. On Windows
 * `path.join` produces backslashes, and bash treats a backslash as an
 * escape, so `C:\Users\...\vendor-update.sh` arrives as
 * `C:UsersRobert...` and the shell reports a file that does not exist.
 * Forward slashes survive on both platforms.
 */
function _bashPath(p) {
  return String(p).replace(/\\/g, "/");
}

// A failing case has to say what the script printed, or the only way to
// find out is to reproduce the run by hand.
function _transcript(result) {
  return "exit=" + String(result.status) +
    " stdout: " + String(result.stdout || "").slice(-1200) +
    " stderr: " + String(result.stderr || "").slice(-1200);
}

/**
 * runCommand(cmd, args, opts) runs a child and resolves with its exit
 * status and output.
 *
 * It has to be the asynchronous spawn, and this is the trap worth writing
 * down. The stand-in registry listens in this process, and a synchronous
 * spawn blocks the event loop for as long as the child runs, so the
 * child's first request waits on a server that cannot answer until the
 * child exits. The deadlock surfaces as a script that hangs and prints
 * nothing, which is a long way from where the problem is.
 *
 * Loopback is excluded from any proxy the machine has configured, so a
 * developer environment with HTTP_PROXY set does not send a request meant
 * for the stand-in registry somewhere else.
 */
function runCommand(cmd, args, opts) {
  opts = opts || {};
  var env = Object.assign({}, process.env, {
    NO_PROXY:  "127.0.0.1,localhost",
    no_proxy:  "127.0.0.1,localhost",
  }, opts.env || {});
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, {
      cwd:   opts.cwd,
      env:   env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    var stdout = "";
    var stderr = "";
    child.stdout.on("data", function (d) { stdout += d.toString(); });
    child.stderr.on("data", function (d) { stderr += d.toString(); });
    child.on("error", reject);
    child.on("close", function (status) {
      resolve({ status: status, stdout: stdout, stderr: stderr });
    });
  });
}

function _runRefresh(repo, registryBase, extraEnv) {
  return runCommand("bash", [_bashPath(repo.script), "blamejs", NEW_VERSION], {
    cwd: repo.root,
    env: Object.assign({ NPM_REGISTRY: registryBase }, extraEnv || {}),
  });
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

// When set, only cases whose label contains this string run. The suite
// leaves it null and runs all of them. It exists so one case at a time can
// be pointed at an earlier version of the refresh script: a run that stops
// at the first failure proves one case would have caught the bug, and
// says nothing about the rest.
var _only = null;

/**
 * _scenarios(scriptPath, opts) runs every case against one copy of the
 * refresh script. `run()` passes the shipped path and no options. The
 * parameters exist so the same cases can be pointed at an earlier version
 * of the script, one at a time, to prove each of them fails on it. A case
 * nobody has seen fail is a case with no evidence behind it.
 */
async function _scenarios(scriptPath, opts) {
  _only = (opts && typeof opts.only === "string") ? opts.only : null;
  var good = _makeTarball(NEW_VERSION, {});
  if (good === null) {
    skip("vendor refresh atomicity: `tar` is not on the path, so no registry tarball could be built");
    return;
  }

  // ---- The refresh that works ----
  await _case("a verified tarball is published", scriptPath, function (repo) {
    return {
      tarball:   good,
      integrity: _integrity(good),
      assert: function (result, before) {
        check("a verified refresh exits 0. " + _transcript(result),
          result.status === 0);
        check("the manifest records the new version",
          _manifestVersion(repo.manifest) === NEW_VERSION);
        check("the published tree is the tarball's tree, not the previous one",
          !_same(_snapshot(repo.dest), before.tree));
        check("the published tree carries the new entry point",
          fs.readFileSync(path.join(repo.dest, "index.js"), "utf8").indexOf(NEW_VERSION) !== -1);
        var recorded = JSON.parse(fs.readFileSync(repo.manifest, "utf8"))
          .packages.blamejs.hashes.server;
        check("the hash the manifest recorded is the hash of the tree on disk",
          recorded === manifestTool.hashTree(repo.dest));
        check("NOTICE follows the manifest to the new version",
          fs.readFileSync(repo.notice, "utf8").indexOf("Version:     " + NEW_VERSION) !== -1);
        check("the README row follows the manifest to the new version",
          fs.readFileSync(repo.readme, "utf8").indexOf("| " + NEW_VERSION + " |") !== -1);
        var leftovers = fs.readdirSync(path.join(repo.root, "lib", "vendor"))
          .filter(function (n) { return n.indexOf(".stage-") === 0 || n.indexOf(".backup-") === 0; });
        check("no staging or backup directory is left behind: " + leftovers.join(","),
          leftovers.length === 0);
      },
    };
  });

  // ---- The publisher's digest does not match ----
  await _case("a digest that does not match refuses before extracting", scriptPath, function () {
    return {
      tarball:   good,
      integrity: "sha512-" + "B".repeat(86) + "==",
      assert: function (result, before, repo) {
        _refused("integrity mismatch", result, before, repo);
        check("the refusal names the mismatch",
          /MISMATCH/.test(String(result.stdout) + String(result.stderr)));
      },
    };
  });

  // ---- The archive will not extract ----
  await _case("an archive that will not extract refuses", scriptPath, function () {
    var junk = Buffer.from("this is not a gzip stream, not even slightly");
    return {
      tarball:   junk,
      integrity: _integrity(junk),
      assert: function (result, before, repo) {
        _refused("extraction failure", result, before, repo);
      },
    };
  });

  // ---- The archive has no package.json ----
  var noManifest = _makeTarball(NEW_VERSION, { noManifest: true });
  if (noManifest !== null) {
    await _case("an archive with no package.json refuses", scriptPath, function () {
      return {
        tarball:   noManifest,
        integrity: _integrity(noManifest),
        assert: function (result, before, repo) {
          _refused("missing package.json", result, before, repo);
        },
      };
    });
  } else {
    skip("vendor refresh atomicity: could not build the package.json-less archive");
  }

  // ---- The archive is a fraction of the size of the tree it replaces ----
  var tiny = _makeTarball(NEW_VERSION, { modules: 1 });
  if (tiny !== null) {
    await _case("an archive a fraction of the size of the live tree refuses", scriptPath, function () {
      return {
        tarball:   tiny,
        integrity: _integrity(tiny),
        assert: function (result, before, repo) {
          _refused("implausible file count", result, before, repo);
        },
      };
    });

    await _case("the same archive is accepted when the operator says the package shrank",
      scriptPath, function () {
        return {
          tarball:   tiny,
          integrity: _integrity(tiny),
          env:       { VENDOR_ALLOW_SHRINK: "1" },
          assert: function (result, before, repo) {
            check("an acknowledged shrink is published. stderr: " +
              String(result.stderr).slice(0, 400),
            result.status === 0);
            check("the manifest records the new version after an acknowledged shrink",
              _manifestVersion(repo.manifest) === NEW_VERSION);
          },
        };
      });
  } else {
    skip("vendor refresh atomicity: could not build the undersized archive");
  }

  // ---- The entry point cannot be required ----
  var broken = _makeTarball(NEW_VERSION, { brokenEntry: true });
  if (broken !== null) {
    await _case("an archive whose entry point throws refuses", scriptPath, function () {
      return {
        tarball:   broken,
        integrity: _integrity(broken),
        assert: function (result, before, repo) {
          _refused("unloadable entry point", result, before, repo);
        },
      };
    });
  } else {
    skip("vendor refresh atomicity: could not build the unloadable archive");
  }

  // ---- The destructive step fails partway ----
  var shimDir = _failureShimDir(BUSY_ENTRY);
  if (shimDir === null) {
    skip("vendor refresh atomicity: could not build the stand-in for rm and mv");
  } else {
    await _case("a destructive step that fails partway leaves the previous tree whole",
      scriptPath, function () {
        return {
          tarball:   good,
          integrity: _integrity(good),
          env:       { PATH: shimDir + path.delimiter + process.env.PATH },
          assert: function (result, before, repo) {
            _refused("a destructive step failing partway", result, before, repo);
            check("the entry the step could not touch is still there",
              fs.existsSync(path.join(repo.dest, BUSY_ENTRY)));
            check("no file from the new release is mixed into the restored tree",
              Object.keys(_snapshot(repo.dest)).every(function (rel) {
                return Object.prototype.hasOwnProperty.call(before.tree, rel);
              }));
          },
        };
      });
  }

  // ---- A previous run's backup is still on disk ----
  await _case("a leftover backup from a previous run stops the refresh", scriptPath, function () {
    return {
      tarball:   good,
      integrity: _integrity(good),
      prepare: function (repo) {
        var stale = path.join(repo.root, "lib", "vendor", ".backup-blamejs.9999");
        fs.mkdirSync(stale, { recursive: true });
        fs.writeFileSync(path.join(stale, "index.js"), "// the only copy of something\n");
      },
      assert: function (result, before, repo) {
        _refused("a leftover backup", result, before, repo);
        check("the leftover backup is not removed by the refusal",
          fs.existsSync(path.join(repo.root, "lib", "vendor", ".backup-blamejs.9999", "index.js")));
        check("the refusal tells the operator what it found",
          /previous refresh left/.test(String(result.stderr)));
      },
    };
  });
}

/**
 * _refused(label, result, before, repo) is the assertion every failure
 * case shares: a non-zero exit, the previous tree back to the byte, and a
 * manifest still describing that tree. The manifest and the tree are
 * checked together on purpose. A refresh that restored the tree and left
 * the manifest pointing at the new version is just as broken as one that
 * did the opposite, and either check on its own passes on it.
 */
function _refused(label, result, before, repo) {
  check(label + ": the refresh exits non-zero",
    result.status !== 0);
  check(label + ": every file of the previous tree is back with its original bytes",
    _same(_snapshot(repo.dest), before.tree));
  check(label + ": the manifest still records the previous version, so it and the tree agree",
    _manifestVersion(repo.manifest) === OLD_VERSION);
  check(label + ": the manifest file is byte-identical to the one that was there",
    _fileDigest(repo.manifest) === before.manifest);
  check(label + ": NOTICE is byte-identical to the one that was there",
    _fileDigest(repo.notice) === before.notice);
  check(label + ": README.md is byte-identical to the one that was there",
    _fileDigest(repo.readme) === before.readme);
  check(label + ": the refusal says something on stderr rather than failing quietly",
    String(result.stderr).trim().length > 0);
}

/**
 * _case(label, scriptPath, build) sets up a temporary repository and a
 * stand-in registry, runs one refresh, and hands the result to the
 * case's own assertions along with a snapshot of everything as it was
 * beforehand.
 */
async function _case(label, scriptPath, build) {
  if (_only !== null && label.indexOf(_only) === -1) return;
  var repo = _makeRepo(scriptPath);
  var spec = build(repo);
  // The metadata document names its own tarball URL, which is not knowable
  // until the stand-in registry has a port, so the routes are filled in
  // after listen and the handler reads them per request.
  var config   = { routes: {} };
  var registry = await startRegistry(config);
  config.routes[META_PATH] = {
    body: _metadata(NEW_VERSION, registry.base + "/tarball", spec.integrity),
  };
  config.routes["/tarball"] = {
    body:        spec.tarball,
    contentType: "application/octet-stream",
  };
  try {
    if (spec.prepare) spec.prepare(repo);
    var before = {
      tree:     _snapshot(repo.dest),
      manifest: _fileDigest(repo.manifest),
      notice:   _fileDigest(repo.notice),
      readme:   _fileDigest(repo.readme),
    };
    var result = await _runRefresh(repo, registry.base, spec.env);
    spec.assert(result, before, repo);
  } finally {
    await registry.close();
    helpers.removeTempDir(repo.root);
  }
}

/**
 * _hashToolCases() covers the measurement the swap is decided on.
 *
 * The refresh compares a hash taken before the swap against one taken
 * after it, and refuses when they differ. Nothing above can force that
 * pair to disagree without a hook in the shipped script, and a test-only
 * hook in a shipped script is worse than the gap. What can be proven, and
 * is what makes the comparison worth anything, is that the measurement is
 * sensitive: two trees that differ anywhere hash differently, and the two
 * entry points into the walk agree. A comparison fed by a hash that
 * ignored a changed byte would pass while the tree was wrong.
 *
 * It also pins the `--hash` contract itself, because `vendor-update.sh`
 * calls it and a change to its output would silently take the refresh's
 * verification with it.
 */
async function _hashToolCases() {
  var a = helpers.tempDir("vendorhashA");
  var b = helpers.tempDir("vendorhashB");
  try {
    _writePackage(a, OLD_VERSION, {});
    _writePackage(b, OLD_VERSION, {});

    var hashA = await _hashCli(a);
    var hashB = await _hashCli(b);
    check("--hash prints a tree digest for a directory. " + hashA.stderr,
      /^sha256-tree:[0-9a-f]{64}$/.test(hashA.value));
    check("two trees with identical contents hash identically",
      hashA.value === hashB.value);
    check("the command line and the exported walk agree on the same tree",
      hashA.value === manifestTool.hashTree(a));

    // One byte, in one file, buried under a subdirectory.
    var buried = path.join(b, "lib", "mod-7.js");
    fs.writeFileSync(buried, fs.readFileSync(buried, "utf8").replace("7;", "8;"));
    check("changing one byte in one nested file changes the tree hash",
      (await _hashCli(b)).value !== hashA.value);

    // Back to identical, then a file that is only present on one side.
    _writePackage(b, OLD_VERSION, {});
    check("restoring the byte restores the hash",
      (await _hashCli(b)).value === hashA.value);
    fs.writeFileSync(path.join(b, "lib", "extra.js"), "module.exports = 0;\n");
    check("adding a file changes the tree hash",
      (await _hashCli(b)).value !== hashA.value);

    // A rename moves no bytes and must still register, because the walk
    // feeds entry names as well as contents.
    _writePackage(b, OLD_VERSION, {});
    fs.renameSync(path.join(b, "lib", "mod-3.js"), path.join(b, "lib", "mod-33.js"));
    check("renaming a file changes the tree hash even though no byte moved",
      (await _hashCli(b)).value !== hashA.value);

    var fileHash = await _hashCli(path.join(a, "package.json"));
    check("--hash prints a file digest for a file",
      /^sha256:[0-9a-f]{64}$/.test(fileHash.value));

    var missing = await _hashCli(path.join(a, "there-is-no-such-file"));
    check("--hash exits non-zero for a path that is not there",
      missing.status !== 0);
    check("--hash names the path it could not read",
      /there-is-no-such-file/.test(missing.stderr));

    var noArg = await runCommand(process.execPath, [REFRESH_SCRIPT, "--hash"], {});
    check("--hash with no path exits non-zero rather than hashing something else",
      noArg.status !== 0);
  } finally {
    helpers.removeTempDir(a);
    helpers.removeTempDir(b);
  }
}

async function _hashCli(target) {
  var r = await runCommand(process.execPath, [REFRESH_SCRIPT, "--hash", target], {});
  return { status: r.status, value: String(r.stdout).trim(), stderr: String(r.stderr).trim() };
}

/**
 * _requireIsInertCase() holds the line that lets anything else require the
 * manifest tool at all.
 *
 * Loading this file used to rewrite `lib/vendor/MANIFEST.json` as a side
 * effect, so the verification gate had to keep its own copy of the walk
 * rather than share one, and any consumer that required it rewrote the
 * record it was about to read. The guard that stopped that is invisible
 * from the outside, which is exactly the kind of thing that gets undone.
 */
async function _requireIsInertCase() {
  var manifestPath = path.join(REPO_ROOT, "lib", "vendor", "MANIFEST.json");
  var before = _fileDigest(manifestPath);
  var r = await runCommand(process.execPath, [
    "-e", "require(process.argv[1]);", REFRESH_SCRIPT,
  ], { cwd: REPO_ROOT });
  check("requiring the manifest tool exits 0. stderr: " + String(r.stderr).slice(0, 300),
    r.status === 0);
  check("requiring the manifest tool writes nothing, so a gate may share its walk",
    _fileDigest(manifestPath) === before);
}

async function run() {
  await helpers.withTestTimeout("vendor refresh atomicity", async function () {
    await _hashToolCases();
    await _requireIsInertCase();
    await _scenarios(SHIPPED_SCRIPT);
  }, { timeoutMs: 300000 });
}

module.exports = {
  run:            run,
  _scenarios:     _scenarios,
  // Shared with the currency cases rather than copied into them.
  startRegistry:  startRegistry,
  closedPort:     closedPort,
  bashPath:       _bashPath,
  runCommand:     runCommand,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
