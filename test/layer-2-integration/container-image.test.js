// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The image, measured against what the documents promise an operator.
 *
 * Every other file in this layer assembles the server inside the test
 * process, which is a view that cannot see a single thing the image
 * decides. The user the process runs as, the mode of the data
 * directory, which files came along, what a health probe is pointed at,
 * whether an interpreter nobody asked for is sitting on the path: all of
 * it is invisible from source and all of it is what an operator gets.
 *
 * Two of those were wrong when this file was written, and neither was
 * visible from anything the suite already ran.
 *
 * The data directory shipped at mode 0755. The production posture
 * assertion the server runs at boot requires 0750 or tighter, so the
 * published image refused to start, named the mode, and exited before
 * binding a single listener. A named volume takes its mode from the
 * image directory it is initialized from, so the compose stack inherited
 * the same refusal. The quick start could not have worked for anyone.
 *
 * And the runtime base carries a busybox shell and npm. The Dockerfile
 * said it carried neither. That claim is not decoration: an operator
 * sizing what a code execution defect in a mail parser would reach reads
 * it as the answer. Measured against the pinned digest and against the
 * tag it tracks, both carry both, and the image's own package inventory
 * lists them. So the posture recorded here is the measured one, pinned
 * as an exact set: a base image that grows an operating system package
 * manager, or loses the interpreter the record names, fails this file
 * rather than shipping.
 *
 * Nothing here needs the server to run. It needs the image to exist,
 * which is the point.
 *
 * Run standalone: node test/layer-2-integration/container-image.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var harness   = require("./container-harness");

var REPO_ROOT = helpers.REPO_ROOT;
var DATA_PATH = harness.DATA_PATH;

// The production posture assertion refuses a data directory looser than
// this, so the image has to ship one at or below it or the server never
// starts. Named here rather than inlined because the number is the whole
// finding.
var DATA_DIR_MAX_MODE = 0o750;

// The runtime user. Four shipped documents name it, so it is asserted
// twice: as the image's declared User, and as the identity a process
// actually runs under.
var RUNTIME_UID = 65532;

// The interpreter and package tooling the runtime base supplies, as
// measured. Every entry is provided by a package the base image's own
// inventory lists, so this set is a record of the base rather than of
// anything blamepost installs. An exact match is required in both
// directions: something new on this list is an attack surface nobody
// reviewed, and something missing means a document describing the
// posture has gone stale.
var BASE_INTERPRETERS = [
  "/bin/sh",           // busybox
  "/bin/busybox",      // busybox
  "/usr/bin/npm",      // npm
  "/usr/bin/npx",      // npm
  "/usr/bin/node-gyp", // node-gyp
];

// An operating system package manager would let anything with code
// execution pull a toolchain from the network. None is present and none
// may appear.
var OS_PACKAGE_MANAGERS = [
  "/sbin/apk", "/usr/bin/apk",
  "/usr/bin/apt", "/usr/bin/apt-get",
  "/usr/bin/dnf", "/usr/bin/yum",
  "/usr/bin/pacman", "/usr/bin/zypper",
];

// Everything the listener table in the operator guide says binds, plus
// POP3, which is declared because it binds once an operator switches it
// on. Nothing binds 993 or 995 on any configuration, so neither is
// declared.
var DECLARED_PORTS = ["25/tcp", "110/tcp", "143/tcp", "465/tcp", "587/tcp",
  "4190/tcp", "8080/tcp", "8443/tcp"];

// A value that seals data at rest or authenticates an account must never
// be baked into a layer, where it is readable by anyone who can pull the
// image.
var NEVER_BAKED = ["BLAMEPOST_VAULT_PASSPHRASE", "BLAMEPOST_ADMIN_PASSWORD",
  "BLAMEPOST_ADMIN_EMAIL"];

var count = helpers.count;

// The probe that runs inside the image. One expression, one JSON object,
// so a caller reads a result rather than parsing a transcript.
function probeExpression() {
  return [
    "var fs=require('node:fs');",
    "function stat(p){try{var s=fs.lstatSync(p);",
    "return {mode:s.mode&4095,uid:s.uid,gid:s.gid,dir:s.isDirectory(),link:s.isSymbolicLink()};}",
    "catch(e){return null;}}",
    "var want=" + JSON.stringify(BASE_INTERPRETERS.concat(OS_PACKAGE_MANAGERS)) + ";",
    "var seen={};want.forEach(function(p){seen[p]=stat(p)!==null;});",
    // A manifest that cannot be read reports why. Left silent, an
    // unreadable file and a version mismatch produce the same failure
    // and only one of them is about the version.
    "var manifest=null,manifestError=null;",
    "try{manifest=JSON.parse(fs.readFileSync('/app/lib/vendor/MANIFEST.json','utf8'));}",
    "catch(e){manifestError=String((e&&e.message)||e);}",
    "process.stdout.write(JSON.stringify({",
    "manifestError:manifestError,",
    "uid:process.getuid(),gid:process.getgid(),version:process.version,cwd:process.cwd(),",
    "dataDir:stat(" + JSON.stringify(DATA_PATH) + "),",
    "appRoot:stat('/app'),",
    "appEntries:fs.readdirSync('/app').sort(),",
    "present:seen,",
    "vendorIndex:stat('/app/lib/vendor/blamejs/index.js')!==null,",
    "vendorVersion:manifest&&manifest.packages&&manifest.packages.blamejs",
    "?manifest.packages.blamejs.version:null,",
    "cliEntry:stat('/app/bin/blamepost.js')!==null",
    "}));",
  ].join("");
}

// Compares a dotted version against a floor, numerically rather than
// lexically, because "26.3.1" sorts below "9.0.0" as text.
function atLeast(version, floor) {
  var a = String(version).replace(/^v/, "").split(".").map(Number);
  var f = String(floor).split(".").map(Number);
  for (var i = 0; i < 3; i += 1) {
    var left  = a[i] || 0;
    var right = f[i] || 0;
    if (left > right) return true;
    if (left < right) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------

function theImageRunsAsTheDocumentedUser(config, probe) {
  count("the image declares the unprivileged runtime user",
    config.User === RUNTIME_UID + ":" + RUNTIME_UID, config.User);
  count("a process in the image actually runs as that user",
    probe.uid === RUNTIME_UID && probe.gid === RUNTIME_UID,
    "uid " + probe.uid + " gid " + probe.gid);
  count("the working directory is the application root", probe.cwd === "/app", probe.cwd);
}

// The failure this covers is the one that made the published image
// unstartable: the server asserts its production posture at boot and
// refuses a data directory anyone but its owner can enter. The image
// ships that directory, and a fresh named volume is initialized from it,
// so a mode set here decides whether the compose stack starts at all.
function theDataDirectoryIsShippedAtAModeTheServerAccepts(probe) {
  count("the image ships the data directory", probe.dataDir !== null && probe.dataDir.dir,
    JSON.stringify(probe.dataDir));
  count("the data directory is owned by the runtime user",
    probe.dataDir.uid === RUNTIME_UID && probe.dataDir.gid === RUNTIME_UID,
    "uid " + probe.dataDir.uid + " gid " + probe.dataDir.gid);
  // The server's own predicate, restated. It compares the mode against
  // the ceiling numerically, so this asserts the same thing an operator
  // would be told at boot rather than something adjacent to it.
  count("the data directory mode is one the production posture assertion accepts, " +
    "so the server can start against a volume initialized from it",
    probe.dataDir.mode <= DATA_DIR_MAX_MODE,
    "mode 0" + probe.dataDir.mode.toString(8) + ", ceiling 0" + DATA_DIR_MAX_MODE.toString(8));
  // Stricter than the numeric ceiling on purpose: a mode such as 0705 is
  // below it and still lets any identity in the container walk the
  // sealed keys and the message blobs.
  count("no other identity may enter the data directory",
    (probe.dataDir.mode & 0o007) === 0, "mode 0" + probe.dataDir.mode.toString(8));
}

// The base image ships the application root world-writable. Measured at
// 0777 on the pinned digest and on the tag it tracks, so an identity
// with execution inside the container could rewrite the code the next
// start runs. Nothing needs it: the server runs as the user that owns
// the directory.
function theApplicationRootIsNotWritableByEveryone(probe) {
  count("the image ships the application root", probe.appRoot !== null && probe.appRoot.dir,
    JSON.stringify(probe.appRoot));
  count("the application root is not writable by every identity in the container",
    (probe.appRoot.mode & 0o002) === 0, "mode 0" + probe.appRoot.mode.toString(8));
  count("the application root is owned by the runtime user",
    probe.appRoot.uid === RUNTIME_UID, "uid " + probe.appRoot.uid);
}

// The posture recorded is the measured one. An exact match in both
// directions, because a base image that grows a package manager and one
// that quietly drops the interpreter a document describes are both
// changes somebody has to look at.
function theExecutableSurfaceIsTheOneOnRecord(probe) {
  OS_PACKAGE_MANAGERS.forEach(function (path_) {
    count("no operating system package manager at " + path_,
      probe.present[path_] === false);
  });
  var missing = BASE_INTERPRETERS.filter(function (p) { return probe.present[p] === false; });
  count("the interpreter surface the base supplies is the one on record, " +
    "so a base image bump that changes it is reviewed rather than inherited",
    missing.length === 0, "missing from the image: " + (missing.join(", ") || "nothing"));
}

// Hard rule 1 in the form an operator can check: the framework is
// vendored in the tree and nothing is resolved from a registry, so the
// image carries the framework and carries no dependency directory.
function theImageCarriesNoResolvedDependencies(probe, manifestVersion) {
  count("the application root holds no dependency directory",
    probe.appEntries.indexOf("node_modules") === -1, probe.appEntries.join(" "));
  count("the vendored framework arrived in the image", probe.vendorIndex === true);
  count("the image carries a readable vendor manifest",
    probe.manifestError === null, String(probe.manifestError));
  count("the vendored framework in the image is the version the tree pins",
    probe.vendorVersion === manifestVersion,
    "image " + probe.vendorVersion + ", tree " + manifestVersion);
  count("the operator's entry point arrived in the image", probe.cliEntry === true);
}

function theRuntimeMeetsTheDeclaredFloor(probe, floor) {
  count("the Node runtime in the image meets the floor the package declares",
    atLeast(probe.version, floor), "image " + probe.version + ", floor " + floor);
}

// The entry point, the default command and the health probe are all
// argument arrays. That is what keeps a shell out of the container's own
// operation whatever the base image happens to carry: nothing the image
// runs is handed to one for word splitting.
function nothingTheImageRunsGoesThroughAShell(config) {
  var SHELL_TOKENS = /(?:^|\/)(?:sh|bash|ash|dash|busybox)$/;
  count("the entry point is the Node binary rather than a shell",
    Array.isArray(config.Entrypoint) && config.Entrypoint.length === 1 &&
    config.Entrypoint[0] === "/usr/bin/node", JSON.stringify(config.Entrypoint));
  count("the default command runs the server",
    Array.isArray(config.Cmd) && config.Cmd.join(" ") === "bin/blamepost.js serve",
    JSON.stringify(config.Cmd));
  var probeTest = (config.Healthcheck && config.Healthcheck.Test) || [];
  count("the health probe is an argument array rather than a shell string",
    probeTest[0] === "CMD", JSON.stringify(probeTest));
  var invokesShell = probeTest.slice(1).some(function (token) {
    return SHELL_TOKENS.test(String(token));
  }) || (Array.isArray(config.Cmd) && config.Cmd.some(function (t) {
    return SHELL_TOKENS.test(String(t));
  }));
  count("nothing the image is configured to run names a shell", invokesShell === false);
}

// The probe reads one value for the port. That is the same value the
// compose file publishes and hands the optional terminator, so a moved
// port moves the probe with it rather than leaving it checking a port
// nothing binds and restarting a healthy server.
function theHealthProbeFollowsThePortVariable(config) {
  var probeTest = (config.Healthcheck && config.Healthcheck.Test) || [];
  var body = probeTest.join(" ");
  count("the image declares a health probe", probeTest.length > 0);
  count("the health probe reads the port from the environment variable the compose " +
    "file sets, rather than carrying a second copy of the number",
    body.indexOf("BLAMEPOST_HTTP_PORT") !== -1, body.slice(0, 200));
  count("the health probe asks the readiness endpoint",
    body.indexOf("/healthz") !== -1, body.slice(0, 200));
  count("the health probe waits before its first verdict counts, so a boot that " +
    "unseals a vault is not restarted underneath itself",
    config.Healthcheck.StartPeriod > 0, String(config.Healthcheck.StartPeriod));
}

function theDeclaredSurfaceMatchesTheListenerTable(config) {
  var exposed = Object.keys(config.ExposedPorts || {}).sort();
  DECLARED_PORTS.slice().sort().forEach(function (port) {
    count("the image declares " + port, exposed.indexOf(port) !== -1, exposed.join(" "));
  });
  count("the image declares no port outside the listener table",
    exposed.every(function (p) { return DECLARED_PORTS.indexOf(p) !== -1; }), exposed.join(" "));
  var volumes = Object.keys(config.Volumes || {});
  count("exactly one data volume is declared, at the documented path",
    volumes.length === 1 && volumes[0] === DATA_PATH, volumes.join(" "));
}

function noSecretIsBakedIntoALayer(config) {
  var baked = (config.Env || []).map(function (pair) { return pair.split("=")[0]; });
  NEVER_BAKED.forEach(function (name) {
    count("no value for " + name + " is baked into the image",
      baked.indexOf(name) === -1, baked.join(" "));
  });
  count("the image sets the production runtime mode",
    (config.Env || []).indexOf("NODE_ENV=production") !== -1);
}

// ---------------------------------------------------------------------------

async function run() {
  await harness.requireStack("container-image.test.js");
  var image = await harness.buildImage();

  var pkg = JSON.parse(nodeFs.readFileSync(nodePath.join(REPO_ROOT, "package.json"), "utf8"));
  var floor = String(pkg.engines.node).replace(/^[^\d]*/, "");
  var manifest = JSON.parse(nodeFs.readFileSync(
    nodePath.join(REPO_ROOT, "lib", "vendor", "MANIFEST.json"), "utf8"));
  var pinned = manifest.packages.blamejs.version;

  try {
    var inspected = await harness.inspect(image);
    var config    = inspected.Config;
    var probe     = await harness.nodeInImage(image, probeExpression());

    theImageRunsAsTheDocumentedUser(config, probe);
    theDataDirectoryIsShippedAtAModeTheServerAccepts(probe);
    theApplicationRootIsNotWritableByEveryone(probe);
    theExecutableSurfaceIsTheOneOnRecord(probe);
    theImageCarriesNoResolvedDependencies(probe, pinned);
    theRuntimeMeetsTheDeclaredFloor(probe, floor);
    nothingTheImageRunsGoesThroughAShell(config);
    theHealthProbeFollowsThePortVariable(config);
    theDeclaredSurfaceMatchesTheListenerTable(config);
    noSecretIsBakedIntoALayer(config);
  } finally {
    await harness.cleanup();
  }

  return helpers.getChecks();
}

module.exports = { name: "container-image", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
