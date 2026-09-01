// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The container, driven the way an operator drives it.
 *
 * Everything else in the integration layer builds the server inside the
 * test process. That view cannot see anything the image decides: which
 * user the process runs as, which files came along, whether the health
 * probe agrees with the listeners, whether a published port reaches
 * anything. The files that use this helper stand the real image up and
 * talk to it from outside, so what is asserted is what an operator gets
 * rather than what the source would produce if it were assembled by
 * hand.
 *
 * Two properties of this file are load bearing.
 *
 * Every docker invocation goes through `spawn` with an argument ARRAY
 * and no shell. On Windows a POSIX looking argument handed to a shell is
 * rewritten into a Windows path before docker ever sees it, so a value
 * such as the data directory arrives inside the Linux container as a
 * drive letter path, which is relative there, and the run writes its
 * database somewhere nobody expects. Measured directly on this platform:
 * a container asked to echo an environment value set to a POSIX path
 * prints a drive letter path instead. Passing an argument array bypasses
 * the shell entirely, so the rewrite has nothing to act on. Never build
 * a docker command as one string here.
 *
 * And absence is reported, never passed over. A file that needs the
 * image and cannot find a working docker says so and fails, because a
 * run that quietly skips the only checks that touch the shipped artifact
 * reports the same green as a run that made them.
 *
 * Nothing in here is shipped. It lives beside the files that use it so
 * the integration layer keeps one way of starting a container instead of
 * three that disagree about cleanup.
 */

var nodeCrypto = require("node:crypto");
var nodePath   = require("node:path");
var { spawn, spawnSync } = require("node:child_process");

var helpers = require("../helpers");
var cli     = require("../helpers/cli");

// The image these files test is built from the working tree, so what is
// asserted is this tree's Dockerfile rather than whatever was published
// last. `BLAMEPOST_TEST_IMAGE` points the run at an already built image
// instead, which is how a release pipeline tests the artifact it just
// produced.
var IMAGE_TAG = "blamepost-integration:working-tree";

var DOCKER_BIN = process.env.BLAMEPOST_DOCKER_BIN || "docker";

// A cold build pulls two base images and can take minutes on a slow
// link. A warm one is seconds. The ceiling is sized for the cold case so
// a first run on a fresh machine is not reported as a hang.
var BUILD_TIMEOUT_MS = 600000;
var CLI_TIMEOUT_MS   = 120000;
var PROBE_TIMEOUT_MS = 30000;

// How long a container gets to report itself healthy. The image's own
// HEALTHCHECK has a thirty second start period before its first probe
// counts, so anything shorter than that measures the start period rather
// than the server.
var HEALTHY_TIMEOUT_MS = 120000;

// Everything this process created, so a thrown assertion still leaves
// the machine clean. Removal on exit is synchronous because an exit
// handler cannot await.
var _containers = [];
var _volumes    = [];

function uniqueName(prefix) {
  if (typeof prefix !== "string" || !/^[a-z0-9][a-z0-9_-]{0,24}$/.test(prefix)) {
    throw new TypeError("uniqueName: prefix must match /^[a-z0-9][a-z0-9_-]{0,24}$/");
  }
  return prefix + "-" + nodeCrypto.randomBytes(6).toString("hex");
}

/**
 * @primitive test.layer2.containerHarness.docker
 * @signature docker(args, opts?) -> Promise<{ code, stdout, stderr, timedOut }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: argument array only, never a command string)
 *
 * One docker invocation. Resolves with the exit code rather than
 * rejecting, so a caller that expects a failure reads it as data.
 */
function docker(args, opts) {
  opts = opts || {};
  if (!Array.isArray(args) || args.length === 0) {
    throw new TypeError("docker: args must be a non-empty array");
  }
  args.forEach(function (a) {
    if (typeof a !== "string") throw new TypeError("docker: every argument must be a string");
  });
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : CLI_TIMEOUT_MS;
  return new Promise(function (resolve) {
    var child = spawn(DOCKER_BIN, args, {
      shell: false,
      cwd:   opts.cwd || helpers.REPO_ROOT,
      env:   opts.env || process.env,
    });
    var stdout   = "";
    var stderr   = "";
    var timedOut = false;
    var timer = setTimeout(function () {
      timedOut = true;
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the resolve below carries the verdict */ }
    }, timeoutMs);
    child.stdout.on("data", function (d) { stdout += d.toString(); });
    child.stderr.on("data", function (d) { stderr += d.toString(); });
    child.on("close", function (code) {
      clearTimeout(timer);
      resolve({ code: code, stdout: stdout, stderr: stderr, timedOut: timedOut });
    });
    child.on("error", function (e) {
      clearTimeout(timer);
      resolve({
        code:     -1,
        stdout:   "",
        stderr:   String((e && e.message) || e),
        timedOut: false,
      });
    });
  });
}

// A docker invocation whose failure is a test failure rather than a
// result. The message carries what docker actually said, because the
// alternative is a bare exit code and another run to find out why.
async function dockerOrThrow(args, what, opts) {
  var rv = await docker(args, opts);
  if (rv.code !== 0) {
    throw new Error(what + ": docker " + args.slice(0, 3).join(" ") +
      " exited " + rv.code + (rv.timedOut ? " (timed out)" : "") +
      "; stderr: " + rv.stderr.trim().split("\n").slice(-6).join(" | "));
  }
  return rv;
}

/**
 * @primitive test.layer2.containerHarness.preflight
 * @signature preflight() -> Promise<{ ok, reason }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: absence is reported, never passed over)
 *
 * Whether a container engine is reachable. Reports the reason rather
 * than a boolean alone, because "docker is not installed" and "docker is
 * installed and its daemon is not running" need different answers from
 * whoever reads the failure.
 */
async function preflight() {
  var rv = await docker(["version", "--format", "{{.Server.Version}}"], { timeoutMs: 30000 });
  if (rv.code === -1) {
    return { ok: false, reason: "the docker command could not be run: " + rv.stderr.trim() };
  }
  if (rv.code !== 0) {
    return {
      ok:     false,
      reason: "the docker daemon did not answer: " +
        (rv.stderr.trim() || rv.stdout.trim() || "exit " + rv.code),
    };
  }
  return { ok: true, reason: "server " + rv.stdout.trim() };
}

/**
 * @primitive test.layer2.containerHarness.requireStack
 * @signature requireStack(fileName) -> Promise<string>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: a missing engine fails loudly and names the remedy)
 *
 * The gate every container file opens with. Throws a message that names
 * the file, the reason and what to do about it, so a run on a machine
 * with no engine reads as an unmet prerequisite rather than as a defect
 * in the server.
 */
async function requireStack(fileName) {
  var seen = await preflight();
  if (!seen.ok) {
    throw new Error(
      fileName + " drives the shipped container image and cannot run without one. " +
      seen.reason + ". Start a container engine and run this file again, or run the " +
      "suite without the integration layer, which reports the layer as skipped by name " +
      "and file count instead of passing quietly.");
  }
  return seen.reason;
}

/**
 * @primitive test.layer2.containerHarness.buildImage
 * @signature buildImage() -> Promise<string>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: test the tree's own Dockerfile, not a published tag)
 *
 * Builds the image from the working tree and returns the tag. Honors
 * `BLAMEPOST_TEST_IMAGE`, which points a run at an already built image
 * so a release pipeline can assert against the artifact it published.
 */
var _builtTag = null;
async function buildImage() {
  if (process.env.BLAMEPOST_TEST_IMAGE) return process.env.BLAMEPOST_TEST_IMAGE;
  if (_builtTag !== null) return _builtTag;
  await dockerOrThrow(
    ["build", "--file", nodePath.join(helpers.REPO_ROOT, "Dockerfile"),
      "--tag", IMAGE_TAG, helpers.REPO_ROOT],
    "building the image under test",
    { timeoutMs: BUILD_TIMEOUT_MS });
  _builtTag = IMAGE_TAG;
  return _builtTag;
}

// One `docker inspect`, parsed. `inspect` answers with an array even for
// a single reference, so the element is what a caller wants.
async function inspect(ref) {
  var rv = await dockerOrThrow(["inspect", ref], "inspecting " + ref);
  var parsed = JSON.parse(rv.stdout);
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw new Error("inspecting " + ref + ": expected one object, got " + parsed.length);
  }
  return parsed[0];
}

/**
 * @primitive test.layer2.containerHarness.nodeInImage
 * @signature nodeInImage(image, expression, opts?) -> Promise<object>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: read the filesystem the image actually ships)
 *
 * Runs one Node expression inside the image and parses the single JSON
 * object it prints. The entry point is overridden because the image's
 * own entry point is the server, and the question here is what is on the
 * filesystem rather than what the server does with it.
 */
async function nodeInImage(image, expression, opts) {
  opts = opts || {};
  var args = ["run", "--rm", "--entrypoint", "/usr/bin/node"];
  (opts.env || []).forEach(function (pair) { args.push("-e", pair); });
  (opts.extra || []).forEach(function (a) { args.push(a); });
  args.push(image, "-e", expression);
  var rv = await dockerOrThrow(args, "probing the image filesystem", {
    timeoutMs: opts.timeoutMs || PROBE_TIMEOUT_MS,
  });
  var text = rv.stdout.trim();
  try { return JSON.parse(text); }
  catch (_e) {
    throw new Error("probing the image filesystem: expected one JSON object, got " +
      JSON.stringify(text.slice(0, 400)));
  }
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

async function createVolume(prefix) {
  var name = uniqueName(prefix);
  await dockerOrThrow(["volume", "create", name], "creating the data volume");
  _volumes.push(name);
  return name;
}

async function removeVolume(name) {
  var i = _volumes.indexOf(name);
  if (i !== -1) _volumes.splice(i, 1);
  await docker(["volume", "rm", "-f", name]);
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

/**
 * @primitive test.layer2.containerHarness.Container
 * @signature new Container(name, image)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one place that knows how to stop and remove)
 *
 * One container. Created through `Container.start`, which registers it
 * for removal so a thrown assertion cannot leave it running.
 */
function Container(name, image) {
  this.name  = name;
  this.image = image;
}

/**
 * Starts a detached container and returns the handle.
 *
 * opts.env      array of NAME=value strings
 * opts.publish  array of container ports to publish on an ephemeral
 *               loopback port, so parallel runs cannot collide
 * opts.volume   name of the volume mounted at the data path
 * opts.extra    further docker arguments, already split
 * opts.command  arguments after the image, overriding the image CMD
 */
Container.start = async function (image, prefix, opts) {
  opts = opts || {};
  var name = uniqueName(prefix);
  var args = ["run", "--detach", "--name", name];
  if (opts.volume) args.push("--volume", opts.volume + ":" + DATA_PATH);
  (opts.publish || []).forEach(function (port) {
    args.push("--publish", "127.0.0.1::" + port);
  });
  (opts.env || []).forEach(function (pair) { args.push("--env", pair); });
  (opts.extra || []).forEach(function (a) { args.push(a); });
  args.push(image);
  (opts.command || []).forEach(function (a) { args.push(a); });
  _containers.push(name);
  await dockerOrThrow(args, "starting container " + name);
  return new Container(name, image);
};

// The host port docker chose for a container port. Read back rather than
// reserved in advance, because a port reserved on the host and then
// released is a port something else can take before docker binds it.
Container.prototype.hostPort = async function (containerPort) {
  var rv = await dockerOrThrow(["port", this.name, String(containerPort) + "/tcp"],
    "reading the published port for " + containerPort);
  var found = /(\d+)\s*$/.exec(rv.stdout.trim().split("\n")[0] || "");
  if (!found) {
    throw new Error("container " + this.name + " published nothing for port " +
      containerPort + "; docker said " + JSON.stringify(rv.stdout.trim()));
  }
  return parseInt(found[1], 10);
};

Container.prototype.state = async function () {
  var seen = await inspect(this.name);
  return {
    status: seen.State.Status,
    exit:   seen.State.ExitCode,
    health: (seen.State.Health && seen.State.Health.Status) || null,
    log:    (seen.State.Health && seen.State.Health.Log) || [],
  };
};

Container.prototype.logs = async function () {
  var rv = await docker(["logs", this.name]);
  return rv.stdout + rv.stderr;
};

// Waits for the image's own HEALTHCHECK to report healthy.
//
// An exit is terminal and is reported straight away with the container's
// own last lines. Routing it through the poll predicate instead would
// swallow it as "not ready yet" and spend the whole budget before saying
// anything, which turns a server that refused to start and explained
// itself into a bare timeout.
Container.prototype.waitHealthy = async function (label) {
  var self = this;
  var settled = await helpers.waitUntil(async function () {
    var seen = await self.state();
    if (seen.status === "exited") return { exited: seen };
    return seen.health === "healthy" ? { healthy: seen } : false;
  }, { timeoutMs: HEALTHY_TIMEOUT_MS, intervalMs: 500, label: label });
  if (settled.exited) {
    throw new Error(label + ": the container exited with code " + settled.exited.exit +
      " instead of reporting healthy. Its last output was: " +
      (await self.logs()).trim().split("\n").slice(-6).join(" | "));
  }
  return settled.healthy;
};

Container.prototype.remove = async function () {
  var i = _containers.indexOf(this.name);
  if (i !== -1) _containers.splice(i, 1);
  await docker(["rm", "--force", "--volumes", this.name]);
};

// ---------------------------------------------------------------------------
// The one data path, named once
// ---------------------------------------------------------------------------

var DATA_PATH = "/var/lib/blamepost";

// The framework's boot lines are stripped before anything is asserted,
// so a log line cannot satisfy a check about what the operator was told.
//
// The filter is `test/helpers/cli.js`'s, imported rather than restated.
// It runs the same binary; the only difference here is that the process
// is inside a container, which changes how the run is started and not
// what comes back. A copy would be a second opinion about what a boot
// line looks like, and the two would drift.
var withoutBootLines = cli.withoutBootLines;

// A one shot run of the shipped CLI against a volume. This is the shape
// the quick start documents for every step that is not the server
// itself, so driving it here drives what an operator is told to type.
async function runCli(image, volume, env, argv, opts) {
  opts = opts || {};
  var args = ["run", "--rm", "--volume", volume + ":" + DATA_PATH];
  (env || []).forEach(function (pair) { args.push("--env", pair); });
  (opts.extra || []).forEach(function (a) { args.push(a); });
  args.push(image);
  argv.forEach(function (a) { args.push(a); });
  var rv = await docker(args, { timeoutMs: opts.timeoutMs || CLI_TIMEOUT_MS });
  return {
    code:   rv.code,
    stdout: withoutBootLines(rv.stdout),
    stderr: withoutBootLines(rv.stderr),
    raw:    rv,
  };
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async function cleanup() {
  while (_containers.length) {
    var name = _containers.pop();
    await docker(["rm", "--force", "--volumes", name]);
  }
  while (_volumes.length) {
    var vol = _volumes.pop();
    await docker(["volume", "rm", "--force", vol]);
  }
}

// Drop-silent by design: this runs on the failure path, where the
// assertion that failed is the result and a cleanup error would replace
// it. Synchronous because an exit handler cannot await.
process.on("exit", function () {
  _containers.forEach(function (name) {
    try { spawnSync(DOCKER_BIN, ["rm", "--force", "--volumes", name], { shell: false }); }
    catch (_e) { /* drop-silent by design */ }
  });
  _volumes.forEach(function (vol) {
    try { spawnSync(DOCKER_BIN, ["volume", "rm", "--force", vol], { shell: false }); }
    catch (_e) { /* drop-silent by design */ }
  });
});

module.exports = {
  IMAGE_TAG:          IMAGE_TAG,
  DATA_PATH:          DATA_PATH,
  BUILD_TIMEOUT_MS:   BUILD_TIMEOUT_MS,
  HEALTHY_TIMEOUT_MS: HEALTHY_TIMEOUT_MS,

  docker:        docker,
  dockerOrThrow: dockerOrThrow,
  preflight:     preflight,
  requireStack:  requireStack,
  buildImage:    buildImage,
  inspect:       inspect,
  nodeInImage:   nodeInImage,

  createVolume:     createVolume,
  removeVolume:     removeVolume,
  Container:        Container,
  runCli:           runCli,
  withoutBootLines: withoutBootLines,
  uniqueName:       uniqueName,
  cleanup:          cleanup,
};
