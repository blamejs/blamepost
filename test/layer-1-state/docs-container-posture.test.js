// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The container posture the shipped documents promise, held against the
 * image that would have to satisfy it.
 *
 * A claim about what the server defends against is the one kind of
 * documentation drift that costs an operator a decision rather than a
 * command. Somebody sizing what a code execution defect in a mail parser
 * would reach, or deciding whether a runtime flag is load bearing, acts
 * on the sentence. Three of those sentences were measurably wrong.
 *
 * The executable surface. Four documents said the image ships no shell
 * and no package manager on a distroless base. Measured against the
 * pinned base digest and against the tag it tracks, the runtime base
 * carries busybox, which is `/bin/sh`, plus npm, npx and node-gyp, and
 * the image's own package inventory under `/var/lib/db/sbom` lists all
 * three. What is genuinely absent is an operating system package
 * manager: no apk, apt, dnf or yum, so nothing in the image can install
 * a package from the network. Half the claim held and half did not, and
 * the half that did not is the half an operator would have relied on.
 *
 * The port floor. One document said the runtime user cannot bind ports
 * below 1024 under the default kernel floor, which made the sysctl in
 * the quick start read as the thing that permits the bind. In a
 * container's own network namespace on current Docker the floor already
 * reads 0, and the image binds 25, 465, 587 and 143 as UID 65532 with
 * every capability dropped and no sysctl at all. The one case where the
 * floor is real is host networking, where it is the host's own 1024 and
 * where the sysctl is refused rather than applied, and that is the case
 * the per listener port variables answer.
 *
 * The data directory mode. The production posture assertion refuses a
 * data directory looser than 0750 and exits before binding a listener.
 * An operator bind mounting a directory created at the usual umask gets
 * 0755 and a refusal, and no document said so.
 *
 * What this file asserts is therefore of two shapes. A claim of absence
 * is checked against the measurement, by the claim's shape rather than
 * by any sentence, so a rewording that keeps the claim keeps failing.
 * And the facts the corrected wording rests on are read out of the
 * artifacts themselves: the invocation forms out of the Dockerfile, the
 * refusal threshold out of the framework primitive that enforces it.
 *
 * `container-image.test.js` measures the same posture against the built
 * image and needs the image to exist. This file needs neither Docker nor
 * a server, because a document can be wrong long before either is
 * available to say so.
 *
 * Run standalone: node test/layer-1-state/docs-container-posture.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");

var skip  = helpers.skip;

// Everything an operator reads that could carry a posture claim, plus
// the two artifacts that describe the image, because a false claim in a
// build file reaches exactly the same reader.
var CLAIM_SURFACES = [
  "README.md",
  "SECURITY.md",
  "THREAT-MODEL.md",
  "ARCHITECTURE.md",
  "ROADMAP.md",
  "CHANGELOG.md",
  "docs/operator-guide.md",
  "release-notes/v0.1.x.json",
  "Dockerfile",
  "compose.yml",
];

// The settings reference. It is the document an operator is sent to for
// the alternative when a port cannot be taken, so it is the document
// that has to name the case where that alternative is the only answer.
var SETTINGS_REFERENCE = "docs/operator-guide.md";

// The image definition, read as text so this file runs without Docker.
var IMAGE_DEFINITION = "Dockerfile";
var COMPOSE_FILE     = "compose.yml";

// The workflow that publishes the image. It is the authority on what an
// operator can actually pull, which is what a verification recipe or a
// quick start has to name.
var CONTAINER_WORKFLOW = ".github/workflows/release-container.yml";

// The published repository, and a reference to a version of it.
var IMAGE_REPOSITORY = "ghcr.io/blamejs/blamepost";
var IMAGE_TAG_RE     = /ghcr\.io\/blamejs\/blamepost:([^\s`'")\\]+)/g;

// What the runtime base supplies, as measured. Every entry is provided
// by a package the base image's own inventory lists, so this records the
// base rather than anything blamepost installs.
var BASE_SUPPLIES = {
  shell:            true,   // busybox, reachable at /bin/sh and /bin/busybox
  nodePackageTools: true,   // npm, npx and node-gyp
  osPackageManager: false,  // no apk, apt, dnf or yum
};

// Claims of absence the measurement above refuses. Each is a shape, not
// a sentence: the invariant is that a document may not assert the
// absence of something the base supplies, however the assertion is
// phrased. The qualified form "no operating system package manager" is
// true and matches none of these, which is the distinction that matters,
// because npm is a package manager and it is present.
var FALSE_ABSENCE_CLAIMS = [
  {
    subject: "shell",
    present: function () { return BASE_SUPPLIES.shell; },
    // "shell script" and "shell history" are ordinary prose about
    // something other than the image's executable surface.
    re: /\b(?:no|without(?: a| any)?)\s+shell\b(?!\s*(?:script|history|expansion|glob))/i,
    why: "the runtime base carries busybox, so /bin/sh is in the image",
  },
  {
    subject: "interpreter",
    present: function () { return BASE_SUPPLIES.shell || BASE_SUPPLIES.nodePackageTools; },
    re: /\b(?:no|without(?: a| any)?)\s+interpreters?\b/i,
    why: "the runtime base carries a shell and the Node toolchain",
  },
  {
    subject: "package manager",
    present: function () { return BASE_SUPPLIES.nodePackageTools; },
    // Unqualified only. The true form is "no operating system package
    // manager", and the qualifier it carries is what keeps "no" from
    // sitting directly against "package", so it matches nothing here.
    re: /\b(?:no|without(?: a| any)?)\s+package\s+managers?\b/i,
    why: "npm is a package manager and the runtime base carries it; " +
      "the true claim names the operating system package manager it lacks",
  },
  {
    subject: "distroless base",
    present: function () { return BASE_SUPPLIES.shell || BASE_SUPPLIES.nodePackageTools; },
    re: /\bdistroless\b/i,
    why: "a base carrying busybox, npm and node-gyp is not distroless",
  },
];

// The port floor claim, in the shape that asserts the floor is what
// stops the bind. A conditional sentence, of the form "use these when
// the process cannot bind a privileged port", is correct guidance and
// matches nothing here: what this refuses is the assertion that the
// default floor blocks this image.
var FALSE_PORT_FLOOR_CLAIM = {
  re: /cannot bind[^.]{0,100}\b1024\b[^.]{0,80}(?:floor|sysctl|namespace)/i,
  why: "in a container's own network namespace the floor already reads 0, and the " +
    "image binds 25, 465, 587 and 143 as UID 65532 with every capability dropped " +
    "and no sysctl set",
};

// The host network case. It is where the floor is genuinely the host's
// own 1024, where the sysctl is refused rather than applied, and
// therefore where the per listener port variables are the only answer.
var HOST_NETWORK_RE = /(?:--network[= ]host|host network|network_mode:\s*['"]?host)/i;
var PORT_VARIABLE_RE = /BLAMEPOST_(?:MX|SUBMISSION|SMTPS|IMAP|POP3|MANAGESIEVE)_PORT/;
var SYSCTL_RE        = /ip_unprivileged_port_start/;

// Names an argument array may not carry if nothing the image runs is to
// go through a shell.
var SHELL_TOKENS = /(?:^|\/)(?:sh|bash|ash|dash|busybox)$/;

function read(rel) {
  return nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, rel), "utf8");
}

var count = helpers.count;

// Line numbers for every match, so a failure names the place to edit
// rather than only the file. Matching runs over the line with its own
// whitespace collapsed, because a claim that wraps across two lines is
// the same claim.
function matchingLines(text, re) {
  var lines = text.split(/\r?\n/);
  var found = [];
  for (var i = 0; i < lines.length; i++) {
    // Two lines at a time, because these documents wrap at column 80 and
    // a claim split across a wrap is the same claim. The single line is
    // tested as well so a match confined to one line still reports that
    // line rather than the pair it starts.
    var single = lines[i].replace(/\s+/g, " ");
    var pair   = (lines[i] + " " + (lines[i + 1] || "")).replace(/\s+/g, " ");
    if (re.test(single) || re.test(pair)) found.push(i + 1);
  }
  return found;
}

// ---- claims of absence ------------------------------------------------------

function noDocumentClaimsAnAbsenceTheBaseDoesNotHave() {
  CLAIM_SURFACES.forEach(function (rel) {
    var text = read(rel);
    FALSE_ABSENCE_CLAIMS.forEach(function (claim) {
      if (!claim.present()) return;
      var hits = matchingLines(text, claim.re);
      count("no claim in " + rel + " asserts the image has " + claim.subject +
        " absent, because " + claim.why,
        hits.length === 0, hits.length === 0 ? undefined : "lines " + hits.join(", "));
    });
  });
}

// Deleting a false half must not take the true half with it. What the
// image genuinely lacks is the operating system package manager, and
// that is the half an operator sizing a code execution defect can act
// on: nothing inside the container can fetch a toolchain. Removing the
// overstated sentence and leaving nothing in its place would be a
// quieter version of the same failure, so the qualified statement has to
// survive somewhere an operator reads.
function theHalfOfTheClaimThatHoldsIsStillStated() {
  count("the record says the base supplies no operating system package manager, " +
    "which is what makes the qualified claim below a true one",
    BASE_SUPPLIES.osPackageManager === false);

  var qualified = /\bno\s+(?:operating\s+system|os)\s+package\s+managers?\b/i;
  var stating = CLAIM_SURFACES.filter(function (rel) {
    return qualified.test(read(rel).replace(/\s+/g, " "));
  });
  count("at least one shipped document states the absence that does hold, so the " +
    "correction did not leave an operator with nothing to size the container by",
    stating.length > 0, stating.join(", ") || "no document states it");
}

function noDocumentClaimsTheFloorStopsTheBind() {
  CLAIM_SURFACES.forEach(function (rel) {
    var hits = matchingLines(read(rel), FALSE_PORT_FLOOR_CLAIM.re);
    count("no claim in " + rel + " asserts the unprivileged port floor stops this " +
      "image binding a mail port, because " + FALSE_PORT_FLOOR_CLAIM.why,
      hits.length === 0, hits.length === 0 ? undefined : "lines " + hits.join(", "));
  });
}

// The alternative has to be findable from the case that needs it. A
// document that offers per listener ports without naming host
// networking leaves the operator who actually needs them guessing, and
// that operator is the one for whom the sysctl in the quick start fails
// at run rather than at read.
function theSettingsReferenceNamesTheCaseThePortVariablesAnswer() {
  var text = read(SETTINGS_REFERENCE);
  count("the settings reference names the per listener port variables",
    PORT_VARIABLE_RE.test(text));
  count("the settings reference names the unprivileged port floor sysctl, so an " +
    "operator meets it where the ports are chosen rather than only in the image",
    SYSCTL_RE.test(text));
  count("the settings reference names host networking, which is the case where the " +
    "sysctl is refused and the per listener port variables are the only answer",
    HOST_NETWORK_RE.test(text));
}

// ---- the tag an operator can actually pull ----------------------------------

// The git tag and the image tag are not the same string, and a document
// that confuses them hands an operator a command that answers "manifest
// unknown". That failure is worst in a verification recipe, where the
// operator concludes something about the release rather than about the
// name they typed. The direction is read out of the publishing workflow
// rather than written down twice.
function everyImageReferenceNamesATagTheWorkflowPublishes() {
  var workflow = read(CONTAINER_WORKFLOW);
  var stripsThePrefix = /GITHUB_REF#refs\/tags\/v\}/.test(workflow);
  count("the publishing workflow derives the image tag by stripping the git tag's " +
    "leading v, so the image tag and the git tag differ by that character",
    stripsThePrefix, "read from " + CONTAINER_WORKFLOW);
  if (!stripsThePrefix) return;

  CLAIM_SURFACES.forEach(function (rel) {
    var text = read(rel);
    var found = [];
    var m;
    IMAGE_TAG_RE.lastIndex = 0;
    while ((m = IMAGE_TAG_RE.exec(text)) !== null) found.push(m[1]);
    found.forEach(function (tag) {
      count("the image reference in " + rel + " names a tag the workflow publishes, " +
        "rather than the git tag's v prefixed form which resolves to nothing",
        !/^v\d/.test(tag) && !/^vX/.test(tag), IMAGE_REPOSITORY + ":" + tag);
    });
  });
}

// ---- what the image is configured to run ------------------------------------

// The Dockerfile with its line continuations joined, so a HEALTHCHECK
// whose CMD sits on the next line is read as one instruction.
function imageInstructions() {
  var joined = read(IMAGE_DEFINITION).replace(/\\\r?\n\s*/g, " ");
  return joined.split(/\r?\n/).filter(function (line) {
    return /^\s*(?:CMD|ENTRYPOINT|HEALTHCHECK|SHELL)\b/i.test(line);
  }).map(function (line) { return line.trim(); });
}

// The argument list of an instruction, when it is written in the JSON
// exec form. A shell form has no brackets and returns null, which is
// the failure the caller reports.
function execArray(instruction) {
  var open = instruction.indexOf("[");
  if (open === -1) return null;
  try {
    var parsed = JSON.parse(instruction.slice(open));
    return Array.isArray(parsed) ? parsed : null;
  } catch (_e) { return null; }
}

function nothingTheImageIsConfiguredToRunGoesThroughAShell() {
  var instructions = imageInstructions();
  count("the image definition declares the instructions this check reads",
    instructions.length >= 2, instructions.length + " found");

  var sawCmd = false;
  var sawProbe = false;
  instructions.forEach(function (instruction) {
    var verb = instruction.split(/\s+/)[0].toUpperCase();
    count("the image definition sets no SHELL instruction, which would give the " +
      "shell form of every later instruction a shell to run in",
      verb !== "SHELL", instruction);
    if (verb === "SHELL") return;

    var args = execArray(instruction);
    count("the " + verb + " instruction is an argument array rather than a shell " +
      "string, so nothing it names is handed to a shell for word splitting",
      args !== null, instruction.slice(0, 120));
    if (args === null) return;

    // A HEALTHCHECK carries its own verb ahead of the array. `CMD` runs
    // the array as given; `CMD-SHELL` is the form that hands the string
    // to a shell, and it is the one this refuses.
    if (verb === "HEALTHCHECK") {
      var head = instruction.slice(0, instruction.indexOf("["));
      count("the health probe uses the CMD form rather than CMD-SHELL",
        /\bCMD\b/.test(head) && !/\bCMD-SHELL\b/i.test(head), head.slice(0, 160));
      sawProbe = true;
    }
    if (verb === "CMD") sawCmd = true;

    var named = args.filter(function (token) {
      return SHELL_TOKENS.test(String(token));
    });
    count("the " + verb + " instruction names no shell", named.length === 0,
      named.join(" "));
  });

  count("the image definition declares a default command", sawCmd);
  count("the image definition declares a health probe", sawProbe);

  // The compose stack overrides the probe, so its form is a second place
  // the same guarantee has to hold.
  var compose = read(COMPOSE_FILE);
  count("the compose stack's health probe uses the exec form",
    /^\s*-\s*CMD\s*$/m.test(compose));
  count("the compose stack invokes no shell form probe",
    compose.indexOf("CMD-SHELL") === -1);
}

// ---- the data directory mode ------------------------------------------------

// The mode the image ships the data directory at, read out of the
// instruction that sets it rather than out of a second copy of the
// number written down here.
function imageDataDirMode() {
  var text = read(IMAGE_DEFINITION);
  var m = text.match(/chmodSync\(\s*'\/var\/lib\/blamepost'\s*,\s*0o([0-7]+)\s*\)/);
  return m === null ? null : parseInt(m[1], 8);
}

// The threshold the boot assertion enforces, taken from the primitive
// that enforces it. The check is POSIX only, so on Windows there is no
// refusal to read and the caller records a skip rather than a pass.
async function enforcedDataDirMode() {
  if (process.platform === "win32") return null;
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "docs-posture-"));
  try {
    nodeFs.chmodSync(dir, 0o777);
    try {
      await helpers.b.security.assertProduction({
        vault: false, dbAtRest: false, auditSigning: false, ntpStrict: false,
        minNodeMajor: false, minTlsVersion: false, forbidNodeEnv: false,
        audit: false, dataDir: dir,
      });
      return { refused: false };
    } catch (err) {
      var failures = (err && err.failures) || [];
      var row = failures.filter(function (f) {
        return f.code === "security/datadir-permissions";
      })[0];
      if (!row) return { refused: false };
      var m = row.message.match(/requires <= 0([0-7]+)/);
      return { refused: true, mode: m === null ? null : parseInt(m[1], 8), row: row };
    }
  } finally {
    try { nodeFs.rmSync(dir, { recursive: true, force: true }); }
    catch (_e) { /* drop-silent by design: the verdict above is the result */ }
  }
}

async function theDataDirectoryModeIsDocumentedAtTheNumberBootEnforces() {
  var guide = read(SETTINGS_REFERENCE);
  var shipped = imageDataDirMode();

  count("the image sets the data directory mode explicitly",
    shipped !== null, String(shipped));
  count("the settings reference tells an operator what mode a bind mounted data " +
    "directory needs, because the boot assertion refuses a looser one and exits " +
    "before binding a listener",
    /\b0750\b/.test(guide));
  count("the settings reference prints the fix the refusal itself prints",
    /chmod\s+750\b/.test(guide));
  count("the mode the settings reference names is the mode the image ships",
    shipped === 0o750, "image 0" + (shipped === null ? "?" : shipped.toString(8)));

  var enforced = await enforcedDataDirMode();
  if (enforced === null) {
    skip("the data directory mode assertion reads a POSIX file mode and is skipped " +
      "on this platform, so the enforced threshold could not be measured here");
    return;
  }
  count("a data directory looser than the documented mode is refused at boot",
    enforced.refused === true);
  count("the threshold the boot assertion enforces is the number the settings " +
    "reference prints",
    enforced.mode === 0o750,
    "enforced 0" + (enforced.mode === null ? "?" : enforced.mode.toString(8)));
}

// The stop grace the compose stack gives the container, against the two
// constants the shutdown actually spends. `bin/blamepost.js` drains for
// one and then force-exits after the other, so a grace under their sum
// severs the drain: sessions are cut mid-command and the queue can stop
// between the body it wrote and the descriptor that names it. The
// runtime's own default is ten seconds, under the sum, so an unset value
// ships the case the shutdown code and SECURITY.md both warn about.
//
// Read from the source rather than restated, because the number in
// compose.yml is a third copy of a fact two constants already hold, and
// this repository has found more of that shape than any other.
function theStopGraceOutlastsTheShutdownItHasToCover() {
  var cli     = read("bin/blamepost.js");
  var compose = read(COMPOSE_FILE);

  var seconds = function (name) {
    var found = new RegExp("var\\s+" + name + "\\s*=\\s*TIME\\.seconds\\((\\d{1,4})\\)").exec(cli);
    return found ? Number(found[1]) : null;
  };
  var grace  = seconds("SHUTDOWN_GRACE_MS");
  var margin = seconds("SHUTDOWN_FORCE_MARGIN_MS");

  count("the shutdown constants are still readable, so this compares numbers " +
    "rather than passing over a rename",
    grace !== null && margin !== null, "grace " + grace + "s, margin " + margin + "s");
  if (grace === null || margin === null) return;

  var declared = /stop_grace_period:\s*(\d{1,5})s/.exec(compose);
  count("the compose stack names a stop grace rather than inheriting the " +
    "runtime default, which is shorter than this server's own shutdown",
    declared !== null, declared ? declared[1] + "s" : "unset");
  if (declared === null) return;

  count("and the grace it names outlasts the drain and the force margin " +
    "together, so a stop is a shutdown rather than a kill",
    Number(declared[1]) > grace + margin,
    declared[1] + "s against " + grace + " + " + margin + " = " + (grace + margin) + "s");
}

// ---- runner -----------------------------------------------------------------

async function run() {
  theStopGraceOutlastsTheShutdownItHasToCover();
  noDocumentClaimsAnAbsenceTheBaseDoesNotHave();
  theHalfOfTheClaimThatHoldsIsStillStated();
  noDocumentClaimsTheFloorStopsTheBind();
  theSettingsReferenceNamesTheCaseThePortVariablesAnswer();
  everyImageReferenceNamesATagTheWorkflowPublishes();
  nothingTheImageIsConfiguredToRunGoesThroughAShell();
  await theDataDirectoryModeIsDocumentedAtTheNumberBootEnforces();
  return helpers.getChecks();
}

module.exports = {
  name: "docs-container-posture",
  run: run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
