// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Names read off the data volume, on their way to an operator's
 * terminal.
 *
 * Two of this server's reporting verbs answer by walking a directory and
 * printing what they found there. `blobs report` names every file under
 * `blobs/` that is not a sealed body at the path its own digest gives,
 * and `doctor` names every file in the key directory that no selector
 * record claims. Both lists exist precisely because the file is one
 * nothing on this server put there under a name nothing on this server
 * chose, so the name is not a value this server validated on the way in.
 *
 * A terminal acts on what it is handed. U+009B is the control sequence
 * introducer, so a file whose name carries it followed by `2K` erases the
 * line it is printed on, and the operator reads a report with a finding
 * missing from it. The report that hides a line is the report written to
 * say what is wrong with the volume.
 *
 * `blamepost.text.forDisplay` is the one screen between text somebody
 * else wrote and a person reading it, and these two verbs reach the
 * operator without it. Both are driven here through the shipped binary,
 * against a real data directory, with the code point planted in a file
 * name on disk.
 *
 * What is asserted is that the code point does not reach either stream,
 * and that the finding is still reported: a screen that dropped the line
 * would satisfy the first half and hide the same fault the raw byte
 * hides.
 *
 * Planting the name needs write access to the data volume, which is a
 * higher reach than the outage it produces. It is still the shape this
 * server screens everywhere else it prints a name somebody else chose,
 * and the volume is writable by more than this process: a restore puts
 * back whatever a bundle carried, and an operator's own recovery work
 * leaves files behind.
 *
 * The code point is built from its number rather than written, because a
 * raw C1 octet does not survive an editor or a file read intact.
 *
 * Every case runs even when an earlier one fails, and the failures are
 * reported together.
 *
 * Run standalone: node test/layer-1-state/volume-name-display-screen.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var bundles = require("../helpers/bundle");
var quiet   = require("../helpers/dns-quiet");

var count = helpers.count;

// The control sequence introducer, and the two characters that make it
// erase the line. The framework's own control-character table stops
// below this code point, which is why a value carrying it reaches a
// terminal at all.
var CSI = String.fromCharCode(0x9b);
var ERASE_LINE = CSI + "2K";

// A name a terminal acts on, with a readable part either side so a
// report that printed the screened form can still be found in the
// transcript.
function plantedName(stem) {
  return stem + ERASE_LINE + "repainted";
}

// Whether a transcript carries any code point in the C1 range. The
// screen replaces them, so the answer on a screened stream is false
// whatever else the line says.
function carriesC1(text) {
  for (var i = 0; i < text.length; i += 1) {
    var code = text.charCodeAt(i);
    if (code >= 0x0080 && code <= 0x009f) return true;
  }
  return false;
}

// ---- cases ------------------------------------------------------------------

async function aBlobNameIsScreenedBeforeItReachesTheTerminal(ctx) {
  var name = plantedName("not-a-blob");
  var fanOut = nodePath.join(ctx.vol.dataDir, "blobs", "aa", "bb");
  nodeFs.mkdirSync(fanOut, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(fanOut, name), "not a sealed body\n");

  var run = ctx.cli(["blobs", "report"]);
  count("`blobs report` reports a file under blobs/ that is not a body", run.status === 1,
    "exit " + run.status + " " + run.both.slice(0, 400));
  count("and names it", run.both.indexOf("not-a-blob") !== -1, run.both.slice(0, 900));
  count("and no control sequence introducer reaches the operator",
    !carriesC1(run.both), JSON.stringify(run.both.slice(0, 900)));
  count("and the report still counts it as something to decide about",
    run.both.indexOf("Nothing removes it") !== -1, run.both.slice(0, 900));
}

async function aKeyFileNameIsScreenedBeforeItReachesTheTerminal(ctx) {
  var name = plantedName("no-selector-names-this");
  var keyDir = nodePath.join(ctx.vol.dataDir, "keys");
  nodeFs.mkdirSync(keyDir, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(keyDir, name), "not a sealed key\n");

  var run = ctx.doctor(["doctor"]);
  count("`doctor` names a key file no selector record claims",
    run.both.indexOf("no-selector-names-this") !== -1, run.both.slice(0, 1200));
  count("and no control sequence introducer reaches the operator",
    !carriesC1(run.both), JSON.stringify(run.both.slice(0, 1200)));
  count("and the finding still says what to do with it",
    run.both.indexOf("Delete them from") !== -1, run.both.slice(0, 1200));
}

// A message body in the spool that no descriptor names. `queue list`
// prints these ids rather than counting them, because clearing one takes
// an id, and the id is the file's own name with its suffix removed. So
// the name a stranded body was written under reaches the terminal, and
// this is the listing an operator is reading when the queue looks empty
// and mail is being refused anyway.
async function aStrandedBodyNameIsScreenedBeforeItReachesTheTerminal(ctx) {
  var name = plantedName("stranded-body");
  var spoolDir = nodePath.join(ctx.vol.dataDir, "queue");
  nodeFs.mkdirSync(spoolDir, { recursive: true });
  var planted = nodePath.join(spoolDir, name + ".eml");
  nodeFs.writeFileSync(planted, "From: a@example.net\r\n\r\nbody\r\n");

  // Inside the settle window a body without a descriptor is a message
  // arriving normally, and the listing says nothing about it. Age it past
  // the window so it is reported as stranded.
  var old = Date.now() - (30 * 60 * 1000);
  nodeFs.utimesSync(planted, new Date(old), new Date(old));

  var run = ctx.cli(["queue", "list"]);
  count("`queue list` names a message body no descriptor accounts for",
    run.both.indexOf("stranded-body") !== -1, run.both.slice(0, 1200));
  count("and no control sequence introducer reaches the operator",
    !carriesC1(run.both), JSON.stringify(run.both.slice(0, 1200)));
  count("and the listing still says how to clear it",
    run.both.indexOf("queue remove") !== -1, run.both.slice(0, 1200));
}

// ---- runner -----------------------------------------------------------------

var CASES = [
  aBlobNameIsScreenedBeforeItReachesTheTerminal,
  aKeyFileNameIsScreenedBeforeItReachesTheTerminal,
  aStrandedBodyNameIsScreenedBeforeItReachesTheTerminal,
];

async function run() {
  var vol = bundles.volume("volume-name-display-screen");
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  try {
    process.env.BLAMEJS_TMPDIR = vol.workDir;
    var cfg = bundles.configFor(vol);
    var cli = bundles.cliFor(vol);
    await bundles.addAccount(cfg, "alice");

    // `doctor` resolves records. Pointed at an address nothing answers
    // on, every lookup fails fast and the local checks this file is about
    // are reported all the same.
    if (!(await quiet.endpointIsRefusing())) {
      helpers.skip("something is listening on " + quiet.HOST + ":" + quiet.PORT +
        ", so a quiet resolver cannot be arranged");
      return helpers.getChecks();
    }
    var armed = {};
    armed[quiet.ARMED_VAR] = "1";
    var doctor = bundles.cliFor(vol, {
      env:      armed,
      execArgv: ["--require", quiet.PRELOAD],
    });

    var ctx = { vol: vol, cfg: cfg, cli: cli, doctor: doctor };
    var failures = [];
    for (var i = 0; i < CASES.length; i += 1) {
      try {
        await CASES[i](ctx);
      } catch (e) {
        failures.push(CASES[i].name + ": " + ((e && e.message) || String(e)));
      }
    }
    if (failures.length > 0) {
      throw new Error(failures.length + " of " + CASES.length + " case(s) failed:\n  " +
        failures.join("\n  "));
    }
    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(vol.root);
  }
}

module.exports = {
  name:      "volume-name-display-screen",
  run:       run,
  getChecks: helpers.getChecks,
};

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
