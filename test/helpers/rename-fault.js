// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A command-line run whose data directory behaves like a mounted volume,
 * or that is killed partway through putting files into it.
 *
 * Loaded into the spawned binary with `--require`, like
 * `helpers/audit-sink-fault.js`, because the behavior under test belongs
 * to that process. It patches `fs.renameSync`, the call every directory
 * swap and every atomic write ends in, which is the same seam
 * `helpers.installWriteFault` uses in-process.
 *
 * Two modes, chosen by the value of the armed variable.
 *
 * `mount` reproduces what Linux does when the data directory is a volume
 * mount point, as it is in the shipped container. Renaming the directory
 * itself fails with EBUSY, and renaming anything between a path inside
 * it and a path outside it fails with EXDEV, because the two are on
 * different filesystems. Both answers were measured in a container with a
 * named volume at `/var/lib/blamepost`.
 *
 * `interrupt` kills the process with SIGKILL on the first rename that
 * puts an entry into the data directory from somewhere else, or that
 * replaces the data directory as a whole. That is the moment a swap has
 * taken the old files out and has not finished putting the new ones in.
 *
 * `interrupt-second` does the same on the second such rename, so one
 * entry has already been put into the data directory when the process
 * stops.
 *
 * Nothing under `lib/` or `bin/` reads these variables.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var ARMED_VAR  = "BLAMEPOST_RENAME_FAULT";
var VOLUME_VAR = "BLAMEPOST_RENAME_FAULT_VOLUME";

var MODES = ["mount", "interrupt", "interrupt-second"];

function _inside(volume, candidate) {
  return candidate === volume || candidate.indexOf(volume + nodePath.sep) === 0;
}

function _refusal(code, message) {
  var e = new Error(code + ": " + message);
  e.code = code;
  return e;
}

var mode = process.env[ARMED_VAR];
if (MODES.indexOf(mode) !== -1) {
  var volume = nodePath.resolve(String(process.env[VOLUME_VAR] || ""));
  var real = nodeFs.renameSync;
  var intoVolume = 0;
  nodeFs.renameSync = function (from, to) {
    var source = nodePath.resolve(String(from));
    var target = nodePath.resolve(String(to));
    if (mode === "mount") {
      if (source === volume || target === volume) {
        throw _refusal("EBUSY", "resource busy or locked, rename '" + source + "' -> '" + target + "'");
      }
      if (_inside(volume, source) !== _inside(volume, target)) {
        throw _refusal("EXDEV", "cross-device link not permitted, rename '" + source + "' -> '" +
          target + "'");
      }
    } else if (target === volume ||
        (nodePath.dirname(target) === volume && nodePath.dirname(source) !== volume)) {
      intoVolume += 1;
      if (mode === "interrupt" || intoVolume >= 2) process.kill(process.pid, "SIGKILL");
    }
    return real.apply(nodeFs, arguments);
  };
}

module.exports = {
  PRELOAD:    __filename,
  ARMED_VAR:  ARMED_VAR,
  VOLUME_VAR: VOLUME_VAR,
};
