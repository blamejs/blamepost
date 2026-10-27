// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/listening-owners.js
 *
 * Which process on this machine holds a listening TCP port.
 *
 * WHY THIS EXISTS. A greeting says which SOFTWARE answered. It cannot say
 * which PROCESS did, and on a developer machine those are different
 * questions with different answers. Measured on this one: a blamepost left
 * running from an earlier week held 25, 143, 465, 587 and 4190, answered
 * every greeting perfectly, and reported the same version string as the tree
 * under test, because the version had not been bumped between them. A gate
 * reading greetings alone reported five endpoints answering as this server
 * and every word of that was true about the machine and none of it was about
 * the build anybody was testing.
 *
 * So the port has to be attributed to a process, and nothing in Node exposes
 * that. The operating system's own listening-socket table does, through a
 * tool that ships with the system, and this file is the one reader of it.
 *
 * WHAT IT REFUSES TO GUESS. An address family and a bind address are not the
 * unit here: a listener on 0.0.0.0 answers a probe to 127.0.0.1, and on
 * Windows one process routinely holds the same port on both families. So the
 * table is keyed by PORT and carries every distinct pid seen listening on it.
 * More than one pid on a port is reported as more than one rather than
 * resolved by picking, because that is a machine state a caller has to see.
 *
 * WHAT IT CANNOT SEE. A port on another host, and a port a forwarder holds on
 * this host on behalf of a process somewhere else, which is what a published
 * container port looks like from outside the container. In the first case
 * there is no row at all; in the second the row names the forwarder. Neither
 * is a fault here, and both are things the caller has to decide about rather
 * than have decided for it, so the answer carries what was read and the
 * caller carries the policy.
 *
 * PARSERS ARE SEPARATE FROM THE SPAWN, and exported, because a parser is the
 * part that rots: a tool's output differs by version, by platform and by the
 * locale it was invoked under, and a parser that quietly matches nothing
 * returns an empty table that reads exactly like a machine with nothing
 * listening on it. They are driven directly by
 * test/layer-0-primitives/listening-owners.test.js over captured output, so
 * the shape each one accepts is pinned without a socket.
 *
 * Validation posture: config-time. A caller passing something other than
 * text gets a TypeError rather than an empty table.
 */

var execFile = require("node:child_process").execFile;

// How long the system's own tool gets. It reads a kernel table; a machine
// where this does not answer in seconds is one where the answer would be
// stale anyway.
var TOOL_TIMEOUT_MS = 8000;

// Output ceiling. A busy host has thousands of sockets and the table is
// still small; this is a bound on a runaway rather than a real limit.
var TOOL_BUFFER = 8 * 1024 * 1024;

function _requireText(text, who) {
  if (typeof text !== "string") {
    throw new TypeError(who + ": expected the tool's output as text, got " + typeof text);
  }
  return text;
}

// The port out of a local-address field, in every shape the tools write one:
// "0.0.0.0:25", "[::]:25", "*:25", "[::1]:8080", "127.0.0.1:8080".
function _port(address) {
  var at = String(address).lastIndexOf(":");
  if (at === -1) return null;
  var n = Number(String(address).slice(at + 1));
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : 0;
}

function _add(byPort, port, pid) {
  if (!port || !pid) return;
  if (!Object.prototype.hasOwnProperty.call(byPort, port)) byPort[port] = [];
  if (byPort[port].indexOf(pid) === -1) byPort[port].push(pid);
}

/**
 * @primitive scripts.listeningOwners.parseNetstat
 * @signature parseNetstat(text) -> { "<port>": [ pid, ... ] }
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: a listening row is one whose FOREIGN port is zero)
 *
 * Windows `netstat -ano`.
 *
 * The state word is NOT what selects a row, and that is deliberate: it is
 * translated, so a matcher looking for "LISTENING" reads an empty table on
 * every machine whose Windows is not running in English and reports it as a
 * machine with nothing listening. A listening socket is the one with no peer,
 * which the foreign address writes as port zero in every locale.
 *
 * The protocol filter is not passed either. Measured here: `-p TCP` returns
 * 1035 rows and the bare command returns 1093, and the 58 it leaves out are
 * the IPv6 listeners, which Windows files under `TCPv6` while still writing
 * `TCP` in the protocol column. A gate probing ::1 would find the port held
 * by nobody and refuse a healthy server. UDP rows carry no state column and
 * so cannot satisfy the five fields this reads.
 */
function parseNetstat(text) {
  _requireText(text, "parseNetstat");
  var byPort = {};
  var re = /^[ \t]*TCP[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\d+)[ \t]*$/gm;
  var m;
  while ((m = re.exec(text)) !== null) {
    if (_port(m[2]) !== 0) continue;
    _add(byPort, _port(m[1]), Number(m[4]));
  }
  return byPort;
}

/**
 * @primitive scripts.listeningOwners.parseSs
 * @signature parseSs(text) -> { "<port>": [ pid, ... ] }
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the process column is optional and its absence is not a pid of zero)
 *
 * Linux `ss -H -l -t -n -p`.
 *
 * A row whose socket belongs to another user carries no process column, and
 * that row contributes nothing rather than contributing a port with no owner:
 * the caller's question is which process holds the port, and "a row exists"
 * is the answer that started this whole class of fault.
 */
function parseSs(text) {
  _requireText(text, "parseSs");
  var byPort = {};
  String(text).split(/\r?\n/).forEach(function (line) {
    if (line.trim().length === 0) return;
    var fields = line.trim().split(/\s+/);
    // State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, [Process]
    if (fields.length < 5 || fields[0] !== "LISTEN") return;
    var port = _port(fields[3]);
    var pids = line.match(/pid=(\d+)/g) || [];
    pids.forEach(function (token) { _add(byPort, port, Number(token.slice(4))); });
  });
  return byPort;
}

/**
 * @primitive scripts.listeningOwners.parseLsof
 * @signature parseLsof(text) -> { "<port>": [ pid, ... ] }
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the field format is a stream, and a name belongs to the pid above it)
 *
 * `lsof -nP -iTCP -sTCP:LISTEN -F pn`, which is the fallback for a machine
 * with no `ss` and the ordinary answer on macOS.
 *
 * The field format writes one record per line, `p` for a process and `n` for
 * a name under it, so a name line belongs to the last `p` seen. A name with
 * no `p` above it is dropped rather than attributed to whatever came before
 * the parse started.
 */
function parseLsof(text) {
  _requireText(text, "parseLsof");
  var byPort = {};
  var pid = null;
  String(text).split(/\r?\n/).forEach(function (line) {
    if (line.charAt(0) === "p") {
      var n = Number(line.slice(1));
      pid = Number.isInteger(n) && n > 0 ? n : null;
      return;
    }
    if (line.charAt(0) !== "n" || pid === null) return;
    // "n*:8080", "n127.0.0.1:8080", "n[::1]:8080"
    _add(byPort, _port(line.slice(1)), pid);
  });
  return byPort;
}

// The tools this file knows, in the order it tries them per platform. Each
// carries its own parser, so a tool answering in another tool's shape is a
// parse that finds nothing rather than a table built out of the wrong
// columns.
var TOOLS = Object.freeze({
  win32: Object.freeze([
    { bin: "netstat", args: ["-ano"], parse: parseNetstat },
  ]),
  posix: Object.freeze([
    { bin: "ss",   args: ["-H", "-l", "-t", "-n", "-p"],                 parse: parseSs },
    { bin: "lsof", args: ["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pn"],   parse: parseLsof },
  ]),
});

function _run(tool) {
  return new Promise(function (resolve) {
    execFile(tool.bin, tool.args, {
      timeout:    TOOL_TIMEOUT_MS,
      maxBuffer:  TOOL_BUFFER,
      windowsHide: true,
      // The tools are read for their columns, and a translated column heading
      // is still a column. What must not vary is the number formatting, so the
      // child is asked for the invariant locale.
      env:        Object.assign({}, process.env, { LC_ALL: "C", LANG: "C" }),
    }, function (err, stdout, stderr) {
      // `ss` and `lsof` exit non-zero when they could not read every socket
      // and still print the ones they could, so the output is parsed whatever
      // the code was and emptiness is the failure rather than the code.
      var text = String(stdout || "") + (err && !stdout ? String(stderr || "") : "");
      resolve({ text: text, err: err || null });
    });
  });
}

/**
 * @primitive scripts.listeningOwners.owners
 * @signature owners() -> Promise<{ ok, byPort, source, reason }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: an empty table is a failure to read, never a machine with nothing on it)
 *
 * The listening TCP ports on this machine and the processes holding them.
 *
 * `ok` false carries `reason`, a sentence naming the tools that were tried.
 * An EMPTY table is one of those failures and not an answer: this runs on a
 * machine whose ports the caller has just been talking to, so a table with
 * nothing in it is a tool that is missing, refused, or writing a shape this
 * file does not read. Returning it as a clean empty answer is the exact
 * defect this file was written against.
 */
async function owners() {
  var list = process.platform === "win32" ? TOOLS.win32 : TOOLS.posix;
  var tried = [];
  for (var i = 0; i < list.length; i += 1) {
    var tool = list[i];
    var rv = await _run(tool);
    var byPort;
    try { byPort = tool.parse(rv.text); }
    catch (e) { tried.push(tool.bin + ": " + ((e && e.message) || e)); continue; }
    if (Object.keys(byPort).length > 0) {
      return { ok: true, byPort: byPort, source: tool.bin, reason: null };
    }
    tried.push(tool.bin + ": " +
      (rv.err ? ((rv.err.code === "ENOENT" ? "not on this machine" : (rv.err.message || String(rv.err))))
              : "ran and named no listening socket"));
  }
  return {
    ok:     false,
    byPort: {},
    source: null,
    reason: "no tool on this machine could say which process holds a listening port (" +
            tried.join("; ") + ")",
  };
}

module.exports = {
  TOOL_TIMEOUT_MS: TOOL_TIMEOUT_MS,
  parseNetstat:    parseNetstat,
  parseSs:         parseSs,
  parseLsof:       parseLsof,
  owners:          owners,
};
