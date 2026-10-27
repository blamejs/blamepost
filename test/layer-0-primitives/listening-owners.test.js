// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * listening-owners: the reader that says which process holds a port.
 *
 * `scripts/check-services.js` decides whether the stack the interop suite
 * is about to run against is up. A greeting tells it which software
 * answered and a version tells it which build, and neither separates two
 * processes running the same build, which is the ordinary state of a
 * machine where a server from an earlier session is still holding the
 * mail ports. `scripts/listening-owners.js` is what closes that, by
 * reading the operating system's own listening-socket table.
 *
 * ## Why the parsers are tested and not the spawn
 *
 * The spawn either finds the tool or does not, and the gate above says
 * which. The PARSER is the part that fails silently: a tool's output
 * differs by version, by platform and by the locale it ran under, and a
 * regex that stops matching returns an empty table that reads exactly
 * like a machine with nothing listening on it. That is the same shape as
 * the fault this whole mechanism was written for, one level down.
 *
 * So each parser is driven over output CAPTURED from the tool rather
 * than written to suit the regex. The Linux captures were taken from
 * `ss` and `lsof` inside an alpine container with listeners bound on
 * IPv4, on IPv6 and dual-stack; the Windows capture is from `netstat`
 * on the machine this runs on. A fixture invented to match the pattern
 * would prove the pattern matches itself.
 *
 * ## What each case is for
 *
 * A parser has to find the rows, attribute them to the right process,
 * and REFUSE the rows that are not listeners. The last one is what stops
 * the table filling with established connections whose local port
 * happens to be one the gate probes, which would attribute a port to
 * whichever client last connected to it.
 *
 * No sockets, no disk, no child process.
 *
 * Run standalone: node test/layer-0-primitives/listening-owners.test.js
 */

var helpers = require("../helpers");
var owners  = require("../../scripts/listening-owners");

var count = helpers.count;

// ---------------------------------------------------------------------------
// Captured output
// ---------------------------------------------------------------------------

// Windows `netstat -ano`, as it prints on the machine this suite runs on.
// The IPv6 rows carry `TCP` in the protocol column while living under
// TCPv6, the UDP rows carry no state column at all, and the established
// row is the one that must not be read as a listener.
var NETSTAT = [
  "",
  "Active Connections",
  "",
  "  Proto  Local Address          Foreign Address        State           PID",
  "  TCP    0.0.0.0:25             0.0.0.0:0              LISTENING       59888",
  "  TCP    0.0.0.0:143            0.0.0.0:0              LISTENING       59888",
  "  TCP    0.0.0.0:4190           0.0.0.0:0              LISTENING       59888",
  "  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       41424",
  "  TCP    127.0.0.1:6327         127.0.0.1:51400        ESTABLISHED     37540",
  "  TCP    [::]:22                [::]:0                 LISTENING       5016",
  "  TCP    [::1]:8080             [::]:0                 LISTENING       41424",
  "  UDP    0.0.0.0:53             *:*                                    2888",
  "",
].join("\r\n");

// Linux `ss -H -l -t -n -p`, captured in a container with a dual-stack
// listener, an IPv6 loopback listener and an IPv4 loopback listener. The
// column widths are the tool's own, which is why the parser splits on
// runs of whitespace rather than on fixed offsets.
var SS = [
  "LISTEN 0      1      *:18443 *:* users:((\"python3\",pid=13,fd=3))",
  "LISTEN 0      1      *:12025 *:* users:((\"nc\",pid=15,fd=3))     ",
  "LISTEN 0      1      127.0.0.1:18080 0.0.0.0:* users:((\"python3\",pid=13,fd=4))",
  "LISTEN 0      1          [::1]:18443    [::]:* users:((\"python3\",pid=13,fd=3))",
  "",
].join("\n");

// The same command on a machine where the sockets belong to another
// user: `ss` prints the row and omits the process column entirely.
var SS_NO_PROCESS_COLUMN = [
  "LISTEN 0      4096   0.0.0.0:25 0.0.0.0:*",
  "LISTEN 0      4096   0.0.0.0:143 0.0.0.0:*",
  "",
].join("\n");

// `lsof -nP -iTCP -sTCP:LISTEN -F pn`, captured beside the ss output
// above. One process holding two ports writes one `p` line and two `n`
// lines under it.
var LSOF = [
  "p13",
  "n[::1]:18443",
  "n127.0.0.1:18080",
  "p15",
  "n*:12025",
  "",
].join("\n");

function _pids(table, port) {
  var held = Object.prototype.hasOwnProperty.call(table, port) ? table[port] : [];
  return held.slice().sort(function (a, b) { return a - b; }).join(",");
}

// ---------------------------------------------------------------------------
// The parsers
// ---------------------------------------------------------------------------

function theWindowsTableIsRead() {
  var table = owners.parseNetstat(NETSTAT);

  // Canary first. A parser that matched nothing would satisfy every
  // refusal below and would leave the gate unable to attribute any row,
  // which is the failure this file exists to catch rather than to
  // introduce.
  count("netstat: the listening rows are found at all",
    Object.keys(table).length === 5, Object.keys(table).sort().join(", "));

  count("netstat: a mail port is attributed to the process holding it",
    _pids(table, 25) === "59888", _pids(table, 25));
  count("netstat: a row bound to loopback is read the same way",
    _pids(table, 8080) === "41424", _pids(table, 8080));
  count("netstat: an IPv6 row is read, and not left to a protocol filter to drop",
    _pids(table, 22) === "5016", _pids(table, 22));

  // The two families of one process on one port collapse to one pid
  // rather than reading as two processes disagreeing about the port,
  // which the gate refuses.
  count("netstat: both address families of one process are one owner",
    table[8080].length === 1, JSON.stringify(table[8080]));

  // An established connection's LOCAL port is a port something is using
  // and not a port something is listening on. Reading it as a listener
  // would attribute a probed port to whichever client last connected.
  count("netstat: an established connection is not a listener",
    Object.prototype.hasOwnProperty.call(table, 6327) === false,
    Object.keys(table).sort().join(", "));
  count("netstat: a UDP row is not a TCP listener",
    Object.prototype.hasOwnProperty.call(table, 53) === false,
    Object.keys(table).sort().join(", "));
}

function theLinuxTableIsRead() {
  var table = owners.parseSs(SS);

  count("ss: the listening rows are found at all",
    Object.keys(table).length === 3, Object.keys(table).sort().join(", "));
  count("ss: a dual-stack row is attributed to its process",
    _pids(table, 12025) === "15", _pids(table, 12025));
  count("ss: two rows of one process on one port are one owner",
    _pids(table, 18443) === "13", _pids(table, 18443));
  count("ss: a bracketed IPv6 local address is read",
    _pids(table, 18080) === "13", _pids(table, 18080));

  // A row with no process column is a socket this run cannot attribute.
  // Recording the port with no owner would put it in the table as
  // something that was read, and the caller's question is which process
  // holds it.
  var blind = owners.parseSs(SS_NO_PROCESS_COLUMN);
  count("ss: a row with no process column contributes no owner",
    Object.keys(blind).length === 0, JSON.stringify(blind));
}

function theFallbackTableIsRead() {
  var table = owners.parseLsof(LSOF);

  count("lsof: the listening rows are found at all",
    Object.keys(table).length === 3, Object.keys(table).sort().join(", "));
  count("lsof: a name line is attributed to the process line above it",
    _pids(table, 18443) === "13" && _pids(table, 18080) === "13",
    _pids(table, 18443) + " / " + _pids(table, 18080));
  count("lsof: the next process line takes over",
    _pids(table, 12025) === "15", _pids(table, 12025));

  // A stream that begins with a name has no process to attribute it to,
  // and the honest answer is nothing rather than the last pid from
  // whatever the caller parsed before.
  var orphaned = owners.parseLsof("n*:12025\nn*:18080\n");
  count("lsof: a name with no process above it is not attributed",
    Object.keys(orphaned).length === 0, JSON.stringify(orphaned));
}

// A parser handed the wrong tool's output has to come back empty rather
// than build a table out of whatever the columns happened to line up as.
// Empty is what the caller reads as "this tool did not answer", and it
// then tries the next one or refuses the run.
function aParserHandedAnotherToolsOutputFindsNothing() {
  count("cross: the Windows parser does not read ss output",
    Object.keys(owners.parseNetstat(SS)).length === 0, "");
  count("cross: the Linux parser does not read netstat output",
    Object.keys(owners.parseSs(NETSTAT)).length === 0, "");
  count("cross: the fallback parser does not read ss output",
    Object.keys(owners.parseLsof(SS)).length === 0, "");
}

// Entry points a caller uses directly, so bad input is refused rather
// than degrading to an empty table, which here means "the tool said
// nothing" and would be the wrong answer entirely.
function badInputThrows() {
  ["parseNetstat", "parseSs", "parseLsof"].forEach(function (name) {
    var threw = false;
    try { owners[name](null); } catch (e) { threw = e instanceof TypeError; }
    count("input: " + name + " refuses a non-string", threw, name);
  });
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  theWindowsTableIsRead();
  theLinuxTableIsRead();
  theFallbackTableIsRead();
  aParserHandedAnotherToolsOutputFindsNothing();
  badInputThrows();

  // The whole reader, on this machine, through whichever tool it has.
  // The parsers above prove the shapes; this proves one of them is
  // actually reached here, which is the difference between a checker
  // that fires and a checker that ran.
  var live = await owners.owners();
  count("live: this machine's socket table can be read",
    live.ok === true, live.ok ? live.source + ", " + Object.keys(live.byPort).length + " port(s)"
      : String(live.reason));
  count("live: and it names the tool it read",
    live.ok === true && typeof live.source === "string" && live.source.length > 0,
    String(live.source));

  return helpers.getChecks();
}

module.exports = { name: "listening-owners", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
