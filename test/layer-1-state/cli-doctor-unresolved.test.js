// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost doctor` prints when the resolver goes quiet.
 *
 * The posture check answers three things about a record rather than two:
 * whether it matches, and whether anything was learned about it at all. A
 * lookup that did not complete produces a finding that deliberately
 * carries no expected value and no found value, because this server saw
 * neither.
 *
 * The report an operator reads had two marks for those three answers, so
 * a record nobody could read printed as a FAIL. That is the wrong
 * instruction, and it is wrong in the expensive direction: it sends an
 * operator to edit records that may well be published and correct, and
 * the report they stop trusting is the one that would have caught the
 * next real fault. A resolver that has stopped answering is fixed by
 * looking at the resolver.
 *
 * So the mark and the closing summary are measured here, against a run
 * whose lookups all fail. Every DNS row must carry the mark that means
 * nothing was learned, none may carry a failure mark, and the summary has
 * to count records that could not be checked apart from checks that were
 * made and disagreed. An operator with some of each has two different
 * jobs and needs to know how much of each they have.
 *
 * The fault is the shipped DoH transport pointed at an address nothing
 * answers on, loaded into the spawned process ahead of the binary. No
 * handle is replaced and the resolver is the one the server builds for
 * itself. `test/helpers/dns-quiet.js` holds it.
 *
 * Run standalone: node test/layer-1-state/cli-doctor-unresolved.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var quiet     = require("../helpers/dns-quiet");
var blamepost = require("../../lib");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The marks the report uses, read from the report rather than described,
// so a row is classified the way an operator's eye classifies it.
var PASS_MARK       = "  ok    ";
var FAIL_MARK       = "  FAIL  ";
var NOTE_MARK       = "  note  ";
var UNRESOLVED_MARK = "  ?     ";

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// Whether the address the fault points at is genuinely closed. A machine
// with something listening there would be measuring a different failure,
// and reporting that as a pass is what `skip` exists to prevent.
function portIsClosed(host, port) {
  return new Promise(function (resolve) {
    var socket = nodeNet.connect({ host: host, port: port });
    var settled = false;
    function done(closed) {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_e) { /* the verdict is already decided */ }
      resolve(closed);
    }
    socket.once("connect", function () { done(false); });
    socket.once("error", function () { done(true); });
  });
}

// The rows of one domain's block, as the operator reads them: the lines
// that carry a mark, in order.
function markedLines(text) {
  return String(text).split("\n").filter(function (line) {
    return line.indexOf(PASS_MARK) === 0 || line.indexOf(FAIL_MARK) === 0 ||
      line.indexOf(NOTE_MARK) === 0 || line.indexOf(UNRESOLVED_MARK) === 0;
  });
}

// Only the lines below the domain heading. The local checks print with
// the same marks and are not what this file is about: they ran, and they
// reached verdicts.
function dnsMarkedLines(text) {
  var lines = String(text).split("\n");
  var start = -1;
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i] === DOMAIN) { start = i; break; }
  }
  if (start === -1) return [];
  return markedLines(lines.slice(start).join("\n"));
}

// ---- what the volume holds before anything is checked -------------------------

async function populate(cfg) {
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var dkim = blamepost.mail.dkim.create({ dataDir: cfg.paths.dataDir, store: handle });
    if (dkim.list(DOMAIN).length === 0) await dkim.generate({ domain: DOMAIN });
  } finally {
    handle.close();
  }
}

// ---- cases --------------------------------------------------------------------

function everyRecordIsMarkedUnchecked(run) {
  var checked = run(["doctor", "--domain", DOMAIN]);
  var rows = dnsMarkedLines(checked.stdout);

  count("the run reached the zone block, so there are rows to read",
    rows.length > 0, checked.stdout.slice(0, 600));

  var failed = rows.filter(function (line) { return line.indexOf(FAIL_MARK) === 0; });
  count("no record is marked as a failure, because this server never saw one to fail",
    failed.length === 0, JSON.stringify(failed));

  var passed = rows.filter(function (line) { return line.indexOf(PASS_MARK) === 0; });
  count("and none is marked as a pass either, since nothing was read back",
    passed.length === 0, JSON.stringify(passed));

  var unresolved = rows.filter(function (line) { return line.indexOf(UNRESOLVED_MARK) === 0; });
  count("every record carries the mark that means it could not be checked",
    unresolved.length === rows.length, JSON.stringify(rows));

  // The advisory record is the one most likely to be misfiled. It is
  // advisory and it was not read, and the second of those is what an
  // operator has to act on: a note reads as a decision this server made
  // about a record it looked at.
  count("including the advisory record, which was not read either and so is not a note",
    rows.some(function (line) { return /TLS-RPT/.test(line); }) &&
    !rows.some(function (line) {
      return line.indexOf(NOTE_MARK) === 0 && /TLS-RPT/.test(line);
    }),
    JSON.stringify(rows));

  return checked;
}

function noRowInventsAValue(run) {
  var checked = run(["doctor", "--domain", DOMAIN, "--json"]);
  var parsed = parseJson(checked.stdout);
  count("the JSON report says the run could not settle, beside whether the zone matched",
    parsed !== null && parsed.dns && parsed.dns.unresolved === true && parsed.dns.ok === false,
    checked.stdout.slice(0, 400));

  var findings = [];
  ((parsed && parsed.dns && parsed.dns.domains) || []).forEach(function (entry) {
    count("the domain block carries the same answer as the report above it",
      entry.unresolved === true, JSON.stringify({ domain: entry.domain, ok: entry.ok }));
    findings = findings.concat(entry.findings);
  });

  // A finding that named an expected or a found value would be claiming
  // an observation, and the row is there precisely because there was
  // none.
  var invented = findings.filter(function (f) {
    return f.unresolved === true && (f.expected !== null || f.found !== null);
  });
  count("and no unread record names an expected or a found value, which would be this " +
    "server describing something it did not see",
    invented.length === 0, JSON.stringify(invented).slice(0, 300));

  return parsed;
}

function theSummaryCountsThemApart(checked, parsed) {
  var text = checked.stdout;

  count("the report does not say everything is in place, when some of it was never read",
    !/Everything this server expects is in place/.test(text), text.slice(-500));

  var unread = /(\d+) records? could not be checked/.exec(text);
  count("the closing summary says how many records could not be checked",
    unread !== null, text.slice(-500));

  var dnsRows = dnsMarkedLines(text).length;
  count("and the number it gives is the number of rows carrying that mark",
    unread !== null && Number(unread[1]) === dnsRows,
    JSON.stringify({ said: unread && unread[1], rows: dnsRows }));

  count("and it sends the operator to the resolver rather than to their zone",
    /resolver this server reads/.test(text), text.slice(-500));

  // The other half of the count. Local checks can fail on their own and
  // an operator with both needs both numbers; what must never happen is
  // a record nobody read being counted among the records that disagreed.
  var localFailures = ((parsed && parsed.local) || []).filter(function (f) { return !f.ok; });
  var mismatch = /(\d+) checks? do(?:es)? not match what this server expects/.exec(text);
  count("and a record nobody could read is not counted among the checks that disagreed",
    localFailures.length === 0 ? mismatch === null
      : (mismatch !== null && Number(mismatch[1]) === localFailures.length),
    JSON.stringify({
      said: mismatch && mismatch[1],
      localFailures: localFailures.map(function (f) { return f.check; }),
    }));
}

// ---- runner -------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-doctor-unresolved");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    await populate(cfg);

    if (!(await portIsClosed(quiet.HOST, quiet.PORT))) {
      helpers.skip("something is listening on " + quiet.HOST + ":" + quiet.PORT + ", so a " +
        "lookup sent there would fail differently from a resolver that has gone quiet");
      return helpers.getChecks();
    }

    var armed = {};
    armed[quiet.ARMED_VAR] = "1";
    var run = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      execArgv:        ["--require", quiet.PRELOAD],
      env:             armed,
    });

    var checked = everyRecordIsMarkedUnchecked(run);
    var parsed  = noRowInventsAValue(run);
    theSummaryCountsThemApart(checked, parsed);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-doctor-unresolved", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
