// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost doctor` tells an operator about a zone it really
 * resolved.
 *
 * The boot gate asks the operator whether the records exist, which is a
 * claim about the world. This command goes and looks, so it is the only
 * thing standing between an operator and a domain whose mail nobody can
 * authenticate. Both of its failure modes cost real mail. A record the
 * command passes and a receiver refuses leaves the operator confident and
 * undelivered. A record it fails and a receiver accepts trains the
 * operator to stop reading the report, which costs them the next finding
 * as well.
 *
 * `test/layer-1-state/inbound-posture.test.js` settles the verdicts by
 * handing a resolver handle to the checker inside this process. That
 * reaches everything the checker decides and nothing the command decides:
 * the mark on each line, the two counts in the closing summary and the
 * exit status all live in `bin/blamepost.js` and read a report the
 * checker already produced. So the zone here is served over DNS-over-
 * HTTPS by `test/helpers/dns-doh.js` and resolved by the spawned run's
 * own resolver, through the shipped transport, with no handle replaced.
 *
 * One property that needs the wire and cannot be had from a handle: RFC
 * 4035 §3.2.3 makes DNSSEC authentication a fact about the RESPONSE, and
 * the resolver reads it off the AD bit. RFC 7672 §1.3 then forbids a
 * sender from using a TLSA record that was not authenticated, and the
 * framework's own DANE reader refuses one outright. A command that calls
 * such a record healthy is telling an operator their server can be
 * DANE-authenticated when no sender will ever do it.
 *
 * Run standalone: node test/layer-1-state/cli-doctor-zone.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var doh       = require("../helpers/dns-doh");
var blamepost = require("../../lib");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The marks the report uses, read from the report rather than described,
// so a row is classified the way an operator's eye classifies it.
var PASS_MARK       = "  ok    ";
var FAIL_MARK       = "  FAIL  ";
var NOTE_MARK       = "  note  ";
var UNRESOLVED_MARK = "  ?     ";

// A run that hangs has to be reported as one rather than waiting out
// whatever budget the binary carries. Generous, because it spawns a
// process, opens an encrypted volume and resolves a zone.
var RUN_CEILING_MS = 90000;

function parseJson(text) {
  // The verb prints its JSON pretty, so its first line is a bare brace.
  var at = String(text).indexOf("\n{");
  var body = at === -1 ? String(text) : String(text).slice(at + 1);
  try { return JSON.parse(body); } catch (_e) { return null; }
}

function markedLines(text) {
  return String(text).split("\n").filter(function (line) {
    return line.indexOf(PASS_MARK) === 0 || line.indexOf(FAIL_MARK) === 0 ||
      line.indexOf(NOTE_MARK) === 0 || line.indexOf(UNRESOLVED_MARK) === 0;
  });
}

// The row for one record, as the operator reads it, with the mark still
// on the front.
function rowFor(text, record) {
  var wanted = markedLines(text).filter(function (line) {
    return line.slice(8).indexOf(record + " at ") === 0 || line.slice(8) === record;
  });
  return wanted.length === 0 ? null : wanted[0];
}

function findingFor(parsed, record) {
  var out = null;
  ((parsed && parsed.dns && parsed.dns.domains) || []).forEach(function (entry) {
    entry.findings.forEach(function (f) { if (f.record === record && out === null) out = f; });
  });
  return out;
}

// An SPF record past the 450 octets RFC 7208 caps a published record at,
// ending in -all and correct in every other respect. It is what a domain
// arrives at by adding one sending provider at a time, and every
// receiver answers a record this long with a permanent error, so the
// domain has no usable SPF at all while its record looks right.
var OVERSIZE_SPF = (function () {
  var terms = ["v=spf1", "mx"];
  for (var i = 0; i < 20; i += 1) {
    terms.push("include:_spf" + i + ".provider" + i + ".example");
  }
  terms.push("-all");
  return terms.join(" ");
}());

// ---- the zone every case varies one record of --------------------------------

function goodZone(extra) {
  var z = {};
  z[DOMAIN] = { mx: [HOSTNAME], txt: ["v=spf1 mx -all"] };
  z["_dmarc." + DOMAIN]     = { txt: ["v=DMARC1; p=reject; rua=mailto:dmarc@" + DOMAIN] };
  z["_mta-sts." + DOMAIN]   = { txt: ["v=STSv1; id=20260919T000000"] };
  z["_smtp._tls." + DOMAIN] = { txt: ["v=TLSRPTv1; rua=mailto:tls@" + DOMAIN] };
  Object.keys(extra || {}).forEach(function (name) { z[name] = extra[name]; });
  return z;
}

// ---- what the volume holds before anything is checked ------------------------

async function populate(cfg) {
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var dkim = blamepost.mail.dkim.create({ dataDir: cfg.paths.dataDir, store: handle });
    if (dkim.list(DOMAIN).length === 0) await dkim.generate({ domain: DOMAIN });
    return dkim.dnsRecords(DOMAIN);
  } finally {
    handle.close();
  }
}

// A run against one zone, from a fresh server so nothing a previous case
// published is still being answered.
async function against(zone, args, root, workDir, dataDir) {
  var served = await doh.start(zone, { caDir: workDir });
  try {
    var run = cliHelper.createAsync({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      execArgv:        ["--require", doh.PRELOAD],
      env:             doh.armedEnv(served),
      ceilingMs:       RUN_CEILING_MS,
    });
    var result = await run(args);
    result.asked = served.asked();
    return result;
  } finally {
    served.close();
  }
}

// ---- the records the operator guide requires ---------------------------------

// Each of these is one record wrong in a zone that is otherwise right,
// which is the shape that keeps a pass from coming from somewhere else.
// A run where several records are wrong cannot say which one a verdict
// belongs to.
async function eachRecordIsNamedForWhatIsWrongWithIt(ctx) {
  var cases = [
    { what: "an MX record that points somewhere else",
      zone: { "example.com": { mx: ["mx.elsewhere.example"], txt: ["v=spf1 mx -all"] } },
      record: "MX", says: /being delivered somewhere else/i },
    { what: "a null MX, which refuses mail outright",
      zone: { "example.com": { mx: [""], txt: ["v=spf1 mx -all"] } },
      record: "MX", says: /null mx/i },
    { what: "no MX record at all",
      zone: { "example.com": { mx: [], txt: ["v=spf1 mx -all"] } },
      record: "MX", says: /publishes no mx record/i },
    { what: "two SPF records, which RFC 7208 §4.5 makes a permanent error",
      zone: { "example.com": { mx: [HOSTNAME],
        txt: ["v=spf1 mx -all", "v=spf1 a -all"] } },
      record: "SPF", says: /2 spf records/i },
    { what: "an SPF record ending in ~all",
      zone: { "example.com": { mx: [HOSTNAME], txt: ["v=spf1 mx ~all"] } },
      record: "SPF", says: /change the ending to -all/i },
    { what: "an SPF record longer than a receiver will read, which is the shape a domain " +
        "grows into one include at a time",
      zone: { "example.com": { mx: [HOSTNAME], txt: [OVERSIZE_SPF] } },
      record: "SPF", says: /450|octets/i },
    { what: "a DMARC record a receiver cannot parse",
      zone: { "_dmarc.example.com": { txt: ["v=DMARC1; p=sometimes"] } },
      record: "DMARC", says: /could not be read|no dmarc record/i },
    { what: "a DMARC policy of p=none",
      zone: { "_dmarc.example.com": { txt: ["v=DMARC1; p=none"] } },
      record: "DMARC", says: /p=none/i },
    { what: "no MTA-STS TXT record, which leaves the policy file unread",
      zone: { "_mta-sts.example.com": doh.ABSENT },
      record: "MTA-STS TXT", says: /no mta-sts txt record/i },
    { what: "an MTA-STS TXT record with no id tag to rotate on",
      zone: { "_mta-sts.example.com": { txt: ["v=STSv1"] } },
      record: "MTA-STS TXT", says: /no id tag/i },
    { what: "a TLS-RPT record naming no destination",
      zone: { "_smtp._tls.example.com": { txt: ["v=TLSRPTv1;"] } },
      record: "TLS-RPT", says: /nowhere to go/i },
    { what: "a TLS-RPT record that does not open with the version tag",
      zone: { "_smtp._tls.example.com": { txt: ["rua=mailto:tls@example.com"] } },
      record: "TLS-RPT", says: /version tag/i },
  ];

  for (var i = 0; i < cases.length; i += 1) {
    var one = cases[i];
    var checked = await against(goodZone(one.zone), ["doctor", "--domain", DOMAIN, "--json"],
      ctx.root, ctx.workDir, ctx.dataDir);
    var parsed = parseJson(checked.both);
    var finding = findingFor(parsed, one.record);
    count(one.what + " is reported against " + one.record,
      finding !== null && finding.ok === false && finding.unresolved !== true,
      one.what + " -> " + JSON.stringify(finding) + checked.both.slice(0, 200));
    count("and the sentence says what is wrong with it rather than blaming the resolver",
      finding !== null && one.says.test(finding.detail || ""),
      one.what + " -> " + (finding && finding.detail));
  }
}

// A selector record this server holds the private half of, and the zone
// it is not published in. Nothing this server signs verifies, and the
// sending side cannot see that on its own.
async function aMissingSelectorRecordIsNamedBySelector(ctx, published) {
  var withKeys = {};
  published.forEach(function (r) { withKeys[r.dnsName] = { txt: [r.dnsTxtValue] }; });
  var whole = await against(goodZone(withKeys), ["doctor", "--domain", DOMAIN, "--json"],
    ctx.root, ctx.workDir, ctx.dataDir);
  var wholeParsed = parseJson(whole.both);
  var wholeDkim = ((wholeParsed && wholeParsed.dns && wholeParsed.dns.domains) || [])
    .reduce(function (all, entry) {
      return all.concat(entry.findings.filter(function (f) { return f.record === "DKIM"; }));
    }, []);
  count("a selector published exactly as this server instructs passes",
    wholeDkim.length > 0 && wholeDkim.every(function (f) { return f.ok === true; }),
    JSON.stringify(wholeDkim.map(function (f) { return f.name + ":" + f.ok; })));

  var gone = await against(goodZone(), ["doctor", "--domain", DOMAIN, "--json"],
    ctx.root, ctx.workDir, ctx.dataDir);
  var goneParsed = parseJson(gone.both);
  var goneDkim = ((goneParsed && goneParsed.dns && goneParsed.dns.domains) || [])
    .reduce(function (all, entry) {
      return all.concat(entry.findings.filter(function (f) { return f.record === "DKIM"; }));
    }, []);
  count("a selector this server signs with and the zone does not publish is reported",
    goneDkim.length > 0 && goneDkim.some(function (f) {
      return f.ok === false && /selector record is missing/i.test(f.detail || "");
    }),
    JSON.stringify(goneDkim.map(function (f) { return f.name + ":" + f.ok; })));
  count("and the row names the selector rather than the domain, which is what gets published",
    goneDkim.some(function (f) { return /\._domainkey\./.test(String(f.name || "")); }),
    JSON.stringify(goneDkim.map(function (f) { return f.name; })));
}

// ---- a TLSA record no sender may use -----------------------------------------

// The record an operator publishes so other servers can authenticate
// this one under DANE. RFC 7672 §1.3 lets a sender use it only when the
// answer carrying it was DNSSEC-authenticated, and the framework's DANE
// reader refuses an unauthenticated one rather than using it. So a zone
// with TLSA records and no DNSSEC over them reaches exactly nobody, and
// a command that calls it healthy has told the operator the opposite of
// what is true.
//
// Nothing but the wire can ask this. RFC 4035 §3.2.3 puts the answer in
// the AD bit of the response, so a resolver handed to the checker as an
// object cannot carry it and cannot be wrong about it either.
async function aTlsaRecordNobodyAuthenticatedIsNotAPass(ctx) {
  var tlsaName = "_25._tcp." + HOSTNAME;

  var signed = {};
  signed[tlsaName] = { tlsa: 2 };
  var good = await against(goodZone(signed), ["doctor", "--domain", DOMAIN, "--dane", "--json"],
    ctx.root, ctx.workDir, ctx.dataDir);
  var goodFinding = findingFor(parseJson(good.both), "TLSA");
  count("a TLSA record in a zone whose answers are authenticated passes",
    goodFinding !== null && goodFinding.ok === true, JSON.stringify(goodFinding));

  var unsigned = {};
  unsigned[tlsaName] = { tlsa: 2, authenticated: false };
  var bare = await against(goodZone(unsigned), ["doctor", "--domain", DOMAIN, "--dane", "--json"],
    ctx.root, ctx.workDir, ctx.dataDir);
  var bareFinding = findingFor(parseJson(bare.both), "TLSA");
  count("the same records in a zone with no DNSSEC over them are not a pass, because no " +
    "sender is permitted to use them",
    bareFinding !== null && bareFinding.ok === false, JSON.stringify(bareFinding));
  count("and the sentence names DNSSEC as what is missing rather than the records",
    bareFinding !== null && /dnssec/i.test(bareFinding.detail || ""),
    bareFinding && bareFinding.detail);
  // The same zone read as an operator reads it. The JSON above is what a
  // script sees, and a verdict that only reaches one of the two is a
  // verdict half the audience never gets.
  var printed = await against(goodZone(unsigned), ["doctor", "--domain", DOMAIN, "--dane"],
    ctx.root, ctx.workDir, ctx.dataDir);
  count("and the row an operator reads carries a failure mark rather than a pass",
    (rowFor(printed.both, "TLSA") || "").indexOf(FAIL_MARK) === 0,
    JSON.stringify(rowFor(printed.both, "TLSA")) + printed.both.slice(-400));
  count("and the run exits non-zero, so a script that checks the status sees it too",
    bare.status !== 0 && printed.status !== 0,
    "status " + bare.status + " / " + printed.status);

  var none = await against(goodZone(), ["doctor", "--domain", DOMAIN, "--dane", "--json"],
    ctx.root, ctx.workDir, ctx.dataDir);
  var noneFinding = findingFor(parseJson(none.both), "TLSA");
  count("DANE asked for with no TLSA record at all is still reported as the record missing",
    noneFinding !== null && noneFinding.ok === false &&
    /no tlsa record/i.test(noneFinding.detail || ""), JSON.stringify(noneFinding));
  count("and without --dane no TLSA row is printed, because nothing asked for one",
    rowFor((await against(goodZone(), ["doctor", "--domain", DOMAIN],
      ctx.root, ctx.workDir, ctx.dataDir)).both, "TLSA") === null, "no TLSA row");
}

// ---- what the operator is told at the end ------------------------------------

// The closing summary is the line most readers take away, so its two
// numbers have to be the rows above it. They are counted apart because
// they send the operator to different places: a record that disagrees is
// answered in the zone, and a record nobody could read is answered at the
// resolver.
async function theClosingSummaryCountsTheRowsItPrinted(ctx) {
  var broken = goodZone({ "example.com": { mx: [HOSTNAME], txt: ["v=spf1 mx ~all"] },
    "_dmarc.example.com": doh.FAILING });
  var checked = await against(broken, ["doctor", "--domain", DOMAIN],
    ctx.root, ctx.workDir, ctx.dataDir);
  var text = checked.both;

  var failures = markedLines(text).filter(function (l) { return l.indexOf(FAIL_MARK) === 0; });
  var unread   = markedLines(text).filter(function (l) {
    return l.indexOf(UNRESOLVED_MARK) === 0;
  });

  var said = /(\d+) checks? do(?:es)? not match what this server expects/.exec(text);
  count("the summary says how many checks disagreed, and it is the number of FAIL rows",
    said !== null && Number(said[1]) === failures.length,
    JSON.stringify({ said: said && said[1], rows: failures.length }));

  var couldNot = /(\d+) records? could not be checked/.exec(text);
  count("and how many could not be checked, which is the number of rows carrying that mark",
    couldNot !== null && Number(couldNot[1]) === unread.length,
    JSON.stringify({ said: couldNot && couldNot[1], rows: unread.length }));

  // The sentence that sends an operator looking. A summary naming a FAIL
  // when none was printed is a reader hunting for a line that is not
  // there, and it is the exact shape a stale branch takes.
  count("a summary that names a FAIL only says so when one was printed",
    !/Each FAIL above names one/.test(text) || failures.length > 0,
    JSON.stringify({ failures: failures.length, tail: text.slice(-400) }));

  count("a zone with a record nobody could read never reads as everything being in place",
    !/Everything this server expects is in place/.test(text), text.slice(-400));

  count("and the run exits non-zero", checked.status !== 0, "status " + checked.status);
}

// Every value in a finding came out of a zone this server does not
// control, and the command prints them as plain lines. An escape
// sequence in one repaints the terminal of the person deciding what to
// change in their zone.
async function aHostileRecordReachesTheTerminalThroughTheScreen(ctx) {
  // Built from code points rather than written out, so this file carries
  // none of them. A source line holding a raw escape repaints the
  // terminal of everybody who ever reads the repository, which is a
  // larger audience than the one command under test.
  var ESCAPE   = String.fromCharCode(0x1B);
  var BELL     = String.fromCharCode(0x07);
  var OVERRIDE = String.fromCharCode(0x202E);
  var hostile = goodZone({ "example.com": {
    mx: [HOSTNAME],
    txt: ["v=spf1 include:" + ESCAPE + "[31mred" + BELL + ".example " +
      OVERRIDE + "evil ~all"],
  } });
  var checked = await against(hostile, ["doctor", "--domain", DOMAIN],
    ctx.root, ctx.workDir, ctx.dataDir);

  count("a record carrying an escape sequence is still reported",
    /SPF/.test(checked.both), checked.both.slice(0, 400));
  count("and no part of it reaches the terminal as something the terminal would act on",
    checked.both.indexOf(ESCAPE) === -1 && checked.both.indexOf(BELL) === -1,
    JSON.stringify(checked.both.slice(0, 400)));
  count("including the bidirectional override, which reverses the name being acted on",
    checked.both.indexOf(OVERRIDE) === -1, JSON.stringify(checked.both.slice(0, 400)));
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-doctor-zone");
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
    var published = await populate(cfg);

    var ctx = { root: root, dataDir: dataDir, workDir: workDir };
    await eachRecordIsNamedForWhatIsWrongWithIt(ctx);
    await aMissingSelectorRecordIsNamedBySelector(ctx, published);
    await aTlsaRecordNobodyAuthenticatedIsNotAPass(ctx);
    await theClosingSummaryCountsTheRowsItPrinted(ctx);
    await aHostileRecordReachesTheTerminalThroughTheScreen(ctx);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-doctor-zone", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
