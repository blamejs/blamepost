// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The DMARC policy stepper, followed from the server that assembles it to
 * the command line an operator drives it from.
 *
 * `dmarc-policy-step.test.js` drives the decision itself over seeded
 * reports, which answers what the rules do with evidence and says nothing
 * about whether anything reaches them. This file answers the other half.
 * The module was complete, green and composed by nothing at all, which is
 * the shape this project gets wrong most often: a subsystem that works
 * everywhere except where an operator can reach it.
 *
 *   - assembling a server builds the stepper, and the verdict it answers
 *     with is read through the report handle that server was opened
 *     with, so the counting behind a step is the counting on the volume;
 *   - `describe` reports the rules in force and the address a record it
 *     offers points its rua tag at, so a console and an operator read
 *     the numbers actually being applied;
 *   - a store whose report handle sweeps and cannot count is refused at
 *     assembly rather than started, because a server that binds every
 *     port and answers every policy question with a stack trace fails at
 *     the moment an operator first asks one;
 *   - the command line reads a real verdict off a real volume, records a
 *     marking to the audit trail and reads it back;
 *   - and `dmarc preview` prints the record text for every level while
 *     another process holds the volume, because an operator publishing
 *     the weaker record is doing it on a day something is already wrong.
 *
 * The rua address is derived in two places and this file holds them
 * against each other. `blamepost.create` reads it off the outbound handle
 * and the command line resolves it from the configuration, because
 * `preview` cannot build an outbound handle: building one creates the
 * spool directory, and `preview` has to answer on a volume that will not
 * open.
 *
 * Real database, real vault, real audit chain, real binary in a child
 * process. The zone is a table, because what is under test is the wiring
 * rather than the resolver.
 *
 * Run standalone: node test/layer-1-state/dmarc-policy-wiring.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var cliHelper = require("../helpers/cli");
var dnsZone   = require("../helpers/dns-zone");
var quiet     = require("../helpers/dns-quiet");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var address   = require("../../lib/store/address");
var blamepost = require("../../lib");
var policyMod = require("../../lib/mail/dmarc-policy");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
// A second hosted domain, so the command line's marking round trip
// starts from a domain nothing has been written about. The first one
// carries a marking by the time the child process runs, written through
// the assembled server, and a round trip that began with one already
// there could not tell an empty answer from a stale one.
var MARK_DOMAIN = "example.net";
var ABSENT      = "nothosted.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The sending address one marking is written about. It is in the range
// RFC 5737 reserves for documentation, so nothing here names a host
// somebody operates.
var FAILING_SOURCE = "198.51.100.20";

var MARK_REASON = "a hosting range with no relationship to this domain";

// The listeners the assembled server is composed with. Nothing is
// started, so these are reserved rather than bound; a port left at its
// default would have this run composed against the number a real
// deployment holds.
var LISTENER_NAMES = ["mx", "submission", "submissions", "imap", "managesieve"];

// What the domain publishes while the assembled server reads it. The SPF
// record ends in -all because a step asks for one that does, and the
// DMARC record carries a reporting address of its own so the record the
// stepper offers has a tag to preserve.
var PUBLISHED_DMARC = "v=DMARC1; p=none; rua=mailto:dmarc-reports@" + DOMAIN + "; adkim=s";

function zoneFor() {
  var zone = {};
  zone[DOMAIN] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  zone["_dmarc." + DOMAIN] = { txt: [PUBLISHED_DMARC] };
  return zone;
}

// ---- what assembling a server built ----------------------------------------

function _runtimeConfig(cfg, sections) {
  return Object.assign({}, cfg, { httpPort: 0, httpsPort: 0, listeners: sections });
}

function theStepperIsOnTheServerHandle(server) {
  var handle = server.mail.dmarcPolicy;
  count("assembling a server builds the DMARC policy stepper and puts it on the handle, so " +
    "the module is reachable from the server rather than only from a require",
    handle !== undefined && handle !== null &&
    typeof handle.evaluate === "function" && typeof handle.markSource === "function" &&
    typeof handle.markings === "function" && typeof handle.describe === "function",
    handle === undefined || handle === null
      ? String(handle)
      : Object.keys(handle).join(", "));

  var shape = server.describe().dmarcPolicy;
  count("and describe reports it, so an operator asking what a step is measured against " +
    "reads the numbers in force rather than a document",
    shape !== undefined && shape !== null &&
    shape.quarantine !== undefined && shape.reject !== undefined,
    JSON.stringify(shape === undefined ? null : Object.keys(shape)));
  count("the rules it reports are the module's own constants rather than a second copy " +
    "assembled at the wiring",
    shape.sourceFloorMessages === policyMod.SOURCE_FLOOR_MESSAGES &&
    shape.maxGapDays === policyMod.MAX_GAP_DAYS &&
    shape.fixGraceDays === policyMod.FIX_GRACE_DAYS &&
    shape.sourceListLimit === policyMod.SOURCE_LIST_LIMIT,
    JSON.stringify({ floor: shape.sourceFloorMessages, gap: shape.maxGapDays,
      grace: shape.fixGraceDays, listed: shape.sourceListLimit }));
  count("and both steps are published with a threshold on each, so a console renders what " +
    "is required beside what a domain has",
    shape.quarantine.spanDays > 0 && shape.reject.spanDays > shape.quarantine.spanDays &&
    shape.reject.heldDays > 0,
    JSON.stringify({ quarantine: shape.quarantine, reject: shape.reject }));

  // Compared through the one derivation that decides what a name means
  // here, because the outbound default carries an uppercase local part
  // and the stepper canonicalizes what it is handed. The two are the
  // same mailbox and this is the check that they stay one address.
  var outbound = server.describe().outbound.postmaster;
  count("the rua address it would offer is the postmaster the outbound path resolved, so " +
    "the record this server prints and the mailbox it reads reports at cannot name two " +
    "different addresses",
    shape.reportingAddress === address.canonical(outbound, "postmaster").address,
    shape.reportingAddress + " against " + outbound);
}

// The reading a verdict rests on comes off the volume this server was
// opened with. Nothing else in this file can show that: a stepper wired
// to a store of its own would answer every one of these the same way
// while counting somebody else's rows.
async function theVerdictIsReadThroughTheWiredStore(server) {
  var verdict = await server.mail.dmarcPolicy.evaluate({ domain: DOMAIN });

  count("the stepper reads the policy the domain publishes through the resolver the server " +
    "shares, rather than one of its own",
    verdict.level === "none", JSON.stringify({ level: verdict.level, reason: verdict.reason }));
  count("and it judges the step to quarantine, which is what a domain at p=none is asking " +
    "about",
    verdict.next === "quarantine", String(verdict.next));

  // The four readings the module makes of the report handle all run
  // before the first refusal is returned, so this is the wiring itself
  // answering rather than an early exit that never reached the volume.
  count("the counting behind the verdict came back from the report handle this server was " +
    "opened with",
    verdict.evidence !== null && verdict.evidence.counted === 0 &&
    verdict.evidence.windowDays > 0,
    JSON.stringify(verdict.evidence));

  var named = verdict.checks.map(function (check) { return check.name; });
  count("and every rule is reported with what it asks for beside what the domain has, so a " +
    "console can show how far along a domain is rather than only that it is not there yet",
    named.indexOf("evidence") !== -1 && named.indexOf("spf") !== -1,
    named.join(", "));

  var absent = verdict.checks.filter(function (check) {
    return check.reason === policyMod.CODES.evidenceAbsent;
  });
  count("a domain nobody has reported on is answered as evidence nobody has sent rather " +
    "than as a fault",
    absent.length === 1 && absent[0].ok === false,
    JSON.stringify(verdict.checks.map(function (c) { return c.name + "=" + c.ok; })));

  // The case an operator hits first, and the one the record text exists
  // for: nothing has been reported, the step is refused, and the value to
  // publish for every level is in the answer anyway.
  count("the record text for all three levels is answered on a refusal, so the value an " +
    "operator publishes is in front of them without this server agreeing to anything",
    typeof verdict.records.none === "string" &&
    typeof verdict.records.quarantine === "string" &&
    typeof verdict.records.reject === "string" &&
    verdict.records.quarantine.indexOf("p=quarantine") !== -1,
    JSON.stringify(verdict.records));
  count("and the reporting address already published is carried into every one of them, so " +
    "a step changes the policy and nothing else",
    verdict.records.reject.indexOf("rua=mailto:dmarc-reports@" + DOMAIN) !== -1 &&
    verdict.records.reject.indexOf("adkim=s") !== -1,
    verdict.records.reject);

  count("stepping down is reported as ungated on a reading that refuses to step up",
    verdict.reversal !== null && verdict.reversal.gated === false,
    JSON.stringify(verdict.reversal));
}

// A marking written through the server handle and read back through it.
// Both halves reach the audit trail on the open volume, which is the one
// thing a stepper built over the wrong store could not do.
async function aMarkingWrittenThroughTheServerIsReadBack(server) {
  var written = await server.mail.dmarcPolicy.markSource({
    domain:      DOMAIN,
    sourceIp:    FAILING_SOURCE,
    disposition: policyMod.MARK_NOT_OURS,
    reason:      MARK_REASON,
  });
  count("a marking written through the assembled server reaches the audit trail",
    written.recorded === true, JSON.stringify(written));

  var held = await server.mail.dmarcPolicy.markings({ domain: DOMAIN });
  var ids = Object.keys(held.marked);
  count("and reading the markings back finds it, so the identifier it was filed under is " +
    "one this volume can derive again",
    held.ok === true && ids.length === 1 &&
    held.marked[ids[0]].disposition === policyMod.MARK_NOT_OURS,
    JSON.stringify(held));
  count("the operator's sentence is the reason column of the row rather than something " +
    "reconstructed beside it",
    ids.length === 1 && held.marked[ids[0]].reason === MARK_REASON,
    ids.length === 1 ? held.marked[ids[0]].reason : "no marking");
  count("and the sending address is not in the identifier in the clear, because it belongs " +
    "to somebody with no account here",
    ids.length === 1 && ids[0].indexOf(FAILING_SOURCE) === -1,
    ids.join(", "));
}

// ---- what a store missing half the handle does ------------------------------

// The report handle answers six things this server needs and the
// composition facade used to check two of them. A handle that sweeps and
// cannot count assembles a server that binds every port, reports every
// listener bound, and throws the first time anybody asks about a policy.
//
// The browser surface names the same four on its own required list, and
// that is not a substitute: it is built after the mail side here, its
// list is about the pages it renders, and a page dropped from it would
// take the mail side's guarantee with it silently. So the refusal that
// has to fire is the facade's own, which is what these assert on.
function aStoreThatCannotCountIsRefused(identity, runtimeConfig) {
  var missing = ["rollup", "failingSources", "reporters", "describe"];
  var refusedAll = [];
  missing.forEach(function (name) {
    var crippled = {};
    Object.keys(identity.reports).forEach(function (key) {
      if (key !== name) crippled[key] = identity.reports[key];
    });
    var refused = null;
    try {
      blamepost.create({
        config:       runtimeConfig,
        store:        Object.assign({}, identity, { reports: crippled }),
        mailStore:    identity.mailbox,
        messageStore: identity.messageStore,
        resolver:     dnsZone.resolverOver(zoneFor()),
      });
    } catch (e) { refused = e; }
    refusedAll.push({
      name:    name,
      refused: refused !== null,
      message: refused === null ? null : String(refused.message),
    });
  });

  count("a report handle short of any one of the four readings a step rests on is refused " +
    "at assembly rather than started with the stepper broken",
    refusedAll.every(function (entry) { return entry.refused; }),
    JSON.stringify(refusedAll.map(function (e) { return e.name + "=" + e.refused; })));
  count("and the refusal is the composition facade's own, made where the mail side reads " +
    "the handle rather than falling out of the browser surface's list of pages",
    refusedAll.every(function (entry) {
      return entry.message !== null && entry.message.indexOf("blamepost.create:") === 0;
    }),
    JSON.stringify(refusedAll.map(function (e) {
      return e.message === null ? "assembled" : e.message.slice(0, 60);
    })));
  count("and it names every reading the handle has to answer, so the operator is told what " +
    "to build it with rather than which one this run happened to remove",
    refusedAll.every(function (entry) {
      return entry.message !== null && missing.every(function (reading) {
        return entry.message.indexOf(reading) !== -1;
      });
    }),
    refusedAll[0].message === null ? "assembled" : refusedAll[0].message);
}

// ---- the command line -------------------------------------------------------

// The one verb that answers while another process holds the volume, and
// the reason it exists. Everything else here needs the volume, so this
// runs while the parent still holds it.
function previewAnswersWhileTheVolumeIsHeld(run) {
  var held = run(["dmarc", "preview", DOMAIN]);
  count("`dmarc preview` answers while another process holds the data volume, because a " +
    "reversal that needs this server's database to open is missing on the day it is wanted",
    held.status === 0, "exit " + held.status + " " + held.both.slice(0, 200));
  count("and it prints the record text for every level",
    /p=none/.test(held.stdout) && /p=quarantine/.test(held.stdout) &&
    /p=reject/.test(held.stdout),
    held.stdout.slice(0, 400));
  count("including a rua tag, because a domain that asks for no reports accumulates no " +
    "evidence",
    /rua=mailto:/.test(held.stdout), held.stdout.slice(0, 400));

  var one = run(["dmarc", "preview", DOMAIN, "--level", "none"]);
  count("--level narrows it to the one record an operator is about to publish",
    one.status === 0 && /p=none/.test(one.stdout) && /p=reject/.test(one.stdout) === false,
    "exit " + one.status + " " + one.stdout.slice(0, 300));

  var wrong = run(["dmarc", "preview", DOMAIN, "--level", "off"]);
  count("and a level outside the three is refused rather than answered about the nearest one",
    wrong.status === 2 && /none, quarantine, reject/.test(wrong.both),
    "exit " + wrong.status + " " + wrong.both.slice(0, 200));

  // The verb that does need the volume, run at the same moment. Without
  // this the check above would pass on a run where nothing was holding
  // anything.
  var blocked = run(["dmarc", "status", DOMAIN]);
  count("`dmarc status` is refused at the same moment, so preview is answering past a " +
    "volume that is genuinely held rather than one that happens to be free",
    blocked.status !== 0, "exit " + blocked.status + " " + blocked.both.slice(0, 200));

  return held;
}

// The rua address the command line resolves against the one the server
// resolved. The two derivations are separate on purpose and this is what
// keeps them from drifting.
function theCommandLineAndTheServerNameTheSameAddress(run, fromServer) {
  var structured = run(["dmarc", "preview", DOMAIN, "--json"]);
  var parsed;
  try { parsed = JSON.parse(structured.stdout); }
  catch (_e) { parsed = null; }
  count("the command line publishes the address its record points at, so a script reading " +
    "one is reading the same value the server would",
    parsed !== null && typeof parsed.reportingAddress === "string",
    structured.stdout.slice(0, 300));
  count("and it is the address the assembled server resolved, which is the whole of what " +
    "keeps the two derivations in step",
    parsed !== null && parsed.reportingAddress === fromServer,
    (parsed === null ? "unparsed" : parsed.reportingAddress) + " against " + fromServer);
}

function theCommandLineReadsARealVerdict(run) {
  var elsewhere = run(["dmarc", "status", ABSENT]);
  count("a domain this server does not host is refused against the domain rows rather than " +
    "answered about a zone nobody asked after",
    elsewhere.status === 2 && elsewhere.both.indexOf(ABSENT) !== -1,
    "exit " + elsewhere.status + " " + elsewhere.both.slice(0, 200));
  count("and the refusal names the domains it does host, so the operator can see the " +
    "spelling they meant",
    elsewhere.both.indexOf(DOMAIN) !== -1, elsewhere.both.slice(0, 300));

  var verdict = run(["dmarc", "status", DOMAIN]);
  count("a hosted domain answers with a verdict and exits zero, because a domain still " +
    "collecting reports is the ordinary state rather than a fault",
    verdict.status === 0, "exit " + verdict.status + " " + verdict.both.slice(0, 300));
  count("and the answer carries the record text for every level, which is what an operator " +
    "reverses with",
    /p=none/.test(verdict.stdout) && /p=quarantine/.test(verdict.stdout) &&
    /p=reject/.test(verdict.stdout), verdict.stdout.slice(0, 500));
  count("and says plainly that stepping down needs no evidence",
    /needs no evidence|nothing to step/.test(verdict.stdout), verdict.stdout.slice(0, 600));
}

function aMarkingRoundTripsThroughTheCommandLine(run) {
  var empty = run(["dmarc", "markings", MARK_DOMAIN]);
  count("a domain with nothing written down says so rather than printing an empty block",
    empty.status === 0 && /0 markings/.test(empty.stdout),
    "exit " + empty.status + " " + empty.stdout.slice(0, 200));

  var badDisposition = run(["dmarc", "mark", MARK_DOMAIN, "--source", FAILING_SOURCE,
    "--disposition", "probably-fine", "--reason", MARK_REASON]);
  count("a disposition outside the pair is refused, because the two are read differently " +
    "and a third would be read as neither",
    badDisposition.status === 2 && /ours-and-fixed/.test(badDisposition.both),
    "exit " + badDisposition.status + " " + badDisposition.both.slice(0, 200));

  var noReason = run(["dmarc", "mark", MARK_DOMAIN, "--source", FAILING_SOURCE,
    "--disposition", "not-ours"]);
  count("and a marking with no reason is refused, because the reason is the evidence a " +
    "policy tightens on",
    noReason.status === 2 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 200));

  var badSource = run(["dmarc", "mark", MARK_DOMAIN, "--source", "not-an-address",
    "--disposition", "not-ours", "--reason", MARK_REASON]);
  count("an address that is not one is refused at the argument rather than filed under a " +
    "digest of the typo",
    badSource.status === 2, "exit " + badSource.status + " " + badSource.both.slice(0, 200));

  var stillEmpty = run(["dmarc", "markings", MARK_DOMAIN]);
  count("and none of those three left a row behind, so a refused argument costs nothing on " +
    "the trail",
    stillEmpty.status === 0 && /0 markings/.test(stillEmpty.stdout),
    stillEmpty.stdout.slice(0, 200));

  var marked = run(["dmarc", "mark", MARK_DOMAIN, "--source", FAILING_SOURCE,
    "--disposition", "not-ours", "--reason", MARK_REASON]);
  count("a marking with every argument reading is recorded",
    marked.status === 0, "exit " + marked.status + " " + marked.both.slice(0, 300));

  var listed = run(["dmarc", "markings", MARK_DOMAIN]);
  count("and it is read back off the trail with the disposition and the sentence that was " +
    "written",
    listed.status === 0 && /not-ours/.test(listed.stdout) &&
    listed.stdout.indexOf(MARK_REASON) !== -1,
    "exit " + listed.status + " " + listed.stdout.slice(0, 400));
  count("the address itself is not printed back, because the trail does not hold it",
    listed.stdout.indexOf(FAILING_SOURCE) === -1, listed.stdout.slice(0, 400));

  // The marking written through the assembled server, read back through
  // the binary. The two surfaces derive the identifier a marking is
  // filed under separately, and a digest that differed between them
  // would leave every marking invisible to the other side.
  var throughTheServer = run(["dmarc", "markings", DOMAIN]);
  count("the marking the assembled server wrote is the one the command line reads back, so " +
    "both surfaces file a source under the same identifier",
    throughTheServer.status === 0 && /1 marking in force/.test(throughTheServer.stdout) &&
    throughTheServer.stdout.indexOf(MARK_REASON) !== -1,
    "exit " + throughTheServer.status + " " + throughTheServer.stdout.slice(0, 400));
}

// ---- the run ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-policy-wiring");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var identity = null;
  try {
    // The store refuses to open without this: it decrypts a working copy
    // of the database and will not put one somewhere it was not told to.
    process.env.BLAMEJS_TMPDIR = workDir;

    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: MARK_DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });
    await identity.domains.acknowledgeDns({
      domain: MARK_DOMAIN, acknowledgedBy: "operator@" + MARK_DOMAIN,
    });

    var sections = {};
    for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
      sections[LISTENER_NAMES[i]] = {
        enabled: true,
        port:    await wire.reservePort(),
        address: "127.0.0.1",
      };
    }
    var runtimeConfig = _runtimeConfig(cfg, sections);

    aStoreThatCannotCountIsRefused(identity, runtimeConfig);

    // Nothing is started. Every reading below is about what assembling
    // built, and a bound port would only add a listener to close.
    var server = blamepost.create({
      config:       runtimeConfig,
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      resolver:     dnsZone.resolverOver(zoneFor()),
    });

    theStepperIsOnTheServerHandle(server);
    await theVerdictIsReadThroughTheWiredStore(server);
    await aMarkingWrittenThroughTheServerIsReadBack(server);

    var fromServer = server.describe().dmarcPolicy.reportingAddress;

    // The command line, against the same volume. The parent still holds
    // it here, which is what the first group measures.
    //
    // The child's resolver is sent to a port nothing answers on, so
    // every lookup it makes fails in a few milliseconds through the
    // shipped transport rather than reaching whatever the machine
    // running this happens to resolve. What the record text is built out
    // of when the record IS readable is measured in process above,
    // against the zone table this server was assembled over.
    if (!(await quiet.endpointIsRefusing())) {
      helpers.skip("something is listening on " + quiet.HOST + ":" + quiet.PORT + ", so a " +
        "lookup sent there would be accepted and never answered, which is a different " +
        "failure and one that burns the whole DNS budget");
      return helpers.getChecks();
    }
    var armed = {};
    armed[quiet.ARMED_VAR] = "1";
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      execArgv:        ["--require", quiet.PRELOAD],
      env:             armed,
    });

    previewAnswersWhileTheVolumeIsHeld(cli);
    theCommandLineAndTheServerNameTheSameAddress(cli, fromServer);

    // The CLI opens the same database in a child process and the handle
    // is one per process on each side, so the parent gives it back
    // before the verbs that need it run.
    identity.close();
    identity = null;

    theCommandLineReadsARealVerdict(cli);
    aMarkingRoundTripsThroughTheCommandLine(cli);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "dmarc-policy-wiring",
  run:       run,
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
