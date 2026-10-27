// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * interop-gate-contract: the release gate that proves nothing says so.
 *
 * `scripts/test-integration.js` runs the interop suite: files that drive
 * a running server from the outside with clients that are not this
 * codebase. `node scripts/release.js` runs it inside the smoke and push
 * phases and treats a failure as a hard stop.
 *
 * Three states, and only one of them is green.
 *
 *   - Files exist and pass. The gate ran and proved something.
 *   - Files exist and one fails. A hard stop, or an audited override
 *     that prints the reason it was overridden.
 *   - No file exists. Nothing was proven, and that is neither of the
 *     above. It has its own exit code, it is printed as nothing proven,
 *     and the release flow publishes it as a gate that did not run. The
 *     directory is tracked and wired up, so its absence stays a broken
 *     tree rather than collapsing into the empty case.
 *
 * The state worth guarding is the third one, because the easy way to
 * make a release command pass is to report an empty suite as "OK, 0
 * checks passed" and the easy way to make it fail is to hard stop
 * forever, which trains an operator to pass the override on every cut
 * until the override stops meaning anything.
 *
 * The other thing asserted here is where the runner points. The layered
 * suites build the server inside the test process on ephemeral loopback
 * ports; they prove nothing about what another implementation makes of
 * the bytes, and pointing this runner at them would report a green
 * interop gate for a suite that has no interop in it.
 *
 * No sockets and no database. It spawns the two gate scripts and reads
 * what they say.
 *
 * Run standalone: node test/layer-0-primitives/interop-gate-contract.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var foreign  = require("../helpers/foreign-client");
var clients  = require("../../test/integration/clients");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var INTEGRATION_DIR = nodePath.join(helpers.REPO_ROOT, "test", "integration");
var RUN_CEILING_MS  = 60000;

// A name nothing on any machine can start, for the runs that need the
// clients to be absent. `locate` tries an override ALONE, so naming one
// here is the whole of what makes a client missing.
var NO_SUCH_CLIENT = nodePath.join(helpers.REPO_ROOT, "no-such-client-for-the-interop-gate");

// The service pre-flight probes listeners, and every case below drives the
// runner over a fixture suite with nothing bound. Skipping it takes a written
// reason, which is the thing `anUnjustifiedServiceSkipIsRefused` holds it to,
// so the vectors that are about something else carry one here.
var SKIP_SERVICE_CHECK = [
  "--skip-service-check",
  "--service-check-skip-reason=these cases drive a fixture suite with no listener bound, " +
    "so the pre-flight would report a stack that is down as the reason a run about " +
    "something else did not proceed",
];

// The exit code for the bypass with no reason behind it. Read as a frozen
// contract rather than restated: a caller that mistyped the override and one
// with a broken tree have different next moves.
var UNJUSTIFIED_SKIP_EXIT = 7;

function runNode(argv, env) {
  return spawnRun.runNodeScript(argv, {
    cwd:       helpers.REPO_ROOT,
    env:       env ? Object.assign({}, process.env, env) : undefined,
    ceilingMs: RUN_CEILING_MS,
  });
}

function theSuiteDirectoryIsTracked() {
  count("interop suite: the directory the runner reads exists in the tree",
    nodeFs.existsSync(INTEGRATION_DIR), INTEGRATION_DIR);

  var entries = nodeFs.readdirSync(INTEGRATION_DIR);
  count("interop suite: it carries the contract a file has to meet",
    entries.indexOf("README.md") !== -1, entries.join(", "));
}

async function anEmptySuiteReportsNothingProven() {
  var files = nodeFs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); });

  // Everything below describes the empty state. Once an interop file
  // lands, the runner takes a different path and these cases stop being
  // the ones that matter, so say which state was observed rather than
  // asserting the empty one is permanent.
  if (files.length > 0) {
    helpers.skip("the interop suite now holds " + files.length + " file(s), so the " +
      "empty-suite path is not the one this run exercises; a run of the suite itself " +
      "is what covers it from here");
    return;
  }

  var rv = await runNode(["scripts/test-integration.js"]);

  count("empty suite: it exits with the code that means nothing was proven",
    rv.code === 4, "exit " + rv.code);
  count("empty suite: it says so in as many words",
    /nothing was proven/i.test(rv.out) && /not a pass/i.test(rv.out), rv.out.trim());
  count("empty suite: it never reports checks passing",
    !/checks passed/i.test(rv.out), rv.out.trim());
  count("empty suite: it names the directory an interop file belongs in",
    rv.out.indexOf("test/integration/") !== -1, rv.out.trim());

  // The service gate probes real mail ports and prints a table of what
  // is down. Running it for a suite with nothing in it would report a
  // stack that is not up as the reason, which is a true statement about
  // the machine and the wrong answer to the question asked.
  count("empty suite: it does not probe listeners for a suite with nothing in it",
    rv.out.indexOf("[check-services]") === -1, rv.out.trim());
}

async function theReleaseFlowPublishesTheGateAsNotRun() {
  var files = nodeFs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); });
  if (files.length > 0) {
    helpers.skip("the interop suite now holds " + files.length + " file(s), so the release " +
      "flow runs the gate rather than reporting it as not run");
    return;
  }

  var rv = await runNode(["scripts/release.js", "interop"]);

  count("release flow: an empty suite does not stop the flow",
    rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 4));
  count("release flow: it prints that the gate did not run",
    /did not run/i.test(rv.out), tail(rv.out, 6));
  count("release flow: it never calls the gate green",
    !/interop green/i.test(rv.out), tail(rv.out, 6));
  count("release flow: it says the state is not a pass",
    /not a pass/i.test(rv.out), tail(rv.out, 6));
}

// ---------------------------------------------------------------------------
// A run that located no client
// ---------------------------------------------------------------------------

// An interop file whose non-client cases ran and whose client cases did
// not, which is the ordinary shape on a machine that has none of the
// clients: the file exits clean, reports checks and a skip, and the
// whole suite reads as green.
var CLAIMS_A_CLIENT =
  "\"use strict\";\n" +
  "var clients = { spec: function (id) { return { id: id }; } };\n" +
  "var PYTHON = clients.spec(\"python-smtplib\");\n" +
  "var CURL   = clients.spec(\"curl-smtp\");\n" +
  "console.log(\"  claimed: \" + PYTHON.id + \" and \" + CURL.id);\n" +
  "console.log(\"SKIP: the cases needing a foreign parser did not run.\");\n" +
  "console.log(\"CHECKS 3\");\n" +
  "console.log(\"SKIPS 1\");\n";

function _suiteWithOneFile(label) {
  var dir = helpers.tempDir(label);
  nodeFs.writeFileSync(nodePath.join(dir, "claims-a-client.test.js"), CLAIMS_A_CLIENT, "utf8");
  return dir;
}

// The clients are located at run time and never installed, so a machine
// with none of them is the ordinary case rather than a broken one. That
// run put no foreign parser on any socket, and it printed "OK, 3 checks
// passed" and exited 0. Wired into a pipeline it is a green badge over
// a run that asserted no interop property at all.
async function aRunThatLocatedNoClientIsRefused() {
  var dir = _suiteWithOneFile("interop-no-client");
  try {
    var absent = {
      BLAMEPOST_INTEGRATION_DIR: dir,
      BLAMEPOST_PYTHON_BIN:      NO_SUCH_CLIENT,
      BLAMEPOST_CURL_BIN:        NO_SUCH_CLIENT,
    };

    var rv = await runNode(["scripts/test-integration.js"].concat(SKIP_SERVICE_CHECK), absent);
    count("no client: a run that located none of them does not exit 0",
      rv.code !== 0, "exit " + rv.code + ": " + tail(rv.out, 4));
    count("no client: and every client it could not locate is named",
      rv.out.indexOf("python-smtplib") !== -1 && rv.out.indexOf("curl-smtp") !== -1 &&
      /ABSENT/.test(rv.out), tail(rv.out, 6));
    count("no client: and the empty unit is refused by name",
      /REFUSED: 0 located-clients/.test(rv.out), tail(rv.out, 6));
    count("no client: and the counts are published on the failing run too",
      /EXAMINED 1 interop-files/.test(rv.out) && /EXAMINED 3 driven-checks/.test(rv.out),
      tail(rv.out, 6));

    // The stricter posture, which is what a pipeline wants: the client
    // being missing is the finding rather than something to route
    // around, and it is decided before anything is spawned.
    var required = await runNode(["scripts/test-integration.js"].concat(SKIP_SERVICE_CHECK),
      Object.assign({ INTEGRATION_REQUIRE_CLIENTS: "1" }, absent));
    count("no client: require-mode refuses the run rather than skipping",
      required.code === 5, "exit " + required.code + ": " + tail(required.out, 4));
    count("no client: and refuses before it spawns an interop file",
      required.out.indexOf("integration file") === -1, tail(required.out, 6));
    count("no client: and names each client the selected files need",
      /INTEGRATION_REQUIRE_CLIENTS=1/.test(required.out) &&
      required.out.indexOf("python-smtplib") !== -1,
      tail(required.out, 6));
  } finally {
    helpers.removeTempDir(dir);
  }
}

// Canary. A runner that refused every run would satisfy the cases above
// and would also refuse the machine it exists to admit, so the same
// fixture is run again with the clients it claims actually present.
async function aRunThatLocatedItsClientsStillPasses() {
  var located = await foreign.locate(clients.spec("python-smtplib"));
  if (!located.found) {
    helpers.skip("the canary needs one of the clients the suite claims to be on this " +
      "machine, and there is not one: " + located.reason + ". What did not run is the " +
      "evidence that the runner still admits a machine that has its clients.");
    return;
  }

  var dir = _suiteWithOneFile("interop-with-client");
  try {
    var rv = await runNode(["scripts/test-integration.js"].concat(SKIP_SERVICE_CHECK),
      { BLAMEPOST_INTEGRATION_DIR: dir, BLAMEPOST_CURL_BIN: NO_SUCH_CLIENT });
    count("canary: a run that located a client is not refused for the count",
      /REFUSED: 0 located-clients/.test(rv.out) === false, tail(rv.out, 6));
    count("canary: and publishes what it located",
      /EXAMINED 1 located-clients/.test(rv.out), tail(rv.out, 6));
    count("canary: and still names the one it could not locate",
      rv.out.indexOf("curl-smtp") !== -1 && /ABSENT/.test(rv.out), tail(rv.out, 6));
  } finally {
    helpers.removeTempDir(dir);
  }
}

// ---------------------------------------------------------------------------
// The service pre-flight bypass
// ---------------------------------------------------------------------------

// The pre-flight probes the listeners the suite is about to drive and refuses a
// partial-up stack once, here, rather than as a dozen connection errors spread
// across the files. So skipping it skips the answer to whether the thing under
// test is running at all, and it was a bare flag: no reason, no banner, nothing
// in the transcript to say the run had not been told the stack was up. The
// sibling override on the release flow's interop gate has demanded a written
// reason all along, and the asymmetry is what makes this one the cheap way
// past. A bypass nobody has to justify becomes the shape every run is typed in,
// and the run it silently skips is the one that would have failed.
async function anUnjustifiedServiceSkipIsRefused() {
  var dir = _suiteWithOneFile("interop-bare-skip");
  try {
    var bare = await runNode(["scripts/test-integration.js", "--skip-service-check"],
      { BLAMEPOST_INTEGRATION_DIR: dir });

    count("bare skip: the flag alone does not run the suite",
      bare.code === UNJUSTIFIED_SKIP_EXIT,
      "exit " + bare.code + ", expected " + UNJUSTIFIED_SKIP_EXIT + ": " + tail(bare.out, 6));
    count("bare skip: it names the reason flag it wants",
      bare.out.indexOf("--service-check-skip-reason") !== -1, tail(bare.out, 6));
    count("bare skip: it says what skipping the pre-flight gives up",
      /whether the server is up/i.test(bare.out), tail(bare.out, 6));
    count("bare skip: and it refuses before spawning an interop file",
      bare.out.indexOf("integration file") === -1, tail(bare.out, 8));

    // The control. A refusal that also refused the justified form would make
    // the override unusable, and the reason has to reach the transcript or it
    // is a token typed to quieten a check rather than a record of a decision.
    var justified = await runNode(
      ["scripts/test-integration.js",
        "--skip-service-check",
        "--service-check-skip-reason=the stack is up under a different runner"],
      { BLAMEPOST_INTEGRATION_DIR: dir });

    count("justified skip: the run proceeds",
      justified.code !== UNJUSTIFIED_SKIP_EXIT,
      "exit " + justified.code + ": " + tail(justified.out, 6));
    count("justified skip: the bypass is announced rather than silent",
      /SERVICE PRE-FLIGHT SKIPPED BY OPERATOR OVERRIDE/.test(justified.out),
      tail(justified.out, 10));
    count("justified skip: and the reason is in the transcript",
      justified.out.indexOf("the stack is up under a different runner") !== -1,
      tail(justified.out, 10));
    count("justified skip: and the pre-flight really did not run",
      justified.out.indexOf("[check-services]") === -1, tail(justified.out, 10));
  } finally {
    helpers.removeTempDir(dir);
  }
}

// Every capability in the table is claimed by a file in the suite.
//
// The runner refuses a run that located none of the clients its files
// need, so an entry nothing claims would be a client the gate insists on
// for cases that do not exist. The reconciliation runs both ways for the
// reason the greeting parity in the service gate does: an id claimed by
// a file and absent from the table throws at the first call, and an id
// in the table that nothing claims fails silently and forever.
function theClientTableAndTheFilesAgree() {
  var files = nodeFs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); });

  // Canary: a scan that found no file would satisfy the reconciliation
  // below without reading anything.
  count("client table: there are interop files to reconcile against",
    files.length > 0, files.join(", "));
  count("client table: it carries capabilities to reconcile",
    clients.IDS.length > 0, clients.IDS.join(", "));

  var claimed = {};
  files.forEach(function (name) {
    var source = nodeFs.readFileSync(nodePath.join(INTEGRATION_DIR, name), "utf8");
    clients.claimedBy(source).forEach(function (id) { claimed[id] = name; });
  });

  var orphaned = clients.IDS.filter(function (id) { return claimed[id] === undefined; });
  count("client table: every registered capability is claimed by a file",
    orphaned.length === 0,
    orphaned.length === 0 ? Object.keys(claimed).join(", ")
      : "claimed by nothing: " + orphaned.join(", ") + ". The runner looks for every client " +
        "its selected files claim, so an entry nothing claims is a client it can never be " +
        "asked for and never report on.");
}

// The runner and the layered suites answer different questions, and the
// cheap way to make this command pass is to point it at the suite that
// already runs. That would report a green interop gate for files that
// never speak to anything outside this codebase, and would run them
// twice.
async function theRunnerIsNotPointedAtTheLayeredSuites() {
  var rv = await runNode(["scripts/test-integration.js"]);
  var namesALayer = /layer-\d+-/.test(rv.out);
  count("suite target: the runner does not read a layered suite directory",
    namesALayer === false, rv.out.trim());

  var layered = nodeFs.readdirSync(nodePath.join(helpers.REPO_ROOT, "test"), { withFileTypes: true })
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .map(function (e) { return e.name; });
  // Canary: a scan that finds no layered suite would agree with anything.
  count("suite target: the layered suites are still where they were",
    layered.length >= 3, layered.join(", "));
  count("suite target: the interop suite is not one of them",
    layered.indexOf("integration") === -1, layered.join(", "));
}

async function run() {
  theSuiteDirectoryIsTracked();
  theClientTableAndTheFilesAgree();
  await anEmptySuiteReportsNothingProven();
  await theReleaseFlowPublishesTheGateAsNotRun();
  await aRunThatLocatedNoClientIsRefused();
  await aRunThatLocatedItsClientsStillPasses();
  await anUnjustifiedServiceSkipIsRefused();
  await theRunnerIsNotPointedAtTheLayeredSuites();
  return helpers.getChecks();
}

module.exports = { name: "interop-gate-contract", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
