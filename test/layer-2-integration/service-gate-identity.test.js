// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The gate that decides the stack is up has to be talking to this
 * server.
 *
 * `scripts/test-integration.js` will not spawn an interop file until
 * `scripts/check-services.js` says every listener is answering, so that
 * script is the instrument every interop result rests on. An instrument
 * that pins something adjacent to what matters is worse than none,
 * because everything downstream of it reports green about the wrong
 * subject.
 *
 * It was measured being wrong on an ordinary developer machine. Another
 * project's container held the port the browser surface is documented
 * on and answered the health path 200; a scratch proxy held 993, which
 * this server does not bind at all; and this server's own web listener,
 * moved to a free port, was never contacted. The gate printed that
 * every required endpoint was responding. Nothing in that report was
 * false and none of it was about blamepost.
 *
 * ## What is asserted
 *
 * Two things, and they fail for different reasons.
 *
 * The BEHAVIOR: a listener that speaks the right protocol and is not
 * this server has to be refused. Four shapes, each one a thing that has
 * really held one of these ports: another MTA's banner, another mailbox
 * server's greeting, somebody else's health endpoint, and a TLS
 * terminator that completes a handshake and speaks nothing behind it.
 * A fifth shape is this server's own version answered by a build that
 * is not the one under test, which is the stale process left over from
 * an earlier run and the case a name check alone cannot see.
 *
 * The LINK: the greeting patterns the gate matches against are written
 * out in the gate, because importing them would pull the framework and
 * the store into a script that runs before anything is known to be up.
 * Two copies of one vocabulary drift, and the direction that drifts
 * silently is the gate quietly ceasing to recognize its own server. So
 * the greetings `lib/mail/listeners.js` actually composes are read here
 * and reconciled against those patterns BOTH ways: every greeting is
 * matched by a pattern, and every pattern matches a greeting.
 *
 * ## Why the fixtures are their own process
 *
 * A listener bound inside this process is not reachable from a child on
 * every machine this suite runs on, and the gate under test is
 * necessarily a child. So the fixtures bind in their own process and
 * both ends are ordinary processes over loopback. It also means a
 * fixture that wedges is killed rather than left holding a port inside
 * the runner.
 *
 * Every case drives the SHIPPED script, spawned the way the interop
 * runner spawns it, and reads its exit code and its table. A case that
 * called an exported predicate would assert on a function while the
 * script kept its own opinion about ports, hosts and what counts as an
 * answer.
 *
 * Run standalone: node test/layer-2-integration/service-gate-identity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var { spawn } = require("node:child_process");

var helpers  = require("../helpers");
var certs    = require("../helpers/certs");
var spawnRun = require("../helpers/spawn");

var gate = require("../../scripts/check-services");
var pkg  = require("../../package.json");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var FIXTURE = nodePath.join(helpers.REPO_ROOT, "test", "layer-2-integration",
  "service-gate-fixture.js");
var CHECK_SERVICES = nodePath.join("scripts", "check-services.js");

// Short, because two of the cases below are a probe that has to give up
// on a listener that never speaks, and the file should not spend four
// seconds each proving it.
var PROBE_TIMEOUT_MS   = 1500;
var GATE_CEILING_MS    = 30000;
var FIXTURE_CEILING_MS = 20000;

// The name and shape this server puts on the wire, restated here as the
// thing the fixtures imitate. The host name is the operator's, so the
// fixture picks one and the gate must not be matching on it.
var HOSTNAME = "mx.example.com";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// One fixture process holding every listener a scenario needs.
// Resolves once it has announced its ports, so a gate is never started
// against a half-bound fixture.
function startFixture(specs, tlsFiles) {
  return new Promise(function (resolve, reject) {
    var argv = [FIXTURE, JSON.stringify(specs)];
    if (tlsFiles) argv.push(tlsFiles.certFile, tlsFiles.keyFile);
    var child = spawn(process.execPath, argv, { stdio: ["ignore", "pipe", "pipe"] });
    var out = "";
    var settled = false;
    var ceiling = setTimeout(function () {
      if (settled) return;
      settled = true;
      try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      reject(new Error("service-gate fixture never announced its ports within " +
        FIXTURE_CEILING_MS + "ms. It said: " + JSON.stringify(out.slice(0, 300))));
    }, FIXTURE_CEILING_MS);
    child.stdout.on("data", function (d) {
      out += d.toString();
      var m = /PORTS (\[[^\]]*\])/.exec(out);
      if (!m || settled) return;
      settled = true;
      clearTimeout(ceiling);
      resolve({ ports: JSON.parse(m[1]), pid: child.pid, stop: function () {
        try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      } });
    });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.once("error", function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      reject(e);
    });
    child.once("close", function (code) {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      reject(new Error("service-gate fixture exited " + code + " before binding. It said: " +
        JSON.stringify(out.slice(0, 300))));
    });
  });
}

// Run the shipped gate against a fixture, naming only the rows the
// scenario is about. The port override is the same one an operator uses
// for a deployment that moved a port, so nothing here reaches a code
// path a real run does not.
async function runGate(names, ports, extra) {
  var pairs = names.map(function (n, i) { return n + "=" + ports[i]; }).join(",");
  var env = Object.assign({}, process.env, {
    BLAMEPOST_SERVICE_HOST:             "127.0.0.1",
    BLAMEPOST_SERVICE_PORTS:            pairs,
    BLAMEPOST_SERVICE_PROBE_TIMEOUT_MS: String(PROBE_TIMEOUT_MS),
  });
  // The gate reads these for the browser surface, and a machine that has
  // them set for a real server would otherwise move the row out from
  // under the fixture the scenario just bound. The same goes for the
  // process pin and the declaration that turns the attribution off:
  // a scenario that did not ask for either has to run without one.
  delete env.BLAMEPOST_HTTP_PORT;
  delete env.BLAMEPOST_HTTPS_PORT;
  delete env.BLAMEPOST_SERVICE_PID;
  delete env.BLAMEPOST_SERVICE_PROCESS_CHECK;
  Object.assign(env, extra || {});
  return await spawnRun.runNodeScript([CHECK_SERVICES].concat(names), {
    cwd:       helpers.REPO_ROOT,
    env:       env,
    ceilingMs: GATE_CEILING_MS,
  });
}

// One scenario: bind, probe, report, tear down. The teardown is in a
// finally, because a fixture left holding a port outlives the run and
// the next scenario's bind lands somewhere else.
async function scenario(spec) {
  var up = await startFixture(spec.listeners, spec.tls);
  try {
    var rv = await runGate(spec.names, up.ports);
    count(spec.label,
      spec.expectRefused ? rv.code !== 0 : rv.code === 0,
      "exit " + rv.code + (rv.ceilingHit ? " (ceiling hit)" : "") + ": " + tail(rv.out, 3));
    if (spec.says) {
      count(spec.label + ", and says why",
        spec.says.test(rv.out), tail(rv.out, 3));
    }
    return rv;
  } finally {
    up.stop();
  }
}

// ---------------------------------------------------------------------------
// The behavior
// ---------------------------------------------------------------------------

async function aForeignListenerIsRefused(tls) {
  // Another MTA on the port this server's inbound listener takes. It
  // answers 220, it is a perfectly good SMTP server, and it is not
  // this one.
  await scenario({
    label:  "a different MTA answering on the inbound port is refused",
    names:  ["mx"],
    expectRefused: true,
    says:   /not this server/,
    listeners: [{ kind: "line", text: "220 relay.example.org ESMTP Postfix\r\n" }],
  });

  // Another mailbox server on 143. It even advertises IMAP4rev2.
  await scenario({
    label:  "a different mailbox server answering on the IMAP port is refused",
    names:  ["imap"],
    expectRefused: true,
    says:   /not this server/,
    listeners: [{ kind: "line",
      text: "* OK [CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN] Dovecot ready.\r\n" }],
  });

  // Somebody else's health endpoint. This is the shape that was
  // measured passing: a 2xx with a plausible body and nothing in it
  // that says whose it is.
  await scenario({
    label:  "another project's health endpoint answering 200 is refused",
    names:  ["http"],
    expectRefused: true,
    says:   /not this server's health report|without saying what it is/,
    listeners: [{ kind: "http", body: "{\"status\":\"ok\"}" }],
  });

  // The submission listener's implicit-TLS port, held by something that
  // completes a handshake and speaks nothing. A gate that stopped at
  // the handshake recorded this as a listener that was up.
  await scenario({
    label:  "a bare TLS terminator on the implicit-TLS port is refused",
    names:  ["submissions"],
    expectRefused: true,
    says:   /timeout|greeting/,
    tls:    tls,
    listeners: [{ kind: "hush" }],
  });
}

// The one a name check cannot see. It IS this server, answering
// correctly, and it is a different build from the tree under test:
// the orphaned process from an earlier run, serving another data
// directory.
async function aStaleBuildOfThisServerIsRefused() {
  await scenario({
    label:  "this server at another version, left over from an earlier run, is refused",
    names:  ["http"],
    expectRefused: true,
    says:   /left over from an earlier run/,
    listeners: [{ kind: "http",
      body: JSON.stringify({ status: "ok", version: "0.0.0-stale" }) }],
  });
}

// What this server puts on the wire, as one listener set. Two processes
// serving it are indistinguishable to every probe the gate makes: the
// same greetings, the same protocol words, the same build reported at
// the health path.
function thisServersSignals() {
  return [
    { kind: "line", text: "220 " + HOSTNAME + " ESMTP blamepost ready\r\n" },
    { kind: "line", text: "* OK [CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN] " +
      HOSTNAME + " IMAP4rev2 blamepost\r\n" },
    { kind: "http", body: JSON.stringify({ status: "ok", version: pkg.version }) },
  ];
}

// The case neither signal above can see.
//
// A greeting says which SOFTWARE answered and a version says which
// BUILD. Two processes running the same build have neither to separate
// them, and that pair is the ordinary state of a developer machine: a
// server started for an earlier session is still holding the mail ports
// while the one under test binds what is left. Measured on this
// machine, with a blamepost from a previous week on 25, 143, 465, 587
// and 4190 and no version bump between them, the gate reported five
// endpoints answering as this server and exited zero.
//
// So the gate is shown two processes emitting the same bytes and asked
// which one it is talking to. Both are started for every case here
// rather than one being reused, because the whole assertion is about
// telling apart two things a probe cannot.
async function aSecondInstanceOfThisSoftwareIsRefused() {
  var underTest = await startFixture(thisServersSignals());
  var other     = null;
  try {
    other = await startFixture(thisServersSignals());

    // Canary first. The two are byte-identical on the wire, so a gate
    // that refused both would satisfy every assertion below while
    // failing the stack it exists to admit.
    var alone = await runGate(["mx", "imap", "http"], underTest.ports);
    count("two instances: the one under test is still accepted on its own",
      alone.code === 0, "exit " + alone.code + ": " + tail(alone.out, 3));

    // The measured shape: the browser surface is the process under test
    // and the mail ports are the older one. This is the combination that
    // used to pass, and the one that would have run the whole interop
    // suite against a build nobody was testing.
    var mixed = await runGate(["mx", "imap", "http"],
      [other.ports[0], other.ports[1], underTest.ports[2]]);
    count("two instances: mail ports held by the other process are refused",
      mixed.code !== 0, "exit " + mixed.code + ": " + tail(mixed.out, 4));
    count("two instances: and the refusal names both process ids",
      /DIFFERENT PROCESS/.test(mixed.out) &&
      mixed.out.indexOf("pid " + other.pid) !== -1 &&
      mixed.out.indexOf("pid " + underTest.pid) !== -1,
      tail(mixed.out, 4));

    // The other half. Every row is the other process, coherently, so
    // nothing in the probe set disagrees with anything else and only the
    // caller naming what it started can say this is the wrong server.
    var pinned = await runGate(["mx", "imap", "http"], other.ports,
      { BLAMEPOST_SERVICE_PID: String(underTest.pid) });
    count("two instances: a whole coherent stack that is the wrong process is refused",
      pinned.code !== 0, "exit " + pinned.code + ": " + tail(pinned.out, 4));
    count("two instances: and the refusal names the pin it was measured against",
      /BLAMEPOST_SERVICE_PID/.test(pinned.out), tail(pinned.out, 4));

    // Without the pin, that same coherent stack passes, and the reason
    // is worth pinning here rather than discovering later: a run with no
    // caller to name the process derives one from the rows it has, so a
    // stack entirely served by the wrong process agrees with itself.
    // The pin is what closes that, and this case is what says so.
    var coherent = await runGate(["mx", "imap", "http"], other.ports);
    count("two instances: with no pin, a wholly coherent wrong stack is not separable",
      coherent.code === 0, "exit " + coherent.code + ": " + tail(coherent.out, 3));

    // The declaration, which is the only way past the attribution and
    // says so in the transcript rather than silently.
    var off = await runGate(["mx", "imap", "http"],
      [other.ports[0], other.ports[1], underTest.ports[2]],
      { BLAMEPOST_SERVICE_PROCESS_CHECK: "off" });
    count("two instances: the declaration turns the attribution off",
      off.code === 0, "exit " + off.code + ": " + tail(off.out, 3));
    count("two instances: and the transcript says no row was attributed",
      /no row below is attributed to a process/.test(off.out), tail(off.out, 4));
  } finally {
    underTest.stop();
    if (other !== null) other.stop();
  }
}

// Canary. Every case above would also be reported by a gate that
// refused everything, and a gate that refused everything would fail the
// stack it exists to admit. These are the same fixtures saying what
// this server says, and they have to be accepted.
async function whatThisServerSaysIsAccepted(tls) {
  await scenario({
    label:  "canary: this server's own greetings and health report are accepted",
    names:  ["mx", "imap", "http"],
    expectRefused: false,
    listeners: [
      { kind: "line", text: "220 " + HOSTNAME + " ESMTP blamepost ready\r\n" },
      { kind: "line", text: "* OK [CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN] " +
        HOSTNAME + " IMAP4rev2 blamepost\r\n" },
      { kind: "http", body: JSON.stringify({ status: "ok", version: pkg.version }) },
    ],
  });

  await scenario({
    label:  "canary: the implicit-TLS port is accepted when the protocol is behind it",
    names:  ["submissions"],
    expectRefused: false,
    tls:    tls,
    listeners: [{ kind: "tls", text: "220 " + HOSTNAME + " Submission blamepost ready\r\n" }],
  });
}

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

// The wire prefix each greeting arrives behind, so what is reconciled
// is the line a client reads rather than the fragment this repository
// concatenates. The IMAP capability code is the framework's and its
// contents do not matter here; what matters is that a pattern written
// for a greeting is tested against the shape the greeting is delivered
// in.
var WIRE_FORM = Object.freeze({
  ESMTP:      function (g) { return "220 " + g + " ready\r\n"; },
  Submission: function (g) { return "220 " + g + " ready\r\n"; },
  IMAP4rev2:  function (g) { return "* OK [CAPABILITY IMAP4rev2 STARTTLS] " + g + "\r\n"; },
  POP3:       function (g) { return "+OK " + g + " ready\r\n"; },
  ManageSieve: function (g) { return "OK \"" + g + " ready\"\r\n"; },
});

// The greetings lib/mail/listeners.js composes, read out of the source.
// Every one is `hostname + " <protocol> blamepost"`, and the host name
// is substituted here because it is the operator's at run time.
function composedGreetings() {
  var source = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, "lib", "mail", "listeners.js"), "utf8");
  var out = [];
  var re = /greeting:\s*hostname \+ "([^"]+)"/g;
  var m;
  while ((m = re.exec(source)) !== null) out.push(HOSTNAME + m[1]);
  return out;
}

function theGateRecognizesEveryGreetingThisServerSends() {
  var greetings = composedGreetings();

  // Canary: a scan that found nothing would satisfy one half of the
  // reconciliation below and say nothing at all.
  count("parity: the listener module still composes greetings this can read",
    greetings.length >= 5, greetings.length + " found: " + greetings.join(" | "));

  var patterns = gate.GREETING_IDENTITY;
  var patternNames = Object.keys(patterns);
  count("parity: the gate still carries identity patterns to reconcile against",
    patternNames.length >= 5, patternNames.join(", "));

  var matchedBy = {};
  greetings.forEach(function (greeting) {
    var word = (/ (ESMTP|Submission|IMAP4rev2|POP3|ManageSieve) /.exec(greeting + " ") || [])[1];
    count("parity: the greeting " + JSON.stringify(greeting) + " names a protocol with a wire form",
      Boolean(word && WIRE_FORM[word]), String(word));
    if (!word || !WIRE_FORM[word]) return;
    var line = WIRE_FORM[word](greeting);
    var hits = patternNames.filter(function (name) { return patterns[name].test(line); });
    hits.forEach(function (name) { matchedBy[name] = true; });
    count("parity: the gate recognizes " + JSON.stringify(greeting) + " on the wire",
      hits.length > 0,
      "no pattern in check-services.js matched " + JSON.stringify(line) +
        ". A greeting reworded in lib/mail/listeners.js has to be reworded there too, " +
        "or the gate stops recognizing this server and reports the stack as down.");
  });

  var orphaned = patternNames.filter(function (name) { return !matchedBy[name]; });
  count("parity: no identity pattern in the gate matches a greeting nothing sends",
    orphaned.length === 0,
    orphaned.length === 0 ? "every pattern is reachable"
      : "unreachable: " + orphaned.join(", ") + ". A pattern that matches no greeting " +
        "this server composes cannot refuse an impostor either.");
}

// The port this server does not bind cannot be a required row: a
// required probe for a port nothing serves can only pass when something
// else is holding it.
function nothingRequiresAPortThisServerDoesNotBind() {
  var byName = {};
  gate.BASE_SERVICES.forEach(function (s) { byName[s.name] = s; });

  count("the gate still has a row for the implicit-TLS mailbox port",
    Boolean(byName.imaps), Object.keys(byName).join(", "));
  count("and it is not required, because this server binds no 993",
    byName.imaps && byName.imaps.required === false,
    "required: " + (byName.imaps && byName.imaps.required));

  var listeners = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, "lib", "mail", "listeners.js"), "utf8");
  count("and the listener module still binds no 993 for it to have required",
    /port:\s*993/.test(listeners) === false,
    "a 993 bind in lib/mail/listeners.js would make this row required again");

  var requiredKinds = gate.BASE_SERVICES
    .filter(function (s) { return s.required; })
    .filter(function (s) { return s.kind === "tcp"; });
  count("no required row is satisfied by a bare TCP accept",
    requiredKinds.length === 0,
    requiredKinds.map(function (s) { return s.name; }).join(", "));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  theGateRecognizesEveryGreetingThisServerSends();
  nothingRequiresAPortThisServerDoesNotBind();

  var workDir = helpers.tempDir("service-gate-identity");
  try {
    // The fixture's own certificate. The default algorithm, because both
    // ends here are this runtime and the chain is not what any case is
    // about; the gate does not verify it and says so.
    var material = await certs.writePair(nodePath.join(workDir, "tls"), { hostname: HOSTNAME });
    var tls = { certFile: material.certFile, keyFile: material.keyFile };

    await aForeignListenerIsRefused(tls);
    await aStaleBuildOfThisServerIsRefused();
    await aSecondInstanceOfThisSoftwareIsRefused();
    await whatThisServerSaysIsAccepted(tls);
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(workDir);
  }
}

module.exports = { name: "service-gate-identity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
