// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One port value, four places that have to agree.
 *
 * The compose stack sets the browser, admin and JMAP port once. The
 * published port, the environment the container reads, the health probe
 * inside it and the optional terminator upstream all derive from that
 * one value. Any of them carrying its own copy is a defect with a
 * particularly quiet failure: the probe checks a port nothing binds,
 * calls a healthy server unhealthy, and the restart policy takes the
 * mail server down on a timer.
 *
 * That defect was found by reading the file rather than by running
 * anything, which is why this exists. Compose resolves the interpolation
 * itself, so asking it to render the stack is asking the same parser the
 * operator's own `docker compose up` uses, rather than re-implementing
 * the substitution here and agreeing with a mistake.
 *
 * It is rendered twice, at two values, neither of them the default. A
 * single render at the default passes against a file with the number
 * hardcoded in all four places, which is the exact shape being ruled
 * out.
 *
 * Two neighbors of that claim are settled here as well, because both
 * are the same mechanism.
 *
 * Compose injects only the variables it names, so one a settings
 * reference documents and this file never names reaches nothing at all:
 * the listener stays where the image baked it and the operator is told
 * no different. The TLS port was in exactly that position, so it is
 * moved here too, and the absence of the per listener port variables is
 * asserted rather than assumed so that stack's choice of the sysctl path
 * stays a decision.
 *
 * And the terminator's configuration is run through the terminator's own
 * parser at the version the stack pins. Nothing else reads that file, so
 * a directive that stopped being valid, or one the terminator itself
 * calls unnecessary, showed up as a warning at every start and reached
 * every operator who brought the profile up.
 *
 * Run standalone: node test/layer-2-integration/compose-port-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var harness = require("./container-harness");

// Two values, neither the shipped default, so a hardcoded 8080 fails on
// the first render rather than passing on both.
var FIRST_PORT  = 9797;
var SECOND_PORT = 18081;
var DEFAULT_PORT     = 8080;
var DEFAULT_TLS_PORT = 8443;

// The mail ports the stack publishes one to one. They are not derived
// from a variable, because a receiving MTA finds this server at 25 and
// nowhere else.
var FIXED_PUBLISHED = ["25:25", "465:465", "587:587", "143:143", "4190:4190"];

var count = helpers.count;

// Renders the stack the way compose renders it for an operator, with
// the optional terminator included so its upstream is in the answer.
//
// `overrides` names the variables an operator would put in their .env.
// Anything absent from it is deleted from the environment first, so a
// value this shell happens to carry cannot decide the answer.
async function render(overrides) {
  var env = Object.assign({}, process.env, {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_VAULT_PASSPHRASE: "a long enough vault passphrase for one render",
  });
  ["BLAMEPOST_HTTP_PORT", "BLAMEPOST_HTTPS_PORT", "BLAMEPOST_MX_PORT"]
    .forEach(function (name) { delete env[name]; });
  Object.keys(overrides || {}).forEach(function (name) {
    env[name] = String(overrides[name]);
  });
  var rv = await harness.dockerOrThrow(
    ["compose", "--profile", "tls", "config", "--format", "json"],
    "rendering compose.yml with " + JSON.stringify(overrides || {}),
    { env: env });
  return JSON.parse(rv.stdout);
}

function publishedPairs(service) {
  return (service.ports || []).map(function (p) {
    return String(p.published) + ":" + String(p.target);
  });
}

// Every place the value has to reach, read out of one render.
function readsOf(rendered) {
  var app   = rendered.services.blamepost;
  var caddy = rendered.services.caddy;
  return {
    published:   publishedPairs(app),
    env:         app.environment.BLAMEPOST_HTTP_PORT,
    tlsEnv:      app.environment.BLAMEPOST_HTTPS_PORT,
    mxEnv:       app.environment.BLAMEPOST_MX_PORT,
    probe:       (app.healthcheck && app.healthcheck.test) || [],
    terminator:  caddy && caddy.environment && caddy.environment.BLAMEPOST_HTTP_PORT,
    volumes:     (app.volumes || []).map(function (v) { return v.target; }),
    capDrop:     app.cap_drop || [],
    securityOpt: app.security_opt || [],
    sysctls:     app.sysctls || {},
  };
}

function theValueReachesEveryPlace(seen, port) {
  var pair = port + ":" + port;
  count("the published port follows the value at " + port,
    seen.published.indexOf(pair) !== -1, seen.published.join(" "));
  count("the container environment follows the value at " + port,
    String(seen.env) === String(port), String(seen.env));
  count("the optional terminator upstream follows the value at " + port,
    String(seen.terminator) === String(port), String(seen.terminator));
  count("the health probe reads that same environment value rather than a copy of " +
    "the number, at " + port,
    seen.probe.join(" ").indexOf("BLAMEPOST_HTTP_PORT") !== -1, seen.probe.join(" "));
  count("no stale default is left published beside the moved port, at " + port,
    seen.published.indexOf(DEFAULT_PORT + ":" + DEFAULT_PORT) === -1,
    seen.published.join(" "));
}

// The terminator's own parser, over the configuration this repository
// ships, at the version this stack pins. Nothing else reads that file,
// so a directive that stopped being valid, or one the terminator itself
// calls unnecessary, reached every operator who brought the profile up
// and showed as a warning at every start. Warnings that always appear
// are warnings nobody reads.
//
// The image reference comes from the rendered stack rather than from a
// constant here, so the file cannot be validated against a version the
// stack does not run.
async function theTerminatorAcceptsTheConfiguration(repoRoot, rendered) {
  var image = rendered.services.caddy.image;
  var rv = await harness.docker([
    "run", "--rm",
    "--volume", nodePath.join(repoRoot, "docker", "caddy", "Caddyfile") +
      ":/etc/caddy/Caddyfile:ro",
    "--env", "BLAMEPOST_WEB_HOSTNAME=mail.example.com",
    "--env", "BLAMEPOST_HTTP_PORT=" + DEFAULT_PORT,
    "--entrypoint", "caddy", image, "validate", "--config", "/etc/caddy/Caddyfile",
  ], { timeoutMs: 180000 });
  var said = rv.stdout + rv.stderr;
  count("the terminator accepts the configuration this repository ships",
    rv.code === 0 && said.indexOf("Valid configuration") !== -1,
    "exit " + rv.code + " " + said.trim().split("\n").slice(-3).join(" | "));
  var warnings = said.split("\n").filter(function (line) {
    return line.indexOf("\"level\":\"warn\"") !== -1;
  });
  count("it accepts the configuration without a warning, so a start that does warn " +
    "is telling the operator something new",
    warnings.length === 0, warnings.join(" | ").slice(0, 400));
}

// The terminator's own configuration is a file rather than a compose
// value, so it is read directly. Compose hands it the variable; the
// Caddyfile has to be the thing that consumes it.
function theTerminatorConfigurationConsumesTheVariable(repoRoot) {
  var text = nodeFs.readFileSync(
    nodePath.join(repoRoot, "docker", "caddy", "Caddyfile"), "utf8");
  var upstream = /reverse_proxy\s+blamepost:\{\$BLAMEPOST_HTTP_PORT:(\d+)\}/.exec(text);
  count("the terminator proxies to the port variable rather than to a fixed number",
    upstream !== null, text.split("\n").filter(function (l) {
      return l.indexOf("reverse_proxy") !== -1;
    }).join(" "));
  count("its fallback is the same default the application uses, so a stack that " +
    "never sets the variable still resolves to one port",
    upstream !== null && parseInt(upstream[1], 10) === DEFAULT_PORT,
    upstream && upstream[1]);
  // The claim the file makes about itself, held against the file it
  // makes the claim about rather than against a path written here. A
  // literal pinned in this test agrees with the Caddyfile and says
  // nothing about the image, so the two could be moved apart one at a
  // time with this check still green, which is the state the comment in
  // the Caddyfile was already in: it named the readiness endpoint while
  // configuring the liveness one, and the assertion agreed with the
  // configuration and not with the sentence.
  var terminatorPath = /health_uri\s+(\/\S+)/.exec(text);
  var dockerfile = nodeFs.readFileSync(nodePath.join(repoRoot, "Dockerfile"), "utf8");
  var probePath = /HEALTHCHECK[\s\S]*?127\.0\.0\.1[^\n]*?(\/[a-z]+)'\)/.exec(dockerfile);
  count("the terminator names a health path at all",
    terminatorPath !== null, text.slice(0, 200));
  count("the image's own probe names one too, so there is something to compare it against",
    probePath !== null, dockerfile.slice(dockerfile.indexOf("HEALTHCHECK"), 400));
  count("and the two are the same endpoint, which is what the terminator's configuration " +
    "says of itself",
    terminatorPath !== null && probePath !== null && terminatorPath[1] === probePath[1],
    JSON.stringify({
      terminator: terminatorPath && terminatorPath[1],
      probe:      probePath && probePath[1],
    }));
}

function theHardeningPostureIsDeclared(seen) {
  count("the stack drops every Linux capability",
    seen.capDrop.indexOf("ALL") !== -1, seen.capDrop.join(" "));
  count("the stack refuses privilege escalation",
    seen.securityOpt.indexOf("no-new-privileges:true") !== -1, seen.securityOpt.join(" "));
  count("the stack lowers the unprivileged port floor inside its own network namespace " +
    "rather than granting a capability back",
    String(seen.sysctls["net.ipv4.ip_unprivileged_port_start"]) === "0",
    JSON.stringify(seen.sysctls));
  count("exactly one volume is mounted, at the documented data path",
    seen.volumes.length === 1 && seen.volumes[0] === harness.DATA_PATH,
    seen.volumes.join(" "));
}

function theMailPortsArePublishedWhereReceiversLook(seen) {
  FIXED_PUBLISHED.forEach(function (pair) {
    count("the stack publishes " + pair, seen.published.indexOf(pair) !== -1,
      seen.published.join(" "));
  });
  count("POP3 is not published, because it is off unless an operator asks for it",
    seen.published.indexOf("110:110") === -1, seen.published.join(" "));
}

// The TLS half of the same surface. Compose injects only the variables
// it names, so one that a settings reference documents and this file
// never names reaches nothing at all: the listener stays where the image
// baked it and the operator sees no error. That is the same shape as a
// variable read by nothing, and it looks exactly like one that works.
function theTlsPortFollowsItsOwnValue(seen, port) {
  count("the TLS listener follows the value it is given, at " + port,
    String(seen.tlsEnv) === String(port), String(seen.tlsEnv));
  count("the published TLS port follows the same value, at " + port,
    seen.published.indexOf(port + ":" + port) !== -1, seen.published.join(" "));
}

// The per listener port variables are deliberately not a knob in this
// stack: it lowers the unprivileged port floor instead, so the listeners
// sit on the standard ports and the peer address is not rewritten.
// Asserting the absence keeps that a decision rather than an oversight,
// and demonstrates the mechanism the check above depends on.
function anUnnamedVariableReachesNothing(seen) {
  count("a variable this stack does not name reaches nothing inside the container, " +
    "which is why every knob the stack means to expose has to be named",
    seen.mxEnv === undefined, String(seen.mxEnv));
}

// compose.yml restates the probe the image already declares. A second
// copy of one expression is a drift surface, so the two are compared
// rather than trusted: an edit to either that is not made to both fails
// here instead of at three in the morning, when a probe pointed at a
// port nothing binds restarts a healthy mail server on a timer.
async function theProbeInBothPlacesIsOneProbe(seen, image) {
  var declared = (await harness.inspect(image)).Config.Healthcheck;
  var imageTest = (declared && declared.Test) || [];
  count("the image declares a health probe of its own", imageTest.length > 0);
  count("the probe compose sets is the probe the image declares, character for character",
    JSON.stringify(seen.probe) === JSON.stringify(imageTest),
    JSON.stringify(seen.probe) + " against " + JSON.stringify(imageTest));
}

async function run() {
  await harness.requireStack("compose-port-parity.test.js");

  var firstRender = await render({
    BLAMEPOST_HTTP_PORT: FIRST_PORT, BLAMEPOST_HTTPS_PORT: FIRST_PORT + 1,
  });
  var first  = readsOf(firstRender);
  var second = readsOf(await render({
    BLAMEPOST_HTTP_PORT: SECOND_PORT, BLAMEPOST_HTTPS_PORT: SECOND_PORT + 1,
  }));
  var unset  = readsOf(await render({ BLAMEPOST_MX_PORT: 2525 }));

  theValueReachesEveryPlace(first, FIRST_PORT);
  theValueReachesEveryPlace(second, SECOND_PORT);
  theTlsPortFollowsItsOwnValue(first, FIRST_PORT + 1);
  theTlsPortFollowsItsOwnValue(second, SECOND_PORT + 1);
  anUnnamedVariableReachesNothing(unset);

  count("moving the value moved the published port rather than leaving it where it was",
    first.published.indexOf(FIRST_PORT + ":" + FIRST_PORT) !== -1 &&
    second.published.indexOf(FIRST_PORT + ":" + FIRST_PORT) === -1,
    first.published.join(" ") + " then " + second.published.join(" "));
  count("moving the value moved the terminator upstream with it",
    String(first.terminator) !== String(second.terminator),
    first.terminator + " then " + second.terminator);

  count("a stack that sets nothing still resolves to the application's own default",
    String(unset.env) === String(DEFAULT_PORT) &&
    unset.published.indexOf(DEFAULT_PORT + ":" + DEFAULT_PORT) !== -1,
    unset.env + " " + unset.published.join(" "));
  count("the terminator inherits that same default when nothing is set",
    String(unset.terminator) === String(DEFAULT_PORT), String(unset.terminator));
  count("the TLS surface inherits its own default when nothing is set",
    String(unset.tlsEnv) === String(DEFAULT_TLS_PORT) &&
    unset.published.indexOf(DEFAULT_TLS_PORT + ":" + DEFAULT_TLS_PORT) !== -1,
    unset.tlsEnv + " " + unset.published.join(" "));

  theTerminatorConfigurationConsumesTheVariable(helpers.REPO_ROOT);
  await theTerminatorAcceptsTheConfiguration(helpers.REPO_ROOT, firstRender);
  theHardeningPostureIsDeclared(first);
  theMailPortsArePublishedWhereReceiversLook(first);
  await theProbeInBothPlacesIsOneProbe(first, await harness.buildImage());

  return helpers.getChecks();
}

module.exports = { name: "compose-port-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
