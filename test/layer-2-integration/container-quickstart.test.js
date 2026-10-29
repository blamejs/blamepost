// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The quick start, typed the way the documents type it, against the
 * image the tree builds.
 *
 * The claim under test is the one an operator cares about most: follow
 * the published sequence and you end up with a mail server you can sign
 * in to. Every step here is a step a document tells someone to run, in
 * the order it tells them to run it, and each is driven from outside the
 * container by an ordinary client.
 *
 * Three things this catches that nothing in the suite could.
 *
 * Whether the server starts at all under the shipped image. The
 * production posture assertion reads the mode of the data directory, and
 * the data directory is something the image ships and a fresh volume
 * inherits. A refusal there is invisible from every in process fixture,
 * because a fixture makes its own directory.
 *
 * Whether `serve` leaves an operator able to sign in. It does not, and
 * that was documented the other way round for a long time. `init` is the
 * only command that creates an account, so the sequence is driven with
 * the administrator variables already set, a sign in attempted before
 * `init` runs and refused, `init` run, and the same sign in attempted
 * again and accepted. The refusal is the assertion; a run that only did
 * the second half would pass against a server that had silently created
 * the account at boot, which is precisely the behavior the documents
 * used to claim.
 *
 * Whether the port the documents send an operator to is the port that
 * takes a password. This server accepts a credential over TLS, from a
 * peer a named proxy speaks for, or from loopback, and from nowhere
 * else. A request published out of a container arrives from the bridge
 * gateway rather than from the loopback interface, so the cleartext port
 * refuses one whatever address the host dialed, and the TLS port is
 * where the first sign in happens. Both directions are driven here: the
 * form renders and a correct password is accepted on 8443, and the same
 * password is refused on 8080 with no session written. A run that only
 * proved the refusal would pass against a server nobody can sign in to.
 *
 * And whether either documented way of reaching the mail ports works.
 * The default lowers the unprivileged port floor inside the container's
 * own network namespace and lets the listeners take 25, 465, 587, 143
 * and 4190 directly; the alternative moves them with the per listener
 * port variables and publishes the standard ports on the host. Both are
 * driven here, because the per listener variables were read by nothing
 * until recently and a variable that is read by nothing looks exactly
 * like one that works. The listening sockets are enumerated from inside
 * the container in both cases, so the answer comes from the kernel
 * rather than from a port forwarder that accepts and then finds nothing
 * to hand the connection to.
 *
 * The default is driven at both ends of the one transition that decides
 * it. Port 25 is enumerated on a fresh volume, where it is shut because
 * no domain is hosted, and again once `init` has created one and
 * `domain acknowledge` has recorded its posture, where it is bound. The
 * same reader answers both times, so the pair measures a state change
 * rather than agreeing by coincidence, and neither half is a claim about
 * a flag that was passed.
 *
 * POP3 is measured the same way, and it is the listener that most needed
 * it. It is the one an operator switches on by hand, so the only state a
 * container had ever held it in was the state where it is off, and an
 * unbound port is the same answer whether the listener works or not.
 * Both states are driven now. The run that switches it on finds 110
 * bound and walks a client's whole session against it; the run left on
 * the shipped settings finds it shut. The implicit TLS port beside it is
 * asked about in both, because "this server binds 995 on no setting" is
 * only a claim in the run where POP3 is on: where it is off, an unbound
 * 995 follows from the listener being off and says nothing an unbound
 * 110 had not already said.
 *
 * A socket in the listening state is half the answer. It says the bind
 * succeeded and says nothing about what is behind it, so the port is
 * then driven the way a receiving MTA drives it: banner, EHLO, the in
 * band upgrade, the extension set re-read over TLS, and an envelope for
 * a mailbox this server hosts beside one it does not. A listener that
 * bound and then spoke nothing would satisfy the enumeration and fail
 * every line after it.
 *
 * Run standalone: node test/layer-2-integration/container-quickstart.test.js
 */

var nodeNet  = require("node:net");
var nodePath = require("node:path");

var helpers = require("../helpers");
var browser = require("../helpers/browser");
var wire    = require("../helpers/wire");
var harness = require("./container-harness");
var web     = require("../../lib/web");
var b       = require("../../lib/vendor/blamejs");

var Wire  = wire.Wire;

var LOOPBACK  = "127.0.0.1";
var HOSTNAME  = "mx.example.com";
var DOMAIN    = "example.com";
var ADMIN     = "admin@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one container run";
var ADMIN_PASSWORD   = "quiet lantern bicycle 4291";

// The MX listener is moved off its default so the per listener variable
// is driven end to end rather than asserted from the schema.
var MOVED_MX_PORT   = 2525;
var DEFAULT_MX_PORT = 25;

// The POP3 pair. The plaintext port is published, enumerated and driven
// by the run that switches the listener on; the implicit TLS port is
// enumerated by that run and by the one left on the shipped settings,
// and is expected to be unbound in both. Named rather than written as
// bare numbers because each now appears in more than one place, and two
// literals that drift apart stop being about the same listener.
var POP3_PORT          = 110;
var POP3_IMPLICIT_PORT = 995;

// The browser pair. Both are published by every run below, because the
// two carry different answers to the same request and a run holding one
// of them can only ask half the question.
var WEB_PORT     = 8080;
var WEB_TLS_PORT = 8443;

// What a peer writes when it dials the MX port. Nobody here owns the
// sender, and nobody here hosts the second recipient's domain, which is
// what makes the pair of answers to them readable: an acceptance for a
// mailbox this server holds beside a refusal for one it does not.
var PEER_HELO           = "peer.example.net";
var PEER_SENDER         = "postmaster@peer.example.net";
var STRANGER_RECIPIENT  = "someone@nowhere.example.org";

var WIRE_TIMEOUT_MS  = 15000;
var QUIET_WINDOW_MS  = 400;

var count = helpers.count;

// ---- a client on the other end of a published port -------------------------

// Reads whatever a listener says first. A greeting is the cheapest proof
// that a published port reaches a protocol rather than reaching the
// port forwarder and stopping there.
function greeting(port, label) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port });
    var buf = "";
    var timer = setTimeout(function () {
      socket.destroy();
      reject(new Error(label + ": nothing was said on port " + port + " within " +
        WIRE_TIMEOUT_MS + "ms; buffer was " + JSON.stringify(buf)));
    }, WIRE_TIMEOUT_MS);
    socket.setEncoding("utf8");
    socket.on("data", function (chunk) {
      buf += chunk;
      if (buf.indexOf("\n") === -1) return;
      clearTimeout(timer);
      socket.destroy();
      resolve(buf.split("\n")[0].replace(/\r$/, ""));
    });
    socket.on("error", function (e) {
      clearTimeout(timer);
      reject(new Error(label + ": port " + port + " refused the connection (" + e.code + ")"));
    });
  });
}

// ---- a browser --------------------------------------------------------------

// The part of the refusal that names what turned the reader away. A page
// carrying it says the connection was the problem, and a page without it
// says something else was, which is the difference between the two
// directions driven below.
var TRANSPORT_MARK = "not accept a password";

// A reader on the published TLS port, verifying the chain against the
// authority this run minted. The name is passed rather than left to the
// address the port is dialed at, so the identity check is made against
// the hostname the certificate was issued for.
function tlsReader(hostPort, caPem) {
  return browser.browserAt("https://" + LOOPBACK + ":" + hostPort, {
    ca: caPem, servername: HOSTNAME,
  });
}

// A reader on the published cleartext port. The host dials 127.0.0.1 and
// the request still arrives at the server from the bridge gateway, which
// is the whole reason this port and the one above answer differently.
function cleartextReader(hostPort) {
  return browser.browserAt("http://" + LOOPBACK + ":" + hostPort);
}

// One sign in, carrying the token the form handed out and the cookies
// that came with it. The status is the verdict: a redirect means the
// session exists, anything else means the server declined and the page
// says why.
async function signIn(reader, address, password) {
  var posted = await reader.signIn(address, password);
  return {
    accepted:  posted.status === 302 || posted.status === 303,
    status:    posted.status,
    page:      posted.body,
    setCookie: posted.setCookie || [],
  };
}

// Whether a sign in left the browser holding a session.
function sessionWritten(result) {
  return result.setCookie.some(function (line) {
    return String(line).indexOf(web.SESSION_COOKIE + "=") === 0;
  });
}

// ---- a mail client that verifies the certificate ---------------------------

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

/**
 * An IMAP session through a published port, raised to TLS and
 * authenticated as the account init created.
 *
 * The chain is verified against the authority this run minted, and
 * verification stays on. That is the claim: the documents tell an
 * operator to put a certificate and key in the data volume's tls folder
 * and name them in two variables, and nothing else in the suite proves
 * the listener presents that pair rather than one of its own. A test
 * that turned verification off would pass against a listener presenting
 * anything at all.
 */
async function imapOverTls(port, caPem, address, password) {
  var session = await Wire.connect(port, "imap");
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, password));
  await session.read(/^a1 OK/m, "authenticated");
  session.send("a2 SELECT INBOX");
  var selected = await session.read(/^a2 (OK|NO|BAD)/m, "INBOX selected");
  return { session: session, selected: selected };
}

// ---- what is actually listening inside the container -----------------------

// Enumerates listening TCP sockets from the container's own kernel view,
// which is the only answer that cannot be confused by a port forwarder
// accepting a connection it then fails to hand anywhere.
var LISTENING_EXPRESSION = [
  "var fs=require('node:fs');",
  "function read(p){try{return fs.readFileSync(p,'utf8');}catch(e){return '';}}",
  "var ports=[];",
  "['/proc/net/tcp','/proc/net/tcp6'].forEach(function(p){",
  "read(p).split('\\n').slice(1).forEach(function(line){",
  "var f=line.trim().split(/\\s+/);",
  "if(f.length<4||f[3]!=='0A')return;",
  "var hex=f[1].split(':')[1];",
  "if(hex)ports.push(parseInt(hex,16));",
  "});});",
  "ports.sort(function(a,c){return a-c;});",
  "process.stdout.write(JSON.stringify({listening:ports.filter(function(v,i,arr){",
  "return arr.indexOf(v)===i;})}));",
].join("");

async function listeningPorts(container) {
  var rv = await harness.dockerOrThrow(
    ["exec", container.name, "/usr/bin/node", "-e", LISTENING_EXPRESSION],
    "enumerating listening sockets inside " + container.name);
  return JSON.parse(rv.stdout.trim()).listening;
}

// Every port this run reached a verdict on from that enumeration,
// published at the end as the unit examined.
//
// The count is here because most of these verdicts are absence claims,
// and an absence claim is exactly what an enumeration returning nothing
// satisfies. A run whose reader had stopped reaching the kernel would
// report every "stays shut" as a pass, fail only the handful of "is
// bound" lines, and look like a server with no listeners rather than
// like a broken reader. The number of ports actually asked about is the
// only thing that tells those two apart.
var _portsExamined = [];

function portVerdict(bound, port, expectListening, label) {
  if (!Array.isArray(bound)) {
    throw new TypeError("portVerdict: bound must be the array listeningPorts() returned");
  }
  if (typeof port !== "number" || !isFinite(port) || port <= 0) {
    throw new TypeError("portVerdict: port must be a port number");
  }
  // A truthy non-boolean here compares unequal to both `true` and
  // `false`, so it turns every claim it is passed to into its opposite
  // and the file still reads as if it said what it meant to say. The
  // one shape this helper exists to make hard to get wrong is exactly
  // that one, so it is refused rather than coerced.
  if (typeof expectListening !== "boolean") {
    throw new TypeError("portVerdict: expectListening must be true or false, got " +
      JSON.stringify(expectListening));
  }
  if (_portsExamined.indexOf(port) === -1) _portsExamined.push(port);
  count(label, (bound.indexOf(port) !== -1) === expectListening, bound.join(" "));
}

// The floor below which an unprivileged process may not bind, read from
// the container's own network namespace rather than assumed from the
// flag that was passed.
var PORT_FLOOR_EXPRESSION =
  "process.stdout.write(JSON.stringify({floor:parseInt(require('node:fs')" +
  ".readFileSync('/proc/sys/net/ipv4/ip_unprivileged_port_start','utf8').trim(),10)}))";

async function unprivilegedPortFloor(container) {
  var rv = await harness.dockerOrThrow(
    ["exec", container.name, "/usr/bin/node", "-e", PORT_FLOOR_EXPRESSION],
    "reading the unprivileged port floor inside " + container.name);
  return JSON.parse(rv.stdout.trim()).floor;
}

// ---- the probe, from where the image's own health check runs it -------------

// The image polls its health endpoint from inside the container over the
// loopback interface, and that peer is the one the endpoint answers in
// full. Driven the same way here, because the reason a probe is failing
// is only worth anything if it reaches the reader who has the failure in
// front of them, and that reader is `docker inspect`.
//
// Measured rather than assumed: a client reaching the same endpoint
// through the published port arrives from the bridge gateway rather than
// from the loopback interface, so the two callers below genuinely differ
// in what they are told.
function probeExpression(path) {
  return [
    "var port=process.env.BLAMEPOST_HTTP_PORT||8080;",
    "fetch('http://127.0.0.1:'+port+'" + path + "')",
    ".then(function(r){return r.text().then(function(t){",
    "process.stdout.write(JSON.stringify({code:r.status,body:t}));});})",
    ".catch(function(e){process.stdout.write(JSON.stringify({code:0,",
    "body:String((e&&e.message)||e)}));});",
  ].join("");
}

function parseProbe(raw, what) {
  try {
    return JSON.parse(raw);
  } catch (_e) {
    throw new Error(what + " answered something that is not JSON: " +
      JSON.stringify(String(raw).slice(0, 300)));
  }
}

async function probeInside(container, path) {
  var rv = await harness.dockerOrThrow(
    ["exec", container.name, "/usr/bin/node", "-e", probeExpression(path)],
    "polling " + path + " from inside " + container.name);
  var envelope = parseProbe(rv.stdout.trim(), path + " inside " + container.name);
  return { code: envelope.code, body: parseProbe(envelope.body, path + " body") };
}

// The reason a named listener is being held back, out of the probe's own
// answer. Absent rather than thrown when the check said nothing about
// it, so the assertion reports what the probe actually carried.
function withheldReason(body, name) {
  var check = (body.checks || {})["listeners-withheld"] || {};
  var rows  = Array.isArray(check.withheld) ? check.withheld : [];
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i] && rows[i].name === name) return String(rows[i].reason || "");
  }
  return null;
}

// What the container's own health check last wrote, as `docker inspect`
// reports it. A probe that exits non-zero having written nothing leaves
// an operator a failing streak and no reason for it, which is the same
// amount of help as no probe at all.
function lastProbeOutput(state) {
  var log = Array.isArray(state.log) ? state.log : [];
  if (log.length === 0) return null;
  return String(log[log.length - 1].Output || "");
}

// ---- the run ----------------------------------------------------------------

// Writes the certificate pair into the volume as the runtime user, at
// the path the documents name. Every listener requires TLS and none has
// a plaintext mode, so this is a prerequisite of the first start rather
// than a convenience.
var SEED_EXPRESSION = [
  "var fs=require('node:fs');",
  "var dir='/var/lib/blamepost/tls';",
  "fs.mkdirSync(dir,{recursive:true,mode:0o700});",
  "fs.writeFileSync(dir+'/fullchain.pem',Buffer.from(process.env.SEED_CERT,'base64'),{mode:0o600});",
  "fs.writeFileSync(dir+'/privkey.pem',Buffer.from(process.env.SEED_KEY,'base64'),{mode:0o600});",
  "process.stdout.write(JSON.stringify({wrote:fs.readdirSync(dir).sort()}));",
].join("");

function baseEnv() {
  return [
    "BLAMEPOST_HOSTNAME=" + HOSTNAME,
    "BLAMEPOST_VAULT_PASSPHRASE=" + VAULT_PASSPHRASE,
    "BLAMEPOST_DNS_ACKNOWLEDGED=1",
    "BLAMEPOST_TLS_CERT=" + harness.DATA_PATH + "/tls/fullchain.pem",
    "BLAMEPOST_TLS_KEY=" + harness.DATA_PATH + "/tls/privkey.pem",
    "BLAMEPOST_LOG_LEVEL=warn",
  ];
}

// The security posture the compose file runs the image under, restated
// here so the run that proves the listeners bind is the same run that
// proves they bind with every capability dropped.
var HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"];

// The documented default for the privileged mail ports: the same
// hardening, plus the unprivileged port floor lowered inside the
// container's own network namespace. Nothing else in the suite proves
// that a process running as an unprivileged user with no capability at
// all reaches port 25 under it.
var PORT_FLOOR_LOWERED = HARDENING.concat([
  "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
]);

async function run() {
  await harness.requireStack("container-quickstart.test.js");
  var image = await harness.buildImage();

  var root = helpers.tempDir("container-qs");
  var volume = await harness.createVolume("blamepost-qs");
  var before    = null;
  var after     = null;
  var onDefault = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    // The life on this leaf is load-bearing rather than arbitrary. The
    // probes read the certificate on every poll and reduce their verdict
    // once one is inside the fortnight a renewal client should already
    // have replaced it in, so a leaf minted with a day left would leave
    // this server degraded from the moment it came up and the transition
    // this file is here to measure would have nothing to show. Ninety
    // days is what a publicly trusted certificate is issued for.
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK, "localhost"],
      validityDays: 90,
    });

    var seeded = await harness.docker([
      "run", "--rm", "--volume", volume + ":" + harness.DATA_PATH,
      // The leaf followed by the authority that issued it, which is what
      // the file this is written to is named after and what an operator
      // actually deploys. A bare leaf is the single most common way a
      // mail certificate is wrong: browsers fetch the missing issuer
      // themselves and sending mail servers do not, so seeding one here
      // would have this run prove the quickstart works against the one
      // client that cannot see the mistake.
      "--env", "SEED_CERT=" + Buffer.from(leaf.cert + leaf.ca).toString("base64"),
      "--env", "SEED_KEY=" + Buffer.from(leaf.key).toString("base64"),
      "--entrypoint", "/usr/bin/node", image, "-e", SEED_EXPRESSION,
    ]);
    count("the runtime user can write into a fresh data volume, so the certificate " +
      "the documents ask for can be placed where they say to place it",
      seeded.code === 0, seeded.stderr.trim().slice(-300));

    // ---- serve, before init -------------------------------------------------
    //
    // Both administrator variables are set, which is what an operator who
    // read only the settings table would do. The point of this half is
    // that setting them is not enough.
    before = await harness.Container.start(image, "blamepost-before", {
      volume:  volume,
      publish: [WEB_PORT, WEB_TLS_PORT],
      extra:   PORT_FLOOR_LOWERED,
      env:     baseEnv().concat([
        "BLAMEPOST_ADMIN_EMAIL=" + ADMIN,
        "BLAMEPOST_ADMIN_PASSWORD=" + ADMIN_PASSWORD,
      ]),
    });
    var healthyBefore = await before.waitHealthy(
      "the shipped image reports itself healthy before init");
    // This is the state the documented sequence puts every operator
    // through. `init` runs after the container is up, so a probe that
    // called a fresh volume down would hold a readiness gate, a
    // dependent service and a load balancer off the server for the whole
    // setup window, while submission, IMAP, ManageSieve and the browser
    // surface were all bound and serving.
    count("the image's own health probe reaches a verdict of healthy on a fresh volume, " +
      "before the one command that creates the first domain has been run",
      healthyBefore.health === "healthy", JSON.stringify(healthyBefore.health));

    var beforePort = await before.hostPort(WEB_PORT);
    var beforeState = await before.state();
    count("the container is running", beforeState.status === "running", beforeState.status);

    var beforeInspect = await harness.inspect(before.name);
    count("the container ran with every Linux capability dropped",
      (beforeInspect.HostConfig.CapDrop || []).indexOf("ALL") !== -1,
      JSON.stringify(beforeInspect.HostConfig.CapDrop));
    count("the container ran with privilege escalation refused",
      (beforeInspect.HostConfig.SecurityOpt || []).indexOf("no-new-privileges:true") !== -1,
      JSON.stringify(beforeInspect.HostConfig.SecurityOpt));
    count("exactly one volume is mounted, at the documented data path",
      beforeInspect.Mounts.length === 1 && beforeInspect.Mounts[0].Destination === harness.DATA_PATH,
      JSON.stringify(beforeInspect.Mounts.map(function (m) { return m.Destination; })));

    // The documented default for the privileged mail ports, end to end.
    // The floor is read from the container's own namespace rather than
    // inferred from the flag that was passed, and the socket is then
    // looked for on the port a receiving MTA dials.
    var floor = await unprivilegedPortFloor(before);
    count("the unprivileged port floor inside the container's own network namespace " +
      "is lowered, and reads that way from the container rather than from the flag",
      floor === 0, "floor " + floor);
    var boundBefore = await listeningPorts(before);
    // Before `init` this server hosts no domain, and an MX listener
    // with nothing hosted has no address that resolves to a mailbox
    // here. What it would answer a peer is `250` to a stranger's
    // sender and `250` to a stranger's recipient, which is the answer
    // an open relay gives and the answer a scanner records, followed by
    // a refusal once the peer has sent the whole message. So the port a
    // receiving MTA dials stays shut until there is something to
    // receive for, and the check is made from inside the container
    // because that is where a socket either exists or does not.
    portVerdict(boundBefore, DEFAULT_MX_PORT, false,
      "the MX port stays shut while the server hosts no domain, so a fresh volume " +
      "never answers a relay probe the way an open relay answers one");
    // The rest come up regardless. `init` opens the data directory
    // directly and needs nothing listening, so the browser surface has
    // to survive the one step that creates the first domain.
    [587, 465, 143, 4190].forEach(function (port) {
      portVerdict(boundBefore, port, true,
        "the privileged listener on port " + port + " binds as an unprivileged user " +
        "with every capability dropped and no port mapping in the way");
    });

    // ---- what the probe says about that shut port ---------------------------
    //
    // Serving and fully running are two different answers, and the probe
    // has to give the one that is true. Reporting a failure here calls a
    // server down that is doing exactly what it was built to do;
    // reporting nothing at all leaves a monitor believing mail is
    // arriving on a port that is deliberately shut. Neither is what an
    // operator or a monitoring system can act on.
    var beforeHealth = await probeInside(before, "/healthz");
    count("the probe answers rather than refusing, so nothing acting on this server's " +
      "health treats a first boot as a process that failed to come up",
      beforeHealth.code === 200, String(beforeHealth.code));
    count("and it reports the server as serving with something held back rather than as " +
      "fully fit, so a monitor is not told everything is fine while port 25 is shut",
      beforeHealth.body.status === "degraded", JSON.stringify(beforeHealth.body.status));
    count("the listener the server is holding back is named, so the answer is a fact an " +
      "operator can act on rather than a word",
      withheldReason(beforeHealth.body, "mx") !== null,
      JSON.stringify(beforeHealth.body.checks));
    count("and the reason travels with it, naming the state the server is in and the " +
      "command that leaves it",
      /hosts no domain/.test(withheldReason(beforeHealth.body, "mx") || "") &&
      /blamepost init/.test(withheldReason(beforeHealth.body, "mx") || ""),
      JSON.stringify(withheldReason(beforeHealth.body, "mx")));
    // The critical half of the verdict has to stay clean here, because a
    // failure state that a deliberate withholding also produces is a
    // failure state that no longer means failure.
    count("nothing that was supposed to bind is reported as having failed to, so the " +
      "refusing verdict is still available to mean a listener that did not come up",
      ((beforeHealth.body.checks || {}).listeners || {}).ok === true,
      JSON.stringify((beforeHealth.body.checks || {}).listeners));

    var beforeReady = await probeInside(before, "/readyz");
    count("readiness answers the same way, so a load balancer and a dependent service " +
      "keep reaching the browser surface the operator has to use to finish the setup",
      beforeReady.code === 200 && beforeReady.body.status === "degraded",
      beforeReady.code + " " + JSON.stringify(beforeReady.body.status));

    // The reason reaches the container's own probe over the loopback
    // interface. A client arriving through the published port comes from
    // the bridge gateway instead, and is told the verdict and nothing
    // else: an endpoint that is reachable from wherever the browser
    // surface is reachable does not publish its internals.
    var publicHealth = await fetch("http://" + LOOPBACK + ":" + beforePort + "/healthz");
    var publicBody = await publicHealth.json();
    count("the same endpoint reached from off the container carries the verdict and no " +
      "internal detail, so the reason reaches the operator's own probe without being " +
      "published to everything else that can reach the port",
      publicBody.status === "degraded" && publicBody.checks === undefined,
      JSON.stringify(publicBody));

    // The measured symptom was a failing streak beside an empty output.
    // A verdict nobody can read is the same defect wearing a different
    // word, so the probe writes what it saw whichever way it exits.
    var beforeProbeLog = lastProbeOutput(await before.state());
    count("the image's own health check writes what it read, so `docker inspect` carries " +
      "the verdict rather than an empty string beside a streak of failures",
      beforeProbeLog !== null && beforeProbeLog.indexOf("degraded") !== -1,
      JSON.stringify(beforeProbeLog));

    // The port the quick start sends an operator to. A container publishes
    // both, and only this one takes a password: the cleartext port sees
    // the bridge gateway as its peer whatever the host dialed, and this
    // one is TLS end to end from the browser to the listener.
    var beforeTlsPort = await before.hostPort(WEB_TLS_PORT);
    var beforeReader  = tlsReader(beforeTlsPort, leaf.ca);
    var landing = await beforeReader.get("/sign-in");
    count("the sign in page renders over the published TLS port, against the certificate " +
      "the documents told the operator to place in the data volume",
      landing.status === 200, String(landing.status));
    count("and it offers a password field, so what came back is the form rather than the " +
      "page a connection that cannot carry a password gets",
      landing.body.indexOf("type=\"password\"") !== -1 &&
      landing.body.indexOf(TRANSPORT_MARK) === -1,
      landing.body.replace(/\s+/g, " ").slice(0, 240));

    var refused = await signIn(beforeReader, ADMIN, ADMIN_PASSWORD);
    count("serve creates no account, so the administrator address cannot sign in yet " +
      "however the administrator variables are set",
      refused.accepted === false, "status " + refused.status);
    // The refusal has to be about the credential. A transport refusal
    // would satisfy the line above without the account question ever
    // being asked, which is the reading this whole file exists to avoid.
    count("and it is the credential that was turned away rather than the connection, so " +
      "the absence of an account is what the refusal above measured",
      refused.page.indexOf(TRANSPORT_MARK) === -1,
      refused.page.replace(/\s+/g, " ").slice(0, 240));

    // Stopped as the operator guide stops it, so the server shuts down and
    // gives the volume lock back before the next container opens it.
    await before.stop();
    await before.remove();
    before = null;

    // ---- init, the one step that creates an account -------------------------
    // The exact line the quick start tells an operator to run, with the
    // structured report asked for, so what is asserted is a document's
    // own command rather than a paraphrase of it.
    var init = await harness.runCli(image, volume, baseEnv(), [
      "bin/blamepost.js", "init", "--admin-email", ADMIN,
      "--admin-password", ADMIN_PASSWORD, "--json",
    ]);
    count("init exits cleanly against the same data volume",
      init.code === 0, init.stderr.trim().slice(-400));
    // The report is pretty printed, and the framework's boot lines are
    // already stripped, so the remaining object is the one the operator
    // reads. Parsing it rather than matching a substring means a log
    // line cannot satisfy any of the three checks below.
    var opened = init.stdout.indexOf("{");
    var closed = init.stdout.lastIndexOf("}");
    var initReport = opened === -1 || closed <= opened
      ? {}
      : JSON.parse(init.stdout.slice(opened, closed + 1));
    count("init reports the administrator it created",
      initReport.admin === ADMIN,
      JSON.stringify(initReport.admin) + " from " + init.stdout.trim().slice(0, 300));
    count("init hosts the administrator's domain, so no separate step is needed",
      initReport.domain === DOMAIN, JSON.stringify(initReport.domain));
    count("init prints the records to publish rather than leaving the operator to derive them",
      Array.isArray(initReport.publish) && initReport.publish.length > 0,
      JSON.stringify((initReport.publish || []).length));
    count("init put the data directory where the image says it is",
      initReport.dataDir === harness.DATA_PATH, JSON.stringify(initReport.dataDir));

    var ack = await harness.runCli(image, volume, baseEnv(), [
      "bin/blamepost.js", "domain", "acknowledge", DOMAIN, "--by", ADMIN,
    ]);
    count("the domain's own DNS posture is acknowledged, which the MX listener waits on",
      ack.code === 0, ack.stderr.trim().slice(-400));

    // ---- serve, after init, with the MX listener moved -----------------------
    // POP3 is switched on here rather than in a container of its own.
    // This run already holds everything the question needs: an
    // initialized volume, an account to authenticate as, and a process
    // running unprivileged with every capability dropped. So the answer
    // costs one more published port and one more variable, rather than a
    // fourth container start on every run of this suite for a listener
    // that is off by default. The two states POP3 has are then measured
    // in the two runs that were already happening.
    after = await harness.Container.start(image, "blamepost-after", {
      volume:  volume,
      publish: [WEB_PORT, WEB_TLS_PORT, 143, 4190, MOVED_MX_PORT, DEFAULT_MX_PORT, POP3_PORT],
      extra:   HARDENING,
      env:     baseEnv().concat([
        "BLAMEPOST_MX_PORT=" + MOVED_MX_PORT,
        "BLAMEPOST_POP3_ENABLED=true",
      ]),
    });
    await after.waitHealthy("the server reports itself healthy after init");

    var httpPort    = await after.hostPort(WEB_PORT);
    var httpsPort   = await after.hostPort(WEB_TLS_PORT);
    var accepted = await signIn(tlsReader(httpsPort, leaf.ca), ADMIN, ADMIN_PASSWORD);
    count("the administrator init created signs in over the published TLS port, so the " +
      "documented sequence leaves an operator with a server they can use",
      accepted.accepted === true, "status " + accepted.status +
      " page " + accepted.page.slice(0, 200));
    count("and the session that sign in minted is written to the browser",
      sessionWritten(accepted), JSON.stringify(accepted.setCookie));

    var wrongPassword = await signIn(tlsReader(httpsPort, leaf.ca), ADMIN, "not the password 0000");
    count("a wrong password is still refused after init",
      wrongPassword.accepted === false, "status " + wrongPassword.status);

    // ---- the port that does not take a password ------------------------------
    //
    // The other direction, and the one that needs an account to mean
    // anything: this run holds a credential that has just been proved
    // correct on the port beside this one, so a refusal here is about the
    // connection rather than about the password. Both shapes are driven,
    // because a gate that fired only on the post would fire after the
    // password had already crossed the wire.
    var cleartextForm = await cleartextReader(httpPort).get("/sign-in");
    count("the sign in page reached over the published cleartext port refuses rather " +
      "than rendering, because a request published out of the container arrives from the " +
      "bridge gateway rather than over the loopback interface",
      cleartextForm.status === 403, String(cleartextForm.status));
    count("and it carries no password field and names the connection as the reason, so " +
      "no password reaches that wire at all",
      cleartextForm.body.indexOf("type=\"password\"") === -1 &&
      cleartextForm.body.indexOf(TRANSPORT_MARK) !== -1,
      cleartextForm.body.replace(/\s+/g, " ").slice(0, 240));

    var overCleartext = await signIn(cleartextReader(httpPort), ADMIN, ADMIN_PASSWORD);
    count("the same correct password posted to that port is refused, naming the " +
      "connection rather than the credential",
      overCleartext.accepted === false && overCleartext.status === 403 &&
      overCleartext.page.indexOf(TRANSPORT_MARK) !== -1,
      "status " + overCleartext.status + " " +
      overCleartext.page.replace(/\s+/g, " ").slice(0, 240));
    count("and no session cookie is written, so nothing was recorded as a sign in",
      sessionWritten(overCleartext) === false, JSON.stringify(overCleartext.setCookie));

    // ---- the listeners, from outside and from inside -------------------------
    var mxBanner = await greeting(await after.hostPort(MOVED_MX_PORT), "mx");
    count("the MX listener answers with an SMTP banner on the port the per listener " +
      "variable named, not on the default",
      /^220 /.test(mxBanner) && mxBanner.indexOf(HOSTNAME) !== -1, mxBanner);

    var imapBanner = await greeting(await after.hostPort(143), "imap");
    count("the IMAP listener answers with an untagged OK carrying its capabilities",
      /^\* OK \[CAPABILITY /.test(imapBanner), imapBanner);
    count("the IMAP capability line offers the in band upgrade rather than expecting " +
      "an implicit TLS port nothing binds",
      imapBanner.indexOf("STARTTLS") !== -1, imapBanner);

    var sieveBanner = await greeting(await after.hostPort(4190), "managesieve");
    count("the ManageSieve listener answers with its implementation capability",
      /^"IMPLEMENTATION"/.test(sieveBanner), sieveBanner);

    // The one claim only a container can settle: the certificate an
    // operator placed in the volume is the certificate the listener
    // presents. Verification against the run's own authority stays on,
    // so a listener offering anything else fails the handshake here
    // rather than being accepted and asserted about.
    var imapPort = await after.hostPort(143);
    var mail = await imapOverTls(imapPort, leaf.ca, ADMIN, ADMIN_PASSWORD);
    try {
      count("a mail client upgrades the published IMAP port to TLS and verifies the " +
        "chain against the authority that signed the pair placed in the data volume",
        true);
      count("the account init created authenticates over that connection and selects " +
        "its inbox, so the quick start ends at a working mailbox",
        /^a2 OK/m.test(mail.selected), mail.selected.slice(0, 200));
    } finally {
      mail.session.close();
    }

    // The listener an operator turns on by hand, driven the way a mail
    // client drives it. A socket on 110 says the bind succeeded and says
    // nothing about what is behind it, and this is the one listener for
    // which no container had ever been in a position to say more: every
    // run before this one had POP3 off, where an unbound port is what a
    // working listener and a broken one both produce.
    //
    // The ladder is the suite's own, so the greeting, the upgrade and the
    // credential are the same sequence every other file drives, and it
    // throws rather than handing back a session it could not raise. The
    // verdict is therefore whether it returned one.
    var pop3Port        = await after.hostPort(POP3_PORT);
    var maildrop        = null;
    var maildropFailure = null;
    try {
      maildrop = await Wire.pop3(pop3Port, {
        caPem:      leaf.ca,
        servername: HOSTNAME,
        address:    ADMIN,
        password:   ADMIN_PASSWORD,
        label:      "pop3",
      });
    } catch (e) {
      maildropFailure = e;
    }
    count("a mail client walks a whole POP3 session against the port an operator switched " +
      "on: the greeting, the in band upgrade, the chain verified against the authority that " +
      "signed the pair placed in the data volume, and the account init created accepted",
      maildrop !== null, maildropFailure === null ? "" : String(maildropFailure.message));

    if (maildrop !== null) {
      try {
        maildrop.send("CAPA");
        var caps = await maildrop.read(/^\.\r\n/m, "CAPA answered over TLS");
        // RFC 2595 section 4 confines STLS to the authorization state and
        // this listener stops advertising it once it has been taken, which
        // is the POP3 spelling of what RFC 3207 requires of SMTP. The
        // comparison an operator cares about is the same one: a client
        // must not be invited to negotiate again inside the session it
        // already raised.
        count("the capability list is served over the raised session and no longer offers " +
          "the upgrade, so a client is not invited to negotiate again inside a session that " +
          "is already encrypted",
          /^\+OK/m.test(caps) && !/^STLS\r$/m.test(caps), wire.visible(caps));
        count("and it advertises the verbs a client needs to read a maildrop without " +
          "destroying it, so what came up on that port speaks POP3 rather than answering OK",
          /^UIDL\r$/m.test(caps) && /^TOP\r$/m.test(caps), wire.visible(caps));

        maildrop.send("STAT");
        var stat = await maildrop.read(/^(\+OK|-ERR)/m, "STAT answered");
        count("the account's maildrop answers with a message count and a size, so the " +
          "session reached the store rather than stopping at the credential exchange",
          /^\+OK \d+ \d+/m.test(stat), wire.visible(stat));

        maildrop.send("QUIT");
        var pop3Quit = await maildrop.read(/^(\+OK|-ERR)/m, "QUIT answered");
        count("and the session closes the way RFC 1939 ends one, so what ran was a " +
          "conversation rather than a socket that happened to have bytes in it",
          /^\+OK/m.test(pop3Quit), wire.visible(pop3Quit));
      } finally {
        maildrop.close();
      }
    }

    // ---- the other side of the transition -----------------------------------
    //
    // The degraded answer before init is only worth having if it clears
    // once the thing it was waiting for exists. A probe stuck on the
    // reduced verdict would be a server nobody could ever confirm was
    // fully up, which is the same defect in the direction that hides
    // rather than the direction that alarms.
    var health = await fetch("http://" + LOOPBACK + ":" + httpPort + "/healthz");
    var healthBody = await health.json();
    count("the health endpoint the probe asks answers over the wire",
      health.status === 200 && healthBody.status === "ok",
      health.status + " " + JSON.stringify(healthBody));

    var afterHealth = await probeInside(after, "/healthz");
    count("the reduced verdict clears once a domain is hosted and the MX listener takes " +
      "its port, so the two states an operator has to tell apart are actually distinct",
      afterHealth.body.status === "ok", JSON.stringify(afterHealth.body.status));
    count("and nothing is left named as held back, so the answer is not carrying a " +
      "reason that has stopped being true",
      withheldReason(afterHealth.body, "mx") === null,
      JSON.stringify((afterHealth.body.checks || {})["listeners-withheld"]));

    var afterReady = await probeInside(after, "/readyz");
    count("readiness reports the same, so what routes traffic and what decides a " +
      "dependent service may start both see a server that is fully up",
      afterReady.code === 200 && afterReady.body.status === "ok",
      afterReady.code + " " + JSON.stringify(afterReady.body.status));
    // The clean verdict, pinned to a named reason rather than to an
    // accident. This probe also reads the certificate on disk, so a
    // future change to the material seeded above could reduce the whole
    // answer and leave the assertion above failing with nothing to say
    // about why.
    count("the certificate seeded into the volume is one the probe read and found nothing " +
      "wrong with, so the clean verdict above is a certificate this server can present " +
      "rather than a certificate nobody looked at",
      (afterReady.body.checks || {}).certificate !== undefined &&
      afterReady.body.checks.certificate.read === true &&
      afterReady.body.checks.certificate.ok === true &&
      afterReady.body.checks.certificate.usable === true,
      JSON.stringify((afterReady.body.checks || {}).certificate));

    var afterProbeLog = lastProbeOutput(await after.state());
    count("the container's own probe writes the healthy verdict too, so the output is a " +
      "record of what was read rather than something only a failure produces",
      afterProbeLog !== null && afterProbeLog.indexOf("ok") !== -1,
      JSON.stringify(afterProbeLog));

    var bound = await listeningPorts(after);
    portVerdict(bound, MOVED_MX_PORT, true,
      "the MX listener bound the port the variable named");
    portVerdict(bound, DEFAULT_MX_PORT, false,
      "nothing was left listening on the MX default once the variable moved it");
    [587, 465, 143, 4190, WEB_PORT, WEB_TLS_PORT].forEach(function (port) {
      portVerdict(bound, port, true,
        "the listener on port " + port + " bound inside the container");
    });
    // This run passes no port floor flag, so the only thing letting a
    // process with no capability at all hold a privileged port is the
    // floor the engine already set inside the container. Read rather than
    // assumed, because a run that asserted the bind without reading it
    // reports the bind and leaves the reason to be worked out the next
    // time it stops happening.
    var afterFloor = await unprivilegedPortFloor(after);
    count("the unprivileged port floor in this container is low enough for a privileged " +
      "port to be taken by a process holding no capability, read from the container's own " +
      "network namespace rather than assumed from the engine's defaults",
      afterFloor === 0, "floor " + afterFloor);
    // Each POP3 port is its own verdict. Asserting the pair together
    // reports a run where one of the two came up without naming which,
    // and the plaintext port and the implicit TLS port fail for
    // different reasons.
    portVerdict(bound, POP3_PORT, true,
      "POP3 takes its port once an operator switches it on, as an unprivileged user with " +
      "every capability dropped, which is the state no container run had ever held this " +
      "listener in");
    // And this is the run where the implicit TLS port is worth asking
    // about at all. With POP3 off, an unbound 995 follows from the
    // listener being off. With POP3 on, it is a measurement of what this
    // server offers: the upgrade in band on the plaintext port, and no
    // implicit TLS mode anywhere.
    portVerdict(bound, POP3_IMPLICIT_PORT, false,
      "the implicit TLS POP3 port stays unbound with POP3 switched on, so a client that " +
      "can only do implicit TLS finds no route here rather than a socket that accepts it " +
      "and then refuses every credential");
    portVerdict(bound, 993, false,
      "nothing binds the implicit TLS IMAP port, which no configuration uses");

    // The published default MX port reaches nothing. Docker's forwarder
    // accepts and then finds no listener, so the claim is the absence of
    // a banner across a window rather than a refused connection, and no
    // predicate can express an absence.
    var quietPort = await after.hostPort(DEFAULT_MX_PORT);
    var quiet = await Promise.race([
      greeting(quietPort, "mx-default").then(function (line) { return line; },
        function () { return null; }),
      helpers.passiveObserve(QUIET_WINDOW_MS, "the moved MX default stays silent")
        .then(function () { return null; }),
    ]);
    count("the published MX default carries no protocol once the listener moved",
      quiet === null, String(quiet));

    await after.stop();
    await after.remove();
    after = null;

    // ---- serve, after init, on the port the documents leave alone ------------
    //
    // The shipped default, which is the one configuration the quick
    // start actually tells an operator to run: no per listener variable,
    // the unprivileged port floor lowered inside the container's own
    // network namespace, and a hosted domain whose posture has been
    // acknowledged.
    //
    // Nothing had reached that composition. Every other file that drives
    // the MX listener builds it inside the test process on an ephemeral
    // loopback port, and the two runs above only ever find port 25 shut,
    // once because no domain is hosted and once because a variable moved
    // the listener off it. Port 25 is no different from 465 to the
    // kernel, which is why the absence went unnoticed rather than why it
    // was acceptable: it is the port a receiving MTA dials, and no run
    // had watched it come up.
    //
    // The same volume the run above left behind, so the only difference
    // between the fresh volume that had this port shut and this one is
    // `init` and `domain acknowledge`.
    onDefault = await harness.Container.start(image, "blamepost-default", {
      volume:  volume,
      publish: [DEFAULT_MX_PORT],
      extra:   PORT_FLOOR_LOWERED,
      env:     baseEnv(),
    });
    await onDefault.waitHealthy("the server reports itself healthy on the default MX port");

    var boundDefault = await listeningPorts(onDefault);
    portVerdict(boundDefault, DEFAULT_MX_PORT, true,
      "the port a receiving MTA dials is bound once a domain is hosted and its DNS " +
      "posture acknowledged, read from the container's own kernel view rather than " +
      "from a forwarder that would accept the connection either way");
    // The other state POP3 has, and it belongs to this run rather than to
    // one that moved a listener with a variable: this is the container
    // started on the shipped settings, so an unbound port here is what an
    // operator who set nothing gets. The same reader answered the run
    // that switched the listener on, so the pair measures a setting
    // rather than agreeing by coincidence.
    portVerdict(boundDefault, POP3_PORT, false,
      "POP3 stays off unless an operator asks for it, so a container started on the " +
      "shipped settings holds no socket on its port");
    portVerdict(boundDefault, POP3_IMPLICIT_PORT, false,
      "and none on the implicit TLS port beside it either");

    var defaultPort = await onDefault.hostPort(DEFAULT_MX_PORT);
    var defaultBanner = await greeting(defaultPort, "mx-default");
    count("and something is behind it: the banner is an SMTP greeting naming this server, " +
      "not a forwarder accepting a connection it has nowhere to hand",
      /^220 /.test(defaultBanner) && defaultBanner.indexOf(HOSTNAME) !== -1, defaultBanner);

    // The ladder a peer walks, in full. A greeting proves bytes come
    // back; EHLO proves the command reader is running, the upgrade
    // proves the extension it advertises is one it will honor, and the
    // second EHLO proves the session survived the handshake. The ladder
    // throws rather than handing back a session it could not raise, so
    // the verdict is whether it returned one.
    var peer = null;
    var peerFailure = null;
    try {
      peer = await Wire.mx(defaultPort, {
        caPem:      leaf.ca,
        servername: HOSTNAME,
        helo:       PEER_HELO,
        label:      "mx-default",
      });
    } catch (e) {
      peerFailure = e;
    }
    count("a peer walks the whole inbound ladder against the default port: EHLO accepted, " +
      "the in band upgrade offered and completed, and the extension set re-read over TLS",
      peer !== null, peerFailure === null ? "" : String(peerFailure.message));

    if (peer !== null) {
      try {
        peer.send("MAIL FROM:<" + PEER_SENDER + ">");
        var peerMail = await peer.read(/^\d{3} /m, "MAIL FROM answered");
        count("a sender nobody here owns is accepted, which is what every inbound peer is",
          /^250 /m.test(peerMail), peerMail);

        peer.send("RCPT TO:<" + ADMIN + ">");
        var peerRcpt = await peer.read(/^\d{3} /m, "RCPT TO answered");
        count("and a recipient this server hosts is accepted, so the default port reaches " +
          "a mailbox rather than reaching a parser that stops there",
          /^250 /m.test(peerRcpt), peerRcpt);

        // The other half of the same answer. A port that accepted every
        // recipient would satisfy the line above and be an open relay,
        // which is the exact shape the shut-while-no-domain case exists
        // to keep off the internet.
        peer.send("RCPT TO:<" + STRANGER_RECIPIENT + ">");
        var peerRelay = await peer.read(/^\d{3} /m, "relay RCPT answered");
        count("while a recipient at a domain this server does not host is refused with a " +
          "permanent code, so the port that just came up is not an open relay",
          /^550 /m.test(peerRelay) && /5\.7\.1/.test(peerRelay), peerRelay);

        peer.send("QUIT");
        var peerQuit = await peer.read(/^\d{3} /m, "QUIT answered");
        count("and the session closes the way RFC 5321 ends one, so what ran was a " +
          "conversation rather than a socket that happened to have bytes in it",
          /^221 /m.test(peerQuit), peerQuit);

        // RFC 3207 section 4.2: the server discards what it told the
        // client before the handshake and re-advertises, and STARTTLS is
        // not among what it offers the second time. A listener still
        // advertising it over TLS invites a client to negotiate again
        // inside the session it already raised, and the transcript is
        // the only place the two EHLO answers can be compared.
        var beforeUpgrade = peer.transcript().split("-- TLS established --")[0];
        var afterUpgrade  = peer.transcript().split("-- TLS established --")[1] || "";
        count("the extension set the default port advertises changes across the upgrade the " +
          "way RFC 3207 says it must: offered in the clear, and gone once it has been taken",
          /250[ -]STARTTLS/.test(beforeUpgrade) && !/250[ -]STARTTLS/.test(afterUpgrade),
          peer.transcript(), { limit: 1200 });
      } finally {
        peer.close();
      }
    }

    await onDefault.remove();
    onDefault = null;
  } finally {
    if (before !== null) {
      try { await before.remove(); }
      catch (_e) { /* drop-silent by design: the assertion that failed is the result */ }
    }
    if (after !== null) {
      try { await after.remove(); }
      catch (_e) { /* drop-silent by design: the assertion that failed is the result */ }
    }
    if (onDefault !== null) {
      try { await onDefault.remove(); }
      catch (_e) { /* drop-silent by design: the assertion that failed is the result */ }
    }
    await harness.cleanup();
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "container-quickstart", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined: most of the port claims here
// are absence claims, and an enumeration that had stopped reaching the
// container's kernel satisfies every one of them. The check total cannot
// tell that apart from a server holding the ports it should; the number
// of ports actually asked about can.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + _portsExamined.length + " container-listening-port");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
