// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `test/helpers/certs.js` mints, and who can read it.
 *
 * Every listener this project ships requires TLS and has no plaintext
 * mode, so a test that wants to reach past a greeting needs a
 * certificate. The helper mints one, and the algorithm it picks decides
 * which clients can be on the other end of the socket. That is not a
 * detail of the fixture: a client whose TLS stack cannot verify the
 * leaf fails at the handshake, before one byte of the protocol under
 * test is spoken, and the case that was written to prove something
 * about IMAP reports a connection error instead.
 *
 * ## Why the default stays post-quantum
 *
 * ML-DSA-87 is the framework's default and this project's posture. A
 * helper whose quiet answer was the classical one would turn every test
 * built on it into a measurement of a posture this project does not
 * hold, and nothing would say so, because the classical key works
 * everywhere and therefore never fails in a way anybody reads.
 *
 * So the default is the strong one and a departure is a sentence the
 * caller writes. The `interopReason` requirement is the whole design:
 * an algorithm opt on its own would let a test take the weaker key
 * because the stronger one was inconvenient, which is the same failure
 * with an extra step.
 *
 * ## Why a foreign TLS stack is asked rather than reasoned about
 *
 * The claim being made is about implementations that are not this one,
 * so the only evidence is one of them. Python's `ssl` module is a
 * separate build of OpenSSL, shipped with the interpreter rather than
 * taken from this machine, and it is the stack behind `imaplib` and
 * behind most operator tooling. It is asked to LOAD each key, which is
 * where an algorithm a build does not implement stops being parseable
 * metadata and becomes something it has to compute with. No socket is
 * involved, so there is nothing here to flake.
 *
 * The last case is a trip-wire and is meant to be read as one. It
 * asserts that the foreign stack STILL cannot take the post-quantum
 * key. The day it can, that case fails, and the right response is to
 * retire the classical bridge rather than to weaken the case: the
 * bridge exists only for the interval in which a common client is on
 * the wrong side of that line.
 *
 * No sockets. A temporary directory holds the material handed to the
 * foreign stack, because a key is passed to it by path.
 *
 * Run standalone: node test/layer-0-primitives/test-certificate-algorithm.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var certs   = require("../helpers/certs");
var foreign = require("../helpers/foreign-client");

var count = helpers.count;

// Minting a key pair is real asymmetric key generation, and ML-DSA-87 is
// the slowest of the two. Generous, because a machine under a full test
// run is not the machine this number was measured on.
var MINT_CEILING_MS  = 60000;
var PROBE_CEILING_MS = 30000;

// The foreign stack. Its own self-description has to name an OpenSSL,
// because a build with no `ssl` module answers `--version` perfectly
// well and can say nothing about a certificate.
var PYTHON = {
  name:            "python",
  envVar:          "BLAMEPOST_PYTHON_BIN",
  candidates:      ["python3", "python", "py"],
  probeArgs:       ["-c", "import ssl;print('OPENSSL ' + ssl.OPENSSL_VERSION)"],
  requireInOutput: /^OPENSSL OpenSSL /m,
  timeoutMs:       PROBE_CEILING_MS,
};

// The program the foreign stack runs. It reports one word per pair, so
// a build that prints a warning of its own cannot be mistaken for a
// verdict. Loading is done through a server context because that is the
// call that needs the PRIVATE key, and a public key a build cannot use
// still parses.
var PROBE_SOURCE = [
  "import ssl, sys",
  "print('OPENSSL ' + ssl.OPENSSL_VERSION)",
  "for label, chain, key in zip(sys.argv[1::3], sys.argv[2::3], sys.argv[3::3]):",
  "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)",
  "    try:",
  "        ctx.load_cert_chain(certfile=chain, keyfile=key)",
  "        print('USABLE ' + label)",
  "    except Exception as e:",
  "        print('UNUSABLE ' + label + ' ' + type(e).__name__)",
  "",
].join("\n");

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

async function theDefaultIsThePostQuantumOne() {
  var material = await certs.pair();
  count("a caller that names no algorithm gets the post-quantum one",
    material.algorithm === certs.ALGORITHM_PQC,
    "minted " + material.algorithm + ", expected " + certs.ALGORITHM_PQC);
  count("and it reports what it minted, so a caller can say what it presented",
    typeof material.algorithm === "string" && material.algorithm.length > 0,
    JSON.stringify(material.algorithm));
  count("the chain is the leaf followed by the authority",
    material.chain === material.cert + material.caPem,
    material.chain.length + " chain octets, " + material.cert.length + " leaf, " +
      material.caPem.length + " authority");
}

async function anExplicitChoiceIsHonored() {
  var pqc = await certs.pair({ algorithm: certs.ALGORITHM_PQC });
  count("naming the post-quantum algorithm outright mints that one",
    pqc.algorithm === certs.ALGORITHM_PQC, pqc.algorithm);

  var classic = await certs.pair({
    algorithm:     certs.ALGORITHM_CLASSIC,
    interopReason: "this case measures what a stack that is not node:tls can take",
  });
  count("naming the classical bridge with a reason mints that one",
    classic.algorithm === certs.ALGORITHM_CLASSIC, classic.algorithm);
}

// The three ways of getting the choice wrong, each refused where the
// caller can still fix it. Construction-time input, so it throws rather
// than degrading to a default: a helper that quietly substituted the
// classical key for an unreadable request would be the defect this
// whole file is downstream of.
async function theWaysOfGettingItWrongAreRefused() {
  await refuses("an algorithm the certificate engine does not know",
    { algorithm: "RSA-2048" }, /must be one of/);
  await refuses("the classical bridge taken with no reason written down",
    { algorithm: certs.ALGORITHM_CLASSIC }, /interopReason/);
  await refuses("a reason with no departure for it to explain",
    { interopReason: "no algorithm named beside it" }, /without opts\.algorithm/);

  async function refuses(label, opts, expected) {
    var threw = null;
    try { await certs.pair(opts); }
    catch (e) { threw = e; }
    count("refused: " + label,
      threw !== null && expected.test(String(threw && threw.message)),
      threw === null ? "it was accepted" : String(threw.message).slice(0, 200));
  }
}

// Canary. Every refusal above would also be reported by a helper that
// refused everything, and a helper that minted nothing would pass the
// whole file. This is the same call shape the refusals use, with the
// one thing that makes it valid, and it has to succeed.
async function theRefusalsAreNotJustRefusingEverything() {
  var material = await certs.pair({
    algorithm:     certs.ALGORITHM_CLASSIC,
    interopReason: "canary: the same call the refusal cases make, made correctly",
  });
  count("canary: the call the refusals reject is accepted once it is correct",
    material.algorithm === certs.ALGORITHM_CLASSIC && material.key.length > 0,
    material.algorithm + ", " + material.key.length + " key octets");
}

// ---------------------------------------------------------------------------
// The foreign stack
// ---------------------------------------------------------------------------

async function aStackThatIsNotThisOneIsAsked(workDir) {
  var client = await foreign.locate(PYTHON);
  if (!client.found) {
    helpers.skip("the interoperability cases need a TLS stack that is not this runtime's, " +
      "and there is not one here: " + client.reason + ". The contract cases above still ran; " +
      "what did not run is the evidence that the classical bridge is needed at all.");
    return;
  }

  var pqc = await certs.pair();
  var classic = await certs.pair({
    algorithm:     certs.ALGORITHM_CLASSIC,
    interopReason: "the case below is what measures whether this bridge is still needed",
  });

  var args = [nodePath.join(workDir, "probe.py")];
  nodeFs.writeFileSync(args[0], PROBE_SOURCE, "utf8");
  [pqc, classic].forEach(function (m) {
    var chainFile = nodePath.join(workDir, m.algorithm + "-chain.pem");
    var keyFile   = nodePath.join(workDir, m.algorithm + "-key.pem");
    nodeFs.writeFileSync(chainFile, m.chain, "utf8");
    nodeFs.writeFileSync(keyFile, m.key, "utf8");
    args.push(m.algorithm, chainFile, keyFile);
  });

  var rv = await foreign.run(client.bin, args, { timeoutMs: PROBE_CEILING_MS });
  var said = rv.stdout.toString("utf8") + rv.stderr.toString("utf8");
  var oneLine = said.replace(/[\r\n]+/g, " ").trim().slice(0, 300);

  count("the foreign stack ran and reported which build it is",
    rv.started && /^OPENSSL OpenSSL /m.test(said),
    "exit " + rv.code + (rv.timedOut ? " (timed out)" : "") + ": " + oneLine);
  if (!/^OPENSSL OpenSSL /m.test(said)) return;

  console.log("  foreign stack: " + client.bin + " -- " + client.detail);
  console.log("  it said:       " + oneLine);

  count("the classical bridge is one that stack can actually use",
    new RegExp("^USABLE " + certs.ALGORITHM_CLASSIC + "$", "m").test(said), oneLine);

  // The trip-wire. It reports the interval this bridge exists for. The
  // answer depends on which OpenSSL the host's foreign stack carries:
  // 3.0, which current long-term distributions ship, cannot use the
  // post-quantum default, and 3.5 can. A host whose stack can use it
  // says nothing about the clients that still need the bridge, so the
  // case records a named skip there rather than a pass. The bridge is
  // retired once every supported client stack reads USABLE here.
  if (new RegExp("^USABLE " + certs.ALGORITHM_PQC + "\\b", "m").test(said)) {
    helpers.skip("the foreign stack on this host (" + client.detail + ") can use " +
      certs.ALGORITHM_PQC + ", so this host does not measure whether " +
      certs.ALGORITHM_CLASSIC + " is still needed. A host whose stack carries OpenSSL 3.0 " +
      "does; retire the bridge once no supported client stack needs it.");
    return;
  }
  count("the post-quantum default is still one that stack cannot use, " +
    "which is why the bridge exists",
    new RegExp("^UNUSABLE " + certs.ALGORITHM_PQC + "\\b", "m").test(said),
    oneLine);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  var workDir = helpers.tempDir("certificate-algorithm");
  try {
    await helpers.withTestTimeout("certificate-algorithm: minting the contract cases",
      async function () {
        await theDefaultIsThePostQuantumOne();
        await anExplicitChoiceIsHonored();
        await theWaysOfGettingItWrongAreRefused();
        await theRefusalsAreNotJustRefusingEverything();
      }, { timeoutMs: MINT_CEILING_MS });
    await aStackThatIsNotThisOneIsAsked(workDir);
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(workDir);
  }
}

module.exports = { name: "test-certificate-algorithm", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
