// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * How many ways there are to spell one password on the wire.
 *
 * SASL PLAIN carries its three fields base64-encoded, and RFC 4648
 * section 3.5 is explicit that the encoding has one canonical form: the
 * characters come in whole groups of four, and the bits a padded group
 * cannot use are zero. A decoder that ignores both rules accepts several
 * distinct lines for one credential, because `Buffer.from(x, "base64")`
 * silently drops what it cannot use rather than refusing. The same
 * sign-in can then arrive spelled differently every time.
 *
 * That matters in exactly the place it is hardest to notice. Nothing an
 * account holder does changes: their client emits the canonical form and
 * always did. What changes is everything downstream that treats the
 * response as an identifier: a log correlation, an intrusion signature,
 * a replay window, an operator grepping for a credential seen in a
 * breach dump. Each of those is defeated by an attacker appending one
 * character.
 *
 * One verifier serves all four authenticating listeners, so the rule is
 * shared and the vectors are not: submission, IMAP, POP3 and ManageSieve
 * each get their own session, because a rule several protocols share is
 * a rule that has to be read off each of their sockets. The refusal code
 * asserted is the one that protocol defines.
 *
 * The credential used is a real one, and every non-canonical spelling
 * below decodes to exactly it. So a listener that accepts one is not
 * being generous about formatting. It is accepting a line no conforming
 * client would send, on the strength of a password that happens to be
 * correct.
 *
 * Run standalone: node test/layer-2-integration/wire-sasl-canonical.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var NUL = String.fromCharCode(0);

var count = helpers.count;

// The credential as a conforming client encodes it.
function canonicalResponse(address, password) {
  return Buffer.from(NUL + address + NUL + password, "utf8").toString("base64");
}

// A response whose fields are octets rather than text. RFC 4616 section
// 2 puts the whole SASL PLAIN message in UTF-8, so a payload that is not
// valid UTF-8 is a line no conforming client sends. The decoder
// underneath does not refuse one: it replaces every sequence it cannot
// read with the replacement character, so responses carrying different
// octets arrive as one credential, which is the same many-to-one the
// encoding rule above exists to close.
function undecodableResponse(address, octets) {
  return Buffer.concat([
    Buffer.from(NUL + address + NUL, "utf8"),
    Buffer.from(octets),
  ]).toString("base64");
}

var UNDECODABLE_OCTETS = [
  { name: "0x80 0x80", octets: [0x80, 0x80] },
  { name: "0xFF 0xFE", octets: [0xFF, 0xFE] },
];

// The verifier is asked for a verdict only once the response has parsed,
// so the identity store is where the two kinds of refusal separate: a
// credential that is wrong reaches it and a line that is malformed does
// not. Counting the calls is the only way to read that from outside,
// because both refusals answer the same code on the wire.
function countAuthenticate(identity) {
  var accounts = identity.accounts;
  var original = accounts.authenticate;
  var state    = { asked: 0 };
  accounts.authenticate = function (credentials) {
    state.asked += 1;
    return original.call(accounts, credentials);
  };
  return state;
}

// A fifth character on the final group. It carries no whole byte, so
// the decoder drops it and the credential underneath is unchanged.
function trailingSextet(canonical) {
  return canonical + "A";
}

// One more padding character than the encoding calls for. Padding is
// positional rather than counted by a permissive check, so this passes
// an alphabet-and-padding test and decodes to the same bytes.
function overPadded(canonical) {
  return canonical + "=";
}

// Whitespace after the response. The submission and ManageSieve
// listeners hand the argument on exactly as the client wrote it, so
// this is a line the server sees with the space still on it.
function trailingSpace(canonical) {
  return canonical + " ";
}

// The spellings that are wrong in the encoding itself. Every listener
// hands these to the verifier exactly as the client wrote them, so
// refusing them is this server's decision on all four.
function encodingSpellings(address, password) {
  var canonical = canonicalResponse(address, password);
  return [
    { name: "a trailing sextet the decoder drops", value: trailingSextet(canonical) },
    { name: "one padding character too many",      value: overPadded(canonical) },
  ];
}

// The spelling that is wrong in the framing around it. Only the
// listeners that pass the argument through byte for byte can put this
// in front of the verifier: submission takes everything after the
// mechanism name, and ManageSieve takes a counted literal. IMAP strips
// the surrounding whitespace before the verifier is called and POP3
// splits its arguments on it, so on those two the space is gone before
// this server has an opinion about it, and asserting a refusal there
// would be asserting the framework's behavior rather than this one's.
function framingSpellings(address, password) {
  return [
    { name: "trailing whitespace", value: trailingSpace(canonicalResponse(address, password)) },
  ];
}

function spellings(address, password) {
  return encodingSpellings(address, password).concat(framingSpellings(address, password));
}

// The claim every case rests on: these are not different credentials,
// they are different spellings of one. Asserted rather than assumed,
// because a spelling that decoded to something else would make the
// refusals below prove nothing.
function everySpellingDecodesToTheSameCredential(address, password) {
  var want = NUL + address + NUL + password;
  spellings(address, password).forEach(function (spelling) {
    count("the response with " + spelling.name + " decodes to the same credential",
      Buffer.from(spelling.value, "base64").toString("utf8") === want,
      JSON.stringify(spelling.value.slice(-8)));
  });
}

// ---- submission ------------------------------------------------------------

async function submissionRefusesEverySpelling(port, caPem, address) {
  var canonical = canonicalResponse(address, ALICE_PASSWORD);
  var cases     = spellings(address, ALICE_PASSWORD);

  for (var i = 0; i < cases.length; i += 1) {
    var session = await Wire.connect(port, "submission-" + i);
    await session.read(/^220 /m, "banner");
    session.send("EHLO client.example.net");
    await session.read(/^250 /m, "EHLO accepted");
    session.send("STARTTLS");
    await session.read(/^220 /m, "STARTTLS accepted");
    await session.upgrade(caPem, HOSTNAME);
    session.send("EHLO client.example.net");
    await session.read(/^250 /m, "EHLO accepted over TLS");

    session.send("AUTH PLAIN " + cases[i].value);
    var reply = await session.read(/^\d{3} /m, "AUTH answered");
    count("submission refuses a PLAIN response with " + cases[i].name,
      !/^235 /m.test(reply), visible(reply));
    // RFC 4954 section 6 gives 535 to a failed authentication, and an
    // operator watching for credential abuse filters on that.
    count("and answers 535, the code RFC 4954 gives a failed AUTH",
      /^535 /m.test(reply), visible(reply));
    session.send("QUIT");
    session.close();
  }

  // The account still works, so the refusals above are about the
  // spelling and not about the password having stopped being right.
  var good = await Wire.connect(port, "submission-canonical");
  await good.read(/^220 /m, "banner");
  good.send("EHLO client.example.net");
  await good.read(/^250 /m, "EHLO accepted");
  good.send("STARTTLS");
  await good.read(/^220 /m, "STARTTLS accepted");
  await good.upgrade(caPem, HOSTNAME);
  good.send("EHLO client.example.net");
  await good.read(/^250 /m, "EHLO accepted over TLS");
  good.send("AUTH PLAIN " + canonical);
  var accepted = await good.read(/^\d{3} /m, "AUTH answered");
  count("while the canonical spelling of the same credential still signs in",
    /^235 /m.test(accepted), visible(accepted));
  good.send("QUIT");
  good.close();
}

// ---- IMAP ------------------------------------------------------------------

async function imapRefusesEverySpelling(port, caPem, address) {
  var canonical = canonicalResponse(address, ALICE_PASSWORD);
  var cases     = encodingSpellings(address, ALICE_PASSWORD);

  for (var i = 0; i < cases.length; i += 1) {
    var session = await Wire.connect(port, "imap-" + i);
    await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
    session.send("a0 STARTTLS");
    await session.read(/^a0 OK/m, "STARTTLS accepted");
    await session.upgrade(caPem, HOSTNAME);

    session.send("a1 AUTHENTICATE PLAIN " + cases[i].value);
    var reply = await session.read(/^a1 (OK|NO|BAD)/m, "AUTHENTICATE answered");
    count("IMAP refuses a PLAIN response with " + cases[i].name,
      !/^a1 OK/m.test(reply), visible(reply));
    // RFC 9051 section 6.2.2: a refused AUTHENTICATE is tagged NO. BAD
    // would say the command itself was unparseable, which it was not.
    count("and tags it NO, the response RFC 9051 gives a refused AUTHENTICATE",
      /^a1 NO/m.test(reply), visible(reply));
    session.close();
  }

  var good = await Wire.connect(port, "imap-canonical");
  await good.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  good.send("a0 STARTTLS");
  await good.read(/^a0 OK/m, "STARTTLS accepted");
  await good.upgrade(caPem, HOSTNAME);
  good.send("a1 AUTHENTICATE PLAIN " + canonical);
  var accepted = await good.read(/^a1 (OK|NO|BAD)/m, "AUTHENTICATE answered");
  count("while the canonical spelling still opens an IMAP session",
    /^a1 OK/m.test(accepted), visible(accepted));
  good.send("a2 LOGOUT");
  good.close();
}

// ---- POP3 ------------------------------------------------------------------

async function pop3RefusesEverySpelling(port, caPem, address) {
  var canonical = canonicalResponse(address, ALICE_PASSWORD);
  var cases     = encodingSpellings(address, ALICE_PASSWORD);

  for (var i = 0; i < cases.length; i += 1) {
    var session = await Wire.connect(port, "pop3-" + i);
    await session.read(/^\+OK /m, "greeting");
    session.send("STLS");
    await session.read(/^\+OK /m, "STLS accepted");
    await session.upgrade(caPem, HOSTNAME);

    session.send("AUTH PLAIN " + cases[i].value);
    var reply = await session.read(/^(\+OK|-ERR)/m, "AUTH answered");
    count("POP3 refuses a PLAIN response with " + cases[i].name,
      !/^\+OK/m.test(reply), visible(reply));
    // RFC 1939 section 3 has two replies and only one of them is a
    // refusal, so the code is the whole of what the client is told.
    count("and answers -ERR, the refusal RFC 1939 defines",
      /^-ERR/m.test(reply), visible(reply));
    session.send("QUIT");
    session.close();
  }

  var good = await Wire.connect(port, "pop3-canonical");
  await good.read(/^\+OK /m, "greeting");
  good.send("STLS");
  await good.read(/^\+OK /m, "STLS accepted");
  await good.upgrade(caPem, HOSTNAME);
  good.send("AUTH PLAIN " + canonical);
  var accepted = await good.read(/^(\+OK|-ERR)/m, "AUTH answered");
  count("while the canonical spelling still signs in over POP3",
    /^\+OK/m.test(accepted), visible(accepted));
  good.send("QUIT");
  good.close();
}

// ---- ManageSieve -----------------------------------------------------------

// RFC 5804 section 2.1 carries the initial response as a literal, so the
// response is framed by a byte count rather than by the line, and the
// command is terminated by CRLF after it. The count is written from the
// bytes actually sent, because a count that disagreed with them would
// be testing the framing rather than the encoding.
//
// A listener that does not consume that terminator reads it as a line
// with nothing on it and answers a refusal of its own beside the
// authentication verdict, which a client pairing replies with commands
// in order takes as the answer to its AUTHENTICATE. The vendored
// listener consumes it, and `sieve-managesieve-wire.test.js` is where
// that count is pinned. Here the verdict is picked out by CONTENT
// rather than by position, so this file asserts the same thing about
// the same credential whichever way that goes: what it is about is the
// encoding of the response, and a reply count is not evidence either
// way.
var MANAGESIEVE_TERMINATOR_COMPLAINT = "empty command line";

// The authentication verdict out of a transcript, told apart from the
// complaint above should one arrive beside it, in either order.
function manageSieveVerdict(text) {
  var lines = String(text).split("\r\n").filter(function (line) { return line.length > 0; });
  for (var i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i].indexOf(MANAGESIEVE_TERMINATOR_COMPLAINT) === -1) return lines[i];
  }
  return "";
}

async function manageSieveRefusesEverySpelling(port, caPem, address) {
  var canonical = canonicalResponse(address, ALICE_PASSWORD);
  var cases     = spellings(address, ALICE_PASSWORD);

  async function authenticate(session, response) {
    var size  = Buffer.byteLength(response, "utf8");
    var note  = 'AUTHENTICATE "PLAIN" {' + size + "+} <response> CRLF";
    session.sendRaw('AUTHENTICATE "PLAIN" {' + size + "+}\r\n" + response + "\r\n", note);
    var text = await session.read(/^(OK|NO|BYE)/m, "AUTHENTICATE answered");
    if (manageSieveVerdict(text) === "") {
      text += await session.read(/^(OK|NO|BYE)/m, "the authentication verdict");
    }
    return manageSieveVerdict(text);
  }

  for (var i = 0; i < cases.length; i += 1) {
    var session = await Wire.connect(port, "managesieve-" + i);
    await session.read(/^OK /m, "greeting");
    session.send("STARTTLS");
    await session.read(/^OK /m, "STARTTLS accepted");
    await session.upgrade(caPem, HOSTNAME);
    await session.read(/^OK /m, "capabilities after TLS");

    var reply = await authenticate(session, cases[i].value);
    count("ManageSieve refuses a PLAIN response with " + cases[i].name,
      reply.length > 0 && !/^OK/.test(reply), visible(reply));
    // RFC 5804 section 1.2: NO is the refusal. BYE would end the
    // session, which a wrong credential does not earn on its own.
    count("and answers NO, the refusal RFC 5804 defines",
      /^NO/.test(reply), visible(reply));
    session.send("LOGOUT");
    session.close();
  }

  var good = await Wire.connect(port, "managesieve-canonical");
  await good.read(/^OK /m, "greeting");
  good.send("STARTTLS");
  await good.read(/^OK /m, "STARTTLS accepted");
  await good.upgrade(caPem, HOSTNAME);
  await good.read(/^OK /m, "capabilities after TLS");
  var accepted = await authenticate(good, canonical);
  count("while the canonical spelling still signs in over ManageSieve",
    /^OK/.test(accepted), visible(accepted));
  good.send("LOGOUT");
  good.close();
}

// ---- octets that are not text ----------------------------------------------

// The claim the wire cases below rest on: these are not two credentials,
// they are two lines this server cannot tell apart. Asserted rather than
// assumed, because responses that decoded to different things would make
// the refusals prove nothing.
function twoResponsesCarryingDifferentOctetsArriveAsOneCredential(address) {
  var first  = undecodableResponse(address, UNDECODABLE_OCTETS[0].octets);
  var second = undecodableResponse(address, UNDECODABLE_OCTETS[1].octets);
  count("two responses carrying different octets are different lines",
    first !== second, JSON.stringify([first, second]));
  count("and the encoding rule refuses neither, because both are canonical base64",
    b.safeBuffer.isCanonicalBase64(first) && b.safeBuffer.isCanonicalBase64(second),
    JSON.stringify([first, second]));
  count("while a utf8 decode turns the two of them into one credential",
    Buffer.from(first, "base64").toString("utf8") ===
    Buffer.from(second, "base64").toString("utf8"),
    JSON.stringify(Buffer.from(first, "base64").toString("utf8")));
}

// One response that is not valid UTF-8, put in front of each of the four
// listeners a client authenticates against. The refusal is the protocol's
// own, and the identity store is not asked for a verdict on a line that
// never parsed: a malformed response is a permanent answer about the
// line rather than a guess at a password, and one that reaches the store
// spends the mailbox's failure budget on an attacker's behalf.
async function everyListenerRefusesAResponseItCannotDecode(sections, caPem, address, counter) {
  var response = undecodableResponse(address, UNDECODABLE_OCTETS[0].octets);
  var opts     = { caPem: caPem, servername: HOSTNAME };
  var before   = counter.asked;

  var submission = await Wire.submission(sections.submission.port,
    Object.assign({ label: "submission-octets" }, opts));
  submission.send("AUTH PLAIN " + response);
  var smtpReply = await submission.read(/^\d{3} /m, "AUTH answered");
  count("submission refuses a PLAIN response that is not valid UTF-8",
    /^535 /m.test(smtpReply), visible(smtpReply));
  submission.send("QUIT");
  submission.close();

  var imap = await Wire.imap(sections.imap.port, Object.assign({ label: "imap-octets" }, opts));
  var imapTag = imap.tag();
  imap.send(imapTag + " AUTHENTICATE PLAIN " + response);
  var imapReply = await imap.read(new RegExp("^" + imapTag + " (OK|NO|BAD)", "m"),
    "AUTHENTICATE answered");
  count("IMAP refuses it too, tagged NO",
    new RegExp("^" + imapTag + " NO", "m").test(imapReply), visible(imapReply));
  imap.close();

  var pop3 = await Wire.pop3(sections.pop3.port, Object.assign({ label: "pop3-octets" }, opts));
  pop3.send("AUTH PLAIN " + response);
  var pop3Reply = await pop3.read(/^(\+OK|-ERR)/m, "AUTH answered");
  count("POP3 refuses it too, with the one refusal RFC 1939 defines",
    /^-ERR/m.test(pop3Reply), visible(pop3Reply));
  pop3.send("QUIT");
  pop3.close();

  var sieve = await Wire.managesieve(sections.managesieve.port,
    Object.assign({ label: "managesieve-octets" }, opts));
  sieve.sendNonSyncLiteral('AUTHENTICATE "PLAIN"', response, "<the SASL response>");
  var sieveText = await sieve.read(/^(OK|NO|BYE)/m, "AUTHENTICATE answered");
  if (manageSieveVerdict(sieveText) === "") {
    sieveText += await sieve.read(/^(OK|NO|BYE)/m, "the authentication verdict");
  }
  count("ManageSieve refuses it too, with the NO RFC 5804 defines",
    /^NO/.test(manageSieveVerdict(sieveText)), visible(manageSieveVerdict(sieveText)));
  sieve.send("LOGOUT");
  sieve.close();

  count("and none of the four asked the identity store to rule on a line that never parsed",
    counter.asked === before, (counter.asked - before) + " call(s) reached the store");

  // The counter has to be able to move, or the claim above is satisfied
  // by an instrument that never counts anything.
  var control = await Wire.submission(sections.submission.port,
    Object.assign({ label: "submission-wrong-password" }, opts));
  control.send("AUTH PLAIN " + canonicalResponse(address, "not the password alice set 8830"));
  var controlReply = await control.read(/^\d{3} /m, "AUTH answered");
  count("while a well formed response carrying a wrong password does reach it",
    /^535 /m.test(controlReply) && counter.asked === before + 1,
    visible(controlReply) + " after " + (counter.asked - before) + " call(s)");
  control.send("QUIT");
  control.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("wire-sasl-canonical");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_POP3_ENABLED:     "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "sasl canonical test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var counter = countAuthenticate(identity);

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    everySpellingDecodesToTheSameCredential(alice.address, ALICE_PASSWORD);
    await submissionRefusesEverySpelling(sections.submission.port, leaf.ca, alice.address);
    await imapRefusesEverySpelling(sections.imap.port, leaf.ca, alice.address);
    await pop3RefusesEverySpelling(sections.pop3.port, leaf.ca, alice.address);
    await manageSieveRefusesEverySpelling(sections.managesieve.port, leaf.ca, alice.address);

    twoResponsesCarryingDifferentOctetsArriveAsOneCredential(alice.address);
    await everyListenerRefusesAResponseItCannotDecode(sections, leaf.ca, alice.address, counter);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "wire-sasl-canonical", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
