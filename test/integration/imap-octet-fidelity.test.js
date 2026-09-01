// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A message goes in through one client and comes back out through the
 * same one, and the octets are compared. Nothing in this file is this
 * codebase's opinion of what it emitted.
 *
 * The layered suites build the server inside the test process and assert
 * against it, so what they check is this project's own accounting of the
 * bytes. That accounting is the thing that has been wrong here: a
 * submission stored a 260-octet message as 1,178 octets, corrupting the
 * relayed copy and the stored copy, and signing the result. Every test
 * covering it read the same counter that was doing the miscounting, so
 * every one of them agreed.
 *
 * The judge here is curl, an independent C implementation of IMAP that
 * shares no code with this repository. It is what decides how many
 * octets to announce in the APPEND literal, and it is what reads the
 * literal count in the response and stops there. If this server's idea
 * of a length and a foreign parser's disagree, the disagreement lands in
 * the bytes curl writes out, which is the only place it can be seen.
 *
 * ## The fixture, and why it is shaped like that
 *
 * The body carries two things at once and needs both:
 *
 *   - Octets that are NOT valid UTF-8. Mail carries them. An 8BITMIME
 *     peer sends a Latin-1 body and an unencoded 8-bit header field is
 *     ordinary. Decoding one replaces it with U+FFFD, which is three
 *     octets where there was one, so a server that decodes returns
 *     neither the message that was stored nor the size it reported.
 *
 *   - A length in octets that differs from the length in UTF-16 code
 *     units, which is what a decoded copy of the same message measures.
 *     The fixture is 248 octets and 244 code units, so the last four
 *     octets of the message are past the end of its decoded form. A
 *     window addressed there is inside the message and would come back
 *     empty from a server slicing text.
 *
 * Both matter because the two only agree while every octet is ASCII, and
 * a fixture that is all ASCII cannot tell the two implementations apart.
 *
 * ## What is checked
 *
 * RFC 9051 section 6.4.5 defines the partial fetch `<start.count>` on
 * octets, and section 4.3 gives the literal an octet count that tells a
 * client where the response ends. RFC 4315 section 3 gives the APPEND
 * response the UID the server assigned. So:
 *
 *   - the whole message comes back byte for byte,
 *   - RFC822.SIZE is the octet count that was stored,
 *   - a window addressed in octets is served in octets, over the
 *     multi-byte run and over the run that is not valid UTF-8,
 *   - a window past the decoded length still has octets in it,
 *   - and a client walking the message by the counts it is handed
 *     reassembles it exactly and terminates where the message ends.
 *
 * The walk is the claim a real client relies on, and its window size is
 * deliberately not a divisor of anything: a walk whose windows line up
 * with the characters can reassemble a message even from a server
 * counting the wrong unit, which is how a case like this passes with the
 * defect live.
 *
 * Two controls run first, because a file that cannot fail is not
 * evidence. The comparison is handed a copy with one octet changed and
 * has to report it, which proves the comparison is live rather than
 * agreeing with everything. And a fetch of a UID that was never appended
 * has to come back with nothing, which proves the payload of every other
 * fetch arrived because the server sent it.
 *
 * ## What this file does not do
 *
 * It drives port 143 and upgrades in band with STARTTLS, which is the
 * posture this server ships. It does not drive IMAPS, and that is a
 * statement about the server rather than a gap here. Nothing binds 993:
 * the mailbox listeners negotiate TLS in band and an operator wanting
 * implicit TLS is told to put a terminator in front of 143. Behind one,
 * the listener sees a plaintext connection and answers every credential
 * with `BAD AUTHENTICATE requires TLS (use STARTTLS first)`, so no
 * client can sign in at all. It is the correct refusal from a listener
 * that cannot see the TLS it is behind, and there is no implicit-TLS
 * mode and no trusted-terminator path on this listener to tell it
 * otherwise. An IMAPS vector opens here the day one of those exists.
 *
 * It does not delete the message it appends. Removing it means EXPUNGE,
 * which routes through the retention floor and the legal-hold substrate
 * and can refuse per message by design. A refusal there is a correct
 * answer to a different question, and a file that quietly depended on it
 * would report a retention refusal as an octet failure. Each run
 * addresses the UID the server assigned to its own APPEND, so a mailbox
 * holding earlier runs changes nothing.
 *
 * ## Running it
 *
 * `node scripts/test-integration.js` runs this after
 * `scripts/check-services.js` reports the listeners answering. The
 * server is expected to already host a domain and an account; nothing
 * here provisions one, because provisioning is an operator step and a
 * test that did it would be driving this codebase again.
 *
 * Environment:
 *   BLAMEPOST_INTEROP_HOST       host the client dials. Default 127.0.0.1.
 *   BLAMEPOST_INTEROP_IMAP_PORT  IMAP port, for a server that moved it
 *                                off 143. Default 143. The session is
 *                                upgraded in band whichever port it is,
 *                                because that is the only way this
 *                                listener reaches an encrypted state.
 *   BLAMEPOST_INTEROP_ADDRESS    the account the client signs in as.
 *   BLAMEPOST_INTEROP_PASSWORD   its password.
 *   BLAMEPOST_INTEROP_CA         PEM the client verifies the chain
 *                                against. Required unless a skip of
 *                                verification is declared.
 *   BLAMEPOST_INTEROP_TLS_INSECURE
 *                                "1", and only "1", declares that the
 *                                run accepts an unverified chain. It is
 *                                written down so it can be read back;
 *                                an absent CA is not that declaration.
 *   BLAMEPOST_CURL_BIN           an explicit curl, for a machine whose
 *                                curl is not the one on the path.
 *
 * The address and the password are REQUIRED and their absence is a
 * failure, not a skip. A stack that is up and holds no account the suite
 * can sign in as is a stack this file can prove nothing about, and a
 * gate that shrugged at that would stop gating on the day somebody
 * forgot to provision it, which is the state the empty-suite exit code
 * exists to keep visible.
 *
 * Run standalone: node test/integration/imap-octet-fidelity.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers = require("../helpers");
var foreign = require("../helpers/foreign-client");

var count = helpers.count;

// A ceiling on one client invocation. Every call here is a single short
// IMAP session against loopback; anything near this is a hang.
var CLIENT_TIMEOUT_MS = 30000;

// curl's exit code for a resource the server did not return, which is
// what a fetch of a UID that was never appended has to produce.
var CURLE_REMOTE_FILE_NOT_FOUND = 78;

// The window the walk advances by. Not a divisor of the message and not
// a multiple of any character width in it, so a walk that lines up with
// the characters cannot rebuild the message by accident.
var WALK_WINDOW = 7;

// How many windows the walk is allowed before it is called a runaway.
// The fixture needs five; a walk that never terminates is a server
// answering an out-of-range window with data, and it must not spin.
var WALK_CEILING = 64;

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

// A Message-ID that belongs to this run alone, so a mailbox carrying
// earlier runs is unambiguous to anybody reading it later. The UID the
// server assigns is what the cases address; this is for the human.
var RUN_ID = nodeCrypto.randomBytes(8).toString("hex");

var HEADER = Buffer.from([
  "From: sender@example.net",
  "Subject: octet fidelity probe",
  "Date: Mon, 24 Aug 2026 12:00:00 +0000",
  "Message-ID: <interop-octet-" + RUN_ID + "@example.net>",
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=iso-8859-1",
  "",
  "",
].join("\r\n"), "ascii");

// The body, laid out so an octet window and a character window over it
// cannot coincide:
//
//   offset  0  aaaa                    4 octets,  4 characters
//   offset  4  U+00E9 x4 as UTF-8      8 octets,  4 characters
//   offset 12  bbbbbbbb                8 octets,  8 characters
//   offset 20  "premi" 0xe8 "re"       8 octets, not valid UTF-8
//   offset 28  CRLF                    2 octets
//
// 0xe8 is `e` grave in Latin-1 and is a valid octet in a mail body. It
// is not valid UTF-8 anywhere in this message, so a decode of the body
// cannot round trip and the length of the decoded copy is not the length
// of the message.
var BODY = Buffer.concat([
  Buffer.from("aaaa", "ascii"),
  Buffer.from("éééé", "utf8"),
  Buffer.from("bbbbbbbb", "ascii"),
  Buffer.from([0x70, 0x72, 0x65, 0x6d, 0x69, 0xe8, 0x72, 0x65]),
  Buffer.from("\r\n", "ascii"),
]);

var MESSAGE = Buffer.concat([HEADER, BODY]);

// Where the interesting runs are, derived rather than written down, so
// editing a header line cannot leave a window pointing somewhere else
// while the case still says the words it was written to say.
var BODY_AT       = HEADER.length;
var MULTIBYTE_AT  = BODY_AT + 4;    // the four accented characters
var MULTIBYTE_LEN = 8;
var EIGHT_BIT_AT  = BODY_AT + 20;   // the run that is not valid UTF-8
var EIGHT_BIT_LEN = 8;

// The message measured the way a decoded copy of it measures. Every
// octet past this point is inside the message and past the end of its
// decoded form, which is the window the last case asks for.
var DECODED_LENGTH = MESSAGE.toString("utf8").length;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function _required(name, what) {
  var value = process.env[name];
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(
    "interop: " + name + " is not set, and it is " + what + ". This file drives a running " +
    "server as a mailbox owner and cannot invent one. On a stack brought up from " +
    "compose.yml:\n" +
    "  docker compose exec blamepost node bin/blamepost.js domain add example.com\n" +
    "  docker compose exec blamepost node bin/blamepost.js account add alice@example.com " +
    "--password <secret>\n" +
    "then set BLAMEPOST_INTEROP_ADDRESS and BLAMEPOST_INTEROP_PASSWORD to that pair. A skip " +
    "here would report a stack nobody provisioned as a gate that ran.");
}

function readConfig() {
  // The account first. It is the setting an unprovisioned stack is
  // missing, and reporting a TLS argument to somebody who has not
  // created a mailbox yet sends them to the wrong problem.
  var address  = _required("BLAMEPOST_INTEROP_ADDRESS", "the account the client signs in as");
  var password = _required("BLAMEPOST_INTEROP_PASSWORD", "that account's password");

  var host = process.env.BLAMEPOST_INTEROP_HOST || "127.0.0.1";
  var portText = process.env.BLAMEPOST_INTEROP_IMAP_PORT || "143";
  var port = Number(portText);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new TypeError("interop: BLAMEPOST_INTEROP_IMAP_PORT must be a TCP port, got " +
      JSON.stringify(portText));
  }

  var caFile   = process.env.BLAMEPOST_INTEROP_CA || null;
  var insecure = process.env.BLAMEPOST_INTEROP_TLS_INSECURE;
  if (insecure !== undefined && insecure !== "1") {
    throw new TypeError("interop: BLAMEPOST_INTEROP_TLS_INSECURE is \"1\" or unset. Any other " +
      "value is refused rather than guessed at, because a misspelt opt-out that silently " +
      "verifies (or silently does not) is the ambiguity it exists to remove.");
  }
  if (caFile === null && insecure !== "1") {
    throw new Error("interop: set BLAMEPOST_INTEROP_CA to the PEM the listener's chain is " +
      "verified against, or declare BLAMEPOST_INTEROP_TLS_INSECURE=1. Every listener here " +
      "requires TLS, and a client that verified nothing would report the same green against " +
      "any server that answered the port.");
  }
  if (caFile !== null && !nodeFs.existsSync(caFile)) {
    throw new Error("interop: BLAMEPOST_INTEROP_CA names " + caFile + ", which is not there.");
  }

  return {
    host:     host,
    port:     port,
    address:  address,
    password: password,
    caFile:   caFile,
    verify:   caFile !== null,
  };
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

// curl reports the protocols its build was compiled with in its own
// version banner. A curl without IMAP is on the path, answers
// `--version`, and cannot open a mailbox, so the capability is read out
// of what it says about itself rather than assumed from the name.
var CURL = {
  name:            "curl",
  envVar:          "BLAMEPOST_CURL_BIN",
  candidates:      ["curl"],
  probeArgs:       ["--version"],
  requireInOutput: /^Protocols:.*\bimaps?\b/m,
  timeoutMs:       CLIENT_TIMEOUT_MS,
};

// The IMAP URL this run addresses, RFC 5092. `;UID=` names the message
// and `;PARTIAL=<start>.<count>` names a window of it in octets, which
// is the whole point: the offset the client writes here and the count
// the server answers with have to be the same unit.
function url(cfg, suffix) {
  return "imap://" + cfg.host + ":" + cfg.port + "/INBOX" + (suffix || "");
}

// Everything every invocation carries. `--ssl-reqd` is not decoration:
// without it curl would continue in the clear if the upgrade failed, and
// a case that passed over an unencrypted session would be proving
// something about a server this project does not ship.
//
// `--ssl-no-revoke` is scoped to revocation checking and to the backends
// that do it in the first place. A private authority minted for a test
// run publishes no revocation list, so the check cannot succeed and is
// not what any case here is about. The chain itself is still verified,
// against `--cacert`, whenever a CA was named.
function baseArgs(cfg) {
  var args = ["--silent", "--show-error", "--ssl-no-revoke", "--ssl-reqd"];
  if (cfg.verify) args.push("--cacert", cfg.caFile);
  else args.push("--insecure");
  args.push("--user", cfg.address + ":" + cfg.password);
  return args;
}

// The listeners cap how many connections one source address may open in
// a rolling minute, and every listener answers over that cap with the
// same sentence. It is a correct answer to a different question, and
// nothing about the octets can be read out of a session that was never
// admitted. So it is recognized by the sentence the listener sends
// rather than left to surface as an empty payload, which is what it
// looks like from a client and is indistinguishable from a server that
// returned nothing.
//
// It is a failure and not a retry. A retry loop would turn a listener
// that refuses every time into a slow pass, and the count below is the
// number a reader compares against the ceiling to see whether the file
// or something else on the machine spent the budget.
var CEILING_REFUSAL_RE = /Too many connections from your IP/;

// Connections one run of this file opens, so the message above can say
// what the file itself costs: one to prove the client returns only what
// the server sent, one to append, one for the reads, one for the size,
// one for the walk. Fetches that belong together share a session, which
// is both what a mail client does and what keeps this number a twentieth
// of the shipped ceiling rather than most of it.
var CONNECTIONS_PER_RUN = 5;

function refusedByCeiling(rv) {
  return CEILING_REFUSAL_RE.test(rv.stderr.toString("utf8") + rv.stdout.toString("utf8"));
}

// A session the listener never admitted carries no answer about octets,
// so it stops the file here rather than reaching a comparison. From a
// client the refusal looks like an empty payload, which is
// indistinguishable from a message the server does not have, and a case
// that read one as the other would report a refused connection as a
// short message.
function refuseIfCeiling(rv, what) {
  if (!refusedByCeiling(rv)) return;
  throw new Error("interop: " + what + " was refused before the session began. " + said(rv));
}

// What a failed invocation says, bounded so a message body cannot forge
// extra rows in a report.
function said(rv) {
  var text = rv.stderr.toString("utf8") + rv.stdout.toString("utf8");
  var detail = "exit " + rv.code + (rv.timedOut ? " (timed out)" : "") + ": " +
    text.replace(/[\r\n]+/g, " ").trim().slice(0, 300);
  if (!refusedByCeiling(rv)) return detail;
  return detail + " -- this is the per-address connection ceiling, not an octet result. " +
    "One run of this file opens about " + CONNECTIONS_PER_RUN + " connections; compare that " +
    "against limits.connectionsPerIpPerMinute and against anything else reaching this " +
    "listener from the same address.";
}

// One IMAP session that fetches several windows. curl reuses the
// connection across the URLs of a single invocation, so this is one
// sign-in and a series of FETCH commands, which is what a mail client
// does and is not what a fresh process per assertion does. The
// difference is not only tidiness: the listeners cap connections per
// address per minute, and a file that opened one session per assertion
// spends that budget on nothing.
//
// Each window is written to its own file rather than read off a pipe. A
// payload that comes back through a pipe and is turned into a string on
// the way has been decoded, and a decode is the transformation every
// case here exists to detect.
// Each output file is removed BEFORE the client runs. A request the
// client never completed leaves the previous answer on disk, and reading
// that back is a case comparing one window against the octets of
// another and finding them plausible. The walk found this the hard way:
// re-reading a stale window advanced it by a count nothing had answered,
// and it walked until its own ceiling stopped it.
//
// `--verbose` is on because the reply line is evidence. The body still
// goes to the output file; what verbose adds to stderr is the protocol
// exchange, which is where a refusal says which refusal it is. Without
// it a connection the listener declined and a message the server does
// not have look identical from here: both are an empty file.
async function fetchWindows(cfg, client, requests) {
  var args = baseArgs(cfg).concat(["--verbose"]);
  requests.forEach(function (r) {
    try { nodeFs.rmSync(r.into, { force: true }); }
    catch (_e) { /* drop-silent by design: the existsSync below decides what was written */ }
    args.push("--output", r.into, "--url", url(cfg, r.suffix));
  });
  var rv = await foreign.run(client.bin, args, { timeoutMs: CLIENT_TIMEOUT_MS });
  refuseIfCeiling(rv, "a fetch of " + requests.length + " window(s)");
  var bytes = requests.map(function (r) {
    return nodeFs.existsSync(r.into) ? nodeFs.readFileSync(r.into) : Buffer.alloc(0);
  });
  return { rv: rv, bytes: bytes };
}

// The single-window form, for the walk, whose next offset is decided by
// the answer to the one before it and so cannot be batched.
async function fetchOctets(cfg, client, suffix, into) {
  var got = await fetchWindows(cfg, client, [{ suffix: suffix, into: into }]);
  return { rv: got.rv, bytes: got.bytes[0] };
}

// One command whose answer is the transcript rather than a payload:
// RFC822.SIZE, and the APPEND that reports the UID it assigned. curl
// echoes each server line it read, so the reply is quoted verbatim, and
// what is matched in it is the protocol's own frozen shape rather than
// curl's framing of it.
async function transcript(cfg, client, extra) {
  var args = baseArgs(cfg).concat(["--verbose"]).concat(extra);
  var rv = await foreign.run(client.bin, args, { timeoutMs: CLIENT_TIMEOUT_MS });
  refuseIfCeiling(rv, "a command session");
  return { rv: rv, text: rv.stderr.toString("utf8") + rv.stdout.toString("utf8") };
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

// A comparison that agrees with everything reports the same green on a
// corrupted message as on a correct one. This hands it a copy with one
// octet changed and requires it to object, so every equality asserted
// below is known to be capable of failing.
function theComparisonCanFail() {
  var mutated = Buffer.from(MESSAGE);
  mutated[EIGHT_BIT_AT + 5] = mutated[EIGHT_BIT_AT + 5] ^ 0xff;
  count("control: the byte comparison objects to a message with one octet changed",
    mutated.equals(MESSAGE) === false,
    "mutated offset " + (EIGHT_BIT_AT + 5) + " of " + MESSAGE.length);
  count("control: and still accepts the message itself",
    Buffer.from(MESSAGE).equals(MESSAGE), MESSAGE.length + " octets");
}

// Every payload below arrives in a file the client wrote. A file left
// behind by an earlier step, or a client that wrote nothing while the
// case read a stale copy, would make the comparison agree for a reason
// nobody chose. Asking for a UID the server never assigned proves the
// bytes come from the server: it has to answer with nothing.
async function theClientOnlyReturnsWhatTheServerSent(cfg, client, workDir) {
  var absent = nodePath.join(workDir, "absent.bin");
  var got = await fetchOctets(cfg, client, ";UID=4294967290", absent);
  count("control: a fetch of a UID that was never appended returns no octets",
    got.bytes.length === 0, got.bytes.length + " octets, " + said(got.rv));
  count("control: and the client reports it as a resource the server did not return",
    got.rv.code === CURLE_REMOTE_FILE_NOT_FOUND,
    "exit " + got.rv.code + ", expected " + CURLE_REMOTE_FILE_NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// The client frames the APPEND literal itself: it announces the octet
// count it measured on the file, waits for the continuation, and sends
// exactly that many octets. RFC 4315 section 3 has the tagged OK carry
// APPENDUID with the UID assigned, which is what every case addresses,
// so a mailbox holding earlier runs is not something this file has to
// reason about.
async function appendReturnsTheUidItAssigned(cfg, client, workDir) {
  var file = nodePath.join(workDir, "message.eml");
  nodeFs.writeFileSync(file, MESSAGE);

  var seen = await transcript(cfg, client,
    ["--upload-file", file, "--url", url(cfg, "")]);

  count("a message carrying octets that are not valid UTF-8 is accepted",
    seen.rv.started && seen.rv.code === 0, said(seen.rv));
  count("and the client announced the stored octet count in the literal",
    new RegExp("APPEND [^\\r\\n]*\\{" + MESSAGE.length + "\\}").test(seen.text),
    "expected a {" + MESSAGE.length + "} literal in " +
      seen.text.replace(/[\r\n]+/g, " ").slice(-300));

  var assigned = /\[APPENDUID\s+(\d+)\s+(\d+)\]/.exec(seen.text);
  count("the server reports the UID it assigned",
    assigned !== null, seen.text.replace(/[\r\n]+/g, " ").slice(-300));
  if (assigned === null) {
    throw new Error("interop: the APPEND did not report an APPENDUID, so there is no message " +
      "for the cases below to address. What the client saw: " +
      seen.text.replace(/[\r\n]+/g, " ").slice(-500));
  }
  return { uidValidity: assigned[1], uid: assigned[2] };
}

// The whole message and the three windows, in ONE session. Every one of
// them is a claim about the same stored message, and issuing them down a
// single connection is what a mail client does; a session per assertion
// is not a client, it is a burst.
//
// The window offsets are derived from the fixture rather than written
// down, so editing a header line moves them together instead of leaving
// a case pointing somewhere else while still saying the words it was
// written to say.
async function theStoredOctetsComeBack(cfg, client, uid, workDir) {
  var tailAt  = DECODED_LENGTH;
  var tailLen = MESSAGE.length - DECODED_LENGTH;

  // Canary: with an all-ASCII fixture the octet length and the decoded
  // length are equal, the tail window asks for nothing, and the case
  // that is the whole reason for the 8-bit octets reports a pass having
  // compared two empty buffers.
  count("the fixture is longer in octets than the decoding of it is in code units",
    tailLen > 0, MESSAGE.length + " octets, " + DECODED_LENGTH + " code units");

  var reads = [
    {
      label:  "the whole message",
      suffix: ";UID=" + uid,
      into:   nodePath.join(workDir, "whole.bin"),
      wanted: MESSAGE,
    },
    {
      label:  "a window over a run of multi-byte characters",
      suffix: ";UID=" + uid + ";PARTIAL=" + MULTIBYTE_AT + "." + MULTIBYTE_LEN,
      into:   nodePath.join(workDir, "window-multibyte.bin"),
      wanted: MESSAGE.subarray(MULTIBYTE_AT, MULTIBYTE_AT + MULTIBYTE_LEN),
    },
    {
      label:  "a window over a run that is not valid UTF-8",
      suffix: ";UID=" + uid + ";PARTIAL=" + EIGHT_BIT_AT + "." + EIGHT_BIT_LEN,
      into:   nodePath.join(workDir, "window-eightbit.bin"),
      wanted: MESSAGE.subarray(EIGHT_BIT_AT, EIGHT_BIT_AT + EIGHT_BIT_LEN),
    },
    {
      label:  "a window starting past the decoded length",
      suffix: ";UID=" + uid + ";PARTIAL=" + tailAt + "." + tailLen,
      into:   nodePath.join(workDir, "window-tail.bin"),
      wanted: MESSAGE.subarray(tailAt, tailAt + tailLen),
    },
  ];

  var got = await fetchWindows(cfg, client, reads);
  count("the reads are answered in one session",
    got.rv.code === 0, said(got.rv));

  for (var i = 0; i < reads.length; i += 1) {
    var r = reads[i];
    var have = got.bytes[i];
    count(r.label + " returns the octet count it asked for",
      have.length === r.wanted.length,
      "asked for " + r.wanted.length + ", got " + have.length);
    count(r.label + " returns the stored octets",
      have.equals(r.wanted),
      "got " + nodeCrypto.createHash("sha256").update(have).digest("hex") +
        " (" + have.length + " octets), stored " +
        nodeCrypto.createHash("sha256").update(r.wanted).digest("hex") +
        " (" + r.wanted.length + " octets)");
  }
}

// RFC822.SIZE is what a client allocates on before it asks for the body.
// A size that is not the octet count is a client reading a message into
// a buffer of the wrong length.
async function reportedSizeIsTheStoredOctetCount(cfg, client, uid) {
  var seen = await transcript(cfg, client,
    ["--request", "UID FETCH " + uid + " (RFC822.SIZE)", "--url", url(cfg, "")]);

  count("the server answers a size for the message",
    seen.rv.code === 0, said(seen.rv));
  var reported = /RFC822\.SIZE\s+(\d+)/.exec(seen.text);
  count("and it reports one",
    reported !== null, seen.text.replace(/[\r\n]+/g, " ").slice(-300));
  if (reported === null) return;
  count("RFC822.SIZE is the octet count that was stored, not the length of a decoding of it",
    parseInt(reported[1], 10) === MESSAGE.length,
    "reported " + reported[1] + ", stored " + MESSAGE.length +
      ", decoded length " + DECODED_LENGTH);
}

// The claim a real client actually relies on. Reading a large body means
// asking at an offset, taking what arrives, advancing by that many
// octets and asking again. The walk only terminates on the right message
// when the offset the client names and the count the server answers are
// the same unit.
//
// The windows go down ONE session, at the offsets a correct walk visits,
// and the walk is then replayed against the answers: start at zero, take
// the window that was asked for at that offset, advance by the count
// that came back, and require the next window to be the one already at
// that offset. A server that answered short in the middle lands the
// advance somewhere no window was asked for, and that is the failure.
//
// This is what a sequential walk asserts, and it is stricter, because a
// sequential walk re-aims at whatever it is given and would rebuild the
// message from short windows without ever saying they were short. It is
// also one connection instead of thirty-seven, which matters: the
// listeners cap connections per address per minute, and a claim about
// octets should not spend two thirds of an operator's budget to make
// itself.
async function aWalkByTheCountsGivenRebuildsTheMessage(cfg, client, uid, workDir) {
  function window(at) {
    return {
      at:     at,
      suffix: ";UID=" + uid + ";PARTIAL=" + at + "." + WALK_WINDOW,
      into:   nodePath.join(workDir, "walk-" + at + ".bin"),
    };
  }
  var planned = [];
  for (var at = 0; at < MESSAGE.length && planned.length < WALK_CEILING; at += WALK_WINDOW) {
    planned.push(window(at));
  }
  // The window a walk asks for after it has consumed the message. It is
  // planned explicitly rather than left to the stride, which lands on it
  // only when the window size happens to divide the message: with a
  // stride that does not, the loop above stops one window short and the
  // case that proves the walk terminates would be reading the tail of
  // the message instead.
  planned.push(window(MESSAGE.length));
  count("the walk is bounded rather than planned forever",
    planned.length < WALK_CEILING,
    planned.length + " windows of " + WALK_WINDOW + " octets over " + MESSAGE.length);

  var got = await fetchWindows(cfg, client, planned);
  count("every window of the walk is answered in one session",
    got.rv.code === 0, said(got.rv));

  var pieces = [];
  var walked = 0;
  var offGrid = null;
  for (var i = 0; i < planned.length; i += 1) {
    if (planned[i].at !== walked) { offGrid = { step: i, expected: walked, asked: planned[i].at }; break; }
    if (got.bytes[i].length === 0) break;
    pieces.push(got.bytes[i]);
    walked += got.bytes[i].length;
  }

  count("advancing by each count lands on the offset the next window was asked for",
    offGrid === null,
    offGrid === null ? "every step on grid"
      : "step " + offGrid.step + " advanced to " + offGrid.expected +
        " and the next window was asked for at " + offGrid.asked);
  count("it ends where the message ends",
    walked === MESSAGE.length, "walked to " + walked + ", message is " + MESSAGE.length);
  count("the window past the end of the message is empty",
    got.bytes[got.bytes.length - 1].length === 0,
    "last window at " + planned[planned.length - 1].at + " returned " +
      got.bytes[got.bytes.length - 1].length + " octets");

  var rebuilt = Buffer.concat(pieces);
  count("a client walking the message by the counts it is handed reassembles it exactly",
    rebuilt.equals(MESSAGE),
    "rebuilt " + rebuilt.length + " octets sha256 " +
      nodeCrypto.createHash("sha256").update(rebuilt).digest("hex") +
      ", appended " + MESSAGE.length + " octets sha256 " +
      nodeCrypto.createHash("sha256").update(MESSAGE).digest("hex"));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  var cfg = readConfig();

  var client = await foreign.locate(CURL);
  if (!client.found) {
    // Nothing was proven and nothing is claimed. The runner counts this
    // separately from a check, so a machine with no client cannot report
    // the same total as one that ran the cases.
    helpers.skip("the octet cases need an IMAP client that is not this codebase, and there " +
      "is not one here: " + client.reason + ". Install curl, or set BLAMEPOST_CURL_BIN to one " +
      "built with IMAP, and run this file again.");
    return helpers.getChecks();
  }

  // What went on the wire, printed rather than left to a failure
  // message. A run that passes should still say which octets it proved
  // something about, because the next reader of this log is somebody
  // asking whether the case that passed was the case they care about.
  console.log("  client:   " + client.bin + " -- " + client.detail);
  console.log("  fixture:  " + MESSAGE.length + " octets, " + DECODED_LENGTH +
    " code units decoded, sha256 " +
    nodeCrypto.createHash("sha256").update(MESSAGE).digest("hex"));
  console.log("  body:     " + BODY.length + " octets " + BODY.toString("hex"));
  console.log("  endpoint: " + url(cfg, "") + " as " + cfg.address +
    (cfg.verify ? " (chain verified against " + cfg.caFile + ")"
                : " (chain NOT verified: BLAMEPOST_INTEROP_TLS_INSECURE=1 was declared)"));

  var workDir = helpers.tempDir("interop-octets");
  try {
    theComparisonCanFail();
    await theClientOnlyReturnsWhatTheServerSent(cfg, client, workDir);

    var appended = await appendReturnsTheUidItAssigned(cfg, client, workDir);
    await theStoredOctetsComeBack(cfg, client, appended.uid, workDir);
    await reportedSizeIsTheStoredOctetCount(cfg, client, appended.uid);
    await aWalkByTheCountsGivenRebuildsTheMessage(cfg, client, appended.uid, workDir);

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(workDir);
  }
}

module.exports = { name: "imap-octet-fidelity", run: run, getChecks: helpers.getChecks };

// The runner parses `CHECKS <n>` and `SKIPS <n>` out of this file's stdout.
// Both are printed every run: a report that omits the skip line when there
// were none leaves a reader unable to tell a file with nothing skipped from
// one that forgot to say.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
    console.log("SKIPS " + helpers.getSkips());
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
