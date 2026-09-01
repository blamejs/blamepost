// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Who this server thinks you are when you send mail through it, asked
 * with clients that are not this codebase.
 *
 * Hard rule five is the most security-critical property here: an
 * authenticated account may only put its own addresses on the mail it
 * submits. Everything that enforces it lives behind a socket, and until
 * now every test of it was this project asking itself. A binding that
 * holds against an in-process fixture and fails against a real client is
 * a binding that holds against nobody, because the accounts that matter
 * arrive through Thunderbird, a phone, a cron script and a library.
 *
 * Two bindings, and they are not the same rule.
 *
 * ## The envelope binding
 *
 * `MAIL FROM` is the return path. A receiver bounces to it and never
 * shows it to anybody. The submission listener compares it against the
 * addresses the authenticated account owns, and refuses anything else
 * with `553 5.7.1 Sender address rejected: not owned by authenticated
 * identity`, at the command, before a recipient has been named.
 *
 * The refusal is only half the claim. The other half is that the SESSION
 * SURVIVES it. A client that guessed wrong once has to be able to
 * correct itself on the same connection, because that is what a real
 * client does: it tries the identity it was configured with, reads the
 * refusal, and tries another. A listener that dropped the connection
 * instead would be enforcing the same rule and would still be broken,
 * and no in-process test would notice, because a function call has no
 * connection to drop. So the cases below issue two refused envelopes and
 * then a good one down one socket, with no `RSET` in between, and
 * require the good one to complete.
 *
 * ## The author binding
 *
 * `From` is the address a person reads, and it is the one an
 * impersonation is written into. It is bound at the relay handoff rather
 * than at a command, so its refusal reaches the client as the
 * framework's `451 4.3.0 Local delivery error` at the end of the message
 * body. That text says nothing about authors and a transient code is a
 * poor fit for a permanent verdict; it is what the wire carries, so it
 * is what this file checks. Reading the intent out of the source and
 * calling that the client's experience is the error this whole layer
 * exists to stop making.
 *
 * The message is carried BOTH ways a client can carry one. The listener
 * advertises CHUNKING, so `BDAT` is a second door into the same handoff,
 * and a binding enforced on one door and not the other is a binding with
 * a documented way around it.
 *
 * ## What IS possible, which a refusal file has to say
 *
 * A file that only proves refusals reports the same green against a
 * server that refuses everything, so every refusal here is paired with
 * an acceptance: the account's own address, a display name wrapped
 * around it, the same address in another case, a subaddress of it, and
 * an outside author carrying the account's own address in `Sender`,
 * which is the on-behalf-of shape RFC 5322 section 3.6.2 describes.
 *
 * The subaddress is the one worth reading twice. `From` accepts a
 * subaddress of the account and `MAIL FROM` refuses the identical
 * string, so the two halves of one identity disagree about one address.
 * Both cases below are written as the measurement rather than as a
 * verdict on it.
 *
 * ## Two clients, and what each can answer
 *
 * Python's `smtplib` drives the sessions. It stays on the socket after a
 * refusal, which is the only way the survival claim can be measured at
 * all, and it reports a dead connection as an exception rather than as a
 * missing reply, so "the session survived" and "the session died" are
 * different observations rather than the same silence. Unlike `imaplib`
 * it has no version gate to fail, so it reaches this server where the
 * sibling file's client could not.
 *
 * curl is the second implementation, and it is not decoration: it is a C
 * codebase that shares nothing with Python's, and it reads the same
 * reply lines off the same listener. It cannot answer the survival
 * question, and the reason is a finding rather than a limitation: curl
 * abandons the connection the moment `MAIL FROM` is refused. That is the
 * client giving up, not the server hanging up, and it is exactly why the
 * survival claim needs a client that does not.
 *
 * ## Both clients are made to fail first
 *
 * A session that verified nothing reads the same from anything holding
 * the port, so each client is first pointed at a session it must refuse.
 * Python opens one with the run's authority left out and has to fail the
 * chain. curl dials a name the certificate does not carry and has to
 * fail the name. Between them the chain and the name are both known to
 * be live, and the sessions that follow are known to have been checked.
 *
 * ## Reading a failure here
 *
 * Every case is written to hold while the state it describes holds:
 *
 *   - A refusal that stops arriving is hard rule five no longer being
 *     enforced on that path, which is an open relay for every
 *     authenticated account.
 *   - An acceptance that stops arriving is an account that can no longer
 *     send its own mail.
 *   - A survival case that fails means the listener now drops the
 *     connection on a refused envelope, and every client that retries
 *     with a second identity has to reconnect and re-authenticate.
 *   - The subaddress pair failing means the two halves of the identity
 *     agreed, which is the good outcome and retires the pair.
 *
 * ## What this file does not do
 *
 * It does not provision. The account it signs in as has to exist
 * already, because provisioning is an operator step and a file that did
 * it would be driving this codebase again. That leaves one refusal
 * unmeasured: `553 5.7.1 Sender address rejected: authenticated identity
 * has no assigned mailboxes`, which needs an account holding no mailbox
 * at all. It is covered here the day this suite is handed the name of
 * such an account, in a variable of its own, and not before.
 *
 * It does not check that an accepted message LANDED. That is an IMAP
 * question and the sibling file in this directory owns that socket. What
 * is claimed for every acceptance is what the submission listener
 * answered, which is the property the refusals are measured against.
 *
 * It does not clean up after itself, and every accepted message is
 * addressed to the account itself, so a run leaves them in that
 * mailbox. Removing them would mean EXPUNGE, which routes through the
 * retention floor and the legal-hold substrate and can refuse per
 * message by design, and a file that quietly depended on that would
 * report a retention refusal as a submission failure. Each message
 * carries this run's identifier in its Message-ID, so a mailbox holding
 * earlier runs stays readable.
 *
 * ## Running it
 *
 * `node scripts/test-integration.js` runs this after
 * `scripts/check-services.js` reports the listeners answering.
 *
 * Environment:
 *   BLAMEPOST_INTEROP_HOST        where the listeners answer.
 *                                 Default 127.0.0.1.
 *   BLAMEPOST_INTEROP_SUBMISSION_PORT
 *                                 the submission port upgraded in band
 *                                 with STARTTLS. Default 587.
 *   BLAMEPOST_INTEROP_SUBMISSIONS_PORT
 *                                 the implicit-TLS submission port.
 *                                 Default 465.
 *   BLAMEPOST_INTEROP_SERVERNAME  the name the listener's certificate
 *                                 carries. curl dials this name and
 *                                 checks it. Default mx.example.com.
 *   BLAMEPOST_INTEROP_ADDRESS     the account the clients sign in as.
 *   BLAMEPOST_INTEROP_PASSWORD    its password.
 *   BLAMEPOST_INTEROP_CA          PEM the chain is verified against.
 *                                 Required: every case here reads what
 *                                 the server said on an encrypted
 *                                 session, and a session that verified
 *                                 nothing would read the same from
 *                                 anything answering the port. There is
 *                                 no opt-out in this file for that
 *                                 reason.
 *   BLAMEPOST_INTEROP_UNOWNED_ADDRESS
 *                                 optional. An address at a domain this
 *                                 server hosts that the account does NOT
 *                                 hold, such as a colleague's mailbox.
 *                                 Left unset, one is derived from the
 *                                 account's own domain with a local part
 *                                 carrying this run's identifier, which
 *                                 no account can be holding.
 *   BLAMEPOST_PYTHON_BIN          an explicit interpreter.
 *   BLAMEPOST_CURL_BIN            an explicit curl.
 *
 * The address and the password are REQUIRED and their absence is a
 * failure, not a skip. A stack that is up and holds no account this file
 * can sign in as is a stack it can prove nothing about, and a gate that
 * shrugged at that would stop gating on the day somebody forgot to
 * provision it.
 *
 * Run standalone: node test/integration/smtp-submission.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers = require("../helpers");
var foreign = require("../helpers/foreign-client");

var count = helpers.count;

// A ceiling on one client invocation. Every session here is a handful of
// short commands against loopback; anything near this is a hang.
var CLIENT_TIMEOUT_MS = 60000;

// What the driver gives one socket before it calls it dead. Smaller than
// the ceiling above, so a stalled listener surfaces as the driver's own
// timeout on a named step rather than as a killed process with no
// transcript.
var SESSION_TIMEOUT_S = 20;

// curl's exit codes, from its manual. They are the frozen contract for
// "this transfer did not happen and here is the class of reason", and
// they are what a script wrapping curl actually branches on.
var CURLE_WEIRD_SERVER_REPLY   = 8;
var CURLE_SEND_ERROR           = 55;
var CURLE_PEER_FAILED_VERIFY   = 60;

// The name this suite's clients announce in EHLO. RFC 2606 reserves
// example.net for exactly this.
var HELO = "client.example.net";

// The reply the envelope binding refuses with, as the framework writes
// it. Matched as the code and the sentence rather than as a substring of
// either, because the code alone is shared with several other refusals
// and the sentence alone would survive the code changing.
var ENVELOPE_REFUSAL_CODE = 553;
var ENVELOPE_REFUSAL_TEXT =
  "5.7.1 Sender address rejected: not owned by authenticated identity";

// The reply a refused relay handoff produces. There is one for every
// reason, which is the point of checking it: whatever the author binding
// rejected a message for, this is the whole of what the client is told.
var AUTHOR_REFUSAL_CODE = 451;
var AUTHOR_REFUSAL_TEXT = "4.3.0 Local delivery error";

// The reply a completed submission draws.
var ACCEPTED_CODE = 250;

// Connections one run of this file opens against the submission
// listeners, so a reader hitting the per-address ceiling can tell
// whether this file or something else on the machine spent it: three
// sessions the driver drives, one it opens expecting to be refused
// during the handshake, and five curl invocations, each of which opens
// its own because curl does not reuse a connection across them.
var CONNECTIONS_PER_RUN = 9;

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

function _port(name, fallback) {
  var text = process.env[name] || String(fallback);
  var port = Number(text);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new TypeError("interop: " + name + " must be a TCP port, got " + JSON.stringify(text));
  }
  return port;
}

function readConfig() {
  // The account first. It is the setting an unprovisioned stack is
  // missing, and reporting a TLS argument to somebody who has not
  // created a mailbox yet sends them to the wrong problem.
  var address  = _required("BLAMEPOST_INTEROP_ADDRESS", "the account the clients sign in as");
  var password = _required("BLAMEPOST_INTEROP_PASSWORD", "that account's password");

  var at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1) {
    throw new Error("interop: BLAMEPOST_INTEROP_ADDRESS is " + JSON.stringify(address) +
      ", which is not an address with a domain on it. Every identity this file builds is " +
      "derived from that domain, so a value it cannot split would produce cases that read " +
      "as refusals of something else.");
  }

  var caFile = process.env.BLAMEPOST_INTEROP_CA;
  if (!caFile) {
    throw new Error("interop: set BLAMEPOST_INTEROP_CA to the PEM the listeners' chain is " +
      "verified against. Every case here reads what the server said on an encrypted session " +
      "about who it thinks the client is, and a session that verified nothing would read the " +
      "same from anything answering the port. There is no opt-out in this file for that " +
      "reason.");
  }
  if (!nodeFs.existsSync(caFile)) {
    throw new Error("interop: BLAMEPOST_INTEROP_CA names " + caFile + ", which is not there.");
  }

  var cfg = {
    host:           process.env.BLAMEPOST_INTEROP_HOST || "127.0.0.1",
    submission:     _port("BLAMEPOST_INTEROP_SUBMISSION_PORT", 587),
    submissions:    _port("BLAMEPOST_INTEROP_SUBMISSIONS_PORT", 465),
    servername:     process.env.BLAMEPOST_INTEROP_SERVERNAME || "mx.example.com",
    address:        address,
    password:       password,
    caFile:         caFile,
    localPart:      address.slice(0, at),
    domain:         address.slice(at + 1),
    unownedHosted:  null,
    unownedIsDerived: true,
  };

  var named = process.env.BLAMEPOST_INTEROP_UNOWNED_ADDRESS;
  if (typeof named === "string" && named.length > 0) {
    if (named.toLowerCase() === address.toLowerCase()) {
      throw new Error("interop: BLAMEPOST_INTEROP_UNOWNED_ADDRESS names the same address as " +
        "BLAMEPOST_INTEROP_ADDRESS. It has to be one the account does NOT hold, or every " +
        "refusal below would be asking the server to reject the identity it just accepted.");
    }
    cfg.unownedHosted = named;
    cfg.unownedIsDerived = false;
  }
  return cfg;
}

// ---------------------------------------------------------------------------
// The identities under test
// ---------------------------------------------------------------------------

// A run identifier, so the derived addresses below cannot collide with a
// real mailbox and so a message that reached a store is attributable to
// the run that sent it.
var RUN_ID = nodeCrypto.randomBytes(6).toString("hex");

// Filled in once the configuration is read, because every one of them is
// derived from the account's own address.
var ID = null;

function readIdentities(cfg) {
  return {
    // The account itself, which every acceptance below is written
    // around.
    own: cfg.address,

    // The same address written the way a mail program that upper-cases
    // its configured identity would write it. RFC 5321 section 2.4
    // leaves the local part's case to the receiving host, and this one
    // folds it, so an acceptance here is the measurement of that.
    ownUpper: cfg.address.toUpperCase(),

    // A subaddress of the account, RFC 5233. Mail sent to it lands in
    // the same mailbox, which is what makes the pair of cases about it
    // worth having: one half of the identity treats it as the account
    // and the other does not.
    subaddress: cfg.localPart + "+interop-" + RUN_ID + "@" + cfg.domain,

    // An address at a domain this server hosts that this account does
    // not hold. Derived unless the operator named a real one: the run
    // identifier in the local part is what makes it impossible for the
    // account to be holding it, which is the property the case needs and
    // the only one it needs.
    unownedHosted: cfg.unownedHosted ||
      ("not-" + cfg.localPart + "-" + RUN_ID + "@" + cfg.domain),

    // An address at a domain this server does not host. It gets no
    // signature from this server and is answered by its own domain's
    // policy, which is a different reason to refuse it as an author and
    // the same reason to refuse it as an envelope.
    unownedOutside: "nobody-" + RUN_ID + "@example.net",
  };
}

// ---------------------------------------------------------------------------
// The message fixtures
// ---------------------------------------------------------------------------

// One message, from the header fields a case is about. Every fixture
// shares a body, because the body is not what any case here is
// measuring, and a Message-ID carrying the run identifier so anything
// that reaches a mailbox says which run put it there.
function message(key, fields) {
  return fields.concat([
    "To: " + ID.own,
    "Subject: interop submission " + key,
    "Message-ID: <interop-submission-" + key + "-" + RUN_ID + "@example.net>",
    "Date: Mon, 24 Aug 2026 12:00:00 +0000",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=us-ascii",
    "",
    "This message exists to be accepted or refused at the submission listener.",
    "",
  ]).join("\r\n");
}

// A line opening with a dot ends a DATA transaction early, so a fixture
// carrying one would be measured as a different message than the one
// written here, and it would be measured that way silently. Every
// fixture is checked rather than every fixture being written carefully.
function noBareDot(text) {
  return String(text).split("\r\n").every(function (line) { return line.charAt(0) !== "."; });
}

// Every fixture is also pure ASCII. The driver encodes them as ASCII, so
// anything else would fail inside the client rather than at the
// listener, and a case would report a client-side encoding error as a
// server verdict.
function isAscii(text) {
  return /^[\x00-\x7F]*$/.test(String(text));
}

// ---------------------------------------------------------------------------
// The author cases
// ---------------------------------------------------------------------------

// Each entry is one message the account submits with its OWN address in
// the envelope, so the only thing under test is the header. `accept`
// says what the relay handoff does with it. `carriedBy` is DATA unless
// the case exists to prove the second door into the handoff.
//
// They all run down ONE session, in the order written, which is what
// makes the second entry a claim about survival rather than about
// acceptance. A claim that depends on the order is declared with
// `mustFollowARefusal`, and the control below checks it, because
// reordering this array would otherwise leave the case saying the words
// it was written to say while measuring something else.
function authorCases() {
  return [
    {
      key:    "hosted-author-the-account-does-not-hold",
      claim:  "an author at a domain this server signs for that the account does not hold is " +
              "refused, because mail written that way would leave under this domain's own " +
              "signature over somebody else's name",
      fields: ["From: " + ID.unownedHosted],
      accept: false,
    },
    {
      key:    "own-address-again-on-the-same-session",
      claim:  "the account's own mail is accepted on the same session that just carried a " +
              "refused author, with no RSET in between, so a client that got the header wrong " +
              "once can correct it without reconnecting",
      fields: ["From: " + ID.own],
      accept: true,
      mustFollowARefusal: true,
    },
    {
      key:    "no-author-at-all",
      claim:  "a message with no From header is refused, because RFC 5322 section 3.6 requires " +
              "one and this server will not sign a message whose author it cannot read",
      fields: [],
      accept: false,
    },
    {
      key:    "two-authors",
      claim:  "a message carrying two From headers is refused, because which address a " +
              "recipient is shown would depend on which mail program opened it",
      fields: ["From: " + ID.own, "From: " + ID.unownedHosted],
      accept: false,
    },
    {
      key:    "two-addresses-in-one-author",
      claim:  "a From header naming the account and an address it does not hold is refused, so " +
              "a second name cannot ride along beside a permitted one",
      fields: ["From: " + ID.own + ", " + ID.unownedHosted],
      accept: false,
    },
    {
      key:    "author-nobody-here-can-be-named-for",
      claim:  "a message whose only author is at a domain this server does not host is refused, " +
              "because nothing in it is attributable to the account that signed in for it",
      fields: ["From: " + ID.unownedOutside],
      accept: false,
    },
    {
      key:    "sender-does-not-license-a-local-author",
      claim:  "a Sender header naming a hosted address the account does not hold is refused, so " +
              "the on-behalf-of header cannot be used to write a local address the From header " +
              "would have been refused for",
      fields: ["From: " + ID.unownedOutside, "Sender: " + ID.unownedHosted],
      accept: false,
    },
    {
      key:    "on-behalf-of-an-outside-author",
      claim:  "an outside author with the account's own address in Sender is accepted, which is " +
              "the transmitting-agent shape RFC 5322 section 3.6.2 describes and the one real " +
              "clients emit",
      fields: ["From: " + ID.unownedOutside, "Sender: " + ID.own],
      accept: true,
    },
    {
      key:    "display-name-around-the-account",
      claim:  "a display name wrapped around the account's own address is accepted, so the " +
              "binding reads the address rather than the header",
      fields: ["From: Interop Suite <" + ID.own + ">"],
      accept: true,
    },
    {
      key:    "the-account-in-another-case",
      claim:  "the account's own address written in upper case is accepted, so a mail program " +
              "that upper-cases its configured identity is not locked out",
      fields: ["From: " + ID.ownUpper],
      accept: true,
    },
    {
      key:    "a-subaddress-of-the-account",
      claim:  "a subaddress of the account is accepted as the author, which is what RFC 5233 " +
              "routing already treats as the same mailbox",
      fields: ["From: " + ID.subaddress],
      accept: true,
    },
    {
      key:       "hosted-author-carried-by-bdat",
      claim:     "the same refused author is refused when the message arrives through BDAT, so " +
                 "the CHUNKING extension this listener advertises is not a second door past " +
                 "the binding",
      fields:    ["From: " + ID.unownedHosted],
      accept:    false,
      carriedBy: "bdat",
    },
    {
      key:       "own-author-carried-by-bdat",
      claim:     "and the account's own mail still goes through BDAT, so the case above is a " +
                 "refusal of the author rather than of the verb",
      fields:    ["From: " + ID.own],
      accept:    true,
      carriedBy: "bdat",
    },
  ];
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

// Python's smtplib is asked for the capability rather than for the name:
// an interpreter built without it answers `--version` perfectly well and
// cannot open a submission session.
var PYTHON = {
  name:            "python",
  envVar:          "BLAMEPOST_PYTHON_BIN",
  candidates:      ["python3", "python", "py"],
  probeArgs:       ["-c", "import smtplib;print('SMTPLIB ' + smtplib.__name__)"],
  requireInOutput: /^SMTPLIB smtplib/m,
  timeoutMs:       CLIENT_TIMEOUT_MS,
};

// curl reports the protocols its build was compiled with in its own
// version banner. A curl without SMTP is on the path, answers
// `--version`, and cannot submit anything, so the capability is read out
// of what it says about itself rather than assumed from the name.
var CURL = {
  name:            "curl",
  envVar:          "BLAMEPOST_CURL_BIN",
  candidates:      ["curl"],
  probeArgs:       ["--version"],
  requireInOutput: /^Protocols:.*\bsmtps?\b/m,
  timeoutMs:       CLIENT_TIMEOUT_MS,
};

// The driver runs a plan and reports every reply as data. A step that
// threw is reported too, and as a different kind of line, because a
// session that died and a session that answered are the two outcomes one
// case here is written to tell apart, and folding them together is
// exactly the mistake that case exists to catch.
//
// The plan arrives in a file rather than on the command line: it carries
// whole messages and a command line has a length its author cannot see.
// The credential stays on the command line, which is where the curl half
// of this file already puts it.
var DRIVER_SOURCE = [
  "import base64",
  "import json",
  "import smtplib",
  "import ssl",
  "import sys",
  "",
  "ca, host, address, password, planFile = sys.argv[1:6]",
  "",
  // The CHAIN is verified, against the authority this run was pointed
  // at. Only the name check is off, and only because this client dials
  // the address the suite is pointed at while the certificate carries
  // the host name the listener answers to. The curl half of this file
  // dials that name and checks it, so between the two clients the chain
  // and the name are both covered by something.
  "trusted = ssl.create_default_context(cafile=ca)",
  "trusted.check_hostname = False",
  "",
  // The same session without this run's authority. It has to fail, and
  // its failing is what makes every session above a verified one rather
  // than a session with anything at all on the other end.
  "untrusted = ssl.create_default_context()",
  "untrusted.check_hostname = False",
  "",
  "with open(planFile, 'r', encoding='utf-8') as fh:",
  "    plan = json.load(fh)",
  "",
  "def sasl(a, p):",
  "    nul = chr(0)",
  "    return base64.b64encode((nul + a + nul + p).encode('utf-8')).decode('ascii')",
  "",
  "def say(label, kind, code, text):",
  "    if isinstance(text, bytes):",
  "        text = text.decode('utf-8', 'replace')",
  "    print('%s %s %s %s' % (kind, label, code, ' '.join(str(text).split())))",
  "",
  "session = None",
  "",
  // A session is ended the way a client ends one, with QUIT, and only
  // dropped when that cannot be written. A run that abandoned three
  // sockets would leave the listener counting them against the
  // per-address ceiling for longer than the run took.
  "def shut():",
  "    global session",
  "    if session is None:",
  "        return",
  "    try:",
  "        session.quit()",
  "    except Exception:",
  "        try:",
  "            session.close()",
  "        except Exception:",
  "            pass",
  "    session = None",
  "",
  "for step in plan:",
  "    label = step['label']",
  "    try:",
  "        op = step['op']",
  "        if op == 'open':",
  "            shut()",
  "            ctx = trusted if step['trusted'] else untrusted",
  "            if step['implicit']:",
  "                session = smtplib.SMTP_SSL(host, step['port'], local_hostname=step['helo'],",
  "                                           context=ctx, timeout=step['seconds'])",
  "            else:",
  "                session = smtplib.SMTP(host, step['port'], local_hostname=step['helo'],",
  "                                       timeout=step['seconds'])",
  "                session.ehlo(step['helo'])",
  "                session.starttls(context=ctx)",
  "            code, text = session.ehlo(step['helo'])",
  "            say(label, 'REPLY', code, text)",
  // Whether the listener still offers an upgrade inside an established
  // session. RFC 3207 section 4.2 has a server stop advertising STARTTLS
  // once TLS is on, and RFC 8314 section 3 puts implicit TLS on its own
  // port for the same reason, so an offer here is a listener that cannot
  // see the TLS it is inside.
  "            offered = 'starttls' in session.esmtp_features",
  "            say(label + '.starttls-offered', 'REPLY', 0, 'yes' if offered else 'no')",
  "        elif op == 'auth':",
  "            code, text = session.docmd('AUTH', 'PLAIN ' + sasl(address, password))",
  "            say(label, 'REPLY', code, text)",
  "        elif op == 'command':",
  "            code, text = session.docmd(step['command'], step['argument'])",
  "            say(label, 'REPLY', code, text)",
  "        elif op == 'data':",
  "            code, text = session.docmd('DATA')",
  "            say(label + '.open', 'REPLY', code, text)",
  "            session.send(step['message'].encode('ascii') + b'.\\r\\n')",
  "            code, text = session.getreply()",
  "            say(label, 'REPLY', code, text)",
  "        elif op == 'bdat':",
  // RFC 3030 section 2: the chunk follows the command line and is
  // exactly the octet count the command announced. There is no dot to
  // stuff and no terminator to append.
  "            chunk = step['message'].encode('ascii')",
  "            session.putcmd('BDAT', '%d LAST' % len(chunk))",
  "            session.send(chunk)",
  "            code, text = session.getreply()",
  "            say(label, 'REPLY', code, text)",
  "        else:",
  "            say(label, 'RAISED', 'UnknownStep', op)",
  "    except Exception as e:",
  "        say(label, 'RAISED', type(e).__name__, str(e))",
  "",
  "shut()",
  "print('PLAN-END %d' % len(plan))",
  "",
].join("\n");

// ---------------------------------------------------------------------------
// Building the plan
// ---------------------------------------------------------------------------

function Plan() {
  this.steps = [];
}
Plan.prototype.open = function (label, port, implicit, trusted) {
  this.steps.push({
    op:       "open",
    label:    label,
    port:     port,
    implicit: implicit === true,
    trusted:  trusted !== false,
    helo:     HELO,
    seconds:  SESSION_TIMEOUT_S,
  });
  return this;
};
Plan.prototype.auth = function (label) {
  this.steps.push({ op: "auth", label: label });
  return this;
};
Plan.prototype.command = function (label, command, argument) {
  this.steps.push({ op: "command", label: label, command: command, argument: argument || "" });
  return this;
};
Plan.prototype.mailFrom = function (label, address) {
  return this.command(label, "MAIL", "FROM:<" + address + ">");
};
Plan.prototype.rcptTo = function (label, address) {
  return this.command(label, "RCPT", "TO:<" + address + ">");
};
Plan.prototype.body = function (label, carriedBy, text) {
  this.steps.push({ op: carriedBy === "bdat" ? "bdat" : "data", label: label, message: text });
  return this;
};

// One complete submission: envelope, recipient, message. The recipient
// is always the account itself, so nothing this file sends leaves for
// the internet and no case depends on a domain resolving.
Plan.prototype.submit = function (prefix, carriedBy, text) {
  this.mailFrom(prefix + ".mail", ID.own);
  this.rcptTo(prefix + ".rcpt", ID.own);
  this.body(prefix + ".end", carriedBy, text);
  return this;
};

function buildPlan(cfg, cases) {
  var plan = new Plan();

  // A session opened without the run's authority, first, so everything
  // after it is known to have been verified against something.
  plan.open("untrusted", cfg.submission, false, false);

  // The envelope binding, and whether the session outlives it.
  plan.open("inband", cfg.submission, false, true);
  plan.auth("inband.auth");
  plan.mailFrom("envelope.hosted", ID.unownedHosted);
  // Immediately, with no recovery in between: a refusal that let a
  // recipient be named would have accepted the transaction it was
  // supposed to have stopped.
  plan.rcptTo("envelope.hosted.rcpt", ID.own);
  plan.mailFrom("envelope.outside", ID.unownedOutside);
  plan.mailFrom("envelope.subaddress", ID.subaddress);
  // Still no RSET. This is the survival claim.
  plan.submit("envelope.recovered", "data", message("recovered", ["From: " + ID.own]));

  // The author binding, every shape, down one session.
  plan.open("author", cfg.submission, false, true);
  plan.auth("author.auth");
  cases.forEach(function (c) {
    plan.submit("author." + c.key, c.carriedBy || "data", c.message);
  });

  // The implicit-TLS submission listener, which is a second profile of
  // the same listener and not a second copy of the rule.
  plan.open("implicit", cfg.submissions, true, true);
  plan.auth("implicit.auth");
  plan.mailFrom("implicit.hosted", ID.unownedHosted);
  plan.submit("implicit.recovered", "data", message("implicit", ["From: " + ID.own]));

  // No closing step: the driver ends whatever session is open with QUIT
  // when the plan runs out, so a step here would be a second one and its
  // reply would be a refusal of a command sent after goodbye.
  return plan.steps;
}

// ---------------------------------------------------------------------------
// Reading what the driver said
// ---------------------------------------------------------------------------

var REPLY_RE  = /^REPLY (\S+) (\S+) ?(.*)$/;
var RAISED_RE = /^RAISED (\S+) (\S+) ?(.*)$/;

// Steps go in a map of their own rather than onto the result object. A
// label that happened to be spelled like one of the result's own fields
// would otherwise overwrite it, and the case reading that field would
// report whatever the step said instead of failing.
function readTranscript(text) {
  var seen = { end: null, steps: Object.create(null) };
  String(text).split(/\r?\n/).forEach(function (line) {
    var reply = REPLY_RE.exec(line);
    if (reply !== null) {
      seen.steps[reply[1]] = { kind: "reply", code: Number(reply[2]), text: reply[3] };
      return;
    }
    var raised = RAISED_RE.exec(line);
    if (raised !== null) {
      seen.steps[raised[1]] = { kind: "raised", code: null, text: raised[2] + ": " + raised[3] };
      return;
    }
    var end = /^PLAN-END (\d+)$/.exec(line);
    if (end !== null) seen.end = Number(end[1]);
  });
  return seen;
}

// What one step produced, in one line, for a failure to quote. A step
// that produced nothing at all says so rather than reading as an empty
// reply, because a driver that stopped early and a listener that said
// nothing are different faults with different fixes.
function said(seen, label) {
  var hit = seen.steps[label];
  if (hit === undefined) {
    return label + ": the driver reported nothing for this step, so it did not reach it";
  }
  if (hit.kind === "raised") return label + ": the session raised " + hit.text;
  return label + ": " + hit.code + " " + hit.text;
}

function codeOf(seen, label) {
  var hit = seen.steps[label];
  return hit === undefined || hit.kind !== "reply" ? null : hit.code;
}

function textOf(seen, label) {
  var hit = seen.steps[label];
  return hit === undefined || hit.kind !== "reply" ? "" : hit.text;
}

// ---------------------------------------------------------------------------
// The cases the driver answers
// ---------------------------------------------------------------------------

function theFixturesCanCarryWhatTheyClaim(cases) {
  var offenders = cases.filter(function (c) { return !noBareDot(c.message); });
  count("control: no fixture carries a line opening with a dot, which would end its DATA " +
    "transaction early and have the listener judge a message nobody wrote",
    offenders.length === 0,
    offenders.map(function (c) { return c.key; }).join(", "));

  var wide = cases.filter(function (c) { return !isAscii(c.message); });
  count("control: every fixture is ASCII, so a refusal is the listener's and not the client's " +
    "encoder objecting before the message left",
    wide.length === 0,
    wide.map(function (c) { return c.key; }).join(", "));

  // A file whose author cases were all refusals could not tell a working
  // binding from a listener that refuses every message, and a file whose
  // cases were all acceptances could not tell one from a listener that
  // accepts every message. Both halves have to be present for either to
  // mean anything.
  var accepted = cases.filter(function (c) { return c.accept === true; }).length;
  var refused  = cases.length - accepted;
  count("control: the author cases carry both verdicts, so neither a listener that refuses " +
    "everything nor one that accepts everything could satisfy them",
    accepted > 0 && refused > 0,
    accepted + " accepted, " + refused + " refused, of " + cases.length);

  // The order the cases run in is load bearing for the ones that claim
  // something about the session rather than about the message. A case
  // that says "on the same session that just carried a refused author"
  // is only saying that while a refused author is the entry before it.
  var misplaced = cases.filter(function (c, i) {
    if (c.mustFollowARefusal !== true) return false;
    return i === 0 || cases[i - 1].accept !== false;
  });
  count("control: every case claiming something about what a session survived is preceded by " +
    "the refusal it claims to have survived",
    misplaced.length === 0,
    misplaced.map(function (c) { return c.key; }).join(", "));
}

function theDriverVerifiedTheChainItConnectedOver(seen) {
  var hit = seen.steps.untrusted;
  count("control: a session opened without this run's authority is refused during the " +
    "handshake, so every session below verified the chain rather than accepting whatever " +
    "held the port",
    hit !== undefined && hit.kind === "raised",
    said(seen, "untrusted"));
  count("control: and it is refused for the certificate rather than for the port, so the " +
    "control is measuring verification and not an absent listener",
    /CertificateError|SSLError|SSLCertVerificationError|certificate verify failed/i
      .test((hit && hit.text) || ""),
    said(seen, "untrusted"));
}

function theSessionReachedAnAuthenticatedState(seen, prefix, what) {
  count(what + ": the listener greets the client and completes an authentication, so every " +
    "verdict below is one it reached with an identity rather than without one",
    codeOf(seen, prefix + ".auth") === 235,
    said(seen, prefix + ".auth"));
  count(what + ": and it does not offer STARTTLS inside the established session, which RFC " +
    "3207 section 4.2 requires of a server that has already upgraded",
    textOf(seen, prefix + ".starttls-offered") === "no",
    said(seen, prefix + ".starttls-offered"));
}

// Hard rule five, at the command where it is enforced.
function theEnvelopeBindingRefuses(seen) {
  [
    {
      label: "envelope.hosted",
      what:  "an address at a domain this server hosts that the account does not hold",
    },
    {
      label: "envelope.outside",
      what:  "an address at a domain this server does not host at all",
    },
  ].forEach(function (vector) {
    count("MAIL FROM naming " + vector.what + " is refused " + ENVELOPE_REFUSAL_CODE,
      codeOf(seen, vector.label) === ENVELOPE_REFUSAL_CODE, said(seen, vector.label));
    count("and the refusal names the identity rather than the address, in the framework's " +
      "own words, for " + vector.what,
      textOf(seen, vector.label) === ENVELOPE_REFUSAL_TEXT,
      said(seen, vector.label) + ", expected " + JSON.stringify(ENVELOPE_REFUSAL_TEXT));
  });

  // Where the refusal landed. RFC 5321 section 3.3 opens a transaction
  // at MAIL FROM, so a listener that refused the sender and then took a
  // recipient would have opened one for an envelope it had rejected.
  count("no recipient can be named after the refusal, so it landed before the transaction " +
    "rather than beside it",
    codeOf(seen, "envelope.hosted.rcpt") === 503,
    said(seen, "envelope.hosted.rcpt"));
}

// The half no in-process test can see. A function call has no connection
// to drop, so a listener that hung up on a refused envelope would look
// identical to one that did not, everywhere except here.
function theSessionSurvivesTheRefusal(seen) {
  count("the account's own address is accepted on the same connection that just carried " +
    "three refused ones, with no RSET in between, so a client that guessed wrong can " +
    "correct itself rather than reconnect",
    codeOf(seen, "envelope.recovered.mail") === ACCEPTED_CODE,
    said(seen, "envelope.recovered.mail"));
  count("and the recipient after it is accepted, so what survived is a usable session rather " +
    "than an open socket",
    codeOf(seen, "envelope.recovered.rcpt") === ACCEPTED_CODE,
    said(seen, "envelope.recovered.rcpt"));
  count("and the message completes, so the session that carried the refusals carried a whole " +
    "submission afterwards",
    codeOf(seen, "envelope.recovered.end") === ACCEPTED_CODE,
    said(seen, "envelope.recovered.end"));
}

// The pair. Both halves of one identity are asked about one address, and
// they answer differently.
function theTwoHalvesOfTheIdentityDisagreeAboutASubaddress(seen) {
  count("MAIL FROM naming a subaddress of the account is refused, so the envelope half of the " +
    "identity folds case but not the RFC 5233 tag",
    codeOf(seen, "envelope.subaddress") === ENVELOPE_REFUSAL_CODE,
    said(seen, "envelope.subaddress") +
      " -- an acceptance here means the two halves agreed, which retires this case and its " +
      "partner in the author section rather than needing either rewritten");
}

function theAuthorBindingAnswersEachShape(seen, cases) {
  cases.forEach(function (c) {
    var prefix = "author." + c.key;
    // The envelope was the account's own address every time, so a
    // verdict below is about the header. Without this the refusals could
    // all be the envelope binding firing again and the file would read
    // the same.
    count(c.key + ": the envelope is accepted first, so the verdict on the message is about " +
      "the header and not about the sender",
      codeOf(seen, prefix + ".mail") === ACCEPTED_CODE, said(seen, prefix + ".mail"));
    count(c.key + ": and the recipient is accepted, so the message reached the handoff",
      codeOf(seen, prefix + ".rcpt") === ACCEPTED_CODE, said(seen, prefix + ".rcpt"));

    if (c.accept) {
      count(c.key + ": " + c.claim,
        codeOf(seen, prefix + ".end") === ACCEPTED_CODE, said(seen, prefix + ".end"));
      return;
    }
    count(c.key + ": " + c.claim,
      codeOf(seen, prefix + ".end") === AUTHOR_REFUSAL_CODE, said(seen, prefix + ".end"));
    count(c.key + ": and the client is told " + AUTHOR_REFUSAL_CODE + " " +
      AUTHOR_REFUSAL_TEXT + ", which is the whole of what a refused handoff can say",
      textOf(seen, prefix + ".end") === AUTHOR_REFUSAL_TEXT,
      said(seen, prefix + ".end") + ", expected " + JSON.stringify(AUTHOR_REFUSAL_TEXT));
  });
}

function theImplicitTlsListenerEnforcesTheSameRule(seen) {
  count("the implicit-TLS submission listener refuses the same unowned envelope, in the same " +
    "words, so the rule belongs to the listener rather than to the upgrade that reached it",
    codeOf(seen, "implicit.hosted") === ENVELOPE_REFUSAL_CODE &&
      textOf(seen, "implicit.hosted") === ENVELOPE_REFUSAL_TEXT,
    said(seen, "implicit.hosted"));
  count("and it accepts the account's own mail, so the refusal above is the binding rather " +
    "than a listener nobody can send through",
    codeOf(seen, "implicit.recovered.end") === ACCEPTED_CODE,
    said(seen, "implicit.recovered.end"));
}

function theDriverRanEveryStepItWasGiven(seen, planned) {
  count("the driver reached the end of the plan, so a case that reported nothing is a listener " +
    "that said nothing rather than a client that stopped early",
    seen.end === planned,
    "reported " + seen.end + " of " + planned + " steps");
}

// ---------------------------------------------------------------------------
// The second implementation
// ---------------------------------------------------------------------------

// What every curl invocation carries. `--ssl-reqd` is not decoration:
// without it curl would continue in the clear if the upgrade failed, and
// a case that passed over an unencrypted session would be proving
// something about a server this project does not ship.
//
// `--resolve` is what lets the NAME be checked. curl dials the name the
// certificate carries and is told which address to open, so the chain
// and the name are both verified while the connection still goes to the
// loopback address this suite is pointed at.
//
// `--ssl-no-revoke` is scoped to revocation checking and to the backends
// that do it at all. A private authority minted for a test run publishes
// no revocation list, so that check cannot succeed and is not what any
// case here is about.
function curlArgs(cfg, opts) {
  var name = opts.name || cfg.servername;
  var port = opts.port;
  var scheme = opts.implicit ? "smtps" : "smtp";
  return [
    "--silent", "--show-error", "--verbose", "--ssl-no-revoke", "--ssl-reqd",
    "--cacert", cfg.caFile,
    "--resolve", name + ":" + port + ":" + cfg.host,
    "--user", cfg.address + ":" + cfg.password,
    "--mail-from", "<" + opts.mailFrom + ">",
    "--mail-rcpt", "<" + ID.own + ">",
    "--upload-file", opts.file,
    "--url", scheme + "://" + name + ":" + port + "/" + HELO,
  ];
}

async function curlSubmits(cfg, client, opts) {
  var rv = await foreign.run(client.bin, curlArgs(cfg, opts), { timeoutMs: CLIENT_TIMEOUT_MS });
  return {
    rv:   rv,
    text: rv.stderr.toString("utf8") + rv.stdout.toString("utf8"),
  };
}

// What a failed invocation said, on one line, bounded so a message body
// cannot forge extra rows in a report.
function curlSaid(seen) {
  return "exit " + seen.rv.code + (seen.rv.timedOut ? " (timed out)" : "") + ": " +
    seen.text.replace(/[\r\n]+/g, " ").trim().slice(0, 300);
}

// curl echoes every server line it read, prefixed. The reply lines below
// are matched in that echo, so what is asserted is the listener's own
// bytes as a second implementation received them rather than curl's
// summary of them.
function echoed(text, code, sentence) {
  return new RegExp("^< " + code + " " + sentence.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "m")
    .test(text);
}

async function aSecondImplementationReadsTheSameReplies(cfg, client, workDir) {
  var ownFile = nodePath.join(workDir, "own-author.eml");
  var forgedFile = nodePath.join(workDir, "forged-author.eml");
  nodeFs.writeFileSync(ownFile, message("curl-own", ["From: " + ID.own]), "ascii");
  nodeFs.writeFileSync(forgedFile, message("curl-forged", ["From: " + ID.unownedHosted]), "ascii");

  // The control, first. A name the certificate does not carry has to
  // stop the client before it offers a credential, which is what makes
  // every invocation after it a verified one.
  var wrongName = await curlSubmits(cfg, client, {
    name:     "not-" + RUN_ID + "." + cfg.servername,
    port:     cfg.submission,
    mailFrom: ID.own,
    file:     ownFile,
  });
  count("control: curl refuses a session under a name the certificate does not carry, so the " +
    "invocations below verified the name as well as the chain",
    wrongName.rv.code === CURLE_PEER_FAILED_VERIFY,
    curlSaid(wrongName) + ", expected exit " + CURLE_PEER_FAILED_VERIFY);
  count("control: and it stops before a credential is offered, so nothing was sent to a " +
    "server it had not authenticated",
    /AUTH PLAIN/.test(wrongName.text) === false, curlSaid(wrongName));

  // The ordinary submission, so the refusals below are known to be
  // refusals rather than a listener a second client cannot use at all.
  var accepted = await curlSubmits(cfg, client, {
    port:     cfg.submission,
    mailFrom: ID.own,
    file:     ownFile,
  });
  count("a second implementation completes an ordinary submission as the account itself",
    accepted.rv.code === 0, curlSaid(accepted));
  count("and reads the acceptance off the wire",
    echoed(accepted.text, ACCEPTED_CODE, "2.6.0 Message accepted"), curlSaid(accepted));

  var overImplicitTls = await curlSubmits(cfg, client, {
    port:     cfg.submissions,
    implicit: true,
    mailFrom: ID.own,
    file:     ownFile,
  });
  count("and completes one over implicit TLS, which is the profile a mail program configured " +
    "for port 465 uses",
    overImplicitTls.rv.code === 0, curlSaid(overImplicitTls));

  // The envelope binding, read by a parser that shares nothing with the
  // driver's.
  var refusedEnvelope = await curlSubmits(cfg, client, {
    port:     cfg.submission,
    mailFrom: ID.unownedHosted,
    file:     ownFile,
  });
  count("a second implementation is refused " + ENVELOPE_REFUSAL_CODE + " for an envelope the " +
    "account does not own, in the framework's own words",
    echoed(refusedEnvelope.text, ENVELOPE_REFUSAL_CODE, ENVELOPE_REFUSAL_TEXT),
    curlSaid(refusedEnvelope));
  count("and it reports the refusal as a failure of MAIL rather than of the message, so a " +
    "script wrapping it can tell the two apart",
    refusedEnvelope.rv.code === CURLE_SEND_ERROR && /MAIL failed: 553/.test(refusedEnvelope.text),
    curlSaid(refusedEnvelope) + ", expected exit " + CURLE_SEND_ERROR);
  // What curl does next, which is the reason the survival claim above
  // needed a different client. This is not a fault in the server and it
  // is not one in curl; it is why one client cannot answer both
  // questions.
  count("and it then abandons the connection rather than trying another identity on it, which " +
    "is why the survival claim above is measured with a client that stays",
    /shutting down connection/.test(refusedEnvelope.text) ||
      /Closing connection/.test(refusedEnvelope.text),
    curlSaid(refusedEnvelope));

  // The author binding, likewise.
  var refusedAuthor = await curlSubmits(cfg, client, {
    port:     cfg.submission,
    mailFrom: ID.own,
    file:     forgedFile,
  });
  count("a second implementation is refused " + AUTHOR_REFUSAL_CODE + " for an author the " +
    "account may not write, after an envelope it may",
    echoed(refusedAuthor.text, AUTHOR_REFUSAL_CODE, AUTHOR_REFUSAL_TEXT),
    curlSaid(refusedAuthor));
  count("and what it makes of that reply is an unexpected one rather than a transient one, so " +
    "the transient code buys the client nothing it could act on",
    refusedAuthor.rv.code === CURLE_WEIRD_SERVER_REPLY,
    curlSaid(refusedAuthor) + ", expected exit " + CURLE_WEIRD_SERVER_REPLY);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function driveThePlan(cfg, client, workDir, cases) {
  var program = nodePath.join(workDir, "submission-driver.py");
  var planFile = nodePath.join(workDir, "submission-plan.json");
  var steps = buildPlan(cfg, cases);
  nodeFs.writeFileSync(program, DRIVER_SOURCE, "utf8");
  nodeFs.writeFileSync(planFile, JSON.stringify(steps), "utf8");

  var rv = await foreign.run(client.bin, [
    program, cfg.caFile, cfg.host, cfg.address, cfg.password, planFile,
  ], { timeoutMs: CLIENT_TIMEOUT_MS });
  var text = rv.stdout.toString("utf8") + rv.stderr.toString("utf8");

  var seen = readTranscript(text);
  if (seen.end === null) {
    throw new Error("interop: the driver did not reach the end of its plan, so there is no " +
      "transcript for the cases to read. exit " + rv.code + (rv.timedOut ? " (timed out)" : "") +
      ": " + text.replace(/[\r\n]+/g, " ").trim().slice(0, 600));
  }
  return { seen: seen, planned: steps.length, text: text };
}

async function run() {
  var cfg = readConfig();
  ID = readIdentities(cfg);

  var cases = authorCases().map(function (c) {
    return Object.assign({}, c, { message: message(c.key, c.fields) });
  });

  console.log("  endpoint:   " + cfg.host + " ports " + cfg.submission + " and " +
    cfg.submissions + ", chain verified against " + cfg.caFile);
  console.log("  account:    " + ID.own);
  console.log("  unowned:    " + ID.unownedHosted +
    (cfg.unownedIsDerived ? " (derived for this run)" : " (named by the operator)") +
    ", and " + ID.unownedOutside + " off this server's domains");
  console.log("  subaddress: " + ID.subaddress);
  console.log("  budget:     about " + CONNECTIONS_PER_RUN + " connections, against " +
    "limits.connectionsPerIpPerMinute");

  // These need no client and are the reason a failure below can be read
  // as a verdict about the server.
  theFixturesCanCarryWhatTheyClaim(cases);

  var driver = await foreign.locate(PYTHON);
  var curl   = await foreign.locate(CURL);
  if (!driver.found && !curl.found) {
    // Nothing was proven and nothing is claimed. The runner counts this
    // separately from a check, so a machine with no client cannot report
    // the same total as one that ran the cases.
    helpers.skip("the submission cases need a mail client that is not this codebase, and " +
      "there is not one here. The driver: " + driver.reason + ". curl: " + curl.reason + ". " +
      "What did not run is every claim about who this server lets an authenticated account " +
      "say it is.");
    return helpers.getChecks();
  }

  var workDir = helpers.tempDir("interop-submission");
  try {
    if (driver.found) {
      console.log("  driver:     " + driver.bin + " -- " + driver.detail);
      var drove = await driveThePlan(cfg, driver, workDir, cases);
      theDriverVerifiedTheChainItConnectedOver(drove.seen);
      theSessionReachedAnAuthenticatedState(drove.seen, "inband", "in band");
      theEnvelopeBindingRefuses(drove.seen);
      theSessionSurvivesTheRefusal(drove.seen);
      theTwoHalvesOfTheIdentityDisagreeAboutASubaddress(drove.seen);
      theSessionReachedAnAuthenticatedState(drove.seen, "author", "author session");
      theAuthorBindingAnswersEachShape(drove.seen, cases);
      theSessionReachedAnAuthenticatedState(drove.seen, "implicit", "implicit TLS");
      theImplicitTlsListenerEnforcesTheSameRule(drove.seen);
      theDriverRanEveryStepItWasGiven(drove.seen, drove.planned);
    } else {
      helpers.skip("the sessions need an interpreter with smtplib, and there is not one here: " +
        driver.reason + ". What did not run is every claim that needs a client which stays on " +
        "the socket after a refusal, which is the whole of the survival evidence and every " +
        "author shape; the curl cases below still ran.");
    }

    if (curl.found) {
      console.log("  second:     " + curl.bin + " -- " + curl.detail);
      await aSecondImplementationReadsTheSameReplies(cfg, curl, workDir);
    } else {
      helpers.skip("the second-implementation cases need curl built with SMTP, and there is " +
        "not one here: " + curl.reason + ". What did not run is the evidence that a C parser " +
        "sharing no code with the driver reads the same refusals off the same listener.");
    }

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(workDir);
  }
}

module.exports = { name: "smtp-submission", run: run, getChecks: helpers.getChecks };

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
