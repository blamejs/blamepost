// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the IMAP listener says to a command it does not serve, and to one
 * it cannot read.
 *
 * A wire-protocol reader refuses malformed input with the error code its
 * protocol defines, at the point of parse. RFC 9051 section 7.1 splits
 * that into two verdicts and they are not interchangeable: `BAD` says
 * the command could not be parsed or is not known, and `NO` says a
 * parsed command was not carried out. A client retries a `NO` against
 * another mailbox and gives up on a `BAD`, so answering one where the
 * other belongs sends a conforming client into a loop or stops it
 * trying something that would have worked.
 *
 * ## The two halves
 *
 * **Commands answered `NO`.** `COPY` and `MOVE` are not served. The
 * mailbox verbs beside them are, and each is driven here with a mailbox
 * name shaped like another account's, because a served verb is one whose
 * name reaches a folder lookup: `..` as a level is refused at the point
 * of parse, and a name that passes the screen and names no mailbox this
 * account holds is refused as a mailbox that is not there. `DELETE
 * INBOX` carries the second question with it: RFC 9051 section 6.3.5
 * lets a server remove a mailbox holding messages, and this server
 * removing INBOX would leave the account's deliveries with nowhere to
 * land.
 *
 * `CREATE` has the same vector written for it: the name is refused at
 * the point of parse, because a level spelled as a relative path token
 * addresses somewhere other than where it reads. The case beside it
 * sends an ordinary name from the same session, so the refusal is read
 * as being about the name rather than about the verb.
 *
 * **Commands this server cannot read.** A missing tag, a tag outside
 * the grammar, an unknown verb, and an argument on a verb RFC 9051
 * gives none. Each is a shape the command guard is supposed to refuse
 * before a handler sees it, and each is checked for two things: that the
 * refusal arrives, and that the session is still usable afterwards. A
 * reader that dropped the connection on a malformed line would pass an
 * assertion that only looked for the absence of an `OK`.
 *
 * ## The literal forms
 *
 * RFC 7888 lets a client announce a literal with `{N+}` and send the
 * octets without waiting to be invited. This server does not advertise
 * `LITERAL+`, and a client that uses it anyway is the interesting case:
 * the octets are already in flight, so a listener that refuses the
 * command and then reads the payload off the socket reads somebody's
 * message body as a sequence of commands.
 *
 * An `APPEND` before authentication is the same question asked earlier.
 * It is the one verb that carries a literal from an unauthenticated
 * session, so it is the one place a peer that has proved nothing can ask
 * this server to read a length it chose.
 *
 * ## IDLE
 *
 * RFC 2177 says the client ends an IDLE with `DONE`. What it does not
 * say is what a server does with anything else, and a session left in
 * IDLE while its commands are executed is one where the client and the
 * server disagree about which state it is in.
 *
 * Run standalone: node test/layer-2-integration/imap-command-refusals.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var b = helpers.b;

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Distinctive enough that finding it anywhere in a transcript is proof
// the other account's mail was reached rather than a coincidence.
var ALICE_MARKER = "alice-own-message-4d1f7a";
var BOB_MARKER   = "bob-private-message-9c3e28";

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + marker + ".\r\n", "utf8");
}

// One command and everything the listener said up to its tagged
// completion. The tag is the session's own, so a reply to an earlier
// command cannot satisfy the wait.
async function ask(session, command, what) {
  var tag = session.tag();
  session.send(tag + " " + command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { tag: tag, text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

function existsIn(text) {
  var found = /^\* (\d+) EXISTS/m.exec(text);
  return found === null ? -1 : parseInt(found[1], 10);
}

// RFC 9051 section 7.5 writes a continuation as a line OPENING with
// `+`, which is the only shape a client waits for. Searching a
// transcript for the two characters instead finds them inside
// `LITERAL+ (RFC 7888)`, and an assertion written that way reports an
// invitation the listener never sent.
var CONTINUATION = /^\+/m;

// ---- commands this server does not serve -----------------------------------

// Every unserved verb, each carrying a name shaped like the other
// account's mailbox. Two claims per verb: the command is refused, and
// the refusal is `NO` rather than `BAD`, because the command parsed and
// was not carried out. A `BAD` here would tell a client the syntax was
// wrong and send it away rewriting a command that was written correctly.
async function theUnservedVerbsAreRefused(ctx) {
  var session = await ctx.session("alice", "unserved-verbs");
  var opened = await ask(session, "SELECT INBOX");
  count("alice's INBOX opens and holds her one message",
    existsIn(opened.text) === 1, visible(opened.text));

  var elsewhere = "\"../bob@" + DOMAIN + "/INBOX\"";
  var verbs = [
    "RENAME INBOX " + elsewhere,
    "COPY 1 " + elsewhere,
    "MOVE 1 " + elsewhere,
    "SUBSCRIBE \"#shared/bob/INBOX\"",
    // The subscribed set is kept by name and outlives the mailbox each
    // one names (RFC 9051 section 6.3.8), so the name a client sends is
    // the whole of what stands between one account's set and another's
    // mailbox.
    "UNSUBSCRIBE " + elsewhere,
    // RFC 9051 section 6.3.5. A server MAY remove a mailbox that holds
    // messages, and this one removing INBOX would leave every delivery
    // to this account with nowhere to land.
    "DELETE INBOX",
  ];
  for (var i = 0; i < verbs.length; i += 1) {
    var answered = await ask(session, verbs[i]);
    count("`" + verbs[i] + "` is refused",
      answered.verdict !== "OK", visible(answered.text));
    count("and refused with NO rather than BAD, because the command parsed and was not " +
      "carried out: `" + verbs[i] + "`",
      answered.verdict === "NO", visible(answered.text));
    count("and nothing of the other account's mail is named in the answer to `" +
      verbs[i] + "`",
      answered.text.indexOf(BOB_MARKER) === -1 && answered.text.indexOf("bob@") === -1,
      visible(answered.text));
  }

  // The consequence, read from a fresh SELECT rather than from the
  // session that issued the commands. A session can stop mentioning a
  // mailbox the store still holds, and it can keep mentioning one the
  // store has lost.
  var again = await ctx.session("alice", "unserved-verbs-after");
  var reopened = await ask(again, "SELECT INBOX");
  count("INBOX is still there after DELETE was refused, and still holds the message",
    existsIn(reopened.text) === 1, visible(reopened.text));
  var fetched = await ask(again, "FETCH 1 BODY[]");
  count("and the message in it is alice's own, unmoved",
    fetched.text.indexOf(ALICE_MARKER) !== -1, visible(fetched.text));

  session.close();
  again.close();
}

// CREATE is served, so the name it is given is the whole of what stands
// between one account and another's mailbox. A name shaped like a path
// out of this account's namespace is refused at the point of parse: in
// a path `a/../b` names `b`, and a mailbox name is written into a URL
// path segment by the browser surface, so a level spelled as a relative
// token addresses somewhere other than where it reads.
//
// The refusal is `NO` rather than `BAD`, because the command parsed and
// was not carried out, and it quotes back the level it refused rather
// than the name, so asking for a mailbox somewhere else is answered
// without the answer repeating where.
async function aCreateCannotNameAMailboxOutsideTheAccount(ctx) {
  var session = await ctx.session("alice", "create-elsewhere");
  var elsewhere = "\"../bob@" + DOMAIN + "/INBOX\"";

  var refused = await ask(session, "CREATE " + elsewhere);
  count("a CREATE naming a path out of the account is refused",
    refused.verdict === "NO", visible(refused.text));
  count("and nothing of the other account is named in the answer",
    refused.text.indexOf(BOB_MARKER) === -1 && refused.text.indexOf("bob@") === -1,
    visible(refused.text));

  // The ordinary case from the same session, so the refusal above is
  // about the name rather than about the verb being unavailable.
  var ordinary = await ask(session, "CREATE Receipts");
  count("while an ordinary name from the same session is created",
    ordinary.verdict === "OK", visible(ordinary.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and the listing names the mailbox that was created and nothing of the other account",
    listed.text.indexOf("Receipts") !== -1 && listed.text.indexOf("bob@") === -1,
    visible(listed.text));

  session.close();
}

// The other account's side of the same question. Nothing above may have
// reached bob's mailbox, and the place that answers is bob's own
// session rather than alice's.
async function theOtherAccountIsUntouched(ctx) {
  var session = await ctx.session("bob", "other-account");
  var opened = await ask(session, "SELECT INBOX");
  count("bob's INBOX still holds his one message", existsIn(opened.text) === 1,
    visible(opened.text));
  var fetched = await ask(session, "FETCH 1 BODY[]");
  count("and it is his own message rather than one copied in from the other account",
    fetched.text.indexOf(BOB_MARKER) !== -1 && fetched.text.indexOf(ALICE_MARKER) === -1,
    visible(fetched.text));
  session.close();
}

// LIST patterns, which are the one place a wildcard is an argument
// rather than a name. RFC 9051 section 6.3.9 gives `*` and `%` their
// meaning inside the pattern, so a pattern is the shortest way to ask a
// server for a mailbox list wider than the account.
async function noListPatternReachesAnotherAccount(ctx) {
  var session = await ctx.session("alice", "list-patterns");
  var patterns = [
    "LIST \"\" \"*\"",
    "LIST \"\" \"%\"",
    "LIST \"\" \"*/*\"",
    "LIST \"#shared\" \"*\"",
    "LIST \"../\" \"*\"",
    "LIST \"\" \"../*\"",
    "LIST \"\" \"INBOX/../*\"",
  ];
  for (var i = 0; i < patterns.length; i += 1) {
    var listed = await ask(session, patterns[i]);
    count("`" + patterns[i] + "` names no mailbox belonging to the other account",
      listed.text.indexOf("bob") === -1, visible(listed.text));
    count("and leaks no store folder name through `" + patterns[i] + "`",
      listed.text.indexOf("mbx_") === -1 && listed.text.indexOf("obj_") === -1,
      visible(listed.text));
  }
  session.close();
}

// ---- commands this server cannot read --------------------------------------

// The shapes a command guard exists to refuse. Each is sent raw,
// because each is malformed in the part a helper would otherwise write
// correctly, and each is followed by a well-formed command on the same
// session: a listener that answered by dropping the connection would
// otherwise read as a refusal.
async function malformedCommandsRefuseLoudAndKeepTheSession(ctx) {
  var cases = [
    { label: "a line carrying no tag at all",       raw: "NOOP\r\n" },
    { label: "a tag holding a space",               raw: "a b NOOP\r\n" },
    { label: "a tag written as the wildcard",       raw: "* NOOP\r\n" },
    { label: "a verb this server does not know",    raw: "z1 FROBNICATE\r\n" },
    { label: "an argument on a verb RFC 9051 gives none",
      raw: "z2 NOOP extra-argument\r\n" },
    { label: "an argument on CAPABILITY",           raw: "z3 CAPABILITY extra\r\n" },
    { label: "an empty line",                       raw: "\r\n" },
  ];

  for (var i = 0; i < cases.length; i += 1) {
    // One session per case. A refusal may legitimately end the
    // connection, and sharing a session would make the next case report
    // the previous one's teardown.
    var session = await ctx.session("alice", "malformed-" + i);
    session.sendRaw(cases[i].raw, cases[i].label);
    var answered = await session.readQuietly("answer to " + cases[i].label);
    count(cases[i].label + " draws a refusal rather than silence",
      /(BAD|NO)/.test(answered), visible(answered));
    count("and " + cases[i].label + " is never answered OK",
      !/^\S+ OK/m.test(answered), visible(answered));

    // The session afterwards. A guard that refuses the line and keeps
    // reading is what lets a client recover; one that leaves the
    // connection in a state where a correct command goes unanswered has
    // turned a typo into a hung mail client.
    var recovered = await ask(session, "NOOP", "NOOP after " + cases[i].label);
    count("and a well-formed command on the same session is answered afterwards, after " +
      cases[i].label,
      recovered.verdict === "OK", visible(recovered.text));
    session.close();
  }
}

// ---- the literal forms -----------------------------------------------------

// RFC 7888 `{N+}`. The octets follow the command line with no
// continuation asked for, which is what makes a refusal of this shape
// different from a refusal of `{N}`: with a synchronizing literal the
// client is still waiting to be invited and no payload exists yet, and
// with this one the payload is already on the wire.
//
// The refusal is measured before authentication, because that is where
// the boundary is. A session that has proved nothing sends the
// announcement and a payload of well-formed commands, and what has to
// hold is that the payload cannot carry the session past the state it
// is in: it may not authenticate it, and it may not reach a verb that
// needs an account.
//
// What the listener does with those octets is recorded rather than
// asserted either way. The composed reader refuses the announcement and
// resumes parsing at the next line, so the payload is read as commands
// rather than drained, and the pre-auth state table is what stops them
// mattering. That is the vendored listener's behavior rather than this
// server's composition, and the assertions below are the ones that stay
// true whichever way it is settled.
async function aRefusedNonSynchronizingLiteralCannotCarryASessionForward(ctx) {
  var session = await ctx.unauthenticated("literal-plus");
  var smuggled = "s9 NOOP\r\ns8 SELECT INBOX\r\ns7 FETCH 1 BODY[]\r\n";
  session.sendNonSyncLiteral("q1 LOGIN", smuggled, "<a LITERAL+ announcement>");
  var answered = await session.readQuietly("answer to the LITERAL+ announcement");

  count("a LITERAL+ announcement is refused, because this server does not advertise it",
    /(BAD|NO)/.test(answered), visible(answered));
  count("and no continuation invites the octets",
    !CONTINUATION.test(answered), visible(answered));

  // The two that matter. `LOGIN` is the verb the announcement was
  // written on, so a payload that completed it would have signed a
  // session in with bytes the guard refused to read.
  count("the refused announcement does not authenticate the session",
    answered.indexOf("q1 OK") === -1, visible(answered));
  count("and nothing in the payload opens a mailbox or reads a message",
    answered.indexOf("s8 OK") === -1 && answered.indexOf("s7 OK") === -1 &&
    answered.indexOf("* 1 EXISTS") === -1 && answered.indexOf(ALICE_MARKER) === -1,
    visible(answered));

  // Read back from the session itself rather than from the transcript,
  // because a session can be advanced without saying so.
  var selected = await ask(session, "SELECT INBOX", "SELECT after the refused announcement");
  count("and the session is still unauthenticated afterwards",
    selected.verdict !== "OK", visible(selected.text));
  session.close();
}

// The same question asked by a peer that has proved nothing. APPEND is
// the one verb carrying a literal that a client may reach for before it
// authenticates, so it is the one place an unauthenticated peer names a
// length this server would otherwise allocate against.
async function anAppendBeforeAuthenticationIsRefused(ctx) {
  var session = await ctx.unauthenticated("append-pre-auth");
  session.sendRaw("p1 APPEND INBOX {40}\r\n", "<APPEND before authentication>");
  var answered = await session.readQuietly("answer to the pre-auth APPEND");

  count("an APPEND before authentication is refused",
    /(BAD|NO)/.test(answered), visible(answered));
  count("and no continuation invites its octets",
    !CONTINUATION.test(answered), visible(answered));

  // The session is still unauthenticated afterwards, which is the part
  // that matters: a refusal that left the state machine advanced would
  // be worse than one that did not arrive.
  var selected = await ask(session, "SELECT INBOX", "SELECT after the refused APPEND");
  count("and the session is still unauthenticated, so nothing opened a mailbox",
    selected.verdict !== "OK", visible(selected.text));
  session.close();
}

// ---- IDLE ------------------------------------------------------------------

// RFC 2177 ends an IDLE with `DONE`. A command sent instead is the case
// the specification does not write down, and the two answers that are
// safe are refusing it and ending the IDLE; the unsafe one is running it
// while the client believes the session is idling.
async function aCommandDuringIdleDoesNotRunBehindTheClientsBack(ctx) {
  var session = await ctx.session("alice", "idle-command");
  await ask(session, "SELECT INBOX");

  session.send("i1 IDLE");
  var invited = await session.read(/^\+|^i1 (OK|NO|BAD)/m, "IDLE answered");
  count("IDLE is accepted with a continuation", CONTINUATION.test(invited),
    visible(invited));

  session.send("i2 STATUS INBOX (MESSAGES)");
  var during = await session.readQuietly("answer to a command sent during IDLE");
  count("a command sent during an IDLE is not completed as an ordinary command",
    !/^i2 OK/m.test(during), visible(during));
  count("and it is refused for being something other than DONE, rather than ignored",
    /^\* BAD/m.test(during) && /DONE/.test(during), visible(during));
  count("and it reports nothing about the mailbox on its way to being refused",
    !/^\* STATUS/m.test(during), visible(during));

  session.send("DONE");
  var done = await session.readQuietly("answer to DONE");
  count("DONE completes the IDLE against the tag that opened it",
    /^i1 OK/m.test(done), visible(done));

  // The command refused during the IDLE stays refused. One held back
  // and run at DONE would be a command the client believes never
  // executed, running against a mailbox it may have stopped watching.
  count("and the command refused during the IDLE is not run once the IDLE ends",
    !/^i2 /m.test(done), visible(done));

  // The session is ordinary again afterwards, which is what says DONE
  // ended the IDLE rather than the connection.
  var after = await ask(session, "NOOP", "NOOP after DONE");
  count("and the session takes commands again after DONE",
    after.verdict === "OK", visible(after.text));
  session.close();
}

// IDLE needs a session that has proved who it is, because it is what
// holds a connection open indefinitely.
async function idleBeforeAuthenticationIsRefused(ctx) {
  var session = await ctx.unauthenticated("idle-pre-auth");
  session.send("j1 IDLE");
  var answered = await session.readQuietly("answer to a pre-auth IDLE");
  count("IDLE before authentication is refused",
    /(BAD|NO)/.test(answered), visible(answered));
  count("and no continuation invites the client to hold the connection open",
    !CONTINUATION.test(answered), visible(answered));
  session.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-command-refusals");
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
  var sessions = [];

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    identity.mailbox.appendMessage("INBOX", message(ALICE_MARKER, alice.address),
      { actor: { id: alice.id } });
    identity.mailbox.appendMessage("INBOX", message(BOB_MARKER, bob.address),
      { actor: { id: bob.id } });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var who = {
      alice: { address: alice.address, password: ALICE_PASSWORD },
      bob:   { address: bob.address,   password: BOB_PASSWORD },
    };

    var ctx = {
      identity: identity,
      session:  async function (name, label) {
        var opened = await Wire.imap(sections.imap.port, {
          caPem: leaf.ca, servername: HOSTNAME,
          address: who[name].address, password: who[name].password,
          label: "imap-command-refusals " + label,
        });
        sessions.push(opened);
        return opened;
      },
      // The same ladder stopped one rung short. `Wire.imap` refuses to
      // hand back a session that did not authenticate, which is right
      // for every other file and is exactly what these cases need to
      // undo: the state before a credential is the state under test.
      unauthenticated: async function (label) {
        var opened = await Wire.connect(sections.imap.port,
          "imap-command-refusals " + label);
        sessions.push(opened);
        await opened.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
        opened.send("u0 STARTTLS");
        await opened.read(/^u0 OK/m, "STARTTLS accepted");
        await opened.upgrade(leaf.ca, HOSTNAME);
        return opened;
      },
    };

    await theUnservedVerbsAreRefused(ctx);
    await aCreateCannotNameAMailboxOutsideTheAccount(ctx);
    await theOtherAccountIsUntouched(ctx);
    await noListPatternReachesAnotherAccount(ctx);
    await malformedCommandsRefuseLoudAndKeepTheSession(ctx);
    await aRefusedNonSynchronizingLiteralCannotCarryASessionForward(ctx);
    await anAppendBeforeAuthenticationIsRefused(ctx);
    await aCommandDuringIdleDoesNotRunBehindTheClientsBack(ctx);
    await idleBeforeAuthenticationIsRefused(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) {
      try { s.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    });
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

module.exports = { name: "imap-command-refusals", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
