// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an IMAP session has selected, and whether it may change it.
 *
 * RFC 9051 section 6.3.3 opens a mailbox read-only under EXAMINE and
 * permits no change to its permanent state from that session, the
 * `\Seen` flag included. Section 6.3.2 says a SELECT that fails leaves no
 * mailbox selected. Section 6.4.1 has CLOSE remove every message flagged
 * `\Deleted` from a mailbox opened read-write, and nothing from one
 * opened read-only.
 *
 * The first two are the destructive half. A session that opened a
 * mailbox to look at it, or a client that tried to open a second mailbox
 * and was refused, believes nothing it sends can remove mail from the
 * first one. An EXPUNGE that runs anyway removes the messages another
 * session flagged, from a mailbox the client did not think it held.
 *
 * Every case drives a real session against the listener, and every
 * removal is read back from the message store as well as from a fresh
 * SELECT, because a session can stop mentioning a message the store
 * still holds.
 *
 * Run standalone: node test/layer-2-integration/imap-selected-state.test.js
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
var ALICE_PASSWORD   = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

function message(marker) {
  return [
    "From: sender@example.net",
    "To: alice@" + DOMAIN,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "",
    "Body of " + marker + ".",
    "",
  ].join("\r\n");
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

async function append(session, mailbox, marker) {
  var tag = session.tag();
  await session.sendLiteral(tag + " APPEND " + mailbox, message(marker), "<" + marker + ">");
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND " + marker);
  count("the fixture message " + marker + " is appended",
    new RegExp("^" + tag + " OK", "m").test(text), visible(text));
}

function existsIn(text) {
  var found = /^\* (\d+) EXISTS/m.exec(text);
  return found === null ? -1 : parseInt(found[1], 10);
}

function storeFolderOf(identity, accountId, wireName) {
  var found = identity.mailbox.accountFolders({ id: accountId })
    .filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function storedCount(identity, accountId, wireName) {
  return identity.messageStore.queryByModseq(storeFolderOf(identity, accountId, wireName),
    { sinceModseq: 0 }).length;
}

// ---- cases -----------------------------------------------------------------

// A session that EXAMINEs a mailbox is not the session that decides what
// leaves it. The message here is flagged by a read-write session, which
// is the ordinary shape: a client with two connections open, one of
// them browsing.
async function anExamineSessionRemovesNothing(ctx) {
  var writer = await ctx.session("examine-writer");
  await append(writer, "INBOX", "examine-one");
  await append(writer, "INBOX", "examine-two");
  await ask(writer, "SELECT INBOX");
  var flagged = await ask(writer, "STORE 1 +FLAGS (\\Deleted)");
  count("the read-write session flags the first message deleted",
    flagged.verdict === "OK", visible(flagged.text));

  var reader = await ctx.session("examine-reader");
  var examined = await ask(reader, "EXAMINE INBOX");
  count("EXAMINE opens the mailbox read-only",
    /^\S+ OK \[READ-ONLY\]/m.test(examined.text), visible(examined.text));

  var expunged = await ask(reader, "EXPUNGE");
  count("EXPUNGE from the read-only session is refused rather than completed",
    expunged.verdict === "NO", visible(expunged.text));
  count("and it reports no message removed",
    !/^\* \d+ EXPUNGE/m.test(expunged.text), visible(expunged.text));
  count("the message store still holds both messages",
    storedCount(ctx.identity, ctx.alice.id, "INBOX") === 2,
    String(storedCount(ctx.identity, ctx.alice.id, "INBOX")));

  var closed = await ask(reader, "CLOSE");
  count("CLOSE on the read-only session completes",
    closed.verdict === "OK", visible(closed.text));
  count("and removes nothing either, which RFC 9051 section 6.4.1 says of a read-only mailbox",
    storedCount(ctx.identity, ctx.alice.id, "INBOX") === 2,
    String(storedCount(ctx.identity, ctx.alice.id, "INBOX")));

  var reopened = await ask(writer, "SELECT INBOX");
  count("a fresh SELECT still counts both messages",
    existsIn(reopened.text) === 2, visible(reopened.text));

  // The flag goes back off, so the cases after this one start from a
  // mailbox with nothing marked for removal.
  await ask(writer, "STORE 1 -FLAGS (\\Deleted)");
  writer.close();
  reader.close();
}

// A read is a change of per-user state when it sets `\Seen`, and
// EXAMINE permits no such change. The flag is read back from a second
// session, because the session that fetched could agree with itself.
async function anExamineReadLeavesTheMessageUnseen(ctx) {
  var reader = await ctx.session("examine-read");
  await ask(reader, "EXAMINE INBOX");
  var fetched = await ask(reader, "FETCH 2 BODY[]");
  count("a read-only session reads the whole message",
    fetched.verdict === "OK" && fetched.text.indexOf("Body of examine-two.") !== -1,
    visible(fetched.text));

  var checker = await ctx.session("examine-read-check");
  await ask(checker, "EXAMINE INBOX");
  var flags = await ask(checker, "FETCH 2 (FLAGS)");
  count("the read did not set \\Seen on a message in a read-only mailbox",
    flags.verdict === "OK" && !/\\Seen/.test(flags.text), visible(flags.text));

  // The same read from a read-write session does set it, so the
  // assertion above is about the mode rather than about a read that
  // never records anything.
  var writer = await ctx.session("select-read");
  await ask(writer, "SELECT INBOX");
  await ask(writer, "FETCH 2 BODY[]");
  var after = await ask(checker, "FETCH 2 (FLAGS)");
  count("the same read from a read-write session does set \\Seen",
    /\\Seen/.test(after.text), visible(after.text));
  await ask(writer, "STORE 2 -FLAGS (\\Seen)");

  reader.close();
  checker.close();
  writer.close();
}

// Two sessions of one account hold two selections. A read-only session
// stays read-only when another session of the same account opens the
// same mailbox read-write, and the other way round.
async function twoSessionsOfOneAccountKeepTheirOwnMode(ctx) {
  var viewer = await ctx.session("mode-viewer");
  var editor = await ctx.session("mode-editor");
  await ask(viewer, "EXAMINE INBOX");
  await ask(editor, "SELECT INBOX");
  await ask(editor, "STORE 1 +FLAGS (\\Deleted)");

  var refused = await ask(viewer, "EXPUNGE");
  count("the read-only session is still read-only after another session selected the mailbox",
    refused.verdict === "NO" && !/^\* \d+ EXPUNGE/m.test(refused.text), visible(refused.text));
  await ask(viewer, "FETCH 1 BODY[]");
  var unseen = await ask(editor, "FETCH 1 (FLAGS)");
  count("and a read from it still leaves the message unseen",
    !/\\Seen/.test(unseen.text), visible(unseen.text));

  var removed = await ask(editor, "EXPUNGE");
  count("the read-write session of the same account removes the flagged message",
    removed.verdict === "OK" && /^\* 1 EXPUNGE/m.test(removed.text), visible(removed.text));
  count("and the store agrees one message is left",
    storedCount(ctx.identity, ctx.alice.id, "INBOX") === 1,
    String(storedCount(ctx.identity, ctx.alice.id, "INBOX")));

  viewer.close();
  editor.close();
}

// A SELECT the store refuses leaves nothing selected, so the EXPUNGE a
// client sends next cannot reach the mailbox that was open before it.
async function aRefusedSelectLeavesNothingSelected(ctx) {
  var session = await ctx.session("refused-select");
  await append(session, "Archive", "refused-one");
  await append(session, "Archive", "refused-two");
  await ask(session, "SELECT Archive");
  await ask(session, "STORE 1 +FLAGS (\\Deleted)");

  var missing = await ask(session, "SELECT NoSuchMailbox");
  count("a SELECT naming a mailbox the account does not hold is refused",
    missing.verdict === "NO", visible(missing.text));
  count("with the NONEXISTENT code RFC 9051 section 7.1 defines for it",
    /^\S+ NO \[NONEXISTENT\]/m.test(missing.text), visible(missing.text));

  var expunged = await ask(session, "EXPUNGE");
  count("EXPUNGE after the refused SELECT does not complete",
    expunged.verdict !== "OK", visible(expunged.text));
  count("and removes nothing from the mailbox that was open before it",
    !/^\* \d+ EXPUNGE/m.test(expunged.text) &&
      storedCount(ctx.identity, ctx.alice.id, "Archive") === 2,
    visible(expunged.text) + " stored=" + storedCount(ctx.identity, ctx.alice.id, "Archive"));

  var fetched = await ask(session, "FETCH 1 (FLAGS)");
  count("a FETCH after the refused SELECT is answered as a command outside the Selected state",
    fetched.verdict === "BAD", visible(fetched.text));

  // A SELECT whose arguments cannot be read fails as well, with BAD
  // rather than NO, and leaves the same empty selection behind.
  await ask(session, "SELECT Archive");
  var malformed = await ask(session, "SELECT Archive (NOSUCHPARAMETER)");
  count("a SELECT carrying a parameter this server does not know is refused as BAD",
    malformed.verdict === "BAD", visible(malformed.text));
  var afterMalformed = await ask(session, "FETCH 1 (FLAGS)");
  count("and nothing is selected after it either",
    afterMalformed.verdict === "BAD", visible(afterMalformed.text));

  await ask(session, "SELECT Archive");
  await ask(session, "STORE 1 -FLAGS (\\Deleted)");
  session.close();
}

// CLOSE removes what a read-write session flagged, through the same
// delete path EXPUNGE takes, and answers without an untagged EXPUNGE.
// The hold is what shows the delete path ran: a CLOSE that removed
// messages some other way would take the held one too.
async function closeRemovesFlaggedMessagesThroughTheDeletePath(ctx) {
  var session = await ctx.session("close");
  await append(session, "Sent", "close-ordinary");
  await append(session, "Sent", "close-held");
  await append(session, "Sent", "close-kept");

  var folder = storeFolderOf(ctx.identity, ctx.alice.id, "Sent");
  var rows = ctx.identity.messageStore.queryByModseq(folder, { sinceModseq: 0 });
  var held = rows.filter(function (row) {
    var stored = ctx.identity.messageStore.fetchByObjectId(folder, row.objectid);
    return stored && stored.subject === "close-held";
  })[0];
  count("the message to hold is found in the store", !!held, JSON.stringify(rows.length));
  ctx.identity.messageStore.setLegalHold([held.objectid], { hold: true });

  await ask(session, "SELECT Sent");
  await ask(session, "STORE 1:2 +FLAGS (\\Deleted)");
  var closed = await ask(session, "CLOSE");
  count("CLOSE on a read-write session completes", closed.verdict === "OK", visible(closed.text));
  count("without an untagged EXPUNGE, which RFC 9051 section 6.4.1 says CLOSE does not send",
    !/^\* \d+ EXPUNGE/m.test(closed.text), visible(closed.text));

  count("the store no longer holds the flagged message that was not held, " +
    "and still holds the held one and the unflagged one",
    storedCount(ctx.identity, ctx.alice.id, "Sent") === 2,
    String(storedCount(ctx.identity, ctx.alice.id, "Sent")));

  var fetched = await ask(session, "FETCH 1 (FLAGS)");
  count("CLOSE leaves the session with nothing selected",
    fetched.verdict === "BAD", visible(fetched.text));

  var reopened = await ask(session, "SELECT Sent");
  count("a fresh SELECT counts the two messages left", existsIn(reopened.text) === 2,
    visible(reopened.text));
  var bodies = await ask(session, "FETCH 1:2 BODY.PEEK[HEADER.FIELDS (SUBJECT)]");
  count("and they are the held message and the one that was never flagged",
    bodies.text.indexOf("close-held") !== -1 && bodies.text.indexOf("close-kept") !== -1 &&
      bodies.text.indexOf("close-ordinary") === -1, visible(bodies.text));

  await ask(session, "UNSELECT");
  var outside = await ask(session, "CLOSE");
  count("CLOSE with no mailbox selected is refused as a command outside the Selected state",
    outside.verdict === "BAD", visible(outside.text));

  session.close();
}

// RFC 7162 section 3.1.8 gives SELECT and EXAMINE a CONDSTORE parameter,
// which a server advertising CONDSTORE has to accept. RFC 7162 section
// 3.2.5 answers BAD to a QRESYNC parameter from a session that has not
// enabled QRESYNC, and this server does not offer it.
async function selectParametersAreReadRatherThanTakenAsAName(ctx) {
  var session = await ctx.session("select-params");
  var condstore = await ask(session, "SELECT INBOX (CONDSTORE)");
  count("SELECT with the CONDSTORE parameter opens the mailbox",
    condstore.verdict === "OK" && /^\* OK \[HIGHESTMODSEQ \d+\]/m.test(condstore.text),
    visible(condstore.text));
  var fetched = await ask(session, "FETCH 1 (FLAGS)");
  count("and FETCH responses carry MODSEQ afterwards",
    /MODSEQ \(\d+\)/.test(fetched.text), visible(fetched.text));

  var quoted = await ask(session, "EXAMINE \"INBOX\" (CONDSTORE)");
  count("EXAMINE takes the parameter after a quoted mailbox name as well",
    /^\S+ OK \[READ-ONLY\]/m.test(quoted.text), visible(quoted.text));

  var qresync = await ask(session, "SELECT INBOX (QRESYNC (1 1))");
  count("a QRESYNC parameter is refused as BAD", qresync.verdict === "BAD",
    visible(qresync.text));

  var literal = session.tag();
  await session.sendLiteral(literal + " SELECT", "INBOX", "<INBOX as a literal>");
  var byLiteral = await session.read(new RegExp("^" + literal + " (OK|NO|BAD)", "m"),
    "SELECT with a literal name");
  count("a mailbox name sent as a literal is still read as the name",
    new RegExp("^" + literal + " OK \\[READ-WRITE\\]", "m").test(byLiteral), visible(byLiteral));

  session.close();
}

// What a selection says can be kept.
//
// RFC 9051 section 6.3.2 makes an untagged `OK [PERMANENTFLAGS (...)]`
// a required response to SELECT and to EXAMINE. It is the only thing
// that tells a client which flags survive the session and whether it may
// invent keywords of its own, and a client that is not told assumes
// every flag it sends is kept.
//
// Both halves are measured against what the server then does, because a
// list is a claim: the flags it names are set and read back from a
// second session, and the read-only selection that names none is asked
// to change one.
async function aSelectionSaysWhichFlagsItKeeps(ctx) {
  var session = await ctx.session("permanentflags");
  await append(session, "Junk", "permanent-one");

  var selected = await ask(session, "SELECT Junk");
  var announced = /^\* OK \[PERMANENTFLAGS \(([^)]*)\)\]/m.exec(selected.text);
  count("SELECT sends the PERMANENTFLAGS response RFC 9051 section 6.3.2 requires",
    announced !== null, visible(selected.text));
  var permanent = announced === null ? [] : announced[1].split(" ").filter(Boolean);

  var system = ["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"];
  var missing = system.filter(function (flag) { return permanent.indexOf(flag) === -1; });
  count("it names every system flag this server keeps", missing.length === 0,
    missing.join(" ") + " of " + permanent.join(" "));
  count("and not \\Recent, which IMAP4rev2 removed",
    permanent.indexOf("\\Recent") === -1, permanent.join(" "));
  count("the FLAGS response is sent alongside it",
    /^\* FLAGS \(/m.test(selected.text), visible(selected.text));

  // `\*` is a claim that a client may invent keywords. It is measured
  // rather than read: a keyword the client chose is set, and a second
  // session reads it back, because the session that set it could be
  // holding it in memory of its own.
  count("it carries \\*, which RFC 9051 section 7.1 makes the mark of a mailbox that " +
    "keeps new keywords", permanent.indexOf("\\*") !== -1, permanent.join(" "));
  var stored = await ask(session, "STORE 1 +FLAGS ($Label1)");
  count("a keyword the client invented is accepted", stored.verdict === "OK",
    visible(stored.text));

  var reader = await ctx.session("permanentflags-reader");
  await ask(reader, "SELECT Junk");
  var readBack = await ask(reader, "FETCH 1 (FLAGS)");
  count("and a second session reads it back, so \\* is what this server does",
    /\$Label1/.test(readBack.text), visible(readBack.text));
  reader.close();

  // RFC 9051 section 6.3.2 permits no change to the permanent state of a
  // mailbox opened with EXAMINE, so the list of flags that session can
  // keep is empty.
  var examined = await ask(session, "EXAMINE Junk");
  var readOnly = /^\* OK \[PERMANENTFLAGS \(([^)]*)\)\]/m.exec(examined.text);
  count("EXAMINE sends the response too", readOnly !== null, visible(examined.text));
  count("and names no flag, because nothing a read-only session sets is kept",
    readOnly !== null && readOnly[1] === "", readOnly === null ? "" : readOnly[1]);
  count("the FLAGS response is still sent, because the mailbox has the same flags " +
    "whichever way it was opened", /^\* FLAGS \(/m.test(examined.text), visible(examined.text));

  var refused = await ask(session, "STORE 1 +FLAGS (\\Flagged)");
  count("a STORE from the read-only session is refused, so the empty list is the truth " +
    "rather than a formality", refused.verdict === "NO", visible(refused.text));

  await ask(session, "SELECT Junk");
  await ask(session, "STORE 1 -FLAGS ($Label1)");
  session.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-selected-state");
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

    var ctx = {
      identity: identity,
      alice:    alice,
      session:  async function (label) {
        var opened = await Wire.imap(sections.imap.port, {
          caPem: leaf.ca, servername: HOSTNAME,
          address: alice.address, password: ALICE_PASSWORD,
          label: "imap-selected-state " + label,
        });
        sessions.push(opened);
        return opened;
      },
    };

    await anExamineSessionRemovesNothing(ctx);
    await anExamineReadLeavesTheMessageUnseen(ctx);
    await twoSessionsOfOneAccountKeepTheirOwnMode(ctx);
    await aRefusedSelectLeavesNothingSelected(ctx);
    await closeRemovesFlaggedMessagesThroughTheDeletePath(ctx);
    await selectParametersAreReadRatherThanTakenAsAName(ctx);
    await aSelectionSaysWhichFlagsItKeeps(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) { s.close(); });
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

module.exports = { name: "imap-selected-state", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
