// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The marks a reader's own actions write on one message, asked of every
 * surface that can write one and every surface that can read one.
 *
 * An account holder reads mail from more than one place at once: a
 * desktop client on IMAP, a phone on JMAP, a browser tab on the webmail
 * pages. Marking a message read in one of them and finding it still bold
 * in the next is the oldest complaint there is about a mail server, and
 * it is a complaint about agreement rather than about any one surface.
 * All three write through `b.mail.agent.flag` onto the same adapter
 * rows, so agreement is what the composition is FOR, and nothing asked
 * the three of them the same question.
 *
 * Two families of mark are driven, and they behave differently on
 * purpose.
 *
 * THE FOUR SYSTEM FLAGS RFC 8621 section 4.1.1 exposes. `\Seen`,
 * `\Flagged`, `\Answered` and `\Draft` each have a JMAP keyword, so all
 * three surfaces can write one and two of them can read it. Each is
 * written on one surface here and read back on the others, so a write
 * that lands somewhere only its own surface looks is a failing vector
 * rather than a support request.
 *
 * `\Deleted`, WHICH IS NOT ONE OF THEM. It is what an IMAP client draws
 * a message struck through for, and it is what the browser's own Trash
 * button sets when a reader files a message away. JMAP exposes no
 * keyword for it and the browser offers no control that clears it, so on
 * those two surfaces filing the message back somewhere is the only way a
 * reader says they want it, and both of them have to take the mark off.
 * Only the browser's half was driven; the JMAP `mailboxIds` patch
 * reaches the same clearing step and nothing asked it. The failure that
 * leaves is quiet: the message comes back out of the bin, the client
 * that filed it sees nothing wrong because its protocol never showed it
 * the mark, and every IMAP client the account holder owns draws that
 * message struck through in the inbox with no verb on either of the
 * other two surfaces able to undo it.
 *
 * So every mark below is read over IMAP, and every mark JMAP exposes is
 * read there as well. Reading one back through the adapter that wrote it
 * would be asserting on the layer that did the writing.
 *
 * Nothing external is needed. Every port is ephemeral on the loopback
 * interface and the volume is a temporary directory.
 *
 * Run standalone: node test/layer-2-integration/message-mark-surface-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var INBOX = "INBOX";
var TRASH = "Trash";

var DELETED_FLAG    = "\\Deleted";
var DELETED_KEYWORD = "$deleted";

var SHUTDOWN_TIMEOUT_MS = 5000;

// One subject per message, distinctive enough that a SEARCH for it can
// only match the message it was written for. A run whose cases shared a
// subject would read one case's mark while asserting about another's.
var SUBJECTS = Object.freeze({
  seenFromTheBrowser: "markparityalpha",
  flaggedFromImap:    "markparitybravo",
  answeredFromJmap:   "markparitycharlie",
  browserBack:        "markparitydelta",
  jmapBack:           "markparityecho",
  intoTrash:          "markparityfoxtrot",
  untouched:          "markparitygolf",
});

function message(to, subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + subject + ".\r\n", "utf8");
}

// ---- what an IMAP client sees ----------------------------------------------

// One message, found by the subject it was written with, and what the
// listener says about it. This is the client's own route to the answer:
// select the folder, search for the message, fetch its flags. Nothing
// reads the adapter, because the adapter is what wrote them.
//
// It answers `{ matched, seq, flags, text }`. `matched` is how many
// messages the folder held for that subject, so a case can tell a
// message that moved from one that is in two places; `seq` is the
// sequence number a STORE addresses it by; `flags` is null when the
// search matched anything other than exactly one message.
async function findOverImap(session, folder, subject) {
  var selected = await session.imapAsk("SELECT " + folder, "SELECT " + folder);
  if (selected.verdict !== "OK") {
    return { matched: -1, seq: null, flags: null, text: selected.text };
  }
  var found = await session.imapAsk('SEARCH SUBJECT "' + subject + '"',
    "SEARCH " + subject + " in " + folder);
  var line = /^\* SEARCH([^\r\n]*)\r?$/m.exec(found.text);
  var numbers = line === null
    ? []
    : line[1].trim().split(/\s+/).filter(function (part) { return part.length > 0; });
  if (numbers.length !== 1) {
    return { matched: numbers.length, seq: null, flags: null, text: found.text };
  }
  var fetched = await session.imapAsk("FETCH " + numbers[0] + " (FLAGS)",
    "FETCH FLAGS in " + folder);
  var set = /FLAGS \(([^)]*)\)/.exec(fetched.text);
  return {
    matched: 1,
    seq:     numbers[0],
    flags:   set === null
      ? null
      : set[1].split(/\s+/).filter(function (part) { return part.length > 0; }),
    text:    fetched.text,
  };
}

function carries(reading, flag) {
  return reading.flags !== null && reading.flags.indexOf(flag) !== -1;
}

// ---- what a JMAP client sees -----------------------------------------------

async function keywordsOverJmap(reader, accountId, objectId) {
  var answer = await reader.jmap([
    ["Email/get", { accountId: accountId, ids: [objectId], properties: ["keywords"] }, "c0"],
  ]);
  var body = browser.answer(answer)[1];
  var first = (body.list || [])[0];
  return {
    found:    first !== undefined,
    keywords: first === undefined ? {} : (first.keywords || {}),
    text:     String(answer.body).slice(0, 400),
  };
}

function carriesKeyword(seen, keyword) {
  return Object.prototype.hasOwnProperty.call(seen.keywords, keyword) &&
    seen.keywords[keyword] === true;
}

// ---- the surfaces that write a mark ----------------------------------------

async function markWithTheBrowser(reader, folder, action, objectId) {
  var answered = await reader.form("/mail/actions?folder=" + encodeURIComponent(folder), {
    action: action, objectId: objectId,
  });
  return {
    ok:   answered.status === 302,
    text: answered.status + " " + String(answered.location || ""),
  };
}

async function markWithJmap(reader, accountId, objectId, keyword, value) {
  var patch = {};
  patch[objectId] = {};
  patch[objectId]["keywords/" + keyword] = value;
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, update: patch }, "c0"],
  ]);
  var body = browser.answer(answer)[1];
  return {
    ok:   body.updated !== undefined &&
          Object.prototype.hasOwnProperty.call(body.updated, objectId),
    text: String(answer.body).slice(0, 400),
  };
}

// ---- the surfaces that file a message --------------------------------------

async function fileWithTheBrowser(reader, from, to, objectId) {
  var moved = await reader.form("/mail/actions?folder=" + encodeURIComponent(from), {
    action: "move", objectId: objectId, destination: to,
  });
  return { ok: moved.status === 302, text: moved.status + " " + String(moved.location || "") };
}

async function fileWithJmap(reader, accountId, to, objectId) {
  var patch = {};
  patch[objectId] = { mailboxIds: {} };
  patch[objectId].mailboxIds[to] = true;
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, update: patch }, "c0"],
  ]);
  var body = browser.answer(answer)[1];
  return {
    ok:   body.updated !== undefined &&
          Object.prototype.hasOwnProperty.call(body.updated, objectId),
    text: String(answer.body).slice(0, 400),
  };
}

// ---- the four flags every surface can reach --------------------------------

// One mark, written on one surface and read on the other two. The three
// cases below rotate which surface writes, because a server that only
// reads what it wrote itself passes any one of them.
async function aMarkWrittenOnOneSurfaceIsReadOnTheOthers(spec) {
  var written = await spec.write();
  count(spec.writer + " writes " + spec.flag + " on " + spec.subject, written.ok === true,
    written.text);

  var reading = await findOverImap(spec.session, INBOX, spec.subject);
  count("an IMAP client finds " + spec.subject + " in the inbox", reading.matched === 1,
    String(reading.matched) + " " + visible(reading.text));
  count("and it carries " + spec.flag + ", written by " + spec.writer,
    carries(reading, spec.flag), JSON.stringify(reading.flags));

  var seen = await keywordsOverJmap(spec.reader, spec.accountId, spec.objectId);
  count("a JMAP client reads the same message", seen.found, seen.text);
  count("and is shown " + spec.keyword + " on it, written by " + spec.writer,
    carriesKeyword(seen, spec.keyword), JSON.stringify(seen.keywords));
}

// The other direction. A mark taken off on one surface has to be gone on
// the others, or a reader who marked a message unread on their phone
// finds it read again the moment their desktop client polls.
async function aMarkTakenOffOnOneSurfaceIsGoneOnTheOthers(spec) {
  var cleared = await spec.clear();
  count(spec.clearer + " takes " + spec.flag + " back off " + spec.subject,
    cleared.ok === true, cleared.text);

  var reading = await findOverImap(spec.session, INBOX, spec.subject);
  count("an IMAP client no longer sees " + spec.flag + " on it",
    reading.matched === 1 && carries(reading, spec.flag) === false,
    String(reading.matched) + " " + JSON.stringify(reading.flags));

  var seen = await keywordsOverJmap(spec.reader, spec.accountId, spec.objectId);
  count("and a JMAP client is shown no " + spec.keyword + " on it either",
    seen.found && carriesKeyword(seen, spec.keyword) === false,
    JSON.stringify(seen.keywords));
}

// ---- the mark only one surface writes and only one surface reads -----------

// The setup every later case reads against, and a claim of its own: the
// browser's Trash button is the one verb on any surface that writes this
// mark, and an IMAP client has to be able to see what it wrote.
async function theTrashButtonWritesTheMark(reader, session, objectIds, subject) {
  var trashed = await markWithTheBrowser(reader, INBOX, "trash", objectIds[subject]);
  count("the Trash button files " + subject + " away", trashed.ok === true, trashed.text);

  var reading = await findOverImap(session, TRASH, subject);
  count("an IMAP client finds " + subject + " in Trash", reading.matched === 1,
    String(reading.matched) + " " + visible(reading.text));
  count("carrying the mark that says it is waiting there", carries(reading, DELETED_FLAG),
    JSON.stringify(reading.flags));
}

// The asymmetry the rule rests on. A JMAP client is shown four keywords
// and this is not one of them, so it has no verb that clears the mark
// and filing the message is the only thing it can do.
async function aJmapClientIsShownNoDeletedKeyword(reader, accountId, objectId, subject) {
  var seen = await keywordsOverJmap(reader, accountId, objectId);
  count("a JMAP client reads " + subject + " while it sits marked in Trash", seen.found,
    seen.text);
  count("and is shown no keyword for the mark, so it holds no verb that could clear one",
    Object.prototype.hasOwnProperty.call(seen.keywords, DELETED_KEYWORD) === false,
    JSON.stringify(seen.keywords));
}

// Both halves of the shared rule, one per surface, each asserted the
// same way so a difference between them is a difference in the server
// rather than in how it was asked.
async function filingOutOfTrashClearsTheMark(spec) {
  var filed = await spec.file();
  count(spec.surface + " files " + spec.subject + " back out of Trash", filed.ok === true,
    filed.text);

  var reading = await findOverImap(spec.session, INBOX, spec.subject);
  count("an IMAP client finds " + spec.subject + " back in the inbox", reading.matched === 1,
    String(reading.matched) + " " + visible(reading.text));
  count("and the mark came off it, so no client draws it struck through in a folder " +
    "nothing purges (" + spec.surface + ")", carries(reading, DELETED_FLAG) === false,
    JSON.stringify(reading.flags));

  var behind = await findOverImap(spec.session, TRASH, spec.subject);
  count("with nothing left behind in Trash (" + spec.surface + ")", behind.matched === 0,
    String(behind.matched) + " " + visible(behind.text));
}

// The cell that stays shut. Trash is where a marked message belongs, so
// filing one INTO it must leave the mark alone: a move that cleared it
// would take the strike-through off the message the reader just binned.
async function filingIntoTrashLeavesTheMark(reader, session, accountId, objectIds) {
  var subject = SUBJECTS.intoTrash;
  var trashed = await markWithTheBrowser(reader, INBOX, "trash", objectIds[subject]);
  count("the Trash button files " + subject + " away", trashed.ok === true, trashed.text);

  var marked = await findOverImap(session, TRASH, subject);
  count(subject + " is in Trash carrying the mark", carries(marked, DELETED_FLAG),
    JSON.stringify(marked.flags));

  // A JMAP patch naming the folder the message is already in. The filing
  // step is skipped, so the clearing step behind it is skipped too, and
  // the mark has to still be there afterwards.
  var again = await fileWithJmap(reader, accountId, TRASH, objectIds[subject]);
  count("a JMAP patch naming Trash for a message already in Trash is answered",
    again.ok === true, again.text);

  var after = await findOverImap(session, TRASH, subject);
  count("and the mark is still on it, because Trash is where a marked message belongs",
    carries(after, DELETED_FLAG), JSON.stringify(after.flags));
}

// The control. A move is not a way to write this mark, so a message that
// never carried one must not come out of either surface's move with one.
async function movingAnUnmarkedMessageWritesNoMark(reader, session, accountId, objectIds) {
  var subject = SUBJECTS.untouched;
  var before = await findOverImap(session, INBOX, subject);
  count(subject + " starts in the inbox with no mark on it",
    before.matched === 1 && carries(before, DELETED_FLAG) === false,
    String(before.matched) + " " + JSON.stringify(before.flags));

  var out = await fileWithJmap(reader, accountId, TRASH, objectIds[subject]);
  count("a JMAP client files " + subject + " into Trash", out.ok === true, out.text);
  var inTrash = await findOverImap(session, TRASH, subject);
  count("a JMAP move into Trash writes no mark, because only the browser's own soft " +
    "delete does", inTrash.matched === 1 && carries(inTrash, DELETED_FLAG) === false,
    String(inTrash.matched) + " " + JSON.stringify(inTrash.flags));

  var back = await fileWithTheBrowser(reader, TRASH, INBOX, objectIds[subject]);
  count("the browser files " + subject + " back out again", back.ok === true, back.text);
  var home = await findOverImap(session, INBOX, subject);
  count("and it is still unmarked, so the clearing step invented nothing",
    home.matched === 1 && carries(home, DELETED_FLAG) === false,
    String(home.matched) + " " + JSON.stringify(home.flags));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("message-mark");
  var dataDir = helpers.dataDir(root);
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  var session  = null;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // Put in place through the adapter's own append, which is the call
    // inbound delivery makes once a message has been accepted. What is
    // under test is the mark, so the arrival is set up rather than
    // driven.
    var owner = { id: alice.id, address: alice.address, roles: ["account"] };
    var objectIds = {};
    var names = Object.keys(SUBJECTS);
    for (var n = 0; n < names.length; n += 1) {
      var subject = SUBJECTS[names[n]];
      var stored = identity.mailbox.appendMessage(INBOX,
        message(alice.address, subject), { actor: owner });
      objectIds[subject] = stored.objectid;
    }
    count("every message this run reads about is in the inbox to begin with",
      Object.keys(objectIds).length === names.length,
      Object.keys(objectIds).join(", "));

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
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    var reader = browser.browserAt("https://" + LOOPBACK + ":" + bound.https,
      { ca: material.caPem });
    var landed = await reader.signIn(alice.address, ALICE_PASSWORD);
    count("the account holder is signed in to the browser surface", landed.status === 302,
      landed.status + " " + String(landed.body).slice(0, 200));

    session = await Wire.imap(sections.imap.port, {
      caPem:      material.caPem,
      servername: HOSTNAME,
      label:      "imap-message-mark",
      address:    alice.address,
      password:   ALICE_PASSWORD,
    });

    // The three surfaces take a turn at writing, so no case is satisfied
    // by a server that only reads back what it wrote itself.
    await aMarkWrittenOnOneSurfaceIsReadOnTheOthers({
      writer:    "the browser's mark-read action",
      subject:   SUBJECTS.seenFromTheBrowser,
      flag:      "\\Seen",
      keyword:   "$seen",
      session:   session,
      reader:    reader,
      accountId: alice.id,
      objectId:  objectIds[SUBJECTS.seenFromTheBrowser],
      write:     function () {
        return markWithTheBrowser(reader, INBOX, "read",
          objectIds[SUBJECTS.seenFromTheBrowser]);
      },
    });

    await aMarkWrittenOnOneSurfaceIsReadOnTheOthers({
      writer:    "an IMAP STORE",
      subject:   SUBJECTS.flaggedFromImap,
      flag:      "\\Flagged",
      keyword:   "$flagged",
      session:   session,
      reader:    reader,
      accountId: alice.id,
      objectId:  objectIds[SUBJECTS.flaggedFromImap],
      write:     async function () {
        var located = await findOverImap(session, INBOX, SUBJECTS.flaggedFromImap);
        if (located.seq === null) {
          return { ok: false, text: "the message was not found to STORE against" };
        }
        var stored = await session.imapAsk("STORE " + located.seq + " +FLAGS (\\Flagged)",
          "STORE +FLAGS");
        return { ok: stored.verdict === "OK", text: visible(stored.text) };
      },
    });

    await aMarkWrittenOnOneSurfaceIsReadOnTheOthers({
      writer:    "a JMAP keyword patch",
      subject:   SUBJECTS.answeredFromJmap,
      flag:      "\\Answered",
      keyword:   "$answered",
      session:   session,
      reader:    reader,
      accountId: alice.id,
      objectId:  objectIds[SUBJECTS.answeredFromJmap],
      write:     function () {
        return markWithJmap(reader, alice.id,
          objectIds[SUBJECTS.answeredFromJmap], "$answered", true);
      },
    });

    // And the other direction, on the mark a reader takes off most often.
    await aMarkTakenOffOnOneSurfaceIsGoneOnTheOthers({
      clearer:   "the browser's mark-unread action",
      subject:   SUBJECTS.seenFromTheBrowser,
      flag:      "\\Seen",
      keyword:   "$seen",
      session:   session,
      reader:    reader,
      accountId: alice.id,
      objectId:  objectIds[SUBJECTS.seenFromTheBrowser],
      clear:     function () {
        return markWithTheBrowser(reader, INBOX, "unread",
          objectIds[SUBJECTS.seenFromTheBrowser]);
      },
    });

    await theTrashButtonWritesTheMark(reader, session, objectIds, SUBJECTS.browserBack);
    await aJmapClientIsShownNoDeletedKeyword(reader, alice.id,
      objectIds[SUBJECTS.browserBack], SUBJECTS.browserBack);
    await filingOutOfTrashClearsTheMark({
      surface: "the browser move form",
      subject: SUBJECTS.browserBack,
      session: session,
      file:    function () {
        return fileWithTheBrowser(reader, TRASH, INBOX, objectIds[SUBJECTS.browserBack]);
      },
    });

    await theTrashButtonWritesTheMark(reader, session, objectIds, SUBJECTS.jmapBack);
    await filingOutOfTrashClearsTheMark({
      surface: "a JMAP mailboxIds patch",
      subject: SUBJECTS.jmapBack,
      session: session,
      file:    function () {
        return fileWithJmap(reader, alice.id, INBOX, objectIds[SUBJECTS.jmapBack]);
      },
    });

    await filingIntoTrashLeavesTheMark(reader, session, alice.id, objectIds);
    await movingAnUnmarkedMessageWritesNoMark(reader, session, alice.id, objectIds);

    // RFC 9051 section 6.1.3 has the server write an untagged BYE before
    // it closes, and that is what is waited for here. The tagged
    // completion the same section asks for is not: this listener writes
    // it and then destroys the socket in the same turn, so it does not
    // reach a client, and a teardown that waited for it would hang for
    // the whole wire budget on every run.
    session.send("z9 LOGOUT");
    var closing = await session.read(/^\* BYE/m, "LOGOUT answered");
    count("the listener says goodbye rather than dropping the connection",
      /^\* BYE/m.test(closing), visible(closing));
    session.close();
    session = null;

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (session !== null) {
      try { session.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
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

module.exports = {
  name:      "message-mark-surface-parity",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
