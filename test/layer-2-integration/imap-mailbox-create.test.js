// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Making a mailbox over IMAP.
 *
 * RFC 9051 section 6.3.4 makes CREATE part of IMAP4rev2, which this
 * server advertises in its greeting. An account holder whose client
 * offers a "new folder" control reaches this verb and nothing else.
 *
 * The cases below drive real sessions against the bound listener. A
 * mailbox that CREATE reports as made has to be one LIST names, one
 * SELECT opens and one APPEND files into, because a name recorded
 * somewhere no other verb reads is not a mailbox.
 *
 * The name arrives from a stranger. It is stored, listed back to every
 * client the account holds, quoted into refusals, written into audit
 * rows and printed in an operator's terminal, so it passes the screen
 * every other mailbox name on this server passes rather than a second
 * one written for this verb.
 *
 * Run standalone: node test/layer-2-integration/imap-mailbox-create.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var mailbox   = require("../../lib/mail/mailbox");

var b = helpers.b;

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE_PASSWORD   = "a long enough account password for one test run";
var BOB_PASSWORD     = "a second long enough account password for one run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

// A code point written from its number rather than pasted, so the
// fixture says which character it means and a file rewritten by an
// editor that normalizes text still carries it.
function cp(value) {
  return String.fromCodePoint(value);
}

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

// The same, with the argument sent as a synchronizing literal rather
// than on the command line.
async function askLiteral(session, command, payload, what) {
  var tag = session.tag();
  await session.sendLiteral(tag + " " + command, payload, what || command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { tag: tag, text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

// The mailbox names one LIST reply carries, read off the untagged lines
// rather than from the store, because the question is what the client
// was told.
function listedNames(text) {
  var names = [];
  var line = /^\* LIST \(([^)]*)\) "([^"]*)" (?:"((?:[^"\\]|\\.)*)"|(\S+))\r?$/gm;
  var found = line.exec(text);
  while (found !== null) {
    names.push({
      attributes: found[1],
      separator:  found[2],
      name:       found[3] === undefined ? found[4] : found[3].replace(/\\(.)/g, "$1"),
    });
    found = line.exec(text);
  }
  return names;
}

function listedNamed(text, name) {
  return listedNames(text).filter(function (entry) { return entry.name === name; })[0] || null;
}

// ---- cases -----------------------------------------------------------------

// The ordinary case, and the whole of what makes it a mailbox rather
// than a row: LIST names it, SELECT opens it, APPEND files into it and
// STATUS counts what was filed.
async function aCreatedMailboxIsOneEveryOtherVerbSees(ctx) {
  var session = await ctx.session("create-basic");

  var created = await ask(session, "CREATE Receipts");
  count("CREATE answers a new mailbox name with a tagged OK",
    created.verdict === "OK", visible(created.text));

  var listed = await ask(session, "LIST \"\" *");
  var entry = listedNamed(listed.text, "Receipts");
  count("LIST names the created mailbox", entry !== null, visible(listed.text));
  count("and gives it the hierarchy separator this server uses",
    entry !== null && entry.separator === "/", entry === null ? "" : entry.separator);

  var selected = await ask(session, "SELECT Receipts");
  count("SELECT opens the created mailbox", selected.verdict === "OK", visible(selected.text));
  count("and it opens empty", /^\* 0 EXISTS/m.test(selected.text), visible(selected.text));
  count("with a UIDVALIDITY of its own (RFC 9051 section 2.3.1.1)",
    /^\* OK \[UIDVALIDITY [1-9]\d*\]/m.test(selected.text), visible(selected.text));

  var filed = session.tag();
  await session.sendLiteral(filed + " APPEND Receipts", message("created-one"), "<created-one>");
  var appended = await session.read(new RegExp("^" + filed + " (OK|NO|BAD)", "m"),
    "APPEND into the created mailbox");
  count("APPEND files a message into the created mailbox",
    new RegExp("^" + filed + " OK", "m").test(appended), visible(appended));

  var status = await ask(session, "STATUS Receipts (MESSAGES UIDNEXT)");
  count("STATUS counts the message the created mailbox now holds",
    /MESSAGES 1/.test(status.text), visible(status.text));

  session.close();
}

// RFC 9051 section 6.3.4: an OK is returned only when a new mailbox has
// been created, and a name referring to an extant mailbox is an error.
// Section 7.1 gives that error the ALREADYEXISTS response code, which is
// what tells a client the name is taken rather than the command broken.
async function anExistingNameIsRefusedRatherThanRecreated(ctx) {
  var session = await ctx.session("create-existing");

  await ask(session, "CREATE Statements2026");
  var again = await ask(session, "CREATE Statements2026");
  count("a second CREATE of the same name is refused", again.verdict === "NO",
    visible(again.text));
  count("and it carries the ALREADYEXISTS response code of RFC 9051 section 7.1",
    /\[ALREADYEXISTS\]/.test(again.text), visible(again.text));

  var provisioned = await ask(session, "CREATE Archive");
  count("a name the account was provisioned with is refused the same way",
    provisioned.verdict === "NO" && /\[ALREADYEXISTS\]/.test(provisioned.text),
    visible(provisioned.text));

  // RFC 9051 section 5.1 matches INBOX without regard to case and no
  // other name, so every spelling of it names the one mailbox that
  // already exists.
  var inbox = await ask(session, "CREATE INBOX");
  count("CREATE INBOX is refused, which RFC 9051 section 6.3.4 calls an error",
    inbox.verdict === "NO", visible(inbox.text));
  var lower = await ask(session, "CREATE inbox");
  count("and so is any other case of it, because section 5.1 matches INBOX case insensitively",
    lower.verdict === "NO", visible(lower.text));

  // The converse of the same rule: a name that is not INBOX is compared
  // as written, so one differing only in case is a different mailbox.
  var cased = await ask(session, "CREATE statements2026");
  count("a non-INBOX name differing only in case is a different mailbox and is created",
    cased.verdict === "OK", visible(cased.text));
  var both = await ask(session, "LIST \"\" *");
  count("and both spellings are listed",
    listedNamed(both.text, "Statements2026") !== null &&
      listedNamed(both.text, "statements2026") !== null, visible(both.text));

  session.close();
}

// RFC 9051 section 6.3.4: a name suffixed with the hierarchy separator
// declares that the client means to create names under it, a server that
// does not need the declaration ignores it, and the name created carries
// no trailing separator. A server that stored the trailing form would
// hold a name whose every level but the last renders as the name the
// client asked for.
async function aTrailingSeparatorIsADeclarationRatherThanPartOfTheName(ctx) {
  var session = await ctx.session("create-trailing");

  var created = await ask(session, "CREATE Projects/");
  count("a name ending in the hierarchy separator is accepted", created.verdict === "OK",
    visible(created.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and the name created carries no trailing separator",
    listedNamed(listed.text, "Projects") !== null &&
      listedNamed(listed.text, "Projects/") === null, visible(listed.text));

  var selected = await ask(session, "SELECT Projects");
  count("the mailbox opens under the name without the separator",
    selected.verdict === "OK", visible(selected.text));

  var again = await ask(session, "CREATE Projects/");
  count("and the declaration form of a name that now exists is refused as existing",
    again.verdict === "NO" && /\[ALREADYEXISTS\]/.test(again.text), visible(again.text));

  session.close();
}

// RFC 9051 section 6.3.4: where the separator appears inside the name,
// the server SHOULD create the superior names the new one needs. A
// client that made "a/b/c" and found no "a" would be holding a mailbox
// whose parent LIST cannot name.
async function superiorLevelsAreCreatedWithTheNameThatNeedsThem(ctx) {
  var session = await ctx.session("create-superior");

  var created = await ask(session, "CREATE Clients/Acme/2026");
  count("a nested name is created", created.verdict === "OK", visible(created.text));

  var listed = await ask(session, "LIST \"\" *");
  count("its superior levels are created with it",
    listedNamed(listed.text, "Clients") !== null &&
      listedNamed(listed.text, "Clients/Acme") !== null &&
      listedNamed(listed.text, "Clients/Acme/2026") !== null, visible(listed.text));
  var parent = listedNamed(listed.text, "Clients");
  count("and a level holding another is listed with the HasChildren attribute",
    parent !== null && /HasChildren/.test(parent.attributes),
    parent === null ? "" : parent.attributes);
  var leaf = listedNamed(listed.text, "Clients/Acme/2026");
  count("while the deepest level is listed with HasNoChildren",
    leaf !== null && /HasNoChildren/.test(leaf.attributes),
    leaf === null ? "" : leaf.attributes);

  var opened = await ask(session, "SELECT Clients/Acme");
  count("a superior level created this way is a mailbox SELECT opens rather than a name " +
    "LIST shows and no other verb answers for", opened.verdict === "OK", visible(opened.text));

  // The levels that already exist are not recreated, so a second nested
  // name under the same parent completes rather than failing on it.
  var sibling = await ask(session, "CREATE Clients/Acme/2025");
  count("a second name under an existing parent is created",
    sibling.verdict === "OK", visible(sibling.text));
  var after = await ask(session, "LIST \"\" *");
  count("and the parent is still listed once",
    listedNames(after.text).filter(function (e) { return e.name === "Clients/Acme"; }).length === 1,
    visible(after.text));

  session.close();
}

// The name reaches this server as a quoted string, as a bare atom or as
// a literal. RFC 9051 section 4.3 makes the literal the form that
// carries a name a quoted string cannot, which on a UTF-8 name is the
// form a real client sends.
async function aNameArrivesInEveryFormTheGrammarAllows(ctx) {
  var session = await ctx.session("create-forms");

  var quoted = await ask(session, "CREATE \"Trip Notes\"");
  count("a quoted name carrying a space is created", quoted.verdict === "OK",
    visible(quoted.text));

  var nonLatin = cp(0x4ED5) + cp(0x4E8B);
  var literal = await askLiteral(session, "CREATE", nonLatin, "<a name sent as a literal>");
  count("a name sent as a literal is created", literal.verdict === "OK", visible(literal.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and both are listed under the names that were sent",
    listedNamed(listed.text, "Trip Notes") !== null &&
      listedNamed(listed.text, nonLatin) !== null, visible(listed.text));

  var selected = await askLiteral(session, "SELECT", nonLatin, "<SELECT by literal>");
  count("the name sent as a literal opens under the same name",
    selected.verdict === "OK", visible(selected.text));

  session.close();
}

// A name this server will not keep is refused at the point of parse, and
// nothing is created. The screen is the one every other mailbox name
// passes: a second screen written for this verb is the pair that comes
// apart, leaving a name CREATE stores and SELECT cannot open.
async function anUnkeepableNameIsRefusedAndCreatesNothing(ctx) {
  var session = await ctx.session("create-refusals");

  // A control character cannot reach this verb on the command line: the
  // line reader ends a line on CR LF, so the only form that can carry
  // one into a mailbox name is a literal, and that is the form these are
  // sent in.
  var refusals = [
    { name: null, literal: "Two" + cp(0x000A) + "Lines",
      what: "a name carrying a line feed" },
    // U+009B, the control sequence introducer. It is outside the C0
    // block, so a table that stops there admits an escape sequence this
    // server prints into an operator's terminal itself.
    { name: null, literal: "Repaint" + cp(0x009B) + "2J",
      what: "a name carrying a C1 control character" },
    // U+202E, the right-to-left override: a stored name renders as a
    // different one in every client that lists it.
    { name: null, literal: "Bidi" + cp(0x202E) + "gnp.exe",
      what: "a name carrying a bidirectional override" },
    // U+200B, a zero-width space: two names render identically.
    { name: null, literal: "Two" + cp(0x200B) + "Words",
      what: "a name carrying an invisible formatting character" },
    { name: "\"Half*Done\"", what: "a name carrying the LIST wildcard *", literal: null },
    { name: "\"Half%Done\"", what: "a name carrying the LIST wildcard %", literal: null },
    { name: "\"/Leading\"", what: "a name opening with the hierarchy separator", literal: null },
    { name: "\"Two//Levels\"", what: "a name repeating the hierarchy separator", literal: null },
    { name: "\"obj_beef\"", what: "a level spelled like a message address", literal: null },
    { name: "\" Padded\"", what: "a level padded with a space", literal: null },
    { name: "\"\"", what: "an empty name", literal: null },
  ];

  var kept = [];
  for (var i = 0; i < refusals.length; i += 1) {
    var one = refusals[i];
    var answer = one.literal === null
      ? await ask(session, "CREATE " + one.name, one.what)
      : await askLiteral(session, "CREATE", one.literal, one.what);
    count(one.what + " is refused", answer.verdict !== "OK", visible(answer.text));
    if (answer.verdict === "OK") kept.push(one.what);
  }
  count("no refused name reached the mailbox namespace", kept.length === 0, kept.join(", "));

  var listed = await ask(session, "LIST \"\" *");
  count("and LIST names none of them",
    listedNames(listed.text).filter(function (entry) {
      return /[*%]|^\/|\/\/|^obj_|^ | $/.test(entry.name) ||
        entry.name.indexOf(cp(0x202E)) !== -1 || entry.name.indexOf(cp(0x200B)) !== -1;
    }).length === 0, visible(listed.text));

  // A name longer than this server keeps. The ceiling is on the stored
  // bytes, so the refusal has to arrive on the name rather than on the
  // line, which is why it is sent as a literal.
  var overlong = await askLiteral(session, "CREATE", "L".repeat(256), "<an overlong name>");
  count("a name above the byte ceiling is refused", overlong.verdict !== "OK",
    visible(overlong.text));

  session.close();
}

// RFC 6154 section 3 puts a USE parameter on CREATE, under a capability
// this server does not advertise. A server that folded the parameter
// into the name would make a mailbox called `Archives (USE (\Archive))`,
// which is the failure shape for every unread argument: the command
// completes and the wrong thing exists.
async function anArgumentThisServerCannotReadIsRefusedRatherThanStored(ctx) {
  var session = await ctx.session("create-arguments");

  var use = await ask(session, "CREATE Archives (USE (\\Archive))");
  count("a CREATE carrying the RFC 6154 USE parameter is refused",
    use.verdict !== "OK", visible(use.text));

  var extra = await ask(session, "CREATE Ledger Extra");
  count("a CREATE carrying a second argument is refused", extra.verdict !== "OK",
    visible(extra.text));

  var none = await ask(session, "CREATE");
  count("a CREATE carrying no name at all is refused", none.verdict !== "OK",
    visible(none.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and none of the three left a mailbox behind",
    listedNames(listed.text).filter(function (entry) {
      return /^Archives|^Ledger/.test(entry.name);
    }).length === 0, visible(listed.text));

  session.close();
}

// The mailbox belongs to the account that made it. This server gives
// every account its own namespace above one message store, so a name one
// account takes says nothing about what another account holds.
async function aCreatedMailboxBelongsToTheAccountThatMadeIt(ctx) {
  var alice = await ctx.session("create-owner");
  var bob   = await ctx.bobSession("create-other");

  var made = await ask(alice, "CREATE Private/Alice");
  count("the first account creates a mailbox", made.verdict === "OK", visible(made.text));

  var listed = await ask(bob, "LIST \"\" *");
  count("the second account is not shown it",
    listedNamed(listed.text, "Private/Alice") === null &&
      listedNamed(listed.text, "Private") === null, visible(listed.text));

  var opened = await ask(bob, "SELECT Private/Alice");
  count("and cannot open it", opened.verdict === "NO", visible(opened.text));

  var same = await ask(bob, "CREATE Private/Alice");
  count("the same name is free for the second account to take",
    same.verdict === "OK", visible(same.text));

  alice.close();
  bob.close();
}

// A ceiling, because an authenticated client can send this verb in a
// loop. Every folder a mailbox holds is compared against every other one
// on each LIST to work out which of them hold children, so an account
// with unbounded folders is a listing whose cost grows with the square
// of what the client created.
async function anAccountCannotCreateFoldersWithoutBound(ctx) {
  var ceiling = mailbox.MAX_FOLDERS_PER_ACCOUNT;
  count("the folder ceiling is a whole positive number the wire can be driven to",
    typeof ceiling === "number" && isFinite(ceiling) && ceiling > 6, String(ceiling));

  var actor = { id: ctx.carol.id };
  // Filled through the adapter rather than over the wire: the refusal is
  // what this case is about and it is driven over the wire below, while
  // the fill is the same call the listener makes and would cost one
  // round trip per mailbox if it were sent as one.
  var held = ctx.identity.mailbox.accountFolders(actor).length;
  var made = 0;
  while (held + made < ceiling) {
    ctx.identity.mailbox.createFolder(actor, "Filler" + made);
    made += 1;
  }
  var filled = ctx.identity.mailbox.accountFolders(actor).length;
  count("the account is filled to the ceiling", filled === ceiling, String(filled));

  var session = await ctx.carolSession("create-ceiling");
  var refused = await ask(session, "CREATE OneTooMany");
  count("a CREATE above the ceiling is refused rather than answered OK",
    refused.verdict === "NO", visible(refused.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and the refused name was not created",
    listedNamed(listed.text, "OneTooMany") === null, visible(listed.text));
  count("while every folder under the ceiling is still there",
    ctx.identity.mailbox.accountFolders(actor).length === ceiling,
    String(ctx.identity.mailbox.accountFolders(actor).length));

  session.close();
}

// CREATE is an Authenticated state command (RFC 9051 section 6.3). A
// session that has sent no credential names no account, and this server
// has no mailbox that is not an account's.
async function createNeedsAnAuthenticatedSession(ctx) {
  var session = await Wire.imap(ctx.imapPort, {
    caPem: ctx.caPem, servername: HOSTNAME,
    label: "imap-mailbox-create unauthenticated",
  });
  ctx.track(session);
  var refused = await ask(session, "CREATE Anything");
  count("CREATE before authentication is refused", refused.verdict !== "OK",
    visible(refused.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and the unauthenticated session is shown no mailbox either",
    listed.verdict !== "OK" || listedNames(listed.text).length === 0, visible(listed.text));

  session.close();
}

// The verbs that undo a CREATE. A mailbox a client can make and can
// never remove or rename is half a feature, so the pair is driven from
// the same session that made the mailbox: what CREATE put in the
// namespace, DELETE takes out of it and RENAME moves inside it.
//
// `imap-mailbox-lifecycle` is where the two are covered in full, down to
// the mail underneath a removal and what happens to the hierarchy. This
// is the round trip alone.
async function theVerbsThatUndoACreateCompleteIt(ctx) {
  var session = await ctx.session("create-undo");
  await ask(session, "CREATE Temporary");

  var renamed = await ask(session, "RENAME Temporary Permanent");
  count("RENAME moves a created mailbox to another name", renamed.verdict === "OK",
    visible(renamed.text));

  var moved = await ask(session, "LIST \"\" *");
  count("and the mailbox is listed under the new name only",
    listedNamed(moved.text, "Permanent") !== null &&
      listedNamed(moved.text, "Temporary") === null, visible(moved.text));

  var removed = await ask(session, "DELETE Permanent");
  count("DELETE removes it", removed.verdict === "OK", visible(removed.text));

  var listed = await ask(session, "LIST \"\" *");
  count("and neither name is listed afterwards",
    listedNamed(listed.text, "Temporary") === null &&
      listedNamed(listed.text, "Permanent") === null, visible(listed.text));

  session.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-mailbox-create");
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
    var carol = await identity.accounts.create({
      address: "carol@" + DOMAIN, password: BOB_PASSWORD });

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

    function opener(address, password) {
      return async function (label) {
        var opened = await Wire.imap(sections.imap.port, {
          caPem: leaf.ca, servername: HOSTNAME,
          address: address, password: password,
          label: "imap-mailbox-create " + label,
        });
        sessions.push(opened);
        return opened;
      };
    }

    var ctx = {
      identity:     identity,
      alice:        alice,
      bob:          bob,
      carol:        carol,
      imapPort:     sections.imap.port,
      caPem:        leaf.ca,
      track:        function (session) { sessions.push(session); },
      session:      opener(alice.address, ALICE_PASSWORD),
      bobSession:   opener(bob.address, BOB_PASSWORD),
      carolSession: opener(carol.address, BOB_PASSWORD),
    };

    await aCreatedMailboxIsOneEveryOtherVerbSees(ctx);
    await anExistingNameIsRefusedRatherThanRecreated(ctx);
    await aTrailingSeparatorIsADeclarationRatherThanPartOfTheName(ctx);
    await superiorLevelsAreCreatedWithTheNameThatNeedsThem(ctx);
    await aNameArrivesInEveryFormTheGrammarAllows(ctx);
    await anUnkeepableNameIsRefusedAndCreatesNothing(ctx);
    await anArgumentThisServerCannotReadIsRefusedRatherThanStored(ctx);
    await aCreatedMailboxBelongsToTheAccountThatMadeIt(ctx);
    await theVerbsThatUndoACreateCompleteIt(ctx);
    await createNeedsAnAuthenticatedSession(ctx);
    await anAccountCannotCreateFoldersWithoutBound(ctx);

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

module.exports = { name: "imap-mailbox-create", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
