// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What one account reaches of another's mail over IMAP, and what a peer
 * reaches before it has signed in.
 *
 * The message store keeps one flat namespace of folders and records no
 * owner, so every mailbox name an IMAP client sends is resolved against
 * the signed-in account by the adapter, and nothing below it can tell
 * one account's INBOX from another's. `cross-account-isolation` drives
 * the browser surface and JMAP against that boundary; this file drives
 * IMAP, with every spelling of a name that could plausibly resolve
 * somewhere else: the other account's store folder, a path climbing out
 * of the account, the shared namespace prefixes other servers use, case
 * forms of INBOX, the legacy modified UTF-7 encoding, and a control
 * byte carried in a literal where the command line cannot carry one.
 *
 * The second half is the boundary in front of authentication. RFC 9051
 * section 11.1 has the listener discard whatever a client pipelined
 * behind STARTTLS, because those bytes arrived in plaintext and would
 * otherwise be read as commands on the encrypted session (the
 * CVE-2021-38371 class). A credential offered before TLS is refused
 * rather than accepted and logged.
 *
 * Run standalone: node test/layer-2-integration/imap-account-boundary.test.js
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
var PASSWORD         = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

var DEFAULT_MAILBOXES = ["Archive", "Drafts", "INBOX", "Junk", "Sent", "Trash"];

// Distinctive enough that finding it in a response is proof the response
// carried bob's mail.
var BOBS_SUBJECT = "bobs private quarterly numbers";
var BOBS_BODY    = "zebra7741 belongs to bob and to nobody else";
var BOBS_NOTE    = "bobs annotation";

function message(subject, to, body) {
  return Buffer.from("From: sender@example.net\r\nTo: " + to + "\r\nSubject: " + subject +
    "\r\n\r\n" + body + "\r\n", "utf8");
}

async function ask(session, command, what) {
  var tag = session.tag();
  session.send(tag + " " + command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

function carriesBob(text) {
  return text.indexOf(BOBS_SUBJECT) !== -1 || text.indexOf(BOBS_BODY) !== -1 ||
    text.indexOf(BOBS_NOTE) !== -1;
}

// ---- cases -----------------------------------------------------------------

async function listNamesOnlyTheAccountsOwnMailboxes(session, bobsFolder) {
  var listed = await ask(session, "LIST \"\" \"*\"");
  var names = [];
  var pattern = /^\* LIST \([^)]*\) "\/" "([^"]*)"/gm;
  var hit = pattern.exec(listed.text);
  while (hit !== null) { names.push(hit[1]); hit = pattern.exec(listed.text); }
  count("LIST names the six mailboxes the account owns and nothing else",
    names.slice().sort().join(",") === DEFAULT_MAILBOXES.join(","), names.join(","));
  count("and no store folder name reaches the client",
    listed.text.indexOf("mbx_") === -1 && listed.text.indexOf(bobsFolder) === -1,
    visible(listed.text));
}

async function noSpellingOfAMailboxNameReachesAnotherAccount(session, bobsFolder) {
  var names = [
    bobsFolder,
    "\"" + bobsFolder + "\"",
    "\"../bob@" + DOMAIN + "/INBOX\"",
    "\"bob@" + DOMAIN + "/INBOX\"",
    "\"#shared/bob/INBOX\"",
    "\"#public/INBOX\"",
    "\"Other Users/bob/INBOX\"",
    "\"user/bob/INBOX\"",
    "&AGIAbwBi-",
    "\"INBOX/../../" + bobsFolder + "\"",
  ];
  for (var i = 0; i < names.length; i += 1) {
    var selected = await ask(session, "SELECT " + names[i]);
    count("SELECT " + names[i] + " is refused", selected.verdict !== "OK", visible(selected.text));
    var examined = await ask(session, "EXAMINE " + names[i]);
    count("EXAMINE " + names[i] + " is refused", examined.verdict !== "OK", visible(examined.text));
    var status = await ask(session, "STATUS " + names[i] + " (MESSAGES UNSEEN)");
    count("STATUS " + names[i] + " is refused and reports nothing about the mailbox",
      status.verdict !== "OK" && !/^\* STATUS/m.test(status.text), visible(status.text));
    var tag = session.tag();
    session.send(tag + " APPEND " + names[i] + " {20}");
    var opener = await session.read(new RegExp("^(\\+|" + tag + " (OK|NO|BAD)|\\* BAD)", "m"),
      "APPEND opener for " + names[i]);
    if (/^\+/m.test(opener)) {
      session.sendRaw("Subject: planted\r\n\r\n\r\n", "<planted message>");
      opener = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
        "APPEND to " + names[i]);
    }
    count("APPEND into " + names[i] + " is refused",
      !new RegExp("^" + tag + " OK", "m").test(opener), visible(opener));
    var meta = await ask(session, "GETMETADATA " + names[i] + " /private/comment");
    count("GETMETADATA on " + names[i] + " carries none of the other account's annotations",
      !carriesBob(meta.text), visible(meta.text));
  }

  // Every case form of INBOX is the account's own INBOX (RFC 9051 section
  // 5.1), which holds alice's message and not bob's.
  var forms = ["inbox", "Inbox", "iNbOx", "\"INBOX\""];
  for (var f = 0; f < forms.length; f += 1) {
    var own = await ask(session, "SELECT " + forms[f]);
    count("SELECT " + forms[f] + " opens the account's own INBOX", own.verdict === "OK",
      visible(own.text));
    var body = await ask(session, "FETCH 1:* BODY.PEEK[]");
    count("and what it holds is the account's own mail, not the other account's",
      !carriesBob(body.text) && body.text.indexOf("alices own message") !== -1,
      visible(body.text));
  }

  // A literal carries bytes the command line refuses, so a control byte
  // inside a name is sent that way.
  var tag2 = session.tag();
  await session.sendLiteral(tag2 + " SELECT", "IN" + String.fromCharCode(0) + "BOX",
    "<a name with a NUL in it>");
  var nul = await session.read(new RegExp("^" + tag2 + " (OK|NO|BAD)", "m"), "SELECT with a NUL");
  count("a mailbox name carrying a NUL is refused",
    !new RegExp("^" + tag2 + " OK", "m").test(nul), visible(nul));
}

// A UID names a message within the selected mailbox, so no set of them
// reaches a message in another account's folder, however the numbers
// line up.
async function noUidSetReachesAnotherAccountsMessage(session) {
  await ask(session, "SELECT INBOX");
  var all = await ask(session, "UID FETCH 1:4294967295 (UID BODY.PEEK[])");
  count("a UID set spanning every possible UID returns only the account's own messages",
    all.verdict === "OK" && !carriesBob(all.text), visible(all.text));
  var stored = await ask(session, "UID STORE 1:4294967295 +FLAGS (\\Flagged)");
  count("a UID STORE over the same span changes only the account's own messages",
    stored.verdict === "OK" && (stored.text.match(/^\* \d+ FETCH/gm) || []).length === 1,
    visible(stored.text));
  var searched = await ask(session, "UID SEARCH SUBJECT \"" + BOBS_SUBJECT + "\"");
  count("and SEARCH does not find the other account's message by its subject",
    /^\* SEARCH\r?$/m.test(searched.text), visible(searched.text));
}

async function nothingPipelinedBehindStartTlsSurvivesTheUpgrade(port, caPem) {
  var peer = await Wire.connect(port, "imap-starttls-injection");
  await peer.read(/^\* OK \[CAPABILITY/m, "greeting");
  peer.sendRaw("s1 STARTTLS\r\ns2 CAPABILITY\r\n", "<STARTTLS with CAPABILITY pipelined>");
  var started = await peer.read(/^s1 (OK|NO|BAD)/m, "STARTTLS answered");
  count("STARTTLS is accepted", /^s1 OK/m.test(started), visible(started));
  await peer.upgrade(caPem, HOSTNAME);
  var after = await peer.readQuietly("anything answered after the upgrade");
  count("the command pipelined in plaintext is not answered on the encrypted session",
    after.indexOf("s2 ") === -1 && after.indexOf("CAPABILITY") === -1, visible(after));

  var again = await ask(peer, "STARTTLS");
  count("a second STARTTLS is refused", again.verdict === "BAD", visible(again.text));
  peer.close();
}

async function aCredentialBeforeTlsIsRefused(port, address) {
  var peer = await Wire.connect(port, "imap-cleartext-credential");
  await peer.read(/^\* OK \[CAPABILITY/m, "greeting");
  var auth = await ask(peer, "AUTHENTICATE PLAIN " + wire.saslPlain(address, PASSWORD));
  count("AUTHENTICATE before STARTTLS is refused", auth.verdict === "BAD", visible(auth.text));
  var login = await ask(peer, "LOGIN " + address + " \"" + PASSWORD + "\"");
  count("LOGIN before STARTTLS is refused", login.verdict !== "OK", visible(login.text));
  var select = await ask(peer, "SELECT INBOX");
  count("and the session stays unauthenticated", select.verdict !== "OK", visible(select.text));
  peer.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-account-boundary");
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
    var alice = await identity.accounts.create({ address: "alice@" + DOMAIN, password: PASSWORD });
    var bob   = await identity.accounts.create({ address: "bob@" + DOMAIN, password: PASSWORD });

    identity.mailbox.appendMessage("INBOX",
      message("alices own message", alice.address, "alice body"), { actor: { id: alice.id } });
    identity.mailbox.appendMessage("INBOX",
      message(BOBS_SUBJECT, bob.address, BOBS_BODY), { actor: { id: bob.id } });
    identity.mailbox.setMetadata({ id: bob.id }, "INBOX",
      [{ entry: "/private/comment", value: BOBS_NOTE }]);
    var bobsFolder = identity.mailbox.accountFolders({ id: bob.id })
      .filter(function (f) { return f.name === "INBOX"; })[0].storeName;
    count("the other account's INBOX has a store folder name to aim at",
      /^mbx_/.test(bobsFolder), bobsFolder);

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

    var session = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME, address: alice.address, password: PASSWORD,
      label: "imap-account-boundary alice",
    });
    sessions.push(session);

    await listNamesOnlyTheAccountsOwnMailboxes(session, bobsFolder);
    await noSpellingOfAMailboxNameReachesAnotherAccount(session, bobsFolder);
    await noUidSetReachesAnotherAccountsMessage(session);
    await nothingPipelinedBehindStartTlsSurvivesTheUpgrade(sections.imap.port, leaf.ca);
    await aCredentialBeforeTlsIsRefused(sections.imap.port, alice.address);

    // Bob's mail is where it was, read as bob, so every refusal above is
    // a refusal and not a mailbox that had nothing in it.
    var bobs = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME, address: bob.address, password: PASSWORD,
      label: "imap-account-boundary bob",
    });
    sessions.push(bobs);
    await ask(bobs, "SELECT INBOX");
    var own = await ask(bobs, "FETCH 1:* BODY.PEEK[]");
    count("the other account still reads its own message, so the refusals above had " +
      "something to refuse", carriesBob(own.text) && own.text.indexOf("alices own message") === -1,
      visible(own.text));

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

module.exports = { name: "imap-account-boundary", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
