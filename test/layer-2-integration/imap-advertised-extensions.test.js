// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The IMAP capability line names only what this server answers.
 *
 * A client reads the capability line once and decides from it what to
 * send. An extension named there and refused on use is a client that
 * built its synchronization on something that does not work: a QRESYNC
 * client waits for the VANISHED responses that tell it which messages
 * were expunged, and a server that never sends them leaves every
 * expunged message in that client's cache. RFC 5161 section 3.1 applies
 * the same rule to ENABLE, whose ENABLED response lists only what the
 * server actually turned on.
 *
 * The line is read in all three places RFC 9051 writes it: the
 * greeting, the answer to CAPABILITY, and the code completing
 * AUTHENTICATE. Then every extension still named is exercised, so the
 * list cannot shrink to something that is honest and also broken.
 *
 * Run standalone: node test/layer-2-integration/imap-advertised-extensions.test.js
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

// Extensions the framework can name and this server does not serve.
var UNSERVED = ["QRESYNC", "NOTIFY", "CATENATE"];

// Extensions this server does serve, each exercised below.
var SERVED = ["IMAP4rev2", "CONDSTORE", "METADATA", "METADATA-SERVER", "AUTH=PLAIN"];

function capabilitiesIn(text) {
  var found = /\[CAPABILITY ([^\]]*)\]|^\* CAPABILITY ([^\r\n]*)/m.exec(text);
  if (found === null) return null;
  return (found[1] || found[2]).trim().split(/\s+/);
}

function assertHonest(where, text) {
  var caps = capabilitiesIn(text);
  count("the capability line is present in " + where, caps !== null, visible(text));
  UNSERVED.forEach(function (name) {
    count(where + " does not name " + name + ", which this server does not serve",
      caps.indexOf(name) === -1, caps.join(" "));
  });
  SERVED.forEach(function (name) {
    count(where + " names " + name, caps.indexOf(name) !== -1, caps.join(" "));
  });
}

async function ask(session, command, what) {
  var tag = session.tag();
  session.send(tag + " " + command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

// ---- cases -----------------------------------------------------------------

async function theLineIsHonestWhereverItIsWritten(port, caPem, address) {
  var session = await Wire.connect(port, "imap-capabilities");
  var greeting = await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  assertHonest("the greeting", greeting);

  var early = await ask(session, "ENABLE CONDSTORE");
  count("ENABLE before authentication is refused, because RFC 5161 section 3.1 makes it " +
    "an Authenticated state command", early.verdict === "BAD", visible(early.text));

  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);

  var asked = await ask(session, "CAPABILITY");
  assertHonest("the CAPABILITY answer", asked.text);

  session.send("a1 AUTHENTICATE PLAIN " + wire.saslPlain(address, ALICE_PASSWORD));
  var authed = await session.read(/^a1 (OK|NO|BAD)[^\r\n]*\r\n/m, "authenticated");
  assertHonest("the AUTHENTICATE completion", authed);
  return session;
}

async function enableTurnsOnOnlyWhatIsServed(session) {
  var qresync = await ask(session, "ENABLE QRESYNC");
  count("ENABLE QRESYNC completes", qresync.verdict === "OK", visible(qresync.text));
  count("and its ENABLED response does not claim QRESYNC",
    /^\* ENABLED/m.test(qresync.text) && !/^\* ENABLED[^\r\n]*QRESYNC/m.test(qresync.text),
    visible(qresync.text));

  var condstore = await ask(session, "ENABLE CONDSTORE");
  count("ENABLE CONDSTORE turns CONDSTORE on",
    /^\* ENABLED CONDSTORE\r?$/m.test(condstore.text), visible(condstore.text));
  var again = await ask(session, "ENABLE CONDSTORE");
  count("and a second ENABLE of it lists nothing, because nothing new was turned on",
    /^\* ENABLED\r?$/m.test(again.text), visible(again.text));

  // With QRESYNC refused, an expunge is reported the way RFC 9051 section
  // 7.5.1 reports it, not with the VANISHED response only a QRESYNC client
  // reads.
  var tag = session.tag();
  await session.sendLiteral(tag + " APPEND Junk", "Subject: gone\r\n\r\nbody\r\n", "<message>");
  await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered");
  await ask(session, "SELECT Junk");
  await ask(session, "STORE 1 +FLAGS (\\Deleted)");
  var expunged = await ask(session, "EXPUNGE");
  count("an expunge is reported with EXPUNGE rather than VANISHED",
    /^\* 1 EXPUNGE/m.test(expunged.text) && !/VANISHED/.test(expunged.text),
    visible(expunged.text));
  await ask(session, "UNSELECT");
}

// CONDSTORE, exercised: a conditional STORE that loses the race is
// reported under MODIFIED, in sequence numbers for STORE and in UIDs for
// UID STORE (RFC 7162 section 3.1.3), and a FETCH asking for changes
// since a mod-sequence gets only what changed (section 3.1.4.1).
async function condstoreIsServed(session, second) {
  var tag = session.tag();
  await session.sendLiteral(tag + " APPEND Archive", "Subject: one\r\n\r\nbody\r\n", "<one>");
  await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered");
  tag = session.tag();
  await session.sendLiteral(tag + " APPEND Archive", "Subject: two\r\n\r\nbody\r\n", "<two>");
  await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered");

  var selected = await ask(session, "SELECT Archive (CONDSTORE)");
  var highest = parseInt(/HIGHESTMODSEQ (\d+)/.exec(selected.text)[1], 10);
  var modseqs = await ask(session, "FETCH 1:2 (UID MODSEQ)");
  var uid2 = parseInt(/^\* 2 FETCH \([^\r\n]*UID (\d+)/m.exec(modseqs.text)[1], 10);

  await ask(second, "SELECT Archive");
  await ask(second, "STORE 2 +FLAGS (\\Flagged)");

  var conflict = await ask(session, "STORE 1:2 (UNCHANGEDSINCE " + highest + ") +FLAGS (\\Seen)");
  count("a conditional STORE over a message changed since the mod-sequence names it under MODIFIED",
    /^\S+ OK \[MODIFIED 2\]/m.test(conflict.text), visible(conflict.text));
  // The flag list is matched loosely. `\Seen` is what this STORE asked
  // for, and beside it the message carries the mark recorded when it was
  // filed saying whether it carries files, which no client set and no
  // STORE removes.
  count("and applies to the message that did not change",
    /^\* 1 FETCH \(FLAGS \([^)]*\\Seen[^)]*\) MODSEQ \(\d+\)\)/m.test(conflict.text),
    visible(conflict.text));

  await ask(second, "STORE 2 +FLAGS (\\Answered)");
  var uidConflict = await ask(session, "UID STORE " + uid2 + " (UNCHANGEDSINCE " + highest +
    ") +FLAGS (\\Seen)");
  count("UID STORE names the conflicting message by UID",
    new RegExp("^\\S+ OK \\[MODIFIED " + uid2 + "\\]", "m").test(uidConflict.text),
    visible(uidConflict.text));

  var changed = await ask(session, "FETCH 1:2 (FLAGS) (CHANGEDSINCE " + highest + ")");
  count("FETCH CHANGEDSINCE returns the messages changed since that mod-sequence",
    /^\* 1 FETCH/m.test(changed.text) && /^\* 2 FETCH/m.test(changed.text), visible(changed.text));
  var latest = parseInt(/HIGHESTMODSEQ (\d+)/.exec((await ask(second, "SELECT Archive")).text)[1], 10);
  var nothing = await ask(session, "FETCH 1:2 (FLAGS) (CHANGEDSINCE " + latest + ")");
  count("and nothing when nothing has changed since",
    nothing.verdict === "OK" && !/^\* \d+ FETCH/m.test(nothing.text), visible(nothing.text));
}

// RFC 7162 section 3.1 gives every STORE command a mod-sequence of its
// own, greater than the one before it in the session. The message store
// resets its counter to the clock when it expunges, so every step the
// counter takes ahead of the clock is a step a later STORE can land
// behind. One STORE command is therefore one step, however many
// messages it changes.
async function oneStoreCommandIsOneModSequence(session) {
  for (var i = 1; i <= 6; i += 1) {
    var tag = session.tag();
    await session.sendLiteral(tag + " APPEND Sent", "Subject: batch " + i + "\r\n\r\nbody\r\n",
      "<batch " + i + ">");
    await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered");
  }
  await ask(session, "SELECT Sent (CONDSTORE)");
  var before = parseInt(/HIGHESTMODSEQ (\d+)/.exec(
    (await ask(session, "STATUS Sent (HIGHESTMODSEQ)")).text)[1], 10);

  var stored = await ask(session, "STORE 1:6 +FLAGS (\\Flagged)");
  var modseqs = (stored.text.match(/MODSEQ \((\d+)\)/g) || []).map(function (m) {
    return /(\d+)/.exec(m)[1];
  });
  count("STORE over six messages reports a mod-sequence for each of them",
    modseqs.length === 6, visible(stored.text));
  count("and it is one mod-sequence for the whole command",
    modseqs.filter(function (m) { return m === modseqs[0]; }).length === 6, modseqs.join(","));
  var after = parseInt(/HIGHESTMODSEQ (\d+)/.exec(
    (await ask(session, "STATUS Sent (HIGHESTMODSEQ)")).text)[1], 10);
  count("so the mailbox's highest mod-sequence moves once for the command, not once per message",
    after === before + 1, before + " -> " + after);

  // Replacing flags writes a different change for messages holding
  // different flags, and each distinct change is still one step.
  await ask(session, "STORE 1:3 +FLAGS (\\Seen)");
  var replaced = await ask(session, "STORE 1:6 FLAGS (\\Answered)");
  var distinct = {};
  (replaced.text.match(/MODSEQ \((\d+)\)/g) || []).forEach(function (m) { distinct[m] = true; });
  count("a FLAGS replacement over messages holding two different flag sets takes two steps",
    Object.keys(distinct).length === 2, visible(replaced.text));
  // The derived attachment mark is not a flag a client sets, so a
  // replacement keeps it beside the flags it named.
  var replacedFlags = replaced.text.match(/FLAGS \(\\Answered \$HasNoAttachment\) MODSEQ/g) || [];
  count("and leaves all six holding exactly the flags it named, plus the attachment mark",
    replacedFlags.length === 6, visible(replaced.text));

  // The STORE after an EXPUNGE lands above the one before it.
  var first = /MODSEQ \((\d+)\)/.exec((await ask(session, "STORE 1 +FLAGS (\\Deleted)")).text);
  await ask(session, "EXPUNGE");
  var second = /MODSEQ \((\d+)\)/.exec((await ask(session, "STORE 1 +FLAGS (\\Flagged)")).text);
  count("a STORE after an EXPUNGE carries a greater mod-sequence than the STORE before it",
    first !== null && second !== null && Number(second[1]) > Number(first[1]),
    (first && first[1]) + " then " + (second && second[1]));
  await ask(session, "UNSELECT");
}

async function metadataIsServed(session) {
  var set = await ask(session, "SETMETADATA INBOX (/private/comment \"kept\")");
  count("SETMETADATA is answered", set.verdict === "OK", visible(set.text));
  var got = await ask(session, "GETMETADATA INBOX /private/comment");
  count("GETMETADATA reads it back",
    got.verdict === "OK" && /"kept"/.test(got.text), visible(got.text));
  var server = await ask(session, "GETMETADATA \"\" /private/comment");
  count("the server-wide annotations METADATA-SERVER names are answered",
    server.verdict === "OK", visible(server.text));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-advertised-extensions");
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

    var session = await theLineIsHonestWhereverItIsWritten(sections.imap.port, leaf.ca,
      alice.address);
    sessions.push(session);
    await enableTurnsOnOnlyWhatIsServed(session);

    var second = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: alice.address, password: ALICE_PASSWORD,
      label: "imap-advertised-extensions second session",
    });
    sessions.push(second);
    await condstoreIsServed(session, second);
    await oneStoreCommandIsOneModSequence(session);
    await metadataIsServed(session);

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

module.exports = { name: "imap-advertised-extensions", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
