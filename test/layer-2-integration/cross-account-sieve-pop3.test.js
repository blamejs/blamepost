// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Two accounts on one server, and what each of them can reach of the
 * other's filter scripts over ManageSieve and of the other's mail over
 * POP3.
 *
 * `test/layer-2-integration/cross-account-isolation.test.js` makes this
 * claim for the browser surface and for JMAP. The two store protocols
 * had no version of it. `sieve-managesieve-wire.test.js` creates one
 * account, so its isolation-adjacent cases are about how a domain is
 * spelled rather than about two identities; the store-level equivalent
 * in `test/layer-1-state/sieve-script-lifecycle.test.js` calls the
 * adapter directly, which proves the store scopes and says nothing about
 * whether the listener does. POP3's only cross-account case was the blob
 * substitution one.
 *
 * The gap matters because of the shape isolation defects take here. The
 * scoping is one derivation, `_accountOf(actor)`, and every read is a
 * `where({ account: account })` beside it. A guard that compares against
 * a field the actor does not carry compares against undefined, matches
 * everything, and reports nothing: that is how the browser layer once
 * listed a stranger's folders and served the mail inside them. Nothing
 * about that failure is visible from one account's session.
 *
 * So this drives two, and asserts the refusal each protocol writes
 * exactly rather than that some refusal arrived. The code is what an
 * operator filters their logs on and what a client branches on, and a
 * server answering a wrong-but-negative code is a server nobody can
 * write a rule for.
 *
 * ManageSieve, RFC 5804. Alice cannot list, read, delete, activate or
 * rename Bob's scripts:
 *
 *   - LISTSCRIPTS names hers and no more.
 *   - GETSCRIPT of his draws `NO "(NONEXISTENT) Script not found"`,
 *     which section 1.3 defines and section 2.9 sends here.
 *   - DELETESCRIPT, SETACTIVE and RENAMESCRIPT each draw the store's
 *     own sentence, quoted below in full.
 *   - PUTSCRIPT under his script's name is ACCEPTED, and that is the
 *     right answer: a script name is per account, so the upload creates
 *     hers. The claim is read from Bob's session afterwards, where his
 *     body is the body he uploaded. A test that expected a refusal here
 *     would be asserting that one account's naming choices restrict
 *     another's.
 *
 * POP3, RFC 1939. The protocol gives a client no way to name another
 * account's maildrop, so the reach worth measuring is what her own
 * maildrop contains and what a number outside it does. Bob holds three
 * messages and Alice holds one, so a message number that is valid in his
 * maildrop is outside hers, and a maildrop built without the account
 * scope would answer it with his mail.
 *
 * Both accounts hold their maildrops at the same time on purpose.
 * Section 3 leases a maildrop to one session at a time PER MAILBOX, so
 * two accounts opening at once is the ordinary case, and holding both
 * open is what lets one session's writes be read from the other's.
 *
 * Run standalone: node test/layer-2-integration/cross-account-sieve-pop3.test.js
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
var uidlPairs   = wire.pop3Uidl;
var statCount   = wire.pop3Stat;
var lastReply   = wire.lastManageSieveReply;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var SHUTDOWN_TIMEOUT_MS = 5000;

var count = helpers.count;

// One reply line, the shape `sieve-managesieve-wire` waits on. Every
// ManageSieve command answers with exactly one of these.
var ONE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

// ---- what each account holds ------------------------------------------------

// Distinctive enough that finding one anywhere in the other account's
// session is proof that session carried mail or a script it should not
// have, rather than a coincidence of ordinary words.
var BOBS_SCRIPT_MARKER  = "zebra7741";
var ALICES_SCRIPT_MARKER = "octopus3312";
var BOBS_BODY_MARKER    = "bob body kestrel5518";
var ALICES_BODY_MARKER  = "alice body marmot9043";

// Bob keeps two scripts. The one this file aims a DELETESCRIPT at is the
// INACTIVE one, and that is deliberate: RFC 5804 section 2.10 refuses to
// delete the active script whoever asks, so a case aimed at the active
// one would draw a NO from the wrong rule and pass while the scoping was
// gone.
var BOBS_ACTIVE  = "bobs-active";
var BOBS_PRIVATE = "bobs-private";
var ALICES_SCRIPT = "alices-rules";

function scriptBody(marker) {
  return "require [\"fileinto\"];\n" +
    "if header :contains \"X-Category\" \"" + marker + "\" { fileinto \"Junk\"; }\n";
}

// The exact refusals. Each is the whole reply line the listener writes,
// so a change to the sentence fails here rather than being absorbed by a
// pattern that only asked whether the reply began with NO.
//
// `NO (NONEXISTENT)` comes from the listener itself, which answers a
// GETSCRIPT that found nothing with the RFC 5804 section 1.3 response
// code. The other three are the store's sentences, carried to the wire
// by the catch on each handler, so they say which verb was refused.
var NO_SUCH_SCRIPT   = 'NO "(NONEXISTENT) Script not found"';
var NO_DELETE_TARGET = 'NO "DELETESCRIPT: no script by that name."';
var NO_ACTIVE_TARGET = 'NO "SETACTIVE: no script by that name."';
var NO_RENAME_SOURCE = 'NO "RENAMESCRIPT: no script named \'' + BOBS_ACTIVE + '\'."';

// The POP3 refusals, whole lines for the same reason. `no such message`
// is the listener's own answer to a number its maildrop does not carry;
// the DELE sentence is the store's, because a mark is the one POP3 verb
// that reaches past the listing.
var NO_SUCH_MESSAGE  = "-ERR no such message";
var NO_MESSAGE_TO_MARK =
  "-ERR DELE: no message with that number in this maildrop.";

function messageFor(address, marker) {
  return Buffer.from([
    "From: sender@example.net",
    "To: " + address,
    "Subject: for " + address,
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker.replace(/[^a-z0-9]/gi, "-") + "@example.net>",
    "",
    marker,
    "",
  ].join("\r\n"), "utf8");
}

// The actor a signed in session holds. `b.permissions` reads a scopes
// array in preference to roles, so this carries roles and no scopes.
function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// ---- ManageSieve ------------------------------------------------------------

function replyTo(session, what) {
  return session.read(ONE_REPLY, what).then(lastReply);
}

// A command carrying a literal payload, in the non-synchronizing form,
// so the client does not have to tell a continuation apart from the
// final reply.
function sendLiteral(session, command, payload, note) {
  var bytes = Buffer.byteLength(payload, "utf8");
  session.send(command + " {" + bytes + "+}");
  session.sendRaw(payload + "\r\n", note);
}

// Alice's whole reach across the boundary, on the listener her filter
// rules arrive over.
async function alicesSessionReachesNoneOfBobsScripts(session) {
  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("LISTSCRIPTS names this account's own script",
    listing.indexOf('"' + ALICES_SCRIPT + '"') !== -1, visible(listing));
  count("and names neither of the other account's, so the listing is one account's rather " +
    "than the server's",
    listing.indexOf('"' + BOBS_ACTIVE + '"') === -1 &&
    listing.indexOf('"' + BOBS_PRIVATE + '"') === -1, visible(listing));
  count("and carries none of the other account's script text",
    listing.indexOf(BOBS_SCRIPT_MARKER) === -1, visible(listing));

  session.send('GETSCRIPT "' + BOBS_PRIVATE + '"');
  var fetched = await session.read(ONE_REPLY, "GETSCRIPT answered");
  count("GETSCRIPT of another account's script is refused with the response code RFC 5804 " +
    "section 1.3 defines for a name that is not there",
    lastReply(fetched) === NO_SUCH_SCRIPT, visible(fetched));
  count("and the refusal carries no literal, so nothing of that script reached the socket " +
    "ahead of it",
    fetched.indexOf(BOBS_SCRIPT_MARKER) === -1 && !/\{\d+\}\r\n/.test(fetched),
    visible(fetched));

  session.send('DELETESCRIPT "' + BOBS_PRIVATE + '"');
  var deleted = await replyTo(session, "DELETESCRIPT answered");
  count("DELETESCRIPT of another account's inactive script is refused as a name this " +
    "account does not hold, rather than as the active-script rule that would refuse it " +
    "for the wrong reason",
    deleted === NO_DELETE_TARGET, visible(deleted));

  session.send('SETACTIVE "' + BOBS_ACTIVE + '"');
  var activated = await replyTo(session, "SETACTIVE answered");
  count("SETACTIVE naming another account's script is refused",
    activated === NO_ACTIVE_TARGET, visible(activated));

  session.send('RENAMESCRIPT "' + BOBS_ACTIVE + '" "taken"');
  var renamed = await replyTo(session, "RENAMESCRIPT answered");
  count("RENAMESCRIPT cannot take another account's script out from under it",
    renamed === NO_RENAME_SOURCE, visible(renamed));

  // The replace half, and the one whose right answer is an acceptance.
  // A script name belongs to one account, so this stores hers under a
  // name he also uses. What must not have happened is read from his
  // session below.
  sendLiteral(session, 'PUTSCRIPT "' + BOBS_PRIVATE + '"',
    scriptBody(ALICES_SCRIPT_MARKER), "<a script named the way the other account names one>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("PUTSCRIPT under a name the other account also uses is accepted, because a script " +
    "name is per account rather than per server",
    stored === 'OK "PUTSCRIPT completed"', visible(stored));

  session.send('GETSCRIPT "' + BOBS_PRIVATE + '"');
  var readBack = await session.read(ONE_REPLY, "GETSCRIPT after PUTSCRIPT answered");
  count("and reading that name back in the same session returns this account's own body",
    readBack.indexOf(ALICES_SCRIPT_MARKER) !== -1 &&
    readBack.indexOf(BOBS_SCRIPT_MARKER) === -1, visible(readBack));
}

// The other direction, and the check on the acceptance above. Every one
// of Bob's properties has to be where he left it.
async function bobsScriptsAreAsBobLeftThem(session) {
  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("the other account still holds both of its scripts",
    listing.indexOf('"' + BOBS_ACTIVE + '"') !== -1 &&
    listing.indexOf('"' + BOBS_PRIVATE + '"') !== -1, visible(listing));
  count("and the one it activated is still the active one",
    new RegExp('"' + BOBS_ACTIVE + '" ACTIVE').test(listing), visible(listing));
  count("and the first account's script is not in its listing either, so the boundary " +
    "holds in both directions",
    listing.indexOf('"' + ALICES_SCRIPT + '"') === -1, visible(listing));

  session.send('GETSCRIPT "' + BOBS_PRIVATE + '"');
  var fetched = await session.read(ONE_REPLY, "GETSCRIPT answered");
  count("the script the other account uploaded under the same name did not replace this " +
    "one, which still returns the body its owner wrote",
    fetched.indexOf(BOBS_SCRIPT_MARKER) !== -1 &&
    fetched.indexOf(ALICES_SCRIPT_MARKER) === -1, visible(fetched));

  session.send('GETSCRIPT "' + ALICES_SCRIPT + '"');
  var reachedAcross = await session.read(ONE_REPLY, "GETSCRIPT across answered");
  count("and this session reaches the first account's script no more than that one reached " +
    "these",
    lastReply(reachedAcross) === NO_SUCH_SCRIPT, visible(reachedAcross));
}

// ---- POP3 -------------------------------------------------------------------

// Every uid the maildrop this session is holding carries.
async function uidsHeldBy(session, label) {
  session.send("UIDL");
  var listing = await session.read(/^\.\r\n/m, label);
  return uidlPairs(listing);
}

async function alicesMaildropHoldsOnlyAlicesMail(session, bobsUids) {
  session.send("STAT");
  var stat = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
  count("the maildrop holds this account's one message rather than every message on the " +
    "server", statCount(stat).messages === 1, visible(stat));

  var uids = await uidsHeldBy(session, "UIDL answered");
  count("UIDL lists that one message and numbers it from one",
    uids.length === 1 && uids[0].msgNum === 1, JSON.stringify(uids));
  count("and none of the other account's unique ids is among them",
    uids.filter(function (row) { return bobsUids.indexOf(row.uid) !== -1; }).length === 0,
    uids.map(function (row) { return row.uid; }).join(",") + " against " + bobsUids.join(","));

  session.send("RETR 1");
  var mine = await session.read(/(\r\n\.\r\n|^-ERR)/m, "RETR 1 answered");
  count("RETR returns this account's own message",
    mine.indexOf(ALICES_BODY_MARKER) !== -1, visible(mine.slice(0, 300)));
  count("and none of the other account's",
    mine.indexOf(BOBS_BODY_MARKER) === -1, visible(mine.slice(0, 300)));

  // Two is a message number the other account's maildrop carries and
  // this one does not, so a maildrop opened without the account scope
  // would answer it with his mail.
  session.send("RETR 2");
  var beyond = await session.read(/(\r\n\.\r\n|^-ERR)/m, "RETR 2 answered");
  count("a message number the other account's maildrop carries and this one does not is " +
    "refused rather than served",
    lastPopLine(beyond) === NO_SUCH_MESSAGE, visible(beyond.slice(0, 300)));
  count("and the refusal carries none of that account's mail",
    beyond.indexOf(BOBS_BODY_MARKER) === -1, visible(beyond.slice(0, 300)));

  session.send("TOP 2 0");
  var topped = await session.read(/(\r\n\.\r\n|^-ERR)/m, "TOP 2 answered");
  count("the header-only read of the same number is refused the same way, so the two " +
    "routes to a message body answer alike",
    lastPopLine(topped) === NO_SUCH_MESSAGE, visible(topped.slice(0, 300)));

  session.send("DELE 2");
  var marked = await session.read(/^(\+OK|-ERR)/m, "DELE 2 answered");
  count("and a mark aimed at that number is refused by the maildrop rather than by the " +
    "listing, which is the one POP3 verb that reaches past it",
    lastPopLine(marked) === NO_MESSAGE_TO_MARK, visible(marked));
}

// The last +OK or -ERR line in what a read took off the socket. A
// pattern run over the whole buffer would match inside a message body,
// and a message body is exactly what these cases are checking is absent.
function lastPopLine(text) {
  var lines = String(text).split("\r\n").filter(function (line) {
    return /^(\+OK|-ERR)/.test(line);
  });
  return lines.length === 0 ? "" : lines[lines.length - 1];
}

// The destructive half. RFC 1939 section 6 applies a session's marks at
// QUIT, so this is the moment one account's deletions could reach
// another's mailbox, and the other session is still holding its own
// maildrop while it happens.
async function alicesQuitDeletesOnlyAlicesMail(session, bob) {
  session.send("DELE 1");
  var marked = await session.read(/^(\+OK|-ERR)/m, "DELE 1 answered");
  count("this account can mark its own message", /^\+OK/m.test(marked), visible(marked));

  session.send("QUIT");
  var goodbye = await session.read(/^(\+OK|-ERR)/m, "QUIT answered");
  count("and its QUIT applies the mark", /^\+OK/m.test(goodbye), visible(goodbye));

  bob.send("STAT");
  var his = await bob.read(/^(\+OK|-ERR)/m, "STAT answered");
  count("the other account's open maildrop still holds every message it opened with, so a " +
    "commit in the UPDATE state reached one mailbox and not the server's",
    statCount(his).messages === 3, visible(his));
}

// ---- runner -----------------------------------------------------------------

async function endManageSieve(session) {
  session.send("LOGOUT");
  try { await session.read(ONE_REPLY, "LOGOUT answered"); }
  catch (_e) { /* drop-silent by design: the session's verdict is already read */ }
  session.close();
}

async function run() {
  var root    = helpers.tempDir("cross-store");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

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
      },
      cwd: root,
    });

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    // Seeded through the store rather than uploaded over the wire, so
    // what a session reaches is read against a fixture this file owns.
    // A witness written by a PUTSCRIPT would make every assertion below
    // depend on the upload path as well, and the claim here is about who
    // a credential names.
    var aliceActor = actorFor(alice);
    var bobActor   = actorFor(bob);
    identity.mailbox.sieveScripts.put(aliceActor, ALICES_SCRIPT,
      scriptBody(ALICES_SCRIPT_MARKER));
    identity.mailbox.sieveScripts.put(bobActor, BOBS_ACTIVE, scriptBody(BOBS_SCRIPT_MARKER));
    identity.mailbox.sieveScripts.put(bobActor, BOBS_PRIVATE, scriptBody(BOBS_SCRIPT_MARKER));
    identity.mailbox.sieveScripts.setActive(bobActor, BOBS_ACTIVE);

    // Different counts on purpose: a message number valid in one
    // maildrop has to be outside the other.
    identity.mailbox.appendMessage("INBOX", messageFor(alice.address, ALICES_BODY_MARKER),
      { actor: aliceActor });
    for (var i = 0; i < 3; i += 1) {
      identity.mailbox.appendMessage("INBOX",
        messageFor(bob.address, BOBS_BODY_MARKER + " " + i), { actor: bobActor });
    }

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default and half of this file is about it.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var base = { caPem: leaf.ca, servername: HOSTNAME };

    // ---- ManageSieve ------------------------------------------------------
    await helpers.withTestTimeout("cross-account: neither ManageSieve session reaches the " +
      "other account's scripts", async function () {
      var alicesSieve = await Wire.managesieve(sections.managesieve.port,
        Object.assign({ label: "sieve-alice", address: alice.address,
          password: ALICE_PASSWORD }, base));
      try {
        await alicesSessionReachesNoneOfBobsScripts(alicesSieve);
      } finally {
        await endManageSieve(alicesSieve);
      }

      var bobsSieve = await Wire.managesieve(sections.managesieve.port,
        Object.assign({ label: "sieve-bob", address: bob.address,
          password: BOB_PASSWORD }, base));
      try {
        await bobsScriptsAreAsBobLeftThem(bobsSieve);
      } finally {
        await endManageSieve(bobsSieve);
      }
    }, { timeoutMs: 30000 });

    // ---- POP3 -------------------------------------------------------------
    await helpers.withTestTimeout("cross-account: neither maildrop carries the other " +
      "account's mail", async function () {
      var bobsDrop = await Wire.pop3(sections.pop3.port,
        Object.assign({ label: "pop3-bob", address: bob.address, password: BOB_PASSWORD },
          base));
      try {
        bobsDrop.send("STAT");
        var his = await bobsDrop.read(/^(\+OK|-ERR)/m, "STAT answered");
        count("one account opens a maildrop holding its three messages",
          statCount(his).messages === 3, visible(his));
        var bobsUids = (await uidsHeldBy(bobsDrop, "UIDL answered")).map(function (row) {
          return row.uid;
        });
        count("and its unique ids are readable, so the other session's listing can be " +
          "checked against them rather than against an assumption",
          bobsUids.length === 3, bobsUids.join(","));

        // Opened while the first is still held. Section 3 leases per
        // mailbox, so a second account is not a second session on one
        // maildrop, and holding both is what lets one be read from the
        // other.
        var alicesDrop = await Wire.pop3(sections.pop3.port,
          Object.assign({ label: "pop3-alice", address: alice.address,
            password: ALICE_PASSWORD }, base));
        try {
          await alicesMaildropHoldsOnlyAlicesMail(alicesDrop, bobsUids);
          await alicesQuitDeletesOnlyAlicesMail(alicesDrop, bobsDrop);
        } finally {
          alicesDrop.close();
        }

        bobsDrop.send("QUIT");
        await bobsDrop.read(/^(\+OK|-ERR)/m, "QUIT answered");
      } finally {
        bobsDrop.close();
      }

      // Read back on a session of its own, so the count comes off the
      // volume rather than off the snapshot the session above opened
      // with.
      var after = await Wire.pop3(sections.pop3.port,
        Object.assign({ label: "pop3-bob-again", address: bob.address,
          password: BOB_PASSWORD }, base));
      try {
        after.send("STAT");
        var still = await after.read(/^(\+OK|-ERR)/m, "STAT answered");
        count("and a maildrop opened afterwards finds all three still on the volume",
          statCount(still).messages === 3, visible(still));
        after.send("QUIT");
        await after.read(/^(\+OK|-ERR)/m, "QUIT answered");
      } finally {
        after.close();
      }
    }, { timeoutMs: 30000 });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cross-account-sieve-pop3", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
