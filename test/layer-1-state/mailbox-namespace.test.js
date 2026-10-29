// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The folder namespace rule, settled before anything can create a
 * folder.
 *
 * A wire name is the only handle an account has on one of its
 * mailboxes, and it arrives from four directions: a URL path segment,
 * an IMAP command, a JMAP identifier, and the name an account holder
 * types into a client's new folder control. The last of those is the
 * one that puts a name INTO the namespace, and a name already stored in
 * somebody's mailbox is a name nobody can take back.
 *
 * The rule lives inside `blamepost.mail.mailbox.create`, in one
 * function, applied both where a name arrives from a client and where
 * one enters the namespace, so there is one answer to what a wire name
 * may be. `blamepost.mail.mailbox.createFolder` applies it per level,
 * because a level is a name a client addresses on its own.
 *
 * The cases below are the collisions, not a spelling preference. A name
 * carrying a bidi override renders as one folder and addresses another
 * in the IMAP LIST reply and the browser sidebar alike. A name spelled
 * like a message address makes one path name a mailbox in one reading
 * and a message in the other. A name carrying a LIST wildcard cannot be
 * asked for unambiguously by the command that lists it. Each is
 * refused under one code, because one code is what a listener maps onto
 * its own protocol reply.
 *
 * Run standalone: node test/layer-1-state/mailbox-namespace.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var mailbox = require("../../lib/mail/mailbox");

// The assertion that quotes the value that produced the verdict, and
// the counter behind it, are both the shared ones. A file that kept its
// own counter reported a total that only covered the assertions made
// through its own wrapper, so a `check` written directly ran and was
// invisible in the number the runner aggregated.
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var BAD_NAME = "mailbox/bad-mailbox-name";
var NO_FOLDER = "mailbox/no-folder";

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    // The shape a signed in session carries, roles and no scopes array.
    // `b.permissions` reads a scopes array in preference to the roles,
    // so an empty one here would be an actor granted nothing rather than
    // an actor with a role.
    roles:     ["account"],
  };
}

// Every codepoint under test is written from its number rather than
// typed, so this file stays readable and its own bytes stay ASCII. A
// bidi override pasted into a source file reorders the source.
function cp(code) { return String.fromCodePoint(code); }

// The refusal, by code. A name is refused at the point of parse, so
// the check is that the parse refuses and not that a lookup came back
// empty: `mailbox/no-folder` for a name this rule accepts is a
// different and correct answer.
function refuses(handle, actor, label, name) {
  var thrown = null;
  try { handle.mailbox.selectFolder(actor, name, {}); }
  catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === BAD_NAME,
    thrown === null ? "accepted" : thrown.code + " " + thrown.message);
}

// A name this rule accepts reaches the folder lookup, which is where a
// name nobody has created is refused. Asserting the code distinguishes
// "the rule let it through" from "the rule refused it for another
// reason", which is the way a screen quietly becomes a deny-all.
function reaches(handle, actor, label, name) {
  var thrown = null;
  try { handle.mailbox.selectFolder(actor, name, {}); }
  catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === NO_FOLDER,
    thrown === null ? "selected" : thrown.code + " " + thrown.message);
}

function testTheThreatCatalog(handle, actor) {
  // CVE-2021-42574 Trojan Source. The override characters render as
  // nothing and reverse the order of everything after them, so one
  // stored name displays as another.
  [
    ["U+202E RIGHT-TO-LEFT OVERRIDE", 0x202E],
    ["U+202A LEFT-TO-RIGHT EMBEDDING", 0x202A],
    ["U+2066 LEFT-TO-RIGHT ISOLATE", 0x2066],
    ["U+2069 POP DIRECTIONAL ISOLATE", 0x2069],
    ["U+200F RIGHT-TO-LEFT MARK", 0x200F],
    ["U+061C ARABIC LETTER MARK", 0x061C],
  ].forEach(function (entry) {
    refuses(handle, actor, "a mailbox name carrying " + entry[0] + " is refused",
      "Arch" + cp(entry[1]) + "ive");
  });

  // Invisible formatting. Two folders whose names differ only by a
  // zero-width character are two folders that render identically.
  [
    ["U+200B ZERO WIDTH SPACE", 0x200B],
    ["U+200D ZERO WIDTH JOINER", 0x200D],
    ["U+2060 WORD JOINER", 0x2060],
    ["U+00AD SOFT HYPHEN", 0x00AD],
    ["U+FEFF BYTE ORDER MARK", 0xFEFF],
  ].forEach(function (entry) {
    refuses(handle, actor, "a mailbox name carrying " + entry[0] + " is refused",
      "Arch" + cp(entry[1]) + "ive");
  });

  // The Unicode Tags block carries an invisible copy of an ASCII
  // string. It renders as nothing and reads back verbatim.
  refuses(handle, actor,
    "a mailbox name carrying a Unicode Tags block character is refused",
    "Arch" + cp(0xE0041) + "ive");

  // UTS #39. A Cyrillic letter inside an otherwise-Latin word produces
  // a second Trash that files mail nobody meant to file there.
  refuses(handle, actor,
    "a mailbox name mixing writing systems inside one word is refused",
    "Tr" + cp(0x0430) + "sh");
}

function testControlCharacters(handle, actor) {
  // A control character in a name reaches the IMAP and ManageSieve
  // wire as a line the peer never sent. The listener's own quoting
  // escapes a quote and a backslash and nothing else, so a line
  // terminator here is a response the client parses as a new line.
  [
    ["NUL", 0x00],
    ["TAB", 0x09],
    ["LF", 0x0A],
    ["CR", 0x0D],
    ["ESC", 0x1B],
    ["DEL", 0x7F],
  ].forEach(function (entry) {
    refuses(handle, actor, "a mailbox name carrying " + entry[0] + " is refused",
      "Arch" + cp(entry[1]) + "ive");
  });
}

function testNamespaceCollisions(handle, actor) {
  refuses(handle, actor, "an empty mailbox name is refused", "");
  refuses(handle, actor, "a mailbox name past 255 bytes is refused",
    new Array(257).join("a"));

  refuses(handle, actor, "a mailbox name that begins with the hierarchy delimiter is refused",
    "/Archive");
  refuses(handle, actor, "a mailbox name that ends with the hierarchy delimiter is refused",
    "Archive/");
  refuses(handle, actor, "a mailbox name with an empty level is refused", "Archive//2026");

  refuses(handle, actor,
    "a mailbox level spelled like a message address is refused, because the same path " +
    "would name both",
    "INBOX/obj_deadbeef");

  // The same class as the level above. A mailbox name is written into a
  // URL path segment by the browser surface, and in a path `a/../b`
  // names `b`, so a level spelled as one of the two relative tokens is
  // a name that addresses somewhere else wherever the name is joined to
  // anything. A dot inside a level is ordinary and stays ordinary.
  refuses(handle, actor,
    "a mailbox level spelled as the parent-directory token is refused", "..");
  refuses(handle, actor,
    "a nested mailbox level spelled as the parent-directory token is refused",
    "../bob@example.com/INBOX");
  refuses(handle, actor,
    "a mailbox level spelled as the current-directory token is refused", "Work/./2026");

  // RFC 9051 section 6.3.9 gives LIST two wildcards. A folder named
  // for one of them cannot be asked for by the command that lists it.
  refuses(handle, actor, "a mailbox name carrying the LIST wildcard '*' is refused",
    "Arch*ive");
  refuses(handle, actor, "a mailbox name carrying the LIST wildcard '%' is refused",
    "Arch%ive");

  // A level padded with whitespace is a twin of the level without it.
  refuses(handle, actor, "a mailbox level that begins with a space is refused", " Archive");
  refuses(handle, actor, "a mailbox level that ends with a space is refused", "Archive ");
  refuses(handle, actor, "a mailbox level padded with a no-break space is refused",
    "Archive" + cp(0x00A0));
  refuses(handle, actor, "a nested mailbox level padded with a space is refused",
    "Work/ 2026");
}

function testWhatTheRuleAccepts(handle, actor) {
  // The rule screens for collisions, not for a writing system. A name
  // that is legitimately not English is a name this server keeps.
  reaches(handle, actor, "an ordinary nested name reaches the folder lookup", "Work/2026");
  reaches(handle, actor, "a name in one non-Latin script reaches the folder lookup",
    cp(0x4ED5) + cp(0x4E8B));
  reaches(handle, actor, "an accented Latin name reaches the folder lookup",
    cp(0x00C4) + "rger");
  reaches(handle, actor, "a name carrying digits alongside its script reaches the folder lookup",
    cp(0x4ED5) + cp(0x4E8B) + "/2026");
  reaches(handle, actor, "a name carrying an emoji reaches the folder lookup",
    cp(0x1F4C1) + " Photos");

  // RFC 9051 section 5.1: INBOX is the one name matched without regard
  // to case, and it is the one name that must not be refused for
  // mixing case.
  var byUpper = handle.mailbox.selectFolder(actor, "INBOX", {});
  var byLower = handle.mailbox.selectFolder(actor, "inbox", {});
  count("INBOX is matched without regard to case, and no other name is",
    byUpper.uidvalidity === byLower.uidvalidity, String(byUpper.uidvalidity));
  reaches(handle, actor, "a name that differs from a real folder only in case is a " +
    "different name", "archive");
}

// The names the account is provisioned with have to survive the rule
// they are read back through, or an account starts life with a folder
// it cannot open.
function testTheDefaultSetSurvivesItsOwnRule(handle, actor) {
  var listed = handle.mailbox.listFolders(actor);
  count("the account has its default folder set", listed.length === 6, String(listed.length));
  var unopenable = [];
  for (var i = 0; i < listed.length; i += 1) {
    try { handle.mailbox.selectFolder(actor, listed[i].name, {}); }
    catch (e) { unopenable.push(listed[i].name + " (" + e.code + ")"); }
  }
  count("every folder the account is provisioned with can be opened by the name it is " +
    "listed under", unopenable.length === 0, unopenable.join(", "));
}

// A name entering the namespace is screened the way a name arriving
// from a client is, per level, and it is stored as the screen wrote it.
// That is what keeps a stored name reachable: a mailbox whose row
// carries a name the screen rewrites is a mailbox that answers to
// nothing a client can send.
function testWhatEnteringTheNamespaceIsScreenedBy(handle, actor) {
  var made = handle.mailbox.createFolder(actor, "Clients/Acme/2026");
  count("a nested name reports the levels it brought into existence",
    made.name === "Clients/Acme/2026" &&
      made.created.join(",") === "Clients,Clients/Acme,Clients/Acme/2026",
    made.created.join(","));

  var opened = [];
  for (var i = 0; i < made.created.length; i += 1) {
    try { handle.mailbox.selectFolder(actor, made.created[i], {}); opened.push(made.created[i]); }
    catch (_e) { /* left out of the list below, which is what the count reads */ }
  }
  count("every level it created can be opened by the name it was created under",
    opened.length === made.created.length, opened.join(","));

  // What is above a name, from the one derivation every surface that
  // reports a hierarchy reads: the IMAP listing keeps a removed level
  // reachable from it, and the JMAP mailbox answer builds `parentId` and
  // the level-only name from it. CREATE names the same levels from the
  // other direction, so the two are compared against each other rather
  // than against a list written out here.
  var above = mailbox.superiorLevels("Clients/Acme/2026");
  count("the levels above a name are the ones CREATE brought into existence under it",
    above.join(",") === made.created.slice(0, made.created.length - 1).join(","),
    above.join(",") + " against " + made.created.join(","));
  count("a name with nothing above it has no levels above it",
    mailbox.superiorLevels("INBOX").length === 0,
    JSON.stringify(mailbox.superiorLevels("INBOX")));

  var second = handle.mailbox.createFolder(actor, "Clients/Acme/2025");
  count("a second name under an existing parent creates the leaf alone",
    second.created.join(",") === "Clients/Acme/2025", second.created.join(","));

  // RFC 9051 section 5.1 matches INBOX without regard to case, so a
  // level spelling it is INBOX whatever case it arrives in. Screening
  // per level is what keeps a second row from being written under that
  // name, which would be a mailbox with no name of its own to open it
  // by.
  var undeINBOX = handle.mailbox.createFolder(actor, "inbox/Kept");
  count("a first level spelling inbox is the INBOX the account already has",
    undeINBOX.created.join(",") === "inbox/Kept", undeINBOX.created.join(","));
  count("so no second mailbox is written under that name",
    handle.mailbox.accountFolders(actor).filter(function (f) {
      return f.name.toUpperCase() === "INBOX";
    }).length === 1,
    handle.mailbox.accountFolders(actor).map(function (f) { return f.name; }).join(","));

  var refused = [];
  [
    cp(0x202E) + "Reversed", "Wild*card", "Two//Levels", "obj_beef", " Padded",
    "Trailing ", "", cp(0x200B) + "Invisible",
  ].forEach(function (name) {
    try { handle.mailbox.createFolder(actor, name); }
    catch (e) { if (e.code === BAD_NAME) refused.push(name); }
  });
  count("every name the rule refuses on the way in is refused on the way out too",
    refused.length === 8, String(refused.length));

  // The ceiling is the same number the wire is driven to, read from the
  // module rather than written a second time here.
  count("the module names how many mailboxes one account may hold",
    typeof mailbox.MAX_FOLDERS_PER_ACCOUNT === "number" &&
      mailbox.MAX_FOLDERS_PER_ACCOUNT > 6,
    String(mailbox.MAX_FOLDERS_PER_ACCOUNT));
}

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-namespace-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var handle = await store.open(cfg);
    await handle.domains.add({ domain: "example.com" });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD }));

    testTheDefaultSetSurvivesItsOwnRule(handle, alice);
    testTheThreatCatalog(handle, alice);
    testControlCharacters(handle, alice);
    testNamespaceCollisions(handle, alice);
    testWhatTheRuleAccepts(handle, alice);
    testWhatEnteringTheNamespaceIsScreenedBy(handle, alice);

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not
      // a test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = {
  name: "mailbox-namespace",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
