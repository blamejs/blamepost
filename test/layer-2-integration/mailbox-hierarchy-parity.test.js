// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One account's folders, created over IMAP and read back over JMAP.
 *
 * RFC 9051 section 6.3.4 gives CREATE a name whose levels are separated
 * by the hierarchy delimiter, and this server makes every superior level
 * the new name needs. So an account holder with an ordinary mail client
 * can end a session holding `Clients/Acme/2026`, and the same account is
 * what a JMAP client opens next.
 *
 * RFC 8621 section 2 carries that hierarchy as two properties rather
 * than as a path: `parentId` names the mailbox above this one, and `name`
 * is the level alone, which the section says MUST NOT include the name of
 * the parent. A client draws its folder tree from those two and from
 * `maxMailboxDepth`, which section 1.6.2 defines as one more than the
 * greatest number of ancestors a mailbox may have.
 *
 * What is asserted is that the two protocols describe ONE account. Every
 * name IMAP listed is answered over JMAP; each answer's `name` is the
 * level rather than the path; each `parentId` names a mailbox that is in
 * the same answer, so a client resolving it finds the parent rather than
 * dropping the child; and the advertised depth covers the hierarchy the
 * account actually holds.
 *
 * The deleted middle level is the case that decides whether a client can
 * draw the tree at all. RFC 9051 section 6.3.5 removes only the name
 * DELETE was given, so removing `Clients/Acme` leaves `Clients/Acme/2026`
 * with an ancestor no mailbox row answers to. IMAP keeps that level
 * reachable in a listing; a JMAP answer that names it as a `parentId`
 * without carrying it is a reference a client cannot resolve, and the
 * mailbox under it disappears from the tree the owner is shown.
 *
 * It needs no external service. The ports are ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/mailbox-hierarchy-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
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
var ALICE            = "alice@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// Three levels, none of them carrying an RFC 6154 role, so DELETE and
// RENAME of any of them is an ordinary removal rather than a refusal
// about a mailbox this server files into by name.
var TOP    = "Clients";
var MIDDLE = "Clients/Acme";
var LEAF   = "Clients/Acme/2026";

// The mailbox whose ancestor is removed while it stays. Kept apart from
// the tree above so the two cases do not decide each other.
var ORPHAN_TOP    = "Suppliers";
var ORPHAN_MIDDLE = "Suppliers/Northwind";
var ORPHAN_LEAF   = "Suppliers/Northwind/2025";

// ---- the account as each protocol describes it -----------------------------

// Every mailbox name one IMAP session is listed, with the delimiter the
// reply carried. Read off the untagged lines, because the question is
// what the client was told.
async function imapNamespace(ctx, label) {
  var session = await Wire.imap(ctx.ports.imap, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    var listed = await session.imapAsk('LIST "" "*"', "the whole namespace");
    count(label + ": the listing completes", listed.verdict === "OK", visible(listed.text));
    var entries = wire.imapListed(listed.text);
    count(label + ": the listing names mailboxes", entries.length > 0, visible(listed.text));
    var delimiters = entries.map(function (e) { return e.separator; })
      .filter(function (d, i, all) { return all.indexOf(d) === i; });
    count(label + ": every entry carries one hierarchy delimiter",
      delimiters.length === 1 && delimiters[0].length === 1, JSON.stringify(delimiters));
    return { delimiter: delimiters[0], entries: entries,
      names: entries.map(function (e) { return e.name; }) };
  } finally {
    session.close();
  }
}

// Every mailbox one JMAP client is answered with, by id.
async function jmapMailboxes(reader, alice, label) {
  var response = await reader.jmap([["Mailbox/get", { accountId: alice.id }, "c0"]]);
  var answer = browser.answer(response, 0);
  count(label + ": Mailbox/get answers", answer[0] === "Mailbox/get",
    JSON.stringify(answer).slice(0, 200));
  var list = (answer[1] || {}).list || [];
  count(label + ": the answer carries mailboxes", list.length > 0,
    JSON.stringify(answer).slice(0, 200));
  return list;
}

// ---- what the two have to agree about --------------------------------------

async function bothProtocolsDescribeTheSameFolders(ctx, reader, label) {
  var over = await imapNamespace(ctx, label + "-imap");
  var list = await jmapMailboxes(reader, ctx.alice, label + "-jmap");
  var ids  = list.map(function (row) { return row.id; });

  var missing = over.names.filter(function (name) { return ids.indexOf(name) === -1; });
  count(label + ": every mailbox IMAP lists is answered over JMAP, because the two " +
    "protocols are reading one account",
    missing.length === 0, "IMAP listed " + JSON.stringify(over.names) +
    ", JMAP answered " + JSON.stringify(ids));

  return { imap: over, jmap: list, ids: ids };
}

function theNameOfEachMailboxIsItsOwnLevel(view, label) {
  var delimiter = view.imap.delimiter;
  var carrying = view.jmap.filter(function (row) {
    return String(row.name).indexOf(delimiter) !== -1;
  });
  count(label + ": no mailbox name carries the hierarchy delimiter, because RFC 8621 " +
    "section 2 keeps the parent's name out of the child's",
    carrying.length === 0,
    JSON.stringify(carrying.map(function (row) { return { id: row.id, name: row.name }; })));
}

function everyParentReferenceResolves(view, label) {
  var ids = view.ids;
  var dangling = view.jmap.filter(function (row) {
    return row.parentId !== null && ids.indexOf(row.parentId) === -1;
  });
  count(label + ": every parentId names a mailbox in the same answer, because a client " +
    "that cannot resolve one drops the mailbox under it",
    dangling.length === 0,
    JSON.stringify(dangling.map(function (row) {
      return { id: row.id, parentId: row.parentId };
    })));
}

function eachNestedNameIsAnsweredWithItsParent(view, label) {
  var delimiter = view.imap.delimiter;
  var nested = view.imap.names.filter(function (name) {
    return name.indexOf(delimiter) !== -1;
  });
  count(label + ": the account holds a nested name for this to be a question about",
    nested.length > 0, JSON.stringify(view.imap.names));

  for (var i = 0; i < nested.length; i += 1) {
    var name   = nested[i];
    var cut    = name.lastIndexOf(delimiter);
    var parent = name.slice(0, cut);
    var leaf   = name.slice(cut + delimiter.length);
    var answered = view.jmap.filter(function (row) { return row.id === name; })[0] || null;
    count(label + ": " + name + " is answered with " + parent + " as its parent",
      answered !== null && answered.parentId === parent,
      JSON.stringify(answered && { id: answered.id, parentId: answered.parentId }));
    count(label + ": " + name + " is named " + leaf + " rather than by its whole path",
      answered !== null && answered.name === leaf,
      JSON.stringify(answered && { id: answered.id, name: answered.name }));
  }
}

// RFC 8621 section 1.6.2 types `maxMailboxDepth` as an unsigned integer
// or null, and null is no limit. Either answer is honest; a number below
// the depth the account already holds is not, because a client reads it
// once and draws a window that cannot show what IMAP made.
async function theAdvertisedDepthCoversWhatTheAccountHolds(reader, alice, view, label) {
  var session = await reader.get("/jmap/session", { Accept: "application/json" });
  count(label + ": the session document answers", session.status === 200, session.status);
  var doc = JSON.parse(session.body);
  var account = (doc.accounts || {})[alice.id] || {};
  var mail = (account.accountCapabilities || {})["urn:ietf:params:jmap:mail"] || {};
  var advertised = mail.maxMailboxDepth;

  var deepest = view.imap.names.reduce(function (most, name) {
    var levels = name.split(view.imap.delimiter).length;
    return levels > most ? levels : most;
  }, 0);

  count(label + ": maxMailboxDepth is at least as deep as the hierarchy this account " +
    "holds, or null for no limit",
    advertised === null || (Number.isInteger(advertised) && advertised >= deepest),
    JSON.stringify(advertised) + " against a namespace " + deepest + " levels deep: " +
    JSON.stringify(view.imap.names));
}

// ---- driving the wire ------------------------------------------------------

async function imapCreates(ctx, names, label) {
  var session = await Wire.imap(ctx.ports.imap, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    for (var i = 0; i < names.length; i += 1) {
      var made = await session.imapAsk('CREATE "' + names[i] + '"', "CREATE " + names[i]);
      count(label + ": CREATE " + names[i] + " is accepted", made.verdict === "OK",
        visible(made.text));
    }
  } finally {
    session.close();
  }
}

async function imapDeletes(ctx, name, label) {
  var session = await Wire.imap(ctx.ports.imap, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    var gone = await session.imapAsk('DELETE "' + name + '"', "DELETE " + name);
    count(label + ": DELETE " + name + " is accepted", gone.verdict === "OK", visible(gone.text));
    var listed = await session.imapAsk('LIST "" "*"', "the namespace after the removal");
    var entry = wire.imapListedNamed(listed.text, name);
    count(label + ": the removed level stays in the listing, because what is under it " +
      "is still there", entry !== null && /NonExistent/i.test(entry.attributes),
      visible(listed.text));
  } finally {
    session.close();
  }
}

// ---- one running server ----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("mbx-hier");
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
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });

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

    await fn({
      ports:    { imap: sections.imap.port },
      httpPort: server.web.describe().bound.http,
      caPem:    leaf.ca,
      identity: identity,
      alice:    alice,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
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

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await reader.signIn(ALICE, ALICE_PASSWORD);
    count("the account signs in, because the JMAP methods are behind the door",
      landed.status === 302, landed.status + " " + String(landed.location));

    // One CREATE of the deepest name makes every level above it, which
    // is what RFC 9051 section 6.3.4 asks of the verb.
    await imapCreates(ctx, [LEAF, ORPHAN_LEAF], "created");

    var made = await bothProtocolsDescribeTheSameFolders(ctx, reader, "after-create");
    count("the levels one CREATE brought into existence are all listed",
      [TOP, MIDDLE, LEAF, ORPHAN_TOP, ORPHAN_MIDDLE, ORPHAN_LEAF]
        .every(function (name) { return made.imap.names.indexOf(name) !== -1; }),
      JSON.stringify(made.imap.names));
    theNameOfEachMailboxIsItsOwnLevel(made, "after-create");
    everyParentReferenceResolves(made, "after-create");
    eachNestedNameIsAnsweredWithItsParent(made, "after-create");
    await theAdvertisedDepthCoversWhatTheAccountHolds(reader, ctx.alice, made, "after-create");

    // The middle level goes and what is under it stays, which is the
    // reference a JMAP client has to be able to resolve anyway.
    await imapDeletes(ctx, ORPHAN_MIDDLE, "orphaned");

    var orphaned = await bothProtocolsDescribeTheSameFolders(ctx, reader, "after-delete");
    count("the mailbox under the removed level is still listed",
      orphaned.imap.names.indexOf(ORPHAN_LEAF) !== -1, JSON.stringify(orphaned.imap.names));
    theNameOfEachMailboxIsItsOwnLevel(orphaned, "after-delete");
    everyParentReferenceResolves(orphaned, "after-delete");
    await theAdvertisedDepthCoversWhatTheAccountHolds(reader, ctx.alice, orphaned, "after-delete");
  });

  return helpers.getChecks();
}

module.exports = { name: "mailbox-hierarchy-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
