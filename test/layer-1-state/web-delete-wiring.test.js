// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The wiring behind every delete and every move the browser surface
 * offers, checked where it is decided rather than where it shows.
 *
 * The mail agent owns the message store's row. The mailbox adapter owns
 * the row binding that message to a folder and to the UID an IMAP
 * client addresses it by, and the sealed original octets under
 * `blobs/`. So a delete or a move is one operation over three pieces of
 * state, and the only verbs that carry all three are the adapter's
 * `expungeObjects` and `moveObjects`. A surface that reaches past them
 * to the agent gets half of the operation and is told it succeeded.
 *
 * Two things follow, and both are asserted here because neither is
 * visible from a wire transcript.
 *
 * The browser surface has to refuse a mailbox handle that cannot carry
 * the whole operation, at construction, so a wiring mistake fails the
 * boot by name rather than the first purge an account drives. A handle
 * answering `accountFolders` alone used to be accepted, which is
 * exactly the handle a partial adapter would present.
 *
 * And no direct agent delete or move may survive in the surface itself.
 * That is a composition boundary rather than a behavior, so it is
 * asserted against the shipped source: a wire test cannot see it,
 * because the adapter intersects its own rows with the store's before
 * answering a client and an orphaned row is therefore invisible rather
 * than wrong.
 *
 * The behavior on either side of this boundary is covered where it
 * belongs. `mailbox-expunge-path` drives the adapter verbs against a
 * real store, and `web-delete-adapter` drives the browser and JMAP over
 * sockets against real listeners.
 *
 * Run standalone: node test/layer-1-state/web-delete-wiring.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two verbs that carry the whole operation. Named here rather than
// spelled into each assertion, so adding a third is one edit.
var WHOLE_OPERATION_VERBS = ["expungeObjects", "moveObjects"];

// The shapes that take half of one. Anchored on the call rather than on
// a helper name, because a helper can be renamed and this cannot.
var HALF_OPERATION_CALLS = ["agent.expunge(", "agent.move("];

var WEB_SOURCE = nodePath.join(helpers.REPO_ROOT, "lib", "web", "index.js");

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function threw(fn) {
  try {
    fn();
    return null;
  } catch (e) {
    return e;
  }
}

// Everything `blamepost.web.create` needs, composed the way
// `lib/index.js` composes it, with one field replaceable so a case can
// hand it a handle that is missing something.
function wiringFor(cfg, identity, overrides) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  var wiring = {
    agent: helpers.b.mail.agent.create({
      store: identity.messageStore, dispatch: { mode: "local" },
    }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return []; },
    address:   LOOPBACK,
    httpPort:  0,
  };
  if (overrides) {
    var keys = Object.keys(overrides);
    for (var i = 0; i < keys.length; i += 1) wiring[keys[i]] = overrides[keys[i]];
  }
  return wiring;
}

// ---- the construction contract ---------------------------------------------

function theAdapterCarriesTheWholeOperation(identity) {
  for (var i = 0; i < WHOLE_OPERATION_VERBS.length; i += 1) {
    var verb = WHOLE_OPERATION_VERBS[i];
    count("the mailbox adapter exposes " + verb,
      typeof identity.mailbox[verb] === "function", typeof identity.mailbox[verb]);
  }
}

function aCompleteWiringIsAccepted(cfg, identity) {
  var failure = threw(function () { blamepost.web.create(wiringFor(cfg, identity)); });
  count("the browser surface builds against the real adapter", failure === null,
    failure ? failure.message.slice(0, 200) : "");
}

// The handle a partial adapter presents: it can say which folders an
// account owns and nothing else. Accepting it is how a surface ends up
// driving the agent directly, because the verb that would have carried
// the whole operation is simply not there to call.
function aPartialAdapterIsRefusedAtConstruction(cfg, identity) {
  var partial = {
    accountFolders: function (actor) { return identity.mailbox.accountFolders(actor); },
  };
  var failure = threw(function () {
    blamepost.web.create(wiringFor(cfg, identity, { mailbox: partial }));
  });
  count("a mailbox handle that cannot carry the whole operation is refused",
    failure !== null, failure ? failure.message.slice(0, 200) : "accepted");
  count("and the refusal is a type error, which is what a boot reports by name",
    failure instanceof TypeError, failure ? failure.constructor.name : "none");
  for (var i = 0; i < WHOLE_OPERATION_VERBS.length; i += 1) {
    var verb = WHOLE_OPERATION_VERBS[i];
    count("the refusal names " + verb + ", so the operator is told what is missing",
      failure !== null && failure.message.indexOf(verb) !== -1,
      failure ? failure.message.slice(0, 200) : "accepted");
  }
}

// One verb missing is the case a hand-written double produces, and it
// has to fail the same way as a handle missing both.
function anAdapterMissingOneVerbIsRefusedToo(cfg, identity) {
  for (var i = 0; i < WHOLE_OPERATION_VERBS.length; i += 1) {
    var absent = WHOLE_OPERATION_VERBS[i];
    var partial = { accountFolders: identity.mailbox.accountFolders };
    for (var v = 0; v < WHOLE_OPERATION_VERBS.length; v += 1) {
      if (WHOLE_OPERATION_VERBS[v] === absent) continue;
      partial[WHOLE_OPERATION_VERBS[v]] = identity.mailbox[WHOLE_OPERATION_VERBS[v]];
    }
    var failure = threw(function () {
      blamepost.web.create(wiringFor(cfg, identity, { mailbox: partial }));
    });
    count("a mailbox handle missing " + absent + " alone is refused",
      failure !== null && failure.message.indexOf(absent) !== -1,
      failure ? failure.message.slice(0, 200) : "accepted");
  }
}

// ---- the composition boundary ----------------------------------------------

// The surface may read and flag through the agent. What it may not do
// is delete or move through it, because those are the two verbs whose
// state lives in more than one place.
function noHalfOperationSurvivesInTheSurface() {
  var source = nodeFs.readFileSync(WEB_SOURCE, "utf8");
  count("the browser surface source is readable", source.length > 0, WEB_SOURCE);

  for (var i = 0; i < HALF_OPERATION_CALLS.length; i += 1) {
    var shape = HALF_OPERATION_CALLS[i];
    var hits = [];
    var lines = source.split("\n");
    for (var n = 0; n < lines.length; n += 1) {
      if (lines[n].indexOf(shape) !== -1) hits.push(n + 1);
    }
    count("no '" + shape + "' call is left in lib/web/index.js",
      hits.length === 0, "line(s) " + hits.join(", "));
  }

  // The counterpart assertion, so the one above cannot pass on a file
  // that stopped calling the adapter altogether. A surface with no
  // adapter call is a surface doing the work somewhere else.
  for (var w = 0; w < WHOLE_OPERATION_VERBS.length; w += 1) {
    var verb = WHOLE_OPERATION_VERBS[w];
    count("lib/web/index.js drives mailbox." + verb + " instead",
      source.indexOf("mailbox." + verb + "(") !== -1, verb);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-delete-wiring");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });

    theAdapterCarriesTheWholeOperation(identity);
    aCompleteWiringIsAccepted(cfg, identity);
    aPartialAdapterIsRefusedAtConstruction(cfg, identity);
    anAdapterMissingOneVerbIsRefusedToo(cfg, identity);
    noHalfOperationSurvivesInTheSurface();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "web-delete-wiring", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to
// aggregate the suite total. Printing any other wording still exits
// zero, so the run would read as passing while contributing nothing to
// the count, which is the output a file asserting nothing produces.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    // Set the code rather than calling process.exit, which would tear
    // the process down before the stack above is flushed.
    process.exitCode = 1;
  });
}
