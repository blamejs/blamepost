// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The browser surface, composed the way the server composes it: a real
 * temporary data directory, a real vault, a real encrypted database and
 * the real message store underneath. Nothing here is stubbed.
 *
 * What this file pins is that the surface is reachable at all.
 * `lib/web` was two thousand lines nothing required: the composition
 * facade never built it, the command line never mounted it, and webmail,
 * the administration console, the JMAP mount and the readiness probe
 * were all present and none of them answered. A test that only exercised
 * the mail listeners reported that state as healthy.
 *
 * It also pins what the probes mean, and they do not mean the same
 * thing. `/healthz` is what a container runtime polls to decide whether
 * to KILL this process, and `/readyz` is what a load balancer polls to
 * decide whether to route to it. A closed store fails both, because a
 * process that cannot reach its mail is worth restarting. A listener
 * that was configured and did not bind fails only readiness: no restart
 * frees a port something else is holding, and killing the process takes
 * away the surface an operator would have read the reason from.
 *
 * The third case is the one a boolean could not carry. A listener this
 * server deliberately holds shut is not a failure on either probe, and
 * it is not silence either: it answers degraded and names what is being
 * held and why. The probe controller is driven directly here, which is
 * the same code path the endpoint runs without needing a socket.
 *
 * The rest of the file signs in and reads mail, because a surface that
 * answers is not yet a surface that answers only its own reader. Two
 * accounts are provisioned, one message each, and the routes are driven
 * over a loopback port the operating system hands out: the folder list,
 * a folder page, a message page, a mutation, and the JMAP methods that
 * answer the same questions to a client.
 *
 * Every one of those assertions pins one property. The message store
 * keeps a single flat namespace of folders and records no owner, so the
 * map from an account to the folders it owns exists in exactly one
 * place, the mailbox adapter, and a surface that asks anything else
 * lists the whole server. `b.mail.agent.folders` is the tempting wrong
 * answer: it takes an actor for its scope check and its audit trail and
 * then returns the store's folder table whole. A folder name accepted
 * back off a URL then reads the mail inside it, which is one account
 * reading another's over HTTP, so it is driven over a socket here rather
 * than argued about against a fake.
 *
 * The same drive covers the other half of that defect. A redirect built
 * from a constant folder name lands on whichever bootstrap folder the
 * store created under that name, which belongs to no account and is
 * empty for that reason, so the reader's own mail has to be visible on
 * the page the sign in leads to.
 *
 * Draining, and the certificate the browser port presents, belong to the
 * boot file, which takes every port this server binds.
 *
 * Run standalone: node test/layer-1-state/web.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var LOOPBACK = "127.0.0.1";
var DOMAIN   = "example.com";

var ALICE_PASSWORD = "quiet lantern bicycle 4291";
var BOB_PASSWORD   = "another quiet lantern 7715";

// Distinctive enough that finding one anywhere in a response body is
// proof the response carried that account's mail, rather than a
// coincidence of ordinary words in a page of markup.
var ALICE_SUBJECT = "Alices own quarterly note";
var BOB_SUBJECT   = "Bobs private quarterly numbers";
var BOB_BODY      = "zebra7741 belongs to bob and to nobody else";

// The six mailboxes every account is provisioned with. RFC 6154 names
// the five special use roles beside the inbox.
var DEFAULT_FOLDER_NAMES = ["INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive"];

// The adapter names each account's physical folders with this prefix.
// A name carrying it has escaped the one layer that maps an account to
// its folders, so seeing one in a page or in a JMAP answer is the leak
// itself rather than a cosmetic problem.
var STORE_FOLDER_PREFIX = "mbx_";

// Ceiling on the listener drain, so a shutdown that hangs fails as a
// bounded assertion rather than holding the runner until the job budget
// runs out. The per request ceiling belongs to the reader in
// test/helpers/browser.js.
var HTTP_TIMEOUT_MS = 5000;

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

// Assert a call refuses, and that the refusal names the thing that is
// wrong. Both halves matter: a wiring mistake that throws without saying
// which handle is missing costs the same debugging session as one that
// waited for the first request.
function refuses(label, pattern, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label,
    thrown !== null && pattern.test(String(thrown.message || thrown)),
    thrown === null ? "nothing was thrown" : thrown.message);
}

// Every handle the browser surface asks for, built from the modules
// `lib/index.js` builds them from, so this drives the composition that
// ships rather than a set of stand ins.
function wiringFor(cfg, identity, mailStore) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({ store: mailStore, dispatch: { mode: "local" } }),
    store:     identity,
    // The adapter answers which folders an account owns; the store under
    // it answers with folders and carries no owner at all.
    mailbox:   identity.mailbox,
    mailStore: mailStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: mailStore,
    }),
    dkim:     dkimHandle,
    delivery: deliveryHandle,
    config:   cfg,
  };
}

// ---- composition ----

function testFacadeExposesTheSurface() {
  check("blamepost exports the browser surface, so it can be required and driven",
    blamepost.web !== undefined && typeof blamepost.web.serve === "function");
  check("blamepost.web.create is the route builder the listener composes",
    typeof blamepost.web.create === "function");
}

function testServeDescribesItsPorts(wiring) {
  var listener = blamepost.web.serve(wiring);
  var shape = listener.describe();
  count("blamepost.web.serve.describe reports the cleartext port from the configuration",
    shape.httpPort === 8080, shape.httpPort);
  count("blamepost.web.serve takes no TLS port when no certificate was named",
    shape.httpsPort === null, shape.httpsPort);
  count("blamepost.web.serve binds every interface unless told otherwise",
    shape.address === "0.0.0.0", shape.address);
  check("blamepost.web.serve holds no port before start",
    Object.keys(shape.bound).length === 0);
  check("blamepost.web.serve carries the probe controller the endpoints run on",
    shape !== null && typeof listener.health.registerCheck === "function");
  check("blamepost.web.serve mounts JMAP inside the application rather than on a port",
    listener.jmap !== null && typeof listener.jmap.apiHandler === "function" &&
    typeof listener.jmap.sessionHandler === "function");
  return listener;
}

function testServeRefusesBadWiring(wiring, certFile, keyFile) {
  refuses("blamepost.web.serve names the handle that is missing", /agent/,
    function () {
      blamepost.web.serve(Object.assign({}, wiring, { agent: null }));
    });
  refuses("blamepost.web.serve names a message store that is not one", /mailStore/,
    function () {
      blamepost.web.serve(Object.assign({}, wiring, { mailStore: {} }));
    });
  refuses("blamepost.web.serve refuses a port that is not a port", /httpPort/,
    function () {
      blamepost.web.serve(Object.assign({}, wiring, { httpPort: "8080" }));
    });
  refuses("blamepost.web.serve refuses cleartext and TLS on the same port", /same port/,
    function () {
      blamepost.web.serve(Object.assign({}, wiring, {
        httpPort:  8443,
        httpsPort: 8443,
        tls:       { certFile: certFile, keyFile: keyFile },
      }));
    });
  refuses("blamepost.web.serve refuses half a certificate pair", /certFile, keyFile/,
    function () {
      blamepost.web.serve(Object.assign({}, wiring, { tls: { certFile: certFile } }));
    });
}

// ---- readiness ----

var WITHHELD_REASON = "this server hosts no domain, so there is nothing to receive for";

async function testProbeReportsUnboundListeners(wiring) {
  var table = [
    { name: "mx", state: "unbound", reason: "the listener is enabled and holds no port" },
    { name: "imap", state: "bound", reason: null },
  ];
  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    listeners: function () { return table; },
  }));

  var refusing = await listener.health.runChecks("readiness");
  count("readiness fails while a configured listener has not bound",
    refusing.status === "fail", refusing.status);
  count("the refusal names the listener that did not bind",
    refusing.checks.listeners.unbound.length === 1 &&
    refusing.checks.listeners.unbound[0] === "mx",
    JSON.stringify(refusing.checks.listeners));
  check("the refusal still finds the message store open",
    refusing.checks["mail-store"].ok === true);

  // The same table on the other probe. A runtime reading this one
  // decides whether to kill the process, and a port another process is
  // holding is still held after a restart.
  var live = await listener.health.runChecks("liveness");
  count("liveness does not fail on it, so a listener that did not bind is not answered " +
    "with a restart into the same failure",
    live.status === "degraded", live.status);

  // A listener held shut on purpose reaches the same place by a
  // different route, and the two have to stay distinguishable.
  table[0].state  = "withheld";
  table[0].reason = WITHHELD_REASON;
  var held = await listener.health.runChecks("readiness");
  count("a listener held shut on purpose does not fail readiness",
    held.status === "degraded", held.status);
  count("and the critical listener verdict is clean, so the failing state still means " +
    "a listener that failed",
    held.checks.listeners.ok === true, JSON.stringify(held.checks.listeners));
  count("the listener being held is named with the reason it is being held",
    held.checks["listeners-withheld"].withheld.length === 1 &&
    held.checks["listeners-withheld"].withheld[0].name === "mx" &&
    held.checks["listeners-withheld"].withheld[0].reason === WITHHELD_REASON,
    JSON.stringify(held.checks["listeners-withheld"]));

  table[0].state  = "bound";
  table[0].reason = null;
  var passing = await listener.health.runChecks("readiness");
  count("readiness passes once every listener is bound", passing.status === "ok",
    passing.status);

  // A state this application does not know is not a listener it can
  // report as fine. An unrecognized row read as one more healthy entry
  // is how an inventory nobody can parse passes every check under it.
  table[0].state = "probably-fine";
  var unknown = await listener.health.runChecks("readiness");
  count("a listener state this application does not recognize refuses rather than passing",
    unknown.status === "fail", unknown.status);
  table[0].state = "bound";

  return listener;
}

// What the probes answer about a certificate that has already run out.
//
// This is the state the certificate check exists for and the one it can
// never be shown in a running deployment, because this server refuses to
// boot on a certificate whose validity has closed. It is only reachable
// by a process that was already up when the date passed, so the reading
// is taken the way `blamepost.certificateReport` is built to allow: a
// real pair, on disk, measured at an instant past its expiry. The
// certificate engine mints whole positive days of life and nothing else,
// so a leaf that has already expired cannot be produced to read instead.
//
// The verdict is the assertion. Reduced on both probes and refused on
// neither: a liveness failure asks for a restart this server would not
// complete, and a readiness failure withdraws the browser surface, which
// is where an operator reads which of the two files went wrong and the
// one part of this server a certificate fault leaves working.
async function testProbeReportsAnExpiredCertificate(wiring, root) {
  var material = await certs.writePair(nodePath.join(root, "expired-tls"), {
    hostname: "mx.example.com",
  });
  var pastItsExpiry = Date.parse(material.expiresAt) + b.constants.TIME.days(1);

  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    listeners: function () { return [{ name: "imap", state: "bound", reason: null }]; },
    certificateReport: function () {
      return blamepost.certificateReport({
        certFile: material.certFile,
        keyFile:  material.keyFile,
        hostname: "mx.example.com",
        now:      pastItsExpiry,
      });
    },
  }));

  var ready = await listener.health.runChecks("readiness");
  count("an expired certificate reduces readiness rather than refusing it, because the " +
    "browser surface a proxy is terminating TLS in front of is serving exactly as before " +
    "and it is where the operator reads what went wrong",
    ready.status === "degraded", ready.status);
  count("and the reduced answer says the pair is not one this server could present, with " +
    "the days remaining gone negative rather than merely small",
    ready.checks.certificate.read === true &&
    ready.checks.certificate.ok === false &&
    ready.checks.certificate.usable === false &&
    ready.checks.certificate.expiresInDays < 0 &&
    ready.checks.certificate.faults.indexOf("certificate validity") !== -1,
    JSON.stringify(ready.checks.certificate));

  var live = await listener.health.runChecks("liveness");
  count("liveness is reduced too and does not fail, so nothing restarts a process into a " +
    "boot that refuses on the same certificate",
    live.status === "degraded", live.status);
}

// ---- a sealed key the TLS port cannot open ----

// An operator may seal the private key on the volume, and the browser
// surface unseals it on its way to the bind. There are exactly two ways
// it does not open: the bytes were written under a different volume's
// vault key, or they have been damaged where they lie. A seal
// authenticates what it carries end to end, so those two are
// indistinguishable from the outside and the refusal names both.
//
// The passphrase is not a third. It opens `vault.key.sealed` while the
// vault itself is being opened, which happens before anything binds and
// refuses the boot outright when it does not fit, so a bind that runs at
// all is running under a passphrase that fitted. Offering it as a cause
// sends an operator to check the one thing already proven correct. The
// reading the doctor composes says exactly this, and two copies of one
// sentence drift apart the moment only one of them is corrected.
//
// The vault is a stand-in on purpose: what is being read is the sentence
// this layer composes, and a real vault refusing for a real reason would
// be testing the vault instead.
async function testASealedKeyThatWillNotOpenNamesTheTwoCausesThereAre(wiring, root) {
  var dir = nodePath.join(root, "sealed-web-tls");
  var material = await certs.writePair(dir, { hostname: "mx.example.com" });
  var sealedKey = nodePath.join(dir, "sealed-privkey.pem");
  nodeFs.writeFileSync(sealedKey, "vault:not-openable-here\n", "utf8");

  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    httpPort:  0,
    httpsPort: 0,
    tls: {
      certFile: material.certFile,
      keyFile:  sealedKey,
      vault: {
        seal:   function (value) { return "vault:" + value; },
        unseal: function () { throw new Error("authentication tag mismatch"); },
      },
    },
  }));

  var thrown = null;
  try { await listener.start(); }
  catch (e) { thrown = e; }
  finally { await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS }); }

  var said = thrown === null ? "" : String(thrown.message || thrown);
  count("a sealed key the TLS port cannot open refuses the bind", thrown !== null, said);
  count("the refusal names the key written under another volume's vault key",
    /different volume's vault key/.test(said), said);
  count("and names damage in place, which is the other of the two and has the same remedy",
    /damaged where they lie/.test(said), said);
  count("and does not send the operator after the passphrase, which opens the vault at " +
    "start and stops the boot when it does not fit, so it cannot be the cause of a bind " +
    "that ran",
    said.indexOf("passphrase") === -1, said);
  count("and says what to do about it rather than only what happened",
    /Restore the file from a backup/.test(said), said);
}

async function testProbeFailsOnAClosedStore(wiring) {
  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    listeners: function () { return [{ name: "imap", state: "bound", reason: null }]; },
  }));
  check("the probe passes with the store open and the listeners bound",
    (await listener.health.runChecks("liveness")).status === "ok");

  store.close();
  // Both probes, because this is the one condition where a restart is
  // the right answer: the process is up and cannot reach its mail.
  var afterClose = await listener.health.runChecks("liveness");
  count("the liveness probe fails once the store is closed",
    afterClose.status === "fail", afterClose.status);
  check("the failed probe points at the message store",
    afterClose.checks["mail-store"].ok === false);
  check("readiness fails on it too",
    (await listener.health.runChecks("readiness")).status === "fail");
}

// ---- the substrate and the agent over it ----

// The substrate's write path is where the backend shim earns its place:
// the store wraps an append in `transaction(fn)()`, and a database handed
// over unwrapped runs the body on the first call and then throws on the
// result. Nothing catches that until the first message arrives.
function testTheSubstrateAcceptsAWrite(mailStore) {
  var raw = Buffer.from(
    "Message-ID: <probe.1@mx.example.com>\r\n" +
    "From: alice@example.com\r\n" +
    "To: bob@example.com\r\n" +
    "Subject: one message\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" +
    "body text\r\n", "utf8");
  var stored = mailStore.appendMessage("INBOX", raw, {});
  count("the message substrate takes an append, so the backend shim is in place",
    typeof stored.objectid === "string" && stored.objectid.length > 0,
    JSON.stringify(stored));
}

// The permission table the facade wires onto the agent. Without it the
// agent skips the scope check entirely, so an actor assembled without a
// role would read whatever it asked for.
async function testTheAgentChecksScopes(server) {
  var reader = { id: "probe-account", roles: ["account"] };
  var result = await server.mail.agent.folders({ actor: reader });
  count("an account reads its folders through the agent",
    result !== null && Array.isArray(result.folders), JSON.stringify(result));

  var thrown = null;
  try {
    await server.mail.agent.folders({ actor: { id: "probe-account", roles: [] } });
  } catch (e) { thrown = e; }
  count("an actor carrying no role is refused by the agent rather than served",
    thrown !== null && thrown.code === "mail-agent/permission-denied",
    thrown === null ? "nothing was thrown" : thrown.code);
}

// ---- the facade ----

function testCreateAttachesTheSurface(cfg, identity) {
  // The arguments the command line's serve verb passes, so this drives
  // the path an operator drives rather than a convenient rearrangement
  // of it. The wire adapter and the substrate the agent dispatches over
  // are two different handles, and handing the adapter to the agent is
  // the mistake this pins.
  check("the identity layer carries the wire adapter the listeners take",
    identity.mailbox !== undefined && typeof identity.mailbox.selectFolder === "function");

  // A real SecureContext carrying no certificate. Nothing binds in this
  // file, so nothing ever has to present one; what is under test is that
  // the facade wires the browser surface at all.
  var server = blamepost.create({
    config:     cfg,
    store:      identity,
    mailStore:  identity.mailbox,
    tlsContext: nodeTls.createSecureContext({}),
  });

  var shape = server.describe();
  count("blamepost.create describes the browser surface beside the mail listeners",
    shape.web !== undefined && shape.web.httpPort === 8080, JSON.stringify(shape.web));
  check("blamepost.create hands back the running browser listener",
    server.web !== undefined && typeof server.web.start === "function");
  check("blamepost.create builds the mailbox access agent the surface reads through",
    server.mail.agent !== undefined && typeof server.mail.agent.expunge === "function");
  check("blamepost.create leaves the browser surface unbound until start",
    Object.keys(shape.web.bound).length === 0);

  return server;
}

async function testCreateProbeSeesTheMailListeners(server) {
  var verdict = await server.web.health.runChecks("readiness");
  count("a server that has not started reports itself unfit to serve traffic",
    verdict.status === "fail", verdict.status);
  // The default listener set is MX, submission on both ports, IMAP and
  // ManageSieve. POP3 is off unless the operator turns it on.
  var unboundNames = verdict.checks.listeners.unbound;
  count("every enabled mail listener is reported unbound before start",
    unboundNames.indexOf("mx") !== -1 &&
    unboundNames.indexOf("submission") !== -1 &&
    unboundNames.indexOf("imap") !== -1 &&
    unboundNames.indexOf("managesieve") !== -1,
    JSON.stringify(unboundNames));
  count("a listener the operator turned off is not counted against readiness",
    unboundNames.indexOf("pop3") === -1, JSON.stringify(unboundNames));
  // It is still in the inventory, as what it is. Leaving it out would
  // make an absence carry the answer, and an absence is also what a
  // listener wrongly read as switched off would produce.
  count("and it is reported as switched off rather than left out of the inventory",
    verdict.checks.listeners.disabled.indexOf("pop3") !== -1,
    JSON.stringify(verdict.checks.listeners));
  count("the browser surface counts itself in the same table",
    unboundNames.indexOf("http") !== -1, JSON.stringify(unboundNames));

  // The other probe, on the same server. Nothing here is a reason to
  // kill a process that has not finished coming up, which is what a
  // failing liveness verdict asks a runtime to do.
  var live = await server.web.health.runChecks("liveness");
  count("liveness does not answer a server that has not started yet with a restart",
    live.status === "degraded", live.status);
}

// ---- a signed in reader, over a real port ----

function messageFor(recipient, subject, body) {
  return Buffer.from(
    "Message-ID: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

// The reader that drives the application the way a browser drives it,
// holding its cookies and taking the token off the rendered form, lives
// in test/helpers/browser.js. It is shared rather than copied because
// three files need it now, and two readers that disagree about what a
// sign in looks like is how one of them stops catching things.

// Every distinct folder name the page links to. The mailbox view links a
// folder as `/mail/<name>` and a message as `/mail/<name>/<id>`, so the
// trailing quote is what separates the two.
function linkedFolders(body) {
  var pattern = /href="\/mail\/([^"/]*)"/g;
  var names = [];
  var seen = Object.create(null);
  var hit = pattern.exec(body);
  while (hit !== null) {
    var name = decodeURIComponent(hit[1]);
    if (!seen[name]) {
      seen[name] = true;
      names.push(name);
    }
    hit = pattern.exec(body);
  }
  return names;
}

async function testSigningInReachesTheReadersOwnMail(reader) {
  var landed = await reader.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
  count("the sign in form carried a token for the reader to send back",
    reader.csrf().length > 0, JSON.stringify(reader.csrf()));
  count("a correct credential is answered with a redirect rather than the form again",
    landed.status === 302, landed.status + " " + landed.body.slice(0, 160));
  count("the redirect names a mailbox path",
    typeof landed.location === "string" && landed.location.indexOf("/mail/") === 0,
    landed.location);

  var inbox = await reader.get(landed.location);
  count("the mailbox the sign in leads to renders", inbox.status === 200, inbox.status);
  // The store bootstraps a folder set of its own under the same names.
  // A redirect built from a constant lands on one of those, which
  // belongs to no account, and the page then renders an empty mailbox
  // while the reader's mail sits in a folder the page never names.
  count("the mailbox it leads to is the one holding this reader's own message",
    inbox.body.indexOf(ALICE_SUBJECT) !== -1, inbox.body.slice(0, 200));
  return inbox;
}

function testTheFolderListHoldsOnlyTheReadersFolders(inbox, otherFolder) {
  var listed = linkedFolders(inbox.body);
  count("the folder list carries the six mailboxes this account owns",
    listed.length === DEFAULT_FOLDER_NAMES.length, listed.join(","));
  for (var i = 0; i < DEFAULT_FOLDER_NAMES.length; i += 1) {
    count("the reader's own " + DEFAULT_FOLDER_NAMES[i] + " is on the list",
      listed.indexOf(DEFAULT_FOLDER_NAMES[i]) !== -1, listed.join(","));
  }
  var leaked = listed.filter(function (name) {
    return name.indexOf(STORE_FOLDER_PREFIX) === 0;
  });
  count("no store folder name reaches the page", leaked.length === 0, leaked.join(","));
  count("the other account's folder is not on the list",
    listed.indexOf(otherFolder) === -1, listed.join(","));
}

async function testAnotherAccountsMailIsUnreachable(reader, other) {
  var otherFolder = other.storeFolder;
  var otherMessage = other.objectId;
  var folderPage = await reader.get("/mail/" + encodeURIComponent(otherFolder));
  count("a URL naming the other account's folder is refused rather than served",
    folderPage.status === 404 || folderPage.status === 403, folderPage.status);
  count("the refusal carries none of that account's mail",
    folderPage.body.indexOf(BOB_SUBJECT) === -1, folderPage.body.slice(0, 200));

  var messagePage = await reader.get("/mail/" + encodeURIComponent(otherFolder) +
    "/" + encodeURIComponent(otherMessage));
  count("a message inside the other account's folder is refused the same way",
    messagePage.status === 404 || messagePage.status === 403, messagePage.status);
  count("that refusal carries none of the message body",
    messagePage.body.indexOf(BOB_BODY) === -1, messagePage.body.slice(0, 200));

  // The same message id under a folder name this reader does own. The
  // name resolves, so the refusal has to come from the message lookup
  // being scoped to the folder behind that name rather than from the
  // name failing to match.
  var borrowed = await reader.get("/mail/INBOX/" + encodeURIComponent(otherMessage));
  count("the other account's message is refused under a folder name this reader does own",
    borrowed.status === 404 || borrowed.status === 403, borrowed.status);
  count("that refusal carries none of the message body either",
    borrowed.body.indexOf(BOB_BODY) === -1, borrowed.body.slice(0, 200));
}

// Reading is the loud half. A mutation through the same URL is the half
// that leaves no page behind for anyone to notice, so it runs last: a
// mutation that lands empties the folder, and every read assertion after
// it would then pass by finding nothing where the leak used to be.
async function testAMutationAimedAtAnotherAccountIsRefused(reader, identity, other) {
  var mutation = await reader.post("/mail/" + encodeURIComponent(other.storeFolder) + "/actions",
    "application/x-www-form-urlencoded",
    "action=trash&objectId=" + encodeURIComponent(other.objectId));
  count("a mutation aimed at the other account's folder is refused",
    mutation.status === 404 || mutation.status === 403, mutation.status);

  // A refusal is only a refusal if nothing moved. A route that files the
  // message and then answers 404 has done the damage and hidden it.
  var owner = identity.mailbox.selectFolder({ id: other.accountId }, "INBOX", {});
  count("the other account's inbox still holds its message after the refusal",
    owner.exists === 1, owner.exists);
}

async function testJmapAnswersForTheReaderAlone(reader, readerId, otherId, otherFolder, otherMessage) {
  var mailboxes = await reader.jmap([["Mailbox/get", { accountId: readerId }, "c0"]]);
  count("JMAP answers Mailbox/get for a signed in account", mailboxes.status === 200,
    mailboxes.status + " " + mailboxes.body.slice(0, 160));
  var mailboxList = JSON.parse(mailboxes.body).methodResponses[0][1].list;
  count("JMAP returns the six mailboxes this account owns",
    mailboxList.length === DEFAULT_FOLDER_NAMES.length, String(mailboxList.length));
  var storeIds = mailboxList.filter(function (row) {
    return String(row.id).indexOf(STORE_FOLDER_PREFIX) === 0;
  });
  count("no mailbox id is a store folder name", storeIds.length === 0,
    mailboxList.map(function (row) { return row.id; }).join(","));

  // RFC 8620 section 3.6.1. An accountId the actor is not enumerated for
  // is refused by name, so naming the other account is not a way around
  // the session.
  var borrowed = await reader.jmap([["Mailbox/get", { accountId: otherId }, "c0"]]);
  var borrowedAnswer = JSON.parse(borrowed.body).methodResponses[0];
  count("a JMAP call naming the other account's id is refused",
    borrowedAnswer[0] === "error" &&
    borrowedAnswer[1].type === "urn:ietf:params:jmap:error:accountNotFound",
    JSON.stringify(borrowedAnswer));

  var query = await reader.jmap([
    ["Email/query", { accountId: readerId, filter: { inMailbox: otherFolder } }, "c0"],
  ]);
  var queryAnswer = JSON.parse(query.body).methodResponses[0][1];
  count("an Email/query naming the other account's folder returns nothing",
    Array.isArray(queryAnswer.ids) && queryAnswer.ids.length === 0,
    JSON.stringify(queryAnswer.ids));

  var fetched = await reader.jmap([
    ["Email/get", { accountId: readerId, ids: [otherMessage] }, "c0"],
  ]);
  var fetchedAnswer = JSON.parse(fetched.body).methodResponses[0][1];
  count("an Email/get naming the other account's message answers not found",
    fetchedAnswer.list.length === 0 && fetchedAnswer.notFound.length === 1,
    JSON.stringify(fetchedAnswer.notFound));
  count("the Email/get answer carries none of that message's content",
    fetched.body.indexOf(BOB_SUBJECT) === -1 && fetched.body.indexOf(BOB_BODY) === -1,
    fetched.body.slice(0, 200));

  // The reader's own mail, through the same two methods, because an
  // isolation check that passes by answering nothing to anybody has
  // certified a broken mailbox rather than a private one.
  var own = await reader.jmap([
    ["Email/query", { accountId: readerId, filter: { inMailbox: "INBOX" } }, "c0"],
  ]);
  var ownIds = JSON.parse(own.body).methodResponses[0][1].ids;
  count("an Email/query over the reader's own inbox finds the reader's own message",
    Array.isArray(ownIds) && ownIds.length === 1, JSON.stringify(ownIds));

  var ownMessage = await reader.jmap([
    ["Email/get", { accountId: readerId, ids: ownIds }, "c0"],
  ]);
  var ownAnswer = JSON.parse(ownMessage.body).methodResponses[0][1];
  count("that message is the one addressed to the reader",
    ownAnswer.list.length === 1 && ownAnswer.list[0].subject === ALICE_SUBJECT,
    JSON.stringify(ownAnswer.notFound));
}

// The provisioning and the drive, in the order a reader meets them.
async function testIsolationOverTheBrowserSurface(identity, wiring) {
  await identity.domains.add({ domain: DOMAIN });
  var alice = await identity.accounts.create({
    address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
  var bob = await identity.accounts.create({
    address: "bob@" + DOMAIN, password: BOB_PASSWORD });

  identity.mailbox.appendMessage("INBOX",
    messageFor(alice.address, ALICE_SUBJECT, "alice body"), { actor: { id: alice.id } });
  var bobsStored = identity.mailbox.appendMessage("INBOX",
    messageFor(bob.address, BOB_SUBJECT, BOB_BODY), { actor: { id: bob.id } });

  // The other account's folder and message, read from the one layer that
  // holds the map. This is the test naming what a signed in stranger has
  // no legitimate route to, so that the routes can be proven shut.
  var bobsFolders = identity.mailbox.accountFolders({ id: bob.id });
  var bobsInbox = bobsFolders.filter(function (row) { return row.name === "INBOX"; })[0];
  var alicesFolders = identity.mailbox.accountFolders({ id: alice.id });
  var alicesInbox = alicesFolders.filter(function (row) { return row.name === "INBOX"; })[0];
  count("the two accounts hold their inboxes in different store folders",
    bobsInbox !== undefined && alicesInbox !== undefined &&
    bobsInbox.storeName !== alicesInbox.storeName,
    JSON.stringify([alicesInbox && alicesInbox.storeName, bobsInbox && bobsInbox.storeName]));
  count("the message under test is in the other account's inbox",
    typeof bobsStored.objectid === "string" && bobsStored.objectid.length > 0,
    JSON.stringify(bobsStored));

  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    address:   LOOPBACK,
    httpPort:  0,
    listeners: function () { return []; },
  }));
  try {
    var ports = await listener.start();
    count("the browser surface took an ephemeral loopback port",
      typeof ports.http === "number" && ports.http > 0, JSON.stringify(ports));

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var other = {
      accountId:  bob.id,
      storeFolder: bobsInbox.storeName,
      objectId:   bobsStored.objectid,
    };
    var inbox = await testSigningInReachesTheReadersOwnMail(reader);
    testTheFolderListHoldsOnlyTheReadersFolders(inbox, other.storeFolder);
    await testAnotherAccountsMailIsUnreachable(reader, other);
    await testJmapAnswersForTheReaderAlone(reader, alice.id, bob.id,
      other.storeFolder, other.objectId);
    await testAMutationAimedAtAnotherAccountIsRefused(reader, identity, other);
  } finally {
    await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS });
  }
}

// ---- runner ----

async function run() {
  var root = helpers.tempDir("web");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted at rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  // Two files that only have to exist. The certificate pair is read at
  // bind time and nothing here binds, so their contents never matter;
  // what they drive is the pair and collision checks at construction.
  var certFile = nodePath.join(root, "cert.pem");
  var keyFile  = nodePath.join(root, "key.pem");
  nodeFs.writeFileSync(certFile, "certificate bytes\n", "utf8");
  nodeFs.writeFileSync(keyFile, "key bytes\n", "utf8");

  try {
    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    var identity = await store.open(cfg);
    // The substrate the agent dispatches over, built the way the facade
    // builds it: on the framework database itself.
    var mailStore = b.mailStore.create({ backend: b.db });
    var wiring = wiringFor(cfg, identity, mailStore);

    testFacadeExposesTheSurface();
    testServeDescribesItsPorts(wiring);
    testServeRefusesBadWiring(wiring, certFile, keyFile);
    await testProbeReportsUnboundListeners(wiring);
    testTheSubstrateAcceptsAWrite(mailStore);

    var server = testCreateAttachesTheSurface(cfg, identity);
    await testCreateProbeSeesTheMailListeners(server);
    await testTheAgentChecksScopes(server);

    await testIsolationOverTheBrowserSurface(identity, wiring);
    await testProbeReportsAnExpiredCertificate(wiring, root);
    await testASealedKeyThatWillNotOpenNamesTheTwoCausesThereAre(wiring, root);

    // Last, because it closes the store out from under everything above.
    await testProbeFailsOnAClosedStore(wiring);
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "web", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
