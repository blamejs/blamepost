// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Withdrawing a hosted domain has to change what port 25 accepts, now,
 * on the running process.
 *
 * The framework's MX listener reads the hosted set per recipient at RCPT
 * with an `indexOf` (`mail-server-mx.js`, `localDomains`), from what it
 * was given at construction. `lib/mail/listeners.js` gives it an array,
 * built once in `start()` from the domains the store called active at
 * that moment, so the set a listener was built with is the set it keeps
 * until something builds another one.
 *
 * The option also takes a function, answered per recipient. This server
 * does not pass one: that resolver is synchronous and the hosted set here
 * is a store read, so the function form needs a live in-memory mirror of
 * the domain table rather than a different argument, and it would move
 * the refusal into the framework's relay check, which writes no audit
 * row. So the array stays and the currency is answered below.
 *
 * So an operator disables a hosted domain, every management surface
 * agrees it is gone, and the listener that is actually holding port 25
 * has never been told. What the peer meets then is not a delivery: the
 * message store still refuses every recipient, so nothing lands in a
 * mailbox. What it meets is `250` at RCPT for an address this server
 * says it no longer serves, an invitation to transmit the entire
 * message, and a `451` at the end of it, repeated for the whole of that
 * peer's retry window. `250` to a stranger's recipient is the answer an
 * open relay gives and the answer a scanner records, and it is the
 * exact shape the zero domain case next door refuses to bind for.
 *
 * Removing a domain is the same defect through a different branch, and
 * it is the worse one. Before the removal, an address at that domain is
 * refused at RCPT with `550`, because the domain is hosted and holds no
 * mailbox. After it, the store answers that the address is not local at
 * all, the recipient policy reads that as somebody else's question and
 * stands aside, and the same address starts being accepted. Removing a
 * domain makes the listener more permissive about it than hosting it
 * was.
 *
 * Both are answered at the one live question the composition already
 * asks per recipient. `recipientPolicy` runs on every RCPT and resolves
 * the address against the store at that moment, so the current state of
 * the domain is already in its hand; it was being read and then
 * discarded.
 *
 * The cases run against ONE server that is never restarted, because a
 * restart is the thing that hides the bug.
 *
 * Run standalone: node test/layer-2-integration/mx-hosted-domain-currency.test.js
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
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";

// The domain that holds a mailbox. It is switched off and back on
// again, which is the case an operator reaches through `blamepost
// domain` and the one they can reverse.
var DOMAIN = "example.com";

// A second hosted domain holding nothing, because `domains.remove`
// refuses while any account or alias still belongs to the domain. An
// empty one is the only kind that can be removed from a running server,
// and it is enough: the question is what the listener answers for a
// domain that has left the hosted set, not what was in it.
var SPARE_DOMAIN = "spare.example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The sender a peer writes. Nobody here owns it, which is what an
// inbound peer looks like.
var PEER_SENDER = "postmaster@peer.example.net";

// The action the refusal is filed under. Read from the test rather than
// from the module so a rename has to be a decision: the row is what an
// operator greps for months later, when the symptom is mail that
// bounced and the cause is a domain somebody switched off.
var DOMAIN_NOT_HOSTED = "blamepost.mail.listeners.mx_recipient_domain_not_hosted";

var count = helpers.count;

// ---- the fixture -----------------------------------------------------------

// One server, two hosted domains, one mailbox, and no restart for the
// whole of the run. Every case below takes a fresh SMTP session against
// the same bound listener, so what changes between them is the store
// and nothing else.
async function withServer(body) {
  var root    = helpers.tempDir("hosted-domain-currency");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable. Pointing it inside the test's
  // own tree keeps the encrypted at rest path exactly as it ships.
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
      // The classical bridge rather than the CA default: this
      // certificate exists so a node:tls handshake happens on loopback,
      // and node verifies this algorithm on every runtime the suite runs.
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

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "hosted domain currency test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    await identity.domains.add({ domain: SPARE_DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: SPARE_DOMAIN, by: "hosted domain currency test" });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS at the end of DATA and this process has no resolver,
        // so enforce mode would defer on a lookup error and the cases
        // would be measuring the absence of DNS. Everything asserted here
        // is decided at RCPT, before that gate runs at all.
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });

    await server.start();
    running = true;

    await body({
      server:   server,
      identity: identity,
      caPem:    leaf.ca,
      mxPort:   sections.mx.port,
      alice:    alice.address,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
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

// One RCPT, asked over a session of its own, and the reply to it.
//
// A session each rather than one held open across the run, because the
// listener resolves the recipient per RCPT and a connection that
// straddles a store change would leave which side of it a reply came
// from up to timing. Opening a new one makes the ordering the test's
// rather than the socket's.
async function rcptReply(ctx, label, recipient) {
  var peer = await Wire.mx(ctx.mxPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    helo: "peer.example.net",
  });
  peer.send("MAIL FROM:<" + PEER_SENDER + ">");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + recipient + ">");
  var reply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

// ---- cases -----------------------------------------------------------------

// The control. A domain that is still hosted and a mailbox that exists
// are accepted, so every refusal below is the store's answer about that
// domain rather than a listener that stopped working.
async function anActiveDomainIsStillAccepted(ctx) {
  var reply = await rcptReply(ctx, "active-domain", ctx.alice);
  count("a mailbox at a domain that is still hosted is accepted at RCPT",
    /^250 /m.test(reply), visible(reply));
}

// The finding. The domain is switched off on the running server and the
// very next session has to be told so.
async function aWithdrawnDomainIsRefusedWithoutARestart(ctx) {
  await ctx.identity.domains.setStatus({
    domain: DOMAIN, status: "disabled",
    reason: "hosted domain currency test: withdrawn while the listener holds port 25",
  });

  var reply = await rcptReply(ctx, "withdrawn-domain", ctx.alice);
  count("a mailbox at a withdrawn domain is refused at RCPT, with no restart in between",
    /^550 /m.test(reply), visible(reply));
  count("and the refusal is permanent, so the sender reports rather than retrying forever",
    /^5\d\d /m.test(reply) && /5\.\d\.\d/.test(reply), visible(reply));
  count("and it says the domain is not served here rather than naming a mailbox",
    /does not handle mail for that domain/i.test(reply), visible(reply));
}

// The peer must not be invited to transmit a message it has no
// recipient for. A refusal at RCPT that still ends in `354` costs the
// peer the whole message on every retry, which is most of what makes
// the accept-then-refuse shape expensive.
async function aWithdrawnDomainNeverReachesTheMessage(ctx) {
  var peer = await Wire.mx(ctx.mxPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "withdrawn-no-data",
    helo: "peer.example.net",
  });
  peer.send("MAIL FROM:<" + PEER_SENDER + ">");
  var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + ctx.alice + ">");
  await peer.read(/^\d{3} /m, "RCPT TO answered");
  peer.send("DATA");
  var dataReply = await peer.read(/^\d{3} /m, "DATA answered");
  count("the peer is never invited to send a message for a withdrawn domain",
    !/^354 /m.test(dataReply), visible(mailReply) + " then " + visible(dataReply));
  peer.send("QUIT");
  peer.close();
}

// The row an operator reads afterwards. The wire reply deliberately
// tells a stranger nothing about whether this server ever hosted the
// domain, so the distinction between switched off and removed lives
// here or nowhere.
async function theRefusalIsOnTheAuditChain() {
  await b.audit.flush();
  var rows = await b.audit.query({ action: DOMAIN_NOT_HOSTED, limit: 50 });
  count("a recipient refused for its domain is on the audit chain under its own action",
    Array.isArray(rows) && rows.length >= 1,
    Array.isArray(rows) ? rows.length + " row(s)" : String(rows));
  if (!Array.isArray(rows) || rows.length === 0) return;

  count("and it is filed as a denial rather than a failure",
    rows.every(function (row) { return row.outcome === "denied"; }),
    JSON.stringify(rows.map(function (row) { return row.outcome; })));

  var text = JSON.stringify(rows);
  count("the row names the domain that is no longer served",
    text.indexOf(DOMAIN) !== -1, "looked for " + DOMAIN);
  count("and it names which of the two states the domain is in",
    text.indexOf("disabled") !== -1, text);
}

// Withdrawal is reversible, and the reversal has to be as immediate as
// the withdrawal was. An operator who switches a domain back on and
// finds mail still bouncing has been given a one way door.
async function aReEnabledDomainIsAcceptedAgainWithoutARestart(ctx) {
  await ctx.identity.domains.setStatus({
    domain: DOMAIN, status: "active",
    reason: "hosted domain currency test: brought back while the listener holds port 25",
  });
  var reply = await rcptReply(ctx, "re-enabled-domain", ctx.alice);
  count("a domain switched back on is accepted again, with no restart in between",
    /^250 /m.test(reply), visible(reply));
}

// The sibling branch. A hosted domain holding no mailbox refuses the
// address; the same domain removed has to keep refusing it. Both halves
// are asserted, because the defect is that the second is more
// permissive than the first.
async function aRemovedDomainIsRefusedWithoutARestart(ctx) {
  var before = await rcptReply(ctx, "spare-hosted", "anyone@" + SPARE_DOMAIN);
  count("an address at a hosted domain that holds no mailbox is refused at RCPT",
    /^550 /m.test(before), visible(before));

  await ctx.identity.domains.remove({
    domain: SPARE_DOMAIN,
    reason: "hosted domain currency test: removed while the listener holds port 25",
  });

  var after = await rcptReply(ctx, "spare-removed", "anyone@" + SPARE_DOMAIN);
  count("and removing the domain does not start accepting it, with no restart in between",
    /^550 /m.test(after), visible(after));
  count("the removed domain is refused for not being served here",
    /does not handle mail for that domain/i.test(after), visible(after));
}

// The check the recipient policy was already performing. A live domain
// question must not have displaced the local part question that shares
// the hook with it.
async function theLocalPartRefusalStillHolds(ctx) {
  var reply = await rcptReply(ctx, "no-such-mailbox", "nobody@" + DOMAIN);
  count("a name that holds no mailbox at a hosted domain is still refused at RCPT",
    /^550 /m.test(reply), visible(reply));
  count("and it is still refused as a missing mailbox rather than as a missing domain",
    /No mailbox by that name/i.test(reply), visible(reply));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    await anActiveDomainIsStillAccepted(ctx);
    await aWithdrawnDomainIsRefusedWithoutARestart(ctx);
    await aWithdrawnDomainNeverReachesTheMessage(ctx);
    await theRefusalIsOnTheAuditChain();
    await aReEnabledDomainIsAcceptedAgainWithoutARestart(ctx);
    await aRemovedDomainIsRefusedWithoutARestart(ctx);
    await theLocalPartRefusalStillHolds(ctx);
  });
  return helpers.getChecks();
}

module.exports = { name: "mx-hosted-domain-currency", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
