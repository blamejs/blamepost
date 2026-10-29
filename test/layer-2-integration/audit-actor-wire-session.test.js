// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a row a mail session writes says where the command came from.
 *
 * `test/layer-1-state/audit-actor-attribution.test.js` asks this of the
 * administrative surfaces, where the principal is an account that signed
 * in to the browser or an operator at a terminal. This file asks it of
 * the wire, where the same question has two different answers and the
 * difference is the point.
 *
 * SECURITY.md tells an operator which column to read during an incident.
 * A session that authenticated has both halves: the account the
 * credential named, and the address the socket came from. A stranger's
 * connection has the second and not the first, and a refused credential
 * is given no first half on purpose, because the name a refused attempt
 * claimed is a name whoever is guessing chose. An operator reading the
 * trail after a break-in asks what else came from one address, and that
 * question is answerable only if the address is in the column the query
 * filters on rather than inside a metadata blob or absent altogether.
 *
 * What is driven:
 *
 *   - A refused IMAP CREATE from an authenticated session. The row has
 *     to name the account AND the loopback address the session came
 *     from.
 *   - The IMAP verbs that succeed, because a trail carrying the peer
 *     only on refusals cannot answer what else an address did.
 *   - The same claim on every protocol a session can be held on. IMAP,
 *     POP3, ManageSieve and submission each hold a session whose account
 *     is then suspended, and each refusal row has to name both halves.
 *     One protocol proving it says nothing about the other three: the
 *     rows are written from different handlers.
 *   - A submission session offering a message whose author it does not
 *     own, which is a refusal an operator reads during an account
 *     takeover.
 *   - The other direction, on the same run: a stranger refused at RCPT
 *     for a domain this server no longer hosts. That row names the peer
 *     and names NOBODY, and a run that proved only the first four cases
 *     would pass equally against a server that had started writing a
 *     claimed identity into the column an auditor trusts.
 *
 * Nothing external is needed. Every port is ephemeral on the loopback
 * interface and the volume is a temporary directory.
 *
 * Run standalone: node test/layer-2-integration/audit-actor-wire-session.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
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

var HOSTNAME         = "mx.example.com";
var DOMAIN           = "example.com";
var WITHDRAWN_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// How long a row is waited for. The trail is written through the sink
// every other row on this server goes through, so it lands a moment
// after the reply the client already read.
var ROW_TIMEOUT_MS = 8000;

// One ManageSieve reply line, the shape every command here answers with.
var ONE_SIEVE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

var ACTIONS = {
  createRefused: "blamepost.mail.listeners.imap_create_refused",
  create:        "blamepost.mail.listeners.imap_create",
  select:        "blamepost.mail.listeners.imap_select",
  search:        "blamepost.mail.listeners.imap_search",
  close:         "blamepost.mail.listeners.imap_close",
  stopped:       "blamepost.mail.listeners.session_account_stopped",
  authorRefused: "blamepost.mail.listeners.submission_from_not_owned",
  strangerRcpt:  "blamepost.mail.listeners.mx_recipient_domain_not_hosted",
};

// The message a submission session offers when the case is about the
// envelope rather than about the author.
function ownMail(from) {
  return "From: <" + from + ">\r\n" +
    "To: <" + from + ">\r\n" +
    "Subject: a message the account may write\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <own." + from.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.";
}

// The same message with somebody else's address in the author header,
// which the identity binding refuses at the handoff.
function borrowedMail(envelopeFrom, claimedAuthor) {
  return "From: <" + claimedAuthor + ">\r\n" +
    "To: <" + envelopeFrom + ">\r\n" +
    "Subject: a message naming an author this account does not hold\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <borrowed." + envelopeFrom.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.";
}

// The actor the message store wants for a seeded append.
function actorFor(row) {
  return {
    id:        row.id,
    username:  row.address,
    address:   row.address,
    domain:    row.domain,
    isAdmin:   false,
    mailboxes: [String(row.address).toLowerCase()],
    roles:     ["account"],
  };
}

function seedMail(to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: the message a wire session reads\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <seed." + to.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.\r\n", "utf8");
}

// ---- reading the rows ------------------------------------------------------

// One row under `action` that a predicate picks out, waited for rather
// than slept on. A predicate is taken because more than one session
// writes under the same action in one run, and the claim is about the
// row belonging to the session the case drove.
function rowMatching(audit, action, pick, label) {
  return helpers.waitUntil(function () {
    var found = audit.forAction(action).filter(pick);
    return found.length > 0 ? found[found.length - 1] : false;
  }, { timeoutMs: ROW_TIMEOUT_MS, label: "audit-actor-wire-session: " + label });
}

// Whether a row names the loopback address the session came from. The
// listener reads the peer off the socket, which on this platform is
// either the dotted form or the IPv4-mapped IPv6 one, so the claim is
// that the address is in there rather than that it is spelled one way.
function namesTheLoopbackPeer(row) {
  return typeof row.actorIp === "string" && row.actorIp.indexOf(LOOPBACK) !== -1;
}

// What a failing check quotes, so a run that reports a missing column
// says which columns the row did carry.
function actorColumns(row) {
  return "actorUserId=" + JSON.stringify(row && row.actorUserId) +
    " actorIp=" + JSON.stringify(row && row.actorIp) +
    " actorSessionId=" + JSON.stringify(row && row.actorSessionId);
}

// ---- cases -----------------------------------------------------------------

// The vector this file exists for. An account holder's client asks for a
// mailbox name that is already taken, the server refuses, and an
// operator reading the trail afterwards is told who and from where.
async function aRefusedImapVerbNamesTheAccountAndThePeer(ctx) {
  var session = await ctx.imapSession(ctx.alice, "create-refused");

  var refused = await session.imapAsk("CREATE INBOX", "CREATE INBOX refused");
  count("CREATE of a name the account already holds is refused on the wire",
    refused.verdict === "NO", visible(refused.text));

  var row = await rowMatching(ctx.audit, ACTIONS.createRefused, function (candidate) {
    return candidate.actorUserId === ctx.alice.id || candidate.actorUserId === null;
  }, "the refused CREATE row");

  count("the refused CREATE names the account that sent it",
    row.actorUserId === ctx.alice.id, actorColumns(row));
  count("and it names the address the session came from, which is the column an operator " +
    "filters on when they ask what else came from one peer",
    namesTheLoopbackPeer(row), actorColumns(row));
  count("and it names the connection the command was sent on, so two sessions held by one " +
    "account are told apart",
    typeof row.actorSessionId === "string" && row.actorSessionId.length > 0,
    actorColumns(row));

  session.close();
}

// A trail that carries the peer only where something was refused cannot
// answer the question an incident actually asks, which is what else the
// same address did while it held a session.
async function theImapVerbsThatSucceedNameThemToo(ctx) {
  var session = await ctx.imapSession(ctx.alice, "verbs-succeeding");

  var made = await session.imapAsk("CREATE Receipts", "CREATE Receipts");
  count("CREATE of a free name completes", made.verdict === "OK", visible(made.text));

  var selected = await session.imapAsk('SELECT "INBOX"', "SELECT INBOX");
  count("SELECT opens INBOX", selected.verdict === "OK", visible(selected.text));

  var searched = await session.imapAsk("SEARCH ALL", "SEARCH ALL");
  count("SEARCH answers", searched.verdict === "OK", visible(searched.text));

  var closed = await session.imapAsk("CLOSE", "CLOSE");
  count("CLOSE completes", closed.verdict === "OK", visible(closed.text));

  var names = ["create", "select", "search", "close"];
  for (var i = 0; i < names.length; i += 1) {
    var action = ACTIONS[names[i]];
    var row = await rowMatching(ctx.audit, action, function (candidate) {
      return candidate.actorUserId === ctx.alice.id || candidate.actorUserId === null;
    }, "the " + names[i] + " row");
    count("the " + names[i] + " row names the account", row.actorUserId === ctx.alice.id,
      actorColumns(row));
    count("and the " + names[i] + " row names the peer", namesTheLoopbackPeer(row),
      actorColumns(row));
  }

  session.close();
}

// The same claim, on each protocol a session can be held on. The rows
// come out of different handlers, so one protocol proving it says
// nothing about the other three.
async function everyProtocolNamesBothHalvesWhenTheAccountStops(ctx) {
  for (var i = 0; i < ctx.suspendable.length; i += 1) {
    var subject = ctx.suspendable[i];
    var session = await subject.open(ctx);

    await subject.serves(session);

    await ctx.identity.accounts.suspend({
      id: subject.account.id, reason: "the credential was reported stolen" });

    var refused = await subject.ask(session);
    count(subject.protocol + " stops serving the session that was already open",
      refused.ok === false, refused.text);

    var row = await rowMatching(ctx.audit, ACTIONS.stopped, function (candidate) {
      return helpers.metadataOf(candidate).accountId === subject.account.id;
    }, subject.protocol + ": the refusal row");

    count("the " + subject.protocol + " refusal names the account whose session it was",
      row.actorUserId === subject.account.id, actorColumns(row));
    count("and the " + subject.protocol + " refusal names the address it came from",
      namesTheLoopbackPeer(row), actorColumns(row));

    session.close();
  }
}

// An account offering a message whose author it does not hold. This is
// the row an operator reads during a takeover, and the address the
// attempt came from is the whole of what they can act on.
async function aBorrowedAuthorNamesTheAccountAndThePeer(ctx) {
  var session = await Wire.submission(ctx.ports.submission, {
    caPem: ctx.caPem, servername: HOSTNAME,
    address: ctx.alice.address, password: PASSWORD,
    label: "audit-actor-wire-session submission author",
  });
  ctx.track(session);

  session.send("MAIL FROM:<" + ctx.alice.address + ">");
  var from = await session.read(/^\d{3} /m, "MAIL FROM answered");
  count("the account's own envelope sender is accepted", /^250/m.test(from), visible(from));

  session.send("RCPT TO:<" + ctx.alice.address + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  var invited = await session.read(/^\d{3} /m, "DATA answered");
  count("the message is invited", /^354/m.test(invited), visible(invited));

  session.sendRaw(borrowedMail(ctx.alice.address, ctx.bob.address) + "\r\n.\r\n",
    "<a message naming another account as its author>");
  var answered = await session.read(/^\d{3} /m, "the message answered");
  count("a message naming an author this account does not hold is refused",
    /^5\d\d/m.test(answered), visible(answered));

  var row = await rowMatching(ctx.audit, ACTIONS.authorRefused, function (candidate) {
    return candidate.actorUserId === ctx.alice.id || candidate.actorUserId === null;
  }, "the refused author row");

  count("the refused author row names the account that offered the message",
    row.actorUserId === ctx.alice.id, actorColumns(row));
  count("and it names the address the submission session came from",
    namesTheLoopbackPeer(row), actorColumns(row));

  session.close();
}

// The other direction, and the reason the four cases above are not the
// whole claim. A stranger at port 25 proved nothing, so the column that
// answers who acted stays empty and the peer is the whole of what the
// row can stand behind.
async function aStrangerIsNamedByPeerAndByNobody(ctx) {
  await ctx.identity.domains.setStatus({
    domain: WITHDRAWN_DOMAIN, status: "disabled",
    reason: "audit actor wire session: withdrawn while the listener holds port 25",
  });

  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME,
    label: "audit-actor-wire-session mx stranger",
    helo: "peer.example.net",
  });
  ctx.track(peer);

  peer.send("MAIL FROM:<sender@example.net>");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + ctx.ivy.address + ">");
  var reply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  count("a recipient at a domain this server no longer hosts is refused",
    /^5\d\d/m.test(reply), visible(reply));

  var row = await rowMatching(ctx.audit, ACTIONS.strangerRcpt, function () { return true; },
    "the stranger's refusal row");

  count("the stranger's refusal names the address it came from",
    namesTheLoopbackPeer(row), actorColumns(row));
  count("and it names nobody, because a peer that presented no credential proved no " +
    "identity and a claimed one would be a name the peer chose",
    row.actorUserId === null, actorColumns(row));

  var metadata = helpers.metadataOf(row);
  count("the peer is recorded once, in the column a query filters on rather than in the " +
    "blob beside it", metadata.remoteAddress === undefined, JSON.stringify(metadata));

  peer.send("QUIT");
  peer.close();
}

// ---- the subjects that hold a session --------------------------------------

function imapSubject(account) {
  return {
    protocol: "IMAP",
    account:  account,
    open:     async function (ctx) {
      var session = await ctx.imapSession(account, "stopped-imap");
      var selected = await session.imapAsk('SELECT "INBOX"', "SELECT INBOX");
      count("the IMAP session opens INBOX before anything changes",
        selected.verdict === "OK", visible(selected.text));
      return session;
    },
    serves:   async function (session) {
      var listed = await session.imapAsk('LIST "" "*"', "LIST answered");
      count("IMAP serves the session while the mailbox is in service",
        listed.verdict === "OK", visible(listed.text));
    },
    ask:      async function (session) {
      var answer = await session.imapAsk('LIST "" "*"', "LIST after the suspension");
      return { ok: answer.verdict === "OK", text: visible(answer.text) };
    },
  };
}

function pop3Subject(account) {
  return {
    protocol: "POP3",
    account:  account,
    open:     function (ctx) { return ctx.pop3Session(account, "stopped-pop3"); },
    serves:   async function (session) {
      session.send("STAT");
      var stat = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("POP3 serves the session while the mailbox is in service",
        /^\+OK/m.test(stat), visible(stat));
    },
    ask:      async function (session) {
      session.send("STAT");
      var stat = await session.read(/^(\+OK|-ERR)/m, "STAT after the suspension");
      return { ok: /^\+OK/m.test(stat), text: visible(stat) };
    },
  };
}

function manageSieveSubject(account) {
  return {
    protocol: "ManageSieve",
    account:  account,
    open:     function (ctx) { return ctx.sieveSession(account, "stopped-managesieve"); },
    serves:   async function (session) {
      session.send("LISTSCRIPTS");
      var listed = await session.read(ONE_SIEVE_REPLY, "LISTSCRIPTS answered");
      count("ManageSieve serves the session while the mailbox is in service",
        /^OK/.test(wire.lastManageSieveReply(listed)), visible(listed));
    },
    ask:      async function (session) {
      session.send("LISTSCRIPTS");
      var listed = await session.read(ONE_SIEVE_REPLY, "LISTSCRIPTS after the suspension");
      return { ok: /^OK/.test(wire.lastManageSieveReply(listed)), text: visible(listed) };
    },
  };
}

function submissionSubject(account) {
  async function offer(session, what) {
    session.send("MAIL FROM:<" + account.address + ">");
    var from = await session.read(/^\d{3} /m, "MAIL FROM " + what);
    if (!/^250/m.test(from)) return { ok: false, text: visible(from) };
    session.send("RCPT TO:<" + account.address + ">");
    var rcpt = await session.read(/^\d{3} /m, "RCPT TO " + what);
    if (!/^25\d/m.test(rcpt)) return { ok: false, text: visible(rcpt) };
    session.send("DATA");
    var invited = await session.read(/^\d{3} /m, "DATA " + what);
    if (!/^354/m.test(invited)) return { ok: false, text: visible(invited) };
    session.sendRaw(ownMail(account.address) + "\r\n.\r\n", "<the message>");
    var accepted = await session.read(/^\d{3} /m, "the message " + what);
    return { ok: /^250/m.test(accepted), text: visible(accepted) };
  }
  return {
    protocol: "submission",
    account:  account,
    open:     function (ctx) { return ctx.submissionSession(account, "stopped-submission"); },
    serves:   async function (session) {
      var answer = await offer(session, "while the mailbox is in service");
      count("submission serves the session while the mailbox is in service",
        answer.ok === true, answer.text);
    },
    ask:      function (session) { return offer(session, "after the suspension"); },
  };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("audit-actor-wire");
  var dataDir = helpers.dataDir(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;
  var audit    = null;
  var sessions = [];
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "audit actor wire session" });
    await identity.domains.add({ domain: WITHDRAWN_DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: WITHDRAWN_DOMAIN, by: "audit actor wire session" });

    async function standUp(local, domain) {
      var row = await identity.accounts.create({
        address: local + "@" + domain, password: PASSWORD });
      identity.mailbox.appendMessage("INBOX", seedMail(row.address), { actor: actorFor(row) });
      return row;
    }

    var alice = await standUp("alice", DOMAIN);
    var bob   = await standUp("bob", DOMAIN);
    var ivy   = await standUp("ivy", WITHDRAWN_DOMAIN);
    var perProtocol = {
      imap:        await standUp("imapholder", DOMAIN),
      pop3:        await standUp("pop3holder", DOMAIN),
      managesieve: await standUp("sieveholder", DOMAIN),
      submission:  await standUp("sendholder", DOMAIN),
    };

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS at the end of DATA and this process has no resolver.
        // Everything the stranger case asserts is decided at RCPT,
        // before that gate runs at all.
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;
    audit = helpers.auditCapture();

    function ladder(open, label) {
      return async function (account, what) {
        var session = await open(Object.assign({}, {
          caPem:      material.caPem,
          servername: HOSTNAME,
          address:    account.address,
          password:   PASSWORD,
          label:      "audit-actor-wire-session " + label + "/" + what,
        }));
        sessions.push(session);
        return session;
      };
    }

    var ctx = {
      identity: identity,
      audit:    audit,
      caPem:    material.caPem,
      alice:    alice,
      bob:      bob,
      ivy:      ivy,
      ports:    {
        mx:          sections.mx.port,
        submission:  sections.submission.port,
        imap:        sections.imap.port,
        pop3:        sections.pop3.port,
        managesieve: sections.managesieve.port,
      },
      track:    function (session) { sessions.push(session); },
      imapSession: ladder(function (o) { return Wire.imap(sections.imap.port, o); }, "imap"),
      pop3Session: ladder(function (o) { return Wire.pop3(sections.pop3.port, o); }, "pop3"),
      sieveSession: ladder(
        function (o) { return Wire.managesieve(sections.managesieve.port, o); }, "managesieve"),
      submissionSession: ladder(
        function (o) { return Wire.submission(sections.submission.port, o); }, "submission"),
    };
    ctx.suspendable = [
      imapSubject(perProtocol.imap),
      pop3Subject(perProtocol.pop3),
      manageSieveSubject(perProtocol.managesieve),
      submissionSubject(perProtocol.submission),
    ];

    await aRefusedImapVerbNamesTheAccountAndThePeer(ctx);
    await theImapVerbsThatSucceedNameThemToo(ctx);
    await everyProtocolNamesBothHalvesWhenTheAccountStops(ctx);
    await aBorrowedAuthorNamesTheAccountAndThePeer(ctx);
    await aStrangerIsNamedByPeerAndByNobody(ctx);

    sessions.forEach(function (s) { s.close(); });
    sessions = [];

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) {
      try { s.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    });
    if (audit) {
      try { audit.release(); }
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
  name:      "audit-actor-wire-session",
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
