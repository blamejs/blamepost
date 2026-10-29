// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A correct password on a mailbox that is out of service, offered on
 * every surface a credential arrives on.
 *
 * `blamepost.store.accounts.authenticate` refuses a sign in twice over.
 * It refuses a password that does not match, and it refuses a password
 * that DOES match when the account's own status is not active or when
 * the domain the address belongs to is not active. The second half is
 * the one an operator reaches for during an incident: they suspend a
 * mailbox whose password they believe somebody else is holding, and the
 * password is still the right one.
 *
 * Five surfaces funnel into that one verb. `lib/mail/listeners.js`
 * builds one verifier and gives it to IMAP, POP3, ManageSieve and
 * submission; `lib/web/index.js` calls the same verb from the sign-in
 * form. Nothing drove the refusal past the verb on any of them.
 * `test/layer-1-state/account-state-matrix.test.js` asks the same
 * question of the identity layer and says in as many words that the
 * wire side is asked where the sockets are, which is here.
 *
 * What is driven, on all five surfaces:
 *
 *   - The control. An account in service on a hosted domain signs in.
 *     Without it every refusal below is satisfied by a listener that
 *     stopped accepting anything.
 *   - Every status that is not active, taken from the store's own frozen
 *     list rather than spelled out, so a fifth status added to the store
 *     arrives here as a failing vector rather than as a silent hole.
 *     Each account holds the password it was created with and presents
 *     it correctly, so the only thing between it and the mailbox is the
 *     state.
 *   - An account whose own status is active on a domain the operator has
 *     withdrawn. That is a second gate with a second reason, and an
 *     implementation reading only the account row passes every case
 *     above and fails this one.
 *   - The reinstatement. A suspended mailbox returned to service signs
 *     in again, on every surface, which is what separates a gate from a
 *     listener that has started refusing that address for good.
 *
 * The browser surface carries one thing the wire protocols do not. RFC
 * 9051 section 6.2.2, RFC 4954 section 6 and RFC 5804 section 1.2 all
 * answer a failed authentication with one verdict and no diagnosis, so
 * what a mail client can be told is whether it was let in. A person
 * reading the sign-in page can be told more, and is: a held mailbox
 * draws the sentence for the state it is held in, so somebody whose
 * password is already right is not sent to reset it. Those sentences are
 * asserted per state.
 *
 * JMAP takes no credential of its own. It answers under the session the
 * sign-in form mints, so a refused sign-in leaves nothing for it to
 * answer under, and the session document is asked after each refusal to
 * settle that rather than assume it.
 *
 * Nothing external is needed. Every port is ephemeral on the loopback
 * interface and the volume is a temporary directory.
 *
 * Run standalone: node test/layer-2-integration/account-status-wire-signin.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME        = "mx.example.com";
var DOMAIN          = "example.com";
var WITHDRAWN_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// One password for every subject here. Each account presents its own
// correct password on every attempt, so a refusal can only be the state:
// a run where one subject held a wrong password would report the gate
// working while measuring the credential compare.
var PASSWORD = "quiet lantern bicycle 4291";

var ACTIVE_ADDRESS    = "clara@" + DOMAIN;
var WITHDRAWN_ADDRESS = "ivy@" + WITHDRAWN_DOMAIN;

// What keeps an erasure from finishing, so the run holds a real
// `erasing` row rather than a status written onto one by hand. A
// preservation order over one message the erasure was asked to destroy
// keeps the mail, and the mail keeps the identity that owns it.
var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Every status that is not active, read off the store's frozen list.
// Spelling them out here is what this file exists to stop: a gate
// written as a list of states passes its own test and misses whichever
// member nobody thought of.
var OUT_OF_SERVICE = tables.ACCOUNT_STATUS.filter(function (name) {
  return name !== "active";
});

// The sentence the sign-in page shows for each state. A person whose
// password is already right needs to be told which of these it is:
// two of the three are lifted by the operator and the third is not
// lifted at all, so a shared sentence would send half the readers to
// ask for something nobody can do.
var SIGN_IN_SENTENCE = Object.freeze({
  suspended: "That account is suspended. The operator can reinstate it.",
  archived:  "That account is archived and no longer accepts sign in. The operator " +
             "can reopen it.",
  erasing:   "That account is being erased and cannot be reopened. Ask the operator " +
             "what is left of it.",
});

// What a reader is told when the address and the password do not name a
// mailbox this server will open, and what a withdrawn domain draws. The
// domain's state is the operator's business rather than the stranger's,
// so it is deliberately not named.
var UNMATCHED_SENTENCE = "That address and password do not match an account here.";

function addressFor(status) {
  return status + "@" + DOMAIN;
}

// The message a preservation order is placed over. The adapter keeps the
// bytes it was handed rather than a re-encoding, so anything built
// another way would not be a message this server could serve back.
function heldMail(to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: the record an order keeps\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <held." + to.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.\r\n", "utf8");
}

// ---- one sign-in attempt, per surface --------------------------------------
//
// Each answers `{ ok, text }`: whether the surface admitted the
// credential, and what it said. The four wire surfaces go through the
// shared session ladders, which raise a greeting, upgrade, verify the
// chain against this run's own authority and authenticate, and which
// throw rather than hand back a session they could not raise. That throw
// quotes the verdict, so a refusal here carries the transcript the
// listener actually wrote.

async function wireAttempt(ladder, port, caPem, address, password, label) {
  var session = null;
  try {
    session = await ladder(port, {
      caPem:      caPem,
      servername: HOSTNAME,
      label:      label,
      address:    address,
      password:   password,
    });
    return { ok: true, text: "the listener admitted the credential" };
  } catch (e) {
    return { ok: false, text: (e && e.message) || String(e) };
  } finally {
    if (session !== null) session.close();
  }
}

// The browser form, driven by a reader of its own each time. A reader
// that carried a session from an earlier attempt would answer from that
// session rather than from this credential.
async function browserAttempt(origin, caPem, address, password) {
  var reader = browser.browserAt(origin, { ca: caPem });
  var landed = await reader.signIn(address, password);
  // A JMAP client answers under the session the form mints, so what it
  // can reach is decided here rather than on a route of its own.
  var jmapSession = await reader.get("/jmap/session", { Accept: "application/json" });
  return {
    ok:     landed.status === 302,
    text:   landed.status + " " + String(landed.body).slice(0, 400),
    status: landed.status,
    body:   String(landed.body),
    jmap:   jmapSession.status,
  };
}

function surfacesOver(ports, caPem, origin) {
  return [
    {
      name: "IMAP",
      sign: function (address, label) {
        return wireAttempt(Wire.imap, ports.imap, caPem, address, PASSWORD, label);
      },
    },
    {
      name: "POP3",
      sign: function (address, label) {
        return wireAttempt(Wire.pop3, ports.pop3, caPem, address, PASSWORD, label);
      },
    },
    {
      name: "ManageSieve",
      sign: function (address, label) {
        return wireAttempt(Wire.managesieve, ports.managesieve, caPem, address,
          PASSWORD, label);
      },
    },
    {
      name: "submission",
      sign: function (address, label) {
        return wireAttempt(Wire.submission, ports.submission, caPem, address,
          PASSWORD, label);
      },
    },
    {
      name: "the browser sign-in form",
      sign: function (address) {
        return browserAttempt(origin, caPem, address, PASSWORD);
      },
    },
  ];
}

// ---- standing the states up ------------------------------------------------

// One account per state, each made to reach that state the way an
// operator reaches it rather than by writing a status onto a row.
async function standUpStates(identity) {
  var subjects = {};
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var status = OUT_OF_SERVICE[i];
    var address = addressFor(status);
    var row = await identity.accounts.create({ address: address, password: PASSWORD });

    if (status === "suspended") {
      await identity.accounts.suspend({
        id: row.id, reason: "the credential was reported stolen" });
    } else if (status === "archived") {
      await identity.accounts["delete"]({ id: row.id, reason: "the owner has left" });
    } else if (status === "erasing") {
      var owner = {
        id: row.id, address: row.address, domain: row.domain,
        isAdmin: false, mailboxes: [row.address], roles: ["account"],
      };
      var kept = identity.mailbox.appendMessage("INBOX", heldMail(address), { actor: owner });
      await identity.mailbox.legalHold.place(owner, "INBOX", [kept.objectid], {
        reason: HOLD_REASON, citation: HOLD_CITATION });
      var partial = await identity.accounts["delete"]({
        id: row.id, destroy: true, reason: "erasure requested by the account holder" });
      count("the run holds an account part way through an erasure, left behind by an " +
        "order rather than by a status written onto a row",
        partial.outcome === "partially-erased", JSON.stringify(partial.outcome));
    } else {
      // A status the store has grown since this file was written. It is
      // reported rather than skipped: a state nobody stood up is a state
      // nobody measured, and a run that quietly passed over it would
      // report the same total as one that drove it.
      count("the run knows how to put an account into every state the store declares, " +
        "including " + status, false,
        "add the operator verb that reaches '" + status + "' beside the others");
    }

    var reached = identity.accounts.get(address);
    count(address + " is " + status + " before anything signs in",
      reached !== null && reached !== undefined && reached.status === status,
      reached === null || reached === undefined ? "no row" : String(reached.status));
    subjects[status] = row;
  }
  return subjects;
}

// ---- the cases -------------------------------------------------------------

// The control, and it runs first. Every refusal below is only readable
// against a server that admits the credential it should.
async function aMailboxInServiceSignsInEverywhere(surfaces) {
  for (var i = 0; i < surfaces.length; i += 1) {
    var landed = await surfaces[i].sign(ACTIVE_ADDRESS, "active");
    count(surfaces[i].name + " admits a mailbox in service on a hosted domain",
      landed.ok === true, landed.text);
  }
}

// The refusal, per state, per surface. What the wire can show is whether
// the session was let in, which is what every claim here rests on.
async function aHeldMailboxIsRefusedEverywhere(surfaces, status) {
  var address = addressFor(status);
  for (var i = 0; i < surfaces.length; i += 1) {
    var attempt = await surfaces[i].sign(address, status);
    count(surfaces[i].name + " refuses the correct password for a " + status + " mailbox",
      attempt.ok === false, attempt.text);
  }
}

// The sentence a person reads, which is the half a mail client cannot be
// given. Asserted per state, because the three are not interchangeable.
async function theSignInPageNamesTheState(origin, caPem, status) {
  var attempt = await browserAttempt(origin, caPem, addressFor(status), PASSWORD);
  count("the sign-in page answers a " + status + " mailbox with 401 rather than a page " +
    "that looks like a wrong password", attempt.status === 401, attempt.text);
  count("and it names the state, so somebody whose password is already right is not " +
    "sent to reset it (" + status + ")",
    attempt.body.indexOf(SIGN_IN_SENTENCE[status]) !== -1, attempt.text);
  count("nothing was signed in, so a JMAP client has no session to answer under (" +
    status + ")", attempt.jmap === 401, String(attempt.jmap));
}

// The second gate. The account's own row says active; the domain it
// belongs to has been withdrawn. An implementation reading the account
// row alone admits this one.
async function aMailboxOnAWithdrawnDomainIsRefusedEverywhere(surfaces, identity) {
  var row = identity.accounts.get(WITHDRAWN_ADDRESS);
  count("the mailbox on the domain about to be withdrawn is itself in service, so the " +
    "refusal below is the domain rather than the account",
    row !== null && row !== undefined && row.status === "active",
    row === null || row === undefined ? "no row" : String(row.status));

  var before = await surfaces[0].sign(WITHDRAWN_ADDRESS, "before-withdrawal");
  count("and it signs in while its domain is hosted", before.ok === true, before.text);

  await identity.domains.setStatus({
    domain: WITHDRAWN_DOMAIN,
    status: "disabled",
    reason: "the domain is under investigation",
  });
  count("the operator has withdrawn the domain",
    identity.domains.get(WITHDRAWN_DOMAIN).status === "disabled",
    String(identity.domains.get(WITHDRAWN_DOMAIN).status));

  for (var i = 0; i < surfaces.length; i += 1) {
    var attempt = await surfaces[i].sign(WITHDRAWN_ADDRESS, "withdrawn");
    count(surfaces[i].name + " refuses a mailbox whose domain the operator has withdrawn",
      attempt.ok === false, attempt.text);
  }
}

// The domain's state is not a stranger's business. A reader is told the
// address and password do not match a mailbox here, and nothing about
// which of the two it was or what the operator has done to the domain.
//
// The address the reader typed comes back in the form field, which is
// how every sign-in page works and is why the claim is phrased on the
// sentences rather than on the domain name: the name is on the page
// because the reader put it there. What must not be on the page is a
// sentence describing a state, because none of the three is true of this
// mailbox and each of them tells the reader to ask the operator for
// something different.
async function theWithdrawnDomainIsNotNamedToTheReader(origin, caPem) {
  var attempt = await browserAttempt(origin, caPem, WITHDRAWN_ADDRESS, PASSWORD);
  count("the sign-in page answers a withdrawn domain with the unmatched sentence",
    attempt.body.indexOf(UNMATCHED_SENTENCE) !== -1, attempt.text);
  var named = Object.keys(SIGN_IN_SENTENCE).filter(function (status) {
    return attempt.body.indexOf(SIGN_IN_SENTENCE[status]) !== -1;
  });
  count("and describes no account state, because the account's own row is in service",
    named.length === 0, named.join(", "));
}

// The cell that is deliberately open. A gate that never lets go is not a
// gate, and a listener that has started refusing an address for good
// passes every case above.
async function areinstatedMailboxSignsInAgainEverywhere(surfaces, identity, subjects) {
  await identity.accounts.reinstate({ id: subjects.suspended.id });
  count("the suspended mailbox is back in service",
    identity.accounts.get(addressFor("suspended")).status === "active",
    String(identity.accounts.get(addressFor("suspended")).status));

  for (var i = 0; i < surfaces.length; i += 1) {
    var landed = await surfaces[i].sign(addressFor("suspended"), "reinstated");
    count(surfaces[i].name + " admits the same credential once the mailbox is back in " +
      "service", landed.ok === true, landed.text);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("account-status");
  var dataDir = helpers.dataDir(root);
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;

  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: WITHDRAWN_DOMAIN });

    await identity.accounts.create({ address: ACTIVE_ADDRESS, password: PASSWORD });
    await identity.accounts.create({ address: WITHDRAWN_ADDRESS, password: PASSWORD });
    var subjects = await standUpStates(identity);

    // Inbound mail takes no credential and is the one listener this file
    // has no question for, so it stays unbound, which also keeps the DNS
    // posture gate out of a run that is not about it.
    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
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
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only one a credential may " +
      "be presented on", typeof bound.https === "number" && bound.https > 0,
      JSON.stringify(bound));
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var ports = {
      imap:        sections.imap.port,
      pop3:        sections.pop3.port,
      managesieve: sections.managesieve.port,
      submission:  sections.submission.port,
    };
    var surfaces = surfacesOver(ports, material.caPem, origin);
    count("five surfaces take a credential, which is what makes this a claim about " +
      "agreement rather than about one listener", surfaces.length === 5,
      surfaces.map(function (s) { return s.name; }).join(", "));

    await aMailboxInServiceSignsInEverywhere(surfaces);
    for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
      await aHeldMailboxIsRefusedEverywhere(surfaces, OUT_OF_SERVICE[i]);
      await theSignInPageNamesTheState(origin, material.caPem, OUT_OF_SERVICE[i]);
    }
    await aMailboxOnAWithdrawnDomainIsRefusedEverywhere(surfaces, identity);
    await theWithdrawnDomainIsNotNamedToTheReader(origin, material.caPem);
    await areinstatedMailboxSignsInAgainEverywhere(surfaces, identity, subjects);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
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

module.exports = {
  name:      "account-status-wire-signin",
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
