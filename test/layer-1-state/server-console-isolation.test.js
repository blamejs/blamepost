// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The whole server, from a certificate on disk to a signed in reader,
 * with the two questions that decide whether a multi account mail
 * server is safe to run: can this account reach another account's mail,
 * and can it reach the operator's console.
 *
 * Every earlier run of this coverage answered them against a browser
 * surface built by hand on a cleartext port, with a certificate context
 * carrying no certificate. Three things were missing from that, and
 * each one is a class of defect the run could not see:
 *
 *   - **A certificate that exists.** The configuration names two files
 *     on disk, the way an operator names an ACME issued pair, and
 *     nothing here passes a ready made context. That is the only path
 *     that reaches the certificate loader, the capped file reads, the
 *     sealed key unwrap and the TLS port of the browser surface, and it
 *     is the only way the reader can hold a session at all: the session
 *     cookie carries the `__Host-` prefix and the `Secure` attribute,
 *     so the transport a browser would keep it over is TLS and nothing
 *     else. A run over cleartext is a run in the one configuration
 *     where the cookie policy cannot be observed.
 *   - **A reader who is not the operator.** Every route under `/admin`
 *     is gated on a flag the accounts table carries, and an account
 *     created without it is what an ordinary mailbox owner is. Signing
 *     in as the operator and finding the console renders proves the
 *     console renders. It proves nothing about the gate.
 *   - **Both surfaces.** The browser routes and the JMAP methods are
 *     two different resolvers over one body of mail, and this project
 *     has already shipped a defect where one of them was scoped and the
 *     other was not. A rule tested on one is a rule tested on half the
 *     server.
 *
 * So the run below builds the server the command line's serve verb
 * builds, starts it, and drives it over TLS as a non-admin account:
 *
 *   - the certificate the configuration named is the one presented, and
 *     the chain verifies against the authority that signed it;
 *   - the session cookie carries the prefix and the attributes that
 *     keep it off a cleartext transport;
 *   - the reader reads their own mail and reaches none of the other
 *     account's, by folder and by message identifier;
 *   - JMAP answers for the reader's own account and refuses the other
 *     account's identifier, on the methods and on the blob endpoints;
 *   - every route of the operator console refuses this reader, on GET
 *     and on POST, with a refusal rather than a redirect to sign in;
 *   - an account that does carry the flag is served, so the refusals
 *     above are the gate working rather than the console being broken;
 *   - signing out destroys the session on the server, proven by
 *     replaying the token the reader was holding.
 *
 * And the omission vector, because a guarantee with no test that
 * leaving it out fails is a guarantee nobody has checked: a
 * configuration naming no certificate binds no TLS port at all.
 *
 * Run standalone: node test/layer-1-state/server-console-isolation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

// A query answer as rows. The audit reader answers an array, and a read
// that could not be served answers nothing at all, which is not an empty
// trail and is not something to iterate either.
function _asRows(value) { return Array.isArray(value) ? value : []; }

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";
var ADMIN_PASSWORD   = "an operator passphrase 5512";

var ALICE_SUBJECT = "Alices own quarterly note";
var BOB_SUBJECT   = "Bobs private quarterly numbers";
var BOB_BODY      = "zebra7741 belongs to bob and to nobody else";

// The session cookie, and the attributes that decide which transport a
// browser will send it back over. The prefix is not decoration: RFC
// 6265bis section 4.1.3 lets a browser refuse a `__Host-` cookie that
// is not Secure, path `/` and free of a Domain attribute.
var SESSION_COOKIE = "__Host-bp_session";

// The adapter names each account's physical folders with this prefix,
// so finding one anywhere in a rendered page or a JMAP answer is the
// leak itself rather than a hint of one.
var STORE_FOLDER_PREFIX = "mbx_";

// Every route the operator console mounts. A gate tested on the
// overview page and nowhere else is a gate on one page.
var ADMIN_PAGES = [
  "/admin",
  "/admin/domains",
  "/admin/accounts",
  "/admin/aliases",
  "/admin/dkim",
  "/admin/queue",
  "/admin/audit",
  // The lockout page reads which accounts have exhausted their sign-in
  // budget and which source addresses are being refused, so a reader
  // that reaches it learns which credentials are under attack and how
  // close each one is to being locked. It is listed here because the
  // mutation sweep below already drives its POST: a page whose write is
  // gated and whose read is not still hands that away.
  "/admin/lockouts",
];

// The address a refused alias would have claimed, and where it would
// have pointed. Named here so the refusal and the read back that proves
// nothing was created are talking about the same row.
var SEIZED_DOMAIN = "seized.example";
var SEIZED_ALIAS  = "root@" + DOMAIN;
var SEIZED_TARGET = "attacker@example.net";

// The console's mutations, each with a payload that would do real
// damage if the gate were open. A refusal on GET and an open POST is a
// console anyone can drive with a form.
//
// Every field name here is one the handler actually reads. A payload
// naming fields the route ignores is refused by the gate and would also
// have been refused by the handler, so the read back below would report
// the state unchanged with the gate wide open: the vector proves the
// gate only while it would otherwise have landed. The account and the
// selector are settled at run time, because an id and a selector name
// are minted rather than written down.
function adminMutations(target) {
  return [
    { path: "/admin/domains",  fields: { action: "add", domain: SEIZED_DOMAIN } },
    // Carrying the typed confirmation as well as the reason, because the
    // console asks for both before it archives anything. A payload
    // missing either would be refused by the handler for a reason that
    // has nothing to do with the gate, and the read back below would then
    // report the account unchanged with the gate wide open.
    { path: "/admin/accounts", fields: { action: "archive", id: target.accountId,
                                         confirm: target.address,
                                         reason: "seizing the mailbox" } },
    { path: "/admin/aliases",  fields: { action: "add", address: SEIZED_ALIAS,
                                         destination: SEIZED_TARGET } },
    { path: "/admin/dkim",     fields: { action: "rotate", domain: DOMAIN } },
    { path: "/admin/queue",    fields: { action: "run" } },
    { path: "/admin/lockouts", fields: { address: target.address,
                                         reason: "seizing the sign-in budget" } },
  ];
}

// The row the console gate files when it turns a signed-in account away.
// Read back by name rather than assumed from the fact that a line of
// code emits it, because the audit chain drops an event whose namespace
// was never registered rather than storing it.
var CONSOLE_DENIED = "blamepost.web.console_not_permitted";

var SHUTDOWN_TIMEOUT_MS = 5000;

function messageFor(recipient, subject, body) {
  return Buffer.from(
    "Message-ID: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

function baseEnv(dataDir, material) {
  var env = {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
  };
  if (material !== null) {
    env.BLAMEPOST_TLS_CERT = material.certFile;
    env.BLAMEPOST_TLS_KEY  = material.keyFile;
  }
  return env;
}

// Every mail listener off, and one on. The listeners are not what this
// file is about, but a server assembled with none of them is not the
// server an operator runs, and the IMAP listener is the one that proves
// the mailbox adapter reached the composition.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = {
      enabled: names[i] === "imap",
      port:    await wire.reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

// ---- the certificate the configuration named ------------------------------

function testTheConfiguredCertificateIsTheOnePresented(landing, material) {
  var tls = landing.tls;
  count("the reader reached the browser surface over TLS", tls !== null,
    JSON.stringify(landing.status));
  count("the chain verifies against the authority that signed the configured pair",
    tls.authorized === true, tls.authorizedError);

  var presented = tls.peerCertificate;
  count("the certificate carries the name this server answers to",
    typeof presented.subjectaltname === "string" &&
    presented.subjectaltname.indexOf("DNS:" + HOSTNAME) !== -1,
    presented.subjectaltname);
  count("it also carries the address the reader connected to, so the same pair " +
    "serves a name and an address",
    typeof presented.subjectaltname === "string" &&
    presented.subjectaltname.indexOf("IP Address:" + LOOPBACK) !== -1,
    presented.subjectaltname);

  // The bytes on the wire against the bytes on disk. A server presenting
  // some other certificate that happens to verify would pass everything
  // above and would not be serving what the operator configured.
  var onDisk = nodeFs.readFileSync(material.certFile, "utf8");
  var fingerprintOnWire = String(presented.fingerprint256 || "");
  count("the presented leaf is the one written to the file the configuration names",
    fingerprintOnWire.length > 0 && onDisk.indexOf("BEGIN CERTIFICATE") !== -1 &&
    onDisk.indexOf(material.cert.trim()) !== -1,
    fingerprintOnWire);
}

function testTheSessionCookieStaysOffACleartextTransport(landing) {
  var written = landing.setCookie.filter(function (line) {
    return String(line).indexOf(SESSION_COOKIE + "=") === 0;
  });
  count("signing in writes the session cookie", written.length === 1,
    JSON.stringify(landing.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  var attributes = String(written[0]);
  count("the session cookie carries the host prefix that binds it to this origin",
    attributes.indexOf(SESSION_COOKIE) === 0, attributes.slice(0, 60));
  count("it is Secure, so a browser sends it back over TLS and nothing else",
    /;\s*Secure/i.test(attributes), attributes.slice(-120));
  count("it is HttpOnly, so a script on the page cannot read it",
    /;\s*HttpOnly/i.test(attributes), attributes.slice(-120));
  count("it is SameSite=Strict, so another site cannot ride it",
    /;\s*SameSite=Strict/i.test(attributes), attributes.slice(-120));
  count("it is scoped to the whole origin rather than to one path, which the host " +
    "prefix requires", /;\s*Path=\/(?:;|$)/i.test(attributes), attributes.slice(-120));
  count("it carries no Domain attribute, which the host prefix also requires",
    !/;\s*Domain=/i.test(attributes), attributes.slice(-120));
}

// ---- the reader's own mail ------------------------------------------------

async function testTheReaderReachesTheirOwnMail(reader, landing) {
  count("signing in redirects the reader to a mailbox rather than back to the form",
    landing.status === 302 && String(landing.location).indexOf("/mail?") === 0,
    landing.status + " " + landing.location);

  var inbox = await reader.get(landing.location);
  count("the reader's own folder renders", inbox.status === 200, inbox.status);
  count("it carries the message addressed to them",
    inbox.body.indexOf(ALICE_SUBJECT) !== -1, inbox.status + " " + inbox.body.length);
  count("no physical folder name reaches the page",
    inbox.body.indexOf(STORE_FOLDER_PREFIX) === -1,
    inbox.body.slice(Math.max(0, inbox.body.indexOf(STORE_FOLDER_PREFIX) - 60), 120));
  return inbox;
}

async function testAnotherAccountsMailIsUnreachableOverHttp(reader, own, victim) {
  // The differential first. A route that answered 404 to every message
  // identifier would pass every refusal below and would also be a
  // mailbox nobody can read, so the reader's own message has to open
  // through exactly the shape the refusals use.
  var mine = await reader.get("/mail/" + encodeURIComponent(own.objectId) + "?folder=INBOX");
  count("the reader's own message opens through its identifier", mine.status === 200,
    mine.status);
  count("and the page is the message rather than a folder listing",
    mine.body.indexOf(ALICE_SUBJECT) !== -1, mine.status + " " + mine.body.length);

  var byFolder = await reader.get("/mail?folder=" + encodeURIComponent(victim.storeFolder));
  count("the other account's physical folder name resolves to nothing",
    byFolder.status === 404, byFolder.status);
  count("and the refusal carries none of that account's mail",
    byFolder.body.indexOf(BOB_BODY) === -1 && byFolder.body.indexOf(BOB_SUBJECT) === -1,
    byFolder.status + " " + byFolder.body.length);

  var byWireName = await reader.get("/mail/" + encodeURIComponent(victim.objectId) +
    "?folder=INBOX");
  count("the other account's message identifier, asked for through a folder this " +
    "reader does own, resolves to nothing", byWireName.status === 404, byWireName.status);
  count("and that refusal carries none of it either",
    byWireName.body.indexOf(BOB_BODY) === -1 && byWireName.body.indexOf(BOB_SUBJECT) === -1,
    byWireName.status + " " + byWireName.body.length);

  // The same identifier again, through a bulk action rather than a
  // read. The two routes resolve the identifier separately, and a
  // project that has already shipped a scoped reader beside an unscoped
  // writer does not get to assume they agree. The message store's flag
  // write takes an identifier and ignores the folder it was handed, so
  // an unresolved identifier here reaches every message on the server.
  var ownFlagged = await reader.form("/mail/actions?folder=INBOX",
    { action: "flag", objectId: own.objectId });
  count("flagging the reader's own message reports the flags updated",
    String(ownFlagged.location || "").indexOf("notice=flagged") !== -1,
    ownFlagged.status + " " + String(ownFlagged.location));

  var foreignFlagged = await reader.form("/mail/actions?folder=INBOX",
    { action: "flag", objectId: victim.objectId });
  count("the same action naming the other account's message reports nothing updated",
    String(foreignFlagged.location || "").indexOf("notice=flagged") === -1,
    foreignFlagged.status + " " + String(foreignFlagged.location));
  count("and it is refused as a message this folder does not hold",
    foreignFlagged.status === 404, foreignFlagged.status);

  var searched = await reader.get("/search?q=" + encodeURIComponent("zebra7741"));
  count("a search for a word that appears only in the other account's mail finds nothing",
    searched.status === 200 && searched.body.indexOf(BOB_BODY) === -1,
    searched.status + " " + searched.body.length);
}

// ---- the same question over JMAP ------------------------------------------

async function testJmapAnswersForTheReaderAlone(reader, own, victim) {
  var session = await reader.get("/jmap/session", { Accept: "application/json" });
  count("the JMAP session document renders for a signed in account",
    session.status === 200, session.status);
  var parsed = JSON.parse(session.body);
  var accountIds = Object.keys(parsed.accounts || {});
  count("it enumerates this reader's account and no other",
    accountIds.length === 1 && accountIds[0] === own.accountId,
    JSON.stringify(accountIds));
  count("the primary account for mail is the reader's own",
    parsed.primaryAccounts["urn:ietf:params:jmap:mail"] === own.accountId,
    JSON.stringify(parsed.primaryAccounts));

  var mine = browser.answer(await reader.jmap([
    ["Mailbox/get", { accountId: own.accountId, ids: null }, "c0"],
  ]));
  count("Mailbox/get answers for the reader's own account", mine[0] === "Mailbox/get",
    JSON.stringify(mine[0]));
  var names = (mine[1].list || []).map(function (row) { return row.id; });
  count("the mailboxes it returns are named by their wire names rather than by the " +
    "store folder that holds them",
    names.length > 0 && names.every(function (id) {
      return String(id).indexOf(STORE_FOLDER_PREFIX) !== 0;
    }), JSON.stringify(names));
  count("the other account's store folder is not among them",
    names.indexOf(victim.storeFolder) === -1, JSON.stringify(names));

  var foreign = browser.answer(await reader.jmap([
    ["Mailbox/get", { accountId: victim.accountId, ids: null }, "c0"],
  ]));
  count("naming the other account's identifier is refused rather than answered",
    foreign[0] === "error", JSON.stringify(foreign));
  count("and the refusal is the one RFC 8620 section 3.6.1 defines for an account " +
    "the actor may not touch",
    foreign[1] && foreign[1].type === "urn:ietf:params:jmap:error:accountNotFound",
    JSON.stringify(foreign[1]));

  var email = browser.answer(await reader.jmap([
    ["Email/get", { accountId: own.accountId, ids: [victim.objectId],
                    properties: ["subject", "preview"] }, "c0"],
  ]));
  count("asking for the other account's message under the reader's own account " +
    "returns it as not found",
    email[0] === "Email/get" && Array.isArray(email[1].notFound) &&
    email[1].notFound.indexOf(victim.objectId) !== -1,
    JSON.stringify(email[1]).slice(0, 200));
  count("and nothing of that message comes back in the list",
    (email[1].list || []).length === 0, JSON.stringify(email[1].list));

  var query = browser.answer(await reader.jmap([
    ["Email/query", { accountId: own.accountId, filter: { text: "zebra7741" } }, "c0"],
  ]));
  count("a JMAP query for a word that appears only in the other account's mail " +
    "matches nothing",
    query[0] === "Email/query" && (query[1].ids || []).length === 0,
    JSON.stringify(query[1]).slice(0, 200));
}

// The blob endpoints the session document advertises. RFC 8620 section
// 2 makes `uploadUrl` and `downloadUrl` mandatory session fields, so
// they are advertised whether or not a backend stands behind them, and
// what matters is that the answer is a typed JMAP refusal rather than a
// stack trace or, worse, somebody else's bytes.
async function testTheBlobEndpointsRefuseRatherThanLeak(reader, own, victim) {
  var mine = await reader.post("/jmap/upload/" + own.accountId, "text/plain",
    "an attachment this build has nowhere to put", { Accept: "application/json" });
  count("an upload to the reader's own account is answered rather than crashing",
    mine.status >= 200 && mine.status < 600, mine.status);
  var mineBody = JSON.parse(mine.body);
  count("and the answer is a typed JMAP problem rather than an untyped failure",
    typeof mineBody.type === "string" &&
    mineBody.type.indexOf("urn:ietf:params:jmap:error:") === 0,
    mine.status + " " + mine.body.slice(0, 160));

  var foreignUpload = await reader.post("/jmap/upload/" + victim.accountId, "text/plain",
    "an attachment aimed at somebody else's account", { Accept: "application/json" });
  count("an upload naming the other account's identifier does not succeed",
    foreignUpload.status !== 201, foreignUpload.status + " " + foreignUpload.body.slice(0, 160));

  var foreignDownload = await reader.get(
    "/jmap/download/" + victim.accountId + "/" + encodeURIComponent(victim.objectId) +
    "/numbers.txt", { Accept: "application/json" });
  count("a download naming the other account's identifier does not succeed",
    foreignDownload.status !== 200,
    foreignDownload.status + " " + foreignDownload.body.slice(0, 160));
  count("and it carries none of that account's mail",
    foreignDownload.body.indexOf(BOB_BODY) === -1,
    foreignDownload.body.slice(0, 160));
}

// ---- the operator console --------------------------------------------------

async function testEveryConsolePageRefusesThisReader(reader) {
  for (var i = 0; i < ADMIN_PAGES.length; i += 1) {
    var page = await reader.get(ADMIN_PAGES[i]);
    count("a mailbox owner is refused at " + ADMIN_PAGES[i],
      page.status === 403, page.status + " " + String(page.location));
    // A redirect to the sign in form would mean the reader was treated
    // as a stranger, which is a different answer to a different
    // question and would hide an open gate the moment a session existed.
    count("the refusal at " + ADMIN_PAGES[i] + " is about the role rather than about " +
      "being signed in", page.location === null, String(page.location));
    count("the refused page carries none of the console",
      page.body.indexOf("/admin/domains") === -1 || page.status === 403,
      page.status);
  }
}

async function testEveryConsoleMutationRefusesThisReader(reader, identity, target, dkim) {
  var moves = adminMutations(target);
  for (var i = 0; i < moves.length; i += 1) {
    var move = moves[i];
    var answer = await reader.form(move.path, move.fields);
    count("a mailbox owner posting to " + move.path + " is refused",
      answer.status === 403, answer.status + " " + String(answer.location));
  }
  // The refusals above are only worth anything if the mutations they
  // refused would otherwise have landed, so the state each one aimed at
  // is read back rather than assumed.
  var domains = await identity.domains.list({});
  var hosted = (domains || []).map(function (row) { return row.domain || row; });
  count("the domain the refused post named is not hosted here",
    hosted.indexOf(SEIZED_DOMAIN) === -1, JSON.stringify(hosted));
  var bob = await identity.accounts.get(target.address);
  count("the account the refused post aimed to archive is still active",
    bob !== null && bob.status === "active", bob && bob.status);
  var aliases = await identity.aliases.list({ includeDisabled: true });
  var aliasNames = (aliases || []).map(function (row) { return row.address || ""; });
  count("the alias the refused post named was not created",
    aliasNames.indexOf(SEIZED_ALIAS) === -1, JSON.stringify(aliasNames));
  // The selector set the refused rotation aimed at. A rotation mints a
  // second active pair, so the count moving is what a landed rotation
  // looks like from here.
  var selectors = dkim.list(DOMAIN);
  count("the signing selectors the refused rotation named are the pair that was minted",
    selectors.length === target.selectorCount,
    selectors.length + " now, " + target.selectorCount + " before");
  return moves;
}

// Every refusal above, read back off the audit chain.
//
// A console refusal is the event an incident is reconstructed from: an
// account that holds no operator role asking to archive a mailbox, mint
// a domain, rotate a signing key or release somebody else's sign-in
// budget is the whole of what an auditor is looking for, and a gate that
// turns it away without recording it leaves that trail showing only the
// callers who never tried. The framework's own session gate already
// records `auth.required.denied` for a caller with no session at all, so
// a console that records nothing for a caller who HAS one reports the
// weaker event and drops the stronger one.
async function testEveryConsoleRefusalIsOnTheAuditChain(own, refused, pages) {
  // The rows are written from a request that has already been answered,
  // so they queue and land within the second. Draining first is what
  // makes the read the current one.
  await b.audit.flush();
  var rows = _asRows(await b.audit.query({
    action: CONSOLE_DENIED, order: "desc", limit: 200,
  }));
  count("every console refusal leaves a row, on the read and on the write alike",
    rows.length >= refused.length + pages.length,
    rows.length + " row(s) for " + (refused.length + pages.length) + " refusal(s)");

  var first = rows.length > 0 ? rows[0] : null;
  count("and the row is filed as a denial rather than as a fault",
    first !== null && first.outcome === "denied", JSON.stringify(first && first.outcome));
  count("and it names the account that was turned away, in the column an auditor " +
    "filters on",
    first !== null && first.actorUserId === own.accountId,
    JSON.stringify(first && first.actorUserId));

  // Which verb was refused, not merely that one was. An operator reading
  // this trail during an incident is asking what the account tried to
  // reach, and a row that answers only "the console" answers nothing
  // they can act on.
  var reached = rows.map(function (row) {
    var held;
    try { held = JSON.parse(row.metadata || "{}"); } catch (_e) { held = {}; }
    return String(held.method || "") + " " + String(held.path || "");
  });
  var missing = [];
  for (var i = 0; i < refused.length; i += 1) {
    if (reached.indexOf("POST " + refused[i].path) === -1) missing.push(refused[i].path);
  }
  count("each refused mutation is named by its own row, so the trail says what was tried",
    missing.length === 0, JSON.stringify(missing));
  var missingReads = [];
  for (var p = 0; p < pages.length; p += 1) {
    if (reached.indexOf("GET " + pages[p]) === -1) missingReads.push(pages[p]);
  }
  count("and so is each refused read", missingReads.length === 0, JSON.stringify(missingReads));
}

function testTheConsoleIsNotOfferedToAReaderWhoCannotUseIt(inbox) {
  count("the mailbox page offers this reader no way into the console",
    inbox.body.indexOf("href=\"/admin\"") === -1, inbox.status);
}

// The other half of the same gate. Refusals mean nothing until an
// account that does hold the flag is served, because a console that is
// broken for everybody refuses everybody.
async function testTheOperatorIsServed(origin, caPem, operatorAddress) {
  var operator = browser.browserAt(origin, { ca: caPem });
  var landed = await operator.signIn(operatorAddress, ADMIN_PASSWORD);
  count("the operator signs in over the same surface", landed.status === 302,
    landed.status + " " + landed.location);
  for (var i = 0; i < ADMIN_PAGES.length; i += 1) {
    var page = await operator.get(ADMIN_PAGES[i]);
    count("the operator is served " + ADMIN_PAGES[i], page.status === 200,
      page.status + " " + String(page.location));
  }
  var overview = await operator.get("/admin");
  count("the console the operator is served links to its own sections",
    overview.body.indexOf("/admin/domains") !== -1 &&
    overview.body.indexOf("/admin/accounts") !== -1, overview.status);

  // The other side of the withheld link. A mailbox page that renders the
  // way into the console for nobody would satisfy the reader's half of
  // this gate exactly as a working one does, so the same page is asked of
  // the account that may use it.
  var operatorInbox = await operator.get(landed.location);
  count("and the operator's own mailbox page carries the way in, so withholding it from " +
    "the reader is the gate rather than a link nothing renders",
    operatorInbox.status === 200 && operatorInbox.body.indexOf("href=\"/admin\"") !== -1,
    operatorInbox.status + " " + String(operatorInbox.location));
  return operator;
}

// ---- signing out -----------------------------------------------------------

async function testSigningOutDestroysTheSessionOnTheServer(reader) {
  var held = reader.cookies.read(SESSION_COOKIE);
  count("the reader is holding a session token to sign out of",
    typeof held === "string" && held.length > 0, typeof held);

  var out = await reader.signOut();
  count("signing out sends the reader back to the form",
    out.status === 302 && String(out.location).indexOf("/sign-in") === 0,
    out.status + " " + out.location);
  count("the reader is no longer holding the session cookie",
    reader.cookies.read(SESSION_COOKIE) === null,
    JSON.stringify(reader.cookies.names()));

  // The claim is that the server destroyed the session, not that the
  // client stopped sending it. Those are different guarantees and only
  // one of them survives a stolen cookie, so the token goes back.
  reader.cookies.set(SESSION_COOKIE, held);
  var replayed = await reader.get("/mail?folder=INBOX");
  count("replaying the token the reader was holding reaches no mail",
    replayed.status === 302 && String(replayed.location).indexOf("/sign-in") === 0,
    replayed.status + " " + String(replayed.location));

  var replayedJmap = await reader.jmap([["Mailbox/get", { accountId: "any", ids: null }, "c0"]]);
  count("and it reaches no mail over JMAP either",
    replayedJmap.status !== 200 ||
    String(replayedJmap.body).indexOf("Mailbox/get") === -1,
    replayedJmap.status + " " + String(replayedJmap.body).slice(0, 120));
}

// ---- the omission vector ---------------------------------------------------

// A guarantee with no test that omitting it fails is a guarantee nobody
// has checked. With no certificate named, the browser surface takes the
// cleartext port and nothing else, which is the shape behind a proxy
// that terminates TLS and holds the only copy of the key.
async function testNoCertificateMeansNoTlsPort(root, dataDir, identity, sections) {
  var cfg = config.load({ env: baseEnv(dataDir, null), cwd: root });
  count("a configuration naming no certificate loads rather than refusing",
    cfg.tlsCert === null && cfg.tlsKey === null,
    JSON.stringify([cfg.tlsCert, cfg.tlsKey]));

  var thrown = null;
  var server = null;
  try {
    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
  } catch (e) { thrown = e; }
  count("and assembling a server from it is refused, because every mail listener " +
    "here requires TLS and none of them has a plaintext mode",
    thrown !== null && /certificate/i.test(String(thrown.message)),
    thrown === null ? "nothing was thrown" : String(thrown.message).slice(0, 160));
  if (server !== null) await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("console");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it finds through this variable. Pointing it inside the
  // run's own tree keeps the encrypted at rest path exactly as it ships
  // rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });
    count("the configuration reads the certificate pair off disk rather than being " +
      "handed a context", cfg.tlsCert === material.certFile && cfg.tlsKey === material.keyFile,
      JSON.stringify([cfg.tlsCert, cfg.tlsKey]));

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "console isolation run" });

    // The reader is an ordinary mailbox owner. The flag is left off
    // deliberately and read back, because a run that signed in as the
    // operator by accident would report every console refusal below as
    // a pass it never earned.
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    var operatorAccount = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });
    count("the reader this run drives administers nothing", alice.isAdmin === false,
      JSON.stringify({ alice: alice.isAdmin, operator: operatorAccount.isAdmin }));
    count("the account kept back to prove the console works does administer it",
      operatorAccount.isAdmin === true, operatorAccount.isAdmin);

    var alicesStored = identity.mailbox.appendMessage("INBOX",
      messageFor(alice.address, ALICE_SUBJECT, "alice body"), { actor: { id: alice.id } });
    var bobsStored = identity.mailbox.appendMessage("INBOX",
      messageFor(bob.address, BOB_SUBJECT, BOB_BODY), { actor: { id: bob.id } });
    var bobsInbox = identity.mailbox.accountFolders({ id: bob.id })
      .filter(function (row) { return row.name === "INBOX"; })[0];
    var alicesInbox = identity.mailbox.accountFolders({ id: alice.id })
      .filter(function (row) { return row.name === "INBOX"; })[0];
    count("the two accounts hold their inboxes in different store folders, so there " +
      "is something for the routes below to get wrong",
      bobsInbox !== undefined && alicesInbox !== undefined &&
      bobsInbox.storeName !== alicesInbox.storeName,
      JSON.stringify([alicesInbox && alicesInbox.storeName, bobsInbox && bobsInbox.storeName]));

    var sections = await listenerSections();
    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    count("the browser surface took a cleartext port", typeof bound.http === "number" &&
      bound.http > 0, JSON.stringify(bound));
    count("and a TLS port, because the configuration named a certificate",
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));
    count("the two are different sockets", bound.http !== bound.https, JSON.stringify(bound));

    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(origin, { ca: material.caPem });

    var form = await reader.readCsrf("/sign-in");
    count("the sign in form carries a token for the reader to send back",
      form.token.length > 0, form.page.status + " " + form.page.body.slice(0, 120));

    var landing = await reader.signIn(alice.address, ALICE_PASSWORD);
    testTheConfiguredCertificateIsTheOnePresented(landing, material);
    testTheSessionCookieStaysOffACleartextTransport(landing);

    var own = {
      accountId:   alice.id,
      storeFolder: alicesInbox.storeName,
      objectId:    alicesStored.objectid,
    };
    var victim = {
      accountId:   bob.id,
      storeFolder: bobsInbox.storeName,
      objectId:    bobsStored.objectid,
    };

    var inbox = await testTheReaderReachesTheirOwnMail(reader, landing);
    await testAnotherAccountsMailIsUnreachableOverHttp(reader, own, victim);
    await testJmapAnswersForTheReaderAlone(reader, own, victim);
    await testTheBlobEndpointsRefuseRatherThanLeak(reader, own, victim);
    testTheConsoleIsNotOfferedToAReaderWhoCannotUseIt(inbox);
    await testEveryConsolePageRefusesThisReader(reader);

    // What the refused mutations aim at, settled before they are sent so
    // the read back afterwards compares against a measurement rather
    // than against a guess. The signing pair is minted here for the same
    // reason: a rotation refused on a domain that holds no key would
    // have been refused by the signer too.
    var minted = await server.mail.dkim.generate({ domain: DOMAIN });
    count("the domain holds a signing pair for the refused rotation to aim at",
      minted !== null && server.mail.dkim.list(DOMAIN).length > 0,
      String(server.mail.dkim.list(DOMAIN).length));
    var target = {
      accountId:     bob.id,
      address:       bob.address,
      selectorCount: server.mail.dkim.list(DOMAIN).length,
    };
    var refused = await testEveryConsoleMutationRefusesThisReader(
      reader, identity, target, server.mail.dkim);
    await testEveryConsoleRefusalIsOnTheAuditChain(own, refused, ADMIN_PAGES);

    await testTheOperatorIsServed(origin, material.caPem, operatorAccount.address);
    await testSigningOutDestroysTheSessionOnTheServer(reader);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    await testNoCertificateMeansNoTlsPort(root, dataDir, identity, sections);

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

module.exports = { name: "server-console-isolation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
