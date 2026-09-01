// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The way back from a spent sign-in budget, driven from the browser.
 *
 * A mailbox whose failure budget is gone is refused on every protocol at
 * once, including with the right password, and until this page existed
 * the only thing an operator could do was tell the account holder to
 * wait. The command line cannot carry it: every `account` verb opens the
 * data volume, one process holds that volume at a time, and the budgets
 * are counters in the running server's memory, so a release issued with
 * the server stopped would build an empty set of counters and report
 * that nothing was locked. The counters and the administration console
 * are in the same process, which is why the release lives there.
 *
 * Every request below arrives from a source address the one before it
 * did not use, so nothing here is satisfied by the per address bounds
 * this server already carries: the sign-in form admits ten posts per
 * address per five minutes and each address posts once, and each mail
 * listener admits ten authentication failures per address per quarter
 * hour and no address here reaches that.
 *
 * The shape driven here is the ordinary one rather than the dramatic
 * one: a mail client left holding a password its owner has since
 * changed, retrying on a timer. That spends TWO budgets, which is what
 * makes the release interesting. The one kept against the mailbox
 * refuses the account holder from everywhere, and the smaller one kept
 * against that machine and that mailbox together refuses that machine
 * even after the first has been given back. An operator who releases
 * only the first and is told the mailbox is released has been told
 * something true about a person who still cannot read their mail on
 * their phone.
 *
 * Claims:
 *
 *   - The console shows the lockouts BEFORE it offers to release one:
 *     the mailbox, the machine the failures came from, and when each
 *     lockout is recorded to lift on its own.
 *   - Each one carries a link that fills the release form in from it,
 *     so the mailbox and the machine are not retyped by hand during a
 *     call.
 *   - It says plainly that the budget each listener keeps against a
 *     source address is a separate one that this release does not touch,
 *     rather than implying it released something it did not.
 *   - The release goes through the same cross-origin protection every
 *     other state change on this server does: a post carrying no token
 *     is refused.
 *   - A release with no reason is refused, and the budget still refuses
 *     the correct password afterwards.
 *   - A signed-in account that does not administer this server is
 *     refused, and the budget still refuses the correct password
 *     afterwards.
 *   - Releasing a mailbox that was never locked out says so rather than
 *     reporting a release.
 *   - A release by the operator restores sign in on a MAIL listener in
 *     the same process, which is the whole point: the browser and the
 *     listeners read one budget.
 *   - A release that names no machine leaves that machine's own budget
 *     alone, and naming it releases that one too. This is why the form
 *     asks for it.
 *   - The notice says WHICH budget was holding rather than answering two
 *     questions with one word, and it says it from what the release
 *     actually gave back rather than from what was typed into the form.
 *     Naming no machine says the mailbox is back and that the machine
 *     budget is untouched. Naming one says whether both were holding,
 *     whether only that machine was, whether only the mailbox was and
 *     that machine is therefore ruled out, or whether neither was. An
 *     operator who cannot tell those apart cannot tell a finished call
 *     from one that is about to come back, and cannot tell which device
 *     to look at when it does.
 *   - A machine this server cannot read as an address refuses the WHOLE
 *     release rather than releasing the mailbox and quietly releasing no
 *     machine. The machine budget is read first when a sign in is
 *     judged, so a machine that has spent its own allowance stays
 *     refused after the mailbox budget has been given back, which is
 *     exactly the case an operator is trying to fix when they name a
 *     machine at all. The submission listener answers the same shape the
 *     same way: a sender the authenticated account does not own refuses
 *     the whole message rather than accepting part of it.
 *   - A machine recorded as a key rather than as an address round-trips
 *     through the console. An IPv6 client is counted under the prefix
 *     its site is allocated, and that key is what the console shows and
 *     what an operator copies back into the form.
 *   - The audit row names the operator who released it, carries the
 *     reason they gave, and names the mailbox.
 *
 * The trail answers what happened. The counters answer what is true now,
 * and they are the thing that refuses the password, so the console reads
 * them as well:
 *
 *   - Each recorded lockout carries the live reading of the budget it
 *     names, so an operator sees whether that budget is still holding
 *     somebody out rather than inferring it from a recorded window.
 *   - A budget that is already held and one that is merely counting
 *     failures read differently. The framework resets the counter on the
 *     failure that spends a budget, so a held budget reads zero
 *     attempts, and a page printing that number beside it would say the
 *     opposite of what is happening. The count is shown only while a
 *     budget is still running down.
 *   - A mailbox that has never been locked out reads as clear rather
 *     than as an error.
 *   - A recorded lockout counted against an address this server hosts no
 *     mailbox at carries no live reading at all, rather than reading as
 *     clear. There is no budget here to answer for it and the page does
 *     not invent one.
 *   - The live read refuses an address with no mailbox here and a
 *     malformed address the same way the release does.
 *   - Only an operator can ask. A signed-in mailbox owner is refused the
 *     live state of another account and of their own.
 *
 * What the counters themselves answer, and the shape of the keys the
 * trail records them under, is driven in
 * test/layer-1-state/lockout-identity-budget.test.js.
 *
 * Run standalone: node test/layer-2-integration/lockout-admin-release.test.js
 */

var nodeFs   = require("node:fs");
var nodeHttp = require("node:http");
var nodeNet  = require("node:net");
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "opening harbour cassette 5518";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "steady harbour pumpkin 7715";
var CAROL_PASSWORD   = "patient meadow rucksack 3364";
var DAVE_PASSWORD    = "certain thimble marina 9042";
var ERIN_PASSWORD    = "amber trellis foghorn 6127";
var FRANK_PASSWORD   = "distant kettle sandbar 2408";
var WRONG_PASSWORD   = "not the password that was set 8830";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// The whole of 127.0.0.0/8 is local, so a client can bind a different
// source per attempt and the server reports each as its own peer.
var ADMIN_SOURCE = "127.0.0.20";
var BOB_SOURCE   = "127.0.0.21";
// The client holding the stale password. One machine, retrying, which is
// what spends the budget kept against that machine as well as the one
// kept against the mailbox.
var ALICE_PHONE  = "127.0.0.22";
// Somewhere else the account holder reads their mail from, which has
// spent nothing and is refused anyway once the mailbox budget is gone.
var ALICE_DESK   = "127.0.0.23";
// A machine that gets a mailbox's password wrong twice and stops, which
// is the ordinary shape of somebody mistyping. It spends no budget and
// is the state the console has to tell apart from a spent one.
var DAVE_LAPTOP  = "127.0.0.24";
// Somebody working through addresses. The one it names has no mailbox
// here, and a budget is still kept against it, so the trail carries a
// lockout for an address the console can offer nothing live about.
var GUESSER      = "127.0.0.25";
// A second account with the same two budgets spent, kept apart from the
// first so the release naming a machine this server cannot read can be
// driven against a mailbox that is still locked out at that point.
var ERIN_PHONE   = "127.0.0.26";
var ERIN_DESK    = "127.0.0.27";
// Where a last run of failures comes from, and a machine that has never
// failed a sign in against that mailbox. Together they drive the release
// that finds the mailbox budget holding and the named machine clear,
// which is the answer that rules a device out rather than fixing it.
var LAST_CLIENT  = "127.0.0.28";
var UNUSED_CLIENT = "127.0.0.29";

// What an operator types when they write down the answer to "which
// device is it?" as the account holder gave it. Nothing in it reads as
// an address, so no counter was ever kept under it and no release can
// name one by it.
var UNREADABLE_MACHINE = "erins-phone.local";

// An IPv6 client. It is counted under the prefix its site is allocated
// rather than under the address it dialled from, so the console shows a
// key rather than this string and the operator copies that key back.
// Written from the range RFC 3849 reserves for documentation, so it
// names nothing.
var V6_PEER = "2001:db8:1a2b:3c4d::9";

// An address this server hosts no mailbox at. A budget is spent against
// it exactly as one with a mailbox is, which is what stops the counters
// answering which addresses exist.
var NO_MAILBOX = "nobody@" + DOMAIN;

// An address no parse accepts, so the live read refuses it where the
// release refuses it.
var MALFORMED = "not an address";

// How many wrong passwords spend a budget. The framework's ladder
// engages on the fifth failure inside a quarter of an hour.
var BUDGET_ATTEMPTS = 5;

// Wrong passwords that do not spend one. Far enough below the threshold
// that the counter is still running down when the console reads it.
var COUNTING_ATTEMPTS = 2;

var SHUTDOWN_TIMEOUT_MS = 5000;
var HTTP_TIMEOUT_MS     = 15000;

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;


// ---- a browser, from a named source address --------------------------------
//
// `fetch` has no way to name the local address it dials out from, and
// naming it is half of what these claims rest on, so the requests here
// are node:http.

function request(opts) {
  return new Promise(function (resolve, reject) {
    var req = nodeHttp.request({
      host:         LOOPBACK,
      port:         opts.port,
      localAddress: opts.source,
      method:       opts.method || "GET",
      path:         opts.path,
      headers:      opts.headers || {},
      timeout:      HTTP_TIMEOUT_MS,
    }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { body += chunk; });
      res.on("end", function () {
        resolve({
          status:    res.statusCode,
          headers:   res.headers,
          location:  res.headers.location || "",
          setCookie: res.headers["set-cookie"] || [],
          body:      body,
        });
      });
    });
    req.on("timeout", function () { req.destroy(new Error("http timeout")); });
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

// One browser: one cookie jar, one source address, carried across every
// request it makes. A session that changed address between the sign in
// and the post would be a different peer to this server, which is the
// thing several claims below turn on.
function browser(port, source) {
  var cookies = Object.create(null);

  function absorb(res) {
    for (var i = 0; i < res.setCookie.length; i += 1) {
      var first = res.setCookie[i].split(";")[0];
      var eq = first.indexOf("=");
      if (eq === -1) continue;
      cookies[first.slice(0, eq).trim()] = first.slice(eq + 1).trim();
    }
  }

  function header() {
    return Object.keys(cookies).map(function (k) { return k + "=" + cookies[k]; }).join("; ");
  }

  async function get(path) {
    var res = await request({
      port: port, source: source, path: path,
      headers: { "Cookie": header(), "Host": LOOPBACK + ":" + port },
    });
    absorb(res);
    return res;
  }

  async function post(path, fields) {
    // The token comes off the page the form is on, which is what a
    // browser does and what proves the token this server issues is the
    // one it accepts.
    var page = await get(path);
    var found = /name="_csrf" value="([^"]*)"/.exec(page.body);
    if (!found) throw new Error(path + " carried no token: " + page.body.slice(0, 300));
    var parts = ["_csrf=" + encodeURIComponent(found[1])];
    Object.keys(fields).forEach(function (name) {
      parts.push(encodeURIComponent(name) + "=" + encodeURIComponent(fields[name]));
    });
    var body = parts.join("&");
    var res = await request({
      port:   port,
      source: source,
      method: "POST",
      path:   path,
      headers: {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "Origin":         "http://" + LOOPBACK + ":" + port,
        "Host":           LOOPBACK + ":" + port,
        "Cookie":         header(),
      },
      body: body,
    });
    absorb(res);
    return res;
  }

  // The same post with the token left off, which is what a form on
  // somebody else's page can produce and a form on this one cannot.
  async function postUntokened(path, fields) {
    var parts = [];
    Object.keys(fields).forEach(function (name) {
      parts.push(encodeURIComponent(name) + "=" + encodeURIComponent(fields[name]));
    });
    var body = parts.join("&");
    return request({
      port:   port,
      source: source,
      method: "POST",
      path:   path,
      headers: {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "Host":           LOOPBACK + ":" + port,
        "Cookie":         header(),
      },
      body: body,
    });
  }

  // A form post that changes something answers with a redirect carrying
  // a notice, and the notice is words on the next page rather than the
  // code in the query string. Following it is what the reader does, so
  // it is what these claims read.
  async function postAndFollow(path, fields) {
    var res = await post(path, fields);
    if (res.status !== 302 && res.status !== 303) return res;
    var next = await get(res.location);
    return { status: res.status, location: res.location, body: next.body };
  }

  async function signIn(address, password) {
    var res = await post("/sign-in", { address: address, password: password });
    return { ok: res.status === 302 || res.status === 303, status: res.status, page: res.body };
  }

  return {
    get:            get,
    post:           post,
    postUntokened:  postUntokened,
    postAndFollow:  postAndFollow,
    signIn:         signIn,
  };
}

// ---- an IMAP client, from a named source address ---------------------------

function connectFrom(port, source, label) {
  return new Promise(function (resolve, reject) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port, localAddress: source }, function () {
      resolve(new Wire(socket, label + "@" + source));
    });
    socket.once("error", reject);
  });
}

async function imapAttempt(port, caPem, source, address, password, label) {
  var session = await connectFrom(port, source, "imap-" + label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("x0 STARTTLS");
  await session.read(/^x0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, password));
  var verdict = await session.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  session.close();
  return { ok: /^x1 OK/m.test(verdict), text: verdict };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("lockout-admin");
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

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var operator = await identity.accounts.create({
      address: "operator@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    var carol = await identity.accounts.create({
      address: "carol@" + DOMAIN, password: CAROL_PASSWORD });
    var dave = await identity.accounts.create({
      address: "dave@" + DOMAIN, password: DAVE_PASSWORD });
    var erin = await identity.accounts.create({
      address: "erin@" + DOMAIN, password: ERIN_PASSWORD });
    var frank = await identity.accounts.create({
      address: "frank@" + DOMAIN, password: FRANK_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };
    var httpPort = await reservePort();

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: httpPort, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var imapPort = sections.imap.port;
    var caPem    = leaf.ca;

    var console_ = browser(httpPort, ADMIN_SOURCE);
    var signedIn = await console_.signIn(operator.address, ADMIN_PASSWORD);
    count("the operator signs in to the administration console",
      signedIn.ok === true, "status " + signedIn.status);

    // One machine, holding a password that is no longer the password,
    // retrying. It spends the budget kept against the mailbox and the
    // one kept against that machine and that mailbox together.
    var phone = browser(httpPort, ALICE_PHONE);
    for (var i = 0; i < BUDGET_ATTEMPTS; i += 1) {
      var guess = await phone.signIn(alice.address, WRONG_PASSWORD);
      count("the stale client's wrong password is refused, attempt " + (i + 1),
        guess.ok === false && guess.status === 401, "status " + guess.status);
    }

    // A second machine, mistyping and stopping. Its budget is running
    // down rather than spent, which is the state a page reading only the
    // recorded trail cannot see at all: nothing is recorded until a
    // budget runs out.
    var laptop = browser(httpPort, DAVE_LAPTOP);
    for (var d = 0; d < COUNTING_ATTEMPTS; d += 1) {
      var mistyped = await laptop.signIn(dave.address, WRONG_PASSWORD);
      count("the mistyped password is refused, attempt " + (d + 1),
        mistyped.ok === false && mistyped.status === 401, "status " + mistyped.status);
    }

    var beforeRelease = await imapAttempt(imapPort, caPem, ALICE_DESK,
      alice.address, ALICE_PASSWORD, "before-release");
    count("IMAP refuses the account holder's correct password from a machine that spent " +
      "nothing, so the mailbox itself is locked out",
      beforeRelease.ok === false, visible(beforeRelease.text));

    // 1. The state, before anything is offered. An operator who cannot
    //    see whether the mailbox is locked out is guessing at the same
    //    thing the account holder is.
    var page = await console_.get("/admin/lockouts");
    count("the console answers the operator on the lockouts page",
      page.status === 200, "status " + page.status);
    count("and it names the mailbox that was locked out",
      page.body.indexOf(alice.address) !== -1, page.body.slice(0, 400));
    count("and it names the machine the failures came from, so the operator can release " +
      "that machine's own budget too",
      page.body.indexOf(ALICE_PHONE) !== -1, page.body.slice(0, 400));
    count("and it says when the lockout lifts on its own",
      /lifts|until/i.test(page.body), page.body.slice(0, 400));
    count("and it separates the budget kept against the mailbox from the one kept " +
      "against that machine, because they are released separately",
      /one machine/i.test(page.body) && /from anywhere/i.test(page.body),
      page.body.slice(0, 400));
    count("and it says which of them are still inside the window they were recorded to " +
      "lift in, so the operator is not reading history as a live refusal",
      /inside the window/i.test(page.body), page.body.slice(0, 400));

    // 1c. What the page says about the budgets it CANNOT release, which
    //     is where an operator on a support call actually ends up.
    //
    //     Three bounds can refuse a sign-in and only one of them is on
    //     this page. The mailbox budget is released here and its counter
    //     decays from the last failure. The per-address budget each
    //     listener keeps is a rolling window and behaves the opposite
    //     way: at the ceiling the listener refuses and closes before the
    //     password is read, so nothing further is recorded and the wait
    //     runs from the EARLIEST failure that spent it. Telling an
    //     operator it runs from the last failure inverts the one fact
    //     they need, and sends them to wait out a window that expired
    //     while they were being told to keep waiting.
    //
    //     The browser bound is the third, and an operator locked out of
    //     their own console is usually behind it rather than either of
    //     the other two. A page that never mentions it leaves them
    //     reading a mailbox that says clear while the form keeps
    //     refusing them.
    count("the page does not describe the per-address listener budget as clearing from " +
      "the last failure, which is the mailbox budget's rule and the opposite of this one",
      /clears itself a quarter of an hour after the\s+last failure/i.test(page.body) === false,
      page.body.slice(0, 2400));

    count("it says that budget runs from the earliest failure that spent it, so an " +
      "operator is not told to keep waiting from the wrong end of the window",
      /earliest/i.test(page.body), page.body.slice(0, 2400));

    count("and that going on trying does not push it back, because the listener refuses " +
      "before it reaches the password and records nothing further",
      /does not push the wait back|nothing further is counted/i.test(page.body),
      page.body.slice(0, 2400));

    // The page renders this bound from the value that enforces it, so the
    // check is that the two agree rather than that the page contains a
    // number somebody typed. A page naming a ceiling the server does not
    // hold is worse than one that says nothing: an operator waits out a
    // slot that has already ended, or walks into one they were told they
    // had room inside.
    count("and the page names the browser sign-in bound as well, which is the one an " +
      "operator locked out of this console is usually sitting behind",
      /five-minute|five minute|5-minute/i.test(page.body) &&
      /too many requests/i.test(page.body) &&
      /\bposts\b/i.test(page.body),
      page.body.slice(0, 2400));

    count("and it names a count, which the page renders from the value that enforces " +
      "the bound rather than from a number typed into the prose",
      /\bposts\b[^.]{0,40}?\b\d+\b|\b\d+\b[^.]{0,40}?\bin any\b/i.test(page.body),
      page.body.slice(0, 2400));

    // 1a. The counters, beside the record. A recorded window is what was
    //     written down when a budget ran out; the counter is the thing
    //     that refuses the password now. An operator reading only the
    //     first is reading history and calling it a diagnosis.
    count("each recorded lockout carries the live reading of the budget it names",
      /holding now/i.test(page.body), page.body.slice(0, 1600));

    // 1b. The counters for one mailbox, on request. The trail records a
    //     budget only once it has run out, so a mailbox halfway through
    //     its attempts is on it nowhere and a mailbox nobody has touched
    //     is on it nowhere either. Both are what somebody on a support
    //     call is asking about.
    var askAlice = await console_.get("/admin/lockouts?address=" +
      encodeURIComponent(alice.address));
    count("the console reads the counters for one mailbox on request",
      askAlice.status === 200 && /read the counters for one mailbox/i.test(askAlice.body),
      "status " + askAlice.status);
    count("and answers that the spent budget is holding that mailbox now",
      /holding now/i.test(askAlice.body), askAlice.body.slice(0, 1600));
    count("and does not print an attempt count beside a budget that is already holding, " +
      "because the failure that spends a budget resets that count to zero and printing it " +
      "would say the opposite of what is happening",
      /not a number a held budget can carry/i.test(askAlice.body),
      askAlice.body.slice(0, 1600));

    var askDave = await console_.get("/admin/lockouts?address=" +
      encodeURIComponent(dave.address));
    count("a budget that is still running down reads as clear rather than as held",
      /clear now/i.test(askDave.body), askDave.body.slice(0, 1600));
    count("and carries the failures counted so far, which is the early warning the recorded " +
      "trail cannot give because nothing is recorded until a budget runs out",
      askDave.body.indexOf(COUNTING_ATTEMPTS + " wrong passwords counted") !== -1,
      askDave.body.slice(0, 1600));

    var askCarol = await console_.get("/admin/lockouts?address=" +
      encodeURIComponent(carol.address));
    count("a mailbox that has never failed a sign in reads as clear rather than as an error",
      askCarol.status === 200 && /clear now/i.test(askCarol.body),
      "status " + askCarol.status + " " + askCarol.body.slice(0, 600));

    // 1c. And the read refuses what the release refuses. An answer about
    //     an address this server hosts no mailbox at would be an answer
    //     about nothing, dressed as a fact about a mailbox.
    var askUnhosted = await console_.get("/admin/lockouts?address=" +
      encodeURIComponent(NO_MAILBOX));
    count("a live read of an address this server hosts no mailbox at is refused rather than " +
      "answered about",
      askUnhosted.body.indexOf("no account at " + NO_MAILBOX) !== -1,
      askUnhosted.body.slice(0, 800));

    var askMalformed = await console_.get("/admin/lockouts?address=" +
      encodeURIComponent(MALFORMED));
    count("and a malformed address is refused where the release refuses one",
      /is not a usable mailbox address/i.test(askMalformed.body),
      askMalformed.body.slice(0, 800));

    // 2. The row carries the release straight into the form. During an
    //    incident the operator is copying an address and a machine out of
    //    a table by hand, and a mistyped machine releases nothing while
    //    the mailbox release beside it reports success.
    var fillHref = /href="(\/admin\/lockouts\?address=[^"]*)"/.exec(page.body);
    count("each lockout carries a link that fills the release form in from it",
      fillHref !== null, page.body.slice(0, 800));
    var filled = await console_.get(fillHref[1].replace(/&amp;/g, "&"));
    count("and following it puts the mailbox and the machine into the form, rather than " +
      "leaving the operator to retype them",
      filled.body.indexOf('value="' + alice.address + '"') !== -1 &&
      filled.body.indexOf('value="' + ALICE_PHONE + '"') !== -1,
      filled.body.slice(0, 800));

    // 3. And it does not imply it releases the budget each listener
    //    keeps against a source address, which nothing in this process
    //    can release and which decays on its own.
    count("the page says the budget a listener keeps against a source address is separate",
      /source address/i.test(page.body) && /(not released|separate|decay)/i.test(page.body),
      page.body.slice(0, 600));

    // 4. The release is a state change, so it goes through the same
    //    cross-origin protection every other one on this server does. A
    //    page on another origin can make a browser post here; it cannot
    //    read the token this server issued for this session.
    var untokened = await console_.postUntokened("/admin/lockouts",
      { address: alice.address, reason: "posted from somewhere else" });
    count("a release posted without the token this server issued is refused",
      untokened.status === 403, "status " + untokened.status);

    // 5. A release with no reason is refused. Releasing is the one
    //    operator action that removes a defense, and the audit row is
    //    where it is answered for, so a row with no reason answers
    //    nothing later.
    var noReason = await console_.post("/admin/lockouts",
      { address: alice.address, reason: "" });
    count("a release with no reason is refused",
      noReason.status === 400, "status " + noReason.status);
    count("and the refusal says a reason is what the audit trail needs",
      /reason/i.test(noReason.body), noReason.body.slice(0, 400));

    var stillAfterNoReason = await imapAttempt(imapPort, caPem, ALICE_DESK,
      alice.address, ALICE_PASSWORD, "after-no-reason");
    count("and the budget still refuses the correct password, so nothing was released",
      stillAfterNoReason.ok === false, visible(stillAfterNoReason.text));

    // 6. Only an operator. A signed-in mailbox owner is not one.
    var notOperator = browser(httpPort, BOB_SOURCE);
    var bobIn = await notOperator.signIn(bob.address, BOB_PASSWORD);
    count("an ordinary account signs in", bobIn.ok === true, "status " + bobIn.status);
    var bobTried = await notOperator.post("/admin/lockouts",
      { address: alice.address, reason: "unlock my friend" });
    count("an account that does not administer this server is refused the release",
      bobTried.status === 403, "status " + bobTried.status);

    // Reading is not a lesser action than releasing. Which mailboxes are
    // being guessed at and from where is a map of who is under attack on
    // this server, so the read is behind the same gate the release is.
    var bobAsked = await notOperator.get("/admin/lockouts?address=" +
      encodeURIComponent(alice.address));
    count("and is refused the live state of another account's mailbox",
      bobAsked.status === 403, "status " + bobAsked.status);
    count("and the refusal carries none of that state",
      bobAsked.body.indexOf(alice.address) === -1 &&
      !/holding now/i.test(bobAsked.body) && !/clear now/i.test(bobAsked.body),
      bobAsked.body.slice(0, 400));

    var bobAskedSelf = await notOperator.get("/admin/lockouts?address=" +
      encodeURIComponent(bob.address));
    count("and asking about its own mailbox is refused too, because this console is the " +
      "operator's rather than a mailbox owner's",
      bobAskedSelf.status === 403 && !/clear now/i.test(bobAskedSelf.body),
      "status " + bobAskedSelf.status);

    var stillAfterBob = await imapAttempt(imapPort, caPem, ALICE_DESK,
      alice.address, ALICE_PASSWORD, "after-non-admin");
    count("and the budget still refuses the correct password",
      stillAfterBob.ok === false, visible(stillAfterBob.text));

    // 7. A mailbox that was never locked out. Reporting a release here
    //    would tell the operator the account holder's problem is solved
    //    when it is somewhere else entirely.
    var clear = await console_.postAndFollow("/admin/lockouts",
      { address: carol.address, reason: "reported trouble signing in" });
    count("releasing a mailbox that was not locked out says so rather than reporting a release",
      /already clear|nothing was holding/i.test(clear.body), clear.body.slice(0, 600));

    // 8. The release, naming no machine. It gives the mailbox back and
    //    it is the whole point of the page: the budget released from the
    //    browser is the budget a MAIL listener reads, in one process,
    //    with no restart and no wait.
    var released = await console_.postAndFollow("/admin/lockouts", {
      address: alice.address,
      reason:  "client was sending a password the owner had already changed",
    });
    count("the operator releases the mailbox and the console reports it released",
      /released/i.test(released.body) && !/already clear/i.test(released.body),
      released.body.slice(0, 600));
    count("and names the one budget it acted on rather than reporting a release that could " +
      "have been either of two",
      /the budget kept against the mailbox is released/i.test(released.body),
      released.body.slice(0, 900));

    var afterRelease = await imapAttempt(imapPort, caPem, ALICE_DESK,
      alice.address, ALICE_PASSWORD, "after-release");
    count("and the account holder signs in on IMAP again, in the same process, with no wait",
      afterRelease.ok === true, visible(afterRelease.text));

    // 9. And the machine that did the failing is still refused, because
    //    the budget kept against it was not named and so was not
    //    released. An interface that reported the mailbox released and
    //    left this unsaid would send the operator away from a person who
    //    still cannot read their mail on their phone.
    var phoneStill = await imapAttempt(imapPort, caPem, ALICE_PHONE,
      alice.address, ALICE_PASSWORD, "phone-after-mailbox-release");
    count("the machine that spent its own budget is still refused after a release that " +
      "did not name it", phoneStill.ok === false, visible(phoneStill.text));

    var namedMachine = await console_.postAndFollow("/admin/lockouts", {
      address: alice.address,
      source:  ALICE_PHONE,
      reason:  "the client that was retrying, now holding the current password",
    });
    count("naming the machine releases the budget kept against it",
      /the budget kept against the machine you named is released/i.test(namedMachine.body),
      namedMachine.body.slice(0, 900));
    // The mailbox budget was given back a moment ago, so this release
    // found it clear and only the machine was still holding. Reported as
    // "both released" it would tell the operator the mailbox had been
    // the problem twice over, which is a wrong account of a call that
    // came back precisely because the first release did not reach the
    // device. The notice reads off what was released rather than off
    // what was typed into the form, and that is what lets it say so.
    count("and says which of the two was holding, rather than covering both with one word: " +
      "the mailbox budget was already clear and the machine was the one still refusing",
      /the budget kept against the mailbox was already clear/i.test(namedMachine.body),
      namedMachine.body.slice(0, 900));

    var phoneBack = await imapAttempt(imapPort, caPem, ALICE_PHONE,
      alice.address, ALICE_PASSWORD, "phone-after-source-release");
    count("and that machine signs in again", phoneBack.ok === true, visible(phoneBack.text));

    // 10. The page closes the loop. A lockout the operator has already
    //     given back has to stop reading as one still holding somebody
    //     out, or the next person to open this page releases it again
    //     and is told nothing was locked.
    var settled = await console_.get("/admin/lockouts");
    count("the console shows the released lockouts as released rather than as standing",
      /released/i.test(settled.body) && !/inside the window/i.test(settled.body),
      settled.body.slice(0, 800));

    // 11. The trail. An operator action on somebody else's mailbox that
    //     nothing names an operator for is an action nobody answers for.
    var rows = await b.audit.query({ action: "account.lockout_released", order: "desc", limit: 20 });
    var mine = rows.filter(function (row) { return row.actorUserId === operator.id; });
    count("the audit trail records the release against the operator who made it",
      mine.length >= 1, "rows " + rows.length + ", by this operator " + mine.length);
    count("and the row carries the reason the operator gave",
      mine.some(function (row) {
        return typeof row.reason === "string" &&
          row.reason.indexOf("a password the owner had already changed") !== -1;
      }), JSON.stringify(mine.map(function (row) { return row.reason; })));
    count("and names the mailbox it was made against",
      mine.some(function (row) {
        return typeof row.metadata === "string" && row.metadata.indexOf(alice.address) !== -1;
      }), JSON.stringify(mine.map(function (row) { return row.metadata; })));

    // 12. A lockout counted against an address this server hosts no
    //     mailbox at. The budget is spent against one exactly as it is
    //     against a real mailbox, which is what stops the counters
    //     answering which addresses exist, so the trail carries rows the
    //     console has nothing live to say about. It has to say nothing
    //     rather than say clear, and it has to keep rendering: an
    //     unanswerable question on one row is not a reason to answer the
    //     operator with a failed page.
    //
    //     Left until here because these lockouts stand for a minute of
    //     their own and the claims above read a page that has to have
    //     none standing on it.
    var guesser = browser(httpPort, GUESSER);
    for (var g = 0; g < BUDGET_ATTEMPTS; g += 1) {
      var guessed = await guesser.signIn(NO_MAILBOX, WRONG_PASSWORD);
      count("the guess at an address with no mailbox is refused, attempt " + (g + 1),
        guessed.ok === false && guessed.status === 401, "status " + guessed.status);
    }

    var guessedTrail = await console_.get("/admin/lockouts");
    count("the console still answers with a lockout recorded against an address it hosts no " +
      "mailbox at on the page", guessedTrail.status === 200, "status " + guessedTrail.status);
    count("and names the address that was guessed at",
      guessedTrail.body.indexOf(NO_MAILBOX) !== -1, guessedTrail.body.slice(0, 1600));
    count("and gives it no live reading, rather than reading as a budget that is clear",
      /no live reading/i.test(guessedTrail.body), guessedTrail.body.slice(0, 1600));

    // 13. A machine this server cannot read is a refusal, not half a
    //     release.
    //
    //     The budget kept against one machine is read FIRST when a sign
    //     in is judged, so a machine that has spent its own allowance
    //     stays refused after the mailbox budget has been given back.
    //     That is precisely the case an operator is trying to fix when
    //     they name a machine at all. A release that took a machine it
    //     could not read, released the mailbox, released no machine and
    //     answered with one word would send that operator away from a
    //     person who still cannot read their mail on the one device they
    //     called about.
    //
    //     The submission listener already answers this shape the same
    //     way: a sender the authenticated account does not own refuses
    //     the whole message rather than accepting part of it, on the
    //     reasoning that a half done operation the caller believes
    //     succeeded is worse than a clean refusal. Releasing is the same
    //     bargain. A refusal costs the operator one retype; a false
    //     success costs a second support call.
    //
    //     A second mailbox rather than the first, because this needs a
    //     mailbox whose two budgets are BOTH still spent, and the first
    //     one's were given back above.
    var erinPhone = browser(httpPort, ERIN_PHONE);
    for (var p = 0; p < BUDGET_ATTEMPTS; p += 1) {
      var erinGuess = await erinPhone.signIn(erin.address, WRONG_PASSWORD);
      count("a second stale client's wrong password is refused, attempt " + (p + 1),
        erinGuess.ok === false && erinGuess.status === 401, "status " + erinGuess.status);
    }

    var erinBefore = await imapAttempt(imapPort, caPem, ERIN_DESK,
      erin.address, ERIN_PASSWORD, "erin-before");
    count("IMAP refuses that mailbox from a machine that spent nothing, so the mailbox " +
      "budget is what is holding and the machine budget is holding beside it",
      erinBefore.ok === false, visible(erinBefore.text));

    var unreadable = await console_.post("/admin/lockouts", {
      address: erin.address,
      source:  UNREADABLE_MACHINE,
      reason:  "the account holder named the device rather than an address",
    });
    count("naming a machine this server cannot read refuses the whole release",
      unreadable.status === 400, "status " + unreadable.status);
    count("and says nothing in what was named reads as an address",
      /reads as an address/i.test(unreadable.body), unreadable.body.slice(0, 900));
    count("and sends the operator on to no notice at all, so nothing reports a budget " +
      "released", unreadable.location.indexOf("notice=") === -1,
      "location " + JSON.stringify(unreadable.location));

    var erinAfterRefusal = await imapAttempt(imapPort, caPem, ERIN_DESK,
      erin.address, ERIN_PASSWORD, "erin-after-refusal");
    count("and the mailbox budget is untouched afterwards, so the request was refused whole " +
      "rather than half done under a notice that read as a fix",
      erinAfterRefusal.ok === false, visible(erinAfterRefusal.text));

    // 13a. A post with both halves of the form wrong is answered about
    //      the address. There is one refusal order rather than two: the
    //      mailbox is looked up before the machine is resolved, so an
    //      operator who mistyped the address reads about the address. A
    //      console that resolved the machine ahead of the release to
    //      check it would answer about the machine instead, and send
    //      that operator away to fix the half that was already right.
    var bothWrong = await console_.post("/admin/lockouts", {
      address: NO_MAILBOX,
      source:  UNREADABLE_MACHINE,
      reason:  "both halves of the form are wrong",
    });
    count("a release naming an address with no mailbox and a machine that reads as none is " +
      "refused", bothWrong.status === 400, "status " + bothWrong.status);
    count("and is answered about the address, which is what is checked first, rather than " +
      "about the machine",
      bothWrong.body.indexOf("no account at " + NO_MAILBOX +
        ", so there is no mailbox here to release") !== -1,
      bothWrong.body.slice(0, 900));

    // 13b. Naming no machine at all. The mailbox comes back and the
    //      notice says the machine budget was left alone, which is the
    //      sentence that stops the operator closing the call.
    var mailboxOnly = await console_.postAndFollow("/admin/lockouts", {
      address: erin.address,
      reason:  "the client on that device now holds the current password",
    });
    count("releasing without naming a machine says the mailbox budget is released",
      /the budget kept against the mailbox is released/i.test(mailboxOnly.body),
      mailboxOnly.body.slice(0, 900));
    count("and says the budget kept against a single machine is untouched, rather than " +
      "leaving an operator to read that out of a silence",
      /untouched/i.test(mailboxOnly.body) && /machine/i.test(mailboxOnly.body),
      mailboxOnly.body.slice(0, 900));

    var erinDeskBack = await imapAttempt(imapPort, caPem, ERIN_DESK,
      erin.address, ERIN_PASSWORD, "erin-desk-back");
    count("and the mailbox signs in from a machine that spent nothing",
      erinDeskBack.ok === true, visible(erinDeskBack.text));

    var erinPhoneStill = await imapAttempt(imapPort, caPem, ERIN_PHONE,
      erin.address, ERIN_PASSWORD, "erin-phone-still");
    count("while the machine that spent its own budget is still refused, which is what the " +
      "notice above has to say out loud", erinPhoneStill.ok === false,
      visible(erinPhoneStill.text));

    // 13c. And naming a machine this server can read releases that
    //      machine's own budget and says so as its own answer. The
    //      mailbox budget was given back a moment ago, so the honest
    //      account of this release is that the machine was the only one
    //      of the two still holding: that is the second half of the same
    //      call, and an operator reading "both released" here would be
    //      told the mailbox had been the problem twice.
    var machineReleased = await console_.postAndFollow("/admin/lockouts", {
      address: erin.address,
      source:  ERIN_PHONE,
      reason:  "the device the account holder was calling about",
    });
    count("naming a machine the server can read releases the budget kept against it",
      /the budget kept against the machine you named is released/i.test(machineReleased.body),
      machineReleased.body.slice(0, 900));
    count("and reports the mailbox budget beside it as one that was already clear, so the " +
      "answer names which budget was refusing that device rather than answering two " +
      "questions with one word",
      /the budget kept against the mailbox was already clear/i.test(machineReleased.body),
      machineReleased.body.slice(0, 900));

    var erinPhoneBack = await imapAttempt(imapPort, caPem, ERIN_PHONE,
      erin.address, ERIN_PASSWORD, "erin-phone-back");
    count("and that machine signs in again", erinPhoneBack.ok === true,
      visible(erinPhoneBack.text));

    // 13d. Releasing the same pair again finds neither budget holding,
    //      and says so about both rather than about the mailbox alone. An
    //      operator repeating a release because the account holder called
    //      back has learned something from this answer: the sign-in
    //      budgets are not what is refusing them, and the next place to
    //      look is elsewhere.
    var neitherHolding = await console_.postAndFollow("/admin/lockouts", {
      address: erin.address,
      source:  ERIN_PHONE,
      reason:  "the account holder called back, so both budgets are checked again",
    });
    count("releasing a pair that is already clear says nothing was holding either of them",
      /nothing was holding that mailbox or that machine back/i.test(neitherHolding.body),
      neitherHolding.body.slice(0, 900));

    // 14. A machine recorded as a key rather than as an address.
    //
    //     An IPv6 client is counted under the prefix its site is
    //     allocated, so that rotating the low bits of its own address
    //     does not mint a fresh budget every attempt. That collapsed
    //     form is what the console shows and what an operator copies out
    //     of it, so a release naming it has to find the counter it names.
    //
    //     The failures are spent through the identity layer rather than
    //     over a socket because a client cannot dial a documentation
    //     address from this runner. What is driven here is the release,
    //     which is the console's own path and the one that was reporting
    //     a mailbox released while releasing no machine.
    for (var v = 0; v < BUDGET_ATTEMPTS; v += 1) {
      await identity.accounts.authenticate({
        address: frank.address, password: WRONG_PASSWORD, source: V6_PEER });
    }
    var v6Before = await identity.accounts.lockoutState({
      address: frank.address, source: V6_PEER });
    count("an IPv6 machine is counted under a key rather than under the address it dialled " +
      "from", v6Before.source !== null && v6Before.source !== V6_PEER,
      JSON.stringify(v6Before.source));
    count("and that machine's own budget is holding before the release",
      v6Before.peer !== null && v6Before.peer.locked === true, JSON.stringify(v6Before));

    var v6Key = v6Before.source;
    var v6Page = await console_.get("/admin/lockouts");
    count("the console shows that key, which is what the operator copies into the form",
      v6Page.body.indexOf(v6Key) !== -1, v6Page.body.slice(0, 2400));

    var v6Released = await console_.postAndFollow("/admin/lockouts", {
      address: frank.address,
      source:  v6Key,
      reason:  "the key the console showed, handed straight back to it",
    });
    count("releasing by the key the console showed says both budgets are released",
      /both sign-in budgets are released/i.test(v6Released.body),
      v6Released.body.slice(0, 900));

    var v6After = await identity.accounts.lockoutState({
      address: frank.address, source: v6Key });
    count("and that machine's budget is clear afterwards, rather than nothing being released " +
      "while the mailbox beside it is reported released",
      v6After.peer !== null && v6After.peer.locked === false, JSON.stringify(v6After));

    // 15. The last answer a release can give, and the one that rules a
    //     device out: the mailbox budget was holding and the machine the
    //     operator named was already clear. It is the opposite of the
    //     answer in 13c, and reporting both released here would send the
    //     operator to inspect a machine that never refused anything while
    //     the account holder is refused from a second one nobody has
    //     looked at.
    for (var w = 0; w < BUDGET_ATTEMPTS; w += 1) {
      await identity.accounts.authenticate({
        address: frank.address, password: WRONG_PASSWORD, source: LAST_CLIENT });
    }
    var ruledOut = await console_.postAndFollow("/admin/lockouts", {
      address: frank.address,
      source:  UNUSED_CLIENT,
      reason:  "the machine the account holder named turned out not to be the one failing",
    });
    count("a release whose named machine was already clear reports the mailbox budget as the " +
      "one it gave back",
      /the budget kept against the mailbox is released/i.test(ruledOut.body),
      ruledOut.body.slice(0, 900));
    count("and rules that machine out rather than reporting it released, so the operator is " +
      "not sent to inspect a device that was never refusing anything",
      /the machine you named was already clear/i.test(ruledOut.body),
      ruledOut.body.slice(0, 900));

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "lockout-admin-release",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
