// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The bound the sign in form keeps on how often it will be posted to.
 *
 * Every post to the sign in form costs this server one password
 * verification, and it costs it whether or not the address named has a
 * mailbox here: the identity layer burns a verification on a miss on
 * purpose, so timing cannot be used to ask which addresses exist. That
 * makes the form the most expensive unauthenticated route this server
 * has, and the bound in front of it is what stops one client turning
 * that cost into the server's whole CPU.
 *
 * It is NOT the bound on guessing. Guessing is bounded per mailbox, at
 * five failures in a quarter of an hour, and that budget is keyed on the
 * mailbox precisely so that moving between source addresses does not
 * refill it. This one is keyed on the source address and counts POSTS,
 * so it answers a different question: how much work one client may ask
 * for.
 *
 * What makes this worth a file of its own is that a bound like this is
 * easy to declare and easy to leave unenforced, and an unenforced one is
 * invisible. The page describing it renders, the requests all succeed,
 * and nothing anywhere says the number is not the number. So nothing
 * below reads a constant out of the application. The limit is taken from
 * what the server ADVERTISES on its own responses, the run is driven
 * until the server refuses, and the refusal is read for whether it came
 * from a window or from a smoothing bucket that would refill in under a
 * second. A limiter that was deleted outright advertises nothing and
 * refuses nothing, and every claim here fails.
 *
 * Claims:
 *
 *   - The form advertises a limit and a remaining count, the remaining
 *     count reaches zero exactly at the advertised limit, and the very
 *     next post is refused.
 *   - The refusal tells the reader to wait a share of a window rather
 *     than the sub second a token refill would name, so the bound is the
 *     one the console describes rather than a smoothing bucket wearing
 *     the same numbers.
 *   - A second machine that has posted nothing still signs in, so one
 *     client running at the form does not shut the console for everyone.
 *   - The trail names the route that was flooded and the peer it came
 *     from, which is what an operator reading it during an incident has
 *     to be able to tell apart from every other bounded route.
 *
 * Every post below carries an empty password, which the route refuses
 * before it reaches the identity layer. That is deliberate: it isolates
 * this bound from every other gate, because a post that never reaches a
 * credential cannot be refused by a credential budget. The bound is
 * spent by the post rather than by what the post carried, which is
 * exactly the claim.
 *
 * Run standalone: node test/layer-2-integration/signin-attempt-bound.test.js
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

var count       = helpers.count;
var reservePort = wire.reservePort;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// The whole of 127.0.0.0/8 is local, so each reader below can dial out
// from an address of its own and arrive at the server as its own peer.
// A second flood source is held back for the one case the run can meet
// that is not a fault: a five minute window that rolls over mid burst
// hands the first source a fresh count, and the crossing then lands
// somewhere other than where the advertised limit says it should. The
// answer is to run the burst again from a source that has spent nothing.
var FLOOD_SOURCES = ["127.0.0.31", "127.0.0.32"];
var QUIET_SOURCE  = "127.0.0.33";

// An address this server hosts no mailbox at. Nothing below wants a
// mailbox: the posts are refused by the route for carrying no password,
// which is the cheapest way to spend the bound and the only way to spend
// it without also spending something else.
var NO_MAILBOX = "nobody@" + DOMAIN;

// A limit outside this range is not a bound this file can report on. Too
// small and an ordinary sign in would meet it; too large and it is a
// formality rather than a ceiling. The range is deliberately wide: this
// is a sanity check on the advertised number, not a second copy of it.
var SMALLEST_DEFENSIBLE_LIMIT = 5;
var LARGEST_DEFENSIBLE_LIMIT  = 200;

// The longest wait a five minute window can name, which is the window
// itself. The window is aligned to the clock rather than opened by the
// first post, so a refusal names the time to the next boundary and any
// value up to this one is ordinary.
var LONGEST_WINDOW_WAIT_SECONDS = 300;

// How long the run waits before asking a standing refusal again. Long
// enough that a bound refilling several posts a second would have handed
// some back, short enough not to make this file the slowest in the
// suite. Nothing is polled across it: the claim is that nothing changed.
var REFILL_OBSERVATION_MS = 2500;

// How far past the advertised limit the burst will go before giving up.
// A bound that is being kept refuses one post after the count reaches
// zero; a bound that is not kept never refuses at all, and this is what
// stops that case running forever.
function _burstCeiling(limit) { return (limit * 2) + 2; }

var SHUTDOWN_TIMEOUT_MS = 5000;

function _header(res, name) {
  var raw = res.headers[name];
  if (raw === undefined || raw === null) return null;
  var value = Number(Array.isArray(raw) ? raw[0] : raw);
  return isFinite(value) ? value : null;
}

// One run at the form from one source, stopped at the first refusal.
//
// Returns the whole sequence rather than a verdict, because which post
// was refused and what the server said was left before it are the two
// halves of the claim, and a helper that reduced them to a boolean would
// be answering the question this file exists to ask.
async function burstAt(port, source, limit) {
  var reader = browser.browserAt("http://" + LOOPBACK + ":" + port,
    { localAddress: source });
  var remaining = [];
  var ceiling = limit === null ? _burstCeiling(LARGEST_DEFENSIBLE_LIMIT) : _burstCeiling(limit);
  var advertised = limit;
  var refusedAt = 0;
  var refusal = null;

  // When the window this burst is spending began, as closely as a caller
  // can know it: the limiter opens it on the first post it counts, and
  // that is the first one below.
  //
  // Recorded because the wait a refusal names is the REMAINDER of the
  // window, so its size means nothing on its own. Every post here buys
  // one deliberately slow password verification, and on a loaded machine
  // fifty of them can spend most of a five minute window, at which point
  // a correct fixed window names a handful of seconds and looks exactly
  // like a bucket refilling a token.
  var startedAt = Date.now();
  var refusedAtMs = 0;

  for (var posted = 1; posted <= ceiling; posted += 1) {
    var res = await reader.signIn(NO_MAILBOX, "");
    if (advertised === null) advertised = _header(res, "x-ratelimit-limit");
    if (res.status === 429) {
      refusedAt = posted; refusal = res; refusedAtMs = Date.now(); break;
    }
    remaining.push(_header(res, "x-ratelimit-remaining"));
  }

  // A remaining count that goes UP between two posts is a window that
  // rolled over underneath the run. Nothing is wrong when that happens;
  // it just means the burst spanned a boundary and the crossing below
  // would land in the wrong place.
  var rolledOver = false;
  for (var i = 1; i < remaining.length; i += 1) {
    if (remaining[i] !== null && remaining[i - 1] !== null &&
        remaining[i] > remaining[i - 1]) rolledOver = true;
  }

  return {
    source:     source,
    limit:      advertised,
    remaining:  remaining,
    refusedAt:  refusedAt,
    refusal:    refusal,
    rolledOver: rolledOver,
    // Seconds of the window already spent when the refusal arrived.
    spentSec:   refusedAtMs === 0 ? null : (refusedAtMs - startedAt) / 1000,
  };
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("signin-bound");
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
    // Every listener this server runs requires TLS and none has a
    // plaintext mode, so it refuses to start without the pair an
    // operator supplies. The reader below still speaks cleartext HTTP on
    // the browser port, which is the port a terminator would sit in
    // front of and the one the container's own health check polls.
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

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // No mail listener takes a port here. The bound under test is in
    // front of a browser route, and a listener that binds nothing is a
    // listener that cannot fail this run for a reason of its own.
    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var n = 0; n < names.length; n += 1) {
      sections[names[n]] = { enabled: false, port: await reservePort(), address: LOOPBACK };
    }
    var httpPort = await reservePort();

    server = blamepost.create({
      // The TLS port takes whatever the host has free. Nothing here
      // reaches it, and a fixed one collides with any other run on this
      // machine, which is a failure that says nothing about the bound.
      config:       Object.assign({}, cfg,
        { httpPort: httpPort, httpsPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    // 1. The run, from one machine, at the form.
    var burst = await burstAt(httpPort, FLOOD_SOURCES[0], null);
    if (burst.rolledOver && burst.limit !== null) {
      burst = await burstAt(httpPort, FLOOD_SOURCES[1], burst.limit);
    }

    count("the sign in form advertises the bound it keeps, so a reader is told how many " +
      "posts are left rather than finding out by being refused",
      burst.limit !== null, "X-RateLimit-Limit was " + String(burst.limit));

    count("and the number it advertises is a ceiling rather than a formality: high enough " +
      "that a person signing in never meets it, low enough to cap the password " +
      "verifications one machine can ask this server to perform",
      burst.limit !== null &&
      burst.limit >= SMALLEST_DEFENSIBLE_LIMIT &&
      burst.limit <= LARGEST_DEFENSIBLE_LIMIT,
      "limit " + String(burst.limit));

    count("the remaining count falls by one for every post and reaches zero exactly at the " +
      "advertised limit, so what is advertised is what is being counted",
      burst.limit !== null &&
      burst.remaining.length >= burst.limit &&
      burst.remaining[burst.limit - 1] === 0,
      "limit " + String(burst.limit) + ", remaining after each post " +
        JSON.stringify(burst.remaining.slice(0, 4)) + " … " +
        JSON.stringify(burst.remaining.slice(-3)));

    count("the post after the advertised limit is refused, so the bound is enforced rather " +
      "than declared",
      burst.limit !== null && burst.refusedAt === burst.limit + 1,
      burst.refusedAt === 0
        ? "nothing was refused in " + burst.remaining.length + " posts"
        : "refused at post " + burst.refusedAt + " with a limit of " + String(burst.limit));

    var retryAfter = burst.refusal === null ? null : _header(burst.refusal, "retry-after");
    count("and the refusal tells the reader how long to wait",
      retryAfter !== null && retryAfter > 0, "Retry-After was " + String(retryAfter));

    // The wait names a moment inside the window, and that is the whole of
    // what its SIZE can be held to.
    //
    // It is tempting to read a large wait as proof of a window and a small
    // one as proof of a bucket refilling a token, and that reading is
    // wrong. The window is aligned to the clock rather than opened by the
    // first post: the backend takes `Math.floor(now / windowMs) * windowMs`,
    // so what a refusal names is the time to the next boundary, and where a
    // run lands inside the window is arbitrary. Measured on this tree, one
    // run named 266s after spending 0.1s and another named 6s; both were
    // the same correct window. An assertion on the magnitude passes or
    // fails on where the clock happened to be, which is a coin toss wearing
    // the clothes of a check.
    //
    // Which algorithm is running is settled below instead, by waiting long
    // enough for a bucket to have refilled several posts and asking again.
    // That is a behavioral difference and it does not move with the clock.
    count("the wait it names falls inside the window the console describes, so a reader is " +
      "told a moment that belongs to this bound rather than an arbitrary number",
      retryAfter !== null && retryAfter > 0 &&
      retryAfter <= LONGEST_WINDOW_WAIT_SECONDS,
      "Retry-After " + String(retryAfter) + "s against a " +
      LONGEST_WINDOW_WAIT_SECONDS + "s window, refused after spending " +
      (burst.spentSec === null ? "an unknown time" : burst.spentSec.toFixed(1) + "s"));

    // The claim behind the wait. A bound that hands back a share of the
    // budget every second is not the bound the console describes,
    // whatever the two numbers beside it say: it refuses, the client
    // waits a moment, and the run carries on at a rate set by the refill
    // rather than by the limit. So the refusal is asked again after a
    // pause long enough to have refilled several posts' worth, and it
    // has to still be a refusal.
    //
    // `passiveObserve` rather than a poll, because the claim is that
    // nothing changed over the window and there is no condition to wait
    // for. It burns its whole budget by design.
    await helpers.passiveObserve(REFILL_OBSERVATION_MS,
      "sign in bound: whether the refusal lapses on its own within a couple of seconds");
    var stillRefused = await browser
      .browserAt("http://" + LOOPBACK + ":" + httpPort, { localAddress: burst.source })
      .signIn(NO_MAILBOX, "");
    count("and the refusal is still standing seconds later, so the wait an operator is told " +
      "to serve is the wait they actually serve rather than a pause the next post walks " +
      "straight past",
      stillRefused.status === 429, "status " + stillRefused.status);

    // 2. The bound is kept against the machine that spent it. One client
    //    running at the form is a client that has to be stopped; it is
    //    not a reason for everybody else to be shut out of their mail.
    var quiet = browser.browserAt("http://" + LOOPBACK + ":" + httpPort,
      { localAddress: QUIET_SOURCE });
    var signedIn = await quiet.signIn(alice.address, ALICE_PASSWORD);
    count("a machine that has posted nothing still signs in while another is being refused, " +
      "so the bound is kept per source rather than as one count for the whole server",
      signedIn.status === 302 || signedIn.status === 303,
      "status " + signedIn.status);

    // 3. What an operator reads afterwards. A trail that recorded the
    //    peer alone would say a machine was refused somewhere, which is
    //    not something to act on: this server bounds several routes and
    //    the answer to a flood at the sign in form is not the answer to a
    //    flood anywhere else.
    var rows = await b.audit.query({
      action: "system.ratelimit.block", order: "desc", limit: 10 });
    count("the refusal is recorded", rows.length >= 1, "rows " + rows.length);

    var named = rows.filter(function (row) {
      var detail;
      try { detail = JSON.parse(typeof row.metadata === "string" ? row.metadata : "{}"); }
      catch (_e) { return false; }
      return typeof detail.key === "string" &&
        detail.key.indexOf("/sign-in") !== -1 &&
        detail.key.indexOf(burst.source) !== -1;
    });
    count("and the row names both the route that was flooded and the machine it came from, " +
      "so the trail distinguishes a run at the sign in form from a run at any other " +
      "bounded route",
      named.length >= 1,
      JSON.stringify(rows.slice(0, 2).map(function (row) { return row.metadata; })));

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
  name:      "signin-attempt-bound",
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
