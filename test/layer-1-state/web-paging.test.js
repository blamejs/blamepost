// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Reading a folder that holds more messages than one store window.
 *
 * A page is a window over a folder's sequence numbers, and the store
 * offers one shape of read: forward from a floor, capped. So the browser
 * surface has to choose the floor, and the two things it chooses from
 * are the cursor a reader arrived with and the folder's own high-water
 * mark.
 *
 * Those two are not on the same scale after a permanent delete. Every
 * ordinary write moves the mark by one; a delete moves it to a wall
 * clock reading. One purge therefore leaves a folder whose mark reads
 * about a trillion and whose rows are still numbered in the thousands,
 * and every window sized downward from the mark lands in the gap between
 * them.
 *
 * `test/layer-1-state/web-isolation.test.js` pins the small-folder half
 * of that: a purge must not empty the folder. This file pins the half
 * that only appears past the window cap, where finding the rows again is
 * not enough on its own. The read walks up from the bottom a window at a
 * time, and the last window is as short as the folder's row count
 * happens to leave it, so a page taken from that window alone is however
 * many rows fell into it rather than a page.
 *
 * Driven over a real loopback port with a real session, because the
 * question is what the reader is shown.
 *
 * Run standalone: node test/layer-1-state/web-paging.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var web       = require("../../lib/web");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var LOOPBACK = "127.0.0.1";
var DOMAIN   = "example.com";

var READER_PASSWORD = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 20000;

// Enough messages that the folder needs two store windows and the second
// one comes back shorter than a page. Reading the last window alone
// therefore shows thirty rows where fifty belong, which is the shape this
// file exists to catch.
var WINDOW_CAP  = 1000;
var TAIL_ROWS   = 30;
var TOTAL_NOTES = WINDOW_CAP + TAIL_ROWS;

// How far above the folder's row count its high-water mark has to sit
// before a window sized from the mark can no longer reach the rows. A
// purge sets the mark from a clock, so the real distance is nine orders
// of magnitude; anything past a thousand times the row count is already
// off the scale the rows are on.
var OFF_SCALE_MULTIPLE = 1000;

function subjectFor(n) {
  return "Paging note " + n + " of the set";
}

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

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
    agent:     b.mail.agent.create({ store: mailStore, dispatch: { mode: "local" } }),
    store:     identity,
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

function messageFor(recipient, n) {
  var subject = subjectFor(n);
  return Buffer.from(
    "Message-ID: <paging" + n + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\nbody of " + n + "\r\n", "utf8");
}

function cookieJar() {
  var held = Object.create(null);
  return {
    absorb: function (res) {
      var list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
      for (var i = 0; i < list.length; i += 1) {
        var pair = list[i].split(";")[0];
        var eq = pair.indexOf("=");
        if (eq === -1) continue;
        held[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    },
    header: function () {
      var names = Object.keys(held);
      var out = [];
      for (var i = 0; i < names.length; i += 1) out.push(names[i] + "=" + held[names[i]]);
      return out.join("; ");
    },
  };
}

function readerAt(origin) {
  var jar = cookieJar();
  var csrf = "";

  function _headers(extra) {
    return Object.assign({
      "Cookie":     jar.header(),
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) blamepost test reader",
    }, extra || {});
  }

  async function _finish(res) {
    jar.absorb(res);
    return {
      status:   res.status,
      body:     await res.text(),
      location: res.headers.get("location"),
    };
  }

  async function get(path) {
    return _finish(await fetch(origin + path, {
      redirect: "manual",
      headers:  _headers({ "Accept": "text/html" }),
      signal:   AbortSignal.timeout(HTTP_TIMEOUT_MS),
    }));
  }

  return {
    get: get,
    signIn: async function (address, password) {
      var form = await get("/sign-in");
      var found = /name="_csrf" value="([^"]*)"/.exec(form.body);
      csrf = found === null ? "" : found[1];
      return _finish(await fetch(origin + "/sign-in", {
        method:   "POST",
        redirect: "manual",
        headers:  _headers({
          "Content-Type": "application/x-www-form-urlencoded",
          "Origin":       origin,
        }),
        body: "address=" + encodeURIComponent(address) +
          "&password=" + encodeURIComponent(password) +
          "&_csrf=" + encodeURIComponent(csrf),
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      }));
    },
    post: async function (path, payload) {
      return _finish(await fetch(origin + path, {
        method:   "POST",
        redirect: "manual",
        headers:  _headers({
          "Content-Type": "application/x-www-form-urlencoded",
          "Origin":       origin,
          "X-CSRF-Token": csrf,
        }),
        body:   payload + "&_csrf=" + encodeURIComponent(csrf),
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      }));
    },
  };
}

function rowsOn(body) {
  var matches = body.match(/class="msg-subject"/g);
  return matches ? matches.length : 0;
}

// The agent, with every folder read counted. What a page read costs is
// part of what it is: the surface picks a window and widens it when the
// window misses, so a request that can steer the first guess arbitrarily
// far wrong is a request that can order up the widening.
function countingAgent(agent, tally) {
  var wrapped = {};
  Object.keys(agent).forEach(function (name) {
    if (typeof agent[name] !== "function") {
      wrapped[name] = agent[name];
      return;
    }
    wrapped[name] = function () {
      if (name === "search") tally.reads += 1;
      return agent[name].apply(agent, arguments);
    };
  });
  return wrapped;
}

// ---- the vectors ----

// The page a reader lands on, in a folder whose sequence numbers have the
// gap a purge leaves in them. It has to be a full page of the newest
// messages: a short one is the last window's row count showing through,
// and an old one is the first window's.
async function testTheNewestPageSurvivesAPurge(reader) {
  var page = await reader.get("/mail/INBOX");
  count("the folder renders", page.status === 200, page.status);
  count("a full page of messages is shown",
    rowsOn(page.body) === web.PAGE_SIZE,
    rowsOn(page.body) + " rows, expected " + web.PAGE_SIZE);
  count("the newest message is on it",
    page.body.indexOf(subjectFor(TOTAL_NOTES)) !== -1, "missing " + TOTAL_NOTES);
  count("so is the oldest message a full page back",
    page.body.indexOf(subjectFor(TOTAL_NOTES - web.PAGE_SIZE + 1)) !== -1,
    "missing " + (TOTAL_NOTES - web.PAGE_SIZE + 1));
  count("and the one before that is not, so the page is a page rather than the folder",
    page.body.indexOf(subjectFor(TOTAL_NOTES - web.PAGE_SIZE)) === -1,
    "found " + (TOTAL_NOTES - web.PAGE_SIZE));
  count("the purged message is gone",
    page.body.indexOf(subjectFor(1)) === -1, "found the purged one");
}

// Paging back from that first page. The cursor a reader carries is a real
// row's sequence number rather than the folder's mark, so this is the
// read the gap does not reach, and it has to keep working.
async function testThePageBeforeItStillReads(reader) {
  var first = await reader.get("/mail/INBOX");
  var older = /href="(\/mail\/INBOX\?before=[0-9]+)"/.exec(first.body);
  count("the folder offers a way back through older mail",
    older !== null, first.body.indexOf("before=") === -1 ? "no cursor rendered" : "");

  var second = await reader.get(older[1].replace(/&amp;/g, "&"));
  count("the older page renders", second.status === 200, second.status);
  count("it is a full page as well",
    rowsOn(second.body) === web.PAGE_SIZE,
    rowsOn(second.body) + " rows, expected " + web.PAGE_SIZE);
  count("it carries the message just before the first page started",
    second.body.indexOf(subjectFor(TOTAL_NOTES - web.PAGE_SIZE)) !== -1,
    "missing " + (TOTAL_NOTES - web.PAGE_SIZE));
  count("and none of the first page's messages",
    second.body.indexOf(subjectFor(TOTAL_NOTES)) === -1, "the newest is on both pages");
}

// A cursor above everything the folder holds is not a cursor into it. It
// reads as the newest page rather than as an empty one, and it costs the
// same reads as landing on the folder with no cursor at all: a request
// that could steer the first window arbitrarily far above the rows would
// be a request that orders up every widening step behind it.
async function testACursorPastTheFolderReadsAsTheNewestPage(reader, tally) {
  tally.reads = 0;
  var plain = await reader.get("/mail/INBOX");
  var plainReads = tally.reads;

  tally.reads = 0;
  var beyond = await reader.get("/mail/INBOX?before=" + Number.MAX_SAFE_INTEGER);
  count("a cursor past everything renders", beyond.status === 200, beyond.status);
  count("and shows the newest page rather than nothing",
    rowsOn(beyond.body) === web.PAGE_SIZE &&
    beyond.body.indexOf(subjectFor(TOTAL_NOTES)) !== -1,
    rowsOn(beyond.body) + " rows");
  count("it reads the same page the folder reads with no cursor at all",
    rowsOn(beyond.body) === rowsOn(plain.body),
    rowsOn(beyond.body) + " against " + rowsOn(plain.body));
  count("and costs no more folder reads than that one did",
    tally.reads <= plainReads, tally.reads + " reads against " + plainReads);
}

// ---- the drive ----

async function driveTheSurface(identity, wiring) {
  await identity.domains.add({ domain: DOMAIN });
  var reader = await identity.accounts.create({
    address: "reader@" + DOMAIN, password: READER_PASSWORD });

  var stored = [];
  for (var n = 1; n <= TOTAL_NOTES; n += 1) {
    stored.push(identity.mailbox.appendMessage("INBOX",
      messageFor(reader.address, n), { actor: { id: reader.id } }));
  }
  count("the folder holds more messages than one store window",
    stored.length > WINDOW_CAP, stored.length);

  var tally = { reads: 0 };
  var listener = blamepost.web.serve(Object.assign({}, wiring, {
    agent:     countingAgent(wiring.agent, tally),
    address:   LOOPBACK,
    httpPort:  0,
    listeners: function () { return []; },
  }));
  try {
    var ports = await listener.start();
    var client = readerAt("http://" + LOOPBACK + ":" + ports.http);
    var landed = await client.signIn("reader@" + DOMAIN, READER_PASSWORD);
    count("the reader is signed in", landed.status === 302,
      landed.status + " " + landed.body.slice(0, 160));

    // Once on a folder whose numbers run without a gap, where the first
    // window lands on the rows, and again below on one whose numbers
    // have the gap in them. The two are different reads and the cursor
    // has to cost the same on both.
    await testACursorPastTheFolderReadsAsTheNewestPage(client, tally);

    // The purge is what moves the folder's mark onto the other scale, so
    // it runs before every read below rather than being one of them. The
    // oldest message goes, so the newest page is untouched by it and any
    // change to that page is the read getting it wrong.
    var purged = await client.post("/mail/INBOX/actions",
      "action=purge&objectId=" + encodeURIComponent(stored[0].objectid));
    count("the oldest message is purged", purged.status === 302,
      purged.status + " " + purged.body.slice(0, 200));

    var folders = identity.mailbox.accountFolders({ id: reader.id });
    var inbox = folders.filter(function (f) { return f.name === "INBOX"; })[0];
    count("the purge moved the folder's mark off the scale its rows are on",
      inbox.modseqMax > TOTAL_NOTES * OFF_SCALE_MULTIPLE,
      inbox.modseqMax + " against " + TOTAL_NOTES + " rows");

    await testTheNewestPageSurvivesAPurge(client);
    await testThePageBeforeItStillReads(client);
    await testACursorPastTheFolderReadsAsTheNewestPage(client, tally);
  } finally {
    await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS });
  }
}

// ---- runner ----

async function run() {
  var root = helpers.tempDir("web-paging");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    var identity = await store.open(cfg);
    var mailStore = b.mailStore.create({ backend: b.db });
    await driveTheSurface(identity, wiringFor(cfg, identity, mailStore));
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "web-paging", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
