// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two console acts on a sending credential's ceilings, measured on
 * the next message a real client sends.
 *
 * A credential at either ceiling is refused with 452 4.5.3 on SMTP
 * submission and with 429 on `POST /api/send`. The refusal text says an
 * operator can raise the ceiling or give the window back, and both acts
 * are forms on `/admin/credentials`. The counters are held in memory by
 * the registry inside the running process, so a 302 from the console
 * shows only that the route ran. Every claim below reads the effect of an
 * act off the next send instead.
 *
 * Claims:
 *
 *   - A credential filled through submission is refused with 452 4.5.3.
 *     The operator presses "Give the window back" on the credentials
 *     page and confirms it, and the next message through the same
 *     submission listener is accepted and reaches the recipient's mailbox.
 *   - The release reaches only the credential it names. A second
 *     credential in the same domain, filled the same way, is still
 *     refused afterwards, and the page still shows it at its ceiling.
 *   - The release is not tied to one transport. A window filled over
 *     submission is refused with 429 on the sending route as well, and
 *     after the operator releases it the next message over the sending
 *     route is accepted.
 *   - Raising the message ceiling on a full window lets the next message
 *     through on both transports without a release, and the window still
 *     holds everything counted before the raise.
 *   - A window-length change on a full window is refused with 409, and
 *     the message ceiling named in the same post does not move. A ceiling
 *     written as something other than a whole number is refused with 400.
 *   - Both acts ask before acting. A post with no confirmation, a post
 *     confirming a different credential, a post with no reason or a
 *     reason made of spaces, a post with no token, and a post from a
 *     signed-in account that does not administer this server each leave
 *     the credential refused on the wire and write no audit row.
 *   - Each act that goes through writes one audit row naming the
 *     operator's account, the credential, the reason that was typed and
 *     what moved.
 *
 * The operator drives the forms the pages render. The release button's
 * fields and the ceilings form are read off `/admin/credentials`, and the
 * confirming post carries the fields read off the confirmation page.
 *
 * Run standalone: node test/layer-2-integration/sending-credential-console-ceilings.test.js
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

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "opening harbor cassette 5518";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

var CONSOLE_PATH = "/admin/credentials";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Room for three messages. The registry counts the message in front of
// it and refuses it when the count goes past the ceiling, so a message
// ceiling of three accepts three messages and refuses the fourth.
var SMALL_CEILING = 3;

// The message ceiling the raise moves to. It is well above the volume
// this file puts into the window, so no send after the raise reaches it.
var RAISED_CEILING = 50;

// A window length other than the default hour, for the change that has
// to be refused while the window holds anything.
var OTHER_WINDOW_MINUTES = 120;

var SMTP_ACCEPTED   = /^250 /m;
var CEILING_REFUSAL = /^452 4\.5\.3 /m;

var RELEASED     = "domain.sending_credential_ceiling_released";
var CEILINGS_SET = "domain.sending_credential_ceilings_set";

// The sentences the operator types. Each one is distinct, so a row
// carrying one of them cannot be mistaken for the row of another act.
var RELEASE_REASON        = "the order confirmations were checked against the shop's own log";
var SECOND_RELEASE_REASON = "the newsletter run was the application's and has finished";
var RAISE_REASON          = "the seasonal announcement run needs more room than three messages";

// ---- transports ------------------------------------------------------------

var _sequence = 0;

// A marker no other marker in the run contains. The sequence number is
// written at a fixed width, so the first message's marker is not a
// prefix of the tenth's and a mailbox search cannot find one inside the
// other.
function _marker(transport, slug) {
  _sequence += 1;
  return "console-ceiling-" + transport + "-" + slug + "-" + String(_sequence).padStart(4, "0");
}

// One message over SMTP submission under a credential. Every message
// carries a marker in its Subject, so the verdict read off the wire is
// settled against the recipient's mailbox at the end of the run.
async function overSubmission(ctx, token, label) {
  var marker = _marker("smtp", label);
  var session = await Wire.submission(ctx.ports.submission, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "console-ceiling-" + label,
    address: DOMAIN, password: token,
  });
  try {
    session.send("MAIL FROM:<shop@" + DOMAIN + ">");
    var envelope = await session.read(/^\d{3} /m, "MAIL FROM answered");
    if (!SMTP_ACCEPTED.test(envelope)) {
      return { accepted: false, ceiling: false, reply: visible(envelope), marker: marker };
    }
    session.send("RCPT TO:<" + ctx.bob + ">");
    var rcpt = await session.read(/^\d{3} /m, "RCPT TO answered");
    if (!SMTP_ACCEPTED.test(rcpt)) {
      return { accepted: false, ceiling: false, reply: visible(rcpt), marker: marker };
    }
    session.send("DATA");
    await session.read(/^354 /m, "DATA answered");
    session.sendRaw([
      "From: shop@" + DOMAIN,
      "To: " + ctx.bob,
      "Subject: " + marker,
      "Date: Mon, 14 Sep 2026 12:00:00 +0000",
      "Message-ID: <" + marker + "@" + DOMAIN + ">",
      "",
      "A message an application sent under a sending credential.",
      "",
      ".",
      "",
    ].join("\r\n"), "<" + marker + ">");
    var answered = await session.read(/^\d{3} /m, "message answered");
    return {
      accepted: SMTP_ACCEPTED.test(answered),
      ceiling:  CEILING_REFUSAL.test(answered),
      reply:    visible(answered),
      marker:   marker,
    };
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// The same message over the sending route. The reader holds no cookie,
// because the route refuses a request carrying one.
async function overSendRoute(ctx, token, label) {
  var marker = _marker("http", label);
  var answer = await ctx.application.post("/api/send", "application/json", JSON.stringify({
    from: "shop@" + DOMAIN, to: [ctx.bob], subject: marker,
    text: "A message an application sent under a sending credential.",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": marker,
    "Accept":          "application/json",
  });
  return {
    accepted: answer.status === 202,
    ceiling:  answer.status === 429,
    status:   answer.status,
    reply:    answer.status + ": " + String(answer.body).slice(0, 300),
    marker:   marker,
  };
}

// Sends over submission until the credential is refused, and records
// which messages were accepted and which were refused so the mailbox can
// be read against both lists afterwards.
async function fillOverSubmission(ctx, made, label, slug) {
  var accepted = 0;
  for (var i = 0; i < SMALL_CEILING + 2; i += 1) {
    var sent = await overSubmission(ctx, made.token, slug + "-fill");
    if (sent.ceiling) {
      ctx.refused.push(sent.marker);
      count(label + ": once the window is full the submission listener refuses the " +
        "credential with 452 4.5.3, after the message ceiling of " + SMALL_CEILING +
        " let " + SMALL_CEILING + " messages through",
        accepted === SMALL_CEILING, accepted + " accepted; " + sent.reply);
      return;
    }
    count(label + ": a message inside the window is accepted", sent.accepted, sent.reply);
    ctx.delivered.push(sent.marker);
    accepted += 1;
  }
  count(label + ": the credential reaches its ceiling", false,
    "no 452 4.5.3 after " + (SMALL_CEILING + 2) + " messages");
}

// The reading every refused console post is measured by: the credential
// is still refused on the wire. A refused send is counted against the
// window as well, so the window stays full.
async function stillRefusedOnTheWire(ctx, made, label) {
  var sent = await overSubmission(ctx, made.token, "unmoved");
  ctx.refused.push(sent.marker);
  count(label + ", and the submission listener still refuses the credential's next " +
    "message with 452 4.5.3", sent.ceiling, sent.reply);
}

// ---- reading the console ---------------------------------------------------

function _decode(text) {
  return String(text)
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function _attribute(tag, name) {
  var found = new RegExp("\\b" + name + "=\"([^\"]*)\"").exec(tag);
  return found === null ? null : _decode(found[1]);
}

// Every form on a page that posts, with the hidden fields it submits and
// the names of the fields an operator fills in. The `_csrf` field is left
// out because the reader appends the token it holds to every form post.
function postForms(html) {
  var forms = [];
  var formRe = /<form\b[^>]*\bmethod="post"[^>]*>([\s\S]*?)<\/form>/gi;
  var match;
  while ((match = formRe.exec(String(html))) !== null) {
    var hidden = {};
    var typed = [];
    var inputRe = /<(input|select)\b[^>]*>/gi;
    var input;
    while ((input = inputRe.exec(match[1])) !== null) {
      var name = _attribute(input[0], "name");
      if (name === null || name === "_csrf") continue;
      if (input[1].toLowerCase() === "input" && _attribute(input[0], "type") === "hidden") {
        hidden[name] = _attribute(input[0], "value") || "";
      } else {
        typed.push(name);
      }
    }
    forms.push({ markup: match[1], hidden: hidden, typed: typed });
  }
  return forms;
}

function formFor(html, action, id) {
  var forms = postForms(html);
  for (var i = 0; i < forms.length; i += 1) {
    if (forms[i].hidden.action !== action) continue;
    if (id !== undefined && forms[i].hidden.id !== id) continue;
    return forms[i];
  }
  return null;
}

// The table row a credential is listed on, with its whitespace folded so
// a count split across template lines reads as one sentence.
function rowFor(html, id) {
  var text = String(html);
  var start = text.indexOf("<th scope=\"row\"><code>" + id + "</code></th>");
  if (start === -1) return "";
  var end = text.indexOf("</tr>", start);
  return text.slice(start, end === -1 ? text.length : end).replace(/\s+/g, " ");
}

function noticeOf(answer) {
  var location = String(answer.location || "");
  var at = location.indexOf("notice=");
  return at === -1 ? "" : location.slice(at + "notice=".length).split("&")[0];
}

// The same form post with no token in the body or in the header, which is
// the post a page on another site can make a signed-in browser send.
function untokened(reader, fields) {
  var parts = Object.keys(fields).map(function (name) {
    return encodeURIComponent(name) + "=" + encodeURIComponent(fields[name]);
  });
  return reader.post(CONSOLE_PATH, "application/x-www-form-urlencoded", parts.join("&"),
    { "X-CSRF-Token": "" });
}

async function auditRows(action) {
  await b.audit.flush();
  var rows = await b.audit.query({ action: action, order: "desc", limit: 50 });
  return Array.isArray(rows) ? rows : [];
}

// ---- the confirmation, shared by both acts ---------------------------------

// Every way a post can fail to be the operator's confirmed act, each one
// followed by a real send that has to be refused. Returns the page the
// first post answered with, whose form the confirming post is built from.
async function theActIsGated(ctx, opts) {
  var rowsBefore = (await auditRows(opts.auditAction)).length;

  var asked = await ctx.operator.form(CONSOLE_PATH, opts.firstPost);
  count(opts.label + ": the first post answers with a page that asks rather than acting",
    asked.status === 200 && noticeOf(asked) === "",
    asked.status + " " + String(asked.location));
  count(opts.label + ": and the page names the credential it is about to act on",
    String(asked.body).indexOf(opts.made.id) !== -1, String(asked.body).slice(0, 600));
  var confirming = formFor(asked.body, opts.firstPost.action, opts.made.id);
  count(opts.label + ": and it carries a form posting the same act for the same credential, " +
    "with a box for the identifier and a box for the reason",
    confirming !== null && confirming.typed.indexOf("confirm") !== -1 &&
      confirming.typed.indexOf("reason") !== -1,
    JSON.stringify(confirming && { hidden: confirming.hidden, typed: confirming.typed }));
  await stillRefusedOnTheWire(ctx, opts.made, opts.label + ": a post carrying no confirmation");

  var wrong = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, confirming.hidden, {
    confirm: opts.other.id, reason: opts.reason,
  }));
  count(opts.label + ": a confirmation naming a different credential is refused",
    wrong.status === 400 && noticeOf(wrong) === "",
    wrong.status + " " + String(wrong.location));
  count(opts.label + ": and the page says the identifier typed is not the one named",
    /not the identifier named above/i.test(String(wrong.body)),
    String(wrong.body).slice(0, 600));
  await stillRefusedOnTheWire(ctx, opts.made,
    opts.label + ": a post confirming a different credential");

  var noReason = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, confirming.hidden, {
    confirm: opts.made.id,
  }));
  count(opts.label + ": the right identifier with no reason asks again rather than acting",
    noReason.status === 200 && noticeOf(noReason) === "",
    noReason.status + " " + String(noReason.location));
  await stillRefusedOnTheWire(ctx, opts.made, opts.label + ": a post carrying no reason");

  var blank = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, confirming.hidden, {
    confirm: opts.made.id, reason: "     ",
  }));
  count(opts.label + ": a reason made only of spaces asks again rather than acting",
    blank.status === 200 && noticeOf(blank) === "",
    blank.status + " " + String(blank.location));
  await stillRefusedOnTheWire(ctx, opts.made, opts.label + ": a post whose reason is blank");

  var forged = await untokened(ctx.operator, Object.assign({}, confirming.hidden, {
    confirm: opts.made.id, reason: opts.reason,
  }));
  count(opts.label + ": a complete post carrying no token is refused",
    forged.status === 403, forged.status + " " + String(forged.location));
  await stillRefusedOnTheWire(ctx, opts.made, opts.label + ": a post carrying no token");

  var stranger = await ctx.stranger.form(CONSOLE_PATH, Object.assign({}, confirming.hidden, {
    confirm: opts.made.id, reason: opts.reason,
  }));
  // Read off the page as well as the code. The token gate also answers
  // 403, and a stranger whose token had gone wrong would pass on the
  // status alone without the role check ever being reached.
  count(opts.label + ": a complete post from a signed-in account that does not administer " +
    "this server is refused by the role check rather than by the token gate",
    stranger.status === 403 &&
      /does not administer this server/i.test(String(stranger.body)),
    stranger.status + " " + String(stranger.body).slice(0, 300));
  await stillRefusedOnTheWire(ctx, opts.made,
    opts.label + ": a post from an account that does not administer this server");

  console.log("  measured: " + opts.label + " unconfirmed=" + asked.status +
    " wrong=" + wrong.status + " no-reason=" + noReason.status + " blank=" + blank.status +
    " untokened=" + forged.status + " non-admin=" + stranger.status);

  var rowsAfterRefusals = (await auditRows(opts.auditAction)).length;
  count(opts.label + ": none of the refused posts wrote an audit row for the act",
    rowsAfterRefusals === rowsBefore,
    rowsBefore + " rows before, " + rowsAfterRefusals + " after");

  return { confirming: confirming, rowsBefore: rowsBefore };
}

// ---- 1. giving the window back ---------------------------------------------

async function theReleaseLetsTheNextSendThrough(ctx, released, stillFull) {
  var label = "giving the window back";

  var page = await ctx.operator.get(CONSOLE_PATH + "?domain=" + encodeURIComponent(DOMAIN));
  count("the credentials page answers the operator", page.status === 200, String(page.status));
  count("and it shows the filled credential at its message ceiling",
    /at the message ceiling/.test(rowFor(page.body, released.id)), rowFor(page.body, released.id));
  var button = formFor(page.body, "release-window", released.id);
  count("and the credential's row carries the release button, posting the act and the " +
    "credential's identifier",
    button !== null, JSON.stringify(postForms(page.body).map(function (f) { return f.hidden; })));

  var gated = await theActIsGated(ctx, {
    label:       label,
    firstPost:   button.hidden,
    made:        released,
    other:       stillFull,
    reason:      RELEASE_REASON,
    auditAction: RELEASED,
  });

  var held = await ctx.identity.credentials.counters.read(released.id);
  var done = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, gated.confirming.hidden, {
    confirm: released.id, reason: RELEASE_REASON,
  }));
  console.log("  measured: release held=" + held.messages + "/" + held.maxMessages +
    " confirmed=" + done.status + " " + noticeOf(done));
  count(label + ": the typed identifier and a reason let the act through",
    done.status === 302 && noticeOf(done) === "credential-window-released",
    done.status + " " + String(done.location));

  // The question this file exists for.
  var after = await overSubmission(ctx, released.token, "after-release");
  count(label + ": the next message through the SAME submission listener is accepted, so " +
    "the console released the counter the listener reads rather than one of its own",
    after.accepted, after.reply);
  ctx.delivered.push(after.marker);

  var page2 = await ctx.operator.get(CONSOLE_PATH + "?domain=" + encodeURIComponent(DOMAIN));
  count(label + ": the page shows the released credential holding only the one message sent " +
    "since the release, and not at a ceiling",
    /\b1 message\(s\) to 1 recipient\(s\)/.test(rowFor(page2.body, released.id)) &&
      !/at the message ceiling/.test(rowFor(page2.body, released.id)),
    rowFor(page2.body, released.id));

  // The release names one credential and reaches only that one.
  count(label + ": the page still shows the other filled credential at its ceiling",
    /at the message ceiling/.test(rowFor(page2.body, stillFull.id)),
    rowFor(page2.body, stillFull.id));
  var other = await overSubmission(ctx, stillFull.token, "other-after-release");
  ctx.refused.push(other.marker);
  count(label + ": and a second credential in the same domain, filled the same way, is " +
    "still refused with 452 4.5.3, so the release reached only the credential it named",
    other.ceiling, other.reply);

  var rows = await auditRows(RELEASED);
  count(label + ": the act wrote exactly one audit row",
    rows.length === gated.rowsBefore + 1, gated.rowsBefore + " before, " + rows.length + " after");
  var row = rows.length > 0 ? rows[0] : null;
  var meta = row === null ? {} : helpers.metadataOf(row);
  count(label + ": the row names the operator's account in the actor column",
    row !== null && row.actorUserId === ctx.admin.id,
    JSON.stringify(row && row.actorUserId) + " expected " + ctx.admin.id);
  count(label + ": and the credential it released",
    meta.credentialId === released.id, JSON.stringify(meta.credentialId));
  count(label + ": and the domain the credential sends for",
    row !== null && row.resourceId === DOMAIN && meta.domain === DOMAIN,
    JSON.stringify({ resourceId: row && row.resourceId, domain: meta.domain }));
  count(label + ": and the reason the operator typed",
    row !== null && String(row.reason || "").indexOf(RELEASE_REASON) !== -1,
    JSON.stringify(row && row.reason));
  count(label + ": and what the window held when it was released, which is the volume the " +
    "counter reported just before the confirming post",
    meta.messages === held.messages && meta.recipients === held.recipients &&
      meta.messages >= SMALL_CEILING,
    JSON.stringify({ row: { messages: meta.messages, recipients: meta.recipients },
      counted: { messages: held.messages, recipients: held.recipients } }));
}

// ---- 4. the release on the other transport ---------------------------------

async function theReleaseHoldsOnTheSendingRoute(ctx, made) {
  var label = "giving the window back, read on the sending route";

  var before = await overSendRoute(ctx, made.token, "before-release");
  ctx.refused.push(before.marker);
  count(label + ": a window filled over submission refuses the same credential with 429 " +
    "on the sending route, so the two transports read one window",
    before.ceiling, before.reply);

  var page = await ctx.operator.get(CONSOLE_PATH + "?domain=" + encodeURIComponent(DOMAIN));
  var button = formFor(page.body, "release-window", made.id);
  count(label + ": the credential's row carries its own release button",
    button !== null, rowFor(page.body, made.id));
  var asked = await ctx.operator.form(CONSOLE_PATH, button.hidden);
  var confirming = formFor(asked.body, "release-window", made.id);
  count(label + ": the button asks before acting",
    asked.status === 200 && confirming !== null, asked.status + " " + String(asked.location));
  var done = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, confirming.hidden, {
    confirm: made.id, reason: SECOND_RELEASE_REASON,
  }));
  count(label + ": the confirmed release goes through",
    done.status === 302 && noticeOf(done) === "credential-window-released",
    done.status + " " + String(done.location));

  var after = await overSendRoute(ctx, made.token, "after-release");
  count(label + ": the first message after the release, sent over the sending route rather " +
    "than over submission, is accepted",
    after.accepted, after.reply);
  ctx.delivered.push(after.marker);

  var wireAfter = await overSubmission(ctx, made.token, "route-release-wire");
  count(label + ": and submission accepts the credential too",
    wireAfter.accepted, wireAfter.reply);
  ctx.delivered.push(wireAfter.marker);
}

// ---- 2. raising the ceiling ------------------------------------------------

async function theRaiseLetsTheNextSendThrough(ctx, raised, other) {
  var label = "changing the ceilings";

  var page = await ctx.operator.get(CONSOLE_PATH + "?domain=" + encodeURIComponent(DOMAIN));
  var ceilings = formFor(page.body, "set-ceilings");
  count("the credentials page carries the ceilings form, offering the filled credential and " +
    "boxes for both ceilings and the window",
    ceilings !== null &&
      ceilings.markup.indexOf("value=\"" + raised.id + "\"") !== -1 &&
      ceilings.typed.indexOf("id") !== -1 &&
      ceilings.typed.indexOf("maxMessages") !== -1 &&
      ceilings.typed.indexOf("maxRecipients") !== -1 &&
      ceilings.typed.indexOf("windowMinutes") !== -1,
    JSON.stringify(ceilings && { hidden: ceilings.hidden, typed: ceilings.typed }));

  // A number this page cannot read, refused before anything is asked.
  var unreadable = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, ceilings.hidden, {
    id: raised.id, maxMessages: "fifty",
  }));
  count(label + ": a ceiling written as something other than a whole number is refused " +
    "with 400", unreadable.status === 400, unreadable.status + " " +
    String(unreadable.body).slice(0, 300));
  await stillRefusedOnTheWire(ctx, raised, label + ": a ceiling that is not a number");

  var gated = await theActIsGated(ctx, {
    label:       label,
    firstPost:   Object.assign({}, ceilings.hidden, {
      id: raised.id, maxMessages: String(RAISED_CEILING),
    }),
    made:        raised,
    other:       other,
    reason:      RAISE_REASON,
    auditAction: CEILINGS_SET,
  });
  count(label + ": the confirmation page carries the new ceiling into its form, so the " +
    "confirming post sets the number the operator asked for",
    gated.confirming.hidden.maxMessages === String(RAISED_CEILING),
    JSON.stringify(gated.confirming.hidden));

  // The window length is the one field the counters cannot absorb while
  // the window holds anything, so a post moving it with the message
  // ceiling is refused whole.
  var lengthened = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, ceilings.hidden, {
    id: raised.id, maxMessages: String(RAISED_CEILING),
    windowMinutes: String(OTHER_WINDOW_MINUTES),
    confirm: raised.id, reason: RAISE_REASON,
  }));
  count(label + ": moving the window length while the window holds messages is refused " +
    "with 409, and the refusal says to give the window back first",
    lengthened.status === 409 && /give the window back first/i.test(String(lengthened.body)),
    lengthened.status + " " + String(lengthened.body).slice(0, 400));
  var unchanged = await ctx.identity.credentials.counters.read(raised.id);
  count(label + ": and the message ceiling named in the same post did not move",
    unchanged.maxMessages === SMALL_CEILING, JSON.stringify(unchanged));
  await stillRefusedOnTheWire(ctx, raised, label + ": a post moving the window length");
  var rowsAfterLength = (await auditRows(CEILINGS_SET)).length;
  count(label + ": and the refused change wrote no audit row",
    rowsAfterLength === gated.rowsBefore,
    gated.rowsBefore + " before, " + rowsAfterLength + " after");

  var held = await ctx.identity.credentials.counters.read(raised.id);
  var done = await ctx.operator.form(CONSOLE_PATH, Object.assign({}, gated.confirming.hidden, {
    confirm: raised.id, reason: RAISE_REASON,
  }));
  count(label + ": the typed identifier and a reason let the act through",
    done.status === 302 && noticeOf(done) === "credential-ceilings-set",
    done.status + " " + String(done.location));

  var after = await overSubmission(ctx, raised.token, "after-raise");
  count(label + ": the next message through the SAME submission listener is accepted " +
    "without the window being given back",
    after.accepted, after.reply);
  ctx.delivered.push(after.marker);

  var overRoute = await overSendRoute(ctx, raised.token, "after-raise");
  count(label + ": and the next message over the sending route is accepted as well",
    overRoute.accepted, overRoute.reply);
  ctx.delivered.push(overRoute.marker);

  var reading = await ctx.identity.credentials.counters.read(raised.id);
  console.log("  measured: raise held=" + held.messages + "/" + held.maxMessages +
    " after=" + reading.messages + "/" + reading.maxMessages + " smtp=" +
    (after.accepted ? "250" : after.reply) + " route=" + overRoute.status +
    " window-length=" + lengthened.status + " unreadable=" + unreadable.status);
  count(label + ": the window still holds everything counted before the raise plus the two " +
    "messages after it, so the raise let them through rather than a release",
    reading.messages === held.messages + 2 && reading.messages > SMALL_CEILING &&
      reading.maxMessages === RAISED_CEILING,
    JSON.stringify({ before: held.messages, after: reading.messages,
      maxMessages: reading.maxMessages }));

  var rows = await auditRows(CEILINGS_SET);
  count(label + ": the act wrote exactly one audit row",
    rows.length === gated.rowsBefore + 1, gated.rowsBefore + " before, " + rows.length + " after");
  var row = rows.length > 0 ? rows[0] : null;
  var meta = row === null ? {} : helpers.metadataOf(row);
  count(label + ": the row names the operator's account in the actor column",
    row !== null && row.actorUserId === ctx.admin.id,
    JSON.stringify(row && row.actorUserId) + " expected " + ctx.admin.id);
  count(label + ": and the credential whose ceilings moved",
    meta.credentialId === raised.id, JSON.stringify(meta.credentialId));
  count(label + ": and the reason the operator typed",
    row !== null && String(row.reason || "").indexOf(RAISE_REASON) !== -1,
    JSON.stringify(row && row.reason));
  count(label + ": and both readings of the message ceiling, with the recipient ceiling and " +
    "the window recorded as unmoved",
    meta.maxMessagesFrom === SMALL_CEILING && meta.maxMessagesTo === RAISED_CEILING &&
      meta.maxRecipientsFrom === meta.maxRecipientsTo &&
      meta.windowMsFrom === meta.windowMsTo && meta.slicesDropped === false,
    JSON.stringify(meta));
}

// ---- the mailbox -------------------------------------------------------------

async function mailboxText(ctx) {
  var reader = await Wire.imap(ctx.ports.imap, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "console-ceiling-settle",
    address: ctx.bob, password: BOB_PASSWORD,
  });
  try {
    var selectTag = reader.tag();
    reader.send(selectTag + " SELECT INBOX");
    var selected = await reader.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
      "SELECT answered");
    var existing = /^\* (\d+) EXISTS/m.exec(selected);
    var held = existing === null ? 0 : parseInt(existing[1], 10);
    var seen = "";
    for (var seq = 1; seq <= held; seq += 1) {
      var fetchTag = reader.tag();
      reader.send(fetchTag + " FETCH " + seq + " BODY.PEEK[HEADER.FIELDS (SUBJECT)]");
      seen += await reader.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
        "message " + seq + " fetched");
    }
    reader.send(reader.tag() + " LOGOUT");
    return seen;
  } finally {
    reader.close();
  }
}

// A wire code is a claim about what the server did next. The recipient's
// mailbox settles it for every message this file sent.
async function theMailboxAgreesWithTheWire(ctx) {
  var seen = await helpers.waitUntil(async function () {
    var text = await mailboxText(ctx);
    var all = ctx.delivered.every(function (marker) { return text.indexOf(marker) !== -1; });
    return all ? text : false;
  }, {
    timeoutMs:  10000,
    intervalMs: 250,
    label:      "sending-credential-console-ceilings: every accepted message in the mailbox",
  });
  count("every message the wire or the route accepted reached the recipient's mailbox, " +
    "including the ones sent after each console act",
    ctx.delivered.every(function (marker) { return seen.indexOf(marker) !== -1; }),
    ctx.delivered.length + " accepted");
  var leaked = ctx.refused.filter(function (marker) { return seen.indexOf(marker) !== -1; });
  count("and none of the " + ctx.refused.length + " messages refused at a ceiling reached it",
    leaked.length === 0, JSON.stringify(leaked));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-console-ceilings");
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
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "console ceilings test" });

    var admin = await identity.accounts.create({
      address: "operator@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({ address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    // Three credentials with the same small ceiling, one per act, so no
    // act is measured against a window another act already moved.
    function issue(reason) {
      return identity.credentials.create({
        domain: DOMAIN, bounceMailbox: BOUNCE_MAILBOX, reason: reason,
        maxMessages: SMALL_CEILING, maxRecipients: 100,
      });
    }
    var released = await issue("the shop front sends order confirmations");
    var viaRoute = await issue("the newsletter application posts to the sending route");
    var raised   = await issue("the announcement application sends a seasonal run");

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var readerOpts = { ca: material.caPem, servername: HOSTNAME };

    var ctx = {
      identity:    identity,
      admin:       admin,
      bob:         bob.address,
      caPem:       material.caPem,
      ports:       { submission: sections.submission.port, imap: sections.imap.port },
      operator:    browser.browserAt(origin, readerOpts),
      stranger:    browser.browserAt(origin, readerOpts),
      application: browser.browserAt(origin, readerOpts),
      delivered:   [],
      refused:     [],
    };

    var operatorIn = await ctx.operator.signIn(admin.address, ADMIN_PASSWORD);
    count("the operator signs in to the console",
      operatorIn.status === 302 || operatorIn.status === 303,
      operatorIn.status + " " + String(operatorIn.location));
    var strangerIn = await ctx.stranger.signIn(bob.address, BOB_PASSWORD);
    count("an account that does not administer this server signs in too",
      strangerIn.status === 302 || strangerIn.status === 303,
      strangerIn.status + " " + String(strangerIn.location));

    await fillOverSubmission(ctx, released, "the credential to be released", "released");
    await fillOverSubmission(ctx, viaRoute, "the credential released for the sending route",
      "via-route");
    await fillOverSubmission(ctx, raised, "the credential whose ceiling is raised", "raised");

    await theReleaseLetsTheNextSendThrough(ctx, released, viaRoute);
    await theReleaseHoldsOnTheSendingRoute(ctx, viaRoute);
    await theRaiseLetsTheNextSendThrough(ctx, raised, released);
    await theMailboxAgreesWithTheWire(ctx);

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
  name:      "sending-credential-console-ceilings",
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
