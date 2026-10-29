// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A reply or a forward opened in the browser is derived by the outbound
 * composer, and the derivation is the one the composer applies when it
 * sends a reply outright.
 *
 * Three things about a reply are wrong in ways nobody notices until a
 * conversation has already broken, and each is driven here through the
 * URL the conversation page hands a reader:
 *
 *   Threading. RFC 5322 section 3.6.4 puts the parent's Message-Id in
 *   `In-Reply-To` and the parent's own chain plus the parent in
 *   `References`. An id repeated in that chain is a chain that claims
 *   the same message is two ancestors, and an unbounded one eventually
 *   meets a receiver's header size limit, at which point the message is
 *   refused rather than threaded.
 *
 *   Subject prefixing. A reader answering a reply must not produce
 *   `Re: Re: lunch`, and the prefix that has to be recognized is not
 *   always `Re`: `Aw`, `Sv`, `Antw`, `Odp` and `Re[2]` all name the
 *   same thing, and a reader that recognizes only the English spelling
 *   stacks a second prefix on top of the first every time a German or a
 *   Polish client answers.
 *
 *   What gets quoted. A message with an HTML body and no plain-text
 *   alternative has to be reduced to text before it can be quoted into
 *   a reply's own text part, and the reduction decides what the account
 *   holder sends onward under their own name. Script source and
 *   attribute values are inside the markup and are not what the sender
 *   wrote to be read.
 *
 * The vectors below are what the specification and the composer say,
 * driven over the route rather than against the derivation, because the
 * question is what the account holder is handed.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-1-state/web-compose-draft-derivation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var mailboxModule = require("../../lib/mail/mailbox");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var DOMAIN   = "example.com";
var HOSTNAME = "mx.example.com";
var ALICE    = "alice@" + DOMAIN;
var CAROL    = "carol@peer.example";
var PEER     = "bob@peer.example";
var DANA     = "dana@peer.example";
var DESK     = "desk@peer.example";

// A second account on the same server, holding a message of its own. A
// forward posted from alice's form naming that message must attach
// nothing.
var ERIN          = "erin@" + DOMAIN;
var ERIN_PASSWORD = "copper meadow harbor 7310";

// A departmental address the account holds as well as its own. Mail
// addressed here reaches the same mailbox, and a reply from that
// mailbox must not copy it.
var ALIAS_HELD = "sales@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var HTTP_TIMEOUT_MS = 10000;

// The composer keeps the root of a conversation and the most recent
// ancestors, and nothing between them, so a chain never outgrows a
// receiver's header limit. RFC 5322 section 3.6.4 sets no number; this
// is the one the composer applies.
var MAX_REFERENCES = 20;

// U+202E, which reverses the rendering of everything after it. A display
// name carrying one is how a stranger makes a line read as something
// other than what it says.
var RTL_OVERRIDE = "‮";

// A zero-width joiner holds the three codepoints of this sequence
// together as one glyph. Removing it leaves three separate people, which
// is what happens to a quoted body that is screened as though it were a
// header value.
var FAMILY_EMOJI = "\u{1F468}‍\u{1F469}‍\u{1F467}";

var FIELD_RE = {
  to:         /<input id="to"[^>]*\svalue="([^"]*)"/,
  cc:         /<input id="cc"[^>]*\svalue="([^"]*)"/,
  subject:    /<input id="subject"[^>]*\svalue="([^"]*)"/,
  inReplyTo:  /<input type="hidden" name="inReplyTo" value="([^"]*)"/,
  references: /<input type="hidden" name="references" value="([^"]*)"/,
};

var TEXT_FIELD_RE = /<textarea id="text" name="text"[^>]*>([\s\S]*?)<\/textarea>/;

var FORWARD_OF_RE     = /<input type="hidden" name="forwardOf" value="([^"]*)"/;
var FORWARD_FOLDER_RE = /<input type="hidden" name="forwardFolder" value="([^"]*)"/;
var ATTACHED_NOTE_RE  = /<p class="hint" id="forward-attached">/;
var SOURCE_NOTE_RE    = /<div class="notice notice-warn" role="status" id="source-note">\s*<span[^>]*><\/span>\s*<p>([^<]*)<\/p>/;
var PROBLEM_RE        = /<div class="notice notice-bad" role="alert">\s*<span[^>]*><\/span>\s*<p>([^<]*)<\/p>/;

function matchOf(re, page) {
  var found = re.exec(page.body);
  return found === null ? null : unescapeHtml(found[1]);
}

function unescapeHtml(value) {
  return String(value)
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

function fieldOf(page, name) {
  var found = FIELD_RE[name].exec(page.body);
  return found === null ? null : unescapeHtml(found[1]);
}

function draftTextOf(page) {
  var found = TEXT_FIELD_RE.exec(page.body);
  return found === null ? null : unescapeHtml(found[1]);
}

// The lines of the draft that carry the quotation marker, with the
// marker taken off, which is the text the account holder sends onward.
function quotedLinesOf(page) {
  var text = draftTextOf(page);
  if (text === null) return null;
  return text.split(/\r?\n/)
    .filter(function (line) { return line.indexOf("> ") === 0 || line === ">"; })
    .map(function (line) { return line === ">" ? "" : line.slice(2); })
    .join("\n");
}

// ---- the messages being answered -------------------------------------------

function plainMessage(fields) {
  var lines = [
    "Message-ID: " + fields.messageId,
    "From: " + fields.from,
    "To: " + fields.to,
  ];
  if (fields.cc) lines.push("Cc: " + fields.cc);
  if (fields.replyTo) lines.push("Reply-To: " + fields.replyTo);
  if (fields.references) lines.push("References: " + fields.references);
  lines.push("Subject: " + fields.subject);
  lines.push("Date: Sat, 22 Aug 2026 09:00:00 +0000");
  if (fields.utf8Body) {
    lines.push("MIME-Version: 1.0");
    lines.push("Content-Type: text/plain; charset=utf-8");
  }
  lines.push("");
  lines.push(fields.body === undefined ? "The body." : fields.body);
  lines.push("");
  return Buffer.from(lines.join("\r\n"), "utf8");
}

var HTML_BOUNDARY = "draft-derivation-boundary";

// A message offering both alternatives with nothing in the plain-text
// one, which is the shape that leaves the draft with only markup to
// quote.
function htmlOnlyMessage(marker, html) {
  return Buffer.from([
    "Message-ID: <" + marker + "@peer.example>",
    "From: Dana Reyes <dana@peer.example>",
    "To: " + ALICE,
    "Subject: " + marker,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "MIME-Version: 1.0",
    "Content-Type: multipart/alternative; boundary=\"" + HTML_BOUNDARY + "\"",
    "",
    "--" + HTML_BOUNDARY,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "--" + HTML_BOUNDARY,
    "Content-Type: text/html; charset=utf-8",
    "",
    html,
    "--" + HTML_BOUNDARY + "--",
    "",
  ].join("\r\n"), "utf8");
}

function draftHref(objectId, mode) {
  return "/compose?source=" + encodeURIComponent(objectId) +
    "&folder=INBOX&mode=" + encodeURIComponent(mode);
}

// ---- cases -----------------------------------------------------------------

// Every spelling of a reply prefix a client in another language writes.
// A reader that knows only the English one stacks a second prefix on
// each of these, and the subject line grows a word every time the
// conversation crosses a border.
async function subjectPrefixesAreNotStacked(reader, seeded) {
  var vectors = [
    ["a subject with no prefix",            "lunch",              "Re: lunch"],
    ["a subject already answered once",     "Re: lunch",          "Re: lunch"],
    ["a subject answered twice",            "RE: Re: lunch",      "Re: lunch"],
    ["the German spelling",                 "Aw: Mittagessen",    "Re: Mittagessen"],
    ["the Swedish spelling",                "Sv: lunch",          "Re: lunch"],
    ["the Polish spelling",                 "Odp: obiad",         "Re: obiad"],
    ["a numbered prefix",                   "Re[2]: status",      "Re: status"],
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var seed = seeded["subject-" + i];
    var page = await reader.get(draftHref(seed, "reply"));
    count("reply subject, " + vectors[i][0] + ": the draft renders",
      page.status === 200, "HTTP " + page.status);
    count("reply subject, " + vectors[i][0] + ": " + JSON.stringify(vectors[i][1]) +
      " answers as " + JSON.stringify(vectors[i][2]),
      fieldOf(page, "subject") === vectors[i][2], JSON.stringify(fieldOf(page, "subject")));
  }
}

async function forwardSubjectPrefixesAreNotStacked(reader, seeded) {
  var vectors = [
    ["a subject with no prefix",        "notes",        "Fwd: notes"],
    ["a subject already forwarded",     "Fwd: notes",   "Fwd: notes"],
    ["the short English spelling",      "Fw: notes",    "Fwd: notes"],
    ["the German spelling",             "WG: Notizen",  "Fwd: Notizen"],
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var seed = seeded["forward-subject-" + i];
    var page = await reader.get(draftHref(seed, "forward"));
    count("forward subject, " + vectors[i][0] + ": the draft renders",
      page.status === 200, "HTTP " + page.status);
    count("forward subject, " + vectors[i][0] + ": " + JSON.stringify(vectors[i][1]) +
      " forwards as " + JSON.stringify(vectors[i][2]),
      fieldOf(page, "subject") === vectors[i][2], JSON.stringify(fieldOf(page, "subject")));
  }
}

// The chain a reply hangs off. The parent's own chain, then the parent.
async function theThreadingChainIsBuilt(reader, seeded) {
  var page = await reader.get(draftHref(seeded.threaded, "reply"));
  count("threading: the draft renders", page.status === 200, "HTTP " + page.status);
  count("threading: In-Reply-To names the message being answered",
    fieldOf(page, "inReplyTo") === "<third@peer.example>",
    JSON.stringify(fieldOf(page, "inReplyTo")));
  count("threading: References carries the parent's chain with the parent appended",
    fieldOf(page, "references") ===
      "<first@peer.example> <second@peer.example> <third@peer.example>",
    JSON.stringify(fieldOf(page, "references")));
}

// A parent whose own References already names it. Appending it again
// says the same message is two ancestors of the reply, and a client
// walking the chain reads a conversation that loops.
async function theChainNamesEachAncestorOnce(reader, seeded) {
  var page = await reader.get(draftHref(seeded.selfReferential, "reply"));
  count("threading: a parent already named in its own chain renders",
    page.status === 200, "HTTP " + page.status);
  var chain = fieldOf(page, "references");
  var ids = chain === null ? [] : chain.split(/\s+/).filter(function (t) { return t.length > 0; });
  var unique = ids.filter(function (id, at) { return ids.indexOf(id) === at; });
  count("threading: no ancestor is named twice",
    ids.length === unique.length && ids.length > 0, JSON.stringify(chain));
}

// A long conversation. The chain keeps the root and the most recent
// ancestors, so the header stays inside what a receiver will take.
async function theChainIsBounded(reader, seeded) {
  var page = await reader.get(draftHref(seeded.longChain, "reply"));
  count("threading: a long conversation renders", page.status === 200, "HTTP " + page.status);
  var chain = fieldOf(page, "references");
  var ids = chain === null ? [] : chain.split(/\s+/).filter(function (t) { return t.length > 0; });
  count("threading: the chain is bounded at " + MAX_REFERENCES + " ids",
    ids.length === MAX_REFERENCES, ids.length + " ids");
  count("threading: the root of the conversation is kept",
    ids[0] === "<a0@peer.example>", JSON.stringify(ids[0]));
  count("threading: the message being answered is the last of them",
    ids[ids.length - 1] === "<long-parent@peer.example>", JSON.stringify(ids[ids.length - 1]));
}

// Reply-all. The author comes off her own copy list; everybody else on
// the conversation stays on it.
async function replyAllCopiesTheConversation(reader, seeded) {
  var page = await reader.get(draftHref(seeded.conversation, "reply-all"));
  count("reply-all: the draft renders", page.status === 200, "HTTP " + page.status);
  var cc = fieldOf(page, "cc");
  count("reply-all: the other recipient is copied",
    cc !== null && cc.indexOf(CAROL) !== -1, JSON.stringify(cc));
  count("reply-all: the author is not copied on her own reply",
    cc !== null && cc.toLowerCase().indexOf("alice") === -1, JSON.stringify(cc));
  count("reply-all: the reply is addressed to the sender",
    fieldOf(page, "to") === PEER, JSON.stringify(fieldOf(page, "to")));
}

// The same question asked of an account addressed at an alias it holds.
// A copy list measured against the account's own address alone leaves
// the alias on it, so the reply copies the replier back to themselves
// under the other name they were written to.
async function replyAllDropsEveryAddressTheAccountHolds(reader, seeded) {
  var page = await reader.get(draftHref(seeded.viaAlias, "reply-all"));
  count("reply-all via an alias: the draft renders", page.status === 200, "HTTP " + page.status);
  var cc = fieldOf(page, "cc");
  count("reply-all via an alias: the alias the message was addressed to is not copied back " +
    "to the account that holds it",
    cc !== null && cc.indexOf(ALIAS_HELD) === -1, JSON.stringify(cc));
  count("reply-all via an alias: and the other recipient is still copied, so the exclusion " +
    "did not simply empty the list",
    cc !== null && cc.indexOf(CAROL) !== -1, JSON.stringify(cc));
}

// A `To` that lists a bare address between two named mailboxes. The
// draft is a form the account holder reads before sending, so every
// address the header lists is put on it, and the bare one is not folded
// into the display name of the mailbox after it.
async function replyAllKeepsABareAddressBetweenNamedOnes(reader, seeded) {
  var page = await reader.get(draftHref(seeded.mixedList, "reply-all"));
  count("reply-all over a mixed list: the draft renders", page.status === 200,
    "HTTP " + page.status);
  var cc = fieldOf(page, "cc");
  count("reply-all over a mixed list: the bare address is copied",
    cc !== null && cc.indexOf(DANA) !== -1, JSON.stringify(cc));
  count("reply-all over a mixed list: and so is the named mailbox after it",
    cc !== null && cc.indexOf(CAROL) !== -1, JSON.stringify(cc));
  count("reply-all over a mixed list: and the author is not",
    cc !== null && cc.indexOf(ALICE) === -1, JSON.stringify(cc));
}

// What a message with only markup contributes to the quote. The reader
// sends this onward under their own name, so what the sender wrote to
// be READ is what belongs in it.
async function theQuotedMarkupIsReducedToWhatWasRead(reader, seeded) {
  var vectors = [
    ["an ordinary element",           "<p>Hello there</p>",                 "Hello there"],
    ["a character reference",         "<p>a &amp; b</p>",                   "a & b"],
    ["script source",                 "x<script>alert(1)</script>y",        "xy"],
    ["an attribute holding a bracket", "<a title=\"x>y\">z</a>",            "z"],
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var seed = seeded["html-" + i];
    var page = await reader.get(draftHref(seed, "reply"));
    count("quoting " + vectors[i][0] + ": the draft renders",
      page.status === 200, "HTTP " + page.status);
    var quoted = quotedLinesOf(page);
    count("quoting " + vectors[i][0] + ": the quote carries exactly " +
      JSON.stringify(vectors[i][2]),
      quoted !== null && quoted.trim() === vectors[i][2], JSON.stringify(quoted));
  }
}

// A forward names the message it forwards in a header block, and the
// message itself goes with it as a message/rfc822 part. The draft does
// not quote the body as well, because the attached original carries it.
async function theForwardCarriesTheMessageItNames(reader, seeded) {
  var page = await reader.get(draftHref(seeded.threaded, "forward"));
  count("forward: the draft renders", page.status === 200, "HTTP " + page.status);
  var text = draftTextOf(page);
  count("forward: the header block names the sender, the date and the subject",
    text !== null && text.indexOf("From: " + PEER) !== -1 &&
      text.indexOf("Date: ") !== -1 && text.indexOf("Subject: the third message") !== -1,
    JSON.stringify(text));
  count("forward: the form names the message it will attach",
    matchOf(FORWARD_OF_RE, page) === seeded.threaded &&
      matchOf(FORWARD_FOLDER_RE, page) === "INBOX",
    JSON.stringify([matchOf(FORWARD_OF_RE, page), matchOf(FORWARD_FOLDER_RE, page)]));
  count("forward: the page tells the account holder the original is attached",
    ATTACHED_NOTE_RE.test(page.body), "no attachment hint on the page");
  count("forward: the body is not quoted as well, because the attached original carries it",
    text !== null && text.indexOf("> The body.") === -1, JSON.stringify(text));
  count("forward: the chain of the conversation is carried",
    fieldOf(page, "references") ===
      "<first@peer.example> <second@peer.example> <third@peer.example>",
    JSON.stringify(fieldOf(page, "references")));
  count("forward: and In-Reply-To is left off, because a forward answers nobody",
    fieldOf(page, "inReplyTo") === "", JSON.stringify(fieldOf(page, "inReplyTo")));
}

// The ceiling on the quote. A stored message reaches 50 MiB and every
// octet above the ceiling is carried into the draft, back up on the
// post and out on the wire.
async function theQuoteIsBounded(reader, seeded) {
  var page = await reader.get(draftHref(seeded.huge, "reply"));
  count("quoting: a very long message renders", page.status === 200, "HTTP " + page.status);
  var quoted = quotedLinesOf(page);
  count("quoting: the quote is cut rather than carried whole",
    quoted !== null && Buffer.byteLength(quoted, "utf8") <= b.constants.BYTES.kib(64),
    quoted === null ? "no quote" : Buffer.byteLength(quoted, "utf8") + " bytes");
}

// Half of a draft is written by this server out of header values a
// stranger chose, and half of it is the stranger's message, which the
// account holder has already read on the conversation page. The two
// halves are screened differently, and both directions matter: a bidi
// override in a display name changes what the attribution line LOOKS
// like, and removing zero-width characters from the quotation damages
// ordinary text in several writing systems.
async function theDraftScreensWhatThisServerWroteAndQuotesTheRest(reader, seeded) {
  var page = await reader.get(draftHref(seeded.hostileName, "reply"));
  count("screening: the draft renders", page.status === 200, "HTTP " + page.status);
  var text = draftTextOf(page);
  count("screening: no bidi override reaches the attribution line this server wrote",
    text !== null && text.indexOf(RTL_OVERRIDE) === -1,
    JSON.stringify(text));
  count("screening: and the sender is still named on it",
    text !== null && text.indexOf("Stone") !== -1, JSON.stringify(text));
  count("screening: the quoted body keeps the zero-width joiner that holds an emoji " +
    "sequence together, because the account holder read it that way",
    text !== null && text.indexOf(FAMILY_EMOJI) !== -1,
    JSON.stringify(text === null ? null : text.slice(-120)));
}

// ---- the headers the stored row does not keep, over the route ---------------

// RFC 5322 section 3.6.2: a message carrying Reply-To names where replies
// go. The draft has to read that header from the message itself.
async function aReplyGoesWhereReplyToNames(reader, seeded) {
  var page = await reader.get(draftHref(seeded.withReplyTo, "reply"));
  count("Reply-To: the draft renders", page.status === 200, "HTTP " + page.status);
  count("Reply-To: the reply is addressed to the Reply-To address rather than to From",
    fieldOf(page, "to") === DESK, JSON.stringify(fieldOf(page, "to")));

  var all = await reader.get(draftHref(seeded.withReplyTo, "reply-all"));
  count("Reply-To: a reply-all is addressed there too",
    fieldOf(all, "to") === DESK, JSON.stringify(fieldOf(all, "to")));
}

// RFC 5322 section 3.6.3: a reply-all answers everybody on To and on Cc.
async function aReplyAllKeepsEveryoneOnCc(reader, seeded) {
  var page = await reader.get(draftHref(seeded.withCc, "reply-all"));
  count("Cc: the reply-all draft renders", page.status === 200, "HTTP " + page.status);
  var cc = fieldOf(page, "cc");
  count("Cc: a recipient who was only on Cc is copied on the reply-all",
    cc !== null && cc.indexOf(DANA) !== -1, JSON.stringify(cc));
  count("Cc: the other To recipient is still copied",
    cc !== null && cc.indexOf(CAROL) !== -1, JSON.stringify(cc));
  count("Cc: an alias the account holds is taken off the copy list when it arrived on Cc",
    cc !== null && cc.indexOf(ALIAS_HELD) === -1, JSON.stringify(cc));
  count("Cc: and the author is not copied on her own reply",
    cc !== null && cc.toLowerCase().indexOf("alice") === -1, JSON.stringify(cc));

  var single = await reader.get(draftHref(seeded.withCc, "reply"));
  count("Cc: a plain reply copies nobody",
    fieldOf(single, "cc") === "", JSON.stringify(fieldOf(single, "cc")));
}

// The fields a forward posts back, read off the page the server rendered.
function forwardFieldsOf(page, to) {
  return {
    to:            to,
    subject:       fieldOf(page, "subject") || "",
    text:          draftTextOf(page) || "",
    inReplyTo:     fieldOf(page, "inReplyTo") || "",
    references:    fieldOf(page, "references") || "",
    forwardOf:     matchOf(FORWARD_OF_RE, page) || "",
    forwardFolder: matchOf(FORWARD_FOLDER_RE, page) || "",
  };
}

// RFC 2046 section 5.2.1. The forward that leaves carries the original
// as a message/rfc822 part holding its own headers.
async function aSentForwardCarriesTheOriginal(reader, outbound, seeded) {
  var page = await reader.get(draftHref(seeded.threaded, "forward"));
  var before = outbound.count();
  var posted = await reader.form("/compose", forwardFieldsOf(page, CAROL));
  count("forward sent: the form is accepted", posted.status === 302,
    "HTTP " + posted.status + " " + String(matchOf(PROBLEM_RE, posted)));
  count("forward sent: one message reached the outbound path",
    outbound.count() === before + 1, outbound.count() + " after " + before);
  var out = outbound.last();
  var parts = out === null ? []
    : b.safeMime.extractAttachments(b.safeMime.parse(Buffer.from(out.rfc822, "utf8")));
  var attached = parts.filter(function (part) {
    return String(part.contentType || "").toLowerCase() === "message/rfc822";
  });
  count("forward sent: the message carries a message/rfc822 part",
    attached.length === 1,
    JSON.stringify(parts.map(function (part) { return part.contentType; })));
  var body = attached.length === 1 ? String(attached[0].body || "") : "";
  count("forward sent: the part holds the original with its own Message-ID",
    body.indexOf("Message-ID: <third@peer.example>") !== -1, JSON.stringify(body.slice(0, 160)));
}

// The attachment is named by a form field, so the account posting it is
// the account whose mailbox it is read from. A message identifier this
// account does not hold, or a folder it does not own, attaches nothing
// and sends nothing.
async function aForwardNamingSomebodyElsesMessageSendsNothing(reader, outbound, seeded) {
  var page = await reader.get(draftHref(seeded.threaded, "forward"));
  var vectors = [
    ["another account's message", { forwardOf: seeded.erinsMessage, forwardFolder: "INBOX" }],
    ["a folder this account does not own", { forwardOf: seeded.threaded, forwardFolder: "Nowhere" }],
    ["an identifier nothing answers to", { forwardOf: "obj_0000000000000000", forwardFolder: "INBOX" }],
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var fields = Object.assign(forwardFieldsOf(page, CAROL), vectors[i][1]);
    var before = outbound.count();
    var posted = await reader.form("/compose", fields);
    count("forward naming " + vectors[i][0] + ": the form is refused",
      posted.status === 400, "HTTP " + posted.status);
    count("forward naming " + vectors[i][0] + ": nothing reached the outbound path",
      outbound.count() === before, outbound.count() + " after " + before);
    count("forward naming " + vectors[i][0] + ": the page says why",
      matchOf(PROBLEM_RE, posted) !== null, String(matchOf(PROBLEM_RE, posted)));
  }
}

// Deriving a draft is a read. The message stays unread and no
// modification sequence moves, so an IMAP client and a CONDSTORE client
// see the mailbox as they left it.
async function derivingADraftWritesNothing(reader, identity, actor, sourceReads, seeded) {
  function flagsOf() {
    return identity.mailbox.searchScan(actor, "INBOX").map(function (row) {
      return row.objectid + ":" + row.flags.slice().sort().join("|");
    }).join(" ");
  }
  function modseqOf() {
    return identity.mailbox.accountFolders(actor)
      .filter(function (f) { return f.name === "INBOX"; })[0].modseqMax;
  }
  function seenOf(objectid) {
    var hit = identity.mailbox.searchScan(actor, "INBOX")
      .filter(function (row) { return row.objectid === objectid; })[0];
    return hit ? hit.flags.indexOf("\\Seen") !== -1 : null;
  }

  var flagsBefore  = flagsOf();
  var modseqBefore = modseqOf();
  var readsBefore  = sourceReads.length;
  count("no writes: the message is unread before any draft is derived from it",
    seenOf(seeded.withCc) === false, String(seenOf(seeded.withCc)));

  var modes = ["reply", "reply-all", "forward"];
  for (var i = 0; i < modes.length; i += 1) {
    var page = await reader.get(draftHref(seeded.withCc, modes[i]));
    count("no writes: the " + modes[i] + " draft renders", page.status === 200,
      "HTTP " + page.status);
  }

  var opened = sourceReads.slice(readsBefore).filter(function (read) {
    return read.objectid === seeded.withCc && read.opened === true;
  });
  count("no writes: each draft was derived from the message's own octets",
    opened.length === modes.length, opened.length + " source reads for " + modes.length + " drafts");
  count("no writes: no flag moved on any message in the folder",
    flagsOf() === flagsBefore, flagsBefore + " became " + flagsOf());
  count("no writes: the message is still unread",
    seenOf(seeded.withCc) === false, String(seenOf(seeded.withCc)));
  count("no writes: the folder's highest modification sequence did not move",
    modseqOf() === modseqBefore, modseqBefore + " became " + modseqOf());
}

// A stored message reaches 50 MiB. A message above the source read bound
// is not opened: the draft comes from the stored row, the page says what
// that costs, and a forward quotes rather than attaches.
async function anOversizedMessageIsNotOpened(reader, outbound, sourceReads, seeded) {
  var readsBefore = sourceReads.length;
  var page = await reader.get(draftHref(seeded.oversized, "reply-all"));
  count("oversized: the reply-all draft renders", page.status === 200, "HTTP " + page.status);
  var reads = sourceReads.slice(readsBefore).filter(function (read) {
    return read.objectid === seeded.oversized;
  });
  count("oversized: the source read was asked and did not open the message",
    reads.length === 1 && reads[0].opened === false && reads[0].withheld === "message-too-large",
    JSON.stringify(reads));
  var note = matchOf(SOURCE_NOTE_RE, page);
  count("oversized: the page says Reply-To and Cc were not read",
    note !== null && note.indexOf("Reply-To") !== -1 && note.indexOf("Cc") !== -1,
    String(note));
  count("oversized: the notice names the bound in MiB",
    note !== null && note.indexOf((mailboxModule.MAX_SOURCE_READ_BYTES / b.constants.BYTES.mib(1)) +
      " MiB") !== -1, String(note));
  var quoted = quotedLinesOf(page);
  count("oversized: the quote is still cut at the composer's ceiling",
    quoted !== null && quoted.length > 0 &&
      Buffer.byteLength(quoted, "utf8") <= b.constants.BYTES.kib(64),
    quoted === null ? "no quote" : Buffer.byteLength(quoted, "utf8") + " bytes");

  var forwardPage = await reader.get(draftHref(seeded.oversized, "forward"));
  count("oversized: the forward draft renders", forwardPage.status === 200,
    "HTTP " + forwardPage.status);
  count("oversized: the forward offers no attachment",
    matchOf(FORWARD_OF_RE, forwardPage) === null && !ATTACHED_NOTE_RE.test(forwardPage.body),
    String(matchOf(FORWARD_OF_RE, forwardPage)));
  count("oversized: the forward quotes the message instead",
    (draftTextOf(forwardPage) || "").indexOf("> oversized-body-") !== -1,
    JSON.stringify((draftTextOf(forwardPage) || "").slice(0, 200)));
  var forwardNote = matchOf(SOURCE_NOTE_RE, forwardPage);
  count("oversized: the forward page says the message is quoted rather than attached",
    forwardNote !== null && forwardNote.indexOf("quoted") !== -1, String(forwardNote));

  var fields = forwardFieldsOf(forwardPage, CAROL);
  fields.forwardOf = seeded.oversized;
  fields.forwardFolder = "INBOX";
  var before = outbound.count();
  var posted = await reader.form("/compose", fields);
  count("oversized: a forward posted by hand naming it as an attachment is refused",
    posted.status === 400, "HTTP " + posted.status);
  count("oversized: and nothing reached the outbound path",
    outbound.count() === before, outbound.count() + " after " + before);
}

// ---- the same derivation, given the message's own octets -------------------

// The browser surface hands the composer a message the STORE read, and
// that row carries fewer headers than the message does: it has no
// `Reply-To` and no `Cc`, and it holds no octets to attach. The
// derivation answers all three when it is given the message itself, and
// these vectors are what says so, because the difference is in the
// source rather than in the rule.
async function theBytePathAnswersTheHeadersTheStoredRowDropped(composer) {
  var original = plainMessage({
    messageId: "<byte-path@peer.example>",
    from:      "Bob Stone <" + PEER + ">",
    to:        ALICE + ", " + CAROL,
    cc:        "dana@peer.example",
    replyTo:   "desk@peer.example",
    subject:   "Aw: the quarterly review",
    references: "<first@peer.example>",
  });

  var answered = await composer.reply({
    original: original, from: ALICE, replyAll: true, draft: true,
  });
  count("the byte path addresses the reply to Reply-To rather than to From, which is " +
    "the whole point of that header",
    answered.to.length === 1 && answered.to[0].indexOf("desk@peer.example") !== -1,
    JSON.stringify(answered.to));
  count("reply-all copies the original Cc as well as the original To",
    answered.cc.join(", ").indexOf("dana@peer.example") !== -1, JSON.stringify(answered.cc));
  count("and the replying identity is still off its own copy list",
    answered.cc.join(", ").toLowerCase().indexOf("alice") === -1, JSON.stringify(answered.cc));
  count("the German reply prefix is recognized here too",
    answered.subject === "Re: the quarterly review", JSON.stringify(answered.subject));
  count("and the chain carries the parent's own chain with the parent appended",
    answered.references.join(" ") === "<first@peer.example> <byte-path@peer.example>",
    JSON.stringify(answered.references));

  // The copy list is measured against the addresses the caller says
  // name the replying account. Both directions are pinned, because an
  // exclusion that dropped the alias for some other reason would
  // satisfy the positive claim on its own.
  var addressedAtAlias = plainMessage({
    messageId: "<addressed-at-alias@peer.example>",
    from:      PEER,
    to:        ALIAS_HELD + ", " + CAROL,
    subject:   "addressed to the department",
  });
  var unnamed = await composer.reply({
    original: addressedAtAlias, from: ALICE, replyAll: true, draft: true,
  });
  count("a caller naming no identities has only its author excluded, so the alias it was " +
    "addressed at stays on the copy list",
    unnamed.cc.join(", ").indexOf(ALIAS_HELD) !== -1, JSON.stringify(unnamed.cc));

  var named = await composer.reply({
    original:   addressedAtAlias,
    from:       ALICE,
    identities: [ALICE, ALIAS_HELD],
    replyAll:   true,
    draft:      true,
  });
  count("naming them takes the alias off the copy list",
    named.cc.join(", ").indexOf(ALIAS_HELD) === -1, JSON.stringify(named.cc));
  count("and leaves everybody else on it",
    named.cc.join(", ").indexOf(CAROL) !== -1, JSON.stringify(named.cc));

  var forwarded = await composer.forward({ original: original, draft: true });
  count("a forward given the octets carries the original as a message/rfc822 part, so the " +
    "receiver gets the real headers and the real attachments",
    forwarded.attachments.length === 1 &&
      forwarded.attachments[0].contentType === "message/rfc822",
    JSON.stringify(forwarded.attachments.map(function (a) { return a.contentType; })));
  count("and the part is the message itself rather than a rendering of it",
    Buffer.isBuffer(forwarded.attachments[0].content) &&
      forwarded.attachments[0].content.equals(original),
    String(forwarded.attachments[0].content && forwarded.attachments[0].content.length));
  count("the forward answers nobody, so it names no In-Reply-To",
    forwarded.inReplyTo === undefined, JSON.stringify(forwarded.inReplyTo));
}

// ---- the outbound path a sent forward reaches -------------------------------

function recorder() {
  var sent = [];
  var handle = helpers.standInDelivery({
    send: function (envelope) {
      sent.push({
        to:     (envelope.to || []).slice(),
        rfc822: Buffer.isBuffer(envelope.rfc822)
          ? envelope.rfc822.toString("utf8")
          : String(envelope.rfc822),
      });
      return Promise.resolve({ delivered: (envelope.to || []).slice(), deferred: [], failed: [] });
    },
  });
  return {
    delivery: handle,
    count:    function () { return sent.length; },
    last:     function () { return sent.length === 0 ? null : sent[sent.length - 1]; },
  };
}

// The real mailbox adapter, with every source read it answers recorded.
// Everything else is the adapter's own verb.
function observedMailbox(real, reads) {
  var observed = Object.create(real);
  observed.readMessageSource = function (actorArg, folderName, objectid) {
    var answer = real.readMessageSource(actorArg, folderName, objectid);
    reads.push({
      objectid: objectid,
      opened:   answer !== null && Buffer.isBuffer(answer.bytes),
      withheld: answer === null ? null : answer.withheld,
    });
    return answer;
  };
  return observed;
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-compose-draft-derivation");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });
    // The departmental address alice also holds. Submission binds her
    // `From` against this set, and the copy list is measured against
    // the same one.
    await identity.aliases.add({ address: ALIAS_HELD, destination: ALICE });
    var actor = { id: alice.id };

    function seed(bytes) {
      return identity.mailbox.appendMessage("INBOX", bytes, { actor: actor }).objectid;
    }

    var seeded = {};

    var replySubjects = ["lunch", "Re: lunch", "RE: Re: lunch", "Aw: Mittagessen",
      "Sv: lunch", "Odp: obiad", "Re[2]: status"];
    replySubjects.forEach(function (subject, i) {
      seeded["subject-" + i] = seed(plainMessage({
        messageId: "<subject" + i + "@peer.example>",
        from: PEER, to: ALICE, subject: subject,
      }));
    });

    var forwardSubjects = ["notes", "Fwd: notes", "Fw: notes", "WG: Notizen"];
    forwardSubjects.forEach(function (subject, i) {
      seeded["forward-subject-" + i] = seed(plainMessage({
        messageId: "<fwdsubject" + i + "@peer.example>",
        from: PEER, to: ALICE, subject: subject,
      }));
    });

    seeded.threaded = seed(plainMessage({
      messageId: "<third@peer.example>",
      from: PEER, to: ALICE, subject: "the third message",
      references: "<first@peer.example> <second@peer.example>",
    }));

    seeded.selfReferential = seed(plainMessage({
      messageId: "<loop@peer.example>",
      from: PEER, to: ALICE, subject: "a chain naming its own end",
      references: "<first@peer.example> <loop@peer.example>",
    }));

    var longChain = [];
    for (var n = 0; n < 25; n += 1) longChain.push("<a" + n + "@peer.example>");
    seeded.longChain = seed(plainMessage({
      messageId: "<long-parent@peer.example>",
      from: PEER, to: ALICE, subject: "a long conversation",
      references: longChain.join(" "),
    }));

    seeded.conversation = seed(plainMessage({
      messageId: "<conversation@peer.example>",
      from: PEER, to: ALICE + ", " + CAROL, subject: "the quarterly review",
    }));

    seeded.mixedList = seed(plainMessage({
      messageId: "<mixed-list@peer.example>",
      from: PEER,
      to: "Alice <" + ALICE + ">, " + DANA + ", Carol <" + CAROL + ">",
      subject: "a list mixing named and bare addresses",
    }));

    seeded.viaAlias = seed(plainMessage({
      messageId: "<via-alias@peer.example>",
      from: PEER, to: ALIAS_HELD + ", " + CAROL,
      subject: "addressed to the department",
    }));

    seeded.withReplyTo = seed(plainMessage({
      messageId: "<with-reply-to@peer.example>",
      from: "Bob Stone <" + PEER + ">", to: ALICE, replyTo: DESK,
      subject: "replies go to the desk",
    }));

    seeded.withCc = seed(plainMessage({
      messageId: "<with-cc@peer.example>",
      from: PEER, to: ALICE + ", " + CAROL, cc: DANA + ", " + ALIAS_HELD,
      subject: "a conversation with people on copy",
    }));

    // One octet-count class above the source read bound, carrying both
    // headers the stored row does not keep.
    var bulkLine = new Array(9).join("oversized-body-");
    var bulkLines = Math.ceil(mailboxModule.MAX_SOURCE_READ_BYTES / (bulkLine.length + 2)) + 16;
    var bulk = [];
    for (var m = 0; m < bulkLines; m += 1) bulk.push(bulkLine);
    seeded.oversized = seed(plainMessage({
      messageId: "<oversized@peer.example>",
      from: PEER, to: ALICE, cc: DANA, replyTo: DESK,
      subject: "a message above the source read bound",
      body: bulk.join("\r\n"),
    }));

    var erin = await identity.accounts.create({ address: ERIN, password: ERIN_PASSWORD });
    seeded.erinsMessage = identity.mailbox.appendMessage("INBOX", plainMessage({
      messageId: "<erins-own@peer.example>",
      from: PEER, to: ERIN, subject: "a message in another account",
    }), { actor: { id: erin.id } }).objectid;

    seeded.hostileName = seed(plainMessage({
      messageId: "<hostile-name@peer.example>",
      from: "Bob " + RTL_OVERRIDE + "Stone <" + PEER + ">",
      to: ALICE, subject: "a display name that reverses what follows it",
      utf8Body: true,
      body: "Hello " + FAMILY_EMOJI + " there",
    }));

    var htmlBodies = ["<p>Hello there</p>", "<p>a &amp; b</p>",
      "x<script>alert(1)</script>y", "<a title=\"x>y\">z</a>"];
    htmlBodies.forEach(function (html, i) {
      seeded["html-" + i] = seed(htmlOnlyMessage("html" + i, html));
    });

    // Well above the ceiling, in whole lines so the cut is visible as a
    // shorter quote rather than as a broken one.
    var longLine = new Array(129).join("x");
    var longBody = [];
    for (var k = 0; k < 1600; k += 1) longBody.push(longLine);
    seeded.huge = seed(plainMessage({
      messageId: "<huge@peer.example>",
      from: PEER, to: ALICE, subject: "a very long message",
      body: longBody.join("\r\n"),
    }));

    var deliveryHandle = blamepost.mail.delivery.create({
      hostname: cfg.hostname, dataDir: cfg.dataDir });
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: cfg.dataDir, store: identity });
    // The composer's outbound path records rather than delivers. The
    // claim about a sent forward is about the message that leaves, and a
    // real transport would answer about this host's resolver instead.
    var outbound = recorder();
    var composer = blamepost.mail.compose.create({
      delivery:  outbound.delivery,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    });
    var sourceReads = [];

    listener = blamepost.web.serve({
      agent:     b.mail.agent.create({
        store: identity.messageStore, dispatch: { mode: "local" } }),
      store:     identity,
      mailbox:   observedMailbox(identity.mailbox, sourceReads),
      mailStore: identity.messageStore,
      compose:   composer,
      dkim:      dkimHandle,
      delivery:  deliveryHandle,
      config:    cfg,
      address:   LOOPBACK,
      httpPort:  0,
      listeners: function () { return []; },
    });
    var ports = await listener.start();

    var reader = browser.browserAt("http://" + LOOPBACK + ":" + ports.http,
      { timeoutMs: HTTP_TIMEOUT_MS });
    await reader.signIn(ALICE, ALICE_PASSWORD);

    // First, while every message in the folder is still unread.
    await derivingADraftWritesNothing(reader, identity, actor, sourceReads, seeded);
    await aReplyGoesWhereReplyToNames(reader, seeded);
    await aReplyAllKeepsEveryoneOnCc(reader, seeded);
    await aSentForwardCarriesTheOriginal(reader, outbound, seeded);
    await aForwardNamingSomebodyElsesMessageSendsNothing(reader, outbound, seeded);
    await anOversizedMessageIsNotOpened(reader, outbound, sourceReads, seeded);

    await subjectPrefixesAreNotStacked(reader, seeded);
    await forwardSubjectPrefixesAreNotStacked(reader, seeded);
    await theThreadingChainIsBuilt(reader, seeded);
    await theChainNamesEachAncestorOnce(reader, seeded);
    await theChainIsBounded(reader, seeded);
    await replyAllCopiesTheConversation(reader, seeded);
    await replyAllDropsEveryAddressTheAccountHolds(reader, seeded);
    await replyAllKeepsABareAddressBetweenNamedOnes(reader, seeded);
    await theQuotedMarkupIsReducedToWhatWasRead(reader, seeded);
    await theForwardCarriesTheMessageItNames(reader, seeded);
    await theQuoteIsBounded(reader, seeded);
    await theDraftScreensWhatThisServerWroteAndQuotesTheRest(reader, seeded);
    await theBytePathAnswersTheHeadersTheStoredRowDropped(composer);

    return helpers.getChecks();
  } finally {
    if (listener) {
      try { await listener.stop({ timeoutMs: HTTP_TIMEOUT_MS }); }
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
  name:      "web-compose-draft-derivation",
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
