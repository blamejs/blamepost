// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The removal RFC 8601 section 5 requires, measured against the reader it
 * has to agree with.
 *
 * A receiver adding its own `Authentication-Results` header removes every
 * existing one carrying its own authserv-id first, because a sender that
 * attaches one is handing every downstream consumer a verdict of its own
 * choosing. The removal and the reading are separate code, and the defect
 * class is the removal being narrower than the reading: a header shape the
 * removal skips past and the reader accepts is a verdict a stranger wrote
 * under this server's name.
 *
 * `blamepost.mail.listeners.screenReceiverVerdicts` is the removal, and
 * the claim here is not a list of shapes somebody thought of. It is a
 * property over every shape `b.safeMime.parse` reads as an
 * `Authentication-Results` header, that parser being the one
 * `blamepost.mail.listeners` hands the recipient's Sieve script: whatever
 * it reads as this server's verdict, the screen has to reach. The
 * spellings are built from the grammar rather than written out, so a
 * reader that grows more tolerant is caught by this file rather than by a
 * message.
 *
 * `test/layer-2-integration/inbound-auth-results-smuggling.test.js` drives
 * the same removal over a real SMTP session and a real Sieve script. This
 * file is what covers the shapes that are cheap to state and expensive to
 * put on a wire, and the byte fidelity a delivered message needs.
 *
 * Run standalone: node test/layer-0-primitives/receiver-verdict-screen.test.js
 */

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var listeners = require("../../lib/mail/listeners");
var mailbox   = require("../../lib/mail/mailbox");

var count = helpers.count;
var check = helpers.check;

var screen = listeners.screenReceiverVerdicts;

var RECEIVER  = "mx.example.com";
var FORWARDER = "relay.example.org";

var CLAIMED  = "spf=pass; dkim=pass; dmarc=pass";
var MEASURED = "spf=fail; dkim=none; dmarc=fail";

// The caps a delivered message is parsed under, taken from the module
// that owns them rather than restated. A second set of caps here would
// make this file agree with a reader nothing runs.
var PARSE_CAPS = mailbox.MESSAGE_PARSE_CAPS;

// ---- the spelling grammar --------------------------------------------------

// Every way RFC 5322 and RFC 8601 let one header be written, crossed.
// RFC 5322 section 3.6.8 writes the field name against its colon and
// section 4.5.8 carries the form with whitespace between them; section
// 2.2.3 folds a long value onto continuation lines; RFC 8601 section 2.2
// writes the authserv-id as a bare token or as a quoted string, with an
// optional version after it.
var FIELD_NAMES = ["Authentication-Results", "authentication-results", "AUTHENTICATION-RESULTS"];
var BEFORE_COLON = ["", " ", "\t"];
var AFTER_COLON  = [" ", "", "\r\n\t", "\r\n "];
var IDENTITIES   = ["<id>", "\"<id>\"", "<id> 1"];

function spellingsFor(identity) {
  var out = [];
  for (var f = 0; f < FIELD_NAMES.length; f += 1) {
    for (var c = 0; c < BEFORE_COLON.length; c += 1) {
      for (var a = 0; a < AFTER_COLON.length; a += 1) {
        for (var i = 0; i < IDENTITIES.length; i += 1) {
          out.push({
            label: JSON.stringify(FIELD_NAMES[f] + BEFORE_COLON[c] + ":" +
              AFTER_COLON[a] + IDENTITIES[i].replace("<id>", identity)),
            header: FIELD_NAMES[f] + BEFORE_COLON[c] + ":" + AFTER_COLON[a] +
              IDENTITIES[i].replace("<id>", identity) + "; " + CLAIMED,
          });
        }
      }
    }
  }
  return out;
}

// ---- messages --------------------------------------------------------------

// A delivered message as the funnel sees one: this server's own verdict
// on top, the sender's headers under it. `extra` goes between the two,
// which is where a sender's own header sits once this server has
// prepended its.
function delivered(extra, opts) {
  opts = opts || {};
  var eol = opts.eol || "\r\n";
  var head = [];
  if (opts.receiverWrote !== false) {
    head.push("Authentication-Results: " + RECEIVER + "; " + MEASURED);
  }
  head = head.concat(extra || []).concat([
    "From: sender@evil.example",
    "To: alice@example.com",
    "Subject: probe",
  ]);
  return Buffer.concat([
    Buffer.from(head.join(eol) + eol + eol, "latin1"),
    // Body octets that are not text in any charset this file names, so a
    // screen that decoded the message would change them.
    Buffer.from([0x54, 0x68, 0x65, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x20, 0xc3, 0x28, 0xfe, 0x0d,
      0x0a]),
  ]);
}

// What the reader this server runs makes of a message.
function readAs(bytes) {
  var parsed = b.safeMime.parse(bytes, PARSE_CAPS);
  var raw = (parsed && parsed.headers && parsed.headers.raw) || {};
  return raw["authentication-results"] || [];
}

// Which of those values claim to have been written by this server. RFC
// 8601 section 2.2 puts the authserv-id first, optionally quoted and
// optionally followed by a version token.
function claimingReceiver(values) {
  var mine = [];
  for (var i = 0; i < values.length; i += 1) {
    var head = b.structuredFields.splitUnquoted(values[i], ";")[0];
    if (head === undefined || head === null) continue;
    head = String(head).trim();
    var space = head.search(/[ \t]/);
    var identity = b.structuredFields.stripDoubleQuotes(
      space === -1 ? head : head.slice(0, space)).trim();
    if (identity === RECEIVER) mine.push(values[i]);
  }
  return mine;
}

// ---- cases -----------------------------------------------------------------

// The property. Every spelling the reader takes for this server's own
// verdict, the screen has to reach. A spelling the reader does not take
// is not this file's business and is skipped rather than counted, because
// a reader that stopped reading a shape is a different change from a
// screen that stopped removing one.
function theScreenIsNeverNarrowerThanTheReader() {
  var spellings = spellingsFor(RECEIVER);
  var exercised = 0;
  for (var s = 0; s < spellings.length; s += 1) {
    var forged = delivered([spellings[s].header]);
    var before = claimingReceiver(readAs(forged));
    if (before.length < 2) continue;
    exercised += 1;
    var after = claimingReceiver(readAs(screen(forged, RECEIVER, true)));
    check("the sender's verdict at " + spellings[s].label + " does not survive the screen, " +
      "and this server's own does: " + JSON.stringify(after), after.length === 1);
    check("and the one left is the failure this server measured, not the pass the sender " +
      "wrote: " + JSON.stringify(after), /dmarc=fail/.test(after[0]));
  }
  // A property proved over nothing is a property nobody checked. The
  // grammar above is 108 spellings and the reader takes most of them, so
  // a number far below that says the reader moved and this file went
  // quiet rather than red.
  count("the reader took enough of the grammar for the property to mean something",
    exercised >= 60, exercised + " of " + spellings.length + " spellings exercised");
}

// A verdict this server did not write is not made trustworthy by being
// the only one on the message. A message an account submitted carries no
// computed verdict, so every claim under this server's name on it is the
// sender's.
function nothingUnderThisNameSurvivesAMessageThisServerDidNotAuthenticate() {
  var spellings = spellingsFor(RECEIVER);
  var exercised = 0;
  for (var s = 0; s < spellings.length; s += 1) {
    var forged = delivered([spellings[s].header], { receiverWrote: false });
    if (claimingReceiver(readAs(forged)).length === 0) continue;
    exercised += 1;
    var after = claimingReceiver(readAs(screen(forged, RECEIVER, false)));
    check("nothing claiming this server survives " + spellings[s].label + " on a message it " +
      "authenticated nothing about: " + JSON.stringify(after), after.length === 0);
  }
  count("the grammar reached the unauthenticated case too",
    exercised >= 60, exercised + " of " + spellings.length + " spellings exercised");
}

// The control. RFC 8601 section 5 removes the receiver's own record and
// nothing else, because a record an earlier hop wrote is what it found
// before this server saw the message.
function apriorHopsRecordIsUntouched() {
  var spellings = spellingsFor(FORWARDER);
  for (var s = 0; s < spellings.length; s += 1) {
    var message = delivered([spellings[s].header]);
    var screened = screen(message, RECEIVER, true);
    check("a record naming another receiver at " + spellings[s].label + " is left where it " +
      "was, byte for byte", screened.equals(message));
  }
}

// A message carrying nothing to remove comes back as itself. The screen
// reads a header block and never rewrites one it did not change, so a
// delivered message is the octets the peer transmitted.
function amessageWithNothingToRemoveIsUnchanged() {
  var plain = delivered([]);
  count("a message carrying only this server's own verdict is returned unchanged",
    screen(plain, RECEIVER, true).equals(plain), plain.length + " octets");

  var none = delivered([], { receiverWrote: false });
  count("and so is one carrying no such header at all",
    screen(none, RECEIVER, false).equals(none), none.length + " octets");
}

// The body is octets and stays octets. A screen that decoded the message
// would turn every byte sequence it could not read into a replacement
// character, which changes the message this server stores and the copy a
// forward puts back on the wire.
function thebodyIsNeverDecoded() {
  var forged = delivered(["Authentication-Results:", "\t" + RECEIVER + "; " + CLAIMED]);
  var screened = screen(forged, RECEIVER, true);
  var brk = mailbox.headerBreak(forged);
  var body = forged.slice(brk.at + brk.terminator * 2);
  var screenedBrk = mailbox.headerBreak(screened);
  var screenedBody = screened.slice(screenedBrk.at + screenedBrk.terminator * 2);
  count("the body of a screened message is the octets it arrived as",
    screenedBody.equals(body), JSON.stringify(screenedBody.toString("latin1")));
  count("and the message got shorter, so something really was removed",
    screened.length < forged.length, forged.length + " to " + screened.length);
}

// Where the header block ends is asked of the one derivation that answers
// it, and that derivation reads a bare LF as an end of line. A screen
// that searched for the CRLF spelling alone would read a message written
// with bare LF as headers all the way down, and the sender would then
// choose which of its own body lines the screen treats as a header.
function abareLfMessageIsScreenedTheSameWay() {
  var forged = delivered(["Authentication-Results: " + RECEIVER + "; " + CLAIMED],
    { eol: "\n" });
  count("the reader takes both verdicts off a message written with bare LF",
    claimingReceiver(readAs(forged)).length === 2,
    JSON.stringify(claimingReceiver(readAs(forged))));
  var after = claimingReceiver(readAs(screen(forged, RECEIVER, true)));
  count("and the screen leaves one of them", after.length === 1, JSON.stringify(after));
  count("which is the one this server wrote",
    after.length === 1 && /dmarc=fail/.test(after[0]), JSON.stringify(after));
}

// The topmost claim is this server's, because this server prepends it.
// Keeping any other one would be keeping a verdict a sender chose from a
// message where this server had already written its own.
function theverdictKeptIsTheTopmost() {
  var forged = delivered([
    "Authentication-Results: " + RECEIVER + "; spf=pass; dmarc=pass",
    "Authentication-Results:", "\t" + RECEIVER + "; spf=pass; dmarc=pass",
  ]);
  var after = claimingReceiver(readAs(screen(forged, RECEIVER, true)));
  count("one verdict under this server's name is left out of three",
    after.length === 1, JSON.stringify(after));
  count("and it is the one at the top, which is the one this server prepended",
    after.length === 1 && /dmarc=fail/.test(after[0]), JSON.stringify(after));
}

// Construction refuses nothing and returns the message when it is given
// no identity to screen against. A server with no authserv-id wrote no
// verdict, so it has no name on the message to defend.
function anemptyAuthservIdChangesNothing() {
  var forged = delivered(["Authentication-Results: " + RECEIVER + "; " + CLAIMED]);
  count("a screen with no identity to defend returns the message",
    screen(forged, "", true).equals(forged), forged.length + " octets");
}

// ---- runner ----------------------------------------------------------------

async function run() {
  theScreenIsNeverNarrowerThanTheReader();
  nothingUnderThisNameSurvivesAMessageThisServerDidNotAuthenticate();
  apriorHopsRecordIsUntouched();
  amessageWithNothingToRemoveIsUnchanged();
  thebodyIsNeverDecoded();
  abareLfMessageIsScreenedTheSameWay();
  theverdictKeptIsTheTopmost();
  anemptyAuthservIdChangesNothing();
  return helpers.getChecks();
}

module.exports = { name: "receiver-verdict-screen", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
