// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * published-bound-parity: the bounds this server publishes are bounds
 * this repository holds, and every place that has to name one does.
 *
 * Three of them are published to operators and none of them used to be
 * set here. SECURITY.md names a socket ceiling of 1024 per listener and a
 * body-rate floor of a hundred bytes a second, and says neither is
 * settable. THREAT-MODEL.md says MIME is parsed under EXPLICIT caps. All
 * three were the vendored framework's defaults, which the framework is
 * free to move: a refresh would have changed what this server accepts
 * while the shipped documents went on naming the old numbers, and nothing
 * anywhere would have said so.
 *
 * Five more are published as SETTINGS, in the operator guide's ceilings
 * table, each with the value it ships at. A setting is the harder case
 * rather than the easier one. The field an operator writes reaches the
 * listener because they wrote it, so the half that can rot is the value
 * that governs when they write nothing, and there is no configuration
 * anywhere in which that half is visible. The message ceiling is the
 * worked example: the listeners advertised it on every EHLO and the
 * message store was built without being told it, so a message inside the
 * advertised number was taken in full and refused at the append.
 *
 * The wire vectors in layer 2 measure each of the three on a real
 * listener, which is what proves the bound is applied. They cannot answer
 * the question this file asks, and the difference matters: a vector that
 * reads 1024 off a listener reads the same 1024 whether this repository
 * set it or inherited it, so it passes for the wrong reason and a
 * divergence between the document and the framework is invisible to it.
 *
 * So this file asks the other half, at the cheapest layer:
 *
 *   - The documents still publish the numbers. A bound quietly dropped
 *     from SECURITY.md leaves the code holding a promise nobody made.
 *   - The exported constants equal them, written out here the way the
 *     documents write them rather than read back off the framework. A
 *     parser asked to confirm its own default agrees with itself before a
 *     refresh and after one.
 *   - The values are held rather than borrowed: the module that defines
 *     each one carries the number as a literal and does not compute it
 *     from the framework's own table.
 *   - Every site that has to pass one does. This is the half that rots
 *     first, because a constant can be declared, exported, asserted here,
 *     and never reach the call that acts on it: five listener builders
 *     name the socket ceiling, the limits builder names the floor, both
 *     places the message store is built name the structure caps, and
 *     every MIME parse in lib/ names them too. A parse left on the
 *     parser's defaults is the word "explicit" being false on exactly the
 *     path that decides delivery.
 *
 * No sockets, no database. It reads three shipped documents, the source
 * files that hold and pass the numbers, and the exported constants.
 *
 * Run standalone: node test/layer-0-primitives/published-bound-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var listeners = require("../../lib/mail/listeners");
var mailbox   = require("../../lib/mail/mailbox");
var config    = require("../../lib/config");

var check = helpers.check;
var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

// The numbers the documents publish, written here as the documents write
// them. Read off the framework instead and every case below would assert
// that the framework agrees with itself, which is the one thing that
// stays true across the refresh this file exists to catch.
var DOCUMENTED_SOCKET_CEILING       = 1024;
var DOCUMENTED_FLOOR_BYTES_PER_SECOND = 100;

// The two structure caps. No shipped document spells these out as
// numbers; THREAT-MODEL.md promises that caps exist and that they are
// explicit, and `test/layer-2-integration/mime-structure-caps.test.js`
// measures them on the wire at these values. They are restated here so
// the constant and the vector cannot drift apart without one of them
// failing.
var MEASURED_MAX_NESTING_DEPTH = 16;
var MEASURED_MAX_PARTS         = 64;

// The five ceilings docs/operator-guide.md lists in its own table under
// Connection and message ceilings, written here as that table writes
// them. Four of them bound one source address and the fifth bounds one
// message; all five are fields an operator may lower, so unlike the two
// above they are published AS settings with a shipped value beside each.
//
// A shipped value is the half that rots. A field an operator sets
// reaches the listener because they set it, and a field they leave alone
// reaches whatever the code puts there when nobody named one, which is
// the framework's own table unless this repository writes a number.
var DOCUMENTED_LIMIT_DEFAULTS = Object.freeze({
  maxConcurrentConnectionsPerIp: 10,
  connectionsPerIpPerMinute:     60,
  authFailuresPerIpPer15Min:     10,
  rcptFailuresPerIpPerMinute:    50,
  maxMessageBytes:               52428800,
});

// A stored body is base64 inside a seal that is itself base64, so the
// file on disk is sixteen ninths of the message. Measured rather than
// assumed: at 1, 8 and 32 mebibytes the factor comes out 1.7800, 1.7781
// and 1.7778, converging on 16/9 with the seal header falling away.
var BLOB_SEAL_EXPANSION = 16 / 9;

function _read(relative) {
  return nodeFs.readFileSync(nodePath.join(REPO_ROOT, relative), "utf8");
}

// A document's prose with every run of whitespace collapsed to one
// space. The sentences below are wrapped in the source at whatever
// column the paragraph reached, so a search for one of them against the
// raw file finds it or misses it depending on where the line broke, and
// a reflow that changed nothing an operator reads would fail this file.
function _prose(relative) {
  return _read(relative).replace(/\s+/g, " ");
}

// ---- the documents still say it --------------------------------------------

// Read before anything is compared against them. A parity check whose
// source of truth came back empty compares nothing and reports green.
function theDocumentsPublishTheseBounds() {
  var security = _prose("SECURITY.md");
  var threat   = _prose("THREAT-MODEL.md");

  check("SECURITY.md is readable and not empty", security.length > 1000);
  check("THREAT-MODEL.md is readable and not empty", threat.length > 1000);

  count("SECURITY.md publishes the per-listener socket ceiling, " +
    DOCUMENTED_SOCKET_CEILING,
    security.indexOf("at most " + DOCUMENTED_SOCKET_CEILING + " sockets at once") !== -1,
    "the sentence naming the ceiling is absent");

  count("SECURITY.md publishes the body-rate floor a peer is cut below",
    security.indexOf("below a hundred bytes a second") !== -1,
    "the sentence naming the floor is absent");

  count("and says neither of the two is an operator setting, which is what these " +
    "constants being held rather than offered has to keep true",
    security.indexOf("Neither number is settable") !== -1,
    "the sentence is absent");

  count("THREAT-MODEL.md promises the MIME caps are explicit rather than whatever the " +
    "parser happens to default to",
    /explicit size, depth and part-count caps/.test(threat),
    "the sentence is absent");

  // The third copy. The operator guide repeats both numbers under its
  // ceilings table, and a number written out in three documents and one
  // module is three chances for one of them to move alone.
  var guide = _prose("docs/operator-guide.md");
  check("the operator guide is readable and not empty", guide.length > 1000);

  count("the operator guide repeats the socket ceiling, and the code holds one number for " +
    "both documents to agree with",
    guide.indexOf("at most " + DOCUMENTED_SOCKET_CEILING + " sockets at once") !== -1,
    "the sentence naming the ceiling is absent");

  count("the operator guide repeats the body-rate floor",
    guide.indexOf("slower than a hundred bytes a second") !== -1,
    "the sentence naming the floor is absent");

  count("and it says the two hold at fixed values rather than being fields an operator sets",
    guide.indexOf("Two further bounds hold at fixed values, and neither is a field") !== -1,
    "the sentence is absent");

  // The five settable ones, each published with the value it ships at.
  Object.keys(DOCUMENTED_LIMIT_DEFAULTS).forEach(function (key) {
    var row = "| `" + key + "` | `" + DOCUMENTED_LIMIT_DEFAULTS[key] + "`";
    count("the operator guide's ceilings table publishes " + key + " at " +
      DOCUMENTED_LIMIT_DEFAULTS[key],
      guide.indexOf(row) !== -1, "no row reading " + row);
  });
}

// ---- the constants are the published numbers -------------------------------

function theExportedConstantsAreThosePublishedNumbers() {
  count("the mail stack exports the socket ceiling it passes to every listener",
    typeof listeners.MAX_CONNECTIONS === "number",
    typeof listeners.MAX_CONNECTIONS);
  count("and it is the number SECURITY.md publishes",
    listeners.MAX_CONNECTIONS === DOCUMENTED_SOCKET_CEILING,
    String(listeners.MAX_CONNECTIONS));

  count("the mail stack exports the body-rate floor it passes to every listener",
    typeof listeners.BODY_RATE_FLOOR_BYTES_PER_SECOND === "number",
    typeof listeners.BODY_RATE_FLOOR_BYTES_PER_SECOND);
  count("and it is the number SECURITY.md publishes",
    listeners.BODY_RATE_FLOOR_BYTES_PER_SECOND === DOCUMENTED_FLOOR_BYTES_PER_SECOND,
    String(listeners.BODY_RATE_FLOOR_BYTES_PER_SECOND));

  var caps = mailbox.MESSAGE_PARSE_CAPS;
  check("the mail stack exports the caps every message parse runs under",
    caps !== undefined && caps !== null && typeof caps === "object");

  // Frozen, because these travel into a framework handle that keeps the
  // object for the life of the store. A caller able to write to it could
  // move the bound on a running server, from anywhere holding the export.
  count("the caps are frozen, so nothing can move them on a running server",
    Object.isFrozen(caps), String(Object.isFrozen(caps)));

  count("the nesting cap is the depth the wire vector measures",
    caps.maxNestingDepth === MEASURED_MAX_NESTING_DEPTH, String(caps.maxNestingDepth));
  count("the part cap is the count the wire vector measures",
    caps.maxParts === MEASURED_MAX_PARTS, String(caps.maxParts));

  // The size half of the same object. A parse under a smaller size cap
  // than the store accepts refuses a message this server has already
  // stored, which is a mailbox that will not open rather than a message
  // that never arrived.
  count("the parse carries the message ceiling the guide publishes, so a stored message is " +
    "one every path can still read",
    caps.maxMessageBytes === DOCUMENTED_LIMIT_DEFAULTS.maxMessageBytes,
    String(caps.maxMessageBytes));

  // Equal on purpose. A body is a part of the message carrying it and
  // can never be larger than one, so a lower number here is a second
  // ceiling nobody published, and it is the one an ordinary single-part
  // message meets first.
  count("and the body cap is the same number rather than a lower one, because a single-part " +
    "message IS its body and a lower body cap makes the published ceiling unreachable",
    caps.maxBodyBytes === DOCUMENTED_LIMIT_DEFAULTS.maxMessageBytes,
    String(caps.maxBodyBytes));
}

// ---- the settable ceilings, and their shipped values ------------------------

// The four per-address ceilings and the message ceiling. Each is a field
// an operator may lower, so each has a shipped value that governs when
// they lower nothing, and that value is published beside the field name.
function theShippedCeilingsAreThePublishedOnes() {
  var defaults = config.LIMIT_DEFAULTS;
  check("the configuration module exports the shipped value of every settable ceiling",
    defaults !== undefined && defaults !== null && typeof defaults === "object");

  count("the table is frozen, so nothing can move a shipped ceiling on a running server",
    Object.isFrozen(defaults), String(Object.isFrozen(defaults)));

  Object.keys(DOCUMENTED_LIMIT_DEFAULTS).forEach(function (key) {
    count("the shipped " + key + " is the number the operator guide publishes",
      defaults[key] === DOCUMENTED_LIMIT_DEFAULTS[key], String(defaults[key]));
  });

  // Neither more nor fewer. A ceiling the schema accepts and this table
  // does not name is one the framework still decides, which is the whole
  // fault; a name here that the schema does not accept is a shipped
  // value for a field nobody can set.
  var named  = Object.keys(defaults).sort().join(",");
  var wanted = Object.keys(DOCUMENTED_LIMIT_DEFAULTS).sort().join(",");
  count("and the table names every settable ceiling and no others", named === wanted, named);

  count("the four per-address ceilings are exactly the rate-limit keys the listeners copy, " +
    "so a key added to one and not the other cannot go unnoticed",
    listeners.RATE_LIMIT_KEYS.slice().sort().join(",") ===
      Object.keys(DOCUMENTED_LIMIT_DEFAULTS).filter(function (k) {
        return k !== "maxMessageBytes";
      }).sort().join(","),
    listeners.RATE_LIMIT_KEYS.join(", "));

  // How the shipped value reaches anything: `blamepost.config.limitInEffect`
  // is the one resolver, so the wire and the message store cannot each
  // decide what an unset field means. Both spellings of unset are the
  // same answer, because a configuration that names no `limits` at all
  // and one that names the section without this field are the same
  // statement by the operator.
  count("an absent limits section resolves to the shipped ceiling",
    config.limitInEffect(null, "maxMessageBytes") ===
      DOCUMENTED_LIMIT_DEFAULTS.maxMessageBytes,
    String(config.limitInEffect(null, "maxMessageBytes")));

  count("and so does a section that names other ceilings and not this one",
    config.limitInEffect({ connectionsPerIpPerMinute: 90 }, "maxMessageBytes") ===
      DOCUMENTED_LIMIT_DEFAULTS.maxMessageBytes,
    String(config.limitInEffect({ connectionsPerIpPerMinute: 90 }, "maxMessageBytes")));

  count("while a ceiling the operator wrote is the one that comes back",
    config.limitInEffect({ maxMessageBytes: 1048576 }, "maxMessageBytes") === 1048576,
    String(config.limitInEffect({ maxMessageBytes: 1048576 }, "maxMessageBytes")));

  // A name this table does not hold has no shipped value to fall back
  // to, so answering with undefined would hand a caller the framework's
  // number by another route. It refuses instead.
  var refused = null;
  try { config.limitInEffect(null, "maxRecipients"); }
  catch (e) { refused = (e && e.code) || (e && e.message) || String(e); }
  count("and a field this table does not hold is refused rather than answered with nothing",
    refused !== null && String(refused).indexOf("unknown-limit") !== -1,
    String(refused));
}

// ---- the ceiling and the bounds derived from it -----------------------------

// One number decides several others, and each of them is a literal
// somewhere else. A relationship that holds by arithmetic nobody
// re-checks is one a later edit to the ceiling silently breaks.
function theDerivedBoundsStillCoverTheCeiling() {
  var ceiling = DOCUMENTED_LIMIT_DEFAULTS.maxMessageBytes;

  // A message the store accepts is sealed and written as one file, and
  // the read path serving IMAP BODY[] refuses a file above its own cap.
  // A ceiling raised past what that cap carries is a message stored and
  // then unfetchable.
  var largestBlob = Math.ceil(ceiling * BLOB_SEAL_EXPANSION);
  count("the blob read cap covers the largest message the ceiling admits, so a message this " +
    "server stores is one it can still serve",
    mailbox.MAX_BLOB_FILE_BYTES >= largestBlob,
    mailbox.MAX_BLOB_FILE_BYTES + " against " + largestBlob + " needed");

  // The reconciliation opens the same files. Two literals for one bound
  // is the pair that comes apart, and the walk reporting a body the
  // reader serves as unreadable is what it looks like when it does.
  var blobSource = _read("lib/store/blobs.js");
  count("and the reconciliation reads that cap from the module that owns it rather than " +
    "holding a second copy of the number",
    /MAX_BLOB_FILE_BYTES = mailbox\.MAX_BLOB_FILE_BYTES;/.test(blobSource),
    "a second literal is held here");

  // The schema's own ceiling. An operator may lower the message ceiling
  // and may not raise it, because everything above is sized for the
  // shipped number and a higher one is accepted at boot and lost at
  // delivery.
  var configSource = _read("lib/config/index.js");
  count("the configuration schema caps maxMessageBytes at the shipped ceiling rather than at " +
    "a number the storage path cannot carry",
    /max: *LIMIT_DEFAULTS\.maxMessageBytes/.test(configSource),
    "the schema's max is not the shipped ceiling");
}

// ---- held here, not borrowed -----------------------------------------------

// The distinction this whole file rests on. A constant assigned from the
// framework's own table would satisfy every case above and move on the
// next refresh, silently, which is the state all three of these were in.
function theValuesAreHeldRatherThanBorrowed() {
  var listenerSource = _read("lib/mail/listeners.js");
  var mailboxSource  = _read("lib/mail/mailbox.js");

  count("the socket ceiling is a literal in the module that owns it",
    new RegExp("var MAX_CONNECTIONS = " + DOCUMENTED_SOCKET_CEILING + ";").test(listenerSource),
    "no literal assignment found");

  count("the body-rate floor is a literal in the module that owns it",
    new RegExp("var BODY_RATE_FLOOR_BYTES_PER_SECOND = " +
      DOCUMENTED_FLOOR_BYTES_PER_SECOND + ";").test(listenerSource),
    "no literal assignment found");

  count("the structure caps are literals in the module that owns them",
    /var MESSAGE_PARSE_CAPS = Object\.freeze\(\{/.test(mailboxSource) &&
      new RegExp("maxNestingDepth: " + MEASURED_MAX_NESTING_DEPTH + ",").test(mailboxSource) &&
      new RegExp("maxParts: *" + MEASURED_MAX_PARTS + ",").test(mailboxSource),
    "no literal assignment found");

  // The five settable ones, in the module holding the schema they are
  // settable through. A shipped value written anywhere else is a second
  // answer to what this server does when the operator writes nothing.
  var configSource = _read("lib/config/index.js");
  count("the shipped ceilings are literals in the module that owns the defaults table",
    /var LIMIT_DEFAULTS = Object\.freeze\(\{/.test(configSource),
    "no frozen table found");

  Object.keys(DOCUMENTED_LIMIT_DEFAULTS).forEach(function (key) {
    count("the shipped " + key + " is written out there rather than computed",
      new RegExp(key + ": +" + DOCUMENTED_LIMIT_DEFAULTS[key] + ",").test(configSource),
      "no literal assignment found");
  });

  // The negative half. A later edit that "removed the duplication" by
  // reading the framework's published default would leave every case
  // above green and put the number back under the vendored tree.
  count("and none of them is read out of the framework's own defaults, which would put " +
    "the number back under the vendored tree while every case above stayed green",
    listenerSource.indexOf("rateLimit.DEFAULTS") === -1 &&
      listenerSource.indexOf("DEFAULT_MAX_CONNECTIONS") === -1 &&
      configSource.indexOf("rateLimit.DEFAULTS") === -1 &&
      configSource.indexOf("mailStore.DEFAULTS") === -1 &&
      mailboxSource.indexOf("safeMime.DEFAULTS") === -1,
    "a framework default is being read where a number should be held");
}

// ---- and every site that must name one does --------------------------------

// The declared-but-never-enforced half. Each of these is a call that
// ACTS on the value, as opposed to the declaration above that merely
// holds it.
function everySiteThatActsOnThemNamesThem() {
  var listenerSource = _read("lib/mail/listeners.js");
  var facadeSource   = _read("lib/index.js");
  var storeSource    = _read("lib/store/index.js");

  // Five listeners, and the ceiling is per listener: one left out is one
  // listener running on the framework's number while the document speaks
  // for all of them.
  var ceilingSites = listenerSource.match(/maxConnections: +MAX_CONNECTIONS,/g) || [];
  count("all five listener builders pass the socket ceiling, because it is a per-listener " +
    "bound and one left out is one listener the published number does not describe",
    ceilingSites.length === 5, ceilingSites.length + " of 5 builders");

  // The floor rides the rate-limit specification, which every listener is
  // built from, so one site covers all of them. It has to be written into
  // the specification unconditionally: a configuration naming no ceilings
  // at all still gets the floor, and gets it before anything the operator
  // wrote is read.
  count("the limits builder writes the body-rate floor into the specification every " +
    "listener is built from, ahead of the section it then reads",
    /var rateLimit = Object\.assign\(\s*\{ minBytesPerSecond: BODY_RATE_FLOOR_BYTES_PER_SECOND \},/
      .test(listenerSource),
    "the floor is not written into the specification");

  count("and the floor stays off the settable list, so SECURITY.md's claim that the " +
    "number cannot be set holds",
    listeners.RATE_LIMIT_KEYS.indexOf("minBytesPerSecond") === -1,
    listeners.RATE_LIMIT_KEYS.join(", "));

  // Both places the message store is built. The parse that decides
  // whether a message is delivered runs inside that store's append, and
  // its options are fixed when the handle is built rather than chosen per
  // message, so a handle built without them is every delivery through it
  // running on the parser's defaults.
  count("the composition facade names the structure caps where it builds the message store",
    /safeMimeOpts: +mailbox\.MESSAGE_PARSE_CAPS/.test(facadeSource),
    "the facade builds a message store with no structure caps");

  count("and the store does too, so a reader opened there and a server started here agree " +
    "about which messages are readable",
    /safeMimeOpts: +mailbox\.MESSAGE_PARSE_CAPS/.test(storeSource),
    "the store builds a message store with no structure caps");

  // The size ceiling at the same two places, and it is a separate opt
  // from the parse caps: the store checks the whole message against its
  // own number BEFORE it parses, so a handle told the caps and not the
  // ceiling still refuses at the framework's fifty mebibytes. This is
  // the half that decided delivery for a message the wire had already
  // accepted in full.
  [
    { label: "the composition facade", source: facadeSource },
    { label: "the store",              source: storeSource },
  ].forEach(function (site) {
    count(site.label + " names the message ceiling where it builds the message store, so the " +
      "number the listeners advertise is the number the append applies",
      /maxMessageBytes: +messageBytes,/.test(site.source),
      "the message store is built without a ceiling, so the framework's own governs");

    count("and " + site.label + " names the body ceiling too, which is the one an ordinary " +
      "single-part message meets first",
      /maxBodyBytes: +messageBytes,/.test(site.source),
      "the message store is built without a body ceiling");
  });

  // The listeners' end of the same number. A specification built only
  // from what the operator wrote leaves every field they left alone to
  // the framework, which is five published numbers this repository does
  // not set.
  count("and it seeds the four settable ceilings from the shipped table in the same " +
    "expression, so a configuration naming none still runs this server's numbers",
    /LIMIT_DEFAULTS_RATE\);/.test(listenerSource),
    "the specification starts from what the operator wrote");

  count("and the message ceiling resolves to the shipped one when the operator names none, " +
    "rather than being handed to the listeners as absent",
    /maxMessageBytes = LIMIT_DEFAULTS\.maxMessageBytes;/.test(listenerSource),
    "an unset ceiling reaches the listeners as undefined");
}

// Every MIME parse in lib/, against the ones that name the caps. An
// unbounded parse is not a style inconsistency: it is a walk over a
// structure a stranger chose the size of.
function everyMimeParseInTheApplicationIsBounded() {
  var roots = ["lib/mail", "lib/store", "lib/web", "lib"];
  var files = [];
  roots.forEach(function (dir) {
    var full = nodePath.join(REPO_ROOT, dir);
    nodeFs.readdirSync(full, { withFileTypes: true }).forEach(function (entry) {
      if (!entry.isFile() || !/\.js$/.test(entry.name)) return;
      var rel = dir + "/" + entry.name;
      if (files.indexOf(rel) === -1) files.push(rel);
    });
  });

  var parses    = 0;
  var unbounded = [];
  files.forEach(function (rel) {
    var source = _read(rel);
    var lines  = source.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      if (lines[i].indexOf("b.safeMime.parse(") === -1) continue;
      parses += 1;
      // The caps may be named on the same line or on the continuation
      // under it, since a long call wraps.
      var window = lines[i] + "\n" + (lines[i + 1] || "");
      if (window.indexOf("MESSAGE_PARSE_CAPS") !== -1) continue;

      // One level of indirection, and one only. A caller that narrows a
      // dimension passes a local built FROM the shared caps, and reading
      // just the call line would report that as unbounded. So the name in
      // the second argument is resolved to where the file declares it,
      // and the caps have to be named there.
      //
      // This does not soften the rule. A local assembled from its own
      // literals still fails, which is the shape that actually went
      // wrong: a bounds object written out by hand carried no nesting
      // depth, leaving the parse that reads mail from strangers as the
      // only unbounded one in the application. Only one level is
      // followed, because a chain of locals is a place to hide a bound
      // and there is no reason to write one.
      var passed = /b\.safeMime\.parse\(\s*[A-Za-z0-9_.()]{1,80}\s*,\s*([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*\)/
        .exec(window);
      var declared = passed
        ? new RegExp("var\\s+" + passed[1] + "\\s*=([\\s\\S]{0,400})").exec(source)
        : null;
      if (!declared || declared[1].indexOf("MESSAGE_PARSE_CAPS") === -1) {
        unbounded.push(rel + ":" + (i + 1));
      }
    }
  });

  // Published, so a run that reached no parse at all cannot report the
  // same green as a run that reached them and found them bounded.
  count("the walk reached the MIME parses in lib/ rather than an empty file list",
    parses >= 5, parses + " parse call(s) over " + files.length + " file(s)");

  count("every one of them names the structure caps, so the bound is the same wherever a " +
    "message is read rather than one the parser chose",
    unbounded.length === 0, unbounded.join(", ") || "none unbounded");
}

// ---- runner ----------------------------------------------------------------

function run() {
  theDocumentsPublishTheseBounds();
  theExportedConstantsAreThosePublishedNumbers();
  theShippedCeilingsAreThePublishedOnes();
  theDerivedBoundsStillCoverTheCeiling();
  theValuesAreHeldRatherThanBorrowed();
  everySiteThatActsOnThemNamesThem();
  everyMimeParseInTheApplicationIsBounded();
  return helpers.getChecks();
}

module.exports = { name: "published-bound-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
