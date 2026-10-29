// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * published-number-parity: an operator-visible number written into a
 * sentence is the number the module that acts on it holds.
 *
 * published-bound-parity holds the operator guide's ceilings TABLE
 * against the shipped values, and a table is the easy half. The hard half
 * is the same number written into prose somewhere else, because prose
 * carries no key beside the value and nothing reads it. Every number
 * below was correct when it was typed and is a hand copy with no gate on
 * it:
 *
 *   - The README states all five settable ceilings in sentences, with
 *     both ends of the range each one accepts. It is the only document
 *     that publishes those ranges at all: the guide's table publishes the
 *     shipped value and names one floor in passing, so a range that moved
 *     in the schema would leave the README describing a server that
 *     refuses a value it takes, or takes one it refuses.
 *   - The read cap that decides whether a stored message can be fetched
 *     back is stated as a size in two documents, along with the size a
 *     message of the shipped ceiling reaches on disk. Neither is a
 *     setting, so neither has anywhere else to be read from.
 *   - The outbound spool's two ceilings are stated as numerals in the
 *     guide's settings row, which is compared elsewhere, and SPELLED OUT
 *     in the paragraph that explains the queue, which is not. The share
 *     of the depth an arriving message may take is spelled out beside
 *     them and is a product of two constants rather than either one.
 *   - The README prints a configuration file an operator copies. Its
 *     values are illustrative rather than shipped, which is why they are
 *     not compared against the defaults, but a value the loader refuses
 *     is an example that stops the start of any server it is pasted into.
 *   - The README and ARCHITECTURE.md each carry a port table. The guide's
 *     firewall table, the image's EXPOSE lines and the compose file are
 *     all compared against the listeners; these two are not, so a moved
 *     port sends a reader of either one to open the wrong hole.
 *   - The guide quotes the refusal a write verb meets while the server
 *     holds the data volume, and that refusal ENUMERATES the commands
 *     that answer anyway. The guide then names the same set again in the
 *     paragraph below it. Neither copy is a number, but both are the same
 *     hand copy of a set that lives in a table, and a set has the same
 *     failure a count does: it is correct when it is typed and nothing
 *     reads it afterwards. Both had fallen behind the table.
 *
 * A set is compared as a set rather than as a substring. A document that
 * names every member and one more has a name in it an operator will type
 * and be refused for, which a containment check passes over.
 *
 * The numbers are read off the modules that own them, and where a module
 * holds one as a literal that literal is read out of the source, because
 * a constant computed from the framework's own table agrees with the
 * framework before a vendor refresh and after one. That is the same
 * distinction published-bound-parity rests on.
 *
 * A count is published for every set this file walks, so a paragraph that
 * moved out from under an anchor is a failure rather than a comparison
 * over nothing.
 *
 * No sockets, no database. It reads the shipped documents, three source
 * files and the configuration schema.
 *
 * Run standalone: node test/layer-0-primitives/published-number-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var store   = require("../../lib/store");

var check = helpers.check;
var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

var MIB = 1024 * 1024;

// A stored body is base64 inside a seal that is itself base64, so the
// file on disk is sixteen ninths of the message. The same factor
// published-bound-parity measures, restated here because the sentence in
// the guide that gives the resulting file size is derived from it.
var BLOB_SEAL_EXPANSION = 16 / 9;

function _read(relative) {
  return nodeFs.readFileSync(nodePath.join(REPO_ROOT, relative), "utf8");
}

// A document's prose with every run of whitespace collapsed to one
// space. Every sentence searched for below wraps at whatever column its
// paragraph reached, so a search against the raw file would find it or
// miss it depending on where the line broke.
function _prose(relative) {
  return _read(relative).replace(/\s+/g, " ");
}

// The stretch of a document between two sentences, with both asserted
// present first. An anchor that moved leaves an empty region, and an
// empty region satisfies every question asked of it.
function _region(rel, prose, start, end, what) {
  var from = prose.indexOf(start);
  count(rel + " still opens " + what,
    from !== -1, "the text \"" + start.slice(0, 60) + "\" is absent");
  var to = prose.indexOf(end, from + start.length);
  count("and " + rel + " still closes " + what + ", so what follows is read out of that " +
    "passage rather than out of the whole file",
    to !== -1, "the text \"" + end.slice(0, 60) + "\" is absent after it");
  return prose.slice(from, to);
}

// A whole number written the way the guide's prose writes it. Null for
// anything this speller cannot render, which is a failure at the call
// site: a ceiling moved to a number no sentence can spell is a sentence
// that has to be rewritten by a person.
var IN_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
  "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
  "seventeen", "eighteen", "nineteen", "twenty"];
var IN_TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy",
  "eighty", "ninety"];

function _inWords(n) {
  if (typeof n !== "number" || !isFinite(n) || n !== Math.floor(n) || n < 0) return null;
  if (n % 1000 === 0 && n / 1000 >= 1 && n / 1000 < IN_WORDS.length) {
    return IN_WORDS[n / 1000] + " thousand";
  }
  if (n < IN_WORDS.length) return IN_WORDS[n];
  if (n < 100) {
    var tens = IN_TENS[Math.floor(n / 10)];
    var unit = n % 10;
    return unit === 0 ? tens : tens + " " + IN_WORDS[unit];
  }
  return null;
}

// A span of milliseconds the way the guide writes one, which is whole
// days and whole minutes and nothing between. Null for a span that does
// not land on a minute, which is a schedule whose total no sentence
// currently spells and which a person has to write out.
function _spanInWords(ms) {
  var days    = Math.floor(ms / 86400000);
  var minutes = (ms - days * 86400000) / 60000;
  if (minutes !== Math.floor(minutes)) return null;
  var parts = [];
  if (days === 1) parts.push("a day");
  else if (days > 1) {
    var spelledDays = _inWords(days);
    if (spelledDays === null) return null;
    parts.push(spelledDays + " days");
  }
  if (minutes > 0) {
    var spelledMinutes = _inWords(minutes);
    if (spelledMinutes === null) return null;
    parts.push(spelledMinutes + " minutes");
  }
  return parts.length === 0 ? null : parts.join(" and ");
}

// A spelled number at the start of a sentence, where the guide writes it
// with a capital.
function _capitalize(words) {
  return words === null ? null : words.charAt(0).toUpperCase() + words.slice(1);
}

// A byte count as mebibytes when it is a whole number of them, so a
// sentence writing "50 MiB" is compared against the same value a table
// writes as 52428800.
function _asMib(bytes) {
  return bytes % MIB === 0 ? bytes / MIB : null;
}

// ---- the README's ceilings, with the range each one accepts ----------------

// The five settable ceilings. Read off the schema and the defaults table
// rather than listed here, so a sixth added to either is compared the day
// it lands instead of being a ceiling the README may describe or not.
function _limitFields() {
  var setting = config.SETTINGS.filter(function (s) { return s.key === "limits"; })[0];
  return setting === undefined ? null : setting.fields;
}

function theReadmeStatesEveryCeilingTheSchemaAccepts() {
  var fields = _limitFields();
  check("the configuration schema publishes the limits section's own fields", fields !== null);

  var keys = Object.keys(config.LIMIT_DEFAULTS);
  count("the ceilings compared are read off the shipped defaults table rather than listed here",
    keys.length >= 5, keys.length + " ceiling(s): " + keys.join(", "));

  var named = keys.filter(function (key) { return fields[key] !== undefined; });
  check("and every one of them is a field the schema accepts, so a shipped value with no " +
    "field is not compared against a range that does not exist" +
    (named.length === keys.length
      ? ""
      : ", and these are not: " + keys.filter(function (k) {
        return fields[k] === undefined;
      }).join(", ")),
    named.length === keys.length);

  var prose  = _prose("README.md");
  var region = _region("README.md", prose,
    "`limits` holds five ceilings",
    "Anything the server cannot honor stops the start",
    "the paragraph stating what each ceiling ships at and what it accepts");

  count("that paragraph carries text to read", region.length > 400,
    region.length + " character(s)");

  // Each ceiling is described from where it is named to where the next
  // one is, which is the structural boundary in the paragraph. A window
  // measured in characters would stop matching as the sentence around a
  // ceiling grew.
  var positions = keys.map(function (key) {
    return { key: key, at: region.indexOf("`" + key + "`") };
  }).sort(function (a, b) { return a.at - b.at; });

  var unnamed = positions.filter(function (p) { return p.at === -1; })
    .map(function (p) { return p.key; });
  check("every shipped ceiling is named in that paragraph" +
    (unnamed.length ? ", and these are not: " + unnamed.join(", ") : ""),
    unnamed.length === 0);

  var compared  = 0;
  var wrongShip = [];
  var wrongRange = [];
  positions.forEach(function (position, index) {
    var next = positions[index + 1];
    var window = region.slice(position.at, next === undefined ? region.length : next.at);
    compared += 1;

    var shipped = config.LIMIT_DEFAULTS[position.key];
    var asMib   = _asMib(shipped);
    var ships   = window.indexOf("ships at " + shipped) !== -1 ||
      (asMib !== null && window.indexOf("ships at " + asMib + " MiB") !== -1);
    if (!ships) {
      wrongShip.push(position.key + " ships at " + shipped +
        (asMib === null ? "" : " (" + asMib + " MiB)") + " and the paragraph does not say so");
    }

    var field = fields[position.key];
    var range = "accepts `" + field.min + "` to `" + field.max + "`";
    if (window.indexOf(range) === -1) {
      wrongRange.push(position.key + " accepts " + field.min + " to " + field.max +
        " and the paragraph does not say so");
    }
  });

  count("each ceiling's own sentences are read, bounded by the next ceiling the paragraph " +
    "names rather than by a character budget",
    compared === keys.length, compared + " of " + keys.length + " ceiling(s) read");

  check("and each one is stated at the value it ships at" +
    (wrongShip.length ? ": " + wrongShip.join("; ") : ""),
    wrongShip.length === 0);

  check("and with the range the schema accepts at both ends, which no other document " +
    "publishes" + (wrongRange.length ? ": " + wrongRange.join("; ") : ""),
    wrongRange.length === 0);
}

// ---- the read cap the message ceiling is sized against ---------------------

// Not a setting, so no configuration carries it and no row publishes it.
// Both documents state it as a size, and the guide states the size a
// message at the shipped ceiling reaches on disk, which is a product of
// the ceiling and the seal rather than a number anything holds.
function theReadCapIsTheOneBothDocumentsState() {
  var cap = mailbox.MAX_BLOB_FILE_BYTES;
  count("the mail stack exports the cap the read path serving BODY[] opens a file at",
    typeof cap === "number" && cap > 0, String(cap));

  var capMib = _asMib(cap);
  count("and it is a whole number of mebibytes, which is how both documents write it",
    capMib !== null, cap + " bytes");

  // Held rather than borrowed, in the module that owns it. A cap read off
  // the framework's own table would satisfy every sentence below and move
  // on the next refresh with both documents left naming the old size.
  var mailboxSource = _read("lib/mail/mailbox.js");
  count("the cap is a literal in the module that owns it rather than read out of the " +
    "framework's defaults",
    new RegExp("var MAX_BLOB_FILE_BYTES = BYTES\\.mib\\(" + capMib + "\\);").test(mailboxSource),
    "no literal assignment at " + capMib + " MiB");

  var readme = _prose("README.md");
  var guide  = _prose("docs/operator-guide.md");

  count("the README states the size the read path opens a file at",
    readme.indexOf("opens at most " + capMib + " MiB") !== -1,
    "no sentence naming " + capMib + " MiB");

  count("and the operator guide states the same size",
    guide.indexOf("the " + capMib + " MiB the read path") !== -1,
    "no sentence naming " + capMib + " MiB");

  // The two sizes the guide derives from the ceiling. Both are arithmetic
  // nobody re-runs, so a ceiling that moved leaves the sentence describing
  // a message size this server no longer accepts.
  var ceiling    = config.LIMIT_DEFAULTS.maxMessageBytes;
  var ceilingMib = _asMib(ceiling);
  var storedMib  = Math.round(ceiling * BLOB_SEAL_EXPANSION / MIB);

  count("the shipped message ceiling is a whole number of mebibytes, which is how the guide " +
    "writes it in that sentence", ceilingMib !== null, ceiling + " bytes");

  count("the guide states the size a message at the shipped ceiling reaches on disk, and it " +
    "is the ceiling through the seal rather than a number written by hand",
    guide.indexOf(ceilingMib + " MiB of mail is an " + storedMib + " MiB file") !== -1,
    ceilingMib + " MiB of mail is an " + storedMib + " MiB file");

  count("and that stored size is inside the cap, so a message this server accepts is one it " +
    "can still serve", storedMib <= capMib, storedMib + " MiB against " + capMib + " MiB");
}

// ---- the outbound spool's ceilings, spelled out ----------------------------

// The guide's settings row prints these as numerals and is compared
// against the composer elsewhere. The paragraph explaining the queue
// spells them out instead, and a spelled number is invisible to every
// comparison that looks for a numeral.
function theSpoolCeilingsAreTheOnesTheGuideSpells() {
  var deliverySource = _read("lib/mail/delivery.js");

  var depth = /var DEFAULT_MAX_SPOOL_MESSAGES = (\d+);/.exec(deliverySource);
  count("the delivery composer holds the spool's depth ceiling as a literal",
    depth !== null, depth === null ? "no literal assignment found" : depth[1]);

  var bytes = /var DEFAULT_MAX_SPOOL_BYTES = BYTES\.gib\((\d+)\);/.exec(deliverySource);
  count("and its byte ceiling as a literal count of gibibytes",
    bytes !== null, bytes === null ? "no literal assignment found" : bytes[1] + " GiB");

  var share = /var STRANGER_SPOOL_SHARE = ([0-9.]+);/.exec(deliverySource);
  count("and the share of the depth a message arriving for forwarding may take",
    share !== null, share === null ? "no literal assignment found" : share[1]);

  var depthValue = parseInt(depth[1], 10);
  var shareValue = parseFloat(share[1]);

  var depthWords = _inWords(depthValue);
  var shareWords = _inWords(Math.round(depthValue * shareValue));
  count("both the ceiling and the share of it are numbers a sentence can spell, because the " +
    "paragraph that explains the queue spells them rather than printing them",
    depthWords !== null && shareWords !== null,
    depthValue + " -> " + depthWords + ", " + Math.round(depthValue * shareValue) +
      " -> " + shareWords);

  var guide = _prose("docs/operator-guide.md");

  count("the guide spells the depth ceiling in the paragraph explaining the queue",
    guide.indexOf(depthWords + " entries") !== -1 ||
      guide.indexOf(depthWords + " slots") !== -1,
    "no sentence spelling " + depthWords);

  count("and it spells the share an arriving message stops short at, which is a product of " +
    "two constants rather than either one of them",
    guide.indexOf(shareWords + " of the " + depthWords + " entries") !== -1,
    shareWords + " of the " + depthWords + " entries");

  // The guide's own settings row, as numerals. It is compared against the
  // composer's describe() in test/layer-1-state/docs-surface.test.js;
  // what is added here is that the numerals and the spelled words are the
  // same number, which neither comparison can see on its own.
  var byteValue = parseInt(bytes[1], 10) * 1024 * 1024 * 1024;
  count("the guide's settings row prints the same two ceilings the paragraph spells",
    guide.indexOf("{\"maxMessages\":" + depthValue + ",\"maxBytes\":" + byteValue + "}") !== -1,
    "{\"maxMessages\":" + depthValue + ",\"maxBytes\":" + byteValue + "}");
}

// ---- the give-up times the guide works out for a reader --------------------

// The retry schedule's own row prints the waits and the attempt count as
// numerals, and test/layer-1-state/docs-surface.test.js holds those
// against the composer. The same cell then works out what they come to,
// three times, for the shipped count and for two an operator might set
// instead. Those totals are arithmetic over both values at once, so a
// wait or the count moving alone leaves all three describing a give-up
// time this server no longer keeps, and the row they sit beside would
// still compare clean.
var TIME_UNITS = { seconds: 1000, minutes: 60000, hours: 3600000, days: 86400000 };

function _shippedBackoff(source) {
  var at = source.indexOf("var DEFAULT_RETRY_BACKOFF_MS = Object.freeze([");
  if (at === -1) return null;
  var end = source.indexOf("]);", at);
  if (end === -1) return null;
  var out = [];
  var re  = /TIME\.([a-z]+)\((\d+)\)/g;
  var m;
  while ((m = re.exec(source.slice(at, end))) !== null) {
    if (TIME_UNITS[m[1]] === undefined) return null;
    out.push(TIME_UNITS[m[1]] * parseInt(m[2], 10));
  }
  return out.length === 0 ? null : out;
}

// What a message waits in total before its sender is told it failed. The
// last wait repeats for every attempt past the end of the list, which is
// how the delivery path indexes the schedule.
function _giveUpMs(attempts, backoff) {
  var total = 0;
  for (var i = 0; i < attempts - 1; i += 1) {
    total += backoff[Math.min(i, backoff.length - 1)];
  }
  return total;
}

function theGiveUpTimesTheGuideWorksOutAreTheScheduleItPrints() {
  var deliverySource = _read("lib/mail/delivery.js");

  var backoff = _shippedBackoff(deliverySource);
  count("the delivery composer holds the shipped wait schedule",
    backoff !== null, backoff === null ? "no frozen schedule found" : backoff.join(", ") + " ms");

  var attempts = /var DEFAULT_MAX_ATTEMPTS = (\d+);/.exec(deliverySource);
  count("and the number of attempts it spends them over",
    attempts !== null, attempts === null ? "no literal assignment found" : attempts[1]);

  var shippedAttempts = parseInt(attempts[1], 10);
  var guide = _prose("docs/operator-guide.md");

  count("the guide spells the shipped attempt count in the sentence that works out what it " +
    "comes to",
    guide.indexOf(_inWords(shippedAttempts) + " attempts") !== -1 ||
      guide.indexOf(_capitalize(_inWords(shippedAttempts)) + " attempts") !== -1,
    _inWords(shippedAttempts) + " attempts");

  // Every give-up time the cell works out, found by the shape it writes
  // them in rather than by the counts it happens to have chosen. A second
  // example added later is compared the day it lands.
  var stated = [];
  var re = /`(\d+)` (?:gives up )?after ((?:[a-z]+ )+minutes)/g;
  var m;
  while ((m = re.exec(guide)) !== null) {
    stated.push({ attempts: parseInt(m[1], 10), words: m[2].trim() });
  }

  var shippedWords = _spanInWords(_giveUpMs(shippedAttempts, backoff));
  count("the total for the shipped count is a span a sentence can spell",
    shippedWords !== null, String(shippedWords));

  count("and the guide states it",
    guide.indexOf("spend " + shippedWords) !== -1, "spend " + shippedWords);

  count("the give-up times the guide works out for other attempt counts are found by the " +
    "shape it writes them in, so one added later is compared too",
    stated.length >= 2,
    stated.map(function (s) { return s.attempts + " -> " + s.words; }).join(", "));

  var wrong = stated.filter(function (s) {
    return _spanInWords(_giveUpMs(s.attempts, backoff)) !== s.words;
  }).map(function (s) {
    return s.attempts + " attempts is stated as " + s.words + " and comes to " +
      _spanInWords(_giveUpMs(s.attempts, backoff));
  });
  check("and each of them is what the shipped schedule really spends over that many attempts" +
    (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);
}

// ---- the configuration the README prints is one the loader takes -----------

// The block is illustrative: it moves the IMAP port and widens two
// ceilings so a reader can see the shape, so its values are not the
// shipped ones and are not compared against them. What can be compared is
// that the loader would accept every one of them, because an example
// pasted into a configuration file has to start the server it is pasted
// into.
function theConfigExampleTheReadmePrintsIsOneTheLoaderTakes() {
  var readme = _read("README.md");
  var block  = /```json\n([\s\S]*?)\n```/.exec(readme);
  count("the README prints a configuration file an operator can copy",
    block !== null, block === null ? "no json block found" : block[1].length + " character(s)");

  var parsed = null;
  var failed = null;
  try { parsed = JSON.parse(block[1]); }
  catch (e) { failed = (e && e.message) || String(e); }
  count("and it parses, because a reader pastes it into a file the loader reads as JSON",
    parsed !== null, failed === null ? "parsed" : failed);

  var checked  = 0;
  var unbound  = 0;
  var refused  = [];

  function _measure(where, value, spec) {
    if (spec === undefined || spec === null) { unbound += 1; return; }
    if (Array.isArray(value)) {
      value.forEach(function (item, index) {
        _measure(where + "[" + index + "]", item, spec.element);
      });
      return;
    }
    if (typeof value !== "number") { unbound += 1; return; }
    if (spec.min === undefined && spec.max === undefined) { unbound += 1; return; }
    checked += 1;
    if (spec.min !== undefined && value < spec.min) {
      refused.push(where + " is " + value + " and the floor is " + spec.min);
    }
    if (spec.max !== undefined && value > spec.max) {
      refused.push(where + " is " + value + " and the ceiling is " + spec.max);
    }
  }

  config.SETTINGS.forEach(function (setting) {
    var shown = parsed[setting.key];
    if (shown === undefined) return;
    if (setting.min !== undefined || setting.max !== undefined) {
      _measure(setting.key, shown, setting);
      return;
    }
    if (setting.fields === undefined || shown === null || typeof shown !== "object") return;
    Object.keys(shown).forEach(function (field) {
      _measure(setting.key + "." + field, shown[field], setting.fields[field]);
    });
  });

  count("the example's numbers are measured against the schema's own floors and ceilings, " +
    "and the ones the schema bounds by something other than a number are counted rather " +
    "than passed over",
    checked >= 8, checked + " value(s) measured, " + unbound + " with no numeric bound");

  check("and the loader accepts every one of them, so the example starts the server it is " +
    "pasted into" + (refused.length ? ": " + refused.join("; ") : ""),
    refused.length === 0);
}

// ---- the ports two more documents publish ----------------------------------

// The guide's firewall table, the image's EXPOSE lines and the compose
// file are all held against the listeners in
// test/layer-1-state/docs-surface.test.js. These two carry the same ports
// in a shape that comparison does not read, so a listener moved to a new
// port leaves them naming the old one.
function everyPortThoseTwoDocumentsNameIsOneAListenerBinds() {
  var bound = {};
  config.LISTENER_NAMES.forEach(function (listener) {
    bound[config.LISTENER_DEFAULTS[listener].port] = listener;
  });
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === "httpPort")  bound[setting.fallback] = "the browser and JMAP surface";
    if (setting.key === "httpsPort") bound[setting.fallback] = "the same surface over TLS";
  });
  var wanted = Object.keys(bound).sort(function (a, b) { return a - b; });

  count("the ports compared are the ones the listener table and the browser surface bind, " +
    "read off the schema rather than listed here",
    wanted.length >= 8, wanted.join(" "));

  [
    {
      rel:     "README.md",
      shape:   /^\| ?(\d+) ?\|/gm,
      describe: "the protocol table's first column",
    },
    {
      rel:     "ARCHITECTURE.md",
      shape:   /`:(\d+)`/g,
      describe: "the ports written beside each primitive",
    },
  ].forEach(function (table) {
    var text  = _read(table.rel);
    var found = [];
    var m;
    table.shape.lastIndex = 0;
    while ((m = table.shape.exec(text)) !== null) {
      if (found.indexOf(m[1]) === -1) found.push(m[1]);
    }
    found.sort(function (a, b) { return a - b; });

    count(table.rel + " publishes ports in " + table.describe + ", so this is comparing " +
      "something", found.length >= 6, found.join(" "));

    var stray = found.filter(function (port) { return bound[port] === undefined; });
    check("and every port it publishes is one this server binds" +
      (stray.length ? ", and these are not: " + stray.join(", ") : ""),
      stray.length === 0);

    var absent = wanted.filter(function (port) { return found.indexOf(port) === -1; });
    check("and every port this server binds is published there, so a listener added or moved " +
      "is added or moved in " + table.rel + " with it" +
      (absent.length
        ? ", and these are missing: " + absent.map(function (p) {
          return p + " (" + bound[p] + ")";
        }).join(", ")
        : ""),
      absent.length === 0);
  });
}

// ---- the one other range a document publishes ------------------------------

// The window a sender may be asked to cache the MTA-STS policy for. The
// README prints both ends of it in the row's own sentence, and the schema
// is the only other place either number exists.
function theCachingWindowTheReadmePrintsIsTheSchemaWindow() {
  var setting = config.SETTINGS.filter(function (s) { return s.key === "mtaStsMaxAge"; })[0];
  count("the schema publishes the window a sender may be asked to cache the policy for",
    setting !== undefined && typeof setting.min === "number" &&
      typeof setting.max === "number",
    setting === undefined ? "no such setting" : setting.min + " to " + setting.max);

  var readme = _prose("README.md");
  count("and the README's row prints both ends of it",
    readme.indexOf("Between `" + setting.min + "` and `" + setting.max + "`") !== -1,
    "Between `" + setting.min + "` and `" + setting.max + "`");
}

// ---- the commands that answer while the server holds the volume ------------

// Every command the store will serve from a read-only open, written the
// way an operator types it. `doctor` is a whole command rather than a
// group and a verb, so the table lists it against the empty string.
function _snapshotCommands() {
  var out = [];
  Object.keys(store.SNAPSHOT_VERBS).forEach(function (group) {
    store.SNAPSHOT_VERBS[group].forEach(function (verb) {
      out.push(verb === "" ? group : group + " " + verb);
    });
  });
  return out;
}

// Which of a set of command names a passage carries, and which it does
// not. `account list` is a prefix of nothing else in the table, but a
// group name is a prefix of every command under it, so a passage naming
// only `account list` must not read as naming `account` on its own.
// Every name here is a whole command, so a plain search for each is
// exact in both directions.
function _namedIn(passage, commands) {
  var present = [];
  var absent  = [];
  commands.forEach(function (command) {
    if (passage.indexOf(command) === -1) absent.push(command);
    else present.push(command);
  });
  return { present: present, absent: absent };
}

function theGuideNamesEveryCommandTheStoreWillServeFromACopy() {
  var commands = _snapshotCommands();

  count("the store publishes the commands it will serve from a read-only open, so the " +
    "documents below are compared against a table rather than against each other",
    commands.length >= 8, commands.length + " command(s): " + commands.join(", "));

  var frozen = Object.isFrozen(store.SNAPSHOT_VERBS) &&
    Object.keys(store.SNAPSHOT_VERBS).every(function (group) {
      return Object.isFrozen(store.SNAPSHOT_VERBS[group]);
    });
  count("and the table is frozen, so a caller reading it cannot edit the set the refusal " +
    "names on its way past", frozen, "frozen: " + frozen);

  var guide = _prose("docs/operator-guide.md");

  // The refusal the guide quotes, bounded by its own first and last
  // sentences. A search over the whole document would find these command
  // names in the paragraph below it and report the quoted block correct
  // whatever it said.
  var quoted = _region("docs/operator-guide.md", guide,
    "Stop the server and run this again.",
    "A verb that reports and also records that it read is not among them",
    "the refusal a write verb meets while the server holds the volume");

  count("the quoted refusal carries text to read", quoted.length > 100,
    quoted.length + " character(s)");

  var inRefusal = _namedIn(quoted, commands);
  check("every command the store will serve from a copy is named in the refusal the guide " +
    "quotes, so an operator refused at the wall is told about all of them" +
    (inRefusal.absent.length ? ", and these are not: " + inRefusal.absent.join(", ") : ""),
    inRefusal.absent.length === 0);

  // The other direction. A refusal naming a command the table does not
  // hold sends an operator to a verb that will be refused for the same
  // reason they were, which is worse than naming none.
  var strayInRefusal = _strayCommands(quoted, commands);
  check("and it names no command the table does not hold" +
    (strayInRefusal.length ? ": " + strayInRefusal.join(", ") : ""),
    strayInRefusal.length === 0);

  // The paragraph below the refusal, which is where an operator reading
  // the guide rather than meeting the wall finds the same set.
  var paragraph = _region("docs/operator-guide.md", guide,
    "### The reporting verbs answer while the server runs",
    "A read-only open decrypts a working copy of its own",
    "the paragraph naming the commands that do not refuse");

  var inParagraph = _namedIn(paragraph, commands.map(function (command) {
    return "`" + command + "`";
  }));
  check("the guide's own paragraph names the same set, in backticks" +
    (inParagraph.absent.length
      ? ", and these are not: " + inParagraph.absent.join(", ")
      : ""),
    inParagraph.absent.length === 0);

  // No count survives beside either list. A total written next to an
  // enumeration is a second statement of the same fact, and it is the
  // one that goes stale, because the enumeration is what a reader
  // checks.
  var counted = /\b(two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|\d+) verbs?\b/i;
  var quotedTotal = counted.exec(quoted);
  count("the quoted refusal states no total beside the list it prints",
    quotedTotal === null, quotedTotal === null ? "none" : quotedTotal[0]);

  var paragraphTotal = counted.exec(paragraph);
  count("and neither does the paragraph",
    paragraphTotal === null, paragraphTotal === null ? "none" : paragraphTotal[0]);
}

// A command name a passage carries that the table does not hold. Built
// from the groups the table names rather than from a list here, so a
// group added to the table is searched for the day it lands.
function _strayCommands(passage, commands) {
  var stray = [];
  Object.keys(store.SNAPSHOT_VERBS).forEach(function (group) {
    var re = new RegExp("\\b" + group + " ([a-z][a-z-]*)", "g");
    var m;
    while ((m = re.exec(passage)) !== null) {
      var named = group + " " + m[1];
      if (commands.indexOf(named) === -1 && stray.indexOf(named) === -1) stray.push(named);
    }
  });
  return stray;
}

// ---- runner ----------------------------------------------------------------

function run() {
  theReadmeStatesEveryCeilingTheSchemaAccepts();
  theReadCapIsTheOneBothDocumentsState();
  theSpoolCeilingsAreTheOnesTheGuideSpells();
  theGiveUpTimesTheGuideWorksOutAreTheScheduleItPrints();
  theConfigExampleTheReadmePrintsIsOneTheLoaderTakes();
  everyPortThoseTwoDocumentsNameIsOneAListenerBinds();
  theCachingWindowTheReadmePrintsIsTheSchemaWindow();
  theGuideNamesEveryCommandTheStoreWillServeFromACopy();
  return helpers.getChecks();
}

module.exports = { name: "published-number-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
