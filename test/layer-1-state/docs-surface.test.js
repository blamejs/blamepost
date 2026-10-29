// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every setting, port and path a shipped document names, held against the
 * code that would have to honor it.
 *
 * Documentation drifting from the interface is the most frequent defect
 * class in this project. `cli-surface.test.js` closed the half of it that
 * is a command line by running every documented invocation against the
 * binary. This file closes the other half, which is everything an
 * operator sets rather than runs: an environment variable, a port, a
 * directory on the data volume, a default value.
 *
 * Each of the five reconciliations below exists because a document
 * carried something the code did not:
 *
 * The variable has to exist. `BLAMEPOST_IMAPS_PORT` and
 * `BLAMEPOST_POP3S_PORT` were both documented in the container image, and
 * neither is a name the configuration schema has ever read. An operator
 * setting one gets no error and no effect, which is the worst of the
 * three possible outcomes.
 *
 * The variable has to be documented. `BLAMEPOST_COMPLIANCE_POSTURE` is
 * the one setting that changes what deleting a message means, and it
 * appeared in no operator document at all while fifteen others did. A
 * setting nobody is told about is a setting nobody sets deliberately.
 *
 * The port has to be one something binds. Ports 993 and 995 were
 * published by the compose file, exposed by the image, listed in the
 * README as protocols this server speaks, and named in the requirements
 * as ports to open at the firewall. Nothing has ever bound either: IMAP
 * and POP3 negotiate TLS in band here. An operator following that opened
 * two holes onto nothing and had clients that could not connect.
 *
 * The path has to be one the code writes. The architecture document drew
 * the data volume with `blamepost.db` in it. The file is `db.enc`, and
 * three sealed key files sit beside it that no document mentioned.
 *
 * And the default has to be the real default. Every setting whose
 * fallback is a plain value is checked against the value the operator
 * guide prints for it, so the table cannot quietly describe the
 * configuration of an earlier release.
 *
 * The last one is a citation rather than a value. Two ROADMAP entries
 * named an issue on the vendored framework's tracker as the reason an
 * envelope sender could not be an alias or a subaddress. The issue
 * closed, the fix arrived in a vendor refresh, the entries were composed
 * against it, and the sentences stayed. A number in somebody else's
 * repository is not something an operator can act on, and it stops being
 * true without saying so, so no shipped surface carries one.
 *
 * That last reconciliation reads a wider set than the four above it, and
 * the two scopes are different on purpose. The four ask what an operator
 * was told they could set, so they read the documents an operator reads.
 * The citation rule asks what this project puts in front of anybody who
 * did not write it, so it reads everything the package manifest ships,
 * plus the templates GitHub renders and the release notes each changelog
 * entry is generated from. A comment in a source file that lands in the
 * tarball is read by strangers exactly as a paragraph in the README is.
 * What stays out is the machinery: `test/`, `scripts/` and the workflow
 * definitions, where naming an issue for the people who maintain the
 * pipeline is the right thing to write.
 *
 * Run standalone: node test/layer-1-state/docs-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var manifest  = require("../../lib/vendor/MANIFEST.json");
var pkg       = require("../../package.json");

var check = helpers.check;
var count = helpers.count;

// The documents an operator reads. A claim in any of them is a claim
// this server has to answer for.
var DOC_FILES = [
  "README.md",
  "ARCHITECTURE.md",
  "THREAT-MODEL.md",
  "ROADMAP.md",
  "SECURITY.md",
  "SUPPORT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "LTS-CALENDAR.md",
  "CODE_OF_CONDUCT.md",
  "MIGRATING.md",
  "CHANGELOG.md",
  "NOTICE",
  "docs/operator-guide.md",
  "compose.yml",
  "Dockerfile",
];

// The document that has to carry every setting. The house rule is that a
// new knob costs a schema entry, a default and a line here, all three in
// the same change; this is the line-here half made mechanical.
var SETTINGS_REFERENCE = "docs/operator-guide.md";

// A variable a compose file substitutes for its own purposes rather than
// one the server reads. Nothing outside this list gets that excuse, and
// an entry needs the reason written next to it.
var COMPOSE_ONLY_VARS = {
  // The hostname the optional HTTPS terminator answers on. Caddy reads
  // it out of its own container environment to open its site block and
  // to get a certificate for that name. Nothing in this server reads it,
  // and adding it to the schema would be the defect this file exists to
  // catch, pointed the other way: a setting an operator can set and the
  // process never consults. The name a proxy in front of the web
  // interface serves never reaches the process, which has
  // BLAMEPOST_HOSTNAME for the identity its own mail listeners present.
  // It carries the BLAMEPOST_ prefix because it is this stack's variable
  // and an operator sets it in the same .env as the rest.
  BLAMEPOST_WEB_HOSTNAME: "the hostname the optional terminator serves, read by Caddy",
};

function read(rel) {
  return nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, rel), "utf8");
}

// ---- what the code really has -----------------------------------------------

// Every environment variable the configuration layer reads, from the
// schema itself rather than from a second list here. A setting added
// there is covered the moment it lands.
function realVariables() {
  var names = {};
  config.SETTINGS.forEach(function (setting) {
    names[setting.env] = "the " + setting.key + " setting";
  });
  config.LISTENER_NAMES.forEach(function (listener) {
    names[config.LISTENER_DEFAULTS[listener].portVar] = "the " + listener + " listener's port";
  });
  // Named in the environment only, because it is the variable that names
  // the file every other setting may also come from.
  names.BLAMEPOST_CONFIG = "the configuration file path";
  return names;
}

// Every TCP port this process will try to bind, listeners and the browser
// surface together. The browser ports come from the schema's own
// fallbacks so a change to either is picked up here.
function realPorts() {
  var ports = {};
  config.LISTENER_NAMES.forEach(function (listener) {
    ports[config.LISTENER_DEFAULTS[listener].port] = listener;
  });
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === "httpPort")  ports[setting.fallback] = "the browser and JMAP surface";
    if (setting.key === "httpsPort") ports[setting.fallback] = "the same surface over TLS";
  });
  return ports;
}

// ---- variables --------------------------------------------------------------

// Every BLAMEPOST_ name any document spells, and which documents spell it.
function documentedVariables() {
  var found = {};
  DOC_FILES.forEach(function (rel) {
    var text;
    try { text = read(rel); } catch (_e) { return; }
    (text.match(/BLAMEPOST_[A-Z0-9_]+/g) || []).forEach(function (name) {
      if (!found[name]) found[name] = [];
      if (found[name].indexOf(rel) === -1) found[name].push(rel);
    });
  });
  return found;
}

function everyDocumentedVariableIsRead(real, documented) {
  var names = Object.keys(documented);
  // A scan that found nothing would report a clean sweep, which is the
  // failure mode a reconciliation has to rule out before it reports one.
  check("the documents name settings at all, so this is comparing something",
    names.length >= 15);

  var invented = names.filter(function (name) {
    return !real[name] && !COMPOSE_ONLY_VARS[name];
  });
  check("every BLAMEPOST_ variable the documents name is one the server reads" +
    (invented.length
      ? ", and these are not: " + invented.map(function (n) {
        return n + " in " + documented[n].join(", ");
      }).join("; ")
      : ""),
    invented.length === 0);
}

function everySettingIsDocumented(real, documented) {
  var undocumented = Object.keys(real).filter(function (name) {
    return !documented[name];
  });
  check("every setting the server reads is named in at least one document" +
    (undocumented.length ? ", and these are not: " + undocumented.join(", ") : ""),
    undocumented.length === 0);

  var text = read(SETTINGS_REFERENCE);
  var missing = Object.keys(real).filter(function (name) {
    return text.indexOf(name) === -1;
  });
  check("and in " + SETTINGS_REFERENCE + ", which is the reference an operator " +
    "reads to find out what is settable" +
    (missing.length ? ", and these are not: " + missing.join(", ") : ""),
    missing.length === 0);
}

// The reference has to carry a ROW per setting rather than a passing
// mention, because a variable named inside a paragraph about something
// else is not a place an operator can look a default up.
function everySettingHasAReferenceRow(rows) {
  var missing = config.SETTINGS.filter(function (setting) {
    return !rows[setting.env];
  }).map(function (setting) { return setting.env; });
  check("every setting has its own row in the " + SETTINGS_REFERENCE + " table" +
    (missing.length ? ", and these do not: " + missing.join(", ") : ""),
    missing.length === 0);
}

// ---- defaults ---------------------------------------------------------------

// Every document that prints a default an operator reads, and which cell
// of each row holds it.
//
// Two documents rather than one. The operator guide is the full
// reference and the README carries a shorter table with a default column
// of its own, and until both were read here only the guide was, so the
// shorter table was free to describe a different server from the one
// beside it. A default written twice by hand is two answers to the same
// question, and the second one drifts.
//
// The cell differs because the tables do: the guide names the
// configuration key between the variable and the default, and the README
// does not.
var DEFAULT_TABLES = [
  { rel: SETTINGS_REFERENCE, defaultCell: 1 },
  { rel: "README.md",        defaultCell: 0 },
];

// The settings-table rows of one document, keyed by variable, as the
// cells they hold. The table is the operator's answer to "what happens
// if I leave this alone", so the answer has to be the one the loader
// would give.
function referenceRows(rel) {
  var rows = {};
  read(rel === undefined ? SETTINGS_REFERENCE : rel).split("\n").forEach(function (line) {
    var m = /^\|\s*`(BLAMEPOST_[A-Z0-9_]+)`\s*\|(.*)$/.exec(line);
    if (!m) return;
    rows[m[1]] = m[2].split("|").map(function (cell) { return cell.trim(); });
  });
  return rows;
}

// A default cell carries a value only when it prints one as code. A cell
// reading `unset`, `*required*` or `this server's hostname` is describing
// a state rather than printing a value, and there is nothing in it to
// hold against the loader.
function printsAValue(cell) {
  return /`[^`]+`/.test(String(cell === undefined ? "" : cell));
}

function everyPrintedDefaultIsTheRealOne() {
  var checked = 0;
  var wrong   = [];

  DEFAULT_TABLES.forEach(function (table) {
    var rows = referenceRows(table.rel);
    config.SETTINGS.forEach(function (setting) {
      var fallback = setting.fallback;
      // Only the settings whose default is a plain value can be compared.
      // A required setting has none, and one computed from the hostname
      // at start is prose rather than a literal.
      if (typeof fallback !== "string" && typeof fallback !== "number" &&
          typeof fallback !== "boolean") return;
      var row = rows[setting.env];
      // A document that carries no row for a setting is answered by
      // everySettingIsDocumented and everySettingHasAReferenceRow, which
      // hold the guide to a row per setting and let the README be the
      // shorter table it is.
      if (!row) return;
      var printed = row[table.defaultCell] === undefined ? "" : row[table.defaultCell];
      if (!printsAValue(printed)) return;
      checked += 1;
      if (printed.indexOf(String(fallback)) === -1) {
        wrong.push(table.rel + " prints " + setting.env + " as " + JSON.stringify(printed) +
          " and the loader falls back to " + JSON.stringify(fallback));
      }
    });
  });

  count("the documents that print defaults compare a real number of them, across every " +
    "one of them rather than the longest",
    checked >= 16, checked + " default(s) over " +
      DEFAULT_TABLES.map(function (t) { return t.rel; }).join(", "));
  check("and every default any of them prints is the one the loader would use" +
    (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);
}

// ---- defaults that are not plain values -------------------------------------

// Why the check above stops where it does, and why the answer is not to
// widen the schema.
//
// A setting whose value is an object or an array carries `fallback:
// null`, and that is deliberate rather than an omission: the module that
// ACTS on the value owns it. The delivery composer holds the retry
// schedule, the spool ceilings and the outbound transport posture, and
// the configuration layer passes an absent value through so those
// modules can apply their own. Writing a real object into the schema
// would put a second copy of every one of those numbers beside the first
// one, which is the drift this file exists to catch, one layer up.
//
// So the comparison is against the module that publishes the value. What
// decides whether a row can be compared at all is what the row PRINTS. A
// cell holding a literal is a promise about specific values and is
// compared field by field. A cell holding prose promises nothing to
// compare, and one holding a template names a value computed at start.
// A literal cell with no source named fails, so a prose cell rewritten
// into a literal is caught rather than inheriting the old exemption.
//
// The retry schedule is also driven end to end in
// test/layer-1-state/delivery-budget.test.js, which spends the whole
// budget over a real spool. What is added here is that no literal row
// escapes comparison, which is a property of the table rather than of
// any one setting.

// A row whose default cell is a literal that nothing publishes, with the
// reason and what would close it. An entry here is read every run and
// named in the output; it is not a silent exemption.
// The list is empty, which is the state to keep it in: a row whose
// default an operator can read is a row this file can compare, and the
// check below fails a literal that nothing publishes rather than
// letting it through. An entry belongs here only for a value whose
// owning module genuinely cannot publish it, and it says which module
// and what would let it.
var UNRECONCILED_OBJECT_DEFAULTS = {};

// A cell that reads as a template rather than a value. The angle
// brackets stand for something resolved at start, such as the hostname
// this server answers for, so there is no literal to compare.
var TEMPLATE_CELL_RE = /<[^>]+>/;

// The default cell as a value, or null when the cell is prose or a
// template. Backticks are the table's own formatting and come off first.
function printedLiteral(cell) {
  var text = String(cell === undefined ? "" : cell).replace(/`/g, "").trim();
  if (text.length === 0) return null;
  if (TEMPLATE_CELL_RE.test(text)) return null;
  var parsed;
  try { parsed = JSON.parse(text); }
  catch (_e) { return null; }
  return parsed !== null && typeof parsed === "object" ? parsed : null;
}

function sameValue(printed, real) {
  if (Array.isArray(printed) || Array.isArray(real)) {
    if (!Array.isArray(printed) || !Array.isArray(real)) return false;
    if (printed.length !== real.length) return false;
    for (var i = 0; i < printed.length; i += 1) {
      if (!sameValue(printed[i], real[i])) return false;
    }
    return true;
  }
  return printed === real;
}

// What the modules that own these values report when nothing is set.
//
// The delivery block is built from one composer with no options beyond
// the two it requires, so what it reports is what an operator gets by
// changing nothing, which is exactly what the table's default column
// claims. The inbound block is the constant the MX listener applies at
// the one place it builds the envelope guard, published for this
// comparison; that the listener still applies it is driven over the
// wire in test/layer-1-state/inbound-absence-verdicts.test.js, which
// starts a server with the setting absent.
function publishedObjectDefaults(dataDir) {
  var shipped = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    audit:    false,
  }).describe();

  return {
    BLAMEPOST_INBOUND: {
      mode:        blamepost.mail.listeners.DEFAULT_INBOUND.mode,
      onTemperror: blamepost.mail.listeners.DEFAULT_INBOUND.onTemperror,
    },
    BLAMEPOST_OUTBOUND_POLICY: {
      mtaSts:          shipped.policy.mtaSts,
      dane:            shipped.policy.dane,
      dnssecValidated: shipped.policy.dnssecValidated,
    },
    BLAMEPOST_OUTBOUND_RETRY: {
      maxAttempts: shipped.policy.maxAttempts,
      backoffMs:   shipped.policy.backoffMs,
    },
    BLAMEPOST_OUTBOUND_SPOOL: {
      maxMessages: shipped.spool.maxMessages,
      maxBytes:    shipped.spool.maxBytes,
    },
  };
}

function everyPrintedObjectDefaultIsTheRealOne(rows, published) {
  var compared  = 0;
  var literals  = 0;
  var prose     = 0;
  var wrong     = [];
  var unsourced = [];
  var carried   = [];

  config.SETTINGS.forEach(function (setting) {
    if (setting.kind !== "object" && setting.kind !== "array") return;
    var row = rows[setting.env];
    // A setting with no row at all is the absence everySettingHasAReferenceRow
    // reports; counting it again here would name one fault twice.
    if (!row) return;

    var printed = printedLiteral(row[1]);
    if (printed === null) { prose += 1; return; }
    literals += 1;

    var real = published[setting.env];
    if (real === undefined) {
      if (UNRECONCILED_OBJECT_DEFAULTS[setting.env]) {
        carried.push(setting.env + ": " + UNRECONCILED_OBJECT_DEFAULTS[setting.env]);
        return;
      }
      unsourced.push(setting.env + " prints " + JSON.stringify(printed));
      return;
    }

    Object.keys(printed).forEach(function (field) {
      compared += 1;
      if (!sameValue(printed[field], real[field])) {
        wrong.push(setting.env + " prints " + field + " as " +
          JSON.stringify(printed[field]) + " and the server uses " +
          JSON.stringify(real[field]));
      }
    });
    Object.keys(real).forEach(function (field) {
      if (!Object.prototype.hasOwnProperty.call(printed, field)) {
        wrong.push(setting.env + " leaves " + field + " out of its default, which the " +
          "server sets to " + JSON.stringify(real[field]));
      }
    });
  });

  count("the reference prints object defaults as values a reader can act on, so this is " +
    "comparing something", literals >= 3 && compared >= 6,
    literals + " literal row(s), " + prose + " prose row(s), " + compared + " field(s) compared");

  check("every field of every object default the reference prints is the one the server " +
    "uses" + (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);

  check("and every object default printed as a literal is one something publishes, so a " +
    "row rewritten from prose into a value is compared rather than exempt" +
    (unsourced.length ? ", and these are not: " + unsourced.join("; ") : ""),
    unsourced.length === 0);

  count("the rows printing a literal nothing publishes are named rather than passed over",
    carried.length === Object.keys(UNRECONCILED_OBJECT_DEFAULTS).length,
    carried.length ? carried.join("; ") : "none");
}

// ---- ports ------------------------------------------------------------------

// The mail ports the container image declares. `EXPOSE` is documentation
// that a tool reads, so a port here that nothing binds sends an operator
// to open a hole onto a closed socket.
function exposedPorts() {
  var ports = [];
  read("Dockerfile").split("\n").forEach(function (line) {
    var m = /^EXPOSE\s+(.+?)\s*$/.exec(line);
    if (!m) return;
    m[1].split(/\s+/).forEach(function (token) {
      var port = parseInt(token, 10);
      if (!isNaN(port) && ports.indexOf(port) === -1) ports.push(port);
    });
  });
  return ports;
}

// The ports the compose file publishes for the blamepost service itself.
// The optional services publish their own and are not this server's to
// answer for, so the scan stops at the first service that follows.
function composePublishedPorts() {
  var lines  = read("compose.yml").split("\n");
  var ports  = [];
  var inMine = false;
  var inList = false;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var service = /^ {2}([a-z][a-z0-9-]*):\s*$/.exec(line);
    if (service) {
      inMine = service[1] === "blamepost";
      inList = false;
      continue;
    }
    if (!inMine) continue;
    if (/^ {4}ports:\s*$/.test(line)) { inList = true; continue; }
    // Any other key at the service's own indentation ends the list.
    if (inList && /^ {4}\S/.test(line)) { inList = false; continue; }
    if (!inList) continue;
    // A commented entry is deliberately not published, so it is read for
    // the port it names without being counted as one that is open.
    var m = /^\s*(?:#\s*)?-\s*"(\d+):(\d+)"/.exec(line);
    if (m) {
      var container = parseInt(m[2], 10);
      if (ports.indexOf(container) === -1) ports.push(container);
    }
  }
  return ports;
}

function everyDeclaredPortIsBound(real) {
  var exposed = exposedPorts();
  count("the image declares its mail ports, so this is comparing something",
    exposed.length >= 5, exposed.join(" "));
  var strayExposed = exposed.filter(function (port) { return !real[port]; });
  check("every port the image exposes is one a listener binds" +
    (strayExposed.length ? ", and these are not: " + strayExposed.join(", ") : ""),
    strayExposed.length === 0);

  var published = composePublishedPorts();
  count("the compose file publishes ports for this server, so this is comparing something",
    published.length >= 5, published.join(" "));
  var strayPublished = published.filter(function (port) { return !real[port]; });
  check("every container port the compose file names is one a listener binds" +
    (strayPublished.length ? ", and these are not: " + strayPublished.join(", ") : ""),
    strayPublished.length === 0);
}

// The operator guide's firewall table is where an operator gets the port
// they open, so each row has to carry the port that listener really takes.
function theFirewallTableMatchesTheListenerTable() {
  var rows = 0;
  var wrong = [];
  read(SETTINGS_REFERENCE).split("\n").forEach(function (line) {
    var m = /^\|\s*(\d+)\s*\|\s*`([a-z0-9]+)`\s*\|/.exec(line);
    if (!m) return;
    var port     = parseInt(m[1], 10);
    var listener = m[2];
    if (config.LISTENER_NAMES.indexOf(listener) === -1) return;
    rows += 1;
    if (config.LISTENER_DEFAULTS[listener].port !== port) {
      wrong.push(listener + " is documented on " + port + " and binds " +
        config.LISTENER_DEFAULTS[listener].port);
    }
  });
  count("the guide's firewall table names the listeners by name", rows >= 5, String(rows));
  check("and each one against the port it actually binds" +
    (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);

  // The per-listener port variables are offered as the way to move a
  // listener off a privileged port, so each one has to be named beside
  // the listener it moves.
  var text = read(SETTINGS_REFERENCE);
  var missing = config.LISTENER_NAMES.filter(function (listener) {
    return text.indexOf(config.LISTENER_DEFAULTS[listener].portVar) === -1;
  });
  check("and every listener's own port variable is documented" +
    (missing.length ? ", and these are not: " + missing.join(", ") : ""),
    missing.length === 0);
}

// ---- paths ------------------------------------------------------------------

// Everything a document says lives on the data volume, against what the
// server puts there. The layout is read off a real directory rather than
// off the paths table, because the table names what the configuration
// layer creates and the store writes files of its own beside them.
//
// A fresh directory does not hold everything the server writes. The store
// declares the top-level names that belong to the volume itself in
// `VOLUME_RESERVED`: the lock, and the directory a restore works in, which
// appears only once a restore has run. Those count as written. The list is
// read from the store, so a name it stops declaring stops being accepted.
function everyDocumentedPathIsWritten(freshEntries) {
  var reserved = Array.isArray(store.VOLUME_RESERVED) ? store.VOLUME_RESERVED : [];
  count("the store declares the names that belong to the volume, so this reads a real list",
    reserved.indexOf("blamepost.lock") !== -1, JSON.stringify(reserved));
  var realEntries = freshEntries.concat(reserved.filter(function (name) {
    return freshEntries.indexOf(name) === -1;
  }));
  var mentioned = {};
  DOC_FILES.forEach(function (rel) {
    var text;
    try { text = read(rel); } catch (_e) { return; }
    (text.match(/\/var\/lib\/blamepost\/[A-Za-z0-9._-]+/g) || []).forEach(function (hit) {
      var segment = hit.slice("/var/lib/blamepost/".length);
      if (!mentioned[segment]) mentioned[segment] = [];
      if (mentioned[segment].indexOf(rel) === -1) mentioned[segment].push(rel);
    });
  });

  var segments = Object.keys(mentioned);
  // Naming one known entry rather than counting, so a regex that stopped
  // matching fails here instead of reporting a clean sweep of nothing.
  count("the documents name paths on the data volume, so this is comparing something",
    segments.indexOf("tls") !== -1, segments.join(", "));

  var stray = segments.filter(function (segment) {
    return realEntries.indexOf(segment) === -1;
  });
  check("every path under the data volume that a document names is one the server writes" +
    (stray.length
      ? ", and these are not: " + stray.map(function (s) {
        return s + " in " + mentioned[s].join(", ");
      }).join("; ")
      : ""),
    stray.length === 0);
}

// The names inside the data-volume tree ARCHITECTURE.md draws, taken from
// the fenced block that opens with the volume's own path. A tree entry is
// a name that follows one of the box-drawing prefixes.
function drawnVolumeEntries() {
  var lines = read("ARCHITECTURE.md").split("\n");
  var entries = [];
  var inTree = false;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (!inTree) {
      if (/^\/var\/lib\/blamepost\/\s*$/.test(line)) inTree = true;
      continue;
    }
    if (/^```/.test(line)) break;
    var m = /^[├└][─]{2}\s+([A-Za-z0-9._-]+)\/?\s/.exec(line);
    if (m && entries.indexOf(m[1]) === -1) entries.push(m[1]);
  }
  return entries;
}

// The architecture document draws the volume as a tree, and the drawing
// is what an operator reads to prepare a backup or to audit where key
// material sits. It has to agree with the volume in both directions: a
// file missing from the drawing is one nobody knows to protect, and a
// name in the drawing that nothing writes sends them looking for a file
// that was never there.
function theDrawnVolumeIsTheWrittenOne(realEntries) {
  var drawn = drawnVolumeEntries();
  count("ARCHITECTURE.md draws the data volume, so this is comparing something",
    drawn.length >= 4, drawn.join(", "));

  var missing = realEntries.filter(function (entry) {
    return drawn.indexOf(entry) === -1;
  });
  check("every file and directory the server writes to the data volume is drawn in " +
    "ARCHITECTURE.md" + (missing.length ? ", and these are not: " + missing.join(", ") : ""),
    missing.length === 0);

  var invented = drawn.filter(function (entry) {
    return realEntries.indexOf(entry) === -1;
  });
  check("and every name it draws is one the server writes" +
    (invented.length ? ", and these are not: " + invented.join(", ") : ""),
    invented.length === 0);
}

// ---- upstream tracker citations ---------------------------------------------

// Everything this project hands to somebody who did not write it.
//
// The npm manifest's `files` array decides what goes in the tarball, so it
// is read here rather than copied: a document that starts shipping is
// covered the day the manifest names it, and one that stops shipping drops
// out without a second edit. Beside it sit the templates GitHub renders to
// a stranger about to open an issue or a pull request, and the release
// notes, which are the authored source every CHANGELOG entry is generated
// from, so a citation written there reaches an operator whether or not
// anybody looks at the generated file.
var EXTRA_SHIPPED_ROOTS = [
  ".github/ISSUE_TEMPLATE",
  ".github/PULL_REQUEST_TEMPLATE.md",
  "release-notes",
];

// The vendored framework is somebody else's tree, read-only here, and an
// issue number in it names that project's own tracker for that project's
// own maintainers. It is the one place the citation is the right thing to
// write.
var VENDOR_PREFIX = "lib/vendor/";

// Declared to ship, built at release time, absent from a working tree by
// design. Named with the reason rather than skipped by a rule that would
// also hide a document somebody deleted: every other root has to resolve.
var GENERATED_ROOTS = {
  "sbom.cdx.json": "a component inventory the release pipeline writes, carrying no prose",
};

// Bytes that cannot hold a sentence. Reading one as UTF-8 puts replacement
// characters into the scan instead of leaving it honest about what it did
// not read, so these are counted apart and reported.
var BINARY_EXTS = {
  ".png": 1, ".ico": 1, ".jpg": 1, ".jpeg": 1, ".gif": 1, ".webp": 1,
  ".woff": 1, ".woff2": 1, ".ttf": 1, ".otf": 1, ".pdf": 1, ".gz": 1,
  ".zip": 1, ".wasm": 1,
};

// Every shipped path, expanded from the roots above. A root that is a
// directory contributes every file under it, so a new page under `docs/`
// or a new view under `lib/web/views/` needs no edit here.
function shippedSurfaces() {
  var out = { files: [], binary: [], vendor: 0, missing: [] };

  function walk(rel) {
    var stat;
    try { stat = nodeFs.statSync(nodePath.join(helpers.REPO_ROOT, rel)); }
    catch (_e) {
      if (!GENERATED_ROOTS[rel]) out.missing.push(rel);
      return;
    }
    if (stat.isDirectory()) {
      nodeFs.readdirSync(nodePath.join(helpers.REPO_ROOT, rel)).sort()
        .forEach(function (name) { walk(rel + "/" + name); });
      return;
    }
    if (rel.indexOf(VENDOR_PREFIX) === 0) { out.vendor += 1; return; }
    if (BINARY_EXTS[nodePath.extname(rel).toLowerCase()]) { out.binary.push(rel); return; }
    out.files.push(rel);
  }

  pkg.files.concat(EXTRA_SHIPPED_ROOTS).forEach(function (root) {
    walk(String(root).replace(/\/+$/, ""));
  });
  return out;
}

// The shapes a citation takes, and the reason each one is here.
//
// The word `upstream` on its own is ordinary vocabulary in these
// documents and matching it would fire on correct prose all day: a
// resolver has an upstream, the optional TLS terminator has an upstream,
// and a contributing guide says where a framework change goes. What
// separates a citation from all of those is a tracking verb or a tracker
// noun sitting against the word, or an issue number on the same line.
//
// The verbs are the participle forms only, and that is the whole
// discrimination. "File a framework bug upstream" routes a contributor
// and stays true forever; "filed upstream" asserts that a named thing is
// sitting in somebody else's queue, which is the claim an operator cannot
// check and which stops being true without saying so.
function citationPatterns(packages) {
  return [
    {
      name: "a vendored package and an issue number",
      re:   new RegExp("(?:" + packages.join("|") + ")#\\d+", "i"),
    },
    {
      name: "a tracking verb against upstream",
      re:   /\b(?:blocked|tracked|filed|reported|raised|logged|opened|pending|awaiting|queued|fixed)\s+(?:it\s+|this\s+|that\s+|them\s+)?upstream\b/i,
    },
    {
      name: "upstream naming a tracker item",
      re:   /\bupstream\s+(?:issue|ticket|bug|tracker|pr)\b/i,
    },
    {
      name: "an issue number on the same line as upstream",
      re:   /upstream[^\n]{0,80}#\d+|#\d+[^\n]{0,80}upstream/i,
    },
  ];
}

// Lines that MUST match, and lines from the shipped tree that must NOT.
//
// A matcher is worth nothing until it has been shown to fire, and worth
// less than nothing once it fires on prose that is right, because that is
// the point people start working around it. The second list is quoted
// from the real documents: every legitimate sense of the word this
// project uses, so widening the first list cannot quietly swallow one.
var CITATION_CANARIES = [
  "Tracked upstream as blamejs#665; when it lands, the table gains two rows.",
  "Sending under an alias is blocked upstream.",
  "The octet handling is a limit in the vendored framework, filed upstream.",
  "Reported upstream; until it changes, the correct line is the one written here.",
  "This is pending upstream and there is nothing to set.",
  "See the upstream issue for the shape the fix will take.",
  "Awaiting upstream before the refusal comes out.",
  "The behavior is fixed upstream in the next bundle.",
  "Carried as upstream #700 against the POP3 stage guards.",
];

var NOT_CITATIONS = [
  "One resolver serves every mail path and no setting names its upstream, so",
  "goes upstream to blamejs, or gets composed here from the surface that already",
  "It has no accounts to sell, no usage to meter, and no upstream to phone.",
  "the guards. If it genuinely does not, the answer is upstream, not a second entry",
  "| A framework primitive, a protocol parser, a crypto envelope | upstream in blamejs |",
  "Fail fast rather than queueing behind a wedged upstream.",
  "the resolver this server builds already bounds each of its own upstream fetches",
  "no lookup this server makes asks its upstream for a DNSSEC verdict",
  "the published port, the health probe and this upstream cannot drift",
  "File a framework primitive upstream rather than patching the vendored tree.",
];

// A shipped surface may not cite an issue on somebody else's tracker, and
// may not tell an operator that something is sitting in one.
//
// Two things are wrong with either form. An operator cannot act on it:
// the number names a conversation in a repository they do not have, and
// the bare phrase does not even give them that, so what they are left
// with is the news that a capability is missing and no way to find out
// whether it still is. And it goes stale without saying so. The sentence
// is written while a limitation is real, the issue closes, the vendored
// tree is refreshed, and the sentence keeps describing a limitation that
// no longer exists. Two entries in ROADMAP.md sat that way across a
// refresh, describing an envelope binding that had already been composed.
//
// The package names come from the vendor manifest rather than from a list
// here, so a second vendored package is covered the day it lands and a
// rename of the existing one cannot leave this matching nothing.
function noShippedSurfaceCitesAnUpstreamTracker() {
  var packages = Object.keys(manifest.packages).sort();
  count("the vendor manifest names at least one package, so the numbered shape " +
    "is built from something", packages.length >= 1, packages.join(", "));

  var patterns = citationPatterns(packages);

  function citationIn(line) {
    for (var i = 0; i < patterns.length; i += 1) {
      if (patterns[i].re.test(line)) return patterns[i].name;
    }
    return null;
  }

  // Every shape proved to fire, and every legitimate sense proved not to,
  // before a single verdict is taken from this matcher. A shape that has
  // quietly stopped matching fails here rather than reporting a clean
  // tree, which is the one failure a scan cannot report on its own.
  var silent = CITATION_CANARIES.filter(function (line) { return !citationIn(line); });
  count("every citation shape this matcher claims is one it fires on",
    silent.length === 0, silent.join(" | "));

  var shapesFired = {};
  CITATION_CANARIES.forEach(function (line) {
    var name = citationIn(line);
    if (name) shapesFired[name] = true;
  });
  count("and every pattern in the set is the one some canary needed",
    Object.keys(shapesFired).length === patterns.length,
    Object.keys(shapesFired).join("; "));

  var crying = NOT_CITATIONS.filter(function (line) { return citationIn(line); });
  count("and none of them fires on the senses of the word these documents " +
    "legitimately use, because a gate that fires on correct prose is one " +
    "people learn to route around",
    crying.length === 0,
    crying.map(function (l) { return citationIn(l) + " on " + l; }).join(" | "));

  var shipped = shippedSurfaces();

  var hits  = [];
  var lines = 0;
  var files = 0;
  shipped.files.forEach(function (rel) {
    // Deliberately not caught. A listed path that cannot be read means the
    // walk and the tree disagree, and reporting that as a clean file is
    // exactly how a scan comes back green having read nothing.
    var text = read(rel);
    files += 1;
    text.split(/\r?\n/).forEach(function (line, i) {
      lines += 1;
      var name = citationIn(line);
      if (name) hits.push(rel + ":" + (i + 1) + " (" + name + ") " + line.trim().slice(0, 120));
    });
  });

  // Published before any verdict is taken from the walk, so the run that
  // fails says what it read as plainly as the run that passes. Files and
  // lines both: a walk that resolved against the wrong base and a walk
  // that read every file as empty are different faults, and only the
  // second number tells them apart.
  console.log("EXAMINED " + files + " shipped-surfaces");
  console.log("EXAMINED " + lines + " scanned-lines");

  count("every path the package manifest says ships is one that is here" +
    (shipped.missing.length ? ", and these are not: " + shipped.missing.join(", ") : ""),
    shipped.missing.length === 0, shipped.missing.join(", "));

  count("the walk reached the shipped tree, rather than reporting it clean unread",
    files >= 40 && lines >= 20000, files + " file(s), " + lines + " line(s), " +
      shipped.binary.length + " binary skipped, " + shipped.vendor + " vendored skipped");

  check("no shipped surface cites an upstream tracker, because an operator cannot " +
    "act on one and it stops being true without saying so" +
    (hits.length ? ", and these do: " + hits.join("; ") : ""),
    hits.length === 0);
}

// ---- runner -----------------------------------------------------------------

// What a fresh data directory holds once the server has prepared it. Run
// rather than read, because the question is what lands on the volume and
// the only answer that cannot drift is the one taken from the volume.
async function realVolumeEntries(root) {
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:         "mx.example.com",
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: "a long enough vault passphrase for one test run",
    },
    cwd: root,
  });
  config.ensureDataDirectories(cfg);

  var opened = await store.open(cfg);
  try { opened.close(); }
  catch (_e) { /* drop-silent by design: the listing below is the verdict */ }

  return nodeFs.readdirSync(dataDir).sort();
}

async function run() {
  var root = helpers.tempDir("docs-surface");

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    var workDir = nodePath.join(root, "work");
    nodeFs.mkdirSync(workDir, { recursive: true });
    process.env.BLAMEJS_TMPDIR = workDir;

    var real       = realVariables();
    var documented = documentedVariables();
    var rows       = referenceRows();

    everyDocumentedVariableIsRead(real, documented);
    everySettingIsDocumented(real, documented);
    everySettingHasAReferenceRow(rows);
    everyPrintedDefaultIsTheRealOne();

    var spoolDir = nodePath.join(root, "delivery");
    nodeFs.mkdirSync(spoolDir, { recursive: true });
    everyPrintedObjectDefaultIsTheRealOne(rows, publishedObjectDefaults(spoolDir));

    everyDeclaredPortIsBound(realPorts());
    theFirewallTableMatchesTheListenerTable();

    noShippedSurfaceCitesAnUpstreamTracker();

    var entries = await realVolumeEntries(root);
    count("preparing a data directory writes something to it", entries.length >= 4,
      entries.join(", "));
    everyDocumentedPathIsWritten(entries);
    theDrawnVolumeIsTheWrittenOne(entries);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "docs-surface", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
