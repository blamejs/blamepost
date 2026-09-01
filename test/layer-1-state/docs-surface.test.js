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
 * Each of the four reconciliations below exists because a document
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
 * Run standalone: node test/layer-1-state/docs-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");

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

// The settings-table rows, keyed by variable, as the cells they hold. The
// table is the operator's answer to "what happens if I leave this alone",
// so the answer has to be the one the loader would give.
function referenceRows() {
  var rows = {};
  read(SETTINGS_REFERENCE).split("\n").forEach(function (line) {
    var m = /^\|\s*`(BLAMEPOST_[A-Z0-9_]+)`\s*\|(.*)$/.exec(line);
    if (!m) return;
    rows[m[1]] = m[2].split("|").map(function (cell) { return cell.trim(); });
  });
  return rows;
}

function everyPrintedDefaultIsTheRealOne(rows) {
  var checked = 0;
  var wrong   = [];
  config.SETTINGS.forEach(function (setting) {
    var fallback = setting.fallback;
    // Only the settings whose default is a plain value can be compared.
    // A required setting has none, and one computed from the hostname at
    // start is prose rather than a literal.
    if (typeof fallback !== "string" && typeof fallback !== "number" &&
        typeof fallback !== "boolean") return;
    var row = rows[setting.env];
    if (!row) return;
    // Cell 0 is the JSON key and cell 1 is the default.
    var printed = row[1] === undefined ? "" : row[1];
    checked += 1;
    if (printed.indexOf(String(fallback)) === -1) {
      wrong.push(setting.env + " prints " + JSON.stringify(printed) +
        " and the loader falls back to " + JSON.stringify(fallback));
    }
  });
  check("the reference compares a real number of defaults", checked >= 8);
  check("and every default it prints is the one the loader would use" +
    (wrong.length ? ": " + wrong.join("; ") : ""),
    wrong.length === 0);
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
function everyDocumentedPathIsWritten(realEntries) {
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
// is what an operator reads to plan a backup or to audit where key
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

  var store = await require("../../lib/store").open(cfg);
  try { store.close(); }
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
    everyPrintedDefaultIsTheRealOne(rows);

    everyDeclaredPortIsBound(realPorts());
    theFirewallTableMatchesTheListenerTable();

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
