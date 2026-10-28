// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every command line the documentation tells an operator to run, run
 * against the binary that has to answer it.
 *
 * This is the most frequent defect in the project by a wide margin. A
 * document has named a verb or a flag that was never built at least
 * fifteen times: `doctor --domain`, `dkim activate`, `dkim show`, nine
 * `queue` verbs against three real ones, `account show` for something it
 * does not print, and a further nine `account` and `queue` commands
 * found the first time this reconciliation ran. Every one of them was
 * caught by a person reading carefully, which is not a control.
 *
 * So the reconciliation is mechanical, and it covers three things.
 *
 * The verb has to exist. The documented set is extracted from the
 * shipped documents and compared against the verbs each group prints in
 * its own usage block.
 *
 * The flags have to exist too, and that half is what a verb-only check
 * misses: `domain remove --destroy` was declared, described in the help
 * text, documented in the guide, and read by nothing. So every
 * documented command line is re-run against a target that does not
 * exist, and the binary must not answer that the verb does not take one
 * of the flags on it.
 *
 * And the documented line has to be complete. `blamepost domain remove
 * example.com` appeared in the guide against a verb that requires two
 * flags, so an operator following it got a refusal rather than a
 * removal. A run that comes back asking for a flag the document never
 * mentioned is the same defect pointing the other way.
 *
 * The flag half runs in both directions, and the second one is newer. A
 * flag a document names has to be one the verb reads, and a flag the verb
 * reads has to be one its own usage block names: `dkim generate` took
 * `--selector` and printed a usage block that did not mention it, so the
 * only way to find the flag was to read the source.
 *
 * The argument half is the same question about names rather than flags. A
 * lookup answers null for a mailbox that is not here and for a string that
 * could never name one, and the two are different answers: one is fixed by
 * creating the account, the other by retyping the line. `account show
 * a@@b` reported the second as the first, at the exit code that means this
 * server tried and failed, while `account add a@@b` refused the same
 * string as an argument fault. A script driving either could not tell a
 * typo from a missing mailbox.
 *
 * The gate behind those two checks is proven live rather than assumed:
 * a flag the verb does not read, and an argument too many, both have to
 * be refused by name.
 *
 * The rest of the file covers what `account suspend` and `account
 * resume` actually do, because suspension is the first move on a
 * compromised credential and the guide had its effect backwards: it said
 * a suspended account still receives mail, and the store refuses
 * delivery to it.
 *
 * Run standalone: node test/layer-1-state/cli-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The command groups that take a verb, and the commands that take flags
// instead. Both halves are reconciled; only the shape of the comparison
// differs.
var VERB_GROUPS  = ["account", "domain", "dkim", "zone", "credential", "reports", "dmarc",
  "queue", "blobs", "attachments", "audit", "backup", "restore"];
var FLAG_COMMANDS = ["serve", "init", "doctor"];

// Documents an operator reads. A command named in any of them has to be
// a command that exists, spelled with flags that exist.
var DOC_FILES = [
  "README.md",
  "docs/operator-guide.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "SUPPORT.md",
  "ARCHITECTURE.md",
  "THREAT-MODEL.md",
  "ROADMAP.md",
];

// Values for the flags that take one. A documented line is replayed
// against a target that does not exist, so nothing it names can be
// changed; these only have to be well formed enough to reach the verb
// and be recognized as the flag's value rather than as an argument.
var FLAG_VALUES = {
  domain:      "nothosted.example",
  account:     "nobody@nothosted.example",
  destination: "nothosted.example",
  reason:      "reconciling the documentation against the binary",
  by:          "nobody@nothosted.example",
  script:      "no-such-script",
  selector:    "bp000000",
  // The preservation-order verbs. A replayed line names an account that
  // does not exist, so it reaches the flag check and stops before any
  // mailbox is opened; these only have to be shaped like what an
  // operator would type.
  mailbox:     "INBOX",
  message:     "obj_00000000000000000000000000000000",
  citation:    "FRCP-26",
  custodian:   "nobody@nothosted.example",
  approver:    "nobody@nothosted.example",
  password:    "a long enough stand-in password 4291",
  quota:       "1",
  // The bundle verbs. Every one of them refuses on the passphrase file
  // before it opens a store or creates a directory, and nothing here
  // names a file that exists, so a replayed line reaches the flag check
  // and stops. The dates and counts are well formed because a value the
  // parser cannot coerce would refuse for the wrong reason.
  storage:            "no-such-backup-store",
  bundle:             "2026-01-01T00-00-00-000Z-0123abcd",
  point:              "no-such-rollback-point",
  "passphrase-file":  "no-such-passphrase-file",
  // The zone credential. It names no file that exists, so a replayed
  // line reaches the flag check and stops before anything is sealed.
  "token-file":       "no-such-token-file",
  // The sending credential verbs. A replayed line names a domain or an
  // identifier that is not on the volume, so it reaches the flag check
  // and stops before a credential is issued or changed. The two windows
  // are inside the bounds the registry holds, because a value outside
  // them would refuse for the bound rather than for the flag.
  "bounce-to":        "nobody@nothosted.example",
  expires:            "2099-01-01T00:00:00Z",
  "max-messages":     "1",
  "max-recipients":   "1",
  "window-minutes":   "60",
  "grace-hours":      "1",
  "local-part":       "postmaster",
  fingerprint:        "0000000000000000000000000000000000000000000000000000000000000000",
  out:                "no-such-output-bundle",
  in:                 "no-such-input-bundle",
  archive:            "no-such-archive-bundle",
  before:             "2026-01-01T00:00:00Z",
  from:               "2026-01-01T00:00:00Z",
  to:                 "2026-12-31T23:59:59Z",
  action:             "account.created",
  outcome:            "success",
  limit:              "1",
  keep:               "1",
};

// Flags that take no value. Passing one a value would make the value
// look like an argument and produce a refusal about arity instead.
var BOOLEAN_FLAGS = ["destroy", "withdraw", "immediate", "force", "dane", "json", "confirm",
  "verify", "include-archived", "include-unauthenticated", "clear", "include-revoked",
  "include-expired"];

// A name no verb in the group can read. The address carries two at
// signs and the domain an empty label, so each is refused by the shape
// check rather than looked up and missed, and neither can collide with a
// row this run created.
var UNREADABLE = {
  account: "a@@b",
  domain:  "a..b",
};

// What a refusal has to say about one. Naming the value back and saying
// it could not be read is the half an operator acts on; the exit code is
// the half a script acts on.
var REFUSED_UNREADABLE = /is not a usable (mailbox address|domain name)/;

// A refusal that means the flag or the argument was not part of the
// verb's surface, and one that means a required flag was missing. Both
// are the CLI's own wording, so they say what the operator was told
// rather than what an internal call returned.
// A flag can be wrong in two ways, and both have shipped in a document
// before: one the parser has never heard of, and one the group declares
// but this verb does not act on.
var REFUSED_UNREAD  = /does not take|unknown flag/;
var REFUSED_MISSING = /give --([a-z-]+)/;

// ---- reading the binary ----------------------------------------------------

// The verbs a group really has, read out of its own usage block. Each
// line of the block starts with two spaces and the verb.
// The table has no prototype, and the reason is the comparison it feeds.
// The verb pattern matches any run of lowercase letters, so `constructor`,
// `toString` and `valueOf` are all shapes a document could name. On an
// ordinary object each of those reads back truthy without ever having been
// listed, so an invented verb with one of those names would be reported as
// one that exists. A table with nothing behind it answers only for what was
// put in it.
function verbsOf(run, group) {
  var usage = run([group]).both;
  var verbs = Object.create(null);
  usage.split("\n").forEach(function (line) {
    var m = /^ {2}([a-z][a-z0-9-]*)\s/.exec(line);
    if (m) verbs[m[1]] = true;
  });
  return verbs;
}

// The flags a group's usage block names against each of its verbs. A
// verb's own line carries them, and so does any continuation line
// beneath it, which is how `account sieve` documents `--script`.
function usageFlagsOf(run, group) {
  var perVerb = {};
  var current = null;
  run([group]).both.split("\n").forEach(function (line) {
    var m = /^ {2}([a-z][a-z0-9-]*)\s/.exec(line);
    if (m) {
      current = m[1];
      if (!perVerb[current]) perVerb[current] = [];
    }
    if (!current) return;
    var flags = line.match(/--[a-z][a-z0-9-]*/g) || [];
    flags.forEach(function (raw) {
      var name = raw.slice(2);
      if (perVerb[current].indexOf(name) === -1) perVerb[current].push(name);
    });
  });
  return perVerb;
}

// The flags a flag-taking command really has, read out of its own help.
function helpFlagsOf(run, command) {
  var text = run([command, "--help"]).both;
  var found = {};
  text.split("\n").forEach(function (line) {
    var flags = line.match(/--[a-z][a-z0-9-]*/g) || [];
    flags.forEach(function (raw) { found[raw.slice(2)] = true; });
  });
  return found;
}

// ---- reading the documents -------------------------------------------------

// Every `blamepost ...` invocation an operator is told to run, as the
// group, the verb and the flags on the line. Backslash continuations are
// joined first, because the erasure example spans three lines, and a
// trailing comment or a closing backtick ends the command.
function documentedInvocations() {
  var out = [];
  DOC_FILES.forEach(function (rel) {
    var text;
    try { text = nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, rel), "utf8"); }
    catch (_e) { return; }
    text.replace(/\\\r?\n\s*/g, " ").split("\n").forEach(function (line) {
      var m = /blamepost\s+(.*)$/.exec(line);
      if (!m) return;
      var rest = m[1].split("`")[0].replace(/\s+#.*$/, "");
      var tokens = rest.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return;
      var group = tokens[0];
      var isVerbGroup = VERB_GROUPS.indexOf(group) !== -1;
      if (!isVerbGroup && FLAG_COMMANDS.indexOf(group) === -1) return;

      var verb = null;
      var index = 1;
      if (isVerbGroup) {
        if (!/^[a-z][a-z0-9-]*$/.test(tokens[1] || "")) return;
        verb = tokens[1];
        index = 2;
      }
      var flags = [];
      for (; index < tokens.length; index += 1) {
        var token = tokens[index];
        if (token.indexOf("--") !== 0) continue;
        var name = token.slice(2).split("=")[0];
        if (/^[a-z][a-z0-9-]*$/.test(name) && flags.indexOf(name) === -1) flags.push(name);
      }
      // A line with nothing after the verb is prose naming the verb
      // rather than a line to copy, and replaying one would report a
      // flag the sentence never claimed to give. The verb itself is
      // still reconciled; only the replay skips it.
      out.push({
        file:     rel,
        group:    group,
        verb:     verb,
        flags:    flags,
        runnable: tokens.length > (isVerbGroup ? 2 : 1),
      });
    });
  });
  return out;
}

// ---- every command named anywhere in the tree ------------------------------

// The documents above are not the only place a command is named, and they
// are not the place an operator is most likely to be reading. `bin` prints
// advice mid-run: after an erasure that could not finish, beside a queue
// that has filled, under a restore that stopped. That text arrives at a
// terminal during an incident, which is a worse moment to be sent to a
// verb that does not exist than a document is. The admin pages name
// commands too, and so do the release notes.
//
// So the verb half of the reconciliation reads the whole tree. Only the
// verb half: a line in a source string names its argument as `<id>` or
// `<domain>` rather than giving one, so it is not a line to replay, and
// the replay set above is left exactly as it was.
// Generated directories that hold no shipped source. `.playwright-mcp` is the
// browser tool's snapshot output: gitignored, rewritten on every browser run,
// and carrying whatever page text was on screen, so a verb it quotes says
// nothing about a document an operator reads. Named one by one rather than
// skipping every dot-directory, because `.github/` is committed source and its
// workflows can name a real command.
var SKIP_DIRS  = { ".git": 1, "node_modules": 1, "vendor": 1, ".test-output": 1, "coverage": 1,
  ".playwright-mcp": 1 };
var SCAN_EXTS  = { ".js": 1, ".mjs": 1, ".md": 1, ".json": 1, ".html": 1, ".yml": 1, ".yaml": 1, ".sh": 1 };

// A command split by a string concatenation is still one command:
//
//   "... `blamepost account " +
//     "alias`."
//
// A scanner reading a line at a time sees `blamepost account` and stops,
// which is how a verb that does not exist survived in `bin` while this
// file was watching for exactly that. The join is part of the pattern,
// and the match runs against the whole file so it can cross the newline.
var JOIN = '(?:[ \\t]|"[ \\t]*\\+[ \\t]*\\r?\\n?[ \\t]*")+';
var NAMED_RE = new RegExp(
  'blamepost' + JOIN + '([a-z][a-z0-9-]*)(?:' + JOIN + '([a-z][a-z0-9-]*))?', 'g');

function _filesUnder(dir, out) {
  var entries;
  try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return out; }
  entries.forEach(function (entry) {
    var full = nodePath.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS[entry.name]) return;
      _filesUnder(full, out);
      return;
    }
    if (SCAN_EXTS[nodePath.extname(entry.name)]) out.push(full);
  });
  return out;
}

// Every `blamepost <group> <verb>` this repository writes down, wherever
// it writes it, with the file and line that says it.
function commandsNamedAnywhere(verbs) {
  var files = _filesUnder(helpers.REPO_ROOT, []);
  var named = {};
  var chained = [];
  var mentions = 0;
  files.forEach(function (full) {
    var rel = nodePath.relative(helpers.REPO_ROOT, full).replace(/\\/g, "/");
    if (rel.indexOf("lib/vendor/") === 0) return;
    var text;
    try { text = nodeFs.readFileSync(full, "utf8"); } catch (_e) { return; }
    if (text.indexOf("blamepost") === -1) return;

    // Newline offsets once per file, so naming the line is a search rather
    // than a re-count. A gate that reports the wrong line sends the reader
    // to the wrong place, which is the defect this one is hunting.
    var breaks = [];
    for (var i = 0; i < text.length; i += 1) {
      if (text.charCodeAt(i) === 10) breaks.push(i);
    }
    function lineAt(offset) {
      var lo = 0, hi = breaks.length;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (breaks[mid] < offset) lo = mid + 1; else hi = mid;
      }
      return lo + 1;
    }

    var match;
    NAMED_RE.lastIndex = 0;
    while ((match = NAMED_RE.exec(text))) {
      mentions += 1;
      var group = match[1];
      var verb  = match[2];
      if (VERB_GROUPS.indexOf(group) === -1) continue;
      if (!verb) continue;                     // the group alone is ordinary prose
      var key = group + " " + verb;
      if (!named[key]) named[key] = [];
      named[key].push(rel + ":" + lineAt(match.index));

      // A verb followed by another of its own group's verbs. No command
      // here takes a verb name as an argument, so this is somebody
      // writing `account messages list` for what is spelled `account
      // messages <address>`, and at a terminal it looks up an account
      // named `list`. The verb half of the reconciliation cannot see it,
      // because both words are real verbs.
      //
      // The token is compared whole. `account show list@example.com`
      // ends in a real address that starts with a verb's name, and
      // reading a prefix would report it as this mistake.
      var after = text.slice(match.index + match[0].length);
      var third = /^[ \t]+([a-z0-9][a-z0-9._@-]*)/.exec(after);
      if (third && Object.prototype.hasOwnProperty.call(verbs, group) &&
          verbs[group][third[1]]) {
        chained.push("`blamepost " + group + " " + verb + " " + third[1] + "` at " +
          rel + ":" + lineAt(match.index));
      }
    }
  });
  return { named: named, chained: chained, files: files.length, mentions: mentions };
}

// ---- replaying a documented line -------------------------------------------

// A target no verb can find. Each call gets its own, so replaying one
// line cannot change what the next line sees, and nothing an operator
// might recognize is ever named.
var uniqueTarget = 0;
function absentTarget(group) {
  uniqueTarget += 1;
  var host = "nothosted-" + uniqueTarget + ".example";
  if (group === "account") return "nobody@" + host;
  if (group === "queue")   return b.crypto.generateToken(12);
  return host;
}

function _spawnReplay(run, group, verb, flags, target) {
  var argv = [group, verb];
  if (target !== null) argv.push(target);
  flags.forEach(function (name) {
    if (name === "config" || name === "data-dir") return;  // would repoint the run
    argv.push("--" + name);
    if (BOOLEAN_FLAGS.indexOf(name) === -1) {
      argv.push(FLAG_VALUES[name] === undefined ? "stand-in" : FLAG_VALUES[name]);
    }
  });
  return run(argv);
}

// A verb that takes an argument has to be given one, or its own missing
// argument branch answers before the flags are ever looked at. Which
// verbs those are is read off the binary rather than kept in a second
// table here: the arity refusal names itself, so a run that trips it is
// repeated without the target.
function replay(run, group, verb, flags) {
  var withTarget = _spawnReplay(run, group, verb, flags, absentTarget(group));
  if (!/would be ignored/.test(withTarget.both)) return withTarget;
  return _spawnReplay(run, group, verb, flags, null);
}

// ---- cases -----------------------------------------------------------------

function everyDocumentedVerbExists(run, documented) {
  var real = {};
  VERB_GROUPS.forEach(function (group) { real[group] = verbsOf(run, group); });

  // A group whose usage could not be read would make every command below
  // look invented, so the reading is checked before the comparison.
  VERB_GROUPS.forEach(function (group) {
    count("the " + group + " group reports its own verbs",
      Object.keys(real[group]).length > 0, Object.keys(real[group]).join(", "));
  });

  // Every comparison below is a lookup into those tables, so a table that
  // answers for something nobody listed reports an invented verb as real.
  // These four names are the ones an ordinary object answers for, and the
  // verb pattern matches all of them.
  var PROTOTYPE_NAMES = ["constructor", "toString", "valueOf", "hasOwnProperty"];
  var answeredUnlisted = [];
  VERB_GROUPS.forEach(function (group) {
    PROTOTYPE_NAMES.forEach(function (name) {
      if (real[group][name]) answeredUnlisted.push(group + " " + name);
    });
  });
  count("no group answers for a verb it never listed",
    answeredUnlisted.length === 0, answeredUnlisted.join(", "));

  var named = {};
  documented.forEach(function (entry) {
    if (!entry.verb) return;
    var key = entry.group + " " + entry.verb;
    if (!named[key]) named[key] = [];
    if (named[key].indexOf(entry.file) === -1) named[key].push(entry.file);
  });
  var names = Object.keys(named).sort();
  count("the documents name commands at all, so this is comparing something",
    names.length >= 10, names.length + " found");

  var invented = names.filter(function (name) {
    var parts = name.split(" ");
    return !real[parts[0]][parts[1]];
  });
  count("every command the documents name is a command that exists",
    invented.length === 0,
    invented.map(function (n) { return n + " in " + named[n].join(", "); }).join("; "));

  // The same question over the whole tree. The documents are the place
  // this reconciliation started and the place it is least likely to find
  // anything now, because they are the half that has been checked all
  // along.
  var everywhere = commandsNamedAnywhere(real);
  // Published before the verdict below, not after it. A count that only
  // prints on a passing run answers for nothing on the run where somebody
  // needs to know what was read.
  console.log("EXAMINED " + everywhere.files + " files");
  console.log("EXAMINED " + everywhere.mentions + " command mentions");

  count("the tree was actually read, rather than reported clean unread",
    everywhere.files >= 100 && everywhere.mentions >= 100,
    everywhere.files + " file(s), " + everywhere.mentions + " mention(s)");

  var anywhereNames = Object.keys(everywhere.named).sort();
  count("and it names commands, so this is comparing something",
    anywhereNames.length >= 10, anywhereNames.length + " distinct command(s) named");

  var inventedAnywhere = anywhereNames.filter(function (name) {
    var parts = name.split(" ");
    return !real[parts[0]][parts[1]];
  });
  count("every command named anywhere in this repository is a command that exists",
    inventedAnywhere.length === 0,
    inventedAnywhere.map(function (n) {
      return "`blamepost " + n + "` at " + everywhere.named[n].join(", ");
    }).join("; "));

  // The mistake the check above structurally cannot see: two real verbs
  // written one after the other. `account messages list` is spelled from
  // two things that exist and is not a command, and at a terminal it
  // looks up an account named `list`.
  count("and no command names one verb where the next word is another of its own verbs",
    everywhere.chained.length === 0, everywhere.chained.join("; "));
  return real;
}

// The flag half, and the one a verb-only reconciliation cannot see.
function everyDocumentedFlagIsRead(run, documented) {
  var runnable = documented.filter(function (e) { return e.verb && e.runnable; });
  count("the documents carry command lines to copy, so this is comparing something",
    runnable.length >= 15, runnable.length + " runnable command line(s) found");
  count("and some of them spell out flags",
    runnable.filter(function (e) { return e.flags.length > 0; }).length >= 8,
    runnable.filter(function (e) { return e.flags.length > 0; }).length + " carry flags");

  // One replay per distinct line, so a document that repeats the same
  // invocation does not pay for it twice.
  var seen = {};
  var unread  = [];
  var missing = [];
  runnable.forEach(function (entry) {
    var key = entry.group + " " + entry.verb + " " + entry.flags.slice().sort().join(",");
    if (seen[key]) return;
    seen[key] = true;
    var result = replay(run, entry.group, entry.verb, entry.flags);
    var line = "blamepost " + entry.group + " " + entry.verb +
      (entry.flags.length ? " --" + entry.flags.join(" --") : "") + " in " + entry.file;
    if (REFUSED_UNREAD.test(result.both)) unread.push(line + " -> " + result.both.trim());
    var asked = REFUSED_MISSING.exec(result.both);
    if (asked && entry.flags.indexOf(asked[1]) === -1) {
      missing.push(line + " -> " + result.both.trim());
    }
  });

  count("every flag the documents put on a command is one that command reads",
    unread.length === 0, unread.join(" ; "));
  count("and every documented command line carries the flags its verb requires",
    missing.length === 0, missing.join(" ; "));
}

// The usage block is what an operator reads when they run the group with
// no verb, so it is reconciled the same way the documents are.
function everyUsageFlagIsRead(run) {
  var stray = [];
  VERB_GROUPS.forEach(function (group) {
    var perVerb = usageFlagsOf(run, group);
    Object.keys(perVerb).forEach(function (verb) {
      if (perVerb[verb].length === 0) return;
      var result = replay(run, group, verb, perVerb[verb]);
      if (REFUSED_UNREAD.test(result.both)) {
        stray.push("blamepost " + group + " " + verb + " --" + perVerb[verb].join(" --") +
          " -> " + result.both.trim());
      }
    });
  });
  count("every flag a group's usage block offers is one that verb reads",
    stray.length === 0, stray.join(" ; "));
}

function everyDocumentedCommandFlagExists(run, documented) {
  var stray = [];
  FLAG_COMMANDS.forEach(function (command) {
    var real = helpFlagsOf(run, command);
    count("`" + command + "` reports its own flags",
      Object.keys(real).length > 0, Object.keys(real).join(", "));
    documented.forEach(function (entry) {
      if (entry.group !== command) return;
      entry.flags.forEach(function (name) {
        if (real[name]) return;
        stray.push("blamepost " + command + " --" + name + " in " + entry.file);
      });
    });
  });
  count("every flag the documents put on serve, init or doctor is one it declares",
    stray.length === 0, stray.join("; "));
}

// The gate covers a verb only if the verb has a row in the table behind
// it, and a verb without one keeps working while quietly accepting
// anything. So the table is reconciled against the verbs each group
// prints, in both directions: a verb in the usage and not the table is
// an ungated verb, and a verb in the table and not the usage is one no
// operator is told about.
function theGateCoversEveryVerbTheGroupOffers(run) {
  var surface = require("../../bin/blamepost.js").VERB_SURFACE;
  count("the binary publishes the table the gate reads",
    surface && Object.keys(surface).length === VERB_GROUPS.length,
    surface ? Object.keys(surface).join(", ") : String(surface));

  var ungated = [];
  var unadvertised = [];
  VERB_GROUPS.forEach(function (group) {
    var offered = Object.keys(verbsOf(run, group));
    var gated   = Object.keys(surface[group] || {});
    offered.forEach(function (verb) {
      if (gated.indexOf(verb) === -1) ungated.push(group + " " + verb);
    });
    gated.forEach(function (verb) {
      if (offered.indexOf(verb) === -1) unadvertised.push(group + " " + verb);
    });
  });
  count("every verb a group offers is one the flag gate covers",
    ungated.length === 0, ungated.join(", "));
  count("and every verb the gate covers is one the group offers",
    unadvertised.length === 0, unadvertised.join(", "));
}

// The gate the reconciliations lean on. A check that reads a refusal the
// binary never emits passes for every input, which is the worst failure
// mode a reconciliation has.
function theUnreadFlagGateIsLive(run) {
  var strayFlag = run(["account", "list", "--script", "anything"]);
  count("a flag the verb does not read is refused rather than dropped",
    strayFlag.status === 2, "exit " + strayFlag.status + " " + strayFlag.both.slice(0, 140));
  count("and the refusal names the flag that will not be acted on",
    /--script/.test(strayFlag.both), strayFlag.both.slice(0, 160));
  count("and says which flags the verb does read",
    /--domain/.test(strayFlag.both), strayFlag.both.slice(0, 160));

  var strayArg = run(["account", "show", ADDRESS, "someone-else@" + DOMAIN]);
  count("an argument too many is refused rather than ignored",
    strayArg.status === 2, "exit " + strayArg.status + " " + strayArg.both.slice(0, 140));
  count("and the refusal names the argument that would have been dropped",
    strayArg.both.indexOf("someone-else@" + DOMAIN) !== -1, strayArg.both.slice(0, 200));
}

// A name the operator typed that could not be read, on every verb that
// takes one.
//
// `store.accounts.get` and `store.domains.get` both answer null for a row
// that is not here AND for a string that could never name one, which is
// the right answer for a lookup: a wire listener holding attacker input
// wants a verdict rather than a throw. Deciding which of the two happened
// is this surface's job, because this is the layer an operator types at.
// Folding them together prints "no account a@@b" over a string that is
// not an address, at the exit code reserved for a server that tried and
// failed, so a script driving a bulk run cannot tell a typo from a
// mailbox somebody already removed.
//
// The verbs are read off the published table rather than listed here, so
// a verb added to either group is covered without a second edit. Every
// flag the verb reads is supplied, because a verb that asks for a reason
// first would otherwise answer about the reason and never reach the name.
//
// The target cannot match anything on the volume, which is what makes it
// safe to hand the destructive verbs their own flags: there is no row for
// `--destroy` to reach.
function anUnreadableNameIsAnArgumentFault(run) {
  var surface = require("../../bin/blamepost.js").VERB_SURFACE;
  var wrong = [];
  var examined = 0;

  Object.keys(UNREADABLE).forEach(function (group) {
    Object.keys(surface[group]).forEach(function (verb) {
      if (surface[group][verb].args < 1) return;
      examined += 1;
      var result = _spawnReplay(run, group, verb, surface[group][verb].flags,
        UNREADABLE[group]);
      var line = "blamepost " + group + " " + verb + " " + UNREADABLE[group] +
        " -> exit " + result.status + " " + result.both.trim().slice(0, 160);
      if (result.status !== 2 || !REFUSED_UNREADABLE.test(result.both)) wrong.push(line);
    });
  });

  count("there are verbs taking a name to check, so this is comparing something",
    examined >= 15, examined + " verb(s) examined");
  count("a name that cannot be read is refused as the argument fault it is, and the " +
    "refusal says it could not be read rather than that the record is absent",
    wrong.length === 0, wrong.join(" ; "));
}

// The same question the other way round, and the one a verb-only
// reconciliation cannot see.
//
// `everyUsageFlagIsRead` proves the usage block offers nothing the verb
// will refuse. It cannot see a flag pointing the other way: one the verb
// reads and its usage block never prints. `dkim generate --selector` was
// declared in the table, read at the call, described in the flag list the
// parser prints, and absent from the block an operator reads when they
// run the group with no verb, which is the page that says which verb
// takes what.
function everyFlagAVerbReadsIsInItsUsage(run) {
  var surface = require("../../bin/blamepost.js").VERB_SURFACE;
  var hidden = [];
  var examined = 0;

  VERB_GROUPS.forEach(function (group) {
    var printed = usageFlagsOf(run, group);
    Object.keys(surface[group]).forEach(function (verb) {
      examined += 1;
      var shown = printed[verb] || [];
      surface[group][verb].flags.forEach(function (name) {
        if (shown.indexOf(name) !== -1) return;
        hidden.push("`" + group + " " + verb + "` reads --" + name +
          " and its usage block prints " +
          (shown.length ? "--" + shown.join(" --") : "no flag against it"));
      });
    });
  });

  count("every verb in the table was held against its usage block",
    examined >= 50, examined + " verb(s) examined");
  count("every flag a verb reads is one its own usage block names, so the only way to " +
    "find it is not to read the source",
    hidden.length === 0, hidden.join(" ; "));
}

// The three commands the table above cannot speak for.
//
// `VERB_SURFACE` is keyed by verb, and `serve`, `init` and `doctor` have
// none, so the reconciliation next door reaches none of them and the
// dispatcher called them without their positionals at all. An argument
// on one of those lines was read by the parser and then dropped, which
// is the one outcome the gate exists to prevent: `blamepost doctor
// example.com` looks like a report about that domain and is a report
// about every hosted domain, with nothing said about the name it
// ignored. A clean answer about a zone nobody asked after is worse than
// a refusal, because the operator acts on it.
//
// Driven on `doctor` because it is the one an operator plausibly types
// that way, and asserted on all three because the hole is the dispatch
// rather than the verb.
function theVerblessCommandsRefuseAnArgument(run) {
  var doctored = run(["doctor", DOMAIN]);
  count("`doctor` refuses an argument rather than checking every domain and saying nothing " +
    "about the one it was handed",
    doctored.status === 2, "exit " + doctored.status + " " + doctored.both.slice(0, 200));
  count("and the refusal names the argument that would have been dropped",
    doctored.both.indexOf(DOMAIN) !== -1, doctored.both.slice(0, 200));
  count("and says what the command actually does, so the operator can tell whether they " +
    "wanted it at all",
    /checks every hosted domain/.test(doctored.both), doctored.both.slice(0, 200));

  var served = run(["serve", DOMAIN]);
  count("`serve` refuses one the same way",
    served.status === 2 && served.both.indexOf(DOMAIN) !== -1,
    "exit " + served.status + " " + served.both.slice(0, 200));

  var inited = run(["init", DOMAIN]);
  count("and so does `init`",
    inited.status === 2 && inited.both.indexOf(DOMAIN) !== -1,
    "exit " + inited.status + " " + inited.both.slice(0, 200));
}

function anUnknownVerbIsRefused(run) {
  var unknown = run(["account", "frobnicate"]);
  // A verb that does nothing and exits zero reads as success in a script,
  // which during an incident means an operator believes an account was
  // suspended when it was not.
  count("an unknown verb exits non-zero rather than looking like success",
    unknown.status !== 0, "exit " + unknown.status);
  count("and prints the usage so the operator can see the real verbs",
    /Usage: blamepost account/.test(unknown.both), unknown.both.slice(0, 90));

  // The argument parser refuses an undeclared command before the
  // dispatcher sees it, so the message is the parser's rather than the
  // one in the switch statement's default branch. That branch is still
  // reachable by declaring a command and forgetting to handle it, which
  // is why it stays.
  var unknownCommand = run(["frobnicate"]);
  count("an unknown command group is refused the same way",
    unknownCommand.status !== 0 && /unknown command/.test(unknownCommand.both),
    "exit " + unknownCommand.status + " " + unknownCommand.both.slice(0, 80));
  count("and the refusal points at where the real commands are listed",
    /blamepost help/.test(unknownCommand.both), unknownCommand.both.slice(0, 110));
}

// Resolve an address in a freshly opened store.
//
// The database is encrypted at rest and each process decrypts its own
// working copy, so a handle opened before the CLI child ran holds the
// snapshot from before the child's write. Reading through it reports the
// account still active and the assertion fails for a reason that has
// nothing to do with suspension. Open after the writer has exited, every
// time.
async function resolveFresh(cfg, address) {
  var handle = await store.open(cfg);
  try { return await handle.resolve(address); }
  finally { handle.close(); }
}

async function suspensionStopsSendingAndReceiving(run, cfg) {
  var noReason = run(["account", "suspend", ADDRESS]);
  count("suspending without a reason is refused",
    noReason.status !== 0 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 100));

  var before = await resolveFresh(cfg, ADDRESS);
  count("the account is a deliverable target while it is active",
    before.deliverable === true, JSON.stringify(before.reason || null));

  var suspended = run(["account", "suspend", ADDRESS,
    "--reason", "outbound spike 2026-08-22"]);
  count("suspending with a reason succeeds", suspended.status === 0,
    "exit " + suspended.status + " " + suspended.both.slice(0, 100));

  // The guide said a suspended account still receives. It does not, and
  // an operator who believed otherwise would suspend a mailbox expecting
  // its mail to keep arriving.
  var after = await resolveFresh(cfg, ADDRESS);
  count("a suspended account stops being a deliverable target",
    after.deliverable === false, JSON.stringify(after));
  count("and the refusal says it is the suspension",
    String(after.reason || "").indexOf("suspend") !== -1, String(after.reason));

  var shown = run(["account", "show", ADDRESS]);
  count("the status and the reason are both readable afterwards",
    /suspended/.test(shown.stdout) && /outbound spike/.test(shown.stdout),
    shown.stdout.slice(0, 140));

  var resumed = run(["account", "resume", ADDRESS]);
  count("resuming succeeds", resumed.status === 0,
    "exit " + resumed.status + " " + resumed.both.slice(0, 100));

  var back = await resolveFresh(cfg, ADDRESS);
  count("and the account is deliverable again",
    back.deliverable === true, JSON.stringify(back.reason || null));

  // Running it twice is what an operator does when they are unsure
  // whether the first one landed.
  var again = run(["account", "resume", ADDRESS]);
  count("resuming an account that is already active is not an error",
    again.status === 0 && /already active/.test(again.stdout),
    "exit " + again.status + " " + again.stdout.slice(0, 100));

  // The other state `resume` takes back, and the one the line above
  // makes easy to miss.
  //
  // `reinstate` returns a suspended account to service AND an archived
  // one, so the verb has two real inputs and the message read only the
  // first. Un-archiving a mailbox therefore printed "was already active,
  // so nothing changed" over a change that had just happened, which is
  // the sentence an operator checks BEFORE telling the account holder to
  // try again. It is the worst shape a wrong message can take: not an
  // error, not silence, but a confident denial that the thing they asked
  // for occurred.
  var archived = run(["account", "remove", ADDRESS, "--reason", "the owner is on leave"]);
  count("removing an account without --destroy archives it rather than erasing it",
    archived.status === 0 && /Archived/.test(archived.stdout),
    "exit " + archived.status + " " + archived.stdout.slice(0, 140));

  var unarchived = run(["account", "resume", ADDRESS]);
  count("resuming an archived account succeeds",
    unarchived.status === 0, "exit " + unarchived.status + " " +
    unarchived.both.slice(0, 140));
  count("and it is not reported as a run that changed nothing, because it changed the one " +
    "thing the operator asked it to",
    /nothing changed/.test(unarchived.stdout) === false,
    unarchived.stdout.slice(0, 200));
  count("and the line names the state it came back from, so the operator can see which " +
    "hold was lifted",
    /archived/.test(unarchived.stdout), unarchived.stdout.slice(0, 200));

  var deliverableAgain = await resolveFresh(cfg, ADDRESS);
  count("and the mailbox really is back in service, so the message and the volume agree",
    deliverableAgain.deliverable === true,
    JSON.stringify(deliverableAgain.reason || null));
}

// An archived account is one the command line can act on and could not
// show. `account resume` takes an archived mailbox back and says so in
// its own output, while `account list` left archived rows out with no way
// to ask for them, so an operator was told to resume something they had
// no way to find the address of. The browser console has asked the
// identity layer for those rows since it was written, and the layer has
// taken the request since it was written; only this surface never made
// it.
//
// The default stays as it is. The common question is which mailboxes are
// live, and an archived one is not, so leaving them out by default is a
// decision rather than the defect. The defect was that it was the only
// answer available.
function anArchivedAccountIsListedWhenAskedFor(run) {
  var archived = run(["account", "remove", ADDRESS, "--reason", "the owner is on leave"]);
  count("the run has an archived account to look for",
    archived.status === 0 && /Archived/.test(archived.stdout),
    "exit " + archived.status + " " + archived.stdout.slice(0, 140));

  var quiet = run(["account", "list"]);
  count("the default listing still leaves an archived account out, because the common " +
    "question is which mailboxes are live",
    quiet.status === 0 && quiet.stdout.indexOf(ADDRESS) === -1,
    "exit " + quiet.status + " " + quiet.stdout.slice(0, 200));

  var asked = run(["account", "list", "--include-archived"]);
  count("asking for archived rows is a flag the verb reads rather than a refusal",
    asked.status === 0, "exit " + asked.status + " " + asked.both.slice(0, 200));
  count("and it produces the archived account, so the address `account resume` takes back " +
    "is one an operator can find",
    asked.stdout.indexOf(ADDRESS) !== -1, asked.stdout.slice(0, 300));
  count("the row names the state it is in, so it is not mistaken for a live mailbox",
    /archived/.test(asked.stdout), asked.stdout.slice(0, 300));

  // The same ask through the machine readable form, because a flag that
  // only reaches the printed lines is one a script cannot use.
  var structured = run(["account", "list", "--include-archived", "--json"]);
  var parsed;
  try { parsed = JSON.parse(structured.stdout); }
  catch (_e) { parsed = null; }
  count("and the structured output carries the archived row too",
    Array.isArray(parsed) && parsed.some(function (row) {
      return row && row.address === ADDRESS && row.status === "archived";
    }), structured.stdout.slice(0, 300));

  // Put the fixture back the way this case found it, so a case added
  // after this one is not measuring an archived mailbox by accident.
  var back = run(["account", "resume", ADDRESS]);
  count("and the account goes back into service, leaving the run as this case found it",
    back.status === 0, "exit " + back.status + " " + back.both.slice(0, 140));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-surface");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var identity = null;
  try {
    process.env.BLAMEJS_TMPDIR = workDir;
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
    await identity.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    // The CLI opens the same database in a child process, and the handle
    // is one per process on each side. Closing here keeps the two from
    // holding it at once.
    identity.close();
    identity = null;

    // The sweep starts a process for every documented invocation, so its
    // children collect no coverage; the verbs' own files cover what runs.
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      coverage:        false,
    });

    var documented = documentedInvocations();
    everyDocumentedVerbExists(cli, documented);
    theGateCoversEveryVerbTheGroupOffers(cli);
    theUnreadFlagGateIsLive(cli);
    anUnreadableNameIsAnArgumentFault(cli);
    theVerblessCommandsRefuseAnArgument(cli);
    everyDocumentedFlagIsRead(cli, documented);
    everyUsageFlagIsRead(cli);
    everyFlagAVerbReadsIsInItsUsage(cli);
    everyDocumentedCommandFlagExists(cli, documented);
    anUnknownVerbIsRefused(cli);
    await suspensionStopsSendingAndReceiving(cli, cfg);
    anArchivedAccountIsListedWhenAskedFor(cli);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-surface", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
