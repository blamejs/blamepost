// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a DKIM key-lifecycle row says who did it and which key it was.
 *
 * A signing key is the asset THREAT-MODEL.md names, on the reasoning
 * that whoever holds one signs mail as the domain and the damage
 * outlives the rotation that ends it. SECURITY.md tells an operator to
 * verify the chain on a schedule and to read it during an incident, and
 * an incident involving a signing key is the one where the trail gets
 * consulted. Minting a selector, rotating one, retiring one and
 * withdrawing one are the four moments that decide which key could
 * possibly have signed a given message, so each of them has to leave a
 * row naming the operator and naming the selectors involved.
 *
 * Three claims are settled here and each needs the whole path:
 *
 *   - The row exists and names the operator. The command is the real
 *     binary in its own process, so the identity on the row is the one
 *     the shipped entry point established rather than one a test handed
 *     to a helper. A shell user is not an account, so the identity
 *     carries a mark that tells it apart from an account id at a glance
 *     and by a filter.
 *   - A rotation names BOTH selectors. The question an incident asks is
 *     which key was live when a particular message was signed, and a
 *     row carrying only the replacement answers half of it: the outgoing
 *     name is what ties the row to the signature already on the wire.
 *   - A refusal leaves a row too. The selector that differs from a live
 *     one only in case was a real defect once, and the attempt that gets
 *     refused is exactly the one an incident goes looking for.
 *
 * Nothing that identifies a key is allowed to be key material. The rows
 * are read back and scanned against the published key bytes for every
 * selector this run created, because a row carrying the public half of a
 * key pair hands a guesser a way to confirm a candidate private half
 * offline, and the audit chain is append-only, so a value written into
 * it once is written into it permanently.
 *
 * Every row is read back through `blamepost audit read`, which is the
 * path an operator drives. A column populated in the table and dropped
 * on the way out answers nobody.
 *
 * The last claim runs the other way round. Writing the row must never
 * decide whether the key operation happened, because a rotation that
 * fails for want of a row is worse than a rotation nobody recorded: the
 * keys are minted, the records are printed, and the operator is told it
 * did not work. That one is settled by making the sink fail for these
 * rows and only these rows, through the framework's own external-store
 * seam, and then driving a rotation, a retirement and a sweep across it.
 *
 * Run standalone: node test/layer-1-state/dkim-key-attribution.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var dkimMod   = require("../../lib/mail/dkim");

// The shared assertion rather than a copy of it, because a private
// wrapper that formats a failure differently is a failure line nobody
// can grep for.
var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The mark a command-line actor carries in the identity column. One
// column holds both kinds of principal, so a shell operator has to be
// distinguishable from an account id by a filter and not only by eye.
var COMMAND_LINE_MARK = "cli:";

// The actions a key-lifecycle operation is filed under. Written out
// here rather than imported, because an action name is the contract an
// operator types at the terminal and a test that imports the constant
// cannot tell a rename from a working filter.
var GENERATED = "blamepost.mail.dkim.keys_generated";
var ROTATED   = "blamepost.mail.dkim.keys_rotated";
var RETIRED   = "blamepost.mail.dkim.keys_retired";
var SWEPT     = "blamepost.mail.dkim.selectors_swept";
var RESEALED  = "blamepost.mail.dkim.keys_resealed";

// A replacement selector named so it cannot collide with the one this
// server mints by default, which carries the year and month of the run.
var REPLACEMENT = "bp999901";

// The same name in the case an operator's shell history hands back. It
// folds to the live one, so it names a selector that already exists.
var REPLACEMENT_SHOUTED = "BP999901";

// A selector no run of this file ever creates.
var ABSENT_SELECTOR = "bp000000";

// The domain the leftover-key refusal runs against, and the selector it
// asks for. A domain of its own, because the refusal has to meet a
// volume that already holds the file name the mint would take and a
// store that holds no selector row at all.
var LEFTOVER_DOMAIN   = "leftover.example.com";
var LEFTOVER_SELECTOR = "bpleft";

// Markers that would mean private key material had reached a row.
var KEY_MATERIAL_MARKERS = ["PRIVATE KEY", "BEGIN ", "-----"];

// Characters that change what a line looks like without being characters
// a reader can see. The override reverses the drawing order of
// everything after it, so a selector, a domain and a verb arrive in an
// order nobody wrote; the zero-width space hides the difference between
// two names that a row exists to tell apart.
var DISPLAY_OVERRIDES = [
  { name: "a right-to-left override", point: "‮" },
  { name: "a zero-width space",       point: "​" },
];

// A selector name carrying both. It is refused for not being a DNS
// label, and the refusal quotes it, which is how it reaches a row.
var HOSTILE_SELECTOR = "bp" + DISPLAY_OVERRIDES[0].point + "evil" +
  DISPLAY_OVERRIDES[1].point + "x";

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// The operating-system account this run executes as, read defensively
// because a container with no passwd entry for its user id makes the
// lookup throw and a run on such a host still checks everything else.
function osUserName() {
  try { return String(nodeOs.userInfo().username || ""); }
  catch (_e) { return ""; }
}

// Rows for one action, read back the way an operator reads them.
function rowsFor(cli, action, outcome) {
  var args = ["audit", "read", "--action", action, "--limit", "20", "--json"];
  if (outcome) args = args.concat(["--outcome", outcome]);
  var read = cli(args);
  var rows = parseJson(read.stdout);
  return {
    ok:   read.status === 0,
    rows: Array.isArray(rows) ? rows : [],
    both: read.both,
  };
}

// One row as a reader sees all of it: the columns and the metadata blob
// together. A selector recorded in either place answers the question;
// one recorded in neither does not.
function wholeRow(row) {
  return JSON.stringify(row);
}

// The claim every row in this file has to satisfy, kept in one place so
// a row added later is measured the same way.
function theRowNamesTheOperator(label, row, operator) {
  count(label + " records who performed it",
    typeof row.actorUserId === "string" && row.actorUserId.length > 0,
    label + " actorUserId=" + JSON.stringify(row.actorUserId));
  count(label + " is marked as a command-line operator rather than an account",
    typeof row.actorUserId === "string" && row.actorUserId.indexOf(COMMAND_LINE_MARK) === 0,
    String(row.actorUserId));
  if (operator.length > 0) {
    count(label + " names the operating-system account the command ran as",
      typeof row.actorUserId === "string" && row.actorUserId.indexOf(operator) !== -1,
      String(row.actorUserId) + " against " + operator);
  }
}

function newest(cli, action, outcome, label) {
  var found = rowsFor(cli, action, outcome);
  count("the trail can be read for " + label, found.ok, found.both.slice(0, 240));
  count(label + " left a row", found.rows.length >= 1, found.both.slice(0, 400));
  return found.rows.length > 0 ? found.rows[0] : null;
}

// ---- the four moments --------------------------------------------------------

// Hosting a domain mints its first pair, so the successful mint arrives
// through the verb an operator actually runs to get one.
function theFirstMintIsAttributed(cli, operator) {
  var hosted = cli(["domain", "add", DOMAIN]);
  count("the operator hosts a domain, which mints its first pair", hosted.status === 0,
    "exit " + hosted.status + " " + hosted.both.slice(0, 240));

  var listed = cli(["dkim", "list", DOMAIN, "--json"]);
  var selectors = parseJson(listed.stdout) || [];
  count("the domain holds a pair of selectors afterwards", selectors.length === 2,
    listed.both.slice(0, 300));

  var row = newest(cli, GENERATED, null, "minting the first pair");
  if (row === null) return selectors;
  theRowNamesTheOperator("the mint", row, operator);
  count("the mint records that it succeeded", row.outcome === "success", String(row.outcome));

  var text = wholeRow(row);
  selectors.forEach(function (sel) {
    count("the mint names the " + sel.algorithm + " selector it created",
      text.indexOf(sel.selector) !== -1, sel.selector + " in " + text.slice(0, 400));
  });
  return selectors;
}

// A domain that already holds keys refuses a second mint, and the
// refusal is the row an operator looks for when a second run of the
// setup script did nothing.
function theRefusedMintIsAttributed(cli, operator) {
  var again = cli(["dkim", "generate", "--domain", DOMAIN]);
  count("a second mint for a domain that already has keys is refused", again.status !== 0,
    "exit " + again.status + " " + again.both.slice(0, 240));

  var row = newest(cli, GENERATED, "denied", "the refused mint");
  if (row === null) return;
  theRowNamesTheOperator("the refused mint", row, operator);
  count("the refused mint records why it was refused",
    typeof row.reason === "string" && row.reason.length > 0,
    "reason=" + JSON.stringify(row.reason));
}

// A mint that changed nothing, refused for a reason that arises below the
// point where the module starts writing.
//
// The two outcomes a key-lifecycle row can carry when an operation does
// not complete are not interchangeable, and the module's own comment says
// which is which: a refusal that changed nothing leaves the domain
// exactly as it was, and a run that stopped part way can leave a sealed
// private key on the volume that nothing will sign with and no row points
// at. An operator filtering the trail for refusals reads the first;
// somebody looking for a volume to go and inspect reads the second. A
// refused mint filed under the second sends one of them to the wrong
// place and hides it from the other.
//
// The refusal driven here is the key file already being on the volume,
// which is the one refusal a mint reaches after generating material and
// before writing any of it. A file under the name the mint would take is
// planted first: a key file and the selector row naming it are two writes
// and nothing spans them, so a run that stopped between them leaves
// exactly this state, and a later mint asked for that selector derives
// the same name.
function theRefusedMintOverALeftoverKeyIsADenial(cli, operator, keyDir) {
  var hosted = cli(["domain", "add", LEFTOVER_DOMAIN]);
  count("the operator hosts a second domain to mint for", hosted.status === 0,
    "exit " + hosted.status + " " + hosted.both.slice(0, 240));

  // Hosting mints the domain's first pair, so the selector this vector
  // asks for has to be one that pair does not hold, and the name has to
  // be claimed on the volume before the mint runs.
  var keyRef = LEFTOVER_DOMAIN + "." + LEFTOVER_SELECTOR + ".ed25519.sealed";
  nodeFs.mkdirSync(keyDir, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(keyDir, keyRef),
    "a stand-in for the sealed private key a stopped run left behind", { mode: 0o600 });

  var refused = cli(["dkim", "rotate", "--domain", LEFTOVER_DOMAIN,
    "--selector", LEFTOVER_SELECTOR]);
  count("a mint over a key file already on the volume is refused rather than writing over " +
    "the only copy of whatever is under that name",
    refused.status !== 0 && /already in the keys folder/.test(refused.both),
    "exit " + refused.status + " " + refused.both.slice(0, 300));

  var listed = parseJson(cli(["dkim", "list", LEFTOVER_DOMAIN, "--json"]).stdout) || [];
  count("and nothing was written, so the refusal really did leave the domain as it was",
    listed.length === 2 && listed.every(function (sel) {
      return sel.selector !== LEFTOVER_SELECTOR;
    }),
    JSON.stringify(listed.map(function (sel) { return sel.selector + ":" + sel.state; })));

  var row = newest(cli, ROTATED, "denied", "the mint refused over a leftover key");
  if (row === null) return;
  theRowNamesTheOperator("the mint refused over a leftover key", row, operator);
  count("the refusal is filed as a denial rather than as a failure, because an operator " +
    "filtering the trail for refused mints is the one who has to find it",
    row.outcome === "denied", String(row.outcome));
  count("and it names the selector that was asked for",
    wholeRow(row).indexOf(LEFTOVER_SELECTOR) !== -1, wholeRow(row).slice(0, 500));

  // The other half of the same claim. A run filed as a denial has to be a
  // run that really changed nothing, so the trail carries no row for this
  // attempt under the outcome that says something was left behind.
  var faulted = rowsFor(cli, ROTATED, "failure").rows.filter(function (r) {
    return wholeRow(r).indexOf(LEFTOVER_SELECTOR) !== -1;
  });
  count("and no row files the same attempt as a run that stopped part way, which is what " +
    "would send somebody to inspect a volume nothing was written to",
    faulted.length === 0, JSON.stringify(faulted).slice(0, 400));
}

// The claim this file exists for. A rotation is the moment one key stops
// being the only answer and another starts, so the row has to carry both
// names or an incident cannot place a signature in time.
function theRotationNamesBothSelectors(cli, operator, before) {
  var outgoing = before.map(function (sel) { return sel.selector; });
  var rotated = cli(["dkim", "rotate", "--domain", DOMAIN, "--selector", REPLACEMENT]);
  count("the operator mints a replacement pair", rotated.status === 0,
    "exit " + rotated.status + " " + rotated.both.slice(0, 240));

  var row = newest(cli, ROTATED, null, "the rotation");
  if (row === null) return;
  theRowNamesTheOperator("the rotation", row, operator);
  count("the rotation records that it succeeded", row.outcome === "success", String(row.outcome));

  var text = wholeRow(row);
  count("the rotation names the replacement selector",
    text.indexOf(REPLACEMENT) !== -1, text.slice(0, 500));
  outgoing.forEach(function (name) {
    count("the rotation names the outgoing selector " + name +
      ", which is what ties the row to a signature already on the wire",
      text.indexOf(name) !== -1, text.slice(0, 500));
  });
}

// The selector that differs from a live one only in case. It folds to
// the live name, so it is refused, and the attempt is what an incident
// reads as somebody trying to mint over a key that is signing.
function theCaseFoldedRefusalIsAttributed(cli, operator) {
  var refused = cli(["dkim", "rotate", "--domain", DOMAIN,
    "--selector", REPLACEMENT_SHOUTED]);
  count("a selector differing from a live one only in case is refused",
    refused.status !== 0, "exit " + refused.status + " " + refused.both.slice(0, 240));

  var row = newest(cli, ROTATED, "denied", "the refused rotation");
  if (row === null) return;
  theRowNamesTheOperator("the refused rotation", row, operator);

  var text = wholeRow(row);
  count("the refused rotation names the selector that was asked for",
    text.toLowerCase().indexOf(REPLACEMENT) !== -1, text.slice(0, 500));

  var listed = cli(["dkim", "list", DOMAIN, "--json"]);
  var selectors = parseJson(listed.stdout) || [];
  count("and nothing was minted by the attempt", selectors.length === 4,
    listed.both.slice(0, 300));
}

// Retiring is the moment private key material is destroyed, which is
// the one an incident asking what is still recoverable reads first.
function theRetirementIsAttributed(cli, operator, outgoing) {
  var eddsa = outgoing.filter(function (sel) { return sel.algorithm !== "rsa-sha256"; })[0];
  count("the run knows which selector to retire", eddsa !== undefined,
    JSON.stringify(outgoing.map(function (s) { return s.selector + ":" + s.algorithm; })));
  if (eddsa === undefined) return;

  var out = cli(["dkim", "retire", "--domain", DOMAIN, "--selector", eddsa.selector]);
  count("the operator retires the outgoing pair", out.status === 0,
    "exit " + out.status + " " + out.both.slice(0, 240));

  var row = newest(cli, RETIRED, null, "the retirement");
  if (row === null) return;
  theRowNamesTheOperator("the retirement", row, operator);
  count("the retirement records that it succeeded", row.outcome === "success",
    String(row.outcome));

  var text = wholeRow(row);
  outgoing.forEach(function (sel) {
    count("the retirement names the " + sel.algorithm + " selector that stopped signing",
      text.indexOf(sel.selector) !== -1, sel.selector + " in " + text.slice(0, 500));
  });
}

function theRefusedRetirementIsAttributed(cli, operator) {
  var refused = cli(["dkim", "retire", "--domain", DOMAIN, "--selector", ABSENT_SELECTOR]);
  count("retiring a selector this domain does not hold is refused", refused.status !== 0,
    "exit " + refused.status + " " + refused.both.slice(0, 240));

  var row = newest(cli, RETIRED, "denied", "the refused retirement");
  if (row === null) return;
  theRowNamesTheOperator("the refused retirement", row, operator);
  count("the refused retirement names the selector that was asked for",
    wholeRow(row).indexOf(ABSENT_SELECTOR) !== -1, wholeRow(row).slice(0, 500));
}

// Withdrawing a record before its overlap elapses is the answer to one
// situation only, a key believed exposed, and it turns mail still being
// retried into DKIM failures. An operator reading the trail afterwards
// has to be able to see that it was the early answer and who chose it.
function theEarlyWithdrawalIsAttributed(cli, operator, retiredNames) {
  var swept = cli(["dkim", "sweep", "--domain", DOMAIN, "--immediate"]);
  count("the operator withdraws the retired records early", swept.status === 0,
    "exit " + swept.status + " " + swept.both.slice(0, 240));

  var row = newest(cli, SWEPT, null, "the sweep");
  if (row === null) return;
  theRowNamesTheOperator("the sweep", row, operator);

  var text = wholeRow(row);
  retiredNames.forEach(function (name) {
    count("the sweep names the withdrawn selector " + name,
      text.indexOf(name) !== -1, text.slice(0, 500));
  });
  count("the sweep records that the records were pulled before the overlap elapsed, " +
    "which is the answer only an exposed key calls for",
    /immediate|before the overlap/i.test(text), text.slice(0, 500));
}

// ---- what may never reach a row ---------------------------------------------

// A row carrying the public half of a signing pair hands a guesser a way
// to confirm a candidate private half without ever touching this server,
// and the chain is append-only, so the value is there for good. The
// selector and the algorithm are what a receiver already reads off the
// message, so they identify a key without adding anything.
function noRowCarriesKeyMaterial(cli, published) {
  var actions = [GENERATED, ROTATED, RETIRED, SWEPT];
  var text = "";
  for (var i = 0; i < actions.length; i += 1) {
    text += JSON.stringify(rowsFor(cli, actions[i]).rows);
  }

  KEY_MATERIAL_MARKERS.forEach(function (marker) {
    count("no key-lifecycle row carries " + JSON.stringify(marker),
      text.indexOf(marker) === -1, marker);
  });

  count("the run captured the published key bytes to check against",
    published.length >= 2, String(published.length));
  published.forEach(function (entry) {
    count("no key-lifecycle row carries the published key bytes of " + entry.selector +
      ", which would let a guessed private half be confirmed offline",
      entry.publicKey.length > 0 && text.indexOf(entry.publicKey) === -1,
      entry.selector + " " + entry.publicKey.slice(0, 24));
  });
}

// ---- a sink that cannot write --------------------------------------------------

// The framework's external-store seam, in the mode where a failure
// reaches the caller. It is the shipped way to put a sink in front of
// the chain, so the fault is injected through surface this server
// already composes rather than by reaching into the framework.
//
// It fails for the key-lifecycle rows and lets everything else through.
// That is a narrowing rather than something forced: a sink refusing
// every event no longer breaks anything else in a run, because the
// writes around these verbs drop what they cannot file and report their
// own outcome, which is what `audit-sink-refusal.test.js` measures with
// a sink that refuses the lot. Aiming the fault at these rows leaves
// this file's claim about one thing, which is what a failed row does to
// the key operation it was describing, with nothing else failing at the
// same moment to account for.
function aSinkThatRefusesKeyRows() {
  var seen = 0;
  b.audit.useStore({
    replaceChain: true,
    record:       function (row) {
      if (row && typeof row.action === "string" &&
          row.action.indexOf("blamepost.mail.dkim.") === 0) {
        seen += 1;
        throw new Error("the audit sink is unavailable");
      }
      return null;
    },
  });
  return function refused() { return seen; };
}

async function aFailedRowDoesNotUndoTheKeyOperation(root) {
  var dataDir  = nodePath.join(root, "sink-data");
  nodeFs.mkdirSync(dataDir, { recursive: true });

  var identity = null;
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

    var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
    var first = await dkim.generate({ domain: DOMAIN, selector: "bpsink" });
    count("the run has a pair to rotate away from", first.publish.length === 2,
      String(first.publish.length));

    var attempts = aSinkThatRefusesKeyRows();

    var rotated = await dkim.rotate({ domain: DOMAIN, selector: REPLACEMENT });
    count("a rotation completes while the row describing it cannot be written",
      rotated.minted.length === 2,
      JSON.stringify(rotated.minted.map(function (m) { return m.selector; })));
    count("and the replacement is signing rather than half minted",
      dkim.list(DOMAIN).filter(function (s) { return s.state === "active"; }).length === 4,
      JSON.stringify(dkim.list(DOMAIN).map(function (s) {
        return s.selector + ":" + s.state;
      })));

    var out = await dkim.retire({ domain: DOMAIN, selector: "bpsink" });
    count("a retirement completes on the same terms", out.retired.length === 2,
      JSON.stringify(out.retired.map(function (r) { return r.selector; })));
    count("and the sealed private keys are gone, which is what it was for",
      nodeFs.readdirSync(dkim.describe().keyDir)
        .filter(function (f) { return f.indexOf(DOMAIN + ".bpsink.") === 0; }).length === 0,
      nodeFs.readdirSync(dkim.describe().keyDir).join(","));

    var swept = await dkim.sweep({ domain: DOMAIN, immediate: true });
    count("and a sweep withdraws the records it was going to report",
      swept.withdrawn.length === 2,
      JSON.stringify(swept.withdrawn.map(function (s) { return s.selector; })));

    // A refusal has to behave the same way. It reports the refusal the
    // operator caused rather than the one the sink caused, because a
    // rewritten error sends them to fix the wrong thing.
    var refusal = null;
    try { await dkim.retire({ domain: DOMAIN, selector: ABSENT_SELECTOR }); }
    catch (e) { refusal = e; }
    count("a refusal still refuses with its own reason rather than the sink's",
      refusal !== null && /Nothing has been retired/.test(String(refusal && refusal.message)) &&
      String(refusal.message).indexOf(ABSENT_SELECTOR) !== -1,
      refusal ? String(refusal.message).slice(0, 200) : "accepted");

    // Four operations ran with the sink in place and each one writes a
    // single key-lifecycle row, so the count is exact. A looser bound
    // would pass on a run where the sink was never reached at all, and
    // then everything above it would be proving nothing.
    count("and all four of those rows reached the sink and failed there, so the checks " +
      "above ran against a sink that really could not write",
      attempts() === 4, String(attempts()));
  } finally {
    // Unregistered before anything else runs, because the seam is
    // process-wide and a later file sharing this process would write
    // through it.
    b.audit.useStore(null);
    if (identity !== null) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
    }
  }
}

// ---- a name that would rewrite the terminal it is read in ---------------------

// A refused verb quotes the selector name it was given, and that name is
// whatever somebody typed. It reaches two places a person reads: the
// `requested` entry in the row's metadata, and the `reason` the refusal
// was worded with. Both are read back in a terminal by `blamepost audit
// read`, and the chain is append-only, so a value written into it once
// cannot be taken back out.
//
// Control characters were already cut. A right-to-left override is not a
// control character and does every bit as much: it reverses the order
// the rest of the line is drawn in, so an operator reading the trail for
// a refused mint is shown a selector, a domain and a verb in an order
// nobody wrote. A zero-width joiner hides the difference between two
// names entirely, which is the difference this row exists to record.
//
// Both go through the one screen this server puts between somebody
// else's text and a reader, rather than a fourth hand-written table of
// what a terminal acts on.
async function aNameThatWouldRewriteTheTerminalIsScreenedOutOfTheRow(root) {
  var dataDir = nodePath.join(root, "screen-data");
  nodeFs.mkdirSync(dataDir, { recursive: true });

  var identity = null;
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

    var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
    var refused = null;
    try { await dkim.generate({ domain: DOMAIN, selector: HOSTILE_SELECTOR }); }
    catch (e) { refused = e; }
    count("a selector carrying a display override is refused, because it is not a DNS label",
      refused !== null, refused === null ? "minted under it" : String(refused.message).slice(0, 160));

    await b.audit.flush();
    var domainRow = identity.domains.get(DOMAIN);
    var rows = await b.audit.query({ action: GENERATED, order: "desc", limit: 20 });
    rows = (Array.isArray(rows) ? rows : []).filter(function (r) {
      return domainRow !== null && String(r.resourceId) === String(domainRow.id);
    });
    count("the refused mint still left a row, which is what carries the name",
      rows.length >= 1, String(rows.length));

    var whole = rows.length > 0 ? wholeRow(rows[0]) : "";
    DISPLAY_OVERRIDES.forEach(function (entry) {
      count("no key-lifecycle row carries " + entry.name +
        ", which would redraw the line an operator reads the trail in",
        whole.length > 0 && whole.indexOf(entry.point) === -1,
        entry.name + " at offset " + whole.indexOf(entry.point));
    });
    count("and the row still says which selector was asked for, screened rather than dropped",
      whole.indexOf("bp") !== -1, whole.slice(0, 240));
  } finally {
    if (identity !== null) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
    }
  }
}

// Sealing the keys already on a volume to the selectors they belong to
// rewrites key material at rest, so it leaves a row like the four verbs
// that change which keys exist. This volume's keys were minted by this
// build and are already sealed that way, so the run rewrites nothing,
// which is the run an operator makes when they are not sure whether it
// has happened. The row still has to name who ran it and what it looked
// at: a migration that reports nothing and records nothing is
// indistinguishable from one that never ran.
function theResealIsAttributed(cli, operator) {
  var run = cli(["dkim", "reseal", "--domain", DOMAIN]);
  count("sealing the keys already on the volume succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 240));
  count("and says the keys are already sealed to their selectors rather than answering with " +
    "nothing", run.both.indexOf("already sealed") !== -1, run.both.slice(0, 240));

  var row = newest(cli, RESEALED, null, "sealing the keys to their selectors");
  if (row === null) return;
  theRowNamesTheOperator("the reseal", row, operator);
  count("the reseal records that it succeeded", row.outcome === "success", String(row.outcome));

  var text = wholeRow(row);
  count("and the row names the domain it ran over",
    text.indexOf(DOMAIN) !== -1, text.slice(0, 400));
  count("and names each selector it examined, so a later run can be held against this one",
    parseJson(cli(["dkim", "list", DOMAIN, "--json"]).stdout || "[]")
      .every(function (sel) { return text.indexOf(sel.selector) !== -1; }),
    text.slice(0, 400));
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-key-attribution");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
    var operator = osUserName();
    if (operator.length === 0) {
      helpers.skip("this host has no readable operating-system user name, so a row's actor " +
        "cannot be checked against the account that ran the command");
    }

    var first = theFirstMintIsAttributed(cli, operator);
    theRefusedMintIsAttributed(cli, operator);
    // The keys folder is fixed at `<dataDir>/keys`, which is where the
    // module resolves every keyRef to, so the leftover is planted by the
    // same path a stopped run would have written it under.
    theRefusedMintOverALeftoverKeyIsADenial(cli, operator, nodePath.join(dataDir, "keys"));
    theRotationNamesBothSelectors(cli, operator, first);
    theCaseFoldedRefusalIsAttributed(cli, operator);
    // Before the retirement below, so the selectors it names are still
    // on the volume with their keys beside them.
    theResealIsAttributed(cli, operator);

    // Captured while every selector this run created is still on the
    // volume, because a retired one's row is gone by the end and its key
    // bytes are exactly what the rows must never carry.
    var everything = parseJson(cli(["dkim", "list", DOMAIN, "--json"]).stdout) || [];
    var published = everything.filter(function (sel) {
      return typeof sel.publicKey === "string" && sel.publicKey.length > 0;
    });

    theRetirementIsAttributed(cli, operator, first);
    theRefusedRetirementIsAttributed(cli, operator);
    theEarlyWithdrawalIsAttributed(cli, operator,
      first.map(function (sel) { return sel.selector; }));
    noRowCarriesKeyMaterial(cli, published);

    // The other half runs in this process, against a volume of its own,
    // because the fault it needs is one no command-line flag can ask
    // for. The spawned commands above have all exited by now, so one
    // process holds one data directory throughout.
    process.env.BLAMEJS_TMPDIR = workDir;
    await aFailedRowDoesNotUndoTheKeyOperation(root);
    await aNameThatWouldRewriteTheTerminalIsScreenedOutOfTheRow(root);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "dkim-key-attribution", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
