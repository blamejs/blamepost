// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * primitive-freeze-coverage: every primitive this project documents is a
 * primitive the api snapshot has frozen, and the gates that govern them
 * all read the same list.
 *
 * THE DEFECT THIS PINS. `api-snapshot.json` records each primitive's
 * introduction version, and `scripts/check-api-snapshot.js` treats that
 * record as immutable. The immutability only ever applied to tokens the
 * baseline already held. A primitive documented after the last refresh
 * satisfied the version check trivially, because the `@since` a freshly
 * written block carries IS the current package version, so it passed every
 * run while nothing recorded it. Ten of them had accumulated that way, and
 * a breaking change to any one would have gone through unremarked.
 *
 * WHY THE EXPORT WALK CANNOT ANSWER THIS. The snapshot's `surface` tree is
 * what `require("../lib/index.js")` yields, walked as exports, and most of
 * those ten are members of the handle `create()` returns rather than
 * module exports. A static gate must not instantiate the handle to find
 * out what ships: doing so needs a config, a vault, a data directory and a
 * clock, and a gate that boots the application fails for reasons that have
 * nothing to do with the surface. So the documented set is read from
 * source, and the case below that names a handle-only primitive is the one
 * that would fail if anyone re-derived the list from exports again.
 *
 * WHY THE COUNTS ARE COMPARED ACROSS GATES. Three gates govern these
 * blocks and each governs exactly the set it found. Two lists built by two
 * walks agree only by luck, and the disagreement is silent in the
 * direction that matters: a primitive a gate cannot see is one it reports
 * nothing about, and its verdict still reads clean. They now share one
 * reader, and the cheapest proof that they still do is that they publish
 * the same number over the same tree.
 *
 * The pure vectors on the checker are here so the tree invariant above
 * cannot pass vacuously. A checker that returned an empty list for every
 * input would satisfy every "the tree is clean" case in this file.
 *
 * No sockets, no database, no network. It reads the committed snapshot,
 * the source tree, and spawns the gate scripts.
 *
 * Run standalone:
 * node test/layer-0-primitives/primitive-freeze-coverage.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT = helpers.REPO_ROOT;
var SNAPSHOT  = nodePath.join(REPO_ROOT, "api-snapshot.json");

var RUN_CEILING_MS = 60000;

var sourcePrimitives = require("../../scripts/source-primitives.js");
var snap             = require("../../scripts/refresh-api-snapshot.js");

// The root name every documented token is written under. It is the package's
// own name in the documentation, not a path, so it is stripped before the
// surface tree is walked. Taken from the module that does the stripping,
// rather than spelled again here: a second copy of the root is a second
// thing to keep in step, and the one that drifts is the one nobody watches.
var TOKEN_ROOT = snap.TOKEN_ROOT;

function _snapshot() {
  return JSON.parse(nodeFs.readFileSync(SNAPSHOT, "utf8"));
}

// Resolve a dotted token against the captured `surface` tree, which is the
// export walk. Returns false for anything the walk never reached, which is
// what a handle member looks like from here.
//
// This used to be a private copy in this file while the checker that needed
// exactly this question had none, so a tombstone could be written over a
// callable the walk still reached and nothing compared the two. The
// resolver now lives beside the checker and this file drives the same one,
// which is what keeps the vectors below about the rule rather than about a
// second implementation of it.
var _inSurface = snap.resolvesInSurface;

// The published `EXAMINED <n> <unit>` lines of a gate's stdout, as
// { unit: n }. The same reading scripts/release.js performs, so a gate that
// stopped answering fails here rather than in the middle of a cut.
function _examined(stdout) {
  var out = {};
  String(stdout).split(/\r?\n/).forEach(function (line) {
    var m = /^EXAMINED\s+(\d+)\s+([a-z0-9-]+)$/.exec(line.trim());
    if (m) out[m[2]] = Number(m[1]);
  });
  return out;
}

async function _runGate(rel) {
  return spawnRun.runNodeScript([nodePath.join(REPO_ROOT, rel)], {
    cwd:       REPO_ROOT,
    ceilingMs: RUN_CEILING_MS,
  });
}

// ---------------------------------------------------------------------------
// The tree: documented and frozen are the same set
// ---------------------------------------------------------------------------

function documentedTokensAreAllFrozen() {
  var documented = sourcePrimitives.collectPrimitives();
  var frozen = _snapshot().sinceByPrimitive || {};

  // Canaries. A parse that found nothing, or a baseline that recorded
  // nothing, would agree with every claim below about the two agreeing.
  count("the source parse still finds primitive blocks", documented.length > 0,
    documented.length + " block(s)");
  count("the committed snapshot still records introduction versions",
    Object.keys(frozen).length > 0, Object.keys(frozen).length + " entry(ies)");

  var untracked = documented
    .filter(function (p) { return !Object.prototype.hasOwnProperty.call(frozen, p.token); })
    .map(function (p) { return p.token + " (" + p.file + ":" + p.line + ")"; });
  count("every documented primitive's introduction version is recorded in the snapshot, " +
    "so the immutability freeze actually covers it",
  untracked.length === 0,
  untracked.join(", "));

  var declared = {};
  documented.forEach(function (p) { declared[p.token] = p.since; });
  var ghosts = Object.keys(frozen).filter(function (tok) { return !(tok in declared); });
  count("every recorded token is still documented in source, so the snapshot carries no " +
    "entry for a primitive that no longer exists",
  ghosts.length === 0, ghosts.join(", "));

  var mismatched = Object.keys(frozen).filter(function (tok) {
    return tok in declared && declared[tok] !== frozen[tok];
  });
  count("no recorded introduction version disagrees with the source that declares it",
    mismatched.length === 0, mismatched.join(", "));
}

// The specific blind spot, named. Most of what went untracked is reachable
// only through the handle create() returns, so a list rebuilt from module
// exports would drop it again. Asserting that at least one frozen primitive
// is invisible to the export walk is what makes that regression fail here
// instead of silently shrinking the governed set.
function handleOnlyPrimitivesAreFrozenToo() {
  var s = _snapshot();
  var frozen = s.sinceByPrimitive || {};
  var handleOnly = Object.keys(frozen).filter(function (tok) {
    return tok.indexOf(TOKEN_ROOT) === 0 && !_inSurface(s.surface, tok);
  });

  count("the freeze reaches primitives the export walk cannot see, so the documented " +
    "surface rather than the module exports is what the snapshot governs",
  handleOnly.length > 0,
  "frozen tokens absent from the surface tree: " + handleOnly.length);

  // The surface walk is not redundant, and deleting it would lose the
  // question it answers. Both readings have to still be finding things.
  var inSurface = Object.keys(frozen).filter(function (tok) {
    return _inSurface(s.surface, tok);
  });
  count("the export walk still resolves primitives of its own, so the surface tree is " +
    "answering rather than empty",
  inSurface.length > 0, inSurface.length + " token(s) resolve through the export walk");
}

// ---------------------------------------------------------------------------
// The checker itself, so the tree cases cannot pass vacuously
// ---------------------------------------------------------------------------

function theUntrackedCheckerRefusesAndPermits() {
  var complete = { "a.one": "0.1.0", "a.two": "0.1.0" };

  count("a documented token the baseline never recorded is a violation naming it",
    (function () {
      var v = snap.checkSinceUntracked({ "a.one": "0.1.0" }, complete);
      return v.length === 1 && v[0].indexOf("a.two") === 0;
    })(),
    JSON.stringify(snap.checkSinceUntracked({ "a.one": "0.1.0" }, complete)));

  count("every documented token being recorded is clean",
    snap.checkSinceUntracked(complete, complete).length === 0);

  count("several untracked tokens are all reported rather than only the first",
    snap.checkSinceUntracked({}, complete).length === 2,
    JSON.stringify(snap.checkSinceUntracked({}, complete)));

  // The direction that was already covered must not start reporting here
  // too, or the two gates would disagree about which one owns a deletion.
  count("a recorded token missing from source is not this checker's finding",
    snap.checkSinceUntracked(complete, { "a.one": "0.1.0" }).length === 0);

  // A tree with no baseline at all is the bootstrap, and the gate refuses
  // that earlier with its own message. Reporting every primitive here would
  // bury it.
  count("an absent baseline is left to the gate's own missing-baseline refusal",
    snap.checkSinceUntracked(null, complete).length === 0);
}

// ---------------------------------------------------------------------------
// The excuses, and the primitive each one answers for
// ---------------------------------------------------------------------------

// A dropped `@since` vacates a freeze, so the gate refuses one unless
// something answers for it. Every such answer NAMES the token it answers
// for, and it has to: an introduction version is shared by every primitive
// that shipped in the same release, so a declaration carrying a version
// alone is satisfied by any of them and therefore answers for all of them
// and for every future drop at that version. That is the whole tree going
// quiet on the strength of one line, and the line reads like an ordinary
// correction while it does it.

var DROPPED   = "blamepost.store.deletedOutright";
var ALSO_GONE = "blamepost.store.alsoDeleted";
var CORRECTED = "blamepost.store.pathWasWrong";
var LIVE      = "blamepost.store.stillShipping";

// A tombstone record in the shape the source reader produces one, so the
// checker vectors below drive the same record shape the gate does.
function _tomb(value, line) {
  var m = /^(\S+)\s+(\d+\.\d+\.\d+)$/.exec(value);
  return {
    token:   m ? m[1] : null,
    version: m ? m[2] : null,
    value:   value,
    file:    "lib/store/index.js",
    line:    line || 12,
  };
}

// The live defect. `@originated` was matched by its VALUE against the
// version of each dropped token, so one declaration excused every primitive
// introduced in that release: the one it was written for, the ones nobody
// had looked at, and every drop at that version thereafter.
function anOriginatedDeclarationExcusesOnlyTheTokenItNames() {
  var oldMap = {};
  oldMap[CORRECTED] = "0.1.0";
  oldMap[DROPPED]   = "0.1.0";
  var newMap = {};
  newMap[LIVE] = "0.1.0";

  var named = {};
  named[LIVE] = CORRECTED + " 0.1.0";
  var v = snap.checkSinceDropped(oldMap, newMap, named, []);

  count("the corrected path it names is excused",
    !v.some(function (m) { return m.indexOf(CORRECTED) === 0; }), JSON.stringify(v));
  count("a different primitive at the same introduction version is still reported",
    v.length === 1 && v[0].indexOf(DROPPED) === 0, JSON.stringify(v));

  // The shape the tag used to carry. A version on its own names nothing, so
  // it answers for nothing rather than for everything.
  var bare = {};
  bare[LIVE] = "0.1.0";
  count("a declaration carrying a version alone excuses no removal at all",
    snap.checkSinceDropped(oldMap, newMap, bare, []).length === 2,
    JSON.stringify(snap.checkSinceDropped(oldMap, newMap, bare, [])));

  // The version still has to be the one that shipped, or the origin being
  // preserved is not the origin that was recorded.
  var wrongVersion = {};
  wrongVersion[LIVE] = CORRECTED + " 0.9.9";
  count("a declaration naming the token with a version the record disagrees with excuses nothing",
    snap.checkSinceDropped(oldMap, newMap, wrongVersion, []).length === 2,
    JSON.stringify(snap.checkSinceDropped(oldMap, newMap, wrongVersion, [])));
}

// The same rule, on the gate's other reader of the same declarations.
function theOriginatedGateAlsoAnswersPerToken() {
  var oldMap = {};
  oldMap[CORRECTED] = "0.1.0";
  oldMap[DROPPED]   = "0.1.0";
  var newMap = {};
  newMap[LIVE] = "0.1.0";
  var named = {};
  named[LIVE] = CORRECTED + " 0.1.0";

  var v = snap.checkOriginated(oldMap, newMap, named, [], true);
  count("a path correction excuses its own token on the unchanged-surface path",
    !v.some(function (m) { return m.indexOf(CORRECTED) === 0; }), JSON.stringify(v));
  count("and leaves the unrelated drop reported there too",
    v.length === 1 && v[0].indexOf(DROPPED) === 0, JSON.stringify(v));
}

// The third answer, and the one that did not exist. A primitive can be
// deleted outright: not renamed, not moved, its mechanism replaced by
// something that derives nothing. Neither existing tag is true of that.
// Restoring the `@since` re-documents a callable that no longer ships, and
// `@originated` states that the path was corrected and the callable is
// still reachable, which is a false statement about a deletion.
function aDeliberateRemovalIsDeclarableAndExcusesOnlyItself() {
  var oldMap = {};
  oldMap[DROPPED]   = "0.1.0";
  oldMap[ALSO_GONE] = "0.1.0";
  var newMap = {};
  newMap[LIVE] = "0.1.0";

  count("an undeclared drop is reported",
    snap.checkSinceDropped(oldMap, newMap, {}, []).length === 2,
    JSON.stringify(snap.checkSinceDropped(oldMap, newMap, {}, [])));

  var tombstones = [_tomb(DROPPED + " 0.1.0")];
  var v = snap.checkSinceDropped(oldMap, newMap, {}, tombstones);
  count("a declared removal excuses the drop it names",
    !v.some(function (m) { return m.indexOf(DROPPED) === 0; }), JSON.stringify(v));
  count("and excuses nothing else",
    v.length === 1 && v[0].indexOf(ALSO_GONE) === 0, JSON.stringify(v));

  // The refusal has to offer all three answers now. An author reading the
  // old one was told the only ways out were the two that would be false, and
  // the second of those was a tree-wide off switch for this gate.
  count("the refusal names the removal record beside the other two answers",
    /@removed/.test(v[0]), v[0]);
}

// The tombstone is a declaration, which makes it an input that can only ever
// make the gate quieter, and it gets the treatment the other such input
// gets: it names something the record holds, it says something readable, and
// there is exactly one of it.
function aRemovalDeclarationThatGovernsNothingIsRefused() {
  var oldSince = {}; oldSince[DROPPED] = "0.1.0";
  var newSince = {}; newSince[LIVE]    = "0.1.0";

  var clean = snap.checkRemovals([_tomb(DROPPED + " 0.1.0")], oldSince, newSince, {});
  count("a tombstone naming a recorded primitive at the version it shipped is accepted",
    clean.length === 0, JSON.stringify(clean));

  var unreadable = snap.checkRemovals([_tomb("0.1.0")], oldSince, newSince, {});
  count("a tombstone that names no token and version is refused rather than skipped",
    unreadable.length === 1 && /does not read as/.test(unreadable[0]), JSON.stringify(unreadable));
  count("the refusal points at the declaration's own file and line",
    unreadable[0].indexOf("lib/store/index.js:12") !== -1, unreadable[0]);

  var ghost = snap.checkRemovals(
    [_tomb("blamepost.store.neverExisted 0.1.0")], oldSince, newSince, {});
  count("a tombstone for a primitive the record never held governs nothing and is refused",
    ghost.length === 1 && /governs nothing/.test(ghost[0]), JSON.stringify(ghost));

  var wrong = snap.checkRemovals([_tomb(DROPPED + " 0.9.9")], oldSince, newSince, {});
  count("a tombstone disagreeing with the recorded introduction version is refused",
    wrong.length === 1 && /records/.test(wrong[0]), JSON.stringify(wrong));

  var alive = snap.checkRemovals([_tomb(LIVE + " 0.1.0")], oldSince, newSince, {});
  count("a tombstone over a primitive that still ships is refused",
    alive.length === 1 && /still documented/.test(alive[0]), JSON.stringify(alive));

  var twice = snap.checkRemovals(
    [_tomb(DROPPED + " 0.1.0", 12), _tomb(DROPPED + " 0.1.0", 40)], oldSince, newSince, {});
  count("one primitive declared removed twice is refused rather than counted once",
    twice.length === 1 && /more than once/.test(twice[0]), JSON.stringify(twice));
}

// THE LIVE DEFECT. A tombstone was held to the DOCUMENTATION and never to
// the CALLABLE. The checker asked whether the token is still documented as a
// `@primitive`, which a commit that deletes the block and adds an `@removed`
// line beside it satisfies by construction: the block is gone, so nothing
// contradicts the record. The callable is still exported and still callable,
// and the frozen surface now says it is gone, so every later change to it is
// governed by a record that has already written it off.
//
// Measured on this tree before the fix: `blamepost.resolver`, a live
// exported callable, was declarable removed with zero findings from
// checkRemovals and zero from the dropped-record gate.
function aTombstoneOverALiveCallableIsRefused() {
  var s = _snapshot();

  // A real token off the live surface rather than a fixture one, because
  // what makes this a defect is that the export walk reaches it.
  var live = Object.keys(s.sinceByPrimitive || {}).filter(function (tok) {
    return _inSurface(s.surface, tok);
  })[0];
  count("the export walk still reaches a documented primitive to test against",
    typeof live === "string" && live.length > 0, String(live));

  var oldSince = {}; oldSince[live] = s.sinceByPrimitive[live];
  var record = {
    token: live, version: s.sinceByPrimitive[live], value: live + " " + s.sinceByPrimitive[live],
    file: "lib/store/index.js", line: 1377,
  };

  // The commit under test: the block deleted, the declaration added, the
  // export untouched.
  var refused = snap.checkRemovals([record], oldSince, {}, {}, s.surface);
  count("a tombstone over a callable the export walk still reaches is refused",
    refused.length === 1 && refused[0].indexOf(live) === 0, JSON.stringify(refused));
  count("the refusal says the callable still ships rather than that it is still documented",
    /still reaches it/.test(refused[0]) && !/still documented/.test(refused[0]), refused[0]);
  count("it points at the declaration's own file and line",
    refused[0].indexOf("lib/store/index.js:1377") !== -1, refused[0]);

  // The parameter is what closed it, stated as a vector so a caller that
  // stops passing the surface fails here rather than going quiet.
  count("without the surface the same record is accepted, which is the defect",
    snap.checkRemovals([record], oldSince, {}, {}).length === 0,
    JSON.stringify(snap.checkRemovals([record], oldSince, {}, {})));

  // The asymmetry, and the reason a false is never read as proof. Most
  // documented primitives are members of the handle create() returns, which
  // the export walk cannot see at all, and a static gate must not boot the
  // application to find out. So only a TRUE resolution refuses.
  var handleOnly = Object.keys(s.sinceByPrimitive || {}).filter(function (tok) {
    return !_inSurface(s.surface, tok);
  })[0];
  var hOld = {}; hOld[handleOnly] = s.sinceByPrimitive[handleOnly];
  count("a handle-only primitive is still declarable removed, because a false says nothing",
    snap.checkRemovals([{
      token: handleOnly, version: s.sinceByPrimitive[handleOnly],
      value: "x", file: "lib/x.js", line: 2,
    }], hOld, {}, {}, s.surface).length === 0, String(handleOnly));

  // A token under no package root resolves to nothing rather than throwing
  // or slicing a name it does not carry.
  count("a token that is not under the package root resolves to nothing",
    _inSurface(s.surface, "somethingelse.store.thing") === false &&
    _inSurface(s.surface, "") === false);

  // The tree's own record, with the surface now in play. The one removal
  // this repository declares names a callable the walk really cannot reach.
  var v = snap.checkRemovals(sourcePrimitives.collectRemovals(), s.sinceByPrimitive || {},
    sourcePrimitives.tagMap(sourcePrimitives.collectPrimitives(), "since"),
    s.removedPrimitives || {}, s.surface);
  count("every removal this tree declares names a callable that really has gone",
    v.length === 0, JSON.stringify(v));
}

// The record has to outlive the refresh that writes it, in both directions.
// The snapshot keeps the removal so the token can never come back wearing a
// rewritten introduction version, and the source keeps the sentence saying
// why it went, because the snapshot is not what a maintainer reads.
function aRecordedRemovalStaysRecorded() {
  var prior = {};
  prior[DROPPED] = { since: "0.1.0", removedIn: "0.1.1" };

  var kept = snap.checkRemovals([_tomb(DROPPED + " 0.1.0")], {}, {}, prior);
  count("a tombstone is still accepted once the introduction record it was written " +
    "against has left the since map, because the snapshot carries it instead",
  kept.length === 0, JSON.stringify(kept));

  var orphaned = snap.checkRemovals([], {}, {}, prior);
  count("a recorded removal whose declaration was deleted is refused, so the record " +
    "cannot be dropped from the source a maintainer actually reads",
  orphaned.length === 1 && /no @removed declaration/.test(orphaned[0]), JSON.stringify(orphaned));

  // The control. Without a record on either side the same tombstone governs
  // nothing, so acceptance above came from the carried record rather than
  // from a checker that accepts anything once the since map is empty.
  var unrecorded = snap.checkRemovals([_tomb(DROPPED + " 0.1.0")], {}, {}, {});
  count("with nothing recorded on either side the same tombstone governs nothing",
    unrecorded.length === 1 && /governs nothing/.test(unrecorded[0]),
    JSON.stringify(unrecorded));
}

// What the refresh writes down, which is the half of the record that has to
// survive its own consumption. The run that deletes a block is the last one
// on which the version that block shipped at is still readable, so a refresh
// that did not carry it into the snapshot would lose it for good.
function theRefreshRecordsAndThenCarriesTheRemoval() {
  var oldSince = {}; oldSince[DROPPED] = "0.1.0";
  var newSince = {}; newSince[LIVE]    = "0.1.0";

  var first = snap.nextRemovals([_tomb(DROPPED + " 0.1.0")], oldSince, newSince, {}, "0.2.0");
  count("the refresh records the removal, naming the version it shipped at and the one " +
    "that took it out",
  first[DROPPED] && first[DROPPED].since === "0.1.0" && first[DROPPED].removedIn === "0.2.0",
  JSON.stringify(first));

  // The next refresh: the token has already left the since map, so nothing
  // but this record can answer for it.
  var later = snap.nextRemovals([_tomb(DROPPED + " 0.1.0")], {}, newSince, first, "0.9.0");
  count("a later refresh carries the entry through unchanged rather than restamping it " +
    "with whatever version happened to be current",
  later[DROPPED] && later[DROPPED].since === "0.1.0" && later[DROPPED].removedIn === "0.2.0",
  JSON.stringify(later));

  // A tombstone naming something that never left records nothing, so a
  // declaration cannot mint a removal for a primitive that still ships.
  var spurious = snap.nextRemovals([_tomb(LIVE + " 0.1.0")], oldSince, newSince, {}, "0.2.0");
  count("a tombstone over a primitive that is still documented records no removal",
    Object.keys(spurious).length === 0, JSON.stringify(spurious));

  // And one the record never held, so a refresh cannot invent an
  // introduction version by writing a removal for it.
  var unknown = snap.nextRemovals(
    [_tomb("blamepost.store.neverExisted 0.1.0")], oldSince, newSince, {}, "0.2.0");
  count("a tombstone the snapshot never had an introduction record for records nothing",
    Object.keys(unknown).length === 0, JSON.stringify(unknown));
}

// The reader, against source on disk, in both comment styles. A declaration
// written one way and read the other is a record that exists and governs
// nothing.
function theRemovalDeclarationIsReadFromSource() {
  var dir  = helpers.tempDir("removal");
  var file = nodePath.join(dir, "store.js");
  nodeFs.writeFileSync(file, [
    "// The scratch directory this derived went with the mechanism.",
    "// @removed blamepost.store.snapshotPathFor 0.1.0",
    "var x = 1;",
    "",
    "/**",
    " * @removed blamepost.store.snapshotScratch 0.1.0",
    " */",
    "var y = 2;",
    "",
    "// A sentence that merely mentions a primitive that was removed is not one.",
    "",
  ].join("\n"));

  var records = sourcePrimitives.collectRemovals([file]);
  count("both comment styles are read", records.length === 2, JSON.stringify(records));
  count("prose that merely mentions a removal is not a declaration",
    records.length === 2, JSON.stringify(records));
  count("the token and the version are parsed out of the declaration",
    records[0].token === "blamepost.store.snapshotPathFor" && records[0].version === "0.1.0",
    JSON.stringify(records[0]));
  count("each record points at the line the declaration sits on",
    records[0].line === 2 && records[1].line === 6,
    JSON.stringify([records[0].line, records[1].line]));

  // An unreadable value is CARRIED rather than dropped, so the checker can
  // refuse it. A reader that silently skipped it would leave a declaration
  // an author believes is in force and nothing is reading.
  nodeFs.writeFileSync(file, "// @removed 0.1.0\n");
  var bad = sourcePrimitives.collectRemovals([file]);
  count("an unreadable declaration is carried to the checker rather than skipped",
    bad.length === 1 && bad[0].token === null && bad[0].value === "0.1.0",
    JSON.stringify(bad));

  helpers.removeTempDir(dir);
}

// The tree. Whatever this repository has declared removed is a removal the
// committed record agrees with, and nothing recorded there has lost its
// sentence.
function theTreesOwnRemovalRecordIsHonest() {
  var s = _snapshot();
  var documented = sourcePrimitives.tagMap(sourcePrimitives.collectPrimitives(), "since");
  var v = snap.checkRemovals(sourcePrimitives.collectRemovals(),
    s.sinceByPrimitive || {}, documented, s.removedPrimitives || {});
  count("every removal this tree declares agrees with the record, and every recorded " +
    "removal still carries the sentence that explains it",
  v.length === 0, JSON.stringify(v));
}

// ---------------------------------------------------------------------------
// The refresh, driven end to end in a tree it is allowed to rewrite
// ---------------------------------------------------------------------------

// `refresh-api-snapshot.js` and `source-primitives.js` both resolve their
// root as the parent of their own directory, so a copy of the two under
// `<temp>/scripts/` reads `<temp>/lib` and `<temp>/package.json`. That is
// what makes the write path drivable at all: the real script always writes
// the repository's own baseline, and a case that let it do so would rewrite
// the record every other case in this file reads.
var FIXTURE_SCRIPTS = ["refresh-api-snapshot.js", "source-primitives.js", "check-api-snapshot.js"];

// One documented primitive that the export walk reaches, and one exported
// array that declares what kind of list it is, because the refresh refuses
// an array that declares nothing.
function _fixtureLib(opts) {
  opts = opts || {};
  var lines = [
    '"use strict";',
    "",
  ];
  if (opts.removed) {
    lines.push("// The mechanism this derived from went with it.");
    lines.push("// @removed blamepost.demo.ping 0.1.0");
  } else {
    lines.push("/**");
    lines.push(" * @primitive blamepost.demo.ping");
    lines.push(" * @signature ping() -> true");
    lines.push(" * @since     0.1.0");
    lines.push(" * @status    experimental");
    lines.push(" *");
    lines.push(" * A fixture primitive.");
    lines.push(" */");
  }
  lines.push("function ping() { return true; }");
  lines.push("");
  lines.push("// @membership blamepost.demo.KEYS " + (opts.polarity || "capability"));
  lines.push("var KEYS = Object.freeze([\"one\", \"two\"]);");
  lines.push("");
  // The export is left in place whether or not the block is: that IS the
  // commit under test.
  lines.push("module.exports = { demo: { ping: ping, KEYS: KEYS } };");
  lines.push("");
  return lines.join("\n");
}

function _fixtureTree(opts) {
  var root = helpers.tempDir("snapshotrefresh");
  nodeFs.mkdirSync(nodePath.join(root, "scripts"), { recursive: true });
  nodeFs.mkdirSync(nodePath.join(root, "lib"), { recursive: true });
  FIXTURE_SCRIPTS.forEach(function (name) {
    nodeFs.copyFileSync(nodePath.join(REPO_ROOT, "scripts", name),
      nodePath.join(root, "scripts", name));
  });
  // `source-primitives.js` requires the documentation block reader. It is
  // carried through a `lib/web` link the walk does not descend into, so the
  // fixture documents the one primitive `_fixtureLib` writes and none of the
  // reader's own.
  helpers.carryDocumentationReader(root);
  nodeFs.writeFileSync(nodePath.join(root, "package.json"),
    JSON.stringify({ name: "@blamejs/blamepost", version: "0.1.0" }, null, 2) + "\n");
  nodeFs.writeFileSync(nodePath.join(root, "lib", "index.js"), _fixtureLib(opts));
  return root;
}

async function _refresh(root, args) {
  return spawnRun.runNodeScript(
    [nodePath.join(root, "scripts", "refresh-api-snapshot.js")].concat(args || []),
    { cwd: root, ceilingMs: RUN_CEILING_MS });
}

// `rm api-snapshot.json` re-baselined all 118 frozen versions with one line
// of stdout. Every gate in the refresh treats a null baseline as the first
// run and reports nothing, so deleting the file re-derives the whole record
// from whatever source says that day and contradicts nothing. Deleting a
// file is not a declaration; the bootstrap has to be something somebody
// types.
async function anAbsentBaselineIsRefusedRatherThanReBaselined() {
  var root = _fixtureTree();

  var refused = await _refresh(root);
  count("absent baseline: the refresh refuses rather than minting one",
    refused.code === 2, "exit " + refused.code + ": " + tail(refused.out, 6));
  count("absent baseline: it says what a fresh snapshot would reset",
    /introduction versions/.test(refused.out) && /polarities/.test(refused.out),
    tail(refused.out, 6));
  count("absent baseline: it offers restoring the file before minting a new one",
    /git checkout/.test(refused.out), tail(refused.out, 6));
  count("absent baseline: nothing was written",
    !nodeFs.existsSync(nodePath.join(root, "api-snapshot.json")), root);

  // The bootstrap still has to work, or the refusal is a wall rather than a
  // gate, and it says out loud how much it is minting unchecked.
  var minted = await _refresh(root, ["--bootstrap"]);
  count("bootstrap: the flag mints a first snapshot",
    minted.code === 0 && nodeFs.existsSync(nodePath.join(root, "api-snapshot.json")),
    "exit " + minted.code + ": " + tail(minted.out, 6));
  count("bootstrap: it announces what it recorded with nothing to check it against",
    /minting a first snapshot/.test(minted.out) && /no baseline/.test(minted.out),
    tail(minted.out, 6));

  var written = JSON.parse(nodeFs.readFileSync(nodePath.join(root, "api-snapshot.json"), "utf8"));
  count("bootstrap: the record it wrote carries the introduction version and the polarity",
    written.sinceByPrimitive["blamepost.demo.ping"] === "0.1.0" &&
    written.membershipByArray["blamepost.demo.KEYS"] === "capability",
    JSON.stringify({ since: written.sinceByPrimitive, polarity: written.membershipByArray }));

  // And a second refresh over a baseline that now exists needs no flag,
  // which is the control: without it the vector above would pass on a script
  // that refused every run.
  var again = await _refresh(root);
  count("a refresh over a baseline that exists needs no flag",
    again.code === 0, "exit " + again.code + ": " + tail(again.out, 6));

  helpers.removeTempDir(root);
}

// The same commit the pure vectors describe, driven through the real scripts
// against a tree they may rewrite: the `@primitive` block deleted, an
// `@removed` line added, the export left exactly where it was.
async function theRefreshRefusesATombstoneOverSomethingStillExported() {
  var root = _fixtureTree();
  var seeded = await _refresh(root, ["--bootstrap"]);
  count("tombstone end to end: the baseline seeds with the primitive documented",
    seeded.code === 0, "exit " + seeded.code + ": " + tail(seeded.out, 6));

  // The edit under test. `ping` is still exported; only its documentation
  // changed.
  nodeFs.writeFileSync(nodePath.join(root, "lib", "index.js"), _fixtureLib({ removed: true }));

  var refresh = await _refresh(root);
  count("tombstone end to end: the refresh refuses",
    refresh.code === 2, "exit " + refresh.code + ": " + tail(refresh.out, 8));
  count("tombstone end to end: it names the primitive that still ships",
    refresh.out.indexOf("blamepost.demo.ping") !== -1 && /still reaches it/.test(refresh.out),
    tail(refresh.out, 8));

  var gate = await spawnRun.runNodeScript(
    [nodePath.join(root, "scripts", "check-api-snapshot.js")],
    { cwd: root, ceilingMs: RUN_CEILING_MS });
  count("tombstone end to end: the CI gate refuses it too, so a refresh is not the only reader",
    gate.code === 1 && refresh.out.indexOf("blamepost.demo.ping") !== -1,
    "exit " + gate.code + ": " + tail(gate.out, 8));

  // The control: delete the export as well, which is what a real removal
  // looks like, and the same declaration is accepted.
  var body = _fixtureLib({ removed: true }).replace("{ demo: { ping: ping, KEYS: KEYS } }",
    "{ demo: { KEYS: KEYS } }");
  nodeFs.writeFileSync(nodePath.join(root, "lib", "index.js"), body);
  var real = await _refresh(root);
  count("tombstone end to end: with the callable actually gone the record is accepted",
    real.code === 0, "exit " + real.code + ": " + tail(real.out, 8));

  var written = JSON.parse(nodeFs.readFileSync(nodePath.join(root, "api-snapshot.json"), "utf8"));
  count("tombstone end to end: and the removal is what the snapshot then records",
    written.removedPrimitives["blamepost.demo.ping"] &&
    written.removedPrimitives["blamepost.demo.ping"].since === "0.1.0",
    JSON.stringify(written.removedPrimitives));

  helpers.removeTempDir(root);
}

// The polarity, driven the same way: one word in a comment, and nothing
// anywhere held an earlier value to disagree with it.
async function theRefreshRefusesAReDeclaredPolarity() {
  var root = _fixtureTree({ polarity: "capability" });
  var seeded = await _refresh(root, ["--bootstrap"]);
  count("polarity end to end: the baseline seeds with the declared polarity",
    seeded.code === 0, "exit " + seeded.code + ": " + tail(seeded.out, 6));

  nodeFs.writeFileSync(nodePath.join(root, "lib", "index.js"),
    _fixtureLib({ polarity: "constraint" }));

  var refresh = await _refresh(root);
  count("polarity end to end: the refresh refuses the re-declaration",
    refresh.code === 2, "exit " + refresh.code + ": " + tail(refresh.out, 8));
  count("polarity end to end: it names the array and both words",
    refresh.out.indexOf("blamepost.demo.KEYS") !== -1 &&
    /capability -> constraint/.test(refresh.out), tail(refresh.out, 8));

  var gate = await spawnRun.runNodeScript(
    [nodePath.join(root, "scripts", "check-api-snapshot.js")],
    { cwd: root, ceilingMs: RUN_CEILING_MS });
  count("polarity end to end: the CI gate refuses it too",
    gate.code === 1 && gate.out.indexOf("blamepost.demo.KEYS") !== -1,
    "exit " + gate.code + ": " + tail(gate.out, 8));

  helpers.removeTempDir(root);
}

// ---------------------------------------------------------------------------
// The gates, driven the way the battery drives them
// ---------------------------------------------------------------------------

async function theGateExitsCleanAndSaysWhatItExamined() {
  var run = await _runGate("scripts/check-api-snapshot.js");
  count("the api-snapshot gate exits clean over this tree",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 8));

  var seen = _examined(run.out);
  count("it publishes the walk it performed",
    typeof seen["lib-source-files"] === "number" && seen["lib-source-files"] > 0,
    JSON.stringify(seen));
  count("it publishes the primitives it actually compared against the freeze",
    typeof seen["frozen-primitives"] === "number" && seen["frozen-primitives"] > 0,
    JSON.stringify(seen));

  // The count has to be the comparison, not the size of the source parse.
  // Publishing the documented total would report full coverage on exactly
  // the run where the baseline is missing entries.
  var documented = sourcePrimitives.collectPrimitives().length;
  count("the published count equals the documented set only because the freeze is complete",
    seen["frozen-primitives"] === documented,
    "published " + seen["frozen-primitives"] + ", documented " + documented);

  // The lines are read from the END of stdout by the release battery, so a
  // gate that prints them and then says something else stops being counted.
  var lines = String(run.out).trim().split(/\r?\n/);
  count("the counts are the last lines of stdout, where the battery reads them",
    /^EXAMINED\s+\d+\s+[a-z0-9-]+$/.test(lines[lines.length - 1].trim()) &&
    /^EXAMINED\s+\d+\s+[a-z0-9-]+$/.test(lines[lines.length - 2].trim()),
    tail(run.out, 4));
}

// One reader means one answer. If these three ever disagree about how much
// lib/ there is, or about how many blocks it carries, one of them has grown
// a parse of its own again and is governing a set nobody chose.
async function everyGateGovernsTheSameSet() {
  var api       = await _runGate("scripts/check-api-snapshot.js");
  var blocks    = await _runGate("scripts/validate-source-comment-blocks.js");
  var lifecycle = await _runGate("scripts/check-status-lifecycle.js");

  var a = _examined(api.out), b = _examined(blocks.out), c = _examined(lifecycle.out);

  count("all three gates walked the same lib sources",
    a["lib-source-files"] === b["lib-source-files"] &&
    b["lib-source-files"] === c["lib-source-files"],
    "api " + a["lib-source-files"] + ", blocks " + b["lib-source-files"] +
      ", lifecycle " + c["lib-source-files"]);

  count("all three gates found the same number of primitives, so none of them is " +
    "governing a set the others cannot see",
  a["frozen-primitives"] === b["primitive-blocks"] &&
    b["primitive-blocks"] === c["primitive-blocks"],
  "api froze " + a["frozen-primitives"] + ", blocks read " + b["primitive-blocks"] +
      ", lifecycle read " + c["primitive-blocks"]);
}

async function run() {
  documentedTokensAreAllFrozen();
  handleOnlyPrimitivesAreFrozenToo();
  theUntrackedCheckerRefusesAndPermits();
  anOriginatedDeclarationExcusesOnlyTheTokenItNames();
  theOriginatedGateAlsoAnswersPerToken();
  aDeliberateRemovalIsDeclarableAndExcusesOnlyItself();
  aRemovalDeclarationThatGovernsNothingIsRefused();
  aTombstoneOverALiveCallableIsRefused();
  aRecordedRemovalStaysRecorded();
  theRefreshRecordsAndThenCarriesTheRemoval();
  theRemovalDeclarationIsReadFromSource();
  theTreesOwnRemovalRecordIsHonest();
  await anAbsentBaselineIsRefusedRatherThanReBaselined();
  await theRefreshRefusesATombstoneOverSomethingStillExported();
  await theRefreshRefusesAReDeclaredPolarity();
  await theGateExitsCleanAndSaysWhatItExamined();
  await everyGateGovernsTheSameSet();
  return helpers.getChecks();
}

module.exports = { name: "primitive-freeze-coverage", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
