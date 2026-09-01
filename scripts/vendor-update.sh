#!/usr/bin/env bash
# vendor-update.sh, the single entry point for changing lib/vendor/.
#
# Usage:
#   ./scripts/vendor-update.sh blamejs <version>  # vendor a specific version
#   ./scripts/vendor-update.sh blamejs latest     # vendor the current release
#   ./scripts/vendor-update.sh --check            # vendored vs latest; non-zero on drift
#   ./scripts/vendor-update.sh --diff             # what a refresh would move, and where to read it
#
# The source is the npm registry, not a git clone. Four reasons:
#
#   1. The published tarball is the artifact operators actually consume, and the
#      one covered by the publish workflow's provenance attestation and Sigstore
#      signature. A git tag is not that artifact.
#   2. The registry publishes dist.integrity, a Subresource Integrity digest, so
#      the download can be verified against a value the publisher recorded. A
#      clone offers no equivalent to check the working tree against.
#   3. The tarball carries only the package's `files` allowlist. No tests, no
#      fixtures, no CI configuration, no history. The vendored tree stays small
#      and holds only what actually ships.
#   4. scripts/check-vendor-currency.js already measures the vendored bundle
#      against npm latest. Vendoring from git would measure the tree against a
#      source it did not come from.
#
# What a refresh does:
#   1. Resolves the requested version, or reads dist-tags.latest from the
#      registry.
#   2. Downloads that version's tarball and verifies it against the registry's
#      published dist.integrity BEFORE anything is extracted. A mismatch aborts
#      and writes nothing.
#   3. Extracts into a staging directory beside lib/vendor/blamejs/ and proves
#      the staged tree while the live one is still untouched: it carries a
#      package.json, it is not a fraction of the size of the tree it replaces,
#      and its entry point loads in a fresh process.
#   4. Moves the live tree aside into a recoverable backup, moves the staged
#      tree into place, and proves it again where it now lives: the same file
#      count, the same tree hash, and it still loads. Any failure puts the
#      backup back.
#   5. Only then records version, integrity and resolved tarball URL in
#      lib/vendor/MANIFEST.json, re-hashes the tree through
#      scripts/refresh-vendor-manifest.js, and checks that the hash the
#      manifest recorded is the hash measured off the published tree.
#   6. Keeps the NOTICE and README inventories in step with the manifest.
#
# Nothing is written outside the staging and backup directories until step 5,
# and step 5 is reached only when every check in steps 3 and 4 passed. So the
# manifest and the tree cannot disagree: either the new tree is published and
# the manifest describes it, or the old tree is back and the manifest still
# describes that.
#
# The ordering in steps 3 and 4 is a real failure rather than a precaution.
# Removing the destination and then extracting into it puts the whole tree at
# risk. Measured that way, `rm -rf` deleted everything inside lib/vendor/blamejs/
# and then failed on the directory itself with "Device or resource busy",
# because a sync client held a handle on it. The script exited on that error
# with the framework gone, the manifest still naming the previous version, and
# nothing in the application able to load. The vendored tree is the whole
# runtime, so a refresh that can destroy it is a refresh that can take the
# repository with it.
#
# Then verify and commit:
#   node test/smoke.js
#   git add lib/vendor/ NOTICE README.md && git commit
#
# Hand-edits to lib/vendor/ are forbidden. The tree is replaced wholesale on
# every refresh, so an edit made there survives exactly until the next one and
# vanishes without a trace. Anything the framework does not ship is composed in
# this repository's own lib/, or filed upstream.

set -euo pipefail
cd "$(dirname "$0")/.."

# The staging and backup loops iterate a directory's entries with a glob, so
# both settings are load-bearing: an npm tarball can carry dotfiles, and an
# empty directory must produce no iterations rather than one iteration over
# the literal pattern.
shopt -s dotglob nullglob

VENDOR_ROOT="lib/vendor"
MANIFEST="$VENDOR_ROOT/MANIFEST.json"
DATE="$(date +%Y-%m-%d)"
REGISTRY="${NPM_REGISTRY:-https://registry.npmjs.org}"

# Exactly one vendored package. The list is here rather than inferred from the
# manifest so an entry that was added to the manifest by hand, which is not a
# path this script offers, cannot quietly become something --check reports on.
VENDORED_PACKAGES=("blamejs")

# The npm package behind each vendored directory name. The directory is named
# for the project; the registry name is what gets fetched.
pkg_npm() {
  case "$1" in
    blamejs) echo "@blamejs/core" ;;
    *)       echo "" ;;
  esac
}

# The source repository, used only for the release-notes and compare links a
# reviewer reads. Nothing is fetched from it.
pkg_repo() {
  case "$1" in
    blamejs) echo "blamejs/blamejs" ;;
    *)       echo "" ;;
  esac
}

pkg_license() {
  case "$1" in
    blamejs) echo "Apache-2.0" ;;
    *)       echo "" ;;
  esac
}

# The recorded version, or the empty string when the package is not vendored
# yet. A manifest that does not exist reads as "nothing vendored yet" rather
# than as a crash, so --check on a fresh clone reports the state it is in.
_vendored_ver() {
  node -e "
    var fs = require('node:fs');
    var out = '';
    try {
      var m = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
      var p = (m.packages || {})[process.argv[2]];
      if (p && p.version) out = p.version;
    } catch (_e) { /* absent or unreadable: report as not vendored */ }
    console.log(out);
  " "$MANIFEST" "$1"
}

# Registry metadata for one package, as three tab-separated fields:
#   version <TAB> tarball URL <TAB> integrity
#
# Asks for the abbreviated install format, which carries dist-tags and each
# version's dist block without the full README and history of every release.
# The scope separator is percent-encoded because the registry addresses a
# scoped package as a single path segment.
_npm_meta() {
  local pkg="$1" want="$2" encoded body
  encoded="${pkg/\//%2F}"
  body="$(curl -sfL --connect-timeout 30 --max-time 180 \
    -H "Accept: application/vnd.npm.install-v1+json" \
    -H "User-Agent: blamepost-vendor-update/1" \
    "${REGISTRY}/${encoded}")" || return 1
  printf '%s' "$body" | node -e "
    var data = '';
    process.stdin.on('data', function (c) { data += c; });
    process.stdin.on('end', function () {
      var want = process.argv[1];
      var j;
      try { j = JSON.parse(data); } catch (_e) { process.exit(1); }
      var version = want === 'latest' ? ((j['dist-tags'] || {}).latest || '') : want;
      if (!version) process.exit(1);
      var v = (j.versions || {})[version];
      if (!v || !v.dist || !v.dist.tarball) process.exit(1);
      // Fail closed when the registry publishes no integrity value. Every
      // modern publish carries one; an absent one means the verification this
      // script exists to perform cannot happen, and vendoring anyway would be
      // the silent downgrade the check is meant to prevent.
      if (!v.dist.integrity) {
        process.stderr.write('no dist.integrity published for ' + version + '\n');
        process.exit(1);
      }
      process.stdout.write([version, v.dist.tarball, v.dist.integrity].join('\t'));
    });
  " "$want"
}

_latest_ver() {
  local meta
  meta="$(_npm_meta "$1" latest)" || return 1
  printf '%s' "$meta" | cut -f1
}

# Files under one directory, as a bare integer. A directory that is missing
# counts zero rather than failing, because "not vendored yet" is a state this
# script has to be able to describe.
_count_files() {
  if [ ! -d "$1" ]; then
    echo 0
    return 0
  fi
  find "$1" -type f | wc -l | tr -d '[:space:]'
}

# ---- check mode ----
#
# Reports every vendored package against the current registry release and exits
# non-zero if any is behind. Wired into CI so a pin that stopped moving is a
# release blocker rather than something noticed a year later.
if [ "${1:-}" = "--check" ]; then
  drift=0
  unknown=0
  printf "%-16s %-14s %-14s %s\n" "Package" "Vendored" "Latest" "Status"
  printf "%-16s %-14s %-14s %s\n" "-------" "--------" "------" "------"
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    npm_name="$(pkg_npm "$pkg")"
    vendored="$(_vendored_ver "$pkg")"
    latest="$(_latest_ver "$npm_name" || echo "")"
    if [ -z "$vendored" ]; then
      status="NOT VENDORED"
      drift=1
    elif [ -z "$latest" ]; then
      # A registry that answered nothing usable is reported as UNKNOWN, never
      # as current, and it fails the gate. A network failure that reads as "up
      # to date" is the one answer this gate must never give: the pin stops
      # being measured and nothing says so.
      status="UNKNOWN (registry unreachable)"
      drift=1
      unknown=1
    elif [ "$vendored" = "$latest" ]; then
      status="up to date"
    else
      status="UPDATE AVAILABLE"
      drift=1
    fi
    printf "%-16s %-14s %-14s %s\n" "$pkg" "${vendored:-none}" "${latest:-?}" "$status"
  done
  if [ "$drift" -ne 0 ]; then
    echo ""
    if [ "$unknown" -ne 0 ]; then
      echo "At least one package could not be measured, so its currency is UNKNOWN."
      echo "Re-run when $REGISTRY answers."
    fi
    echo "Refresh with: ./scripts/vendor-update.sh <package> latest"
    exit 1
  fi
  exit 0
fi

# ---- diff mode ----
#
# What a refresh would move, and the two links a reviewer reads before taking
# it. The compare URL is the whole point: vendoring a framework means its diff
# is this repository's diff, so it gets read like one.
if [ "${1:-}" = "--diff" ]; then
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    npm_name="$(pkg_npm "$pkg")"
    repo="$(pkg_repo "$pkg")"
    vendored="$(_vendored_ver "$pkg")"
    latest="$(_latest_ver "$npm_name" || echo "")"
    echo ""
    if [ -z "$vendored" ]; then
      echo "=== $pkg: not vendored yet ==="
      [ -n "$latest" ] && echo "  latest release: $latest"
    elif [ -z "$latest" ]; then
      echo "=== $pkg: v$vendored (could not reach $REGISTRY, so currency is UNKNOWN) ==="
    elif [ "$vendored" = "$latest" ]; then
      echo "=== $pkg: v$vendored, already at the latest release ==="
    else
      echo "=== $pkg: v$vendored -> v$latest ==="
      echo ""
      echo "  Release notes: https://github.com/$repo/releases/tag/v$latest"
      echo "  Compare:       https://github.com/$repo/compare/v${vendored}...v${latest}"
    fi
  done
  echo ""
  exit 0
fi

# ---- refresh mode ----
PKG="${1:-}"
if [ -z "$PKG" ]; then
  echo "usage: ./scripts/vendor-update.sh blamejs <version>"
  echo "       ./scripts/vendor-update.sh blamejs latest"
  echo "       ./scripts/vendor-update.sh --check"
  echo "       ./scripts/vendor-update.sh --diff"
  exit 1
fi

NPM_NAME="$(pkg_npm "$PKG")"
if [ -z "$NPM_NAME" ]; then
  echo "ERROR: unknown package '$PKG'. Vendored packages: ${VENDORED_PACKAGES[*]}" >&2
  exit 1
fi
REPO="$(pkg_repo "$PKG")"

WANT="${2:?usage: ./scripts/vendor-update.sh $PKG <version>|latest}"
# A leading v is accepted for symmetry with the git tags the release notes use,
# but the registry addresses versions without it.
WANT="${WANT#v}"

DEST="$VENDOR_ROOT/$PKG"
# Staging and backup sit beside the destination rather than under the system
# temp root, so moving entries between them is a rename within one filesystem
# rather than a copy. Both names start with a dot, which .gitignore denies, so
# neither can reach a commit if a run is killed before its cleanup.
STAGE="$VENDOR_ROOT/.stage-$PKG.$$"
BACKUP="$VENDOR_ROOT/.backup-$PKG.$$"
TMP=""
DOC_SAVE=""

# Rollback state. Each flag is set BEFORE the step it describes, so a step
# that fails halfway through still unwinds.
#
# BACKED_UP and SWAP_STARTED are two flags rather than one because the two
# halves of the swap leave lib/vendor/blamejs/ holding different things, and
# unwinding them the same way destroys files. A move aside that failed partway
# leaves ORIGINAL entries there, which must be kept. A move aside that
# finished leaves only entries from the staged tree, which must go before the
# originals come back.
BACKED_UP=0
SWAP_STARTED=0
DOCS_SAVED=0
COMMITTED=0
KEEP_BACKUP=0
LIVE_FILES=0

# A previous run that was killed outright leaves one of these behind, and a
# .backup- directory can hold the only copy of the vendored tree. Removing it
# to tidy up is how the failure this script exists to prevent happens on the
# next run instead, so refuse and let the operator look.
_refuse_leftovers() {
  local found
  found="$(find "$VENDOR_ROOT" -maxdepth 1 -type d \
    \( -name ".stage-$PKG.*" -o -name ".backup-$PKG.*" \) 2>/dev/null || true)"
  if [ -n "$found" ]; then
    echo "ERROR: a previous refresh left working directories behind:" >&2
    echo "$found" >&2
    echo "       A .backup- directory may hold the only copy of the vendored tree." >&2
    echo "       Inspect it, restore anything you need, remove it, then re-run." >&2
    exit 1
  fi
}

# Move every entry of one directory into another, one entry at a time, and
# report the entry that could not move. Renaming per entry rather than removing
# the directory is deliberate: unlinking lib/vendor/blamejs/ itself is the
# operation that failed on Windows, while moving what is inside it succeeded.
_move_contents() {
  local from="$1" to="$2" entry rc=0
  if ! mkdir -p "$to"; then
    echo "ERROR: could not create $to" >&2
    return 1
  fi
  for entry in "$from"/*; do
    if ! mv -f "$entry" "$to"/; then
      echo "ERROR: could not move $entry into $to" >&2
      rc=1
    fi
  done
  return "$rc"
}

_restore_docs() {
  local f base failed=0
  [ "$DOCS_SAVED" = "1" ] || return 0
  for f in "$MANIFEST" NOTICE README.md; do
    base="$(basename "$f")"
    if [ -f "$DOC_SAVE/$base" ]; then
      if ! cp -p "$DOC_SAVE/$base" "$f"; then
        failed=1
        echo "ERROR: could not restore $f from $DOC_SAVE/$base" >&2
      fi
    fi
  done
  if [ "$failed" -ne 0 ]; then
    # A manifest describing a version that is not on disk is the state this
    # whole script is arranged around. Say so as loudly as a lost tree.
    KEEP_BACKUP=1
    echo "ERROR: the manifest or an inventory could not be put back, so it may" >&2
    echo "       now describe a release that is not on disk. Restore it from" >&2
    echo "       $DOC_SAVE before running anything else." >&2
    return 1
  fi
  echo "  the manifest and the license inventories are back as they were" >&2
  return 0
}

# Put the tree and the inventories back the way they were found. Called from
# the exit trap on every path that did not reach COMMITTED, which is every
# refusal above as well as an interrupt.
_rollback() {
  local entry restored
  if [ "$DOCS_SAVED" != "1" ] && [ "$BACKED_UP" != "1" ]; then return 0; fi
  echo "" >&2
  echo "=== Rolling back: the vendored tree and the manifest are being restored ===" >&2
  # Explicitly tolerated, so a manifest that could not be put back never
  # stops the tree from being put back. Both failures are reported.
  _restore_docs || true
  if [ "$BACKED_UP" = "1" ]; then
    # Only clear when the move aside finished, which is the only case where
    # everything in here came from the staged tree. Clearing after a move
    # aside that failed partway would delete the originals it could not move,
    # and those are the ones with no copy anywhere else.
    if [ "$SWAP_STARTED" = "1" ] && [ -d "$DEST" ]; then
      for entry in "$DEST"/*; do
        rm -rf "$entry" || echo "ERROR: could not clear $entry" >&2
      done
    fi
    if _move_contents "$BACKUP" "$DEST"; then
      restored="$(_count_files "$DEST")"
      if [ "$restored" -eq "$LIVE_FILES" ]; then
        echo "  restored $restored file(s) into $DEST" >&2
      else
        KEEP_BACKUP=1
        echo "ERROR: $DEST holds $restored file(s), and $LIVE_FILES were saved." >&2
        echo "       $BACKUP is being kept. Compare the two before doing anything else." >&2
      fi
    else
      KEEP_BACKUP=1
      echo "ERROR: the previous tree could not be put back." >&2
      echo "       Its files are in $BACKUP and that directory is being kept." >&2
    fi
  fi
  return 0
}

# The exit status has to be captured on the very first line, because every
# command below overwrites it. bash does not re-enter an EXIT trap that is
# already running, so the explicit exit at the end of this function ends the
# script rather than starting the trap again.
_cleanup() {
  rc=$?
  if [ "$COMMITTED" != "1" ]; then
    _rollback || true
  fi
  if [ -n "$TMP" ]; then rm -rf "$TMP" || true; fi
  if [ -d "$STAGE" ]; then
    rm -rf "$STAGE" || echo "WARNING: could not remove $STAGE, remove it before the next refresh" >&2
  fi
  if [ "$KEEP_BACKUP" != "1" ] && [ -d "$BACKUP" ]; then
    rm -rf "$BACKUP" || echo "WARNING: could not remove $BACKUP, remove it before the next refresh" >&2
  fi
  exit "$rc"
}

_refuse_leftovers
trap _cleanup EXIT

META="$(_npm_meta "$NPM_NAME" "$WANT")" || {
  echo "ERROR: could not resolve $NPM_NAME@$WANT from $REGISTRY" >&2
  exit 1
}
VERSION="$(printf '%s' "$META" | cut -f1)"
TARBALL="$(printf '%s' "$META" | cut -f2)"
INTEGRITY="$(printf '%s' "$META" | cut -f3)"

echo "=== Vendoring $PKG $VERSION from $NPM_NAME on $REGISTRY ==="
echo "  tarball:   $TARBALL"
echo "  integrity: $INTEGRITY"

TMP="$(mktemp -d)"

curl -sfL --connect-timeout 30 --max-time 600 \
  -H "User-Agent: blamepost-vendor-update/1" \
  -o "$TMP/package.tgz" "$TARBALL" \
  || { echo "ERROR: tarball download failed" >&2; exit 1; }

# Verify BEFORE extracting. An unverified archive is never unpacked: the whole
# point of vendoring from a registry rather than a clone is that the publisher
# recorded a digest, and a check performed after the bytes are already on disk
# in their final location is not a check.
node -e "
  var crypto = require('node:crypto');
  var fs     = require('node:fs');
  var expected = process.argv[1];
  var file     = process.argv[2];
  var m = /^([A-Za-z0-9]+)-(.+)\$/.exec(expected);
  if (!m) {
    console.error('  integrity: unparseable value ' + expected);
    process.exit(1);
  }
  var algo = m[1].toLowerCase();
  var want = m[2];
  var got;
  try {
    got = crypto.createHash(algo).update(fs.readFileSync(file)).digest('base64');
  } catch (e) {
    console.error('  integrity: cannot hash with ' + algo + ': ' + e.message);
    process.exit(1);
  }
  if (got !== want) {
    console.error('  integrity: MISMATCH');
    console.error('    expected ' + algo + '-' + want);
    console.error('    actual   ' + algo + '-' + got);
    process.exit(1);
  }
  console.log('  integrity: ' + algo + ' verified');
" "$INTEGRITY" "$TMP/package.tgz" \
  || { echo "ERROR: integrity verification failed, nothing was extracted" >&2; exit 1; }

echo ""
echo "=== Staging the new tree beside the live one ==="

# npm tarballs root every entry under package/, so one leading component is
# stripped to land the package's own layout at the top of the tree.
mkdir -p "$STAGE"
tar -xzf "$TMP/package.tgz" -C "$STAGE" --strip-components=1 \
  || { echo "ERROR: tarball extraction failed, the vendored tree is untouched" >&2; exit 1; }

LIVE_FILES="$(_count_files "$DEST")"
STAGE_FILES="$(_count_files "$STAGE")"
echo "  staged $STAGE_FILES file(s) in $STAGE"

# A staged tree that is empty or missing its manifest is not a replacement.
if [ ! -f "$STAGE/package.json" ] || [ "$STAGE_FILES" -eq 0 ]; then
  echo "ERROR: the extracted tarball has no package.json or no files ($STAGE_FILES found)." >&2
  echo "       The vendored tree is untouched." >&2
  exit 1
fi

# Plausibility, measured against the tree being replaced rather than against a
# number somebody picked. A release that halves its own file count is either a
# genuine restructuring worth reading the notes for, or a truncated archive.
# Both deserve a stop. VENDOR_ALLOW_SHRINK=1 is the way past it, for someone
# who has read the upstream release notes and knows the package really did get
# smaller. The name carries no BLAMEPOST_ prefix on purpose: that prefix names
# server configuration the config schema validates, and this is a knob on a
# maintainer's refresh, alongside NPM_REGISTRY.
if [ "$LIVE_FILES" -gt 0 ] && [ "$((STAGE_FILES * 2))" -lt "$LIVE_FILES" ]; then
  if [ "${VENDOR_ALLOW_SHRINK:-0}" != "1" ]; then
    echo "ERROR: the staged tree holds $STAGE_FILES file(s) against $LIVE_FILES vendored now." >&2
    echo "       That is less than half, which reads as a truncated archive." >&2
    echo "       Read the upstream release notes. If the package really did shrink," >&2
    echo "       re-run with VENDOR_ALLOW_SHRINK=1." >&2
    echo "       The vendored tree is untouched." >&2
    exit 1
  fi
  echo "  WARNING: $STAGE_FILES file(s) staged against $LIVE_FILES vendored, allowed by request"
fi

# The entry point loads BEFORE the live tree is touched. A tarball that cannot
# be required is refused while the running framework is still on disk, so the
# repository is never left with nothing to load.
node -e "
  var path = require('node:path');
  require(path.resolve(process.argv[1]));
  console.log('  the staged entry point loads');
" "$STAGE" \
  || { echo "ERROR: the staged tree does not load. The vendored tree is untouched." >&2; exit 1; }

# The hash the manifest is going to record, measured here, off the tree that is
# about to be published. Both measurements come from the same implementation
# the manifest refresh uses, so this is the value that has to survive the swap
# rather than a second algorithm that agrees until it does not.
STAGE_HASH="$(node scripts/refresh-vendor-manifest.js --hash "$STAGE")" \
  || { echo "ERROR: could not hash the staged tree. The vendored tree is untouched." >&2; exit 1; }
echo "  staged tree hash: $STAGE_HASH"

echo ""
echo "=== Swapping the staged tree into $DEST ==="

mkdir -p "$DEST" || { echo "ERROR: could not create $DEST" >&2; exit 1; }

# From here on a failure restores the backup, so the flag goes up first.
BACKED_UP=1
if ! _move_contents "$DEST" "$BACKUP"; then
  echo "ERROR: the live tree could not be moved aside. Nothing was replaced." >&2
  exit 1
fi

LEFT_BEHIND="$(find "$DEST" -mindepth 1 | wc -l | tr -d '[:space:]')"
if [ "$LEFT_BEHIND" -ne 0 ]; then
  echo "ERROR: $DEST still holds $LEFT_BEHIND entr(ies) after being moved aside." >&2
  echo "       Publishing over them would mix two releases into one tree." >&2
  exit 1
fi

# Past this point everything in $DEST came from the staged tree, so the
# rollback may clear it before putting the originals back.
SWAP_STARTED=1
if ! _move_contents "$STAGE" "$DEST"; then
  echo "ERROR: the new tree could not be moved into $DEST." >&2
  exit 1
fi

# Prove the published tree where it now lives. "0 files vendored" must never
# read as success, and neither must "most of the files vendored": the count and
# the hash together catch a move that dropped an entry, and the require catches
# a tree that is complete on paper and unloadable in practice.
DEST_FILES="$(_count_files "$DEST")"
if [ "$DEST_FILES" -ne "$STAGE_FILES" ]; then
  echo "ERROR: $DEST holds $DEST_FILES file(s) but $STAGE_FILES were staged." >&2
  exit 1
fi

DEST_HASH="$(node scripts/refresh-vendor-manifest.js --hash "$DEST")" \
  || { echo "ERROR: could not hash $DEST after the swap." >&2; exit 1; }
if [ "$DEST_HASH" != "$STAGE_HASH" ]; then
  echo "ERROR: $DEST hashes to $DEST_HASH, and the staged tree hashed to $STAGE_HASH." >&2
  echo "       The tree on disk is not the tree that was verified." >&2
  exit 1
fi

node -e "
  var path = require('node:path');
  require(path.resolve(process.argv[1]));
  console.log('  ' + process.argv[1] + ': OK, ' + process.argv[2] + ' files');
" "$DEST" "$DEST_FILES" \
  || { echo "ERROR: the vendored tree does not load after the swap." >&2; exit 1; }

echo ""
echo "=== Recording the new tree ==="

# The manifest, NOTICE and README are saved before the first of them is
# written, so a failure anywhere in this section puts all three back. The
# manifest describing a tree that is not there is the failure this whole script
# is arranged around, and it is just as wrong in that direction.
DOC_SAVE="$TMP/docs"
mkdir -p "$DOC_SAVE"
for doc in "$MANIFEST" NOTICE README.md; do
  if [ -f "$doc" ]; then
    cp -p "$doc" "$DOC_SAVE/" || { echo "ERROR: could not save $doc" >&2; exit 1; }
  fi
done
DOCS_SAVED=1

LICENSE_ID="$(pkg_license "$PKG")"
node -e "
  var fs = require('node:fs');
  var p = process.argv[1];
  var m;
  try { m = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_e) { m = {}; }
  m.packages = m.packages || {};
  var e = m.packages[process.argv[2]] = m.packages[process.argv[2]] || {};
  e.version   = process.argv[3];
  e.npm       = process.argv[4];
  e.license   = process.argv[5];
  e.source    = process.argv[6];
  e.integrity = process.argv[7];
  e.bundledAt = process.argv[8];
  e.bundler   = 'npm registry tarball, integrity-verified before extraction';
  e.files     = { server: process.argv[9] + '/' };
  require('./scripts/refresh-vendor-manifest.js')
    .writeReplace(p, JSON.stringify(m, null, 2) + '\n');
  console.log('  MANIFEST.json: ' + process.argv[2] + ' -> ' + process.argv[3]);
" "$MANIFEST" "$PKG" "$VERSION" "$NPM_NAME" "$LICENSE_ID" "$TARBALL" "$INTEGRITY" "$DATE" "$DEST" \
  || { echo "ERROR: MANIFEST.json update failed for $PKG" >&2; exit 1; }

# NOTICE is the license inventory operators read, and it goes stale the same way
# a manifest does: the refresh writes one copy and leaves the other to be
# noticed. Rewrite the Version line of the block whose Component names exactly
# this package. A block that is not there is reported rather than passed over,
# because a silent no-op on an inventory is how the inventory drifts.
if [ -f NOTICE ]; then
  node -e "
var fs = require('fs');
var atomic = require('./scripts/refresh-vendor-manifest.js');
var sep = Array(81).join('-');
var pkg = process.argv[1], ver = process.argv[2];
var blocks = fs.readFileSync('NOTICE', 'utf8').split(sep);
var touched = false, seen = false;
for (var i = 0; i < blocks.length; i++) {
  if (blocks[i].indexOf('Component:') === -1) continue;
  var cm = blocks[i].match(/Component:\s+(\S+)/);
  if (!cm || cm[1] !== pkg) continue;
  seen = true;
  var next = blocks[i].replace(/(Version:[ \t]+)\S+/, function (_, p) { return p + ver; });
  if (next !== blocks[i]) { blocks[i] = next; touched = true; }
}
if (touched) {
  atomic.writeReplace('NOTICE', blocks.join(sep));
  console.log('  NOTICE: ' + pkg + ' version -> ' + ver);
} else if (seen) {
  console.log('  NOTICE: ' + pkg + ' already reads ' + ver);
} else {
  console.log('  NOTICE: no Component block names ' + pkg + ', nothing to update');
}
" "$PKG" "$VERSION" || { echo "ERROR: NOTICE update failed for $PKG" >&2; exit 1; }
fi

# The README's vendored-dependency table is the third copy of the same
# inventory. Rewrite the leading semver in the row whose first cell names this
# package; a row with no semver to replace, and a README with no such row at
# all, are both reported and left alone.
if [ -f README.md ]; then
  node -e "
var fs = require('fs');
var atomic = require('./scripts/refresh-vendor-manifest.js');
var pkg = process.argv[1], ver = process.argv[2];
var lines = fs.readFileSync('README.md', 'utf8').split('\n');
var head = '| [\`' + pkg + '\`]';
var seen = false;
for (var i = 0; i < lines.length; i++) {
  if (lines[i].indexOf(head) !== 0) continue;
  seen = true;
  var cells = lines[i].split('|');
  if (cells.length < 3) continue;
  if (!/[0-9]+\.[0-9]+\.[0-9]+/.test(cells[2])) {
    console.log('  README.md: ' + pkg + ' version cell is not a semver, left as written');
    break;
  }
  var next = cells[2].replace(/[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?/, ver);
  if (next === cells[2]) break;
  cells[2] = next;
  lines[i] = cells.join('|');
  atomic.writeReplace('README.md', lines.join('\n'));
  console.log('  README.md: ' + pkg + ' version -> ' + ver);
  break;
}
if (!seen) console.log('  README.md: no vendored row names ' + pkg + ', nothing to update');
" "$PKG" "$VERSION" || { echo "ERROR: README update failed for $PKG" >&2; exit 1; }
fi

echo ""
echo "=== Refreshing MANIFEST.json hashes ==="
# Hashes track the on-disk tree. Without this the version and bundledAt fields
# drift ahead of the recorded hash and the manifest gate fails on the next test
# run, so the refresh runs it rather than relying on operator memory.
node scripts/refresh-vendor-manifest.js || { echo "ERROR: manifest hash refresh failed." >&2; exit 1; }

# The last check closes the loop: the value the manifest ended up recording for
# this package's tree is the value measured off the tree before it was
# published. A disagreement here means the manifest describes something other
# than what is on disk, which is the state this script exists to make
# impossible, so it rolls back rather than reporting success.
node -e "
  var fs = require('node:fs');
  var m = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
  var p = (m.packages || {})[process.argv[2]] || {};
  var files = p.files || {}, hashes = p.hashes || {};
  var want = process.argv[3] + '/';
  var slot = Object.keys(files).filter(function (k) { return files[k] === want; })[0];
  if (!slot) {
    console.error('  the manifest declares no entry for ' + want);
    process.exit(1);
  }
  if (hashes[slot] !== process.argv[4]) {
    console.error('  the manifest records ' + hashes[slot] + ' for ' + want);
    console.error('  the published tree measured ' + process.argv[4]);
    process.exit(1);
  }
  console.log('  the manifest hash is the hash of the tree that was published');
" "$MANIFEST" "$PKG" "$DEST" "$STAGE_HASH" \
  || { echo "ERROR: the manifest and the vendored tree disagree." >&2; exit 1; }

COMMITTED=1

echo ""
echo "=== Done: $PKG $VERSION vendored ==="
echo ""
echo "Next steps:"
echo "  1. Read the diff. A vendored framework's diff is this repository's diff:"
echo "       git diff --stat lib/vendor/"
echo "       https://github.com/$REPO/releases/tag/v$VERSION"
echo "  2. node test/smoke.js"
echo "  3. git add lib/vendor/ NOTICE README.md && git commit"
