#!/usr/bin/env bash
#
# Publish placeholder packages for the unscoped names attackers would
# typosquat against this package. Run ONCE per maintainer rotation to take +
# hold the namespaces. The placeholder packages do nothing (just
# `console.error` + exit 1 + a README pointing operators at the canonical
# `@blamejs/blamepost`); their value is denying attackers the names.
#
# Names to hold:
#   - blamejs-blamepost          (operators who type the scope flat)
#   - blame-post                 (kebab-case typo)
#
# Why this matters:
#
#   Dependency-confusion attack pattern: an attacker publishes
#   `blamejs-blamepost@99.0.0` to the public npm registry. An operator with a
#   private registry that has `@blamejs/blamepost` AND a fallback to public
#   npm types `npm install blamejs-blamepost` (forgetting the scope), the
#   private registry lookup misses (no unscoped package), npm falls through to
#   public, and the attacker's tarball runs lifecycle scripts on the
#   operator's CI machine. Holding the unscoped name with a placeholder denies
#   the squat path.
#
# Run flow (manual, because npm has no workflow-driven equivalent):
#
#   bash scripts/publish-dep-confusion-placeholder.sh
#
# Reads NPM_TOKEN from env. Refuses if the placeholder is already published
# by a different owner. That signals the squat already happened, so file a
# takedown ticket rather than trying to overwrite.

set -euo pipefail

if [ -z "${NPM_TOKEN:-}" ]; then
  echo "::error::NPM_TOKEN env var required"
  exit 1
fi

PLACEHOLDER_VERSION="0.0.1-placeholder"
WORKDIR="$(mktemp -d)"

PLACEHOLDER_NAMES=(
  "blamejs-blamepost"
  "blame-post"
)

for NAME in "${PLACEHOLDER_NAMES[@]}"; do
  echo "::group::Checking $NAME"
  EXISTING_OWNER=$(npm owner ls "$NAME" 2>/dev/null | head -1 | awk '{print $1}' || echo "")
  if [ -n "$EXISTING_OWNER" ] && [ "$EXISTING_OWNER" != "blamejs" ] && [ "$EXISTING_OWNER" != "<your-npm-org>" ]; then
    echo "::warning::$NAME is owned by '$EXISTING_OWNER' (not the blamejs org). File an npm Trust & Safety report at https://www.npmjs.com/support if this is squatting."
    echo "::endgroup::"
    continue
  fi

  PKG_DIR="$WORKDIR/$NAME"
  mkdir -p "$PKG_DIR"
  cat > "$PKG_DIR/package.json" <<EOF
{
  "name": "$NAME",
  "version": "$PLACEHOLDER_VERSION",
  "description": "Placeholder. The canonical package is @blamejs/blamepost. This unscoped name is held by the blamepost maintainers to defend against dependency-confusion typosquats.",
  "main": "index.js",
  "license": "Apache-2.0",
  "homepage": "https://github.com/blamejs/blamepost",
  "repository": { "type": "git", "url": "git+https://github.com/blamejs/blamepost.git" },
  "keywords": ["placeholder", "blamejs", "use @blamejs/blamepost"]
}
EOF
  cat > "$PKG_DIR/index.js" <<'EOF'
"use strict";
console.error(
  "[" + require("./package.json").name + "] You depended on the unscoped " +
  "placeholder package. The canonical mail server is published as " +
  "@blamejs/blamepost. Update your install:\n\n" +
  "  npm install @blamejs/blamepost\n"
);
process.exit(1);
EOF
  cat > "$PKG_DIR/README.md" <<EOF
# Placeholder package: $NAME

This is a placeholder package held by the @blamejs/blamepost maintainers to
defend against dependency-confusion typosquats. The canonical package is
**[\`@blamejs/blamepost\`](https://www.npmjs.com/package/@blamejs/blamepost)**.

\`\`\`
npm install @blamejs/blamepost
\`\`\`
EOF

  echo "Publishing $NAME@$PLACEHOLDER_VERSION..."
  (cd "$PKG_DIR" && npm publish --access public)
  echo "::endgroup::"
done

echo "[dep-confusion-placeholder] done"
