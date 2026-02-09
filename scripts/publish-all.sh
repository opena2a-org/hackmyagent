#!/bin/bash
# Publish all packages with updated READMEs.
# Usage: ./scripts/publish-all.sh [patch|minor|major]
#
# What it does:
# 1. Bumps version on all packages (default: patch)
# 2. Builds all packages via turbo
# 3. Publishes each package to npm
# 4. Commits version bumps and pushes

set -euo pipefail

BUMP="${1:-patch}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGES_DIR="$ROOT/packages"

echo "Publishing all packages with $BUMP bump"
echo ""

# 1. Version bump
echo "=== Version bump ($BUMP) ==="
for pkg in "$PACKAGES_DIR"/*/; do
  if [ -f "$pkg/package.json" ]; then
    name=$(node -p "require('$pkg/package.json').name")
    old=$(node -p "require('$pkg/package.json').version")
    cd "$pkg"
    new=$(npm version "$BUMP" --no-git-tag-version 2>/dev/null | tr -d 'v')
    echo "  $name: $old -> $new"
    cd "$ROOT"
  fi
done
echo ""

# 2. Build
echo "=== Building ==="
cd "$ROOT"
npm run build
echo ""

# 3. Publish
echo "=== Publishing ==="
PUBLISHED=()
for pkg in "$PACKAGES_DIR"/*/; do
  if [ -f "$pkg/package.json" ]; then
    name=$(node -p "require('$pkg/package.json').name")
    version=$(node -p "require('$pkg/package.json').version")
    private=$(node -p "require('$pkg/package.json').private || false")

    if [ "$private" = "true" ]; then
      echo "  SKIP $name (private)"
      continue
    fi

    cd "$pkg"
    if npm publish --access public 2>/dev/null; then
      echo "  OK   $name@$version"
      PUBLISHED+=("$name@$version")
    else
      echo "  FAIL $name@$version"
    fi
    cd "$ROOT"
  fi
done
echo ""

# 4. Commit
echo "=== Committing ==="
cd "$ROOT"
git add packages/*/package.json
git commit -m "Bump all packages ($BUMP): ${PUBLISHED[*]}"
echo ""

echo "Done. Published ${#PUBLISHED[@]} packages."
echo "Run 'git push' to push version bumps."
