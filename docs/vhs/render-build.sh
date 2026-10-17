# shellcheck shell=bash
# Sourced by the docs/vhs render scripts: which hackmyagent build a render runs, and the image it
# runs in. The caller sets REPO_ROOT (the repository root) and PACKAGE_VERSION (the version in
# package.json) first.
#
#   resolve_build <script-name> <version>
#
# Asks npm whether hackmyagent <version> is published. When it is, INTEGRITY is its dist.integrity,
# IMAGE is hma-vhs:<version> and BUILD_VERSION is <version>, the build the image installs. When npm
# answers E404, the checkout is packed instead: <version> has to be the one in package.json,
# dist/cli.js has to exist and src/ and package.json have to be committed; INTEGRITY is then empty,
# IMAGE is hma-vhs:no-build and BUILD_VERSION is none, an image with no build in it. HMA_VHS_IMAGE
# overrides IMAGE either way. BUILD names the build in one line. When npm does not answer, or the
# checkout cannot be packed, it prints why on stderr, naming <script-name>, and exits 1.
#
#   pack_build
#
# When INTEGRITY is empty, packs the checkout into docs/vhs/out and sets PACK_FILE to the tarball's
# name and PACKED_FROM to the commit it was packed from; otherwise both stay empty. The caller
# removes the tarball when it exits.
resolve_build() {
  local name="$1" version="$2" view_err
  view_err="$(mktemp)"
  # An npm that did not answer is not read as "not published".
  if INTEGRITY="$(npm view "hackmyagent@$version" dist.integrity 2>"$view_err")"; then
    :
  elif grep -q "E404" "$view_err"; then
    INTEGRITY=""
  else
    rm -f "$view_err"
    echo "$name: npm did not answer whether hackmyagent $version is published; nothing was rendered." >&2
    exit 1
  fi
  rm -f "$view_err"
  if [ -n "$INTEGRITY" ]; then
    IMAGE="${HMA_VHS_IMAGE:-hma-vhs:$version}"
    BUILD_VERSION="$version"
    BUILD="hackmyagent $version from npm, integrity $INTEGRITY"
    return
  fi
  # Not on npm: pack this checkout. packedFromCommit names HEAD, so the packed sources must be HEAD's.
  if [ "$version" != "$PACKAGE_VERSION" ]; then
    echo "$name: hackmyagent $version is not on npm and is not the version in package.json; nothing was rendered." >&2
    exit 1
  fi
  if [ ! -f "$REPO_ROOT/dist/cli.js" ] || [ -n "$(git -C "$REPO_ROOT" status --porcelain -- src package.json)" ]; then
    echo "$name: hackmyagent $version is not on npm, so the checkout is packed: commit the changes under src/ and package.json, run \`npm run build\`, and run again; nothing was rendered." >&2
    exit 1
  fi
  IMAGE="${HMA_VHS_IMAGE:-hma-vhs:no-build}"
  BUILD_VERSION="none"
  BUILD="hackmyagent $version packed from this checkout at commit $(git -C "$REPO_ROOT" rev-parse HEAD)"
}

pack_build() {
  PACK_FILE=""
  PACKED_FROM=""
  if [ -z "$INTEGRITY" ]; then
    mkdir -p "$REPO_ROOT/docs/vhs/out"
    PACK_FILE="$(cd "$REPO_ROOT" && npm pack --silent --pack-destination docs/vhs/out | tail -1)"
    PACKED_FROM="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  fi
}
