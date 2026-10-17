#!/usr/bin/env bash
# Renders docs/vhs/detect.tape inside the docs-record container and writes the provenance sidecar.
#
#   docs/vhs/record-detect.sh                        renders the fixture in test-fixtures/demo-agents
#   docs/vhs/record-detect.sh <fixture-checkout> [tool-version]
#                                                    renders a git checkout of the five projects
#   docs/vhs/record-detect.sh --dry-run [<fixture-checkout> [tool-version]]
#                                                    prints what that render uses and writes
#   DOCKER=/path/to/docker docs/vhs/record-detect.sh   when the docker client is not on PATH
#
# With no argument, test-fixtures/demo-agents/materialize.mjs writes the five projects into a new
# temporary directory outside any git work tree, the only place their fake credentials exist; the
# render reads that directory and it is removed on exit. The sidecar then names the fixture by its
# path in this repository, with the commit that last changed it and its uncommitted changes.
#
# tool-version is the hackmyagent build the container runs (default, and with no argument: the
# version in package.json), chosen as docs/vhs/record-secure.sh chooses it (docs/vhs/render-build.sh):
# when that version is on npm the image installs it and the sidecar records its npmIntegrity; when it
# is not, the container installs the tarball `npm pack` writes from this checkout (build it first) and
# the sidecar records packedFromCommit. The committed docs/vhs/detect.json was rendered with 0.33.0
# over a demo-agents checkout; pass that checkout and 0.33.0 to render that build again.
#
# The container (docs/vhs/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ffmpeg, ttyd, Chromium, JetBrains Mono, gifsicle, Node 22 and procps, with that hackmyagent build
# installed globally, so the typed `npx hackmyagent detect` runs it with no download on screen.
# The fixture is copied into the container filesystem (a bind mount is slow to walk) with its .git and
# session files removed; the hostname is `laptop`; HOME is fresh. After the tape, the same container
# runs both commands once more with NO_COLOR=1 into detect-capture.txt (the text version of the
# recording), optimises the GIF, and writes detect.json. The last line is the sidecar line
# (docs/vhs/sidecar-line.mjs): the sidecar's path and sha256, the build, the render time, the wall
# clock and the metered cost, for the release record. The script exits 1 instead when the sidecar
# carries no measured wall clock or a metered cost other than 0.
#
# A fixture passed as the argument has to be a git checkout with a commit: the sidecar names it by
# that commit.
#
# --dry-run asks npm which build the render would install and docker whether the image is present,
# prints the tape, the build, the image, the fixture and its commit and the files the render writes
# (the tape's outputs and screenshots, the text capture and the sidecar), and exits 0. It builds no
# image, materializes no fixture, packs nothing, renders nothing and leaves docs/vhs as it was.
#
# A recording never runs with a metered key in reach, so the script refuses to start when one is set.
set -euo pipefail
if [ -n "${ANTHROPIC_API_KEY+set}" ] || [ -n "${OPENAI_API_KEY+set}" ]; then
  echo "record-detect.sh: ANTHROPIC_API_KEY or OPENAI_API_KEY is set in this environment. Unset both and run again; nothing was rendered." >&2
  exit 2
fi
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  shift
fi
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
if [ "$#" -gt 0 ]; then
  FIXTURE="$1"
  FIXTURE_NAME="demo-agents"
  if ! FIXTURE_SHA="$(git -C "$FIXTURE" rev-parse --short HEAD 2>/dev/null)"; then
    echo "record-detect.sh: $FIXTURE is not a git checkout with a commit, and the sidecar names the fixture by its commit; nothing was rendered." >&2
    exit 1
  fi
  FIXTURE_DIRTY="$(git -C "$FIXTURE" status --porcelain | wc -l | tr -d ' ')"
else
  # Materialized after the dry-run exit, so a dry run writes no fixture.
  FIXTURE=""
  FIXTURE_NAME="test-fixtures/demo-agents"
  FIXTURE_SHA="$(git -C "$REPO_ROOT" log -1 --format=%h -- test-fixtures/demo-agents 2>/dev/null || echo unknown)"
  FIXTURE_DIRTY="$(git -C "$REPO_ROOT" status --porcelain -- test-fixtures/demo-agents 2>/dev/null | wc -l | tr -d ' ')"
fi
PACKAGE_VERSION="$(node -p "require(process.argv[1]).version" "$REPO_ROOT/package.json")"
VERSION="${2:-$PACKAGE_VERSION}"
PACK_FILE=""
MATERIALIZED=""
# One EXIT trap for both: a second `trap ... EXIT` would replace the first.
cleanup() {
  if [ -n "$PACK_FILE" ]; then rm -f "$REPO_ROOT/docs/vhs/out/$PACK_FILE"; fi
  if [ -n "$MATERIALIZED" ]; then rm -rf "$MATERIALIZED"; fi
}
trap cleanup EXIT
# shellcheck source=render-build.sh
. "$REPO_ROOT/docs/vhs/render-build.sh"
resolve_build record-detect.sh "$VERSION"
if [ "$DRY_RUN" = 1 ]; then
  if "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
    IMAGE_STATE="present"
  else
    IMAGE_STATE="not found by docker image inspect, so the render builds it from docs/vhs/docker with HMA_VERSION=$BUILD_VERSION"
  fi
  echo "record-detect.sh --dry-run: nothing was built, materialized, packed, rendered or written."
  echo "tape:    docs/vhs/detect.tape"
  echo "build:   $BUILD"
  echo "image:   $IMAGE, $IMAGE_STATE"
  if [ -n "$FIXTURE" ]; then
    echo "fixture: $FIXTURE at commit $FIXTURE_SHA, $FIXTURE_DIRTY uncommitted changes"
  else
    echo "fixture: $FIXTURE_NAME at commit $FIXTURE_SHA, $FIXTURE_DIRTY uncommitted changes, materialized into a new temporary directory that the render removes on exit"
  fi
  echo "writes:"
  {
    sed -n -E "s/^(Output|Screenshot)[[:space:]]+([^[:space:]]+)$/\2/p" "$REPO_ROOT/docs/vhs/detect.tape"
    echo "docs/vhs/detect-capture.txt"
    echo "docs/vhs/detect.json"
  } | sed "s/^/  /"
  exit 0
fi
if [ -z "$FIXTURE" ]; then
  FIXTURE="$(node "$REPO_ROOT/test-fixtures/demo-agents/materialize.mjs")"
  if [ -z "$FIXTURE" ] || [ ! -d "$FIXTURE" ]; then
    echo "record-detect: materialize.mjs printed no directory" >&2
    exit 1
  fi
  MATERIALIZED="$FIXTURE"
fi
pack_build
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$DOCKER" build --build-arg "HMA_VERSION=$BUILD_VERSION" -t "$IMAGE" "$REPO_ROOT/docs/vhs/docker"
fi
"$DOCKER" run --rm --hostname laptop --shm-size=1g \
  -e FIXTURE_NAME="$FIXTURE_NAME" -e FIXTURE_SHA="$FIXTURE_SHA" -e FIXTURE_DIRTY="$FIXTURE_DIRTY" \
  -e HMA_VERSION="$VERSION" -e HMA_INTEGRITY="$INTEGRITY" \
  -e HMA_PACKED_FROM_COMMIT="$PACKED_FROM" -e HMA_PACK_FILE="$PACK_FILE" \
  -v "$REPO_ROOT/docs/vhs":/work/docs/vhs \
  -v "$FIXTURE":/work/fixture:ro \
  --entrypoint bash "$IMAGE" -c '
set -euo pipefail
cp -r /work/fixture /work/demo-agents && rm -rf /work/demo-agents/.git /work/demo-agents/.claude-*
cd /work
SCRATCH="$(mktemp -d)"
cleanup_scratch() { rm -rf "$SCRATCH"; }
trap cleanup_scratch EXIT
if [ -n "$HMA_PACK_FILE" ]; then
  HOME="$SCRATCH" npm install -g --no-audit --no-fund "/work/docs/vhs/out/$HMA_PACK_FILE" >/dev/null
fi
VERSION="$(HOME="$SCRATCH" hackmyagent --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1 || true)"
if [ "$VERSION" != "$HMA_VERSION" ]; then
  echo "record-detect.sh: the container runs hackmyagent $VERSION, not $HMA_VERSION; nothing was rendered." >&2
  exit 1
fi
RAN_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Wall clock of the recording: from the start of vhs to its first "Creating" line, which it prints
# when the last command of the tape has run and it starts to encode.
STARTED="$(date +%s%N)"
vhs docs/vhs/detect.tape 2>&1 | while IFS= read -r line; do
  case "$line" in Creating*) [ -s "$SCRATCH/recorded-at" ] || date +%s%N > "$SCRATCH/recorded-at" ;; esac
  printf "%s\n" "$line"
done
if [ ! -s "$SCRATCH/recorded-at" ]; then
  echo "record-detect.sh: vhs printed no \"Creating\" line, so the wall clock of the recording was not measured; no sidecar was written." >&2
  exit 1
fi
WALL_TENTHS="$(( ($(cat "$SCRATCH/recorded-at") - STARTED) / 100000000 ))"
gifsicle -O3 --lossy=40 --batch docs/vhs/detect.gif
# Frame census: the report streaming into the terminal is the run of full-screen frames; how many
# ticks it spans varies with container load, so the sidecar records it per render.
FRAMES_DIR="$SCRATCH/frames"
mkdir "$FRAMES_DIR"
(cd "$FRAMES_DIR" && gifsicle --explode /work/docs/vhs/detect.gif -o f >/dev/null 2>&1)
FRAME_CENSUS="$(node docs/vhs/frame-census.mjs "$FRAMES_DIR")"
cd /work/demo-agents
{
  echo "\$ npx hackmyagent detect"
  NO_COLOR=1 npx hackmyagent detect && E1=0 || E1=$?
  echo "[exit $E1]"
  echo
  echo "\$ npx hackmyagent detect deploy-runbook-agent"
  NO_COLOR=1 npx hackmyagent detect deploy-runbook-agent && E2=0 || E2=$?
  echo "[exit $E2]"
} > /work/docs/vhs/detect-capture.txt 2>&1
cd /work
VHS_VERSION="$(vhs --version 2>/dev/null | head -1 | sed "s/^vhs version //")"
PATCH_SHA="$(sha256sum docs/vhs/docker/vhs-0.12.0-render-context.patch | cut -d" " -f1)"
GIF_PX="$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0 docs/vhs/detect.gif)"
DURATION="$(ffprobe -v error -show_entries format=duration -of csv=p=0 docs/vhs/detect.mp4)"
node - "$RAN_AT" "$VERSION" "$GIF_PX" "$DURATION" "$E1" "$E2" "$VHS_VERSION" "$PATCH_SHA" "$FRAME_CENSUS" "$WALL_TENTHS" <<NODE > docs/vhs/detect.json
const fs = require("fs"), crypto = require("crypto");
const [ranAtUtc, version, gifPx, duration, e1, e2, vhsVersion, patchSha, frameCensus, wallTenths] = process.argv.slice(2);
const census = JSON.parse(frameCensus);
const sha = f => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const size = f => fs.statSync(f).size;
const file = f => ({ path: f, bytes: size(f), sha256: sha(f) });
const [w, h] = gifPx.split(",").map(Number);
const tape = fs.readFileSync("docs/vhs/detect.tape", "utf8");
const screenshots = [...tape.matchAll(/^Screenshot\s+(\S+)/gm)].map(m => m[1]);
const build = process.env.HMA_INTEGRITY
  ? { npmIntegrity: process.env.HMA_INTEGRITY }
  : { packedFromCommit: process.env.HMA_PACKED_FROM_COMMIT };
const out = {
  tape: "docs/vhs/detect.tape",
  tapeSha256: sha("docs/vhs/detect.tape"),
  commands: ["npx hackmyagent detect", "npx hackmyagent detect deploy-runbook-agent"],
  tool: "hackmyagent",
  version,
  ...build,
  ranAtUtc,
  fixture: process.env.FIXTURE_NAME,
  fixtureSha: process.env.FIXTURE_SHA,
  fixtureUncommittedChanges: Number(process.env.FIXTURE_DIRTY),
  fixturePath: "/work/demo-agents",
  hostname: "laptop",
  runningAssistants: 0,
  columns: 120,
  rows: 40,
  framerate: 10,
  gifsicle: "-O3 --lossy=40 --batch",
  gifFrames: census.frames,
  gifFullScreenFrames: census.fullScreenFrames,
  gifScrollInSpan: census.scrollInSpan,
  gifScrollInNote: "the run of full-screen frames is the report streaming into the terminal; how many frames it spans varies with container load, so the GIF size varies per render",
  renderedPixelSize: { width: w, height: h },
  outputs: {
    gif: file("docs/vhs/detect.gif"),
    mp4: file("docs/vhs/detect.mp4"),
    frames: screenshots.map(file),
    capture: "docs/vhs/detect-capture.txt"
  },
  durationSeconds: Number(Number(duration).toFixed(1)),
  wallClockSeconds: Number(wallTenths) / 10,
  meteredCostUsd: 0,
  exitCodes: [Number(e1), Number(e2)],
  edits: ["setup not shown"],
  environment: {
    container: "docs/vhs/docker/Dockerfile (Debian trixie, Node 22, hackmyagent installed globally)",
    vhs: { version: vhsVersion, patch: "docs/vhs/docker/vhs-0.12.0-render-context.patch", patchSha256: patchSha }
  }
};
console.log(JSON.stringify(out, null, 2));
NODE
'
(cd "$REPO_ROOT" && node docs/vhs/sidecar-line.mjs docs/vhs/detect.json)
