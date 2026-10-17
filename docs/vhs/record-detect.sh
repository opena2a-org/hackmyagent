#!/usr/bin/env bash
# Renders docs/vhs/detect.tape inside the docs-record container and writes the provenance sidecar.
#
#   docs/vhs/record-detect.sh                        renders the fixture in test-fixtures/demo-agents
#   docs/vhs/record-detect.sh <fixture-checkout>     renders a git checkout of the five projects
#   docs/vhs/record-detect.sh --dry-run [<fixture-checkout>]   prints what that render uses and writes
#   DOCKER=/path/to/docker docs/vhs/record-detect.sh   when the docker client is not on PATH
#
# With no argument, test-fixtures/demo-agents/materialize.mjs writes the five projects into a new
# temporary directory outside any git work tree, the only place their fake credentials exist; the
# render reads that directory and it is removed on exit. The sidecar then names the fixture by its
# path in this repository, with the commit that last changed it and its uncommitted changes.
#
# The container (docs/vhs/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ffmpeg, ttyd, Chromium, JetBrains Mono, gifsicle, Node 22, procps and hackmyagent@0.33.0 installed
# globally, so the typed `npx hackmyagent detect` runs the published build with no download on screen.
# The fixture is copied into the container filesystem (a bind mount is slow to walk) with its .git and
# session files removed; the hostname is `laptop`; HOME is fresh. After the tape, the same container
# runs both commands once more with NO_COLOR=1 into detect-capture.txt (the text version of the
# recording), optimises the GIF, and writes detect.json.
#
# A fixture passed as the argument has to be a git checkout with a commit: the sidecar names it by
# that commit.
#
# --dry-run asks docker whether the image is present, prints the tape, the image, the fixture and its
# commit and the files the render writes (the tape's outputs and screenshots, the text capture and
# the sidecar), and exits 0. It builds no image, materializes no fixture, renders nothing and leaves
# docs/vhs as it was.
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
IMAGE="${HMA_VHS_IMAGE:-hma-vhs:0.33.0}"
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
if [ "$DRY_RUN" = 1 ]; then
  if "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
    IMAGE_STATE="present"
  else
    IMAGE_STATE="not found by docker image inspect, so the render builds it from docs/vhs/docker"
  fi
  echo "record-detect.sh --dry-run: nothing was built, materialized, rendered or written."
  echo "tape:    docs/vhs/detect.tape"
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
  cleanup_fixture() { rm -rf "$FIXTURE"; }
  trap cleanup_fixture EXIT
fi
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$DOCKER" build -t "$IMAGE" "$REPO_ROOT/docs/vhs/docker"
fi
"$DOCKER" run --rm --hostname laptop --shm-size=1g \
  -e FIXTURE_NAME="$FIXTURE_NAME" -e FIXTURE_SHA="$FIXTURE_SHA" -e FIXTURE_DIRTY="$FIXTURE_DIRTY" \
  -v "$REPO_ROOT/docs/vhs":/work/docs/vhs \
  -v "$FIXTURE":/work/fixture:ro \
  --entrypoint bash "$IMAGE" -c '
set -euo pipefail
cp -r /work/fixture /work/demo-agents && rm -rf /work/demo-agents/.git /work/demo-agents/.claude-*
cd /work
SCRATCH="$(mktemp -d)"
cleanup_scratch() { rm -rf "$SCRATCH"; }
trap cleanup_scratch EXIT
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
VERSION="$(hackmyagent --version | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)"
VHS_VERSION="$(vhs --version 2>/dev/null | head -1 | sed "s/^vhs version //")"
PATCH_SHA="$(sha256sum docs/vhs/docker/vhs-0.12.0-render-context.patch | cut -d" " -f1)"
INTEGRITY="$(npm view hackmyagent@$VERSION dist.integrity 2>/dev/null || echo unknown)"
GIF_PX="$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0 docs/vhs/detect.gif)"
DURATION="$(ffprobe -v error -show_entries format=duration -of csv=p=0 docs/vhs/detect.mp4)"
node - "$RAN_AT" "$VERSION" "$INTEGRITY" "$GIF_PX" "$DURATION" "$E1" "$E2" "$VHS_VERSION" "$PATCH_SHA" "$FRAME_CENSUS" "$WALL_TENTHS" <<NODE > docs/vhs/detect.json
const fs = require("fs"), crypto = require("crypto");
const [ranAtUtc, version, integrity, gifPx, duration, e1, e2, vhsVersion, patchSha, frameCensus, wallTenths] = process.argv.slice(2);
const census = JSON.parse(frameCensus);
const sha = f => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const size = f => fs.statSync(f).size;
const [w, h] = gifPx.split(",").map(Number);
const out = {
  tape: "docs/vhs/detect.tape",
  tapeSha256: sha("docs/vhs/detect.tape"),
  commands: ["npx hackmyagent detect", "npx hackmyagent detect deploy-runbook-agent"],
  tool: "hackmyagent",
  version,
  npmIntegrity: integrity,
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
    gif: { path: "docs/vhs/detect.gif", bytes: size("docs/vhs/detect.gif") },
    mp4: { path: "docs/vhs/detect.mp4", bytes: size("docs/vhs/detect.mp4") },
    inventoryFrame: "docs/vhs/detect-inventory.png",
    pathForwardFrame: "docs/vhs/detect-path-forward.png",
    capture: "docs/vhs/detect-capture.txt"
  },
  durationSeconds: Number(Number(duration).toFixed(1)),
  wallClockSeconds: Number(wallTenths) / 10,
  meteredCostUsd: 0,
  exitCodes: [Number(e1), Number(e2)],
  frames: {
    "detect-inventory.png": { firstLine: "> npx hackmyagent detect", lastLine: "Fix: hackmyagent harden-soul invoice-reconciliation-agent" },
    "detect-path-forward.png": { firstLine: "HIGH  1 AI agent without governance", lastLine: "Scanned with hackmyagent v0.33.0" }
  },
  edits: ["setup not shown"],
  environment: {
    container: "docs/vhs/docker/Dockerfile (Debian trixie, Node 22, hackmyagent installed globally)",
    vhs: { version: vhsVersion, patch: "docs/vhs/docker/vhs-0.12.0-render-context.patch", patchSha256: patchSha }
  }
};
console.log(JSON.stringify(out, null, 2));
NODE
'
echo "rendered: $(ls -la "$REPO_ROOT"/docs/vhs/detect.* | awk '{print $5, $9}' | tr '\n' ';')"
