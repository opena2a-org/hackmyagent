#!/usr/bin/env bash
# Renders docs/vhs/detect.tape inside the docs-record container and writes the provenance sidecar.
#
#   docs/vhs/record-detect.sh <path-to-demo-agents-checkout>
#   DOCKER=~/.docker/bin/docker docs/vhs/record-detect.sh ~/workspace/demo-agents   (Docker Desktop on macOS)
#
# The container (docs/vhs/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ffmpeg, ttyd, Chromium, JetBrains Mono, gifsicle, Node 22, procps and hackmyagent@0.33.0 installed
# globally, so the typed `npx hackmyagent detect` runs the published build with no download on screen.
# The fixture is copied into the container filesystem (a bind mount is slow to walk) with its .git and
# session files removed; the hostname is `laptop`; HOME is fresh. After the tape, the same container
# runs both commands once more with NO_COLOR=1 into detect-capture.txt (the text version of the
# recording), optimises the GIF, and writes detect.json.
set -euo pipefail
FIXTURE="${1:?path to the demo-agents checkout}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${HMA_VHS_IMAGE:-hma-vhs:0.33.0}"
DOCKER="${DOCKER:-docker}"
FIXTURE_SHA="$(git -C "$FIXTURE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
FIXTURE_DIRTY="$(git -C "$FIXTURE" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$DOCKER" build -t "$IMAGE" "$REPO_ROOT/docs/vhs/docker"
fi
"$DOCKER" run --rm --hostname laptop --shm-size=1g \
  -e FIXTURE_SHA="$FIXTURE_SHA" -e FIXTURE_DIRTY="$FIXTURE_DIRTY" \
  -v "$REPO_ROOT/docs/vhs":/work/docs/vhs \
  -v "$FIXTURE":/work/fixture:ro \
  --entrypoint bash "$IMAGE" -c '
set -euo pipefail
cp -r /work/fixture /work/demo-agents && rm -rf /work/demo-agents/.git /work/demo-agents/.claude-*
cd /work
RAN_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
vhs docs/vhs/detect.tape
gifsicle -O3 --lossy=40 --batch docs/vhs/detect.gif
# Frame census: the report streaming into the terminal is the run of full-screen frames; how many
# ticks it spans varies with container load, so the sidecar records it per render.
FRAMES_DIR="$(mktemp -d)"
cleanup_frames() { rm -rf "$FRAMES_DIR"; }
trap cleanup_frames EXIT
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
node - "$RAN_AT" "$VERSION" "$INTEGRITY" "$GIF_PX" "$DURATION" "$E1" "$E2" "$VHS_VERSION" "$PATCH_SHA" "$FRAME_CENSUS" <<NODE > docs/vhs/detect.json
const fs = require("fs"), crypto = require("crypto");
const [ranAtUtc, version, integrity, gifPx, duration, e1, e2, vhsVersion, patchSha, frameCensus] = process.argv.slice(2);
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
  fixture: "demo-agents",
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
