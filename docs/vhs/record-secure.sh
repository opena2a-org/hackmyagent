#!/usr/bin/env bash
# Renders a docs/vhs tape inside the docs-record container and writes its provenance sidecar.
#
#   docs/vhs/record-secure.sh [tape-name] [tool-version]
#   DOCKER=<path to docker> docs/vhs/record-secure.sh      (when docker is not on PATH)
#
# tape-name is a tape under docs/vhs without its extension (default: secure). tool-version is the
# hackmyagent build the container runs (default: the version in package.json). When that version is
# on npm the image installs it and the sidecar records its npmIntegrity; when it is not, the
# container installs the tarball `npm pack` writes from this checkout (build it first) and the
# sidecar records packedFromCommit.
#
# The container (docs/vhs/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ffmpeg, ttyd, Chromium, JetBrains Mono, gifsicle, git and Node 22, with hackmyagent installed
# globally so the typed `npx hackmyagent ...` runs that build with no install on screen. The
# hostname is `laptop` and the home directory is /work/demo-user, which the tool has not written
# to before the tape. The tape's hidden lines write the fixture (docs/vhs/setup-lab.sh) into the
# container filesystem.
#
# After the tape, the same container runs the tape's hidden lines and typed commands once more with
# NO_COLOR=1 and an empty home directory into <tape-name>-capture.txt (the text version of the
# recording, written to a file and not to a terminal), optimises the GIF, and writes
# <tape-name>.json. The MP4 goes to docs/vhs/out/, which is not committed; its size and sha256 are
# in the sidecar.
#
# A recording never runs with a metered key in reach, so the script refuses to start when one is set.
set -euo pipefail
if [ -n "${ANTHROPIC_API_KEY+set}" ] || [ -n "${OPENAI_API_KEY+set}" ]; then
  echo "record-secure.sh: ANTHROPIC_API_KEY or OPENAI_API_KEY is set in this environment. Unset both and run again; nothing was rendered." >&2
  exit 2
fi

# Prints the tape's typed lines, one per line: `hidden` for those between Hide and Show, `typed`
# for the rest, `screenshots` for the Screenshot paths.
tape_lines() {
  node - "$1" "$2" <<'NODE'
const [tape, want] = process.argv.slice(2);
let hidden = false;
for (const raw of require("fs").readFileSync(tape, "utf8").split("\n")) {
  const line = raw.trim();
  if (line === "Hide") hidden = true;
  else if (line === "Show") hidden = false;
  const typed = line.match(/^Type(?:@\S+)?\s+(["'`])(.*)\1$/);
  const shot = line.match(/^Screenshot\s+(\S+)$/);
  if (typed && want === (hidden ? "hidden" : "typed")) console.log(typed[2]);
  if (shot && want === "screenshots") console.log(shot[1]);
}
NODE
}

inside() {
  cd /work
  local tape="docs/vhs/$TAPE_NAME.tape" gif="docs/vhs/$TAPE_NAME.gif" mp4="docs/vhs/out/$TAPE_NAME.mp4"
  local capture="docs/vhs/$TAPE_NAME-capture.txt" sidecar="docs/vhs/$TAPE_NAME.json"
  local scratch
  scratch="$(mktemp -d)"
  if [ -n "$HMA_PACK_FILE" ]; then
    HOME="$scratch" npm install -g --no-audit --no-fund "/work/docs/vhs/out/$HMA_PACK_FILE" >/dev/null
  fi
  local installed
  installed="$(HOME="$scratch" hackmyagent --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)"
  if [ "$installed" != "$HMA_VERSION" ]; then
    echo "record-secure.sh: the container runs hackmyagent $installed, not $HMA_VERSION; nothing was rendered." >&2
    exit 1
  fi

  mkdir -p docs/vhs/out
  # The home directory the recorded commands see, at a path that names no user. The tool has
  # written nothing to it before the tape, and it is emptied again before the text capture, so
  # both are first runs and print the same paths.
  local demo_home=/work/demo-user
  mkdir "$demo_home"
  # Wall clock of the recording: from the start of vhs to the end of the tape's last command, which
  # is when vhs prints its first "Creating" line and starts to encode.
  local ran_at started wall
  ran_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started="$(date +%s%N)"
  HOME="$demo_home" vhs "$tape" 2>&1 | while IFS= read -r line; do
    case "$line" in Creating*) [ -s "$scratch/recorded-at" ] || date +%s%N > "$scratch/recorded-at" ;; esac
    printf '%s\n' "$line"
  done
  if [ ! -s "$scratch/recorded-at" ]; then
    echo "record-secure.sh: vhs printed no \"Creating\" line, so the wall clock of the recording was not measured; no sidecar was written." >&2
    exit 1
  fi
  wall="$(( ($(cat "$scratch/recorded-at") - started) / 100000000 ))"
  gifsicle -O3 --lossy=40 --batch "$gif"

  # Frame census: a full-screen repaint is a frame over 60 KB after gifsicle (one per held screen,
  # more while a report streams in), so the count varies with container load per render.
  mkdir "$scratch/frames"
  (cd "$scratch/frames" && gifsicle --explode "/work/$gif" -o f >/dev/null 2>&1)
  local census
  census="$(node docs/vhs/frame-census.mjs "$scratch/frames")"

  # The text version: the tape's hidden lines, then each typed command, with NO_COLOR=1 and the
  # home directory emptied so it is a first run like the recording.
  rm -rf "${demo_home:?}"
  mkdir "$demo_home"
  : > "$scratch/exit-codes"
  (
    export HOME="$demo_home" NO_COLOR=1
    while IFS= read -r line; do eval "$line" </dev/null >/dev/null 2>&1 || true; done < <(tape_lines "/work/$tape" hidden)
    first=1
    while IFS= read -r line; do
      [ "$first" = 1 ] || echo
      first=0
      echo "\$ $line"
      eval "$line" </dev/null && code=0 || code=$?
      echo "[exit $code]"
      echo "$code" >> "$scratch/exit-codes"
    done < <(tape_lines "/work/$tape" typed)
  ) > "$capture" 2>&1

  TAPE="$tape" GIF="$gif" MP4="$mp4" CAPTURE="$capture" RAN_AT="$ran_at" WALL_TENTHS="$wall" CENSUS="$census" \
  DEMO_HOME="$demo_home" \
  TYPED="$(tape_lines "$tape" typed)" HIDDEN="$(tape_lines "$tape" hidden)" SHOTS="$(tape_lines "$tape" screenshots)" \
  EXIT_CODES="$(tr '\n' ' ' < "$scratch/exit-codes")" \
  GIF_PX="$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0 "$gif")" \
  DURATION="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$mp4")" \
  VHS_VERSION="$(vhs --version 2>/dev/null | head -1 | sed "s/^vhs version //")" \
  OS_NAME="$(. /etc/os-release && echo "$PRETTY_NAME")" \
  node - <<'NODE' > "$sidecar.tmp"
const fs = require("fs"), crypto = require("crypto"), os = require("os");
const env = process.env;
const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const file = (f) => ({ path: f, bytes: fs.statSync(f).size, sha256: sha(f) });
const lines = (s) => s.split("\n").filter(Boolean);
const tape = fs.readFileSync(env.TAPE, "utf8");
const setting = (name) => Number(tape.match(new RegExp(`^Set ${name} (\\d+)$`, "m"))[1]);
const census = JSON.parse(env.CENSUS);
const [width, height] = env.GIF_PX.split(",").map(Number);
const patch = "docs/vhs/docker/vhs-0.12.0-render-context.patch";
const fixtureDir = (env.HIDDEN.match(/\bcd\s+(\S+)/) || [])[1] || null;
const build = env.HMA_INTEGRITY ? { npmIntegrity: env.HMA_INTEGRITY } : { packedFromCommit: env.HMA_PACKED_FROM_COMMIT };
const out = {
  tape: env.TAPE,
  tapeSha256: sha(env.TAPE),
  commands: lines(env.TYPED),
  tool: "hackmyagent",
  version: env.HMA_VERSION,
  ...build,
  ranAtUtc: env.RAN_AT,
  fixture: "hma-demo, the sample agent project docs/vhs/setup-lab.sh writes",
  fixtureSha: sha("docs/vhs/setup-lab.sh"),
  fixtureUncommittedChanges: Number(env.FIXTURE_DIRTY),
  fixturePath: fixtureDir,
  homePath: env.DEMO_HOME,
  hostname: os.hostname(),
  columns: setting("Columns"),
  rows: setting("Rows"),
  framerate: setting("Framerate"),
  gifsicle: "-O3 --lossy=40 --batch",
  gifFrames: census.frames,
  gifFullScreenFrames: census.fullScreenFrames,
  renderedPixelSize: { width, height },
  outputs: {
    gif: file(env.GIF),
    mp4: file(env.MP4),
    frames: lines(env.SHOTS).map(file),
    capture: env.CAPTURE,
  },
  durationSeconds: Number(Number(env.DURATION).toFixed(1)),
  wallClockSeconds: Number(env.WALL_TENTHS) / 10,
  meteredCostUsd: 0,
  exitCodes: env.EXIT_CODES.trim().split(/\s+/).map(Number),
  vhsPatchSha256: sha(patch),
  edits: env.HIDDEN ? ["setup not shown"] : [],
  environment: {
    container: `docs/vhs/docker/Dockerfile (${env.OS_NAME}, Node ${process.versions.node}, hackmyagent installed globally)`,
    vhs: { version: env.VHS_VERSION, patch, patchSha256: sha(patch) },
  },
};
console.log(JSON.stringify(out, null, 2));
NODE
  mv "$sidecar.tmp" "$sidecar"
  rm -rf "${scratch:?}"
}

if [ "${1:-}" = "--inside" ]; then
  inside
  exit 0
fi

TAPE_NAME="${1:-secure}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
if [ ! -f "$REPO_ROOT/docs/vhs/$TAPE_NAME.tape" ]; then
  echo "record-secure.sh: no tape at docs/vhs/$TAPE_NAME.tape" >&2
  exit 1
fi
PACKAGE_VERSION="$(node -p "require(process.argv[1]).version" "$REPO_ROOT/package.json")"
VERSION="${2:-$PACKAGE_VERSION}"
PACK_FILE=""
PACKED_FROM=""
VIEW_ERR="$REPO_ROOT/docs/vhs/out/npm-view.err"
remove_scratch() {
  rm -f "$VIEW_ERR"
  if [ -n "$PACK_FILE" ]; then rm -f "$REPO_ROOT/docs/vhs/out/$PACK_FILE"; fi
}
trap remove_scratch EXIT
mkdir -p "$REPO_ROOT/docs/vhs/out"
# A version npm does not have is packed from this checkout; an npm that did not answer is not
# read as "not published".
if INTEGRITY="$(npm view "hackmyagent@$VERSION" dist.integrity 2>"$VIEW_ERR")"; then
  :
elif grep -q "E404" "$VIEW_ERR"; then
  INTEGRITY=""
else
  echo "record-secure.sh: npm did not answer whether hackmyagent $VERSION is published; nothing was rendered." >&2
  exit 1
fi
if [ -n "$INTEGRITY" ]; then
  IMAGE="${HMA_VHS_IMAGE:-hma-vhs:$VERSION}"
  BUILD_VERSION="$VERSION"
else
  # Not on npm: pack this checkout. packedFromCommit names HEAD, so the packed sources must be HEAD's.
  if [ "$VERSION" != "$PACKAGE_VERSION" ]; then
    echo "record-secure.sh: hackmyagent $VERSION is not on npm and is not the version in package.json; nothing was rendered." >&2
    exit 1
  fi
  if [ ! -f "$REPO_ROOT/dist/cli.js" ] || [ -n "$(git -C "$REPO_ROOT" status --porcelain -- src package.json)" ]; then
    echo "record-secure.sh: hackmyagent $VERSION is not on npm, so the checkout is packed: commit the changes under src/ and package.json, run \`npm run build\`, and run again; nothing was rendered." >&2
    exit 1
  fi
  IMAGE="${HMA_VHS_IMAGE:-hma-vhs:no-build}"
  BUILD_VERSION="none"
  PACK_FILE="$(cd "$REPO_ROOT" && npm pack --silent --pack-destination docs/vhs/out | tail -1)"
  PACKED_FROM="$(git -C "$REPO_ROOT" rev-parse HEAD)"
fi
# Changes to the fixture script that the next commit would not carry: an unstaged edit or an
# untracked file counts, a fully staged one does not.
FIXTURE_DIRTY="$(git -C "$REPO_ROOT" status --porcelain -- docs/vhs/setup-lab.sh | grep -cv "^[MA]  " || true)"
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$DOCKER" build --build-arg "HMA_VERSION=$BUILD_VERSION" -t "$IMAGE" "$REPO_ROOT/docs/vhs/docker"
fi
"$DOCKER" run --rm --hostname laptop --shm-size=1g \
  -e TAPE_NAME="$TAPE_NAME" -e HMA_VERSION="$VERSION" -e HMA_INTEGRITY="$INTEGRITY" \
  -e HMA_PACKED_FROM_COMMIT="$PACKED_FROM" -e HMA_PACK_FILE="$PACK_FILE" -e FIXTURE_DIRTY="$FIXTURE_DIRTY" \
  -e GIT_AUTHOR_NAME=demo -e GIT_AUTHOR_EMAIL=demo@example.com \
  -e GIT_COMMITTER_NAME=demo -e GIT_COMMITTER_EMAIL=demo@example.com \
  -v "$REPO_ROOT/docs/vhs":/work/docs/vhs \
  --entrypoint bash "$IMAGE" /work/docs/vhs/record-secure.sh --inside
node -e '
const s = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
console.log(`rendered ${s.tape} with hackmyagent ${s.version}: ${s.durationSeconds} s of video, ${s.wallClockSeconds} s wall clock, GIF ${s.outputs.gif.bytes} bytes, MP4 ${s.outputs.mp4.bytes} bytes`);
' "$REPO_ROOT/docs/vhs/$TAPE_NAME.json"
