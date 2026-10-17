---
type: changed
---
#### docs/vhs/record-detect.sh renders the hackmyagent version in package.json, as record-secure.sh does

- `docs/vhs/record-detect.sh` now runs the hackmyagent version in
  `package.json`, over `test-fixtures/demo-agents` with no argument or over a
  fixture checkout, or a version passed after the checkout: from npm when npm
  has it, packed from this checkout when it does not. Before, unless
  `HMA_VHS_IMAGE` named another image, it ran `hma-vhs:0.33.0`, built with
  hackmyagent 0.33.0 when absent, so a re-render at release time could not
  name the version being tagged. `--dry-run` prints the build on a `build:`
  line.
- Both render scripts choose the build in `docs/vhs/render-build.sh`. When npm
  does not answer for the version, or has no such version and it is not the
  one in `package.json`, they exit 1 before calling docker. Before,
  record-detect.sh asked npm only inside the container after the recording,
  for the sidecar's integrity, and wrote `unknown` when npm did not answer.
- The sidecar record-detect.sh writes names the build by `npmIntegrity` or
  `packedFromCommit`, and lists the GIF, the MP4 and each `Screenshot` frame
  with its size and sha256. It no longer writes the first and last lines of
  each frame, which were fixed text naming 0.33.0. The committed
  `docs/vhs/detect.json` is the 0.33.0 render and is unchanged.
