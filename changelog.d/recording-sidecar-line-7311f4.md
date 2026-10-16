---
type: added
---
#### The recording render scripts end with a sidecar line for the release record, and the release checklist re-renders the secure recording

- `docs/vhs/record-secure.sh` and `docs/vhs/record-detect.sh` end a render
  with one line naming the sidecar, its sha256, the hackmyagent version and
  whether it came from npm or was packed from a commit, the render time, the
  wall clock and the metered cost. From the repository root,
  `node docs/vhs/sidecar-line.mjs docs/vhs/<name>.json` prints the same line
  for a sidecar on disk. Before, record-secure.sh ended with the video length,
  the wall clock and the output sizes, and record-detect.sh with a listing of
  the `docs/vhs/detect.*` files.
- A render whose sidecar carries no `wallClockSeconds`, or a
  `meteredCostUsd` other than 0, exits 1 and prints no sidecar line. The
  committed `docs/vhs/detect.json` is the 0.33.0 render and carries neither
  field, so `node docs/vhs/sidecar-line.mjs docs/vhs/detect.json` exits 1
  until it is re-rendered.
- `docs/testing/release-smoke.md` §6.7 re-renders the secure recording after
  the version bump is committed and before the tag push, and records the
  sidecar line in the release notes.
