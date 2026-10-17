---
type: changed
---
#### The recording render scripts take `--dry-run`, and `docs/vhs/record-detect.sh` refuses a metered key as `docs/vhs/record-secure.sh` does

- `docs/vhs/record-secure.sh --dry-run` and
  `docs/vhs/record-detect.sh --dry-run [<checkout>]` print the tape, the image
  and whether docker has it, the fixture, and the files a render writes (the
  tape's outputs and screenshots, the text capture and the sidecar), then exit
  0. With no checkout, record-detect.sh names `test-fixtures/demo-agents` by
  the commit that last changed it and does not materialize it. A dry run
  builds no image, packs nothing, renders nothing and leaves `docs/vhs` as it
  was. Before, record-secure.sh read `--dry-run` as a tape name and exited 1,
  and record-detect.sh exited 128 with no message.
- `docs/vhs/record-detect.sh` refuses to start, with exit code 2, when
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set. Before, it went on to ask
  docker for its image and, with the image absent, to build it.
- `docs/vhs/record-detect.sh` refuses a fixture path passed as its argument
  that is not a git checkout with a commit, and names the path. Before, it
  exited 128 with no message. With no argument it still renders
  `test-fixtures/demo-agents`.
- The sidecar `docs/vhs/record-detect.sh` writes now carries
  `wallClockSeconds`, the measured wall clock of the recording, and
  `meteredCostUsd`, as `docs/vhs/secure.json` does. The committed
  `docs/vhs/detect.json` is from the 0.33.0 render and gains both fields when
  it is re-rendered.
