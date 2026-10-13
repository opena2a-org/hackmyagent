---
type: added
---
#### A recording of `npx hackmyagent secure` and `npx hackmyagent secure --fix`, rendered from a committed tape

- The README links `docs/vhs/secure.gif`: `npx hackmyagent secure` scoring a
  sample agent project, its report held one screen at a time, then `npx
  hackmyagent secure --fix` and its fix summary. The text of both runs is in
  `docs/vhs/secure-capture.txt`.
- `docs/vhs/secure.json` is the recording's provenance sidecar: the build that
  ran, by version and npm integrity, the fixture, the sha256 of the tape, the
  size of each output and the length of the recording.
  `docs/vhs/record-secure.sh` renders the recording again in a container and
  rewrites the sidecar. It refuses to start, with exit code 2, when
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set.
- `docs/demo.tape` and `docs/hackmyagent-demo.gif` are removed. That recording
  typed `npx hackmyagent secure 2>&1 | head -30`, so it showed the first 30
  lines of a report, and nothing recorded which build it ran.
