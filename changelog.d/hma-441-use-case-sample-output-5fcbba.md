---
type: fixed
issue: 441
---
#### The use-case guides show output the current CLI prints (#441)

- `docs/use-cases/scan-my-agent.md`, `openclaw-security.md`,
  `red-team-mcp.md` and `ci-pipeline.md` showed sample output under a
  `HackMyAgent v0.10.1 -- Security Scanner` banner the tool no longer prints,
  with check IDs, counts and a `--format json` shape that no longer match.
  Every `secure` and `secure --fix --dry-run` sample is now output captured
  from the repository's `test-fixtures/` (`insecure-library`, `insecure-mcp`,
  `insecure-openclaw`), trimmed where marked `...`, and the `--format json`
  sample shows the current top-level fields. Samples for commands that change
  files or need a live endpoint (`secure --fix`, `attack <url>`) are labelled
  "Abbreviated sample; your output will differ". The guides now say 320 static
  checks and up to 164 attack payloads, and the OpenClaw guide names the files
  `secure` detects OpenClaw from (`openclaw.json`, `SKILL.md`, `HEARTBEAT.md`,
  or an `.openclaw`, `.moltbot` or `.clawdbot` directory) instead of
  `gateway.yaml`.
