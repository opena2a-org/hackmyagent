---
type: fixed
issue: 448
breaking: true
---
#### `scan` no longer reports config and CLAUDE.md exposure on a host that answers 200 on every path (#448)

- `scan` treated any HTTP 200 as an exposed file, so a host with a catch-all
  route (the default for most single-page apps) got six CRITICAL
  CONFIG-EXPOSED findings and one HIGH CLAUDE-MD-EXPOSED, all false, and the
  run exited 1. Each port is now also asked for a path that cannot exist, and
  a 200 counts only when its body differs from that answer and has the
  file's shape: `.env` opens with a `KEY=value` line, `mcp.json`,
  `.cursor/mcp.json` and `.vscode/mcp.json` are JSON with `mcpServers` or
  `servers`, the other JSON paths are a JSON object, and `CLAUDE.md` is not
  HTML. Such a host now scores 100 and exits 0.
- A real `.env` served as `text/plain` was missed, because only a JSON body
  counted. It is now a CRITICAL CONFIG-EXPOSED and the run exits 1.
- Each CONFIG-EXPOSED and CLAUDE-MD-EXPOSED finding carries a
  `verify` command, `curl -si <url>`, in `--json` and as a `Verify:` line
  in `--verbose` output. Severities are unchanged.
