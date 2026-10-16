---
type: fixed
---
- `hackmyagent scan --help` names the ports a scan tries when `-p` is not
  given. The `--ports` option read `(default: common MCP ports)`, while a scan
  without `-p` tried ports 80 and 443. The option now reads
  `(default: 80,443)`, built from the same list the scan uses.
