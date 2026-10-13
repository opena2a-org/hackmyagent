---
type: fixed
---
#### The OpenClaw usage block in docs/SECURITY_CHECKS.md documents `hackmyagent secure`

- The block taught `hackmyagent secure-openclaw`, a deprecated command that
  `hackmyagent --help` does not list. It now shows `hackmyagent secure
  ~/.openclaw` with `--fix --dry-run`, `--fix` and `--json`: `secure` detects
  an OpenClaw installation and runs the OpenClaw checks alongside the standard
  suite. The block also says that `secure` with no argument scans the current
  directory, so the installation directory has to be named.
