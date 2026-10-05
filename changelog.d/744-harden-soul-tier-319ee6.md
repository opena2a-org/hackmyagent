---
type: added
issue: 744
---
#### harden-soul accepts --tier to pin the agent tier it writes (#744)

- `hackmyagent harden-soul --tier AGENTIC --dry-run` exited 1 with
  `unknown option '--tier'`, although the documentation shows it. `--tier`
  now takes BASIC, TOOL-USING, AGENTIC or MULTI-AGENT and writes that value
  into the `<!-- soul:tier=... -->` marker in place of the detected tier, so
  later `scan-soul` runs evaluate that tier's controls. An unknown value, or
  a value that differs from a tier marker the file already has, is refused
  with exit 1 and the file is left unchanged.
