---
type: added
---
#### Four choices in `docs/chooser.json` carry an example: a committed fixture, the exit code it ends with and its captured output, held to the build

- `secure` in `test-fixtures/insecure-library` (exit 1), `check malicious-skill`
  in `test-fixtures/insecure-openclaw/skills` (exit 1), `scan-soul` in
  `test/fixtures/governed-mcp` (exit 1) and `red-team SKILL.md` in
  `test-fixtures/insecure-openclaw/skills/malicious-skill` (exit 2) each have
  their output in `docs/captures/<choice>.txt`, beside a sidecar
  `docs/captures/<choice>.json` that names the command, the fixture, the exit
  code, the environment and the normalizers applied to the output.
- The normalizers remove the NanoMind classifier download notice and the
  spaces at line ends, and print the temporary folder as `...`, the
  `Scanned with hackmyagent` version as `<version>` and a `Duration:` in
  milliseconds as `<n>ms`.
- `node scripts/chooser-captures.mjs` runs each example from `dist/` in a copy
  of its fixture. It exits 0 when every exit code, capture and sidecar
  matches, and 1 when a run ends with an exit code the data does not declare
  or a capture or sidecar is missing or differs. `--write` regenerates the
  captures and sidecars; for a run that ends with an undeclared exit code it
  leaves the files as they were and exits 1.
