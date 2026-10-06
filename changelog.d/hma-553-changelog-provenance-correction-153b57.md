---
type: fixed
issue: 553
---
#### Which channels read the redaction stamp (#553)

- **Correction to the `[0.32.0]` entry below.** Its bullet "Every channel that publishes
  findings now reads the stamp before a byte leaves" is broader than the code. The JSON
  stdout chokepoint, the `--output` file arms, the SARIF/HTML/ASFF/ASP generators, the
  registry publish builders' input and the MCP tool payloads it lists do read it. Three paths
  that carry finding-derived text do not, read on this tree:
  - the MCP deep-scan result: `buildDeepScanLayer1` asserts the layer-1 findings
    (`src/mcp-server.ts:205`), but the structural findings and discovered files it is built
    with (the `structural.discoverFiles` and `structural.analyze` results handed to
    `buildDeepScanResult` in the `hackmyagent_deep_scan` case of `src/mcp-server.ts`) are
    not asserted. Handing file content to the host
    model is that tool's stated purpose, so this is a statement of scope, not a leak report;
  - the registry publish builder asserts its input (`src/registry/publish.ts:175`), then
    derives an attack result's `message` from the response text
    (`src/registry/publish.ts:211`), which never crosses that read;
  - the narrative channel: `grep -rn assertRedactionProvenance src/narrative/` prints nothing
    and exits 1.
  Nothing about what those paths emit changes here; the sentence stops outrunning the code.
