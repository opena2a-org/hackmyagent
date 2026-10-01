---
type: fixed
issue: 553
---
#### Correction to the `[0.33.0]` redaction-boundary entry (#553)

- **The `[0.33.0]` entry below says "Every channel that publishes findings now reads the
  stamp before a byte leaves." Three paths that carry finding-derived text do not read it,**
  read on `main` at 044301c5:
  - The MCP deep-scan result (`src/mcp-server.ts`). The provenance read covers the Layer 1
    findings (`buildDeepScanLayer1`). The structural findings and the file excerpts
    serialised into the same result are not read. Handing file content to the host model
    is that tool's stated purpose, so this is a statement of scope, not a leak.
  - Registry publish (`src/registry/publish.ts`). The read runs on the input
    (`buildPublishPayload`). The `message` of a successful attack result is then built from
    up to 500 characters of the target's response, and that text never crosses the reader.
  - The narrative channel (`src/narrative/`). No module in it calls
    `assertRedactionProvenance`.
  The entry holds for the channels it names: the JSON stdout chokepoint, the `--output`
  file arms, the SARIF/HTML/ASFF/ASP generators, the registry publish input and the finding
  lists in the MCP tool payloads.
