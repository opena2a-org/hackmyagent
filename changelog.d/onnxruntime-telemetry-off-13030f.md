---
type: security
---
#### NanoMind inference turns the ONNX runtime's own telemetry off

- Before it loads `onnxruntime-node`, local NanoMind inference now sets
  `ORT_DISABLE_TELEMETRY=1` in its own process, which upstream documents as
  preventing the runtime's uploader, its events and its persistent device
  identifier. A scan writes nothing under
  `~/Library/Application Support/Microsoft/DeveloperTools/.onnxruntime`, the
  path the runtime's client uses on macOS.
- The Semantic layer step of `docs/how-it-works.md` names the variable and
  links `docs/onnxruntime-telemetry.md`, which adds the store path, the
  runtime versions whose native libraries carry the client and how to check
  both.
