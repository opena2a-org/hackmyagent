---
type: changed
---
#### `onnxruntime-node` is declared at exactly 1.30.0

- `package.json` declared `onnxruntime-node` as `^1.27.0`, so a fresh install
  of this tool resolved the newest 1.x release on the day, a version the
  runtime's telemetry-off measurement was not made with. It now declares
  `1.30.0`, exact, and the lockfile resolves `onnxruntime-node` 1.30.0 and
  `onnxruntime-common` 1.30.0 from the npm registry (both were 1.27.0), so an
  install resolves the version the runtime was measured with.
  `onnxruntime-node` 1.30.0 declares `adm-zip` as `^0.6.0` (1.27.0 declared
  `^0.5.16`); this tree still resolves `adm-zip` 0.6.1.
