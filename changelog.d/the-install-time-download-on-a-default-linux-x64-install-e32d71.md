---
type: fixed
---
#### The install-time download on a default Linux x64 install

- **Correction to the `[0.27.0]` entry below.** Its last bullet, on the advisory a fresh
  install reports through `adm-zip`, says that the base package ships the execution-provider
  binaries, "so that script exits before requiring `adm-zip` on a default install". On Linux
  x64 neither half holds. Read on 2026-09-20 at `onnxruntime-node` 1.27.0, the version this
  tree's lockfile pins: `script/install.js:22` requires `install-utils.js`, whose line 11
  requires `adm-zip` at module top, before any of the script's exits; the npm package's
  `bin/napi-v6/linux/x64` carries only `libonnxruntime.so.1` and `onnxruntime_binding.node`,
  and `install-metadata.js:13` lists `cuda12` as required on `linux/x64`, so a default
  install on Linux x64 (no `ONNXRUNTIME_NODE_INSTALL` and no `--ignore-scripts`) finds the
  three provider files missing, downloads `Microsoft.ML.OnnxRuntime.Gpu.Linux` from nuget.org
  at `install-utils.js:151` and extracts it with `adm-zip` at `install-utils.js:183`. So a
  default Linux x64 install does run the download and extraction path that entry said it
  never reaches. The range this package declares, `^1.27.0`, resolves to a later release on
  a fresh install: on 2026-09-19 a fresh install resolved `onnxruntime-node` 1.30.0 and,
  through the `^0.6.0` range that version declares, `adm-zip` 0.6.1. What this tool runs is
  unchanged: it requests no execution provider anywhere, so the CPU provider is the only one
  it uses, and `grep -rn "executionProviders" src/` prints nothing and exits 1, read on
  2026-09-20. The README's Install section now carries the two switches that skip the
  download and the reason `--ignore-scripts` is safe for a CI install of this package.
