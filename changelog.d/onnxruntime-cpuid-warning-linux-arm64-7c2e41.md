---
type: fixed
---
- `secure` and `check` no longer print `onnxruntime cpuid_info warning:
  Unknown CPU vendor` on Linux arm64 under Apple silicon virtualization.
  onnxruntime writes that line while its library loads, before any log
  level applies. On Linux the scan now loads the library in a child process
  first, and where that load prints anything it keeps vocabulary scoring
  instead of loading the library into the scan.
