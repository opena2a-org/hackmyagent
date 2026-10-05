---
type: changed
---
#### The NanoMind model download and daemon start use fixed locations

- The classifier model is downloaded from a fixed commit of
  `opena2a/nanomind-security-classifier` instead of its `main` branch, so the
  files always match the hashes HackMyAgent checks them against. The files
  downloaded are the same as before.
- When a scan starts the NanoMind daemon, it runs the CLI of the
  `@nanomind/daemon` package installed alongside HackMyAgent with the Node
  binary that runs HackMyAgent. It no longer looks up `node` or
  `nanomind-daemon` on PATH, so a daemon installed only globally is not started
  automatically. Run `nanomind-daemon start` and the next scan connects to it.
