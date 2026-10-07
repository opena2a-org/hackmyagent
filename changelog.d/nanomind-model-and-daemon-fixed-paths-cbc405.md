---
type: changed
---
#### The NanoMind model download and daemon start use fixed locations

- The classifier model is downloaded from a fixed commit of
  `opena2a/nanomind-security-classifier` instead of its `main` branch, so the
  files always match the hashes HackMyAgent checks them against. The files
  downloaded are the same as before.
- When a scan starts the NanoMind daemon, it runs the CLI of an installed
  `@nanomind/daemon` package with the Node binary that runs HackMyAgent. It no
  longer looks up `node` or `nanomind-daemon` on PATH. The package is found the
  way Node finds HackMyAgent's own dependencies: in a `node_modules` directory
  at or above HackMyAgent's install location, or on `NODE_PATH`. A global
  install of the daemon is therefore started when HackMyAgent is installed
  globally too, and not when HackMyAgent is a project dependency. Run
  `nanomind-daemon start` and the next scan connects to a daemon it did not
  start.
