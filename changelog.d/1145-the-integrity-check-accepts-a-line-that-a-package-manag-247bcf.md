---
type: fixed
issue: 1145
---
#### The integrity check accepts a `#!` line that a package manager rewrote to name its own node (#1145)

- The Homebrew formula install reported in #1145 starts `dist/cli.js` with
  `#!/opt/homebrew/opt/node/bin/node` instead of the built
  `#!/usr/bin/env node`, and `hackmyagent --version` on a copy of the build
  with that first line printed `INTEGRITY CHECK FAILED` and exited 3. The
  check now accepts, in place of `#!/usr/bin/env node`, a first line that
  runs node with no arguments (an absolute path ending in `/node` or
  `/nodejs`, or `env` followed by `node` or `nodejs`) when the bytes after that line
  match the build, and the same run prints the version and exits 0.
- A first line that runs another interpreter (`#!/bin/sh`), or node with an
  argument (`--require ./preload.js`), is still reported with exit 3, as is
  a byte appended after the rewritten first line.
