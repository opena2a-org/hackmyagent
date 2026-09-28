---
type: fixed
issue: 273
---
#### `scan-soul` quotes its target once in the method-scope disclosure line (#273)

- **The `Semantic pass: hackmyagent scan-soul <dir> --deep` line quoted a target that needs
  quoting twice.** `src/cli.ts` applied the citation form before handing the directory to
  `soulScopeDisclosureLines`, which applies it again, so a directory named `a; b` printed as
  `scan-soul ''\''a; b'\''' --deep`: the `;` sat outside every quote and pasting the line ran
  `b`. The call site now passes the directory as typed. The same double application in the
  quick-scan render path (`displayUnifiedCheck`, whose two consumers already quote the
  target) is removed. A new CLI-level test runs `scan-soul` on a directory named with a
  space, `$(…)` and `;` and asks `sh`, `bash` and `zsh` that every printed `scan-soul` and
  `harden-soul` target is one argument naming that directory.
