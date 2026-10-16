---
type: fixed
---
- `hackmyagent check <package>` no longer prints `Deps      0 total · min trust 2/4`.
  The registry block beside a local scan printed the `Deps` line whenever the
  registry record carried a dependency summary, so a count of zero printed
  beside a minimum trust level taken over those zero dependencies (`check
  express`, whose 5.3.0 release lists 28 runtime dependencies on npm). Both registry
  blocks now print the line only when the record counts at least one
  dependency, and omit it otherwise. `check <package> --no-scan --json` still
  carries the registry's `dependencies` object as the registry returned it.
