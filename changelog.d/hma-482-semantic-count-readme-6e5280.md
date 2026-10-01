---
type: fixed
issue: 482
---
#### README says what `check-metadata`'s `semanticChecks` counts (#482)

- **Two semantic figures, each now traced to its source.** The README states 29 NanoMind
  semantic checks, the distinct check ids the seven analyzers emit, and explained that figure
  against the scan `Checks` line but not against `check-metadata`, which reports
  `semanticChecks: 45` from the same tree. The README now says what the 45 is: every `AST-`
  and `SEM-` id in the check taxonomy, which adds the structural layer's 19 `SEM-` checks and
  leaves out the 3 `UNICODE-STEGO` ids the stego analyzer shares with the static catalog
  (29 - 3 + 19 = 45). The golden-count test already pinned the taxonomy; it now also reads
  each count sentence in the README and `docs/SECURITY_CHECKS.md` and holds it to its source:
  the analyzers' emitted `checkId` literals for the 29, `getCheckCounts()` for the rest. On
  the previous README it fails. No count and no field changes. Tests:
  `__tests__/hardening/check-count-consistency.test.ts`.
