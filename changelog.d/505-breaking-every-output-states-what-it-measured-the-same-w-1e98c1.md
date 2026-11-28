---
type: changed
issue: 505
breaking: true
---
#### Breaking: every output states what it measured, the same way in each view (#505)

- **`wild` exits 2 when no attack page could be fetched.** A target with no
  reachable page scored the empty set `100/100 (strong)` and exited 0. The
  score line now reads `not measured (no attack page could be fetched)`,
  `--json` carries `wildResilienceScore: null` and
  `resilienceRating: "not-measured"`, and the run exits 2 with one stderr line.
- **`secure --json` carries a `gate` object**: `failed`, `exitCode`, `reason`
  (the cause that set the exit code), `reasons` (every cause the settlement
  read: `unread-inputs`, `critical-or-high-findings`, `deep-scan-incomplete`,
  `below-fail-below`), `criticalOrHigh`, `unreadInputs`, and `failBelow`
  (`threshold`, `score`, `breached`, or `null` without `--fail-below`).
  `gate.exitCode` equals the top-level `exitCode` and the process exit.
- **`secure -b oasb-1 --format asp`**: `supplyChain.signedComponents` and
  `supplyChain.pinnedDependencies` are `null` when SKILL-001 or DEP-001
  produced no measured record (they read `true`); a `capabilities` value that
  the findings did not show is `not detected` (it read `none`);
  `credentials.hardcodedSecrets` is `null` when no credential check produced a
  result; and `attestation` carries `signed: false`.
- **`secure -b oasb-2`**: a governance domain the profile skips, or one with no
  control at the agent's tier, prints `--` with the reason, as `scan-soul`
  does, instead of `0/0  (0%)`.
- **`trust --batch` and `trust --audit`** show a score only for a completed
  registry scan, by the same rule as `trust <package>`; a pending or failed
  scan reads `Not scanned` instead of a number, and a score the registry sends
  on a 0-100 scale is no longer multiplied by 100. The registry section of
  `check` shows the meter for a scan with warnings, as `trust <package>` does.
