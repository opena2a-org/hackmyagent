---
type: fixed
issue: 384
---
#### Credential findings inside a backup archive name the step that moves them (#384)

- Every failing credential finding located inside `.hackmyagent-backup/` now
  carries `Fix: Rotate the credential, then remove this plaintext copy by hand`,
  whichever detector produced it. CRED-001 already did; the Layer-2 detector on
  the same archived file (`SEM-CRED-002`) printed `npx opena2a-cli protect
  <target>`, which migrates the live tree and cannot move an archive copy. Every
  such finding is marked not auto-fixable, as CRED-001's archive copies already
  were. Check, severity and score are unchanged.
- After `secure --fix`, the `Protect credentials:` and `Auto-fix all issues:`
  next steps and the "remaining issues have fix guidance, run `fix-all`" line are
  decided on the live-tree findings only; copies inside the backup the run just
  created are not counted toward them.
