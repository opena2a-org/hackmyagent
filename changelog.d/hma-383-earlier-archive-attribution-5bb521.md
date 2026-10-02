---
type: fixed
issue: 383
---
#### A second `secure --fix` explains the score an earlier backup holds down (#383)

- **The `Live tree:` line from #374 now has a counterpart for a backup this run did not
  create.** A second `secure --fix` on the same tree archives only the redacted copies, so its
  own archive contributes nothing and the #374 line stayed silent, while the first run's
  plaintext copies kept the score at 69 with no sentence saying why. The report now says how
  many findings sit inside `.hackmyagent-backup` in a copy this run did not create, that they
  count toward the score, and what moves them: rotate, check the live file, delete the backup
  once `rollback` is no longer needed.
- **Attribution only.** The score, the verdict, the exit code and every finding are unchanged,
  and no second score is printed, because which run wrote a copy under the archive base cannot
  be proven. `--json` findings inside the target's archive base carry `inArchive: true`
  (resolved by identity, like the existing archive checks); a directory merely named
  `.hackmyagent-backup` elsewhere in the tree is still reported and never flagged.
- **Next Steps no longer cite commands that cannot move those points.** `secure --fix`,
  `fix-all`, `protect`, `harden-soul` and the MCP audit are offered for live-tree findings
  only; none of them edits a backup.
