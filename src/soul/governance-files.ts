/**
 * The governance artifacts `harden-soul` will target, in priority order.
 *
 * Its own module because two subsystems have to agree on it and they did not.
 * `hardenSoul` writes to whatever `findGovernanceFile()` returns from this
 * list, while `HardeningScanner.BACKUP_FILES` carried a hand-copied subset —
 * `SOUL.md` and `CLAUDE.md`. A repo governed by `.cursorrules` was therefore
 * rewritten with no manifest entry and no backup, and `rollback` reported a
 * clean revert having restored nothing (#271, measured: 113 -> 19055 bytes,
 * `[+] Rollback complete`, exit 0).
 *
 * The fix is not a second constant that must track this one forever. Both
 * sides read THIS list, so adding a governance artifact cannot leave the
 * backup side behind.
 */
export const GOVERNANCE_FILES = [
  'SOUL.md',
  'system-prompt.md',
  'SYSTEM_PROMPT.md',
  '.cursorrules',
  '.github/copilot-instructions.md',
  'CLAUDE.md',
  '.clinerules',
  'instructions.md',
  'constitution.md',
  'agent-config.yaml',
];
