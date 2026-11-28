/**
 * The finding-derived sections of the `--format asp` profile (#505).
 *
 * Each value says what the run measured. A check that produced no record
 * did not measure anything, so its field is `null`, not a pass: the profile
 * printed `signedComponents: true` and `pinnedDependencies: true` for a tree
 * where neither check ran, and `capabilities.shell: 'none'` from a keyword
 * search over finding descriptions that cannot show a capability is absent.
 *
 * Kept out of `cli.ts`, which is side-effectful to import, so the derivation
 * is testable on its own.
 */

export interface AspFinding {
  checkId: string;
  passed?: boolean;
  notApplicable?: unknown;
  description?: string;
}

/**
 * The outcome of one check over a record set: `false` when a measured record
 * failed, `true` when it ran and every measured record passed, `null` when no
 * measured record exists (the check did not run, or its subject was absent).
 */
export function checkOutcome(records: readonly AspFinding[], checkId: string): boolean | null {
  const measured = records.filter(
    (f) => f.checkId === checkId && !f.notApplicable && typeof f.passed === 'boolean',
  );
  if (measured.length === 0) return null;
  return measured.every((f) => f.passed === true);
}

/**
 * The `capabilities` section. The match is a heuristic over the run's own
 * findings, so a miss is `not detected`, never `none`.
 */
export function aspCapabilities(findings: readonly AspFinding[]): Record<'filesystem' | 'network' | 'shell', 'detected' | 'not detected'> {
  const desc = (f: AspFinding) => (f.description ?? '').toLowerCase();
  const filesystem = findings.some((f) => f.checkId.includes('FS-') || desc(f).includes('filesystem'));
  const network = findings.some((f) => f.checkId.includes('NET-') || desc(f).includes('network'));
  const shell = findings.some(
    (f) => f.checkId.includes('SHELL-') || desc(f).includes('shell') || desc(f).includes('exec'),
  );
  const label = (hit: boolean) => (hit ? 'detected' : 'not detected') as 'detected' | 'not detected';
  return { filesystem: label(filesystem), network: label(network), shell: label(shell) };
}

/**
 * `signedComponents` (SKILL-001) and `pinnedDependencies` (DEP-001).
 *
 * A failure in the reported findings is `false`, as before. Otherwise the
 * full record set decides: `true` only when the check ran and passed, `null`
 * when it produced no measured record.
 */
export function aspSupplyChainFlags(
  findings: readonly AspFinding[],
  allFindings: readonly AspFinding[],
): { signedComponents: boolean | null; pinnedDependencies: boolean | null } {
  const flag = (checkId: string): boolean | null => {
    if (findings.some((f) => f.checkId === checkId && f.passed === false)) return false;
    return checkOutcome([...findings, ...allFindings], checkId);
  };
  return { signedComponents: flag('SKILL-001'), pinnedDependencies: flag('DEP-001') };
}

/** True when the record set holds a measured CRED-* or SEM-CRED-* record. */
export function credentialChecksRan(records: readonly AspFinding[]): boolean {
  return records.some(
    (f) => (f.checkId.startsWith('CRED-') || f.checkId.startsWith('SEM-CRED-'))
      && !f.notApplicable && typeof f.passed === 'boolean',
  );
}
