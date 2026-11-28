/**
 * One governance domain's value as `secure -b oasb-2` prints it (#505).
 *
 * A domain the profile skips, or one with no control at the agent's tier,
 * has nothing to measure. The composite table printed it as `0/0  (0%)`,
 * a zero for a domain that was never graded, beside `scan-soul`'s `--` for
 * the same domain of the same file. Both now read the same.
 */
export interface DomainCellInput {
  passed: number;
  total: number;
  percentage: number;
  skippedByProfile?: boolean;
  skippedByTier?: boolean;
}

export function governanceDomainCell(domain: DomainCellInput, agentTier: string): string {
  if (domain.skippedByProfile) return '--  (skipped by profile)';
  if (domain.skippedByTier || domain.total === 0) return `--  (not applicable at ${agentTier} tier)`;
  return `${domain.passed}/${domain.total}  (${domain.percentage}%)`;
}
