/**
 * The registry trust score as every `trust` and `check` view prints it (#505).
 *
 * The single-package view (`trust <pkg>`, via cli-ui `renderCheckBlock`)
 * showed a score only for a completed scan and read `trustScore` on either
 * scale (a fraction, or 0-100). The batch and audit tables (`trust --batch`,
 * `trust --audit`) printed `round(trustScore * 100)/100` whenever the status
 * string was non-empty, so a `pending` or `error` scan showed a number the
 * single view called "not scanned", and a 0-100 value printed as `3500/100`.
 * The local-plus-registry `check` view gated on `completed` alone and dropped
 * the `warnings` status the other view shows. One rule now serves all three.
 */
import { mapScanStatusForMeter } from '@opena2a/check-core';

/**
 * The score on a 0-100 scale, or `null` when the registry holds no usable
 * scan: no status, a pending / failed / not-applicable status, or a value
 * that is not a finite number.
 */
export function measuredTrustScore(trustScore: unknown, scanStatus?: string): number | null {
  if (mapScanStatusForMeter(scanStatus) === undefined) return null;
  if (typeof trustScore !== 'number' || !Number.isFinite(trustScore)) return null;
  // The same normalisation cli-ui applies: a value at or below 1 is a fraction.
  return trustScore <= 1 ? Math.round(trustScore * 100) : Math.round(trustScore);
}

/** The table cell: `NN/100`, or `Not scanned` when there is no usable scan. */
export function trustScoreCell(trustScore: unknown, scanStatus?: string): string {
  const score = measuredTrustScore(trustScore, scanStatus);
  return score === null ? 'Not scanned' : `${score}/100`;
}
