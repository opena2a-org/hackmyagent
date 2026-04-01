/**
 * NanoMind Orchestrator
 *
 * Shared entry point for integrating NanoMind semantic analysis into
 * any HMA command. Extracts the pattern previously inlined in the
 * `secure` command handler so all commands use the same flow:
 *
 *   1. Check flags (staticOnly, ci -> skip NanoMind)
 *   2. Auto-detect daemon availability
 *   3. Run scanner-bridge (compile ASTs, run analyzers)
 *   4. Merge findings using defense-in-depth rules
 *   5. Return merged results + stats
 *
 * Defense-in-depth: static findings can NEVER be suppressed, only upgraded.
 */

import type { SecurityFinding } from '../hardening/security-check.js';
import type { NanoMindScanResult } from './scanner-bridge.js';

export interface OrchestrationOptions {
  staticOnly?: boolean;
  ci?: boolean;
  deep?: boolean;
  silent?: boolean;
}

export interface OrchestrationResult {
  mergedFindings: SecurityFinding[];
  nanomindUsed: boolean;
  compiledArtifacts: number;
  newSemanticFindings: number;
  integrityStatus: string;
}

/**
 * Run NanoMind semantic analysis and merge with existing findings.
 * Safe to call from any command. Gracefully degrades if NanoMind
 * is unavailable (returns original findings unchanged).
 */
export async function orchestrateNanoMind(
  targetDir: string,
  existingFindings: SecurityFinding[],
  options: OrchestrationOptions = {},
): Promise<OrchestrationResult> {
  const { staticOnly = false, ci = false, silent = false } = options;

  // Skip NanoMind only when explicitly opted out
  // CI mode still runs NanoMind (deterministic, no cost, better results)
  if (staticOnly) {
    return {
      mergedFindings: [...existingFindings],
      nanomindUsed: false,
      compiledArtifacts: 0,
      newSemanticFindings: 0,
      integrityStatus: 'SKIPPED',
    };
  }

  try {
    const { runNanoMindScan } = await import('./scanner-bridge.js');
    const nmResult: NanoMindScanResult = await runNanoMindScan(targetDir, existingFindings);

    const newFindings = nmResult.astFindings.filter(f => !f.passed).length;

    if (!silent && newFindings > 0) {
      process.stderr.write(
        `NanoMind: ${nmResult.compiledArtifacts} artifact(s) compiled, ${newFindings} semantic finding(s) added\n`,
      );
    }

    if (!silent && nmResult.integrityStatus !== 'CLEAN') {
      process.stderr.write(`  Integrity: ${nmResult.integrityStatus}\n`);
    }

    return {
      mergedFindings: nmResult.mergedFindings,
      nanomindUsed: nmResult.nanomindAvailable,
      compiledArtifacts: nmResult.compiledArtifacts,
      newSemanticFindings: newFindings,
      integrityStatus: nmResult.integrityStatus,
    };
  } catch {
    // NanoMind unavailable -- static results are still valid
    return {
      mergedFindings: [...existingFindings],
      nanomindUsed: false,
      compiledArtifacts: 0,
      newSemanticFindings: 0,
      integrityStatus: 'UNAVAILABLE',
    };
  }
}
