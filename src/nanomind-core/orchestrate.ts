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
import type { AnalystResponse } from './inference/security-analyst.js';

export interface OrchestrationOptions {
  staticOnly?: boolean;
  ci?: boolean;
  deep?: boolean;
  silent?: boolean;
  /** Run AnaLM generative analysis (--analm flag). */
  analm?: boolean;
}

export interface OrchestrationResult {
  mergedFindings: SecurityFinding[];
  nanomindUsed: boolean;
  compiledArtifacts: number;
  newSemanticFindings: number;
  integrityStatus: string;
  /** AnaLM results (present when --analm is used and model is available). */
  analystFindings?: AnalystResponse[];
  /** Hint shown to user when analyst is available but not used. */
  analystHint?: string;
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
  const { staticOnly = false, ci = false, silent = false, analm = false } = options;

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
    // Ensure NanoMind daemon is running for Tier 2 inference.
    // Non-blocking: if daemon can't start, Tier 0/1 (local TME) still works.
    const { ensureDaemon } = await import('./daemon-lifecycle.js');
    const daemonAvailable = await ensureDaemon();
    if (!silent && daemonAvailable) {
      process.stderr.write('NanoMind daemon: connected\n');
    }

    // Pre-download the ONNX model before scanning starts.
    // For npm users without cached models, this triggers a one-time
    // download from HuggingFace (~5.5MB). Without this, the download
    // happens lazily during the first file compilation which can cause
    // the model to not be ready for subsequent files in the same scan.
    const { getTMEClassifier } = await import('./inference/tme-classifier.js');
    const tme = getTMEClassifier();
    await tme.ensureModel(silent);

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

    // Flush NanoMind classification telemetry (non-blocking, best-effort)
    import('../telemetry/nanomind-telemetry.js')
      .then(m => m.flushNanoMindTelemetry())
      .catch(() => {});

    const result: OrchestrationResult = {
      mergedFindings: nmResult.mergedFindings,
      nanomindUsed: nmResult.nanomindAvailable,
      compiledArtifacts: nmResult.compiledArtifacts,
      newSemanticFindings: newFindings,
      integrityStatus: nmResult.integrityStatus,
    };

    // --- Security Analyst (generative model, --analyze flag) ---
    const { isAnalystReady, runAnalystInference } = await import('./inference/security-analyst.js');

    if (analm) {
      const ready = await isAnalystReady();
      if (ready) {
        if (!silent) process.stderr.write('Running AnaLM analysis...\n');
        result.analystFindings = await runAnalystOnFindings(
          nmResult.mergedFindings,
          runAnalystInference,
        );
        if (!silent && result.analystFindings.length > 0) {
          process.stderr.write(
            `Analyst: ${result.analystFindings.length} finding(s) analyzed\n`,
          );
        }
      } else {
        if (!silent) {
          process.stderr.write(
            'AnaLM not set up. Run: hackmyagent analm setup\n',
          );
        }
      }
    } else if (!silent && !ci) {
      // Check if analyst is available but not used -- show hint once
      const ready = await isAnalystReady();
      if (ready) {
        result.analystHint = 'Add --analm for AI-powered threat analysis';
      }
    }

    return result;
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

/**
 * Run the analyst model on failed findings that warrant deeper analysis.
 * Targets: suspicious/malicious classifications, credential findings,
 * and high/critical severity findings.
 */
async function runAnalystOnFindings(
  findings: SecurityFinding[],
  runInference: typeof import('./inference/security-analyst.js').runAnalystInference,
): Promise<AnalystResponse[]> {
  const results: AnalystResponse[] = [];
  const failed = findings.filter(f => !f.passed && !f.fixed);

  // Limit to top 10 most important findings to keep inference time reasonable
  const prioritized = failed
    .sort((a, b) => {
      const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      return (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0);
    })
    .slice(0, 10);

  for (const finding of prioritized) {
    // Choose task type based on finding category
    const isCredential = finding.checkId?.startsWith('CRED') ||
      finding.attackClass === 'credential_abuse';
    const taskType = isCredential
      ? 'credentialContextClassification' as const
      : 'threatAnalysis' as const;

    const content = [
      finding.name,
      finding.description,
      finding.message,
      finding.file ? `File: ${finding.file}` : '',
      finding.attackClass ? `Attack class: ${finding.attackClass}` : '',
    ].filter(Boolean).join('\n');

    const response = await runInference({
      taskType,
      content,
      context: `Check ID: ${finding.checkId}, Severity: ${finding.severity}`,
    });

    if (response) {
      results.push(response);
    }
  }

  return results;
}
