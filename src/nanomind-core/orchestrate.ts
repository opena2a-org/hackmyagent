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

import type { SecurityFinding, ProjectType } from '../hardening/security-check.js';
import type { NanoMindScanResult } from './scanner-bridge.js';
import type { AnalystResponse } from './inference/security-analyst.js';

export interface OrchestrationOptions {
  staticOnly?: boolean;
  ci?: boolean;
  deep?: boolean;
  silent?: boolean;
  /** Run NanoMind generative analysis (--nanomind flag). */
  nanomind?: boolean;
  projectType?: ProjectType;
}

export interface OrchestrationResult {
  mergedFindings: SecurityFinding[];
  nanomindUsed: boolean;
  compiledArtifacts: number;
  newSemanticFindings: number;
  integrityStatus: string;
  /** NanoMind generative results (present when --nanomind is used and model is available). */
  analystFindings?: AnalystResponse[];
  /** Hint shown to user when NanoMind is available but not used. */
  analystHint?: string;
  /**
   * When --nanomind was requested but produced no per-finding output (e.g., clean scan),
   * carries the model metadata so the CLI can render an honest zero-state block instead
   * of staying silent. Per v0.5.0 validation (2026-04-22), the model is a per-artifact
   * attack-classification specialist; clean-scan intel reports are not a supported task
   * until a dedicated NLM-SUM is trained.
   */
  analystZeroState?: {
    reason: 'clean-scan' | 'not-ready' | 'backend-unavailable';
    modelLabel: string;
  };
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
  const { staticOnly = false, ci = false, silent = false, nanomind = false } = options;

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
    const nmResult: NanoMindScanResult = await runNanoMindScan(targetDir, existingFindings, options.projectType);

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

    if (nanomind) {
      const ready = await isAnalystReady();
      if (ready) {
        const failed = nmResult.mergedFindings.filter(f => !f.passed && !f.fixed);
        // Gate the analyst on HIGH/CRITICAL findings that are tied to a real
        // file. Two reasons to exclude both LOW/MEDIUM and file-less findings:
        // (1) LOW/MEDIUM are typically filesystem-hygiene checks (GIT-001
        //     "Missing .gitignore", PERM-001, etc.) that are not per-artifact
        //     attack classifications.
        // (2) HIGH/CRITICAL findings without a file (AUTH-002 "no auth
        //     configured", PROC-003, NET-005) are synthesized "nothing
        //     configured" checks — they don't feed a per-artifact classifier
        //     any content to reason about.
        // Asking SmolLM2 v0.5.0 to analyze either produces hallucinated attack
        // classes (verified 2026-04-22: empty dir + GIT-001 LOW produced 4
        // confabulated HIGH narratives because file-less passed=false findings
        // like AUTH-002 were being passed in). See memory
        // project_nanomind_v05_intelreport_task_mismatch.
        const significant = failed.filter(f =>
          (f.severity === 'critical' || f.severity === 'high') && !!f.file,
        );
        if (significant.length > 0) {
          if (!silent) process.stderr.write('Running NanoMind generative analysis (typically adds 15-30s per artifact)...\n');
          result.analystFindings = await runAnalystOnFindings(
            significant,
            runAnalystInference,
          );
          if (!silent && result.analystFindings.length > 0) {
            process.stderr.write(
              `NanoMind: ${result.analystFindings.length} finding(s) analyzed\n`,
            );
          }
        } else {
          // No HIGH/CRITICAL findings — skip the analyst call. LOW/MEDIUM-only
          // scans are effectively "clean" from an AI-threat perspective; the
          // deterministic Observations block carries the verdict.
          result.analystZeroState = {
            reason: 'clean-scan',
            modelLabel: 'SmolLM2 v0.5.0 inline',
          };
        }
      } else {
        if (!silent) {
          process.stderr.write(
            'NanoMind generative model not set up. Run: hackmyagent nanomind setup\n',
          );
        }
        result.analystZeroState = {
          reason: 'not-ready',
          modelLabel: 'SmolLM2 v0.5.0 inline',
        };
      }
    } else if (!silent && !ci) {
      // Show hint only if NanoMind is available and there are findings to analyze
      const failed = nmResult.mergedFindings.filter(f => !f.passed && !f.fixed);
      if (failed.length > 0) {
        const ready = await isAnalystReady();
        if (ready) {
          result.analystHint = 'Add --nanomind for AI-powered threat analysis';
        }
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
    const checkId = finding.checkId || '';
    const category = (finding.category || '').toLowerCase();
    const attackClass = finding.attackClass || '';

    let taskType: 'threatAnalysis' | 'credentialContextClassification' | 'governanceReasoning' | 'checkExplanation' | 'falsePositiveDetection';

    if (checkId.startsWith('CRED') || attackClass === 'credential_abuse') {
      taskType = 'credentialContextClassification';
    } else if (
      category === 'governance' || category === 'trust-hierarchy' ||
      checkId.startsWith('AST-GOV') || checkId.startsWith('AST-GOVERN') ||
      checkId.startsWith('AST-PROMPT') || checkId.startsWith('AST-HEARTBEAT')
    ) {
      taskType = 'governanceReasoning';
    } else if (finding.severity === 'critical' || finding.severity === 'high') {
      taskType = 'threatAnalysis';
    } else {
      taskType = 'checkExplanation';
    }

    const content = [
      finding.name,
      finding.description,
      finding.message,
      finding.file ? `File: ${finding.file}` : '',
      finding.attackClass ? `Attack class: ${finding.attackClass}` : '',
      finding.category ? `Category: ${finding.category}` : '',
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
