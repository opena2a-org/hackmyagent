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
import type { NanoMindScanResult, ArtifactSummary, CoverageCandidate } from './scanner-bridge.js';
import type { AnalystResponse, ArtifactCoverageVerdict } from './inference/security-analyst.js';
import { routeAnalystVerdict, combineVerdict } from './analyst-coverage.js';

export type { ArtifactSummary } from './scanner-bridge.js';

export interface OrchestrationOptions {
  staticOnly?: boolean;
  ci?: boolean;
  deep?: boolean;
  silent?: boolean;
  /** Run NanoMind generative analysis (--nanomind flag). */
  nanomind?: boolean;
  projectType?: ProjectType;
  /**
   * Predicate: does this finding survive the product's display filters
   * (projectType applicability, ignore rules)? The coverage sweep uses it
   * when deciding which files are already structurally covered — a finding
   * the product filters OUT does not cover its file (the user never sees
   * it), so the sweep must still read that file. Without this, a file whose
   * only high/critical finding is dropped by the filter is invisible to
   * every channel (DVAA mcp-discovery-exposed: MCP-011 on
   * .well-known/mcp.json filtered for projectType=library while still
   * suppressing the sweep). Absent = all findings count (legacy behavior).
   */
  findingVisible?: (finding: SecurityFinding) => boolean;
}

export interface OrchestrationResult {
  mergedFindings: SecurityFinding[];
  nanomindUsed: boolean;
  compiledArtifacts: number;
  /** Compact per-artifact summaries (skills / MCPs / SOULs / A2A cards).
   *  Empty when NanoMind is unavailable or only source code was scanned. */
  artifactSummaries: ArtifactSummary[];
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
    reason: 'clean-scan' | 'not-ready' | 'backend-unavailable' | 'daemon-error' | 'platform-not-supported';
    modelLabel: string;
  };
  /**
   * Analyst coverage escalations (--nanomind, Phase A P1, CDS-023/024).
   * Files the deterministic scan did NOT flag but the v3.0.0 analyst routed to
   * `attack` or `abstain` under the abstention-gated policy. ADVISORY channel
   * only: these never enter mergedFindings, never change severity, score, or
   * exit code, and never suppress a static finding. Raw analyst auto-verdict
   * is NO-GO (~22% FPR on dual-use security code, weak calibration); the
   * analyst informs, abstention escalates — a human closes the loop.
   */
  analystEscalations?: AnalystEscalation[];
  /** Coverage-sweep accounting so capped scans are never silently partial. */
  coverageSweep?: CoverageSweepStats;
}

/** One advisory escalation from the analyst coverage sweep. */
export interface AnalystEscalation {
  /** Relative path of the escalated artifact (matches SecurityFinding.file). */
  file: string;
  /** Compiler-assigned artifact type (skill, mcp_config, soul, source_code, ...). */
  artifactType: string;
  /** 'attack' = named canonical class at HIGH/CRITICAL; 'abstain' = uncertain. */
  routed: 'attack' | 'abstain';
  /** Analyst-reported attack class (verbatim, sanitized). */
  attackClass: string;
  /** Analyst-reported severity, or null when it reported none. */
  severity: string | null;
  /** Analyst-reported classification (benign | suspicious | malicious | ""). */
  classification: string;
  /** Sanitized analysis narrative (truncated for transport). */
  summary: string;
  modelVersion: string;
  /** The combine policy that produced this escalation. Always 'abstention-gated'. */
  policy: 'abstention-gated';
}

export interface CoverageSweepStats {
  /** Compiled artifacts with no high/critical structural attack finding. */
  candidates: number;
  /** How many the analyst actually classified this scan. */
  swept: number;
  /** Candidates dropped by the per-scan cap or the time budget. */
  skipped: number;
  /**
   * Sweep calls that returned null (daemon absent/errored mid-sweep). Null is
   * "analyst unavailable", never a benign verdict — when every swept call was
   * null the scan must surface daemon-error, not a clean zero-state.
   */
  nullVerdicts: number;
  policy: 'abstention-gated';
}

/**
 * True when the sweep ran but got NO verdict back for anything it swept — the
 * daemon answered healthz at the gate check and then failed every classify
 * (wedged, OOM mid-scan). Distinguishes "swept N, all benign" from "swept N,
 * all unavailable" so a dead daemon is never rendered as a clean scan.
 */
export function sweepIndicatesDaemonError(stats: CoverageSweepStats): boolean {
  return stats.swept > 0 && stats.nullVerdicts === stats.swept;
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
      artifactSummaries: [],
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
      artifactSummaries: nmResult.artifactSummaries,
      newSemanticFindings: newFindings,
      integrityStatus: nmResult.integrityStatus,
    };

    // --- Security Analyst (generative model, --analyze flag) ---
    const { isAnalystReady, runAnalystInference, classifyArtifactForCoverage } = await import('./inference/security-analyst.js');

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
        // Asking the analyst (Qwen3 v3.0.0) to analyze either produces
        // hallucinated attack classes (verified 2026-04-22 on the prior
        // SmolLM2-based v0.1.0: empty dir + GIT-001 LOW produced 4 confabulated
        // HIGH narratives because file-less passed=false findings like AUTH-002
        // were being passed in). See memory
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
          // Daemon was healthy at the gate check but produced zero analyst
          // responses for one or more high-severity findings. Surface this
          // as a visible zero-state (not silence) so the user knows the
          // analyst layer ran but did not contribute. Without this, a
          // wedged-but-listening daemon prints nothing under "NanoMind
          // Analysis" and the user is gaslit into thinking analysis ran.
          if (result.analystFindings.length === 0) {
            result.analystZeroState = {
              reason: 'daemon-error',
              modelLabel: 'Qwen3 v3.0.0 inline',
            };
            if (!silent) {
              process.stderr.write(
                'NanoMind: analyst did not return verdicts for any finding. ' +
                'The daemon may be reachable but unable to classify. ' +
                'Check daemon logs.\n',
              );
            }
          }
        }

        // --- Coverage sweep (Phase A P1, CDS-023): the per-finding stage above
        // only reaches files the structural layer ALREADY flagged. Behavioral
        // attacks the AST is blind to (intent-as-instruction-text: prompt
        // injection, social engineering, code-level RCE in prose) produce zero
        // structural findings and so never reached the analyst — measured as
        // DVAA-full-repo 29.1% structural vs 82.6% with the analyst reading
        // the same artifacts (2026-06-05/06 baseline). The sweep sends compiled
        // artifacts WITHOUT a high/critical structural attack finding through
        // the analyst and routes the verdict under the abstention-gated policy:
        // the analyst can only ESCALATE for human review, never raise the
        // auto-verdict (CDS-024 — raw auto-verdict is NO-GO).
        const sweep = await runCoverageSweep(
          targetDir,
          nmResult.coverageCandidates,
          nmResult.mergedFindings,
          classifyArtifactForCoverage,
          silent,
          options.findingVisible,
        );
        result.coverageSweep = sweep.stats;
        if (sweep.escalations.length > 0) {
          result.analystEscalations = sweep.escalations;
          if (!silent) {
            process.stderr.write(
              `NanoMind: coverage sweep escalated ${sweep.escalations.length} artifact(s) for review\n`,
            );
          }
        }

        if (significant.length === 0 && sweep.escalations.length === 0) {
          // No HIGH/CRITICAL findings and the coverage sweep raised nothing.
          // Distinguish a genuinely clean sweep from a daemon that answered
          // healthz and then failed every classify call — reporting the
          // latter as clean-scan would gaslight the user into thinking
          // analysis ran (same failure mode the per-finding stage guards
          // against above).
          result.analystZeroState = {
            reason: sweepIndicatesDaemonError(sweep.stats) ? 'daemon-error' : 'clean-scan',
            modelLabel: 'Qwen3 v3.0.0 inline',
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
          modelLabel: 'Qwen3 v3.0.0 inline',
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
      artifactSummaries: [],
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

  // Scan-wide deadline. The per-call IPC timeout is 30s; with 10 findings
  // a wedged-but-connecting daemon could stall the scan for 5 minutes. Cap
  // the whole loop at 90s so a single bad scan does not hold up CI.
  const SCAN_DEADLINE_MS = 90_000;
  const deadlineAt = Date.now() + SCAN_DEADLINE_MS;

  for (const finding of prioritized) {
    if (Date.now() >= deadlineAt) {
      process.stderr.write(
        `NanoMind: analyst budget exhausted after ${results.length}/${prioritized.length} findings. ` +
        'Remaining findings skipped.\n',
      );
      break;
    }
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

// ============================================================================
// Coverage sweep (Phase A P1 — CDS-023/024, abstention-gated)
// ============================================================================

/**
 * Posture / hardening checks flag MISSING defenses or an over-permissive
 * posture, not a present attack; they fire on benign and malicious alike. A
 * file whose only high/critical findings are posture checks is still a
 * structural MISS for attack purposes and stays eligible for the sweep. Same
 * set as the published OASB corpus adapter / DVAA benchmark verdict mapping
 * (HARDENING_CHECK_IDS incl. the AST-SCOPE-001 wildcard; AST-SCOPE-003 stays
 * a verdict driver).
 */
export const POSTURE_HARDENING_CHECKS: ReadonlySet<string> = new Set([
  'AST-PROMPT-001', 'AST-PROMPT-003', 'AST-PROMPT-004',
  'AST-GOV-001', 'AST-GOV-002', 'AST-GOV-003', 'AST-GOV-004', 'AST-GOV-005',
  'AST-SCOPE-001',
]);

/** Per-scan cap on analyst coverage calls — mirrors the per-finding stage's
 *  top-10 cap so a --nanomind scan stays bounded at ~20 inference calls. */
const MAX_SWEEP_FILES = 10;

/** Sweep-stage deadline, separate from the per-finding stage's 90s budget. */
const SWEEP_DEADLINE_MS = 90_000;

/** Agent artifact types get sweep priority: they are the primary behavioral
 *  attack surface (instruction text the runtime will obey). */
const AGENT_ARTIFACT_TYPES = new Set([
  'skill', 'mcp_config', 'soul', 'system_prompt', 'agent_config', 'a2a_card',
]);

export interface CoverageSweepOutcome {
  escalations: AnalystEscalation[];
  stats: CoverageSweepStats;
}

/**
 * Run the analyst over compiled artifacts the structural layer did NOT flag
 * with a high/critical attack finding, and route each verdict under the
 * abstention-gated policy. The analyst can only ESCALATE (advisory, human
 * review); it never produces a finding, never changes severity/score/exit
 * code, and never suppresses anything (CDS-024).
 *
 * The classify function is injected so tests can exercise routing without a
 * daemon; production passes classifyArtifactForCoverage (gate + NLM over the
 * NanoMind-Guard Unix socket).
 */
export async function runCoverageSweep(
  targetDir: string,
  candidates: CoverageCandidate[],
  mergedFindings: SecurityFinding[],
  classify: (content: string) => Promise<ArtifactCoverageVerdict | null>,
  silent = false,
  findingVisible?: (finding: SecurityFinding) => boolean,
): Promise<CoverageSweepOutcome> {
  // Files already carrying a high/critical structural ATTACK finding are
  // covered by the per-finding analyst stage; the sweep targets the misses.
  // "Carrying" means carrying IN THE PRODUCT OUTPUT: a finding the display
  // filter drops (findingVisible returns false) does not cover its file —
  // the user never sees it, so the sweep must still read the file.
  const structurallyFlagged = new Set<string>();
  for (const f of mergedFindings) {
    if (f.passed || f.fixed || !f.file) continue;
    if (f.severity !== 'critical' && f.severity !== 'high') continue;
    if (POSTURE_HARDENING_CHECKS.has(f.checkId)) continue;
    if (findingVisible && !findingVisible(f)) continue;
    structurallyFlagged.add(f.file);
  }

  const eligible = candidates.filter(c => !structurallyFlagged.has(c.path));
  // Agent artifacts first (primary behavioral surface), discovery order within
  // each group (stable sort).
  const ordered = [...eligible].sort((a, b) => {
    const aAgent = AGENT_ARTIFACT_TYPES.has(a.artifactType) ? 0 : 1;
    const bAgent = AGENT_ARTIFACT_TYPES.has(b.artifactType) ? 0 : 1;
    return aAgent - bAgent;
  });
  const selected = ordered.slice(0, MAX_SWEEP_FILES);

  const escalations: AnalystEscalation[] = [];
  let swept = 0;
  let nullVerdicts = 0;
  const deadlineAt = Date.now() + SWEEP_DEADLINE_MS;
  const { readFile } = await import('node:fs/promises');
  const { join } = await import('node:path');

  // The analyst is a generative model reading attacker-controlled artifact
  // content, so every model-derived string is rendered/serialized as a single
  // line: embedded newlines could otherwise spoof extra advisory rows or fake
  // Verify: instructions inside HMA's trusted output (adversarial review M2).
  // Control/ANSI sequences are already stripped at the IPC boundary.
  const oneLine = (s: string | null): string =>
    (s ?? '').replace(/\s+/g, ' ').trim();

  for (const candidate of selected) {
    if (Date.now() >= deadlineAt) {
      if (!silent) {
        process.stderr.write(
          `NanoMind: coverage sweep budget exhausted after ${swept}/${selected.length} artifact(s). ` +
          'Remaining artifacts not swept.\n',
        );
      }
      break;
    }

    let content: string;
    try {
      content = await readFile(join(targetDir, candidate.path), 'utf-8');
    } catch {
      continue; // file vanished between scan and sweep — skip, never block
    }

    const verdict = await classify(content);
    swept++;
    if (verdict === null) {
      // Daemon unavailable/errored — not a benign verdict, never fabricate.
      nullVerdicts++;
      continue;
    }

    const routed = routeAnalystVerdict(verdict);
    // structuralAttack=false by selection; under abstention-gated the analyst
    // can only escalate, so `attack` from combineVerdict is always false here.
    const combined = combineVerdict(false, routed, 'abstention-gated');
    if (combined.escalate && (routed === 'attack' || routed === 'abstain')) {
      const severity = oneLine(verdict.severity);
      escalations.push({
        file: candidate.path,
        artifactType: candidate.artifactType,
        routed,
        attackClass: oneLine(verdict.attackClass),
        severity: severity.length > 0 ? severity : null,
        classification: oneLine(verdict.classification),
        summary: oneLine(verdict.analysis).slice(0, 600),
        modelVersion: verdict.modelVersion,
        policy: 'abstention-gated',
      });
    }
  }

  const skipped = eligible.length - swept;
  if (!silent && eligible.length > selected.length) {
    process.stderr.write(
      `NanoMind: coverage sweep capped at ${MAX_SWEEP_FILES} of ${eligible.length} eligible artifact(s). ` +
      'Re-run on a narrower path for full coverage.\n',
    );
  }

  return {
    escalations,
    stats: {
      candidates: eligible.length,
      swept,
      skipped: Math.max(0, skipped),
      nullVerdicts,
      policy: 'abstention-gated',
    },
  };
}
